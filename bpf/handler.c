#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "vmlinux_core.h"

// This license needs to be GPL-compatible because the BTF verifier won't let us
// use many BPF helpers (including `bpf_probe_read_*`).
u8 __license[] SEC("license") = "Dual MIT/GPL"; // NOLINT

// Adds some extra log entries that are usually spam when deployed in the real
// world.
//#define DEBUG

// These constants must be kept in sync with Go.
#define ARGLEN    32    // maximum amount of args in argv we'll copy
#define ARGSIZE   1024  // maximum byte length of each arg in argv we'll copy
#define LOGFMTSIZE 1024 // maximum length of log fmt str sent back to userspace
#define LOGARGLEN 3     // maximum amount of fmt arguments to a log entry

// Maximum levels of PID namespace nesting. PID namespaces have a hierarchy
// limit of 32 since kernel 3.7.
#define MAX_PIDNS_HIERARCHY 32

// This struct is defined according to
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
struct exec_info {
	u16 common_type;            // offset=0,  size=2
	u8  common_flags;           // offset=2,  size=1
	u8  common_preempt_count;   // offset=3,  size=1
	s32 common_pid;             // offset=4,  size=4

	s32             syscall_nr; // offset=8,  size=4
	u32             pad;        // offset=12, size=4 (pad)
	const u8        *filename;  // offset=16, size=8 (ptr)
	const u8 *const *argv;      // offset=24, size=8 (ptr)
	const u8 *const *envp;      // offset=32, size=8 (ptr)
};

// The event struct. This struct must be kept in sync with the Golang
// counterpart.
struct event_t {
	// Details about the process being launched.
	u8  filename[ARGSIZE];
	u8  argv[ARGLEN][ARGSIZE];
	u32 argc; // set to ARGLEN + 1 if there were more than ARGLEN arguments
	u32 uid;
	u32 gid;
	u32 pid;

	// Name of the calling process.
	u8  comm[ARGSIZE];
};

static struct event_t zero_event SEC(".rodata") = {
	.filename = {0},
	.argv = {},
	.argc = 0,
	.uid = 0,
	.gid = 0,
	.pid = 0,
	.comm = {0},
};

// Log entry from eBPF to userspace. This struct must be kept in sync with the
// Golang counterpart.
struct log_entry_t {
	u32 uid;
	u32 gid;
	u32 pid;
	// fmt contains a format string that only contains "%d" and "%u" directives.
	// In userspace we will replace these with the arguments in `args`.
	u8  fmt[LOGFMTSIZE];
	// These are communicated back to userspace as unsigned 32-bit integers, but
	// depending on the format string, they could be treated as signed or
	// unsigned.
	u32 args[LOGARGLEN];
};

static struct log_entry_t zero_log SEC(".rodata") = {
	.fmt = {0},
	.args = {},
};

// This is the ring buffer we'll output events data to. The Go program reads
// from this ring buffer and reads the data into a Go struct for easy usage.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// The ring buffer we will output log entries to.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} logs SEC(".maps");

// The map we'll use to retrieve the configuration about the given filters.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} filters SEC(".maps");

// Indexes in the `filters` map for each configuration option.
static u32 filter_pidns_idx SEC(".rodata") = 0;

// LOG[N] calls log() with the unused parameters zeroed out. `N` is the amount
// of fmt args you want to use.
#define LOG0(fmt) LOG3(fmt, 0, 0, 0)
#define LOG1(fmt, arg0) LOG3(fmt, arg0, 0, 0)
#define LOG2(fmt, arg0, arg1) LOG3(fmt, arg0, arg1, 0)
#define LOG3(fmt, arg0, arg1, arg2) log(fmt, sizeof(fmt), arg0, arg1, arg2)

// log logs to bpf_trace_printk() and sends the formatted log string to the logs
// ringbuf. Call LOG[N]() instead of calling this directly.
static void log(const char *fmt, u32 fmt_size, u32 arg0, u32 arg1, u32 arg2) {
	bpf_trace_printk(fmt, fmt_size, arg0, arg1, arg2);

	struct log_entry_t *entry;
	entry = bpf_ringbuf_reserve(&logs, sizeof(struct log_entry_t), 0);
	if (!entry) {
		bpf_printk("could not reserve logs ringbuf memory");
		return;
	}

	// Zero out the log entry for safety. If we don't do this, we risk sending
	// random kernel memory back to userspace.
	s32 ret = bpf_probe_read_kernel(entry, sizeof(struct log_entry_t), &zero_log);
	if (ret < 0) {
		bpf_printk("zero out log: %d", ret);
		bpf_ringbuf_discard(entry, 0);
		return;
	}

	// Copy the fmt string into the log entry.
	// NOTE: bpf_snprintf is not supported in some of the lower kernel versions
	// we claim to support, so we have to do it this way.
	ret = bpf_probe_read_kernel_str(&entry->fmt, sizeof(entry->fmt), fmt);
	if (ret < 0) {
		bpf_printk("could not read fmt into log struct: %d", ret);
		bpf_ringbuf_discard(entry, 0);
		return;
	}

	entry->uid = bpf_get_current_uid_gid();
	entry->gid = bpf_get_current_uid_gid() >> 32; // NOLINT(readability-magic-numbers)
	entry->pid = bpf_get_current_pid_tgid();
	entry->args[0] = arg0;
	entry->args[1] = arg1;
	entry->args[2] = arg2;

	bpf_ringbuf_submit(entry, 0);
}

// filter_pidns checks if the current task is in a PID namespace equal to or
// under the given target_pidns. Returns a 0 if successful, or a negative error
// on failure.
s32 filter_pidns(u32 target_pidns) {
	struct task_struct___exectrace *task = (void *)bpf_get_current_task(); // NOLINT(performance-no-int-to-ptr)

	struct pid_namespace___exectrace *pidns;
	s32 ret = BPF_CORE_READ_INTO(&pidns, task, nsproxy, pid_ns_for_children);
	if (ret) {
		LOG1("could not read current task pidns: %d", ret);
		return ret;
	}

	// Iterate up the PID NS tree until we either find the net namespace we're
	// filtering for, or until there are no more parent namespaces.
	u32 inum;
	u32 i = 0;
	for (; i < MAX_PIDNS_HIERARCHY; i++) {
		if (i != 0) {
			ret = BPF_CORE_READ_INTO(&pidns, pidns, parent);
			if (ret) {
				LOG2("could not read parent pidns on iteration %u: %d", i, ret);
				return ret;
			}
		}
		if (!pidns) {
			#ifdef DEBUG
			LOG1("no more pidns after %u iterations", i);
			#endif
			return -1;
		}

		ret = BPF_CORE_READ_INTO(&inum, pidns, ns.inum);
		if (ret) {
			LOG2("could not read pidns common on iteration %u: %d", i, ret);
			return ret;
		}

		#ifdef DEBUG
		LOG3("got pidns on iteration %u: %u (target=%u)", i, inum, target_pidns);
		#endif

		if (inum == target_pidns) {
			// One of the parent PID namespaces was the target PID namespace.
			return 0;
		}
	}

	// Iterated through all 32 parent PID namespaces and couldn't find what we
	// were looking for.
	#ifdef DEBUG
	LOG1("does not match pidns filter after %u iterations", i);
	#endif
	return -1;
}

// Tracepoint at the top of execve() syscall.
SEC("tracepoint/syscalls/sys_enter_execve")
s32 enter_execve(struct exec_info *ctx) {
	u32 *target_pidns = bpf_map_lookup_elem(&filters, &filter_pidns_idx);
	if (target_pidns && *target_pidns && filter_pidns(*target_pidns)) {
		return 1;
	}

	// Reserve memory for our event on the `events` ring buffer defined above.
	struct event_t *event;
	event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
	if (!event) {
		LOG0("could not reserve events ringbuf memory");
		return 1;
	}

	// Zero out the event for safety. If we don't do this, we risk sending
	// random kernel memory back to userspace.
	s32 ret = bpf_probe_read_kernel(event, sizeof(event), &zero_event);
	if (ret) {
		LOG1("zero out event: %d", ret);
		bpf_ringbuf_discard(event, 0);
		return 1;
	}

	// Store process/calling process details.
	event->uid = bpf_get_current_uid_gid();
	event->gid = bpf_get_current_uid_gid() >> 32; // NOLINT(readability-magic-numbers)
	event->pid = bpf_get_current_pid_tgid();
	ret = bpf_get_current_comm(&event->comm, sizeof(event->comm));
	if (ret) {
		LOG1("could not get current comm: %d", ret);
		bpf_ringbuf_discard(event, 0);
		return 1;
	}

	// Write the filename in addition to argv[0] because the filename contains
	// the full path to the file which could be more useful in some situations.
	ret = bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ctx->filename);
	if (ret < 0) {
		LOG1("could not read filename into event struct: %d", ret);
		bpf_ringbuf_discard(event, 0);
		return 1;
	}

	// Copy everything from ctx->argv to event->argv, incrementing event->argc
	// as we go.
	for (u32 i = 0; i < ARGLEN; i++) {
		if (!(&ctx->argv[i])) {
			goto out;
		}

		// Copying the arg into it's own variable before copying it into
		// event->argv[i] prevents memory corruption.
		const u8 *argp = NULL;
		ret = bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]);
		if (ret || !argp) {
			goto out;
		}

		// Copy argp to event->argv[i].
		ret = bpf_probe_read_user_str(event->argv[i], sizeof(event->argv[i]), argp);
		if (ret < 0) {
			LOG2("read argv %u: %d", i, ret);
			goto out;
		}

		event->argc++;
	}

	// This won't get hit if we `goto out` in the loop above. This is to signify
	// to userspace that we couldn't copy all of the arguments because it
	// exceeded ARGLEN.
	event->argc++;

out:
	// Write the event to the ring buffer and notify userspace. This will cause
	// the `Read()` call in userspace to return if it was blocked.
	bpf_ringbuf_submit(event, 0);

	return 0;
}
