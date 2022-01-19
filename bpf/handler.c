#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

// This license needs to be GPL-compatible because the BTF verifier won't let us
// use many BPF helpers (including `bpf_probe_read_*`).
u8 __license[] SEC("license") = "Dual MIT/GPL"; // NOLINT

// These constants must be kept in sync with Go.
#define ARGLEN  32   // maximum amount of args in argv we'll copy
#define ARGSIZE 1024 // maximum byte length of each arg in argv we'll copy

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

// This is the ring buffer we'll output events data to. The Go program reads
// from this ring buffer and reads the data into a Go struct for easy usage.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// The map we'll use to retrieve the configuration about the given filters.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} filters SEC(".maps");

// Indexes in the `filters` map for each configuration option.
static u32 filter_pidns_idx SEC(".rodata") = 0;

// Zero values of any char[ARGSIZE] or char[ARGLEN][ARGSIZE] arrays.
static char zero[ARGSIZE] SEC(".rodata") = {0};
static char zero_argv[ARGLEN][ARGSIZE] SEC(".rodata") = {0};

// filter_pidns checks if the current task is in a PID namespace equal to or
// under the given target_pidns. Returns a 0 if successful, or a negative error
// on failure.
s32 filter_pidns(u32 target_pidns) {
	struct task_struct *task = (void *)bpf_get_current_task(); // NOLINT(performance-no-int-to-ptr)

	struct nsproxy *ns;
	s64 ret = bpf_core_read(&ns, sizeof(ns), &task->nsproxy);
	if (ret) {
		bpf_printk("could not read current task nsproxy: %d", ret);
		return ret;
	}

	struct pid_namespace *pidns;
	ret = bpf_core_read(&pidns, sizeof(pidns), &ns->pid_ns_for_children);
	if (ret) {
		bpf_printk("could not read current task pidns: %d", ret);
		return ret;
	}

	// Iterate up the PID NS tree until we either find the net namespace we're
	// filtering for, or until there are no more parent namespaces.
	struct ns_common nsc;
	#pragma unroll
	for (s32 i = 0; i < MAX_PIDNS_HIERARCHY; i++) {
		if (i != 0) {
			ret = bpf_core_read(&pidns, sizeof(pidns), &pidns->parent);
			if (ret) {
				bpf_printk("could not read parent pidns on iteration %d: %d", i, ret);
				return ret;
			}
		}
		if (!pidns) {
			// No more PID namespaces.
			return -1;
		}

		ret = bpf_core_read(&nsc, sizeof(nsc), &pidns->ns);
		if (ret) {
			bpf_printk("could not read pidns common on iteration %d: %d", i, ret);
			return ret;
		}

		if (nsc.inum == target_pidns) {
			// One of the parent PID namespaces was the target PID namespace.
			return 0;
		}
	}

	// Iterated through all 32 parent PID namespaces and couldn't find what we
	// were looking for.
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
		bpf_printk("could not reserve ringbuf memory");
		return 1;
	}

	// Zero out the filename, argv and comm arrays on the event for safety. If
	// we don't do this, we risk sending random kernel memory back to userspace.
	s64 ret = bpf_probe_read_kernel(&event->filename, sizeof(zero), &zero);
	if (ret) {
		bpf_printk("zero out filename: %d", ret);
		bpf_ringbuf_discard(event, 0);
		return 1;
	}
	ret = bpf_probe_read_kernel(&event->argv, sizeof(zero_argv), &zero_argv);
	if (ret) {
		bpf_printk("zero out argv: %d", ret);
		bpf_ringbuf_discard(event, 0);
		return 1;
	}
	ret = bpf_probe_read_kernel(&event->comm, sizeof(zero), &zero);
	if (ret) {
		bpf_printk("zero out comm: %d", ret);
		bpf_ringbuf_discard(event, 0);
		return 1;
	}

	// Store process/calling process details.
	u64 uidgid = bpf_get_current_uid_gid();
	u64 pidtgid = bpf_get_current_pid_tgid();
	event->uid = uidgid;       // uid is the first 32 bits
	event->gid = uidgid >> 32; // gid is the last 32 bits NOLINT(readability-magic-numbers)
	event->pid = pidtgid;      // pid is the first 32 bits
	ret = bpf_get_current_comm(&event->comm, sizeof(event->comm));
	if (ret) {
		bpf_printk("could not get current comm: %d", ret);
		bpf_ringbuf_discard(event, 0);
		return 1;
	}

	// Write the filename in addition to argv[0] because the filename contains
	// the full path to the file which could be more useful in some situations.
	ret = bpf_probe_read_user_str(event->filename, sizeof(event->filename), ctx->filename);
	if (ret < 0) {
		bpf_printk("could not read filename into event struct: %d", ret);
		bpf_ringbuf_discard(event, 0);
		return 1;
	}

	// Copy everything from ctx->argv to event->argv, incrementing event->argc
	// as we go.
	for (s32 i = 0; i < ARGLEN; i++) {
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
			bpf_printk("read argv %d: %d", i, ret);
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
