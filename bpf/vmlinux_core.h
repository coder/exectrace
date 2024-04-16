// This is file is based on the Linux Kernel headers and is licensed under
// GPL-2.0.
//
// Contains CO-RE structs that are adapted and shrunk down from vmlinux.h.

#ifndef __VMLINUX_CORE_H__
#define __VMLINUX_CORE_H__

struct task_struct___exectrace {
	struct nsproxy___exectrace *nsproxy;
} __attribute__((preserve_access_index));

struct nsproxy___exectrace {
	struct pid_namespace___exectrace *pid_ns_for_children;
} __attribute__((preserve_access_index));

struct ns_common___exectrace {
	__u32 inum;
} __attribute__((preserve_access_index));

struct pid_namespace___exectrace {
	struct pid_namespace___exectrace *parent;
	struct ns_common___exectrace ns;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_CORE_H__ */
