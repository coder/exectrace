package exectrace

import "io"

// Handler allows consumers to read exec events from the kernel via an eBPF
// program. `execve()` syscalls are traced in the kernel, and details about the
// event are sent back to this Go interface.
type Handler interface {
	io.Closer

	Start() error
	Read() (*Event, error)
}

// Event builds on top of event and contains more user-friendly fields for
// filtering and logging purposes.
type Event struct {
	Filename string `json:"filename"`
	// Argv contains the raw argv supplied to the process, including argv[0]
	// (which is equal to `filepath.Base(e.Filename)` in most circumstances).
	Argv []string `json:"argv"`
	// Truncated is true if we were unable to read all process arguments into
	// Argv because they were
	Truncated bool `json:"truncated"`

	// Caller contains details about the process that made the `exec()` syscall.
	Caller Process `json:"caller"`
}

type Process struct {
	PID uint32 `json:"pid"`
	// Comm is the "name" of the executable minus the path.
	Comm string `json:"comm"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`

	Cgroup Cgroup `json:"cgroup"`
}

type Cgroup struct {
	// ID contains the cgroup's ID. This number is equal to the inode number of
	// the paths in the cgroup/cgroup2 filesystem.
	//
	// You can find cgroup paths or the unified cgroup2 path by running:
	//     $ find /path/to/cgroupfs -inum 1234
	// Or use the handy fields below.
	ID int32 `json:"id"`
	// PathsV1 contains all cgroup (v1) paths that match the cgroup ID. This is
	// a slice because there can be multiple. The prefix of the cgroup
	// mountpoint is removed in advance, but the forward slash prefix is
	// retained.
	//
	// e.g. `/proc-sys-fs-binfmt_misc.mount/memory.failcnt`, which was
	// originally at
	// `/sys/fs/cgroup/memory/proc-sys-fs-binfmt_misc.mount/memory.failcnt`.
	PathsV1 []string `json:"paths_v1"`
	// PathsV2 contains all cgroup2 paths that match the cgroup ID. The prefix
	// of the cgroup mountpoint is removed in advance, but the forward slash
	// prefix is retained.
	//
	// e.g. `/user.slice/user-1002.slice/session-1.scope`, which was originally
	// at
	// `/sys/fs/cgroup/unified/user.slice/user-1002.slice/session-1.scope`.
	PathV2 string `json:"paths_v2"`
}
