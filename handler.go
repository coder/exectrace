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

	// These values are of the new process. Keep in mind that the exec call may
	// fail and the PID will be released in such a case.
	PID uint32 `json:"pid"`
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`

	// ID contains the cgroup ID of the process. This number is equal to the
	// inode number of the paths in the cgroup2 filesystem.
	//
	// You can find cgroup paths or the unified cgroup2 path by running:
	//     $ find /path/to/cgroupfs -inum 1234
	// Or use the handy fields below.
	CgroupID uint64 `json:"id"`

	// Comm is the "name" of the parent executable minus the path.
	Comm string `json:"comm"`
}
