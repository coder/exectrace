package exectrace

import "io"

// Tracer allows consumers to read exec events from the kernel via an eBPF
// program. `execve()` syscalls are traced in the kernel, and details about the
// event are sent back to this Go interface.
type Tracer interface {
	io.Closer

	Start() error
	Read() (*Event, error)
}

// Event contains data about each exec event with many fields for easy
// filtering and logging.
type Event struct {
	Filename string `json:"filename"`
	// Argv contains the raw argv supplied to the process, including argv[0]
	// (which is equal to `filepath.Base(e.Filename)` in most circumstances).
	Argv []string `json:"argv"`
	// Truncated is true if we were unable to read all process arguments into
	// Argv because there were more than ARGLEN arguments.
	Truncated bool `json:"truncated"`

	// These values are of the new process. Keep in mind that the exec call may
	// fail and the PID will be released in such a case.
	PID uint32 `json:"pid"`
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`

	// Comm is the "name" of the parent executable minus the path.
	Comm string `json:"comm"`
}
