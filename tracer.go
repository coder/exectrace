package exectrace

import "io"

// TracerOpts contains all of the configuration options for the tracer. All are
// optional.
type TracerOpts struct {
	// PidNS filters all processes that are in the given PID namespace or in the
	// child namespace tree of this given namespace. This is very useful for
	// Docker containers, as you can read all processes in a container (or in
	// child containers).
	//
	// You can read the PID namespace ID for a given process by running
	// `readlink /proc/x/ns/pid`.
	//
	// This filter runs in the kernel for high performance.
	PidNS uint32

	// LogFn is called for each log line that is read from the kernel. All logs
	// are considered error logs unless running a debug version of the eBPF
	// program.
	//
	// If unspecified, a default log function is used that logs to stderr.
	LogFn func(uid, gid, pid uint32, logLine string)
}

// Tracer allows consumers to read exec events from the kernel via an eBPF
// program. `execve()` syscalls are traced in the kernel, and details about the
// event are sent back to this Go interface.
type Tracer interface {
	io.Closer

	// Read blocks until an exec event is available, then returns it.
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

	// Comm is the "name" of the parent process, usually the filename of the
	// executable (but not always).
	Comm string `json:"comm"`
}
