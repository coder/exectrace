package exectrace

// Filter contains optional compile-time filters for the eBPF portion of
// exectrace.
type Filter struct {
	// PidNS filters all processes that are in the given PID namespace or in the
	// child namespace tree of this given namespace. This is very useful for
	// Docker containers, as you can read all processes in a container (or in
	// child containers). You can read the PID namespace ID for a given process
	// by running `readlink /proc/x/ns/pid`.
	PidNS uint64
}

// CompileOptions contains options to pass to functions that compile the eBPF
// program used by exectrace.
type CompileOptions struct {
	// Compiler contains the executable name or full path to the C compiler. A
	// recent version of clang is recommended (i.e. clang-11+). Required.
	Compiler string
	// Optional compile-time filters.
	Filter Filter

	// Endianness to compile the program for. If not specified, the current
	// system endianness of the system will be used.
	Endianness Endianness
	// TempDir is where the compilation inputs will be placed to pass to the
	// compiler. This is the working directory where the compilation will take
	// place. Header and source files will be copied to this directory out of
	// the binary; if they already exist then an error will be returned instead
	// of overwriting them.
	//
	// If empty, a temporary dir will be created and automatically cleaned up on
	// error or success. If specified, the dir will not be automatically
	// deleted.
	TempDir string
}
