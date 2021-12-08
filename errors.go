package exectrace

import (
	"runtime"

	"golang.org/x/xerrors"
)

var (
	errTracerClosed  = xerrors.New("tracer is closed")
	errObjectsClosed = xerrors.New("objects are closed")

	errUnsupportedOS = xerrors.Errorf(`%q is an unsupported OS, only "linux" is supported`, runtime.GOOS)
)

// Suppress unused variable errors. These variables are used in files that are
// not included in all builds.
var (
	_ = errTracerClosed
	_ = errObjectsClosed
	_ = errUnsupportedOS
)
