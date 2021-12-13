//go:build !linux
// +build !linux

package exectrace

import (
	"runtime"

	"golang.org/x/xerrors"
)

// New is not supported on OSes other than Linux.
func New(_ *TracerOpts) (Tracer, error) {
	return nil, xerrors.Errorf(`%q is an unsupported OS, only "linux" is supported`, runtime.GOOS)
}
