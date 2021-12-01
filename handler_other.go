//go:build !linux
// +build !linux

package exectrace

import (
	"runtime"

	"golang.org/x/xerrors"
)

// NewHandler creates a Handler using the given BPFObjects
func NewHandler(objs BPFObjects) (Handler, error) {
	return nil, errUnsupportedOS
}
