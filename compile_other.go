//go:build !linux
// +build !linux

package exectrace

import (
	"context"
)

// CompileProgram always returns an error on operating systems other than Linux.
func CompileProgram(_ context.Context, _ CompileOptions) ([]byte, error) {
	return nil, errUnsupportedOS
}
