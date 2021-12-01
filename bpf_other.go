//go:build !linux
// +build !linux

package exectrace

import (
	"io"
)

// BPFObjects contains a loaded BPF program.
type BPFObjects interface {
	io.Closer
}

// LoadBPFObjects reads and parses the programs and maps out of the given BPF
// executable file.
func LoadBPFObjects(_ io.ReaderAt) (BPFObjects, error) {
	return nil, errUnsupportedOS
}
