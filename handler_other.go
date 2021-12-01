//go:build !linux
// +build !linux

package exectrace

// NewHandler creates a Handler using the given BPFObjects
func NewHandler(_ BPFObjects) (Handler, error) {
	return nil, errUnsupportedOS
}
