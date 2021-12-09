//go:build !linux
// +build !linux

package exectrace

// NewTracer creates a Tracer using the given BPFObjects.
func NewTracer(_ BPFObjects) (Tracer, error) {
	return nil, errUnsupportedOS
}
