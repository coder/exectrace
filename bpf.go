package exectrace

import "bytes"

// LoadBPFObjectsBytes is a helper for LoadBPFObjects that automatically wraps
// the given byte slice with a bytes.Reader.
func LoadBPFObjectsBytes(p []byte) (BPFObjects, error) {
	return LoadBPFObjects(bytes.NewReader(p))
}
