package exectrace

import (
	"encoding/binary"
	"unsafe"
)

type Endianness string

const (
	BigEndian    Endianness = "big-endian"
	LittleEndian Endianness = "little-endian"
)

var (
	// NativeEndian is the byte order for the local platform. We test for
	// endianness at runtime because some architectures can be booted into
	// different endian modes.
	NativeEndian binary.ByteOrder
	// NativeEndianness returns the endianness of the current architecture.
	NativeEndianness Endianness
)

// Detect the endianness of the current architecture. Adapted from tensorflow,
// licensed under the MIT license:
// https://github.com/tensorflow/tensorflow/blob/bfcfad55b7b3fa4a1093fa748d4241f9457b2a84/tensorflow/go/tensor.go#L488-L505
func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		NativeEndian = binary.LittleEndian
		NativeEndianness = LittleEndian
	case [2]byte{0xAB, 0xCD}:
		NativeEndian = binary.BigEndian
		NativeEndianness = BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}
