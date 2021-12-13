//go:build (linux && arm64be) || (linux && armbe) || (linux && mips) || (linux && mips64) || (linux && mips64p32) || (linux && ppc64) || (linux && s390) || (linux && s390x) || (linux && sparc) || (linux && sparc64)
// +build linux,arm64be linux,armbe linux,mips linux,mips64 linux,mips64p32 linux,ppc64 linux,s390 linux,s390x linux,sparc linux,sparc64

package exectrace

import (
	_ "embed"
	"encoding/binary"
)

// The native endian of the processor this program was compiled for.
var NativeEndian = binary.BigEndian

// The compiled BPF program on big endian processors.
//go:embed bpf/handler-bpfeb.o
var bpfProgram []byte
