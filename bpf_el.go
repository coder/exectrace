//go:build (linux && 386) || (linux && amd64) || (linux && amd64p32) || (linux && arm) || (linux && arm64) || (linux && mips64le) || (linux && mips64p32le) || (linux && mipsle) || (linux && ppc64le) || (linux && riscv64)
// +build linux,386 linux,amd64 linux,amd64p32 linux,arm linux,arm64 linux,mips64le linux,mips64p32le linux,mipsle linux,ppc64le linux,riscv64

package exectrace

import (
	_ "embed"
	"encoding/binary"
)

// The native endian of the processor this program was compiled for.
var NativeEndian = binary.LittleEndian

// The compiled BPF program on little endian processors.
//go:embed bpf/handler-bpfel.o
var bpfProgram []byte
