# exectrace [![Go Reference](https://pkg.go.dev/badge/cdr.dev/execsnoop.svg)](https://pkg.go.dev/cdr.dev/execsnoop)

Simple [eBPF](https://ebpf.io/)-based exec snooping on Linux, packaged as a
simple Go library.

exectrace compiles an [eBPF program](./bpf/handler.c) with the specified `clang`
compiler on demand (which is very quick), then loads the program into the kernel
to receive details about the `exec` family of syscalls.

## Installation

exectrace only support Go 1.16 and newer.

```
$ go get -u cdr.dev/exectrace
```

## Quick Start

Things you'll need to get started:

- Root access, `CAP_SYS_ADMIN` or `CAP_BPF`.
  - protip: you can use `go run -exec sudo ./cmd/program` to compile a
    program and start it with `sudo`)
- A `clang` compiler. The eBPF program is compiled on demand.
  - You'll also need to know the executable name of your compiler (e.g.
    `clang-13`) or the absolute path to it.

```
$ go install -u cdr.dev/exectrace/cmd/exectrace
$ exectrace --help
...

$ sudo exectrace --compiler clang-13
2021/12/01 16:42:02 Waiting for events..
[pid=1188921, cgroup.id=2870, comm="node"] /bin/sh -c 'which ps'
[pid=1188922, cgroup.id=2870, comm="sh"] which ps
```

## Usage

You can look at the example program [exectrace](./cmd/exectrace/main.go) for a
comprehensive program using this library.

## Status: In Development

The library is currently under heavy development as we develop it out to suit
the needs of Coder's enterprise [product](https://coder.com).

We plan on changing the API to add more features and fields that can be read
from, and potentially adding easier methods for filtering events rather than
implementing filtering yourself.

## See Also

- [`canonical/etrace`](https://github.com/canonical/etrace) - Go binary that
  uses ptrace and tracks the processes that a command launches for debugging and
  analysis
- [`shirou/gopsutil`](https://github.com/shirou/gopsutil) - Go library that has
  methods for listing process details and getting information about the system

---

Dual licensed under the MIT and GPL-2.0 licenses. See [LICENSE](LICENSE).
