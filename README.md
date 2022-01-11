# exectrace [![Go Reference](https://pkg.go.dev/badge/cdr.dev/exectrace.svg)](https://pkg.go.dev/cdr.dev/exectrace)

Simple [eBPF](https://ebpf.io/)-based exec snooping on Linux, packaged as a Go
library.

exectrace loads a precompiled [eBPF program](./bpf/handler.c) into the running
kernel to receive details about the `exec` family of syscalls.

## Installation

exectrace only support Go 1.16+ and Linux kernel 5.8+ (due to use of
`BPF_MAP_TYPE_RINGBUF`).

```
$ go get -u cdr.dev/exectrace
```

## Quick Start

You will need root access, `CAP_SYS_ADMIN` or `CAP_BPF` to run eBPF programs on
your system.

> tip: you can use `go run -exec sudo ./cmd/program` to compile a program and
> start it with `sudo`

```
$ go install -u cdr.dev/exectrace/cmd/exectrace
$ exectrace --help
...

$ sudo exectrace
2021/12/01 16:42:02 Waiting for events..
[1188921, comm="node"] /bin/sh -c 'which ps'
[1188922, comm="sh"] which ps
```

## Usage

You can look at the example program [exectrace](./cmd/exectrace/main.go) for a
comprehensive program using this library.

## Development

Since the eBPF program is packaged as a Go library, the program needs to be
compiled and included in the repo. If you make changes to files under the `bpf`
directory, you should run `make` and include the `.o` files in that directory in
your commit if they changed. CI will ensure that this is done correctly.

You will probably need the following tools:

- Docker (clang is run within a Docker container for reproducibility)
- `golangci-lint`
- `prettier`
- `shellcheck`

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
