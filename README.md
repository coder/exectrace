# exectrace [![Go Reference](https://pkg.go.dev/badge/cdr.dev/exectrace.svg)](https://pkg.go.dev/cdr.dev/exectrace)

Simple [eBPF](https://ebpf.io/)-based exec snooping on Linux packaged as a Go
library.

exectrace loads a pre-compiled [eBPF program](./bpf/handler.c) into the running
kernel to receive details about the `exec` family of syscalls.

## Requirements

exectrace only support Go 1.16+ and Linux kernel 5.8+ (due to the use of
`BPF_MAP_TYPE_RINGBUF`).

## Installation

```console
$ go get -u cdr.dev/exectrace
```

## Quickstart

You will need root access, `CAP_SYS_ADMIN` or `CAP_BPF`, to run eBPF programs on
your system.

> Use `go run -exec sudo ./cmd/program` to compile a program and
> start it with `sudo`

```console
$ go install -u cdr.dev/exectrace/cmd/exectrace
$ exectrace --help
...

$ sudo exectrace
2021/12/01 16:42:02 Waiting for events..
[1188921, comm="node"] /bin/sh -c 'which ps'
[1188922, comm="sh"] which ps
```

## Usage example

For a full usage example, see [exectrace](./cmd/exectrace/main.go), which is a
comprehensive program that uses this library.

## Development

You will need the following:

- Docker (run clang within a Docker container for reproducibility)
- `golangci-lint`
- `prettier`
- `shellcheck`

Since the eBPF program is packaged as a Go library, you need to compile the
program and include it in the repo.

If you change the files in the `bpf` directory, run `make` and ensure that you
include the `.o` files you changed in your commit (CI will verify that you've
done this correctly).

## Status: in development

The library is currently under heavy development as we modify it to suit the
needs of Coder's [enterprise product](https://coder.com).

We plan on adding more features and fields that can be read from the API, as
well as easier-to-use methods for filtering events (currently, you must
implement filtering yourself).

## See also

- [`canonical/etrace`](https://github.com/canonical/etrace) - Go binary that
  uses ptrace and tracks the processes that a command launches for debugging and
  analysis
- [`shirou/gopsutil`](https://github.com/shirou/gopsutil) - Go library that has
  methods for listing process details and getting information about the system

---

Dual licensed under the MIT and GPL-2.0 licenses. See [LICENSE](LICENSE).
