# exectrace [![Go Reference](https://pkg.go.dev/badge/github.com/coder/exectrace.svg)](https://pkg.go.dev/github.com/coder/exectrace)

Simple [eBPF](https://ebpf.io/)-based exec snooping on Linux packaged as a Go
library.

exectrace loads a pre-compiled [eBPF program](./bpf/handler.c) into the running
kernel to receive details about the `exec` family of syscalls.

## Requirements

exectrace only supports Go 1.16+ and Linux kernel 5.8+ (due to the use of
`BPF_MAP_TYPE_RINGBUF`).

## Installation

```console
$ go get -u github.com/coder/exectrace
```

## Quickstart

You will need root access, `CAP_SYS_ADMIN` or `CAP_BPF`, to run eBPF programs on
your system.

> Use `go run -exec sudo ./cmd/program` to compile a program and
> start it with `sudo`

```console
$ go install -u github.com/coder/exectrace/cmd/exectrace
$ exectrace --help
...

$ sudo exectrace
2021/12/01 16:42:02 Waiting for events..
[1188921, comm="node", uid=1002, gid=1003] /bin/sh -c 'which ps'
[1188922, comm="sh", uid=1002, gid=1003] which ps
```

## Usage

exectrace exposes a minimal API surface. Call `exectrace.New(nil)` and then
you can start reading events from the returned `Tracer`.

It is important that you close the tracer to avoid leaking kernel resources,
so we recommend implementing a simple signal handler like the one in this
example:

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/coder/exectrace"
)

func main() {
	tracer, err := exectrace.New(nil)
	if err != nil {
		panic(err)
	}
	defer tracer.Close()

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs
		tracer.Close()
	}()

	for {
		event, err := tracer.Read()
		if err != nil {
			panic(err)
		}

		fmt.Printf("%+v\n", event)
	}
}
```

> For a full usage example, refer to this [comprehensive program](./cmd/exectrace/main.go)
> that uses the library.

## Development

You will need the following:

- Docker (the Makefile runs clang within a Docker container for reproducibility)
- `golangci-lint`
- `prettier`
- `shellcheck`

Since the eBPF program is packaged as a Go library, you need to compile the
program and include it in the repo.

If you change the files in the `bpf` directory, run `make` and ensure that you
include the `.o` files you changed in your commit (CI will verify that you've
done this correctly).

## Status: beta

This library is ready to use as-is, though it is under active development as we
modify it to suit the needs of Coder's [enterprise product](https://coder.com).

We plan on adding more features and fields that can be read from the API, as
well as easier-to-use methods for filtering events (currently, you must
implement additional filtering yourself).

## See also

- [`canonical/etrace`](https://github.com/canonical/etrace) - Go binary that
  uses ptrace and tracks the processes that a command launches for debugging and
  analysis
- [`shirou/gopsutil`](https://github.com/shirou/gopsutil) - Go library that has
  methods for listing process details and getting information about the system

---

Dual licensed under the MIT and GPL 2.0 licenses. See [LICENSE](LICENSE).
