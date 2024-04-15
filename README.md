# exectrace [![Go Reference](https://pkg.go.dev/badge/github.com/coder/exectrace.svg)](https://pkg.go.dev/github.com/coder/exectrace)

Simple [eBPF](https://ebpf.io/)-based exec snooping on Linux packaged as a Go
library.

exectrace loads a pre-compiled [eBPF program](./bpf/handler.c) into the running
kernel to receive details about the `exec` family of syscalls.

## Coder

exectrace provides workspace process logging for Coder v1 and
[Coder v2](https://github.com/coder/coder) (aka. Coder OSS).

Documentation for how to setup workspace process logging for Coder v1 users can
be found
[here](https://coder.com/docs/v1/v1.38/admin/workspace-management/process-logging).

Documentation for Coder v2 users can be found in
[enterprise/README.md](enterprise/README.md).

## Requirements

exectrace only supports Go 1.16+ and Linux kernel 5.8+ (due to the use of
`BPF_MAP_TYPE_RINGBUF`). Additionally, the kernel config
`CONFIG_DEBUG_INFO_BTF=y` is required.

To validate this config is enabled, run either of the following commands
directly on the system:

```console
$ cat /proc/config.gz | gunzip | grep CONFIG_DEBUG_INFO_BTF
```

```console
$ cat "/boot/config-$(uname -r)" | grep CONFIG_DEBUG_INFO_BTF
```

## Installation

```console
$ go get -u github.com/coder/exectrace
```

## Quickstart

You will need root access, `CAP_SYS_ADMIN` or `CAP_BPF`, to run eBPF programs on
your system.

> Use `go run -exec sudo ./cmd/program` to compile a program and start it with
> `sudo`

```console
$ go install -u github.com/coder/exectrace/cmd/exectrace
$ exectrace --help
...

$ sudo exectrace
2021/12/01 16:42:02 Waiting for events..
[1188921, comm="node", uid=1002, gid=1003, filename=/bin/sh] /bin/sh -c 'which ps'
[1188922, comm="sh", uid=1002, gid=1003, filename=/usr/bin/which] which ps
```

## Usage

exectrace exposes a minimal API surface. Call `exectrace.New(nil)` and then you
can start reading events from the returned `Tracer`.

It is important that you close the tracer to avoid leaking kernel resources, so
we recommend implementing a simple signal handler like the one in this example:

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

> For a full usage example, refer to this
> [comprehensive program](./cmd/exectrace/main.go) that uses the library.

## Development

You will need the following:

- Docker (the Makefile runs clang within a Docker container for reproducibility)
- Golang 1.20+
- `golangci-lint`
- `prettier`
- `shellcheck`

Since the eBPF program is packaged using `go:embed`, you will need to compile
the program and include it in the repo.

If you change the files in the `bpf` directory, run `make` and ensure that you
include the `.o` files you changed in your commit (CI will verify that you've
done this correctly).

## Status: stable

This library is ready to use as-is. It has been used in production for years and
has received minimal maintenance over that time period.

In April 2024, a system to send logs from the kernel to userspace was added
which can make discovering potential issues in production/development much
easier.

The API will likely not be further modified as we have no need for additional
fields/features. We will continue to maintain the library as needed.

## See also

- [`canonical/etrace`](https://github.com/canonical/etrace) - Go binary that
  uses ptrace and tracks the processes that a command launches for debugging and
  analysis
- [`shirou/gopsutil`](https://github.com/shirou/gopsutil) - Go library that has
  methods for listing process details and getting information about the system

---

Dual licensed under the MIT and GPL 2.0 licenses. See [LICENSE](LICENSE).

Code in the enterprise directory has a different license. See
[LICENSE.enterprise](LICENSE.enterprise).
