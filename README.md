<h1>
    exectrace
    <span style="float: right;">
        <a href="https://pkg.go.dev/cdr.dev/exectrace"><img src="https://pkg.go.dev/badge/cdr.dev/exectrace.svg" alt="Go Reference"></a>
    </span>
</h1>

Simple [eBPF](https://ebpf.io/)-based exec snooping on Linux, packaged as a
simple Go library.

## Installation

exectrace only support Go 1.16 and newer.

```
$ go get -u cdr.dev/exectrace
```

## Quick Start

Things you'll need to get started:
- Root access (protip: you can use `go run -exec sudo ./cmd/program` to compile
  and start a go program with `sudo`)
- A `clang` compiler. The eBPF program is compiled on demand. You'll also need
  to know the name of your compiler (e.g. `clang-13`) or the full path to it.

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

We plan on changing the API to add more features and fields that can be read
from, and potentially adding easier methods for filtering events rather than
implementing filtering yourself.

----

Dual licensed under the MIT and GPL-2.0 licenses. See [LICENSE](LICENSE).
