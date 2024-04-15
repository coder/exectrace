#!/bin/bash

# Runs go benchmarks in a new PID namespace. Depends on `go` and `unshare`.
#
# Usage: COUNT=10000 ./bench.sh
# Runs `go test -bench=. -run="^#" -count 1 -benchtime "${COUNT:-1000}x"` ./
#
# Usage: ./bench.sh -bench=... ...
# Runs `go test "$@"`. COUNT is ignored.

set -euo pipefail

cd "$(dirname "$0")"

args=("$@")
if [[ "${#args[@]}" -eq 0 ]]; then
    args=('-bench=.' '-run="^#"' '-count=1' "-benchtime=${COUNT:-1000}x" ./)
fi

# Start the go test process in a new PID namespace and exec with sudo.
uid=$(id -u)
gid=$(id -g)
go_binary=$(command -v go)
set -x
exec sudo -E unshare --pid --fork --setuid "$uid" --setgid "$gid" -- "$go_binary" test -exec sudo "${args[@]}"
