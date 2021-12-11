#!/bin/bash

# This script runs the given program with the given arguments in a Docker
# container. The container starts inside the `bpf` directory and runs as the
# same user on the host to avoid permissions problems.
#
# You must call ./clang_image.sh first (Make handles this for you).
#
# Usage: clang.sh clang-13 ... -c in.c -o out.o

set -euo pipefail
cd "$(dirname "$0")"

# Only use the "-t" flag if we're in a TTY. This is useful for development as
# clang outputs colors in a terminal.
terminal_flags="-i"
if [ -t 0 ]; then
    terminal_flags="-it"
fi

docker run \
    "$terminal_flags" \
    --rm \
    --hostname exectrace \
    --name "exectrace_build_$RANDOM" \
    --user "$(id -u):$(id -g)" \
    --volume "$(git rev-parse --show-toplevel):/repo" \
    --workdir "/repo/bpf" \
    exectrace-clang-13 \
    "$@"
