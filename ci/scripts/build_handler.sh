#!/bin/bash

# This script builds the given eBPF handler binary in a Docker container. The
# output file is put into the `bpf` directory.
#
# Usage: build_handler.sh handler-bpfel.o

set -euo pipefail
cd "$(dirname "$0")"

output="$(basename "$1")"
target="${output#handler-}"
target="${target%.o}"

if [[ "$target" != "bpfeb" ]] && [[ "$target" != "bpfel" ]]; then
    echo "Sniffed build target '$target' from input '$output' is invalid"
    exit 1
fi

# Run clang with the following options:
# -O2:
#   Optimize the code so the BTF verifier can understand it properly.
# -mcpu=v1:
#   Clang defaults to mcpu=probe which checks the kernel that we are
#   compiling on. This isn't appropriate for ahead of time compiled code so
#   force the most compatible version.
# -g:
#   We always want BTF to be generated, so enforce debug symbols.
# -Wall -Wextra -Werror:
#   Enable lots of warnings, and treat all warnings as fatal build errors.
# -fno-ident:
#   Don't include the clang version.
# -fdebug-compilation-dir .:
#   Don't output the current directory into debug info.
# -target
#   This is set to bpfeb or bpfel based on the build target.
./clang.sh clang-13 \
	-O2 \
	-mcpu=v1 \
	-g \
	-Wall -Wextra -Werror \
	-fno-ident \
	-fdebug-compilation-dir . \
	-target "$target" \
	-c ./handler.c \
	-o "$output"
