#!/bin/bash

# This file updates the libbpf header files in this directory.

cd "$(dirname "$0")"
set -euo pipefail

# Version of libbpf to fetch headers from.
LIBBPF_VERSION="${LIBBPF_VERSION:-0.4.0}"

# The headers we want to download from the repo. These files are found in the
# src/ directory in the repo.
header_files=(
    "bpf_helper_defs.h"
    "bpf_helpers.h"
)

for f in "${header_files[@]}"; do
    # Attach the license header and source URL.
    cat <<EOF > "$f"
// This file is taken from libbpf v$LIBBPF_VERSION.
// https://github.com/libbpf/libbpf/blob/v$LIBBPF_VERSION/src/$f
//
// Licensed under LGPL 2.1 or the BSD 2 Clause.

EOF

    echo "+ Downloading $f" >&2
    curl -sSL "https://raw.githubusercontent.com/libbpf/libbpf/v$LIBBPF_VERSION/src/$f" >> "$f"

    # Remove extra trailing newlines.
    sed -i -e :a -e '/^\n*$/{$d;N;};/\n$/ba' "$f"
done
