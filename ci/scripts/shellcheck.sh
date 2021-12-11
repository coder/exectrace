#!/bin/bash

# This script runs shellcheck on all `.sh` files in the repository.

set -euo pipefail
cd "$(dirname "$0")"
cd "$(git rev-parse --show-toplevel)"

fail=0
shopt -s globstar nullglob
for file in ./**/*.sh; do
    echo "Linting $file"
    shellcheck "$file" || fail=1
done

if [[ $fail == 1 ]]; then
    echo "Some files failed to lint, look above for details"
    exit 1
fi
