#!/bin/bash

# This script runs shellcheck on all `.sh` files in the repository.

set -euo pipefail
cd "$(dirname "$0")"
cd "$(git rev-parse --show-toplevel)"

shopt -s globstar nullglob
shellcheck -e SC1091 ./**/*.sh
