#!/bin/bash

# This script builds the clang builder image used by clang.sh

set -euo pipefail
cd "$(dirname "$0")/../images/clang-13"

docker build -t exectrace-clang-13 .
