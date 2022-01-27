#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")"
cd "$(git rev-parse --show-toplevel)"

export FORCE_COLOR=true
gotestsum \
  --debug \
  --hide-summary=skipped \
  --packages="." \
  -- \
  -v
