#!/bin/bash

# This script returns 1 and a bunch of log output if there are unstaged files in
# the repository. This is mostly used to make sure there are no changes after
# running fmt or gen steps in CI.

set -euo pipefail
cd "$(dirname "$0")"

FILES="$(git ls-files --other --modified --exclude-standard)"
if [[ "$FILES" != "" ]]; then
  mapfile -t files <<< "$FILES"

  echo "The following files contain unstaged changes:"
  echo
  for file in "${files[@]}"
  do
    echo "  - $file"
  done
  echo

  echo "These are the changes:"
  echo
  for file in "${files[@]}"
  do
    git --no-pager diff "$file"
  done
  exit 1
fi
