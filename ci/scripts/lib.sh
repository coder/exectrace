#!/bin/bash

# This file contains bash helper functions intended for use by other script
# files in this directory.

set -euxo pipefail

echoerr() {
  echo "$@" >&2
}

fatal() {
  echoerr "$@"
  exit 1
}

download_file() {
  url="$1"
  dest="$2"
  temp_dest="$dest.tmp$RANDOM"

  echoerr "+ Downloading $dest"
  rc=0
  curl --fail --location "$url" --output "$temp_dest" || rc=$?
  if [[ $rc != 0 ]]; then
    rm -rf "$temp_dest"
    echoerr "Failed to download file using curl"
    exit $rc
  fi
  mv "$temp_dest" "$dest"
}

download_file_if_exists() {
  url="$1"
  dest="$2"
  if [ ! -e "$dest" ]; then
    download_file "$url" "$dest"
  fi
}

validate_checksum() {
  checksum_file="$(realpath "$1")"
  target_dir="$(dirname "$2")"
  target_file="$(basename "$2")"

  echoerr "+ Validating SHA256 checksum of $target_file"
  pushd "$target_dir"
    rc=0
    grep "$target_file" "$checksum_file" | sha256sum --check || rc=$?
    if [[ $rc != 0 ]]; then
      echoerr "Could not validate SHA256 sum of file '$target_file'"
      rm -rf "$2"
      exit $rc
    fi
  popd
}
