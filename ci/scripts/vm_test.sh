#!/bin/bash

# This script creates a VM with the given architecture and an Ubuntu 20.04
# image, sets it up using cloud-init, installs the given kernel, reboots, and
# run tests using a pre-compiled Go test binary.
#
# Only architectures supported by Golang are supported. You can see a full list
# here:
# https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63#goarch-values
#
# Only architectures supported by Ubuntu 20.04 are supported. You can see a full
# list here:
# https://cloud-images.ubuntu.com/focal/current/
#
# Only kernel versions available in Ubuntu's mainline kernel repository are
# supported. You can see a full list here:
# https://kernel.ubuntu.com/~kernel-ppa/mainline/?C=N;O=D
#
# Usage:
# $ vm_test.sh arm64 5.11.8  # uses qemu-system-aarch64
# $ vm_test.sh amd64 5.16.0  # uses qemu-system-x86_64
#
# Depends on:
# - sudo (and sudoer privileges)
# - go
# - curl
# - sha256sum
# - qemu-nbd
# - cloud-image-utils (for cloud-init)
# - qemu for the corresponding arch
# - qemu-efi when arch is arm
# - ssh, scp

set -euo pipefail

# Don't write `set -x` output to stderr, write it to a temp file instead.
xtrace="$(mktemp)"
exec 24>"$xtrace"
BASH_XTRACEFD=24
set -x

cd "$(dirname "$0")"
source ./lib.sh

arch="$1"
kernel="${2%.0}"

kernel_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v$kernel/$arch"
kernel_sum_file="kernel.CHECKSUMS"
kernel_sum_url="$kernel_url/CHECKSUMS"

image_file="focal-server-cloudimg-$arch.img"
image_url="https://cloud-images.ubuntu.com/focal/current/$image_file"
image_sum_file="SHA256SUMS"
image_sum_url="https://cloud-images.ubuntu.com/focal/current/$image_sum_file"

repo_root="$(git rev-parse --show-toplevel)"

# Create test persistence directory. This should only store things that can be
# cached/used across multiple tests.
persistent_dir="$(realpath ../.test)"
mkdir -p "$persistent_dir"

# Create temporary test directory. This should only store files used by the
# single test run.
temp_dir="$(mktemp -d --suffix=.exectrace_test)"
cd "$temp_dir"
echo "Using temporary directory '$temp_dir'"

# Remap the requested architecture to the qemu equivalent.
vm_arch="$arch"
case "$vm_arch" in
  arm64)
    vm_arch="aarch64"
    ;;
  amd64)
    vm_arch="x86_64"
    ;;
esac

# We have to put the image in the persistent dir to avoid filling tmp.
hostname="exectrace-$arch-${kernel//./-}-$RANDOM"
volume_file="$persistent_dir/$hostname.$image_file.qcow2"
pid=""

# Defer cleanup.
cleanup() {
  rc=$?
  if [[ $rc != 0 ]]; then
      echoerr
      echoerr "The test process failed. Please read the above logs for more"
      echoerr "information."
      echoerr
      if [[ "${CI:-}" == "" ]]; then
        echoerr "Additional information can be found in '$xtrace'."
      else
        echo "::group::Bash xtrace (set -x) output:"
        cat "$xtrace"
        echo "::endgroup"
      fi
      echoerr
      echoerr "Exit code was $rc."
      echoerr
  fi

  if [ "$pid" != "" ]; then
    echoerr "+ Cleanup: kill qemu"
    sudo kill -9 "$pid"
  fi
  if [ -e "$volume_file" ]; then
    echoerr "+ Cleanup: delete volume file"
    sudo rm -rf "$volume_file"
  fi

  echoerr "+ Cleanup: delete temp dir"
  sudo rm -rf "$temp_dir"

  exit $rc
}
trap 'cleanup' EXIT

# Compile a test binary for the target architecture.
test_binary="exectrace.test"
pushd "$repo_root"
  GOARCH="$arch" go test -c -o "$temp_dir/$test_binary" ./
popd
if [ ! -e "$test_binary" ]; then
  fatal "The go toolchain did not produce a binary at '$test_binary'"
fi

# Determine the kernel package names to use from the Ubuntu mainline webserver.
echo "+ Determine kernel package names"
download_file "$kernel_sum_url" "$kernel_sum_file"
kernel_image_pkg="$(grep -ioPm 1 "linux-image-(unsigned-)?.*generic.*\\.deb" "$kernel_sum_file")"
kernel_image_pkg_name="$(echo "$kernel_image_pkg" | grep -io "[0-9].*-generic")"
kernel_module_pkg="$(grep -iom 1 "linux-modules.*generic.*" "$kernel_sum_file")"
if [[ "$kernel_image_pkg" == "" ]] || [[ "$kernel_module_pkg" == "" ]]; then
  fatal "Could not determine the kernel image or module packages."
fi
echoerr "Using kernel image package '$kernel_image_pkg' ($kernel_image_pkg_name) and '$kernel_module_pkg'."

# Download the packages so we can cache them.
kernel_image_path="$persistent_dir/$kernel_image_pkg"
download_file_if_exists "$kernel_url/$kernel_image_pkg" "$kernel_image_path"
validate_checksum "$kernel_sum_file" "$kernel_image_path"
kernel_module_path="$persistent_dir/$kernel_module_pkg"
download_file_if_exists "$kernel_url/$kernel_module_pkg" "$kernel_module_path"
validate_checksum "$kernel_sum_file" "$kernel_module_path"

# Download the Ubuntu image file.
image_path="$persistent_dir/$image_file"
download_file "$image_sum_url" "$image_sum_file"
download_file_if_exists "$image_url" "$image_path"
validate_checksum "$image_sum_file" "$image_path"

# Copy the image to make a fresh volume. We expand the image to increase from 2G
# to a usable size.
echo "+ Copying and resizing root volume"
cp "$image_path" "$volume_file"
qemu-img resize "$volume_file" +10G

# Generate an SSH key if one doesn't exist.
ssh_key_path="$persistent_dir/id_ed25519"
if [ ! -e "$ssh_key_path" ]; then
  echo "+ Generating SSH key file"
  ssh-keygen -t ed25519 -f "$ssh_key_path" -C "exectrace+test@coder.com" -q -N ""
fi

# Create cloud-init config.
username="root"
cat <<EOF > cloud_init.cfg
#cloud-config
hostname: "$hostname"
fqdn: "$hostname.exectrace.cdr.dev"
manage_etc_hosts: true
ssh_pwauth: false
users:
  - name: "$username"
    shell: /bin/bash
    ssh-authorized-keys:
      - "$(cat "$ssh_key_path.pub")"

EOF

# Compile cloud-init config into a seed volume.
echo "+ Creating cloud-init seed file"
cloudinit_seed_file="$temp_dir/cloud_init_seed.img"
cloud-localds \
  -v \
  --disk-format raw \
  --filesystem iso9660 \
  "$cloudinit_seed_file" \
  cloud_init.cfg

# Prepare arguments for qemu.
pid_file="./qemu.pid"
host="$username@localhost"
port="2222"
monitor_socket="$temp_dir/qemu.sock"

qemu_args=(
  -nographic
  -device "virtio-net-pci,netdev=net0"
  -netdev "user,id=net0,hostfwd=tcp::$port-:22"
  -m 2048
  -boot "order=c,menu=off"
  -hda "$volume_file"
  -hdb "$cloudinit_seed_file"
  -pidfile "$pid_file"
  -monitor "unix:$monitor_socket,server,nowait"
)
if [[ "$(uname -m)" == "$arch" ]] || [[ "$(uname -m)" == "$vm_arch" ]]; then
  echo "+ Enabling KVM"
  qemu_args+=(
    --enable-kvm
    -cpu host
  )
else
  if [[ "$arch" == *arm* ]]; then
    qemu_args+=(
      -cpu cortex-a57
      -machine virt
    )
  fi
fi

# Arm requires EFI.
if [[ "$arch" == *arm* ]]; then
  echo "+ Enabling EFI (due to arm requirement)"
  dd if=/dev/zero of=flash0.img bs=1M count=64
  dd if=/usr/share/qemu-efi/QEMU_EFI.fd of=flash0.img conv=notrunc
  dd if=/dev/zero of=flash1.img bs=1M count=64
  qemu_args+=(
    -pflash flash0.img
    -pflash flash1.img
  )
fi

# Start qemu in the background with output being redirected to a file.
log_file="$(mktemp --tmpdir tmp.exectrace-qemu.XXXXX.log)"
echoerr "Starting qemu with log file '$log_file'"
echoerr "QEMU monitor will be available at '$monitor_socket'"
nohup sudo "qemu-system-$vm_arch" "${qemu_args[@]}" &>"$log_file" & disown
sleep 5

dump_log() {
  echoerr "$1"
  echoerr "The qemu log file is as follows:"
  echoerr
  cat "$log_file"
  echoerr
  echoerr "$1"
  echoerr "The qemu log file is pritned above"
}

pid="$(sudo cat "$pid_file" || true)"
if [ "$pid" == "" ]; then
  dump_log "qemu pid file was missing or empty"
  exit 1
fi

ensure_qemu_running() {
  if [ ! -e "/proc/$pid/status" ]; then
    dump_log "The VM process no longer exists (most likely a crash)"
    exit 1
  fi
}
ensure_qemu_running

xssh() {
  # The ConnectTimeout is cranked up because it can take a very long time to
  # connect to emulated VMs.
  ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=30 \
    -q \
    -i "$ssh_key_path" \
    -p "$port" \
    "$host" "$@"
}
xscp() {
  scp \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=30 \
    -q \
    -i "$ssh_key_path" \
    -P "$port" \
    "$@"
}

wait_ssh() {
  echoerr "+ Waiting for the VM to start for up to 10 minutes"
  wait_ssh_end="$(date --date 'now + 10 minutes' '+%s')"
  while true; do
    if [[ "$(date '+%s')" > "$wait_ssh_end" ]]; then
      dump_log "The VM did not become available within 10 minutes"
      exit 1
    fi

    ensure_qemu_running
    if xssh exit 0; then
      echoerr "+ Successfully connected"
      break
    fi

    sleep 1
  done
}

# Install the target kernel and reboot.
wait_ssh
xscp "$kernel_image_path" "$kernel_module_path" "$host:~/"
xssh /bin/bash <<EOF
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "+ Install the target kernel and modules"
apt update
apt install -y "./$kernel_image_pkg" "./$kernel_module_pkg"
rm -f "./$kernel_image_pkg" "./$kernel_module_pkg"

# s390x uses zipl to do the boot process. The most recently installed kernel is
# used for booting.
if command -v zipl; then
  echo "+ Detected non-grub bootloader, rebooting"
  reboot
  exit 0
fi

echo "+ Prepare for reboot"
# Taken from https://askubuntu.com/a/1121712
set +e
menu_entries="\$(awk -F\' '\$1=="menuentry " || \$1=="submenu " {print i++ "\t" \$2}; /\tmenuentry / {print i-1">"j++ "\t" \$2};' /boot/grub/grub.cfg)"
menu_entry="\$(echo "\$menu_entries" | grep -iF "$kernel_image_pkg_name" | grep -iv recovery | head -n1 | awk '{ print \$1 }')"
if [[ "\$menu_entry" == "" ]]; then
  echo "Could not determine grub entry for newly installed kernel:"
  echo "\$menu_entries"
  exit 1
fi
echo "Found grub entry \$menu_entry"
set -e
grub-reboot "\$menu_entry"

echo "+ Reboot"
reboot

EOF

# Copy the test binary to the VM.
sleep 30
wait_ssh
xscp "$test_binary" "$host:~/$test_binary"

echoerr "+ Running test suite"
rc=0
xssh /bin/bash <<EOF || rc=$?
set -euxo pipefail

if [[ "\$(uname -r)" != *"$kernel_image_pkg_name"* ]]; then
  echo "Booted into unwanted kernel:"
  uname -a
  exit 1
fi

# shellcheck disable=SC2088 # intentionally don't want ~ to expand by using "
~/"$test_binary" -test.v -test.timeout=10m
EOF

xssh poweroff || true
sleep 15

exit $rc
