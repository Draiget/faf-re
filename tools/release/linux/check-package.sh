#!/usr/bin/env bash
# Checks that the Linux download loads on the distributions it is for, each in its plain container
# image (issue #394): the oldest it supports (glibc 2.34 to 2.36) and current releases and rolling
# distributions. Needs Docker; the nightly runs it on the runner after the Linux build.
#
#   tools/release/linux/check-package.sh <faf-engine-*-linux-x64.tar.gz> [image...]
#
# In each image `ldd -r` must resolve every library and symbol of ForgedAlliance and of the DXC
# libraries (a weak version glibc lacks is fine: libfaf-glibc-compat.so has those functions), and
# faf-launch must run. Libraries the engine opens only while it runs (Vulkan, X11 or Wayland, audio)
# are not checked: those come from the desktop.
set -euo pipefail

tarball="$1"
shift
images=("$@")
if [ ${#images[@]} -eq 0 ]; then
  # Oldest supported: Ubuntu 22.04 (glibc 2.35; Mint 21), Debian 12 (2.36), AlmaLinux 9 (2.34, RHEL 9).
  # Current: Ubuntu 24.04, Fedora, Arch (also SteamOS 3's base), openSUSE Tumbleweed.
  images=(ubuntu:22.04 debian:12 almalinux:9 ubuntu:24.04 fedora:latest archlinux:latest opensuse/tumbleweed:latest)
fi
[ -f "$tarball" ] || { echo "check-package: no such file: $tarball" >&2; exit 2; }

# Unpacked here, as not every image has tar.
unpack="$(mktemp -d)"
trap 'rm -rf "$unpack"' EXIT
tar -xzf "$tarball" -C "$unpack"
chmod 0755 "$unpack"

failed=0
for image in "${images[@]}"; do
  echo "--- $image"
  # MSYS (Git Bash) would rewrite the container paths into Windows ones.
  if ! MSYS_NO_PATHCONV=1 docker run --rm -v "$unpack:/pkg:ro" "$image" sh -c '
      set -e
      dir=/pkg
      [ -x "$dir/ForgedAlliance" ] || { echo "ForgedAlliance missing or not executable"; exit 1; }
      ldd --version 2>&1 | head -n 1
      for f in "$dir/ForgedAlliance" "$dir/libdxil.so" "$dir/libdxcompiler.so"; do
        problems=$(ldd -r "$f" 2>&1 | grep -v "weak version" | grep -E "not found|undefined symbol" || true)
        if [ -n "$problems" ]; then
          echo "$problems"
          exit 1
        fi
        echo "$(basename "$f"): every library and symbol resolves"
      done
      "$dir/faf-launch" --help > /dev/null
      echo "faf-launch: runs"'; then
    echo "check-package: FAILED on $image" >&2
    failed=1
  fi
done
exit "$failed"
