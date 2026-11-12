#!/bin/bash
# Installs the pinned Linux toolchain (cmake/toolchains/linux-clang-pins.cmake) on Ubuntu 22.04: clang,
# lld, libc++ and the profile and sanitizer runtimes of LLVM 18.1.8 from apt.llvm.org, CMake 3.28.3 and
# Ninja. Every Linux build uses it: the CI jobs (in an ubuntu:22.04 container), tools/linux/Dockerfile
# and anyone building by hand.
#
#   tools/linux/toolchain.sh            the toolchain
#   tools/linux/toolchain.sh --client   plus the headers SDL3 builds its X11, Wayland and audio
#                                       backends against (FAF_LINUX_CLIENT) and the packaging tools
#
# Why 22.04: a program asks the C library (glibc) for the versions of its functions that the build
# machine's headers name, and runs only where glibc is at least that new. Built here the engine needs
# glibc 2.34 (Ubuntu 22.04, Debian 12, Mint 21, RHEL 9 and every newer release, issue #394); built on
# 24.04 it needed 2.38. Ubuntu 22.04's own archive stops at clang 15, so LLVM comes from LLVM's archive,
# pinned to its one 18.1.8 build; the archive key's fingerprint is checked before it is trusted.
set -euo pipefail

LLVM_VERSION="1:18.1.8~++20240731024944+3b5b5c1ec4a3-1~exp1~20240731145000.144"
LLVM_ARCHIVE_FPR=6084F3CF814B57C1CF12EFD515CF4D18AF4F7421
CMAKE_VERSION=3.28.3
CMAKE_SHA256=804d231460ab3c8b556a42d2660af4ac7a0e21c98a7f8ee3318a74b4a9a187a6

client=0
for arg in "$@"; do
  case "$arg" in
    --client) client=1 ;;
    *) echo "toolchain.sh: unknown option $arg" >&2; exit 2 ;;
  esac
done

. /etc/os-release
if [ "$ID" != ubuntu ] || [ "$VERSION_ID" != 22.04 ]; then
  echo "toolchain.sh: this is $PRETTY_NAME; the pinned toolchain is built on Ubuntu 22.04" >&2
  exit 1
fi
sudo=""
[ "$(id -u)" = 0 ] || sudo=sudo
export DEBIAN_FRONTEND=noninteractive

$sudo apt-get update
$sudo apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg git make ninja-build python3 binutils file xz-utils

curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key -o /tmp/llvm.asc
if ! gpg --batch --with-colons --show-keys --with-fingerprint /tmp/llvm.asc | grep -q "^fpr:::::::::${LLVM_ARCHIVE_FPR}:"; then
  echo "toolchain.sh: apt.llvm.org's key is not the expected one (${LLVM_ARCHIVE_FPR})" >&2
  exit 1
fi
gpg --batch --yes --dearmor -o /tmp/apt-llvm.gpg /tmp/llvm.asc
$sudo install -m 0644 /tmp/apt-llvm.gpg /usr/share/keyrings/apt-llvm.gpg
echo "deb [signed-by=/usr/share/keyrings/apt-llvm.gpg] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main" \
  | $sudo tee /etc/apt/sources.list.d/llvm-18.list > /dev/null
$sudo apt-get update
v="$LLVM_VERSION"
$sudo apt-get install -y --no-install-recommends \
  "clang-18=$v" "lld-18=$v" "llvm-18=$v" "libclang-rt-18-dev=$v" \
  "libc++-18-dev=$v" "libc++abi-18-dev=$v" "libunwind-18-dev=$v" \
  "libclang-common-18-dev=$v" "libclang-cpp18=$v" "libllvm18=$v" \
  "libc++1-18=$v" "libc++abi1-18=$v" "libunwind-18=$v"

if ! cmake --version 2>/dev/null | grep -q "version $CMAKE_VERSION\$"; then
  curl -fsSL -o /tmp/cmake.tar.gz \
    "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz"
  echo "${CMAKE_SHA256}  /tmp/cmake.tar.gz" | sha256sum -c -
  $sudo tar -xzf /tmp/cmake.tar.gz -C /opt
  for tool in cmake ctest cpack; do
    $sudo ln -sf "/opt/cmake-${CMAKE_VERSION}-linux-x86_64/bin/$tool" "/usr/local/bin/$tool"
  done
fi

if [ "$client" = 1 ]; then
  $sudo apt-get install -y --no-install-recommends \
    pkg-config patchelf libx11-dev libxext-dev libxrandr-dev libxcursor-dev libxi-dev libxss-dev libxfixes-dev \
    libxtst-dev libxkbcommon-dev libwayland-dev wayland-protocols libdecor-0-dev libegl-dev libgl-dev \
    libdrm-dev libgbm-dev libasound2-dev libpulse-dev libpipewire-0.3-dev libdbus-1-dev libudev-dev
fi

/usr/lib/llvm-18/bin/clang --version | head -n 1
getconf GNU_LIBC_VERSION
cmake --version | head -n 1
