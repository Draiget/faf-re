# Engine addition (dedicated-server plan WPL.1): the Linux toolchain the
# simulation's cross-platform parity is checked with.
#
# The Linux build (linux-clang-x64.cmake, the linux-clang-x64-release preset)
# compiles the simulation for the headless server. Its results must equal the
# Windows builds' bit for bit, so the compiler and C++ library that produce
# them are pinned here, as docker/deps.lock.json pins the Windows dependency
# baselines. linux-clang-x64.cmake refuses to configure with another clang
# release unless FAF_LINUX_ALLOW_UNPINNED_TOOLCHAIN is ON (for trying a new
# compiler; such a build is not a parity build).
#
# Reference machine (2026-10-25): Ubuntu 24.04.5 LTS (WSL2, kernel
# 5.10.16.3-microsoft-standard-WSL2), packages from the Ubuntu archive:
#
#   clang-18           1:18.1.3-1ubuntu1    Ubuntu clang version 18.1.3 (1ubuntu1)
#   lld-18             1:18.1.3-1ubuntu1    Ubuntu LLD 18.1.3
#   libc++-18-dev      1:18.1.3-1ubuntu1    libc++.a (linked statically, plan D9)
#   libc++abi-18-dev   1:18.1.3-1ubuntu1    libc++abi.a
#   libunwind-18-dev   1:18.1.3-1ubuntu1
#   libc6-dev          2.39-0ubuntu8.9      glibc 2.39
#   cmake              3.28.3-1build7
#   ninja-build        1.11.1-2
#   python3            3.12.3-0ubuntu2.1
#   binutils           (ar, ranlib, nm; the LLVM packages above have no llvm-ar)
#
# Not installed: libclang-rt-18-dev (sanitizer runtimes), llvm-18 (llvm-ar,
# llvm-nm, llvm-symbolizer).
#
# A container image built from these pins is plan WP1.6.

set(FAF_LINUX_PINNED_CLANG_VERSION "18.1.3")
set(FAF_LINUX_PINNED_CLANG_PACKAGE "1:18.1.3-1ubuntu1")
set(FAF_LINUX_PINNED_LIBCXX_PACKAGE "1:18.1.3-1ubuntu1")
set(FAF_LINUX_PINNED_GLIBC_VERSION "2.39")
set(FAF_LINUX_PINNED_LLVM_ROOT "/usr/lib/llvm-18")
