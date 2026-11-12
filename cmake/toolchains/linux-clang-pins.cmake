# Engine addition (dedicated-server plan WPL.1): the Linux toolchain the
# simulation's cross-platform parity is checked with.
#
# The Linux build (linux-clang-x64.cmake, the linux-clang-x64-release preset)
# compiles the simulation for the headless server and the client. Its results
# must equal the Windows builds' bit for bit, so the compiler and C++ library
# that produce them are pinned here, as docker/deps.lock.json pins the Windows
# dependency baselines. linux-clang-x64.cmake refuses to configure with another
# clang or glibc release unless FAF_LINUX_ALLOW_UNPINNED_TOOLCHAIN is ON (for
# trying a new compiler; such a build is not a parity build).
#
# One toolchain for every Linux build (the server, the parity and sanitizer
# runs, the downloadable client), installed by tools/linux/toolchain.sh and
# tools/linux/Dockerfile. Ubuntu 22.04, so the programs need glibc 2.34
# (Ubuntu 22.04, Debian 12, Mint 21, RHEL 9 and newer; issue #394):
#
#   ubuntu:22.04       glibc 2.35 (libc6-dev 2.35-0ubuntu3.x)
#   clang-18, lld-18, llvm-18, libclang-rt-18-dev, libc++-18-dev,
#   libc++abi-18-dev, libunwind-18-dev
#                      1:18.1.8~++20240731024944+3b5b5c1ec4a3-1~exp1~20240731145000.144
#                      (apt.llvm.org, llvm-toolchain-jammy-18), "Ubuntu clang
#                      version 18.1.8"; libc++ and libc++abi linked statically
#                      (plan D9); llvm-ar and llvm-ranlib for the profile-guided
#                      preset (cmake/FafLinux.cmake); the profile runtime for
#                      tools/pgo/record.sh, the sanitizer runtime for the
#                      linux-clang-x64-asan preset
#   cmake              3.28.3 (Kitware's release; 22.04 has 3.22)
#   ninja-build        1.10.1, python3 3.10, binutils, make (FFmpeg's build)
#
# Until 2026-11-12 the pins were Ubuntu 24.04's clang 18.1.3-1ubuntu1 and
# glibc 2.39.

set(FAF_LINUX_PINNED_CLANG_VERSION "18.1.8")
set(FAF_LINUX_PINNED_CLANG_PACKAGE "1:18.1.8~++20240731024944+3b5b5c1ec4a3-1~exp1~20240731145000.144")
set(FAF_LINUX_PINNED_LIBCXX_PACKAGE "1:18.1.8~++20240731024944+3b5b5c1ec4a3-1~exp1~20240731145000.144")
set(FAF_LINUX_PINNED_GLIBC_VERSION "2.35")
set(FAF_LINUX_PINNED_LLVM_ROOT "/usr/lib/llvm-18")
