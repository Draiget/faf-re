# Engine addition (dedicated-server plan WPL.2): Linux x86_64 with clang,
# libc++ and lld, for the headless simulation (faf_sim, faf-replay, later
# faf-server). Used by the linux-clang-x64-release preset.
#
#   cmake --preset linux-clang-x64-release && cmake --build --preset linux-clang-x64-release
#
# The top-level CMakeLists.txt sees FAF_LINUX and builds the Linux project
# (cmake/FafLinux.cmake) instead of the Windows one.
#
#   FAF_LINUX_LLVM_ROOT               LLVM install with clang, clang++ and
#                                     ld.lld. Default: the pinned one
#                                     (linux-clang-pins.cmake).
#   FAF_LINUX_ALLOW_UNPINNED_TOOLCHAIN  ON: accept a clang or glibc other than
#                                     the pinned release (not a parity build).
#
# Code generation (what the simulation's results depend on) is in
# cmake/FafCodegen.cmake, shared with the Windows toolchains. Here: the tools,
# the C++ library (libc++, linked statically: plan D9) and the linker.

include("${CMAKE_CURRENT_LIST_DIR}/linux-clang-pins.cmake")

set(FAF_LINUX ON)

# try_compile projects re-read this file; pass the settings on.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES FAF_LINUX_LLVM_ROOT FAF_LINUX_ALLOW_UNPINNED_TOOLCHAIN)

if(NOT FAF_LINUX_LLVM_ROOT)
  set(FAF_LINUX_LLVM_ROOT "${FAF_LINUX_PINNED_LLVM_ROOT}")
endif()
set(FAF_LINUX_LLVM_ROOT "${FAF_LINUX_LLVM_ROOT}" CACHE PATH "LLVM install root (clang, clang++, ld.lld)")
option(FAF_LINUX_ALLOW_UNPINNED_TOOLCHAIN "Accept a clang or glibc release other than the pinned one" OFF)

if(NOT EXISTS "${FAF_LINUX_LLVM_ROOT}/bin/clang++")
  message(FATAL_ERROR "clang++ not found under FAF_LINUX_LLVM_ROOT=${FAF_LINUX_LLVM_ROOT}")
endif()

# --- Pins ---------------------------------------------------------------------------------
execute_process(COMMAND "${FAF_LINUX_LLVM_ROOT}/bin/clang++" --version
  OUTPUT_VARIABLE _faf_clang_banner OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX MATCH "clang version ([0-9]+\\.[0-9]+\\.[0-9]+)" _faf_clang_match "${_faf_clang_banner}")
set(_faf_clang_version "${CMAKE_MATCH_1}")
execute_process(COMMAND getconf GNU_LIBC_VERSION
  OUTPUT_VARIABLE _faf_glibc_banner OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX REPLACE "^glibc " "" _faf_glibc_version "${_faf_glibc_banner}")

set(_faf_pin_problems "")
if(NOT _faf_clang_version STREQUAL FAF_LINUX_PINNED_CLANG_VERSION)
  string(APPEND _faf_pin_problems " clang ${_faf_clang_version} (pinned ${FAF_LINUX_PINNED_CLANG_VERSION});")
endif()
if(NOT _faf_glibc_version STREQUAL FAF_LINUX_PINNED_GLIBC_VERSION)
  string(APPEND _faf_pin_problems " glibc ${_faf_glibc_version} (pinned ${FAF_LINUX_PINNED_GLIBC_VERSION});")
endif()
if(_faf_pin_problems)
  if(FAF_LINUX_ALLOW_UNPINNED_TOOLCHAIN)
    message(WARNING "Unpinned Linux toolchain:${_faf_pin_problems} this is not a parity build.")
  else()
    message(FATAL_ERROR "Linux toolchain differs from cmake/toolchains/linux-clang-pins.cmake:${_faf_pin_problems} "
                        "install the pinned release or set FAF_LINUX_ALLOW_UNPINNED_TOOLCHAIN=ON.")
  endif()
endif()

# --- Tools ----------------------------------------------------------------------------------
set(CMAKE_C_COMPILER   "${FAF_LINUX_LLVM_ROOT}/bin/clang")
set(CMAKE_CXX_COMPILER "${FAF_LINUX_LLVM_ROOT}/bin/clang++")
# ar, ranlib and nm: the system's binutils (the pinned LLVM packages have no
# llvm-ar).

# libc++, linked statically (-static-libstdc++ links libc++.a and libc++abi.a
# with -stdlib=libc++); glibc, libm and libgcc_s stay shared. lld links.
set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++")
foreach(_kind EXE SHARED MODULE)
  set(CMAKE_${_kind}_LINKER_FLAGS_INIT "-fuse-ld=lld -stdlib=libc++ -static-libstdc++ -pthread")
endforeach()

# Release optimises as the Windows builds' /O2 does (CMake's GNU default is -O3).
set(CMAKE_C_FLAGS_RELEASE_INIT "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2 -DNDEBUG")
