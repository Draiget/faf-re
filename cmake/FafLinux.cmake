# Engine addition (dedicated-server plan, Phase D): the Linux build.
#
# Included by the top-level CMakeLists.txt, in place of the Windows project,
# when the toolchain is cmake/toolchains/linux-clang-x64.cmake. Linux builds
# the headless simulation only (plan D2, G6): no window, render device, audio,
# movie, wx or Win32 code.
#
#   cmake --preset linux-clang-x64-release && cmake --build --preset linux-clang-x64-release

if(NOT FAF_LINUX)
  message(FATAL_ERROR "cmake/FafLinux.cmake needs cmake/toolchains/linux-clang-x64.cmake.")
endif()
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
  message(FATAL_ERROR "The Linux build expects clang with the GNU driver: use the linux-clang-x64-release preset.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "The Linux build is x86_64 only.")
endif()
set(FAF_TARGET_ARCH x64)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")

# --- Build-wide settings ------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Release optimises as the Windows builds' /O2 does: CMake appends its GNU
# default (-O3 -DNDEBUG) after the toolchain's -O2, so the later -O3 would win.
foreach(_lang C CXX ASM)
  string(REPLACE "-O3" "-O2" CMAKE_${_lang}_FLAGS_RELEASE "${CMAKE_${_lang}_FLAGS_RELEASE}")
  string(REPLACE "-O2 -DNDEBUG -O2 -DNDEBUG" "-O2 -DNDEBUG" CMAKE_${_lang}_FLAGS_RELEASE "${CMAKE_${_lang}_FLAGS_RELEASE}")
endforeach()

# --- Locations ------------------------------------------------------------------------
set(FAF_DEPENDENCIES_DIR "${PROJECT_SOURCE_DIR}/dependencies" CACHE PATH
    "Third-party tree (dependencies/ in the repository)")

include(FafCodegen)

# --- Toolchain check ------------------------------------------------------------------
# tests/linux/ToolchainCheck.cpp: data model, char signedness, no FMA
# contraction, exceptions through extern "C", threads, default x87 and SSE
# control words. Run it after a toolchain change; `ldd` on it shows the C++
# library is linked statically.
add_executable(faf-linux-toolchain-check "${PROJECT_SOURCE_DIR}/tests/linux/ToolchainCheck.cpp")
target_link_libraries(faf-linux-toolchain-check PRIVATE faf_codegen)

# --- Language dialect ---------------------------------------------------------------------
# clang-cl compiles the Windows build with -fms-extensions -fms-compatibility
# -fms-compatibility-version=19.33 -fms-volatile, also under /permissive-
# (`clang-cl -### /permissive-`). Linux takes the Microsoft keywords and
# intrinsics (-fms-extensions) and volatile semantics (-fms-volatile), not
# -fms-compatibility: without a Windows target it stops defining __GNUC__,
# __STDC__, __EXCEPTIONS and __GXX_RTTI, which glibc, libc++ and boost read.
# Code that relies on Microsoft lookup rules (unqualified names from dependent
# bases) is fixed in the source instead. clang defines no _MSC_VER or _WIN32
# here, so platform code takes its POSIX branches.
set(FAF_LINUX_MS_DIALECT -fms-extensions -fms-volatile)

# --- Dependencies -----------------------------------------------------------------------
# Wild Magic Foundation (the sim's math) and zlib 1.2.3, with the Windows
# builds' source lists.
add_subdirectory("${PROJECT_SOURCE_DIR}/cmake/deps/wildmagic" "${CMAKE_BINARY_DIR}/deps/wildmagic")
add_subdirectory("${PROJECT_SOURCE_DIR}/cmake/deps/zlib" "${CMAKE_BINARY_DIR}/deps/zlib")

# --- faf_sim ----------------------------------------------------------------------------
# The simulation's translation units (src/sim_sources.cmake), in the engine's
# order, as an object library: every object is linked, so every static
# initialiser runs, as in the Windows executable.
include("${PROJECT_SOURCE_DIR}/src/sources.cmake")
include("${PROJECT_SOURCE_DIR}/src/sim_sources.cmake")

# boost.thread 1.34.1 on pthreads: the Win32 TLS hooks are left out.
list(FILTER FAF_SIM_SOURCES EXCLUDE REGEX "/libs/thread/src/tss_(dll|hooks|pe)\\.cpp$")
# The Windows platform services (call stacks, crash-report paths, message
# boxes); the POSIX implementation of the same functions is plan WPL.5.
list(FILTER FAF_SIM_SOURCES EXCLUDE REGEX "^moho/misc/WinPlatform\\.cpp$")

set(_faf_sim_files "")
foreach(_src IN LISTS FAF_SIM_SOURCES)
  if(IS_ABSOLUTE "${_src}")
    list(APPEND _faf_sim_files "${_src}")
  else()
    list(APPEND _faf_sim_files "${PROJECT_SOURCE_DIR}/src/${_src}")
  endif()
endforeach()
list(LENGTH _faf_sim_files _faf_sim_count)
message(STATUS "faf_sim: ${_faf_sim_count} translation units")

file(WRITE "${CMAKE_BINARY_DIR}/win32-alias/windows.h" "#pragma once\n#include <Windows.h>\n")

add_library(faf_sim OBJECT ${_faf_sim_files})
# Its compile and link settings, which targets built from a few sim sources
# (tests/sim_math) share without depending on every faf_sim object.
add_library(faf_sim_settings INTERFACE)
target_link_libraries(faf_sim PUBLIC faf_sim_settings)

# The x64 half of legacy/math/X87Math.cpp, in GNU syntax for System V (the
# Windows build assembles X87Math64.asm, plan WPL.10).
enable_language(ASM)
target_sources(faf_sim PRIVATE "${PROJECT_SOURCE_DIR}/src/legacy/math/X87Math64.S")
# gpg::gal::Math without D3DX (Windows' faf_main uses gpg/gal/Matrix.cpp, plan WPR.12).
target_sources(faf_sim PRIVATE "${PROJECT_SOURCE_DIR}/src/gpg/gal/MatrixPortable.cpp")
# The Win32 calls the shared code makes, on POSIX (plan WPL.5).
target_sources(faf_sim PRIVATE "${PROJECT_SOURCE_DIR}/src/platform/posix/Win32Shim.cpp")

# The Windows build's engine definitions without the Win32 ones (WIN32,
# _WINDOWS, WIN32_LEAN_AND_MEAN, NOMINMAX, UNICODE, _CRT_*).
target_compile_definitions(faf_sim_settings INTERFACE
  LUAPLUS_LIB LUA_NUMBER=float
  BOOST_ALL_NO_LIB BOOST_NO_AUTO_PTR)
target_include_directories(faf_sim_settings INTERFACE
  "${PROJECT_SOURCE_DIR}/src"
  # <Windows.h> and <intrin.h> for the shared code (plan WPL.5), and <windows.h>, the
  # spelling some files use (the file system is case-sensitive here).
  "${PROJECT_SOURCE_DIR}/src/platform/posix/win32"
  "${CMAKE_BINARY_DIR}/win32-alias"
  "${FAF_DEPENDENCIES_DIR}/boost_1_34_1"
  "${FAF_DEPENDENCIES_DIR}/zlib-1.2.3")
target_link_libraries(faf_sim_settings INTERFACE faf_codegen)
target_link_libraries(faf_sim PUBLIC Wm3Foundation zlib123)

set(_faf_sim_options
  # The recovered tree's x86 layout asserts, off as on Windows x64 (see the
  # header).
  "SHELL:-include platform/X64LayoutAsserts.h"
  # The Windows names the shared code uses (plan WPL.5).
  "SHELL:-include platform/PosixCompat.h"
  ${FAF_LINUX_MS_DIALECT}
  # boost.thread checks for the compiler's threading mode (_REENTRANT).
  -pthread
  # The Windows build's diagnostics settings (src/CMakeLists.txt).
  -Wno-microsoft
  -Wno-unused-parameter -Wno-unused-variable -Wno-unused-private-field
  -Wno-unused-function -Wno-unused-local-typedef -Wno-unused-but-set-variable
  -Wno-unused-lambda-capture -Wno-unused-value -Wno-unused-command-line-argument
  -Wno-missing-field-initializers -Wno-sign-compare -Wno-switch
  -Wno-invalid-offsetof -Wno-keyword-macro -Wno-unknown-pragmas
  -Wno-ignored-pragma-intrinsic -Wno-pragma-pack -Wno-ignored-attributes
  -Wno-deprecated-declarations -Wno-deprecated-enum-enum-conversion
  -Wno-nonportable-include-path -Wno-reorder-ctor
  -Wno-delete-non-abstract-non-virtual-dtor -Wno-overloaded-virtual
  -Wno-inconsistent-missing-override -Wno-missing-braces -Wno-braced-scalar-init
  -Wno-char-subscripts -Wno-parentheses -Wno-dangling-else
  -Wno-tautological-constant-out-of-range-compare
  -Wno-tautological-undefined-compare -Wno-undefined-var-template
  -Wno-writable-strings -Wno-comment -Wno-extra-tokens -Wno-nontrivial-memcall
  -Wno-mismatched-tags -Wno-extra-qualification
  # Options clang 18 does not know yet (the Windows build uses a newer clang).
  -Wno-unknown-warning-option)
target_compile_options(faf_sim_settings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:${_faf_sim_options}>")

# boost.thread's own sources, as on Windows (src/CMakeLists.txt).
foreach(_src IN LISTS _faf_sim_files)
  if(_src MATCHES "/libs/thread/src/")
    set_property(SOURCE "${_src}" APPEND PROPERTY COMPILE_DEFINITIONS BOOST_THREAD_BUILD_LIB=1)
    set_property(SOURCE "${_src}" APPEND PROPERTY COMPILE_OPTIONS -w)
  endif()
endforeach()

# --- faf_sim_math_tests (plan WPL.23) ---------------------------------------------------
# The golden sim-math tests (tests/sim_math), compiled with faf_sim's settings.
# Until every faf_sim object compiles and links, the Linux run covers the parts
# whose code builds here (FAF_SIM_MATH_SUBSET: the X87Math helpers, sqrt and the
# navigator's cell arithmetic) and reports the golden cases it skipped.
add_executable(faf_sim_math_tests
  "${PROJECT_SOURCE_DIR}/tests/sim_math/SimMathTests.cpp"
  "${PROJECT_SOURCE_DIR}/src/legacy/math/X87Math.cpp"
  "${PROJECT_SOURCE_DIR}/src/legacy/math/X87Math64.S")
target_link_libraries(faf_sim_math_tests PRIVATE faf_sim_settings)
target_compile_definitions(faf_sim_math_tests PRIVATE FAF_SIM_MATH_SUBSET=1)
set(_faf_sim_math_args "${PROJECT_SOURCE_DIR}/tests/sim_math/golden.txt")
if(EXISTS "${PROJECT_SOURCE_DIR}/tests/sim_math/known_linux-x64.txt")
  list(APPEND _faf_sim_math_args --known "${PROJECT_SOURCE_DIR}/tests/sim_math/known_linux-x64.txt")
endif()
add_custom_command(TARGET faf_sim_math_tests POST_BUILD
  COMMAND "$<TARGET_FILE:faf_sim_math_tests>" ${_faf_sim_math_args}
  COMMENT "Checking the simulation's arithmetic against tests/sim_math/golden.txt"
  VERBATIM)

# --- faf-sim-link -----------------------------------------------------------------------
# Every faf_sim object linked into one executable with no entry point of its
# own, to list what the simulation references outside itself (plan WPL.3):
# `cmake --build ... --target faf-sim-link` fails with that list until it is
# empty.
add_executable(faf-sim-link "${PROJECT_SOURCE_DIR}/tests/linux/SimLinkMain.cpp")
target_link_libraries(faf-sim-link PRIVATE faf_sim)
target_link_options(faf-sim-link PRIVATE -Wl,--error-limit=0)
