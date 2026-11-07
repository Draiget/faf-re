# Engine addition (dedicated-server plan, Phase D): the Linux build.
#
# Included by the top-level CMakeLists.txt, in place of the Windows project,
# when the toolchain is cmake/toolchains/linux-clang-x64.cmake. Linux builds
# the headless simulation only (plan D2, G6): no window, render device, audio,
# movie, wx or Win32 code.
#
#   cmake --preset linux-clang-x64-release && cmake --build --preset linux-clang-x64-release

# Engine addition (#118): a profile-guided build, for a server's speed. The linux-clang-x64-release
# preset uses the stored profile, linux-clang-x64-release-plain none, -pgogen records one
# (tools/pgo/record.sh). See docs/SWITCHES.md.
#   FAF_PGO_GENERATE=ON                counts what the code does; a replay writes the counts on exit
#                                      (LLVM_PROFILE_FILE names the file), llvm-profdata merges them.
#   FAF_PGO_PROFILE=<file.profdata>    ThinLTO with those counts. Needs llvm-ar (package llvm-18).
option(FAF_PGO_GENERATE "Build headless to record a profile for FAF_PGO_PROFILE" OFF)
set(FAF_PGO_PROFILE "" CACHE FILEPATH "Merged LLVM profile to optimise with")
if(FAF_PGO_GENERATE AND FAF_PGO_PROFILE)
  message(FATAL_ERROR "FAF_PGO_GENERATE and FAF_PGO_PROFILE exclude each other.")
endif()
if(FAF_PGO_GENERATE)
  add_compile_options(-fprofile-generate)
  add_link_options(-fprofile-generate)
  add_compile_definitions(FAF_COVERAGE_PROFILE=1)
elseif(FAF_PGO_PROFILE)
  find_program(FAF_LLVM_AR NAMES llvm-ar HINTS "${FAF_LINUX_LLVM_ROOT}/bin")
  find_program(FAF_LLVM_RANLIB NAMES llvm-ranlib HINTS "${FAF_LINUX_LLVM_ROOT}/bin")
  if(NOT FAF_LLVM_AR OR NOT FAF_LLVM_RANLIB)
    message(FATAL_ERROR "A profile-guided build needs llvm-ar and llvm-ranlib: install llvm-18, or use the linux-clang-x64-release-plain preset.")
  endif()
  set(CMAKE_AR "${FAF_LLVM_AR}")
  set(CMAKE_RANLIB "${FAF_LLVM_RANLIB}")
  # A profile from older source still applies to the functions that did not change.
  add_compile_options(-flto=thin "-fprofile-use=${FAF_PGO_PROFILE}" -Wno-profile-instr-unprofiled -Wno-profile-instr-out-of-date -Wno-backend-plugin)
  add_link_options(-flto=thin "-fprofile-use=${FAF_PGO_PROFILE}")
endif()

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
include(FafWarnings)

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

# The net channel (src/remote/net, plan WP10) and its one download, Monocypher, pinned in
# cmake/FafDependencies.cmake; the Windows-only dependencies there are skipped. Without the
# download (FAF_FETCH_DEPENDENCIES=OFF, or no network) the channel is left out and the
# simulation targets build as before.
option(FAF_FETCH_DEPENDENCIES "Fetch the net channel's Monocypher download at configure time" ON)
if(FAF_FETCH_DEPENDENCIES)
  set(FAF_DEPENDENCIES_ONLY monocypher zstd googletest)
  include(FafDependencies)
endif()
add_subdirectory("${PROJECT_SOURCE_DIR}/cmake/deps/monocypher" "${CMAKE_BINARY_DIR}/deps/monocypher")
add_subdirectory("${PROJECT_SOURCE_DIR}/cmake/deps/zstd" "${CMAKE_BINARY_DIR}/deps/zstd")
add_subdirectory("${PROJECT_SOURCE_DIR}/cmake/deps/googletest" "${CMAKE_BINARY_DIR}/deps/googletest")
add_subdirectory("${PROJECT_SOURCE_DIR}/src/remote/net" "${CMAKE_BINARY_DIR}/remote/net")
if(TARGET faf_netchannel)
  add_executable(faf_netchannel_tests EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/tests/remote/net/NetChannelTests.cpp")
  target_link_libraries(faf_netchannel_tests PRIVATE faf_netchannel faf_monocypher gtest_main)
  add_executable(faf_gamelink_tests EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/tests/remote/net/GameLinkTests.cpp")
  target_link_libraries(faf_gamelink_tests PRIVATE faf_netchannel faf_monocypher gtest_main)
endif()

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
# The crash diagnostics on dbghelp, vectored exception handlers, minidumps and debug
# registers; gpg/core/diagnostics/posix/DiagnosticsPosix.cpp implements their headers.
list(FILTER FAF_SIM_SOURCES EXCLUDE REGEX "^gpg/core/diagnostics/(CrashHooks|CrashReport|ProbeWatch)\\.cpp$")
# The lockstep transport: Winsock sockets driven by WSAEventSelect. Linux replays and
# serves games without it (the server has its own channel, plan D3); moho/net/Common.cpp's
# connector factories fail here as on a Windows host without Winsock.
# NetPeerTransport (issue #232) belongs to CNetUDPConnector and goes with it.
list(FILTER FAF_SIM_SOURCES EXCLUDE REGEX "^moho/net/(CNetDatagramSocketImpl|CNetTCPBuf|CNetTCPConnection|CNetTCPConnector|CNetTCPServerImpl|CNetUDPConnection|CNetUDPConnector|NetPeerTransport|INetDatagramSocket|INetTCPServer|INetTCPSocket)\\.cpp$")

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

# The wire format of server-authoritative sessions (remote/sources.cmake, FAF_REMOTE_SOURCES),
# after the engine's sources as in the Windows server-mode build: headless's wire checks
# use it, and the Linux game server will.
include("${PROJECT_SOURCE_DIR}/src/remote/sources.cmake")
# The client half too (FAF_REMOTE_CLIENT_SOURCES), as Windows' server-mode faf_engine links it:
# sim-side server-mode code (SetFocusArmy's driver lookup) calls into it.
foreach(_src IN LISTS FAF_REMOTE_SOURCES FAF_REMOTE_CLIENT_SOURCES)
  list(APPEND _faf_sim_files "${PROJECT_SOURCE_DIR}/src/${_src}")
endforeach()

add_library(faf_sim OBJECT ${_faf_sim_files})
# Its compile and link settings, which targets built from a few sim sources
# (tests/sim_math) share without depending on every faf_sim object.
add_library(faf_sim_settings INTERFACE)
target_link_libraries(faf_sim PUBLIC faf_sim_settings)

# The git commit for gpg/core/diagnostics/BuildInfo.cpp, read on every build.
include(FafBuildInfo)
faf_build_info(faf_sim x64-linux)

# The x64 half of legacy/math/X87Math.cpp, in GNU syntax for System V (the
# Windows build assembles X87Math64.asm, plan WPL.10).
enable_language(ASM)
target_sources(faf_sim PRIVATE "${PROJECT_SOURCE_DIR}/src/legacy/math/X87Math64.S")
# gpg::gal::Math without D3DX (plan WPR.12; Windows' faf_main links it too, #317).
target_sources(faf_sim PRIVATE "${PROJECT_SOURCE_DIR}/src/gpg/gal/MatrixPortable.cpp")
# The Win32 calls the shared code makes, on POSIX (plan WPL.5).
target_sources(faf_sim PRIVATE "${PROJECT_SOURCE_DIR}/src/platform/posix/Win32Shim.cpp")
# The crash diagnostics' headers on POSIX (plan WPL.5).
target_sources(faf_sim PRIVATE "${PROJECT_SOURCE_DIR}/src/gpg/core/diagnostics/posix/DiagnosticsPosix.cpp")
# moho/misc/WinPlatform.cpp's platform services (call stacks, error text, message boxes) and
# the type_info of client classes the sim names (plan WPL.5).
target_sources(faf_sim PRIVATE
  "${PROJECT_SOURCE_DIR}/src/moho/misc/posix/PlatformPosix.cpp"
  "${PROJECT_SOURCE_DIR}/src/platform/posix/ClientTypeInfoPosix.cpp")
# Every thread's x87 control word and MXCSR as on Windows x64 (plan WPL.9): the main thread's
# from a constructor, the others' from pthread_create, wrapped in every program that links the
# sim.
target_sources(faf_sim PRIVATE "${PROJECT_SOURCE_DIR}/src/platform/posix/FpEnvPosix.cpp")
target_link_options(faf_sim_settings INTERFACE "-Wl,--wrap=pthread_create")

# The Windows build's engine definitions without the Win32 ones (WIN32,
# _WINDOWS, WIN32_LEAN_AND_MEAN, NOMINMAX, UNICODE, _CRT_*).
target_compile_definitions(faf_sim_settings INTERFACE
  LUAPLUS_LIB LUA_NUMBER=float
  BOOST_ALL_NO_LIB BOOST_NO_AUTO_PTR
  # The server-mode build, as Windows' faf_engine with FAF_SERVER_MODE (src/CMakeLists.txt):
  # the Linux programs are the server and the replay runner.
  FAF_SERVER_MODE=1)
target_include_directories(faf_sim_settings INTERFACE
  "${PROJECT_SOURCE_DIR}/src"
  # <Windows.h> and <intrin.h> for the shared code (plan WPL.5), and <windows.h>, the
  # spelling some files use (the file system is case-sensitive here).
  "${PROJECT_SOURCE_DIR}/src/platform/posix/win32"
  "${CMAKE_BINARY_DIR}/win32-alias"
  "${FAF_DEPENDENCIES_DIR}/boost_1_34_1"
  "${FAF_DEPENDENCIES_DIR}/zlib-1.2.3")
target_link_libraries(faf_sim_settings INTERFACE faf_codegen)
target_link_libraries(faf_sim PUBLIC Wm3Headers zlib123 faf_monocypher faf_zstd)
# The client half of server mode (remote/client/ServerConnect.cpp, /connectserver) holds the channel to the server:
# every program built from faf_sim links the net channel, as Windows' server-mode faf_main does.
if(TARGET faf_netchannel)
  target_link_libraries(faf_sim PUBLIC faf_netchannel)
endif()

set(_faf_sim_options
  # The recovered tree's x86 layout asserts, off as on Windows x64 (see the
  # header).
  "SHELL:-include platform/LayoutAsserts.h"
  # The Windows names the shared code uses (plan WPL.5).
  "SHELL:-include platform/PosixCompat.h"
  ${FAF_LINUX_MS_DIALECT}
  # boost.thread checks for the compiler's threading mode (_REENTRANT).
  -pthread
  -Wall
  ${FAF_WARNING_OPTIONS}
  # Options clang 18 does not know yet (the Windows build uses a newer clang).
  -Wno-unknown-warning-option)
target_compile_options(faf_sim_settings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:${_faf_sim_options}>")

# boost.thread's own sources, as on Windows (src/CMakeLists.txt).
foreach(_src IN LISTS _faf_sim_files)
  if(_src MATCHES "/libs/thread/src/")
    # Its thread.cpp and tss.cpp use std::auto_ptr, which libc++ keeps behind this opt-in.
    set_property(SOURCE "${_src}" APPEND PROPERTY COMPILE_DEFINITIONS BOOST_THREAD_BUILD_LIB=1 _LIBCPP_ENABLE_CXX17_REMOVED_AUTO_PTR=1)
    set_property(SOURCE "${_src}" APPEND PROPERTY COMPILE_OPTIONS -w)
  endif()
endforeach()
include(FafPrecompiledHeaders)
faf_precompile(faf_sim)

# --- faf_sim_math_tests (plan WPL.23) ---------------------------------------------------
# The golden sim-math tests (tests/sim_math) on every faf_sim object, as Windows runs
# them on faf_engine: every golden case, the pathfinder's and the random stream's too.
add_executable(faf_sim_math_tests "${PROJECT_SOURCE_DIR}/tests/sim_math/SimMathTests.cpp")
target_link_libraries(faf_sim_math_tests PRIVATE faf_sim gtest)
target_compile_definitions(faf_sim_math_tests PRIVATE
  FAF_SIM_MATH_GOLDEN="${PROJECT_SOURCE_DIR}/tests/sim_math/golden.txt"
)
if(EXISTS "${PROJECT_SOURCE_DIR}/tests/sim_math/known_linux-x64.txt")
  target_compile_definitions(faf_sim_math_tests PRIVATE
    FAF_SIM_MATH_KNOWN="${PROJECT_SOURCE_DIR}/tests/sim_math/known_linux-x64.txt"
  )
endif()
set(_faf_sim_math_args "${PROJECT_SOURCE_DIR}/tests/sim_math/golden.txt")
if(EXISTS "${PROJECT_SOURCE_DIR}/tests/sim_math/known_linux-x64.txt")
  list(APPEND _faf_sim_math_args --known "${PROJECT_SOURCE_DIR}/tests/sim_math/known_linux-x64.txt")
endif()
add_custom_command(TARGET faf_sim_math_tests POST_BUILD
  COMMAND "$<TARGET_FILE:faf_sim_math_tests>" ${_faf_sim_math_args}
  COMMENT "Checking the simulation's arithmetic against tests/sim_math/golden.txt"
  VERBATIM)

# --- faf_math_dump (plan WPR.21) --------------------------------------------------------
# The difffuzz targets on every faf_sim object, as Windows builds them on faf_engine,
# checked against retail's outputs (tests/math_dump/golden.txt) after every build
# (tools/difffuzz/dump.cmake).
set(FAF_MATH_DUMP_ENGINE faf_sim)
include("${PROJECT_SOURCE_DIR}/tools/difffuzz/dump.cmake")

# --- faf-sim-link -----------------------------------------------------------------------
# Every faf_sim object linked into one executable with no entry point of its
# own, to list what the simulation references outside itself (plan WPL.3):
# `cmake --build ... --target faf-sim-link` fails with that list until it is
# empty.
add_executable(faf-sim-link "${PROJECT_SOURCE_DIR}/tests/linux/SimLinkMain.cpp")
target_link_libraries(faf-sim-link PRIVATE faf_sim)
target_link_options(faf-sim-link PRIVATE -Wl,--error-limit=0)

# --- headless (plan WPL.7) --------------------------------------------------------------
# The headless replay runner on Linux: headless/sources.cmake on every faf_sim object, as on
# Windows (a plain Lua state for sync packets and launch configs, no wx entry, no
# userInit.lua). Linux has one architecture, so the file is `headless`, without the
# Windows x64 build's `_x64`.
include("${PROJECT_SOURCE_DIR}/src/headless/sources.cmake")
set(_faf_headless_files "")
foreach(_src IN LISTS FAF_HEADLESS_SOURCES)
  list(APPEND _faf_headless_files "${PROJECT_SOURCE_DIR}/src/${_src}")
endforeach()
add_executable(headless ${_faf_headless_files}
  "${PROJECT_SOURCE_DIR}/src/headless/ReplayTargetAudit.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/SeatIntake.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/LobbyRelay.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/LobbySignaller.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/ServerNet.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/ServerViews.cpp"
)
target_compile_definitions(headless PRIVATE FAF_HEADLESS_NET=1)
target_link_libraries(headless PRIVATE faf_netchannel faf_monocypher)
target_link_libraries(headless PRIVATE faf_sim)
target_compile_definitions(headless PRIVATE FAF_SERVER_MODE=1)
target_link_options(headless PRIVATE -Wl,--error-limit=0)

# --- server (plan WP1.1) --------------------------------------------------------------------
# The dedicated server, Linux only (plan D2): the sim, and what `headless` shares for loading a game.
add_executable(server
  "${PROJECT_SOURCE_DIR}/src/server/ServerMain.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/SeatIntake.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/LobbyRelay.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/LobbySignaller.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/ServerNet.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/ServerViews.cpp"
  "${PROJECT_SOURCE_DIR}/src/headless/SessionLoad.cpp"
  "${PROJECT_SOURCE_DIR}/src/headless/ReplayLuaState.cpp"
)
target_link_libraries(server PRIVATE faf_sim faf_netchannel faf_monocypher)
target_compile_definitions(server PRIVATE FAF_SERVER_MODE=1)
target_link_options(server PRIVATE -Wl,--error-limit=0)

add_executable(faf_server_tests EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/tests/server/SpeedWatchTests.cpp")
target_include_directories(faf_server_tests PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(faf_server_tests PRIVATE gtest_main)

add_executable(faf_seat_tests EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/tests/server/SeatTests.cpp" "${PROJECT_SOURCE_DIR}/src/server/SeatIntake.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/LobbyRelay.cpp"
  "${PROJECT_SOURCE_DIR}/src/server/LobbySignaller.cpp")
target_link_libraries(faf_seat_tests PRIVATE faf_sim faf_netchannel faf_monocypher gtest_main)
target_compile_definitions(faf_seat_tests PRIVATE FAF_SERVER_MODE=1)
target_link_options(faf_seat_tests PRIVATE -Wl,--error-limit=0)

add_executable(faf_server_probe EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/tools/server-probe/ProbeMain.cpp"
  "${PROJECT_SOURCE_DIR}/tools/server-probe/ProbeRebuild.cpp"
  "${PROJECT_SOURCE_DIR}/src/headless/SessionLoad.cpp"
  "${PROJECT_SOURCE_DIR}/src/headless/ReplayLuaState.cpp")
target_link_libraries(faf_server_probe PRIVATE faf_sim faf_netchannel faf_monocypher)
target_compile_definitions(faf_server_probe PRIVATE FAF_SERVER_MODE=1)
target_link_options(faf_server_probe PRIVATE -Wl,--error-limit=0)

# --- faf_remote_tests -------------------------------------------------------------------
# The wire format's tests (tests/remote/WireTests.cpp) on the Linux objects, as Windows'
# server-mode build runs them on faf_engine.
add_executable(faf_remote_tests EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/tests/remote/WireTests.cpp")
target_link_libraries(faf_remote_tests PRIVATE faf_sim gtest_main)
target_compile_definitions(faf_remote_tests PRIVATE FAF_SERVER_MODE=1)
target_link_options(faf_remote_tests PRIVATE -Wl,--error-limit=0)

# The libm gate (plan WPL.13): the faf_sim objects call no host libm transcendental outside
# tests/linux/libm_allowlist.txt; headless is not built while one does.
add_custom_target(faf_sim_libm_gate
  COMMAND python3 "${PROJECT_SOURCE_DIR}/tests/linux/LibmGate.py"
          "${PROJECT_SOURCE_DIR}/tests/linux/libm_allowlist.txt" "$<TARGET_OBJECTS:faf_sim>"
  DEPENDS faf_sim
  COMMAND_EXPAND_LISTS
  COMMENT "Checking faf_sim's libm transcendental calls against tests/linux/libm_allowlist.txt"
  VERBATIM)
add_dependencies(headless faf_sim_libm_gate)

# --- faf_registration_dump_sim (plan WPL.4) ----------------------------------------------
# What the static initialisers of the Linux faf_sim objects registered (tests/registry): its
# sections must equal Windows' faf_registration_dump_sim (src/CMakeLists.txt).
add_executable(faf_registration_dump_sim EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/tests/registry/RegistrationDump.cpp")
target_link_libraries(faf_registration_dump_sim PRIVATE faf_sim)
