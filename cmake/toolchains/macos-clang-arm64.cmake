# Engine addition (macOS milestone, #271): macOS on Apple silicon (arm64) with Apple clang and
# libc++, native code with the GNU driver - no clang-cl, no MSVC ABI. Used by the
# macos-clang-arm64-* presets.
#
#   cmake --preset macos-clang-arm64-release && cmake --build --preset macos-clang-arm64-release
#
# The top-level CMakeLists.txt sees this file's name and builds the POSIX project
# (cmake/FafPosix.cmake) instead of the Windows one.
#
#   FAF_MACOS_ALLOW_UNPINNED_TOOLCHAIN  ON: accept an Apple clang other than the pinned release
#                                       (not a parity build).
#
# Code generation (what the simulation's results depend on) is in cmake/FafCodegen.cmake, shared
# with the other toolchains. Here: the target, the tools and the pinned compiler.

set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR arm64)
set(CMAKE_OSX_ARCHITECTURES arm64 CACHE STRING "One architecture per build (cmake/FafPlatform.cmake)")
# macOS 14: the oldest release whose libc++ has every C++23 library feature the engine uses
# (std::to_chars for floating point, std::format) without availability errors.
set(CMAKE_OSX_DEPLOYMENT_TARGET 14.0 CACHE STRING "Oldest macOS the build runs on")

# Apple clang from the active Xcode or Command Line Tools (xcrun), the compiler Apple's SDK and
# libc++ headers are made for.
set(FAF_MACOS_PINNED_CLANG_VERSION "17.0.0")
option(FAF_MACOS_ALLOW_UNPINNED_TOOLCHAIN "Accept an Apple clang release other than the pinned one" OFF)
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES FAF_MACOS_ALLOW_UNPINNED_TOOLCHAIN)

execute_process(COMMAND xcrun --find clang OUTPUT_VARIABLE _faf_clang OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND xcrun --find clang++ OUTPUT_VARIABLE _faf_clangxx OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT _faf_clangxx)
  message(FATAL_ERROR "xcrun found no clang++: install Xcode or the Command Line Tools (xcode-select --install)")
endif()
set(CMAKE_C_COMPILER "${_faf_clang}")
set(CMAKE_CXX_COMPILER "${_faf_clangxx}")

execute_process(COMMAND "${_faf_clangxx}" --version OUTPUT_VARIABLE _faf_clang_banner OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX MATCH "Apple clang version ([0-9]+\\.[0-9]+\\.[0-9]+)" _faf_clang_match "${_faf_clang_banner}")
if(NOT CMAKE_MATCH_1 STREQUAL FAF_MACOS_PINNED_CLANG_VERSION)
  if(FAF_MACOS_ALLOW_UNPINNED_TOOLCHAIN)
    message(WARNING "Apple clang ${CMAKE_MATCH_1} (pinned ${FAF_MACOS_PINNED_CLANG_VERSION}): this is not a parity build.")
  else()
    message(FATAL_ERROR "Apple clang ${CMAKE_MATCH_1} differs from the pinned ${FAF_MACOS_PINNED_CLANG_VERSION}: "
                        "install that Xcode or set FAF_MACOS_ALLOW_UNPINNED_TOOLCHAIN=ON.")
  endif()
endif()

# Release optimises as the Windows builds' /O2 does (CMake's GNU default is -O3).
set(CMAKE_C_FLAGS_RELEASE_INIT "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2 -DNDEBUG")
foreach(_kind EXE SHARED MODULE)
  set(CMAKE_${_kind}_LINKER_FLAGS_INIT "-pthread")
endforeach()
