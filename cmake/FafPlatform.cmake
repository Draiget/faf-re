# Engine addition: the platform and processor a build targets, as CMake variables named like the
# C macros of src/platform/PlatformDefines.h, each ON or OFF. CMake files test these, never
# WIN32, UNIX, APPLE, CMAKE_SYSTEM_NAME or CMAKE_SYSTEM_PROCESSOR, which this file alone reads.
#
#   FAFRE_PLATFORM_WINDOWS  FAFRE_PLATFORM_LINUX  FAFRE_PLATFORM_MACOS  FAFRE_PLATFORM_POSIX
#   FAFRE_ARCH_X86  FAFRE_ARCH_X64  FAFRE_ARCH_ARM64  FAFRE_ARCH_64BIT  FAFRE_ARCH_X87
#   FAFRE_PLATFORM_MACOS_ARM64
#   FAF_TARGET_ARCH         x86, x64 or arm64: the name in file and folder names (headless_x64, ...)
#
# Included right after project(), which reads the toolchain file that sets the target.

set(FAFRE_PLATFORM_WINDOWS OFF)
set(FAFRE_PLATFORM_LINUX OFF)
set(FAFRE_PLATFORM_MACOS OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(FAFRE_PLATFORM_WINDOWS ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(FAFRE_PLATFORM_LINUX ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(FAFRE_PLATFORM_MACOS ON)
else()
  message(FATAL_ERROR "cmake/FafPlatform.cmake: unsupported system ${CMAKE_SYSTEM_NAME}")
endif()
if(FAFRE_PLATFORM_LINUX OR FAFRE_PLATFORM_MACOS)
  set(FAFRE_PLATFORM_POSIX ON)
else()
  set(FAFRE_PLATFORM_POSIX OFF)
endif()

# The processor: what the compiler targets, not the build machine. CMAKE_SYSTEM_PROCESSOR is the
# host's unless a toolchain sets it, and macOS names the target in CMAKE_OSX_ARCHITECTURES.
set(FAFRE_ARCH_X86 OFF)
set(FAFRE_ARCH_X64 OFF)
set(FAFRE_ARCH_ARM64 OFF)
if(FAFRE_PLATFORM_MACOS AND CMAKE_OSX_ARCHITECTURES)
  set(_faf_processor "${CMAKE_OSX_ARCHITECTURES}")
else()
  set(_faf_processor "${CMAKE_SYSTEM_PROCESSOR}")
endif()
string(TOLOWER "${_faf_processor}" _faf_processor)
if(_faf_processor MATCHES "^(arm64|aarch64)$")
  set(FAFRE_ARCH_ARM64 ON)
  set(FAF_TARGET_ARCH arm64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
  set(FAFRE_ARCH_X86 ON)
  set(FAF_TARGET_ARCH x86)
elseif(_faf_processor MATCHES "^(x86_64|amd64)$")
  set(FAFRE_ARCH_X64 ON)
  set(FAF_TARGET_ARCH x64)
else()
  message(FATAL_ERROR "cmake/FafPlatform.cmake: unsupported processor '${_faf_processor}' "
                      "(one architecture per build; CMAKE_OSX_ARCHITECTURES names exactly one on macOS)")
endif()
unset(_faf_processor)

if(FAFRE_ARCH_X64 OR FAFRE_ARCH_ARM64)
  set(FAFRE_ARCH_64BIT ON)
else()
  set(FAFRE_ARCH_64BIT OFF)
endif()
if(FAFRE_ARCH_X86 OR FAFRE_ARCH_X64)
  set(FAFRE_ARCH_X87 ON)
else()
  set(FAFRE_ARCH_X87 OFF)
endif()
if(FAFRE_PLATFORM_MACOS AND FAFRE_ARCH_ARM64)
  set(FAFRE_PLATFORM_MACOS_ARM64 ON)
else()
  set(FAFRE_PLATFORM_MACOS_ARM64 OFF)
endif()
