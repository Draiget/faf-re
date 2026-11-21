# Engine addition (Android port): the shared part of the Android toolchains
# (android-arm64.cmake, android-x64.cmake): the NDK's clang, bionic and libc++,
# for the simulation (faf_sim, headless, the sim-math tests) on Android devices
# and the emulator. Used by the android-*-release presets.
#
#   cmake --preset android-arm64-release && cmake --build --preset android-arm64-release
#
# Android is Linux with another C library, so the top-level CMakeLists.txt
# builds the Linux project (cmake/FafPosix.cmake) for it; FAFRE_PLATFORM_ANDROID
# (cmake/FafPlatform.cmake, from the NDK's CMAKE_SYSTEM_NAME) selects what
# differs there (bionic, the ABI, tests that cannot run on the build host).
#
#   FAF_ANDROID_NDK                 NDK root. Default: the pinned release
#                                   (android-pins.cmake) under the SDK in
#                                   $ANDROID_HOME, $ANDROID_SDK_ROOT or Android
#                                   Studio's default location, else
#                                   $ANDROID_NDK_ROOT or $ANDROID_NDK_HOME (which
#                                   often name another release, e.g. on CI
#                                   runners).
#   FAF_ANDROID_ALLOW_UNPINNED_NDK  ON: accept an NDK release other than the
#                                   pinned one.
#
# Code generation (what the simulation's results depend on) is in
# cmake/FafCodegen.cmake, shared with the other toolchains. Here: the NDK, the
# ABI, the API level and the C++ library (libc++, linked statically).

if(NOT DEFINED FAF_ANDROID_ABI)
  message(FATAL_ERROR "Include android-arm64.cmake or android-x64.cmake, not android-common.cmake.")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/android-pins.cmake")

# try_compile projects re-read this file; pass the settings on.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES FAF_ANDROID_ABI FAF_ANDROID_NDK FAF_ANDROID_ALLOW_UNPINNED_NDK)

# --- NDK ----------------------------------------------------------------------------------
if(NOT FAF_ANDROID_NDK)
  set(_faf_sdk_roots "")
  foreach(_faf_var IN ITEMS ANDROID_HOME ANDROID_SDK_ROOT)
    if(DEFINED ENV{${_faf_var}})
      list(APPEND _faf_sdk_roots "$ENV{${_faf_var}}")
    endif()
  endforeach()
  # Android Studio's default SDK location on Windows, macOS and Linux.
  if(DEFINED ENV{LOCALAPPDATA})
    list(APPEND _faf_sdk_roots "$ENV{LOCALAPPDATA}/Android/Sdk")
  endif()
  if(DEFINED ENV{HOME})
    list(APPEND _faf_sdk_roots "$ENV{HOME}/Library/Android/sdk" "$ENV{HOME}/Android/Sdk")
  endif()
  foreach(_faf_sdk IN LISTS _faf_sdk_roots)
    if(EXISTS "${_faf_sdk}/ndk/${FAF_ANDROID_PINNED_NDK_REVISION}/build/cmake/android.toolchain.cmake")
      set(FAF_ANDROID_NDK "${_faf_sdk}/ndk/${FAF_ANDROID_PINNED_NDK_REVISION}")
      break()
    endif()
  endforeach()
endif()
if(NOT FAF_ANDROID_NDK)
  foreach(_faf_var IN ITEMS ANDROID_NDK_ROOT ANDROID_NDK_HOME)
    if(DEFINED ENV{${_faf_var}} AND EXISTS "$ENV{${_faf_var}}/build/cmake/android.toolchain.cmake")
      set(FAF_ANDROID_NDK "$ENV{${_faf_var}}")
      break()
    endif()
  endforeach()
endif()
file(TO_CMAKE_PATH "${FAF_ANDROID_NDK}" FAF_ANDROID_NDK)
set(FAF_ANDROID_NDK "${FAF_ANDROID_NDK}" CACHE PATH "Android NDK root")
option(FAF_ANDROID_ALLOW_UNPINNED_NDK "Accept an NDK release other than the pinned one" OFF)

if(NOT EXISTS "${FAF_ANDROID_NDK}/build/cmake/android.toolchain.cmake")
  message(FATAL_ERROR "Android NDK ${FAF_ANDROID_PINNED_NDK_REVISION} not found: set FAF_ANDROID_NDK, "
                      "ANDROID_NDK_ROOT or ANDROID_HOME (`sdkmanager \"ndk;${FAF_ANDROID_PINNED_NDK_REVISION}\"` installs it).")
endif()

# --- Pin ----------------------------------------------------------------------------------
file(STRINGS "${FAF_ANDROID_NDK}/source.properties" _faf_ndk_revision REGEX "^Pkg\\.Revision")
string(REGEX REPLACE "^Pkg\\.Revision *= *" "" _faf_ndk_revision "${_faf_ndk_revision}")
if(NOT _faf_ndk_revision STREQUAL FAF_ANDROID_PINNED_NDK_REVISION)
  if(FAF_ANDROID_ALLOW_UNPINNED_NDK)
    message(WARNING "Unpinned Android NDK ${_faf_ndk_revision} (pinned ${FAF_ANDROID_PINNED_NDK_REVISION}).")
  else()
    message(FATAL_ERROR "Android NDK ${_faf_ndk_revision} differs from cmake/toolchains/android-pins.cmake "
                        "(${FAF_ANDROID_PINNED_NDK_REVISION}): install the pinned release or set "
                        "FAF_ANDROID_ALLOW_UNPINNED_NDK=ON.")
  endif()
endif()

# --- The NDK's toolchain ------------------------------------------------------------------
set(ANDROID_ABI "${FAF_ANDROID_ABI}")
set(ANDROID_PLATFORM "android-${FAF_ANDROID_API_LEVEL}")
set(ANDROID_STL c++_static)
include("${FAF_ANDROID_NDK}/build/cmake/android.toolchain.cmake")
