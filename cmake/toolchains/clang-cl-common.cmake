# Shared part of the clang-cl toolchains (clang-cl-x64.cmake, clang-cl-x86.cmake).
#
# Compiles with clang-cl and links with lld-link against the MSVC STL/CRT
# headers and static libraries and the Windows SDK. Those are found here, so a
# configure works from any shell, not only from a Visual Studio developer
# prompt:
#
#   FAF_LLVM_ROOT        LLVM install (clang-cl, lld-link, llvm-lib, llvm-rc,
#                        llvm-mt, llvm-ml). Default: $ENV{LLVM_ROOT}, else
#                        C:/Program Files/LLVM.
#   FAF_MSVC_TOOLS_DIR   VC\Tools\MSVC\<version> of a Visual Studio 2022 with
#                        the C++ workload. Default: $ENV{VCToolsInstallDir}
#                        (developer prompt), else the default toolset of the
#                        newest Visual Studio vswhere reports.
#   FAF_WINSDK_DIR       Windows 10/11 SDK root. Default: $ENV{WindowsSdkDir},
#                        else the KitsRoot10 registry value.
#   FAF_WINSDK_VERSION   SDK version. Default: $ENV{WindowsSDKVersion}, else
#                        the newest one installed (what main.vcxproj's
#                        WindowsTargetPlatformVersion 10.0 picks too).
#
# clang-cl and lld-link take the last three as /vctoolsdir, /winsdkdir and
# /winsdkversion and derive the per-architecture include and library paths
# from them.

if(NOT DEFINED FAF_TARGET_ARCH)
  message(FATAL_ERROR "Include clang-cl-x64.cmake or clang-cl-x86.cmake, not clang-cl-common.cmake.")
endif()

# try_compile projects re-read this file; pass the detected locations on.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES
  FAF_TARGET_ARCH FAF_LLVM_ROOT FAF_MSVC_TOOLS_DIR FAF_WINSDK_DIR FAF_WINSDK_VERSION)

# --- LLVM ---------------------------------------------------------------------
if(NOT FAF_LLVM_ROOT)
  if(DEFINED ENV{LLVM_ROOT})
    set(FAF_LLVM_ROOT "$ENV{LLVM_ROOT}")
  else()
    set(FAF_LLVM_ROOT "C:/Program Files/LLVM")
  endif()
endif()
file(TO_CMAKE_PATH "${FAF_LLVM_ROOT}" FAF_LLVM_ROOT)
set(FAF_LLVM_ROOT "${FAF_LLVM_ROOT}" CACHE PATH "LLVM install root (clang-cl, lld-link, llvm-*)")
if(NOT EXISTS "${FAF_LLVM_ROOT}/bin/clang-cl.exe")
  message(FATAL_ERROR "clang-cl.exe not found under FAF_LLVM_ROOT=${FAF_LLVM_ROOT}")
endif()

# --- MSVC toolset (STL and CRT headers and libraries) -------------------------
if(NOT FAF_MSVC_TOOLS_DIR)
  if(DEFINED ENV{VCToolsInstallDir})
    set(FAF_MSVC_TOOLS_DIR "$ENV{VCToolsInstallDir}")
  else()
    set(_faf_vswhere "$ENV{ProgramFiles\(x86\)}/Microsoft Visual Studio/Installer/vswhere.exe")
    if(EXISTS "${_faf_vswhere}")
      execute_process(
        COMMAND "${_faf_vswhere}" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64
                -property installationPath
        OUTPUT_VARIABLE _faf_vs_root OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
    if(_faf_vs_root)
      file(TO_CMAKE_PATH "${_faf_vs_root}" _faf_vs_root)
      file(STRINGS "${_faf_vs_root}/VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt" _faf_vc_version LIMIT_COUNT 1)
      string(STRIP "${_faf_vc_version}" _faf_vc_version)
      set(FAF_MSVC_TOOLS_DIR "${_faf_vs_root}/VC/Tools/MSVC/${_faf_vc_version}")
    endif()
  endif()
endif()
file(TO_CMAKE_PATH "${FAF_MSVC_TOOLS_DIR}" FAF_MSVC_TOOLS_DIR)
string(REGEX REPLACE "/$" "" FAF_MSVC_TOOLS_DIR "${FAF_MSVC_TOOLS_DIR}")
set(FAF_MSVC_TOOLS_DIR "${FAF_MSVC_TOOLS_DIR}" CACHE PATH "VC/Tools/MSVC/<version> directory")
if(NOT EXISTS "${FAF_MSVC_TOOLS_DIR}/include/vcruntime.h")
  message(FATAL_ERROR "No MSVC toolset found (FAF_MSVC_TOOLS_DIR=${FAF_MSVC_TOOLS_DIR}). "
                      "Install Visual Studio 2022 with the C++ workload or set FAF_MSVC_TOOLS_DIR.")
endif()

# --- Windows SDK ----------------------------------------------------------------
if(NOT FAF_WINSDK_DIR)
  if(DEFINED ENV{WindowsSdkDir})
    set(FAF_WINSDK_DIR "$ENV{WindowsSdkDir}")
  else()
    cmake_host_system_information(RESULT FAF_WINSDK_DIR QUERY WINDOWS_REGISTRY
      "HKLM/SOFTWARE/Microsoft/Windows Kits/Installed Roots" VALUE KitsRoot10 VIEW BOTH)
  endif()
endif()
file(TO_CMAKE_PATH "${FAF_WINSDK_DIR}" FAF_WINSDK_DIR)
string(REGEX REPLACE "/$" "" FAF_WINSDK_DIR "${FAF_WINSDK_DIR}")
set(FAF_WINSDK_DIR "${FAF_WINSDK_DIR}" CACHE PATH "Windows SDK root (Windows Kits/10)")

if(NOT FAF_WINSDK_VERSION)
  if(DEFINED ENV{WindowsSDKVersion})
    string(REGEX REPLACE "[/\\\\]$" "" FAF_WINSDK_VERSION "$ENV{WindowsSDKVersion}")
  else()
    file(GLOB _faf_sdk_versions RELATIVE "${FAF_WINSDK_DIR}/Include" "${FAF_WINSDK_DIR}/Include/10.*")
    set(FAF_WINSDK_VERSION "")
    foreach(_v IN LISTS _faf_sdk_versions)
      if(EXISTS "${FAF_WINSDK_DIR}/Include/${_v}/um/windows.h" AND _v VERSION_GREATER FAF_WINSDK_VERSION)
        set(FAF_WINSDK_VERSION "${_v}")
      endif()
    endforeach()
  endif()
endif()
set(FAF_WINSDK_VERSION "${FAF_WINSDK_VERSION}" CACHE STRING "Windows SDK version (10.0.x.y)")
if(NOT EXISTS "${FAF_WINSDK_DIR}/Include/${FAF_WINSDK_VERSION}/um/windows.h")
  message(FATAL_ERROR "No Windows SDK found (FAF_WINSDK_DIR=${FAF_WINSDK_DIR}, "
                      "FAF_WINSDK_VERSION=${FAF_WINSDK_VERSION}).")
endif()

# --- Tools ----------------------------------------------------------------------
set(CMAKE_C_COMPILER   "${FAF_LLVM_ROOT}/bin/clang-cl.exe")
set(CMAKE_CXX_COMPILER "${FAF_LLVM_ROOT}/bin/clang-cl.exe")
set(CMAKE_LINKER       "${FAF_LLVM_ROOT}/bin/lld-link.exe")
set(CMAKE_AR           "${FAF_LLVM_ROOT}/bin/llvm-lib.exe")
set(CMAKE_RC_COMPILER  "${FAF_LLVM_ROOT}/bin/llvm-rc.exe")
set(CMAKE_MT           "${FAF_LLVM_ROOT}/bin/llvm-mt.exe")
if(FAF_TARGET_ARCH STREQUAL "x64")
  set(CMAKE_ASM_MASM_COMPILER "${FAF_LLVM_ROOT}/bin/llvm-ml64.exe")
else()
  set(CMAKE_ASM_MASM_COMPILER "${FAF_LLVM_ROOT}/bin/llvm-ml.exe")
endif()

# Toolset and SDK locations for the compiler and the linker. Both derive the
# include/library paths for the target architecture from these.
set(_faf_cl_sysroot
  "/vctoolsdir \"${FAF_MSVC_TOOLS_DIR}\" /winsdkdir \"${FAF_WINSDK_DIR}\" /winsdkversion ${FAF_WINSDK_VERSION}")
set(_faf_link_sysroot
  "/vctoolsdir:\"${FAF_MSVC_TOOLS_DIR}\" /winsdkdir:\"${FAF_WINSDK_DIR}\" /winsdkversion:${FAF_WINSDK_VERSION}")

string(APPEND CMAKE_C_FLAGS_INIT " ${_faf_cl_sysroot}")
string(APPEND CMAKE_CXX_FLAGS_INIT " ${_faf_cl_sysroot}")
foreach(_kind EXE SHARED MODULE)
  string(APPEND CMAKE_${_kind}_LINKER_FLAGS_INIT " ${_faf_link_sysroot}")
endforeach()

# llvm-rc preprocesses with clang, which does not take the toolset/SDK
# locations; give it the SDK headers resource scripts include (windows.h,
# winres.h) directly.
set(_faf_sdk_inc "${FAF_WINSDK_DIR}/Include/${FAF_WINSDK_VERSION}")
string(APPEND CMAKE_RC_FLAGS_INIT
  " -I \"${_faf_sdk_inc}/um\" -I \"${_faf_sdk_inc}/shared\" -I \"${_faf_sdk_inc}/ucrt\""
  " -I \"${FAF_MSVC_TOOLS_DIR}/include\"")
