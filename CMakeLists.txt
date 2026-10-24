# FAF engine (recovered Forged Alliance / Moho engine).
#
# CMake build of src/main.vcxproj's engine executable with clang-cl. The MSVC
# project stays the reference build; this one reproduces its sources, order,
# defines and link, with the C/C++ runtime linked statically (/MT) into the
# engine and every library built here, so the executables import no MSVC
# runtime DLL.
#
#   cmake --preset clang-x64-release && cmake --build --preset clang-x64-release
#   cmake --preset clang-x86-release && cmake --build --preset clang-x86-release
#
# See CMakePresets.json and cmake/toolchains/ for the toolchain setup.

cmake_minimum_required(VERSION 3.25)

project(faf_engine LANGUAGES C CXX RC)

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
  message(FATAL_ERROR "This build expects clang-cl (use a preset from CMakePresets.json). "
                      "The MSVC build is src/main.vcxproj.")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(FAF_TARGET_ARCH x64)
else()
  set(FAF_TARGET_ARCH x86)
endif()
if(FAF_TARGET_ARCH STREQUAL "x64")
  enable_language(ASM_MASM)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# --- Build-wide settings ------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 17)

# Static C/C++ runtime everywhere (/MT): no MSVCP140/VCRUNTIME140/api-ms-win-crt
# imports.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
# CodeView in the objects (/Z7) - no shared compiler PDB for parallel builds to
# contend on; the linker writes the executable's PDB.
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT Embedded)

# Exception handling is chosen per target (the engine needs /EHs, see
# src/CMakeLists.txt), so drop CMake's default /EHsc.
string(REGEX REPLACE "/EH[a-z-]+" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
# CMake's /W1-/W4 defaults are replaced per target.
string(REGEX REPLACE "/W[0-4]" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
string(REGEX REPLACE "/W[0-4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

# Release links like the MSVC Release configurations: debug information,
# unreferenced code dropped, identical COMDATs folded.
foreach(_kind EXE SHARED MODULE)
  string(APPEND CMAKE_${_kind}_LINKER_FLAGS_RELEASE " /DEBUG /OPT:REF /OPT:ICF")
endforeach()

# --- Locations ------------------------------------------------------------------------
set(FAF_DEPENDENCIES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dependencies" CACHE PATH
    "Third-party tree (dependencies/ in the repository)")
# Submodules, pinned downloads and patches: see cmake/FafDependencies.cmake.
option(FAF_FETCH_DEPENDENCIES "Fetch and patch dependencies/ at configure time" ON)
if(FAF_FETCH_DEPENDENCIES)
  include(FafDependencies)
endif()
if(DEFINED ENV{DXSDK_DIR})
  file(TO_CMAKE_PATH "$ENV{DXSDK_DIR}" _faf_dxsdk_default)
else()
  set(_faf_dxsdk_default "C:/Program Files (x86)/Microsoft DirectX SDK (June 2010)")
endif()
string(REGEX REPLACE "/$" "" _faf_dxsdk_default "${_faf_dxsdk_default}")
set(FAF_DXSDK_DIR "${_faf_dxsdk_default}" CACHE PATH "DirectX SDK (June 2010): D3DX9, XACT3, X3DAudio")
if(NOT EXISTS "${FAF_DXSDK_DIR}/Include/d3dx9.h")
  message(FATAL_ERROR "DirectX SDK (June 2010) not found: FAF_DXSDK_DIR=${FAF_DXSDK_DIR}")
endif()

include(FafCodegen)

# --- Dependencies (built here, /MT, read-only sources) ----------------------------------
add_subdirectory(cmake/deps/wxwindows)
add_subdirectory(cmake/deps/wildmagic)
if(FAF_TARGET_ARCH STREQUAL "x64")
  add_subdirectory(cmake/deps/zlib)
endif()

# --- Engine -----------------------------------------------------------------------------
add_subdirectory(src)
