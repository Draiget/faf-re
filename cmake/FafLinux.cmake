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
