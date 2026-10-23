# clang-cl / lld-link, 32-bit Windows (main.exe).
# See clang-cl-common.cmake for the toolset and SDK discovery.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR X86)
set(FAF_TARGET_ARCH x86)

set(CMAKE_C_COMPILER_TARGET i686-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET i686-pc-windows-msvc)

include("${CMAKE_CURRENT_LIST_DIR}/clang-cl-common.cmake")
