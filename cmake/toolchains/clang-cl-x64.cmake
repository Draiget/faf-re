# clang-cl / lld-link, 64-bit Windows (main_x64.exe).
# See clang-cl-common.cmake for the toolset and SDK discovery.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)
set(FAF_TARGET_ARCH x64)

set(CMAKE_C_COMPILER_TARGET x86_64-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET x86_64-pc-windows-msvc)

include("${CMAKE_CURRENT_LIST_DIR}/clang-cl-common.cmake")
