# Zstandard 1.5.7 (BSD-3-Clause, LICENSE in the tree): packs the save a returning player is
# sent (moho/net/CRejoinFeed.cpp, issue #275). dependencies/zstd is the release archive, pinned
# by SHA256 in cmake/FafDependencies.cmake. Only the library's C files; no assembly, so one set
# of sources builds for every target. FAF_ZSTD_DIR is for a tree that can't write to its
# dependencies folder.

set(FAF_ZSTD_DIR "${FAF_DEPENDENCIES_DIR}/zstd" CACHE PATH "Where the zstd release is unpacked")
if(NOT EXISTS "${FAF_ZSTD_DIR}/lib/zstd.h")
  message(FATAL_ERROR "Dependencies: zstd not found in ${FAF_ZSTD_DIR}")
endif()

file(GLOB _zstd_sources CONFIGURE_DEPENDS
  "${FAF_ZSTD_DIR}/lib/common/*.c"
  "${FAF_ZSTD_DIR}/lib/compress/*.c"
  "${FAF_ZSTD_DIR}/lib/decompress/*.c")
add_library(faf_zstd STATIC ${_zstd_sources})
target_include_directories(faf_zstd SYSTEM PUBLIC "${FAF_ZSTD_DIR}/lib")
target_compile_definitions(faf_zstd PRIVATE ZSTD_DISABLE_ASM=1 ZSTD_LEGACY_SUPPORT=0)
if(FAF_LINUX)
  target_compile_options(faf_zstd PRIVATE -w)
else()
  target_compile_options(faf_zstd PRIVATE /W0)
endif()
target_link_libraries(faf_zstd PRIVATE faf_codegen)
set_target_properties(faf_zstd PROPERTIES FOLDER "dependencies")
