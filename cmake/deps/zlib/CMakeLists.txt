# zlib 1.2.3, the version the shipped binary carries (main.vcxproj links it on
# x64; Win32 links wx's 1.1.4, see cmake/deps/wxwindows).
#
# dependencies/zlib-1.2.3 is not a source tree: it holds the two public headers
# (include/zconf.h carries the FAF HAVE_UNISTD_H change), two annotated sources
# and a prebuilt /MD zlib.lib (dependencies/patches/zlib_1_2_3_faf_required.md).
# The library is rebuilt here from the upstream release, with the
# dependencies/ headers first on the include path, as the same twelve objects
# the prebuilt zlib.lib contains.
#
# The release archive is fetched at configure time and checked against the
# hash docker/deps.lock.json pins. For an offline build, point
# FAF_ZLIB123_SOURCE_DIR at an extracted zlib-1.2.3, or FAF_ZLIB123_ARCHIVE at
# the tarball.

set(FAF_ZLIB123_SOURCE_DIR "" CACHE PATH "Extracted zlib-1.2.3 release (optional; fetched otherwise)")
set(FAF_ZLIB123_ARCHIVE "https://zlib.net/fossils/zlib-1.2.3.tar.gz" CACHE STRING
    "zlib-1.2.3.tar.gz URL or local path, used when FAF_ZLIB123_SOURCE_DIR is empty")

if(FAF_ZLIB123_SOURCE_DIR)
  set(_zlib_src "${FAF_ZLIB123_SOURCE_DIR}")
else()
  include(FetchContent)
  FetchContent_Declare(faf_zlib123
    URL "${FAF_ZLIB123_ARCHIVE}"
    URL_HASH SHA256=1795c7d067a43174113fdf03447532f373e1c6c57c08d61d9e4e9be5e244b05e
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  # zlib 1.2.3 predates zlib's CMake support, so this only downloads and
  # extracts it; the library is defined below.
  FetchContent_MakeAvailable(faf_zlib123)
  set(_zlib_src "${faf_zlib123_SOURCE_DIR}")
endif()
if(NOT EXISTS "${_zlib_src}/deflate.c")
  message(FATAL_ERROR "zlib 1.2.3 sources not found in ${_zlib_src}")
endif()

add_library(zlib123 STATIC
  "${_zlib_src}/adler32.c" "${_zlib_src}/compress.c" "${_zlib_src}/crc32.c"
  "${_zlib_src}/deflate.c" "${_zlib_src}/gzio.c" "${_zlib_src}/infback.c"
  "${_zlib_src}/inffast.c" "${_zlib_src}/inflate.c" "${_zlib_src}/inftrees.c"
  "${_zlib_src}/trees.c" "${_zlib_src}/uncompr.c" "${_zlib_src}/zutil.c")
target_include_directories(zlib123
  PUBLIC "${FAF_DEPENDENCIES_DIR}/zlib-1.2.3/include"
  PRIVATE "${_zlib_src}")
target_compile_definitions(zlib123 PRIVATE _CRT_SECURE_NO_DEPRECATE _CRT_NONSTDC_NO_DEPRECATE)
target_compile_options(zlib123 PRIVATE /W0)
target_link_libraries(zlib123 PRIVATE faf_codegen)
set_target_properties(zlib123 PROPERTIES FOLDER "dependencies")
