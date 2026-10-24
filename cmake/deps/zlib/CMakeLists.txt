# zlib 1.2.3, the version the shipped binary carries (x64 links it; Win32 links
# wx's 1.1.4, see cmake/deps/wxwindows).
#
# dependencies/zlib-1.2.3 is the madler/zlib submodule at v1.2.3 with
# dependencies/patches/zlib_1_2_3_faf_required.patch applied (the FAF
# HAVE_UNISTD_H change in zconf.h plus provenance comments); see
# cmake/FafDependencies.cmake. The library is the same twelve objects the
# original prebuilt zlib.lib contained.

set(_zlib_src "${FAF_DEPENDENCIES_DIR}/zlib-1.2.3")
if(NOT EXISTS "${_zlib_src}/deflate.c")
  message(FATAL_ERROR "zlib 1.2.3 sources not found in ${_zlib_src} (git submodule update --init)")
endif()

add_library(zlib123 STATIC
  "${_zlib_src}/adler32.c" "${_zlib_src}/compress.c" "${_zlib_src}/crc32.c"
  "${_zlib_src}/deflate.c" "${_zlib_src}/gzio.c" "${_zlib_src}/infback.c"
  "${_zlib_src}/inffast.c" "${_zlib_src}/inflate.c" "${_zlib_src}/inftrees.c"
  "${_zlib_src}/trees.c" "${_zlib_src}/uncompr.c" "${_zlib_src}/zutil.c")
target_include_directories(zlib123 PUBLIC "${_zlib_src}")
target_compile_definitions(zlib123 PRIVATE _CRT_SECURE_NO_DEPRECATE _CRT_NONSTDC_NO_DEPRECATE)
target_compile_options(zlib123 PRIVATE /W0)
target_link_libraries(zlib123 PRIVATE faf_codegen)
set_target_properties(zlib123 PROPERTIES FOLDER "dependencies")
