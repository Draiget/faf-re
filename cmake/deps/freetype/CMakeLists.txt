# FreeType 2.15.0 (FTL, docs/LICENSE.TXT in the tree): reads font outlines for MSDF text
# (moho/render/font, issue #306). dependencies/freetype is the release archive, pinned by SHA256 in
# cmake/FafDependencies.cmake. A static library with only the TrueType and CFF drivers: fonts can
# come from mods, so everything else a font can ask a parser to do stays out (config/, issue #305).
# FAF_FREETYPE_DIR, as a variable or in the environment, is for a tree that can't write to its
# dependencies folder.

if(DEFINED ENV{FAF_FREETYPE_DIR})
  set(FAF_FREETYPE_DIR "$ENV{FAF_FREETYPE_DIR}" CACHE PATH "Where the FreeType release is unpacked")
else()
  set(FAF_FREETYPE_DIR "${FAF_DEPENDENCIES_DIR}/freetype" CACHE PATH "Where the FreeType release is unpacked")
endif()
if(NOT EXISTS "${FAF_FREETYPE_DIR}/include/ft2build.h")
  message(FATAL_ERROR "Dependencies: FreeType not found in ${FAF_FREETYPE_DIR}")
endif()
# A tree from FAF_FREETYPE_DIR isn't patched by cmake/FafDependencies.cmake, and without this patch a
# mod's font that runs FreeType out of its capped memory crashes the game (dependencies/patches/freetype_2_15_0_faf_oom.md).
file(READ "${FAF_FREETYPE_DIR}/src/base/fthash.c" _faf_fthash)
string(FIND "${_faf_fthash}" "The free function walks `size` buckets" _faf_fthash_patched)
if(_faf_fthash_patched EQUAL -1)
  message(FATAL_ERROR "Dependencies: ${FAF_FREETYPE_DIR} lacks dependencies/patches/freetype_2_15_0_faf_oom.patch; "
                      "apply it there with git -c core.autocrlf=false apply")
endif()
unset(_faf_fthash)

add_library(faf_freetype STATIC
  "${FAF_FREETYPE_DIR}/src/autofit/autofit.c"
  "${FAF_FREETYPE_DIR}/src/base/ftbase.c"
  "${FAF_FREETYPE_DIR}/src/base/ftbitmap.c"
  "${FAF_FREETYPE_DIR}/src/base/ftdebug.c"
  "${FAF_FREETYPE_DIR}/src/base/ftinit.c"
  "${FAF_FREETYPE_DIR}/src/base/ftsystem.c"
  "${FAF_FREETYPE_DIR}/src/cff/cff.c"
  "${FAF_FREETYPE_DIR}/src/psaux/psaux.c"
  "${FAF_FREETYPE_DIR}/src/pshinter/pshinter.c"
  "${FAF_FREETYPE_DIR}/src/psnames/psnames.c"
  "${FAF_FREETYPE_DIR}/src/sfnt/sfnt.c"
  "${FAF_FREETYPE_DIR}/src/smooth/smooth.c"
  "${FAF_FREETYPE_DIR}/src/truetype/truetype.c")
target_include_directories(faf_freetype SYSTEM PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/config"
  "${FAF_FREETYPE_DIR}/include")
# Public: every file including FreeType's headers has to see the same options.
target_compile_definitions(faf_freetype
  PUBLIC "FT_CONFIG_OPTIONS_H=<faf_ftoption.h>" "FT_CONFIG_MODULES_H=<faf_ftmodule.h>"
  PRIVATE FT2_BUILD_LIBRARY)
if(FAF_LINUX)
  target_compile_options(faf_freetype PRIVATE -w)
else()
  target_compile_options(faf_freetype PRIVATE /W0)
endif()
target_link_libraries(faf_freetype PRIVATE faf_codegen)
set_target_properties(faf_freetype PROPERTIES FOLDER "dependencies")
