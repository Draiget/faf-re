# msdfgen 1.13 (MIT, LICENSE.txt in the tree): generates MSDF glyphs for text (moho/render/font,
# issue #306). dependencies/msdfgen is the tag's source archive, pinned by SHA256 in
# cmake/FafDependencies.cmake. A static library of the generator and its font import, without the
# command line tool, the file writers or SVG and PNG support. FAF_MSDFGEN_DIR, as a variable or in
# the environment, is for a tree that can't write to its dependencies folder.

if(DEFINED ENV{FAF_MSDFGEN_DIR})
  set(FAF_MSDFGEN_DIR "$ENV{FAF_MSDFGEN_DIR}" CACHE PATH "Where the msdfgen release is unpacked")
else()
  set(FAF_MSDFGEN_DIR "${FAF_DEPENDENCIES_DIR}/msdfgen" CACHE PATH "Where the msdfgen release is unpacked")
endif()
if(NOT EXISTS "${FAF_MSDFGEN_DIR}/msdfgen.h")
  message(FATAL_ERROR "Dependencies: msdfgen not found in ${FAF_MSDFGEN_DIR}")
endif()

add_library(faf_msdfgen STATIC
  "${FAF_MSDFGEN_DIR}/core/Contour.cpp"
  "${FAF_MSDFGEN_DIR}/core/DistanceMapping.cpp"
  "${FAF_MSDFGEN_DIR}/core/EdgeHolder.cpp"
  "${FAF_MSDFGEN_DIR}/core/MSDFErrorCorrection.cpp"
  "${FAF_MSDFGEN_DIR}/core/Projection.cpp"
  "${FAF_MSDFGEN_DIR}/core/Scanline.cpp"
  "${FAF_MSDFGEN_DIR}/core/Shape.cpp"
  "${FAF_MSDFGEN_DIR}/core/contour-combiners.cpp"
  "${FAF_MSDFGEN_DIR}/core/convergent-curve-ordering.cpp"
  "${FAF_MSDFGEN_DIR}/core/edge-coloring.cpp"
  "${FAF_MSDFGEN_DIR}/core/edge-segments.cpp"
  "${FAF_MSDFGEN_DIR}/core/edge-selectors.cpp"
  "${FAF_MSDFGEN_DIR}/core/equation-solver.cpp"
  "${FAF_MSDFGEN_DIR}/core/msdf-error-correction.cpp"
  "${FAF_MSDFGEN_DIR}/core/msdfgen.cpp"
  "${FAF_MSDFGEN_DIR}/core/rasterization.cpp"
  "${FAF_MSDFGEN_DIR}/ext/import-font.cpp")
target_include_directories(faf_msdfgen SYSTEM PUBLIC "${FAF_MSDFGEN_DIR}")
# MSDFGEN_PUBLIC set: no generated msdfgen-config.h, these definitions stand in for it.
target_compile_definitions(faf_msdfgen
  PUBLIC MSDFGEN_PUBLIC= MSDFGEN_USE_CPP11 MSDFGEN_DISABLE_SVG MSDFGEN_DISABLE_PNG MSDFGEN_DISABLE_VARIABLE_FONTS)
if(FAF_LINUX)
  target_compile_options(faf_msdfgen PRIVATE -w)
else()
  target_compile_options(faf_msdfgen PRIVATE /W0)
endif()
target_link_libraries(faf_msdfgen PRIVATE faf_codegen faf_freetype)
set_target_properties(faf_msdfgen PROPERTIES FOLDER "dependencies")
