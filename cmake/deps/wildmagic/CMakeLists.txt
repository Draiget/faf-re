# Wild Magic 3.8: its headers only.
#
# The engine keeps Wild Magic's vector, quaternion, box, sphere and segment types
# (header code, compiled with the engine's own flags). The library's compiled code
# it called - nine query classes, three constants and System::Memcpy - is engine
# code since dedicated-server plan WPR.21: src/moho/math/Wm3Queries.cpp computes
# the queries as the shipped binary's x87 build of Wild Magic did, and
# src/moho/math/Wm3FoundationStatics.cpp defines the rest. No Wild Magic library
# is built, and the Dx9 renderer and application layers (nothing in the engine
# referenced them) are gone with it. The tree is shared and read-only.

set(WM3_ROOT "${FAF_DEPENDENCIES_DIR}/WildMagic3p8")
set(WM3_FOUNDATION "${WM3_ROOT}/Foundation")
set(WM3_FOUNDATION_SUBDIRS
  Approximation Collision Containment Controllers Curves Detail Distance Effects
  ImageAnalysis Interpolation Intersection Math Meshes Miscellaneous Numerics
  ObjectSystem Physics RationalArithmetic SceneGraph Shaders SharedArrays Sorting
  Surfaces System Terrain Tessellation)
set(WM3_FOUNDATION_INCLUDES "${WM3_FOUNDATION}")
foreach(_dir IN LISTS WM3_FOUNDATION_SUBDIRS)
  list(APPEND WM3_FOUNDATION_INCLUDES "${WM3_FOUNDATION}/${_dir}")
endforeach()

add_library(Wm3Headers INTERFACE)
target_include_directories(Wm3Headers INTERFACE ${WM3_FOUNDATION_INCLUDES})
