# Monocypher 4.0.2 (BSD-2-Clause or CC0, LICENCE.md in the tree): the net channel's
# authenticated encryption (src/remote/net, issue #145). dependencies/monocypher is the
# tag's source archive, pinned by SHA256 in cmake/FafDependencies.cmake. One C file.

set(_monocypher_src "${FAF_DEPENDENCIES_DIR}/monocypher/src")
if(NOT EXISTS "${_monocypher_src}/monocypher.c")
  # Nothing in the engine needs the net channel yet, so a tree fetched before it existed
  # (or configured with FAF_FETCH_DEPENDENCIES=OFF) still builds; the channel is left out.
  message(STATUS "Dependencies: Monocypher not found in ${_monocypher_src}; the net channel (src/remote/net) is not built")
  return()
endif()

add_library(faf_monocypher STATIC "${_monocypher_src}/monocypher.c")
target_include_directories(faf_monocypher SYSTEM PUBLIC "${_monocypher_src}")
if(FAF_LINUX)
  target_compile_options(faf_monocypher PRIVATE -w)
else()
  target_compile_options(faf_monocypher PRIVATE /W0)
endif()
target_link_libraries(faf_monocypher PRIVATE faf_codegen)
set_target_properties(faf_monocypher PROPERTIES FOLDER "dependencies")
