# GoogleTest 1.15.2 (BSD-3-Clause, LICENSE in the tree): the framework of the engine's tests
# (tests/README.md). dependencies/googletest is the tag's source archive, pinned by SHA256 in
# cmake/FafDependencies.cmake. gtest and gtest_main as static libraries on the project's static
# runtime (/MT), without gmock. FAF_GTEST_DIR, as a variable or in the environment, is for a tree
# that can't write to its dependencies folder.
#
# Not optional: faf_sim_math_tests links gtest and is part of every build (tests/CMakeLists.txt,
# cmake/FafLinux.cmake), so a missing tree stops the configure here instead of the link later.

if(DEFINED ENV{FAF_GTEST_DIR})
  set(FAF_GTEST_DIR "$ENV{FAF_GTEST_DIR}" CACHE PATH "Where the GoogleTest release is unpacked")
else()
  set(FAF_GTEST_DIR "${FAF_DEPENDENCIES_DIR}/googletest" CACHE PATH "Where the GoogleTest release is unpacked")
endif()
if(NOT EXISTS "${FAF_GTEST_DIR}/CMakeLists.txt")
  message(FATAL_ERROR "Dependencies: googletest not found in ${FAF_GTEST_DIR}")
endif()

set(BUILD_GMOCK OFF CACHE BOOL "Builds the googlemock subproject" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "Enable installation of googletest" FORCE)
set(gtest_force_shared_crt OFF CACHE BOOL "Use shared (DLL) run-time lib even when Google Test is built as static lib" FORCE)
set(gtest_build_tests OFF CACHE BOOL "Build all of gtest's own tests." FORCE)
set(gtest_build_samples OFF CACHE BOOL "Build gtest's sample programs." FORCE)

add_subdirectory("${FAF_GTEST_DIR}" "${CMAKE_BINARY_DIR}/dependencies/googletest" EXCLUDE_FROM_ALL)

foreach(_target gtest gtest_main)
  set_target_properties(${_target} PROPERTIES FOLDER "dependencies")
  if(MSVC)
    target_compile_options(${_target} PRIVATE /EHsc /WX- -Wno-everything)
  endif()
endforeach()
