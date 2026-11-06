# GoogleTest 1.15.2 (BSD-3-Clause)
# Build googletest as a static library for engine tests.

set(FAF_GTEST_DIR "${FAF_DEPENDENCIES_DIR}/googletest" CACHE PATH "GoogleTest source directory")
if(NOT EXISTS "${FAF_GTEST_DIR}/CMakeLists.txt")
  message(STATUS "Dependencies: googletest not found in ${FAF_GTEST_DIR}")
  return()
endif()

set(BUILD_GMOCK OFF CACHE BOOL "Builds the googlemock subproject" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "Enable installation of googletest" FORCE)
set(gtest_force_shared_crt OFF CACHE BOOL "Use shared (DLL) run-time lib even when Google Test is built as static lib" FORCE)
set(gtest_build_tests OFF CACHE BOOL "Build all of gtest's own tests." FORCE)
set(gtest_build_samples OFF CACHE BOOL "Build gtest's sample programs." FORCE)

add_subdirectory("${FAF_GTEST_DIR}" "${CMAKE_BINARY_DIR}/dependencies/googletest" EXCLUDE_FROM_ALL)

if(TARGET gtest)
  set_target_properties(gtest PROPERTIES FOLDER "dependencies")
  if(MSVC)
    target_compile_options(gtest PRIVATE /EHsc /WX- -Wno-everything)
  endif()
endif()

if(TARGET gtest_main)
  set_target_properties(gtest_main PROPERTIES FOLDER "dependencies")
  if(MSVC)
    target_compile_options(gtest_main PRIVATE /EHsc /WX- -Wno-everything)
  endif()
endif()
