# Configure ONLY in an isolated, disposable native x86 build directory.
# The test seam is in the existing Global.cpp object: no duplicate Global symbols.
option(FAF_ALLOCATOR_BOUNDARY_TESTS "Enable test-only x86 allocator seam" OFF)
if(FAF_ALLOCATOR_BOUNDARY_TESTS)
  if(NOT WIN32 OR NOT FAF_TARGET_ARCH STREQUAL "x86" OR NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "Allocator boundary tests require native Windows x86")
  endif()
  target_compile_definitions(faf_engine PRIVATE FAF_ALLOCATOR_BOUNDARY_TESTS=1)
  add_executable(faf_allocator_bounds_tests EXCLUDE_FROM_ALL AllocatorBoundsNative.cpp)
  target_link_libraries(faf_allocator_bounds_tests PRIVATE faf_engine)
  target_link_options(faf_allocator_bounds_tests PRIVATE /LARGEADDRESSAWARE)
  foreach(_case IN ITEMS normal low high map separate)
    add_test(NAME allocator_bounds_${_case} COMMAND faf_allocator_bounds_tests ${_case})
    set_tests_properties(allocator_bounds_${_case} PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE)
    # Exit 77 is deliberately NOT SKIP_RETURN_CODE: unavailable required evidence fails the gate.
  endforeach()
endif()
