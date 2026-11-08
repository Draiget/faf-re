# x86 allocator bounds on real reservations. The cases live in Global.cpp's own
# object (AllocatorBoundsNative.inl), so every Windows x86 build compiles them.
#
#   cmake --build --preset clang-x86-release --target faf_allocator_bounds_tests
#   ctest --test-dir build/clang-x86-release -R "^allocator_bounds_"
if(WIN32 AND FAF_TARGET_ARCH STREQUAL "x86")
  add_executable(faf_allocator_bounds_tests EXCLUDE_FROM_ALL AllocatorBoundsNative.cpp)
  target_link_libraries(faf_allocator_bounds_tests PRIVATE faf_engine gtest_main)
  target_link_options(faf_allocator_bounds_tests PRIVATE /LARGEADDRESSAWARE)
  foreach(_case IN ITEMS Normal Low High Map Separate)
    string(TOLOWER "${_case}" _name)
    add_test(NAME allocator_bounds_${_name} COMMAND faf_allocator_bounds_tests --gtest_filter=AllocatorBounds.${_case})
    set_tests_properties(allocator_bounds_${_name} PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE)
    # Exit 77 is deliberately NOT SKIP_RETURN_CODE: unavailable required evidence fails the gate.
  endforeach()
endif()

include(${CMAKE_CURRENT_LIST_DIR}/LuaArenaTests.cmake)
