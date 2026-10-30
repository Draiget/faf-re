# Real engine regression test; baseline selects the pre-fix behavior.
add_executable(faf_tread_rotation_tests EXCLUDE_FROM_ALL RotationRepairTests.cpp)
target_link_libraries(faf_tread_rotation_tests PRIVATE faf_engine)
set(FAF_TREAD_ROTATION_VARIANT "candidate" CACHE STRING "baseline or candidate source expectation")
if(NOT FAF_TREAD_ROTATION_VARIANT MATCHES "^(baseline|candidate)$")
  message(FATAL_ERROR "Unknown tread rotation source variant")
endif()
add_test(NAME tread_rotation_guard COMMAND faf_tread_rotation_tests ${FAF_TREAD_ROTATION_VARIANT})
set_tests_properties(tread_rotation_guard PROPERTIES TIMEOUT 120)
