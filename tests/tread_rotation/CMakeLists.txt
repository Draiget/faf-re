# CTextureScroller::Tick on a real entity: tread scroll during in-place rotation.
add_executable(faf_tread_rotation_tests EXCLUDE_FROM_ALL RotationRepairTests.cpp)
target_link_libraries(faf_tread_rotation_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_tread_rotation_tests PROPERTIES FOLDER "Tests/Existing")
add_test(NAME tread_rotation_guard COMMAND faf_tread_rotation_tests)
set_tests_properties(tread_rotation_guard PROPERTIES TIMEOUT 120 LABELS "Existing")
