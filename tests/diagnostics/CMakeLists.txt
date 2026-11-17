# The frame sampler (gpg/core/diagnostics/FrameSampler.cpp, Windows only), in a program of its own: it reads
# FAF_FRAME_SAMPLER once per process and then samples the marking thread from a thread it starts.
#
#   cmake --build --preset clang-x64-release --target faf_frame_sampler_tests
#   ctest --test-dir build/clang-x64-release -L Core --output-on-failure
add_executable(faf_frame_sampler_tests EXCLUDE_FROM_ALL FrameSamplerTests.cpp)
target_link_libraries(faf_frame_sampler_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_frame_sampler_tests PROPERTIES FOLDER "Tests/Core")
add_test(NAME frame_sampler COMMAND faf_frame_sampler_tests)
set_tests_properties(frame_sampler PROPERTIES LABELS "Core"
  ENVIRONMENT "FAF_FRAME_SAMPLER=10;FAF_FRAME_SAMPLER_DUMP=${CMAKE_CURRENT_BINARY_DIR}/frame_sampler")
