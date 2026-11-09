# Unit tests for the startup helpers (moho/misc/StartupHelpers.h): path splitting, joining and collapsing, map
# scenario names and the command-line resolution triple. Windows only, as the Linux build doesn't compile
# StartupHelpers.cpp.
#
#   cmake --build --preset clang-x64-release --target faf_startup_tests
#   ctest --test-dir build/clang-x64-release -L Startup --output-on-failure
add_executable(faf_startup_tests EXCLUDE_FROM_ALL
  StartupPathTests.cpp
)
target_link_libraries(faf_startup_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_startup_tests PROPERTIES FOLDER "Tests/Startup")
add_test(NAME startup COMMAND faf_startup_tests)
set_tests_properties(startup PROPERTIES LABELS "Startup")
