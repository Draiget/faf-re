# Unit tests for gpg/core: streams, binary readers and writers, hashes, archives,
# the small utils and the timer. They make their own inputs; files go to a
# temporary folder each test removes.
#
#   cmake --build --preset clang-x64-release --target faf_core_tests
#   ctest --test-dir build/clang-x64-release -L Core --output-on-failure
add_executable(faf_core_tests EXCLUDE_FROM_ALL
  CoreTestSupport.cpp
  StreamTests.cpp
  BinaryIoTests.cpp
  IoStreamTests.cpp
  HashTests.cpp
  ArchiveTests.cpp
  UtilTests.cpp
  StatItemTests.cpp
)
target_link_libraries(faf_core_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_core_tests PROPERTIES FOLDER "Tests/Core")
add_test(NAME core COMMAND faf_core_tests)
set_tests_properties(core PROPERTIES LABELS "Core")
