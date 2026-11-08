# The fa:: (src/legacy/containers, src/legacy/algorithms) and gpg:: (src/gpg/core/containers)
# container templates, mostly checked against a std:: container driven by the same seeded
# operations. Tests named DISABLED_ show a suspected bug; their comments name it.
#
#   cmake --build --preset clang-x64-release --target faf_container_tests
#   ctest --test-dir build/clang-x64-release -L Containers
add_executable(faf_container_tests EXCLUDE_FROM_ALL
  GpgContainerTests.cpp
  GpgFastVectorTests.cpp
  GpgStringTests.cpp
  LegacyAlgorithmTests.cpp
  LegacyDequeTests.cpp
  LegacyHashMapTests.cpp
  LegacyListTests.cpp
  LegacyStringTests.cpp
  LegacyTreeTests.cpp
  LegacyVectorTests.cpp
)
target_link_libraries(faf_container_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_container_tests PROPERTIES FOLDER "Tests/Containers")
add_test(NAME containers COMMAND faf_container_tests)
set_tests_properties(containers PROPERTIES LABELS "Containers")
