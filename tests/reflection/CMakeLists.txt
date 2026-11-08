# Unit tests for the reflection and serialization layer: the type registry, RRef and its adapters, pointer and
# container types (src/gpg/core/reflection), and the saved-game types through WriteArchive/ReadArchive
# (src/moho/serialization). They make their own inputs; archive files go to a temporary folder each test removes.
#
#   cmake --build --preset clang-x64-release --target faf_reflection_tests
#   ctest --test-dir build/clang-x64-release -L Reflection --output-on-failure
add_executable(faf_reflection_tests EXCLUDE_FROM_ALL
  ReflectionTestSupport.cpp
  RegistryTests.cpp
  RefTests.cpp
  PointerTypeTests.cpp
  SavedGameTests.cpp
)
target_link_libraries(faf_reflection_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_reflection_tests PROPERTIES FOLDER "Tests/Reflection")
add_test(NAME reflection COMMAND faf_reflection_tests)
set_tests_properties(reflection PROPERTIES LABELS "Reflection")
