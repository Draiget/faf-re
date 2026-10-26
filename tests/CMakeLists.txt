# Engine tests: console programs linked against the engine's own objects
# (faf_engine, src/CMakeLists.txt). Not part of the default build:
#
#   cmake --build --preset clang-x64-release --target faf_net_tests
#   ctest --test-dir build/clang-x64-release

add_executable(faf_net_tests EXCLUDE_FROM_ALL net/NetRobustnessTests.cpp)
target_link_libraries(faf_net_tests PRIVATE faf_engine)

add_test(NAME net_robustness COMMAND faf_net_tests)

add_executable(faf_slab_tests EXCLUDE_FROM_ALL entity/FixedSlabPoolTests.cpp)
target_link_libraries(faf_slab_tests PRIVATE faf_engine)

add_test(NAME slab_tests COMMAND faf_slab_tests)
