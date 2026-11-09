# The network layer's parts that need no socket: ping statistics, state and protocol names, dotted addresses, the
# peer features announcement and the rejoin seat key. The key test writes its key file in this build folder.
#
#   cmake --build --preset clang-x64-release --target faf_netcore_tests
#   ctest --test-dir build/clang-x64-release -L Net --output-on-failure
add_executable(faf_netcore_tests EXCLUDE_FROM_ALL NetCoreTests.cpp)
target_link_libraries(faf_netcore_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_netcore_tests PROPERTIES FOLDER "Tests/Net")
add_test(NAME netcore COMMAND faf_netcore_tests /rejoinkeyfile "${CMAKE_CURRENT_BINARY_DIR}/rejoin_test_seat.key")
set_tests_properties(netcore PROPERTIES LABELS "Net")
