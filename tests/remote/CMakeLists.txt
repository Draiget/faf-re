# Server-mode wire-format tests (src/remote/wire, plan WP7, WPR.38). The code under test is
# compiled into faf_engine only with FAF_SERVER_MODE, so the target exists only then:
#
#   cmake --build --preset clang-x64-release-server --target faf_remote_tests
#   ctest --test-dir build/clang-x64-release-server -R remote

# The net channel (src/remote/net) is in every build, and so are its tests:
#
#   cmake --build --preset clang-x64-release --target faf_netchannel_tests
if(TARGET faf_netchannel)
  add_executable(faf_netchannel_tests EXCLUDE_FROM_ALL net/NetChannelTests.cpp)
  # Monocypher directly too: the known-answer test calls it.
  target_link_libraries(faf_netchannel_tests PRIVATE faf_netchannel faf_monocypher gtest_main)
  target_compile_options(faf_netchannel_tests PRIVATE /EHsc)
  set_target_properties(faf_netchannel_tests PROPERTIES FOLDER "Tests/Existing")
  add_test(NAME remote_netchannel COMMAND faf_netchannel_tests)
  set_tests_properties(remote_netchannel PROPERTIES LABELS "Existing")

  # The server's player links over real UDP sockets on loopback (plan WP10.1); Linux builds it in cmake/FafLinux.cmake.
  if(WIN32)
    add_executable(faf_gamelink_tests EXCLUDE_FROM_ALL net/GameLinkTests.cpp)
    target_link_libraries(faf_gamelink_tests PRIVATE faf_netchannel faf_monocypher gtest_main)
    target_compile_options(faf_gamelink_tests PRIVATE /EHsc)
    set_target_properties(faf_gamelink_tests PROPERTIES FOLDER "Tests/Existing")
    add_test(NAME remote_gamelink COMMAND faf_gamelink_tests)
    set_tests_properties(remote_gamelink PROPERTIES LABELS "Existing")
  endif()
endif()

if(FAF_SERVER_MODE)
  add_executable(faf_remote_tests EXCLUDE_FROM_ALL WireTests.cpp)
  target_link_libraries(faf_remote_tests PRIVATE faf_engine gtest_main)
  target_compile_definitions(faf_remote_tests PRIVATE FAF_SERVER_MODE=1)
  set_target_properties(faf_remote_tests PROPERTIES FOLDER "Tests/Existing")
  add_test(NAME remote_wire COMMAND faf_remote_tests)
  set_tests_properties(remote_wire PROPERTIES LABELS "Existing")
endif()
