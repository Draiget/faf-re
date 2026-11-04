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
  target_link_libraries(faf_netchannel_tests PRIVATE faf_netchannel faf_monocypher)
  target_compile_options(faf_netchannel_tests PRIVATE /EHsc)
  add_test(NAME remote_netchannel COMMAND faf_netchannel_tests)
endif()

if(FAF_SERVER_MODE)
  add_executable(faf_remote_tests EXCLUDE_FROM_ALL WireTests.cpp)
  target_link_libraries(faf_remote_tests PRIVATE faf_engine)
  target_compile_definitions(faf_remote_tests PRIVATE FAF_SERVER_MODE=1)
  add_test(NAME remote_wire COMMAND faf_remote_tests)
endif()
