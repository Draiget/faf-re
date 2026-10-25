# Server-mode wire-format tests (src/remote/wire, plan WP7, WPR.38). The code under test is
# compiled into faf_engine only with FAF_SERVER_MODE, so the target exists only then:
#
#   cmake --build --preset clang-x64-release-server --target faf_remote_tests
#   ctest --test-dir build/clang-x64-release-server -R remote

if(FAF_SERVER_MODE)
  add_executable(faf_remote_tests EXCLUDE_FROM_ALL WireTests.cpp)
  target_link_libraries(faf_remote_tests PRIVATE faf_engine)
  target_compile_definitions(faf_remote_tests PRIVATE FAF_SERVER_MODE=1)
  add_test(NAME remote_wire COMMAND faf_remote_tests)
endif()
