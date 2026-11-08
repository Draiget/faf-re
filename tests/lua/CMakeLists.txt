# Unit tests for src/lua, the game's Lua 5.0 / LuaPlus fork: the language through the parser and
# the VM, the standard libraries the game opens, the LuaObject C++ API, the SCR byte stream,
# string.dump and both collectors. Expected values come from the Lua 5.0 reference manual and,
# where the fork differs, from the retail binary (the tests cite the addresses).
#
#   cmake --build --preset clang-x64-release --target faf_lua_tests
#   ctest --test-dir build/clang-x64-release -L Lua --output-on-failure
#
# CoroutineTests.cpp and DamageCallbackStackTests.cpp in this folder are separate executables,
# registered in tests/CMakeLists.txt.
add_executable(faf_lua_tests EXCLUDE_FROM_ALL
  LuaTestSupport.cpp
  LuaLanguageTests.cpp
  LuaMetatableTests.cpp
  LuaParserTests.cpp
  LuaBaseLibTests.cpp
  LuaStringLibTests.cpp
  LuaTableLibTests.cpp
  LuaMathLibTests.cpp
  LuaDebugLibTests.cpp
  LuaObjectApiTests.cpp
  LuaSerializeTests.cpp
  LuaGcTests.cpp
)
target_link_libraries(faf_lua_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_lua_tests PROPERTIES FOLDER "Tests/Lua")
add_test(NAME lua COMMAND faf_lua_tests)
set_tests_properties(lua PROPERTIES LABELS "Lua")
