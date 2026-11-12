// The crash report's Lua section (src/lua/LuaCrashDump.cpp): every open VM is registered, named VMs and recorded
// script errors show up in it, a VM caught inside a Lua call shows its frames with chunk and line, and an address
// inside a VM's stack is placed in its slot. In the game this only runs from the crash handler, so a test is the only
// way it runs before a crash needs it. Windows only for now (its Linux build hasn't been checked).

#if FAFRE_PLATFORM_WINDOWS

#include "LuaTestSupport.h"

#include "lua/LuaCrashDump.h"

#include <cstdio>
#include <string>

namespace
{
  std::string gDump;

  std::string Capture(
    void (*write)(std::FILE*)
  )
  {
    std::FILE* const sink = std::tmpfile();
    if (sink == nullptr) {
      return {};
    }
    write(sink);
    std::fflush(sink);
    std::rewind(sink);
    std::string text;
    char buffer[512];
    while (std::fgets(buffer, sizeof(buffer), sink) != nullptr) {
      text += buffer;
    }
    std::fclose(sink);
    return text;
  }

  void WriteSection(
    std::FILE* const sink
  )
  {
    lua::WriteLuaCrashSection(sink, nullptr, nullptr);
  }

  // A C function a script calls: the section is written while the VM is inside the script's frames.
  int DumpFromInsideLua(
    lua_State* const
  )
  {
    gDump = Capture(&WriteSection);
    return 0;
  }
} // namespace

using faf_lua_tests::LuaFixture;

TEST_F(
  LuaFixture,
  CrashSectionListsTheVmItsNameAndRecordedErrors
)
{
  lua::NameLuaVm(L(), "crash-dump-test");
  lua::RecordLuaError(L(), "zoo: a recorded script error");
  const std::string section = Capture(&WriteSection);
  EXPECT_NE(section.find("registered VMs: "), std::string::npos) << section;
  EXPECT_NE(section.find("crash-dump-test"), std::string::npos) << section;
  EXPECT_NE(section.find("zoo: a recorded script error"), std::string::npos) << section;
}

TEST_F(
  LuaFixture,
  CrashSectionShowsTheFramesOfARunningScript
)
{
  lua::NameLuaVm(L(), "crash-dump-frames");
  lua_pushstring(L(), "dump");
  lua_pushcclosure(L(), &DumpFromInsideLua, 0);
  lua_settable(L(), LUA_GLOBALSINDEX);
  gDump.clear();
  Run("local function inner(n)\n  local t = { a = n }\n  dump()\n  return t.a\nend\nreturn inner(5)");
  ASSERT_FALSE(gDump.empty());
  EXPECT_NE(gDump.find("crash-dump-frames"), std::string::npos) << gDump;
  EXPECT_NE(gDump.find(" frame(s)"), std::string::npos) << gDump;
  EXPECT_NE(gDump.find(":3 (lineDefined=1"), std::string::npos) << gDump; // inner, at the dump() call
}

TEST(
  LuaCrashDump,
  AnAddressOutsideEveryVmIsLeftUnannotated
)
{
  int local = 0;
  std::FILE* const sink = std::tmpfile();
  ASSERT_NE(sink, nullptr);
  lua::AnnotateLuaAddress(sink, &local);
  lua::AnnotateLuaAddress(sink, nullptr);
  lua::AnnotateLuaAddress(nullptr, &local);
  EXPECT_EQ(std::ftell(sink), 0L);
  std::fclose(sink);
}

#endif
