// The disk watch (src/moho/misc/CDiskWatch.cpp): FILE_Wild's wildcard matching, the listener's pattern filter and
// pending-event hand-over, and on Windows a real directory watch that reports a file written into a temp folder.
//
// FILE_Wild expectations come from the retail binary: FILE_Wild 0x00411320 throws "Moho::FILE_Wild: Null argument."
// on a null or empty path or pattern, appends "." (0x00E0077C) to a path that has no dot, then tries each
// ';'-separated pattern with the matcher 0x00411500, whose '*' and '?' recurse and whose other characters compare
// through tolower (0x00A831E3), so matching ignores case.

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <thread>
#include <gtest/gtest.h>

#include "gpg/core/containers/String.h"
#include "moho/misc/CDiskWatch.h"
#include "moho/misc/XFileError.h"
#include "platform/PlatformDefines.h"

#if FAFRE_PLATFORM_WINDOWS
#include <Windows.h>
#endif

namespace
{
  bool Wild(
    const char* path,
    const char* pattern
  )
  {
    return moho::FILE_Wild(path, pattern);
  }

  moho::SDiskWatchEvent EventFor(
    const char* path,
    const int action
  )
  {
    moho::SDiskWatchEvent event{};
    event.mPath = path;
    event.mActionCode = action;
    return event;
  }
} // namespace

TEST(
  FileWild,
  StarMatchesAnyRun
)
{
  EXPECT_TRUE(Wild("C:\\game\\lua\\unit.lua", "*.lua"));
  EXPECT_TRUE(Wild("unit.lua", "*"));
  EXPECT_TRUE(Wild("unit.lua", "*.*"));
  EXPECT_TRUE(Wild("unit.lua", "u*t.lua"));
  EXPECT_FALSE(Wild("unit.lua", "*.bp"));
  EXPECT_FALSE(Wild("unit.lua", "x*"));
}

TEST(
  FileWild,
  QuestionMarkMatchesExactlyOneCharacter
)
{
  EXPECT_TRUE(Wild("a1.lua", "a?.lua"));
  EXPECT_FALSE(Wild("a.lua", "a?.lua"));
  EXPECT_FALSE(Wild("a12.lua", "a?.lua"));
}

TEST(
  FileWild,
  IgnoresCase
)
{
  EXPECT_TRUE(Wild("C:\\Game\\UNIT.LUA", "*.lua"));
  EXPECT_TRUE(Wild("unit.lua", "UNIT.*"));
  // The case-sensitive flag is not read by retail either.
  EXPECT_TRUE(moho::FILE_Wild("UNIT.LUA", "unit.lua", true));
}

TEST(
  FileWild,
  PathWithoutDotGetsOne
)
{
  // "readme" is matched as "readme.".
  EXPECT_FALSE(Wild("readme", "readme"));
  EXPECT_TRUE(Wild("readme", "readme."));
  EXPECT_TRUE(Wild("readme", "*."));
  EXPECT_TRUE(Wild("readme", "*.*"));
  EXPECT_FALSE(Wild("readme.txt", "*."));
}

TEST(
  FileWild,
  SemicolonSeparatesPatterns
)
{
  EXPECT_TRUE(Wild("unit.bp", "*.lua;*.bp"));
  EXPECT_TRUE(Wild("unit.lua", "*.lua;*.bp"));
  EXPECT_FALSE(Wild("unit.dds", "*.lua;*.bp"));
  // An empty pattern after a trailing ';' matches only an empty path, which never gets that far.
  EXPECT_FALSE(Wild("unit.dds", "*.lua;"));
  EXPECT_TRUE(Wild("unit.dds", ";*.dds"));
}

TEST(
  FileWild,
  EmptyArgumentsThrow
)
{
  EXPECT_THROW(Wild("", "*"), moho::XFileError);
  EXPECT_THROW(Wild(nullptr, "*"), moho::XFileError);
  EXPECT_THROW(Wild("a.lua", ""), moho::XFileError);
  EXPECT_THROW(Wild("a.lua", nullptr), moho::XFileError);
  try {
    (void)Wild("", "*");
  } catch (const moho::XFileError& error) {
    EXPECT_NE(std::string(error.what()).find("Moho::FILE_Wild: Null argument."), std::string::npos) << error.what();
  }
}

TEST(
  DiskWatchListener,
  WithoutPatternsAcceptsEverything
)
{
  moho::CDiskWatchListener listener("");
  EXPECT_EQ(listener.mWatch, nullptr);
  EXPECT_TRUE(listener.mPatterns.empty());
  EXPECT_TRUE(listener.FilterEvent(EventFor("c:\\x\\a.dds", 1)));
}

TEST(
  DiskWatchListener,
  PatternsFilterEvents
)
{
  moho::CDiskWatchListener listener("");
  listener.mPatterns.push_back(fa::string("*.lua"));
  listener.mPatterns.push_back(fa::string("*.bp"));
  EXPECT_TRUE(listener.FilterEvent(EventFor("c:\\x\\a.lua", 3)));
  EXPECT_TRUE(listener.FilterEvent(EventFor("c:\\x\\A.BP", 3)));
  EXPECT_FALSE(listener.FilterEvent(EventFor("c:\\x\\a.dds", 3)));
}

TEST(
  DiskWatchListener,
  BroadcastDeliversOnlyMatchingEvents
)
{
  moho::CDiskWatch watch;
  moho::CDiskWatchListener lua("");
  lua.mPatterns.push_back(fa::string("*.lua"));
  moho::CDiskWatchListener all("");
  watch.AddListener(&lua);
  watch.AddListener(&all);
  EXPECT_EQ(lua.mWatch, &watch);
  EXPECT_FALSE(lua.AnyChangesPending());

  watch.mListeners.BroadcastEvent(EventFor("c:\\x\\a.lua", 3));
  watch.mListeners.BroadcastEvent(EventFor("c:\\x\\b.dds", 1));
  EXPECT_TRUE(lua.AnyChangesPending());
  EXPECT_TRUE(all.AnyChangesPending());

  fa::vector<moho::SDiskWatchEvent> events;
  lua.CopyAndClearPendingChanges(events);
  ASSERT_EQ(events.size(), 1u);
  EXPECT_STREQ(events[0].mPath.c_str(), "c:\\x\\a.lua");
  EXPECT_EQ(events[0].mActionCode, 3);
  EXPECT_FALSE(lua.AnyChangesPending());

  all.CopyAndClearPendingChanges(events);
  EXPECT_EQ(events.size(), 2u);

  // A removed listener hears nothing more and keeps no watch; its own pending list still works unlocked.
  watch.RemoveListener(&lua);
  EXPECT_EQ(lua.mWatch, nullptr);
  watch.mListeners.BroadcastEvent(EventFor("c:\\x\\c.lua", 3));
  EXPECT_FALSE(lua.AnyChangesPending());
  lua.CopyAndClearPendingChanges(events);
  EXPECT_TRUE(events.empty());
  all.CopyAndClearPendingChanges(events);
  EXPECT_EQ(events.size(), 1u);
  watch.RemoveListener(&all);
}

TEST(
  DiskWatch,
  RejectsEmptyAndUnknownDirectories
)
{
  moho::CDiskWatch watch;
  EXPECT_FALSE(watch.AddDirectory(""));
  EXPECT_FALSE(watch.RemoveDirectoryW("c:\\not\\watched"));
  const std::filesystem::path missing = std::filesystem::temp_directory_path() / "faf_diskwatch_missing_dir";
  EXPECT_FALSE(watch.AddDirectory(missing.string().c_str()));
  EXPECT_TRUE(watch.mDirWatchMap.empty());
}

#if FAFRE_PLATFORM_WINDOWS
TEST(
  DiskWatch,
  ReportsAFileWrittenIntoAWatchedDirectory
)
{
  const std::filesystem::path folder =
    std::filesystem::temp_directory_path() / ("faf_diskwatch_" + std::to_string(::GetCurrentProcessId()));
  std::filesystem::create_directories(folder);

  {
    moho::CDiskWatch watch;
    moho::CDiskWatchListener listener("");
    listener.mPatterns.push_back(fa::string("*.lua"));
    watch.AddListener(&listener);

    ASSERT_TRUE(watch.AddDirectory(folder.string().c_str()));
    // The same folder twice is refused, whatever its case.
    EXPECT_FALSE(watch.AddDirectory(gpg::STR_ToUpper(folder.string().c_str()).c_str()));
    EXPECT_EQ(watch.mDirWatchMap.size(), 1u);

    {
      FILE* file = std::fopen((folder / "changed.lua").string().c_str(), "wb");
      ASSERT_NE(file, nullptr);
      std::fputs("return 1\n", file);
      std::fclose(file);
      FILE* other = std::fopen((folder / "ignored.dds").string().c_str(), "wb");
      ASSERT_NE(other, nullptr);
      std::fclose(other);
    }

    // Events are held for 250 ms after they arrive before listeners hear them.
    fa::vector<moho::SDiskWatchEvent> events;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (events.empty() && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      watch.WatchQuery();
      listener.CopyAndClearPendingChanges(events);
    }
    ASSERT_FALSE(events.empty()) << "no event within 10 s";
    for (const auto& event : events) {
      const std::string path = event.mPath.c_str();
      EXPECT_NE(path.find("\\changed.lua"), std::string::npos) << path;
      // Added (1) or modified (3).
      EXPECT_TRUE(event.mActionCode == 1 || event.mActionCode == 3) << event.mActionCode;
    }

    EXPECT_TRUE(watch.RemoveDirectoryW(folder.string().c_str()));
    EXPECT_FALSE(watch.RemoveDirectoryW(folder.string().c_str()));
    watch.RemoveListener(&listener);
  }

  std::error_code ignored;
  std::filesystem::remove_all(folder, ignored);
}

TEST(
  DiskWatch,
  GlobalWatchAddsAndRemovesDirectories
)
{
  const std::filesystem::path folder =
    std::filesystem::temp_directory_path() / ("faf_diskwatch_g" + std::to_string(::GetCurrentProcessId()));
  std::filesystem::create_directories(folder);
  {
    moho::CDiskWatchListener listener("*.lua");
    EXPECT_NE(listener.mWatch, nullptr);
    EXPECT_TRUE(moho::DISK_AddWatchDirectory(folder.string().c_str()));
    moho::DISK_UpdateWatcher();
    EXPECT_TRUE(moho::DISK_RemoveWatchDirectory(folder.string().c_str()));
    EXPECT_FALSE(moho::DISK_RemoveWatchDirectory(folder.string().c_str()));
    moho::DISK_RemoveWatchListener(&listener);
    EXPECT_EQ(listener.mWatch, nullptr);
    moho::DISK_AddWatchListener(nullptr);
    moho::DISK_RemoveWatchListener(nullptr);
  }
  moho::DISK_ResetWatch();
  std::error_code ignored;
  std::filesystem::remove_all(folder, ignored);
}
#endif
