// Command-line option lookup (moho/misc/StartupHelpers.cpp): CFG_GetArgOption, CFG_GetArgs and the alias helpers the
// window and adapter options go through. Each test swaps the C runtime's __argc/__argv for its own list and restores
// them afterwards.
//
// CFG_GetArgOption follows retail 0x0041B560: arguments from index 1 are compared with _stricmp (0x00AA549E), only
// positions that still have `requiredArgCount` arguments after them are tried (the loop bound is __argc minus the
// count), and on a match the out vector is cleared (0x0041BBC0) and gets the following arguments in order.
// CFG_GetArgs follows 0x0041B690: argv[1..] joined with single spaces.

#include <cstdlib>
#include <vector>
#include <gtest/gtest.h>

#include "gpg/core/containers/String.h"
#include "moho/misc/StartupHelpers.h"

namespace
{
  class ArgsFixture : public ::testing::Test
  {
  protected:
    void TearDown() override
    {
      if (mSwapped) {
        __argc = mSavedArgc;
        __argv = mSavedArgv;
      }
    }

    void SetArgs(
      std::initializer_list<const char*> args
    )
    {
      if (!mSwapped) {
        mSavedArgc = __argc;
        mSavedArgv = __argv;
        mSwapped = true;
      }
      mStorage.assign(args.begin(), args.end());
      mPointers.clear();
      for (const char* arg : mStorage) {
        mPointers.push_back(const_cast<char*>(arg));
      }
      mPointers.push_back(nullptr);
      __argc = static_cast<int>(mStorage.size());
      __argv = mPointers.data();
    }

  private:
    bool mSwapped = false;
    int mSavedArgc = 0;
    char** mSavedArgv = nullptr;
    std::vector<const char*> mStorage;
    std::vector<char*> mPointers;
  };
} // namespace

TEST_F(
  ArgsFixture,
  FindsAnOptionIgnoringCase
)
{
  SetArgs({"game.exe", "/windowed", "1024", "768", "/NoSound"});
  EXPECT_TRUE(moho::CFG_GetArgOption("/nosound", 0, nullptr));
  EXPECT_TRUE(moho::CFG_GetArgOption("/WINDOWED", 0, nullptr));
  EXPECT_FALSE(moho::CFG_GetArgOption("/nomovie", 0, nullptr));
  // argv[0], the program, is never an option.
  EXPECT_FALSE(moho::CFG_GetArgOption("game.exe", 0, nullptr));
}

TEST_F(
  ArgsFixture,
  CopiesTheFollowingArguments
)
{
  SetArgs({"game.exe", "/windowed", "1024", "768", "/nosound"});
  fa::vector<fa::string> args;
  args.push_back(fa::string("stale"));
  ASSERT_TRUE(moho::CFG_GetArgOption("/windowed", 2, &args));
  ASSERT_EQ(args.size(), 2u);
  EXPECT_STREQ(args[0].c_str(), "1024");
  EXPECT_STREQ(args[1].c_str(), "768");

  // Fewer arguments than asked for after the option: no match, and the vector is left alone.
  args.clear();
  args.push_back(fa::string("kept"));
  EXPECT_FALSE(moho::CFG_GetArgOption("/nosound", 1, &args));
  ASSERT_EQ(args.size(), 1u);
  EXPECT_STREQ(args[0].c_str(), "kept");
  EXPECT_TRUE(moho::CFG_GetArgOption("/windowed", 3, nullptr));
  EXPECT_FALSE(moho::CFG_GetArgOption("/windowed", 4, nullptr));
}

TEST_F(
  ArgsFixture,
  AnOptionTooCloseToTheEndIsSkipped
)
{
  // "/log" is last, so it has no argument after it: retail's loop bound never reaches it with a count of 1.
  SetArgs({"game.exe", "/map", "SCMP_001", "/log"});
  fa::vector<fa::string> args;
  ASSERT_TRUE(moho::CFG_GetArgOption("/map", 1, &args));
  ASSERT_EQ(args.size(), 1u);
  EXPECT_STREQ(args[0].c_str(), "SCMP_001");
  EXPECT_FALSE(moho::CFG_GetArgOption("/log", 1, nullptr));
  EXPECT_TRUE(moho::CFG_GetArgOption("/log", 0, nullptr));

  // The same option twice: the first one with enough arguments after it wins.
  SetArgs({"game.exe", "/map", "A", "/x", "/map", "B"});
  ASSERT_TRUE(moho::CFG_GetArgOption("/map", 2, &args));
  ASSERT_EQ(args.size(), 2u);
  EXPECT_STREQ(args[0].c_str(), "A");
  ASSERT_TRUE(moho::CFG_GetArgOption("/map", 1, &args));
  EXPECT_STREQ(args[0].c_str(), "A");
}

TEST_F(
  ArgsFixture,
  EmptyOrNullOptionNeverMatches
)
{
  SetArgs({"game.exe", "/a"});
  EXPECT_FALSE(moho::CFG_GetArgOption(nullptr, 0, nullptr));
  EXPECT_FALSE(moho::CFG_GetArgOption("", 0, nullptr));
}

TEST_F(
  ArgsFixture,
  GetArgsJoinsWithSingleSpaces
)
{
  SetArgs({"game.exe", "/init", "init_faf.lua", "/log", "x.log"});
  EXPECT_STREQ(moho::CFG_GetArgs().c_str(), "/init init_faf.lua /log x.log");
  SetArgs({"game.exe"});
  EXPECT_STREQ(moho::CFG_GetArgs().c_str(), "");
}

TEST_F(
  ArgsFixture,
  AliasesTryEveryPrefix
)
{
  const moho::CfgAliasSet& prefixes = moho::CFG_GetOptionPrefixes();
  ASSERT_GT(prefixes.count, 0u);
  for (std::size_t i = 0; i < prefixes.count; ++i) {
    const fa::string option = gpg::STR_Printf("%smaximized", prefixes.values[i]);
    SetArgs({"game.exe", option.c_str()});
    EXPECT_TRUE(moho::CFG_HasMaximizeOption()) << option.c_str();
  }
  SetArgs({"game.exe", "maximize"});
  EXPECT_FALSE(moho::CFG_HasMaximizeOption());
  SetArgs({"game.exe", "/windowed"});
  EXPECT_FALSE(moho::CFG_HasMaximizeOption());
}

TEST_F(
  ArgsFixture,
  AliasesCopyTheirArguments
)
{
  SetArgs({"game.exe", "-Window", "800", "600"});
  fa::vector<fa::string> args;
  ASSERT_TRUE(moho::CFG_GetArgOptionAliases(moho::CFG_GetWindowedOptionAliases(), 2, &args));
  ASSERT_EQ(args.size(), 2u);
  EXPECT_STREQ(args[0].c_str(), "800");
  EXPECT_STREQ(args[1].c_str(), "600");
  EXPECT_FALSE(moho::CFG_GetArgOptionAliases(moho::CFG_GetWindowedOptionAliases(), 3, nullptr));
  EXPECT_FALSE(moho::CFG_GetArgOptionAliases(moho::CFG_GetFullscreenOptionAliases(), 0, nullptr));

  SetArgs({"game.exe", "/adapter", "1"});
  EXPECT_TRUE(moho::CFG_GetArgOptionAliases(moho::CFG_GetAdapterOptionAliases(), 1, &args));
  ASSERT_EQ(args.size(), 1u);
  EXPECT_STREQ(args[0].c_str(), "1");

  const moho::CfgAliasSet empty{nullptr, 0};
  EXPECT_FALSE(moho::CFG_GetArgOptionAliases(empty, 0, nullptr));
}

TEST_F(
  ArgsFixture,
  ComposedAliasesJoinLeftAndRight
)
{
  // "/dualhead", "+multimonitor", "-twodisplay": every prefix, left alias and right alias combination.
  for (const char* option : {"/dualhead", "+multimonitor", "-twodisplay", "\\multimon"}) {
    SetArgs({"game.exe", option});
    EXPECT_TRUE(
      moho::CFG_GetArgOptionComposedAliases(
        moho::CFG_GetDualOptionAliases(), moho::CFG_GetHeadOptionAliases(), 0, nullptr
      )
    ) << option;
  }
  SetArgs({"game.exe", "/dual"});
  EXPECT_FALSE(
    moho::CFG_GetArgOptionComposedAliases(
      moho::CFG_GetDualOptionAliases(), moho::CFG_GetHeadOptionAliases(), 0, nullptr
    )
  );
  const moho::CfgAliasSet empty{nullptr, 0};
  EXPECT_FALSE(moho::CFG_GetArgOptionComposedAliases(empty, moho::CFG_GetHeadOptionAliases(), 0, nullptr));
}
