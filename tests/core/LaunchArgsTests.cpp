// A match's switches from the in-game launcher (moho::CFG_SetLaunchArgs, .plans/ingame-launcher WP4): read by
// CFG_GetArgOption as if they were on the command line, and gone once cleared.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "moho/misc/StartupHelpers.h"

namespace
{
  struct LaunchArgsTest : testing::Test
  {
    void TearDown() override
    {
      moho::CFG_ClearLaunchArgs();
    }
  };
} // namespace

TEST_F(
  LaunchArgsTest,
  NoneSetMeansTheCommandLineAlone
)
{
  EXPECT_FALSE(moho::CFG_HasLaunchArgs());
  EXPECT_FALSE(moho::CFG_GetArgOption("/gpgnet", 1, nullptr));
}

TEST_F(
  LaunchArgsTest,
  SetSwitchesReadAsCommandLineSwitches
)
{
  moho::CFG_SetLaunchArgs({"/init", "init_faf.lua", "/gpgnet", "127.0.0.1:52114", "/mean", "1512.5", "/nativenet"});
  EXPECT_TRUE(moho::CFG_HasLaunchArgs());

  fa::vector<fa::string> values;
  ASSERT_TRUE(moho::CFG_GetArgOption("/gpgnet", 1, &values));
  ASSERT_EQ(values.size(), 1u);
  EXPECT_STREQ(values[0].c_str(), "127.0.0.1:52114");

  // Case-insensitive, as on the command line.
  ASSERT_TRUE(moho::CFG_GetArgOption("/MEAN", 1, &values));
  EXPECT_STREQ(values[0].c_str(), "1512.5");

  EXPECT_TRUE(moho::CFG_GetArgOption("/nativenet", 0, nullptr));
  // Not enough values after the last switch.
  EXPECT_FALSE(moho::CFG_GetArgOption("/nativenet", 1, &values));
  EXPECT_FALSE(moho::CFG_GetArgOption("/rejoin", 0, nullptr));
}

TEST_F(
  LaunchArgsTest,
  ClearedSwitchesAreGone
)
{
  moho::CFG_SetLaunchArgs({"/gpgnet", "127.0.0.1:1"});
  ASSERT_TRUE(moho::CFG_GetArgOption("/gpgnet", 1, nullptr));
  moho::CFG_ClearLaunchArgs();
  EXPECT_FALSE(moho::CFG_HasLaunchArgs());
  EXPECT_FALSE(moho::CFG_GetArgOption("/gpgnet", 1, nullptr));
}

TEST_F(
  LaunchArgsTest,
  ASecondMatchReplacesTheFirstOnesSwitches
)
{
  moho::CFG_SetLaunchArgs({"/gpgnet", "127.0.0.1:1", "/mean", "1000"});
  moho::CFG_SetLaunchArgs({"/gpgnet", "127.0.0.1:2"});
  fa::vector<fa::string> values;
  ASSERT_TRUE(moho::CFG_GetArgOption("/gpgnet", 1, &values));
  EXPECT_STREQ(values[0].c_str(), "127.0.0.1:2");
  EXPECT_FALSE(moho::CFG_GetArgOption("/mean", 1, nullptr));
}
