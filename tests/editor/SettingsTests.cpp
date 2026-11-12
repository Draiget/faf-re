// The map editor's settings.ini (src/editor/ui/EdSettings.cpp): defaults, values a setting takes and refuses, the
// file read with what it can't use said, and written with every setting.

#include "editor/ui/EdSettings.h"

#include <gtest/gtest.h>

using faf::editor::EdSettings;

namespace
{
  TEST(
    Settings,
    Defaults
  )
  {
    const EdSettings settings;
    EXPECT_EQ(settings.Get(EdSettings::kTitleBar), "own");
    EXPECT_EQ(settings.Get(EdSettings::kRenderer), "auto");
    EXPECT_EQ(settings.GetInt(EdSettings::kBackgroundFps), 30);
    EXPECT_FALSE(settings.GetBool(EdSettings::kFullHelp));
    EXPECT_TRUE(settings.GetBool(EdSettings::kPanelsWhilePlaying));
    EXPECT_EQ(settings.Get("Nope"), "");
  }

  TEST(
    Settings,
    OnlyValuesASettingTakes
  )
  {
    EdSettings settings;
    EXPECT_TRUE(settings.Set(EdSettings::kRenderer, "vulkan"));
    EXPECT_EQ(settings.Get(EdSettings::kRenderer), "vulkan");
    EXPECT_FALSE(settings.Set(EdSettings::kRenderer, "d3d9")) << "the editor runs on D3D12 and Vulkan only";
    EXPECT_EQ(settings.Get(EdSettings::kRenderer), "vulkan") << "refused: unchanged";
    EXPECT_FALSE(settings.SetInt(EdSettings::kBackgroundFps, 25));
    EXPECT_TRUE(settings.SetInt(EdSettings::kBackgroundFps, 0));
    EXPECT_FALSE(settings.Set(EdSettings::kFullHelp, "yes"));
    EXPECT_TRUE(settings.SetBool(EdSettings::kFullHelp, true));
    EXPECT_FALSE(settings.Set("Nope", "1"));
    EXPECT_EQ(EdSettings::Allowed(EdSettings::kTitleBar), (std::vector<std::string>{"own", "windows"}));
  }

  TEST(
    Settings,
    ReadSaysWhatItCantUseAndWriteHasEverything
  )
  {
    EdSettings settings;
    const auto problems = settings.Read(
      "; comment\r\n[Settings]\r\nTitleBar = windows\r\nRenderer=d3d9\r\nColour=blue\r\nBackgroundFps=10\r\n"
    );
    ASSERT_EQ(problems.size(), 2u);
    EXPECT_NE(problems[0].find("Renderer can't be \"d3d9\""), std::string::npos) << problems[0];
    EXPECT_NE(problems[1].find("no setting \"Colour\""), std::string::npos) << problems[1];
    EXPECT_EQ(settings.Get(EdSettings::kTitleBar), "windows");
    EXPECT_EQ(settings.Get(EdSettings::kRenderer), "auto") << "a value it can't take leaves the default";
    EXPECT_EQ(settings.GetInt(EdSettings::kBackgroundFps), 10);

    const std::string text = settings.Write();
    for (const char* const line :
         {"TitleBar=windows\n", "Renderer=auto\n", "BackgroundFps=10\n", "FullHelp=0\n", "PanelsWhilePlaying=1\n"}) {
      EXPECT_NE(text.find(line), std::string::npos) << line << " in\n" << text;
    }
    EdSettings again;
    EXPECT_TRUE(again.Read(text).empty());
    EXPECT_EQ(again.Write(), text);
  }
} // namespace
