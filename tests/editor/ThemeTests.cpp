// The map editor's themes (src/editor/ui/EdTheme.cpp): colours in each spelling, a Lua theme file read as written, its
// mistakes reported without losing what it got right, the built-in themes, and a folder's themes over them.

#include "editor/ui/EdTheme.h"

#include <cmath>
#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

using faf::editor::BuiltInThemeSources;
using faf::editor::EdTheme;
using faf::editor::LoadThemes;
using faf::editor::ParseThemeColor;
using faf::editor::ReadTheme;

namespace
{
  [[nodiscard]] bool Near(
    const float a,
    const float b
  )
  {
    return std::fabs(a - b) < 0.002f;
  }

  TEST(
    Theme,
    ColoursInEachSpelling
  )
  {
    float c[4] = {};
    ASSERT_TRUE(ParseThemeColor("#4ea1ff", c));
    EXPECT_TRUE(Near(c[0], 0x4e / 255.0f) && Near(c[1], 0xa1 / 255.0f) && Near(c[2], 1.0f) && Near(c[3], 1.0f));
    ASSERT_TRUE(ParseThemeColor("1c1f25f7", c));
    EXPECT_TRUE(Near(c[3], 0xf7 / 255.0f));
    ASSERT_TRUE(ParseThemeColor("#fA0", c));
    EXPECT_TRUE(Near(c[0], 1.0f) && Near(c[1], 0xaa / 255.0f) && Near(c[2], 0.0f));
    EXPECT_FALSE(ParseThemeColor("#12345", c));
    EXPECT_FALSE(ParseThemeColor("#gg0000", c));
    EXPECT_FALSE(ParseThemeColor("", c));
  }

  TEST(
    Theme,
    ReadsWhatTheFileSays
  )
  {
    const EdTheme theme = ReadTheme(
      "Theme = { name = 'Mine', base = 'light', accent = '#ff8800', rounding = 6,"
      " colors = { WindowBg = '#ffffff', Text = { 0.1, 0.2, 0.3 }, Border = { 255, 0, 0, 128 } } }",
      "mine.lua"
    );
    EXPECT_TRUE(theme.problems.empty()) << (theme.problems.empty() ? "" : theme.problems[0]);
    EXPECT_EQ(theme.name, "Mine");
    EXPECT_TRUE(theme.light);
    ASSERT_TRUE(theme.hasAccent);
    EXPECT_TRUE(Near(theme.accent[1], 0x88 / 255.0f));
    EXPECT_EQ(theme.rounding, 6.0f);
    ASSERT_EQ(theme.colors.size(), 3u);
    // By name, whatever Lua's table order.
    EXPECT_EQ(theme.colors[0].name, "Border");
    EXPECT_TRUE(Near(theme.colors[0].rgba[0], 1.0f) && Near(theme.colors[0].rgba[3], 128 / 255.0f)) << "0..255 numbers";
    EXPECT_EQ(theme.colors[1].name, "Text");
    EXPECT_TRUE(Near(theme.colors[1].rgba[2], 0.3f) && Near(theme.colors[1].rgba[3], 1.0f)) << "0..1 numbers";
  }

  TEST(
    Theme,
    MistakesAreReportedAndTheRestKept
  )
  {
    const EdTheme broken = ReadTheme("Theme = { name = 'x' ", "broken.lua");
    ASSERT_EQ(broken.problems.size(), 1u);
    EXPECT_NE(broken.problems[0].find("broken.lua"), std::string::npos) << broken.problems[0];

    const EdTheme none = ReadTheme("Colours = {}", "none.lua");
    ASSERT_EQ(none.problems.size(), 1u);
    EXPECT_EQ(none.problems[0], "the file sets no Theme table");

    const EdTheme half =
      ReadTheme("Theme = { base = 'blue', colors = { WindowBg = 'nope', Text = '#fff' } }", "half.lua");
    EXPECT_EQ(half.problems.size(), 2u);
    ASSERT_EQ(half.colors.size(), 1u);
    EXPECT_EQ(half.colors[0].name, "Text");
    EXPECT_FALSE(half.light);
  }

  TEST(
    Theme,
    BuiltInThemesReadCleanly
  )
  {
    ASSERT_EQ(BuiltInThemeSources().size(), 3u);
    for (const std::string_view source : BuiltInThemeSources()) {
      const EdTheme theme = ReadTheme(std::string(source), "built-in");
      EXPECT_TRUE(theme.problems.empty()) << theme.name << ": " << (theme.problems.empty() ? "" : theme.problems[0]);
      EXPECT_FALSE(theme.name.empty());
      EXPECT_TRUE(theme.hasAccent);
      EXPECT_FALSE(theme.colors.empty());
    }
  }

  TEST(
    Theme,
    AFoldersThemesJoinAndReplaceBuiltIns
  )
  {
    const std::filesystem::path folder = std::filesystem::temp_directory_path() / "faf_editor_theme_tests";
    std::filesystem::create_directories(folder);
    std::ofstream(folder / "dark.lua") << "Theme = { name = 'Editor Dark', base = 'dark', accent = '#00ff00' }";
    std::ofstream(folder / "mine.lua") << "Theme = { base = 'light' }";
    std::ofstream(folder / "notes.txt") << "not a theme";
    const std::vector<EdTheme> themes = LoadThemes(folder);
    ASSERT_EQ(themes.size(), 4u);
    EXPECT_EQ(themes[0].name, "Editor Dark");
    EXPECT_TRUE(Near(themes[0].accent[1], 1.0f)) << "the folder's Editor Dark replaced the built-in";
    EXPECT_FALSE(themes[0].file.empty());
    EXPECT_EQ(themes[3].name, "mine") << "a theme without a name is called by its file";
    EXPECT_TRUE(themes[3].light);
    std::filesystem::remove_all(folder);
  }
} // namespace
