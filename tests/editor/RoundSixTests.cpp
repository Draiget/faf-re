// The fourth comparison with FAF Studio (brush target): marker heights in the Check, any-size new maps, the reference
// maps' numbers, the camera's mouse gestures in keys.ini, strata themes.

#include "editor/doc/EdNewMap.h"
#include "editor/doc/EdStrataThemes.h"
#include "editor/tools/EdChecks.h"
#include "editor/tools/EdInterop.h"
#include "editor/tools/EdMarkers.h"
#include "editor/ui/EdCommands.h"
#include "editor/ui/EdKeymap.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace
{
  using namespace faf::editor;

  float Ground(
    const void*,
    float,
    float
  )
  {
    return 10.0f;
  }

  TEST(
    RoundSix,
    MarkersOffTheGroundGetANoteWithTheToGroundFix
  )
  {
    // A path node 8 above the ground, one 2 above (within the slack), one 6 below.
    const std::vector<SaveEntry> markers = {
      NewMarker(*FindMarkerType("Land Path Node"), "LandPN 00", 50.0f, 18.0f, 50.0f),
      NewMarker(*FindMarkerType("Land Path Node"), "LandPN 01", 60.0f, 12.0f, 50.0f),
      NewMarker(*FindMarkerType("Air Path Node"), "AirPN 00", 70.0f, 4.0f, 50.0f),
    };
    MarkerCheckInput input;
    input.markers = &markers;
    input.groundAt = &Ground;
    input.width = 257;
    input.height = 257;
    int above = 0;
    int below = 0;
    for (const CheckIssue& issue : CheckMarkers(input)) {
      if (issue.fix != CheckIssue::Fix::ToGround) {
        continue;
      }
      EXPECT_STREQ(CheckFixName(issue.fix), "To ground");
      above += issue.marker == "LandPN 00" && issue.text.contains("8.0 above") ? 1 : 0;
      below += issue.marker == "AirPN 00" && issue.text.contains("6.0 below") ? 1 : 0;
      EXPECT_NE(issue.marker, "LandPN 01") << "2 units is within the slack";
      EXPECT_FLOAT_EQ(issue.fixX, issue.x);
    }
    EXPECT_EQ(above, 1);
    EXPECT_EQ(below, 1);
  }

  TEST(
    RoundSix,
    AnySizeMapsTakeTheTerrainThatHoldsThemAndCentreTheArea
  )
  {
    NewMapSettings settings;
    settings.widthKm = 7.5f;
    settings.depthKm = 12.0f;
    settings.players = 2;
    // 7.5 km = 384 units (in 512), 12 km = 614.4 -> 616 (in 1024).
    EXPECT_EQ(NewMapWidth(settings), 512);
    EXPECT_EQ(NewMapDepth(settings), 1024);
    const auto area = NewMapPlayable(settings);
    ASSERT_TRUE(area.has_value());
    EXPECT_EQ((*area)[2] - (*area)[0], 384);
    EXPECT_EQ((*area)[3] - (*area)[1], 616);
    EXPECT_EQ((*area)[0] % 4, 0);
    EXPECT_EQ((*area)[1] % 4, 0);
    for (const NewMapSpawn& spawn : NewMapSpawns(settings)) {
      EXPECT_GE(spawn.x, static_cast<float>((*area)[0]));
      EXPECT_LE(spawn.x, static_cast<float>((*area)[2]));
      EXPECT_GE(spawn.z, static_cast<float>((*area)[1]));
      EXPECT_LE(spawn.z, static_cast<float>((*area)[3]));
    }
    const std::string save = NewMapSaveText(settings);
    EXPECT_NE(save.find("['AREA_1']"), std::string::npos);
    EXPECT_NE(NewMapScriptText(true).find("SetPlayableArea('AREA_1'"), std::string::npos);
    // 10 km fills a 512 terrain: no area.
    settings.widthKm = settings.depthKm = 10.0f;
    EXPECT_FALSE(NewMapPlayable(settings).has_value());
    // The size list as before.
    NewMapSettings plain;
    EXPECT_FALSE(NewMapPlayable(plain).has_value());
    EXPECT_EQ(NewMapWidth(plain), kNewMapSizes[plain.size].units);
  }

  TEST(
    RoundSix,
    ReferenceMapsByTheirSize
  )
  {
    EXPECT_EQ(ReferenceStatsFor(512).size, 512);
    EXPECT_EQ(ReferenceStatsFor(512).n, 143);
    EXPECT_FLOAT_EQ(ReferenceStatsFor(512).relief[2], 30.8f);
    EXPECT_EQ(ReferenceStatsFor(1024).size, 1024);
    EXPECT_EQ(ReferenceStatsFor(4096).size, 0) << "too far from any size with numbers: all maps";
    const std::string tall = ReferenceAdvice(512, 80.0f, 9.0f);
    EXPECT_NE(tall.find("taller than 95 %"), std::string::npos) << tall;
    EXPECT_NE(tall.find("143 reference maps at 10 km"), std::string::npos) << tall;
  }

  TEST(
    RoundSix,
    CameraGesturesRoundTripThroughKeysIni
  )
  {
    EdCommands commands;
    ActiveCameraGestures() = DefaultCameraGestures();
    CameraGesture gesture = CameraGesture::Count;
    ASSERT_TRUE(CameraGestureFor(2, false, false, false, gesture));
    EXPECT_EQ(gesture, CameraGesture::Orbit);
    ASSERT_TRUE(CameraGestureFor(2, false, true, false, gesture));
    EXPECT_EQ(gesture, CameraGesture::Pan2);
    ASSERT_TRUE(CameraGestureFor(2, true, false, false, gesture));
    EXPECT_EQ(gesture, CameraGesture::Orbit) << "Ctrl + middle falls back to middle alone";
    // Zoom on Alt + right, written and read back.
    ActiveCameraGestures()[static_cast<std::size_t>(CameraGesture::Zoom)] = MouseChord{1, false, false, true};
    const std::string text = WriteKeymap(commands, {});
    EXPECT_NE(text.find("mouse.zoom=Alt+Right"), std::string::npos) << text;
    ActiveCameraGestures() = DefaultCameraGestures();
    EXPECT_TRUE(ReadKeymap(commands, text).empty());
    ASSERT_TRUE(CameraGestureFor(1, false, false, true, gesture));
    EXPECT_EQ(gesture, CameraGesture::Zoom);
    EXPECT_FALSE(ReadKeymap(commands, "mouse.zoom=Left\nmouse.spin=Right\n").empty()) << "Left and an unknown gesture";
    ActiveCameraGestures() = DefaultCameraGestures();
  }

  TEST(
    RoundSix,
    StrataThemesReadAndWriteBack
  )
  {
    const std::string shipped = "Themes = {\n"
                                "  { id = 'theme_x', name = 'X', group = 'Curated', layers = {\n"
                                "    [0] = { albedo = '/env/a_albedo.dds', size = 6 },\n"
                                "    [4] = { albedo = '/env/b_albedo.dds', normal = '/env/b_normal.dds', size = 8, "
                                "nsize = 8 } } },\n"
                                "  { id = 'empty', name = 'No layers', layers = { } },\n"
                                "}\n";
    std::vector<StrataTheme> themes;
    auto read = ParseStrataThemes(shipped, "Themes", themes);
    ASSERT_TRUE(read) << read.error();
    ASSERT_EQ(themes.size(), 1U) << "a theme without layers is left out";
    EXPECT_EQ(themes[0].layers.size(), 2U);
    EXPECT_EQ(themes[0].layers.at(4).normal, "/env/b_normal.dds");
    EXPECT_FLOAT_EQ(themes[0].layers.at(0).size, 6.0f);
    themes[0].id = StrataThemeId("My Theme 2");
    EXPECT_EQ(themes[0].id, "user_my_theme_2");
    std::vector<StrataTheme> back;
    read = ParseStrataThemes(WriteStrataThemes(themes), "UserThemes", back);
    ASSERT_TRUE(read) << read.error();
    ASSERT_EQ(back.size(), 1U);
    EXPECT_EQ(back[0].id, "user_my_theme_2");
    EXPECT_EQ(back[0].layers.at(4).albedo, "/env/b_albedo.dds");
    EXPECT_FLOAT_EQ(back[0].layers.at(4).nsize, 8.0f);
  }

  TEST(
    RoundSix,
    TheShippedThemeLibraryReads
  )
  {
#ifdef FAF_THEMES_DATA
    std::FILE* const file = std::fopen(FAF_THEMES_DATA, "rb");
    ASSERT_NE(file, nullptr);
    std::string text;
    char buffer[4096];
    for (std::size_t n; (n = std::fread(buffer, 1, sizeof(buffer), file)) > 0;) {
      text.append(buffer, n);
    }
    std::fclose(file);
    std::vector<StrataTheme> themes;
    auto read = ParseStrataThemes(text, "Themes", themes);
    ASSERT_TRUE(read) << read.error();
    EXPECT_EQ(themes.size(), 70U);
#else
    GTEST_SKIP() << "no data path";
#endif
  }
} // namespace
