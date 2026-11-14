// The shell's smaller parts: settings files (format, .bad, reset), data discovery, frame pacing, the tooltip check's
// tally, resource snapping.

#include "editor/doc/EdFafApi.h"
#include "editor/doc/EdSaveFile.h"
#include "editor/doc/EdUserFiles.h"
#include "editor/tools/EdMarkers.h"
#include "editor/ui/EdFramePacing.h"
#include "editor/ui/EdSettings.h"
#include "editor/ui/EdTipCheck.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <set>

namespace faf::editor
{
  TEST(
    UserFiles,
    FormatLine
  )
  {
    EXPECT_EQ(UserFileFormat("; comment\n[Settings]\nFormat=3\nTheme=x\n"), 3);
    EXPECT_EQ(UserFileFormat("format = 2\n"), 2);
    EXPECT_EQ(UserFileFormat("Theme=x\n"), 0);
  }

  TEST(
    UserFiles,
    SettingsWriteTheirFormatAndReadItBack
  )
  {
    EdSettings settings;
    const std::string text = settings.Write();
    EXPECT_NE(text.find("Format=1"), std::string::npos);
    EdSettings again;
    EXPECT_TRUE(again.Read(text).empty());
    EXPECT_EQ(again.FileFormat(), EdSettings::kFormatNow);
    EdSettings newer;
    (void)newer.Read("Format=9\nTitleBar=own\n");
    EXPECT_EQ(newer.FileFormat(), 9);
    EXPECT_TRUE(newer.Set(EdSettings::kIdleFps, "10"));
    EXPECT_FALSE(newer.Set(EdSettings::kIdleFps, "11"));
    EXPECT_TRUE(newer.GetBool(EdSettings::kPopouts));
  }

  TEST(
    UserFiles,
    BadCopyAndPutAside
  )
  {
    const std::filesystem::path folder = std::filesystem::temp_directory_path() / "faf_editor_userfiles_test";
    std::filesystem::remove_all(folder);
    std::filesystem::create_directories(folder);
    std::ofstream(folder / "settings.ini") << "Format=1\n";
    std::ofstream(folder / "keys.ini") << "x\n";
    const std::filesystem::path bad = KeepBadCopy(folder / "keys.ini");
    EXPECT_EQ(bad.filename().string(), "keys.ini.bad");
    EXPECT_TRUE(std::filesystem::exists(bad));
    EXPECT_EQ(PutUserSettingsAside(folder), 2);
    EXPECT_FALSE(std::filesystem::exists(folder / "settings.ini"));
    EXPECT_TRUE(std::filesystem::exists(folder / "settings.ini.reset"));
    EXPECT_TRUE(std::filesystem::exists(folder / "keys.ini.reset"));
    std::filesystem::remove_all(folder);
  }

  TEST(
    UserFiles,
    InitFileIsFoundInTheFafFolders
  )
  {
    const std::vector<std::filesystem::path> candidates = InitFileCandidates("C:/Games/FAF/bin_x64", "C:/ProgramData");
    ASSERT_GE(candidates.size(), 4U);
    EXPECT_EQ(candidates.front(), std::filesystem::path("C:/Games/FAF/bin_x64") / "init_faf.lua");
    const std::filesystem::path wanted = std::filesystem::path("C:/ProgramData") / "FAForever" / "bin" / "init_faf.lua";
    EXPECT_EQ(
      FindInitFile(
        candidates,
        [&](const std::filesystem::path& p) {
      return p == wanted;
    }
      ),
      wanted
    );
    EXPECT_TRUE(FindInitFile(candidates, [](const std::filesystem::path&) {
      return false;
    }).empty());
    EXPECT_TRUE(HasInitArgument({"FafEditor.exe", "/INIT", "x.lua"}));
    EXPECT_FALSE(HasInitArgument({"FafEditor.exe", "/log", "init.txt"}));
  }

  TEST(
    FramePacing,
    CapsByState
  )
  {
    PacingState s;
    EXPECT_EQ(PacedFps(s), 0); // in front, active
    s.secondsSinceInput = 5.0;
    EXPECT_EQ(PacedFps(s), 30); // idle
    s.loading = true;
    EXPECT_EQ(PacedFps(s), 60);
    s.foreground = false;
    s.backgroundFps = 10;
    EXPECT_EQ(PacedFps(s), 10);
    s.playing = true;
    EXPECT_EQ(PacedFps(s), 0);
    PacingState noIdle;
    noIdle.idleFps = 0;
    noIdle.secondsSinceInput = 99.0;
    EXPECT_EQ(PacedFps(noIdle), 0);
  }

  TEST(
    TipCheck,
    GridPointsAndTally
  )
  {
    const std::vector<TipPoint> points = TipCheckPoints({TipRect{"Tools", 0.0f, 0.0f, 28.0f, 14.0f}}, 14.0f);
    ASSERT_EQ(points.size(), 2U);
    EXPECT_FLOAT_EQ(points[0].x, 7.0f);
    EXPECT_FLOAT_EQ(points[1].x, 21.0f);
    EXPECT_EQ(points[0].window, "Tools");
    TipTally tally;
    tally.Record(5U, "Tools", 1.0f, 1.0f, false);
    tally.Record(5U, "Tools", 2.0f, 1.0f, true); // a later hover showed its tooltip
    tally.Record(6U, "Tools", 3.0f, 1.0f, false);
    tally.Record(0U, "Tools", 4.0f, 1.0f, false); // nothing hovered
    EXPECT_EQ(tally.Controls().size(), 2U);
    EXPECT_EQ(tally.WithTooltip(), 1);
    ASSERT_EQ(tally.Missing().size(), 1U);
    EXPECT_EQ(tally.Missing()[0].id, 6U);
  }

  TEST(
    ResourceSnap,
    OffGridResourcesOnly
  )
  {
    const std::vector<SaveEntry> markers = {
      NewMarker(*FindMarkerType("Mass"), "Mass 01", 10.2f, 5.0f, 20.5f), // x off the cell's middle
      NewMarker(*FindMarkerType("Mass"), "Mass 02", 30.5f, 5.0f, 40.5f), // on it
      NewMarker(*FindMarkerType("Hydrocarbon"), "Hydro 01", 7.9f, 5.0f, 8.0f),
      NewMarker(*FindMarkerType("Blank Marker"), "ARMY_1", 3.3f, 5.0f, 3.3f) // not a resource
    };
    const std::vector<ResourceSnap> snaps = ResourceSnaps(markers);
    ASSERT_EQ(snaps.size(), 2U);
    EXPECT_EQ(snaps[0].name, "Mass 01");
    EXPECT_FLOAT_EQ(snaps[0].x, 10.5f);
    EXPECT_FLOAT_EQ(snaps[0].z, 20.5f);
    EXPECT_EQ(snaps[1].name, "Hydro 01");
    EXPECT_FLOAT_EQ(snaps[1].x, 7.5f);
    EXPECT_FLOAT_EQ(snaps[1].z, 8.5f);
  }
  TEST(
    VaultUpload,
    MultipartBodyAsTheClientSendsIt
  )
  {
    const std::string zip(
      "PK\x03\x04"
      "data",
      8
    );
    const std::string body = MapUploadBody("XyZ", "my_map.v0001.zip", zip, true);
    EXPECT_EQ(
      body.find("--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"my_map.v0001.zip\"\r\n"), 0U
    );
    EXPECT_NE(body.find("Content-Type: application/octet-stream\r\n\r\n" + zip + "\r\n--XyZ\r\n"), std::string::npos);
    EXPECT_NE(
      body.find("name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{\"isRanked\":true}"), std::string::npos
    );
    EXPECT_EQ(body.substr(body.size() - 9), "--XyZ--\r\n");
    EXPECT_NE(MapUploadBody("b", "m.zip", "z", false).find("{\"isRanked\":false}"), std::string::npos);
  }
} // namespace faf::editor
