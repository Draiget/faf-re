// The map editor's water bodies (src/editor/doc/EdWaterBodies.cpp): `ScenarioInfo.WaterBodies` read, edited in place,
// written, and turned into what the game fills.

#include "editor/doc/EdLuaText.h"
#include "editor/doc/EdWaterBodies.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace
{
  using faf::editor::WaterBody;

  // A scenario in the shape the game's maps have, with bodies the way tools/scenarios/water-levels writes them.
  const char* const kScenario = R"lua(version = 3 -- Lua Version. Dont touch this
ScenarioInfo = {
    name = "Lakes",
    WaterBodies = {
        { Elevation = 30, Deep = 28, Abyss = 25, Outline = { { 10, 10 }, { 20, 10 }, { 15, 20 } } },
        { Elevation = 23, Seed = { 152, 152 } }, -- a pool
        { Dry = true, FillTo = 3, Outline = { { 1, 1 }, { 9, 1 }, { 5, 9 } } },
    },
    description = 'Water at { many } levels',
    map = '/maps/lakes/lakes.scmap',
    preview = [[a long
string]],
    Configurations = {
        ['standard'] = {
            teams = { { name = 'FFA', armies = { 'ARMY_1', 'ARMY_2' } } },
            customprops = {
                ['ExtraArmies'] = STRING( 'ARMY_9 NEUTRAL_CIVILIAN' ),
            },
        },
    },
}
)lua";

  TEST(WaterBodiesEdit, LuaTextReadsFieldsItemsAndWhereTheyAre)
  {
    faf::editor::LuaText info;
    std::string error;
    ASSERT_TRUE(faf::editor::ReadLuaAssignment(kScenario, "ScenarioInfo", info, error)) << error;
    ASSERT_TRUE(info.isTable);
    const faf::editor::LuaText* const name = info.Field("name");
    ASSERT_NE(name, nullptr);
    EXPECT_EQ(name->atom, "\"Lakes\"");
    EXPECT_EQ(std::string(kScenario).substr(name->start, name->end - name->start), "\"Lakes\"");
    const faf::editor::LuaText* const configurations = info.Field("Configurations");
    ASSERT_NE(configurations, nullptr);
    const faf::editor::LuaText* const standard = configurations->Field("standard");
    ASSERT_NE(standard, nullptr);
    // Calls (the typed values retail maps write) and long strings are kept as their text.
    ASSERT_NE(standard->Field("customprops"), nullptr);
    ASSERT_NE(standard->Field("customprops")->Field("ExtraArmies"), nullptr);
    EXPECT_EQ(standard->Field("customprops")->Field("ExtraArmies")->atom, "STRING( 'ARMY_9 NEUTRAL_CIVILIAN' )");
    ASSERT_NE(info.Field("preview"), nullptr);
    EXPECT_EQ(info.Field("preview")->atom, "[[a long\nstring]]");
    // `version = 3` is the first top-level assignment, not inside ScenarioInfo.
    faf::editor::LuaText version;
    ASSERT_TRUE(faf::editor::ReadLuaAssignment(kScenario, "version", version, error));
    EXPECT_EQ(version.Number(), 3.0);
    EXPECT_FALSE(faf::editor::ReadLuaAssignment(kScenario, "teams", version, error)) << "teams is not top-level";
    EXPECT_EQ(faf::editor::LuaNumber(2.5), "2.5");
    EXPECT_EQ(faf::editor::LuaNumber(30.0), "30");
    EXPECT_EQ(faf::editor::LuaNumber(-0.0001), "0");
    EXPECT_EQ(faf::editor::LuaNumber(12.34567), "12.346");
  }

  TEST(WaterBodiesEdit, ReadsEachField)
  {
    const faf::editor::WaterBodiesRead read = faf::editor::ReadWaterBodies(kScenario);
    ASSERT_TRUE(read.error.empty()) << read.error;
    ASSERT_TRUE(read.present);
    ASSERT_EQ(read.bodies.size(), 3u);

    const WaterBody& crater = read.bodies[0];
    EXPECT_TRUE(crater.raw.empty());
    EXPECT_TRUE(crater.hasElevation);
    EXPECT_EQ(crater.elevation, 30.0f);
    EXPECT_TRUE(crater.hasDeep && crater.hasAbyss);
    EXPECT_EQ(crater.deep, 28.0f);
    EXPECT_EQ(crater.abyss, 25.0f);
    EXPECT_FALSE(crater.hasSeed);
    ASSERT_EQ(crater.outline.size(), 3u);
    EXPECT_EQ(crater.outline[2].first, 15.0f);
    EXPECT_EQ(crater.outline[2].second, 20.0f);

    const WaterBody& pool = read.bodies[1];
    EXPECT_TRUE(pool.hasSeed);
    EXPECT_EQ(pool.seedX, 152.0f);
    EXPECT_FALSE(pool.hasDeep || pool.hasFillTo || pool.hasBounds);

    const WaterBody& polder = read.bodies[2];
    EXPECT_TRUE(polder.dry);
    EXPECT_FALSE(polder.hasElevation);
    EXPECT_TRUE(polder.hasFillTo);
    EXPECT_EQ(polder.fillTo, 3.0f);
  }

  TEST(WaterBodiesEdit, ScenarioWithoutBodies)
  {
    const faf::editor::WaterBodiesRead read = faf::editor::ReadWaterBodies("ScenarioInfo = { name = 'x', map = '/maps/x.scmap' }\n");
    EXPECT_TRUE(read.error.empty());
    EXPECT_FALSE(read.present);
    EXPECT_TRUE(read.bodies.empty());
    EXPECT_FALSE(faf::editor::ReadWaterBodies("-- nothing here\n").error.empty());
  }

  TEST(WaterBodiesEdit, UnreadableBodyIsKeptAsItsText)
  {
    const std::string scenario = "ScenarioInfo = {\n    WaterBodies = {\n        { Elevation = 20 + 5, Seed = { 1, 2 } },\n"
                                 "        { Elevation = 10, Seed = { 3, 4 }, Colour = 'blue' },\n    },\n}\n";
    const faf::editor::WaterBodiesRead read = faf::editor::ReadWaterBodies(scenario);
    ASSERT_EQ(read.bodies.size(), 2u);
    EXPECT_FALSE(read.bodies[1].raw.empty());
    EXPECT_NE(read.bodies[1].unreadable.find("Colour"), std::string::npos);
    EXPECT_EQ(faf::editor::WaterBodyText(read.bodies[1]), "{ Elevation = 10, Seed = { 3, 4 }, Colour = 'blue' }");
    // Written back unchanged; previewed as not readable.
    EXPECT_EQ(faf::editor::WithWaterBodies(scenario, read.bodies).find("Colour = 'blue'") != std::string::npos, true);
    std::vector<std::string> log;
    const auto descs = faf::editor::WaterBodyDescs({read.bodies[1]}, 2.5f, 15.0f, log);
    EXPECT_TRUE(descs.empty());
    ASSERT_EQ(log.size(), 1u);
    EXPECT_NE(log[0].find("can't read"), std::string::npos);
  }

  TEST(WaterBodiesEdit, WrittenBackReadsTheSame)
  {
    const faf::editor::WaterBodiesRead read = faf::editor::ReadWaterBodies(kScenario);
    const std::string written = faf::editor::WithWaterBodies(kScenario, read.bodies);
    const faf::editor::WaterBodiesRead again = faf::editor::ReadWaterBodies(written);
    ASSERT_TRUE(again.error.empty()) << again.error;
    EXPECT_EQ(again.bodies, read.bodies);
    // The rest of the file is as it was.
    EXPECT_NE(written.find("version = 3 -- Lua Version. Dont touch this"), std::string::npos);
    EXPECT_NE(written.find("description = 'Water at { many } levels',"), std::string::npos);
    EXPECT_NE(written.find("        ['standard'] = {"), std::string::npos);
    EXPECT_NE(written.find("    WaterBodies = {\n        { Elevation = 30, Deep = 28, Abyss = 25, Outline = { { 10, 10 }, { 20, 10 }, { 15, 20 } } },\n"),
              std::string::npos)
      << written;
  }

  TEST(WaterBodiesEdit, EditedAddedAndRemoved)
  {
    faf::editor::WaterBodiesRead read = faf::editor::ReadWaterBodies(kScenario);
    read.bodies[1].elevation = 21.5f;
    read.bodies[1].hasBounds = true;
    read.bodies[1].x0 = 140;
    read.bodies[1].z0 = 140;
    read.bodies[1].x1 = 164;
    read.bodies[1].z1 = 164;
    std::string written = faf::editor::WithWaterBodies(kScenario, read.bodies);
    EXPECT_NE(written.find("{ Elevation = 21.5, Seed = { 152, 152 }, Bounds = { 140, 140, 164, 164 } },"), std::string::npos) << written;

    // All taken out: the table and its line go, the rest stays.
    written = faf::editor::WithWaterBodies(written, {});
    EXPECT_EQ(written.find("WaterBodies"), std::string::npos) << written;
    EXPECT_NE(written.find("ScenarioInfo = {\n    name = \"Lakes\",\n    description"), std::string::npos) << written;
    EXPECT_FALSE(faf::editor::ReadWaterBodies(written).present);

    // Added to a scenario without any: at the top of ScenarioInfo.
    WaterBody lake;
    lake.elevation = 12.0f;
    lake.seedX = 256.0f;
    lake.seedZ = 300.25f;
    written = faf::editor::WithWaterBodies(written, {lake});
    EXPECT_NE(written.find("ScenarioInfo = {\n    WaterBodies = {\n        { Elevation = 12, Seed = { 256, 300.25 } },\n    },\n    name"),
              std::string::npos)
      << written;
    const faf::editor::WaterBodiesRead again = faf::editor::ReadWaterBodies(written);
    ASSERT_EQ(again.bodies.size(), 1u);
    EXPECT_EQ(again.bodies[0], lake);
  }

  TEST(WaterBodiesEdit, DescsFollowTheGamesDefaultsAndSkips)
  {
    std::vector<WaterBody> bodies(6);
    // 1: a lake with only a level and a seed: Deep and Abyss from the sea's distances.
    bodies[0].elevation = 20.0f;
    bodies[0].seedX = 5.0f;
    bodies[0].seedZ = 6.0f;
    // 2: no Elevation.
    bodies[1].hasElevation = false;
    // 3: dry without FillTo.
    bodies[2].dry = true;
    bodies[2].hasElevation = false;
    // 4: Deep above the level: the game's 2.5 and 15 below.
    bodies[3].elevation = 10.0f;
    bodies[3].hasDeep = true;
    bodies[3].deep = 11.0f;
    // 5: two outline points.
    bodies[4].elevation = 10.0f;
    bodies[4].outline = {{1.0f, 1.0f}, {2.0f, 2.0f}};
    // 6: an outline and no seed.
    bodies[5].elevation = 8.0f;
    bodies[5].hasSeed = false;
    bodies[5].hasFillTo = true;
    bodies[5].fillTo = 9.0f;
    bodies[5].outline = {{1.0f, 1.0f}, {9.0f, 1.0f}, {5.0f, 9.0f}};

    std::vector<std::string> log;
    const std::vector<moho::SWaterBodyDesc> descs = faf::editor::WaterBodyDescs(bodies, 3.0f, 12.0f, log);
    ASSERT_EQ(descs.size(), 3u);
    EXPECT_EQ(descs[0].deep, 17.0f);
    EXPECT_EQ(descs[0].abyss, 8.0f);
    EXPECT_EQ(descs[0].fillTo, 20.0f);
    EXPECT_TRUE(descs[0].hasSeed);
    EXPECT_EQ(descs[1].deep, 7.5f);
    EXPECT_EQ(descs[1].abyss, -5.0f);
    EXPECT_FALSE(descs[2].hasSeed);
    EXPECT_EQ(descs[2].fillTo, 9.0f);
    EXPECT_EQ(descs[2].outline.size(), 6u);
    const std::vector<std::string> expected = {
      "water body 2 skipped: no Elevation",
      "water body 3 skipped: a dry body needs FillTo",
      "water body 4: Deep and Abyss must be below Elevation; using 2.5 and 15 below it",
      "water body 5 skipped: Outline is not 3 or more { x, z } points",
    };
    EXPECT_EQ(log, expected);
  }

  TEST(WaterBodiesEdit, FilledOverAHeightField)
  {
    // A 17 x 17 bowl: ground at 10 with a pit at 2 in the middle 5 x 5; a lake at 6 seeded in it.
    constexpr int kSize = 17;
    std::vector<std::uint16_t> heights(kSize * kSize, static_cast<std::uint16_t>(10.0f / 0.0078125f));
    for (int z = 6; z <= 10; ++z) {
      for (int x = 6; x <= 10; ++x) {
        heights[static_cast<std::size_t>(z * kSize + x)] = static_cast<std::uint16_t>(2.0f / 0.0078125f);
      }
    }
    WaterBody lake;
    lake.elevation = 6.0f;
    lake.seedX = 8.0f;
    lake.seedZ = 8.0f;
    std::vector<std::string> log;
    const auto descs = faf::editor::WaterBodyDescs({lake}, 2.5f, 15.0f, log);
    const auto filled = moho::CWaterBodies::Build(heights.data(), kSize, kSize, 0.0078125f, descs, &log);
    ASSERT_NE(filled, nullptr);
    ASSERT_EQ(filled->BodyCount(), 1u);
    EXPECT_EQ(filled->Body(1).elevation, 6.0f);
    EXPECT_EQ(filled->BodyOfVertex(8, 8), 1);
    EXPECT_EQ(filled->BodyOfVertex(1, 1), 0);
  }

  TEST(WaterBodiesEdit, EveryRetailScenarioReadsAndTakesABody)
  {
    const char* const folder = std::getenv("FAF_RETAIL_MAPS");
    if (folder == nullptr) {
      GTEST_SKIP() << "FAF_RETAIL_MAPS is not set";
    }
    int scenarios = 0;
    for (const auto& map : std::filesystem::directory_iterator(folder)) {
      for (const auto& file : std::filesystem::directory_iterator(map.path())) {
        const std::string name = file.path().filename().string();
        if (name.size() < 13 || name.substr(name.size() - 13) != "_scenario.lua") {
          continue;
        }
        std::ifstream in(file.path(), std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        const faf::editor::WaterBodiesRead read = faf::editor::ReadWaterBodies(text.str());
        ASSERT_TRUE(read.error.empty()) << file.path() << ": " << read.error;
        WaterBody lake;
        lake.elevation = 20.0f;
        const std::string written = faf::editor::WithWaterBodies(text.str(), {lake});
        const faf::editor::WaterBodiesRead again = faf::editor::ReadWaterBodies(written);
        ASSERT_TRUE(again.error.empty()) << file.path() << ": " << again.error;
        ASSERT_EQ(again.bodies.size(), 1u) << file.path();
        EXPECT_EQ(faf::editor::WithWaterBodies(written, {}), text.str()) << file.path();
        ++scenarios;
      }
    }
    EXPECT_GT(scenarios, 0);
  }
} // namespace
