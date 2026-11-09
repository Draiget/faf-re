// The map editor's new maps (src/editor/doc/EdNewMap.cpp): start positions in a ring inside the map, the
// scenario naming every army and the extra ones, and a preview chunk of the layout the game reads.

#include "editor/doc/EdNewMap.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>

namespace
{
  using faf::editor::NewMapSettings;

  TEST(NewMap, SpawnsFormARingInsideTheMap)
  {
    NewMapSettings settings;
    settings.size = 1; // 512
    settings.players = 6;
    const auto spawns = faf::editor::NewMapSpawns(settings);
    ASSERT_EQ(spawns.size(), 6u);
    for (const auto& spawn : spawns) {
      EXPECT_NEAR(std::hypot(spawn.x - 256.0f, spawn.z - 256.0f), 512.0f * 0.35f, 1.0f);
    }
    EXPECT_FLOAT_EQ(spawns[0].x, 256.0f); // the first at the top
    EXPECT_LT(spawns[0].z, 256.0f);
    settings.players = 1;
    EXPECT_FLOAT_EQ(faf::editor::NewMapSpawns(settings)[0].x, 256.0f);
  }

  TEST(NewMap, ScenarioAndSaveNameEveryArmy)
  {
    NewMapSettings settings;
    settings.folder = "test_map.v0001";
    settings.players = 3;
    const std::string scenario = faf::editor::NewMapScenarioText(settings, "test_map");
    EXPECT_NE(scenario.find("armies = {'ARMY_1','ARMY_2','ARMY_3',}"), std::string::npos);
    EXPECT_NE(scenario.find("map = '/maps/test_map.v0001/test_map.scmap'"), std::string::npos);
    EXPECT_NE(scenario.find("'ARMY_17 NEUTRAL_CIVILIAN'"), std::string::npos);
    const std::string save = faf::editor::NewMapSaveText(settings);
    for (const char* const army : {"['ARMY_1'] =  ", "['ARMY_3'] =  ", "['ARMY_17'] =  ", "['NEUTRAL_CIVILIAN'] =  "}) {
      EXPECT_NE(save.find(army), std::string::npos) << army;
    }
    EXPECT_EQ(save.find("['ARMY_4']"), std::string::npos);
  }

  TEST(NewMap, PreviewChunkHasTheGamesLayout)
  {
    NewMapSettings settings;
    settings.size = 2; // 1024
    const std::vector<char> chunk = faf::editor::NewMapPreviewRecord(settings);
    std::uint32_t word = 0;
    float size = 0.0f;
    std::memcpy(&word, chunk.data(), 4);
    EXPECT_EQ(word, 0xBEEFFEEDu);
    std::memcpy(&word, chunk.data() + 4, 4);
    EXPECT_EQ(word, 2u);
    std::memcpy(&size, chunk.data() + 8, 4);
    EXPECT_FLOAT_EQ(size, 1024.0f);
    // An empty UTF-16 name, no tags, then the payload's size and a 128-byte DDS header plus 256 x 256 x 4.
    std::memcpy(&word, chunk.data() + 18, 4);
    EXPECT_EQ(word, 0u);
    std::memcpy(&word, chunk.data() + 22, 4);
    EXPECT_EQ(word, 128u + 256u * 256u * 4u);
    EXPECT_EQ(chunk.size(), 26u + word);
    EXPECT_EQ(std::memcmp(chunk.data() + 26, "DDS ", 4), 0);
  }
} // namespace
