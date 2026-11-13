// The kind of ground a terrain texture shows (src/editor/tools/EdGroundKind.cpp, FAF Studio's roledetect.lua): from
// the file name's words, from the average colour, and both together.

#include "editor/tools/EdGroundKind.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::GroundKind;
  using faf::editor::GroundKindOf;
  using faf::editor::GroundKindOfColour;
  using faf::editor::GroundKindOfName;

  TEST(
    GroundKind,
    NamesSayTheKind
  )
  {
    EXPECT_EQ(GroundKindOfName("/env/evergreen/layers/Eg_Grass001_albedo.dds").kind, GroundKind::Grass);
    EXPECT_EQ(GroundKindOfName("/env/desert/layers/Des_sand_albedo.dds").kind, GroundKind::Sand);
    EXPECT_EQ(GroundKindOfName("/env/tundra/layers/Tund_snow_albedo.dds").kind, GroundKind::Snow);
    EXPECT_EQ(GroundKindOfName("/env/swamp/layers/sw_mud_albedo.dds").kind, GroundKind::Dirt);
    EXPECT_EQ(GroundKindOfName("/env/lava/layers/LavaPuddle01.dds").kind, GroundKind::Wet);
    EXPECT_EQ(GroundKindOfName("strata.dds").kind, GroundKind::Rock);
    EXPECT_EQ(GroundKindOfName("/env/common/layers/blank.dds").kind, GroundKind::Unknown) << "no word matches";
  }

  TEST(
    GroundKind,
    LongerTokensWinAndModifiersMoveRock
  )
  {
    EXPECT_EQ(GroundKindOfName("sandwet_albedo.dds").kind, GroundKind::Wet) << "sandwet is wet, not sand";
    // Two words: the noun bonus goes to "sand" too (the last word has three letters), so sand wins, as in FAF Studio.
    EXPECT_EQ(GroundKindOfName("SandWet_albedo.dds").kind, GroundKind::Sand);
    EXPECT_EQ(GroundKindOfName("Sandstone.dds").kind, GroundKind::Rock) << "sandstone is rock";
    EXPECT_EQ(GroundKindOfName("DarkRock_albedo.dds").kind, GroundKind::DarkRock);
    EXPECT_EQ(GroundKindOfName("rock_dark.dds").kind, GroundKind::DarkRock) << "a dark word";
    EXPECT_EQ(GroundKindOfName("rock_pale.dds").kind, GroundKind::HighRock) << "a light word";
    EXPECT_EQ(GroundKindOfName("ice_rock.dds").kind, GroundKind::HighRock) << "ice and rock: a pale rock";
    EXPECT_TRUE(GroundKindOfName("cliff01.dds").plainRock);
    EXPECT_FALSE(GroundKindOfName("cliff_dark.dds").plainRock);
  }

  TEST(
    GroundKind,
    ColoursSayTheKind
  )
  {
    EXPECT_EQ(GroundKindOfColour(0.92f, 0.93f, 0.95f).kind, GroundKind::Snow) << "near white";
    EXPECT_EQ(GroundKindOfColour(0.30f, 0.50f, 0.20f).kind, GroundKind::Grass) << "green";
    EXPECT_EQ(GroundKindOfColour(0.80f, 0.70f, 0.50f).kind, GroundKind::Sand) << "bright tan";
    EXPECT_EQ(GroundKindOfColour(0.45f, 0.45f, 0.45f).kind, GroundKind::Rock) << "mid grey";
    EXPECT_EQ(GroundKindOfColour(0.10f, 0.10f, 0.11f).kind, GroundKind::DarkRock) << "near black";
  }

  TEST(
    GroundKind,
    TheColourSettlesWhatTheNameLeavesOpen
  )
  {
    const float grey[3] = {0.12f, 0.12f, 0.12f};
    EXPECT_EQ(GroundKindOf("cliff01.dds", grey).kind, GroundKind::DarkRock)
      << "a plain rock name: the colour says which";
    const float green[3] = {0.30f, 0.50f, 0.20f};
    EXPECT_EQ(GroundKindOf("layer07.dds", green).kind, GroundKind::Grass) << "no name: the colour alone";
    EXPECT_EQ(GroundKindOf("Des_sand_grass.dds", green).kind, GroundKind::Grass) << "names both: the colour decides";
    const float tan[3] = {0.80f, 0.70f, 0.50f};
    EXPECT_EQ(GroundKindOf("Tund_snow_albedo.dds", tan).kind, GroundKind::Snow) << "a clear name wins";
    EXPECT_EQ(GroundKindOf("layer07.dds", nullptr).kind, GroundKind::Unknown);
  }
} // namespace
