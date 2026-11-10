// The map editor's prop paint list (src/editor/doc/EdPropPaint.cpp): FAForeverMapEditor's `.proppaintset`, read and
// written, and the pick by chance.

#include "editor/doc/EdPropPaint.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::PropPaintEntry;

  // As FAFME's ExportPropsSet writes it (JsonUtility, pretty).
  const char* const kFafme = R"({
    "PaintProps": [
        {
            "Blueprint": "/env/evergreen/props/trees/pine06_s1_prop.bp",
            "ScaleMin": 0.800000011920929,
            "ScaleMax": 1.2000000476837159,
            "RotationMin": 0,
            "RotationMax": 360,
            "Chance": 70
        },
        {
            "Blueprint": "/env/evergreen/props/rocks/rock01_prop.bp",
            "ScaleMin": 1.0,
            "ScaleMax": 1.0,
            "RotationMin": 90,
            "RotationMax": 180,
            "Chance": 30
        }
    ]
})";

  TEST(PropPaint, ReadsFafmesSet)
  {
    std::vector<PropPaintEntry> entries;
    std::string error;
    ASSERT_TRUE(faf::editor::PaintSetFromProppaintset(kFafme, entries, error)) << error;
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].blueprint, "/env/evergreen/props/trees/pine06_s1_prop.bp");
    EXPECT_FLOAT_EQ(entries[0].scaleMin, 0.8f);
    EXPECT_FLOAT_EQ(entries[0].scaleMax, 1.2f);
    EXPECT_EQ(entries[0].chance, 70);
    EXPECT_EQ(entries[1].rotationMin, 90);
    EXPECT_EQ(entries[1].rotationMax, 180);
  }

  TEST(PropPaint, WritesEachEntrysOwnValues)
  {
    std::vector<PropPaintEntry> entries;
    std::string error;
    ASSERT_TRUE(faf::editor::PaintSetFromProppaintset(kFafme, entries, error)) << error;
    std::vector<PropPaintEntry> again;
    ASSERT_TRUE(faf::editor::PaintSetFromProppaintset(faf::editor::PaintSetToProppaintset(entries), again, error)) << error;
    ASSERT_EQ(again.size(), entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i) {
      EXPECT_TRUE(again[i] == entries[i]) << "entry " << i;
    }
    // An empty list is a set too.
    ASSERT_TRUE(faf::editor::PaintSetFromProppaintset(faf::editor::PaintSetToProppaintset({}), again, error)) << error;
    EXPECT_TRUE(again.empty());
    EXPECT_FALSE(faf::editor::PaintSetFromProppaintset("{ \"Units\": [] }", again, error));
  }

  TEST(PropPaint, PicksByChance)
  {
    std::vector<PropPaintEntry> entries(3);
    entries[0].chance = 70;
    entries[1].chance = 0;
    entries[2].chance = 30;
    EXPECT_EQ(faf::editor::PickPaintEntry(entries, 0.0f), 0);
    EXPECT_EQ(faf::editor::PickPaintEntry(entries, 0.69f), 0);
    EXPECT_EQ(faf::editor::PickPaintEntry(entries, 0.70f), 2);
    EXPECT_EQ(faf::editor::PickPaintEntry(entries, 0.999f), 2);
    entries[0].chance = 0;
    entries[2].chance = 0;
    EXPECT_EQ(faf::editor::PickPaintEntry(entries, 0.5f), -1);
    EXPECT_EQ(faf::editor::PickPaintEntry({}, 0.5f), -1);
  }
} // namespace
