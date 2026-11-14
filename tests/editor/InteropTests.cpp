// Heightmap import and export (src/editor/tools/EdInterop.cpp): orientation, mapping and blends onto the map's
// heights, the export's sidecar and the live link's settle-then-once watch.

#include "editor/tools/EdInterop.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

namespace
{
  using faf::editor::ExportFacts;
  using faf::editor::ExportSidecar;
  using faf::editor::FileStamp;
  using faf::editor::HeightImage;
  using faf::editor::ImportedHeights;
  using faf::editor::ImportSettings;
  using faf::editor::LiveLink;
  using faf::editor::OrientHeights;

  /** 3 x 2: 0 1 2 / 3 4 5. */
  HeightImage Small()
  {
    HeightImage image;
    image.width = 3;
    image.height = 2;
    image.words = {0, 1, 2, 3, 4, 5};
    return image;
  }

  TEST(
    Interop,
    OrientFlipsAndTurns
  )
  {
    const HeightImage flippedX = OrientHeights(Small(), true, false, 0);
    EXPECT_EQ(flippedX.words, (std::vector<std::uint16_t>{2, 1, 0, 5, 4, 3}));
    const HeightImage flippedZ = OrientHeights(Small(), false, true, 0);
    EXPECT_EQ(flippedZ.words, (std::vector<std::uint16_t>{3, 4, 5, 0, 1, 2}));
    // A quarter turn clockwise: the left column (0, 3) becomes the top row, read bottom to top.
    const HeightImage turned = OrientHeights(Small(), false, false, 1);
    ASSERT_EQ(turned.width, 2);
    ASSERT_EQ(turned.height, 3);
    EXPECT_EQ(turned.words, (std::vector<std::uint16_t>{3, 0, 4, 1, 5, 2}));
    // Four turns, and two turns against flipping both ways.
    EXPECT_EQ(OrientHeights(Small(), false, false, 4).words, Small().words);
    EXPECT_EQ(OrientHeights(Small(), false, false, 2).words, OrientHeights(Small(), true, true, 0).words);
    EXPECT_EQ(OrientHeights(Small(), false, false, -1).words, OrientHeights(Small(), false, false, 3).words);
  }

  TEST(
    Interop,
    MappingAndBlends
  )
  {
    // A 2 x 2 image from black to white on a 2 x 2 map at 10 units.
    HeightImage image;
    image.width = 2;
    image.height = 2;
    image.words = {0, 65535, 0, 65535};
    const std::vector<std::uint16_t> map(4, static_cast<std::uint16_t>(10 * 128));
    ImportSettings s;
    s.low = 5.0f;
    s.high = 25.0f;
    auto out = ImportedHeights(image, map, 2, 2, s);
    EXPECT_EQ(out[0], 5 * 128) << "darkest to low";
    EXPECT_EQ(out[1], 25 * 128) << "brightest to high";
    s.blend = ImportSettings::Blend::Add;
    out = ImportedHeights(image, map, 2, 2, s);
    EXPECT_EQ(out[0], 10 * 128) << "the lowest point adds nothing";
    EXPECT_EQ(out[1], 30 * 128);
    s.blend = ImportSettings::Blend::Max;
    out = ImportedHeights(image, map, 2, 2, s);
    EXPECT_EQ(out[0], 10 * 128);
    EXPECT_EQ(out[1], 25 * 128);
    s.blend = ImportSettings::Blend::Min;
    out = ImportedHeights(image, map, 2, 2, s);
    EXPECT_EQ(out[0], 5 * 128);
    EXPECT_EQ(out[1], 10 * 128);
    s.blend = ImportSettings::Blend::Replace;
    s.strength = 0.5f;
    out = ImportedHeights(image, map, 2, 2, s);
    EXPECT_EQ(out[1], static_cast<std::uint16_t>(17.5f * 128)) << "half way from 10 to 25";
    // Absolute: words are heights, scaled.
    ImportSettings a;
    a.mapping = ImportSettings::Mapping::Absolute;
    a.scale = 0.5f;
    image.words = {256, 512, 1024, 2048};
    out = ImportedHeights(image, map, 2, 2, a);
    EXPECT_EQ(out, (std::vector<std::uint16_t>{128, 256, 512, 1024}));
    // The wrong map size changes nothing.
    EXPECT_EQ(ImportedHeights(image, map, 3, 2, a), map);
  }

  TEST(
    Interop,
    ImportResamplesToTheMap
  )
  {
    // A flat image of a different size fills the whole map with one height.
    HeightImage image;
    image.width = 5;
    image.height = 5;
    image.words.assign(25, 1000);
    const std::vector<std::uint16_t> map(9 * 9, 0);
    ImportSettings a;
    a.mapping = ImportSettings::Mapping::Absolute;
    const auto out = ImportedHeights(image, map, 9, 9, a);
    for (const std::uint16_t w : out) {
      EXPECT_EQ(w, 1000);
    }
  }

  TEST(
    Interop,
    ARegionTakesTheImportAndTheFeatherFadesItIn
  )
  {
    HeightImage image;
    image.width = 2;
    image.height = 2;
    image.words.assign(4, 2560); // 20 units
    const std::vector<std::uint16_t> map(21 * 21, 0);
    ImportSettings a;
    a.mapping = ImportSettings::Mapping::Absolute;
    a.region = true;
    a.regionX0 = 5;
    a.regionZ0 = 5;
    a.regionX1 = 15;
    a.regionZ1 = 15;
    auto out = ImportedHeights(image, map, 21, 21, a);
    EXPECT_EQ(out[4 * 21 + 10], 0) << "outside the region";
    EXPECT_EQ(out[5 * 21 + 10], 2560) << "its edge";
    EXPECT_EQ(out[10 * 21 + 10], 2560);
    a.feather = 4.0f;
    out = ImportedHeights(image, map, 21, 21, a);
    EXPECT_EQ(out[5 * 21 + 10], 0) << "the edge: faded out";
    EXPECT_GT(out[7 * 21 + 10], 0);
    EXPECT_LT(out[7 * 21 + 10], 2560) << "part way in";
    EXPECT_EQ(out[10 * 21 + 10], 2560) << "past the feather: all of it";
  }

  TEST(
    Interop,
    SidecarSaysHowToReadTheWords
  )
  {
    ExportFacts facts;
    facts.map = "Seton \"Clutch\"";
    facts.mapWidth = 1024;
    facts.mapHeight = 1024;
    facts.imageWidth = 1025;
    facts.imageHeight = 1025;
    facts.scale = 1.0f;
    facts.lowest = 12.5f;
    facts.highest = 80.25f;
    facts.sea = 25.0f;
    facts.symmetry = "Point";
    const std::string text = ExportSidecar(facts);
    EXPECT_NE(text.find("\"map\": \"Seton \\\"Clutch\\\"\""), std::string::npos) << text;
    EXPECT_NE(text.find("\"mapSize\": [1024, 1024]"), std::string::npos);
    EXPECT_NE(text.find("\"imageSize\": [1025, 1025]"), std::string::npos);
    EXPECT_NE(text.find("\"heightPerWord\": 0.0078125"), std::string::npos) << "1/128 at scale 1";
    EXPECT_NE(text.find("\"seaLevel\": 25.000"), std::string::npos);
    EXPECT_NE(text.find("\"symmetry\": \"Point\""), std::string::npos);
  }

  TEST(
    Interop,
    LiveLinkWaitsForTheFileToSettleThenFiresOnce
  )
  {
    LiveLink link;
    link.Start({100, 1});
    EXPECT_FALSE(link.Poll({100, 1}, 0.0)) << "unchanged";
    EXPECT_FALSE(link.Poll({200, 2}, 1.0)) << "a write starts";
    EXPECT_FALSE(link.Poll({300, 3}, 1.5)) << "still being written";
    EXPECT_FALSE(link.Poll({300, 3}, 2.0)) << "not settled for a second yet";
    EXPECT_TRUE(link.Poll({300, 3}, 2.6)) << "settled";
    EXPECT_FALSE(link.Poll({300, 3}, 5.0)) << "once";
    EXPECT_FALSE(link.Poll({0, 0}, 6.0)) << "gone: wait";
    EXPECT_FALSE(link.Poll({300, 4}, 7.0));
    EXPECT_TRUE(link.Poll({300, 4}, 8.1)) << "written again";
    // A change back to the applied file after it vanished doesn't fire.
    EXPECT_FALSE(link.Poll({0, 0}, 9.0));
    EXPECT_FALSE(link.Poll({300, 4}, 9.5));
    EXPECT_FALSE(link.Poll({300, 4}, 11.0));
  }
} // namespace
