// The sixth comparison with FAF Studio (brush target): several masks imported by their names, the heightmap import's
// options (a raw file's layout, invert, the sea level, the export's .json), the OBJ import's options.

#include "editor/tools/EdHeightFile.h"
#include "editor/tools/EdInterop.h"
#include "editor/tools/EdMeshImport.h"
#include "editor/tools/EdScm.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace
{
  using namespace faf::editor;

  std::filesystem::path TempFile(
    const char* name
  )
  {
    const std::filesystem::path folder = std::filesystem::temp_directory_path() / "faf_round8";
    std::filesystem::create_directories(folder);
    return folder / name;
  }

  TEST(
    RoundEight,
    MasksAreGuessedByTheirNames
  )
  {
    std::array<std::string, 9> kinds = {"", "grass", "rock", "sand", "high rock", "", "", "", ""};
    MaskImportFile f = GuessMaskImport("C:/x/layer3.png", kinds);
    EXPECT_EQ(f.target, MaskImportFile::Target::Layer);
    EXPECT_EQ(f.layer, 3);
    f = GuessMaskImport("C:/x/Mask_5.png", kinds);
    EXPECT_EQ(f.layer, 5);
    EXPECT_EQ(GuessMaskImport("C:/x/splatmap.png", kinds).target, MaskImportFile::Target::Splat);
    EXPECT_EQ(GuessMaskImport("C:/x/terrain_types.png", kinds).target, MaskImportFile::Target::TerrainType);
    f = GuessMaskImport("C:/x/Beach.png", kinds);
    EXPECT_EQ(f.target, MaskImportFile::Target::Layer);
    EXPECT_EQ(f.layer, 3) << "a beach is sand";
    f = GuessMaskImport("C:/x/rock_high.png", kinds);
    EXPECT_EQ(f.layer, 4) << "the high rock layer before the plain rock one";
    f = GuessMaskImport("C:/x/cliffs.png", kinds);
    EXPECT_EQ(f.layer, 2);
    EXPECT_EQ(GuessMaskImport("C:/x/snow.png", kinds).target, MaskImportFile::Target::Skip) << "no snow layer";
    EXPECT_EQ(GuessMaskImport("C:/x/notes.png", kinds).target, MaskImportFile::Target::Skip);
  }

  TEST(
    RoundEight,
    TheExportsJsonPutsTheHeightsBack
  )
  {
    ExportFacts facts;
    facts.map = "test";
    facts.mapWidth = 256;
    facts.mapHeight = 256;
    facts.imageWidth = 257;
    facts.imageHeight = 257;
    facts.scale = 0.5f;
    facts.lowest = 10.0f;
    facts.highest = 90.0f;
    ImportSettings settings;
    settings.invert = true;
    const auto read = ImportFromSidecar(ExportSidecar(facts), settings);
    ASSERT_TRUE(read) << read.error();
    EXPECT_EQ(settings.mapping, ImportSettings::Mapping::Absolute);
    EXPECT_FALSE(settings.invert);
    // A word read back is that height: words * scale / 128 = units.
    HeightImage image;
    image.width = 2;
    image.height = 2;
    const std::uint16_t word = static_cast<std::uint16_t>(42.0f * 128.0f * facts.scale + 0.5f);
    image.words = {word, word, word, word};
    const std::vector<std::uint16_t> current(4, 0);
    const std::vector<std::uint16_t> out = ImportedHeights(image, current, 2, 2, settings);
    ASSERT_EQ(out.size(), 4U);
    EXPECT_NEAR(out[0] / 128.0f, 42.0f, 0.1f) << "42 units exported, 42 units imported";
    EXPECT_FALSE(ImportFromSidecar("{\"map\": \"x\"}", settings));
  }

  TEST(
    RoundEight,
    InvertAndTheSeaLevelInTheImage
  )
  {
    HeightImage image;
    image.width = 2;
    image.height = 1;
    image.words = {0, 65535};
    const std::vector<std::uint16_t> current(2, 0);
    ImportSettings s;
    s.low = 0.0f;
    s.high = 100.0f;
    std::vector<std::uint16_t> out = ImportedHeights(image, current, 2, 1, s);
    EXPECT_NEAR(out[0] / 128.0f, 0.0f, 0.1f);
    EXPECT_NEAR(out[1] / 128.0f, 100.0f, 0.1f);
    s.invert = true;
    out = ImportedHeights(image, current, 2, 1, s);
    EXPECT_NEAR(out[0] / 128.0f, 100.0f, 0.1f) << "bright is low";
    EXPECT_NEAR(out[1] / 128.0f, 0.0f, 0.1f);
    s.invert = false;
    s.seaPin = true;
    s.seaValue = 0.5f;
    s.seaLevel = 20.0f;
    out = ImportedHeights(image, current, 2, 1, s);
    // Half way (50 units) lands on 20: everything 30 lower (the low end clamps at 0).
    EXPECT_NEAR(out[1] / 128.0f, 70.0f, 0.2f);
  }

  TEST(
    RoundEight,
    ARawFileIsReadByItsLayout
  )
  {
    // 3 x 2 samples, 16-bit big-endian.
    const std::uint16_t words[6] = {1, 2, 300, 4000, 50000, 65535};
    {
      std::ofstream file(TempFile("big.r16"), std::ios::binary);
      for (const std::uint16_t w : words) {
        const char bytes[2] = {static_cast<char>(w >> 8), static_cast<char>(w & 0xFF)};
        file.write(bytes, 2);
      }
    }
    HeightReadOptions options;
    options.bigEndian = true;
    options.rawWidth = 3;
    options.rawHeight = 2;
    auto read = ReadHeightImageWith(TempFile("big.r16"), 0, 0, options);
    ASSERT_TRUE(read) << read.error();
    HeightImage image = std::move(*read);
    ASSERT_EQ(image.width, 3);
    ASSERT_EQ(image.height, 2);
    for (int i = 0; i < 6; ++i) {
      EXPECT_EQ(image.words[static_cast<std::size_t>(i)], words[i]) << i;
    }
    // 32-bit floats, little-endian: 0..1 stretched over the words.
    {
      std::ofstream file(TempFile("float.r32"), std::ios::binary);
      for (const float v : {0.0f, 0.5f, 1.0f, 0.25f}) {
        char bytes[4];
        std::memcpy(bytes, &v, 4);
        file.write(bytes, 4);
      }
    }
    HeightReadOptions floats;
    floats.rawBits = 32;
    floats.rawFloat = true;
    floats.rawWidth = 2;
    floats.rawHeight = 2;
    read = ReadHeightImageWith(TempFile("float.r32"), 0, 0, floats);
    ASSERT_TRUE(read) << read.error();
    image = std::move(*read);
    ASSERT_EQ(image.words.size(), 4U);
    EXPECT_LT(image.words[0], image.words[3]);
    EXPECT_LT(image.words[3], image.words[1]);
    EXPECT_LT(image.words[1], image.words[2]);
    // A size that doesn't match the file is refused.
    floats.rawWidth = 5;
    EXPECT_FALSE(ReadHeightImageWith(TempFile("float.r32"), 0, 0, floats));
  }

  TEST(
    RoundEight,
    TheObjImportOptions
  )
  {
    const auto parsed =
      ParseObj("o first\nv 0 0 0\nv 10 0 0\nv 0 5 0\nf 1 2 3\no second\nv 0 0 10\nv 10 0 10\nv 0 0 20\nf 4 5 6\n");
    ASSERT_TRUE(parsed) << parsed.error();
    const ObjMesh& mesh = *parsed;
    ASSERT_EQ(mesh.triangles.size(), 2U);
    MeshImportOptions options;
    options.zUp = true;
    options.offset[0] = 100.0f;
    options.offset[1] = 1.0f;
    ObjMesh moved = TransformMesh(mesh, options);
    EXPECT_FLOAT_EQ(moved.positions[2][1], 1.0f) << "Z up: the file's y (5) goes to -z";
    EXPECT_FLOAT_EQ(moved.positions[2][2], -5.0f);
    EXPECT_FLOAT_EQ(moved.positions[1][0], 110.0f) << "the offset after the scale";
    options = MeshImportOptions{};
    options.flipWinding = true;
    moved = TransformMesh(mesh, options);
    EXPECT_EQ(moved.triangles[0][1].position, mesh.triangles[0][2].position) << "turned inside out";
    options = MeshImportOptions{};
    options.uvRepeat = 10.0f;
    moved = TransformMesh(mesh, options);
    ASSERT_EQ(moved.uvs.size(), moved.positions.size()) << "texture coordinates from the ground plan";
    EXPECT_FLOAT_EQ(moved.uvs[1][0], 1.0f);
    // One patch a group; a patch past the corner limit is cut.
    options = MeshImportOptions{};
    options.byGroup = true;
    EXPECT_EQ(SplitMesh(mesh, options).size(), 2U);
    options.byGroup = false;
    options.tile = 1000.0f;
    EXPECT_EQ(SplitMesh(mesh, options).size(), 1U);
    options.maxVertices = 3;
    EXPECT_EQ(SplitMesh(mesh, options).size(), 2U) << "three corners a patch: one triangle each";
  }
} // namespace
