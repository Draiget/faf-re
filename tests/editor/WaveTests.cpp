// The map editor's wave generators (src/editor/tools/EdWaves.cpp): the `.scmap`'s wave section and FAForeverMapEditor's
// `.scmwaves`, read and written; wave pattern files; shore points and the waves made on them. With FAF_RETAIL_MAPS set
// to the game's maps folder, every retail map's wave section reads and writes back byte for byte.

#include "editor/tools/EdWaves.h"
#include "TestEnv.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>

namespace
{
  using faf::editor::ShorePoint;
  using faf::editor::WaveRecord;

  WaveRecord Sample()
  {
    WaveRecord wave;
    wave.texture = "/env/common/decals/shoreline/wave05_albedo.dds";
    wave.ramp = "/env/common/decals/shoreline/ramp_waves_01.dds";
    wave.position[0] = 120.5f;
    wave.position[1] = 17.5f;
    wave.position[2] = 300.5f;
    wave.angle = 1.25f;
    wave.velocity[0] = 0.03f;
    wave.velocity[2] = -0.01f;
    wave.lifetime[0] = 15.0f;
    wave.lifetime[1] = 115.0f;
    wave.period[0] = 6.0f;
    wave.period[1] = 14.0f;
    wave.scale[0] = 0.8f;
    wave.scale[1] = 2.4f;
    wave.frameCount = 16.0f;
    wave.frameRate[0] = 0.423f;
    wave.frameRate[1] = 0.517f;
    wave.stripCount = 2.0f;
    return wave;
  }

  TEST(Waves, BytesAndFafmesFileRoundTrip)
  {
    const std::vector<WaveRecord> waves = {Sample(), WaveRecord{}};
    const std::string bytes = faf::editor::WaveRecordsToBytes(waves);
    // A count, then per wave two strings with their ends and 17 floats.
    EXPECT_EQ(bytes.size(), 4u + waves[0].texture.size() + 1 + waves[0].ramp.size() + 1 + 68 + 2 + 68);
    std::vector<WaveRecord> again;
    ASSERT_TRUE(faf::editor::WaveRecordsFromBytes(bytes, again));
    ASSERT_EQ(again.size(), 2u);
    EXPECT_TRUE(again[0] == waves[0]);
    std::string error;
    ASSERT_TRUE(faf::editor::WavesFromScmwaves(faf::editor::WavesToScmwaves(waves), again, error)) << error;
    ASSERT_EQ(again.size(), 2u);
    EXPECT_TRUE(again[0] == waves[0]);
    EXPECT_TRUE(again[1] == waves[1]);
    EXPECT_FALSE(faf::editor::WaveRecordsFromBytes(bytes.substr(0, bytes.size() - 1), again));
    EXPECT_FALSE(faf::editor::WavesFromScmwaves("{ \"Units\": [] }", again, error));
  }

  TEST(Waves, RetailMapsWaveSectionsRoundTrip)
  {
    const std::string folderText = faf::editor::test::EnvText("FAF_RETAIL_MAPS");
    const char* const folder = folderText.empty() ? nullptr : folderText.c_str();
    if (folder == nullptr) {
      GTEST_SKIP() << "FAF_RETAIL_MAPS is not set";
    }
    int maps = 0;
    std::size_t generators = 0;
    for (const auto& map : std::filesystem::directory_iterator(folder)) {
      const std::filesystem::path file = map.path() / (map.path().filename().string() + ".scmap");
      std::ifstream in(file, std::ios::binary);
      if (!in) {
        continue;
      }
      const std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      std::string lower = data;
      for (char& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      // The wave section starts with its count, right before the first generator's texture.
      const std::size_t texture = lower.find("/env/common/decals/shoreline");
      if (texture == std::string::npos || texture < 4) {
        continue;
      }
      std::vector<WaveRecord> waves;
      ASSERT_TRUE(faf::editor::WaveRecordsFromBytes(data.substr(texture - 4), waves)) << file;
      const std::string bytes = faf::editor::WaveRecordsToBytes(waves);
      EXPECT_EQ(data.compare(texture - 4, bytes.size(), bytes), 0) << file;
      ++maps;
      generators += waves.size();
    }
    EXPECT_GT(maps, 0);
    std::printf("[ waves    ] %d retail maps, %zu wave generators round-tripped\n", maps, generators);
  }

  TEST(Waves, ReadsAPatternsFile)
  {
    // The GPG editor's pattern format (as FAForeverMapEditor's wavepatterns.lua has it), with made-up values.
    const char* const lua = R"(
---
--- a test file
---
patterns = {
    {
        name = 'test break',
        preview = '/editor/tools/water/nopreview.bmp',
        parameters = {
            {
                texture = "/env/common/decals/shoreline/wave05_albedo.dds",
                ramp = '/env/common/decals/shoreline/ramp_waves_01.dds',
                position = { 0.0, 0.0, 0.0, },
                period = 10.0,
                periodVariance = 4.0,
                speed = 0.04,
                speedVariance = 0.02,
                lifetime = 65.0,
                lifetimeVariance = 50.0,
                scale = { 0.8, 2.4 },
                scaleVariance = 0.5,
                velocityDelta = { 0.0, 0.0, 0.0, },
                frameCount = 16,
                frameRate = 0.47,
                frameRateVariance = 0.047,
                stripCount = 2,
            },
        },
    },
    { name = 'no parameters' },
}
)";
    std::vector<faf::editor::WavePattern> patterns;
    std::string error;
    ASSERT_TRUE(faf::editor::ParseWavePatterns(lua, patterns, error)) << error;
    ASSERT_EQ(patterns.size(), 1u);
    EXPECT_EQ(patterns[0].name, "test break");
    EXPECT_EQ(patterns[0].ramp, "/env/common/decals/shoreline/ramp_waves_01.dds");
    EXPECT_FLOAT_EQ(patterns[0].period[0], 6.0f);
    EXPECT_FLOAT_EQ(patterns[0].period[1], 14.0f);
    EXPECT_FLOAT_EQ(patterns[0].lifetime[1], 115.0f);
    EXPECT_FLOAT_EQ(patterns[0].scale[1], 2.4f);
    EXPECT_FLOAT_EQ(patterns[0].frameCount, 16.0f);
    EXPECT_NEAR(patterns[0].frameRate[0], 0.423f, 1e-5f);
    EXPECT_FALSE(faf::editor::ParseWavePatterns("x = 1", patterns, error));
  }

  TEST(Waves, ShorePointsFaceUphillAndWavesTravelThere)
  {
    // A slope rising to +x: 0 at x = 0, 32 at x = 32; the water at 16, the waves where the ground is 2 below it: the
    // cell from x 14 to 15.
    const int size = 32;
    std::vector<float> heights(static_cast<std::size_t>(size + 1) * (size + 1));
    for (int z = 0; z <= size; ++z) {
      for (int x = 0; x <= size; ++x) {
        heights[static_cast<std::size_t>(z) * (size + 1) + x] = static_cast<float>(x);
      }
    }
    const std::vector<ShorePoint> points = faf::editor::FindShorePoints(heights, size, size, 16.0f, 2.0f, 0.0f, 180.0f);
    ASSERT_EQ(points.size(), static_cast<std::size_t>(size));
    EXPECT_FLOAT_EQ(points[0].x, 14.5f);
    EXPECT_NEAR(points[0].heading, 0.0f, 1e-6f);
    // A window that faces the other way finds none.
    EXPECT_TRUE(faf::editor::FindShorePoints(heights, size, size, 16.0f, 2.0f, 180.0f, 45.0f).empty());
    // Half of them, none closer than 3 to another.
    const std::vector<ShorePoint> picked = faf::editor::PickShorePoints(points, 0.5f, 3.0f, 7U);
    EXPECT_LE(picked.size(), 16u);
    EXPECT_GE(picked.size(), 8u);
    for (std::size_t i = 0; i < picked.size(); ++i) {
      for (std::size_t j = i + 1; j < picked.size(); ++j) {
        EXPECT_GE(std::hypot(picked[i].x - picked[j].x, picked[i].z - picked[j].z), 3.0f);
      }
    }
    std::uint32_t seed = 1U;
    const WaveRecord wave = faf::editor::MakeShoreWave(faf::editor::BuiltInWavePatterns()[0], points[0], 16.0f, seed);
    EXPECT_FLOAT_EQ(wave.position[1], 16.0f);
    // To the shore (+x), the texture a quarter turn from it, as the retail maps have them.
    EXPECT_GT(wave.velocity[0], 0.0f);
    EXPECT_NEAR(std::atan2(wave.velocity[2], wave.velocity[0]), wave.angle - 3.14159265f / 2.0f, 1e-5f);
  }
} // namespace
