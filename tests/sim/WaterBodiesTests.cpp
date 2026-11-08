// Engine addition: water bodies filled over a height field (.plans/water-levels/PLAN.md).
#include "moho/sim/WaterBodies.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace
{
  using moho::CWaterBodies;
  using moho::SWaterBodyDesc;

  constexpr float kScale = 1.0f / 128.0f;

  /// A height field of `width * height` vertices, every one at `level` world units.
  struct Field
  {
    std::int32_t width;
    std::int32_t height;
    std::vector<std::uint16_t> samples;

    Field(const std::int32_t w, const std::int32_t h, const float level)
      : width(w), height(h), samples(static_cast<std::size_t>(w) * static_cast<std::size_t>(h), Word(level))
    {}

    static std::uint16_t Word(const float level) { return static_cast<std::uint16_t>(level * 128.0f); }

    void Set(const std::int32_t x, const std::int32_t z, const float level)
    {
      samples[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)] = Word(level);
    }

    void Fill(const std::int32_t x0, const std::int32_t z0, const std::int32_t x1, const std::int32_t z1, const float level)
    {
      for (std::int32_t z = z0; z <= z1; ++z) {
        for (std::int32_t x = x0; x <= x1; ++x) {
          Set(x, z, level);
        }
      }
    }

    std::unique_ptr<CWaterBodies> Build(const std::vector<SWaterBodyDesc>& descs, std::vector<std::string>* log = nullptr) const
    {
      return CWaterBodies::Build(samples.data(), width, height, kScale, descs, log);
    }
  };

  SWaterBodyDesc Lake(const float level, const float seedX, const float seedZ)
  {
    SWaterBodyDesc desc;
    desc.elevation = level;
    desc.deep = level - 2.0f;
    desc.abyss = level - 10.0f;
    desc.fillTo = level;
    desc.seedX = seedX;
    desc.seedZ = seedZ;
    return desc;
  }
} // namespace

TEST(WaterBodies, NoBodiesBuildsNothing)
{
  const Field field(17, 17, 50.0f);
  EXPECT_EQ(field.Build({}), nullptr);
}

TEST(WaterBodies, BasinFillsOnlyBelowItsLevel)
{
  // A plateau at 60 with a basin at 40 over vertices [4, 8] x [4, 8].
  Field field(17, 17, 60.0f);
  field.Fill(4, 4, 8, 8, 40.0f);
  const auto bodies = field.Build({Lake(50.0f, 6.0f, 6.0f)});
  ASSERT_NE(bodies, nullptr);
  ASSERT_EQ(bodies->BodyCount(), 1u);

  EXPECT_EQ(bodies->BodyOfVertex(4, 4), 1u);
  EXPECT_EQ(bodies->BodyOfVertex(8, 8), 1u);
  EXPECT_EQ(bodies->BodyOfVertex(3, 6), 0u);
  EXPECT_EQ(bodies->BodyOfVertex(9, 6), 0u);

  // Cells with any corner in the basin: [3, 8] x [3, 8].
  const auto& body = bodies->Body(1u);
  EXPECT_EQ(body.x0, 3);
  EXPECT_EQ(body.z0, 3);
  EXPECT_EQ(body.x1, 9);
  EXPECT_EQ(body.z1, 9);
  EXPECT_EQ(body.cellCount, 36u);

  EXPECT_FLOAT_EQ(bodies->LevelAt(6.5f, 6.5f, 10.0f), 50.0f);
  EXPECT_FLOAT_EQ(bodies->LevelAt(3.5f, 6.5f, 10.0f), 50.0f);
  EXPECT_FLOAT_EQ(bodies->LevelAt(1.5f, 1.5f, 10.0f), 10.0f);
  EXPECT_FLOAT_EQ(bodies->LevelAt(12.0f, 6.5f, moho::kWaterBodyNoWater), moho::kWaterBodyNoWater);
}

TEST(WaterBodies, TwoBasinsAreSeparate)
{
  Field field(33, 17, 60.0f);
  field.Fill(2, 2, 6, 6, 40.0f);
  field.Fill(20, 2, 26, 8, 30.0f);
  const auto bodies = field.Build({Lake(50.0f, 4.0f, 4.0f), Lake(45.0f, 22.0f, 5.0f)});
  ASSERT_NE(bodies, nullptr);
  ASSERT_EQ(bodies->BodyCount(), 2u);
  EXPECT_FLOAT_EQ(bodies->LevelAt(4.2f, 4.2f, 0.0f), 50.0f);
  EXPECT_FLOAT_EQ(bodies->LevelAt(23.0f, 5.0f, 0.0f), 45.0f);
  EXPECT_FLOAT_EQ(bodies->LevelAt(14.0f, 5.0f, 0.0f), 0.0f);
}

TEST(WaterBodies, FillFollowsConnectionNotHeightAlone)
{
  // Two basins at 40 joined by a channel at 45, and a third one apart.
  Field field(33, 9, 60.0f);
  field.Fill(1, 1, 5, 5, 40.0f);
  field.Fill(6, 3, 10, 3, 45.0f);
  field.Fill(11, 1, 15, 5, 40.0f);
  field.Fill(25, 1, 30, 5, 40.0f);
  const auto bodies = field.Build({Lake(50.0f, 3.0f, 3.0f)});
  ASSERT_NE(bodies, nullptr);
  EXPECT_EQ(bodies->BodyOfVertex(13, 3), 1u);
  EXPECT_EQ(bodies->BodyOfVertex(8, 3), 1u);
  EXPECT_EQ(bodies->BodyOfVertex(27, 3), 0u);
}

TEST(WaterBodies, BoundsStopTheFill)
{
  Field field(33, 9, 10.0f);
  SWaterBodyDesc desc = Lake(50.0f, 4.0f, 4.0f);
  desc.hasBounds = true;
  desc.x0 = 0;
  desc.z0 = 0;
  desc.x1 = 8;
  desc.z1 = 8;
  const auto bodies = field.Build({desc});
  ASSERT_NE(bodies, nullptr);
  EXPECT_EQ(bodies->BodyOfVertex(8, 4), 1u);
  EXPECT_EQ(bodies->BodyOfVertex(9, 4), 0u);
}

TEST(WaterBodies, EarlierBodyKeepsItsVertices)
{
  Field field(17, 9, 40.0f);
  const auto bodies = field.Build({Lake(50.0f, 2.0f, 2.0f), Lake(55.0f, 12.0f, 4.0f)});
  ASSERT_NE(bodies, nullptr);
  // The first fills everything; the second's seed is already taken.
  EXPECT_EQ(bodies->BodyCount(), 1u);
}

TEST(WaterBodies, SeedAboveItsLevelIsSkipped)
{
  Field field(17, 17, 60.0f);
  field.Fill(4, 4, 8, 8, 40.0f);
  std::vector<std::string> log;
  const auto bodies = field.Build({Lake(50.0f, 12.0f, 12.0f), Lake(50.0f, 6.0f, 6.0f)}, &log);
  ASSERT_NE(bodies, nullptr);
  EXPECT_EQ(bodies->BodyCount(), 1u);
  ASSERT_EQ(log.size(), 1u);
  EXPECT_NE(log[0].find("water body 1 skipped"), std::string::npos);
}

TEST(WaterBodies, SeedOffTheMapIsSkipped)
{
  const Field field(17, 17, 10.0f);
  std::vector<std::string> log;
  EXPECT_EQ(field.Build({Lake(50.0f, -3.0f, 6.0f)}, &log), nullptr);
  EXPECT_EQ(log.size(), 1u);
}

TEST(WaterBodies, DryBodyHasNoWater)
{
  // A polder at 5 below a sea at 20, closed by a dike at 25.
  Field field(17, 17, 0.0f);
  field.Fill(3, 3, 13, 13, 25.0f);
  field.Fill(5, 5, 11, 11, 5.0f);
  SWaterBodyDesc dry;
  dry.dry = true;
  dry.fillTo = 20.0f;
  dry.seedX = 8.0f;
  dry.seedZ = 8.0f;
  const auto bodies = field.Build({dry});
  ASSERT_NE(bodies, nullptr);
  EXPECT_FLOAT_EQ(bodies->LevelAt(8.0f, 8.0f, 20.0f), moho::kWaterBodyNoWater);
  EXPECT_FLOAT_EQ(bodies->LevelAt(1.0f, 1.0f, 20.0f), 20.0f);
  EXPECT_FLOAT_EQ(bodies->LevelOfVertex(8, 8, 20.0f), moho::kWaterBodyNoWater);
}

TEST(WaterBodies, LookupClampsAndToleratesNaN)
{
  Field field(9, 9, 0.0f);
  const auto bodies = field.Build({Lake(5.0f, 4.0f, 4.0f)});
  ASSERT_NE(bodies, nullptr);
  const float nan = std::numeric_limits<float>::quiet_NaN();
  EXPECT_FLOAT_EQ(bodies->LevelAt(nan, nan, 1.0f), 5.0f);
  EXPECT_FLOAT_EQ(bodies->LevelAt(-100.0f, 1e9f, 1.0f), 5.0f);
  EXPECT_FLOAT_EQ(bodies->HighestLevel(), 5.0f);
}
