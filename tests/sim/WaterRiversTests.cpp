// Engine addition: the derivation of a river's level field, flow and falls (docs/projects/RIVERS.md).
//
// Pure: the code under test is moho/sim/WaterRivers.cpp and WaterBodies.cpp with no engine around, so
// the same file runs in the x64 and the x86 build (the golden checksums below are the proof that both
// derive the same bytes).
#include "moho/sim/WaterBodies.h"
#include "moho/sim/WaterRivers.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace
{
  using moho::CWaterBodies;
  using moho::CWaterRiver;
  using moho::SRiverDesc;
  using moho::SRiverPoint;
  using moho::SWaterBodyDesc;

  constexpr float kScale = 1.0f / 128.0f;

  struct Terrain
  {
    std::int32_t width;
    std::int32_t height;
    std::vector<std::uint16_t> samples;

    Terrain(
      const std::int32_t w,
      const std::int32_t h,
      const float level
    )
      : width(w)
      , height(h)
      , samples(static_cast<std::size_t>(w) * static_cast<std::size_t>(h), Word(level))
    {}

    static std::uint16_t Word(
      const float level
    )
    {
      return static_cast<std::uint16_t>(level * 128.0f);
    }

    void Fill(
      const std::int32_t x0,
      const std::int32_t z0,
      const std::int32_t x1,
      const std::int32_t z1,
      const float level
    )
    {
      for (std::int32_t z = z0; z <= z1; ++z) {
        for (std::int32_t x = x0; x <= x1; ++x) {
          samples[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)] =
            Word(level);
        }
      }
    }
  };

  SRiverPoint Point(
    const float x,
    const float z,
    const float level,
    const float halfWidth
  )
  {
    SRiverPoint point;
    point.x = x;
    point.z = z;
    point.level = level;
    point.halfWidth = halfWidth;
    return point;
  }

  SRiverPoint Fall(
    const float x,
    const float z,
    const float level,
    const float below,
    const float halfWidth
  )
  {
    SRiverPoint point = Point(x, z, level, halfWidth);
    point.fall = true;
    point.below = below;
    return point;
  }

  /// A river along z = 100 with a fall at x = 100: 40 above it, a drop to 30 and on down to 26.
  SRiverDesc StraightRiver()
  {
    SRiverDesc river;
    river.points = {
      Point(20.0f, 100.0f, 40.0f, 6.0f),
      Point(60.0f, 100.0f, 38.5f, 6.0f),
      Fall(100.0f, 100.0f, 38.0f, 30.0f, 6.0f),
      Point(140.0f, 100.0f, 28.0f, 6.0f),
      Point(180.0f, 100.0f, 26.0f, 6.0f),
    };
    return river;
  }

  /// 200 x 160 vertices of ground at 60 with a channel bed at 20 around the river's centreline.
  Terrain Valley()
  {
    Terrain terrain(200, 160, 60.0f);
    terrain.Fill(0, 88, 199, 112, 20.0f);
    return terrain;
  }

  std::shared_ptr<const CWaterRiver> Derive(
    const SRiverDesc& desc,
    const Terrain& terrain,
    std::string* error = nullptr
  )
  {
    return CWaterRiver::Build(desc, terrain.samples.data(), terrain.width, terrain.height, kScale, error);
  }

  float LevelOf(
    const CWaterRiver& river,
    const std::int32_t x,
    const std::int32_t z
  )
  {
    float level = std::numeric_limits<float>::quiet_NaN();
    EXPECT_TRUE(river.VertexLevel(x, z, level)) << "vertex " << x << ", " << z;
    return level;
  }
} // namespace

TEST(
  WaterRivers,
  ValidatesTheDescription
)
{
  EXPECT_TRUE(moho::ValidateRiver(StraightRiver()).empty());

  SRiverDesc river = StraightRiver();
  river.points.resize(1);
  EXPECT_FALSE(moho::ValidateRiver(river).empty());

  river = StraightRiver();
  river.points[1].halfWidth = 0.5f;
  EXPECT_NE(moho::ValidateRiver(river).find("HalfWidth"), std::string::npos);
  river.points[1].halfWidth = 65.0f;
  EXPECT_FALSE(moho::ValidateRiver(river).empty());

  // Levels do not rise downstream.
  river = StraightRiver();
  river.points[1].level = 41.0f;
  EXPECT_NE(moho::ValidateRiver(river).find("rises"), std::string::npos);
  // After a fall the next level must not exceed Below.
  river = StraightRiver();
  river.points[3].level = 31.0f;
  EXPECT_NE(moho::ValidateRiver(river).find("rises"), std::string::npos);

  // A fall is neither the first nor the last point, and its step is large enough to block.
  river = StraightRiver();
  river.points[0].fall = true;
  river.points[0].below = 39.0f;
  EXPECT_FALSE(moho::ValidateRiver(river).empty());
  river = StraightRiver();
  river.points[2].below = 37.5f;
  EXPECT_NE(moho::ValidateRiver(river).find("Fall"), std::string::npos);
  river.points[2].below = 38.0f - moho::kRiverFallDrop;
  EXPECT_TRUE(moho::ValidateRiver(river).empty());

  // At most 16 falls.
  river.points.clear();
  float level = 400.0f;
  river.points.push_back(Point(0.0f, 0.0f, level, 4.0f));
  for (int i = 1; i <= 17; ++i) {
    level -= 10.0f;
    river.points.push_back(Fall(static_cast<float>(i) * 10.0f, 0.0f, level, level - 1.0f, 4.0f));
    level -= 1.0f;
  }
  river.points.push_back(Point(200.0f, 0.0f, level - 1.0f, 4.0f));
  EXPECT_NE(moho::ValidateRiver(river).find("falls"), std::string::npos);

  // Numbers that are not numbers, a step count and a margin out of range.
  river = StraightRiver();
  river.points[0].x = std::numeric_limits<float>::quiet_NaN();
  EXPECT_FALSE(moho::ValidateRiver(river).empty());
  river = StraightRiver();
  river.steps = 0;
  EXPECT_FALSE(moho::ValidateRiver(river).empty());
  river.steps = moho::kRiverMaxSteps + 1;
  EXPECT_FALSE(moho::ValidateRiver(river).empty());
  river = StraightRiver();
  river.margin = 0.5f;
  EXPECT_FALSE(moho::ValidateRiver(river).empty());
}

TEST(
  WaterRivers,
  PolylineIsLinearInLevelAndBreaksAtAFall
)
{
  SRiverDesc river;
  river.points = {Point(0.0f, 0.0f, 10.0f, 4.0f), Point(32.0f, 0.0f, 6.0f, 4.0f)};
  river.steps = 8;
  std::vector<moho::SRiverFall> falls;
  const std::vector<moho::SRiverSegment> straight = moho::RiverSegments(river, &falls);
  ASSERT_EQ(straight.size(), 8u);
  EXPECT_TRUE(falls.empty());
  float length = 0.0f;
  for (const moho::SRiverSegment& segment : straight) {
    EXPECT_FLOAT_EQ(segment.z0, 0.0f);
    EXPECT_FLOAT_EQ(segment.tx, 1.0f);
    EXPECT_FLOAT_EQ(segment.tz, 0.0f);
    EXPECT_FLOAT_EQ(segment.s0, length);
    length += segment.length;
  }
  EXPECT_NEAR(length, 32.0f, 1.0e-4f);
  EXPECT_FLOAT_EQ(straight.front().level0, 10.0f);
  EXPECT_FLOAT_EQ(straight.back().level1, 6.0f);

  // The fall: the span before ends at Level, the span after starts at Below, nothing joins them.
  const std::vector<moho::SRiverSegment> broken = moho::RiverSegments(StraightRiver(), &falls);
  ASSERT_EQ(broken.size(), 32u);
  ASSERT_EQ(falls.size(), 1u);
  EXPECT_FLOAT_EQ(falls[0].x, 100.0f);
  EXPECT_FLOAT_EQ(falls[0].top, 38.0f);
  EXPECT_FLOAT_EQ(falls[0].bottom, 30.0f);
  EXPECT_FLOAT_EQ(falls[0].tx, 1.0f);
  EXPECT_FLOAT_EQ(broken[15].x1, 100.0f);
  EXPECT_FLOAT_EQ(broken[15].level1, 38.0f);
  EXPECT_FLOAT_EQ(broken[16].x0, 100.0f);
  EXPECT_FLOAT_EQ(broken[16].level0, 30.0f);
}

TEST(
  WaterRivers,
  FieldFollowsTheCentrelineAndStaysInsideTheChannel
)
{
  const Terrain terrain = Valley();
  std::string error;
  const auto river = Derive(StraightRiver(), terrain, &error);
  ASSERT_NE(river, nullptr) << error;

  // The profile at the knots, 1/128 unit.
  EXPECT_NEAR(LevelOf(*river, 20, 100), 40.0f, kScale);
  EXPECT_NEAR(LevelOf(*river, 60, 100), 38.5f, kScale);
  EXPECT_NEAR(LevelOf(*river, 140, 100), 28.0f, kScale);
  EXPECT_NEAR(LevelOf(*river, 180, 100), 26.0f, kScale);
  // The same level across the width: the nearest point of the centreline is straight above.
  EXPECT_EQ(LevelOf(*river, 40, 96), LevelOf(*river, 40, 100));
  EXPECT_EQ(LevelOf(*river, 40, 104), LevelOf(*river, 40, 100));
  // It falls downstream between the knots.
  EXPECT_GT(LevelOf(*river, 30, 100), LevelOf(*river, 50, 100));
  EXPECT_GT(LevelOf(*river, 120, 100), LevelOf(*river, 160, 100));

  // Wet: within the half width and above the bed. Support: half width plus the margin.
  EXPECT_TRUE(river->IsWetVertex(40, 94));
  EXPECT_TRUE(river->IsWetVertex(40, 106));
  EXPECT_FALSE(river->IsWetVertex(40, 93));
  float level = 0.0f;
  EXPECT_TRUE(river->VertexLevel(40, 93, level));
  EXPECT_TRUE(river->VertexLevel(40, 107, level));
  EXPECT_FALSE(river->VertexLevel(40, 109, level));
  EXPECT_FALSE(river->VertexLevel(5, 100, level));

  EXPECT_FLOAT_EQ(river->LevelMax(), 40.0f);
  EXPECT_FLOAT_EQ(river->LevelMin(), 26.0f);

  // The flow is along the river.
  float fx = 0.0f;
  float fz = 1.0f;
  ASSERT_TRUE(river->FlowAt(40.0f, 100.0f, fx, fz));
  EXPECT_NEAR(fx, 1.0f, 1.0f / 127.0f);
  EXPECT_NEAR(fz, 0.0f, 1.0f / 127.0f);
  EXPECT_FALSE(river->FlowAt(5.0f, 5.0f, fx, fz));
}

TEST(
  WaterRivers,
  NoLeakIntoABasinBesideTheChannelOrOverARidge
)
{
  Terrain terrain = Valley();
  // A deep basin below the river's level 12 units beside the channel, and a ridge across the channel.
  terrain.Fill(30, 114, 50, 125, 5.0f);
  terrain.Fill(80, 88, 82, 112, 50.0f);
  const auto river = Derive(StraightRiver(), terrain);
  ASSERT_NE(river, nullptr);

  EXPECT_FALSE(river->IsWetVertex(40, 118));
  EXPECT_FALSE(river->IsWetVertex(40, 120));
  // Terrain at 50 is above the 38 or so of the river there: dry, but the level is still defined.
  EXPECT_FALSE(river->IsWetVertex(81, 100));
  float level = 0.0f;
  EXPECT_TRUE(river->VertexLevel(81, 100, level));
  EXPECT_TRUE(river->IsWetVertex(70, 100));
  EXPECT_TRUE(river->IsWetVertex(90, 100));
}

TEST(
  WaterRivers,
  FallStepsTheSurfaceAndMarksItsCells
)
{
  const Terrain terrain = Valley();
  const auto river = Derive(StraightRiver(), terrain);
  ASSERT_NE(river, nullptr);

  // On the line of the fall the tie goes to the lower segment, the one before the fall.
  EXPECT_NEAR(LevelOf(*river, 100, 100), 38.0f, kScale);
  EXPECT_NEAR(LevelOf(*river, 99, 100), 38.0f, 0.1f);
  EXPECT_NEAR(LevelOf(*river, 101, 100), 30.0f, 0.1f);

  // Cells with two wet corners across the step: the 12 rows of the channel and the 2 rows at its banks.
  EXPECT_TRUE(river->HasFalls());
  EXPECT_EQ(river->FallCellCount(), 14u);
  for (std::int32_t z = 93; z <= 106; ++z) {
    EXPECT_TRUE(river->IsFallCell(100, z)) << z;
    EXPECT_FALSE(river->IsFallCell(99, z)) << z;
    EXPECT_FALSE(river->IsFallCell(101, z)) << z;
  }
  EXPECT_FALSE(river->IsFallCell(100, 92));
  EXPECT_FALSE(river->IsFallCell(100, 107));
  EXPECT_FALSE(river->IsFallCell(-1, 100));
  EXPECT_FALSE(river->IsFallCell(500, 100));

  // Nothing wet crosses it: from the cells above the fall, with every move of eight directions that does not
  // enter a fall cell, the cells below are not reached; without the barrier they are.
  const auto reaches = [&](const bool barrier) {
    const std::int32_t cellsX = terrain.width - 1;
    const std::int32_t cellsZ = terrain.height - 1;
    const auto wetCell = [&](const std::int32_t cx, const std::int32_t cz) {
      return river->IsWetVertex(cx, cz) || river->IsWetVertex(cx + 1, cz) || river->IsWetVertex(cx, cz + 1) ||
        river->IsWetVertex(cx + 1, cz + 1);
    };
    std::vector<std::uint8_t> seen(static_cast<std::size_t>(cellsX) * static_cast<std::size_t>(cellsZ), 0u);
    std::vector<std::int32_t> open{50 + 100 * cellsX};
    seen[static_cast<std::size_t>(open.back())] = 1u;
    while (!open.empty()) {
      const std::int32_t at = open.back();
      open.pop_back();
      const std::int32_t cx = at % cellsX;
      const std::int32_t cz = at / cellsX;
      for (std::int32_t dz = -1; dz <= 1; ++dz) {
        for (std::int32_t dx = -1; dx <= 1; ++dx) {
          const std::int32_t nx = cx + dx;
          const std::int32_t nz = cz + dz;
          if (nx < 0 || nz < 0 || nx >= cellsX || nz >= cellsZ || !wetCell(nx, nz)) {
            continue;
          }
          if (barrier && river->IsFallCell(nx, nz)) {
            continue;
          }
          const std::int32_t next = nx + nz * cellsX;
          if (seen[static_cast<std::size_t>(next)] == 0u) {
            seen[static_cast<std::size_t>(next)] = 1u;
            open.push_back(next);
          }
        }
      }
    }
    return seen[static_cast<std::size_t>(150 + 100 * cellsX)] != 0u;
  };
  EXPECT_FALSE(reaches(true));
  EXPECT_TRUE(reaches(false));
}

TEST(
  WaterRivers,
  SteepButContinuousSlopeIsNoFallBelowTheDrop
)
{
  // A slope of 0.2 per unit between neighbouring vertices stays well under the 0.75 step.
  SRiverDesc river;
  river.points = {Point(20.0f, 100.0f, 60.0f, 6.0f), Point(120.0f, 100.0f, 40.0f, 6.0f)};
  const Terrain terrain = Valley();
  const auto derived = Derive(river, terrain);
  ASSERT_NE(derived, nullptr);
  EXPECT_FALSE(derived->HasFalls());
  EXPECT_EQ(derived->FallCellCount(), 0u);
  EXPECT_FALSE(derived->IsFallCell(70, 100));
}

TEST(
  WaterRivers,
  LevelAtIsBilinearOverTheCell
)
{
  SRiverDesc river;
  river.points = {Point(20.0f, 100.0f, 40.0f, 6.0f), Point(120.0f, 100.0f, 30.0f, 6.0f)};
  river.steps = 4;
  const Terrain terrain = Valley();
  const auto derived = Derive(river, terrain);
  ASSERT_NE(derived, nullptr);

  float level = 0.0f;
  ASSERT_TRUE(derived->LevelAt(60.5f, 100.5f, level));
  const float west = LevelOf(*derived, 60, 100);
  const float east = LevelOf(*derived, 61, 100);
  EXPECT_NEAR(level, 0.5f * (west + east), 1.0e-4f);
  ASSERT_TRUE(derived->LevelAt(60.0f, 100.0f, level));
  EXPECT_EQ(level, west);
  ASSERT_TRUE(derived->LevelAt(61.0f, 100.0f, level));
  EXPECT_EQ(level, east);
  EXPECT_LT(east, west);
  // A cell with no corner in the support has no level.
  EXPECT_FALSE(derived->LevelAt(150.0f, 20.0f, level));
}

TEST(
  WaterRivers,
  RefusesWhatItCannotDerive
)
{
  const Terrain terrain = Valley();
  std::string error;

  // Larger than a quarter of the map: a diagonal river's rectangle.
  SRiverDesc river;
  river.points = {Point(10.0f, 10.0f, 40.0f, 6.0f), Point(190.0f, 150.0f, 30.0f, 6.0f)};
  EXPECT_EQ(Derive(river, terrain, &error), nullptr);
  EXPECT_NE(error.find("quarter"), std::string::npos) << error;

  // Over ground above its level: nothing wet.
  Terrain high(200, 160, 60.0f);
  EXPECT_EQ(Derive(StraightRiver(), high, &error), nullptr);
  EXPECT_NE(error.find("below"), std::string::npos) << error;

  // Off the map.
  river.points = {Point(500.0f, 500.0f, 40.0f, 6.0f), Point(550.0f, 500.0f, 30.0f, 6.0f)};
  EXPECT_EQ(Derive(river, terrain, &error), nullptr);
  EXPECT_NE(error.find("off the map"), std::string::npos) << error;

  // Invalid.
  river = StraightRiver();
  river.points[1].level = 99.0f;
  EXPECT_EQ(Derive(river, terrain, &error), nullptr);
  EXPECT_NE(error.find("rises"), std::string::npos) << error;
}

TEST(
  WaterRivers,
  DerivationIsRepeatableAndHasAGoldenChecksum
)
{
  const Terrain terrain = Valley();
  const auto first = Derive(StraightRiver(), terrain);
  const auto second = Derive(StraightRiver(), terrain);
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);
  EXPECT_EQ(first->Checksum(), second->Checksum());
  // The same checksum in the x64 and the x86 build (float code with + - * / and sqrt in a fixed order,
  // -ffp-contract=off): a change here is a change of what every replay of a map with rivers sees.
  EXPECT_EQ(first->Checksum(), 0xC17E796Eu) << std::hex << first->Checksum();

  // A bend: the spline and the nearest-segment projection (Voronoi borders of the corners) are in it too.
  SRiverDesc bend;
  bend.points = {
    Point(20.0f, 100.0f, 40.0f, 5.0f),
    Point(70.0f, 90.0f, 39.0f, 7.0f),
    Point(110.0f, 105.0f, 37.0f, 9.0f),
    Point(160.0f, 95.0f, 33.0f, 6.0f),
  };
  const auto curved = Derive(bend, terrain);
  ASSERT_NE(curved, nullptr);
  EXPECT_EQ(curved->Checksum(), 0x613BD852u) << std::hex << curved->Checksum();
}

TEST(
  WaterRiverBodies,
  RiverBodyOwnsItsChannelAndAnswersPerPosition
)
{
  const Terrain terrain = Valley();
  SWaterBodyDesc desc;
  desc.isRiver = true;
  desc.river = StraightRiver();
  desc.deep = 25.0f;
  desc.abyss = 10.0f;
  std::vector<std::string> log;
  const auto bodies = CWaterBodies::Build(terrain.samples.data(), terrain.width, terrain.height, kScale, {desc}, &log);
  ASSERT_NE(bodies, nullptr);
  EXPECT_TRUE(log.empty());
  ASSERT_EQ(bodies->BodyCount(), 1u);
  EXPECT_TRUE(bodies->HasRivers());
  EXPECT_TRUE(bodies->HasFalls());
  EXPECT_TRUE(bodies->IsRiver(1));
  EXPECT_FALSE(bodies->IsRiver(0));
  EXPECT_FALSE(bodies->IsRiver(2));

  const moho::SWaterBody& body = bodies->Body(1);
  EXPECT_FLOAT_EQ(body.elevation, 40.0f);
  EXPECT_FLOAT_EQ(body.levelMax, 40.0f);
  EXPECT_FLOAT_EQ(body.levelMin, 26.0f);
  EXPECT_GT(body.cellCount, 0u);
  EXPECT_FLOAT_EQ(bodies->HighestLevel(), 40.0f);

  // Per vertex and per position, the sloped level; outside the channel the sea (here 12).
  constexpr float kSea = 12.0f;
  EXPECT_NEAR(bodies->LevelOfVertex(20, 100, kSea), 40.0f, kScale);
  EXPECT_NEAR(bodies->LevelOfVertex(140, 100, kSea), 28.0f, kScale);
  EXPECT_NEAR(bodies->LevelAt(20.5f, 100.5f, kSea), 40.0f, 0.2f);
  EXPECT_NEAR(bodies->LevelAt(140.5f, 100.5f, kSea), 28.0f, 0.2f);
  EXPECT_EQ(bodies->LevelOfVertex(40, 130, kSea), kSea);
  EXPECT_EQ(bodies->LevelAt(40.5f, 130.5f, kSea), kSea);
  EXPECT_EQ(bodies->BodyOfVertex(40, 100), 1u);
  EXPECT_EQ(bodies->BodyOfVertex(40, 93), 0u);

  // The bilinear surface is continuous along the river.
  float previous = bodies->LevelAt(21.5f, 100.5f, kSea);
  for (float x = 22.5f; x < 60.0f; x += 1.0f) {
    const float level = bodies->LevelAt(x, 100.5f, kSea);
    EXPECT_LE(level, previous + 1.0e-4f) << x;
    EXPECT_GT(level, previous - 0.5f) << x;
    previous = level;
  }

  // Falls: one bit per cell, the same cells as the river's.
  EXPECT_TRUE(bodies->IsFallCell(100, 100));
  EXPECT_FALSE(bodies->IsFallCell(99, 100));
  EXPECT_FALSE(bodies->IsFallCell(101, 100));
  EXPECT_FALSE(bodies->IsFallCell(-1, 100));
  EXPECT_FALSE(bodies->IsFallCell(100, 1000));

  float fx = 0.0f;
  float fz = 1.0f;
  EXPECT_TRUE(bodies->FlowAt(40.5f, 100.5f, fx, fz));
  EXPECT_NEAR(fx, 1.0f, 1.0f / 127.0f);
  EXPECT_FALSE(bodies->FlowAt(40.5f, 130.5f, fx, fz));

  // A copy shares the immutable river and answers the same.
  const CWaterBodies copy(*bodies);
  EXPECT_TRUE(copy.IsFallCell(100, 100));
  EXPECT_EQ(copy.LevelAt(140.5f, 100.5f, kSea), bodies->LevelAt(140.5f, 100.5f, kSea));
}

TEST(
  WaterRiverBodies,
  LakesAreUnchangedAndWithoutARiverThereAreNoFalls
)
{
  Terrain terrain(64, 64, 60.0f);
  terrain.Fill(20, 20, 30, 30, 40.0f);
  SWaterBodyDesc lake;
  lake.elevation = 50.0f;
  lake.deep = 48.0f;
  lake.abyss = 40.0f;
  lake.fillTo = 50.0f;
  lake.seedX = 25.0f;
  lake.seedZ = 25.0f;
  const auto bodies =
    CWaterBodies::Build(terrain.samples.data(), terrain.width, terrain.height, kScale, {lake}, nullptr);
  ASSERT_NE(bodies, nullptr);
  EXPECT_FALSE(bodies->HasRivers());
  EXPECT_FALSE(bodies->HasFalls());
  EXPECT_FALSE(bodies->IsRiver(1));
  EXPECT_EQ(bodies->River(1), nullptr);
  EXPECT_FALSE(bodies->IsFallCell(25, 25));
  EXPECT_EQ(bodies->LevelAt(25.5f, 25.5f, -10000.0f), 50.0f);
  EXPECT_EQ(bodies->LevelOfVertex(25, 25, -10000.0f), 50.0f);
  EXPECT_FLOAT_EQ(bodies->Body(1).levelMin, 50.0f);
  EXPECT_FLOAT_EQ(bodies->Body(1).levelMax, 50.0f);
  float fx = 0.0f;
  float fz = 0.0f;
  EXPECT_FALSE(bodies->FlowAt(25.5f, 25.5f, fx, fz));
}

TEST(
  WaterRiverBodies,
  EarlierBodyKeepsItsVerticesAndABadRiverIsSkippedWithAReason
)
{
  const Terrain terrain = Valley();
  // A lake first, then the river over the same channel: the lake keeps the vertices it takes.
  SWaterBodyDesc lake;
  lake.elevation = 45.0f;
  lake.deep = 40.0f;
  lake.abyss = 30.0f;
  lake.fillTo = 45.0f;
  lake.seedX = 100.0f;
  lake.seedZ = 100.0f;
  lake.hasBounds = true;
  lake.x0 = 0;
  lake.z0 = 88;
  lake.x1 = 60;
  lake.z1 = 112;
  SWaterBodyDesc river;
  river.isRiver = true;
  river.river = StraightRiver();
  river.deep = 25.0f;
  river.abyss = 10.0f;
  SWaterBodyDesc bad = river;
  bad.river.points[1].level = 99.0f;
  std::vector<std::string> log;
  // The lake's seed is outside its bounds, so it is skipped too: the river alone is body 1.
  const auto bodies =
    CWaterBodies::Build(terrain.samples.data(), terrain.width, terrain.height, kScale, {lake, bad, river}, &log);
  ASSERT_NE(bodies, nullptr);
  ASSERT_EQ(bodies->BodyCount(), 1u);
  EXPECT_TRUE(bodies->IsRiver(1));
  ASSERT_EQ(log.size(), 2u);
  EXPECT_NE(log[1].find("river"), std::string::npos) << log[1];
  EXPECT_NE(log[1].find("rises"), std::string::npos) << log[1];

  // Lake bounds around the seed this time: the lake takes the upstream part of the channel.
  lake.x0 = 80;
  lake.x1 = 100;
  log.clear();
  const auto both =
    CWaterBodies::Build(terrain.samples.data(), terrain.width, terrain.height, kScale, {lake, river}, &log);
  ASSERT_NE(both, nullptr);
  ASSERT_EQ(both->BodyCount(), 2u);
  EXPECT_FALSE(both->IsRiver(1));
  EXPECT_TRUE(both->IsRiver(2));
  EXPECT_EQ(both->BodyOfVertex(90, 100), 1u);
  EXPECT_EQ(both->BodyOfVertex(40, 100), 2u);
  EXPECT_EQ(both->LevelOfVertex(90, 100, 12.0f), 45.0f);
  EXPECT_NEAR(both->LevelOfVertex(140, 100, 12.0f), 28.0f, kScale);
}
