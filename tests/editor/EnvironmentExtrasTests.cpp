// Environment extras: symmetric decal places (the middle mirrored, not the corner), the generated water masks, the
// shipped moods.

#include "editor/doc/EdLookMoods.h"
#include "editor/tools/EdDecalShape.h"
#include "editor/tools/EdWaterMasks.h"

#include <gtest/gtest.h>

#include <cmath>

namespace faf::editor
{
  TEST(
    DecalSymmetry,
    MiddlesMirroredAndHeadingsCarried
  )
  {
    // A 257-sample map: mirror left-right about x = 128.
    const std::vector<DecalPlace> mirror = DecalCopyPlaces(257, 257, 30.0f, 50.0f, 0.0f, Symmetry::LeftRight, 2);
    ASSERT_EQ(mirror.size(), 2U);
    EXPECT_FLOAT_EQ(mirror[1].x, 226.0f);
    EXPECT_FLOAT_EQ(mirror[1].z, 50.0f);
    // Facing +x on the left faces -x on the right.
    EXPECT_NEAR(std::fabs(mirror[1].heading), 3.14159265f, 1e-4f);
    // Each copy's footprint has its middle where the copy is (DecalAround then DecalCentre).
    for (const DecalPlace& place : mirror) {
      float cx = 0.0f;
      float cz = 0.0f;
      DecalCentre(DecalAround(place.x, place.z, 12.0f, 6.0f, place.heading), cx, cz);
      EXPECT_NEAR(cx, place.x, 1e-3f);
      EXPECT_NEAR(cz, place.z, 1e-3f);
    }
    // A half turn: the middle goes to the opposite point, the heading turns round.
    const std::vector<DecalPlace> half = DecalCopyPlaces(257, 257, 40.0f, 60.0f, 0.5f, Symmetry::HalfTurn, 2);
    ASSERT_EQ(half.size(), 2U);
    EXPECT_FLOAT_EQ(half[1].x, 216.0f);
    EXPECT_FLOAT_EQ(half[1].z, 196.0f);
    EXPECT_NEAR(std::remainder(half[1].heading - (0.5f + 3.14159265f), 6.2831853f), 0.0f, 1e-4f);
    // Four quarter turns: four places, all on the map.
    EXPECT_EQ(DecalCopyPlaces(257, 257, 40.0f, 60.0f, 0.0f, Symmetry::QuarterTurns, 4).size(), 4U);
  }

  TEST(
    WaterMasks,
    GeneratedMaskWrittenByMode
  )
  {
    std::vector<std::uint8_t> cells(4 * 4, 100);
    const auto half = [](const float x, float) {
      return x < 4.0f ? 1.0f : 0.0f; // the left two columns (middles 1 and 3)
    };
    EXPECT_EQ(WriteIntoWaterMask(cells.data(), 4, 4, half, 0, 1.0f), 16);
    EXPECT_EQ(cells[0], 255);
    EXPECT_EQ(cells[3], 0);
    std::vector<std::uint8_t> added(4, 100);
    (void)WriteIntoWaterMask(added.data(), 4, 1, half, 1, 0.5f);
    EXPECT_EQ(added[0], 228); // 100 + 127.5
    EXPECT_EQ(added[3], 100);
    std::vector<std::uint8_t> taken(4, 100);
    (void)WriteIntoWaterMask(taken.data(), 4, 1, half, 2, 1.0f);
    EXPECT_EQ(taken[0], 0);
  }

  TEST(
    LookMoods,
    MoodsSetTheLight
  )
  {
    EXPECT_GE(LookMoods().size(), 18U);
    const LookMood* const dusk = FindLookMood("dusk");
    ASSERT_NE(dusk, nullptr);
    LightingState base;
    base.specular[0] = 0.3f;
    const LightingState lit = MoodLighting(*dusk, base);
    EXPECT_FLOAT_EQ(lit.multiplier, dusk->multiplier);
    EXPECT_FLOAT_EQ(lit.fogColor[0], dusk->fog[0]);
    EXPECT_FLOAT_EQ(lit.specular[0], 0.3f); // the map's specular stays
    float azimuth = 0.0f;
    float elevation = 0.0f;
    SunAnglesOf(lit.sunDirection, azimuth, elevation);
    EXPECT_NEAR(elevation, dusk->elevation, 0.01f);
    EXPECT_EQ(FindLookMood("nope"), nullptr);
  }
} // namespace faf::editor
