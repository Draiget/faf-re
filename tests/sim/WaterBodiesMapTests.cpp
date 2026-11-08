// Engine addition: the map's water queries with water bodies (.plans/water-levels/PLAN.md).
#include "moho/sim/STIMap.h"
#include "moho/sim/WaterBodies.h"

#include <gtest/gtest.h>

#include <cmath>
#include <limits>
#include <memory>
#include <vector>

namespace
{
  using moho::CWaterBodies;
  using moho::EOccupancyCaps;
  using moho::SFootprint;
  using moho::SOCellPos;
  using moho::STIMap;
  using moho::SWaterBodyDesc;

  constexpr float kScale = 1.0f / 128.0f;
  constexpr float kSea = 10.0f;
  constexpr float kLake = 50.0f;

  /**
   * 64 x 64 cells: lowland at 2 (under the sea at 10) for x < 16, a plateau at 60
   * elsewhere, with a basin at 40 over vertices [36, 44] x [20, 28].
   */
  std::unique_ptr<STIMap> MakeMap()
  {
    auto map = std::make_unique<STIMap>(64u, 64u);
    moho::CHeightField* const field = map->mHeightField.get();
    for (std::int32_t z = 0; z < field->height; ++z) {
      for (std::int32_t x = 0; x < field->width; ++x) {
        float level = x < 16 ? 2.0f : 60.0f;
        if (x >= 36 && x <= 44 && z >= 20 && z <= 28) {
          level = 40.0f;
        }
        field->data[static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width) + static_cast<std::size_t>(x)] =
          static_cast<std::uint16_t>(level * 128.0f);
      }
    }
    field->UpdateBounds(gpg::Rect2i{0, 0, 0x7FFFFFFF, 0x7FFFFFFF});
    map->SetWaterEnabledRaw(1u);
    map->SetWaterElevation(kSea);
    map->SetWaterElevationDeep(kSea - 2.0f);
    map->SetWaterElevationAbyss(kSea - 10.0f);
    return map;
  }

  void AddLake(STIMap& map)
  {
    SWaterBodyDesc lake;
    lake.elevation = kLake;
    lake.deep = kLake - 2.0f;
    lake.abyss = kLake - 10.0f;
    lake.fillTo = kLake;
    lake.seedX = 40.0f;
    lake.seedZ = 24.0f;
    const moho::CHeightField* const field = map.mHeightField.get();
    map.mWaterBodies = CWaterBodies::Build(field->data, field->width, field->height, kScale, {lake}, nullptr);
  }

  SFootprint Footprint(const EOccupancyCaps caps, const float minDepth, const float maxDepth)
  {
    SFootprint footprint{};
    footprint.mSizeX = 1;
    footprint.mSizeZ = 1;
    footprint.mOccupancyCaps = caps;
    footprint.mMaxSlope = 0.0f;
    footprint.mMinWaterDepth = minDepth;
    footprint.mMaxWaterDepth = maxDepth;
    return footprint;
  }

  SOCellPos Cell(const std::int16_t x, const std::int16_t z)
  {
    SOCellPos pos{};
    pos.x = x;
    pos.z = z;
    return pos;
  }

  moho::GeomLine3 DownAt(const float x, const float z)
  {
    moho::GeomLine3 line{};
    line.pos = Wm3::Vec3f(x, 200.0f, z);
    line.dir = Wm3::Vec3f(0.0f, -1.0f, 0.0f);
    line.closest = 0.0f;
    line.farthest = 400.0f;
    return line;
  }
} // namespace

TEST(WaterBodiesMap, WithoutBodiesTheSeaIsEverywhere)
{
  const auto map = MakeMap();
  EXPECT_FALSE(map->HasWaterBodies());
  EXPECT_EQ(map->GetWaterElevationAt(40.0f, 24.0f), kSea);
  EXPECT_EQ(map->GetSurface(40.0f, 24.0f), 40.0f);
  EXPECT_EQ(map->GetSurface(8.0f, 8.0f), kSea);
  EXPECT_TRUE(map->AboveWater(Wm3::Vec3f(40.0f, 0.0f, 24.0f)));
}

TEST(WaterBodiesMap, LakeSurfaceStandsAtItsLevel)
{
  const auto map = MakeMap();
  AddLake(*map);
  ASSERT_TRUE(map->HasWaterBodies());

  EXPECT_EQ(map->GetWaterElevationAt(40.5f, 24.5f), kLake);
  EXPECT_EQ(map->GetSurface(40.5f, 24.5f), kLake);
  EXPECT_FALSE(map->AboveWater(Wm3::Vec3f(40.5f, 0.0f, 24.5f)));

  // The sea and the plateau keep their own heights.
  EXPECT_EQ(map->GetSurface(8.0f, 8.0f), kSea);
  EXPECT_EQ(map->GetSurface(55.0f, 50.0f), 60.0f);
  EXPECT_TRUE(map->AboveWater(Wm3::Vec3f(55.0f, 0.0f, 50.0f)));

  // The vertex query that GetElevation(int, int) uses.
  EXPECT_EQ(map->GetElevation(40, 24), kLake);
  EXPECT_EQ(map->GetElevation(8, 8), kSea);
}

TEST(WaterBodiesMap, OccupancySeesTheLakeAsWater)
{
  const auto map = MakeMap();
  const SFootprint naval = Footprint(EOccupancyCaps::OC_WATER, 1.5f, std::numeric_limits<float>::max());
  const SFootprint land = Footprint(EOccupancyCaps::OC_LAND, 0.0f, 0.5f);

  // Sea only: the basin is dry land.
  EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(40, 24), naval)), 0);
  EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(40, 24), land)), static_cast<int>(EOccupancyCaps::OC_LAND));

  AddLake(*map);
  EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(40, 24), naval)), static_cast<int>(EOccupancyCaps::OC_WATER));
  EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(40, 24), land)), 0);
  EXPECT_EQ(
    static_cast<int>(moho::OCCUPY_MobileCheck(naval, *map, Cell(38, 22))), static_cast<int>(EOccupancyCaps::OC_WATER)
  );

  // The plateau stays land, the sea stays water.
  EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(55, 50), land)), static_cast<int>(EOccupancyCaps::OC_LAND));
  EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(5, 5), naval)), static_cast<int>(EOccupancyCaps::OC_WATER));
}

TEST(WaterBodiesMap, RaysHitTheWaterTheyMeetFirst)
{
  const auto map = MakeMap();
  AddLake(*map);

  moho::CColHitResult hit{};
  const Wm3::Vec3f lakeHit = map->SurfaceIntersection(DownAt(40.5f, 24.5f), &hit);
  EXPECT_FLOAT_EQ(lakeHit.y, kLake);
  EXPECT_EQ(hit.hitKind, 3);

  const Wm3::Vec3f seaHit = map->SurfaceIntersection(DownAt(8.0f, 8.0f), &hit);
  EXPECT_FLOAT_EQ(seaHit.y, kSea);
  EXPECT_EQ(hit.hitKind, 3);

  const Wm3::Vec3f groundHit = map->SurfaceIntersection(DownAt(55.0f, 50.0f), &hit);
  EXPECT_NEAR(groundHit.y, 60.0f, 0.01f);
  EXPECT_EQ(hit.hitKind, 1);

  // Starting under the lake's surface: the start point is the hit.
  moho::GeomLine3 under = DownAt(40.5f, 24.5f);
  under.pos.y = 45.0f;
  const Wm3::Vec3f underHit = map->SurfaceIntersection(under, &hit);
  EXPECT_FLOAT_EQ(underHit.y, 45.0f);
}

TEST(WaterBodiesMap, BoundsIncludeTheLake)
{
  auto map = MakeMap();
  // Lower the plateau under the lake level so the lake is the highest thing.
  moho::CHeightField* const field = map->mHeightField.get();
  for (std::int32_t z = 0; z < field->height; ++z) {
    for (std::int32_t x = 16; x < field->width; ++x) {
      std::uint16_t& sample = field->data[static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width) + static_cast<std::size_t>(x)];
      if (sample == static_cast<std::uint16_t>(60.0f * 128.0f)) {
        sample = static_cast<std::uint16_t>(45.0f * 128.0f);
      }
    }
  }
  field->UpdateBounds(gpg::Rect2i{0, 0, 0x7FFFFFFF, 0x7FFFFFFF});
  SWaterBodyDesc lake;
  lake.elevation = kLake;
  lake.fillTo = 41.0f;
  lake.seedX = 40.0f;
  lake.seedZ = 24.0f;
  map->mWaterBodies = CWaterBodies::Build(field->data, field->width, field->height, kScale, {lake}, nullptr);
  ASSERT_TRUE(map->HasWaterBodies());
  EXPECT_GE(map->GetBounds3D().Max.y, kLake);
}

TEST(WaterBodiesMap, CloneKeepsTheBodies)
{
  auto map = MakeMap();
  AddLake(*map);
  STIMap clone(map.get());
  ASSERT_TRUE(clone.HasWaterBodies());
  EXPECT_EQ(clone.GetWaterElevationAt(40.5f, 24.5f), kLake);
}
