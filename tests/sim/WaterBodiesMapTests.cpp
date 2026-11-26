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
        field
          ->data[static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width) + static_cast<std::size_t>(x)] =
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

  void AddLake(
    STIMap& map
  )
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

  SFootprint Footprint(
    const EOccupancyCaps caps,
    const float minDepth,
    const float maxDepth
  )
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

  SOCellPos Cell(
    const std::int16_t x,
    const std::int16_t z
  )
  {
    SOCellPos pos{};
    pos.x = x;
    pos.z = z;
    return pos;
  }

  moho::GeomLine3 DownAt(
    const float x,
    const float z
  )
  {
    moho::GeomLine3 line{};
    line.pos = Wm3::Vec3f(x, 200.0f, z);
    line.dir = Wm3::Vec3f(0.0f, -1.0f, 0.0f);
    line.closest = 0.0f;
    line.farthest = 400.0f;
    return line;
  }
} // namespace

TEST(
  WaterBodiesMap,
  WithoutBodiesTheSeaIsEverywhere
)
{
  const auto map = MakeMap();
  EXPECT_FALSE(map->HasWaterBodies());
  EXPECT_EQ(map->GetWaterElevationAt(40.0f, 24.0f), kSea);
  EXPECT_EQ(map->GetSurface(40.0f, 24.0f), 40.0f);
  EXPECT_EQ(map->GetSurface(8.0f, 8.0f), kSea);
  EXPECT_TRUE(map->AboveWater(Wm3::Vec3f(40.0f, 0.0f, 24.0f)));
}

TEST(
  WaterBodiesMap,
  LakeSurfaceStandsAtItsLevel
)
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

TEST(
  WaterBodiesMap,
  OccupancySeesTheLakeAsWater
)
{
  const auto map = MakeMap();
  const SFootprint naval = Footprint(EOccupancyCaps::OC_WATER, 1.5f, std::numeric_limits<float>::max());
  const SFootprint land = Footprint(EOccupancyCaps::OC_LAND, 0.0f, 0.5f);

  // Sea only: the basin is dry land.
  EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(40, 24), naval)), 0);
  EXPECT_EQ(
    static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(40, 24), land)), static_cast<int>(EOccupancyCaps::OC_LAND)
  );

  AddLake(*map);
  EXPECT_EQ(
    static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(40, 24), naval)), static_cast<int>(EOccupancyCaps::OC_WATER)
  );
  EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(40, 24), land)), 0);
  EXPECT_EQ(
    static_cast<int>(moho::OCCUPY_MobileCheck(naval, *map, Cell(38, 22))), static_cast<int>(EOccupancyCaps::OC_WATER)
  );

  // The plateau stays land, the sea stays water.
  EXPECT_EQ(
    static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(55, 50), land)), static_cast<int>(EOccupancyCaps::OC_LAND)
  );
  EXPECT_EQ(
    static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(5, 5), naval)), static_cast<int>(EOccupancyCaps::OC_WATER)
  );
}

TEST(
  WaterBodiesMap,
  RaysHitTheWaterTheyMeetFirst
)
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

TEST(
  WaterBodiesMap,
  BoundsIncludeTheLake
)
{
  auto map = MakeMap();
  // Lower the plateau under the lake level so the lake is the highest thing.
  moho::CHeightField* const field = map->mHeightField.get();
  for (std::int32_t z = 0; z < field->height; ++z) {
    for (std::int32_t x = 16; x < field->width; ++x) {
      std::uint16_t& sample =
        field->data[static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width) + static_cast<std::size_t>(x)];
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

TEST(
  WaterBodiesMap,
  CloneKeepsTheBodies
)
{
  auto map = MakeMap();
  AddLake(*map);
  STIMap clone(map.get());
  ASSERT_TRUE(clone.HasWaterBodies());
  EXPECT_EQ(clone.GetWaterElevationAt(40.5f, 24.5f), kLake);
}

// ---------------------------------------------------------------------------------------------------------
// Rivers (docs/projects/RIVERS.md): a sloped surface, and falls that nothing crosses.
// ---------------------------------------------------------------------------------------------------------

namespace
{
  using moho::SRiverPoint;

  constexpr float kRiverSea = 10.0f;

  SRiverPoint RiverPoint(
    const float x,
    const float level,
    const float halfWidth = 6.0f
  )
  {
    SRiverPoint point;
    point.x = x;
    point.z = 100.0f;
    point.level = level;
    point.halfWidth = halfWidth;
    return point;
  }

  SRiverPoint RiverFall(
    const float x,
    const float level,
    const float below
  )
  {
    SRiverPoint point = RiverPoint(x, level);
    point.fall = true;
    point.below = below;
    return point;
  }

  /// A river along z = 100: 40 above x = 60, 38 at the lip x = 100, then 30 below the fall (28 at x = 140).
  SWaterBodyDesc RiverBody(
    const bool withFall
  )
  {
    SWaterBodyDesc desc;
    desc.isRiver = true;
    desc.deep = 25.0f;
    desc.abyss = 10.0f;
    desc.river.points = {
      RiverPoint(20.0f, 40.0f),
      RiverPoint(60.0f, 38.5f),
      withFall ? RiverFall(100.0f, 38.0f, 30.0f) : RiverPoint(100.0f, 34.0f),
      RiverPoint(140.0f, 28.0f),
      RiverPoint(180.0f, 26.0f),
    };
    return desc;
  }

  /**
   * 257 x 257 vertices (a power of two of cells, as the height field's tiers need): ground at 60, a flat channel bed at
   * 20 over z in [94, 106] (the river's width), the sea at
   * 10. The ford: the bed raised to 0.04 under the river's surface over x in [90, 100] (the upstream side of the fall).
   */
  std::unique_ptr<STIMap> MakeRiverMap(
    const bool withFall,
    const bool ford
  )
  {
    auto map = std::make_unique<STIMap>(256u, 256u);
    moho::CHeightField* const field = map->mHeightField.get();
    const auto set = [&](const std::int32_t x, const std::int32_t z, const float level) {
      field->data[static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width) + static_cast<std::size_t>(x)] =
        static_cast<std::uint16_t>(level * 128.0f);
    };
    for (std::int32_t z = 0; z < field->height; ++z) {
      for (std::int32_t x = 0; x < field->width; ++x) {
        set(x, z, z >= 94 && z <= 106 ? 20.0f : 60.0f);
      }
    }
    if (ford) {
      // The river's own level there (the water and the bed are both multiples of 1/128).
      const auto probe =
        CWaterBodies::Build(field->data, field->width, field->height, kScale, {RiverBody(withFall)}, nullptr);
      for (std::int32_t x = 90; x <= 100; ++x) {
        for (std::int32_t z = 90; z <= 110; ++z) {
          const float level = probe->LevelOfVertex(x, 100, kRiverSea);
          field
            ->data[static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width) + static_cast<std::size_t>(x)] =
            static_cast<std::uint16_t>(level * 128.0f - 5.0f);
        }
      }
    }
    field->UpdateBounds(gpg::Rect2i{0, 0, 0x7FFFFFFF, 0x7FFFFFFF});
    map->SetWaterEnabledRaw(1u);
    map->SetWaterElevation(kRiverSea);
    map->SetWaterElevationDeep(kRiverSea - 2.0f);
    map->SetWaterElevationAbyss(kRiverSea - 8.0f);
    map->mWaterBodies =
      CWaterBodies::Build(field->data, field->width, field->height, kScale, {RiverBody(withFall)}, nullptr);
    return map;
  }

  SFootprint Foot(
    const std::uint8_t size,
    const std::uint8_t caps,
    const float minDepth,
    const float maxDepth,
    const float slope
  )
  {
    SFootprint footprint{};
    footprint.mSizeX = size;
    footprint.mSizeZ = size;
    footprint.mOccupancyCaps = static_cast<EOccupancyCaps>(caps);
    footprint.mMaxSlope = slope;
    footprint.mMinWaterDepth = minDepth;
    footprint.mMaxWaterDepth = maxDepth;
    return footprint;
  }

  constexpr std::uint8_t kLand = 0x1;
  constexpr std::uint8_t kSeabed = 0x2;
  constexpr std::uint8_t kSub = 0x4;
  constexpr std::uint8_t kWater = 0x8;

  /// The footprints of faf_repo/fa/lua/footprints.lua, one per class of mover.
  struct SNamedFootprint
  {
    const char* name;
    SFootprint footprint;
  };
  std::vector<SNamedFootprint> AllFootprints()
  {
    return {
      {"Vehicle1x1", Foot(1, kLand, 0.0f, 0.05f, 0.75f)},
      {"Vehicle2x2", Foot(2, kLand, 0.0f, 0.05f, 0.75f)},
      {"Amphibious1x1", Foot(1, kLand | kSeabed, 0.0f, 25.0f, 0.75f)},
      {"Amphibious3x3", Foot(3, kLand | kSeabed, 0.0f, 25.0f, 0.75f)},
      {"WaterLand1x1", Foot(1, kLand | kWater, 0.1f, 1.0f, 0.75f)},
      {"WaterLand3x3", Foot(3, kLand | kWater, 0.0f, 5.0f, 0.75f)},
      {"SurfacingSub2x2", Foot(2, kSub | kWater, 1.5f, 1.0e6f, 0.0f)},
      {"Water1x1", Foot(1, kWater, 1.5f, 1.0e6f, 0.0f)},
      {"Water3x3", Foot(3, kWater, 0.25f, 1.0e6f, 0.0f)},
      {"Water4x4", Foot(4, kWater, 1.5f, 1.0e6f, 0.0f)},
    };
  }

  int Caps(
    const STIMap& map,
    const SFootprint& footprint,
    const std::int16_t x,
    const std::int16_t z
  )
  {
    return static_cast<int>(moho::OCCUPY_MobileCheck(footprint, map, Cell(x, z)));
  }
} // namespace

TEST(
  WaterRiversMap,
  SurfaceFollowsTheProfile
)
{
  const auto map = MakeRiverMap(true, false);
  ASSERT_TRUE(map->HasWaterBodies());
  ASSERT_TRUE(map->mWaterBodies->HasRivers());

  EXPECT_NEAR(map->GetWaterElevationAtVertex(20, 100), 40.0f, kScale);
  EXPECT_NEAR(map->GetWaterElevationAtVertex(60, 100), 38.5f, kScale);
  EXPECT_NEAR(map->GetWaterElevationAtVertex(140, 100), 28.0f, kScale);
  EXPECT_NEAR(map->GetWaterElevationAt(60.5f, 100.5f), 38.5f, 0.05f);
  EXPECT_NEAR(map->GetWaterElevationAt(140.5f, 100.5f), 28.0f, 0.1f);
  EXPECT_GT(map->GetWaterElevationAt(40.5f, 100.5f), map->GetWaterElevationAt(80.5f, 100.5f));
  // Off the river: the sea.
  EXPECT_EQ(map->GetWaterElevationAt(60.5f, 130.5f), kRiverSea);
  EXPECT_EQ(map->GetWaterElevationAtVertex(60, 130), kRiverSea);

  // Surface and "above water" read the sloped level.
  EXPECT_NEAR(map->GetSurface(140.5f, 100.5f), 28.0f, 0.1f);
  EXPECT_FALSE(map->AboveWater(Wm3::Vec3f(140.5f, 0.0f, 100.5f)));
  EXPECT_EQ(map->GetSurface(60.5f, 130.5f), 60.0f);
  EXPECT_GE(map->GetBounds3D().Max.y, 60.0f);
}

TEST(
  WaterRiversMap,
  EveryFootprintClassStopsAtTheFall
)
{
  const auto map = MakeRiverMap(true, false);
  ASSERT_TRUE(map->mWaterBodies->HasFalls());

  for (const SNamedFootprint& entry : AllFootprints()) {
    // The cell of the fall (a footprint starting at x = 100 or reaching it from the left).
    EXPECT_EQ(Caps(*map, entry.footprint, 100, 100), 0) << entry.name << " on the fall";
    const std::int16_t reach = static_cast<std::int16_t>(100 - entry.footprint.mSizeX + 1);
    EXPECT_EQ(Caps(*map, entry.footprint, reach, 100), 0) << entry.name << " reaching the fall from the left";
  }

  // Water movers float on both sides, one cell from the fall.
  const SFootprint water = Foot(1, kWater, 1.5f, 1.0e6f, 0.0f);
  EXPECT_EQ(Caps(*map, water, 98, 100), static_cast<int>(EOccupancyCaps::OC_WATER));
  EXPECT_EQ(Caps(*map, water, 101, 100), static_cast<int>(EOccupancyCaps::OC_WATER));
  EXPECT_EQ(
    static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(98, 100), water)), static_cast<int>(EOccupancyCaps::OC_WATER)
  );
  EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(100, 100), water)), 0);

  // The whole width of the fall, bank to bank.
  const SFootprint amphibious = Foot(1, kLand | kSeabed, 0.0f, 25.0f, 0.75f);
  for (std::int16_t z = 93; z <= 106; ++z) {
    EXPECT_EQ(static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(100, z), amphibious)), 0) << z;
  }
  // The ground beside the channel is no fall: a land unit stands there, level with the lip.
  const SFootprint land = Foot(1, kLand, 0.0f, 0.05f, 0.75f);
  EXPECT_EQ(Caps(*map, land, 100, 91), static_cast<int>(EOccupancyCaps::OC_LAND));
  EXPECT_EQ(Caps(*map, land, 100, 109), static_cast<int>(EOccupancyCaps::OC_LAND));
  EXPECT_EQ(Caps(*map, land, 100, 130), static_cast<int>(EOccupancyCaps::OC_LAND));
}

TEST(
  WaterRiversMap,
  NoPathCrossesTheFallForWaterOrAmphibiousMovers
)
{
  const auto reaches =
    [](const STIMap& map, const SFootprint& footprint, const std::int16_t fromX, const std::int16_t toX) {
    constexpr std::int32_t kWidth = 256;
    constexpr std::int32_t kHeight = 256;
    std::vector<std::uint8_t> seen(static_cast<std::size_t>(kWidth) * static_cast<std::size_t>(kHeight), 0u);
    std::vector<std::int32_t> open{fromX + 100 * kWidth};
    seen[static_cast<std::size_t>(open.back())] = 1u;
    while (!open.empty()) {
      const std::int32_t at = open.back();
      open.pop_back();
      const std::int32_t cx = at % kWidth;
      const std::int32_t cz = at / kWidth;
      for (std::int32_t dz = -1; dz <= 1; ++dz) {
        for (std::int32_t dx = -1; dx <= 1; ++dx) {
          const std::int32_t nx = cx + dx;
          const std::int32_t nz = cz + dz;
          if (nx < 1 || nz < 1 || nx >= kWidth - 8 || nz >= kHeight - 8) {
            continue;
          }
          const std::size_t next = static_cast<std::size_t>(nx + nz * kWidth);
          if (
            seen[next] != 0u || Caps(map, footprint, static_cast<std::int16_t>(nx), static_cast<std::int16_t>(nz)) == 0
          ) {
            continue;
          }
          seen[next] = 1u;
          open.push_back(static_cast<std::int32_t>(next));
        }
      }
    }
    return seen[static_cast<std::size_t>(toX + 100 * kWidth)] != 0u;
  };

  const auto fall = MakeRiverMap(true, false);
  const auto slope = MakeRiverMap(false, false);
  ASSERT_FALSE(slope->mWaterBodies->HasFalls());

  // Naval: the river is the only water there is (the sea at 10 lies under the 20 of the bed).
  const SFootprint water = Foot(1, kWater, 1.5f, 1.0e6f, 0.0f);
  EXPECT_FALSE(reaches(*fall, water, 50, 150));
  EXPECT_TRUE(reaches(*fall, water, 50, 90));
  EXPECT_TRUE(reaches(*fall, water, 110, 150));
  EXPECT_TRUE(reaches(*slope, water, 50, 150));

  // Hover: floats on the river (depth 1.5 and more to 5, but no more than the walk over the bed), never over the fall.
  const SFootprint hover = Foot(1, kLand | kWater, 0.1f, 1.0f, 0.75f);
  EXPECT_FALSE(reaches(*fall, hover, 50, 150));
  EXPECT_TRUE(reaches(*slope, hover, 50, 150));

  // Amphibious: walks the bed of the channel (banks of ground at 60 are a cliff its slope limit does not
  // climb), never across the fall.
  const SFootprint amphibious = Foot(1, kLand | kSeabed, 0.0f, 25.0f, 0.75f);
  EXPECT_FALSE(reaches(*fall, amphibious, 50, 150));
  EXPECT_TRUE(reaches(*slope, amphibious, 50, 150));
}

TEST(
  WaterRiversMap,
  FordUpstreamOfTheFallIsCrossedButNotTheFall
)
{
  const auto map = MakeRiverMap(true, true);
  const SFootprint land = Foot(1, kLand, 0.0f, 0.05f, 0.75f);

  // The ford (water 0.04 deep): land units walk bank to bank across the river.
  for (std::int16_t z = 91; z <= 109; ++z) {
    EXPECT_EQ(Caps(*map, land, 95, z), static_cast<int>(EOccupancyCaps::OC_LAND)) << z;
  }
  // Up to the lip.
  EXPECT_EQ(Caps(*map, land, 99, 100), static_cast<int>(EOccupancyCaps::OC_LAND));
  // Not over it: the fall cell and everything whose footprint reaches it, structures included.
  EXPECT_EQ(Caps(*map, land, 100, 100), 0);
  EXPECT_EQ(Caps(*map, Foot(2, kLand, 0.0f, 0.05f, 0.75f), 99, 100), 0);
  EXPECT_EQ(Caps(*map, Foot(2, kLand, 0.0f, 0.05f, 0.75f), 97, 100), static_cast<int>(EOccupancyCaps::OC_LAND));
  const SFootprint building = Foot(5, kLand, 0.0f, 0.05f, 0.75f);
  EXPECT_EQ(Caps(*map, building, 96, 98), 0) << "a 5 x 5 building whose cells include the fall";
  EXPECT_EQ(Caps(*map, building, 93, 98), static_cast<int>(EOccupancyCaps::OC_LAND));
  EXPECT_EQ(Caps(*map, building, 101, 98), 0) << "below the fall the channel is deep water";
}

TEST(
  WaterRiversMap,
  RaysHitTheSlopedSurface
)
{
  const auto map = MakeRiverMap(true, false);
  moho::CColHitResult hit{};

  for (const float x : {30.5f, 50.5f, 80.5f, 120.5f, 150.5f, 170.5f}) {
    const Wm3::Vec3f point = map->SurfaceIntersection(DownAt(x, 100.5f), &hit);
    EXPECT_EQ(hit.hitKind, 3) << x;
    EXPECT_NEAR(point.y, map->GetWaterElevationAt(x, 100.5f), 0.02f) << x;
    EXPECT_LT(point.y, 40.01f) << x;
  }
  // Below the fall the ray does not stop at the 40 of the river's highest level.
  EXPECT_LT(map->SurfaceIntersection(DownAt(150.5f, 100.5f), &hit).y, 30.0f);

  // A slanted ray from above the upstream reach.
  moho::GeomLine3 slanted{};
  slanted.pos = Wm3::Vec3f(30.5f, 80.0f, 100.5f);
  slanted.dir = Wm3::Vec3f(0.70710678f, -0.70710678f, 0.0f);
  slanted.closest = 0.0f;
  slanted.farthest = 400.0f;
  const Wm3::Vec3f entry = map->SurfaceIntersection(slanted, &hit);
  EXPECT_EQ(hit.hitKind, 3);
  EXPECT_NEAR(entry.y, map->GetWaterElevationAt(entry.x, entry.z), 0.05f);
  EXPECT_GT(entry.x, 60.0f);

  // Ground beside the river is the ground.
  const Wm3::Vec3f ground = map->SurfaceIntersection(DownAt(60.5f, 130.5f), &hit);
  EXPECT_NEAR(ground.y, 60.0f, 0.01f);
  EXPECT_EQ(hit.hitKind, 1);
  const Wm3::Vec3f bank = map->SurfaceIntersection(DownAt(60.5f, 92.5f), &hit);
  EXPECT_NEAR(bank.y, 60.0f, 0.01f);
  EXPECT_EQ(hit.hitKind, 1);

  // Starting under the surface: the start is the hit.
  moho::GeomLine3 under = DownAt(60.5f, 100.5f);
  under.pos.y = 30.0f;
  EXPECT_FLOAT_EQ(map->SurfaceIntersection(under, &hit).y, 30.0f);
}

TEST(
  WaterRiversMap,
  MapWithoutFallsIsUnchangedAndCloneKeepsTheRiver
)
{
  const auto map = MakeRiverMap(false, false);
  EXPECT_FALSE(map->mWaterBodies->HasFalls());
  const SFootprint water = Foot(1, kWater, 1.5f, 1.0e6f, 0.0f);
  EXPECT_EQ(Caps(*map, water, 100, 100), static_cast<int>(EOccupancyCaps::OC_WATER));
  EXPECT_EQ(
    static_cast<int>(map->OccupancyCapsOfFootprintAt(Cell(100, 100), water)), static_cast<int>(EOccupancyCaps::OC_WATER)
  );

  const auto withFall = MakeRiverMap(true, false);
  STIMap clone(withFall.get());
  ASSERT_TRUE(clone.HasWaterBodies());
  EXPECT_TRUE(clone.mWaterBodies->HasFalls());
  EXPECT_NEAR(clone.GetWaterElevationAt(140.5f, 100.5f), 28.0f, 0.1f);
  EXPECT_EQ(Caps(clone, water, 100, 100), 0);
}
