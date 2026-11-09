// The client's spatial database (moho/mesh/SpatialDb.h): registration, bounds updates, typed and box
// collects, checked against a brute-force list of the same entries. Owners are only stored and handed back,
// so the test registers stand-in addresses.

#include "moho/mesh/SpatialDb.h"
#include "moho/sim/COGrid.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <random>
#include <set>
#include <vector>

namespace moho
{
  class MeshInstance;
}

namespace
{
  using Db = moho::SpatialDB<moho::MeshInstance>;
  using DbEntry = moho::SpatialDBEntry<moho::MeshInstance>;

  constexpr std::uint32_t kUnit = moho::ENTITYTYPE_Unit;
  constexpr std::uint32_t kProp = moho::ENTITYTYPE_Prop;
  constexpr std::uint32_t kProjectile = moho::ENTITYTYPE_Projectile;
  constexpr std::uint32_t kEntity = moho::ENTITYTYPE_Entity;

  /** One registered object, as the oracle sees it. */
  struct SOracleEntry
  {
    moho::MeshInstance* owner = nullptr;
    std::uint32_t mask = 0;
    Wm3::AxisAlignedBox3f box{};
    bool live = true;
  };

  /**
   * The one map an entry is kept in (SpatialShardData::Insert): the first of unit, projectile, prop that its
   * registration mask has, else entity.
   */
  std::uint32_t MapOf(const std::uint32_t mask)
  {
    if ((mask & kUnit) != 0u) {
      return kUnit;
    }
    if ((mask & kProjectile) != 0u) {
      return kProjectile;
    }
    if ((mask & kProp) != 0u) {
      return kProp;
    }
    return kEntity;
  }

  /** Wild Magic's AxisAlignedBox3::TestIntersection: inclusive on every axis. */
  bool Touch(const Wm3::AxisAlignedBox3f& a, const Wm3::AxisAlignedBox3f& b)
  {
    return !(a.Max.x < b.Min.x || a.Min.x > b.Max.x || a.Max.y < b.Min.y || a.Min.y > b.Max.y || a.Max.z < b.Min.z
             || a.Min.z > b.Max.z);
  }

  std::multiset<moho::MeshInstance*> Owners(const gpg::fastvector<moho::MeshInstance*>& found)
  {
    std::multiset<moho::MeshInstance*> owners;
    for (std::size_t i = 0; i < found.size(); ++i) {
      owners.insert(found[i]);
    }
    return owners;
  }

  class SpatialDbFixture : public testing::Test
  {
  protected:
    static constexpr std::size_t kCount = 400;

    SpatialDbFixture()
      : mStorage(kCount)
    {
      mDb.ResizeForMap(1024, 1024);
      mEntries.resize(kCount); // no reallocation afterwards: an entry holds an iterator into the database
    }

    moho::MeshInstance* OwnerOf(const std::size_t index)
    {
      return reinterpret_cast<moho::MeshInstance*>(&mStorage[index]);
    }

    Wm3::AxisAlignedBox3f RandomBox(std::mt19937& rng, const float low, const float high)
    {
      std::uniform_real_distribution<float> position(low, high);
      std::uniform_real_distribution<float> size(0.5f, 30.0f);
      const Wm3::Vector3f min{position(rng), position(rng) * 0.05f, position(rng)};
      return Wm3::AxisAlignedBox3f(min, {min.x + size(rng), min.y + size(rng), min.z + size(rng)});
    }

    void RegisterAll(std::mt19937& rng)
    {
      const std::uint32_t masks[] = {kUnit, kProp, kProjectile, kEntity, kUnit | kProp, kProp | kProjectile};
      for (std::size_t i = 0; i < kCount; ++i) {
        SOracleEntry entry;
        entry.owner = OwnerOf(i);
        entry.mask = masks[i % 6];
        // A tenth of the boxes lie outside the 1024 x 1024 map: the database keeps them in its overflow lane.
        entry.box = (i % 10 == 9) ? RandomBox(rng, 1200.0f, 2000.0f) : RandomBox(rng, 0.0f, 1000.0f);
        mEntries[i].Register(&mDb, entry.owner, static_cast<std::int32_t>(entry.mask));
        mEntries[i].UpdateBounds(entry.box);
        mOracle.push_back(entry);
      }
    }

    std::multiset<moho::MeshInstance*> ExpectedOfType(const std::uint32_t type) const
    {
      std::multiset<moho::MeshInstance*> owners;
      for (const SOracleEntry& entry : mOracle) {
        if (entry.live && (MapOf(entry.mask) & type) != 0u) {
          owners.insert(entry.owner);
        }
      }
      return owners;
    }

    std::multiset<moho::MeshInstance*> ExpectedUnitsIn(const Wm3::AxisAlignedBox3f& box) const
    {
      std::multiset<moho::MeshInstance*> owners;
      for (const SOracleEntry& entry : mOracle) {
        if (entry.live && MapOf(entry.mask) == kUnit && Touch(entry.box, box)) {
          owners.insert(entry.owner);
        }
      }
      return owners;
    }

    std::multiset<moho::MeshInstance*> Collect(const std::uint32_t type)
    {
      gpg::fastvector<moho::MeshInstance*> found;
      const std::int32_t count = mDb.Collect(found, static_cast<moho::EEntityType>(type));
      EXPECT_EQ(count, static_cast<std::int32_t>(found.size()));
      return Owners(found);
    }

    std::multiset<moho::MeshInstance*> CollectInBox(const Wm3::AxisAlignedBox3f& box)
    {
      gpg::fastvector<moho::MeshInstance*> found;
      const std::int32_t count = mDb.CollectInBox(found, box);
      EXPECT_EQ(count, static_cast<std::int32_t>(found.size()));
      return Owners(found);
    }

    std::vector<std::uint64_t> mStorage; // the stand-in owners' addresses
    Db mDb;                              // declared before the entries, so they unregister first
    std::vector<DbEntry> mEntries;
    std::vector<SOracleEntry> mOracle;
  };
} // namespace

// Each entry is kept in one map, by the first of unit, projectile, prop its mask has (0x00502200), and a typed
// collect returns the entries of the maps whose bits it asks for.
TEST_F(SpatialDbFixture, TypedCollectFindsEachEntryInItsOneMap)
{
  std::mt19937 rng(17);
  RegisterAll(rng);
  for (const std::uint32_t type : {kUnit, kProp, kProjectile, kEntity, kUnit | kProp, kProp | kProjectile | kEntity,
                                   kUnit | kProp | kProjectile | kEntity}) {
    SCOPED_TRACE(testing::Message() << "type 0x" << std::hex << type);
    EXPECT_EQ(Collect(type), ExpectedOfType(type));
  }
}

// A box collect returns the units whose box touches the query box, edges included, inside the map grid and in
// the overflow lane (0x00504040 collects units only).
TEST_F(SpatialDbFixture, BoxCollectFindsTheTouchingUnits)
{
  std::mt19937 rng(23);
  RegisterAll(rng);
  for (int query = 0; query < 60; ++query) {
    const Wm3::AxisAlignedBox3f box = RandomBox(rng, -100.0f, 2100.0f);
    const Wm3::AxisAlignedBox3f grown(box.Min, {box.Max.x + 150.0f, box.Max.y + 150.0f, box.Max.z + 150.0f});
    SCOPED_TRACE(testing::Message() << "query " << query);
    EXPECT_EQ(CollectInBox(grown), ExpectedUnitsIn(grown));
  }
  const Wm3::AxisAlignedBox3f everything({-10000.0f, -10000.0f, -10000.0f}, {10000.0f, 10000.0f, 10000.0f});
  EXPECT_EQ(CollectInBox(everything), ExpectedOfType(kUnit));
}

// Unregistering takes an entry out of every collect; moving it re-seats it where its new box lies.
TEST_F(SpatialDbFixture, UnregisterAndMoveKeepTheCollectsExact)
{
  std::mt19937 rng(31);
  RegisterAll(rng);
  for (std::size_t i = 0; i < kCount; i += 3) {
    mEntries[i].Unregister();
    mOracle[i].live = false;
  }
  for (std::size_t i = 1; i < kCount; i += 3) {
    mOracle[i].box = RandomBox(rng, 0.0f, 2000.0f);
    mEntries[i].UpdateBounds(mOracle[i].box);
  }
  EXPECT_EQ(Collect(kUnit | kProp | kProjectile | kEntity), ExpectedOfType(kUnit | kProp | kProjectile | kEntity));
  for (int query = 0; query < 30; ++query) {
    const Wm3::AxisAlignedBox3f box = RandomBox(rng, -100.0f, 2100.0f);
    const Wm3::AxisAlignedBox3f grown(box.Min, {box.Max.x + 200.0f, box.Max.y + 200.0f, box.Max.z + 200.0f});
    SCOPED_TRACE(testing::Message() << "query " << query);
    EXPECT_EQ(CollectInBox(grown), ExpectedUnitsIn(grown));
  }
}

// A small move inside one cell only grows the cell's bounds (UpdateBounds, 0x00501C10): the entry stays found
// at its new place, and at the old one only where the old box still touches the query.
TEST_F(SpatialDbFixture, SmallMoveStaysFoundAtItsNewPlace)
{
  const Wm3::AxisAlignedBox3f start({100.0f, 0.0f, 100.0f}, {104.0f, 4.0f, 104.0f});
  const Wm3::AxisAlignedBox3f moved({102.0f, 0.0f, 101.0f}, {106.0f, 4.0f, 105.0f});
  mEntries[0].Register(&mDb, OwnerOf(0), static_cast<std::int32_t>(kUnit));
  mEntries[0].UpdateBounds(start);
  mEntries[0].UpdateBounds(moved);
  const std::multiset<moho::MeshInstance*> one{OwnerOf(0)};
  EXPECT_EQ(CollectInBox(Wm3::AxisAlignedBox3f({105.5f, 1.0f, 104.5f}, {107.0f, 2.0f, 106.0f})), one);
  EXPECT_TRUE(CollectInBox(Wm3::AxisAlignedBox3f({99.0f, 1.0f, 99.0f}, {101.5f, 2.0f, 100.5f})).empty());
}

// Entries registered without bounds wait in the database's own map; a collect hands them back whatever type it
// asks for (0x00503F80 walks that map without a type test).
TEST_F(SpatialDbFixture, EntriesWithoutBoundsAreCollectedForAnyType)
{
  mEntries[0].Register(&mDb, OwnerOf(0), static_cast<std::int32_t>(kProp));
  mEntries[1].Register(&mDb, OwnerOf(1), static_cast<std::int32_t>(kUnit));
  const std::multiset<moho::MeshInstance*> both{OwnerOf(0), OwnerOf(1)};
  EXPECT_EQ(Collect(kEntity), both);
  mEntries[0].UpdateBounds(Wm3::AxisAlignedBox3f({10.0f, 0.0f, 10.0f}, {12.0f, 2.0f, 12.0f}));
  const std::multiset<moho::MeshInstance*> unboundUnit{OwnerOf(1)};
  EXPECT_EQ(Collect(kEntity), unboundUnit);
  const std::multiset<moho::MeshInstance*> prop{OwnerOf(0), OwnerOf(1)};
  EXPECT_EQ(Collect(kProp), prop);
}

// The map's order (0x00504990): entries that never fade first, ascending, then fading ones by descending cutoff.
TEST(SpatialEntryOrder, NeverFadingFirstThenLongestFadeFirst)
{
  moho::SpatialEntryLess<moho::MeshInstance> less;
  const auto entry = [](const float fade) {
    moho::SpatialEntry<moho::MeshInstance> e{};
    e.mFadeOut = fade;
    return e;
  };
  EXPECT_TRUE(less(entry(-1.0f), entry(0.0f)));
  EXPECT_FALSE(less(entry(0.0f), entry(0.0f)));
  EXPECT_TRUE(less(entry(0.0f), entry(5.0f)));
  EXPECT_FALSE(less(entry(5.0f), entry(0.0f)));
  EXPECT_TRUE(less(entry(9.0f), entry(5.0f)));
  EXPECT_FALSE(less(entry(5.0f), entry(9.0f)));
  EXPECT_FALSE(less(entry(5.0f), entry(5.0f)));
}
