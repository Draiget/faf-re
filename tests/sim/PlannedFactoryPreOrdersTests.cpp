// Planned factory pre-orders (ui_FactoryPreOrders, src/moho/sim/PlannedFactoryProxy.cpp): the client-only
// unit ids, the command-stream guard, and the bookkeeping that needs no session (sites, builders, slots,
// which new unit a planned factory is, kept orders). The engine paths (ISSUE_Command, selection, the beat
// update) are checked in a game.

#include <gtest/gtest.h>

#include <cstdint>
#include <algorithm>
#include <vector>

#include "moho/console/CConCommand.h"
#include "moho/entity/EntityId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/PlannedFactoryProxy.h"
#include "moho/command/ClientOnlyIds.h"

/// The manager is process-wide; every test starts and ends with it empty and the switch on.
class PlannedFactoryTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mWasEnabled = moho::IsFactoryPreOrdersEnabled();
    moho::SetFactoryPreOrdersEnabled(true);
    moho::PlannedFactoryManager::Get().Clear();
  }

  void TearDown() override
  {
    moho::PlannedFactoryManager::Get().Clear();
    moho::SetFactoryPreOrdersEnabled(mWasEnabled);
  }

  moho::PlannedFactoryManager& Manager()
  {
    return moho::PlannedFactoryManager::Get();
  }

  moho::RUnitBlueprint mLandFactory{nullptr, moho::RResId{}};
  moho::RUnitBlueprint mAirFactory{nullptr, moho::RResId{}};

private:
  bool mWasEnabled{false};
};

namespace
{
  [[nodiscard]] moho::BVSet<moho::EntId, moho::EntIdUniverse> SetOf(
    const std::vector<std::uint32_t>& ids
  )
  {
    moho::BVSet<moho::EntId, moho::EntIdUniverse> set{};
    for (const std::uint32_t id : ids) {
      (void)set.Bits().Add(id);
    }
    return set;
  }

  [[nodiscard]] std::vector<std::uint32_t> IdsOf(
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>& set
  )
  {
    std::vector<std::uint32_t> ids;
    for (const moho::EntId id : set) {
      ids.push_back(static_cast<std::uint32_t>(id));
    }
    return ids;
  }
} // namespace

TEST(
  PlannedFactoryIds,
  SwitchIsOffByDefaultAndFollowsTheConsole
)
{
  const bool before = moho::IsFactoryPreOrdersEnabled();
  moho::CON_Execute("ui_FactoryPreOrders 1");
  EXPECT_TRUE(moho::IsFactoryPreOrdersEnabled());
  moho::CON_Execute("ui_FactoryPreOrders 0");
  EXPECT_FALSE(moho::IsFactoryPreOrdersEnabled());
  moho::SetFactoryPreOrdersEnabled(before);
}

TEST(
  PlannedFactoryIds,
  NoSimSerialIsClientOnly
)
{
  // The PR's first version took every serial with bits 0x7000 for a planned factory: real units with
  // serials 0x7000-0x7FFF and 0xF000-0xFFFF lost their orders.
  for (const std::uint32_t serial : {0x0u, 0x1u, 0x7000u, 0x7001u, 0x7FFFu, 0xF000u, 0xFFFFu, 0x17000u, 0xFEFFFu}) {
    for (const std::uint8_t army : {std::uint8_t{0}, std::uint8_t{1}, std::uint8_t{15}}) {
      const std::uint32_t id = moho::MakeEntityId(moho::EEntityIdFamily::Unit, army, serial);
      EXPECT_FALSE(moho::IsClientOnlyUnitId(id)) << std::hex << id;
    }
  }
}

TEST(
  PlannedFactoryIds,
  EveryProxySlotIsClientOnlyAndDistinct
)
{
  EXPECT_EQ(moho::kMaxPlannedProxies, 0x1000u);
  std::vector<std::uint32_t> seen;
  for (std::uint32_t slot = 0; slot < moho::kMaxPlannedProxies; ++slot) {
    const std::uint32_t id = moho::MakePlannedProxyUnitId(3, slot);
    ASSERT_TRUE(moho::IsClientOnlyUnitId(id)) << std::hex << id;
    EXPECT_EQ(moho::ExtractEntityIdSourceIndex(id), 3u);
    EXPECT_EQ(moho::ExtractEntityIdFamilyNibble(id), 0u);
    seen.push_back(id);
  }
  std::ranges::sort(seen);
  EXPECT_EQ(std::ranges::adjacent_find(seen), seen.end());
}

TEST(
  PlannedFactoryIds,
  OtherFamiliesAndTheInvalidIdAreNotClientOnly
)
{
  EXPECT_FALSE(moho::IsClientOnlyUnitId(moho::MakeEntityId(moho::EEntityIdFamily::Projectile, 1, 0xFF000u)));
  EXPECT_FALSE(moho::IsClientOnlyUnitId(moho::MakeEntityId(moho::EEntityIdFamily::Prop, 1, 0xFFFFFu)));
  EXPECT_FALSE(moho::IsClientOnlyUnitId(moho::ToRaw(moho::EEntityIdSentinel::Invalid)));
  EXPECT_FALSE(moho::IsClientOnlyUnitId(0xFFFFFFFFu));
}

TEST(
  PlannedFactoryIds,
  DriverGuardDropsOnlyClientOnlyIds
)
{
  const std::uint32_t real1 = moho::MakeEntityId(moho::EEntityIdFamily::Unit, 1, 5);
  const std::uint32_t real2 = moho::MakeEntityId(moho::EEntityIdFamily::Unit, 1, 0x7005u);
  const std::uint32_t planned = moho::MakePlannedProxyUnitId(1, 7);

  moho::BVSet<moho::EntId, moho::EntIdUniverse> storage{};
  const auto realOnly = SetOf({real1, real2});
  const auto& same = moho::WithoutClientOnlyUnits(realOnly, storage);
  EXPECT_EQ(&same, &realOnly) << "a set of sim units must pass through untouched";

  const auto mixed = SetOf({real1, planned, real2});
  const auto& filtered = moho::WithoutClientOnlyUnits(mixed, storage);
  EXPECT_EQ(IdsOf(filtered), (std::vector<std::uint32_t>{real1, real2}));
  EXPECT_EQ(IdsOf(mixed).size(), 3u) << "the caller's set is not changed";

  const auto plannedOnly = SetOf({planned});
  EXPECT_TRUE(IdsOf(moho::WithoutClientOnlyUnits(plannedOnly, storage)).empty());
}

TEST(
  PlannedFactoryIds,
  ClientOnlyCommandIdsAreRegisteredAndReleased
)
{
  constexpr std::int32_t kLine = 0x01000123;
  EXPECT_FALSE(moho::IsClientOnlyCommand(kLine));
  moho::RegisterClientOnlyCommand(kLine);
  moho::RegisterClientOnlyCommand(kLine);
  EXPECT_TRUE(moho::IsClientOnlyCommand(kLine));
  EXPECT_FALSE(moho::IsClientOnlyCommand(kLine + 1));
  moho::ReleaseClientOnlyCommand(kLine);
  EXPECT_FALSE(moho::IsClientOnlyCommand(kLine)) << "registered twice, one release frees it";
}

TEST(
  PlannedFactoryIds,
  OnlyLiveClientOnlyUnitsCountInLuaArguments
)
{
  // A Lua argument is a number of any meaning; only the id of a planned factory alive now drops a callback.
  const std::uint32_t planned = moho::MakePlannedProxyUnitId(0, 4);
  EXPECT_FALSE(moho::IsLiveClientOnlyUnit(planned)) << "in the range, but no such planned factory";
  moho::RegisterClientOnlyUnit(planned);
  EXPECT_TRUE(moho::IsLiveClientOnlyUnit(planned));
  EXPECT_FALSE(moho::IsLiveClientOnlyUnit(moho::MakeEntityId(moho::EEntityIdFamily::Unit, 0, 4)));
  moho::RegisterClientOnlyUnit(moho::MakeEntityId(moho::EEntityIdFamily::Unit, 0, 4));
  EXPECT_FALSE(moho::IsLiveClientOnlyUnit(moho::MakeEntityId(moho::EEntityIdFamily::Unit, 0, 4)))
    << "a sim id is never client-only, registered or not";
  moho::ReleaseClientOnlyUnit(planned);
  moho::ReleaseClientOnlyUnit(moho::MakeEntityId(moho::EEntityIdFamily::Unit, 0, 4));
  EXPECT_FALSE(moho::IsLiveClientOnlyUnit(planned));
}

TEST(
  PlannedFactoryIds,
  ClientOnlyTargets
)
{
  moho::SSTITarget target{};
  target.mType = moho::EAiTargetType::AITARGET_Entity;
  target.mEnt = moho::MakePlannedProxyUnitId(0, 3);
  EXPECT_TRUE(moho::IsClientOnlyTarget(target));
  target.mEnt = moho::MakeEntityId(moho::EEntityIdFamily::Unit, 0, 3);
  EXPECT_FALSE(moho::IsClientOnlyTarget(target));
  target.mType = moho::EAiTargetType::AITARGET_Ground;
  target.mEnt = moho::MakePlannedProxyUnitId(0, 3);
  EXPECT_FALSE(moho::IsClientOnlyTarget(target)) << "a ground target's entity field is not sent";
}

TEST_F(
  PlannedFactoryTest,
  ClearReleasesRallyLineIds
)
{
  auto* const proxy = Manager().AddProxy(10, 100, &mLandFactory, {0.0f, 0.0f, 0.0f});
  moho::RallyPointOrder order{};
  order.helperId = 0x01000777;
  moho::RegisterClientOnlyCommand(order.helperId);
  proxy->AddRallyOrder(order, false);
  ASSERT_TRUE(moho::IsClientOnlyCommand(0x01000777));
  // The session's end: the next session hands the same command ids out to real orders.
  Manager().ForgetAll();
  EXPECT_FALSE(moho::IsClientOnlyCommand(0x01000777));
}

TEST_F(
  PlannedFactoryTest,
  BuildersOfOneSiteShareAProxy
)
{
  auto* const first = Manager().AddProxy(10, 100, &mLandFactory, {50.0f, 0.0f, 50.0f});
  ASSERT_NE(first, nullptr);
  auto* const second = Manager().AddProxy(11, 101, &mLandFactory, {50.5f, 0.0f, 50.0f});
  EXPECT_EQ(second, first);
  EXPECT_EQ(first->mBuilders.size(), 2u);
  EXPECT_TRUE(first->HasBuilder(11, 101));

  // The same builder and command again adds nothing.
  (void)Manager().AddProxy(10, 100, &mLandFactory, {50.0f, 0.0f, 50.0f});
  EXPECT_EQ(first->mBuilders.size(), 2u);

  // Another factory kind on the spot, or the same kind further away, is another plan.
  EXPECT_NE(Manager().AddProxy(12, 102, &mAirFactory, {50.0f, 0.0f, 50.0f}), first);
  EXPECT_NE(Manager().AddProxy(13, 103, &mLandFactory, {60.0f, 0.0f, 50.0f}), first);
  EXPECT_EQ(Manager().GetCount(), 3u);
}

TEST_F(
  PlannedFactoryTest,
  SlotsAreReusedAndBounded
)
{
  for (std::uint32_t i = 0; i < moho::kMaxPlannedProxies; ++i) {
    auto* const proxy = Manager().AddProxy(
      i + 1, static_cast<std::int32_t>(i), &mLandFactory, {static_cast<float>(i) * 20.0f, 0.0f, 0.0f}
    );
    ASSERT_NE(proxy, nullptr) << i;
    ASSERT_EQ(proxy->mProxyId, i);
  }
  EXPECT_EQ(Manager().AddProxy(99999, 1, &mLandFactory, {-500.0f, 0.0f, -500.0f}), nullptr)
    << "past the client-only range nothing is planned; the order still goes to the engineer";

  // A freed slot is the next one taken, so ids never run past the range however long the game.
  ASSERT_TRUE(Manager().RemoveUnitlessProxy(5));
  EXPECT_FALSE(Manager().RemoveUnitlessProxy(5));
  auto* const reused = Manager().AddProxy(77777, 5, &mLandFactory, {-500.0f, 0.0f, -500.0f});
  ASSERT_NE(reused, nullptr);
  EXPECT_EQ(reused->mProxyId, 5u);
}

TEST_F(
  PlannedFactoryTest,
  NewUnitMustHaveTheBlueprintAndTheSpot
)
{
  auto* const land = Manager().AddProxy(10, 100, &mLandFactory, {100.0f, 5.0f, 100.0f});
  ASSERT_NE(land, nullptr);

  // The PR's first version gave the orders to any factory within 8 of the plan, on every tick: an
  // existing factory next to the planned one took them before the engineer started.
  EXPECT_EQ(Manager().FindForNewUnit(&mAirFactory, {100.0f, 5.0f, 100.0f}), nullptr);
  EXPECT_EQ(Manager().FindForNewUnit(&mLandFactory, {106.0f, 5.0f, 100.0f}), nullptr);
  EXPECT_EQ(Manager().FindForNewUnit(nullptr, {100.0f, 5.0f, 100.0f}), nullptr);

  EXPECT_EQ(Manager().FindForNewUnit(&mLandFactory, {100.0f, 5.0f, 100.0f}), land);
  EXPECT_EQ(Manager().FindForNewUnit(&mLandFactory, {101.5f, 9.0f, 99.0f}), land) << "height does not count";
}

TEST_F(
  PlannedFactoryTest,
  NewUnitTakesTheNearestPlanOfItsKind
)
{
  auto* const a = Manager().AddProxy(10, 100, &mLandFactory, {100.0f, 0.0f, 100.0f});
  auto* const b = Manager().AddProxy(11, 101, &mLandFactory, {103.0f, 0.0f, 100.0f});
  ASSERT_NE(a, b);
  EXPECT_EQ(Manager().FindForNewUnit(&mLandFactory, {101.8f, 0.0f, 100.0f}), b);
  EXPECT_EQ(Manager().FindForNewUnit(&mLandFactory, {101.2f, 0.0f, 100.0f}), a);
}

TEST_F(
  PlannedFactoryTest,
  RemovingABuilderLeavesTheOthers
)
{
  auto* const proxy = Manager().AddProxy(10, 100, &mLandFactory, {0.0f, 0.0f, 0.0f});
  (void)Manager().AddProxy(10, 104, &mLandFactory, {0.0f, 0.0f, 0.0f});
  (void)Manager().AddProxy(11, 101, &mLandFactory, {0.0f, 0.0f, 0.0f});
  ASSERT_EQ(proxy->mBuilders.size(), 3u);
  EXPECT_EQ(proxy->FirstBuilderId(), 10u);

  Manager().RemoveBuilder(10);
  ASSERT_EQ(proxy->mBuilders.size(), 1u);
  EXPECT_EQ(proxy->FirstBuilderId(), 11u);
  EXPECT_FALSE(proxy->RemoveBuilder(10));
  EXPECT_TRUE(proxy->RemoveBuilder(11));
  EXPECT_EQ(proxy->FirstBuilderId(), 0u);
}

TEST_F(
  PlannedFactoryTest,
  KeptOrdersMergeOnlyWithTheLastEntry
)
{
  auto* const proxy = Manager().AddProxy(10, 100, &mLandFactory, {0.0f, 0.0f, 0.0f});
  proxy->AddPreOrder("uel0101", 5);
  proxy->AddPreOrder("uel0101", 5);
  proxy->AddPreOrder("uel0103", 2);
  proxy->AddPreOrder("uel0101", 1);
  proxy->AddPreOrder("", 3);
  proxy->AddPreOrder("uel0101", 0);
  proxy->AddPreOrder("uel0101", -4);
  ASSERT_EQ(proxy->mPreOrders.size(), 3u);
  EXPECT_EQ(proxy->mPreOrders[0], (moho::PlannedUnitProxy::PreOrder{"uel0101", 10}));
  EXPECT_EQ(proxy->mPreOrders[1], (moho::PlannedUnitProxy::PreOrder{"uel0103", 2}));
  EXPECT_EQ(proxy->mPreOrders[2], (moho::PlannedUnitProxy::PreOrder{"uel0101", 1}));

  // The queue panel's decrease: part of an entry, then the rest, then out of range.
  EXPECT_TRUE(proxy->RemovePreOrderByIndex(0, 4));
  EXPECT_EQ(proxy->mPreOrders[0].count, 6);
  EXPECT_TRUE(proxy->RemovePreOrderByIndex(0, 6));
  ASSERT_EQ(proxy->mPreOrders.size(), 2u);
  EXPECT_EQ(proxy->mPreOrders[0].blueprintId, "uel0103");
  EXPECT_FALSE(proxy->RemovePreOrderByIndex(5, 1));
  EXPECT_FALSE(proxy->RemovePreOrderByIndex(0, 0));
}

TEST_F(
  PlannedFactoryTest,
  RallyOrdersAppendOrReplace
)
{
  auto* const proxy = Manager().AddProxy(10, 100, &mLandFactory, {0.0f, 0.0f, 0.0f});
  moho::RallyPointOrder first{};
  first.position = {10.0f, 0.0f, 10.0f};
  moho::RallyPointOrder second{};
  second.position = {20.0f, 0.0f, 20.0f};

  proxy->AddRallyOrder(first, false);
  proxy->AddRallyOrder(second, false);
  ASSERT_EQ(proxy->mRallyOrders.size(), 2u);
  EXPECT_EQ(proxy->mRallyOrders[1].position.x, 20.0f);

  proxy->AddRallyOrder(first, true);
  ASSERT_EQ(proxy->mRallyOrders.size(), 1u);
  EXPECT_EQ(proxy->mRallyOrders[0].position.x, 10.0f);
}
