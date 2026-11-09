#include <gtest/gtest.h>

#include "moho/console/CConCommand.h"
#include "moho/sim/PlannedFactoryProxy.h"

namespace moho
{
  extern bool ui_FactoryPreOrders;
  [[nodiscard]] bool IsFactoryPreOrdersEnabled();
  void SetFactoryPreOrdersEnabled(bool enabled);
}

TEST(PlannedFactoryPreOrdersTest, DefaultIsEnabled)
{
  moho::SetFactoryPreOrdersEnabled(true);
  EXPECT_TRUE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_TRUE(moho::ui_FactoryPreOrders);
}

TEST(PlannedFactoryPreOrdersTest, SetFactoryPreOrdersEnabledTogglesState)
{
  moho::SetFactoryPreOrdersEnabled(false);
  EXPECT_FALSE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_FALSE(moho::ui_FactoryPreOrders);

  moho::SetFactoryPreOrdersEnabled(true);
  EXPECT_TRUE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_TRUE(moho::ui_FactoryPreOrders);
}

TEST(PlannedFactoryPreOrdersTest, ConCommandExecutionTogglesState)
{
  moho::CON_Execute("ui_FactoryPreOrders 0");
  EXPECT_FALSE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_FALSE(moho::ui_FactoryPreOrders);

  moho::CON_Execute("ui_FactoryPreOrders 1");
  EXPECT_TRUE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_TRUE(moho::ui_FactoryPreOrders);
}

TEST(PlannedFactoryPreOrdersTest, PlannedUnitProxyCreationAndOrderBuffering)
{
  moho::PlannedUnitProxy proxy;
  proxy.mProxyId = 42;
  proxy.mBuilderEntityId = 100;
  proxy.mBuilderCmdIndex = 2;
  proxy.mPosition = moho::Vector3f{10.0f, 0.0f, 20.0f};

  EXPECT_EQ(proxy.mProxyId, 42u);
  EXPECT_EQ(proxy.mBuilderEntityId, 100u);
  EXPECT_EQ(proxy.mBuilderCmdIndex, 2u);
  EXPECT_FLOAT_EQ(proxy.mPosition.x, 10.0f);
  EXPECT_FLOAT_EQ(proxy.mPosition.z, 20.0f);
  EXPECT_FALSE(proxy.mHasRallyPoint);
  EXPECT_FALSE(proxy.mRepeatBuild);
  EXPECT_TRUE(proxy.mPreOrders.empty());

  // Add pre-orders
  proxy.AddPreOrder("uel0201", 3);
  ASSERT_EQ(proxy.mPreOrders.size(), 1u);
  EXPECT_EQ(proxy.mPreOrders[0].blueprintId, "uel0201");
  EXPECT_EQ(proxy.mPreOrders[0].count, 3);

  // Consecutive same blueprint coalesces
  proxy.AddPreOrder("uel0201", 2);
  ASSERT_EQ(proxy.mPreOrders.size(), 1u);
  EXPECT_EQ(proxy.mPreOrders[0].count, 5);

  // Different blueprint creates a new queue entry
  proxy.AddPreOrder("uel0106", 1);
  ASSERT_EQ(proxy.mPreOrders.size(), 2u);
  EXPECT_EQ(proxy.mPreOrders[1].blueprintId, "uel0106");
  EXPECT_EQ(proxy.mPreOrders[1].count, 1);

  // Decrement/cancel pre-orders
  EXPECT_TRUE(proxy.RemovePreOrder("uel0106", 1));
  ASSERT_EQ(proxy.mPreOrders.size(), 1u);
  EXPECT_EQ(proxy.mPreOrders[0].blueprintId, "uel0201");
  EXPECT_EQ(proxy.mPreOrders[0].count, 5);

  EXPECT_TRUE(proxy.RemovePreOrderByIndex(0, 2));
  ASSERT_EQ(proxy.mPreOrders.size(), 1u);
  EXPECT_EQ(proxy.mPreOrders[0].count, 3);

  // Rally point and repeat build
  proxy.SetRallyPoint(moho::Vector3f{50.0f, 0.0f, 60.0f});
  EXPECT_TRUE(proxy.mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy.mRallyPoint.x, 50.0f);
  EXPECT_FLOAT_EQ(proxy.mRallyPoint.z, 60.0f);

  proxy.ClearRallyPoint();
  EXPECT_FALSE(proxy.mHasRallyPoint);

  proxy.SetRepeatBuild(true);
  EXPECT_TRUE(proxy.mRepeatBuild);
  proxy.ToggleRepeatBuild();
  EXPECT_FALSE(proxy.mRepeatBuild);

  proxy.ClearPreOrders();
  EXPECT_TRUE(proxy.mPreOrders.empty());
}

TEST(PlannedFactoryPreOrdersTest, RegisterAndUpdatePreservesOrdersOnDrag)
{
  moho::PlannedFactoryManager mgr;
  moho::Vector3f pos1{100.0f, 20.0f, 100.0f};

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(10, 1, nullptr, pos1);
  ASSERT_NE(proxy, nullptr);
  EXPECT_FLOAT_EQ(proxy->mPosition.x, 100.0f);
  EXPECT_FLOAT_EQ(proxy->mPosition.y, 20.0f);
  EXPECT_FLOAT_EQ(proxy->mPosition.z, 100.0f);
  EXPECT_EQ(mgr.GetCount(), 1u);

  proxy->AddPreOrder("ual0201", 5);
  proxy->SetRallyPoint(moho::Vector3f{150.0f, 0.0f, 150.0f});
  proxy->SetRepeatBuild(true);

  // Waypoint drag to pos2 with same builder and cmdIndex
  moho::Vector3f pos2{110.0f, 20.0f, 105.0f};
  auto* updated = mgr.RegisterOrUpdatePlannedFactory(10, 1, nullptr, pos2);

  EXPECT_EQ(updated, proxy);
  EXPECT_FLOAT_EQ(updated->mPosition.x, 110.0f);
  EXPECT_FLOAT_EQ(updated->mPosition.y, 20.0f);
  EXPECT_FLOAT_EQ(updated->mPosition.z, 105.0f);
  ASSERT_EQ(updated->mPreOrders.size(), 1u);
  EXPECT_EQ(updated->mPreOrders[0].blueprintId, "ual0201");
  EXPECT_EQ(updated->mPreOrders[0].count, 5);
  EXPECT_TRUE(updated->mHasRallyPoint);
  EXPECT_FLOAT_EQ(updated->mRallyPoint.x, 150.0f);
  EXPECT_TRUE(updated->mRepeatBuild);
  EXPECT_EQ(mgr.GetCount(), 1u);
}

TEST(PlannedFactoryPreOrdersTest, AssistingBuildersShareProxyAndCleanupOnDeath)
{
  moho::PlannedFactoryManager mgr;
  moho::Vector3f factoryPos{200.0f, 0.0f, 200.0f};

  auto* proxy1 = mgr.RegisterOrUpdatePlannedFactory(10, 1, nullptr, factoryPos);
  ASSERT_NE(proxy1, nullptr);
  proxy1->AddPreOrder("xrl0305", 2);

  // Builder 20 assists by registering at the same position
  auto* proxy2 = mgr.RegisterOrUpdatePlannedFactory(20, 2, nullptr, factoryPos);
  EXPECT_EQ(proxy1, proxy2);
  EXPECT_EQ(mgr.GetCount(), 1u);

  // Builder 10 dies / cancels -> proxy should survive because builder 20 is still assigned
  mgr.RemoveByBuilder(10);
  EXPECT_EQ(mgr.GetCount(), 1u);
  EXPECT_NE(mgr.FindByPosition(factoryPos, 1.0f), nullptr);
  EXPECT_EQ(mgr.FindByBuilderAndIndex(20, 2), proxy2);
  EXPECT_EQ(mgr.FindByBuilderAndIndex(10, 1), nullptr);

  // Builder 20 dies -> proxy should now be cleaned up
  mgr.RemoveByBuilder(20);
  EXPECT_EQ(mgr.GetCount(), 0u);
  EXPECT_EQ(mgr.FindByPosition(factoryPos, 1.0f), nullptr);
  EXPECT_EQ(mgr.FindByBuilderAndIndex(20, 2), nullptr);
}

TEST(PlannedFactoryPreOrdersTest, RemoveByBuilderAndIndex)
{
  moho::PlannedFactoryManager mgr;
  mgr.RegisterOrUpdatePlannedFactory(30, 1, nullptr, {10.0f, 0.0f, 10.0f});
  mgr.RegisterOrUpdatePlannedFactory(30, 2, nullptr, {50.0f, 0.0f, 50.0f});
  EXPECT_EQ(mgr.GetCount(), 2u);

  mgr.RemoveByBuilderAndIndex(30, 1);
  EXPECT_EQ(mgr.GetCount(), 1u);
  EXPECT_EQ(mgr.FindByPosition({10.0f, 0.0f, 10.0f}, 1.0f), nullptr);
  EXPECT_NE(mgr.FindByPosition({50.0f, 0.0f, 50.0f}, 1.0f), nullptr);

  mgr.ClearAll();
  EXPECT_EQ(mgr.GetCount(), 0u);
}

TEST(PlannedFactoryPreOrdersTest, SpatialLookupAndRayHitTest)
{
  moho::PlannedFactoryManager mgr;
  moho::Vector3f pos{100.0f, 0.0f, 100.0f};
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, pos);
  ASSERT_NE(proxy, nullptr);

  // FindByPosition within tolerance
  EXPECT_EQ(mgr.FindByPosition({100.4f, 0.0f, 100.3f}, 1.0f), proxy);
  EXPECT_EQ(mgr.FindByPosition({105.0f, 0.0f, 100.0f}, 1.0f), nullptr);

  // HitTestRay - ray straight down from above the factory
  moho::Ray pickRay{moho::Vector3f{100.0f, 50.0f, 100.0f}, moho::Vector3f{0.0f, -1.0f, 0.0f}};
  auto* hit = mgr.HitTestRay(pickRay, 5.0f);
  ASSERT_NE(hit, nullptr);
  EXPECT_EQ(hit, proxy);

  // HitTestRay - ray misses the factory
  moho::Ray missRay{moho::Vector3f{120.0f, 50.0f, 100.0f}, moho::Vector3f{0.0f, -1.0f, 0.0f}};
  EXPECT_EQ(mgr.HitTestRay(missRay, 5.0f), nullptr);

  // HitTestRay - ray points away
  moho::Ray awayRay{moho::Vector3f{100.0f, 50.0f, 100.0f}, moho::Vector3f{0.0f, 1.0f, 0.0f}};
  EXPECT_EQ(mgr.HitTestRay(awayRay, 5.0f), nullptr);
}
