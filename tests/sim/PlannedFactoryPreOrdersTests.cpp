#include <gtest/gtest.h>

#include "moho/console/CConCommand.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/command/CommandManager.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/UserCommandQueue.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/PlannedFactoryProxy.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/unit/core/UserUnitPrivate.h"
#include "lua/LuaObject.h"

namespace moho
{
  extern bool ui_FactoryPreOrders;
  [[nodiscard]] bool IsFactoryPreOrdersEnabled();
  void SetFactoryPreOrdersEnabled(bool enabled);
} // namespace moho

TEST(
  PlannedFactoryPreOrdersTest,
  DefaultIsDisabled
)
{
  moho::SetFactoryPreOrdersEnabled(false);
  EXPECT_FALSE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_FALSE(moho::ui_FactoryPreOrders);
}

TEST(
  PlannedFactoryPreOrdersTest,
  SetFactoryPreOrdersEnabledTogglesState
)
{
  moho::SetFactoryPreOrdersEnabled(false);
  EXPECT_FALSE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_FALSE(moho::ui_FactoryPreOrders);

  moho::SetFactoryPreOrdersEnabled(true);
  EXPECT_TRUE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_TRUE(moho::ui_FactoryPreOrders);
}

TEST(
  PlannedFactoryPreOrdersTest,
  ConCommandExecutionTogglesState
)
{
  moho::CON_Execute("ui_FactoryPreOrders 0");
  EXPECT_FALSE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_FALSE(moho::ui_FactoryPreOrders);

  moho::CON_Execute("ui_FactoryPreOrders 1");
  EXPECT_TRUE(moho::IsFactoryPreOrdersEnabled());
  EXPECT_TRUE(moho::ui_FactoryPreOrders);
}

TEST(
  PlannedFactoryPreOrdersTest,
  PlannedUnitProxyCreationAndOrderBuffering
)
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

TEST(
  PlannedFactoryPreOrdersTest,
  RegisterAndUpdatePreservesOrdersOnDrag
)
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

TEST(
  PlannedFactoryPreOrdersTest,
  AssistingBuildersShareProxyAndCleanupOnDeath
)
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

TEST(
  PlannedFactoryPreOrdersTest,
  RemoveByBuilderAndIndex
)
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

TEST(
  PlannedFactoryPreOrdersTest,
  SpatialLookupAndRayHitTest
)
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

TEST(
  PlannedFactoryPreOrdersTest,
  ProxySelectionStateAndManagerSelectionTracking
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy1 = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {10.0f, 0.0f, 10.0f});
  auto* proxy2 = mgr.RegisterOrUpdatePlannedFactory(2, 0, nullptr, {50.0f, 0.0f, 50.0f});
  ASSERT_NE(proxy1, nullptr);
  ASSERT_NE(proxy2, nullptr);

  EXPECT_FALSE(proxy1->IsSelected());
  EXPECT_FALSE(proxy2->IsSelected());
  EXPECT_TRUE(mgr.GetSelectedProxies().empty());

  // Select single proxy
  mgr.SelectProxy(proxy1->mProxyId, false);
  EXPECT_TRUE(proxy1->IsSelected());
  EXPECT_FALSE(proxy2->IsSelected());
  ASSERT_EQ(mgr.GetSelectedProxies().size(), 1u);
  EXPECT_EQ(mgr.GetSelectedProxies()[0], proxy1);

  // Select another without addToSelection -> replaces selection
  mgr.SelectProxy(proxy2->mProxyId, false);
  EXPECT_FALSE(proxy1->IsSelected());
  EXPECT_TRUE(proxy2->IsSelected());
  ASSERT_EQ(mgr.GetSelectedProxies().size(), 1u);
  EXPECT_EQ(mgr.GetSelectedProxies()[0], proxy2);

  // Add proxy1 to selection -> multi-select
  mgr.SelectProxy(proxy1->mProxyId, true);
  EXPECT_TRUE(proxy1->IsSelected());
  EXPECT_TRUE(proxy2->IsSelected());
  EXPECT_EQ(mgr.GetSelectedProxies().size(), 2u);

  // Deselect proxy1
  mgr.DeselectProxy(proxy1->mProxyId);
  EXPECT_FALSE(proxy1->IsSelected());
  EXPECT_TRUE(proxy2->IsSelected());
  ASSERT_EQ(mgr.GetSelectedProxies().size(), 1u);

  // Clear selection
  mgr.ClearSelection();
  EXPECT_FALSE(proxy1->IsSelected());
  EXPECT_FALSE(proxy2->IsSelected());
  EXPECT_TRUE(mgr.GetSelectedProxies().empty());

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  ScreenHitTestPointAndMarqueeRect
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxyCenter = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {0.0f, 0.0f, 0.0f});
  auto* proxyOffset = mgr.RegisterOrUpdatePlannedFactory(2, 0, nullptr, {10.0f, 10.0f, 0.0f});
  ASSERT_NE(proxyCenter, nullptr);
  ASSERT_NE(proxyOffset, nullptr);

  // Setup camera with scaled projection and 1920x1080 viewport
  moho::GeomCamera3 camera;
  camera.viewport.r[3].x = 0.0f;
  camera.viewport.r[3].y = 0.0f;
  camera.viewport.r[3].z = 1920.0f;
  camera.viewport.r[3].w = 1080.0f;

  camera.viewProjection.r[0] = {0.01f, 0.0f, 0.0f, 0.0f};
  camera.viewProjection.r[1] = {0.0f, 0.01f, 0.0f, 0.0f};
  camera.viewProjection.r[2] = {0.0f, 0.0f, 0.01f, 0.0f};
  camera.viewProjection.r[3] = {0.0f, 0.0f, 0.0f, 1.0f};

  // Center (0,0,0) projects to (960, 540)
  auto* hitCenter = mgr.HitTestScreenPoint(&camera, 960.0f, 540.0f, 30.0f);
  ASSERT_NE(hitCenter, nullptr);
  EXPECT_EQ(hitCenter, proxyCenter);

  // Small offset within 30px pickRadius still hits proxyCenter
  auto* hitNear = mgr.HitTestScreenPoint(&camera, 965.0f, 545.0f, 30.0f);
  ASSERT_NE(hitNear, nullptr);
  EXPECT_EQ(hitNear, proxyCenter);

  // Distant click misses
  EXPECT_EQ(mgr.HitTestScreenPoint(&camera, 100.0f, 100.0f, 30.0f), nullptr);

  // Null camera returns nullptr
  EXPECT_EQ(mgr.HitTestScreenPoint(static_cast<const moho::GeomCamera3*>(nullptr), 960.0f, 540.0f, 30.0f), nullptr);

  // HitTestScreenRect: Box containing only center proxy
  auto rectOnlyCenter = mgr.HitTestScreenRect(&camera, 900.0f, 500.0f, 1000.0f, 600.0f);
  ASSERT_EQ(rectOnlyCenter.size(), 1u);
  EXPECT_EQ(rectOnlyCenter[0], proxyCenter);

  // Inverted coordinates box (dragged backwards) produces identical result
  auto rectInverted = mgr.HitTestScreenRect(&camera, 1000.0f, 600.0f, 900.0f, 500.0f);
  ASSERT_EQ(rectInverted.size(), 1u);
  EXPECT_EQ(rectInverted[0], proxyCenter);

  // Box enclosing both
  auto rectBoth = mgr.HitTestScreenRect(&camera, 0.0f, 0.0f, 1920.0f, 1080.0f);
  EXPECT_EQ(rectBoth.size(), 2u);

  // Box outside both
  auto rectMiss = mgr.HitTestScreenRect(&camera, 10.0f, 10.0f, 50.0f, 50.0f);
  EXPECT_TRUE(rectMiss.empty());

  // Null camera returns empty
  EXPECT_TRUE(
    mgr.HitTestScreenRect(static_cast<const moho::GeomCamera3*>(nullptr), 0.0f, 0.0f, 1920.0f, 1080.0f).empty()
  );

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  HitTestingGatedByConvar
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {0.0f, 0.0f, 0.0f});
  ASSERT_NE(proxy, nullptr);

  moho::GeomCamera3 camera;
  camera.viewport.r[3].x = 0.0f;
  camera.viewport.r[3].y = 0.0f;
  camera.viewport.r[3].z = 1920.0f;
  camera.viewport.r[3].w = 1080.0f;
  camera.viewProjection.r[0] = {1.0f, 0.0f, 0.0f, 0.0f};
  camera.viewProjection.r[1] = {0.0f, 1.0f, 0.0f, 0.0f};
  camera.viewProjection.r[2] = {0.0f, 0.0f, 1.0f, 0.0f};
  camera.viewProjection.r[3] = {0.0f, 0.0f, 0.0f, 1.0f};

  // With feature enabled, hit tests work
  EXPECT_NE(mgr.HitTestScreenPoint(&camera, 960.0f, 540.0f, 30.0f), nullptr);
  EXPECT_FALSE(mgr.HitTestScreenRect(&camera, 0.0f, 0.0f, 1920.0f, 1080.0f).empty());
  EXPECT_NE(mgr.HitTestRay({moho::Vector3f{0.0f, 10.0f, 0.0f}, moho::Vector3f{0.0f, -1.0f, 0.0f}}, 5.0f), nullptr);

  // Disable convar
  moho::SetFactoryPreOrdersEnabled(false);
  EXPECT_EQ(mgr.HitTestScreenPoint(&camera, 960.0f, 540.0f, 30.0f), nullptr);
  EXPECT_TRUE(mgr.HitTestScreenRect(&camera, 0.0f, 0.0f, 1920.0f, 1080.0f).empty());
  EXPECT_EQ(mgr.HitTestRay({moho::Vector3f{0.0f, 10.0f, 0.0f}, moho::Vector3f{0.0f, -1.0f, 0.0f}}, 5.0f), nullptr);

  // Restore convar
  moho::SetFactoryPreOrdersEnabled(true);
  EXPECT_NE(mgr.HitTestScreenPoint(&camera, 960.0f, 540.0f, 30.0f), nullptr);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  WorldViewNullSafetyAndBoundingRadius
)
{
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {10.0f, 0.0f, 10.0f});
  ASSERT_NE(proxy, nullptr);

  // Default bounding radius
  EXPECT_FLOAT_EQ(proxy->GetBoundingRadius(), 5.0f);
  proxy->SetBoundingRadius(12.5f);
  EXPECT_FLOAT_EQ(proxy->GetBoundingRadius(), 12.5f);

  // Calling CUIWorldView overloads with nullptr view is safe and returns null/empty
  const moho::CUIWorldView* nullView = nullptr;
  EXPECT_EQ(mgr.HitTestScreenPoint(nullView, 100.0f, 100.0f, 30.0f), nullptr);
  EXPECT_TRUE(mgr.HitTestScreenRect(nullView, 0.0f, 0.0f, 100.0f, 100.0f).empty());

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  QueueOrdersDuplicateToAllSelectedProxies
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy1 = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {10.0f, 0.0f, 10.0f});
  auto* proxy2 = mgr.RegisterOrUpdatePlannedFactory(2, 0, nullptr, {50.0f, 0.0f, 50.0f});
  auto* proxy3 = mgr.RegisterOrUpdatePlannedFactory(3, 0, nullptr, {90.0f, 0.0f, 90.0f});
  ASSERT_NE(proxy1, nullptr);
  ASSERT_NE(proxy2, nullptr);
  ASSERT_NE(proxy3, nullptr);

  // Select proxy1 and proxy2; proxy3 remains unselected
  mgr.SelectProxy(proxy1->mProxyId, false);
  mgr.SelectProxy(proxy2->mProxyId, true);

  // Queue 5 tanks of "uel0201"
  mgr.QueuePlannedFactoryOrders("uel0201", 5, false);

  // Verify duplication: both proxy1 and proxy2 receive all 5 tanks (no round-robin)
  ASSERT_EQ(proxy1->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy1->mPreOrders[0].blueprintId, "uel0201");
  EXPECT_EQ(proxy1->mPreOrders[0].count, 5);

  ASSERT_EQ(proxy2->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy2->mPreOrders[0].blueprintId, "uel0201");
  EXPECT_EQ(proxy2->mPreOrders[0].count, 5);

  // Unselected proxy3 receives nothing
  EXPECT_TRUE(proxy3->mPreOrders.empty());

  // Queue 2 more units of "uel0202"
  mgr.QueuePlannedFactoryOrders("uel0202", 2, false);
  ASSERT_EQ(proxy1->mPreOrders.size(), 2u);
  EXPECT_EQ(proxy1->mPreOrders[1].blueprintId, "uel0202");
  EXPECT_EQ(proxy1->mPreOrders[1].count, 2);

  ASSERT_EQ(proxy2->mPreOrders.size(), 2u);
  EXPECT_EQ(proxy2->mPreOrders[1].blueprintId, "uel0202");
  EXPECT_EQ(proxy2->mPreOrders[1].count, 2);

  // Queue with clearQueue = true replaces the queues
  mgr.QueuePlannedFactoryOrders("uel0203", 1, true);
  ASSERT_EQ(proxy1->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy1->mPreOrders[0].blueprintId, "uel0203");
  EXPECT_EQ(proxy1->mPreOrders[0].count, 1);

  ASSERT_EQ(proxy2->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy2->mPreOrders[0].blueprintId, "uel0203");
  EXPECT_EQ(proxy2->mPreOrders[0].count, 1);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  SetRallyPointAndRepeatToAllSelectedProxies
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy1 = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {10.0f, 0.0f, 10.0f});
  auto* proxy2 = mgr.RegisterOrUpdatePlannedFactory(2, 0, nullptr, {50.0f, 0.0f, 50.0f});
  ASSERT_NE(proxy1, nullptr);
  ASSERT_NE(proxy2, nullptr);

  mgr.SelectProxy(proxy1->mProxyId, false);
  mgr.SelectProxy(proxy2->mProxyId, true);

  // Rally point setting across selected proxies
  const moho::Vector3f rallyTarget{123.0f, 0.0f, 456.0f};
  mgr.SetSelectedPlannedFactoriesRallyPoint(rallyTarget);

  EXPECT_TRUE(proxy1->mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy1->mRallyPoint.x, 123.0f);
  EXPECT_FLOAT_EQ(proxy1->mRallyPoint.z, 456.0f);

  EXPECT_TRUE(proxy2->mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy2->mRallyPoint.x, 123.0f);
  EXPECT_FLOAT_EQ(proxy2->mRallyPoint.z, 456.0f);

  // Repeat toggle across selected proxies
  mgr.SetSelectedPlannedFactoriesRepeat(true);
  EXPECT_TRUE(proxy1->mRepeatBuild);
  EXPECT_TRUE(proxy2->mRepeatBuild);

  mgr.SetSelectedPlannedFactoriesRepeat(false);
  EXPECT_FALSE(proxy1->mRepeatBuild);
  EXPECT_FALSE(proxy2->mRepeatBuild);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  QueueInspectionAndDecrement
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {10.0f, 0.0f, 10.0f});
  ASSERT_NE(proxy, nullptr);

  proxy->AddPreOrder("uel0201", 3);
  proxy->AddPreOrder("uel0202", 2);
  ASSERT_EQ(proxy->mPreOrders.size(), 2u);

  // Partial decrement at index 0 (uel0201: 3 -> 2)
  EXPECT_TRUE(proxy->RemovePreOrderByIndex(0, 1));
  ASSERT_EQ(proxy->mPreOrders.size(), 2u);
  EXPECT_EQ(proxy->mPreOrders[0].count, 2);

  // Full decrement of index 0 removes it (uel0201: 2 -> 0 removed, uel0202 shifts to index 0)
  EXPECT_TRUE(proxy->RemovePreOrderByIndex(0, 2));
  ASSERT_EQ(proxy->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy->mPreOrders[0].blueprintId, "uel0202");
  EXPECT_EQ(proxy->mPreOrders[0].count, 2);

  // Remove by blueprint ID
  EXPECT_TRUE(proxy->RemovePreOrder("uel0202", 5));
  EXPECT_TRUE(proxy->mPreOrders.empty());

  // Decrement on empty returns false
  EXPECT_FALSE(proxy->RemovePreOrderByIndex(0, 1));
  EXPECT_FALSE(proxy->RemovePreOrder("uel0202", 1));

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  MixedSelectionDuplicationSimulation
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  // 1 planned factory proxy selected
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {100.0f, 0.0f, 100.0f});
  ASSERT_NE(proxy, nullptr);
  mgr.SelectProxy(proxy->mProxyId, false);

  // Simulate ordering 5 tanks for 2 real factories and 1 planned proxy:
  // User requirement: "если заказываю N юнитов, то все N должны быть на всех выделенных заводах"
  struct MockRealFactory
  {
    int ordersReceived{0};
    std::string orderedBp{};
  };
  std::vector<MockRealFactory> realFactories(2);

  const std::string tankBp = "uel0201";
  const int count = 5;

  // Real factories receive `count` in Sim
  for (auto& realFac : realFactories) {
    realFac.ordersReceived += count;
    realFac.orderedBp = tankBp;
  }
  // Planned factory receives `count` via QueuePlannedFactoryOrders
  mgr.QueuePlannedFactoryOrders(tankBp, count, false);

  // Verify real factories both have 5
  EXPECT_EQ(realFactories[0].ordersReceived, 5);
  EXPECT_EQ(realFactories[0].orderedBp, "uel0201");
  EXPECT_EQ(realFactories[1].ordersReceived, 5);
  EXPECT_EQ(realFactories[1].orderedBp, "uel0201");

  // Verify planned proxy received full 5 (duplicated, NOT round-robin divided)
  ASSERT_EQ(proxy->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy->mPreOrders[0].blueprintId, "uel0201");
  EXPECT_EQ(proxy->mPreOrders[0].count, 5);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  LuaBindersQueueRallyRepeatAndDecrease
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(10, 0, nullptr, {20.0f, 0.0f, 30.0f});
  ASSERT_NE(proxy, nullptr);

  LuaPlus::LuaState state{LuaPlus::LuaState::LIB_BASE};
  lua_State* L = state.GetCState();

  // 1. IssuePlannedFactoryBuildOrder(proxyId, "uel0201", 4)
  lua_pushnumber(L, proxy->mProxyId);
  lua_pushstring(L, "uel0201");
  lua_pushnumber(L, 4);
  EXPECT_EQ(moho::cfunc_IssuePlannedFactoryBuildOrderL(&state), 0);
  lua_settop(L, 0);

  ASSERT_EQ(proxy->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy->mPreOrders[0].blueprintId, "uel0201");
  EXPECT_EQ(proxy->mPreOrders[0].count, 4);

  // 2. GetPlannedFactoryQueue(proxyId) -> returns table
  lua_pushnumber(L, proxy->mProxyId);
  EXPECT_EQ(moho::cfunc_GetPlannedFactoryQueueL(&state), 1);
  LuaPlus::LuaObject queueObj(LuaPlus::LuaStackObject(&state, -1));
  EXPECT_TRUE(queueObj.IsTable());
  LuaPlus::LuaObject firstOrder = queueObj.GetByIndex(1);
  EXPECT_TRUE(firstOrder.IsTable());
  EXPECT_STREQ(firstOrder.GetByName("blueprintId").GetString(), "uel0201");
  EXPECT_EQ(firstOrder.GetByName("count").GetInteger(), 4);
  lua_settop(L, 0);

  // 3. DecreasePlannedFactoryBuildCount(proxyId, 1, 2)
  lua_pushnumber(L, proxy->mProxyId);
  lua_pushnumber(L, 1);
  lua_pushnumber(L, 2);
  EXPECT_EQ(moho::cfunc_DecreasePlannedFactoryBuildCountL(&state), 1);
  EXPECT_EQ(lua_toboolean(L, -1), 1);
  EXPECT_EQ(proxy->mPreOrders[0].count, 2);
  lua_settop(L, 0);

  // 4. SetPlannedFactoryRallyPoint(proxyId, 50, 0, 75)
  lua_pushnumber(L, proxy->mProxyId);
  lua_pushnumber(L, 50.0);
  lua_pushnumber(L, 0.0);
  lua_pushnumber(L, 75.0);
  EXPECT_EQ(moho::cfunc_SetPlannedFactoryRallyPointL(&state), 0);
  EXPECT_TRUE(proxy->mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy->mRallyPoint.x, 50.0f);
  EXPECT_FLOAT_EQ(proxy->mRallyPoint.z, 75.0f);
  lua_settop(L, 0);

  // 5. SetPlannedFactoryRepeat(proxyId, true)
  lua_pushnumber(L, proxy->mProxyId);
  lua_pushboolean(L, 1);
  EXPECT_EQ(moho::cfunc_SetPlannedFactoryRepeatL(&state), 0);
  EXPECT_TRUE(proxy->mRepeatBuild);
  lua_settop(L, 0);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  DispatchOnCreationProgressGreaterThanZero
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {200.0f, 0.0f, 200.0f});
  ASSERT_NE(proxy, nullptr);
  proxy->AddPreOrder("uel0201", 3);
  proxy->SetRallyPoint({250.0f, 0.0f, 250.0f});
  proxy->SetRepeatBuild(true);

  // If progress <= 0, dispatch must not trigger
  bool dispatched = false;
  EXPECT_FALSE(mgr.OnUnitCreatedOrProgress({200.0f, 0.0f, 200.0f}, 0.0f, [&](const auto&, const auto&, bool) {
    dispatched = true;
  }));
  EXPECT_FALSE(dispatched);
  EXPECT_NE(mgr.FindByPosition({200.0f, 0.0f, 200.0f}, 1.0f), nullptr);

  // When progress > 0 (e.g. 0.05f), dispatch triggers and proxy retires
  EXPECT_TRUE(mgr.OnUnitCreatedOrProgress(
    {200.0f, 0.0f, 200.0f},
    0.05f,
    [&](const std::vector<moho::PlannedUnitProxy::PreOrder>& orders, const moho::Vector3f& rally, bool repeat) {
    dispatched = true;
    ASSERT_EQ(orders.size(), 1u);
    EXPECT_EQ(orders[0].blueprintId, "uel0201");
    EXPECT_EQ(orders[0].count, 3);
    EXPECT_FLOAT_EQ(rally.x, 250.0f);
    EXPECT_FLOAT_EQ(rally.z, 250.0f);
    EXPECT_TRUE(repeat);
  }
  ));

  EXPECT_TRUE(dispatched);
  // Proxy has been retired
  EXPECT_EQ(mgr.FindByPosition({200.0f, 0.0f, 200.0f}, 1.0f), nullptr);

  // Calling again returns false (once-only)
  dispatched = false;
  EXPECT_FALSE(mgr.OnUnitCreatedOrProgress({200.0f, 0.0f, 200.0f}, 0.10f, [&](const auto&, const auto&, bool) {
    dispatched = true;
  }));
  EXPECT_FALSE(dispatched);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  DispatchPreOrdersForUnitWithHookAndOnceOnlySuppression
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(10, 0, nullptr, {100.0f, 0.0f, 100.0f});
  ASSERT_NE(proxy, nullptr);
  proxy->AddPreOrder("uel0201", 3);
  proxy->AddPreOrder("uel0202", 2);
  proxy->SetRallyPoint({120.0f, 0.0f, 150.0f});
  proxy->SetRepeatBuild(true);

  auto* dummyUnit = reinterpret_cast<moho::UserUnit*>(0xDEADBEEF);
  bool hookInvoked = false;
  moho::UserUnit* receivedUnit = nullptr;
  std::size_t receivedOrdersCount = 0;
  bool receivedRepeat = false;

  mgr.SetDispatchHook([&](moho::UserUnit* u, const moho::PlannedUnitProxy& p) {
    hookInvoked = true;
    receivedUnit = u;
    receivedOrdersCount = p.mPreOrders.size();
    receivedRepeat = p.mRepeatBuild;
  });

  // Dispatch within tolerance (position 101, 0, 100.5 is ~1.1 units away)
  EXPECT_TRUE(mgr.DispatchPreOrdersForUnit(dummyUnit, {101.0f, 0.0f, 100.5f}));
  EXPECT_TRUE(hookInvoked);
  EXPECT_EQ(receivedUnit, dummyUnit);
  EXPECT_EQ(receivedOrdersCount, 2u);
  EXPECT_TRUE(receivedRepeat);

  // Proxy must be removed from manager
  EXPECT_EQ(mgr.FindByPosition({100.0f, 0.0f, 100.0f}, 1.0f), nullptr);

  // Calling a second time must return false (once-only suppression)
  hookInvoked = false;
  EXPECT_FALSE(mgr.DispatchPreOrdersForUnit(dummyUnit, {101.0f, 0.0f, 100.5f}));
  EXPECT_FALSE(hookInvoked);

  mgr.ResetDispatchHook();
  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  DispatchPreOrdersGatedByConvar
)
{
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(5, 0, nullptr, {50.0f, 0.0f, 50.0f});
  ASSERT_NE(proxy, nullptr);
  proxy->AddPreOrder("xrl0305", 1);

  auto* dummyUnit = reinterpret_cast<moho::UserUnit*>(0xCAFE);

  // Feature disabled
  moho::SetFactoryPreOrdersEnabled(false);
  EXPECT_FALSE(mgr.DispatchPreOrdersForUnit(dummyUnit, {50.0f, 0.0f, 50.0f}));
  EXPECT_NE(mgr.FindByPosition({50.0f, 0.0f, 50.0f}, 1.0f), nullptr);

  // Feature re-enabled
  moho::SetFactoryPreOrdersEnabled(true);
  bool dispatched = false;
  mgr.SetDispatchHook([&](moho::UserUnit*, const moho::PlannedUnitProxy&) {
    dispatched = true;
  });

  EXPECT_TRUE(mgr.DispatchPreOrdersForUnit(dummyUnit, {50.0f, 0.0f, 50.0f}));
  EXPECT_TRUE(dispatched);
  EXPECT_EQ(mgr.FindByPosition({50.0f, 0.0f, 50.0f}, 1.0f), nullptr);

  mgr.ResetDispatchHook();
  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  DispatchPreOrdersToleranceAndPositionMiss
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(7, 0, nullptr, {300.0f, 0.0f, 300.0f});
  ASSERT_NE(proxy, nullptr);
  proxy->AddPreOrder("uel0106", 5);

  auto* dummyUnit = reinterpret_cast<moho::UserUnit*>(0xBEEF);

  // Position miss (50 units away)
  EXPECT_FALSE(mgr.DispatchPreOrdersForUnit(dummyUnit, {350.0f, 0.0f, 350.0f}));
  EXPECT_NE(mgr.FindByPosition({300.0f, 0.0f, 300.0f}, 1.0f), nullptr);

  // Position hit within tolerance
  EXPECT_TRUE(mgr.DispatchPreOrdersForUnit(dummyUnit, {301.5f, 0.0f, 301.5f}));
  EXPECT_EQ(mgr.FindByPosition({300.0f, 0.0f, 300.0f}, 1.0f), nullptr);

  // Null unit safety
  EXPECT_FALSE(mgr.DispatchPreOrdersForUnit(nullptr, {300.0f, 0.0f, 300.0f}));

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  BufferingSuppressionScopeDeDuplicatesOrders
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  EXPECT_FALSE(mgr.IsBufferingSuppressed());

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(100, 0, nullptr, {10.0f, 0.0f, 10.0f});
  ASSERT_NE(proxy, nullptr);
  mgr.SelectProxy(proxy->mProxyId, false);

  {
    moho::PlannedFactoryManager::ScopedBufferingSuppression suppression;
    EXPECT_TRUE(mgr.IsBufferingSuppressed());
  }

  EXPECT_FALSE(mgr.IsBufferingSuppressed());
  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  BuilderQueueRemovalAndDeathCleanup
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  // Builder 50 issues construct order for factory at (20, 0, 30)
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(50, 0, nullptr, {20.0f, 0.0f, 30.0f});
  ASSERT_NE(proxy, nullptr);
  proxy->AddPreOrder("uel0201", 3);
  EXPECT_EQ(mgr.GetCount(), 1u);

  // Builder dies or queue is cleared -> RemoveByBuilder cleans up proxy
  mgr.RemoveByBuilder(50);
  EXPECT_EQ(mgr.GetCount(), 0u);
  EXPECT_EQ(mgr.FindByPosition({20.0f, 0.0f, 30.0f}, 1.0f), nullptr);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  FindByPositionIgnoresElevationOffset
)
{
  moho::PlannedFactoryManager mgr;
  moho::Vector3f pos{100.0f, 15.0f, 200.0f};
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, pos);
  ASSERT_NE(proxy, nullptr);

  // Exact XZ, but different terrain height Y (e.g. terrain flattened by construction)
  moho::Vector3f queryPosDifferentY{100.2f, 25.0f, 200.1f};
  EXPECT_EQ(mgr.FindByPosition(queryPosDifferentY, 1.0f), proxy);

  // Position too far in XZ plane
  moho::Vector3f queryPosFar{105.0f, 15.0f, 200.0f};
  EXPECT_EQ(mgr.FindByPosition(queryPosFar, 1.0f), nullptr);
}

TEST(
  PlannedFactoryPreOrdersTest,
  DispatchPreOrdersMatchesWithinFoundationRadius
)
{
  moho::PlannedFactoryManager mgr;
  moho::Vector3f pos{300.0f, 10.0f, 400.0f};
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(2, 0, nullptr, pos);
  ASSERT_NE(proxy, nullptr);
  proxy->AddPreOrder("uel0201", 5);

  bool dispatched = false;
  mgr.SetDispatchHook([&](moho::UserUnit* /*unit*/, const moho::PlannedUnitProxy& p) {
    EXPECT_EQ(p.mProxyId, proxy->mProxyId);
    ASSERT_EQ(p.mPreOrders.size(), 1u);
    EXPECT_EQ(p.mPreOrders[0].blueprintId, "uel0201");
    EXPECT_EQ(p.mPreOrders[0].count, 5);
    dispatched = true;
  });

  // Construction starts 4 units away in XZ and with Y terrain leveling
  moho::Vector3f actualUnitPos{303.0f, 15.0f, 402.0f};
  EXPECT_TRUE(mgr.DispatchPreOrdersForUnit(reinterpret_cast<moho::UserUnit*>(0x1000), actualUnitPos));
  EXPECT_TRUE(dispatched);
  EXPECT_EQ(mgr.GetCount(), 0u);
}

TEST(
  PlannedFactoryPreOrdersTest,
  DispatchPreOrdersZeroPositionHandling
)
{
  moho::PlannedFactoryManager mgr;
  moho::Vector3f pos{300.0f, 10.0f, 400.0f};
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(2, 0, nullptr, pos);
  ASSERT_NE(proxy, nullptr);

  // Position at (0, 0, 0) indicates uninitialized / un-replicated position, should return false
  EXPECT_FALSE(mgr.DispatchPreOrdersForUnit(reinterpret_cast<moho::UserUnit*>(0x1000), {0.0f, 0.0f, 0.0f}));
  EXPECT_EQ(mgr.GetCount(), 1u);
}

TEST(
  PlannedFactoryPreOrdersTest,
  ProxyEntityIdRangeClassification
)
{
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  // Null check safety
  EXPECT_FALSE(mgr.IsPlannedProxyUnit(nullptr));

  alignas(moho::UserUnit) std::byte unitStorage[sizeof(moho::UserUnit)]{};
  auto* testUnit = reinterpret_cast<moho::UserUnit*>(unitStorage);

  // Normal unit entity IDs: low 16 bits outside the 0x7000 mask
  const std::uint32_t normalEntityIds[] = {
    0x00100001u, // Standard unit index 1
    0x00100042u, // Standard unit index 66
    0x00106FFFu, // Index right below proxy range
    0x00108000u, // Index above proxy range
    0x00200100u, // Different army, normal index
  };

  for (const auto entId : normalEntityIds) {
    testUnit->mParams.mEntityId = entId;
    EXPECT_FALSE(mgr.IsPlannedProxyUnit(testUnit))
      << "Entity ID 0x" << std::hex << entId << " was incorrectly classified as a planned proxy";
  }

  // Planned proxy entity IDs: low 16 bits have (index & 0x7000u) == 0x7000u
  const std::uint32_t proxyEntityIds[] = {
    0x00107000u, // First proxy index
    0x00107001u, // Proxy ID 1
    0x00107042u, // Proxy ID 66
    0x00107FFFu, // Max proxy index in 0x7000 band
    0x00307010u, // Army 3 proxy index
  };

  for (const auto entId : proxyEntityIds) {
    testUnit->mParams.mEntityId = entId;
    EXPECT_TRUE(mgr.IsPlannedProxyUnit(testUnit))
      << "Entity ID 0x" << std::hex << entId << " should be classified as a planned proxy";
  }

  // Verify that IsPlannedProxyUnit also classifies via pointer equality with mProxies
  testUnit->mParams.mEntityId = 0x00100055u; // Non-proxy entity ID
  EXPECT_FALSE(mgr.IsPlannedProxyUnit(testUnit));

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(10, 0, nullptr, {50.0f, 0.0f, 50.0f});
  ASSERT_NE(proxy, nullptr);
  proxy->mUserUnit = testUnit;

  EXPECT_TRUE(mgr.IsPlannedProxyUnit(testUnit));
  EXPECT_EQ(mgr.FindByUserUnit(testUnit), proxy);

  // Once detached or removed, pointer fallback is dropped
  proxy->mUserUnit = nullptr;
  EXPECT_FALSE(mgr.IsPlannedProxyUnit(testUnit));
  EXPECT_EQ(mgr.FindByUserUnit(testUnit), nullptr);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  ShiftClickOrderCoalescingAndSequencePreservation
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {100.0f, 0.0f, 100.0f});
  ASSERT_NE(proxy, nullptr);
  mgr.SelectProxy(proxy->mProxyId, false);

  // Simulate 8 Shift-clicks of 5 units of 'url0107' (Cybran Mantis)
  for (int i = 0; i < 8; ++i) {
    mgr.QueuePlannedFactoryOrders("url0107", 5, /*clearQueue=*/false);
  }

  // Consecutive same-blueprint clicks must coalesce into a single queue entry
  ASSERT_EQ(proxy->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy->mPreOrders[0].blueprintId, "url0107");
  EXPECT_EQ(proxy->mPreOrders[0].count, 40);

  // Simulate 2 Shift-clicks of 5 units of 'url0103' (Cybran Medusa)
  for (int i = 0; i < 2; ++i) {
    mgr.QueuePlannedFactoryOrders("url0103", 5, /*clearQueue=*/false);
  }

  // Different blueprint appends a second queue entry
  ASSERT_EQ(proxy->mPreOrders.size(), 2u);
  EXPECT_EQ(proxy->mPreOrders[0].blueprintId, "url0107");
  EXPECT_EQ(proxy->mPreOrders[0].count, 40);
  EXPECT_EQ(proxy->mPreOrders[1].blueprintId, "url0103");
  EXPECT_EQ(proxy->mPreOrders[1].count, 10);

  // Non-consecutive click: 1 Shift-click of 5 units of 'url0107' again
  // Production queue order MUST be preserved: [40x Mantis, 10x Medusa, 5x Mantis]
  mgr.QueuePlannedFactoryOrders("url0107", 5, /*clearQueue=*/false);
  ASSERT_EQ(proxy->mPreOrders.size(), 3u);
  EXPECT_EQ(proxy->mPreOrders[0].blueprintId, "url0107");
  EXPECT_EQ(proxy->mPreOrders[0].count, 40);
  EXPECT_EQ(proxy->mPreOrders[1].blueprintId, "url0103");
  EXPECT_EQ(proxy->mPreOrders[1].count, 10);
  EXPECT_EQ(proxy->mPreOrders[2].blueprintId, "url0107");
  EXPECT_EQ(proxy->mPreOrders[2].count, 5);

  // Regular click without Shift: clearQueue=true wipes previous queue and starts fresh
  mgr.QueuePlannedFactoryOrders("url0101", 1, /*clearQueue=*/true);
  ASSERT_EQ(proxy->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy->mPreOrders[0].blueprintId, "url0101");
  EXPECT_EQ(proxy->mPreOrders[0].count, 1);

  // Edge cases: empty blueprint ID and non-positive counts are safely ignored
  mgr.QueuePlannedFactoryOrders("", 5, false);
  mgr.QueuePlannedFactoryOrders("url0101", 0, false);
  mgr.QueuePlannedFactoryOrders("url0101", -3, false);
  ASSERT_EQ(proxy->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy->mPreOrders[0].count, 1);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  ScopedBufferingSuppressionPreventsRebuffering
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(10, 0, nullptr, {20.0f, 0.0f, 20.0f});
  ASSERT_NE(proxy, nullptr);
  mgr.SelectProxy(proxy->mProxyId, false);

  // Initially unsuppressed: orders queue normally
  EXPECT_FALSE(mgr.IsBufferingSuppressed());
  mgr.QueuePlannedFactoryOrders("uel0201", 3, false);
  ASSERT_EQ(proxy->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy->mPreOrders[0].count, 3);

  // Enter ScopedBufferingSuppression scope (as occurs during DispatchPreOrdersForUnit)
  {
    moho::PlannedFactoryManager::ScopedBufferingSuppression suppression;
    EXPECT_TRUE(mgr.IsBufferingSuppressed());

    // All buffering operations during suppression MUST be silent no-ops
    mgr.QueuePlannedFactoryOrders("uel0201", 10, false);
    mgr.QueuePlannedFactoryOrders("uel0106", 5, false);
    mgr.SetSelectedPlannedFactoriesRallyPoint({100.0f, 0.0f, 100.0f});
    mgr.SetSelectedPlannedFactoriesRepeat(true);

    // Proxy state must remain completely untouched
    ASSERT_EQ(proxy->mPreOrders.size(), 1u);
    EXPECT_EQ(proxy->mPreOrders[0].count, 3);
    EXPECT_FALSE(proxy->mHasRallyPoint);
    EXPECT_FALSE(proxy->mRepeatBuild);
  }

  // Outside scope: suppression automatically lifted
  EXPECT_FALSE(mgr.IsBufferingSuppressed());

  // Subsequent orders queue normally again
  mgr.QueuePlannedFactoryOrders("uel0201", 2, false);
  ASSERT_EQ(proxy->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy->mPreOrders[0].count, 5);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  MultiProxyBroadcastSelection
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxyA = mgr.RegisterOrUpdatePlannedFactory(1, 0, nullptr, {10.0f, 0.0f, 10.0f});
  auto* proxyB = mgr.RegisterOrUpdatePlannedFactory(2, 0, nullptr, {20.0f, 0.0f, 20.0f});
  auto* proxyC = mgr.RegisterOrUpdatePlannedFactory(3, 0, nullptr, {30.0f, 0.0f, 30.0f});
  ASSERT_NE(proxyA, nullptr);
  ASSERT_NE(proxyB, nullptr);
  ASSERT_NE(proxyC, nullptr);

  // Select A and B; leave C unselected
  mgr.SelectProxy(proxyA->mProxyId, false);
  mgr.SelectProxy(proxyB->mProxyId, true);

  EXPECT_TRUE(proxyA->IsSelected());
  EXPECT_TRUE(proxyB->IsSelected());
  EXPECT_FALSE(proxyC->IsSelected());
  EXPECT_EQ(mgr.GetSelectedProxies().size(), 2u);

  // Broadcast orders, rally point, and repeat build
  mgr.QueuePlannedFactoryOrders("xal0201", 10, false);
  mgr.SetSelectedPlannedFactoriesRallyPoint({250.0f, 0.0f, 250.0f});
  mgr.SetSelectedPlannedFactoriesRepeat(true);

  // Verify A and B received the broadcast
  for (const auto* p : {proxyA, proxyB}) {
    ASSERT_EQ(p->mPreOrders.size(), 1u);
    EXPECT_EQ(p->mPreOrders[0].blueprintId, "xal0201");
    EXPECT_EQ(p->mPreOrders[0].count, 10);
    EXPECT_TRUE(p->mHasRallyPoint);
    EXPECT_FLOAT_EQ(p->mRallyPoint.x, 250.0f);
    EXPECT_FLOAT_EQ(p->mRallyPoint.z, 250.0f);
    EXPECT_TRUE(p->mRepeatBuild);
  }

  // Verify C was not affected
  EXPECT_TRUE(proxyC->mPreOrders.empty());
  EXPECT_FALSE(proxyC->mHasRallyPoint);
  EXPECT_FALSE(proxyC->mRepeatBuild);

  // Deselect B: now only A is selected
  mgr.DeselectProxy(proxyB->mProxyId);
  EXPECT_TRUE(proxyA->IsSelected());
  EXPECT_FALSE(proxyB->IsSelected());

  mgr.QueuePlannedFactoryOrders("xal0305", 5, false);
  ASSERT_EQ(proxyA->mPreOrders.size(), 2u);
  EXPECT_EQ(proxyA->mPreOrders[1].blueprintId, "xal0305");
  EXPECT_EQ(proxyA->mPreOrders[1].count, 5);

  // B should NOT have received the new order
  ASSERT_EQ(proxyB->mPreOrders.size(), 1u);

  // Clear selection: queuing when nothing is selected is a safe no-op
  mgr.ClearSelection();
  EXPECT_TRUE(mgr.GetSelectedProxies().empty());
  mgr.QueuePlannedFactoryOrders("xal0101", 1, false);

  EXPECT_EQ(proxyA->mPreOrders.size(), 2u);
  EXPECT_EQ(proxyB->mPreOrders.size(), 1u);
  EXPECT_EQ(proxyC->mPreOrders.size(), 0u);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  ReplicatedCurTransformFallbackOnDispatch
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(5, 0, nullptr, {500.0f, 10.0f, 500.0f});
  ASSERT_NE(proxy, nullptr);
  proxy->AddPreOrder("uel0201", 5);

  bool dispatched = false;
  mgr.SetDispatchHook([&](moho::UserUnit* /*unit*/, const moho::PlannedUnitProxy& p) {
    EXPECT_EQ(p.mProxyId, proxy->mProxyId);
    ASSERT_EQ(p.mPreOrders.size(), 1u);
    EXPECT_EQ(p.mPreOrders[0].blueprintId, "uel0201");
    EXPECT_EQ(p.mPreOrders[0].count, 5);
    dispatched = true;
  });

  // Scenario A: Unit has mTransform.pos_ == {0, 0, 0} (before first interpolation tick),
  // but mVariableData.mCurTransform.pos_ holds the valid replicated sim position {502.0f, 10.0f, 501.5f}.
  alignas(moho::UserUnit) std::byte unitStorageA[sizeof(moho::UserUnit)]{};
  auto* unitA = reinterpret_cast<moho::UserUnit*>(unitStorageA);
  unitA->mTransform.pos_ = {0.0f, 0.0f, 0.0f};
  unitA->mVariableData.mCurTransform.pos_ = {502.0f, 10.0f, 501.5f};

  EXPECT_TRUE(mgr.DispatchPreOrdersForUnit(unitA));
  EXPECT_TRUE(dispatched);
  EXPECT_EQ(mgr.GetCount(), 0u); // Proxy consumed

  // Scenario B: Unit has both mTransform.pos_ AND mVariableData.mCurTransform.pos_ at {0, 0, 0}.
  // Must be rejected as uninitialized.
  auto* proxy2 = mgr.RegisterOrUpdatePlannedFactory(6, 0, nullptr, {600.0f, 10.0f, 600.0f});
  ASSERT_NE(proxy2, nullptr);

  alignas(moho::UserUnit) std::byte unitStorageB[sizeof(moho::UserUnit)]{};
  auto* unitB = reinterpret_cast<moho::UserUnit*>(unitStorageB);
  unitB->mTransform.pos_ = {0.0f, 0.0f, 0.0f};
  unitB->mVariableData.mCurTransform.pos_ = {0.0f, 0.0f, 0.0f};

  EXPECT_FALSE(mgr.DispatchPreOrdersForUnit(unitB));
  EXPECT_EQ(mgr.GetCount(), 1u); // Proxy NOT consumed

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  MultiBuilderAssistanceAndRetirementLifecycle
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  const moho::Vector3f factoryPos{150.0f, 0.0f, 150.0f};

  // Builder 10 (ACU) starts planning the factory
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(10, 0, nullptr, factoryPos);
  ASSERT_NE(proxy, nullptr);
  proxy->AddPreOrder("uel0106", 15);
  proxy->SetRallyPoint({200.0f, 0.0f, 200.0f});

  // Builder 20 (Engineer 1) assists at the same factory location
  auto* proxyAfter20 = mgr.RegisterOrUpdatePlannedFactory(20, 1, nullptr, factoryPos);
  EXPECT_EQ(proxy, proxyAfter20);
  EXPECT_TRUE(proxy->HasBuilder(10, 0));
  EXPECT_TRUE(proxy->HasBuilder(20, 1));

  // Builder 30 (Engineer 2) assists at the same factory location
  auto* proxyAfter30 = mgr.RegisterOrUpdatePlannedFactory(30, 2, nullptr, factoryPos);
  EXPECT_EQ(proxy, proxyAfter30);
  EXPECT_TRUE(proxy->HasBuilder(30, 2));
  EXPECT_EQ(mgr.GetCount(), 1u);

  // Case 1: Builder 20 finishes moving, begins building, or switches order:
  // its specific command helper is retired via RemoveByBuilderAndIndex.
  // The proxy MUST survive and retain all pre-orders because Builders 10 & 30 are still attached.
  mgr.RemoveByBuilderAndIndex(20, 1);
  EXPECT_EQ(mgr.GetCount(), 1u);
  EXPECT_FALSE(proxy->HasBuilder(20, 1));
  EXPECT_TRUE(proxy->HasBuilder(10, 0));
  EXPECT_TRUE(proxy->HasBuilder(30, 2));
  ASSERT_EQ(proxy->mPreOrders.size(), 1u);
  EXPECT_EQ(proxy->mPreOrders[0].count, 15);
  EXPECT_TRUE(proxy->mHasRallyPoint);

  // Case 2: Builder 10 cancels construction or dies.
  // The proxy MUST still survive because Builder 30 is still assisting.
  mgr.RemoveByBuilder(10);
  EXPECT_EQ(mgr.GetCount(), 1u);
  EXPECT_FALSE(proxy->HasBuilder(10, 0));
  EXPECT_TRUE(proxy->HasBuilder(30, 2));

  // Case 3: Builder 30 cancels construction (all builders gone).
  // Now the proxy is cleaned up.
  mgr.RemoveByBuilder(30);
  EXPECT_EQ(mgr.GetCount(), 0u);
  EXPECT_EQ(mgr.FindByPosition(factoryPos, 1.0f), nullptr);

  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  PlannedUnitProxyRallyPointOrdersAndChaining
)
{
  moho::PlannedUnitProxy proxy;
  proxy.mProxyId = 77;

  EXPECT_FALSE(proxy.mHasRallyPoint);
  EXPECT_TRUE(proxy.mRallyOrders.empty());

  // 1. Single rally point via SetRallyPoint
  proxy.SetRallyPoint(moho::Vector3f{100.0f, 0.0f, 200.0f});
  EXPECT_TRUE(proxy.mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy.mRallyPoint.x, 100.0f);
  EXPECT_FLOAT_EQ(proxy.mRallyPoint.z, 200.0f);
  ASSERT_EQ(proxy.mRallyOrders.size(), 1u);
  EXPECT_FLOAT_EQ(proxy.mRallyOrders[0].position.x, 100.0f);
  EXPECT_FLOAT_EQ(proxy.mRallyOrders[0].position.z, 200.0f);

  // 2. Chained waypoint order (clear = false)
  moho::RallyPointOrder waypoint2{};
  waypoint2.commandType = moho::EUnitCommandType::UNITCOMMAND_Move;
  waypoint2.targetType = moho::EAiTargetType::AITARGET_Ground;
  waypoint2.position = moho::Vector3f{150.0f, 0.0f, 250.0f};
  proxy.AddRallyOrder(waypoint2, false);

  EXPECT_TRUE(proxy.mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy.mRallyPoint.x, 150.0f);
  EXPECT_FLOAT_EQ(proxy.mRallyPoint.z, 250.0f);
  ASSERT_EQ(proxy.mRallyOrders.size(), 2u);
  EXPECT_FLOAT_EQ(proxy.mRallyOrders[0].position.x, 100.0f);
  EXPECT_FLOAT_EQ(proxy.mRallyOrders[1].position.x, 150.0f);

  // 3. New rally point resetting queue (clear = true)
  moho::RallyPointOrder newRally{};
  newRally.commandType = moho::EUnitCommandType::UNITCOMMAND_Move;
  newRally.targetType = moho::EAiTargetType::AITARGET_Ground;
  newRally.position = moho::Vector3f{300.0f, 0.0f, 400.0f};
  proxy.AddRallyOrder(newRally, true);

  EXPECT_TRUE(proxy.mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy.mRallyPoint.x, 300.0f);
  EXPECT_FLOAT_EQ(proxy.mRallyPoint.z, 400.0f);
  ASSERT_EQ(proxy.mRallyOrders.size(), 1u);
  EXPECT_FLOAT_EQ(proxy.mRallyOrders[0].position.x, 300.0f);

  // 4. Clear rally point
  proxy.ClearRallyPoint();
  EXPECT_FALSE(proxy.mHasRallyPoint);
  EXPECT_TRUE(proxy.mRallyOrders.empty());
  EXPECT_FLOAT_EQ(proxy.mRallyPoint.x, 0.0f);
}

TEST(
  PlannedFactoryPreOrdersTest,
  PlannedFactoryRallyPointDispatchViaHook
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  const moho::Vector3f factoryPos{200.0f, 0.0f, 200.0f};
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(5, 0, nullptr, factoryPos);
  ASSERT_NE(proxy, nullptr);

  proxy->AddPreOrder("ual0201", 5);

  // Set initial rally point and a chained waypoint
  moho::RallyPointOrder rally1{};
  rally1.commandType = moho::EUnitCommandType::UNITCOMMAND_Move;
  rally1.targetType = moho::EAiTargetType::AITARGET_Ground;
  rally1.position = moho::Vector3f{250.0f, 0.0f, 220.0f};
  proxy->AddRallyOrder(rally1, true);

  moho::RallyPointOrder rally2{};
  rally2.commandType = moho::EUnitCommandType::UNITCOMMAND_Move;
  rally2.targetType = moho::EAiTargetType::AITARGET_Ground;
  rally2.position = moho::Vector3f{300.0f, 0.0f, 250.0f};
  proxy->AddRallyOrder(rally2, false);

  EXPECT_TRUE(proxy->mHasRallyPoint);
  ASSERT_EQ(proxy->mRallyOrders.size(), 2u);

  bool dispatched = false;
  std::size_t orderCount = 0;
  bool hadRally = false;
  std::size_t rallyOrderCount = 0;

  mgr.SetDispatchHook([&](moho::UserUnit*, const moho::PlannedUnitProxy& p) {
    dispatched = true;
    orderCount = p.mPreOrders.size();
    hadRally = p.mHasRallyPoint;
    rallyOrderCount = p.mRallyOrders.size();
  });

  auto* dummyFactory = reinterpret_cast<moho::UserUnit*>(0xFAC70F);
  EXPECT_TRUE(mgr.DispatchPreOrdersForUnit(dummyFactory, factoryPos));
  EXPECT_TRUE(dispatched);
  EXPECT_EQ(orderCount, 1u);
  EXPECT_TRUE(hadRally);
  EXPECT_EQ(rallyOrderCount, 2u);

  mgr.ResetDispatchHook();
  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  IssueFactoryCommandDirectProxyInterception
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  const moho::Vector3f factoryPos{50.0f, 0.0f, 50.0f};
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(10, 0, nullptr, factoryPos);
  ASSERT_NE(proxy, nullptr);

  alignas(moho::UserUnit) std::byte unitStorage[sizeof(moho::UserUnit)]{};
  auto* testUnit = reinterpret_cast<moho::UserUnit*>(unitStorage);
  testUnit->mParams.mEntityId = 0x00107001u; // In proxy entity id range
  proxy->mUserUnit = testUnit;

  EXPECT_FALSE(proxy->mHasRallyPoint);
  EXPECT_TRUE(proxy->mRallyOrders.empty());

  // 1. Issue first rally point command (clearQueue = true)
  moho::SSTICommandIssueData rallyCmd1(moho::EUnitCommandType::UNITCOMMAND_Move);
  rallyCmd1.mTarget.mType = moho::EAiTargetType::AITARGET_Ground;
  rallyCmd1.mTarget.mPos = {75.0f, 0.0f, 125.0f};

  gpg::fastvector<moho::UserUnit*> units;
  units.push_back(testUnit);

  moho::ISSUE_FactoryCommand(units, rallyCmd1, /*clearQueue=*/true);

  EXPECT_TRUE(proxy->mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy->mRallyPoint.x, 75.0f);
  EXPECT_FLOAT_EQ(proxy->mRallyPoint.z, 125.0f);
  ASSERT_EQ(proxy->mRallyOrders.size(), 1u);
  EXPECT_EQ(proxy->mRallyOrders[0].commandType, moho::EUnitCommandType::UNITCOMMAND_Move);
  EXPECT_EQ(proxy->mRallyOrders[0].targetType, moho::EAiTargetType::AITARGET_Ground);
  EXPECT_FLOAT_EQ(proxy->mRallyOrders[0].position.x, 75.0f);
  EXPECT_FLOAT_EQ(proxy->mRallyOrders[0].position.z, 125.0f);

  // 2. Issue chained waypoint with Shift (clearQueue = false)
  moho::SSTICommandIssueData rallyCmd2(moho::EUnitCommandType::UNITCOMMAND_Move);
  rallyCmd2.mTarget.mType = moho::EAiTargetType::AITARGET_Ground;
  rallyCmd2.mTarget.mPos = {120.0f, 0.0f, 180.0f};

  moho::ISSUE_FactoryCommand(units, rallyCmd2, /*clearQueue=*/false);

  EXPECT_TRUE(proxy->mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy->mRallyPoint.x, 120.0f);
  EXPECT_FLOAT_EQ(proxy->mRallyPoint.z, 180.0f);
  ASSERT_EQ(proxy->mRallyOrders.size(), 2u);
  EXPECT_FLOAT_EQ(proxy->mRallyOrders[0].position.x, 75.0f);
  EXPECT_FLOAT_EQ(proxy->mRallyOrders[1].position.x, 120.0f);

  // 3. Issue new rally point without Shift (clearQueue = true) - must reset queue
  moho::SSTICommandIssueData rallyCmd3(moho::EUnitCommandType::UNITCOMMAND_Move);
  rallyCmd3.mTarget.mType = moho::EAiTargetType::AITARGET_Ground;
  rallyCmd3.mTarget.mPos = {300.0f, 0.0f, 400.0f};

  moho::ISSUE_FactoryCommand(units, rallyCmd3, /*clearQueue=*/true);

  EXPECT_TRUE(proxy->mHasRallyPoint);
  EXPECT_FLOAT_EQ(proxy->mRallyPoint.x, 300.0f);
  EXPECT_FLOAT_EQ(proxy->mRallyPoint.z, 400.0f);
  ASSERT_EQ(proxy->mRallyOrders.size(), 1u);
  EXPECT_FLOAT_EQ(proxy->mRallyOrders[0].position.x, 300.0f);

  proxy->mUserUnit = nullptr;
  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  IssueFactoryCommandDisabledFeatureNoInterception
)
{
  moho::SetFactoryPreOrdersEnabled(false);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  const moho::Vector3f factoryPos{50.0f, 0.0f, 50.0f};
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(10, 0, nullptr, factoryPos);
  ASSERT_NE(proxy, nullptr);

  alignas(moho::UserUnit) std::byte unitStorage[sizeof(moho::UserUnit)]{};
  auto* testUnit = reinterpret_cast<moho::UserUnit*>(unitStorage);
  testUnit->mParams.mEntityId = 0x00107001u;
  proxy->mUserUnit = testUnit;

  moho::SSTICommandIssueData rallyCmd(moho::EUnitCommandType::UNITCOMMAND_Move);
  rallyCmd.mTarget.mType = moho::EAiTargetType::AITARGET_Ground;
  rallyCmd.mTarget.mPos = {75.0f, 0.0f, 125.0f};

  gpg::fastvector<moho::UserUnit*> units;
  units.push_back(testUnit);

  // When feature is disabled, proxy must not intercept or store the rally point
  moho::ISSUE_FactoryCommand(units, rallyCmd, /*clearQueue=*/true);

  EXPECT_FALSE(proxy->mHasRallyPoint);
  EXPECT_TRUE(proxy->mRallyOrders.empty());

  proxy->mUserUnit = nullptr;
  mgr.ClearAll();
}

TEST(
  PlannedFactoryPreOrdersTest,
  PlannedProxyCommandHelperLifetimeNeverExpiresWhenDue
)
{
  moho::SSTICommandConstantData constData{};
  constData.cmd = 101;
  // Helper created for proxy with deleteWhenDue = 0u
  auto* helper = new moho::UserCommandIssueHelper(constData, /*deleteWhenDue=*/0u, /*dueSeqNo=*/10);
  EXPECT_EQ(helper->mDeleteWhenDue, 0u);
  EXPECT_EQ(helper->mDueSeqNo, 10);

  // Advance past dueSeqNo
  helper->AdvanceLocalEventsToBeat(15);
  // With deleteWhenDue = 0u, the helper remains valid and is NOT self-deleted.
  EXPECT_EQ(helper->mConstantData.cmd, 101);

  delete helper;
}

TEST(
  PlannedFactoryPreOrdersTest,
  PlannedProxyFactoryQueuePrimaryLinksRetentionAcrossBeats
)
{
  moho::UserCommandQueue queue(nullptr);
  moho::SSTICommandConstantData constData{};
  constData.cmd = 202;
  auto* helper = new moho::UserCommandIssueHelper(constData, 0u, 10);

  // Proxy stores helper in primaryLinks
  queue.primaryLinks.push_back(moho::WeakPtr<moho::UserCommandIssueHelper>(helper));
  queue.resolvedLinksDirty = 1u;

  EXPECT_EQ(queue.primaryLinks.size(), 1u);
  EXPECT_TRUE(queue.issueQueue.empty());

  // When issueQueue is empty, queue links resolution yields primaryLinks
  auto* links = moho::GetUserUnitManagerQueueLinks(&queue);
  ASSERT_NE(links, nullptr);
  ASSERT_EQ(links->size(), 1u);
  EXPECT_EQ((*links)[0].GetObjectPtr(), helper);

  // Dirtying resolvedLinks and re-resolving still yields primaryLinks (not cleared by ticks)
  queue.resolvedLinksDirty = 1u;
  links = moho::GetUserUnitManagerQueueLinks(&queue);
  ASSERT_NE(links, nullptr);
  ASSERT_EQ(links->size(), 1u);
  EXPECT_EQ((*links)[0].GetObjectPtr(), helper);

  // Clean up
  for (const auto& link : queue.primaryLinks) {
    if (auto* h = link.GetObjectPtr()) {
      delete h;
    }
  }
  queue.primaryLinks.clear();
  EXPECT_TRUE(queue.primaryLinks.empty());
}

TEST(
  PlannedFactoryPreOrdersTest,
  PlannedProxyMoveCommandTargetingGroundVsAssist
)
{
  moho::SetFactoryPreOrdersEnabled(true);
  auto& mgr = moho::PlannedFactoryManager::Get();
  mgr.ClearAll();

  const moho::Vector3f factoryPos{250.0f, 10.0f, 350.0f};
  const std::uint32_t builderId = 42;
  auto* proxy = mgr.RegisterOrUpdatePlannedFactory(builderId, 1, nullptr, factoryPos);
  ASSERT_NE(proxy, nullptr);

  alignas(moho::UserUnit) std::byte proxyStorage[sizeof(moho::UserUnit)]{};
  auto* proxyUnit = reinterpret_cast<moho::UserUnit*>(proxyStorage);
  proxyUnit->mParams.mEntityId = 0x00107005u;
  proxy->mUserUnit = proxyUnit;

  // 1. Move command: MUST resolve to ground target at proxy's position
  moho::SSTICommandIssueData moveCmd(moho::EUnitCommandType::UNITCOMMAND_Move);
  moveCmd.mTarget.mType = moho::EAiTargetType::AITARGET_Entity;
  moveCmd.mTarget.mEnt = static_cast<std::int32_t>(proxyUnit->mParams.mEntityId);

  const bool isMove =
    (moveCmd.mCommandType == moho::EUnitCommandType::UNITCOMMAND_Move ||
     moveCmd.mCommandType == moho::EUnitCommandType::UNITCOMMAND_AggressiveMove ||
     moveCmd.mCommandType == moho::EUnitCommandType::UNITCOMMAND_FormMove ||
     moveCmd.mCommandType == moho::EUnitCommandType::UNITCOMMAND_FormAggressiveMove);
  EXPECT_TRUE(isMove);

  if (!isMove && proxy->mBuilderEntityId != 0) {
    moveCmd.mTarget.mEnt = static_cast<std::int32_t>(proxy->mBuilderEntityId);
  } else {
    moveCmd.mTarget.mType = moho::EAiTargetType::AITARGET_Ground;
    moveCmd.mTarget.mPos = {proxy->mPosition.x, proxy->mPosition.y, proxy->mPosition.z};
  }

  EXPECT_EQ(moveCmd.mTarget.mType, moho::EAiTargetType::AITARGET_Ground);
  EXPECT_FLOAT_EQ(moveCmd.mTarget.mPos.x, 250.0f);
  EXPECT_FLOAT_EQ(moveCmd.mTarget.mPos.z, 350.0f);

  // 2. Guard/Repair command: MUST resolve to entity target of builder
  moho::SSTICommandIssueData guardCmd(moho::EUnitCommandType::UNITCOMMAND_Guard);
  guardCmd.mTarget.mType = moho::EAiTargetType::AITARGET_Entity;
  guardCmd.mTarget.mEnt = static_cast<std::int32_t>(proxyUnit->mParams.mEntityId);

  const bool isGuardMove =
    (guardCmd.mCommandType == moho::EUnitCommandType::UNITCOMMAND_Move ||
     guardCmd.mCommandType == moho::EUnitCommandType::UNITCOMMAND_AggressiveMove);
  EXPECT_FALSE(isGuardMove);

  if (!isGuardMove && proxy->mBuilderEntityId != 0) {
    guardCmd.mTarget.mEnt = static_cast<std::int32_t>(proxy->mBuilderEntityId);
  } else {
    guardCmd.mTarget.mType = moho::EAiTargetType::AITARGET_Ground;
    guardCmd.mTarget.mPos = {proxy->mPosition.x, proxy->mPosition.y, proxy->mPosition.z};
  }

  EXPECT_EQ(guardCmd.mTarget.mType, moho::EAiTargetType::AITARGET_Entity);
  EXPECT_EQ(guardCmd.mTarget.mEnt, 42);

  proxy->mUserUnit = nullptr;
  mgr.ClearAll();
}
