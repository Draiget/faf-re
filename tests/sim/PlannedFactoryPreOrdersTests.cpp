#include <gtest/gtest.h>

#include "moho/console/CConCommand.h"
#include "moho/render/camera/GeomCamera3.h"
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

TEST(PlannedFactoryPreOrdersTest, ProxySelectionStateAndManagerSelectionTracking)
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

TEST(PlannedFactoryPreOrdersTest, ScreenHitTestPointAndMarqueeRect)
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
  EXPECT_TRUE(mgr.HitTestScreenRect(static_cast<const moho::GeomCamera3*>(nullptr), 0.0f, 0.0f, 1920.0f, 1080.0f).empty());

  mgr.ClearAll();
}

TEST(PlannedFactoryPreOrdersTest, HitTestingGatedByConvar)
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

TEST(PlannedFactoryPreOrdersTest, WorldViewNullSafetyAndBoundingRadius)
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
