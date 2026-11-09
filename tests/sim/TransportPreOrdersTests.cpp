#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "moho/command/SSTICommandIssueData.h"
#include "moho/entity/EntityId.h"
#include "moho/unit/core/UserUnit.h"

namespace
{
  using namespace moho;

  struct MockUserUnitScope
  {
    alignas(UserUnit) std::byte mStorage[sizeof(UserUnit)]{};

    UserUnit* GetUnit(std::uint32_t entityId)
    {
      auto* unit = reinterpret_cast<UserUnit*>(mStorage);
      unit->mParams.mEntityId = entityId;
      return unit;
    }

    ~MockUserUnitScope()
    {
      if (auto* unit = reinterpret_cast<UserUnit*>(mStorage)) {
        unit->ClearTransportPreOrders();
        unit->ClearSelectionBracketPositionOverride();
      }
    }
  };

  TEST(TransportPreOrdersTests, InitialStateIsEmpty)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(101);

    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(TransportPreOrdersTests, QueueSingleOrder)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(102);

    SSTICommandIssueData cmd(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd, false);

    EXPECT_TRUE(unit->HasTransportPreOrders());
    auto orders = unit->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 1u);
    EXPECT_EQ(orders[0].mCommandType, EUnitCommandType::UNITCOMMAND_Move);
  }

  TEST(TransportPreOrdersTests, QueueWithClearQueueReplacesOrders)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(103);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd1, false);

    SSTICommandIssueData cmd2(EUnitCommandType::UNITCOMMAND_Patrol);
    unit->QueueTransportPreOrder(cmd2, true);

    EXPECT_TRUE(unit->HasTransportPreOrders());
    auto orders = unit->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 1u);
    EXPECT_EQ(orders[0].mCommandType, EUnitCommandType::UNITCOMMAND_Patrol);
  }

  TEST(TransportPreOrdersTests, QueueWithoutClearQueueAppendsOrders)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(104);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd1, false);

    SSTICommandIssueData cmd2(EUnitCommandType::UNITCOMMAND_Attack);
    unit->QueueTransportPreOrder(cmd2, false);

    EXPECT_TRUE(unit->HasTransportPreOrders());
    auto orders = unit->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 2u);
    EXPECT_EQ(orders[0].mCommandType, EUnitCommandType::UNITCOMMAND_Move);
    EXPECT_EQ(orders[1].mCommandType, EUnitCommandType::UNITCOMMAND_Attack);
  }

  TEST(TransportPreOrdersTests, ClearPreOrdersEmptiesQueue)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(105);

    SSTICommandIssueData cmd(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd, false);
    EXPECT_TRUE(unit->HasTransportPreOrders());

    unit->ClearTransportPreOrders();
    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(TransportPreOrdersTests, DifferentUnitsHaveIndependentQueues)
  {
    MockUserUnitScope scope1;
    UserUnit* unit1 = scope1.GetUnit(201);

    MockUserUnitScope scope2;
    UserUnit* unit2 = scope2.GetUnit(202);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    unit1->QueueTransportPreOrder(cmd1, false);

    SSTICommandIssueData cmd2(EUnitCommandType::UNITCOMMAND_Attack);
    unit2->QueueTransportPreOrder(cmd2, false);

    EXPECT_EQ(unit1->GetTransportPreOrders().size(), 1u);
    EXPECT_EQ(unit1->GetTransportPreOrders()[0].mCommandType, EUnitCommandType::UNITCOMMAND_Move);

    EXPECT_EQ(unit2->GetTransportPreOrders().size(), 1u);
    EXPECT_EQ(unit2->GetTransportPreOrders()[0].mCommandType, EUnitCommandType::UNITCOMMAND_Attack);

    unit1->ClearTransportPreOrders();
    EXPECT_FALSE(unit1->HasTransportPreOrders());
    EXPECT_TRUE(unit2->HasTransportPreOrders());
  }

  TEST(TransportPreOrdersTests, DispatchDisembarkedPreOrdersClearsQueue)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(301);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    SSTICommandIssueData cmd2(EUnitCommandType::UNITCOMMAND_Attack);
    unit->QueueTransportPreOrder(cmd1, false);
    unit->QueueTransportPreOrder(cmd2, false);

    EXPECT_TRUE(unit->HasTransportPreOrders());
    EXPECT_EQ(unit->GetTransportPreOrders().size(), 2u);

    unit->DispatchDisembarkedPreOrders();

    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(TransportPreOrdersTests, DispatchDisembarkedPreOrdersNoOpWhenEmpty)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(302);

    EXPECT_FALSE(unit->HasTransportPreOrders());
    unit->DispatchDisembarkedPreOrders();
    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(TransportPreOrdersTests, DetachmentTransitionPredicateTriggersDispatch)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(303);

    SSTICommandIssueData cmd(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd, false);

    constexpr std::uint32_t kInvalidEntityId = ToRaw(EEntityIdSentinel::Invalid);
    constexpr std::uint32_t kTransportId = 500u;

    auto ShouldDispatch = [](std::uint32_t oldParent, std::uint32_t newParent) -> bool {
      const bool wasAttached = (oldParent != 0 && oldParent != kInvalidEntityId);
      const bool nowDetached = (newParent == 0 || newParent == kInvalidEntityId);
      return wasAttached && nowDetached;
    };

    // Case 1: Still attached -> Should not dispatch
    EXPECT_FALSE(ShouldDispatch(kTransportId, kTransportId));
    EXPECT_TRUE(unit->HasTransportPreOrders());

    // Case 2: Embarking -> Should not dispatch
    EXPECT_FALSE(ShouldDispatch(kInvalidEntityId, kTransportId));
    EXPECT_TRUE(unit->HasTransportPreOrders());

    // Case 3: Already detached -> Should not dispatch
    EXPECT_FALSE(ShouldDispatch(kInvalidEntityId, kInvalidEntityId));
    EXPECT_TRUE(unit->HasTransportPreOrders());

    // Case 4: Detachment -> Dispatches pre-orders
    EXPECT_TRUE(ShouldDispatch(kTransportId, kInvalidEntityId));
    if (ShouldDispatch(kTransportId, kInvalidEntityId)) {
      if (unit->HasTransportPreOrders()) {
        unit->DispatchDisembarkedPreOrders();
      }
    }
    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(TransportPreOrdersTests, MultipleChainedOrdersSequence)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(401);

    SSTICommandIssueData moveCmd(EUnitCommandType::UNITCOMMAND_Move);
    moveCmd.mTarget.mType = EAiTargetType::AITARGET_Ground;
    moveCmd.mTarget.mPos = Wm3::Vec3f(150.0f, 20.0f, 100.0f);
    unit->QueueTransportPreOrder(moveCmd, false);

    SSTICommandIssueData buildCmd(EUnitCommandType::UNITCOMMAND_BuildMobile);
    buildCmd.mTarget.mType = EAiTargetType::AITARGET_Ground;
    buildCmd.mTarget.mPos = Wm3::Vec3f(120.0f, 20.0f, 100.0f);
    unit->QueueTransportPreOrder(buildCmd, false);

    SSTICommandIssueData patrolCmd(EUnitCommandType::UNITCOMMAND_Patrol);
    patrolCmd.mTarget.mType = EAiTargetType::AITARGET_Ground;
    patrolCmd.mTarget.mPos = Wm3::Vec3f(180.0f, 20.0f, 110.0f);
    unit->QueueTransportPreOrder(patrolCmd, false);

    EXPECT_TRUE(unit->HasTransportPreOrders());
    const auto orders = unit->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 3u);

    EXPECT_EQ(orders[0].mCommandType, EUnitCommandType::UNITCOMMAND_Move);
    EXPECT_FLOAT_EQ(orders[0].mTarget.mPos.x, 150.0f);

    EXPECT_EQ(orders[1].mCommandType, EUnitCommandType::UNITCOMMAND_BuildMobile);
    EXPECT_FLOAT_EQ(orders[1].mTarget.mPos.x, 120.0f);

    EXPECT_EQ(orders[2].mCommandType, EUnitCommandType::UNITCOMMAND_Patrol);
    EXPECT_FLOAT_EQ(orders[2].mTarget.mPos.x, 180.0f);

    unit->DispatchDisembarkedPreOrders();
    EXPECT_FALSE(unit->HasTransportPreOrders());
  }

  TEST(TransportPreOrdersTests, ClearQueueDuringQueueing)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(402);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd1, false);

    SSTICommandIssueData cmd2(EUnitCommandType::UNITCOMMAND_Attack);
    unit->QueueTransportPreOrder(cmd2, false);

    ASSERT_EQ(unit->GetTransportPreOrders().size(), 2u);

    // Now issue order 3 with clearQueue = true (e.g. without Shift)
    SSTICommandIssueData cmd3(EUnitCommandType::UNITCOMMAND_BuildMobile);
    unit->QueueTransportPreOrder(cmd3, true);

    const auto orders = unit->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 1u);
    EXPECT_EQ(orders[0].mCommandType, EUnitCommandType::UNITCOMMAND_BuildMobile);
  }

  TEST(TransportPreOrdersTests, DestructionClearsPreOrdersSafely)
  {
    {
      MockUserUnitScope scope;
      UserUnit* unit = scope.GetUnit(403);
      SSTICommandIssueData cmd(EUnitCommandType::UNITCOMMAND_Move);
      unit->QueueTransportPreOrder(cmd, false);
      EXPECT_TRUE(unit->HasTransportPreOrders());
      // Destructor of MockUserUnitScope calls ClearTransportPreOrders()
    }
    // Storage has destructed, verify unit 403 has no leftover records
    MockUserUnitScope scope2;
    UserUnit* unit2 = scope2.GetUnit(403);
    EXPECT_FALSE(unit2->HasTransportPreOrders());
  }

  TEST(TransportPreOrdersTests, SelectionBracketPositionOverrideInitialState)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(501);

    EXPECT_FALSE(unit->HasSelectionBracketPositionOverride());
    EXPECT_EQ(unit->GetSelectionBracketPositionOverride(), Wm3::Vector3f::ZERO);
  }

  TEST(TransportPreOrdersTests, SetAndClearSelectionBracketPositionOverride)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(502);

    const Wm3::Vector3f pos(100.5f, 25.0f, 200.5f);
    unit->SetSelectionBracketPositionOverride(pos);

    EXPECT_TRUE(unit->HasSelectionBracketPositionOverride());
    EXPECT_EQ(unit->GetSelectionBracketPositionOverride(), pos);

    unit->ClearSelectionBracketPositionOverride();
    EXPECT_FALSE(unit->HasSelectionBracketPositionOverride());
    EXPECT_EQ(unit->GetSelectionBracketPositionOverride(), Wm3::Vector3f::ZERO);
  }
  TEST(TransportPreOrdersTests, StopCommandClearsQueue)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(601);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd1, false);
    EXPECT_TRUE(unit->HasTransportPreOrders());

    SSTICommandIssueData stopCmd(EUnitCommandType::UNITCOMMAND_Stop);
    unit->QueueTransportPreOrder(stopCmd, false);
    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(TransportPreOrdersTests, RemoveTransportPreOrderByIndex)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(602);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    SSTICommandIssueData cmd2(EUnitCommandType::UNITCOMMAND_Attack);
    unit->QueueTransportPreOrder(cmd1, false);
    unit->QueueTransportPreOrder(cmd2, false);

    ASSERT_EQ(unit->GetTransportPreOrders().size(), 2u);

    EXPECT_FALSE(unit->RemoveTransportPreOrder(5)); // Out of bounds
    EXPECT_TRUE(unit->RemoveTransportPreOrder(0)); // Remove first
    ASSERT_EQ(unit->GetTransportPreOrders().size(), 1u);
    EXPECT_EQ(unit->GetTransportPreOrders()[0].mCommandType, EUnitCommandType::UNITCOMMAND_Attack);

    EXPECT_TRUE(unit->RemoveTransportPreOrder(0)); // Remove remaining
    EXPECT_FALSE(unit->HasTransportPreOrders());
  }

  TEST(TransportPreOrdersTests, UpdateTransportPreOrderPositionByIndex)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(603);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    cmd1.mTarget.mPos = Wm3::Vector3f(10.0f, 0.0f, 10.0f);
    unit->QueueTransportPreOrder(cmd1, false);

    const Wm3::Vector3f newPos(20.0f, 5.0f, 30.0f);
    EXPECT_TRUE(unit->UpdateTransportPreOrderPosition(0, newPos));
    EXPECT_FALSE(unit->UpdateTransportPreOrderPosition(5, newPos));

    const auto orders = unit->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 1u);
    EXPECT_EQ(orders[0].mTarget.mPos, newPos);
  }

  TEST(TransportPreOrdersTests, RemoveAndDragTransportPreOrderById)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(604);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    cmd1.mTarget.mPos = Wm3::Vector3f(50.0f, 0.0f, 50.0f);
    unit->QueueTransportPreOrder(cmd1, false);

    const auto orders = unit->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 1u);
    const std::int32_t cmdId = orders[0].nextCommandId;
    EXPECT_GT(cmdId, 0);

    // Test dragging / updating position by ID
    const Wm3::Vector3f draggedPos(75.0f, 2.0f, 85.0f);
    EXPECT_TRUE(UserUnit::UpdateTransportPreOrderPositionById(cmdId, draggedPos));
    EXPECT_FALSE(UserUnit::UpdateTransportPreOrderPositionById(999999, draggedPos));

    const auto updatedOrders = unit->GetTransportPreOrders();
    ASSERT_EQ(updatedOrders.size(), 1u);
    EXPECT_EQ(updatedOrders[0].mTarget.mPos, draggedPos);

    // Test removing by ID
    EXPECT_FALSE(UserUnit::RemoveTransportPreOrderById(999999));
    EXPECT_TRUE(UserUnit::RemoveTransportPreOrderById(cmdId));
    EXPECT_FALSE(unit->HasTransportPreOrders());
  }
  TEST(TransportPreOrdersTests, SharedGroupPreOrdersCommonCommandId)
  {
    MockUserUnitScope scope1;
    MockUserUnitScope scope2;
    UserUnit* unit1 = scope1.GetUnit(701);
    UserUnit* unit2 = scope2.GetUnit(702);

    gpg::fastvector<UserUnit*> group;
    group.push_back(unit1);
    group.push_back(unit2);

    SSTICommandIssueData sharedCmd(EUnitCommandType::UNITCOMMAND_Move);
    sharedCmd.mTarget.mPos = Wm3::Vector3f(120.0f, 0.0f, 130.0f);
    UserUnit::QueueTransportPreOrders(group, sharedCmd, false);

    EXPECT_TRUE(unit1->HasTransportPreOrders());
    EXPECT_TRUE(unit2->HasTransportPreOrders());

    const auto orders1 = unit1->GetTransportPreOrders();
    const auto orders2 = unit2->GetTransportPreOrders();
    ASSERT_EQ(orders1.size(), 1u);
    ASSERT_EQ(orders2.size(), 1u);

    // Both units MUST share the exact same command ID!
    EXPECT_EQ(orders1[0].nextCommandId, orders2[0].nextCommandId);
    const std::int32_t sharedId = orders1[0].nextCommandId;
    EXPECT_GT(sharedId, 0);

    // Dragging the shared command ID must update BOTH units simultaneously!
    const Wm3::Vector3f newSharedPos(150.0f, 5.0f, 160.0f);
    EXPECT_TRUE(UserUnit::UpdateTransportPreOrderPositionById(sharedId, newSharedPos));
    EXPECT_EQ(unit1->GetTransportPreOrders()[0].mTarget.mPos, newSharedPos);
    EXPECT_EQ(unit2->GetTransportPreOrders()[0].mTarget.mPos, newSharedPos);

    // Cancelling the shared command ID must remove it from BOTH units simultaneously!
    EXPECT_TRUE(UserUnit::RemoveTransportPreOrderById(sharedId));
    EXPECT_FALSE(unit1->HasTransportPreOrders());
    EXPECT_FALSE(unit2->HasTransportPreOrders());
  }

  TEST(TransportPreOrdersTests, DisembarkDispatchesGroupPreOrders)
  {
    MockUserUnitScope scope1;
    MockUserUnitScope scope2;
    UserUnit* unit1 = scope1.GetUnit(801);
    UserUnit* unit2 = scope2.GetUnit(802);

    gpg::fastvector<UserUnit*> group;
    group.push_back(unit1);
    group.push_back(unit2);

    SSTICommandIssueData sharedCmd(EUnitCommandType::UNITCOMMAND_Move);
    sharedCmd.mTarget.mPos = Wm3::Vector3f(200.0f, 0.0f, 210.0f);
    UserUnit::QueueTransportPreOrders(group, sharedCmd, false);

    EXPECT_TRUE(unit1->HasTransportPreOrders());
    EXPECT_TRUE(unit2->HasTransportPreOrders());

    // In unit test environment (session == nullptr), disembarking unit1
    // immediately dispatches and clears unit1's queue without crashing or leaking.
    unit1->DispatchDisembarkedPreOrders();
    EXPECT_FALSE(unit1->HasTransportPreOrders());

    // Disembarking unit2 cleans up its queue as well.
    unit2->DispatchDisembarkedPreOrders();
    EXPECT_FALSE(unit2->HasTransportPreOrders());
  }

  TEST(TransportPreOrdersTests, BuildMobilePreOrderQueueing)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(901);

    SSTICommandIssueData buildCmd(EUnitCommandType::UNITCOMMAND_BuildMobile);
    buildCmd.mTarget.mPos = Wm3::Vector3f(300.0f, 10.0f, 320.0f);
    unit->QueueTransportPreOrder(buildCmd, false);

    EXPECT_TRUE(unit->HasTransportPreOrders());
    const auto orders = unit->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 1u);
    EXPECT_EQ(orders[0].mCommandType, EUnitCommandType::UNITCOMMAND_BuildMobile);
    EXPECT_EQ(orders[0].mTarget.mPos, Wm3::Vector3f(300.0f, 10.0f, 320.0f));

    // Position drag updates cleanly
    const Wm3::Vector3f draggedPos(350.0f, 15.0f, 360.0f);
    EXPECT_TRUE(UserUnit::UpdateTransportPreOrderPositionById(orders[0].nextCommandId, draggedPos));
    EXPECT_EQ(unit->GetTransportPreOrders()[0].mTarget.mPos, draggedPos);

    unit->ClearTransportPreOrders();
    EXPECT_FALSE(unit->HasTransportPreOrders());
  }

  TEST(TransportPreOrdersTests, ConVarSwitchTogglesFeature)
  {
    MockUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(902);

    // Disable feature via switch
    moho::ui_TransportPreOrders = false;

    SSTICommandIssueData moveCmd(EUnitCommandType::UNITCOMMAND_Move);
    moveCmd.mTarget.mPos = Wm3::Vector3f(100.0f, 0.0f, 100.0f);
    unit->QueueTransportPreOrder(moveCmd, false);

    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_FALSE(UserUnit::HasAnyTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());

    // Re-enable feature via switch
    moho::ui_TransportPreOrders = true;

    unit->QueueTransportPreOrder(moveCmd, false);
    EXPECT_TRUE(unit->HasTransportPreOrders());
    EXPECT_TRUE(UserUnit::HasAnyTransportPreOrders());
    EXPECT_EQ(unit->GetTransportPreOrders().size(), 1u);

    unit->ClearTransportPreOrders();
    EXPECT_FALSE(unit->HasTransportPreOrders());
  }
}
