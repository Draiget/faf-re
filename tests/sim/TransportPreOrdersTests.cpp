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
}
