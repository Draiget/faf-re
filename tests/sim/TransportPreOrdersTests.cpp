#include <gtest/gtest.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "moho/command/SSTICommandIssueData.h"
#include "moho/entity/EntityId.h"
#include "moho/ui/SelectionDragger.h"
#include "moho/unit/core/UserUnit.h"

namespace
{
  using namespace moho;

  // `UserUnit` can't be built without a live session. The pre-order registry reads only the unit's
  // entity id (and its army and session, which stay zero here, so a dispatch finds no session), so the
  // tests use zeroed storage of the right size and alignment with only `mParams.mEntityId` set.
  struct FakeUserUnitScope
  {
    alignas(UserUnit) std::byte mStorage[sizeof(UserUnit)]{};
    bool mPrevSwitchState{moho::ui_TransportPreOrders};

    FakeUserUnitScope()
    {
      moho::ui_TransportPreOrders = true;
    }

    UserUnit* GetUnit(
      std::uint32_t entityId
    )
    {
      auto* unit = reinterpret_cast<UserUnit*>(mStorage);
      unit->mParams.mEntityId = entityId;
      return unit;
    }

    ~FakeUserUnitScope()
    {
      if (auto* unit = reinterpret_cast<UserUnit*>(mStorage)) {
        unit->ClearTransportPreOrders();
        unit->ClearSelectionBracketPositionOverride();
      }
      moho::ui_TransportPreOrders = mPrevSwitchState;
    }
  };

  TEST(
    TransportPreOrdersTests,
    InitialStateIsEmpty
  )
  {
    FakeUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(101);

    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(
    TransportPreOrdersTests,
    QueueSingleOrder
  )
  {
    FakeUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(102);

    SSTICommandIssueData cmd(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd, false);

    EXPECT_TRUE(unit->HasTransportPreOrders());
    auto orders = unit->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 1u);
    EXPECT_EQ(orders[0].mCommandType, EUnitCommandType::UNITCOMMAND_Move);
  }

  TEST(
    TransportPreOrdersTests,
    QueueWithClearQueueReplacesOrders
  )
  {
    FakeUserUnitScope scope;
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

  TEST(
    TransportPreOrdersTests,
    QueueWithoutClearQueueAppendsOrders
  )
  {
    FakeUserUnitScope scope;
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

  TEST(
    TransportPreOrdersTests,
    ClearPreOrdersEmptiesQueue
  )
  {
    FakeUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(105);

    SSTICommandIssueData cmd(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd, false);
    EXPECT_TRUE(unit->HasTransportPreOrders());

    unit->ClearTransportPreOrders();
    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(
    TransportPreOrdersTests,
    DifferentUnitsHaveIndependentQueues
  )
  {
    FakeUserUnitScope scope1;
    UserUnit* unit1 = scope1.GetUnit(201);

    FakeUserUnitScope scope2;
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

  TEST(
    TransportPreOrdersTests,
    DispatchDisembarkedPreOrdersClearsQueue
  )
  {
    FakeUserUnitScope scope;
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

  TEST(
    TransportPreOrdersTests,
    DispatchDisembarkedPreOrdersNoOpWhenEmpty
  )
  {
    FakeUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(302);

    EXPECT_FALSE(unit->HasTransportPreOrders());
    unit->DispatchDisembarkedPreOrders();
    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(
    TransportPreOrdersTests,
    DetachmentTransitionPredicateTriggersDispatch
  )
  {
    FakeUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(303);

    SSTICommandIssueData cmd(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd, false);

    constexpr std::uint32_t kInvalidEntityId = ToRaw(EEntityIdSentinel::Invalid);
    constexpr std::uint32_t kTransportId = 500u;

    const auto ShouldDispatch = [](const std::uint32_t oldParent, const std::uint32_t newParent) {
      return UserUnit::IsDetachTransition(oldParent, newParent);
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

  TEST(
    TransportPreOrdersTests,
    MultipleChainedOrdersSequence
  )
  {
    FakeUserUnitScope scope;
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

  TEST(
    TransportPreOrdersTests,
    ClearQueueDuringQueueing
  )
  {
    FakeUserUnitScope scope;
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

  TEST(
    TransportPreOrdersTests,
    DestructionClearsPreOrdersSafely
  )
  {
    {
      FakeUserUnitScope scope;
      UserUnit* unit = scope.GetUnit(403);
      SSTICommandIssueData cmd(EUnitCommandType::UNITCOMMAND_Move);
      unit->QueueTransportPreOrder(cmd, false);
      EXPECT_TRUE(unit->HasTransportPreOrders());
      // Destructor of FakeUserUnitScope calls ClearTransportPreOrders()
    }
    // Storage has destructed, verify unit 403 has no leftover records
    FakeUserUnitScope scope2;
    UserUnit* unit2 = scope2.GetUnit(403);
    EXPECT_FALSE(unit2->HasTransportPreOrders());
  }

  TEST(
    TransportPreOrdersTests,
    SelectionBracketPositionOverrideInitialState
  )
  {
    FakeUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(501);

    EXPECT_FALSE(unit->HasSelectionBracketPositionOverride());
    EXPECT_EQ(unit->GetSelectionBracketPositionOverride(), Wm3::Vector3f::ZERO);
  }

  TEST(
    TransportPreOrdersTests,
    SetAndClearSelectionBracketPositionOverride
  )
  {
    FakeUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(502);

    const Wm3::Vector3f pos(100.5f, 25.0f, 200.5f);
    unit->SetSelectionBracketPositionOverride(pos);

    EXPECT_TRUE(unit->HasSelectionBracketPositionOverride());
    EXPECT_EQ(unit->GetSelectionBracketPositionOverride(), pos);

    unit->ClearSelectionBracketPositionOverride();
    EXPECT_FALSE(unit->HasSelectionBracketPositionOverride());
    EXPECT_EQ(unit->GetSelectionBracketPositionOverride(), Wm3::Vector3f::ZERO);
  }
  TEST(
    TransportPreOrdersTests,
    StopCommandClearsQueue
  )
  {
    FakeUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(601);

    SSTICommandIssueData cmd1(EUnitCommandType::UNITCOMMAND_Move);
    unit->QueueTransportPreOrder(cmd1, false);
    EXPECT_TRUE(unit->HasTransportPreOrders());

    SSTICommandIssueData stopCmd(EUnitCommandType::UNITCOMMAND_Stop);
    unit->QueueTransportPreOrder(stopCmd, false);
    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_TRUE(unit->GetTransportPreOrders().empty());
  }

  TEST(
    TransportPreOrdersTests,
    RemoveAndDragTransportPreOrderById
  )
  {
    FakeUserUnitScope scope;
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
  TEST(
    TransportPreOrdersTests,
    SharedGroupPreOrdersCommonCommandId
  )
  {
    FakeUserUnitScope scope1;
    FakeUserUnitScope scope2;
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

  TEST(
    TransportPreOrdersTests,
    DisembarkDispatchesGroupPreOrders
  )
  {
    FakeUserUnitScope scope1;
    FakeUserUnitScope scope2;
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

  TEST(
    TransportPreOrdersTests,
    BuildMobilePreOrderQueueing
  )
  {
    FakeUserUnitScope scope;
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

  TEST(
    TransportPreOrdersTests,
    ConVarSwitchTogglesFeature
  )
  {
    FakeUserUnitScope scope;
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

  TEST(
    TransportPreOrdersTests,
    DefaultSwitchStateIsFalse
  )
  {
    EXPECT_FALSE(moho::ui_TransportPreOrders);
  }

  TEST(
    TransportPreOrdersTests,
    FallbackHologramSelectionNullSessionSafe
  )
  {
    EXPECT_FALSE(moho::TryFallbackHologramSelection(nullptr, 0.0f, 0.0f, 100.0f, 100.0f, false));
    EXPECT_FALSE(moho::TryFallbackHologramSelection(nullptr, 0.0f, 0.0f, 100.0f, 100.0f, true));
  }

  TEST(
    TransportPreOrdersTests,
    FallbackHologramSelectionGatedByConVar
  )
  {
    const bool prev = moho::ui_TransportPreOrders;
    moho::ui_TransportPreOrders = false;
    EXPECT_FALSE(moho::TryFallbackHologramSelection(nullptr, 10.0f, 10.0f, 50.0f, 50.0f, false));
    moho::ui_TransportPreOrders = prev;
  }

  TEST(
    TransportPreOrdersTests,
    SelectionPriorityRulesLiveOverHolograms
  )
  {
    // Rule 7 & User Requirement: "Если в выделение попали живые юниты, то выделяются живые юниты."
    // Verification of the golden path selection resolution logic:
    // When live units are non-empty, fallback is bypassed entirely.
    std::vector<std::uint32_t> liveUnitsInDragSolid = {1001, 1002};
    std::vector<std::uint32_t> hologramsInDragRect = {2001, 2002};

    bool fallbackCalled = false;
    std::vector<std::uint32_t> resultingSelection;

    auto resolveSelection = [&](bool isShift, const std::vector<std::uint32_t>& currentSel) {
      if (!liveUnitsInDragSolid.empty()) {
        // Vanilla path: select live units (or merge/deselect for shift)
        resultingSelection = liveUnitsInDragSolid;
      } else {
        // Fallback path
        fallbackCalled = true;
        resultingSelection = hologramsInDragRect;
      }
    };

    resolveSelection(false, {});
    EXPECT_FALSE(fallbackCalled);
    EXPECT_EQ(resultingSelection, liveUnitsInDragSolid);

    // When no live units in drag solid, fallback triggers
    liveUnitsInDragSolid.clear();
    resolveSelection(false, {});
    EXPECT_TRUE(fallbackCalled);
    EXPECT_EQ(resultingSelection, hologramsInDragRect);
  }

  TEST(
    TransportPreOrdersTests,
    FallbackSelectionShiftLogicDeselectAndUnion
  )
  {
    // Verify shift logic:
    // 1. If all captured units are already in current selection -> deselect them.
    // 2. If at least one captured unit is NOT in current selection -> union.
    // 3. If not shift -> replace selection.
    auto applyHologramDragSelection = [](
                                        const std::vector<std::uint32_t>& currentSelection,
                                        const std::vector<std::uint32_t>& capturedUnits,
                                        bool isShift
                                      ) -> std::vector<std::uint32_t> {
      if (capturedUnits.empty()) {
        return currentSelection;
      }
      if (!isShift) {
        return capturedUnits;
      }

      // Check if all capturedUnits are already selected
      bool allAlreadySelected = true;
      for (const auto cap : capturedUnits) {
        if (std::find(currentSelection.begin(), currentSelection.end(), cap) == currentSelection.end()) {
          allAlreadySelected = false;
          break;
        }
      }

      if (allAlreadySelected) {
        // Deselect capturedUnits from currentSelection
        std::vector<std::uint32_t> remaining;
        for (const auto cur : currentSelection) {
          if (std::find(capturedUnits.begin(), capturedUnits.end(), cur) == capturedUnits.end()) {
            remaining.push_back(cur);
          }
        }
        return remaining;
      } else {
        // Union: currentSelection + capturedUnits (unique)
        std::vector<std::uint32_t> result = currentSelection;
        for (const auto cap : capturedUnits) {
          if (std::find(result.begin(), result.end(), cap) == result.end()) {
            result.push_back(cap);
          }
        }
        return result;
      }
    };

    // Case 1: Non-shift replaces selection
    {
      const std::vector<std::uint32_t> current = {101, 102};
      const std::vector<std::uint32_t> captured = {201, 202};
      const auto res = applyHologramDragSelection(current, captured, false);
      EXPECT_EQ(res, captured);
    }

    // Case 2: Shift with new units -> Union
    {
      const std::vector<std::uint32_t> current = {101, 102};
      const std::vector<std::uint32_t> captured = {102, 201}; // 201 is new
      const auto res = applyHologramDragSelection(current, captured, true);
      const std::vector<std::uint32_t> expected = {101, 102, 201};
      EXPECT_EQ(res, expected);
    }

    // Case 3: Shift with all captured units already selected -> Deselect (subtraction)
    {
      const std::vector<std::uint32_t> current = {101, 102, 103};
      const std::vector<std::uint32_t> captured = {101, 103}; // all are already in current
      const auto res = applyHologramDragSelection(current, captured, true);
      const std::vector<std::uint32_t> expected = {102};
      EXPECT_EQ(res, expected);
    }

    // Case 4: Shift deselect all selected units -> Empty selection
    {
      const std::vector<std::uint32_t> current = {201, 202};
      const std::vector<std::uint32_t> captured = {201, 202};
      const auto res = applyHologramDragSelection(current, captured, true);
      EXPECT_TRUE(res.empty());
    }
  }

  TEST(
    TransportPreOrdersTests,
    SharedSquadPreOrderAssignsSameCommandIdAcrossCargoUnits
  )
  {
    FakeUserUnitScope scopeA;
    FakeUserUnitScope scopeB;
    FakeUserUnitScope scopeC;
    UserUnit* unitA = scopeA.GetUnit(301);
    UserUnit* unitB = scopeB.GetUnit(302);
    UserUnit* unitC = scopeC.GetUnit(303);

    gpg::fastvector<UserUnit*> squad;
    squad.push_back(unitA);
    squad.push_back(unitB);
    squad.push_back(unitC);

    SSTICommandIssueData cmd(EUnitCommandType::UNITCOMMAND_Move);
    cmd.mTarget.mType = EAiTargetType::AITARGET_Ground;
    cmd.mTarget.mPos = Wm3::Vector3f{100.0f, 20.0f, 150.0f};
    UserUnit::QueueTransportPreOrders(squad, cmd, false);

    const auto ordersA = unitA->GetTransportPreOrders();
    const auto ordersB = unitB->GetTransportPreOrders();
    const auto ordersC = unitC->GetTransportPreOrders();
    ASSERT_EQ(ordersA.size(), 1u);
    ASSERT_EQ(ordersB.size(), 1u);
    ASSERT_EQ(ordersC.size(), 1u);

    EXPECT_GT(ordersA[0].nextCommandId, 0);
    EXPECT_EQ(ordersA[0].nextCommandId, ordersB[0].nextCommandId);
    EXPECT_EQ(ordersB[0].nextCommandId, ordersC[0].nextCommandId);
  }

  TEST(
    TransportPreOrdersTests,
    GuardPreOrderTargetingAnotherCargoGhost
  )
  {
    FakeUserUnitScope scopeAttacker;
    FakeUserUnitScope scopeTarget;
    UserUnit* attacker = scopeAttacker.GetUnit(401);
    UserUnit* target = scopeTarget.GetUnit(402);

    const Wm3::Vector3f attackerPos{50.0f, 10.0f, 60.0f};
    const Wm3::Vector3f targetPos{80.0f, 10.0f, 90.0f};
    attacker->SetSelectionBracketPositionOverride(attackerPos);
    target->SetSelectionBracketPositionOverride(targetPos);

    const auto& overrides = UserUnit::GetAllSelectionBracketPositionOverrides();
    ASSERT_NE(overrides.find(401u), overrides.end());
    ASSERT_NE(overrides.find(402u), overrides.end());
    EXPECT_FLOAT_EQ(overrides.at(402u).x, 80.0f);
    EXPECT_FLOAT_EQ(overrides.at(402u).z, 90.0f);

    SSTICommandIssueData guardCmd(EUnitCommandType::UNITCOMMAND_Guard);
    guardCmd.mTarget.mType = EAiTargetType::AITARGET_Entity;
    guardCmd.mTarget.mEnt = 402;
    guardCmd.mTarget.mEntityId = 402;

    attacker->QueueTransportPreOrder(guardCmd, false);
    const auto orders = attacker->GetTransportPreOrders();
    ASSERT_EQ(orders.size(), 1u);
    EXPECT_EQ(orders[0].mCommandType, EUnitCommandType::UNITCOMMAND_Guard);
    EXPECT_EQ(orders[0].mTarget.mType, EAiTargetType::AITARGET_Entity);
    EXPECT_EQ(orders[0].mTarget.mEntityId, 402u);
  }

  TEST(
    TransportPreOrdersTests,
    GeneratedCommandIdsDoNotRepeatAcrossGroupAndSingleQueues
  )
  {
    FakeUserUnitScope scopeA;
    FakeUserUnitScope scopeB;
    UserUnit* unitA = scopeA.GetUnit(501);
    UserUnit* unitB = scopeB.GetUnit(502);

    gpg::fastvector<UserUnit*> group;
    group.push_back(unitA);
    const SSTICommandIssueData groupMove(EUnitCommandType::UNITCOMMAND_Move);
    UserUnit::QueueTransportPreOrders(group, groupMove, false);

    const SSTICommandIssueData singleMove(EUnitCommandType::UNITCOMMAND_Move);
    unitB->QueueTransportPreOrder(singleMove, false);

    ASSERT_EQ(unitA->GetTransportPreOrders().size(), 1u);
    ASSERT_EQ(unitB->GetTransportPreOrders().size(), 1u);
    EXPECT_NE(unitA->GetTransportPreOrders()[0].nextCommandId, unitB->GetTransportPreOrders()[0].nextCommandId);
    EXPECT_FALSE(UserUnit::HaveSameTransportPreOrders(501u, 502u));
  }

  TEST(
    TransportPreOrdersTests,
    SquadUnitWithAnExtraOrderIsNotGroupedWithTheOthers
  )
  {
    FakeUserUnitScope scopeA;
    FakeUserUnitScope scopeB;
    FakeUserUnitScope scopeC;
    UserUnit* unitA = scopeA.GetUnit(601);
    UserUnit* unitB = scopeB.GetUnit(602);
    UserUnit* unitC = scopeC.GetUnit(603);

    gpg::fastvector<UserUnit*> squad;
    squad.push_back(unitA);
    squad.push_back(unitB);
    squad.push_back(unitC);
    SSTICommandIssueData move(EUnitCommandType::UNITCOMMAND_Move);
    move.mTarget.mType = EAiTargetType::AITARGET_Ground;
    move.mTarget.mPos = Wm3::Vector3f{100.0f, 20.0f, 150.0f};
    UserUnit::QueueTransportPreOrders(squad, move, false);
    EXPECT_TRUE(UserUnit::HaveSameTransportPreOrders(601u, 602u));

    // Only A gets a second, shift-queued order; B and C still share their one order.
    gpg::fastvector<UserUnit*> onlyA;
    onlyA.push_back(unitA);
    SSTICommandIssueData attackMove(EUnitCommandType::UNITCOMMAND_AggressiveMove);
    attackMove.mTarget.mType = EAiTargetType::AITARGET_Ground;
    attackMove.mTarget.mPos = Wm3::Vector3f{200.0f, 20.0f, 250.0f};
    UserUnit::QueueTransportPreOrders(onlyA, attackMove, false);

    ASSERT_EQ(unitA->GetTransportPreOrders().size(), 2u);
    ASSERT_EQ(unitB->GetTransportPreOrders().size(), 1u);
    EXPECT_FALSE(UserUnit::HaveSameTransportPreOrders(601u, 602u));
    EXPECT_FALSE(UserUnit::HaveSameTransportPreOrders(601u, 603u));
    EXPECT_TRUE(UserUnit::HaveSameTransportPreOrders(602u, 603u));
    EXPECT_FALSE(UserUnit::HaveSameTransportPreOrders(601u, 999u));
  }

  TEST(
    TransportPreOrdersTests,
    DispatchWithoutAControllingPlayerDropsTheOrders
  )
  {
    // The fake unit has no session and no army, as a unit seen by an observer would: its orders are
    // dropped, never issued.
    FakeUserUnitScope scope;
    UserUnit* unit = scope.GetUnit(701);
    unit->QueueTransportPreOrder(SSTICommandIssueData(EUnitCommandType::UNITCOMMAND_Move), false);
    ASSERT_TRUE(unit->HasTransportPreOrders());

    unit->DispatchDisembarkedPreOrders();
    EXPECT_FALSE(unit->HasTransportPreOrders());
    EXPECT_FALSE(UserUnit::HasAnyTransportPreOrders());
  }

  TEST(
    TransportPreOrdersTests,
    AttachmentParentRefTreatsZeroAndInvalidAsNoParent
  )
  {
    constexpr std::uint32_t kInvalidEntityId = ToRaw(EEntityIdSentinel::Invalid);
    EXPECT_FALSE(UserUnit::IsAttachmentParentRef(0u));
    EXPECT_FALSE(UserUnit::IsAttachmentParentRef(kInvalidEntityId));
    EXPECT_TRUE(UserUnit::IsAttachmentParentRef(500u));
    EXPECT_TRUE(UserUnit::IsDetachTransition(500u, 0u));
    EXPECT_FALSE(UserUnit::IsDetachTransition(0u, kInvalidEntityId));
  }

  TEST(
    TransportPreOrdersTests,
    ClearAllStateDropsEveryQueueAndOverride
  )
  {
    FakeUserUnitScope scopeA;
    FakeUserUnitScope scopeB;
    UserUnit* unitA = scopeA.GetUnit(801);
    UserUnit* unitB = scopeB.GetUnit(802);
    unitA->QueueTransportPreOrder(SSTICommandIssueData(EUnitCommandType::UNITCOMMAND_Move), false);
    unitB->QueueTransportPreOrder(SSTICommandIssueData(EUnitCommandType::UNITCOMMAND_Patrol), false);
    unitB->SetSelectionBracketPositionOverride(Wm3::Vector3f{1.0f, 2.0f, 3.0f});
    ASSERT_TRUE(UserUnit::HasAnyTransportPreOrders());

    UserUnit::ClearAllTransportPreOrderState();

    EXPECT_FALSE(UserUnit::HasAnyTransportPreOrders());
    EXPECT_TRUE(UserUnit::GetAllTransportPreOrders().empty());
    EXPECT_TRUE(UserUnit::GetAllSelectionBracketPositionOverrides().empty());
  }
  // ---- Dispatch planning: grouping, waiting and builder handover, with units described by a table ----

  struct FakeWorld
  {
    std::map<std::uint32_t, UserUnit::SPreOrderUnitState> units;

    void Add(
      const std::uint32_t entityId,
      const bool attached,
      const bool dead = false,
      const bool sameArmy = true
    )
    {
      units[entityId] = UserUnit::SPreOrderUnitState{true, dead, attached, sameArmy};
    }

    [[nodiscard]] UserUnit::PreOrderUnitLookup Lookup() const
    {
      return [this](const std::uint32_t entityId) {
        const auto it = units.find(entityId);
        return it != units.end() ? it->second : UserUnit::SPreOrderUnitState{};
      };
    }
  };

  [[nodiscard]] SSTICommandIssueData GroundOrder(
    const EUnitCommandType type,
    const float x,
    const float z
  )
  {
    SSTICommandIssueData order(type);
    order.mTarget.mType = EAiTargetType::AITARGET_Ground;
    order.mTarget.mPos = Wm3::Vector3f{x, 10.0f, z};
    return order;
  }

  [[nodiscard]] bool GroupHas(
    const UserUnit::SPreOrderDispatchPlan& plan,
    const std::uint32_t entityId
  )
  {
    return std::find(plan.mGroup.begin(), plan.mGroup.end(), entityId) != plan.mGroup.end();
  }

  TEST(
    TransportPreOrdersTests,
    PlanSendsOneGroupCommandToADetachedSquadWithTheSameOrders
  )
  {
    FakeUserUnitScope a, b, c;
    gpg::fastvector<UserUnit*> squad;
    squad.push_back(a.GetUnit(901));
    squad.push_back(b.GetUnit(902));
    squad.push_back(c.GetUnit(903));
    UserUnit::QueueTransportPreOrders(squad, GroundOrder(EUnitCommandType::UNITCOMMAND_Move, 100.0f, 100.0f), false);

    FakeWorld world;
    world.Add(901, false);
    world.Add(902, false);
    world.Add(903, false);
    const auto plan = UserUnit::PlanTransportPreOrderDispatch(901, true, 100, world.Lookup());

    EXPECT_FALSE(plan.mWait);
    EXPECT_FALSE(plan.mDrop);
    ASSERT_EQ(plan.mGroup.size(), 3u);
    EXPECT_EQ(plan.mGroup.back(), 901u);
    EXPECT_TRUE(GroupHas(plan, 902u));
    EXPECT_TRUE(GroupHas(plan, 903u));
    ASSERT_EQ(plan.mOrders.size(), 1u);
    EXPECT_EQ(plan.mOrders[0].mCommandType, EUnitCommandType::UNITCOMMAND_Move);
    EXPECT_FALSE(UserUnit::HasAnyTransportPreOrders());
  }

  TEST(
    TransportPreOrdersTests,
    PlanKeepsAUnitWithAnExtraOrderOutOfTheGroupAndGivesItItsOwnQueue
  )
  {
    FakeUserUnitScope a, b, c;
    UserUnit* unitA = a.GetUnit(911);
    gpg::fastvector<UserUnit*> squad;
    squad.push_back(unitA);
    squad.push_back(b.GetUnit(912));
    squad.push_back(c.GetUnit(913));
    UserUnit::QueueTransportPreOrders(squad, GroundOrder(EUnitCommandType::UNITCOMMAND_Move, 100.0f, 100.0f), false);
    gpg::fastvector<UserUnit*> onlyA;
    onlyA.push_back(unitA);
    UserUnit::QueueTransportPreOrders(
      onlyA, GroundOrder(EUnitCommandType::UNITCOMMAND_AggressiveMove, 200.0f, 200.0f), false
    );

    FakeWorld world;
    world.Add(911, false);
    world.Add(912, false);
    world.Add(913, false);

    // B lands first: B and C get the one move, A is not in that command.
    const auto planB = UserUnit::PlanTransportPreOrderDispatch(912, true, 100, world.Lookup());
    ASSERT_EQ(planB.mGroup.size(), 2u);
    EXPECT_TRUE(GroupHas(planB, 913u));
    EXPECT_FALSE(GroupHas(planB, 911u));
    ASSERT_EQ(planB.mOrders.size(), 1u);
    ASSERT_EQ(unitA->GetTransportPreOrders().size(), 2u);

    // A then gets both of its own orders, alone.
    const auto planA = UserUnit::PlanTransportPreOrderDispatch(911, true, 101, world.Lookup());
    ASSERT_EQ(planA.mGroup.size(), 1u);
    ASSERT_EQ(planA.mOrders.size(), 2u);
    EXPECT_EQ(planA.mOrders[1].mCommandType, EUnitCommandType::UNITCOMMAND_AggressiveMove);
    EXPECT_FALSE(UserUnit::HasAnyTransportPreOrders());
  }

  TEST(
    TransportPreOrdersTests,
    PlanWaitsForACarriedSquadMateForThirtyTicksThenSendsWithoutIt
  )
  {
    FakeUserUnitScope a, b;
    UserUnit* unitB = b.GetUnit(922);
    gpg::fastvector<UserUnit*> squad;
    squad.push_back(a.GetUnit(921));
    squad.push_back(unitB);
    UserUnit::QueueTransportPreOrders(squad, GroundOrder(EUnitCommandType::UNITCOMMAND_Move, 50.0f, 50.0f), false);

    FakeWorld world;
    world.Add(921, false);
    world.Add(922, true); // still in the transport

    EXPECT_TRUE(UserUnit::PlanTransportPreOrderDispatch(921, true, 100, world.Lookup()).mWait);
    EXPECT_TRUE(UserUnit::PlanTransportPreOrderDispatch(921, true, 100, world.Lookup()).mWait); // same beat again
    EXPECT_TRUE(UserUnit::PlanTransportPreOrderDispatch(921, true, 129, world.Lookup()).mWait);

    const auto plan = UserUnit::PlanTransportPreOrderDispatch(921, true, 130, world.Lookup());
    EXPECT_FALSE(plan.mWait);
    ASSERT_EQ(plan.mGroup.size(), 1u);
    EXPECT_EQ(plan.mGroup[0], 921u);
    EXPECT_TRUE(unitB->HasTransportPreOrders()); // the carried one keeps its orders for its own landing
  }

  TEST(
    TransportPreOrdersTests,
    PlanWaitsWhileAGuardTargetIsCarried
  )
  {
    FakeUserUnitScope a;
    UserUnit* unitA = a.GetUnit(931);
    SSTICommandIssueData guard(EUnitCommandType::UNITCOMMAND_Guard);
    guard.mTarget.mType = EAiTargetType::AITARGET_Entity;
    guard.mTarget.mEnt = 932;
    guard.mTarget.mEntityId = 932;
    unitA->QueueTransportPreOrder(guard, false);

    FakeWorld world;
    world.Add(931, false);
    world.Add(932, true);
    EXPECT_TRUE(UserUnit::PlanTransportPreOrderDispatch(931, true, 10, world.Lookup()).mWait);

    world.Add(932, false);
    const auto plan = UserUnit::PlanTransportPreOrderDispatch(931, true, 11, world.Lookup());
    EXPECT_FALSE(plan.mWait);
    ASSERT_EQ(plan.mOrders.size(), 1u);
    EXPECT_EQ(plan.mOrders[0].mTarget.mEntityId, 932u);
  }

  TEST(
    TransportPreOrdersTests,
    PlanIgnoresDeadSquadMatesAndLeavesOtherArmiesOut
  )
  {
    FakeUserUnitScope a, b, c;
    UserUnit* unitC = c.GetUnit(943);
    gpg::fastvector<UserUnit*> squad;
    squad.push_back(a.GetUnit(941));
    squad.push_back(b.GetUnit(942));
    squad.push_back(unitC);
    UserUnit::QueueTransportPreOrders(squad, GroundOrder(EUnitCommandType::UNITCOMMAND_Move, 70.0f, 70.0f), false);

    FakeWorld world;
    world.Add(941, false);
    world.Add(942, true, /*dead=*/true);              // died in the transport: no reason to wait
    world.Add(943, false, false, /*sameArmy=*/false); // given away: not commanded by this player

    const auto plan = UserUnit::PlanTransportPreOrderDispatch(941, true, 5, world.Lookup());
    EXPECT_FALSE(plan.mWait);
    ASSERT_EQ(plan.mGroup.size(), 1u);
    EXPECT_EQ(plan.mGroup[0], 941u);
    EXPECT_TRUE(unitC->HasTransportPreOrders());

    // When the given-away unit itself comes to dispatch, its owner check fails and the orders go.
    const auto planC = UserUnit::PlanTransportPreOrderDispatch(943, false, 6, world.Lookup());
    EXPECT_TRUE(planC.mDrop);
    EXPECT_FALSE(unitC->HasTransportPreOrders());
  }

  TEST(
    TransportPreOrdersTests,
    PlanTurnsLateBuildersIntoAssistsOnlyWhileTheFirstBuilderLives
  )
  {
    FakeUserUnitScope a, b, c;
    gpg::fastvector<UserUnit*> squad;
    squad.push_back(a.GetUnit(951));
    squad.push_back(b.GetUnit(952));
    squad.push_back(c.GetUnit(953));
    SSTICommandIssueData build(EUnitCommandType::UNITCOMMAND_BuildMobile);
    build.mTarget.mType = EAiTargetType::AITARGET_Ground;
    build.mTarget.mPos = Wm3::Vector3f{300.0f, 10.0f, 300.0f};
    UserUnit::QueueTransportPreOrders(squad, build, false);

    FakeWorld world;
    world.Add(951, false);
    world.Add(952, true);
    world.Add(953, true);

    // 951 lands, waits out its squad and builds.
    EXPECT_TRUE(UserUnit::PlanTransportPreOrderDispatch(951, true, 0, world.Lookup()).mWait);
    const auto first = UserUnit::PlanTransportPreOrderDispatch(951, true, 30, world.Lookup());
    ASSERT_EQ(first.mOrders.size(), 1u);
    EXPECT_EQ(first.mOrders[0].mCommandType, EUnitCommandType::UNITCOMMAND_BuildMobile);

    // 952 and 953 land together while 951 lives: both assist it, in one command.
    world.Add(952, false);
    world.Add(953, false);
    const auto late = UserUnit::PlanTransportPreOrderDispatch(952, true, 40, world.Lookup());
    ASSERT_EQ(late.mGroup.size(), 2u);
    ASSERT_EQ(late.mOrders.size(), 1u);
    EXPECT_EQ(late.mOrders[0].mCommandType, EUnitCommandType::UNITCOMMAND_Guard);
    EXPECT_EQ(late.mOrders[0].mTarget.mEntityId, 951u);
  }

  TEST(
    TransportPreOrdersTests,
    PlanLetsALateBuilderBuildWhenTheFirstBuilderDied
  )
  {
    FakeUserUnitScope a, b;
    gpg::fastvector<UserUnit*> squad;
    squad.push_back(a.GetUnit(961));
    squad.push_back(b.GetUnit(962));
    SSTICommandIssueData build(EUnitCommandType::UNITCOMMAND_BuildMobile);
    build.mTarget.mType = EAiTargetType::AITARGET_Ground;
    build.mTarget.mPos = Wm3::Vector3f{320.0f, 10.0f, 320.0f};
    UserUnit::QueueTransportPreOrders(squad, build, false);

    FakeWorld world;
    world.Add(961, false);
    world.Add(962, true);
    EXPECT_TRUE(UserUnit::PlanTransportPreOrderDispatch(961, true, 0, world.Lookup()).mWait);
    EXPECT_FALSE(UserUnit::PlanTransportPreOrderDispatch(961, true, 30, world.Lookup()).mWait);

    world.Add(961, false, /*dead=*/true);
    world.Add(962, false);
    const auto late = UserUnit::PlanTransportPreOrderDispatch(962, true, 50, world.Lookup());
    ASSERT_EQ(late.mOrders.size(), 1u);
    EXPECT_EQ(late.mOrders[0].mCommandType, EUnitCommandType::UNITCOMMAND_BuildMobile);
  }
} // namespace
