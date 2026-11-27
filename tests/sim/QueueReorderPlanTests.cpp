#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <vector>

#include "moho/ui/QueueReorderPlan.h"

namespace
{
  using namespace moho;
  using namespace moho::queue_reorder;

  /// One unit after a plan: its queue, and the order its command dispatch carries out.
  struct UnitAfter
  {
    std::vector<CmdId> mQueue;
    CmdId mRunning;
  };

  /**
   * Applies a plan the way the retail sim does. A removal takes one order off one unit
   * (`Sim::RemoveCommandFromUnitQueue`, 0x00749970); an insert adds one new order to its units
   * before `mBefore`, or at the end for `kAppend`, and leaves a unit alone whose queue lacks
   * `mBefore` (`IssueCommandToSelectedUnits`, 0x006F12C0). Each insert takes the next id from
   * `nextId`, as each `CMDST_IssueCommand` carries a fresh command id. The unit's dispatch keeps
   * carrying out its order unless the head is removed (UCQS_NeedsRefresh interrupts it,
   * IAiCommandDispatchImpl::OnEvent 0x00599030); then it starts whatever is the head after the
   * beat's commands. `copies` gets the id each insert gave its copy, by the order copied.
   */
  std::map<std::int32_t, UnitAfter> Apply(
    const std::vector<UnitQueue>& units,
    const Plan& plan,
    CmdId nextId,
    std::map<CmdId, CmdId>* const copies = nullptr
  )
  {
    std::map<std::int32_t, std::vector<CmdId>> queues;
    std::map<std::int32_t, CmdId> running;
    std::set<std::int32_t> interrupted;
    for (const UnitQueue& unit : units) {
      queues[unit.mUnitId] = unit.mCommands;
      running[unit.mUnitId] = unit.mCommands.empty() ? kAppend : unit.mCommands.front();
    }
    for (const Step& step : plan.mSteps) {
      if (step.mKind == EStepKind::Remove) {
        for (const std::int32_t unitId : step.mUnitIds) {
          auto& queue = queues[unitId];
          const auto at = std::find(queue.begin(), queue.end(), step.mCommand);
          if (at == queue.end()) {
            continue;
          }
          if (at == queue.begin()) {
            interrupted.insert(unitId);
          }
          queue.erase(at);
        }
        continue;
      }
      const CmdId id = nextId++;
      if (copies != nullptr) {
        (*copies)[step.mCommand] = id;
      }
      for (const std::int32_t unitId : step.mUnitIds) {
        auto& queue = queues[unitId];
        if (step.mBefore == kAppend) {
          queue.push_back(id);
          continue;
        }
        const auto at = std::find(queue.begin(), queue.end(), step.mBefore);
        if (at != queue.end()) {
          queue.insert(at, id);
        }
      }
    }
    std::map<std::int32_t, UnitAfter> after;
    for (auto& [unitId, queue] : queues) {
      const bool idle = running[unitId] == kAppend;
      const CmdId now =
        (interrupted.contains(unitId) || idle) ? (queue.empty() ? kAppend : queue.front()) : running[unitId];
      after[unitId] = UnitAfter{queue, now};
    }
    return after;
  }

  const CanCopyFn kAllCopy = [](CmdId) {
    return true;
  };
  constexpr CmdId kNew = 100; // id of the first copy a plan issues in `Apply`

  Step Remove(
    const CmdId command,
    const std::int32_t unitId
  )
  {
    return Step{EStepKind::Remove, command, kAppend, {unitId}};
  }

  Step Insert(
    const CmdId command,
    const CmdId before,
    std::vector<std::int32_t> units
  )
  {
    return Step{EStepKind::Insert, command, before, std::move(units)};
  }

  TEST(
    QueueReorderPlanTests,
    TakeFirstCarriesTheOrderOutNowAndKeepsTheRest
  )
  {
    // Engineers 1 and 2 of a group that shares orders 11..15 do order 14 first.
    const std::vector<UnitQueue> selected{{1, {11, 12, 13, 14, 15}}, {2, {11, 12, 13, 14, 15}}};
    const Plan plan = PlanTakeFirst(selected, 14, EEarlierOrders::Keep, kAllCopy);

    EXPECT_EQ(
      plan.mSteps,
      (std::vector<Step>{
        Remove(11, 1),
        Remove(11, 2),          // the current order comes off: the interrupt
        Insert(14, 12, {1, 2}), // the chosen order's copy, one order both share
        Insert(11, 12, {1, 2}), // the current order's copy, right behind it
        Remove(14, 1),
        Remove(14, 2), // the chosen order where it was
      })
    );

    std::map<CmdId, CmdId> copies;
    const auto after = Apply(selected, plan, kNew, &copies);
    for (const std::int32_t unit : {1, 2}) {
      EXPECT_EQ(after.at(unit).mQueue, (std::vector<CmdId>{copies[14], copies[11], 12, 13, 15}));
      EXPECT_EQ(after.at(unit).mRunning, copies[14]) << "the unit starts the chosen order now";
    }
  }

  TEST(
    QueueReorderPlanTests,
    TakeFirstOfTheNextOrderOnlyTakesTheCurrentOneOff
  )
  {
    const std::vector<UnitQueue> selected{{1, {11, 14, 15}}};
    const Plan plan = PlanTakeFirst(selected, 14, EEarlierOrders::Keep, kAllCopy);

    EXPECT_EQ(plan.mSteps, (std::vector<Step>{Remove(11, 1), Insert(11, 15, {1})}));
    const auto after = Apply(selected, plan, kNew);
    EXPECT_EQ(after.at(1).mQueue, (std::vector<CmdId>{14, kNew, 15}));
    EXPECT_EQ(after.at(1).mRunning, 14);
  }

  TEST(
    QueueReorderPlanTests,
    TakeFirstCanDropTheEarlierOrders
  )
  {
    const std::vector<UnitQueue> selected{{1, {11, 12, 13, 14, 15}}};
    const Plan plan = PlanTakeFirst(selected, 14, EEarlierOrders::Drop, kAllCopy);

    EXPECT_EQ(plan.mSteps, (std::vector<Step>{Remove(11, 1), Remove(12, 1), Remove(13, 1)}));
    const auto after = Apply(selected, plan, kNew);
    EXPECT_EQ(after.at(1).mQueue, (std::vector<CmdId>{14, 15}));
    EXPECT_EQ(after.at(1).mRunning, 14);
  }

  TEST(
    QueueReorderPlanTests,
    TakeFirstLeavesAUnitAlreadyOnTheOrder
  )
  {
    const std::vector<UnitQueue> selected{{1, {14, 15}}};
    EXPECT_TRUE(PlanTakeFirst(selected, 14, EEarlierOrders::Keep, kAllCopy).Empty());
    EXPECT_TRUE(PlanTakeFirst(selected, 14, EEarlierOrders::Drop, kAllCopy).Empty());
  }

  TEST(
    QueueReorderPlanTests,
    TakeFirstGivesIdleAndBusyHelpersACopy
  )
  {
    // 3 is idle, 4 is busy with its own orders 21 and 22, neither holds order 14.
    const std::vector<UnitQueue> selected{{3, {}}, {4, {21, 22}}};
    const Plan plan = PlanTakeFirst(selected, 14, EEarlierOrders::Drop, kAllCopy);

    std::map<CmdId, CmdId> copies;
    const auto after = Apply(selected, plan, kNew, &copies);
    EXPECT_EQ(after.at(3).mQueue, (std::vector<CmdId>{kNew}));
    EXPECT_EQ(after.at(3).mRunning, kNew);
    EXPECT_EQ(after.at(4).mQueue, (std::vector<CmdId>{kNew + 1, copies[21], 22}));
    EXPECT_EQ(after.at(4).mRunning, kNew + 1);
  }

  TEST(
    QueueReorderPlanTests,
    TakeFirstBehindAnOrderThatCantBeCopied
  )
  {
    // Order 11 (a patrol, say) can't be sent again: the chosen order comes right after it.
    const CanCopyFn notEleven = [](const CmdId id) {
      return id != 11;
    };
    const std::vector<UnitQueue> selected{{1, {11, 12, 14}}, {2, {11, 14, 15}}};
    const Plan plan = PlanTakeFirst(selected, 14, EEarlierOrders::Keep, notEleven);

    EXPECT_EQ(plan.mSteps, (std::vector<Step>{Insert(14, 12, {1}), Remove(14, 1)})) << "unit 2 already has it next";
    const auto after = Apply(selected, plan, kNew);
    EXPECT_EQ(after.at(1).mQueue, (std::vector<CmdId>{11, kNew, 12}));
    EXPECT_EQ(after.at(1).mRunning, 11);
  }

  TEST(
    QueueReorderPlanTests,
    TakeFirstGroupsUnitsByTheirCurrentOrder
  )
  {
    const std::vector<UnitQueue> selected{{1, {11, 13, 14}}, {2, {12, 13, 14}}, {3, {11, 13, 14}}};
    const Plan plan = PlanTakeFirst(selected, 14, EEarlierOrders::Keep, kAllCopy);

    std::vector<Step> inserts;
    for (const Step& step : plan.mSteps) {
      if (step.mKind == EStepKind::Insert) {
        inserts.push_back(step);
      }
    }
    EXPECT_EQ(inserts, (std::vector<Step>{Insert(14, 13, {1, 2, 3}), Insert(11, 13, {1, 3}), Insert(12, 13, {2})}));
  }

  TEST(
    QueueReorderPlanTests,
    DragForwardPlacesTheOrderAfterTheTarget
  )
  {
    const std::vector<UnitQueue> units{{1, {11, 12, 13, 14}}, {2, {11, 12, 13, 14}}};
    const Plan plan = PlanMoveToTarget(units, 12, 13, kAllCopy);

    EXPECT_EQ(plan.mSteps, (std::vector<Step>{Insert(12, 14, {1, 2}), Remove(12, 1), Remove(12, 2)}));
    const auto after = Apply(units, plan, kNew);
    EXPECT_EQ(after.at(1).mQueue, (std::vector<CmdId>{11, 13, kNew, 14}));
    EXPECT_EQ(after.at(1).mRunning, 11) << "a move behind the current order doesn't interrupt it";
  }

  TEST(
    QueueReorderPlanTests,
    DragBackPlacesTheOrderBeforeTheTarget
  )
  {
    const std::vector<UnitQueue> units{{1, {11, 12, 13, 14}}};
    const auto after = Apply(units, PlanMoveToTarget(units, 14, 12, kAllCopy), kNew);
    EXPECT_EQ(after.at(1).mQueue, (std::vector<CmdId>{11, kNew, 12, 13}));
    EXPECT_EQ(after.at(1).mRunning, 11);
  }

  TEST(
    QueueReorderPlanTests,
    DragOntoTheCurrentOrderCarriesItOutNow
  )
  {
    const std::vector<UnitQueue> units{{1, {11, 12, 13}}};
    std::map<CmdId, CmdId> copies;
    const auto after = Apply(units, PlanMoveToTarget(units, 13, 11, kAllCopy), kNew, &copies);
    EXPECT_EQ(after.at(1).mQueue, (std::vector<CmdId>{copies[13], copies[11], 12}));
    EXPECT_EQ(after.at(1).mRunning, copies[13]);
  }

  TEST(
    QueueReorderPlanTests,
    DragTheCurrentOrderBackStartsTheNextOne
  )
  {
    const std::vector<UnitQueue> units{{1, {11, 12, 13}}};
    const Plan plan = PlanMoveToTarget(units, 11, 13, kAllCopy);

    EXPECT_EQ(plan.mSteps, (std::vector<Step>{Insert(11, kAppend, {1}), Remove(11, 1)}));
    const auto after = Apply(units, plan, kNew);
    EXPECT_EQ(after.at(1).mQueue, (std::vector<CmdId>{12, 13, kNew}));
    EXPECT_EQ(after.at(1).mRunning, 12);
  }

  TEST(
    QueueReorderPlanTests,
    DragOntoTheNeighbourSwapsThem
  )
  {
    const std::vector<UnitQueue> units{{1, {11, 12, 13, 14}}};
    EXPECT_EQ(
      Apply(units, PlanMoveToTarget(units, 12, 13, kAllCopy), kNew).at(1).mQueue, (std::vector<CmdId>{11, 13, kNew, 14})
    );
    EXPECT_EQ(
      Apply(units, PlanMoveToTarget(units, 13, 12, kAllCopy), kNew).at(1).mQueue, (std::vector<CmdId>{11, kNew, 12, 14})
    );
  }

  TEST(
    QueueReorderPlanTests,
    DragLeavesQueuesWithoutBothOrders
  )
  {
    // Unit 2 shares the dragged order 12 but not the target 13.
    const std::vector<UnitQueue> units{{1, {11, 12, 13}}, {2, {11, 12, 20}}};
    const auto after = Apply(units, PlanMoveToTarget(units, 12, 13, kAllCopy), kNew);
    EXPECT_EQ(after.at(1).mQueue, (std::vector<CmdId>{11, 13, kNew}));
    EXPECT_EQ(after.at(2).mQueue, (std::vector<CmdId>{11, 12, 20}));
  }

  TEST(
    QueueReorderPlanTests,
    DragUnitsWithDifferentNextOrdersGetOneCopyEach
  )
  {
    const std::vector<UnitQueue> units{{1, {10, 11, 13, 14}}, {2, {10, 11, 13, 15}}};
    const Plan plan = PlanMoveToTarget(units, 11, 13, kAllCopy);
    EXPECT_EQ(plan.mSteps[0], Insert(11, 14, {1}));
    EXPECT_EQ(plan.mSteps[1], Insert(11, 15, {2}));
  }

  TEST(
    QueueReorderPlanTests,
    DropOnItselfDoesNothing
  )
  {
    const std::vector<UnitQueue> units{{1, {11, 12}}};
    EXPECT_TRUE(PlanMoveToTarget(units, 12, 12, kAllCopy).Empty());
  }
} // namespace
