#include "moho/ui/QueueReorderPlan.h"

#include <algorithm>
#include <cstddef>

namespace moho::queue_reorder
{
  namespace
  {
    [[nodiscard]] std::ptrdiff_t IndexOf(
      const std::vector<CmdId>& commands,
      const CmdId command
    ) noexcept
    {
      const auto it = std::find(commands.begin(), commands.end(), command);
      return it == commands.end() ? -1 : (it - commands.begin());
    }

    [[nodiscard]] CmdId At(
      const std::vector<CmdId>& commands,
      const std::size_t index
    ) noexcept
    {
      return index < commands.size() ? commands[index] : kAppend;
    }

    /**
     * The steps of a plan in four phases, sent in this order, so the units that need the same
     * step share it (an insert they share stays one order they share):
     *   1. removals of current orders (the interrupt that makes the units start the new head),
     *   2. inserts of the moved order's copy,
     *   3. inserts of the copies of the current orders taken off in 1,
     *   4. removals of the moved order where it was.
     * A removal is per unit anyway; an insert is one message for all its units.
     */
    struct PhasedPlan
    {
      std::vector<Step> mPhases[4];

      void Remove(
        const int phase,
        const CmdId command,
        const std::int32_t unitId
      )
      {
        mPhases[phase].push_back(Step{EStepKind::Remove, command, kAppend, {unitId}});
      }

      void Insert(
        const int phase,
        const CmdId command,
        const CmdId before,
        const std::int32_t unitId
      )
      {
        for (Step& step : mPhases[phase]) {
          if (step.mKind == EStepKind::Insert && step.mCommand == command && step.mBefore == before) {
            step.mUnitIds.push_back(unitId);
            return;
          }
        }
        mPhases[phase].push_back(Step{EStepKind::Insert, command, before, {unitId}});
      }

      [[nodiscard]] Plan Flatten() &&
      {
        Plan plan{};
        for (std::vector<Step>& phase : mPhases) {
          for (Step& step : phase) {
            plan.mSteps.push_back(std::move(step));
          }
        }
        return plan;
      }
    };

    constexpr int kTakeOffHead = 0;
    constexpr int kInsertMoved = 1;
    constexpr int kPutHeadBack = 2;
    constexpr int kRemoveMoved = 3;

    /**
     * `moved` (at `index` in `queue`, or not in it at all for -1) is carried out now: the current
     * order comes off, the moved order (or its copy) is the new head, and the current order's copy
     * goes right behind it. When the current order can't be copied, the moved order only goes
     * right behind it.
     */
    void BringToFront(
      PhasedPlan& plan,
      const UnitQueue& unit,
      const CmdId moved,
      const std::ptrdiff_t index,
      const CanCopyFn& canCopy
    )
    {
      const std::vector<CmdId>& queue = unit.mCommands;
      const CmdId head = queue.front();
      const std::int32_t id = unit.mUnitId;

      if (!canCopy(head)) {
        if (index == 1) {
          return; // already next
        }
        plan.Insert(kInsertMoved, moved, At(queue, 1), id);
        if (index > 0) {
          plan.Remove(kRemoveMoved, moved, id);
        }
        return;
      }

      plan.Remove(kTakeOffHead, head, id);
      if (index == 1) {
        // Taking the head off already makes the moved order the head.
        plan.Insert(kPutHeadBack, head, At(queue, 2), id);
        return;
      }
      const CmdId next = At(queue, 1);
      plan.Insert(kInsertMoved, moved, next, id);
      plan.Insert(kPutHeadBack, head, next, id);
      if (index > 1) {
        plan.Remove(kRemoveMoved, moved, id);
      }
    }
  } // namespace

  Plan PlanTakeFirst(
    const std::vector<UnitQueue>& units,
    const CmdId chosen,
    const EEarlierOrders earlier,
    const CanCopyFn& canCopy
  )
  {
    PhasedPlan plan{};
    for (const UnitQueue& unit : units) {
      if (unit.mCommands.empty()) {
        plan.Insert(kInsertMoved, chosen, kAppend, unit.mUnitId);
        continue;
      }

      const std::ptrdiff_t index = IndexOf(unit.mCommands, chosen);
      if (index == 0) {
        continue;
      }

      if (index > 0 && earlier == EEarlierOrders::Drop) {
        for (std::ptrdiff_t i = 0; i < index; ++i) {
          plan.Remove(kTakeOffHead, unit.mCommands[static_cast<std::size_t>(i)], unit.mUnitId);
        }
        continue;
      }

      BringToFront(plan, unit, chosen, index, canCopy);
    }
    return std::move(plan).Flatten();
  }

  Plan PlanMoveToTarget(
    const std::vector<UnitQueue>& units,
    const CmdId moved,
    const CmdId target,
    const CanCopyFn& canCopy
  )
  {
    PhasedPlan plan{};
    if (moved == target) {
      return std::move(plan).Flatten();
    }

    for (const UnitQueue& unit : units) {
      const std::ptrdiff_t from = IndexOf(unit.mCommands, moved);
      const std::ptrdiff_t to = IndexOf(unit.mCommands, target);
      if (from < 0 || to < 0) {
        continue;
      }

      if (to == 0 && from > 0) {
        BringToFront(plan, unit, moved, from, canCopy);
        continue;
      }

      const CmdId before = from < to ? At(unit.mCommands, static_cast<std::size_t>(to) + 1u) : target;
      plan.Insert(kInsertMoved, moved, before, unit.mUnitId);
      plan.Remove(kRemoveMoved, moved, unit.mUnitId);
    }
    return std::move(plan).Flatten();
  }
} // namespace moho::queue_reorder
