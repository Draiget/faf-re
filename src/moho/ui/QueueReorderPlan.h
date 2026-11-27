#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "moho/command/CmdDefs.h"

namespace moho::queue_reorder
{
  /**
   * Engine addition (`ui_QueueReorder`): plans a change to unit command queues as the two queue
   * edits the retail command stream already has, so nothing new reaches the sim:
   *
   * - a removal is `CMDST_RemoveCommandFromQueue` (one order off one unit's queue; the other units
   *   that share the order keep it), what retail's Shift+Ctrl+right-click on an order sends;
   * - an insert is one `CMDST_IssueCommand` carrying a copy of an order with `mIndex` set to the
   *   order it goes before. The retail sim inserts before the order with that id in each unit's
   *   queue (FUN_006F12C0 0x006F1411..0x006F1440); `kAppend` (top byte 0xFF) appends.
   *
   * The sim only drops what a unit is doing when the order it carries out leaves the front of its
   * queue: removing the head raises UCQS_NeedsRefresh, which interrupts the unit's command dispatch
   * (IAiCommandDispatchImpl::OnEvent, 0x00599030), while an insert raises UCQS_CommandInserted and a
   * removal further back UCQS_Changed, neither of which interrupts it. So an order that has to be
   * carried out now goes in front by taking the current order off and putting a copy of it back
   * behind (`Step` order below); a build copied that way finds its half-built structure again
   * (CUnitMobileBuildTask, 0x005F6C70).
   *
   * The planner is pure: it reads the order ids of each queue, head first, and returns the steps,
   * which are sent in order.
   */
  constexpr CmdId kAppend = -1;

  struct UnitQueue
  {
    std::int32_t mUnitId;
    std::vector<CmdId> mCommands; // head (the order being carried out) first
  };

  enum class EStepKind : std::uint8_t
  {
    Remove, // `mCommand` leaves the queues of `mUnitIds` (one removal per unit)
    Insert, // one new copy of `mCommand` goes before `mBefore` in the queues of `mUnitIds`
  };

  struct Step
  {
    EStepKind mKind;
    CmdId mCommand;
    CmdId mBefore; // Insert only: kAppend for the end of the queue
    std::vector<std::int32_t> mUnitIds;

    friend bool operator==(const Step&, const Step&) = default;
  };

  struct Plan
  {
    std::vector<Step> mSteps; // sent in this order

    [[nodiscard]] bool Empty() const noexcept
    {
      return mSteps.empty();
    }
  };

  /// Whether an order can be sent again as a copy (the client keeps all of its payload).
  using CanCopyFn = std::function<bool(CmdId)>;

  enum class EEarlierOrders : std::uint8_t
  {
    Keep, // the chosen order goes to the front; everything else stays in its order
    Drop, // the orders before the chosen one are removed from these units only
  };

  /**
   * "Do this one first" for `units`: each unit carries `chosen` out now. A unit that holds it
   * moves it to the front (EEarlierOrders::Keep) or drops the orders before it (Drop); a unit that
   * doesn't gets a copy in front, or as its only order when its queue is empty. A unit whose
   * current order already is `chosen` is left alone. When the current order can't be copied, the
   * chosen order goes right behind it instead: it comes next.
   */
  [[nodiscard]] Plan
  PlanTakeFirst(const std::vector<UnitQueue>& units, CmdId chosen, EEarlierOrders earlier, const CanCopyFn& canCopy);

  /**
   * Drag and drop in the queue: in every queue that holds both `moved` and `target`, `moved` takes
   * `target`'s place - after it when dragged forward (from earlier in the queue), before it when
   * dragged back. Dropped in front of the current order, it is carried out now, as with
   * PlanTakeFirst. Queues that lack either order are left alone.
   */
  [[nodiscard]] Plan
  PlanMoveToTarget(const std::vector<UnitQueue>& units, CmdId moved, CmdId target, const CanCopyFn& canCopy);
} // namespace moho::queue_reorder
