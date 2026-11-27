#pragma once

#include "moho/command/CmdDefs.h"

namespace moho
{
  class CScrLuaInitForm;
  class CWldSession;
  class UICommandGraph;
  struct GeomCamera3;

  /**
   * Engine addition: editing unit command queues from the game view, client side only.
   *
   * - Shift+Alt+right-click on a queued order: the selected units carry it out now. Units that
   *   hold the order move it to the front of their queue and keep the rest (or, with
   *   `ui_QueueTakeFirstKeepsRest 0`, drop the orders before it); selected builders that don't hold
   *   a queued build get a copy in front, and help with it when they arrive. The order they were
   *   carrying out goes right behind it (a building they leave half built is picked up again).
   * - Shift+drag an order node and hold Alt when dropping it on another node of the same queue:
   *   the order takes that node's place; dropped on the current order, it is carried out now.
   *
   * Both are sent as orders the retail command stream already has (per-unit
   * `CMDST_RemoveCommandFromQueue`, `CMDST_IssueCommand` with an insert-before id), so the sim,
   * replays and players on the retail executable see ordinary orders. Plans:
   * `moho/ui/QueueReorderPlan.h`.
   */
  extern bool ui_QueueReorder;
  extern bool ui_QueueTakeFirstKeepsRest;

  /// True when queue editing is on for this session (not a replay or an observer) and `commandId`
  /// is an order of the session's command graph - what a Shift+Alt+right-click on it acts on, so
  /// the click never falls back to retail's queued move when nothing can be done.
  bool QUEUE_IsQueueOrder(CWldSession& session, CmdId commandId);

  /// Shift+Alt+right-click on order `chosenId` for the current selection. False when nothing
  /// was sent (no session, an observer, an order that can't be copied, nothing would change).
  bool QUEUE_TakeCommandFirst(CWldSession& session, CmdId chosenId);

  /// Order `movedId` dropped on order `targetId`. False when nothing was sent.
  bool QUEUE_MoveCommandToTarget(CWldSession& session, CmdId movedId, CmdId targetId);

  /// A dragged order released with Alt held at screen point (`screenX`, `screenY`): when it lands
  /// on another order node of `graph`, reorders as `QUEUE_MoveCommandToTarget`. True when sent.
  bool QUEUE_DropCommandOnNode(
    CWldSession& session,
    const UICommandGraph& graph,
    const GeomCamera3& camera,
    float screenX,
    float screenY,
    CmdId movedId
  );

  /// UI Lua `QueueTakeFirst(commandId)` - `QUEUE_TakeCommandFirst` for the selection; true when sent.
  CScrLuaInitForm* func_QueueTakeFirst_LuaFuncDef();

  /// UI Lua `QueueMoveCommand(commandId, targetCommandId)` - `QUEUE_MoveCommandToTarget`; true when sent.
  CScrLuaInitForm* func_QueueMoveCommand_LuaFuncDef();
} // namespace moho
