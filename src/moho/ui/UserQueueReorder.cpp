#include "moho/ui/UserQueueReorder.h"

#include <algorithm>
#include <cstddef>
#include <utility>
#include <vector>

#include "moho/ui/QueueReorderPlan.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CWldSessionPrivate.h"

namespace moho
{
  bool ui_QueueReorder = true;
  bool ui_QueueTakeFirstKeepsRest = true;

  namespace
  {
    /**
     * Order types whose whole payload the client keeps in the order's helper, so a copy is the
     * same order: the type, both targets, the cells, the blueprint and the counts. Left out: orders
     * that carry a Lua payload (`Script`), patrols (the sim chains new patrol legs onto the running
     * patrol, `CUnitCommandQueue::AddCommandToQueue`), formation orders (their shape comes from the
     * whole group; see also BuildOrderCopy), transport and factory orders.
     */
    [[nodiscard]] bool CanCopyOrderType(
      const EUnitCommandType type
    ) noexcept
    {
      switch (type) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
      case EUnitCommandType::UNITCOMMAND_BuildMobile:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_Guard:
      case EUnitCommandType::UNITCOMMAND_Reclaim:
      case EUnitCommandType::UNITCOMMAND_Repair:
      case EUnitCommandType::UNITCOMMAND_Capture:
        return true;
      default:
        return false;
      }
    }

    /// A local edit the sim hasn't confirmed yet that leaves the replicated payload stale (a drag
    /// just released, a type change) or the order on its way out (a delete). Unit and count-up
    /// edits leave the payload as it is.
    [[nodiscard]] bool HasPendingPayloadEdit(
      UserCommandIssueHelper& helper
    )
    {
      for (const UserCommandIssueLocalEvent& event : helper.mLocalQueue) { // fa::deque: no const begin()
        if (
          event.mType == ECommandIssueEvent::SetTarget || event.mType == ECommandIssueEvent::SetCommandType ||
          event.mType == ECommandIssueEvent::DecreaseCount
        ) {
          return true;
        }
      }
      return false;
    }

    /**
     * Rebuilds the issue payload of `helper`'s order - the inverse of what `ISSUE_Command`
     * publishes from a payload (`InitializePublishedCommandDescriptorFromIssueData`,
     * `SSTICommandVariableData(const SSTICommandIssueData&)`). Refused while a payload edit is
     * still waiting for the sim (`HasPendingPayloadEdit`).
     */
    [[nodiscard]] bool BuildOrderCopy(
      UserCommandIssueHelper& helper,
      SSTICommandIssueData& out
    )
    {
      const EUnitCommandType type = ResolveCommandIssueHelperCommandType(helper);
      // A group order laid out in a formation (the drag formation's script index, heading and
      // spacing; CWldSessionCommands.cpp ApplyFormationLanes) would lay its copy out for whichever
      // units get it, so their spots would change: those orders stay where they are. A one-unit
      // order carries the lanes too (index 0 for a single unit's move) and has no layout to change.
      const bool inFormation =
        helper.mConstantData.mFormationScriptIndex != -1 && ResolveCommandIssueCursorEntities(helper)->Size() > 1;
      const bool pendingEdit = HasPendingPayloadEdit(helper);
      if (!CanCopyOrderType(type) || pendingEdit || inFormation) {
        gpg::Logf(
          "[QueueReorder] cmd=0x%08x stays: type %d, formation %d, pending edit %d",
          static_cast<std::uint32_t>(helper.mConstantData.cmd),
          static_cast<int>(type),
          static_cast<int>(helper.mConstantData.mFormationScriptIndex),
          pendingEdit ? 1 : 0
        );
        return false;
      }

      const REntityBlueprint* const blueprint = helper.mConstantData.blueprint;
      RUnitBlueprint* const unitBlueprint =
        blueprint != nullptr ? const_cast<RUnitBlueprint*>(blueprint->IsUnitBlueprint()) : nullptr;
      if (type == EUnitCommandType::UNITCOMMAND_BuildMobile && unitBlueprint == nullptr) {
        return false;
      }

      SSTICommandIssueData data(type);
      data.mTarget = helper.mVariableData.mTarget1;
      data.mTarget2 = helper.mVariableData.mTarget2;
      data.unk38 = helper.mConstantData.mFormationScriptIndex;
      data.mOri = helper.mConstantData.origin;
      data.unk4C = helper.mConstantData.unk1;
      data.mBlueprint = unitBlueprint;
      for (std::size_t i = 0; i < helper.mVariableData.mCells.size(); ++i) {
        data.mCells.push_back(helper.mVariableData.mCells[i]);
      }
      data.unk70 = helper.mVariableData.mMaxCount;
      data.unk74 = helper.mVariableData.mCount;
      out = data;
      return true;
    }

    [[nodiscard]] UserCommandIssueHelper* FindHelper(
      CWldSession& session,
      const CmdId commandId
    )
    {
      if (session.mCommandManager == nullptr) {
        return nullptr;
      }
      const auto found = session.mCommandManager->mCommands.find(commandId);
      return found == session.mCommandManager->mCommands.end() ? nullptr : found->second;
    }

    [[nodiscard]] UserUnit* FindUnit(
      CWldSession& session,
      const std::int32_t unitId
    )
    {
      UserEntity* const entity = session.LookupEntityId(static_cast<EntId>(unitId));
      return entity != nullptr ? entity->IsUserUnit() : nullptr;
    }

    /// The unit's queue as the client shows it (pending local edits included), head first.
    [[nodiscard]] queue_reorder::UnitQueue ReadQueue(
      UserUnit& unit
    )
    {
      queue_reorder::UnitQueue queue{static_cast<std::int32_t>(unit.mParams.mEntityId), {}};
      if (auto* const links = GetUserUnitManagerQueueLinks(unit.GetCommandQueue()); links != nullptr) {
        for (const WeakPtr<UserCommandIssueHelper>& link : *links) {
          if (const UserCommandIssueHelper* const helper = link.GetObjectPtr(); helper != nullptr) {
            queue.mCommands.push_back(static_cast<CmdId>(helper->mConstantData.cmd));
          }
        }
      }
      return queue;
    }

    [[nodiscard]] bool CanEditQueues(
      const CWldSession& session
    )
    {
      return ui_QueueReorder && !session.IsReplay && !session.IsObserver();
    }

    /// Whether an order can be sent again as a copy now (see BuildOrderCopy).
    [[nodiscard]] queue_reorder::CanCopyFn CanCopyIn(
      CWldSession& session
    )
    {
      return [&session](const CmdId commandId) {
        UserCommandIssueHelper* const helper = FindHelper(session, commandId);
        SSTICommandIssueData unused(EUnitCommandType::UNITCOMMAND_None);
        return helper != nullptr && BuildOrderCopy(*helper, unused);
      };
    }

    /**
     * Sends the plan's steps in order: a removal per unit, an insert as one order with its
     * insert-before id. Every copy is built first; when one can't be, nothing is sent.
     */
    [[nodiscard]] bool SendPlan(
      CWldSession& session,
      const queue_reorder::Plan& plan
    )
    {
      std::vector<std::pair<CmdId, SSTICommandIssueData>> copies{};
      for (const queue_reorder::Step& step : plan.mSteps) {
        if (step.mKind != queue_reorder::EStepKind::Insert) {
          continue;
        }
        bool have = false;
        for (const auto& entry : copies) {
          have = have || entry.first == step.mCommand;
        }
        if (have) {
          continue;
        }
        UserCommandIssueHelper* const helper = FindHelper(session, step.mCommand);
        SSTICommandIssueData copy(EUnitCommandType::UNITCOMMAND_None);
        if (helper == nullptr || !BuildOrderCopy(*helper, copy)) {
          return false;
        }
        copies.emplace_back(step.mCommand, copy);
      }

      for (const queue_reorder::Step& step : plan.mSteps) {
        if (step.mKind == queue_reorder::EStepKind::Remove) {
          UserCommandIssueHelper* const helper = FindHelper(session, step.mCommand);
          for (const std::int32_t unitId : step.mUnitIds) {
            UserUnit* const unit = FindUnit(session, unitId);
            if (helper != nullptr && unit != nullptr) {
              ISSUE_RemoveCommandFromUnitQueue(helper, unit);
            }
          }
          continue;
        }

        gpg::fastvector<UserUnit*> units{};
        for (const std::int32_t unitId : step.mUnitIds) {
          if (UserUnit* const unit = FindUnit(session, unitId); unit != nullptr) {
            units.push_back(unit);
          }
        }
        if (units.empty()) {
          continue;
        }
        for (const auto& [source, copy] : copies) {
          if (source == step.mCommand) {
            SSTICommandIssueData data = copy;
            data.mIndex = step.mBefore;
            ISSUE_Command(units, data, false, false); // not a new order: no OnCommandIssued
            break;
          }
        }
      }
      return true;
    }

    [[nodiscard]] std::size_t CountSteps(
      const queue_reorder::Plan& plan,
      const queue_reorder::EStepKind kind
    ) noexcept
    {
      std::size_t count = 0;
      for (const queue_reorder::Step& step : plan.mSteps) {
        if (step.mKind == kind) {
          count += step.mKind == queue_reorder::EStepKind::Remove ? step.mUnitIds.size() : 1u;
        }
      }
      return count;
    }

    /// A selected unit that doesn't hold a queued build joins it only when it can build it.
    [[nodiscard]] bool CanJoinBuild(
      const UserUnit& unit,
      const SSTICommandIssueData& orderCopy
    )
    {
      if (orderCopy.mCommandType != EUnitCommandType::UNITCOMMAND_BuildMobile || orderCopy.mBlueprint == nullptr) {
        return false;
      }
      if (unit.IsBeingBuilt()) {
        return false;
      }
      const RUnitBlueprint* const builder = unit.GetBlueprint();
      return builder != nullptr && EntityCategory::HasBlueprint(orderCopy.mBlueprint, &builder->Economy.CategoryCache);
    }
  } // namespace

  bool QUEUE_IsQueueOrder(
    CWldSession& session,
    const CmdId commandId
  )
  {
    return CanEditQueues(session) && FindHelper(session, commandId) != nullptr;
  }

  bool QUEUE_TakeCommandFirst(
    CWldSession& session,
    const CmdId chosenId
  )
  {
    if (!CanEditQueues(session)) {
      return false;
    }
    UserCommandIssueHelper* const chosen = FindHelper(session, chosenId);
    if (chosen == nullptr) {
      return false;
    }

    SSTICommandIssueData orderCopy(EUnitCommandType::UNITCOMMAND_None);
    const bool haveCopy = BuildOrderCopy(*chosen, orderCopy);

    fa::vector<UserUnit*> selection{};
    session.GetSelectionUnits(selection);

    std::vector<queue_reorder::UnitQueue> queues{};
    for (UserUnit* const unit : selection) {
      if (unit == nullptr) {
        continue;
      }
      queue_reorder::UnitQueue queue = ReadQueue(*unit);
      const bool holds = std::find(queue.mCommands.begin(), queue.mCommands.end(), chosenId) != queue.mCommands.end();
      if (holds || (haveCopy && CanJoinBuild(*unit, orderCopy))) {
        queues.push_back(std::move(queue));
      }
    }

    const queue_reorder::EEarlierOrders earlier =
      ui_QueueTakeFirstKeepsRest ? queue_reorder::EEarlierOrders::Keep : queue_reorder::EEarlierOrders::Drop;
    const queue_reorder::Plan plan = queue_reorder::PlanTakeFirst(queues, chosenId, earlier, CanCopyIn(session));
    if (plan.Empty() || !SendPlan(session, plan)) {
      return false;
    }

    gpg::Logf(
      "[QueueReorder] take first cmd=0x%08x (%s): %zu removal(s), %zu insert(s)",
      static_cast<std::uint32_t>(chosenId),
      earlier == queue_reorder::EEarlierOrders::Keep ? "keep rest" : "drop earlier",
      CountSteps(plan, queue_reorder::EStepKind::Remove),
      CountSteps(plan, queue_reorder::EStepKind::Insert)
    );
    session.DirtyCommandGraph();
    return true;
  }

  bool QUEUE_MoveCommandToTarget(
    CWldSession& session,
    const CmdId movedId,
    const CmdId targetId
  )
  {
    if (!CanEditQueues(session) || movedId == targetId) {
      return false;
    }
    UserCommandIssueHelper* const moved = FindHelper(session, movedId);
    if (moved == nullptr || FindHelper(session, targetId) == nullptr) {
      return false;
    }

    std::vector<queue_reorder::UnitQueue> queues{};
    for (UserUnit* const unit : *ResolveCommandIssueCursorEntities(*moved)) {
      if (unit != nullptr) {
        queues.push_back(ReadQueue(*unit));
      }
    }

    const queue_reorder::Plan plan = queue_reorder::PlanMoveToTarget(queues, movedId, targetId, CanCopyIn(session));
    if (plan.Empty() || !SendPlan(session, plan)) {
      return false;
    }

    gpg::Logf(
      "[QueueReorder] move cmd=0x%08x to cmd=0x%08x: %zu removal(s), %zu insert(s)",
      static_cast<std::uint32_t>(movedId),
      static_cast<std::uint32_t>(targetId),
      CountSteps(plan, queue_reorder::EStepKind::Remove),
      CountSteps(plan, queue_reorder::EStepKind::Insert)
    );
    session.DirtyCommandGraph();
    return true;
  }

  bool QUEUE_DropCommandOnNode(
    CWldSession& session,
    const UICommandGraph& graph,
    const GeomCamera3& camera,
    const float screenX,
    const float screenY,
    const CmdId movedId
  )
  {
    if (!CanEditQueues(session)) {
      return false;
    }
    const CmdId targetId = graph.ResolveDropTargetCommandId(camera, Wm3::Vector2f{screenX, screenY}, movedId);
    return targetId != -1 && QUEUE_MoveCommandToTarget(session, movedId, targetId);
  }

  namespace
  {
    constexpr const char* kQueueTakeFirstHelpText = "QueueTakeFirst(commandId)";
    constexpr const char* kQueueMoveCommandHelpText = "QueueMoveCommand(commandId, targetCommandId)";

    [[nodiscard]] CmdId ReadCommandIdArg(
      LuaPlus::LuaState* const state,
      const int stackIndex
    )
    {
      LuaPlus::LuaStackObject arg(state, stackIndex);
      if (lua_type(state->m_state, stackIndex) != LUA_TNUMBER) {
        LuaPlus::LuaStackObject::TypeError(&arg, "integer");
      }
      // UI Lua numbers are floats; command ids are exact in them up to 2^24 per source byte,
      // the same read `DeleteCommand` does.
      const auto truncated = static_cast<std::int64_t>(lua_tonumber(state->m_state, stackIndex));
      return static_cast<CmdId>(static_cast<std::uint32_t>(truncated));
    }

    int cfunc_QueueTakeFirstL(
      LuaPlus::LuaState* const state
    )
    {
      SCR_ExpectExactArgs(state, 1, kQueueTakeFirstHelpText);
      const CmdId commandId = ReadCommandIdArg(state, 1);
      CWldSession* const session = WLD_GetActiveSession();
      const bool sent = session != nullptr && QUEUE_TakeCommandFirst(*session, commandId);
      lua_pushboolean(state->m_state, sent ? 1 : 0);
      return 1;
    }

    int cfunc_QueueTakeFirst(
      lua_State* const luaContext
    )
    {
      return cfunc_QueueTakeFirstL(SCR_ResolveBindingState(luaContext));
    }

    int cfunc_QueueMoveCommandL(
      LuaPlus::LuaState* const state
    )
    {
      SCR_ExpectExactArgs(state, 2, kQueueMoveCommandHelpText);
      const CmdId movedId = ReadCommandIdArg(state, 1);
      const CmdId targetId = ReadCommandIdArg(state, 2);
      CWldSession* const session = WLD_GetActiveSession();
      const bool sent = session != nullptr && QUEUE_MoveCommandToTarget(*session, movedId, targetId);
      lua_pushboolean(state->m_state, sent ? 1 : 0);
      return 1;
    }

    int cfunc_QueueMoveCommand(
      lua_State* const luaContext
    )
    {
      return cfunc_QueueMoveCommandL(SCR_ResolveBindingState(luaContext));
    }
  } // namespace

  CScrLuaInitForm* func_QueueTakeFirst_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SCR_UserLuaInitSet(), "QueueTakeFirst", &cfunc_QueueTakeFirst, nullptr, "<global>", kQueueTakeFirstHelpText
    );
    return &binder;
  }

  CScrLuaInitForm* func_QueueMoveCommand_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SCR_UserLuaInitSet(), "QueueMoveCommand", &cfunc_QueueMoveCommand, nullptr, "<global>", kQueueMoveCommandHelpText
    );
    return &binder;
  }
} // namespace moho
