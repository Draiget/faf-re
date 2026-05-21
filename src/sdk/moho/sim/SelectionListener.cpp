#include "moho/sim/SelectionListener.h"

#include <cstddef>
#include <cstdint>
#include <exception>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/entity/UserEntity.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SSelectionEvent.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"

namespace
{
  /**
   * Resolves an `SSelectionWeakRefUserEntity` link slot back to its owning
   * `UserEntity` by subtracting `offsetof(UserEntity, mIUnitChainHead)` from
   * the recorded weak-link slot, matching `DecodeSelectedUserEntity` in
   * CWldSession.cpp. Returns nullptr when the slot is null or below the
   * adjustment threshold.
   */
  [[nodiscard]] moho::UserEntity* ResolveSelectedUserEntity(
    const moho::SSelectionWeakRefUserEntity& weakRef
  ) noexcept
  {
    if (!weakRef.mOwnerLinkSlot) {
      return nullptr;
    }

    constexpr std::uintptr_t kSelectionOwnerLinkOffset = offsetof(moho::UserEntity, mIUnitChainHead);
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
    if (raw < kSelectionOwnerLinkOffset) {
      return nullptr;
    }

    return reinterpret_cast<moho::UserEntity*>(raw - kSelectionOwnerLinkOffset);
  }

  /**
   * Resolves a UserUnit's embedded IUnit subobject (at `+0x148`, the
   * `mIUnitAndScriptBridge` lane), matching the `ResolveIUnitBridge` helper
   * in CWldSession.cpp.
   */
  [[nodiscard]] moho::IUnit* ResolveUserUnitBridge(moho::UserUnit* const userUnit) noexcept
  {
    return userUnit ? reinterpret_cast<moho::IUnit*>(userUnit->mIUnitAndScriptBridge) : nullptr;
  }

  /**
   * Walks one selection-set RB-tree from the leftmost live entry to the head
   * sentinel and emits each live entry's `UserUnit` Lua handle into the
   * `outTable` at sequential 1-based indices.
   *
   * Binary fidelity note: the first phase of FUN_00869060 invokes
   * `Moho::WeakSet_UserEntity::Iterator::inc` as an out-of-line call; phases
   * 2–4 inline the same red-black tree successor walk. The
   * `SSelectionSetUserEntity::Iterator_inc` method we call here is the
   * recovered out-of-line lane, and gives bit-identical successor ordering
   * for both shapes.
   */
  void AppendSelectionSetUnitsToLuaSequence(
    moho::SSelectionSetUserEntity* const selectionSet,
    LuaPlus::LuaObject& outTable
  )
  {
    if (selectionSet == nullptr || selectionSet->mHead == nullptr) {
      return;
    }

    std::int32_t luaIndex = 1;

    moho::SSelectionNodeUserEntity* cursor = selectionSet->mHead->mLeft;
    cursor = moho::SSelectionSetUserEntity::find(selectionSet, cursor, &cursor);
    while (cursor != selectionSet->mHead) {
      moho::UserEntity* const entity = ResolveSelectedUserEntity(cursor->mEnt);
      moho::UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
      moho::IUnit* const unitBridge = ResolveUserUnitBridge(userUnit);

      if (unitBridge != nullptr) {
        LuaPlus::LuaObject unitLuaObj = unitBridge->GetLuaObject();
        outTable.SetObject(luaIndex, unitLuaObj);
        ++luaIndex;
      }

      moho::SSelectionSetUserEntity::Iterator_inc(&cursor);
      cursor = moho::SSelectionSetUserEntity::find(selectionSet, cursor, &cursor);
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00869540 (FUN_00869540)
   *
   * What it does:
   * Re-links this listener node into the provided session-listener lane
   * (the lane anchor is the session selection broadcaster sentinel).
   */
  void SelectionListener::AttachToSessionListenerLane(void* const laneContext)
  {
    auto* const laneAnchor = static_cast<Broadcaster*>(laneContext);
    this->mListenerLink.ListLinkBefore(laneAnchor);
  }

  /**
   * Address: 0x00869580 (FUN_00869580)
   *
   * What it does:
   * Detaches this selection-listener node from its current lane and leaves it
   * self-linked.
   */
  void SelectionListener::DetachFromSessionListenerLane(void* const laneContext)
  {
    (void)laneContext;
    this->mListenerLink.ListUnlink();
  }

  /**
   * Address: 0x00869060 (FUN_00869060, Moho::SelectionListener::Receive)
   *
   * What it does:
   * Builds four Lua sequence tables from the previous/current/added/removed
   * selection sets carried by `event`, then dispatches them to
   * `/lua/ui/game/gamemain.lua:OnSelectionChanged(prev, current, added, removed)`.
   *
   * For each selection set, the helper walks the red-black tree from the
   * leftmost live entry, resolves each `SSelectionWeakRefUserEntity` back to
   * its owning `UserEntity`, dispatches the virtual `IsUserUnit()` to filter
   * out non-unit entities, and pushes the unit's `GetLuaObject()` handle into
   * the destination table at the next 1-based sequence index. Lua-level
   * errors raised during the OnSelectionChanged callback are caught and
   * routed through `gpg::Warnf` matching the original `"Error running
   * '/lua/ui/game/gamemain.lua:OnSelectionChanged': %s"` template.
   */
  void SelectionListener::OnEvent(const SSelectionEvent event)
  {
    CWldSession* const activeSession = WLD_GetSession();
    if (activeSession == nullptr) {
      return;
    }

    LuaPlus::LuaState* const luaState = activeSession->mState;
    if (luaState == nullptr) {
      return;
    }

    LuaPlus::LuaObject previousSelectionTable(luaState);
    previousSelectionTable.AssignNewTable(luaState, 0, 0);
    AppendSelectionSetUnitsToLuaSequence(event.mPreviousSelection, previousSelectionTable);

    LuaPlus::LuaObject currentSelectionTable(luaState);
    currentSelectionTable.AssignNewTable(luaState, 0, 0);
    AppendSelectionSetUnitsToLuaSequence(event.mCurrentSelection, currentSelectionTable);

    LuaPlus::LuaObject addedSelectionTable(luaState);
    addedSelectionTable.AssignNewTable(luaState, 0, 0);
    AppendSelectionSetUnitsToLuaSequence(event.mAddedEntities, addedSelectionTable);

    LuaPlus::LuaObject removedSelectionTable(luaState);
    removedSelectionTable.AssignNewTable(luaState, 0, 0);
    AppendSelectionSetUnitsToLuaSequence(event.mRemovedEntities, removedSelectionTable);

    const LuaPlus::LuaObject gameMainModule = SCR_Import(luaState, "/lua/ui/game/gamemain.lua");
    const LuaPlus::LuaObject onSelectionChangedObj = gameMainModule["OnSelectionChanged"];
    if (!onSelectionChangedObj.IsFunction()) {
      onSelectionChangedObj.TypeError("call");
    }

    LuaPlus::LuaFunction onSelectionChangedFn(onSelectionChangedObj);
    try {
      onSelectionChangedFn.Call_Object4(
        previousSelectionTable,
        currentSelectionTable,
        addedSelectionTable,
        removedSelectionTable
      );
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/ui/game/gamemain.lua:OnSelectionChanged': %s",
        exception.what() != nullptr ? exception.what() : "<unknown>"
      );
    } catch (...) {
      gpg::Warnf("Error running '/lua/ui/game/gamemain.lua:OnSelectionChanged': %s", "<unknown>");
    }
  }

  namespace
  {
    /**
     * Address: 0x00F5B538 (.data, SelectionListener singleton instance).
     *
     * Layout evidence:
     * - Static-init constructor FUN_00BE62E0 writes the primary vtable
     *   `??_7SelectionListener@Moho@@6B@` to `*off_F5B538` and the secondary
     *   `??_7SelectionListener@Moho@@6B?$Listener@USSelectionEvent@Moho@@@Moho@@@`
     *   to `*off_F5B53C`, then self-links the listener broadcaster lane at
     *   `off_F5B540/F5B544` (mPrev/mNext) and registers the instance into
     *   `WLD_GetOnTeardownCallbacks()` via FUN_00869950.
     * - Atexit handler FUN_00C075D0 unlinks the broadcaster lane and restores
     *   the base `Listener<SSelectionEvent>` vtable for orderly teardown.
     *
     * The engine constructs exactly one `SelectionListener` for the process
     * lifetime; it is registered with the world-session loader so that
     * session attach/detach lifecycle hooks (slot 0/1 of the primary vtable)
     * are invoked across every session lifecycle.
     */
    SelectionListener& GlobalSelectionListener() noexcept
    {
      static SelectionListener sListener;
      return sListener;
    }

    /**
     * Address: 0x00BE62E0 (FUN_00BE62E0, SelectionListener static-init thunk).
     *
     * What it does:
     * Constructs the process-global `SelectionListener` instance and registers
     * it with the world-session loader's teardown/attach callback vector.
     * Called once during CRT `__xc_a` static initialization; the registration
     * keeps the global instance reachable from the binary's startup graph and
     * the `OnEvent` slot is then dispatched from
     * `Broadcaster<SSelectionEvent>::BroadcastEvent` whenever
     * `CWldSession::SetSelection` runs.
     *
     * The cast to `IWldTeardownCallback*` is layout-compatible: both the
     * recovered `IWldTeardownCallback` slot 0 and the `SelectionListener`
     * primary vtable slot 0 (`AttachToSessionListenerLane(void*)`) accept a
     * single pointer-sized argument; the original binary stored the listener
     * pointer in the same untyped pointer vector lane.
     */
    [[maybe_unused]] const bool kSelectionListenerStaticInit = []() noexcept {
      SelectionListener& listener = GlobalSelectionListener();
      (void)WLD_AddOnTeardownCallback(reinterpret_cast<IWldTeardownCallback*>(&listener));
      return true;
    }();
  } // namespace
} // namespace moho
