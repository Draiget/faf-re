#include "moho/sim/PauseListener.h"

#include <cstddef>
#include <cstdint>

#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CWldSession.h"
#include "moho/unit/Broadcaster.h"

namespace moho
{
  static_assert(sizeof(PauseListener) == 0x10, "PauseListener complete-object size must be 0x10");

  /**
   * Address: 0x00869700 (FUN_00869700)
   *
   * What it does:
   * Detaches this pause-listener node from its current lane and reinserts it
   * into the pause lane embedded at `laneContext + 0x08`.
   */
  void PauseListener::AttachToSessionListenerLane(void* const laneContext)
  {
    auto* const laneOwnerBytes = static_cast<std::uint8_t*>(laneContext);
    auto* const laneAnchor = reinterpret_cast<Broadcaster*>(laneOwnerBytes + 0x08);
    this->mListenerLink.ListLinkBefore(laneAnchor);
  }

  /**
   * Address: 0x00869750 (FUN_00869750)
   *
   * What it does:
   * Detaches this pause-listener node from its current lane and leaves it
   * self-linked.
   */
  void PauseListener::DetachFromSessionListenerLane(void* const laneContext)
  {
    (void)laneContext;
    this->mListenerLink.ListUnlink();
  }

  /**
   * Address: 0x00869630 (FUN_00869630, Moho::PauseListener::Receive)
   * Slot: 0 (Listener<SPauseEvent> secondary vtable)
   *
   * IDA signature:
   * LuaPlus::LuaObject *__stdcall Moho::PauseListener::Receive(bool a1);
   *
   * What it does:
   * Imports `/lua/ui/game/gamemain.lua` from the active world session's Lua
   * state, resolves its `OnUserPause` function, and calls it with the pause
   * flag carried by `event`. Mirrors the `SCR_Import` + `operator[]` +
   * `LuaFunction::Call_Bool` forwarder idiom; the module/key LuaObjects are
   * released before the call, matching the original destructor ordering.
   */
  void PauseListener::OnEvent(const SPauseEvent event)
  {
    LuaPlus::LuaState* const luaState = WLD_GetSession()->mState;

    LuaPlus::LuaFunction onUserPauseFn(
      SCR_Import(luaState, "/lua/ui/game/gamemain.lua")["OnUserPause"]
    );
    onUserPauseFn.Call_Bool(event.mPaused);
  }

  namespace
  {
    /**
     * Address: 0x00F5B548 (.data, process-global PauseListener instance).
     *
     * Layout evidence:
     * - Static-init constructor FUN_00BE6320 registers `&off_F5B548` with the
     *   world-session teardown callback vector (via FUN_00869950 =
     *   `WLD_AddOnTeardownCallback`), self-links the listener broadcaster lane
     *   at `off_F5B550/off_F5B554`, installs the PauseListener primary vtable at
     *   `off_F5B548` and the secondary `Listener<SPauseEvent>` vtable at
     *   `off_F5B54C`, then queues `atexit(FUN_00C07610)`.
     * - Atexit handler FUN_00C07610 restores the base `Listener<SPauseEvent>`
     *   vtable, unlinks the broadcaster lane, and resets it to a self-linked
     *   singleton for orderly teardown.
     *
     * The engine constructs exactly one PauseListener for the process lifetime;
     * registering it with the world-session loader keeps the instance reachable
     * from the binary's startup graph, and its `OnEvent` slot is dispatched from
     * the session pause broadcaster whenever the pause state toggles.
     */
    [[nodiscard]] PauseListener& GlobalPauseListener() noexcept
    {
      static PauseListener sListener;
      return sListener;
    }

    /**
     * Address: 0x00BE6320 (FUN_00BE6320, PauseListener static-init thunk).
     *
     * What it does:
     * Constructs the process-global PauseListener and registers it with the
     * world-session loader's teardown callback vector during CRT `__xc_a`
     * static initialization, keeping the instance reachable from the startup
     * graph.
     *
     * The registry is typed on `ISessionListener`, this listener's primary
     * base, so the registration is an ordinary base conversion - the session
     * loader calls slot 0 (attach) on creation and slot 1 (detach) on
     * teardown. The original binary stored `&off_F5B548`, the same address.
     */
    [[maybe_unused]] const bool kPauseListenerStaticInit = []() noexcept {
      PauseListener& listener = GlobalPauseListener();
      (void)WLD_AddOnTeardownCallback(static_cast<ISessionListener*>(&listener));
      return true;
    }();
  } // namespace
} // namespace moho
