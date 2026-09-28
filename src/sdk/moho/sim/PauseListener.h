#pragma once
#include <cstddef>

#include "../../gpg/core/utils/BoostUtils.h"
#include "ISessionListener.h"
#include "moho/misc/Listener.h"

namespace moho
{
  /**
   * Pause-state event payload delivered to `Listener<SPauseEvent>::OnEvent`.
   *
   * Layout evidence:
   * - Mangled base name `?$Listener@USPauseEvent@Moho@@` (`U` = struct) proves
   *   `SPauseEvent` is a `Moho::SPauseEvent` struct passed by value into
   *   `OnEvent`.
   * - `FUN_00869630` (`Receive`) reads the event as a single boolean argument
   *   (`mov ecx, [ebp+arg_0]` -> `LuaFunction::Call_Bool`), so the struct is a
   *   1-byte pause flag. Modeled as `{ bool mPaused; }` (size note: only the
   *   pause flag is observed in this binary; if a wider layout surfaces later,
   *   revisit).
   */
  struct SPauseEvent
  {
    bool mPaused;
  };

  static_assert(sizeof(SPauseEvent) == 0x01, "SPauseEvent size must be 0x01");

  /**
   * PauseListener
   *
   * Layout evidence (`.?AVPauseListener@Moho@@`, HierarchyAttribs MI):
   * - Primary base `ISessionListener`   mdisp=0  -> vftable@0xE47B4C (2 slots:
   *   AttachToSessionListenerLane / DetachFromSessionListenerLane).
   * - Secondary base `Listener<SPauseEvent>` mdisp=4 -> vftable@0xE47B58
   *   (1 slot: OnEvent, overridden here by `Receive`, FUN_00869630).
   * - `DListItem<Listener<SPauseEvent>>` mdisp=8, the listener's node, with
   *   the `boost::noncopyable` RTTI lists at the same offset.
   *
   * Object layout:
   *   +0x00 ISessionListener vftable
   *   +0x04 Listener<SPauseEvent> vftable
   *   +0x08 the node's two links
   * Complete-object size 0x10.
   *
   * The session attach hook subscribes this listener to the session's pause
   * broadcaster at `session + 0x08` (FUN_00869700); the selection listeners
   * use the one at `session + 0x00`.
   */
  class PauseListener
    : public ISessionListener
    , public Listener<SPauseEvent>
  {
  public:
    /**
     * Address: 0x00869700 (FUN_00869700)
     * Slot: 0 (ISessionListener primary vtable)
     *
     * What it does:
     * Subscribes this listener to `session->mPauseBroadcaster` (+0x08).
     */
    void AttachToSessionListenerLane(CWldSession* session) override;

    /**
     * Address: 0x00869750 (FUN_00869750)
     * Slot: 1 (ISessionListener primary vtable)
     *
     * What it does:
     * Unlinks this listener node from its current session-listener lane.
     */
    void DetachFromSessionListenerLane(CWldSession* session) override;

    /**
     * Address: 0x00869630 (FUN_00869630, Moho::PauseListener::Receive)
     * Slot: 0 (Listener<SPauseEvent> secondary vtable)
     * Mangled: ?Receive@PauseListener@Moho@@ (Listener<SPauseEvent>::OnEvent override)
     *
     * IDA signature:
     * LuaPlus::LuaObject *__stdcall Moho::PauseListener::Receive(bool a1);
     *
     * What it does:
     * Imports `/lua/ui/game/gamemain.lua` from `sWldSession->mState`, resolves
     * its `OnUserPause` function, and invokes it with the pause flag.
     */
    void OnEvent(SPauseEvent event) override;
  };
} // namespace moho
