#pragma once

#include "../../gpg/core/utils/BoostUtils.h"
#include "ISessionListener.h"
#include "SSelectionEvent.h"
#include "moho/misc/Listener.h"
#include "moho/sim/CWldSession.h"

namespace moho
{
  /**
   * IdleUnitSelector
   *
   * Layout evidence (multiple inheritance, matching the shape already
   * established for the sibling `SelectionListener`/`PauseListener` classes):
   * - Primary base `ISessionListener`, vftable
   *   `??_7IdleUnitSelector@Moho@@6B@` at 0x00E47A64 (2 slots:
   *   AttachToSessionListenerLane / DetachFromSessionListenerLane).
   * - Secondary base `Listener<SSelectionEvent>`, vftable
   *   `??_7IdleUnitSelector@Moho@@6B?$Listener@USSelectionEvent@Moho@@@Moho@@@`
   *   at 0x00E47A70 (1 slot: OnEvent, overridden here, FUN_00865540).
   *   VTABLE_CONFIRMED: the static-init constructor FUN_00865490 writes
   *   both vtable pointers into the same process-global instance
   *   (`off_10C4408` = primary at complete-object +0x00, `off_10C440C` =
   *   secondary at +0x04), and independently self-links
   *   `Listener<SSelectionEvent>::mListenerLink` at +0x08/+0x0C - both
   *   confirming the secondary subobject starts at complete-object +0x04,
   *   exactly matching `Listener<T>`'s own 0x0C-byte shape (vtable at
   *   subobject-relative +0x00, `mListenerLink` at subobject-relative
   *   +0x04). `FUN_008656A0`/`FUN_008656E0` (dispatched through the
   *   *primary*, unadjusted vtable) independently confirm the same
   *   `mListenerLink` storage by reading/writing complete-object +0x08/+0x0C
   *   directly from the unadjusted `this`.
   * - `boost::noncopyable_::noncopyable` mixin: constructed once as a
   *   process-global instance (matches the sibling listener singletons).
   *
   * Object layout:
   *   +0x00 ISessionListener vftable
   *   +0x04 Listener<SSelectionEvent> vftable
   *   +0x08 Broadcaster mListenerLink (Listener<SSelectionEvent> subobject)
   *   +0x10 mIdleSet (SSelectionSetUserEntity, own field)
   * Complete-object size 0x20.
   *
   * `FUN_00865490` (the process-global constructor / static-init thunk,
   * called from `FUN_00BE6160`, the same static-init-table shape as
   * `SelectionListener`'s `FUN_00BE62E0` and `PauseListener`'s
   * `FUN_00BE6320`) is deliberately left unrecovered here: its idle-set head
   * allocation calls `FUN_007B08D0`, which `recovered_progress.json` marks
   * `recovered` in `CrtRuntimeHelpers.cpp`, but no such body actually exists
   * there (stale/fake progress entry - `SelectionDragger.h` independently
   * documents `FUN_007B08D0` as still-unrecovered too). That dependency
   * bottoms out in the real, genuine `FUN_007B1420`/`FUN_007B4FA0` leaf
   * allocators in `src/sdk/legacy/containers/Vector.cpp`, a file another
   * recovery pass has in flight as of this change. Recovering the
   * constructor on top of a fabricated dependency would just add more
   * contamination, so it stays `blocked` pending a real `FUN_007B08D0`
   * recovery pass.
   */
  class IdleUnitSelector
    : public ISessionListener
    , public Listener<SSelectionEvent>
    , boost::noncopyable_::noncopyable
  {
    // Primary vftable (ISessionListener, 2 entries)
  public:
    /**
     * Address: 0x008656A0 (FUN_008656A0)
     * Slot: 0 (ISessionListener primary vtable)
     *
     * What it does:
     * Re-links this listener node into the provided session-listener lane.
     */
    void AttachToSessionListenerLane(void* laneContext) override;

    /**
     * Address: 0x008656E0 (FUN_008656E0)
     * Slot: 1 (ISessionListener primary vtable)
     *
     * What it does:
     * Unlinks this listener node from its current session-listener lane.
     */
    void DetachFromSessionListenerLane(void* laneContext) override;

    // Secondary vftable (Listener<SSelectionEvent>, 1 entry)
  public:
    /**
     * Address: 0x00865540 (FUN_00865540)
     * Slot: 0 (Listener<SSelectionEvent> secondary vtable)
     *
     * IDA signature:
     * void __thiscall sub_865540(Listener<SSelectionEvent> *this, SSelectionEvent event);
     *
     * What it does:
     * Compares `mIdleSet` against `event.mCurrentSelection` by live-entity
     * membership; when they no longer match, clears every tracked idle-set
     * node and resets the tree head back to its empty self-linked sentinel
     * state.
     */
    void OnEvent(SSelectionEvent event) override;

  private:
    SSelectionSetUserEntity mIdleSet{}; // +0x10
  };
} // namespace moho
