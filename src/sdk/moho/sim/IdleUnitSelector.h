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
   * `FUN_00BE6320`) needed `FUN_007B08D0` (the idle-set head sentinel
   * allocation) recovered for real first - it is now cited as a sibling
   * `WeakEntitySetUserEntity::BuyNode()` emission (CWldSession.cpp), so the
   * constructor below is real. The raw decompile registers the
   * not-yet-fully-constructed object with `WLD_AddOnTeardownCallback` before
   * either vtable is written (matching `SelectionListener`'s identical
   * pattern) - the callback vector is never touched before real process
   * teardown, so the registration-before-construction-completes ordering is
   * behaviorally inert; the magic-static + register-after modernization
   * already accepted for `SelectionListener` applies here unchanged.
   */
  class IdleUnitSelector
    : public ISessionListener
    , public Listener<SSelectionEvent>
    , boost::noncopyable_::noncopyable
  {
    // Primary vftable (ISessionListener, 2 entries)
  public:
    /**
     * Address: 0x00865490 (FUN_00865490, IdleUnitSelector process-global
     * constructor)
     *
     * What it does:
     * Brings the idle-set head up as an empty self-linked sentinel through
     * the now-recovered `InitWeakEntitySetHead` and zeroes the trailing
     * `mSizeMirrorOrUnused` lane, matching the binary's explicit field-by-field
     * setup (this type has no member default constructors of its own - every
     * owner initializes it explicitly).
     */
    IdleUnitSelector();

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
