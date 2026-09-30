#pragma once

#include "../../gpg/core/utils/BoostUtils.h"
#include "ISessionListener.h"
#include "SSelectionEvent.h"
#include "moho/misc/Listener.h"
#include "moho/sim/CWldSession.h"

namespace moho
{
  class CameraImpl;

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
   *   secondary at +0x04), and independently self-links the listener's
   *   node at +0x08/+0x0C - the secondary subobject starts at +0x04, with
   *   `Listener<T>`'s own shape (vtable, then its `DListItem` node).
   *   `FUN_008656A0`/`FUN_008656E0` (dispatched through the *primary*,
   *   unadjusted vtable) read and write that node at complete-object
   *   +0x08/+0x0C directly.
   *
   * Object layout:
   *   +0x00 ISessionListener vftable
   *   +0x04 Listener<SSelectionEvent> vftable
   *   +0x08 the listener node (Listener<SSelectionEvent>'s DListItem)
   *   +0x10 mIdleSet (WeakSet<UserEntity>)
   *   +0x1C mFocusStep
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
  {
    // Primary vftable (ISessionListener, 2 entries)
  public:
    /**
     * Address: 0x00865490 (FUN_00865490, IdleUnitSelector process-global
     * constructor)
     *
     * What it does:
     * The two bases, then `mIdleSet` (its head bought through 0x007B08D0) and
     * `mFocusStep = 0`.
     */
    IdleUnitSelector();

    /**
     * Address: 0x00865780 (FUN_00865780, IdleUnitSelector process-global
     * destructor)
     *
     * What it does:
     * Nothing of its own: `mIdleSet` is destroyed as a member, then the
     * `Listener` base unlinks the node.
     *
     * The binary calls this through a compiler-generated, argument-less
     * "destroy this one static object" thunk (`FUN_00C07510`) registered
     * with `atexit()` by the static-init thunk at `FUN_00BE6160` -
     * the same magic-static-destructor pattern already established for
     * `SelectionListener`'s `FUN_00C075D0`/`FUN_00BE62E0` pair. Modeling
     * `GlobalIdleUnitSelector()`'s `static IdleUnitSelector sSelector;`
     * as a function-local static reproduces that registration
     * automatically, so no explicit `atexit` call is written in source.
     */
    ~IdleUnitSelector();

    /**
     * Address: 0x008656A0 (FUN_008656A0)
     * Slot: 0 (ISessionListener primary vtable)
     *
     * What it does:
     * Re-links this listener node into the provided session-listener lane.
     */
    void AttachToSessionListenerLane(CWldSession* session) override;

    /**
     * Address: 0x008656E0 (FUN_008656E0)
     * Slot: 1 (ISessionListener primary vtable)
     *
     * What it does:
     * Unlinks this listener node from its current session-listener lane.
     */
    void DetachFromSessionListenerLane(CWldSession* session) override;

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
     * When the new selection is not the one the focus cycle holds (the
     * comparison at 0x00868690), forgets it and restarts the cycle.
     */
    void OnEvent(SSelectionEvent event) override;

    /**
     * Address: 0x00865590 (FUN_00865590)
     *
     * IDA signature:
     * void __usercall sub_865590(Moho::WeakSet_UserEntity *selection@<eax>,
     *     Moho::CameraImpl *camera@<ecx>);
     *
     * What it does:
     * One step of the idle-unit camera cycle over `selection`, the idle units
     * `SelectUnitsByCategory` (0x008662B0) just picked:
     *   0. keep a copy of the selection in `mIdleSet` and arm the cycle;
     *   1. frame all of them at the camera's target zoom;
     *   2. frame the first one's mesh box, then stop tracking.
     * Step 2 goes back to 1. `OnEvent` restarts at 0 when the selection
     * changes. The body addresses the process-global selector directly
     * (0x010C4418, 0x010C4424).
     */
    static void CycleCameraFocus(const WeakSet<UserEntity>& selection, CameraImpl* camera);

  private:
    WeakSet<UserEntity> mIdleSet; // +0x10 (the selection the focus cycle is stepping through)
    std::int32_t mFocusStep;      // +0x1C (0, 1 or 2; see `CycleCameraFocus`)
  };
} // namespace moho
