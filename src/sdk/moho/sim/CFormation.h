#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/sim/WeakEntitySet.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace moho
{
  class IFormationInstance;
  struct SSelectionSetUserEntity;

  class CFormation
  {
  public:
    /**
     * Address: 0x00838070 (FUN_00838070, ??0CFormation@Moho@@QAE@@Z)
     *
     * What it does:
     * Allocates one formation-node tree head, initializes formation runtime
     * lanes, and resets per-command formation state.
     */
    CFormation();

    /**
     * Address: 0x0089B370 (FUN_0089B370, ??1CFormation@Moho@@QAE@XZ)
     *
     * What it does:
     * Releases current formation-instance ownership, tears down the intrusive
     * formation-node tree head/lane, and clears node-count state.
     */
    ~CFormation();

    /**
     * Address: 0x008380E0 (FUN_008380E0, Moho::CFormation::Reset)
     *
     * What it does:
     * Clears formation-node entries, drops the current formation-instance lane,
     * and restores default orientation/timer state for command processing.
     */
    void Reset();

    /**
     * Address: 0x00838860 (FUN_00838860, Moho::CFormation::UpdateOrientation)
     *
     * IDA signature:
     * void __fastcall Moho::CFormation::UpdateOrientation(
     *     Wm3::Vector3f *mouseWorldPos, Moho::CFormation *formation);
     *
     * What it does:
     * Per-frame command-formation orientation update. Once the formation timer
     * expires and the mouse has moved far enough, recomputes the formation
     * direction quaternion from (mouse - finish) and pushes it into the live
     * formation instance via SetOrientation, unless the UI is in NIS mode (then
     * it resets the formation). Modeled static because the binary passes the
     * formation in edx, not as a thiscall receiver.
     */
    static void UpdateOrientation(const Wm3::Vector3f& mouseWorldPos, CFormation* formation);

    /**
     * Address: 0x008384C0 (FUN_008384C0, Moho::CFormation::ChooseFormation)
     *
     * IDA signature:
     * void __stdcall Moho::CFormation::ChooseFormation(
     *     Moho::CFormation *a1, Wm3::Vector3f *a2, std::vector *a3, bool a4);
     *
     * What it does:
     * Rebuilds this formation's own participant-tracking set from `selection`,
     * averaging each live unit's world position (its most recently queued
     * command destination when `useLastQueuedDestination` is set and that
     * destination is valid, else its current position) into `mStart`. Stores
     * `mFinish`/`mMousePos` from `mouseWorldPos`, derives `mDirection` from the
     * start->finish XZ delta, classifies the formation type from the live
     * selection, looks up the formation's script count, and - once the drag
     * distance exceeds 200 units - picks the travel formation; whenever the
     * type has scripts it always re-picks the best formation too (keeping the
     * previous value only when the lookup itself returns `-1`, defaulting to
     * `0` when both are `-1`).
     *
     * `selection`'s decompiled `std::vector*` typing is a decompiler
     * type-confusion (see the field doc on `mParticipants` above): it is really a
     * `SSelectionSetUserEntity*` - the exact tree/node/weak-ref shape
     * `ProcessMouse` (0x00838800) forwards in from its own `eax`-passed
     * selection set, and the same shape `PruneTombstonesAndFindLive`/
     * `Iterator_inc` (CWldSession.h) already operate on elsewhere.
     */
    void ChooseFormation(
      const Wm3::Vector3f& mouseWorldPos,
      SSelectionSetUserEntity* selection,
      bool useLastQueuedDestination
    );

    /**
     * Address: 0x008382A0 (FUN_008382A0, Moho::CFormation::Finalize)
     *
     * What it does:
     * Releases whatever formation instance is currently installed, then --
     * only once a best-formation script has actually been chosen
     * (`mBestFormation >= 0`) -- collects every live participant unit that is
     * not dead, not still under construction, and not attached to another
     * entity into a transient weak-ref set, resolves the chosen script's
     * display name, and builds a fresh `CFormationInstance` from the
     * collected units/name/finish coords/current direction. The freshly
     * built instance becomes the new `mCurInstance` (releasing whatever
     * instance the build itself observed installed there, in case one raced
     * in), `mLastUpdate` is stamped from the system timer, and the transient
     * collection's intrusive weak links are released before returning.
     */
    void Finalize();

    /**
     * Address: 0x00838800 (FUN_00838800, Moho::CFormation::ProcessMouse)
     *
     * IDA signature:
     * void __userpurge Moho::CFormation::ProcessMouse(
     *     std::vector *a1@<eax>, Moho::CFormation *a2, char a3,
     *     Wm3::Vector3f *mousePos, bool a5);
     *
     * What it does:
     * `a1`'s decompiled `std::vector*` typing is the same decompiler
     * type-confusion `ChooseFormation` and `PruneTombstonesAndFindLive`
     * already document -- it is really the world session's
     * `SSelectionSetUserEntity*`. When the trigger flag is clear, or the
     * selection prunes down to no live entity, this drops the formation
     * (`mReady = false`, `Reset()`); otherwise it marks the formation ready
     * and forwards straight into `ChooseFormation()`/`Finalize()`.
     */
    void ProcessMouse(
      SSelectionSetUserEntity* selection,
      bool triggerActive,
      const Wm3::Vector3f& mousePos,
      bool useLastQueuedDestination
    );

    /**
     * Address: 0x00838A80 (FUN_00838A80, Moho::CFormation::LuaFinalize)
     *
     * IDA signature:
     * void __usercall Moho::CFormation::LuaFinalize(Moho::CFormation *a1@<esi>);
     *
     * What it does:
     * Lua-facing re-finalize: only fires once more than one formation script
     * is available, advancing `mBestFormation` to the next script round-robin
     * (`(mBestFormation + 1) % mNumFormationScripts`) before calling
     * `Finalize()` again to rebuild the live formation instance from the new
     * choice, then resets `mTimeLeft` to force an immediate next tick.
     *
     * Not yet invoked from recovered source: its sole caller,
     * `Moho::CUIWorldView::HandleEvent` (0x008704B0, 889 instructions), is
     * still unrecovered. Frontier orphan pending that dispatcher, matching
     * the same pattern as `func_NewCommandDragger`/`NewSelectionDragger`
     * (UiRuntimeTypes.cpp).
     */
    [[maybe_unused]] void LuaFinalize();

  public:
    /// The set of units currently participating in the drag-formation, a
    /// `WeakSet<UserUnit>` embedded at `this + 0x00`: `ChooseFormation`
    /// (0x008384C0) inserts each unit it visits by calling
    /// `WeakSet<UserUnit>::Add` (0x00822270) with `this` verbatim as the "set"
    /// argument - the ASM repurposes `ebp` to hold `this` for the whole
    /// function and pushes it unadjusted - and `Finalize` (0x008382A0) walks it
    /// back out via `sub_7B29C0` (`PruneTombstonesAndFindLive`) to build the
    /// `CFormationInstance`'s unit list. `Reset()`/`~CFormation()` tear the
    /// tree down through the same intrusive owner-chain unlink every other
    /// weak set in the engine uses.
    WeakUnitSetUserUnit mParticipants; // +0x00 { proxy, mHead@+0x04, mSize@+0x08 }
    IFormationInstance* mCurInstance;  // +0x0C
    bool mReady;                       // +0x10
    std::uint8_t mPad11[0x03];         // +0x11
    std::int32_t mType;                // +0x14
    Wm3::Vector3f mStart;              // +0x18
    Wm3::Vector3f mFinish;             // +0x24
    Wm3::Vector3f mMousePos;           // +0x30
    std::int32_t mBestFormation;       // +0x3C
    std::int32_t mTravelFormation;     // +0x40
    std::int32_t mNumFormationScripts; // +0x44
    Wm3::Quaternionf mDirection;       // +0x48 (Wm3 layout: w@+0x48, x@+0x4C, y@+0x50, z@+0x54)
    float mDirectionScale;             // +0x58
    float mTimeLeft;                   // +0x5C
    float mLastUpdate;                 // +0x60
  };

  static_assert(sizeof(CFormation) == 0x64, "CFormation size must be 0x64");
  static_assert(offsetof(CFormation, mParticipants) == 0x00, "CFormation::mParticipants offset must be 0x00");
  static_assert(offsetof(CFormation, mCurInstance) == 0x0C, "CFormation::mCurInstance offset must be 0x0C");
  static_assert(offsetof(CFormation, mType) == 0x14, "CFormation::mType offset must be 0x14");
  static_assert(offsetof(CFormation, mBestFormation) == 0x3C, "CFormation::mBestFormation offset must be 0x3C");
  static_assert(offsetof(CFormation, mTravelFormation) == 0x40, "CFormation::mTravelFormation offset must be 0x40");
  static_assert(offsetof(CFormation, mNumFormationScripts) == 0x44, "CFormation::mNumFormationScripts offset must be 0x44");
  static_assert(offsetof(CFormation, mDirection) == 0x48, "CFormation::mDirection offset must be 0x48");
  static_assert(sizeof(Wm3::Quaternionf) == 0x10, "Wm3::Quaternionf size must be 0x10");
  static_assert(offsetof(CFormation, mTimeLeft) == 0x5C, "CFormation::mTimeLeft offset must be 0x5C");
  static_assert(offsetof(CFormation, mLastUpdate) == 0x60, "CFormation::mLastUpdate offset must be 0x60");
} // namespace moho
