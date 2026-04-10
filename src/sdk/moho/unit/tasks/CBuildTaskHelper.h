#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class Sim;
  class Unit;

  /**
   * Shared build/assist progress helper used by multiple unit command tasks.
   */
  class CBuildTaskHelper
  {
  public:
    CBuildTaskHelper();

    /**
     * Address: 0x005F56F0 (FUN_005F56F0, ??0CBuildTaskHelper@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes helper state for one owning builder/unit pair and stores
     * the build-action label used by script callbacks.
     */
    CBuildTaskHelper(const char* actionName, Unit* unit);

    /**
     * Address: 0x005F5790 (FUN_005F5790, ??1CBuildTaskHelper@Moho@@QAE@@Z)
     *
     * What it does:
     * Stops active build focus lanes, resets owner work-progress, and unlinks
     * helper weak pointers.
     */
    ~CBuildTaskHelper();

    /**
     * Address: 0x005F5A20 (FUN_005F5A20, Moho::CBuildTaskHelper::OnStopBuild)
     *
     * What it does:
     * Stops current build focus/script state and clears linked focus weak lanes.
     */
    void OnStopBuild(bool failed);

    /**
     * Address: 0x005F5B00 (FUN_005F5B00, Moho::CBuildTaskHelper::SetFocus)
     *
     * What it does:
     * Switches helper focus to `focusUnit`, updates owner focus-link state,
     * and dispatches start-build script callbacks.
     */
    void SetFocus(Unit* focusUnit);

    /**
     * Address: 0x005F5BF0 (FUN_005F5BF0, Moho::CBuildTaskHelper::UpdateWorkProgress)
     *
     * What it does:
     * Advances build/repair/enhance work-progress lanes and returns true when
     * this helper's current work item has finished.
     */
    [[nodiscard]] bool UpdateWorkProgress();

  public:
    Unit* mUnit;                 // 0x00
    Sim* mSim;                   // 0x04
    WeakPtr<Unit> mFocus;        // 0x08
    bool mBeingBuilt;            // 0x10
    std::uint8_t mPad11_13[3];   // 0x11
    float mUnknown14;            // 0x14
    float mUnknown18;            // 0x18
    float mDelta;                // 0x1C
    msvc8::string mActionName;   // 0x20
    float mFractionComplete;     // 0x3C
    bool mIsSilo;                // 0x40
    std::uint8_t mPad41_43[3];   // 0x41
  };

  static_assert(sizeof(CBuildTaskHelper) == 0x44, "CBuildTaskHelper size must be 0x44");
  static_assert(offsetof(CBuildTaskHelper, mUnit) == 0x00, "CBuildTaskHelper::mUnit offset must be 0x00");
  static_assert(offsetof(CBuildTaskHelper, mSim) == 0x04, "CBuildTaskHelper::mSim offset must be 0x04");
  static_assert(offsetof(CBuildTaskHelper, mFocus) == 0x08, "CBuildTaskHelper::mFocus offset must be 0x08");
  static_assert(
    offsetof(CBuildTaskHelper, mBeingBuilt) == 0x10, "CBuildTaskHelper::mBeingBuilt offset must be 0x10"
  );
  static_assert(offsetof(CBuildTaskHelper, mDelta) == 0x1C, "CBuildTaskHelper::mDelta offset must be 0x1C");
  static_assert(
    offsetof(CBuildTaskHelper, mActionName) == 0x20, "CBuildTaskHelper::mActionName offset must be 0x20"
  );
  static_assert(
    offsetof(CBuildTaskHelper, mFractionComplete) == 0x3C,
    "CBuildTaskHelper::mFractionComplete offset must be 0x3C"
  );
  static_assert(offsetof(CBuildTaskHelper, mIsSilo) == 0x40, "CBuildTaskHelper::mIsSilo offset must be 0x40");
} // namespace moho
