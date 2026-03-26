#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/misc/WeakPtr.h"
#include "moho/sim/SOCellPos.h"
#include "moho/unit/Broadcaster.h"
#include "wm3/Vector3.h"

namespace moho
{
  class CAiPathFinder;
  class Sim;
  class Unit;

  /**
   * Recovered CAiPathNavigator runtime state.
   *
   * Evidence:
   * - Constructor/destructor/layout: FUN_005AD3E0, FUN_005A44B0.
   * - Goal/path-state helpers: FUN_005AD6E0, FUN_005AD800, FUN_005AD8B0, FUN_005AD9C0, FUN_005ADBA0.
   * - Tick/update chain: FUN_005AE2D0.
   */
  enum EAiPathNavigatorState : std::int32_t
  {
    AIPATHNAVSTATE_Idle = 0,
    AIPATHNAVSTATE_Failed = 1,
    AIPATHNAVSTATE_Thinking = 2,
    AIPATHNAVSTATE_PathEvent3 = 3,
    AIPATHNAVSTATE_PathEvent4 = 4,
    AIPATHNAVSTATE_HasPath = 5,
    AIPATHNAVSTATE_FollowingLeader = 6,
  };

  /**
   * VFTABLE: 0x00E1C66C
   * COL:  0x00E725D8
   */
  class CAiPathNavigator
  {
  public:
    /**
     * Address: 0x005AD3E0 (FUN_005AD3E0, unit ctor)
     */
    explicit CAiPathNavigator(Unit* unit);

    /**
     * Address: 0x005A44B0 (FUN_005A44B0, core dtor body)
     * Address: 0x005A44C0 (FUN_005A44C0, duplicated thunked entry)
     */
    ~CAiPathNavigator();

    /**
     * Address: 0x005AEEB0 (FUN_005AEEB0)
     *
     * What it does:
     * Consumes one pathfinding callback payload and updates path-state machine.
     */
    virtual bool OnEvent(const SNavPath& path);

    /**
     * Address: 0x005AD6E0 (FUN_005AD6E0)
     *
     * What it does:
     * Replaces active goal payload and resets formation-follow sidecars.
     */
    void ConfigureGoal(const SAiNavigatorGoal& goal, bool ignoreFormation);

    /**
     * Address: 0x005AD9C0 (FUN_005AD9C0)
     *
     * What it does:
     * Clears active path/state/link flags and returns to idle path state.
     */
    void ResetPathState();

    /**
     * Address: 0x005ADBA0 (FUN_005ADBA0)
     *
     * What it does:
     * Enters thinking state and initializes formation-follow gating flags.
     */
    void BeginThinking();

    /**
     * Address: 0x005ADFE0 (FUN_005ADFE0)
     *
     * What it does:
     * Starts or refreshes one path-query request cycle for the current goal.
     */
    void RequestPath(std::int32_t requestMode);

    /**
     * Address: 0x005AE210 (FUN_005AE210)
     *
     * What it does:
     * Converts world position to current-cell position using active footprint.
     */
    void SetCurrentPosition(const Wm3::Vector3f& position);

    /**
     * Address: 0x005AE2D0 (FUN_005AE2D0)
     *
     * What it does:
     * Main path tick update: progresses state, formation-follow, and repath gates.
     */
    void UpdateCurrentPosition(const Wm3::Vector3f& position);

    /**
     * Address: 0x005AD800 (FUN_005AD800)
     */
    [[nodiscard]]
    bool IsCellInGoal(const SOCellPos& cellPos) const;

    /**
     * Address: 0x005AD8B0 (FUN_005AD8B0)
     */
    [[nodiscard]]
    Wm3::Vector3f GetTargetPos() const;

    /**
     * Address: 0x005ADAD0 (FUN_005ADAD0 callsite from FUN_005A3CD0)
     */
    [[nodiscard]]
    bool CanPathTo(const SAiNavigatorGoal& goal, Wm3::Vector3f* outTargetPos) const;

    [[nodiscard]]
    SNavPath* GetPath() noexcept
    {
      return &mPath;
    }

    [[nodiscard]]
    const SNavPath* GetPath() const noexcept
    {
      return &mPath;
    }

    [[nodiscard]] static CAiPathNavigator* FromListenerLink(Broadcaster* link) noexcept;
    [[nodiscard]] static const CAiPathNavigator* FromListenerLink(const Broadcaster* link) noexcept;

  private:
    /**
     * Address: 0x005AEC70 (FUN_005AEC70)
     *
     * What it does:
     * Issues a short-horizon continuation path request from the current active path front.
     */
    void RequestContinuationPath(std::int32_t requestMode);

    /**
     * Address: 0x005AF6D0 (FUN_005AF6D0)
     *
     * What it does:
     * Pops the consumed path prefix, updates current target cell, and enters has-path state.
     */
    void SetTargetPoint(std::int32_t targetIndex);

    /**
     * Address: 0x005AF7E0 (FUN_005AF7E0)
     *
     * What it does:
     * Chooses one reachable target point from the active path and applies it.
     */
    [[nodiscard]]
    bool TryAdvanceTargetPoint();

  public:
    static gpg::RType* sType;

    Broadcaster mListenerLink;           // +0x04
    EAiPathNavigatorState mState;        // +0x0C
    CAiPathFinder* mPathFinder;          // +0x10
    SNavPath mPath;                      // +0x14
    SOCellPos mCurrentPos;               // +0x24
    SOCellPos mTargetPos;                // +0x28
    std::uint32_t mLastBlockedCell;      // +0x2C
    SAiNavigatorGoal mGoal;              // +0x30
    std::uint32_t mLastPathLayerToken;   // +0x54
    Sim* mSim;                           // +0x58
    std::int32_t mLastPathNodeIndex;     // +0x5C
    std::int32_t mPathSearchFailCount;   // +0x60
    std::int32_t mPathRetryDelayFrames;  // +0x64
    std::int32_t mNoForwardDistanceFailCount; // +0x68
    float mRepathDistanceThreshold;      // +0x6C
    std::int32_t mLastRepathTick;        // +0x70
    std::int32_t mNoProgressTickCount;   // +0x74
    std::int32_t mLastFormationSyncTick; // +0x78
    WeakPtr<Unit> mLeaderLink;           // +0x7C
    Wm3::Vector3f mLeaderTargetPos;      // +0x84
    std::uint8_t mIsInFormation;         // +0x90
    std::uint8_t mLeaderBusy;            // +0x91 (leader builder busy gate)
    std::uint8_t mHasLeaderTargetPos;    // +0x92
    std::uint8_t mHasForwardProbe;       // +0x93
    std::uint8_t mRepathRequested;       // +0x94
    std::uint8_t mUseExtendedPathProbe;  // +0x95
    std::uint8_t mTargetWithinOneCell;   // +0x96
    std::uint8_t mPad97;                 // +0x97
    std::int32_t mPathRequestMode;       // +0x98
    std::int32_t mPathRequestCountdown;  // +0x9C
    std::int32_t mTickBucket7;           // +0xA0
    std::int32_t mTickBucket13;          // +0xA4
  };

  static_assert(sizeof(CAiPathNavigator) == 0xA8, "CAiPathNavigator size must be 0xA8");
  static_assert(offsetof(CAiPathNavigator, mListenerLink) == 0x04, "CAiPathNavigator::mListenerLink offset must be 0x04");
  static_assert(offsetof(CAiPathNavigator, mState) == 0x0C, "CAiPathNavigator::mState offset must be 0x0C");
  static_assert(offsetof(CAiPathNavigator, mPathFinder) == 0x10, "CAiPathNavigator::mPathFinder offset must be 0x10");
  static_assert(offsetof(CAiPathNavigator, mPath) == 0x14, "CAiPathNavigator::mPath offset must be 0x14");
  static_assert(offsetof(CAiPathNavigator, mCurrentPos) == 0x24, "CAiPathNavigator::mCurrentPos offset must be 0x24");
  static_assert(offsetof(CAiPathNavigator, mTargetPos) == 0x28, "CAiPathNavigator::mTargetPos offset must be 0x28");
  static_assert(offsetof(CAiPathNavigator, mGoal) == 0x30, "CAiPathNavigator::mGoal offset must be 0x30");
  static_assert(offsetof(CAiPathNavigator, mSim) == 0x58, "CAiPathNavigator::mSim offset must be 0x58");
  static_assert(offsetof(CAiPathNavigator, mLeaderLink) == 0x7C, "CAiPathNavigator::mLeaderLink offset must be 0x7C");
  static_assert(
    offsetof(CAiPathNavigator, mLeaderTargetPos) == 0x84, "CAiPathNavigator::mLeaderTargetPos offset must be 0x84"
  );
  static_assert(
    offsetof(CAiPathNavigator, mIsInFormation) == 0x90, "CAiPathNavigator::mIsInFormation offset must be 0x90"
  );
  static_assert(offsetof(CAiPathNavigator, mLeaderBusy) == 0x91, "CAiPathNavigator::mLeaderBusy offset must be 0x91");
  static_assert(
    offsetof(CAiPathNavigator, mHasLeaderTargetPos) == 0x92,
    "CAiPathNavigator::mHasLeaderTargetPos offset must be 0x92"
  );
  static_assert(
    offsetof(CAiPathNavigator, mHasForwardProbe) == 0x93, "CAiPathNavigator::mHasForwardProbe offset must be 0x93"
  );
  static_assert(
    offsetof(CAiPathNavigator, mRepathRequested) == 0x94, "CAiPathNavigator::mRepathRequested offset must be 0x94"
  );
  static_assert(
    offsetof(CAiPathNavigator, mUseExtendedPathProbe) == 0x95,
    "CAiPathNavigator::mUseExtendedPathProbe offset must be 0x95"
  );
  static_assert(
    offsetof(CAiPathNavigator, mTargetWithinOneCell) == 0x96,
    "CAiPathNavigator::mTargetWithinOneCell offset must be 0x96"
  );
  static_assert(
    offsetof(CAiPathNavigator, mPathRequestMode) == 0x98,
    "CAiPathNavigator::mPathRequestMode offset must be 0x98"
  );
  static_assert(
    offsetof(CAiPathNavigator, mPathRequestCountdown) == 0x9C,
    "CAiPathNavigator::mPathRequestCountdown offset must be 0x9C"
  );
  static_assert(offsetof(CAiPathNavigator, mTickBucket7) == 0xA0, "CAiPathNavigator::mTickBucket7 offset must be 0xA0");
  static_assert(offsetof(CAiPathNavigator, mTickBucket13) == 0xA4, "CAiPathNavigator::mTickBucket13 offset must be 0xA4");
} // namespace moho
