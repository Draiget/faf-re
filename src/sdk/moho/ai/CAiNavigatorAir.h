#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/CAiNavigatorImpl.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1BE9C
   * COL:  0x00E71C0C
   */
  class CAiNavigatorAir : public CAiNavigatorImpl
  {
  public:
    /**
     * Address: 0x005A5390 (FUN_005A5390, default ctor)
     */
    CAiNavigatorAir();

    /**
     * Address: 0x005A4880 (FUN_005A4880, unit ctor)
     */
    explicit CAiNavigatorAir(Unit* unit);

    /**
     * Address: 0x005A53F0 (FUN_005A53F0, scalar deleting thunk/core dtor)
     *
     * VFTable SLOT: 0
     */
    ~CAiNavigatorAir() override;

    /**
     * Address: 0x005A4C60 (FUN_005A4C60)
     *
     * VFTable SLOT: 2
     */
    void SetGoal(const SAiNavigatorGoal& goal) override;

    /**
     * Address: 0x005A4A70 (FUN_005A4A70)
     *
     * VFTable SLOT: 3
     */
    void SetDestUnit(Unit* destinationUnit) override;

    /**
     * Address: 0x005A4F00 (FUN_005A4F00)
     *
     * VFTable SLOT: 4
     */
    void AbortMove() override;

    /**
     * Address: 0x005A5080 (FUN_005A5080)
     *
     * VFTable SLOT: 6
     */
    void SetSpeedThroughGoal(bool enabled) override;

    /**
     * Address: 0x005A50B0 (FUN_005A50B0)
     *
     * VFTable SLOT: 7
     */
    [[nodiscard]]
    Wm3::Vector3f GetCurrentTargetPos() const override;

    /**
     * Address: 0x005A49F0 (FUN_005A49F0)
     *
     * VFTable SLOT: 8
     */
    [[nodiscard]]
    Wm3::Vector3f GetGoalPos() const override;

    /**
     * Address: 0x005A4E50 (FUN_005A4E50)
     *
     * VFTable SLOT: 10
     */
    [[nodiscard]]
    bool HasGoodPath() const override;

    /**
     * Address: 0x005A4E60 (FUN_005A4E60)
     *
     * VFTable SLOT: 11
     */
    [[nodiscard]]
    bool FollowingLeader() const override;

    /**
     * Address: 0x005A4A40 (FUN_005A4A40)
     *
     * VFTable SLOT: 12
     */
    void IgnoreFormation(bool ignore) override;

    /**
     * Address: 0x005A4A60 (FUN_005A4A60)
     *
     * VFTable SLOT: 13
     */
    [[nodiscard]]
    bool IsIgnoringFormation() const override;

    /**
     * Address: 0x005A48E0 (FUN_005A48E0)
     *
     * VFTable SLOT: 14
     */
    [[nodiscard]]
    bool AtGoal() const override;

    /**
     * Address: 0x005A49E0 (FUN_005A49E0)
     *
     * VFTable SLOT: 15
     */
    [[nodiscard]]
    bool CanPathTo(const SAiNavigatorGoal& goal) const override;

    /**
     * Address: 0x005A50D0 (FUN_005A50D0, CAiNavigatorAir::Execute)
     *
     * VFTable SLOT (`CTask`): 1
     */
    int Execute() override;

  private:
    /**
     * Address: 0x005A4B00 (FUN_005A4B00, helper used by FUN_005A4C60)
     *
     * What it does:
     * Chooses best perimeter cell in goal rectangle and converts to world target.
     */
    [[nodiscard]]
    Wm3::Vector3f BuildGoalWorldPos(const SAiNavigatorGoal& goal) const;

    /**
     * Address: 0x005A4A90 (FUN_005A4A90, helper chain)
     *
     * What it does:
     * Sends `mCurrentTargetPos` to unit motion with layer fallback logic.
     */
    void ApplyCurrentTargetToMotion();

    /**
     * Address: 0x005A4EA0 (FUN_005A4EA0)
     *
     * What it does:
     * Retargets motion to destination weak-link unit, or aborts when link is missing.
     */
    void UpdateCurrentTargetFromDestinationEntity();

    /**
     * Address: 0x005A4D80 (FUN_005A4D80)
     *
     * What it does:
     * Updates leader-follow target when formation-tracking is active.
     */
    void UpdateCurrentTargetFromFormation();

  public:
    static gpg::RType* sType;

    WeakPtr<Unit> mDestinationUnitLink;  // +0x68
    Wm3::Vector3f mCurrentTargetPos;     // +0x70
    Wm3::Vector3f mGoalPos;              // +0x7C
    std::uint8_t mTrackFormationTarget;  // +0x88
    std::uint8_t mPad89[3];              // +0x89
  };

  static_assert(sizeof(CAiNavigatorAir) == 0x8C, "CAiNavigatorAir size must be 0x8C");
  static_assert(
    offsetof(CAiNavigatorAir, mDestinationUnitLink) == 0x68,
    "CAiNavigatorAir::mDestinationUnitLink offset must be 0x68"
  );
  static_assert(
    offsetof(CAiNavigatorAir, mCurrentTargetPos) == 0x70, "CAiNavigatorAir::mCurrentTargetPos offset must be 0x70"
  );
  static_assert(offsetof(CAiNavigatorAir, mGoalPos) == 0x7C, "CAiNavigatorAir::mGoalPos offset must be 0x7C");
  static_assert(
    offsetof(CAiNavigatorAir, mTrackFormationTarget) == 0x88,
    "CAiNavigatorAir::mTrackFormationTarget offset must be 0x88"
  );
} // namespace moho

