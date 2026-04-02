#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/CAiNavigatorImpl.h"
#include "moho/ai/CAiPathNavigator.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1BE24
   * COL:  0x00E71CAC
   */
  class CAiNavigatorLand : public CAiNavigatorImpl
  {
  public:
    /**
     * Address: 0x005A4420 (FUN_005A4420, default ctor)
     */
    CAiNavigatorLand();

    /**
     * Address: 0x005A3AC0 (FUN_005A3AC0, unit ctor)
     */
    explicit CAiNavigatorLand(Unit* unit);

    /**
     * Address: 0x005A4490 (FUN_005A4490, scalar deleting thunk)
     * Address: 0x005A3B80 (FUN_005A3B80, core dtor)
     *
     * VFTable SLOT: 0
     */
    ~CAiNavigatorLand() override;

    /**
     * Address: 0x005A8F40 (FUN_005A8F40, Moho::CAiNavigatorLand::MemberDeserialize)
     *
     * What it does:
     * Loads base navigator state, owned path-navigator pointer, destination-unit
     * weak link, and goal rectangle payload.
     */
    static void MemberDeserialize(CAiNavigatorLand* object, gpg::ReadArchive* archive);

    /**
     * Address: 0x005A9030 (FUN_005A9030, Moho::CAiNavigatorLand::MemberSerialize)
     *
     * What it does:
     * Saves base navigator state, owned path-navigator pointer,
     * destination-unit weak link, and goal rectangle payload.
     */
    static void MemberSerialize(const CAiNavigatorLand* object, gpg::WriteArchive* archive);

    /**
     * Address: 0x005A3ED0 (FUN_005A3ED0)
     *
     * VFTable SLOT: 2
     */
    void SetGoal(const SAiNavigatorGoal& goal) override;

    /**
     * Address: 0x005A4180 (FUN_005A4180)
     *
     * VFTable SLOT: 3
     */
    void SetDestUnit(Unit* destinationUnit) override;

    /**
     * Address: 0x005A4240 (FUN_005A4240)
     *
     * VFTable SLOT: 6
     */
    void SetSpeedThroughGoal(bool enabled) override;

    /**
     * Address: 0x005A4260 (FUN_005A4260)
     *
     * VFTable SLOT: 7
     */
    [[nodiscard]]
    Wm3::Vector3f GetCurrentTargetPos() const override;

    /**
     * Address: 0x005A3D80 (FUN_005A3D80)
     *
     * VFTable SLOT: 8
     */
    [[nodiscard]]
    Wm3::Vector3f GetGoalPos() const override;

    /**
     * Address: 0x005A3EB0 (FUN_005A3EB0)
     *
     * VFTable SLOT: 10
     */
    [[nodiscard]]
    bool HasGoodPath() const override;

    /**
     * Address: 0x005A3EC0 (FUN_005A3EC0)
     *
     * VFTable SLOT: 11
     */
    [[nodiscard]]
    bool FollowingLeader() const override;

    /**
     * Address: 0x005A3D60 (FUN_005A3D60)
     *
     * VFTable SLOT: 12
     */
    void IgnoreFormation(bool ignore) override;

    /**
     * Address: 0x005A3D70 (FUN_005A3D70)
     *
     * VFTable SLOT: 13
     */
    [[nodiscard]]
    bool IsIgnoringFormation() const override;

    /**
     * Address: 0x005A3BD0 (FUN_005A3BD0)
     *
     * VFTable SLOT: 14
     */
    [[nodiscard]]
    bool AtGoal() const override;

    /**
     * Address: 0x005A3CD0 (FUN_005A3CD0)
     *
     * VFTable SLOT: 15
     */
    [[nodiscard]]
    bool CanPathTo(const SAiNavigatorGoal& goal) const override;

    /**
     * Address: 0x005A3E80 (FUN_005A3E80)
     *
     * VFTable SLOT: 16
     */
    void Func1() override;

    /**
     * Address: 0x005A3EA0 (FUN_005A3EA0)
     *
     * VFTable SLOT: 17
     */
    [[nodiscard]]
    SNavPath* GetNavPath() const override;

    /**
     * Address: 0x005A3E00 (FUN_005A3E00)
     *
     * VFTable SLOT: 19
     */
    [[nodiscard]]
    bool NavigatorMakeIdle() override;

    /**
     * Address: 0x005A4280 (FUN_005A4280, CAiNavigatorLand::Execute)
     *
     * VFTable SLOT (`CTask`): 1
     */
    int Execute() override;

  private:
    void ApplyGoalAndStartPathing(const SAiNavigatorGoal& goal);

  public:
    static gpg::RType* sType;

    CAiPathNavigator* mPathNavigator; // +0x68
    WeakPtr<Unit> mDestinationUnit;   // +0x6C
    SAiNavigatorGoal mGoal;           // +0x74
  };

  static_assert(sizeof(CAiNavigatorLand) == 0x98, "CAiNavigatorLand size must be 0x98");
  static_assert(offsetof(CAiNavigatorLand, mPathNavigator) == 0x68, "CAiNavigatorLand::mPathNavigator offset must be 0x68");
  static_assert(
    offsetof(CAiNavigatorLand, mDestinationUnit) == 0x6C, "CAiNavigatorLand::mDestinationUnit offset must be 0x6C"
  );
  static_assert(offsetof(CAiNavigatorLand, mGoal) == 0x74, "CAiNavigatorLand::mGoal offset must be 0x74");
} // namespace moho
