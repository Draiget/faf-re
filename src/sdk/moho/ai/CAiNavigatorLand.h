// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace moho {
  /**
   * VFTABLE: 0x00E1BE24
   * COL:  0x00E71CAC
   */
  class CAiNavigatorLand
  {
  public:
    /**
     * Address: 0x005A4490
     * Slot: 0
     * Demangled: public: __thiscall Moho::CAiNavigatorLand::~CAiNavigatorLand()
     */
    virtual ~CAiNavigatorLand();

    /**
     * Address: 0x005A3600
     * Slot: 1
     * Demangled: Moho::CAiNavigatorImpl::GetUnit
     */
    virtual void GetUnit() = 0;

    /**
     * Address: 0x005A3ED0
     * Slot: 2
     * Demangled: Moho::CAiNavigatorLand::SetGoal
     */
    virtual void SetGoal() = 0;

    /**
     * Address: 0x005A4180
     * Slot: 3
     * Demangled: Moho::CAiNavigatorLand::SetDestUnit
     */
    virtual void SetDestUnit() = 0;

    /**
     * Address: 0x005A3750
     * Slot: 4
     * Demangled: Moho::CAiNavigatorImpl::AbortMove
     */
    virtual void AbortMove() = 0;

    /**
     * Address: 0x005A3730
     * Slot: 5
     * Demangled: Moho::CAiNavigatorImpl::BroadcastResumeTaskEvent
     */
    virtual void BroadcastResumeTaskEvent() = 0;

    /**
     * Address: 0x005A4240
     * Slot: 6
     * Demangled: Moho::CAiNavigatorLand::SetSpeedThroughGoal
     */
    virtual void SetSpeedThroughGoal() = 0;

    /**
     * Address: 0x005A4260
     * Slot: 7
     * Demangled: Moho::CAiNavigatorLand::GetCurrentTargetPos
     */
    virtual void GetCurrentTargetPos() = 0;

    /**
     * Address: 0x005A3D80
     * Slot: 8
     * Demangled: Moho::CAiNavigatorLand::GetGoalPos
     */
    virtual void GetGoalPos() = 0;

    /**
     * Address: 0x005A37A0
     * Slot: 9
     * Demangled: Moho::CAiNavigatorImpl::GetStatus
     */
    virtual void GetStatus() = 0;

    /**
     * Address: 0x005A3EB0
     * Slot: 10
     * Demangled: Moho::CAiNavigatorLand::HasGoodPath
     */
    virtual void HasGoodPath() = 0;

    /**
     * Address: 0x005A3EC0
     * Slot: 11
     * Demangled: Moho::CAiNavigatorLand::FollowingLeader
     */
    virtual void FollowingLeader() = 0;

    /**
     * Address: 0x005A3D60
     * Slot: 12
     * Demangled: Moho::CAiNavigatorLand::IgnoreFormation
     */
    virtual void IgnoreFormation() = 0;

    /**
     * Address: 0x005A3D70
     * Slot: 13
     * Demangled: Moho::CAiNavigatorLand::IsIgnorningFormation
     */
    virtual void IsIgnorningFormation() = 0;

    /**
     * Address: 0x005A3BD0
     * Slot: 14
     * Demangled: Moho::CAiNavigatorLand::AtGoal
     */
    virtual void AtGoal() = 0;

    /**
     * Address: 0x005A3CD0
     * Slot: 15
     * Demangled: Moho::CAiNavigatorLand::CanPathTo
     */
    virtual void CanPathTo() = 0;

    /**
     * Address: 0x005A3E80
     * Slot: 16
     * Demangled: Moho::CAiNavigatorLand::Func1
     */
    virtual void Func1() = 0;

    /**
     * Address: 0x005A3EA0
     * Slot: 17
     * Demangled: Moho::CAiNavigatorLand::GetNavPath
     */
    virtual void GetNavPath() = 0;

    /**
     * Address: 0x005A36F0
     * Slot: 18
     * Demangled: Moho::CAiNavigatorImpl::PushStack
     */
    virtual void PushStack() = 0;

    /**
     * Address: 0x005A3E00
     * Slot: 19
     * Demangled: Moho::CAiNavigatorLand::NavigatorMakeIdle
     */
    virtual void NavigatorMakeIdle() = 0;
  };
} // namespace moho
