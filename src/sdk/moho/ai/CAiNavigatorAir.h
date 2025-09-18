// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace moho {
  /**
   * VFTABLE: 0x00E1BE9C
   * COL:  0x00E71C0C
   */
  class CAiNavigatorAir
  {
  public:
    /**
     * Address: 0x005A53F0
     * Slot: 0
     * Demangled: public: __thiscall Moho::CAiNavigatorAir::~CAiNavigatorAir()
     */
    virtual ~CAiNavigatorAir();

    /**
     * Address: 0x005A3600
     * Slot: 1
     * Demangled: Moho::CAiNavigatorImpl::GetUnit
     */
    virtual void GetUnit() = 0;

    /**
     * Address: 0x005A4C60
     * Slot: 2
     * Demangled: Moho::CAiNavigatorAir::SetGoal
     */
    virtual void SetGoal() = 0;

    /**
     * Address: 0x005A4A70
     * Slot: 3
     * Demangled: Moho::CAiNavigatorAir::SetDestUnit
     */
    virtual void SetDestUnit() = 0;

    /**
     * Address: 0x005A4F00
     * Slot: 4
     * Demangled: Moho::CAiNavigatorAir::AbortMove
     */
    virtual void AbortMove() = 0;

    /**
     * Address: 0x005A3730
     * Slot: 5
     * Demangled: Moho::CAiNavigatorImpl::BroadcastResumeTaskEvent
     */
    virtual void BroadcastResumeTaskEvent() = 0;

    /**
     * Address: 0x005A5080
     * Slot: 6
     * Demangled: Moho::CAiNavigatorAir::SetSpeedThroughGoal
     */
    virtual void SetSpeedThroughGoal() = 0;

    /**
     * Address: 0x005A50B0
     * Slot: 7
     * Demangled: Moho::CAiNavigatorAir::GetCurrentTargetPos
     */
    virtual void GetCurrentTargetPos() = 0;

    /**
     * Address: 0x005A49F0
     * Slot: 8
     * Demangled: Moho::CAiNavigatorAir::GetGoalPos
     */
    virtual void GetGoalPos() = 0;

    /**
     * Address: 0x005A37A0
     * Slot: 9
     * Demangled: Moho::CAiNavigatorImpl::GetStatus
     */
    virtual void GetStatus() = 0;

    /**
     * Address: 0x005A4E50
     * Slot: 10
     * Demangled: Moho::CAiNavigatorAir::HasGoodPath
     */
    virtual void HasGoodPath() = 0;

    /**
     * Address: 0x005A4E60
     * Slot: 11
     * Demangled: Moho::CAiNavigatorAir::FollowingLeader
     */
    virtual void FollowingLeader() = 0;

    /**
     * Address: 0x005A4A40
     * Slot: 12
     * Demangled: Moho::CAiNavigatorAir::IgnoreFormation
     */
    virtual void IgnoreFormation() = 0;

    /**
     * Address: 0x005A4A60
     * Slot: 13
     * Demangled: Moho::CAiNavigatorAir::IsIgnorningFormation
     */
    virtual void IsIgnorningFormation() = 0;

    /**
     * Address: 0x005A48E0
     * Slot: 14
     * Demangled: Moho::CAiNavigatorAir::AtGoal
     */
    virtual void AtGoal() = 0;

    /**
     * Address: 0x005A49E0
     * Slot: 15
     * Demangled: Moho::CAiNavigatorAir::CanPathTo
     */
    virtual void CanPathTo() = 0;

    /**
     * Address: 0x005A2D10
     * Slot: 16
     * Demangled: Moho::CAiNavigatorImpl::Func1
     */
    virtual void Func1() = 0;

    /**
     * Address: 0x005A2D20
     * Slot: 17
     * Demangled: Moho::CAiNavigatorImpl::GetNavPath
     */
    virtual void GetNavPath() = 0;

    /**
     * Address: 0x005A36F0
     * Slot: 18
     * Demangled: Moho::CAiNavigatorImpl::PushStack
     */
    virtual void PushStack() = 0;

    /**
     * Address: 0x005A3710
     * Slot: 19
     * Demangled: Moho::CAiNavigatorAir::NavigatorMakeIdle
     */
    virtual void NavigatorMakeIdle() = 0;
  };
} // namespace moho
