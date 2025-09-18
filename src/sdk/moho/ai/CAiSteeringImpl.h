// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace moho {
  /**
   * VFTABLE: 0x00E1E0A8
   * COL:  0x00E74E68
   */
  class CAiSteeringImpl
  {
  public:
    /**
     * Address: 0x005D2730
     * Slot: 0
     * Demangled: public: __thiscall Moho::CAiSteeringImpl::operator delete()
     */
    virtual void operator_delete() = 0;

    /**
     * Address: 0x005D29C0
     * Slot: 1
     * Demangled: Moho::CAiSteeringImpl::SetWaypoints
     */
    virtual void SetWaypoints() = 0;

    /**
     * Address: 0x005D2110
     * Slot: 2
     * Demangled: Moho::CAiSteeringImpl::GetWaypoints
     */
    virtual void GetWaypoints() = 0;

    /**
     * Address: 0x005D2170
     * Slot: 3
     * Demangled: Moho::CAiSteeringImpl::GetWaypoint
     */
    virtual void GetWaypoint() = 0;

    /**
     * Address: 0x005D21B0
     * Slot: 4
     * Demangled: Moho::CAiSteeringImpl::IsDone
     */
    virtual void IsDone() = 0;

    /**
     * Address: 0x005D21C0
     * Slot: 5
     * Demangled: Moho::CAiSteeringImpl::GetColInfo
     */
    virtual void GetColInfo() = 0;

    /**
     * Address: 0x005D3B40
     * Slot: 6
     * Demangled: Moho::CAiSteeringImpl::SetCol
     */
    virtual void SetCol() = 0;

    /**
     * Address: 0x005D21D0
     * Slot: 7
     * Demangled: Moho::CAiSteeringImpl::GetPath
     */
    virtual void GetPath() = 0;

    /**
     * Address: 0x005D2390
     * Slot: 8
     * Demangled: Moho::CAiSteeringImpl::CalcAtTopSpeed1
     */
    virtual void CalcAtTopSpeed1() = 0;

    /**
     * Address: 0x005D23E0
     * Slot: 9
     * Demangled: Moho::CAiSteeringImpl::CalcAtTopSpeed2
     */
    virtual void CalcAtTopSpeed2() = 0;

    /**
     * Address: 0x005D2430
     * Slot: 10
     * Demangled: Moho::CAiSteeringImpl::UseTopSpeed
     */
    virtual void UseTopSpeed() = 0;

    /**
     * Address: 0x005D35E0
     * Slot: 11
     * Demangled: Moho::CAiSteeringImpl::Stop
     */
    virtual void Stop() = 0;
  };
} // namespace moho
