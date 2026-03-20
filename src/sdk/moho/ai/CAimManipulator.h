// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  /**
   * VFTABLE: 0x00E213C0
   * COL:  0x00E7AC30
   */
  class CAimManipulator
  {
  public:
    /**
     * Address: 0x00630200
     * Slot: 0
     * Demangled: public: __thiscall Moho::CAniManipulator::operator delete()
     */
    virtual void operator_delete() = 0;

    /**
     * Address: 0x00630DB0
     * Slot: 1
     * Demangled: Moho::CAimManipulator::AimManip
     */
    virtual void AimManip() = 0;
  };

  /**
   * VFTABLE: 0x00E21438
   * COL:  0x00E7A9E8
   */
  using CAimManipulatorSetFiringArc_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21440
   * COL:  0x00E7A998
   */
  using CAimManipulatorSetResetPoseTime_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21448
   * COL:  0x00E7A948
   */
  using CAimManipulatorOnTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21450
   * COL:  0x00E7A8F8
   */
  using CAimManipulatorSetEnabled_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21458
   * COL:  0x00E7A8A8
   */
  using CAimManipulatorGetHeadingPitch_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21460
   * COL:  0x00E7A858
   */
  using CAimManipulatorSetHeadingPitch_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21468
   * COL:  0x00E7A808
   */
  using CAimManipulatorSetAimHeadingOffset_LuaFuncDef = ::moho::CScrLuaBinder;

} // namespace moho
