// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/lua/CScrLuaBinderFwd.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  /**
   * Address: 0x010A6396 (?dbg_Ballistics@Moho@@3_NA)
   *
   * What it does:
   * Global debug toggle for ballistic aim diagnostics.
   */
  extern bool dbg_Ballistics;

  /**
   * VFTABLE: 0x00E213C0
   * COL:  0x00E7AC30
   */
  class CAimManipulator
  {
  public:
    static gpg::RType* sType;

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

    /**
     * Address: 0x00633730 (FUN_00633730, Moho::CAimManipulator::MemberDeserialize)
     *
     * What it does:
     * Loads serialized `CAimManipulator` member lanes from archive state.
     */
    static void MemberDeserialize(CAimManipulator* object, gpg::ReadArchive* archive);

    /**
     * Address: 0x006339D0 (FUN_006339D0, Moho::CAimManipulator::MemberSerialize)
     *
     * What it does:
     * Saves serialized `CAimManipulator` member lanes into archive state.
     */
    static void MemberSerialize(const CAimManipulator* object, gpg::WriteArchive* archive);
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
