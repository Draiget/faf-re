// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace LuaPlus { class LuaObject; class LuaState; } // forward decl

namespace moho {
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
class CAimManipulatorSetFiringArc_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E21440
 * COL:  0x00E7A998
 */
class CAimManipulatorSetResetPoseTime_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E21448
 * COL:  0x00E7A948
 */
class CAimManipulatorOnTarget_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E21450
 * COL:  0x00E7A8F8
 */
class CAimManipulatorSetEnabled_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E21458
 * COL:  0x00E7A8A8
 */
class CAimManipulatorGetHeadingPitch_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E21460
 * COL:  0x00E7A858
 */
class CAimManipulatorSetHeadingPitch_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

/**
 * VFTABLE: 0x00E21468
 * COL:  0x00E7A808
 */
class CAimManipulatorSetAimHeadingOffset_LuaFuncDef
{
public:
  /**
   * Address: 0x004CD3A0
   * Slot: 0
   * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
   */
  virtual void Run(LuaPlus::LuaState *) = 0;
};

} // namespace moho
