// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace LuaPlus { class LuaObject; class LuaState; } // forward decl

namespace moho {
  /**
   * VFTABLE: 0x00E1BF14
   * COL:  0x00E71BD0
   */
  class CAiNavigatorImpl
  {
  public:
    /**
     * Address: 0x005A37B0
     * Slot: 0
     * Demangled: sub_5A37B0
     */
    virtual void sub_5A37B0() = 0;

    /**
     * Address: 0x005A3600
     * Slot: 1
     * Demangled: Moho::CAiNavigatorImpl::GetUnit
     */
    virtual void GetUnit() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 2
     * Demangled: _purecall
     */
    virtual void purecall2() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 3
     * Demangled: _purecall
     */
    virtual void purecall3() = 0;

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
     * Address: 0x00A82547
     * Slot: 6
     * Demangled: _purecall
     */
    virtual void purecall6() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 7
     * Demangled: _purecall
     */
    virtual void purecall7() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 8
     * Demangled: _purecall
     */
    virtual void purecall8() = 0;

    /**
     * Address: 0x005A37A0
     * Slot: 9
     * Demangled: Moho::CAiNavigatorImpl::GetStatus
     */
    virtual void GetStatus() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 10
     * Demangled: _purecall
     */
    virtual void purecall10() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 11
     * Demangled: _purecall
     */
    virtual void purecall11() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 12
     * Demangled: _purecall
     */
    virtual void purecall12() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 13
     * Demangled: _purecall
     */
    virtual void purecall13() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 14
     * Demangled: _purecall
     */
    virtual void purecall14() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 15
     * Demangled: _purecall
     */
    virtual void purecall15() = 0;

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

/**
 * VFTABLE: 0x00E1C160
 * COL:  0x00E71374
 */
class CAiNavigatorImplSetGoal_LuaFuncDef
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
 * VFTABLE: 0x00E1C168
 * COL:  0x00E71324
 */
class CAiNavigatorImplSetDestUnit_LuaFuncDef
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
 * VFTABLE: 0x00E1C170
 * COL:  0x00E712D4
 */
class CAiNavigatorImplAbortMove_LuaFuncDef
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
 * VFTABLE: 0x00E1C178
 * COL:  0x00E71284
 */
class CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef
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
 * VFTABLE: 0x00E1C180
 * COL:  0x00E71234
 */
class CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef
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
 * VFTABLE: 0x00E1C188
 * COL:  0x00E711E4
 */
class CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef
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
 * VFTABLE: 0x00E1C190
 * COL:  0x00E71194
 */
class CAiNavigatorImplGetGoalPos_LuaFuncDef
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
 * VFTABLE: 0x00E1C198
 * COL:  0x00E71144
 */
class CAiNavigatorImplGetStatus_LuaFuncDef
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
 * VFTABLE: 0x00E1C1A0
 * COL:  0x00E710F4
 */
class CAiNavigatorImplHasGoodPath_LuaFuncDef
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
 * VFTABLE: 0x00E1C1A8
 * COL:  0x00E710A4
 */
class CAiNavigatorImplFollowingLeader_LuaFuncDef
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
 * VFTABLE: 0x00E1C1B0
 * COL:  0x00E71054
 */
class CAiNavigatorImplIgnoreFormation_LuaFuncDef
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
 * VFTABLE: 0x00E1C1B8
 * COL:  0x00E71004
 */
class CAiNavigatorImplIsIgnorningFormation_LuaFuncDef
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
 * VFTABLE: 0x00E1C1C0
 * COL:  0x00E70FB4
 */
class CAiNavigatorImplAtGoal_LuaFuncDef
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
 * VFTABLE: 0x00E1C1C8
 * COL:  0x00E70F64
 */
class CAiNavigatorImplCanPathToGoal_LuaFuncDef
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
