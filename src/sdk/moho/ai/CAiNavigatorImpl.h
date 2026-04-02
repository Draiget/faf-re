#pragma once

#include <cstddef>
#include <cstdint>

#include "lua/LuaObject.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CTask.h"

namespace moho
{
  class CScrLuaInitForm;
  /**
   * Legacy 4-byte ownership slot between IAiNavigator and CTask subobjects.
   *
   * Evidence:
   * - CAiNavigatorImpl type-info adds CTask base at +0x10 and CScriptObject base at +0x28 (0x005A38E0).
   * - IAiNavigator size is 0x0C (0x005A31F0), so +0x0C..+0x0F is a distinct subobject slot.
   */
  struct CAiNavigatorImplLegacyPadBase
  {
    std::uint32_t mLegacyPadWord{0};
  };
  static_assert(
    sizeof(CAiNavigatorImplLegacyPadBase) == 0x04, "CAiNavigatorImplLegacyPadBase size must be 0x04"
  );

  /**
   * VFTABLE: 0x00E1BF14
   * COL:  0x00E71BD0
   */
  class CAiNavigatorImpl : public IAiNavigator,
                           private CAiNavigatorImplLegacyPadBase,
                           public CTask,
                           public CScriptObject
  {
  public:
    /**
     * Address: 0x005A3550 (FUN_005A3550, default ctor)
     */
    CAiNavigatorImpl();

    /**
     * Address: 0x005A33E0 (FUN_005A33E0, unit ctor)
     */
    explicit CAiNavigatorImpl(Unit* unit);

    /**
     * Address: 0x005A37B0 (FUN_005A37B0, scalar deleting thunk)
     * Address: 0x005A37E0 (FUN_005A37E0, core dtor)
     *
     * VFTable SLOT: 0
     */
    ~CAiNavigatorImpl() override;

    /**
     * Address: 0x005A8C70 (FUN_005A8C70, Moho::CAiNavigatorImpl::MemberDeserialize)
     *
     * What it does:
     * Loads reflected base lanes (`IAiNavigator`, `CScriptObject`, `CTask`)
     * followed by unit pointer, ignore-formation flag, and navigator status.
     */
    static void MemberDeserialize(CAiNavigatorImpl* object, gpg::ReadArchive* archive, int version);

    /**
     * Address: 0x005A8DD0 (FUN_005A8DD0, Moho::CAiNavigatorImpl::MemberSerialize)
     *
     * What it does:
     * Saves reflected base lanes (`IAiNavigator`, `CScriptObject`, `CTask`)
     * followed by unit pointer, ignore-formation flag, and navigator status.
     */
    static void MemberSerialize(const CAiNavigatorImpl* object, gpg::WriteArchive* archive, int version);

    /**
     * Address: 0x005A33A0 (FUN_005A33A0, ?GetClass@CAiNavigatorImpl@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT (`CScriptObject`): 0
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x005A33C0 (FUN_005A33C0, ?GetDerivedObjectRef@CAiNavigatorImpl@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT (`CScriptObject`): 1
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x005A3600 (FUN_005A3600)
     *
     * VFTable SLOT: 1
     */
    [[nodiscard]]
    Unit* GetUnit() override;

    /**
     * Address: 0x005A3750 (FUN_005A3750)
     *
     * VFTable SLOT: 4
     */
    void AbortMove() override;

    /**
     * Address: 0x005A3730 (FUN_005A3730)
     *
     * VFTable SLOT: 5
     */
    void BroadcastResumeTaskEvent() override;

    /**
     * Address: 0x005A37A0 (FUN_005A37A0)
     *
     * VFTable SLOT: 9
     */
    [[nodiscard]]
    EAiNavigatorStatus GetStatus() const override;

    /**
     * Address: 0x005A2D10 (FUN_005A2D10)
     *
     * VFTable SLOT: 16
     */
    void Func1() override;

    /**
     * Address: 0x005A2D20 (FUN_005A2D20)
     *
     * VFTable SLOT: 17
     */
    [[nodiscard]]
    SNavPath* GetNavPath() const override;

    /**
     * Address: 0x005A36F0 (FUN_005A36F0)
     *
     * VFTable SLOT: 18
     */
    void PushStack(LuaPlus::LuaState* luaState) override;

    /**
     * Address: 0x005A3710 (FUN_005A3710)
     *
     * VFTable SLOT: 19
     */
    [[nodiscard]]
    bool NavigatorMakeIdle() override;

  protected:
    /**
     * Address: 0x005A3610 (FUN_005A3610, ?GetMetatable@CAiNavigatorImpl@Moho@@QAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     *
     * What it does:
     * Loads `/lua/sim/Navigator.lua`, resolves `Navigator` table, then falls back
     * to CAiNavigatorImpl Lua metatable factory when needed.
     */
    [[nodiscard]]
    LuaPlus::LuaObject GetMetatable(LuaPlus::LuaState* luaState);

  protected:
    /**
     * Address: 0x005A6C50 (FUN_005A6C50 helper call chain)
     *
     * What it does:
     * Dispatches one event code to all registered navigator listeners.
     */
    void DispatchNavigatorEvent(std::int32_t eventCode);

  public:
    static gpg::RType* sType;

    Unit* mUnit;                     // +0x5C
    std::uint8_t mIgnoreFormation;   // +0x60
    std::uint8_t mPad61[3];          // +0x61
    EAiNavigatorStatus mStatus;      // +0x64
  };

  static_assert(sizeof(CAiNavigatorImpl) == 0x68, "CAiNavigatorImpl size must be 0x68");
  static_assert(offsetof(CAiNavigatorImpl, mUnit) == 0x5C, "CAiNavigatorImpl::mUnit offset must be 0x5C");
  static_assert(
    offsetof(CAiNavigatorImpl, mIgnoreFormation) == 0x60, "CAiNavigatorImpl::mIgnoreFormation offset must be 0x60"
  );
  static_assert(offsetof(CAiNavigatorImpl, mStatus) == 0x64, "CAiNavigatorImpl::mStatus offset must be 0x64");

  /**
   * VFTABLE: 0x00E1C0B8
   * COL:  0x00E71714
   */
  template <>
  class CScrLuaMetatableFactory<CAiNavigatorImpl> final : public CScrLuaObjectFactory
  {
  public:
    /**
     * Address: 0x1001FDE0 (MohoEngine.dll constructor shape)
     */
    CScrLuaMetatableFactory();

    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x005A7310 (FUN_005A7310, ?Create@?$CScrLuaMetatableFactory@VCAiNavigatorImpl@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CAiNavigatorImpl>) == 0x08,
    "CScrLuaMetatableFactory<CAiNavigatorImpl> size must be 0x08"
  );

  /**
   * VFTABLE: 0x00E1C160
   * COL:  0x00E71374
   */
  using CAiNavigatorImplSetGoal_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C168
   * COL:  0x00E71324
   */
  using CAiNavigatorImplSetDestUnit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C170
   * COL:  0x00E712D4
   */
  using CAiNavigatorImplAbortMove_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C178
   * COL:  0x00E71284
   */
  using CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C180
   * COL:  0x00E71234
   */
  using CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C188
   * COL:  0x00E711E4
   */
  using CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C190
   * COL:  0x00E71194
   */
  using CAiNavigatorImplGetGoalPos_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C198
   * COL:  0x00E71144
   */
  using CAiNavigatorImplGetStatus_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C1A0
   * COL:  0x00E710F4
   */
  using CAiNavigatorImplHasGoodPath_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C1A8
   * COL:  0x00E710A4
   */
  using CAiNavigatorImplFollowingLeader_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C1B0
   * COL:  0x00E71054
   */
  using CAiNavigatorImplIgnoreFormation_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C1B8
   * COL:  0x00E71004
   */
  using CAiNavigatorImplIsIgnorningFormation_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C1C0
   * COL:  0x00E70FB4
   */
  using CAiNavigatorImplAtGoal_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E1C1C8
   * COL:  0x00E70F64
   */
  using CAiNavigatorImplCanPathToGoal_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x00BCC760 (FUN_00BCC760)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links it to recovered
   * navigator-Lua anchor lane `off_F59960`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplLuaInitFormAnchor();

  /**
   * Address: 0x00BCC8C0 (FUN_00BCC8C0, register_CAiNavigatorImplSetGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplSetGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplSetGoal_LuaFuncDef();

  /**
   * Address: 0x00BCC8D0 (FUN_00BCC8D0, register_CAiNavigatorImplSetDestUnit_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplSetDestUnit_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplSetDestUnit_LuaFuncDef();

  /**
   * Address: 0x00BCC8E0 (FUN_00BCC8E0, register_CAiNavigatorImplAbortMove_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplAbortMove_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplAbortMove_LuaFuncDef();

  /**
   * Address: 0x00BCC8F0 (FUN_00BCC8F0, register_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef();

  /**
   * Address: 0x00BCC900 (FUN_00BCC900, register_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef();

  /**
   * Address: 0x00BCC910 (FUN_00BCC910, register_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef();

  /**
   * Address: 0x00BCC920 (FUN_00BCC920, register_CAiNavigatorImplGetGoalPos_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplGetGoalPos_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplGetGoalPos_LuaFuncDef();

  /**
   * Address: 0x00BCC930 (FUN_00BCC930, register_CAiNavigatorImplGetStatus_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplGetStatus_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplGetStatus_LuaFuncDef();

  /**
   * Address: 0x00BCC940 (FUN_00BCC940, register_CAiNavigatorImplHasGoodPath_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplHasGoodPath_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplHasGoodPath_LuaFuncDef();

  /**
   * Address: 0x00BCC950 (FUN_00BCC950, register_CAiNavigatorImplFollowingLeader_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplFollowingLeader_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplFollowingLeader_LuaFuncDef();

  /**
   * Address: 0x00BCC960 (FUN_00BCC960, register_CAiNavigatorImplIgnoreFormation_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplIgnoreFormation_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplIgnoreFormation_LuaFuncDef();

  /**
   * Address: 0x00BCC970 (FUN_00BCC970, register_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef();

  /**
   * Address: 0x00BCC980 (FUN_00BCC980, register_CAiNavigatorImplAtGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplAtgoal_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplAtGoal_LuaFuncDef();

  /**
   * Address: 0x00BCC990 (FUN_00BCC990, j_func_CAiNavigatorImplCanPathToGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk to `func_CAiNavigatorImplCanPathToGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiNavigatorImplCanPathToGoal_LuaFuncDef();

  /**
   * Address: 0x00BCC9E0 (FUN_00BCC9E0)
   *
   * What it does:
   * Allocates and stores the startup Lua metatable-factory index for
   * `CScrLuaMetatableFactory<CAiNavigatorImpl>`.
   */
  int register_CScrLuaMetatableFactory_CAiNavigatorImpl_Index();

  /**
   * Address: 0x00BCCA60 (FUN_00BCCA60)
   *
   * What it does:
   * Installs process-exit cleanup for one startup-owned navigator stats slot.
   */
  int register_CAiNavigatorImplStartupCleanup();
} // namespace moho
