#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/animation/IAniManipulator.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "wm3/Quaternion.h"

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CScrLuaInitForm;
  class CAniActor;
  class Sim;
  class CSlaveManipulator : public IAniManipulator
  {
  public:
    /**
     * Address: 0x00646010 (FUN_00646010, ??0CSlaveManipulator@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes a slave manipulator bound to one owner actor, one watched
     * bone, and one source bone index.
     */
    CSlaveManipulator(Sim* sim, CAniActor* ownerActor, int watchedBoneIndex, int sourceBoneIndex);

    /**
     * Address: 0x00646140 (FUN_00646140, Moho::CSlaveManipulator::MoveManipulator)
     *
     * What it does:
     * Updates destination-bone orientation from the configured source bone and
     * marks the task-event signaled state.
     */
    bool ManipulatorUpdate() override;

    static gpg::RType* sType;

    std::int32_t mSourceBoneIndex = -1;  // +0x80
    Wm3::Quaternionf mCurrentRotation{};  // +0x84
    float mMaxRate = -1.0f;               // +0x94
  };

  static_assert(
    offsetof(CSlaveManipulator, mSourceBoneIndex) == 0x80,
    "CSlaveManipulator::mSourceBoneIndex offset must be 0x80"
  );
  static_assert(
    offsetof(CSlaveManipulator, mCurrentRotation) == 0x84,
    "CSlaveManipulator::mCurrentRotation offset must be 0x84"
  );
  static_assert(offsetof(CSlaveManipulator, mMaxRate) == 0x94, "CSlaveManipulator::mMaxRate offset must be 0x94");
  static_assert(sizeof(CSlaveManipulator) == 0x98, "CSlaveManipulator size must be 0x98");

  /**
   * VFTABLE: 0x00E22D60
   * COL: 0x00E7AED4
   */
  using CSlaveManipulatorSetMaxRate_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E22D10
   * COL: 0x00E7AEF4
   */
  template <>
  class CScrLuaMetatableFactory<CSlaveManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00646610 (FUN_00646610, ?Create@?$CScrLuaMetatableFactory@VCSlaveManipulator@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     *
     * What it does:
     * Builds the metatable object used for `CSlaveManipulator` Lua userdata.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CSlaveManipulator>) == 0x8,
    "CScrLuaMetatableFactory<CSlaveManipulator> size must be 0x8"
  );

  /**
   * Address: 0x00646490 (FUN_00646490, cfunc_CSlaveManipulatorSetMaxRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CSlaveManipulatorSetMaxRateL`.
   */
  int cfunc_CSlaveManipulatorSetMaxRate(lua_State* luaContext);

  /**
   * Address: 0x006464B0 (FUN_006464B0, func_CSlaveManipulatorSetMaxRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CSlaveManipulator:SetMaxRate(self, degrees_per_second)` Lua
   * binder.
   */
  CScrLuaInitForm* func_CSlaveManipulatorSetMaxRate_LuaFuncDef();

  /**
   * Address: 0x006462B0 (FUN_006462B0, cfunc_CreateSlaver)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CreateSlaverL`.
   */
  int cfunc_CreateSlaver(lua_State* luaContext);

  /**
   * Address: 0x00646330 (FUN_00646330, cfunc_CreateSlaverL)
   *
   * What it does:
   * Builds one `CSlaveManipulator` from `(unit, dest_bone, src_bone)`.
   */
  int cfunc_CreateSlaverL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006462D0 (FUN_006462D0, func_CreateSlaver_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateSlaver(unit, dest_bone, src_bone)` Lua binder.
   */
  CScrLuaInitForm* func_CreateSlaver_LuaFuncDef();

  /**
   * Address: 0x00646510 (FUN_00646510, cfunc_CSlaveManipulatorSetMaxRateL)
   *
   * What it does:
   * Resolves one `CSlaveManipulator`, converts degrees/second to radians, and
   * updates the manipulator max-rate lane.
   */
  int cfunc_CSlaveManipulatorSetMaxRateL(LuaPlus::LuaState* state);
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00646A90 (FUN_00646A90, gpg::RRef_CSlaveManipulator)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CSlaveManipulator*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CSlaveManipulator(gpg::RRef* outRef, moho::CSlaveManipulator* value);
} // namespace gpg
