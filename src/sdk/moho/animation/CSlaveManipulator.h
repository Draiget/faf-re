#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/animation/IAniManipulator.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "Wm3Quaternion.h"

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
     * Address: 0x00645F80 (FUN_00645F80, ??0CSlaveManipulator@Moho@@QAE@XZ)
     *
     * What it does:
     * Builds detached/default slave-manipulator state for reflection
     * construction paths.
     */
    CSlaveManipulator();

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

  class CSlaveManipulatorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00645E00 (FUN_00645E00, Moho::CSlaveManipulatorTypeInfo::GetName)
     *
     * What it does:
     * Returns the literal type name "CSlaveManipulator" for reflection.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00645DC0 (FUN_00645DC0, Moho::CSlaveManipulatorTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size/callback lanes for `CSlaveManipulator`, registers
     * `IAniManipulator` base metadata, then finalizes type initialization.
     */
    void Init() override;

    /**
     * Address: 0x00646740 (FUN_00646740, Moho::CSlaveManipulatorTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CSlaveManipulator`, runs detached default construction,
     * and returns its typed reflection reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x006467E0 (FUN_006467E0, Moho::CSlaveManipulatorTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one detached `CSlaveManipulator` in caller-owned storage and
     * returns its typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x006467C0 (FUN_006467C0, Moho::CSlaveManipulatorTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `CSlaveManipulator`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00646850 (FUN_00646850, Moho::CSlaveManipulatorTypeInfo::Destruct)
     *
     * What it does:
     * Runs non-deleting in-place destructor logic for `CSlaveManipulator`.
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00646860 (FUN_00646860, Moho::CSlaveManipulatorTypeInfo::AddBase_IAniManipulator)
     *
     * What it does:
     * Registers `IAniManipulator` as reflected base at offset `0`.
     */
    static void AddBase_IAniManipulator(gpg::RType* typeInfo);

    /**
     * Address: 0x00646660 (FUN_00646660)
     *
     * What it does:
     * Installs all reflection lifecycle callbacks on one type-info instance.
     */
    static CSlaveManipulatorTypeInfo* ConfigureLifecycleCallbacks(CSlaveManipulatorTypeInfo* typeInfo);

    /**
     * Address: 0x00646720 (FUN_00646720)
     *
     * What it does:
     * Installs allocation and placement-construction callback lanes.
     */
    static CSlaveManipulatorTypeInfo* ConfigureCtorCallbacks(CSlaveManipulatorTypeInfo* typeInfo);

    /**
     * Address: 0x00646730 (FUN_00646730)
     *
     * What it does:
     * Installs deletion and in-place destruction callback lanes.
     */
    static CSlaveManipulatorTypeInfo* ConfigureDtorCallbacks(CSlaveManipulatorTypeInfo* typeInfo);
  };

  static_assert(sizeof(CSlaveManipulatorTypeInfo) == 0x64, "CSlaveManipulatorTypeInfo size must be 0x64");

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
