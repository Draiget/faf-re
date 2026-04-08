#pragma once

#include <cstddef>
#include <cstdint>

#include "lua/LuaObject.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"

struct lua_State;

namespace moho
{
  class CScrLuaInitForm;
  class Unit;
  class Sim;

  /**
   * VFTABLE: 0x00E219D8
   * COL: 0x00E7B5D4
   */
  class CCollisionManipulator : public IAniManipulator
  {
  public:
    /**
     * Address: 0x00638770 (FUN_00638770, CCollisionManipulatorTypeInfo::newRefFunc_)
     * Address: 0x00638830 (FUN_00638830, CCollisionManipulatorTypeInfo::ctorRefFunc_)
     *
     * What it does:
     * Constructs default collision-manipulator state used by RTTI allocation paths.
     */
    CCollisionManipulator();

    /**
     * Address: 0x00637B70 (FUN_00637B70)
     *
     * What it does:
     * Builds IAniManipulator base state for an owning unit, stores owner pointer,
     * and initializes runtime collision flags.
     */
    CCollisionManipulator(Unit* ownerUnit, Sim* sim);

    /**
     * Address: 0x00637B40 (FUN_00637B40, scalar deleting body)
     * Address: 0x00639030 (FUN_00639030, deleting thunk from CScriptObject view)
     *
     * VFTable SLOT: 0 (primary IAniManipulator/CTaskEvent view)
     */
    ~CCollisionManipulator() override;

    /**
     * Address: 0x00637860 (FUN_00637860, ?GetClass@CCollisionManipulator@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 1 (CScriptObject subobject)
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x00637880 (FUN_00637880, ?GetDerivedObjectRef@CCollisionManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 2 (CScriptObject subobject)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00637C90 (FUN_00637C90)
     *
     * VFTable SLOT: 1 (primary IAniManipulator/CTaskEvent view)
     *
     * What it does:
     * Evaluates watched bones, raising script callbacks for orientation/terrain
     * collision state transitions.
     */
    bool ManipulatorUpdate() override;

    /**
     * Address: 0x00638020 (FUN_00638020, CreateCollisionDetector Lua path)
     *
     * What it does:
     * Allocates and initializes a collision manipulator for the given unit.
     */
    [[nodiscard]]
    static CCollisionManipulator* CreateCollisionDetector(Unit* ownerUnit);

    /**
     * Address: 0x00638190 (FUN_00638190, Lua wrapper path)
     *
     * What it does:
     * Toggles terrain-based collision detection mode.
     */
    void SetTerrainCollisionCheckEnabled(bool enabled) noexcept;

    /**
     * Address: 0x006382D0 (FUN_006382D0, Lua wrapper path)
     *
     * What it does:
     * Enables per-tick collision callback checks.
     */
    void EnableCollisionCallbacks() noexcept;

    /**
     * Address: 0x00638400 (FUN_00638400, Lua wrapper path)
     *
     * What it does:
     * Disables per-tick collision checks and clears one-shot anim-collision bits.
     */
    void DisableCollisionCallbacks() noexcept;

    /**
     * Address: 0x00638540 (FUN_00638540, Lua wrapper path)
     *
     * What it does:
     * Adds one watch-bone binding and returns its index.
     */
    int WatchBone(int boneIndex);

    [[nodiscard]] Unit* GetOwnerUnit() const noexcept;

  public:
    static gpg::RType* sType;

    Unit* mOwnerUnit;                   // +0x80
    bool mCollisionCallbacksEnabled;    // +0x84
    bool mTerrainCollisionCheckEnabled; // +0x85
    std::uint8_t mReserved86[2]{};      // +0x86
  };

  /**
   * VFTABLE: 0x00E21A40
   * COL: 0x00E7B428
   */
  using CreateCollisionDetector_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21A48
   * COL: 0x00E7B3D8
   */
  using CCollisionManipulatorEnableTerrainCheck_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21A50
   * COL: 0x00E7B388
   */
  using CCollisionManipulatorEnable_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21A58
   * COL: 0x00E7B338
   */
  using CCollisionManipulatorDisable_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21A60
   * COL: 0x00E7B2E8
   */
  using CCollisionManipulatorWatchBone_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E219F8
   * COL: 0x00E7B574
   */
  template <>
  class CScrLuaMetatableFactory<CCollisionManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();
    explicit CScrLuaMetatableFactory(std::int32_t factoryObjectIndex);

  protected:
    /**
     * Address: 0x00638640 (FUN_00638640)
     *
     * What it does:
     * Builds the metatable used for `CCollisionManipulator` Lua userdata.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;
  };

  /**
   * VFTABLE: 0x00E21A30
   * COL: 0x00E7B48C
   */
  class CCollisionManipulatorSerializer
  {
  public:
    /**
     * Address: 0x006386E0 (FUN_006386E0, sub_6386E0)
     * Slot: 0
     *
     * What it does:
     * Registers CCollisionManipulator load/save callbacks into RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  /**
   * VFTABLE: 0x00E21A00
   * COL: 0x00E7B524
   */
  class CCollisionManipulatorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006379A0 (FUN_006379A0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CCollisionManipulatorTypeInfo() override;

    /**
     * Address: 0x00637990 (FUN_00637990, ?GetName@CCollisionManipulatorTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00637950 (FUN_00637950, ?Init@CCollisionManipulatorTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CCollisionManipulator`
     * (`sizeof = 0x88`) and registers `IAniManipulator` as base metadata.
     */
    void Init() override;
  };

  static_assert(
    offsetof(CCollisionManipulator, mOwnerUnit) == 0x80, "CCollisionManipulator::mOwnerUnit offset must be 0x80"
  );
  static_assert(
    offsetof(CCollisionManipulator, mCollisionCallbacksEnabled) == 0x84,
    "CCollisionManipulator::mCollisionCallbacksEnabled offset must be 0x84"
  );
  static_assert(
    offsetof(CCollisionManipulator, mTerrainCollisionCheckEnabled) == 0x85,
    "CCollisionManipulator::mTerrainCollisionCheckEnabled offset must be 0x85"
  );
  static_assert(sizeof(CCollisionManipulator) == 0x88, "CCollisionManipulator size must be 0x88");
  static_assert(
    sizeof(CScrLuaMetatableFactory<CCollisionManipulator>) == 0x8,
    "CScrLuaMetatableFactory<CCollisionManipulator> size must be 0x8"
  );
  static_assert(sizeof(CCollisionManipulatorSerializer) == 0x14, "CCollisionManipulatorSerializer size must be 0x14");
  static_assert(sizeof(CCollisionManipulatorTypeInfo) == 0x64, "CCollisionManipulatorTypeInfo size must be 0x64");

  /**
   * Address: 0x00637FA0 (FUN_00637FA0, cfunc_CreateCollisionDetector)
   *
   * What it does:
   * Unwraps the Lua callback context and dispatches the collision-detector
   * constructor binder.
   */
  int cfunc_CreateCollisionDetector(lua_State* luaContext);

  /**
   * Address: 0x00637FC0 (FUN_00637FC0, func_CreateCollisionDetector_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateCollisionDetector(unit)` Lua binder.
   */
  CScrLuaInitForm* func_CreateCollisionDetector_LuaFuncDef();

  /**
   * Address: 0x00638110 (FUN_00638110, cfunc_CCollisionManipulatorEnableTerrainCheck)
   *
   * What it does:
   * Unwraps the Lua callback context and dispatches the terrain-check enable
   * binder.
   */
  int cfunc_CCollisionManipulatorEnableTerrainCheck(lua_State* luaContext);

  /**
   * Address: 0x00638130 (FUN_00638130, func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CCollisionManipulator:EnableTerrainCheck(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef();

  /**
   * Address: 0x00638250 (FUN_00638250, cfunc_CCollisionManipulatorEnable)
   *
   * What it does:
   * Unwraps the Lua callback context and dispatches the collision enable
   * binder.
   */
  int cfunc_CCollisionManipulatorEnable(lua_State* luaContext);

  /**
   * Address: 0x00638270 (FUN_00638270, func_CCollisionManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CCollisionManipulator:Enable()` Lua binder.
   */
  CScrLuaInitForm* func_CCollisionManipulatorEnable_LuaFuncDef();

  /**
   * Address: 0x00638380 (FUN_00638380, cfunc_CCollisionManipulatorDisable)
   *
   * What it does:
   * Unwraps the Lua callback context and dispatches the collision disable
   * binder.
   */
  int cfunc_CCollisionManipulatorDisable(lua_State* luaContext);

  /**
   * Address: 0x006383A0 (FUN_006383A0, func_CCollisionManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CCollisionManipulator:Disable()` Lua binder.
   */
  CScrLuaInitForm* func_CCollisionManipulatorDisable_LuaFuncDef();

  /**
   * Address: 0x006384C0 (FUN_006384C0, cfunc_CCollisionManipulatorWatchBone)
   *
   * What it does:
   * Unwraps the Lua callback context and dispatches the watch-bone binder.
   */
  int cfunc_CCollisionManipulatorWatchBone(lua_State* luaContext);

  /**
   * Address: 0x006384E0 (FUN_006384E0, func_CCollisionManipulatorWatchBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CCollisionManipulator:WatchBone(bone)` Lua binder.
   */
  CScrLuaInitForm* func_CCollisionManipulatorWatchBone_LuaFuncDef();
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00638D50 (FUN_00638D50, gpg::RRef_CCollisionManipulator)
   *
   * What it does:
   * Builds one typed reflection reference for
   * `moho::CCollisionManipulator*`, preserving dynamic-derived ownership and
   * base-offset adjustment.
   */
  gpg::RRef* RRef_CCollisionManipulator(gpg::RRef* outRef, moho::CCollisionManipulator* value);
} // namespace gpg
