#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/animation/IAniManipulator.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "wm3/Vector3.h"

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CScrLuaInitForm;

  /**
   * VFTABLE: 0x00E21730
   * COL: 0x00E7AE5C
   */
  class CSlideManipulator : public IAniManipulator
  {
  public:
    /**
     * Address: 0x006470D0 (FUN_006470D0, ??0CSlideManipulator@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds the slide manipulator, binds Lua userdata, and arms the initial
     * watched bone state.
     */
    CSlideManipulator(Sim* sim, CAniActor* ownerActor, int boneIndex);

    /**
     * Address: 0x00647300 (FUN_00647300, Moho::CSlideManipulator::MoveManipulator)
     *
     * What it does:
     * Advances slide interpolation toward goal, writes pose-space translation,
     * and updates signaled state when the goal is reached.
     */
    bool ManipulatorUpdate() override;

    static gpg::RType* sType;

    Wm3::Vector3f mCurrentPosition{}; // +0x80
    Wm3::Vector3f mGoal{};            // +0x8C
    float mSpeed = 0.0f;              // +0x98
    float mCurrentSpeed = 0.0f;       // +0x9C
    float mAcceleration = 0.0f;       // +0xA0
    float mDeceleration = 0.0f;       // +0xA4
    std::uint8_t mWorldUnits = 0;     // +0xA8
    std::uint8_t mPadA9[0x07]{};      // +0xA9
  };

  static_assert(offsetof(CSlideManipulator, mCurrentPosition) == 0x80, "CSlideManipulator::mCurrentPosition offset must be 0x80");
  static_assert(offsetof(CSlideManipulator, mGoal) == 0x8C, "CSlideManipulator::mGoal offset must be 0x8C");
  static_assert(offsetof(CSlideManipulator, mSpeed) == 0x98, "CSlideManipulator::mSpeed offset must be 0x98");
  static_assert(offsetof(CSlideManipulator, mCurrentSpeed) == 0x9C, "CSlideManipulator::mCurrentSpeed offset must be 0x9C");
  static_assert(offsetof(CSlideManipulator, mAcceleration) == 0xA0, "CSlideManipulator::mAcceleration offset must be 0xA0");
  static_assert(offsetof(CSlideManipulator, mDeceleration) == 0xA4, "CSlideManipulator::mDeceleration offset must be 0xA4");
  static_assert(offsetof(CSlideManipulator, mWorldUnits) == 0xA8, "CSlideManipulator::mWorldUnits offset must be 0xA8");
  static_assert(sizeof(CSlideManipulator) == 0xB0, "CSlideManipulator size must be 0xB0");

  /**
   * VFTABLE: 0x00E217A8
   * COL: 0x00E7AC14
   */
  using CSlideManipulatorSetWorldUnits_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E217B0
   * COL: 0x00E7ABC4
   */
  using CSlideManipulatorSetSpeed_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E217B8
   * COL: 0x00E7AB74
   */
  using CSlideManipulatorSetAcceleration_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E217C0
   * COL: 0x00E7AB24
   */
  using CSlideManipulatorSetDeceleration_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E217C8
   * COL: 0x00E7AAD4
   */
  using CSlideManipulatorSetGoal_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E217D0
   * COL: 0x00E7AA84
   */
  using CSlideManipulatorBeenDestroyed_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21750
   * COL: 0x00E7ADF4
   */
  template <>
  class CScrLuaMetatableFactory<CSlideManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00648420 (FUN_00648420, ?Create@?$CScrLuaMetatableFactory@VCSlideManipulator@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     *
     * What it does:
     * Builds the metatable object used for `CSlideManipulator` Lua userdata.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CSlideManipulator>) == 0x8,
    "CScrLuaMetatableFactory<CSlideManipulator> size must be 0x8"
  );

  /**
   * Address: 0x00647660 (FUN_00647660, cfunc_CreateSlider)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CreateSliderL`.
   */
  int cfunc_CreateSlider(lua_State* luaContext);

  /**
   * Address: 0x006476E0 (FUN_006476E0, cfunc_CreateSliderL)
   *
   * What it does:
   * Builds one `CSlideManipulator` from `(unit, bone, [goal, speed, world])`.
   */
  int cfunc_CreateSliderL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00647680 (FUN_00647680, func_CreateSlider_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateSlider(unit, bone, [goal_x, goal_y, goal_z, [speed, [world_space]]])`
   * Lua binder.
   */
  CScrLuaInitForm* func_CreateSlider_LuaFuncDef();

  /**
   * Address: 0x00647A30 (FUN_00647A30, cfunc_CSlideManipulatorSetWorldUnits)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CSlideManipulatorSetWorldUnitsL`.
   */
  int cfunc_CSlideManipulatorSetWorldUnits(lua_State* luaContext);

  /**
   * Address: 0x00647A50 (FUN_00647A50, func_CSlideManipulatorSetWorldUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CSlideManipulator:SetWorldUnits(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CSlideManipulatorSetWorldUnits_LuaFuncDef();

  /**
   * Address: 0x00647AB0 (FUN_00647AB0, cfunc_CSlideManipulatorSetWorldUnitsL)
   *
   * What it does:
   * Resolves one `CSlideManipulator*` and updates world-vs-bone-space goal mode.
   */
  int cfunc_CSlideManipulatorSetWorldUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00647B80 (FUN_00647B80, cfunc_CSlideManipulatorSetSpeed)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CSlideManipulatorSetSpeedL`.
   */
  int cfunc_CSlideManipulatorSetSpeed(lua_State* luaContext);

  /**
   * Address: 0x00647BA0 (FUN_00647BA0, func_CSlideManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CSlideManipulator:SetSpeed(speed)` Lua binder.
   */
  CScrLuaInitForm* func_CSlideManipulatorSetSpeed_LuaFuncDef();

  /**
   * Address: 0x00647C00 (FUN_00647C00, cfunc_CSlideManipulatorSetSpeedL)
   *
   * What it does:
   * Resolves optional manipulator object and updates slide speed lanes.
   */
  int cfunc_CSlideManipulatorSetSpeedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00647D80 (FUN_00647D80, cfunc_CSlideManipulatorSetAcceleration)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CSlideManipulatorSetAccelerationL`.
   */
  int cfunc_CSlideManipulatorSetAcceleration(lua_State* luaContext);

  /**
   * Address: 0x00647DA0 (FUN_00647DA0, func_CSlideManipulatorSetAcceleration_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CSlideManipulator:SetAcceleration(acc)` Lua binder.
   */
  CScrLuaInitForm* func_CSlideManipulatorSetAcceleration_LuaFuncDef();

  /**
   * Address: 0x00647E00 (FUN_00647E00, cfunc_CSlideManipulatorSetAccelerationL)
   *
   * What it does:
   * Applies non-negative acceleration value to the manipulator runtime lane.
   */
  int cfunc_CSlideManipulatorSetAccelerationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00647F20 (FUN_00647F20, cfunc_CSlideManipulatorSetDeceleration)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CSlideManipulatorSetDecelerationL`.
   */
  int cfunc_CSlideManipulatorSetDeceleration(lua_State* luaContext);

  /**
   * Address: 0x00647F40 (FUN_00647F40, func_CSlideManipulatorSetDeceleration_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CSlideManipulator:SetDeceleration(dec)` Lua binder.
   */
  CScrLuaInitForm* func_CSlideManipulatorSetDeceleration_LuaFuncDef();

  /**
   * Address: 0x00647FA0 (FUN_00647FA0, cfunc_CSlideManipulatorSetDecelerationL)
   *
   * What it does:
   * Applies non-negative deceleration value to the manipulator runtime lane.
   */
  int cfunc_CSlideManipulatorSetDecelerationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006480C0 (FUN_006480C0, cfunc_CSlideManipulatorSetGoal)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CSlideManipulatorSetGoalL`.
   */
  int cfunc_CSlideManipulatorSetGoal(lua_State* luaContext);

  /**
   * Address: 0x006480E0 (FUN_006480E0, func_CSlideManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CSlideManipulator:SetGoal(goal_x, goal_y, goal_z)` Lua binder.
   */
  CScrLuaInitForm* func_CSlideManipulatorSetGoal_LuaFuncDef();

  /**
   * Address: 0x00648140 (FUN_00648140, cfunc_CSlideManipulatorSetGoalL)
   *
   * What it does:
   * Resolves one manipulator and updates its goal vector from `(x,y,z)` args.
   */
  int cfunc_CSlideManipulatorSetGoalL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006482E0 (FUN_006482E0, cfunc_CSlideManipulatorBeenDestroyed)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CSlideManipulatorBeenDestroyedL`.
   */
  int cfunc_CSlideManipulatorBeenDestroyed(lua_State* luaContext);

  /**
   * Address: 0x00648300 (FUN_00648300, func_CSlideManipulatorBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CSlideManipulator:BeenDestroyed()` Lua binder.
   */
  CScrLuaInitForm* func_CSlideManipulatorBeenDestroyed_LuaFuncDef();

  /**
   * Address: 0x00648360 (FUN_00648360, cfunc_CSlideManipulatorBeenDestroyedL)
   *
   * What it does:
   * Returns Lua boolean reporting whether the optional manipulator handle is null.
   */
  int cfunc_CSlideManipulatorBeenDestroyedL(LuaPlus::LuaState* state);
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00648960 (FUN_00648960, gpg::RRef_CSlideManipulator)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CSlideManipulator*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CSlideManipulator(gpg::RRef* outRef, moho::CSlideManipulator* value);
} // namespace gpg
