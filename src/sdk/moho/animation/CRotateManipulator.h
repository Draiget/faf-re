#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/animation/IAniManipulator.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "Wm3Vector3.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CScrLuaInitForm;
  class CAniActor;
  class Sim;

  /**
   * VFTABLE: 0x00E20E00
   * COL: 0x00E7AD44
   */
  class CRotateManipulator : public IAniManipulator
  {
  public:
    /**
     * Address: 0x00643630 (FUN_00643630)
     *
     * What it does:
     * Builds detached/default rotate-manipulator state for reflection
     * construction paths.
     */
    CRotateManipulator();

    /**
     * Address: 0x006436E0 (FUN_006436E0, ??0CRotateManipulator@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds a rotate manipulator bound to one owner actor/bone with one
     * configured axis lane.
     */
    CRotateManipulator(const Wm3::Vector3f& axis, Sim* sim, CAniActor* ownerActor, int watchedBoneIndex);

    /**
     * Address: 0x00643860 (FUN_00643860, Moho::CRotateManipulator::MoveManipulator)
     *
     * What it does:
     * Advances rotate-manipulator angular lanes (goal/follow/spin-down logic),
     * writes one updated watched-bone quaternion, and updates task signal state.
     */
    bool ManipulatorUpdate() override;

    /**
     * Address: 0x00643CF0 (FUN_00643CF0, Moho::CRotateManipulator::SetCurrentAngle)
     *
     * What it does:
     * Applies one immediate angle to the watched bone and marks that pose lane
     * to skip interpolation on the next frame.
     */
    bool SetCurrentAngle(float angleRadians);

    /**
     * Address: 0x00643400 (FUN_00643400)
     *
     * What it does:
     * Sets spin-down mode flag lane.
     */
    void SetSpinDownEnabled(bool enabled) noexcept;

    /**
     * Address: 0x00643CD0 (FUN_00643CD0)
     *
     * What it does:
     * Updates follow-bone index and marks goal state dirty for next tick.
     */
    void SetFollowBoneTarget(int followBoneIndex) noexcept;

    static gpg::RType* sType;

    std::uint8_t mHasGoal = 0;      // +0x80
    std::uint8_t mSpinDown = 0;     // +0x81
    std::uint8_t mPad82[0x02]{};    // +0x82
    Wm3::Vector3f mAxis{};          // +0x84
    float mCurrentAngle = 0.0f;     // +0x90
    float mGoalAngle = 0.0f;        // +0x94
    float mSpeed = 0.0f;            // +0x98
    float mTargetSpeed = 0.0f;      // +0x9C
    float mAccel = 0.0f;            // +0xA0
    std::int32_t mFollowBone = -1;  // +0xA4
  };

  static_assert(offsetof(CRotateManipulator, mHasGoal) == 0x80, "CRotateManipulator::mHasGoal offset must be 0x80");
  static_assert(offsetof(CRotateManipulator, mSpinDown) == 0x81, "CRotateManipulator::mSpinDown offset must be 0x81");
  static_assert(offsetof(CRotateManipulator, mAxis) == 0x84, "CRotateManipulator::mAxis offset must be 0x84");
  static_assert(
    offsetof(CRotateManipulator, mCurrentAngle) == 0x90, "CRotateManipulator::mCurrentAngle offset must be 0x90"
  );
  static_assert(offsetof(CRotateManipulator, mGoalAngle) == 0x94, "CRotateManipulator::mGoalAngle offset must be 0x94");
  static_assert(offsetof(CRotateManipulator, mSpeed) == 0x98, "CRotateManipulator::mSpeed offset must be 0x98");
  static_assert(
    offsetof(CRotateManipulator, mTargetSpeed) == 0x9C, "CRotateManipulator::mTargetSpeed offset must be 0x9C"
  );
  static_assert(offsetof(CRotateManipulator, mAccel) == 0xA0, "CRotateManipulator::mAccel offset must be 0xA0");
  static_assert(
    offsetof(CRotateManipulator, mFollowBone) == 0xA4, "CRotateManipulator::mFollowBone offset must be 0xA4"
  );
  static_assert(sizeof(CRotateManipulator) == 0xA8, "CRotateManipulator size must be 0xA8");

  class CRotateManipulatorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006434B0 (FUN_006434B0, Moho::CRotateManipulatorTypeInfo::GetName)
     *
     * What it does:
     * Returns the literal type name "CRotateManipulator" for reflection.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00643470 (FUN_00643470, Moho::CRotateManipulatorTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size/callback lanes for `CRotateManipulator`, registers
     * `IAniManipulator` base metadata, then finalizes type initialization.
     */
    void Init() override;

    /**
     * Address: 0x006453A0 (FUN_006453A0, Moho::CRotateManipulatorTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CRotateManipulator`, runs detached default construction,
     * and returns its typed reflection reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00645440 (FUN_00645440, Moho::CRotateManipulatorTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one detached `CRotateManipulator` in caller-owned storage and
     * returns its typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00645420 (FUN_00645420, Moho::CRotateManipulatorTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `CRotateManipulator`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x006454B0 (FUN_006454B0, Moho::CRotateManipulatorTypeInfo::Destruct)
     *
     * What it does:
     * Runs non-deleting in-place destructor logic for `CRotateManipulator`.
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x006454C0 (FUN_006454C0, Moho::CRotateManipulatorTypeInfo::AddBase_IAniManipulator)
     *
     * What it does:
     * Registers `IAniManipulator` as reflected base at offset `0`.
     */
    static void AddBase_IAniManipulator(gpg::RType* typeInfo);

    /**
     * Address: 0x006452C0 (FUN_006452C0)
     *
     * What it does:
     * Installs all reflection lifecycle callbacks on one type-info instance.
     */
    static CRotateManipulatorTypeInfo* ConfigureLifecycleCallbacks(CRotateManipulatorTypeInfo* typeInfo);

    /**
     * Address: 0x00645380 (FUN_00645380)
     *
     * What it does:
     * Installs allocation and placement-construction callback lanes.
     */
    static CRotateManipulatorTypeInfo* ConfigureCtorCallbacks(CRotateManipulatorTypeInfo* typeInfo);

    /**
     * Address: 0x00645390 (FUN_00645390)
     *
     * What it does:
     * Installs deletion and in-place destruction callback lanes.
     */
    static CRotateManipulatorTypeInfo* ConfigureDtorCallbacks(CRotateManipulatorTypeInfo* typeInfo);
  };

  static_assert(sizeof(CRotateManipulatorTypeInfo) == 0x64, "CRotateManipulatorTypeInfo size must be 0x64");

  /**
   * Address: 0x00643D80 (FUN_00643D80, cfunc_CreateRotator)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CreateRotatorL`.
   */
  int cfunc_CreateRotator(lua_State* luaContext);

  /**
   * Address: 0x00643E00 (FUN_00643E00, cfunc_CreateRotatorL)
   *
   * What it does:
   * Builds one `CRotateManipulator` from
   * `(unit, bone, axis, [goal], [speed], [accel], [goalspeed])`.
   */
  int cfunc_CreateRotatorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00643DA0 (FUN_00643DA0, func_CreateRotator_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateRotator(...)` Lua binder.
   */
  CScrLuaInitForm* func_CreateRotator_LuaFuncDef();

  /**
   * Address: 0x006443F0 (FUN_006443F0, cfunc_CRotateManipulatorSetGoal)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CRotateManipulatorSetGoalL`.
   */
  int cfunc_CRotateManipulatorSetGoal(lua_State* luaContext);

  /**
   * Address: 0x00644A80 (FUN_00644A80, cfunc_CRotateManipulatorSetAccel)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CRotateManipulatorSetAccelL`.
   */
  int cfunc_CRotateManipulatorSetAccel(lua_State* luaContext);

  /**
   * Address: 0x00644280 (FUN_00644280, cfunc_CRotateManipulatorSetSpinDown)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CRotateManipulatorSetSpinDownL`.
   */
  int cfunc_CRotateManipulatorSetSpinDown(lua_State* luaContext);
  /**
   * Address: 0x00644470 (FUN_00644470, cfunc_CRotateManipulatorSetGoalL)
   *
   * What it does:
   * Reads `(rotator, goalDegrees)`, validates numeric input, converts to
   * radians, stores goal angle, and updates triggered state.
   */
  int cfunc_CRotateManipulatorSetGoalL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00644300 (FUN_00644300, cfunc_CRotateManipulatorSetSpinDownL)
   *
   * What it does:
   * Reads `(rotator, enabled)`, validates the rotator object, sets spin-down
   * mode, and returns the rotator Lua object.
   */
  int cfunc_CRotateManipulatorSetSpinDownL(LuaPlus::LuaState* state);
  int cfunc_CRotateManipulatorSetSpeed(lua_State* luaContext);

  /**
   * Address: 0x00644790 (FUN_00644790, cfunc_CRotateManipulatorSetSpeedL)
   *
   * What it does:
   * Reads `(rotator, speedDegPerSec)`, validates numeric input, converts to
   * radians/sec, and stores runtime speed lane.
   */
  int cfunc_CRotateManipulatorSetSpeedL(LuaPlus::LuaState* state);
  int cfunc_CRotateManipulatorSetTargetSpeed(lua_State* luaContext);
  /**
   * Address: 0x00644930 (FUN_00644930, cfunc_CRotateManipulatorSetTargetSpeedL)
   *
   * What it does:
   * Reads `(rotator, targetSpeedDegPerSec)`, validates numeric input, converts
   * to radians/sec, stores target speed, and updates triggered state.
   */
  int cfunc_CRotateManipulatorSetTargetSpeedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00644B00 (FUN_00644B00, cfunc_CRotateManipulatorSetAccelL)
   *
   * What it does:
   * Reads `(rotator, accelDegPerSecSq)`, validates numeric input, converts to
   * radians/sec^2, and stores runtime acceleration lane.
   */
  int cfunc_CRotateManipulatorSetAccelL(LuaPlus::LuaState* state);
  int cfunc_CRotateManipulatorClearFollowBone(lua_State* luaContext);

  /**
   * Address: 0x00644CA0 (FUN_00644CA0, cfunc_CRotateManipulatorClearFollowBoneL)
   *
   * What it does:
   * Reads `(rotator)`, clears follow-bone target (`-1`) and marks goal state
   * dirty, then returns the rotator Lua object.
   */
  int cfunc_CRotateManipulatorClearFollowBoneL(LuaPlus::LuaState* state);
  int cfunc_CRotateManipulatorSetFollowBone(lua_State* luaContext);

  /**
   * Address: 0x00644E10 (FUN_00644E10, cfunc_CRotateManipulatorSetFollowBoneL)
   *
   * What it does:
   * Reads `(rotator, bone)`, resolves bone index through owner actor, assigns
   * follow-bone target, and returns the rotator Lua object.
   */
  int cfunc_CRotateManipulatorSetFollowBoneL(LuaPlus::LuaState* state);
  int cfunc_CRotateManipulatorGetCurrentAngle(lua_State* luaContext);

  /**
   * Address: 0x00644FB0 (FUN_00644FB0, cfunc_CRotateManipulatorGetCurrentAngleL)
   *
   * What it does:
   * Reads `(rotator)`, pushes current angle in degrees, and returns one Lua
   * number.
   */
  int cfunc_CRotateManipulatorGetCurrentAngleL(LuaPlus::LuaState* state);
  int cfunc_CRotateManipulatorSetCurrentAngle(lua_State* luaContext);
  /**
   * Address: 0x00645120 (FUN_00645120, cfunc_CRotateManipulatorSetCurrentAngleL)
   *
   * What it does:
   * Reads `(rotator, angleDegrees)`, validates numeric input, converts to
   * radians, applies current-angle lane, and raises Lua error on failure.
   */
  int cfunc_CRotateManipulatorSetCurrentAngleL(LuaPlus::LuaState* state);
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006456F0 (FUN_006456F0, gpg::RRef_CRotateManipulator)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CRotateManipulator*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CRotateManipulator(gpg::RRef* outRef, moho::CRotateManipulator* value);
} // namespace gpg
