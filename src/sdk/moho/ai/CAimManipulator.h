// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "wm3/Vector3.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CAniPoseBone;
  class CScrLuaInitForm;

  /**
   * Address: 0x010A6396 (?dbg_Ballistics@Moho@@3_NA)
   *
   * What it does:
   * Global debug toggle for ballistic aim diagnostics.
   */
  extern bool dbg_Ballistics;

  struct CAimFiringArc
  {
    float mMinHeading;     // +0x00
    float mMaxHeading;     // +0x04
    float mHeadingMaxSlew; // +0x08
    float mMinPitch;       // +0x0C
    float mMaxPitch;       // +0x10
    float mPitchMaxSlew;   // +0x14
  };

  static_assert(offsetof(CAimFiringArc, mMinHeading) == 0x00, "CAimFiringArc::mMinHeading offset must be 0x00");
  static_assert(offsetof(CAimFiringArc, mMaxHeading) == 0x04, "CAimFiringArc::mMaxHeading offset must be 0x04");
  static_assert(
    offsetof(CAimFiringArc, mHeadingMaxSlew) == 0x08, "CAimFiringArc::mHeadingMaxSlew offset must be 0x08"
  );
  static_assert(offsetof(CAimFiringArc, mMinPitch) == 0x0C, "CAimFiringArc::mMinPitch offset must be 0x0C");
  static_assert(offsetof(CAimFiringArc, mMaxPitch) == 0x10, "CAimFiringArc::mMaxPitch offset must be 0x10");
  static_assert(
    offsetof(CAimFiringArc, mPitchMaxSlew) == 0x14, "CAimFiringArc::mPitchMaxSlew offset must be 0x14"
  );
  static_assert(sizeof(CAimFiringArc) == 0x18, "CAimFiringArc size must be 0x18");

  /**
   * VFTABLE: 0x00E213C0
   * COL:  0x00E7AC30
   */
  class CAimManipulator
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0062FDF0 (FUN_0062FDF0, Moho::CAimManipulator::StaticGetClass)
     *
     * What it does:
     * Returns cached reflection type for `CAimManipulator`, resolving it from
     * RTTI on first use.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x0062FE10 (FUN_0062FE10, Moho::CAimManipulator::GetClass)
     *
     * What it does:
     * Returns cached reflection type for this object view.
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x0062FE30 (FUN_0062FE30, Moho::CAimManipulator::GetDerivedObjectRef)
     *
     * What it does:
     * Builds one reflected object reference for this manipulator instance.
     */
    [[nodiscard]] gpg::RRef GetDerivedObjectRef();

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

    /**
     * Address: 0x00630CB0 (FUN_00630CB0, Moho::CAimManipulator::SetFiringArc)
     *
     * What it does:
     * Stores centered heading/pitch arc lanes and corresponding half-range
     * extents for runtime aiming.
     */
    void SetFiringArc(CAimFiringArc arc);

  private:
    /**
     * Address: 0x00630760 (FUN_00630760, Moho::CAimManipulator::Track)
     *
     * What it does:
     * Updates heading/pitch tracking lanes for one target direction and sends
     * start/stop tracking script callbacks based on aim state transitions.
     */
    [[nodiscard]] bool Track(const Wm3::Vector3f& targetDirection, std::uint8_t trackingModeFlags);

    /**
     * Address: 0x006309F0 (FUN_006309F0, Moho::CAimManipulator::CheckTracking)
     *
     * What it does:
     * Computes one heading/pitch tracking step against one watched pose bone,
     * clamps slew/arc lanes, and returns tracking-state bit flags.
     */
    [[nodiscard]] std::uint8_t CheckTracking(
      const Wm3::Vector3f& targetDirection,
      CAniPoseBone* watchBone,
      float minAngleCenter,
      float maxAngleHalfRange,
      float maxAngleSlew,
      float tolerance,
      std::uint8_t trackingModeFlags
    );

    /**
     * Address: 0x00631190 (FUN_00631190, Moho::CAimManipulator::Rotate1)
     *
     * What it does:
     * Applies first-axis (heading) bone rotation using tracked quaternion lane.
     */
    void Rotate1(bool reset);

    /**
     * Address: 0x00631220 (FUN_00631220, Moho::CAimManipulator::Rotate2)
     *
     * What it does:
     * Applies second-axis (pitch) bone rotation using tracked quaternion lane.
     */
    void Rotate2(bool reset);
  };

  template <>
  class CScrLuaMetatableFactory<CAimManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00632C40 (FUN_00632C40)
     * Mangled: ?Create@?$CScrLuaMetatableFactory@VCAimManipulator@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z
     *
     * What it does:
     * Creates the `CAimManipulator` Lua metatable through
     * `SCR_CreateSimpleMetatable`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CAimManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CAimManipulator> size must be 0x8"
  );

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
   * Address: 0x00632140 (FUN_00632140, cfunc_CAimManipulatorSetFiringArc)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAimManipulatorSetFiringArcL`.
   */
  int cfunc_CAimManipulatorSetFiringArc(lua_State* luaContext);

  /**
   * Address: 0x00632160 (FUN_00632160, func_CAimManipulatorSetFiringArc_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAimManipulator:SetFiringArc(...)` Lua binder.
   */
  CScrLuaInitForm* func_CAimManipulatorSetFiringArc_LuaFuncDef();

  /**
   * Address: 0x006321C0 (FUN_006321C0, cfunc_CAimManipulatorSetFiringArcL)
   *
   * What it does:
   * Reads six angle/slew values from Lua, converts to radians/runtime units,
   * and applies them through `CAimManipulator::SetFiringArc`.
   */
  int cfunc_CAimManipulatorSetFiringArcL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00632340 (FUN_00632340, cfunc_CAimManipulatorSetResetPoseTime)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAimManipulatorSetResetPoseTimeL`.
   */
  int cfunc_CAimManipulatorSetResetPoseTime(lua_State* luaContext);

  /**
   * Address: 0x00632360 (FUN_00632360, func_CAimManipulatorSetResetPoseTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAimManipulator:SetResetPoseTime(resetTime)` Lua binder.
   */
  CScrLuaInitForm* func_CAimManipulatorSetResetPoseTime_LuaFuncDef();

  /**
   * Address: 0x006323C0 (FUN_006323C0, cfunc_CAimManipulatorSetResetPoseTimeL)
   *
   * What it does:
   * Resolves one `CAimManipulator*` and stores reset-pose time in simulation
   * ticks (`seconds * 10`).
   */
  int cfunc_CAimManipulatorSetResetPoseTimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006324B0 (FUN_006324B0, cfunc_CAimManipulatorOnTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAimManipulatorOnTargetL`.
   */
  int cfunc_CAimManipulatorOnTarget(lua_State* luaContext);

  /**
   * Address: 0x006324D0 (FUN_006324D0, func_CAimManipulatorOnTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAimManipulator:OnTarget()` Lua binder.
   */
  CScrLuaInitForm* func_CAimManipulatorOnTarget_LuaFuncDef();

  /**
   * Address: 0x00632530 (FUN_00632530, cfunc_CAimManipulatorOnTargetL)
   *
   * What it does:
   * Resolves one `CAimManipulator*` and returns its on-target flag to Lua.
   */
  int cfunc_CAimManipulatorOnTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006325F0 (FUN_006325F0, cfunc_CAimManipulatorSetEnabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAimManipulatorSetEnabledL`.
   */
  int cfunc_CAimManipulatorSetEnabled(lua_State* luaContext);

  /**
   * Address: 0x00632610 (FUN_00632610, func_CAimManipulatorSetEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAimManipulator:SetEnabled(flag)` Lua binder.
   */
  CScrLuaInitForm* func_CAimManipulatorSetEnabled_LuaFuncDef();

  /**
   * Address: 0x00632670 (FUN_00632670, cfunc_CAimManipulatorSetEnabledL)
   *
   * What it does:
   * Resolves one `CAimManipulator*`, writes enabled state, and clears the
   * on-target latch.
   */
  int cfunc_CAimManipulatorSetEnabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00632730 (FUN_00632730, cfunc_CAimManipulatorGetHeadingPitch)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAimManipulatorGetHeadingPitchL`.
   */
  int cfunc_CAimManipulatorGetHeadingPitch(lua_State* luaContext);

  /**
   * Address: 0x00632750 (FUN_00632750, func_CAimManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAimManipulator:GetHeadingPitch()` Lua binder.
   */
  CScrLuaInitForm* func_CAimManipulatorGetHeadingPitch_LuaFuncDef();

  /**
   * Address: 0x006327B0 (FUN_006327B0, cfunc_CAimManipulatorGetHeadingPitchL)
   *
   * What it does:
   * Resolves one `CAimManipulator*` and pushes heading/pitch to Lua.
   */
  int cfunc_CAimManipulatorGetHeadingPitchL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00632890 (FUN_00632890, cfunc_CAimManipulatorSetHeadingPitch)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAimManipulatorSetHeadingPitchL`.
   */
  int cfunc_CAimManipulatorSetHeadingPitch(lua_State* luaContext);

  /**
   * Address: 0x006328B0 (FUN_006328B0, func_CAimManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAimManipulator:SetHeadingPitch(heading, pitch)` Lua binder.
   */
  CScrLuaInitForm* func_CAimManipulatorSetHeadingPitch_LuaFuncDef();

  /**
   * Address: 0x00632910 (FUN_00632910, cfunc_CAimManipulatorSetHeadingPitchL)
   *
   * What it does:
   * Validates Lua args `(self, heading, pitch)`, resolves one
   * `CAimManipulator*`, and writes heading/pitch lanes.
   */
  int cfunc_CAimManipulatorSetHeadingPitchL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E21468
   * COL:  0x00E7A808
   */
  using CAimManipulatorSetAimHeadingOffset_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x00632A40 (FUN_00632A40, cfunc_CAimManipulatorSetAimHeadingOffset)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAimManipulatorSetAimHeadingOffsetL`.
   */
  int cfunc_CAimManipulatorSetAimHeadingOffset(lua_State* luaContext);

  /**
   * Address: 0x00632A60 (FUN_00632A60, func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAimManipulator:SetAimHeadingOffset(offset)` Lua binder.
   */
  CScrLuaInitForm* func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef();

  /**
   * Address: 0x00632AC0 (FUN_00632AC0, cfunc_CAimManipulatorSetAimHeadingOffsetL)
   *
   * What it does:
   * Resolves one `CAimManipulator*` and stores heading-offset radians.
   */
  int cfunc_CAimManipulatorSetAimHeadingOffsetL(LuaPlus::LuaState* state);

} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00633580 (FUN_00633580, gpg::RRef_CAimManipulator)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CAimManipulator*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CAimManipulator(gpg::RRef* outRef, moho::CAimManipulator* value);
} // namespace gpg
