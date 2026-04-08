#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/containers/BitStorage32.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace gpg
{
  class SerConstructResult;
}

namespace moho
{
  class CScrLuaInitForm;
  class Unit;

  using SAniManipBitStorage = SBitStorage32;

  struct SAniManipOwnerLink
  {
    SAniManipOwnerLink** mPrevSlot; // +0x00
    SAniManipOwnerLink* mNext;      // +0x04
  };

  static_assert(sizeof(SAniManipOwnerLink) == 0x08, "SAniManipOwnerLink size must be 0x08");

  class CAnimationManipulator : public IAniManipulator
  {
  public:
    using AnimationResourceRef = boost::SharedPtrRaw<void>;

    /**
     * Address: 0x0063F380 (FUN_0063F380, ??0CAnimationManipulator@Moho@@QAE@XZ)
     *
     * What it does:
     * Builds IAniManipulator base state and initializes owner-link, bone-mask,
     * animation-resource, playback-rate, and runtime flags.
     */
    CAnimationManipulator();

    /**
     * Address context:
     * - constructor lane used by `cfunc_CreateAnimatorL` (`FUN_00640530`).
     *
     * What it does:
     * Builds an animation manipulator bound to one sim/actor owner pair,
     * optionally stores one goal-motion unit weak ref, and creates Lua userdata.
     */
    CAnimationManipulator(Sim* sim, CAniActor* ownerActor, Unit* goalMotionScaleUnit);

    /**
     * Address: 0x0063F440 (FUN_0063F440, scalar deleting destructor thunk)
     * Address: 0x0063F8D0 (FUN_0063F8D0, ??1CAnimationManipulator@Moho@@UAE@XZ)
     *
     * VFTable SLOT: 0 (primary CTaskEvent/CScriptEvent view)
     */
    ~CAnimationManipulator() override;

    /**
     * Address: 0x0063EEE0 (FUN_0063EEE0, ?GetClass@CAnimationManipulator@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 1 (CScriptObject subobject)
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0063EF00 (FUN_0063EF00, ?GetDerivedObjectRef@CAnimationManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 2 (CScriptObject subobject)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0063FDD0 (FUN_0063FDD0, CAnimationManipulator::ManipulatorUpdate)
     *
     * VFTable SLOT: 1 (primary CTaskEvent/CScriptEvent view)
     */
    bool ManipulatorUpdate() override;

    /**
     * Address: 0x0063F9E0 (FUN_0063F9E0)
     */
    void SetAnimationFraction(float fraction);

    /**
     * Address: 0x0063FA90 (FUN_0063FA90)
     */
    void SetAnimationTime(float timeSeconds);

    /**
     * Address: 0x0063FB10 (FUN_0063FB10)
     */
    bool UpdateTriggeredState();

    /**
     * Address: 0x0063FBA0 (FUN_0063FBA0)
     */
    void SetAnimationResource(const AnimationResourceRef& resource, bool looping);

    /**
     * Address: 0x006412C0 (FUN_006412C0)
     */
    void SetBoneEnabled(std::int32_t boneIndex, bool includeDescendants, bool enabled);

    [[nodiscard]] float GetRate() const noexcept;
    void SetRate(float rate);
    [[nodiscard]] float GetAnimationFraction() const;
    [[nodiscard]] float GetAnimationTime() const noexcept;
    [[nodiscard]] float GetAnimationDuration() const;
    void SetOverwriteMode(bool enabled) noexcept;
    void SetDisableOnSignal(bool enabled) noexcept;
    void SetDirectionalAnim(bool enabled) noexcept;

    void InitializeBoneMask(std::uint32_t boneCount);

  public:
    static gpg::RType* sType;

    SAniManipOwnerLink mOwnerLink;      // +0x80
    SAniManipBitStorage mBoneMask;      // +0x88
    AnimationResourceRef mAnimationRef; // +0x9C
    float mRate;                        // +0xA4
    float mAnimationTime;               // +0xA8
    float mLastFramePosition;           // +0xAC
    bool mLooping;                      // +0xB0
    bool mFrameChanged;                 // +0xB1
    bool mIgnoreMotionScaling;          // +0xB2
    bool mOverwriteMode;                // +0xB3
    bool mDisableOnSignal;              // +0xB4
    bool mDirectionalAnim;              // +0xB5
    std::uint8_t mReservedB6[2]{};      // +0xB6
  };

  using CAnimationManipulatorPlayAnim_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorGetRate_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetRate_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorGetAnimationFraction_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetAnimationFraction_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorGetAnimationTime_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetAnimationTime_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorGetAnimationDuration_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetBoneEnabled_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetOverwriteMode_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetDisableOnSignal_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetDirectionalAnim_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E21770
   * COL: 0x00E7AD54
   */
  template <>
  class CScrLuaMetatableFactory<CAnimationManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00641E10 (FUN_00641E10, ?Create@?$CScrLuaMetatableFactory@VCAnimationManipulator@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     *
     * What it does:
     * Builds the metatable object used for `CAnimationManipulator` Lua userdata.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CAnimationManipulator>) == 0x8,
    "CScrLuaMetatableFactory<CAnimationManipulator> size must be 0x8"
  );

  /**
   * Address: 0x006404B0 (FUN_006404B0, cfunc_CreateAnimator)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CreateAnimatorL`.
   */
  int cfunc_CreateAnimator(lua_State* luaContext);

  /**
   * Address: 0x006404D0 (FUN_006404D0, func_CreateAnimator_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateAnimator(unit, [bindGoalUnit])` Lua binder.
   */
  CScrLuaInitForm* func_CreateAnimator_LuaFuncDef();

  /**
   * Address: 0x00640530 (FUN_00640530, cfunc_CreateAnimatorL)
   *
   * What it does:
   * Reads `(unit, [bool])`, creates one animation manipulator, and returns it
   * as Lua userdata.
   */
  int cfunc_CreateAnimatorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00640A20 (FUN_00640A20, cfunc_CAnimationManipulatorSetRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetRateL`.
   */
  int cfunc_CAnimationManipulatorSetRate(lua_State* luaContext);

  /**
   * Address: 0x00640A40 (FUN_00640A40, func_CAnimationManipulatorSetRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetRate(rate)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetRate_LuaFuncDef();

  /**
   * Address: 0x00640AA0 (FUN_00640AA0, cfunc_CAnimationManipulatorSetRateL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and updates its playback rate.
   */
  int cfunc_CAnimationManipulatorSetRateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006408E0 (FUN_006408E0, cfunc_CAnimationManipulatorGetRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorGetRateL`.
   */
  int cfunc_CAnimationManipulatorGetRate(lua_State* luaContext);

  /**
   * Address: 0x00640900 (FUN_00640900, func_CAnimationManipulatorGetRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:GetRate()` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorGetRate_LuaFuncDef();

  /**
   * Address: 0x00640960 (FUN_00640960, cfunc_CAnimationManipulatorGetRateL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and returns current playback
   * rate.
   */
  int cfunc_CAnimationManipulatorGetRateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00640BA0 (FUN_00640BA0, cfunc_CAnimationManipulatorGetAnimationFraction)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorGetAnimationFractionL`.
   */
  int cfunc_CAnimationManipulatorGetAnimationFraction(lua_State* luaContext);

  /**
   * Address: 0x00640BC0 (FUN_00640BC0, func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:GetAnimationFraction()` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef();

  /**
   * Address: 0x00640C20 (FUN_00640C20, cfunc_CAnimationManipulatorGetAnimationFractionL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and returns normalized
   * animation progress.
   */
  int cfunc_CAnimationManipulatorGetAnimationFractionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00640D10 (FUN_00640D10, cfunc_CAnimationManipulatorSetAnimationFraction)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetAnimationFractionL`.
   */
  int cfunc_CAnimationManipulatorSetAnimationFraction(lua_State* luaContext);

  /**
   * Address: 0x00640D30 (FUN_00640D30, func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetAnimationFraction(fraction)` Lua
   * binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef();

  /**
   * Address: 0x00640D90 (FUN_00640D90, cfunc_CAnimationManipulatorSetAnimationFractionL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua, clamps fraction into `[0, 1]`
   * and applies the new playback position.
   */
  int cfunc_CAnimationManipulatorSetAnimationFractionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00640EB0 (FUN_00640EB0, cfunc_CAnimationManipulatorGetAnimationTime)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorGetAnimationTimeL`.
   */
  int cfunc_CAnimationManipulatorGetAnimationTime(lua_State* luaContext);

  /**
   * Address: 0x00640ED0 (FUN_00640ED0, func_CAnimationManipulatorGetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:GetAnimationTime()` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorGetAnimationTime_LuaFuncDef();

  /**
   * Address: 0x00640F30 (FUN_00640F30, cfunc_CAnimationManipulatorGetAnimationTimeL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and returns current animation
   * time in seconds.
   */
  int cfunc_CAnimationManipulatorGetAnimationTimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00640FF0 (FUN_00640FF0, cfunc_CAnimationManipulatorSetAnimationTime)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetAnimationTimeL`.
   */
  int cfunc_CAnimationManipulatorSetAnimationTime(lua_State* luaContext);

  /**
   * Address: 0x00641010 (FUN_00641010, func_CAnimationManipulatorSetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetAnimationTime(fraction)` Lua
   * binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetAnimationTime_LuaFuncDef();

  /**
   * Address: 0x00641070 (FUN_00641070, cfunc_CAnimationManipulatorSetAnimationTimeL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and applies the requested
   * absolute animation time.
   */
  int cfunc_CAnimationManipulatorSetAnimationTimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00641160 (FUN_00641160, cfunc_CAnimationManipulatorGetAnimationDuration)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorGetAnimationDurationL`.
   */
  int cfunc_CAnimationManipulatorGetAnimationDuration(lua_State* luaContext);

  /**
   * Address: 0x00641180 (FUN_00641180, func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:GetAnimationDuration()` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef();

  /**
   * Address: 0x006411E0 (FUN_006411E0, cfunc_CAnimationManipulatorGetAnimationDurationL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and returns clip duration in
   * seconds.
   */
  int cfunc_CAnimationManipulatorGetAnimationDurationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006415F0 (FUN_006415F0, cfunc_CAnimationManipulatorSetBoneEnabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetBoneEnabledL`.
   */
  int cfunc_CAnimationManipulatorSetBoneEnabled(lua_State* luaContext);

  /**
   * Address: 0x00641610 (FUN_00641610, func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes the
   * `CAnimationManipulator:SetBoneEnabled(bone, value, include_decscendants=true)`
   * Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef();

  /**
   * Address: 0x00641670 (FUN_00641670, cfunc_CAnimationManipulatorSetBoneEnabledL)
   *
   * What it does:
   * Resolves one animation manipulator, one bone selector (name/index), and
   * enable flags from Lua, then toggles the bone lane.
   */
  int cfunc_CAnimationManipulatorSetBoneEnabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006417B0 (FUN_006417B0, cfunc_CAnimationManipulatorSetOverwriteMode)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetOverwriteModeL`.
   */
  int cfunc_CAnimationManipulatorSetOverwriteMode(lua_State* luaContext);

  /**
   * Address: 0x006417D0 (FUN_006417D0, func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetOverwriteMode(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef();

  /**
   * Address: 0x00641830 (FUN_00641830, cfunc_CAnimationManipulatorSetOverwriteModeL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and updates overwrite-mode
   * behavior.
   */
  int cfunc_CAnimationManipulatorSetOverwriteModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006418F0 (FUN_006418F0, cfunc_CAnimationManipulatorSetDisableOnSignal)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetDisableOnSignalL`.
   */
  int cfunc_CAnimationManipulatorSetDisableOnSignal(lua_State* luaContext);

  /**
   * Address: 0x00641910 (FUN_00641910, func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetDisableOnSignal(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef();

  /**
   * Address: 0x00641970 (FUN_00641970, cfunc_CAnimationManipulatorSetDisableOnSignalL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and updates disable-on-signal
   * behavior.
   */
  int cfunc_CAnimationManipulatorSetDisableOnSignalL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00641A30 (FUN_00641A30, cfunc_CAnimationManipulatorSetDirectionalAnim)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetDirectionalAnimL`.
   */
  int cfunc_CAnimationManipulatorSetDirectionalAnim(lua_State* luaContext);

  /**
   * Address: 0x00641A50 (FUN_00641A50, func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetDirectionalAnim(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef();

  /**
   * Address: 0x00641AB0 (FUN_00641AB0, cfunc_CAnimationManipulatorSetDirectionalAnimL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and updates directional
   * animation behavior.
   */
  int cfunc_CAnimationManipulatorSetDirectionalAnimL(LuaPlus::LuaState* state);

  class CAnimationManipulatorConstruct
  {
  public:
    /**
     * Address: 0x0063F220 (FUN_0063F220, Moho::CAnimationManipulatorConstruct::Construct)
     *
     * What it does:
     * Allocates one `CAnimationManipulator`, runs constructor setup, and
     * returns an unowned reflected reference through `SerConstructResult`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectStorage, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x00642340 (FUN_00642340, Moho::CAnimationManipulatorConstruct::Deconstruct)
     *
     * What it does:
     * Runs deleting-dtor teardown for one constructed `CAnimationManipulator`.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x00641E70 (FUN_00641E70, sub_641E70)
     * Slot: 0
     *
     * What it does:
     * Installs serialization-construct and delete callbacks into
     * CAnimationManipulator RTTI descriptor.
     */
    virtual void RegisterConstructFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  class CAnimationManipulatorSerializer
  {
  public:
    /**
     * Address: 0x0063F2C0 (FUN_0063F2C0, Moho::CAnimationManipulatorSerializer::Deserialize)
     *
     * What it does:
     * Loads `CAnimationManipulator` serialization payload (base IAniManipulator
     * lane, goal-link lane, bit-mask lane, shared animation resource, and
     * playback/flag scalars) into an existing object.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0063F2D0 (FUN_0063F2D0, Moho::CAnimationManipulatorSerializer::Serialize)
     *
     * What it does:
     * Saves `CAnimationManipulator` serialization payload (base IAniManipulator
     * lane, goal-link lane, bit-mask lane, shared animation resource, and
     * playback/flag scalars) from an existing object.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00641EF0 (FUN_00641EF0, sub_641EF0)
     * Slot: 0
     *
     * What it does:
     * Installs CAnimationManipulator load/save callbacks into RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CAnimationManipulatorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0063F0E0 (FUN_0063F0E0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CAnimationManipulatorTypeInfo() override;

    /**
     * Address: 0x0063F0D0 (FUN_0063F0D0, ?GetName@CAnimationManipulatorTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0063F0A0 (FUN_0063F0A0, ?Init@CAnimationManipulatorTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CAnimationManipulator`
     * (`sizeof = 0xB8`) and registers `IAniManipulator` as base metadata.
     */
    void Init() override;
  };

  static_assert(
    offsetof(CAnimationManipulator, mOwnerLink) == 0x80, "CAnimationManipulator::mOwnerLink offset must be 0x80"
  );
  static_assert(
    offsetof(CAnimationManipulator, mBoneMask) == 0x88, "CAnimationManipulator::mBoneMask offset must be 0x88"
  );
  static_assert(
    offsetof(CAnimationManipulator, mAnimationRef) == 0x9C, "CAnimationManipulator::mAnimationRef offset must be 0x9C"
  );
  static_assert(offsetof(CAnimationManipulator, mRate) == 0xA4, "CAnimationManipulator::mRate offset must be 0xA4");
  static_assert(
    offsetof(CAnimationManipulator, mAnimationTime) == 0xA8, "CAnimationManipulator::mAnimationTime offset must be 0xA8"
  );
  static_assert(
    offsetof(CAnimationManipulator, mLastFramePosition) == 0xAC,
    "CAnimationManipulator::mLastFramePosition offset must be 0xAC"
  );
  static_assert(
    offsetof(CAnimationManipulator, mLooping) == 0xB0, "CAnimationManipulator::mLooping offset must be 0xB0"
  );
  static_assert(
    offsetof(CAnimationManipulator, mOverwriteMode) == 0xB3, "CAnimationManipulator::mOverwriteMode offset must be 0xB3"
  );
  static_assert(
    offsetof(CAnimationManipulator, mDisableOnSignal) == 0xB4,
    "CAnimationManipulator::mDisableOnSignal offset must be 0xB4"
  );
  static_assert(
    offsetof(CAnimationManipulator, mDirectionalAnim) == 0xB5,
    "CAnimationManipulator::mDirectionalAnim offset must be 0xB5"
  );
  static_assert(sizeof(CAnimationManipulator) == 0xB8, "CAnimationManipulator size must be 0xB8");
  static_assert(sizeof(CAnimationManipulatorConstruct) == 0x14, "CAnimationManipulatorConstruct size must be 0x14");
  static_assert(sizeof(CAnimationManipulatorSerializer) == 0x14, "CAnimationManipulatorSerializer size must be 0x14");
  static_assert(sizeof(CAnimationManipulatorTypeInfo) == 0x64, "CAnimationManipulatorTypeInfo size must be 0x64");
} // namespace moho
