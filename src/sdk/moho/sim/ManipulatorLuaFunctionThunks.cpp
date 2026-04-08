#include "moho/sim/ManipulatorLuaFunctionThunks.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"

struct lua_State;

namespace moho
{
  class CBoneEntityManipulator;
  class CBuilderArmManipulator;
  class CRotateManipulator;
  class CThrustManipulator;
  class Entity;

  int cfunc_CBoneEntityManipulatorSetPivot(lua_State* luaContext);
  int cfunc_EntityAttachBoneToEntityBone(lua_State* luaContext);
  int cfunc_CBuilderArmManipulatorSetAimingArc(lua_State* luaContext);
  int cfunc_CBuilderArmManipulatorGetHeadingPitch(lua_State* luaContext);
  int cfunc_CBuilderArmManipulatorSetHeadingPitch(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetSpinDown(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetGoal(lua_State* luaContext);
  int cfunc_CRotateManipulatorClearGoal(lua_State* luaContext);
  int cfunc_CRotateManipulatorClearGoalL(LuaPlus::LuaState* state);
  int cfunc_CRotateManipulatorSetSpeed(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetTargetSpeed(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetAccel(lua_State* luaContext);
  int cfunc_CRotateManipulatorClearFollowBone(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetFollowBone(lua_State* luaContext);
  int cfunc_CRotateManipulatorGetCurrentAngle(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetCurrentAngle(lua_State* luaContext);
  int cfunc_CThrustManipulatorSetThrustingParam(lua_State* luaContext);

  template <>
  class CScrLuaMetatableFactory<CBoneEntityManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CBuilderArmManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<Entity> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CRotateManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CThrustManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CBoneEntityManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CBoneEntityManipulator> size must be 0x8"
  );
  static_assert(
    sizeof(CScrLuaMetatableFactory<CBuilderArmManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CBuilderArmManipulator> size must be 0x8"
  );
  static_assert(sizeof(CScrLuaMetatableFactory<Entity>) == 0x08, "CScrLuaMetatableFactory<Entity> size must be 0x8");
  static_assert(
    sizeof(CScrLuaMetatableFactory<CRotateManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CRotateManipulator> size must be 0x8"
  );
  static_assert(
    sizeof(CScrLuaMetatableFactory<CThrustManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CThrustManipulator> size must be 0x8"
  );

  CScrLuaMetatableFactory<CBoneEntityManipulator> CScrLuaMetatableFactory<CBoneEntityManipulator>::sInstance{};
  CScrLuaMetatableFactory<CBuilderArmManipulator> CScrLuaMetatableFactory<CBuilderArmManipulator>::sInstance{};
  CScrLuaMetatableFactory<Entity> CScrLuaMetatableFactory<Entity>::sInstance{};
  CScrLuaMetatableFactory<CRotateManipulator> CScrLuaMetatableFactory<CRotateManipulator>::sInstance{};
  CScrLuaMetatableFactory<CThrustManipulator> CScrLuaMetatableFactory<CThrustManipulator>::sInstance{};

  CScrLuaMetatableFactory<CBoneEntityManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CBoneEntityManipulator>& CScrLuaMetatableFactory<CBoneEntityManipulator>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CBoneEntityManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<CBuilderArmManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CBuilderArmManipulator>& CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CBuilderArmManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<Entity>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<Entity>& CScrLuaMetatableFactory<Entity>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<Entity>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<CRotateManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CRotateManipulator>& CScrLuaMetatableFactory<CRotateManipulator>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CRotateManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<CThrustManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CThrustManipulator>& CScrLuaMetatableFactory<CThrustManipulator>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CThrustManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }
} // namespace moho

namespace
{
  constexpr const char* kCBoneEntityManipulatorSetPivotName = "SetPivot";
  constexpr const char* kCBoneEntityManipulatorSetPivotClassName = "CBoneEntityManipulator";
  constexpr const char* kCBoneEntityManipulatorSetPivotHelpText =
    "manip:SetPivot(x,y,z) -- Set the pivot point of the attached bone";

  constexpr const char* kEntityAttachBoneToEntityBoneName = "AttachBoneToEntityBone";
  constexpr const char* kEntityAttachBoneToEntityBoneClassName = "Entity";
  constexpr const char* kEntityAttachBoneToEntityBoneHelpText =
    "Attach a unit bone position to an entity bone position";

  constexpr const char* kCBuilderArmManipulatorSetAimingArcName = "SetAimingArc";
  constexpr const char* kCBuilderArmManipulatorClassName = "CBuilderArmManipulator";
  constexpr const char* kCBuilderArmManipulatorSetAimingArcHelpText =
    "BuilderArmManipulator:SetAimingArc(minHeading, maxHeading, headingMaxSlew, minPitch, maxPitch, pitchMaxSlew)";

  constexpr const char* kCBuilderArmManipulatorGetHeadingPitchName = "GetHeadingPitch";
  constexpr const char* kCBuilderArmManipulatorGetHeadingPitchHelpText = "CBuilderArmManipulator:GetHeading()";
  constexpr const char* kCBuilderArmManipulatorSetHeadingPitchName = "SetHeadingPitch";
  constexpr const char* kCBuilderArmManipulatorSetHeadingPitchHelpText =
    "CBuilderArmManipulator:SetHeadingPitch( heading, pitch )";

  constexpr const char* kCRotateManipulatorSetSpinDownName = "SetSpinDown";
  constexpr const char* kCRotateManipulatorSetGoalName = "SetGoal";
  constexpr const char* kCRotateManipulatorClearGoalName = "ClearGoal";
  constexpr const char* kCRotateManipulatorSetSpeedName = "SetSpeed";
  constexpr const char* kCRotateManipulatorSetTargetSpeedName = "SetTargetSpeed";
  constexpr const char* kCRotateManipulatorSetAccelName = "SetAccel";
  constexpr const char* kCRotateManipulatorClearFollowBoneName = "ClearFollowBone";
  constexpr const char* kCRotateManipulatorSetFollowBoneName = "SetFollowBone";
  constexpr const char* kCRotateManipulatorGetCurrentAngleName = "GetCurrentAngle";
  constexpr const char* kCRotateManipulatorSetCurrentAngleName = "SetCurrentAngle";
  constexpr const char* kCRotateManipulatorClassName = "CRotateManipulator";

  constexpr const char* kCRotateManipulatorSetSpinDownHelpText = "RotateManipulator:SetSpinDown(self, flag)";
  constexpr const char* kCRotateManipulatorSetGoalHelpText = "RotateManipulator:SetGoal(self, degrees)";
  constexpr const char* kCRotateManipulatorClearGoalHelpText = "RotateManipulator:ClearGoal()";
  constexpr const char* kCRotateManipulatorSetSpeedHelpText = "RotateManipulator:SetSpeed(self, degrees_per_second)";
  constexpr const char* kCRotateManipulatorSetTargetSpeedHelpText =
    "RotateManipulator:SetTargetSpeed(degrees_per_second)";
  constexpr const char* kCRotateManipulatorSetAccelHelpText =
    "RotateManipulator:SetAccel(degrees_per_second_squared)";
  constexpr const char* kCRotateManipulatorClearFollowBoneHelpText = "RotateManipulator:ClearFollowBone()";
  constexpr const char* kCRotateManipulatorSetFollowBoneHelpText = "RotateManipulator:SetFollowBone(bone)";
  constexpr const char* kCRotateManipulatorGetCurrentAngleHelpText = "RotateManipulator:GetCurrentAngle()";
  constexpr const char* kCRotateManipulatorSetCurrentAngleHelpText = "RotateManipulator:SetCurrentAngle(angle)";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";
  constexpr const char* kInvalidRotatorError = "CSpinManipulator:SetGoal: invalid rotator";

  constexpr const char* kCThrustManipulatorSetThrustingParamName = "SetThrustingParam";
  constexpr const char* kCThrustManipulatorClassName = "CThrustManipulator";
  constexpr const char* kCThrustManipulatorSetThrustingParamHelpText =
    "ThrustManipulator:SetThrustingParam(xCapMin, xCapMax, yCapMin, yCapMax, zCapMin, zCapMax, turnForceMult, "
    "turnSpeed)";

  struct CRotateManipulatorRuntimeView
  {
    std::uint8_t mReserved00_7F[0x80];
    std::uint8_t mHasGoal; // +0x80
  };
  static_assert(
    offsetof(CRotateManipulatorRuntimeView, mHasGoal) == 0x80,
    "CRotateManipulatorRuntimeView::mHasGoal offset must be 0x80"
  );

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] gpg::RType* CachedCRotateManipulatorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CRotateManipulator");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CRotateManipulator");
    }
    return cached;
  }

  [[nodiscard]] LuaPlus::LuaObject GetTableFieldByName(const LuaPlus::LuaObject& tableObject, const char* fieldName)
  {
    LuaPlus::LuaObject out;
    LuaPlus::LuaState* const state = tableObject.GetActiveState();
    if (!state) {
      return out;
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(tableObject).PushStack(lstate);
    lua_pushstring(lstate, fieldName ? fieldName : "");
    lua_gettable(lstate, -2);
    out = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(lstate, top);
    return out;
  }

  [[nodiscard]] gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int stackTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, stackTop);
    return out;
  }

  [[nodiscard]] moho::CScriptObject** ExtractScriptObjectSlot(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = GetTableFieldByName(payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, moho::CScriptObject::GetPointerType());
    return static_cast<moho::CScriptObject**>(upcast.mObj);
  }

  [[nodiscard]] CRotateManipulatorRuntimeView*
  GetRotateManipulatorOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
  {
    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlot(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RType* const rotateType = CachedCRotateManipulatorType();
    const gpg::RRef upcast = rotateType ? gpg::REF_UpcastPtr(sourceRef, rotateType) : gpg::RRef{};
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<CRotateManipulatorRuntimeView*>(upcast.mObj);
  }

  [[nodiscard]] moho::CScrLuaInitFormSet* FindSimLuaInitSet() noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, "sim") == 0) {
        return set;
      }
    }

    return nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindSimLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardManipulatorLuaThunk() noexcept
  {
    return Target();
  }

  struct ManipulatorLuaFunctionThunksBootstrap
  {
    ManipulatorLuaFunctionThunksBootstrap()
    {
      (void)moho::j_func_CreateAimController_LuaFuncDef();
      (void)moho::register_CAimManipulatorSetFiringArc_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef();
      (void)moho::register_CAimManipulatorOnTarget_LuaFuncDef();
      (void)moho::register_CAimManipulatorSetEnabled_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef();
      (void)moho::j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef();
      (void)moho::register_EntityAttachBoneToEntityBone_LuaFuncDef();
      (void)moho::j_func_CreateBuilderArmController_LuaFuncDef();
      (void)moho::j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef();
      (void)moho::j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CreateCollisionDetector_LuaFuncDef();
      (void)moho::j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef();
      (void)moho::j_func_CCollisionManipulatorEnable_LuaFuncDef();
      (void)moho::register_CCollisionManipulatorDisable_LuaFuncDef();
      (void)moho::j_func_CCollisionManipulatorWatchBone_LuaFuncDef();
      (void)moho::register_CreateFootPlantController_LuaFuncDef();
      (void)moho::j_func_IAniManipulatorSetPrecedence_LuaFuncDef();
      (void)moho::register_IAniManipulatorEnable_LuaFuncDef();
      (void)moho::register_IAniManipulatorDisable_LuaFuncDef();
      (void)moho::j_func_IAniManipulatorDestroy_LuaFuncDef();
      (void)moho::j_func_CreateAnimator_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorPlayAnim_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetRate_LuaFuncDef();
      (void)moho::j_func_CAnimationManipulatorSetRate_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef();
      (void)moho::j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetAnimationTime_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetAnimationTime_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef();
      (void)moho::j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef();
      (void)moho::j_func_CreateRotator_LuaFuncDef();
      (void)moho::register_CRotateManipulatorSetSpinDown_LuaFuncDef();
      (void)moho::register_CRotateManipulatorSetGoal_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorClearGoal_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetSpeed_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetAccel_LuaFuncDef();
      (void)moho::register_CRotateManipulatorClearFollowBone_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetFollowBone_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef();
      (void)moho::register_CRotateManipulatorSetCurrentAngle_LuaFuncDef();
      (void)moho::j_func_CreateSlaver_LuaFuncDef();
      (void)moho::register_CSlaveManipulatorSetMaxRate_LuaFuncDef();
      (void)moho::j_func_CreateSlider_LuaFuncDef();
      (void)moho::register_CSlideManipulatorSetWorldUnits_LuaFuncDef();
      (void)moho::register_CSlideManipulatorSetSpeed_LuaFuncDef();
      (void)moho::j_func_CSlideManipulatorSetAcceleration_LuaFuncDef();
      (void)moho::register_CSlideManipulatorSetDeceleration_LuaFuncDef();
      (void)moho::j_func_CSlideManipulatorSetGoal_LuaFuncDef();
      (void)moho::register_CSlideManipulatorBeenDestroyed_LuaFuncDef();
      (void)moho::j_func_CreateStorageManip_LuaFuncDef();
      (void)moho::j_func_CreateThrustController_LuaFuncDef();
      (void)moho::j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef();
    }
  };

  [[maybe_unused]] ManipulatorLuaFunctionThunksBootstrap gManipulatorLuaFunctionThunksBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006445C0 (FUN_006445C0, cfunc_CRotateManipulatorClearGoal)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CRotateManipulatorClearGoalL`.
   */
  int cfunc_CRotateManipulatorClearGoal(lua_State* const luaContext)
  {
    return cfunc_CRotateManipulatorClearGoalL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00644640 (FUN_00644640, cfunc_CRotateManipulatorClearGoalL)
   *
   * What it does:
   * Resolves one rotate manipulator from Lua, clears its goal-armed lane, and
   * raises Lua errors for invalid/mismatched game-object handles.
   */
  int cfunc_CRotateManipulatorClearGoalL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCRotateManipulatorClearGoalHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    CRotateManipulatorRuntimeView* const manipulator = GetRotateManipulatorOptional(manipulatorObject, state);
    if (!manipulator) {
      lua_pushstring(state->m_state, kInvalidRotatorError);
      (void)lua_gettop(state->m_state);
      lua_error(state->m_state);
      return 0;
    }

    manipulator->mHasGoal = 0u;
    return 0;
  }

  /**
   * Address: 0x00634C90 (FUN_00634C90, func_CBoneEntityManipulatorSetPivot_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBoneEntityManipulator:SetPivot(x, y, z)` Lua binder.
   */
  CScrLuaInitForm* func_CBoneEntityManipulatorSetPivot_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCBoneEntityManipulatorSetPivotName,
      &cfunc_CBoneEntityManipulatorSetPivot,
      &CScrLuaMetatableFactory<CBoneEntityManipulator>::Instance(),
      kCBoneEntityManipulatorSetPivotClassName,
      kCBoneEntityManipulatorSetPivotHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00634EA0 (FUN_00634EA0, func_EntityAttachBoneToEntityBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AttachBoneToEntityBone(...)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAttachBoneToEntityBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kEntityAttachBoneToEntityBoneName,
      &cfunc_EntityAttachBoneToEntityBone,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityAttachBoneToEntityBoneClassName,
      kEntityAttachBoneToEntityBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006369F0 (FUN_006369F0, func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBuilderArmManipulator:SetAimingArc(...)` Lua binder.
   */
  CScrLuaInitForm* func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCBuilderArmManipulatorSetAimingArcName,
      &cfunc_CBuilderArmManipulatorSetAimingArc,
      &CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance(),
      kCBuilderArmManipulatorClassName,
      kCBuilderArmManipulatorSetAimingArcHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00636BF0 (FUN_00636BF0, func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBuilderArmManipulator:GetHeadingPitch()` Lua binder.
   */
  CScrLuaInitForm* func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCBuilderArmManipulatorGetHeadingPitchName,
      &cfunc_CBuilderArmManipulatorGetHeadingPitch,
      &CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance(),
      kCBuilderArmManipulatorClassName,
      kCBuilderArmManipulatorGetHeadingPitchHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00636D50 (FUN_00636D50, func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBuilderArmManipulator:SetHeadingPitch(heading, pitch)` Lua
   * binder.
   */
  CScrLuaInitForm* func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCBuilderArmManipulatorSetHeadingPitchName,
      &cfunc_CBuilderArmManipulatorSetHeadingPitch,
      &CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance(),
      kCBuilderArmManipulatorClassName,
      kCBuilderArmManipulatorSetHeadingPitchHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006442A0 (FUN_006442A0, func_CRotateManipulatorSetSpinDown_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetSpinDown(flag)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetSpinDown_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetSpinDownName,
      &cfunc_CRotateManipulatorSetSpinDown,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetSpinDownHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644410 (FUN_00644410, func_CRotateManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetGoal(degrees)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetGoal_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetGoalName,
      &cfunc_CRotateManipulatorSetGoal,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetGoalHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006445E0 (FUN_006445E0, func_CRotateManipulatorClearGoal_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:ClearGoal()` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorClearGoal_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorClearGoalName,
      &cfunc_CRotateManipulatorClearGoal,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorClearGoalHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644730 (FUN_00644730, func_CRotateManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetSpeed(...)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetSpeed_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetSpeedName,
      &cfunc_CRotateManipulatorSetSpeed,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetSpeedHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006448D0 (FUN_006448D0, func_CRotateManipulatorSetTargetSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetTargetSpeed(...)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetTargetSpeed_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetTargetSpeedName,
      &cfunc_CRotateManipulatorSetTargetSpeed,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetTargetSpeedHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644AA0 (FUN_00644AA0, func_CRotateManipulatorSetAccel_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetAccel(...)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetAccel_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetAccelName,
      &cfunc_CRotateManipulatorSetAccel,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetAccelHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644C40 (FUN_00644C40, func_CRotateManipulatorClearFollowBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:ClearFollowBone()` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorClearFollowBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorClearFollowBoneName,
      &cfunc_CRotateManipulatorClearFollowBone,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorClearFollowBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644DB0 (FUN_00644DB0, func_CRotateManipulatorSetFollowBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetFollowBone(bone)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetFollowBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetFollowBoneName,
      &cfunc_CRotateManipulatorSetFollowBone,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetFollowBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644F50 (FUN_00644F50, func_CRotateManipulatorGetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:GetCurrentAngle()` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorGetCurrentAngle_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorGetCurrentAngleName,
      &cfunc_CRotateManipulatorGetCurrentAngle,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorGetCurrentAngleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006450C0 (FUN_006450C0, func_CRotateManipulatorSetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetCurrentAngle(angle)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetCurrentAngle_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetCurrentAngleName,
      &cfunc_CRotateManipulatorSetCurrentAngle,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetCurrentAngleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0064AD30 (FUN_0064AD30, func_CThrustManipulatorSetThrustingParam_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CThrustManipulator:SetThrustingParam(...)` Lua binder.
   */
  CScrLuaInitForm* func_CThrustManipulatorSetThrustingParam_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCThrustManipulatorSetThrustingParamName,
      &cfunc_CThrustManipulatorSetThrustingParam,
      &CScrLuaMetatableFactory<CThrustManipulator>::Instance(),
      kCThrustManipulatorClassName,
      kCThrustManipulatorSetThrustingParamHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BD22D0 (FUN_00BD22D0, j_func_CreateAimController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateAimController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateAimController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateAimController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD22E0 (FUN_00BD22E0, register_CAimManipulatorSetFiringArc_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetFiringArc_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorSetFiringArc_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetFiringArc_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD22F0 (FUN_00BD22F0, j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetResetPoseTime_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetResetPoseTime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2300 (FUN_00BD2300, register_CAimManipulatorOnTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorOnTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorOnTarget_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorOnTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2310 (FUN_00BD2310, register_CAimManipulatorSetEnabled_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetEnabled_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorSetEnabled_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2320 (FUN_00BD2320, j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorGetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorGetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2330 (FUN_00BD2330, j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2340 (FUN_00BD2340, j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD24A0 (FUN_00BD24A0, j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBoneEntityManipulatorSetPivot_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBoneEntityManipulatorSetPivot_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD24B0 (FUN_00BD24B0, register_EntityAttachBoneToEntityBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_EntityAttachBoneToEntityBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityAttachBoneToEntityBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_EntityAttachBoneToEntityBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD25F0 (FUN_00BD25F0, j_func_CreateBuilderArmController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateBuilderArmController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateBuilderArmController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateBuilderArmController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2600 (FUN_00BD2600, j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2610 (FUN_00BD2610, j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2620 (FUN_00BD2620, j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2A60 (FUN_00BD2A60, register_CreateFootPlantController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateFootPlantController_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateFootPlantController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateFootPlantController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2C80 (FUN_00BD2C80, j_func_IAniManipulatorSetPrecedence_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorSetPrecedence_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IAniManipulatorSetPrecedence_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorSetPrecedence_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2C90 (FUN_00BD2C90, register_IAniManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorEnable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IAniManipulatorEnable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorEnable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2CA0 (FUN_00BD2CA0, register_IAniManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorDisable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IAniManipulatorDisable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorDisable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2CB0 (FUN_00BD2CB0, j_func_IAniManipulatorDestroy_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorDestroy_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IAniManipulatorDestroy_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorDestroy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2760 (FUN_00BD2760, j_func_CreateCollisionDetector_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateCollisionDetector_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateCollisionDetector_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateCollisionDetector_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2770 (FUN_00BD2770, j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2780 (FUN_00BD2780, j_func_CCollisionManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorEnable_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorEnable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorEnable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2790 (FUN_00BD2790, register_CCollisionManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorDisable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CCollisionManipulatorDisable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorDisable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD27A0 (FUN_00BD27A0, j_func_CCollisionManipulatorWatchBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorWatchBone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorWatchBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorWatchBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E30 (FUN_00BD2E30, j_func_CreateAnimator_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateAnimator_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateAnimator_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateAnimator_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E40 (FUN_00BD2E40, register_CAnimationManipulatorPlayAnim_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorPlayAnim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorPlayAnim_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorPlayAnim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E50 (FUN_00BD2E50, register_CAnimationManipulatorGetRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetRate_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetRate_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E60 (FUN_00BD2E60, j_func_CAnimationManipulatorSetRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetRate_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetRate_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E70 (FUN_00BD2E70, register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E80 (FUN_00BD2E80, j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E90 (FUN_00BD2E90, register_CAnimationManipulatorGetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationTime_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationTime_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetAnimationTime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EA0 (FUN_00BD2EA0, register_CAnimationManipulatorSetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetAnimationTime_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetAnimationTime_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetAnimationTime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EB0 (FUN_00BD2EB0, register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EC0 (FUN_00BD2EC0, register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2ED0 (FUN_00BD2ED0, register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EE0 (FUN_00BD2EE0, j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EF0 (FUN_00BD2EF0, register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3050 (FUN_00BD3050, j_func_CreateRotator_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateRotator_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateRotator_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateRotator_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3060 (FUN_00BD3060, register_CRotateManipulatorSetSpinDown_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetSpinDown_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetSpinDown_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetSpinDown_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3070 (FUN_00BD3070, register_CRotateManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetGoal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetGoal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3080 (FUN_00BD3080, j_func_CRotateManipulatorClearGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorClearGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorClearGoal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorClearGoal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3090 (FUN_00BD3090, j_func_CRotateManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetSpeed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30A0 (FUN_00BD30A0, j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetTargetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetTargetSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30B0 (FUN_00BD30B0, j_func_CRotateManipulatorSetAccel_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetAccel_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetAccel_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetAccel_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30C0 (FUN_00BD30C0, register_CRotateManipulatorClearFollowBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorClearFollowBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorClearFollowBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorClearFollowBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30D0 (FUN_00BD30D0, j_func_CRotateManipulatorSetFollowBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetFollowBone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetFollowBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetFollowBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30E0 (FUN_00BD30E0, j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorGetCurrentAngle_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorGetCurrentAngle_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30F0 (FUN_00BD30F0, register_CRotateManipulatorSetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetCurrentAngle_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetCurrentAngle_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetCurrentAngle_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3230 (FUN_00BD3230, j_func_CreateSlaver_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateSlaver_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateSlaver_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateSlaver_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3240 (FUN_00BD3240, register_CSlaveManipulatorSetMaxRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlaveManipulatorSetMaxRate_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlaveManipulatorSetMaxRate_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlaveManipulatorSetMaxRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3500 (FUN_00BD3500, j_func_CreateSlider_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateSlider_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateSlider_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateSlider_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3510 (FUN_00BD3510, register_CSlideManipulatorSetWorldUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetWorldUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetWorldUnits_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetWorldUnits_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3520 (FUN_00BD3520, register_CSlideManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetSpeed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3530 (FUN_00BD3530, j_func_CSlideManipulatorSetAcceleration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetAcceleration_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CSlideManipulatorSetAcceleration_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetAcceleration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3540 (FUN_00BD3540, register_CSlideManipulatorSetDeceleration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetDeceleration_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetDeceleration_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetDeceleration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3550 (FUN_00BD3550, j_func_CSlideManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CSlideManipulatorSetGoal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetGoal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3560 (FUN_00BD3560, register_CSlideManipulatorBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorBeenDestroyed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorBeenDestroyed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorBeenDestroyed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD36A0 (FUN_00BD36A0, j_func_CreateStorageManip_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateStorageManip_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateStorageManip_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateStorageManip_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD37E0 (FUN_00BD37E0, j_func_CreateThrustController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateThrustController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateThrustController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateThrustController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD37F0 (FUN_00BD37F0, j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CThrustManipulatorSetThrustingParam_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CThrustManipulatorSetThrustingParam_LuaFuncDef>();
  }
} // namespace moho
