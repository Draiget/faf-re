#include "moho/animation/CSlideManipulator.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <typeinfo>

#include "lua/LuaObject.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"
#include "wm3/Vector3.h"

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

  constexpr const char* kSlideLuaClassName = "CSlideManipulator";
  constexpr float kSlideRateScale = 0.1f;
  constexpr float kSlideInitialSpeed = std::numeric_limits<float>::infinity();
  constexpr const char* kCreateSliderName = "CreateSlider";
  constexpr const char* kCreateSliderClassName = "<global>";
  constexpr const char* kCreateSliderHelpText =
    "CreateSlider(unit, bone, [goal_x, goal_y, goal_z, [speed, [world_space]]])";

  constexpr const char* kSetWorldUnitsName = "SetWorldUnits";
  constexpr const char* kSetWorldUnitsHelpText = "CSlideManipulator:SetWorldUnits(bool)";
  constexpr const char* kSetSpeedName = "SetSpeed";
  constexpr const char* kSetSpeedHelpText = "CSlideManipulator:SetSpeed(speed)";
  constexpr const char* kSetAccelerationName = "SetAcceleration";
  constexpr const char* kSetAccelerationHelpText = "CSlideManipulator:SetAcceleration(acc)";
  constexpr const char* kSetDecelerationName = "SetDeceleration";
  constexpr const char* kSetDecelerationHelpText = "CSlideManipulator:SetDeceleration(dec)";
  constexpr const char* kSetGoalName = "SetGoal";
  constexpr const char* kSetGoalHelpText = "CSlideManipulator:SetGoal(goal_x, goal_y, goal_z)";
  constexpr const char* kBeenDestroyedName = "BeenDestroyed";
  constexpr const char* kBeenDestroyedHelpText = "CSlideManipulator:BeenDestroyed()";

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
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

  [[nodiscard]] moho::CAniPoseBone* ResolvePoseBone(moho::CAniActor* const actor, const int boneIndex) noexcept
  {
    if (actor == nullptr || actor->mPose.px == nullptr || boneIndex < 0) {
      return nullptr;
    }

    moho::CAniPose* const pose = actor->mPose.px;
    moho::CAniPoseBone* const bonesBegin = pose->mBones.begin();
    moho::CAniPoseBone* const bonesEnd = pose->mBones.end();
    if (bonesBegin == nullptr || bonesEnd == nullptr || bonesBegin >= bonesEnd) {
      return nullptr;
    }

    const std::ptrdiff_t boneCount = bonesEnd - bonesBegin;
    if (boneIndex >= boneCount) {
      return nullptr;
    }

    return &bonesBegin[boneIndex];
  }

  [[nodiscard]] bool LimitVectorLengthTo(Wm3::Vector3f* const vector, const float maxLength)
  {
    if (vector == nullptr || maxLength <= 0.0f) {
      return false;
    }

    const float lengthSq = vector->x * vector->x + vector->y * vector->y + vector->z * vector->z;
    const float maxLengthSq = maxLength * maxLength;
    if (lengthSq <= maxLengthSq) {
      return false;
    }

    const float length = std::sqrt(lengthSq);
    if (length <= 1e-6f) {
      return false;
    }

    const float scale = maxLength / length;
    vector->x *= scale;
    vector->y *= scale;
    vector->z *= scale;
    return true;
  }

  [[nodiscard]] bool ShouldDecelerateBeforeGoal(const moho::CSlideManipulator& manipulator)
  {
    const Wm3::Vector3f delta{
      manipulator.mGoal.x - manipulator.mCurrentPosition.x,
      manipulator.mGoal.y - manipulator.mCurrentPosition.y,
      manipulator.mGoal.z - manipulator.mCurrentPosition.z
    };
    const float remainingDistance = std::sqrt(delta.x * delta.x + delta.y * delta.y + delta.z * delta.z);

    const float decelRate = manipulator.mDeceleration * 10.0f;
    const float brakingDistance =
      decelRate <= 0.0f ? 0.0f : ((manipulator.mCurrentSpeed * 10.0f) * (manipulator.mCurrentSpeed * 10.0f)) / (decelRate * 2.0f);
    return brakingDistance > remainingDistance;
  }

  /**
   * Address: 0x00648450 (FUN_00648450, sub_648450)
   *
   * What it does:
   * Resolves/caches reflection type metadata for `CSlideManipulator`.
   */
  [[nodiscard]] gpg::RType* CachedCSlideManipulatorType()
  {
    if (!moho::CSlideManipulator::sType) {
      moho::CSlideManipulator::sType = gpg::LookupRType(typeid(moho::CSlideManipulator));
    }
    if (!moho::CSlideManipulator::sType) {
      moho::CSlideManipulator::sType = gpg::REF_FindTypeNamed("CSlideManipulator");
    }
    if (!moho::CSlideManipulator::sType) {
      moho::CSlideManipulator::sType = gpg::REF_FindTypeNamed("Moho::CSlideManipulator");
    }
    return moho::CSlideManipulator::sType;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  /**
   * Address: 0x006487E0 (FUN_006487E0, func_GetCSlideManipulatorOpt)
   *
   * What it does:
   * Converts one Lua object to `CSlideManipulator*` with type errors for invalid
   * game-object payloads and `nullptr` return for destroyed objects.
   */
  [[nodiscard]] moho::CSlideManipulator*
  GetCSlideManipulatorOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
  {
    moho::CScriptObject** const scriptObjectSlot = moho::SCR_FromLua_CScriptObject(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RType* const slideType = CachedCSlideManipulatorType();
    const gpg::RRef upcast = slideType ? gpg::REF_UpcastPtr(sourceRef, slideType) : gpg::RRef{};
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CSlideManipulator*>(upcast.mObj);
  }

  /**
   * Address: 0x00647530 (FUN_00647530, Moho::CSlideManipulator::SetGoal)
   *
   * What it does:
   * Writes one new goal vector, applies actor-pose scaling when not using world
   * units, and updates the task-event signaled lane when goal equals current
   * slide position.
   */
  void SetSlideManipulatorGoal(moho::CSlideManipulator* const manipulator, const Wm3::Vector3f& goal)
  {
    manipulator->mGoal = goal;

    if (manipulator->mWorldUnits == 0u && manipulator->mOwnerActor && manipulator->mOwnerActor->mPose.px) {
      const float scale = manipulator->mOwnerActor->mPose.px->mScale;
      manipulator->mGoal.x *= scale;
      manipulator->mGoal.y *= scale;
      manipulator->mGoal.z *= scale;
    }

    const bool reachedGoal = !Wm3::Vector3f::Compare(&manipulator->mGoal, &manipulator->mCurrentPosition);
    manipulator->EventSetSignaled(reachedGoal);
  }

  /**
   * Address: 0x006486F0 (FUN_006486F0, func_CreateCSlideManipulatorObject)
   *
   * What it does:
   * Fills one LuaObject with the cached `CSlideManipulator` metatable factory
   * result and returns the destination slot.
   */
  [[nodiscard]] LuaPlus::LuaObject*
  func_CreateCSlideManipulatorObject(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = moho::CScrLuaMetatableFactory<moho::CSlideManipulator>::Instance().Get(state);
    return object;
  }
} // namespace

namespace moho
{
  gpg::RType* CSlideManipulator::sType = nullptr;
  CScrLuaMetatableFactory<CSlideManipulator> CScrLuaMetatableFactory<CSlideManipulator>::sInstance{};
} // namespace moho

/**
 * Address: 0x10015880 (constructor shape)
 *
 * What it does:
 * Stores one metatable-factory index used by `CScrLuaObjectFactory::Get`.
 */
moho::CScrLuaMetatableFactory<moho::CSlideManipulator>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

moho::CScrLuaMetatableFactory<moho::CSlideManipulator>&
moho::CScrLuaMetatableFactory<moho::CSlideManipulator>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00648420 (FUN_00648420, ?Create@?$CScrLuaMetatableFactory@VCSlideManipulator@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
 *
 * What it does:
 * Creates the default metatable used by `CSlideManipulator` Lua userdata.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CSlideManipulator>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x006470D0 (FUN_006470D0, ??0CSlideManipulator@Moho@@QAE@@Z)
 *
 * What it does:
 * Builds the slide manipulator, creates its Lua userdata, and arms the watched
 * bone/signaled state.
 */
moho::CSlideManipulator::CSlideManipulator(moho::Sim* const sim, moho::CAniActor* const ownerActor, const int boneIndex)
  : IAniManipulator(sim, ownerActor, 0)
{
  mCurrentPosition = {};
  mGoal = {};
  mSpeed = kSlideInitialSpeed;
  mCurrentSpeed = 0.0f;
  mAcceleration = 0.0f;
  mDeceleration = 0.0f;
  mWorldUnits = 0u;

  LuaPlus::LuaObject arg3{};
  LuaPlus::LuaObject arg2{};
  LuaPlus::LuaObject arg1{};
  LuaPlus::LuaObject metatable{};
  LuaPlus::LuaObject* const scriptFactory = func_CreateCSlideManipulatorObject(&metatable, sim->mLuaState);
  CreateLuaObject(*scriptFactory, arg1, arg2, arg3);

  AddWatchBone(boneIndex);
  EventSetSignaled(true);
}

/**
 * Address: 0x00647300 (FUN_00647300, Moho::CSlideManipulator::MoveManipulator)
 *
 * What it does:
 * Advances one step toward goal, updates pose-space translation of the watched
 * bone, and marks completion when the destination is reached.
 */
bool moho::CSlideManipulator::ManipulatorUpdate()
{
  const SAniManipBinding* const watchedBinding = mWatchBones.mBegin;
  if (watchedBinding == nullptr || (watchedBinding->mFlags & 0x8000) == 0) {
    return false;
  }

  const float maxSpeed = mSpeed;
  if (maxSpeed > 0.0f) {
    if (mDeceleration > 0.0f && ShouldDecelerateBeforeGoal(*this)) {
      float nextSpeed = mCurrentSpeed - (mDeceleration * kSlideRateScale);
      if (nextSpeed > maxSpeed) {
        nextSpeed = maxSpeed;
      }
      if (nextSpeed < 0.0f) {
        nextSpeed = 0.0f;
      }
      mCurrentSpeed = nextSpeed;
    } else if (mAcceleration > 0.0f) {
      float nextSpeed = mCurrentSpeed + (mAcceleration * kSlideRateScale);
      if (nextSpeed > maxSpeed) {
        nextSpeed = maxSpeed;
      }
      if (nextSpeed < 0.0f) {
        nextSpeed = 0.0f;
      }
      mCurrentSpeed = nextSpeed;
    } else {
      mCurrentSpeed = maxSpeed;
    }
  }

  Wm3::Vector3f delta{
    mGoal.x - mCurrentPosition.x,
    mGoal.y - mCurrentPosition.y,
    mGoal.z - mCurrentPosition.z
  };

  if (maxSpeed > 0.0f && LimitVectorLengthTo(&delta, mCurrentSpeed)) {
    mCurrentPosition.x += delta.x;
    mCurrentPosition.y += delta.y;
    mCurrentPosition.z += delta.z;
    EventSetSignaled(false);
  } else {
    mCurrentSpeed = 0.0f;
    mCurrentPosition = mGoal;
    EventSetSignaled(true);
  }

  CAniPoseBone* const watchedBone = ResolvePoseBone(mOwnerActor, watchedBinding->mBoneIndex);
  if (watchedBone == nullptr) {
    return true;
  }

  Wm3::Vector3f rotatedOffset{};
  Wm3::MultiplyQuaternionVector(&rotatedOffset, mCurrentPosition, watchedBone->mLocalTransform.orient_);
  watchedBone->mLocalTransform.pos_.x += rotatedOffset.x;
  watchedBone->mLocalTransform.pos_.y += rotatedOffset.y;
  watchedBone->mLocalTransform.pos_.z += rotatedOffset.z;
  watchedBone->mCompositeDirty = 1;
  if (mSpeed < 0.0f) {
    watchedBone->mSkipNextInterp = 1;
  }

  return true;
}

/**
 * Address: 0x00647660 (FUN_00647660, cfunc_CreateSlider)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CreateSliderL`.
 */
int moho::cfunc_CreateSlider(lua_State* const luaContext)
{
  return cfunc_CreateSliderL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x006476E0 (FUN_006476E0, cfunc_CreateSliderL)
 *
 * What it does:
 * Reads `(unit, bone, [goal_x, goal_y, goal_z, [speed, [world_space]]])`,
 * constructs one slide manipulator, and returns it to Lua.
 */
int moho::cfunc_CreateSliderL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 7) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kCreateSliderHelpText,
      2,
      7,
      argumentCount
    );
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  moho::Unit* const unit = moho::SCR_FromLua_Unit(unitObject);
  (void)unit->AniActor->GetSkeleton();

  LuaPlus::LuaStackObject boneArg(state, 2);
  const int boneIndex = unit->AniActor->ResolveBoneIndex(boneArg);
  if (boneIndex < 0) {
    LuaPlus::LuaState::Error(boneArg.m_state, "A valid bone is required");
  }

  moho::CSlideManipulator* const manipulator = new moho::CSlideManipulator(unit->SimulationRef, unit->AniActor, boneIndex);

  if (argumentCount >= 7) {
    manipulator->mWorldUnits = LuaPlus::LuaStackObject(state, 7).GetBoolean() ? 1u : 0u;
  }

  if (argumentCount >= 3) {
    LuaPlus::LuaStackObject goalZ(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      goalZ.TypeError("number");
    }
    const float z = static_cast<float>(lua_tonumber(rawState, 5));

    LuaPlus::LuaStackObject goalY(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      goalY.TypeError("number");
    }
    const float y = static_cast<float>(lua_tonumber(rawState, 4));

    LuaPlus::LuaStackObject goalX(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      goalX.TypeError("number");
    }
    const float x = static_cast<float>(lua_tonumber(rawState, 3));

    const Wm3::Vector3f goal{x, y, z};
    SetSlideManipulatorGoal(manipulator, goal);
  }

  if (argumentCount >= 6) {
    LuaPlus::LuaStackObject speedArg(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      speedArg.TypeError("number");
    }

    const float requestedSpeed = static_cast<float>(lua_tonumber(rawState, 6));
    if (requestedSpeed <= 0.0f) {
      manipulator->mSpeed = -1.0f;
      manipulator->mCurrentSpeed = 0.0f;
    } else {
      const float scaledSpeed = requestedSpeed * kSlideRateScale;
      manipulator->mSpeed = scaledSpeed;
      if (manipulator->mWorldUnits == 0u && manipulator->mOwnerActor && manipulator->mOwnerActor->mPose.px) {
        manipulator->mSpeed = manipulator->mOwnerActor->mPose.px->mScale * scaledSpeed;
      }
    }
  }

  manipulator->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00647680 (FUN_00647680, func_CreateSlider_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `CreateSlider(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CreateSlider_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCreateSliderName,
    &moho::cfunc_CreateSlider,
    nullptr,
    kCreateSliderClassName,
    kCreateSliderHelpText
  );
  return &binder;
}

/**
 * Address: 0x00647A30 (FUN_00647A30, cfunc_CSlideManipulatorSetWorldUnits)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CSlideManipulatorSetWorldUnitsL`.
 */
int moho::cfunc_CSlideManipulatorSetWorldUnits(lua_State* const luaContext)
{
  return cfunc_CSlideManipulatorSetWorldUnitsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00647A50 (FUN_00647A50, func_CSlideManipulatorSetWorldUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CSlideManipulator:SetWorldUnits(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CSlideManipulatorSetWorldUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kSetWorldUnitsName,
    &moho::cfunc_CSlideManipulatorSetWorldUnits,
    &CScrLuaMetatableFactory<CSlideManipulator>::Instance(),
    kSlideLuaClassName,
    kSetWorldUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00647AB0 (FUN_00647AB0, cfunc_CSlideManipulatorSetWorldUnitsL)
 *
 * What it does:
 * Resolves one `CSlideManipulator*` and updates world-unit mode from Lua arg #2.
 */
int moho::cfunc_CSlideManipulatorSetWorldUnitsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetWorldUnitsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CSlideManipulator* const manipulator = SCR_FromLua_CSlideManipulator(manipObject, state);
  manipulator->mWorldUnits = LuaPlus::LuaStackObject(state, 2).GetBoolean() ? 1u : 0u;

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x00647B80 (FUN_00647B80, cfunc_CSlideManipulatorSetSpeed)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CSlideManipulatorSetSpeedL`.
 */
int moho::cfunc_CSlideManipulatorSetSpeed(lua_State* const luaContext)
{
  return cfunc_CSlideManipulatorSetSpeedL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00647BA0 (FUN_00647BA0, func_CSlideManipulatorSetSpeed_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CSlideManipulator:SetSpeed(speed)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CSlideManipulatorSetSpeed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kSetSpeedName,
    &moho::cfunc_CSlideManipulatorSetSpeed,
    &CScrLuaMetatableFactory<CSlideManipulator>::Instance(),
    kSlideLuaClassName,
    kSetSpeedHelpText
  );
  return &binder;
}

/**
 * Address: 0x00647C00 (FUN_00647C00, cfunc_CSlideManipulatorSetSpeedL)
 *
 * What it does:
 * Applies one speed scalar and optional pose-space scale conversion.
 */
int moho::cfunc_CSlideManipulatorSetSpeedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetSpeedHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CSlideManipulator* const manipulator = GetCSlideManipulatorOptional(manipObject, state);
  if (manipulator == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  const LuaPlus::LuaStackObject speedArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    speedArg.TypeError("number");
  }
  const float requestedSpeed = static_cast<float>(lua_tonumber(rawState, 2));

  if (requestedSpeed <= 0.0f) {
    manipulator->mSpeed = -1.0f;
    manipulator->mCurrentSpeed = 0.0f;
    lua_settop(rawState, 1);
    return 1;
  }

  const float scaledSpeed = requestedSpeed * kSlideRateScale;
  manipulator->mSpeed = scaledSpeed;
  if (manipulator->mWorldUnits == 0u && manipulator->mOwnerActor && manipulator->mOwnerActor->mPose.px) {
    manipulator->mSpeed = manipulator->mOwnerActor->mPose.px->mScale * scaledSpeed;
  }

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x00647D80 (FUN_00647D80, cfunc_CSlideManipulatorSetAcceleration)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CSlideManipulatorSetAccelerationL`.
 */
int moho::cfunc_CSlideManipulatorSetAcceleration(lua_State* const luaContext)
{
  return cfunc_CSlideManipulatorSetAccelerationL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00647DA0 (FUN_00647DA0, func_CSlideManipulatorSetAcceleration_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CSlideManipulator:SetAcceleration(acc)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CSlideManipulatorSetAcceleration_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kSetAccelerationName,
    &moho::cfunc_CSlideManipulatorSetAcceleration,
    &CScrLuaMetatableFactory<CSlideManipulator>::Instance(),
    kSlideLuaClassName,
    kSetAccelerationHelpText
  );
  return &binder;
}

/**
 * Address: 0x00647E00 (FUN_00647E00, cfunc_CSlideManipulatorSetAccelerationL)
 *
 * What it does:
 * Stores clamped acceleration (`max(0,arg) * 0.1`) into the manipulator lane.
 */
int moho::cfunc_CSlideManipulatorSetAccelerationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAccelerationHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CSlideManipulator* const manipulator = SCR_FromLua_CSlideManipulator(manipObject, state);

  const LuaPlus::LuaStackObject accelerationArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    accelerationArg.TypeError("number");
  }

  const float requestedAcceleration = static_cast<float>(lua_tonumber(rawState, 2));
  const float clampedAcceleration = requestedAcceleration > 0.0f ? requestedAcceleration : 0.0f;
  manipulator->mAcceleration = clampedAcceleration * kSlideRateScale;

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x00647F20 (FUN_00647F20, cfunc_CSlideManipulatorSetDeceleration)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CSlideManipulatorSetDecelerationL`.
 */
int moho::cfunc_CSlideManipulatorSetDeceleration(lua_State* const luaContext)
{
  return cfunc_CSlideManipulatorSetDecelerationL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00647F40 (FUN_00647F40, func_CSlideManipulatorSetDeceleration_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CSlideManipulator:SetDeceleration(dec)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CSlideManipulatorSetDeceleration_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kSetDecelerationName,
    &moho::cfunc_CSlideManipulatorSetDeceleration,
    &CScrLuaMetatableFactory<CSlideManipulator>::Instance(),
    kSlideLuaClassName,
    kSetDecelerationHelpText
  );
  return &binder;
}

/**
 * Address: 0x00647FA0 (FUN_00647FA0, cfunc_CSlideManipulatorSetDecelerationL)
 *
 * What it does:
 * Stores clamped deceleration (`max(0,arg) * 0.1`) into the manipulator lane.
 */
int moho::cfunc_CSlideManipulatorSetDecelerationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetDecelerationHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CSlideManipulator* const manipulator = SCR_FromLua_CSlideManipulator(manipObject, state);

  const LuaPlus::LuaStackObject decelerationArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    decelerationArg.TypeError("number");
  }

  const float requestedDeceleration = static_cast<float>(lua_tonumber(rawState, 2));
  const float clampedDeceleration = requestedDeceleration > 0.0f ? requestedDeceleration : 0.0f;
  manipulator->mDeceleration = clampedDeceleration * kSlideRateScale;

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x006480C0 (FUN_006480C0, cfunc_CSlideManipulatorSetGoal)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CSlideManipulatorSetGoalL`.
 */
int moho::cfunc_CSlideManipulatorSetGoal(lua_State* const luaContext)
{
  return cfunc_CSlideManipulatorSetGoalL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x006480E0 (FUN_006480E0, func_CSlideManipulatorSetGoal_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CSlideManipulator:SetGoal(goal_x, goal_y, goal_z)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CSlideManipulatorSetGoal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kSetGoalName,
    &moho::cfunc_CSlideManipulatorSetGoal,
    &CScrLuaMetatableFactory<CSlideManipulator>::Instance(),
    kSlideLuaClassName,
    kSetGoalHelpText
  );
  return &binder;
}

/**
 * Address: 0x00648140 (FUN_00648140, cfunc_CSlideManipulatorSetGoalL)
 *
 * What it does:
 * Reads `(self, x, y, z)` and applies goal update semantics to the slide
 * manipulator runtime lane.
 */
int moho::cfunc_CSlideManipulatorSetGoalL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetGoalHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CSlideManipulator* const manipulator = SCR_FromLua_CSlideManipulator(manipObject, state);

  const LuaPlus::LuaStackObject zArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    zArg.TypeError("number");
  }
  const float z = static_cast<float>(lua_tonumber(rawState, 4));

  const LuaPlus::LuaStackObject yArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    yArg.TypeError("number");
  }
  const float y = static_cast<float>(lua_tonumber(rawState, 3));

  const LuaPlus::LuaStackObject xArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    xArg.TypeError("number");
  }
  const float x = static_cast<float>(lua_tonumber(rawState, 2));

  const Wm3::Vector3f goal{x, y, z};
  SetSlideManipulatorGoal(manipulator, goal);

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x006482E0 (FUN_006482E0, cfunc_CSlideManipulatorBeenDestroyed)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CSlideManipulatorBeenDestroyedL`.
 */
int moho::cfunc_CSlideManipulatorBeenDestroyed(lua_State* const luaContext)
{
  return cfunc_CSlideManipulatorBeenDestroyedL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00648300 (FUN_00648300, func_CSlideManipulatorBeenDestroyed_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CSlideManipulator:BeenDestroyed()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CSlideManipulatorBeenDestroyed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kBeenDestroyedName,
    &moho::cfunc_CSlideManipulatorBeenDestroyed,
    &CScrLuaMetatableFactory<CSlideManipulator>::Instance(),
    kSlideLuaClassName,
    kBeenDestroyedHelpText
  );
  return &binder;
}

/**
 * Address: 0x00648360 (FUN_00648360, cfunc_CSlideManipulatorBeenDestroyedL)
 *
 * What it does:
 * Returns whether the optional slide-manipulator object reference is null.
 */
int moho::cfunc_CSlideManipulatorBeenDestroyedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kBeenDestroyedHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CSlideManipulator* const manipulator = GetCSlideManipulatorOptional(manipObject, state);

  lua_pushboolean(rawState, manipulator == nullptr);
  (void)lua_gettop(rawState);
  return 1;
}

namespace gpg
{
  /**
   * Address: 0x00648960 (FUN_00648960, gpg::RRef_CSlideManipulator)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CSlideManipulator*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CSlideManipulator(gpg::RRef* const outRef, moho::CSlideManipulator* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCSlideManipulatorType());
    return outRef;
  }
} // namespace gpg
