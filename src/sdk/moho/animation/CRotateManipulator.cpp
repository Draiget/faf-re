#include "moho/animation/CRotateManipulator.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "lua/LuaObject.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/entity/Entity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/sim/ManipulatorLuaFunctionThunks.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint16_t kWatchBoneActiveFlag = 0x8000u;
  constexpr float kDegreesToRadians = 0.017453292f;
  constexpr float kRadiansToDegrees = 57.29578f;
  constexpr float kDegreesPerSecondToRadians = 0.0017453292f;
  constexpr float kDegreesPerSecondSquaredToRadians = 0.00017453294f;
  constexpr float kSpinDownTargetScale = 0.2f;
  constexpr float kSpinDownAngleDampen = 0.5f;

  constexpr const char* kCreateRotatorMethodName = "CreateRotator";
  constexpr const char* kCreateRotatorClassName = "<global>";
  constexpr const char* kCreateRotatorHelpText =
    "manip = CreateRotator(unit, bone, axis, [goal], [speed], [accel], [goalspeed])";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedBetweenArgsWarning = "%s\n  expected between %d and %d args, but got %d";

  constexpr const char* kInvalidAxisError =
    "CreateRotator: Invalid axis, should be \"[+|-]x\", \"[+|-]y\", or \"[+|-]z\" but got \"%s\".";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

  constexpr const char* kInvalidSpinDownError = "CSpinManipulator:SetSpinDown: invalid rotator";
  constexpr const char* kInvalidGoalError = "CSpinManipulator:SetGoal: invalid rotator";
  constexpr const char* kInvalidSpeedError = "CSpinManipulator:SetSpeed: invalid rotator";
  constexpr const char* kInvalidTargetSpeedError = "CSpinManipulator:SetTargetSpeed: invalid rotator";
  constexpr const char* kInvalidAccelError = "CSpinManipulator:SetAccel: invalid rotator";
  constexpr const char* kInvalidClearFollowBoneError = "CSpinManipulator:ClearFollowBone: invalid rotator";
  constexpr const char* kInvalidSetFollowBoneError = "CSpinManipulator:SetFollowBone: invalid rotator";
  constexpr const char* kInvalidGetCurrentAngleError = "CSpinManipulator:GetCurrentAngle: invalid rotator";
  constexpr const char* kCouldNotSetCurrentAngleError = "CSpinManipulator:SetCurrentAngle: Couldn't set current angle";

  constexpr const char* kSetSpinDownHelpText = "RotateManipulator:SetSpinDown(self, flag)";
  constexpr const char* kSetGoalHelpText = "RotateManipulator:SetGoal(self, degrees)";
  constexpr const char* kSetSpeedHelpText = "RotateManipulator:SetSpeed(self, degrees_per_second)";
  constexpr const char* kSetTargetSpeedHelpText = "RotateManipulator:SetTargetSpeed(degrees_per_second)";
  constexpr const char* kSetAccelHelpText = "RotateManipulator:SetAccel(degrees_per_second_squared)";
  constexpr const char* kClearFollowBoneHelpText = "RotateManipulator:ClearFollowBone()";
  constexpr const char* kSetFollowBoneHelpText = "RotateManipulator:SetFollowBone(bone)";
  constexpr const char* kGetCurrentAngleHelpText = "RotateManipulator:GetCurrentAngle()";
  constexpr const char* kSetCurrentAngleHelpText = "RotateManipulator:SetCurrentAngle(angle)";

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
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

  [[nodiscard]] bool ParseAxisText(const char* axisText, Wm3::Vector3f* const outAxis) noexcept
  {
    if (axisText == nullptr || outAxis == nullptr) {
      return false;
    }

    if (*axisText == '+') {
      ++axisText;
    }

    *outAxis = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    if (_stricmp(axisText, "x") == 0) {
      outAxis->x = 1.0f;
      return true;
    }
    if (_stricmp(axisText, "y") == 0) {
      outAxis->y = 1.0f;
      return true;
    }
    if (_stricmp(axisText, "z") == 0) {
      outAxis->z = 1.0f;
      return true;
    }
    if (_stricmp(axisText, "-x") == 0) {
      outAxis->x = -1.0f;
      return true;
    }
    if (_stricmp(axisText, "-y") == 0) {
      outAxis->y = -1.0f;
      return true;
    }
    if (_stricmp(axisText, "-z") == 0) {
      outAxis->z = -1.0f;
      return true;
    }
    return false;
  }

  alignas(moho::CRotateManipulatorTypeInfo)
  unsigned char gCRotateManipulatorTypeInfoStorage[sizeof(moho::CRotateManipulatorTypeInfo)] = {};
  bool gCRotateManipulatorTypeInfoConstructed = false;

  [[nodiscard]] moho::CRotateManipulatorTypeInfo* AcquireCRotateManipulatorTypeInfo()
  {
    if (!gCRotateManipulatorTypeInfoConstructed) {
      new (gCRotateManipulatorTypeInfoStorage) moho::CRotateManipulatorTypeInfo();
      gCRotateManipulatorTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CRotateManipulatorTypeInfo*>(gCRotateManipulatorTypeInfoStorage);
  }

  [[nodiscard]] moho::CRotateManipulatorTypeInfo* PeekCRotateManipulatorTypeInfo() noexcept
  {
    if (!gCRotateManipulatorTypeInfoConstructed) {
      return nullptr;
    }
    return reinterpret_cast<moho::CRotateManipulatorTypeInfo*>(gCRotateManipulatorTypeInfoStorage);
  }

  /**
   * Address: 0x00643410 (FUN_00643410)
   *
   * What it does:
   * Constructs and preregisters startup reflection metadata for
   * `CRotateManipulator`.
   */
  [[nodiscard]] gpg::RType* preregister_CRotateManipulatorTypeInfo()
  {
    moho::CRotateManipulatorTypeInfo* const typeInfo = AcquireCRotateManipulatorTypeInfo();
    gpg::PreRegisterRType(typeid(moho::CRotateManipulator), typeInfo);
    return typeInfo;
  }

  void cleanup_CRotateManipulatorTypeInfo()
  {
    moho::CRotateManipulatorTypeInfo* const typeInfo = PeekCRotateManipulatorTypeInfo();
    if (!typeInfo) {
      return;
    }

    typeInfo->~CRotateManipulatorTypeInfo();
    gCRotateManipulatorTypeInfoConstructed = false;
  }

  int register_CRotateManipulatorTypeInfoStartup()
  {
    (void)preregister_CRotateManipulatorTypeInfo();
    return std::atexit(&cleanup_CRotateManipulatorTypeInfo);
  }

  struct CRotateManipulatorTypeInfoStartupBootstrap
  {
    CRotateManipulatorTypeInfoStartupBootstrap()
    {
      (void)register_CRotateManipulatorTypeInfoStartup();
    }
  };

  CRotateManipulatorTypeInfoStartupBootstrap gCRotateManipulatorTypeInfoStartupBootstrap;

  /**
   * Address: 0x006452A0 (FUN_006452A0, sub_6452A0)
   *
   * What it does:
   * Resolves/caches reflection type metadata for `CRotateManipulator`.
   */
  [[nodiscard]] gpg::RType* CachedCRotateManipulatorType()
  {
    if (!moho::CRotateManipulator::sType) {
      moho::CRotateManipulator::sType = gpg::LookupRType(typeid(moho::CRotateManipulator));
    }
    return moho::CRotateManipulator::sType;
  }

  /**
   * Address: 0x006456B0 (FUN_006456B0)
   *
   * What it does:
   * Upcasts one reflected reference lane to `moho::CRotateManipulator*`.
   */
  [[maybe_unused]] [[nodiscard]] void* TryUpcastCRotateManipulatorRefObject(gpg::RRef* const sourceRef)
  {
    if (!sourceRef) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(*sourceRef, CachedCRotateManipulatorType());
    return upcast.mObj;
  }

  [[nodiscard]] gpg::RType* CachedIAniManipulatorType()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
  }

  /**
   * Address: 0x006458A0 (FUN_006458A0)
   *
   * What it does:
   * Deserializes one `CRotateManipulator` lane from IAniManipulator base data
   * plus rotate-state flags, axis, angular lanes, and follow-bone index.
   */
  [[maybe_unused]] void DeserializeCRotateManipulatorSerializerBody(
    moho::CRotateManipulator* const manipulator,
    gpg::ReadArchive* const archive
  )
  {
    if (!archive || !manipulator) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedIAniManipulatorType(), static_cast<moho::IAniManipulator*>(manipulator), owner);

    bool hasGoal = manipulator->mHasGoal != 0;
    archive->ReadBool(&hasGoal);
    manipulator->mHasGoal = static_cast<std::uint8_t>(hasGoal ? 1 : 0);

    bool spinDown = manipulator->mSpinDown != 0;
    archive->ReadBool(&spinDown);
    manipulator->mSpinDown = static_cast<std::uint8_t>(spinDown ? 1 : 0);

    archive->Read(CachedVector3fType(), &manipulator->mAxis, owner);
    archive->ReadFloat(&manipulator->mCurrentAngle);
    archive->ReadFloat(&manipulator->mGoalAngle);
    archive->ReadFloat(&manipulator->mSpeed);
    archive->ReadFloat(&manipulator->mTargetSpeed);
    archive->ReadFloat(&manipulator->mAccel);
    archive->ReadInt(&manipulator->mFollowBone);
  }

  /**
   * Address: 0x006459A0 (FUN_006459A0)
   *
   * What it does:
   * Serializes one `CRotateManipulator` lane to IAniManipulator base data plus
   * rotate-state flags, axis, angular lanes, and follow-bone index.
   */
  [[maybe_unused]] void SerializeCRotateManipulatorSerializerBody(
    const moho::CRotateManipulator* const manipulator,
    gpg::WriteArchive* const archive
  )
  {
    if (!archive || !manipulator) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(CachedIAniManipulatorType(), manipulator, owner);
    archive->WriteBool(manipulator->mHasGoal != 0);
    archive->WriteBool(manipulator->mSpinDown != 0);
    archive->Write(CachedVector3fType(), &manipulator->mAxis, owner);
    archive->WriteFloat(manipulator->mCurrentAngle);
    archive->WriteFloat(manipulator->mGoalAngle);
    archive->WriteFloat(manipulator->mSpeed);
    archive->WriteFloat(manipulator->mTargetSpeed);
    archive->WriteFloat(manipulator->mAccel);
    archive->WriteInt(manipulator->mFollowBone);
  }

  /**
   * Address: 0x00645520 (FUN_00645520)
   *
   * What it does:
   * First tail-thunk alias that forwards rotate manipulator deserialize lanes
   * into the shared serializer body.
   */
  [[maybe_unused]] void DeserializeCRotateManipulatorSerializerThunkAliasA(
    moho::CRotateManipulator* const manipulator,
    gpg::ReadArchive* const archive
  )
  {
    DeserializeCRotateManipulatorSerializerBody(manipulator, archive);
  }

  /**
   * Address: 0x00645530 (FUN_00645530)
   *
   * What it does:
   * First tail-thunk alias that forwards rotate manipulator serialize lanes
   * into the shared serializer body.
   */
  [[maybe_unused]] void SerializeCRotateManipulatorSerializerThunkAliasA(
    const moho::CRotateManipulator* const manipulator,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCRotateManipulatorSerializerBody(manipulator, archive);
  }

  /**
   * Address: 0x00645690 (FUN_00645690)
   *
   * What it does:
   * Second tail-thunk alias that forwards rotate manipulator deserialize lanes
   * into the shared serializer body.
   */
  [[maybe_unused]] void DeserializeCRotateManipulatorSerializerThunkAliasB(
    moho::CRotateManipulator* const manipulator,
    gpg::ReadArchive* const archive
  )
  {
    DeserializeCRotateManipulatorSerializerBody(manipulator, archive);
  }

  /**
   * Address: 0x006456A0 (FUN_006456A0)
   *
   * What it does:
   * Second tail-thunk alias that forwards rotate manipulator serialize lanes
   * into the shared serializer body.
   */
  [[maybe_unused]] void SerializeCRotateManipulatorSerializerThunkAliasB(
    const moho::CRotateManipulator* const manipulator,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCRotateManipulatorSerializerBody(manipulator, archive);
  }

  struct CRotateManipulatorSerializerHelperNode
  {
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(sizeof(CRotateManipulatorSerializerHelperNode) == 0x10, "CRotateManipulatorSerializerHelperNode size must be 0x10");

  CRotateManipulatorSerializerHelperNode gCRotateManipulatorSerializer;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(THelper& helper) noexcept
  {
    if (helper.mNext != nullptr && helper.mPrev != nullptr) {
      helper.mNext->mPrev = helper.mPrev;
      helper.mPrev->mNext = helper.mNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(helper);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  void DeserializeCRotateManipulatorSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const manipulator = reinterpret_cast<moho::CRotateManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    DeserializeCRotateManipulatorSerializerBody(manipulator, archive);
  }

  void SerializeCRotateManipulatorSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    const auto* const manipulator =
      reinterpret_cast<const moho::CRotateManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    SerializeCRotateManipulatorSerializerBody(manipulator, archive);
  }

  /**
   * Address: 0x006435A0 (FUN_006435A0)
   *
   * What it does:
   * Initializes callback lanes for global `CRotateManipulator` serializer
   * helper storage and returns that helper object.
   */
  [[maybe_unused]] [[nodiscard]] CRotateManipulatorSerializerHelperNode*
  InitializeCRotateManipulatorSerializerStartupThunkPrimary()
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(gCRotateManipulatorSerializer);
    gCRotateManipulatorSerializer.mPrev = self;
    gCRotateManipulatorSerializer.mNext = self;
    gCRotateManipulatorSerializer.mSerLoadFunc = &DeserializeCRotateManipulatorSerializerCallback;
    gCRotateManipulatorSerializer.mSerSaveFunc = &SerializeCRotateManipulatorSerializerCallback;
    return &gCRotateManipulatorSerializer;
  }

  /**
   * Address: 0x006452E0 (FUN_006452E0)
   *
   * What it does:
   * Secondary startup-init entry for global `CRotateManipulator` serializer
   * helper storage that mirrors the primary callback initialization.
   */
  [[maybe_unused]] [[nodiscard]] CRotateManipulatorSerializerHelperNode*
  InitializeCRotateManipulatorSerializerStartupThunkSecondary()
  {
    return InitializeCRotateManipulatorSerializerStartupThunkPrimary();
  }

  /**
   * Address: 0x006435D0 (FUN_006435D0)
   *
   * What it does:
   * Startup cleanup variant that unlinks and self-resets the global
   * CRotateManipulator serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CRotateManipulatorSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(gCRotateManipulatorSerializer);
  }

  /**
   * Address: 0x00643600 (FUN_00643600)
   *
   * What it does:
   * Secondary startup cleanup variant that unlinks and self-resets the global
   * CRotateManipulator serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CRotateManipulatorSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(gCRotateManipulatorSerializer);
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

  [[nodiscard]] moho::CRotateManipulator*
  GetCRotateManipulatorOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
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
    const gpg::RType* const rotateType = CachedCRotateManipulatorType();
    const gpg::RRef upcast = rotateType ? gpg::REF_UpcastPtr(sourceRef, rotateType) : gpg::RRef{};
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CRotateManipulator*>(upcast.mObj);
  }

  [[nodiscard]] moho::CRotateManipulator* RequireRotateManipulator(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* const state,
    const char* const invalidObjectError
  )
  {
    moho::CRotateManipulator* const manipulator = GetCRotateManipulatorOptional(object, state);
    if (manipulator != nullptr) {
      return manipulator;
    }

    lua_pushstring(state->m_state, invalidObjectError);
    (void)lua_gettop(state->m_state);
    lua_error(state->m_state);
    return nullptr;
  }
} // namespace

namespace moho
{
  gpg::RType* CRotateManipulator::sType = nullptr;
} // namespace moho

/**
 * Address: 0x00643630 (FUN_00643630)
 *
 * What it does:
 * Builds detached/default rotate-manipulator state for reflection
 * construction paths.
 */
moho::CRotateManipulator::CRotateManipulator()
  : IAniManipulator()
{
  mHasGoal = 0u;
  mSpinDown = 0u;
  mAxis = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
  mCurrentAngle = 0.0f;
  mGoalAngle = 0.0f;
  mSpeed = 0.0f;
  mTargetSpeed = 0.0f;
  mAccel = 0.0f;
  mFollowBone = -1;
}

/**
 * Address: 0x006436E0 (FUN_006436E0, ??0CRotateManipulator@Moho@@QAE@@Z)
 *
 * What it does:
 * Builds a rotate manipulator bound to one owner actor/bone with one
 * configured axis lane.
 */
moho::CRotateManipulator::CRotateManipulator(
  const Wm3::Vector3f& axis,
  moho::Sim* const sim,
  moho::CAniActor* const ownerActor,
  const int watchedBoneIndex
)
  : IAniManipulator(sim, ownerActor, 0)
{
  mHasGoal = 0u;
  mSpinDown = 0u;
  mAxis = axis;
  mCurrentAngle = 0.0f;
  mGoalAngle = 0.0f;
  mSpeed = 0.0f;
  mTargetSpeed = 0.0f;
  mAccel = 0.0f;
  mFollowBone = -1;

  LuaPlus::LuaObject arg3{};
  LuaPlus::LuaObject arg2{};
  LuaPlus::LuaObject arg1{};
  LuaPlus::LuaObject scriptFactory = moho::CreateRotateManipulatorLuaMetatable(sim->mLuaState);
  CreateLuaObject(scriptFactory, arg1, arg2, arg3);

  AddWatchBone(watchedBoneIndex);
  EventSetSignaled(true);
}

/**
 * Address: 0x00643CF0 (FUN_00643CF0, Moho::CRotateManipulator::SetCurrentAngle)
 *
 * What it does:
 * Applies one immediate angle to the watched bone and marks that pose lane
 * to skip interpolation on the next frame.
 */
bool moho::CRotateManipulator::SetCurrentAngle(const float angleRadians)
{
  if (mOwnerActor == nullptr || mOwnerActor->mPose.px == nullptr || mWatchBones.mBegin == nullptr) {
    return false;
  }

  const std::int32_t watchedBoneIndex = mWatchBones.mBegin->mBoneIndex;
  moho::CAniPoseBone* const watchedBone = ResolvePoseBone(mOwnerActor, watchedBoneIndex);
  if (watchedBone == nullptr) {
    return false;
  }

  watchedBone->mSkipNextInterp = 1u;
  Wm3::Quaternionf rotation{};
  moho::EulerRollToQuat(&mAxis, &rotation, angleRadians);
  watchedBone->Rotate(rotation);
  mCurrentAngle = angleRadians;
  return true;
}

/**
 * Address: 0x00643400 (FUN_00643400)
 *
 * What it does:
 * Sets spin-down mode flag lane.
 */
void moho::CRotateManipulator::SetSpinDownEnabled(const bool enabled) noexcept
{
  mSpinDown = enabled ? 1u : 0u;
}

/**
 * Address: 0x00643CD0 (FUN_00643CD0)
 *
 * What it does:
 * Updates follow-bone index and marks goal state dirty for next tick.
 */
void moho::CRotateManipulator::SetFollowBoneTarget(const int followBoneIndex) noexcept
{
  mFollowBone = followBoneIndex;
  mHasGoal = 1u;
}

/**
 * Address: 0x00643860 (FUN_00643860, Moho::CRotateManipulator::MoveManipulator)
 *
 * What it does:
 * Advances rotate-manipulator angular lanes (goal/follow/spin-down logic),
 * writes one updated watched-bone quaternion, and updates task signal state.
 */
bool moho::CRotateManipulator::ManipulatorUpdate()
{
  const SAniManipBinding* const watchedBinding = mWatchBones.mBegin;
  if (watchedBinding == nullptr || (watchedBinding->mFlags & kWatchBoneActiveFlag) == 0u) {
    return false;
  }

  if (mFollowBone >= 0) {
    if (CAniPoseBone* const followBone = ResolvePoseBone(mOwnerActor, mFollowBone)) {
      const VTransform& composite = followBone->GetCompositeTransform();
      const float x =
        ((composite.orient_.x * composite.orient_.z) + (composite.orient_.w * composite.orient_.y)) * 2.0f;
      const float y =
        1.0f - (((composite.orient_.z * composite.orient_.z) + (composite.orient_.y * composite.orient_.y)) * 2.0f);
      mGoalAngle = std::atan2(x, y);
    }
  }

  const float accelStep = std::fabs(mAccel);
  if (mSpinDown != 0u && mAccel != 0.0f) {
    const float spinDownTargetSpeed = mTargetSpeed * kSpinDownTargetScale;
    if (mSpeed > spinDownTargetSpeed) {
      if (std::fabs(mSpeed) > accelStep) {
        mSpeed += std::copysign(accelStep, -mSpeed);
      } else {
        mSpeed = spinDownTargetSpeed;
      }
      mCurrentAngle = moho::NormalizeAngleSignedRadians(mCurrentAngle + mSpeed);
      EventSetSignaled(false);
    } else if (std::fabs(mCurrentAngle) <= spinDownTargetSpeed) {
      mCurrentAngle *= kSpinDownAngleDampen;
      mSpeed = 0.0f;
      EventSetSignaled(true);
    } else {
      mCurrentAngle = moho::NormalizeAngleSignedRadians(mCurrentAngle + spinDownTargetSpeed);
      EventSetSignaled(false);
    }
  } else if (mHasGoal != 0u) {
    const float goalDelta = moho::NormalizeAngleSignedRadians(mGoalAngle - mCurrentAngle);
    if (mSpeed >= std::fabs(goalDelta)) {
      mCurrentAngle = mGoalAngle;
      EventSetSignaled(true);
    } else {
      mCurrentAngle += std::copysign(mSpeed, goalDelta);
      EventSetSignaled(false);
    }
  } else {
    if (mAccel != 0.0f && mSpeed != mTargetSpeed) {
      const float diff = mTargetSpeed - mSpeed;
      if (std::fabs(diff) > accelStep) {
        mSpeed += std::copysign(accelStep, diff);
      } else {
        mSpeed = mTargetSpeed;
      }
    }

    EventSetSignaled(mTargetSpeed == mSpeed);
    mCurrentAngle = moho::NormalizeAngleSignedRadians(mCurrentAngle + mSpeed);
  }

  if (CAniPoseBone* const watchedBone = ResolvePoseBone(mOwnerActor, watchedBinding->mBoneIndex)) {
    Wm3::Quaternionf rotation{};
    moho::EulerRollToQuat(&mAxis, &rotation, mCurrentAngle);
    watchedBone->Rotate(rotation);
  }

  return true;
}

/**
 * Address: 0x00643D80 (FUN_00643D80, cfunc_CreateRotator)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CreateRotatorL`.
 */
int moho::cfunc_CreateRotator(lua_State* const luaContext)
{
  return cfunc_CreateRotatorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00643DA0 (FUN_00643DA0, func_CreateRotator_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `CreateRotator(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CreateRotator_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCreateRotatorMethodName,
    &moho::cfunc_CreateRotator,
    nullptr,
    kCreateRotatorClassName,
    kCreateRotatorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00643E00 (FUN_00643E00, cfunc_CreateRotatorL)
 *
 * What it does:
 * Builds one `CRotateManipulator` from
 * `(unit, bone, axis, [goal], [speed], [accel], [goalspeed])`.
 */
int moho::cfunc_CreateRotatorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 3 || argumentCount > 7) {
    LuaPlus::LuaState::Error(state, kLuaExpectedBetweenArgsWarning, kCreateRotatorHelpText, 3, 7, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  moho::Unit* const unit = moho::SCR_FromLua_Unit(unitObject);
  (void)unit->AniActor->GetSkeleton();

  LuaPlus::LuaStackObject boneArg(state, 2);
  const int watchedBoneIndex = moho::ENTSCR_ResolveBoneIndex(unit, boneArg, false);

  LuaPlus::LuaStackObject axisArg(state, 3);
  const char* axisText = lua_tostring(rawState, 3);
  if (!axisText) {
    axisArg.TypeError("string");
  }

  Wm3::Vector3f axis{};
  if (!ParseAxisText(axisText, &axis)) {
    LuaPlus::LuaState::Error(state, kInvalidAxisError, axisArg.GetString());
  }

  moho::CRotateManipulator* const manipulator =
    new moho::CRotateManipulator(axis, unit->SimulationRef, unit->AniActor, watchedBoneIndex);

  if (argumentCount >= 4 && lua_type(rawState, 4) != LUA_TNIL) {
    LuaPlus::LuaStackObject goalArg(state, 4);
    const float goalRadians = goalArg.GetNumber() * kDegreesToRadians;
    manipulator->mHasGoal = 1u;
    manipulator->mGoalAngle = goalRadians;
    manipulator->EventSetSignaled(goalRadians == manipulator->mCurrentAngle);
    manipulator->mSpeed = std::numeric_limits<float>::infinity() * kDegreesPerSecondToRadians;
  }

  if (argumentCount >= 5 && lua_type(rawState, 5) != LUA_TNIL) {
    LuaPlus::LuaStackObject speedArg(state, 5);
    manipulator->mSpeed = speedArg.GetNumber() * kDegreesPerSecondToRadians;
  }

  if (argumentCount >= 6 && lua_type(rawState, 6) != LUA_TNIL) {
    LuaPlus::LuaStackObject accelArg(state, 6);
    manipulator->mAccel = accelArg.GetNumber() * kDegreesPerSecondSquaredToRadians;
  }

  if (argumentCount >= 7 && lua_type(rawState, 7) != LUA_TNIL) {
    LuaPlus::LuaStackObject targetSpeedArg(state, 7);
    const float targetSpeed = targetSpeedArg.GetNumber() * kDegreesPerSecondToRadians;
    manipulator->mTargetSpeed = targetSpeed;
    manipulator->EventSetSignaled(manipulator->mSpeed == targetSpeed);
  }

  manipulator->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00644280 (FUN_00644280, cfunc_CRotateManipulatorSetSpinDown)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CRotateManipulatorSetSpinDownL`.
 */
int moho::cfunc_CRotateManipulatorSetSpinDown(lua_State* const luaContext)
{
  return cfunc_CRotateManipulatorSetSpinDownL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00644300 (FUN_00644300, cfunc_CRotateManipulatorSetSpinDownL)
 *
 * What it does:
 * Reads `(rotator, enabled)`, validates the rotator object, sets spin-down
 * mode, and returns the rotator Lua object.
 */
int moho::cfunc_CRotateManipulatorSetSpinDownL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetSpinDownHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CRotateManipulator* const manipulator = RequireRotateManipulator(manipObject, state, kInvalidSpinDownError);
  manipulator->SetSpinDownEnabled(LuaPlus::LuaStackObject(state, 2).GetBoolean());

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x006443F0 (FUN_006443F0, cfunc_CRotateManipulatorSetGoal)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CRotateManipulatorSetGoalL`.
 */
int moho::cfunc_CRotateManipulatorSetGoal(lua_State* const luaContext)
{
  return cfunc_CRotateManipulatorSetGoalL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00644470 (FUN_00644470, cfunc_CRotateManipulatorSetGoalL)
 *
 * What it does:
 * Reads `(rotator, goalDegrees)`, validates numeric input, converts to
 * radians, stores goal angle, and updates triggered state.
 */
int moho::cfunc_CRotateManipulatorSetGoalL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetGoalHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CRotateManipulator* const manipulator = RequireRotateManipulator(manipObject, state, kInvalidGoalError);

  LuaPlus::LuaStackObject goalArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    goalArg.TypeError("number");
  }

  const float goalRadians = static_cast<float>(lua_tonumber(rawState, 2)) * kDegreesToRadians;
  manipulator->mHasGoal = 1u;
  manipulator->mGoalAngle = goalRadians;
  manipulator->EventSetSignaled(goalRadians == manipulator->mCurrentAngle);

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x00644710 (FUN_00644710, cfunc_CRotateManipulatorSetSpeed)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CRotateManipulatorSetSpeedL`.
 */
int moho::cfunc_CRotateManipulatorSetSpeed(lua_State* const luaContext)
{
  return cfunc_CRotateManipulatorSetSpeedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00644790 (FUN_00644790, cfunc_CRotateManipulatorSetSpeedL)
 *
 * What it does:
 * Reads `(rotator, speedDegPerSec)`, validates numeric input, converts to
 * radians/sec, and stores runtime speed lane.
 */
int moho::cfunc_CRotateManipulatorSetSpeedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetSpeedHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CRotateManipulator* const manipulator = RequireRotateManipulator(manipObject, state, kInvalidSpeedError);

  LuaPlus::LuaStackObject speedArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    speedArg.TypeError("number");
  }

  manipulator->mSpeed = static_cast<float>(lua_tonumber(rawState, 2)) * kDegreesPerSecondToRadians;
  lua_settop(rawState, 1);
  return 1;
}

int moho::cfunc_CRotateManipulatorSetTargetSpeed(lua_State* const luaContext)
{
  return cfunc_CRotateManipulatorSetTargetSpeedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00644930 (FUN_00644930, cfunc_CRotateManipulatorSetTargetSpeedL)
 *
 * What it does:
 * Reads `(rotator, targetSpeedDegPerSec)`, validates numeric input, converts
 * to radians/sec, stores target speed, and updates triggered state.
 */
int moho::cfunc_CRotateManipulatorSetTargetSpeedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetTargetSpeedHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CRotateManipulator* const manipulator = RequireRotateManipulator(manipObject, state, kInvalidTargetSpeedError);

  LuaPlus::LuaStackObject targetSpeedArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    targetSpeedArg.TypeError("number");
  }

  const float targetSpeed = static_cast<float>(lua_tonumber(rawState, 2)) * kDegreesPerSecondToRadians;
  manipulator->mTargetSpeed = targetSpeed;
  manipulator->EventSetSignaled(manipulator->mSpeed == targetSpeed);

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x00644A80 (FUN_00644A80, cfunc_CRotateManipulatorSetAccel)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CRotateManipulatorSetAccelL`.
 */
int moho::cfunc_CRotateManipulatorSetAccel(lua_State* const luaContext)
{
  return cfunc_CRotateManipulatorSetAccelL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00644B00 (FUN_00644B00, cfunc_CRotateManipulatorSetAccelL)
 *
 * What it does:
 * Reads `(rotator, accelDegPerSecSq)`, validates numeric input, converts to
 * radians/sec^2, and stores runtime acceleration lane.
 */
int moho::cfunc_CRotateManipulatorSetAccelL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAccelHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CRotateManipulator* const manipulator = RequireRotateManipulator(manipObject, state, kInvalidAccelError);

  LuaPlus::LuaStackObject accelArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    accelArg.TypeError("number");
  }

  manipulator->mAccel = static_cast<float>(lua_tonumber(rawState, 2)) * kDegreesPerSecondSquaredToRadians;
  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x00644C20 (FUN_00644C20, cfunc_CRotateManipulatorClearFollowBone)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CRotateManipulatorClearFollowBoneL`.
 */
int moho::cfunc_CRotateManipulatorClearFollowBone(lua_State* const luaContext)
{
  return cfunc_CRotateManipulatorClearFollowBoneL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00644CA0 (FUN_00644CA0, cfunc_CRotateManipulatorClearFollowBoneL)
 *
 * What it does:
 * Reads `(rotator)`, clears follow-bone target (`-1`) and marks goal state
 * dirty, then returns the rotator Lua object.
 */
int moho::cfunc_CRotateManipulatorClearFollowBoneL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kClearFollowBoneHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CRotateManipulator* const manipulator = RequireRotateManipulator(manipObject, state, kInvalidClearFollowBoneError);
  manipulator->SetFollowBoneTarget(-1);

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x00644D90 (FUN_00644D90, cfunc_CRotateManipulatorSetFollowBone)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CRotateManipulatorSetFollowBoneL`.
 */
int moho::cfunc_CRotateManipulatorSetFollowBone(lua_State* const luaContext)
{
  return cfunc_CRotateManipulatorSetFollowBoneL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00644E10 (FUN_00644E10, cfunc_CRotateManipulatorSetFollowBoneL)
 *
 * What it does:
 * Reads `(rotator, bone)`, resolves bone index through owner actor, assigns
 * follow-bone target, and returns the rotator Lua object.
 */
int moho::cfunc_CRotateManipulatorSetFollowBoneL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetFollowBoneHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CRotateManipulator* const manipulator = RequireRotateManipulator(manipObject, state, kInvalidSetFollowBoneError);

  LuaPlus::LuaStackObject boneArg(state, 2);
  const int followBone = manipulator->mOwnerActor ? manipulator->mOwnerActor->ResolveBoneIndex(boneArg) : -1;
  if (followBone < 0) {
    LuaPlus::LuaState::Error(state, "A valid bone is required");
  }

  manipulator->SetFollowBoneTarget(followBone);
  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x00644F30 (FUN_00644F30, cfunc_CRotateManipulatorGetCurrentAngle)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CRotateManipulatorGetCurrentAngleL`.
 */
int moho::cfunc_CRotateManipulatorGetCurrentAngle(lua_State* const luaContext)
{
  return cfunc_CRotateManipulatorGetCurrentAngleL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00644FB0 (FUN_00644FB0, cfunc_CRotateManipulatorGetCurrentAngleL)
 *
 * What it does:
 * Reads `(rotator)`, pushes current angle in degrees, and returns one Lua
 * number.
 */
int moho::cfunc_CRotateManipulatorGetCurrentAngleL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetCurrentAngleHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CRotateManipulator* const manipulator = RequireRotateManipulator(manipObject, state, kInvalidGetCurrentAngleError);

  lua_pushnumber(rawState, manipulator->mCurrentAngle * kRadiansToDegrees);
  (void)lua_gettop(rawState);
  return 1;
}

int moho::cfunc_CRotateManipulatorSetCurrentAngle(lua_State* const luaContext)
{
  return cfunc_CRotateManipulatorSetCurrentAngleL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00645120 (FUN_00645120, cfunc_CRotateManipulatorSetCurrentAngleL)
 *
 * What it does:
 * Reads `(rotator, angleDegrees)`, validates numeric input, converts to
 * radians, applies current-angle lane, and raises Lua error on failure.
 */
int moho::cfunc_CRotateManipulatorSetCurrentAngleL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetCurrentAngleHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CRotateManipulator* const manipulator = RequireRotateManipulator(manipObject, state, kInvalidGetCurrentAngleError);

  LuaPlus::LuaStackObject angleArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    angleArg.TypeError("number");
  }

  const float angleRadians = static_cast<float>(lua_tonumber(rawState, 2)) * kDegreesToRadians;
  if (!manipulator->SetCurrentAngle(angleRadians)) {
    lua_pushstring(rawState, kCouldNotSetCurrentAngleError);
    (void)lua_gettop(rawState);
    lua_error(rawState);
  }

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x006434B0 (FUN_006434B0, Moho::CRotateManipulatorTypeInfo::GetName)
 *
 * What it does:
 * Returns the literal type name "CRotateManipulator" for reflection.
 */
const char* moho::CRotateManipulatorTypeInfo::GetName() const
{
  return "CRotateManipulator";
}

/**
 * Address: 0x006452C0 (FUN_006452C0)
 *
 * What it does:
 * Installs all reflection lifecycle callbacks on one type-info instance.
 */
moho::CRotateManipulatorTypeInfo* moho::CRotateManipulatorTypeInfo::ConfigureLifecycleCallbacks(
  moho::CRotateManipulatorTypeInfo* const typeInfo
)
{
  typeInfo->newRefFunc_ = &moho::CRotateManipulatorTypeInfo::NewRef;
  typeInfo->ctorRefFunc_ = &moho::CRotateManipulatorTypeInfo::CtrRef;
  typeInfo->deleteFunc_ = &moho::CRotateManipulatorTypeInfo::Delete;
  typeInfo->dtrFunc_ = &moho::CRotateManipulatorTypeInfo::Destruct;
  return typeInfo;
}

/**
 * Address: 0x00645380 (FUN_00645380)
 *
 * What it does:
 * Installs allocation and placement-construction callback lanes.
 */
moho::CRotateManipulatorTypeInfo* moho::CRotateManipulatorTypeInfo::ConfigureCtorCallbacks(
  moho::CRotateManipulatorTypeInfo* const typeInfo
)
{
  typeInfo->newRefFunc_ = &moho::CRotateManipulatorTypeInfo::NewRef;
  typeInfo->ctorRefFunc_ = &moho::CRotateManipulatorTypeInfo::CtrRef;
  return typeInfo;
}

/**
 * Address: 0x00645390 (FUN_00645390)
 *
 * What it does:
 * Installs deletion and in-place destruction callback lanes.
 */
moho::CRotateManipulatorTypeInfo* moho::CRotateManipulatorTypeInfo::ConfigureDtorCallbacks(
  moho::CRotateManipulatorTypeInfo* const typeInfo
)
{
  typeInfo->deleteFunc_ = &moho::CRotateManipulatorTypeInfo::Delete;
  typeInfo->dtrFunc_ = &moho::CRotateManipulatorTypeInfo::Destruct;
  return typeInfo;
}

/**
 * Address: 0x00643470 (FUN_00643470, Moho::CRotateManipulatorTypeInfo::Init)
 *
 * What it does:
 * Sets reflected size/callback lanes for `CRotateManipulator`, registers
 * `IAniManipulator` base metadata, then finalizes type initialization.
 */
void moho::CRotateManipulatorTypeInfo::Init()
{
  size_ = sizeof(moho::CRotateManipulator);
  ConfigureLifecycleCallbacks(this);
  AddBase_IAniManipulator(this);
  gpg::RType::Init();
  Finish();
}

gpg::RRef moho::CRotateManipulatorTypeInfo::NewRef()
{
  auto* const storage = static_cast<moho::CRotateManipulator*>(::operator new(sizeof(moho::CRotateManipulator), std::nothrow));
  moho::CRotateManipulator* object = nullptr;
  if (storage) {
    object = new (storage) moho::CRotateManipulator();
  }

  gpg::RRef out{};
  gpg::RRef_CRotateManipulator(&out, object);
  return out;
}

/**
 * Address: 0x00645440 (FUN_00645440, Moho::CRotateManipulatorTypeInfo::CtrRef)
 *
 * What it does:
 * Constructs one detached `CRotateManipulator` in caller-owned storage and
 * returns its typed reflection reference.
 */
gpg::RRef moho::CRotateManipulatorTypeInfo::CtrRef(void* const objectStorage)
{
  moho::CRotateManipulator* object = nullptr;
  if (objectStorage != nullptr) {
    object = new (objectStorage) moho::CRotateManipulator();
  }

  gpg::RRef out{};
  gpg::RRef_CRotateManipulator(&out, object);
  return out;
}

void moho::CRotateManipulatorTypeInfo::Delete(void* const objectStorage)
{
  delete static_cast<moho::CRotateManipulator*>(objectStorage);
}

void moho::CRotateManipulatorTypeInfo::Destruct(void* const objectStorage)
{
  if (objectStorage != nullptr) {
    static_cast<moho::CRotateManipulator*>(objectStorage)->~CRotateManipulator();
  }
}

void moho::CRotateManipulatorTypeInfo::AddBase_IAniManipulator(gpg::RType* const typeInfo)
{
  gpg::RType* baseType = moho::IAniManipulator::sType;
  if (!baseType) {
    baseType = gpg::LookupRType(typeid(moho::IAniManipulator));
    moho::IAniManipulator::sType = baseType;
  }

  gpg::RField baseField{};
  baseField.mName = baseType->GetName();
  baseField.mType = baseType;
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
  * Alias of FUN_006456F0 (non-canonical helper lane).
 *
 * What it does:
 * Builds one typed reflection reference for `moho::CRotateManipulator*`,
 * preserving dynamic-derived ownership and base-offset adjustment.
 */
gpg::RRef* gpg::RRef_CRotateManipulator(gpg::RRef* const outRef, moho::CRotateManipulator* const value)
{
  const gpg::RRef typed = MakeDerivedRef(value, CachedCRotateManipulatorType());
  outRef->mObj = typed.mObj;
  outRef->mType = typed.mType;
  return outRef;
}
