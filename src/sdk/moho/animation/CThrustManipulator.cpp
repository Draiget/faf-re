#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <typeinfo>

#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/ManipulatorLuaFunctionThunks.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/render/camera/VTransform.h"

namespace moho
{
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace
{
  constexpr std::uint32_t kWatchBoneActiveFlag = 0x00008000u;
  constexpr float kThrustLimitMin = -100.0f;
  constexpr float kThrustLimitMax = 100.0f;
  constexpr float kThrustDefaultForceMult = 1.0f;
  constexpr float kThrustDefaultTurnSpeed = 0.30000001f;

  struct CThrustManipulatorSerializerHelperNode
  {
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(sizeof(CThrustManipulatorSerializerHelperNode) == 0x10, "CThrustManipulatorSerializerHelperNode size must be 0x10");

  CThrustManipulatorSerializerHelperNode gCThrustManipulatorSerializer;

  using ScalarDeletingDtorFn = int(__thiscall*)(void* self, int deleteFlag);

  struct CThrustManipulatorTypeLifecycleSlotsRuntimeView
  {
    std::uint8_t mPad00_47[0x48]{}; // +0x00
    void* mNewRefFunc = nullptr;    // +0x48
    void* mPad4C = nullptr;         // +0x4C
    void* mDeleteFunc = nullptr;    // +0x50
    void* mCtorRefFunc = nullptr;   // +0x54
    void* mPad58 = nullptr;         // +0x58
    void* mDestructFunc = nullptr;  // +0x5C
  };
#if INTPTR_MAX == INT32_MAX
  static_assert(
    offsetof(CThrustManipulatorTypeLifecycleSlotsRuntimeView, mNewRefFunc) == 0x48,
    "CThrustManipulatorTypeLifecycleSlotsRuntimeView::mNewRefFunc offset must be 0x48"
  );
  static_assert(
    offsetof(CThrustManipulatorTypeLifecycleSlotsRuntimeView, mDeleteFunc) == 0x50,
    "CThrustManipulatorTypeLifecycleSlotsRuntimeView::mDeleteFunc offset must be 0x50"
  );
  static_assert(
    offsetof(CThrustManipulatorTypeLifecycleSlotsRuntimeView, mCtorRefFunc) == 0x54,
    "CThrustManipulatorTypeLifecycleSlotsRuntimeView::mCtorRefFunc offset must be 0x54"
  );
  static_assert(
    offsetof(CThrustManipulatorTypeLifecycleSlotsRuntimeView, mDestructFunc) == 0x5C,
    "CThrustManipulatorTypeLifecycleSlotsRuntimeView::mDestructFunc offset must be 0x5C"
  );
#endif

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

  [[nodiscard]] gpg::RType* CachedIAniManipulatorType()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
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

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Quaternionf));
    }
    return type;
  }

  struct CThrustManipulatorSerializerRuntimeView : moho::IAniManipulator
  {
    moho::WeakPtr<moho::Unit> mUnit; // +0x80
    msvc8::string mLabel;            // +0x88
    std::int32_t mStateLane;         // +0xA4
    bool mEnabledLane;               // +0xA8
    std::uint8_t mPadA9AB[0x3]{};    // +0xA9
    Wm3::Vector3f mCapMin;           // +0xAC
    Wm3::Vector3f mCapMax;           // +0xB8
    float mTurnForceMult;            // +0xC4
    float mTurnSpeed;                // +0xC8
    Wm3::Vector3f mDirectionLane;    // +0xCC
    Wm3::Quaternionf mOrientation;   // +0xD8
  };

  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mUnit) == 0x80,
    "CThrustManipulatorSerializerRuntimeView::mUnit offset must be 0x80"
  );
  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mLabel) == 0x88,
    "CThrustManipulatorSerializerRuntimeView::mLabel offset must be 0x88"
  );
  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mStateLane) == 0xA4,
    "CThrustManipulatorSerializerRuntimeView::mStateLane offset must be 0xA4"
  );
  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mEnabledLane) == 0xA8,
    "CThrustManipulatorSerializerRuntimeView::mEnabledLane offset must be 0xA8"
  );
  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mCapMin) == 0xAC,
    "CThrustManipulatorSerializerRuntimeView::mCapMin offset must be 0xAC"
  );
  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mCapMax) == 0xB8,
    "CThrustManipulatorSerializerRuntimeView::mCapMax offset must be 0xB8"
  );
  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mTurnForceMult) == 0xC4,
    "CThrustManipulatorSerializerRuntimeView::mTurnForceMult offset must be 0xC4"
  );
  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mTurnSpeed) == 0xC8,
    "CThrustManipulatorSerializerRuntimeView::mTurnSpeed offset must be 0xC8"
  );
  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mDirectionLane) == 0xCC,
    "CThrustManipulatorSerializerRuntimeView::mDirectionLane offset must be 0xCC"
  );
  static_assert(
    offsetof(CThrustManipulatorSerializerRuntimeView, mOrientation) == 0xD8,
    "CThrustManipulatorSerializerRuntimeView::mOrientation offset must be 0xD8"
  );
  static_assert(
    sizeof(CThrustManipulatorSerializerRuntimeView) == 0xE8,
    "CThrustManipulatorSerializerRuntimeView size must be 0xE8"
  );

  [[nodiscard]] moho::CAniPoseBone* ResolveWatchedBoneForThrustManipulator(
    moho::IAniManipulator* const manipulator
  ) noexcept
  {
    if (manipulator == nullptr || manipulator->mOwnerActor == nullptr ||
        manipulator->mWatchBones.mBegin == manipulator->mWatchBones.mEnd) {
      return nullptr;
    }

    moho::CAniPose* const pose = manipulator->mOwnerActor->mPose.px;
    if (pose == nullptr || pose->mBones.begin() == nullptr || pose->mBones.end() == nullptr) {
      return nullptr;
    }

    const std::int32_t boneIndex = manipulator->mWatchBones.mBegin->mBoneIndex;
    const std::ptrdiff_t boneCount = pose->mBones.end() - pose->mBones.begin();
    if (boneIndex < 0 || static_cast<std::ptrdiff_t>(boneIndex) >= boneCount) {
      return nullptr;
    }

    return &pose->mBones.begin()[boneIndex];
  }

  [[nodiscard]] Wm3::Quaternionf*
  BuildShortestArcDeltaQuaternion(
    Wm3::Quaternionf* const outDelta,
    const Wm3::Vector3f& targetNormal,
    const Wm3::Vector3f& currentUp
  ) noexcept
  {
    if (outDelta == nullptr) {
      return nullptr;
    }

    Wm3::Vector3f halfAxis{
      currentUp.x + targetNormal.x,
      currentUp.y + targetNormal.y,
      currentUp.z + targetNormal.z,
    };
    (void)Wm3::Vector3f::Normalize(&halfAxis);

    const float scalar = (currentUp.x * halfAxis.x) + (currentUp.y * halfAxis.y) + (currentUp.z * halfAxis.z);
    outDelta->x = scalar;
    if (scalar == 0.0f) {
      const double upAbsX = std::fabs(static_cast<double>(currentUp.x));
      const double upAbsY = std::fabs(static_cast<double>(currentUp.y));
      if (upAbsX < upAbsY) {
        const double inverseLength = 1.0 / std::sqrt((currentUp.y * currentUp.y) + (currentUp.z * currentUp.z));
        outDelta->y = 0.0f;
        outDelta->z = static_cast<float>(inverseLength * static_cast<double>(currentUp.z));
        outDelta->w = static_cast<float>(-inverseLength * static_cast<double>(currentUp.y));
      } else {
        const double inverseLength = 1.0 / std::sqrt((currentUp.x * currentUp.x) + (currentUp.z * currentUp.z));
        outDelta->z = 0.0f;
        outDelta->y = static_cast<float>(-inverseLength * static_cast<double>(currentUp.z));
        outDelta->w = static_cast<float>(inverseLength * static_cast<double>(currentUp.x));
      }
      return outDelta;
    }

    outDelta->y = (currentUp.y * halfAxis.z) - (currentUp.z * halfAxis.y);
    outDelta->z = (currentUp.z * halfAxis.x) - (currentUp.x * halfAxis.z);
    outDelta->w = (currentUp.x * halfAxis.y) - (currentUp.y * halfAxis.x);
    return outDelta;
  }

  [[nodiscard]] Wm3::Quaternionf* BlendThrustOrientationDelta(
    const Wm3::Quaternionf& currentOrientation,
    const Wm3::Quaternionf& targetOrientation,
    const float turnStepRadians,
    bool* const outNoStep,
    Wm3::Quaternionf* const outOrientation
  ) noexcept
  {
    if (outOrientation == nullptr) {
      return nullptr;
    }

    float current[4]{};
    float target[4]{};
    std::memcpy(current, &currentOrientation, sizeof(current));
    std::memcpy(target, &targetOrientation, sizeof(target));

    const float targetConjugate[4] = {
      target[0],
      -target[1],
      -target[2],
      -target[3],
    };

    float delta[4]{};
    delta[0] =
      (((current[0] * targetConjugate[0]) - (current[1] * targetConjugate[1])) -
       (current[2] * targetConjugate[2])) -
      (current[3] * targetConjugate[3]);
    delta[1] =
      (((current[3] * targetConjugate[2]) + (current[1] * targetConjugate[0])) +
       (current[0] * targetConjugate[1])) -
      (current[2] * targetConjugate[3]);
    delta[2] =
      (((current[2] * targetConjugate[0]) + (current[1] * targetConjugate[3])) +
       (current[0] * targetConjugate[2])) -
      (current[3] * targetConjugate[1]);
    delta[3] =
      (((current[3] * targetConjugate[0]) + (current[2] * targetConjugate[1])) +
       (current[0] * targetConjugate[3])) -
      (current[1] * targetConjugate[2]);

    Wm3::Quaternionf deltaQuat{};
    std::memcpy(&deltaQuat, delta, sizeof(delta));
    if (!moho::RotateQuatByAngle(&deltaQuat, turnStepRadians)) {
      if (outNoStep != nullptr) {
        *outNoStep = true;
      }
      std::memcpy(outOrientation, current, sizeof(current));
      return outOrientation;
    }

    std::memcpy(delta, &deltaQuat, sizeof(delta));
    float output[4]{};
    output[0] = (((target[0] * delta[0]) - (target[1] * delta[1])) - (target[2] * delta[2])) - (target[3] * delta[3]);
    output[1] = (((target[2] * delta[3]) + (target[1] * delta[0])) + (target[0] * delta[1])) - (target[3] * delta[2]);
    output[2] = (((target[3] * delta[1]) + (target[2] * delta[0])) + (target[0] * delta[2])) - (target[1] * delta[3]);
    output[3] = (((target[3] * delta[0]) + (target[1] * delta[2])) + (target[0] * delta[3])) - (target[2] * delta[1]);

    if (outNoStep != nullptr) {
      *outNoStep = false;
    }
    std::memcpy(outOrientation, output, sizeof(output));
    return outOrientation;
  }

  /**
   * Address: 0x0064B6E0 (FUN_0064B6E0, CThrustManipulator serializer load body)
   *
   * What it does:
   * Deserializes one `CThrustManipulator` lane by loading `IAniManipulator`
   * base state, unit weak-pointer lane, label/state lanes, thrust-cap vectors,
   * turn scalars, direction lane, and orientation quaternion.
   */
  [[maybe_unused]] void DeserializeCThrustManipulatorSerializerState(
    CThrustManipulatorSerializerRuntimeView* const object,
    gpg::ReadArchive* const archive
  )
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedIAniManipulatorType(), static_cast<moho::IAniManipulator*>(object), owner);
    archive->Read(CachedWeakPtrUnitType(), &object->mUnit, owner);
    archive->ReadString(&object->mLabel);
    archive->ReadInt(&object->mStateLane);
    archive->ReadBool(&object->mEnabledLane);
    archive->Read(CachedVector3fType(), &object->mCapMin, owner);
    archive->Read(CachedVector3fType(), &object->mCapMax, owner);
    archive->ReadFloat(&object->mTurnForceMult);
    archive->ReadFloat(&object->mTurnSpeed);
    archive->Read(CachedVector3fType(), &object->mDirectionLane, owner);
    archive->Read(CachedQuaternionfType(), &object->mOrientation, owner);
  }

  /**
   * Address: 0x0064A380 (FUN_0064A380)
   *
   * What it does:
   * Startup cleanup variant that unlinks and self-resets the global
   * CThrustManipulator serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CThrustManipulatorSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(gCThrustManipulatorSerializer);
  }

  /**
   * Address: 0x0064A3B0 (FUN_0064A3B0)
   *
   * What it does:
   * Secondary startup cleanup variant that unlinks and self-resets the global
   * CThrustManipulator serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CThrustManipulatorSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(gCThrustManipulatorSerializer);
  }
} // namespace

namespace moho
{
  [[nodiscard]] gpg::RType* CachedIAniManipulatorTypeForThrustManipulatorTypeInfo()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  [[maybe_unused]] gpg::RRef* BuildNewCThrustManipulatorRef(gpg::RRef* outRef);
  [[maybe_unused]] gpg::RRef* ConstructCThrustManipulatorRefInPlaceRuntime(
    gpg::RRef* outRef,
    void* objectStorage
  );

  /**
   * Address: 0x0064A3E0 (FUN_0064A3E0)
   *
   * What it does:
   * Builds one default detached `CThrustManipulator` runtime lane on top of
   * `IAniManipulator`, initializes weak-unit/string state, and seeds thrust cap
   * and turn scalar defaults used by typeinfo new/ctr callbacks.
   */
  [[maybe_unused]] CThrustManipulatorSerializerRuntimeView* InitializeCThrustManipulatorDefaultRuntime(
    CThrustManipulatorSerializerRuntimeView* const runtime
  ) noexcept
  {
    if (runtime == nullptr) {
      return nullptr;
    }

    (void)new (static_cast<void*>(runtime)) moho::IAniManipulator();

    static std::uint8_t sCThrustManipulatorPrimaryVTableTag = 0;
    static std::uint8_t sCThrustManipulatorScriptObjectVTableTag = 0;
    *reinterpret_cast<void**>(runtime) = &sCThrustManipulatorPrimaryVTableTag;
    *reinterpret_cast<void**>(reinterpret_cast<std::uint8_t*>(runtime) + 0x10) = &sCThrustManipulatorScriptObjectVTableTag;

    (void)new (static_cast<void*>(&runtime->mUnit)) moho::WeakPtr<moho::Unit>();
    (void)new (static_cast<void*>(&runtime->mLabel)) msvc8::string();
    runtime->mStateLane = 0;
    runtime->mEnabledLane = false;
    runtime->mCapMin = Wm3::Vector3f{kThrustLimitMin, kThrustLimitMin, kThrustLimitMin};
    runtime->mCapMax = Wm3::Vector3f{kThrustLimitMax, kThrustLimitMax, kThrustLimitMax};
    runtime->mTurnForceMult = kThrustDefaultForceMult;
    runtime->mTurnSpeed = kThrustDefaultTurnSpeed;
    return runtime;
  }

  /**
   * Address: 0x0064A230 (FUN_0064A230, Moho::CThrustManipulatorTypeInfo::Init)
   *
   * What it does:
   * Initializes one thrust-manipulator RTTI descriptor size/lifecycle callback
   * lanes, registers `IAniManipulator` as a zero-offset base, then finalizes
   * reflected metadata.
   */
  [[maybe_unused]] void InitCThrustManipulatorTypeInfo(gpg::RType* const typeInfo);

  /**
   * Address: 0x0064A4A0 (FUN_0064A4A0, Moho::CThrustManipulator::CThrustManipulator)
   *
   * What it does:
   * Builds one thrust manipulator bound to `{unit, bone}`, initializes weak
   * unit/link + label/state/cap defaults, creates Lua object lanes, and seeds
   * thrust direction/orientation from the watched bone local orientation.
   */
  [[maybe_unused]] CThrustManipulatorSerializerRuntimeView* ConstructCThrustManipulatorRuntime(
    CThrustManipulatorSerializerRuntimeView* const runtime,
    const char* const label,
    moho::Unit* const unit,
    const std::int32_t boneIndex
  )
  {
    if (runtime == nullptr || unit == nullptr) {
      return runtime;
    }

    (void)new (static_cast<void*>(runtime)) moho::IAniManipulator(unit->SimulationRef, unit->AniActor, 0);

    static std::uint8_t sCThrustManipulatorPrimaryVTableTag = 0;
    static std::uint8_t sCThrustManipulatorScriptObjectVTableTag = 0;
    *reinterpret_cast<void**>(runtime) = &sCThrustManipulatorPrimaryVTableTag;
    *reinterpret_cast<void**>(reinterpret_cast<std::uint8_t*>(runtime) + 0x10) = &sCThrustManipulatorScriptObjectVTableTag;

    (void)new (static_cast<void*>(&runtime->mUnit)) moho::WeakPtr<moho::Unit>();
    runtime->mUnit.ResetFromObject(unit);

    (void)new (static_cast<void*>(&runtime->mLabel)) msvc8::string((label != nullptr) ? label : "");
    runtime->mStateLane = 0;
    runtime->mEnabledLane = false;
    runtime->mCapMin = Wm3::Vector3f{kThrustLimitMin, kThrustLimitMin, kThrustLimitMin};
    runtime->mCapMax = Wm3::Vector3f{kThrustLimitMax, kThrustLimitMax, kThrustLimitMax};
    runtime->mTurnForceMult = kThrustDefaultForceMult;
    runtime->mTurnSpeed = kThrustDefaultTurnSpeed;

    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject object;
    (void)func_CreateLuaCThrustManipulator(&object, unit->SimulationRef ? unit->SimulationRef->mLuaState : nullptr);

    auto* const manipulator = reinterpret_cast<moho::IAniManipulator*>(runtime);
    auto* const scriptObject = static_cast<moho::CScriptObject*>(manipulator);
    scriptObject->CreateLuaObject(object, arg1, arg2, arg3);

    runtime->mStateLane = boneIndex;
    (void)manipulator->AddWatchBone(boneIndex);

    moho::CAniPoseBone* const watchedBone = ResolveWatchedBoneForThrustManipulator(manipulator);
    if (watchedBone == nullptr) {
      return runtime;
    }

    const Wm3::Quaternionf& orientation = watchedBone->mLocalTransform.orient_;
    runtime->mDirectionLane.y = ((orientation.w * orientation.z) - (orientation.x * orientation.y)) * 2.0f;
    runtime->mDirectionLane.x = ((orientation.x * orientation.z) + (orientation.w * orientation.y)) * 2.0f;
    runtime->mDirectionLane.z = 1.0f - (((orientation.z * orientation.z) + (orientation.y * orientation.y)) * 2.0f);

    const Wm3::Vector3f worldUp{0.0f, 1.0f, 0.0f};
    (void)BuildShortestArcDeltaQuaternion(&runtime->mOrientation, worldUp, runtime->mDirectionLane);
    return runtime;
  }

  /**
   * Address: 0x0064A800 (FUN_0064A800, Moho::CThrustManipulator::MoveManipulator)
   *
   * What it does:
   * Drives thrust manipulator orientation each tick from owner motion force and
   * roll lanes, clamps local thrust direction to configured caps, computes one
   * shortest-arc delta, applies turn-step interpolation, rotates the watched
   * bone, and stores the latest orientation delta state.
   */
  [[maybe_unused]] void UpdateCThrustManipulatorRuntime(CThrustManipulatorSerializerRuntimeView* const runtime)
  {
    if (runtime == nullptr) {
      return;
    }

    moho::Unit* const unit = runtime->mUnit.GetObjectPtr();
    if (unit == nullptr || unit->IsBeingBuilt()) {
      return;
    }

    auto* const manipulator = reinterpret_cast<moho::IAniManipulator*>(runtime);
    moho::CAniPoseBone* const watchedBone = ResolveWatchedBoneForThrustManipulator(manipulator);
    if (watchedBone == nullptr || unit->UnitMotion == nullptr) {
      return;
    }

    Wm3::Vector3f desiredDirection = unit->UnitMotion->mForce;

    Wm3::Quaternionf rollRotation{};
    const Wm3::Vector3f rollAxis{0.0f, 1.0f, 0.0f};
    (void)moho::EulerRollToQuat(&rollAxis, &rollRotation, unit->UnitMotion->mVector108.y);

    const moho::VTransform& unitTransform = unit->GetTransform();
    const moho::VTransform boneWorldTransform = unit->GetBoneWorldTransform(runtime->mStateLane);
    Wm3::Vector3f boneOffset{
      boneWorldTransform.pos_.x - unitTransform.pos_.x,
      boneWorldTransform.pos_.y - unitTransform.pos_.y,
      boneWorldTransform.pos_.z - unitTransform.pos_.z,
    };

    Wm3::Vector3f rolledOffset{};
    (void)moho::MultQuadVec(&rolledOffset, &boneOffset, &rollRotation);
    desiredDirection.x += (rolledOffset.x - boneOffset.x) * runtime->mTurnForceMult;
    desiredDirection.y += (rolledOffset.y - boneOffset.y) * runtime->mTurnForceMult;
    desiredDirection.z += (rolledOffset.z - boneOffset.z) * runtime->mTurnForceMult;

    const moho::VTransform& compositeTransform = watchedBone->GetCompositeTransform();
    Wm3::Quaternionf inverseComposite = compositeTransform.orient_;
    inverseComposite.y = -inverseComposite.y;
    inverseComposite.z = -inverseComposite.z;
    inverseComposite.w = -inverseComposite.w;

    Wm3::Vector3f localDesired{};
    (void)moho::MultQuadVec(&localDesired, &desiredDirection, &inverseComposite);

    localDesired.x = std::max(runtime->mCapMin.x, localDesired.x);
    localDesired.y = std::max(runtime->mCapMin.y, localDesired.y);
    localDesired.z = std::max(runtime->mCapMin.z, localDesired.z);

    localDesired.x = std::min(runtime->mCapMax.x, localDesired.x);
    localDesired.y = std::min(runtime->mCapMax.y, localDesired.y);
    localDesired.z = std::min(runtime->mCapMax.z, localDesired.z);

    (void)Wm3::Vector3f::Normalize(&localDesired);

    Wm3::Quaternionf targetOrientation{};
    (void)BuildShortestArcDeltaQuaternion(&targetOrientation, localDesired, runtime->mDirectionLane);

    Wm3::Quaternionf blendedOrientation{};
    (void)BlendThrustOrientationDelta(runtime->mOrientation, targetOrientation, runtime->mTurnSpeed, nullptr, &blendedOrientation);

    watchedBone->Rotate(blendedOrientation);
    runtime->mOrientation = blendedOrientation;
  }

  [[maybe_unused]] void DeleteCThrustManipulatorStorageRuntime(void* const objectStorage)
  {
    if (objectStorage == nullptr) {
      return;
    }

    auto* const vtable = *reinterpret_cast<ScalarDeletingDtorFn**>(objectStorage);
    (void)vtable[0](objectStorage, 1);
  }

  [[maybe_unused]] void DestructCThrustManipulatorStorageRuntime(void* const objectStorage)
  {
    auto* const vtable = *reinterpret_cast<ScalarDeletingDtorFn**>(objectStorage);
    (void)vtable[0](objectStorage, 0);
  }

  [[nodiscard]] gpg::RRef NewCThrustManipulatorRefForTypeInfo()
  {
    gpg::RRef out{};
    (void)BuildNewCThrustManipulatorRef(&out);
    return out;
  }

  [[nodiscard]] gpg::RRef ConstructCThrustManipulatorRefForTypeInfo(void* const objectStorage)
  {
    gpg::RRef out{};
    (void)ConstructCThrustManipulatorRefInPlaceRuntime(&out, objectStorage);
    return out;
  }

  [[maybe_unused]] void AddBaseIAniManipulatorToCThrustManipulatorTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedIAniManipulatorTypeForThrustManipulatorTypeInfo();
    if (baseType == nullptr) {
      return;
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
   * Address: 0x0064B100 (FUN_0064B100, sub_64B100)
   *
   * What it does:
   * Installs thrust-manipulator type-info lifecycle callbacks into one
   * `gpg::RType` callback slot lane.
   */
  [[maybe_unused]] gpg::RType* BindCThrustManipulatorTypeInfoLifecycleCallbacks(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewCThrustManipulatorRefForTypeInfo;
    typeInfo->ctorRefFunc_ = &ConstructCThrustManipulatorRefForTypeInfo;
    typeInfo->deleteFunc_ = &DeleteCThrustManipulatorStorageRuntime;
    typeInfo->dtrFunc_ = &DestructCThrustManipulatorStorageRuntime;
    return typeInfo;
  }

  [[maybe_unused]] void InitCThrustManipulatorTypeInfo(gpg::RType* const typeInfo)
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->size_ = sizeof(CThrustManipulatorSerializerRuntimeView);
    (void)BindCThrustManipulatorTypeInfoLifecycleCallbacks(typeInfo);
    AddBaseIAniManipulatorToCThrustManipulatorTypeInfo(typeInfo);
    typeInfo->gpg::RType::Init();
    typeInfo->Finish();
  }

  /**
   * Address: 0x0064B1E0 (FUN_0064B1E0, Moho::CThrustManipulatorTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one thrust manipulator runtime object, runs detached default
   * constructor lanes, and writes the resulting reflected reference.
   */
  [[maybe_unused]] gpg::RRef* BuildNewCThrustManipulatorRef(gpg::RRef* const outRef)
  {
    auto deleteRuntime = [](CThrustManipulatorSerializerRuntimeView* const runtime) noexcept {
      ::operator delete(static_cast<void*>(runtime));
    };
    std::unique_ptr<CThrustManipulatorSerializerRuntimeView, decltype(deleteRuntime)> ownedRuntime(nullptr, deleteRuntime);

    CThrustManipulatorSerializerRuntimeView* const allocated =
      static_cast<CThrustManipulatorSerializerRuntimeView*>(::operator new(sizeof(CThrustManipulatorSerializerRuntimeView)));
    ownedRuntime.reset(allocated);

    CThrustManipulatorSerializerRuntimeView* const runtime =
      allocated ? InitializeCThrustManipulatorDefaultRuntime(allocated) : nullptr;

    gpg::RRef reflected{};
    (void)gpg::RRef_CThrustManipulator(&reflected, reinterpret_cast<moho::CThrustManipulator*>(runtime));
    ownedRuntime.release();

    outRef->mObj = reflected.mObj;
    outRef->mType = reflected.mType;
    return outRef;
  }

  /**
   * Address: 0x0064B280 (FUN_0064B280, Moho::CThrustManipulatorTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one thrust manipulator runtime object into caller
   * storage and writes the resulting reflected reference.
   */
  [[maybe_unused]] gpg::RRef* ConstructCThrustManipulatorRefInPlaceRuntime(
    gpg::RRef* const outRef,
    void* const objectStorage
  )
  {
    auto* const runtimeStorage = static_cast<CThrustManipulatorSerializerRuntimeView*>(objectStorage);
    CThrustManipulatorSerializerRuntimeView* const runtime =
      runtimeStorage ? InitializeCThrustManipulatorDefaultRuntime(runtimeStorage) : nullptr;

    gpg::RRef reflected{};
    (void)gpg::RRef_CThrustManipulator(&reflected, reinterpret_cast<moho::CThrustManipulator*>(runtime));
    outRef->mObj = reflected.mObj;
    outRef->mType = reflected.mType;
    return outRef;
  }
} // namespace moho
