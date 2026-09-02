#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <typeinfo>

#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptEvent.h"
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

    /**
     * Address: 0x0064A740 (FUN_0064A740, Moho::CThrustManipulator::~CThrustManipulator)
     *
     * IDA signature:
     * void __usercall sub_64A740(Moho::CThrustManipulator *this@<esi>);
     *
     * What it does:
     * Complete-object destructor. Releases the label heap storage, unlinks the
     * weak unit pointer from its owner chain, then runs `IAniManipulator` base
     * teardown as a tail call.
     */
    ~CThrustManipulatorSerializerRuntimeView() override;

    /**
     * Address: 0x0064A480 (FUN_0064A480, Moho::CThrustManipulator::dtr)
     * Slot: 0
     *
     * IDA signature:
     * void *__thiscall sub_64A480(void *this, char deleteFlags);
     *
     * What it does:
     * Scalar-deleting destructor (vtable slot 0). Runs the complete-object
     * teardown and frees the object storage when `deleteFlags & 1` is set.
     */
    virtual void operator_delete(std::int32_t deleteFlags);
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

  /**
   * Address: 0x0064A740 (FUN_0064A740, Moho::CThrustManipulator::~CThrustManipulator)
   *
   * What it does:
   * Complete-object destructor. Releases the heap-backed label storage, unlinks
   * the weak unit pointer from its owner chain, then runs `IAniManipulator` base
   * teardown as a tail call. The two MSVC vtable restores at function entry are
   * expressed implicitly by the C++ destructor.
   */
  CThrustManipulatorSerializerRuntimeView::~CThrustManipulatorSerializerRuntimeView()
  {
    mLabel.tidy(true, 0U);
    mUnit.UnlinkFromOwnerChain();

    auto* const baseManipulator = static_cast<moho::IAniManipulator*>(this);
    baseManipulator->IAniManipulator::~IAniManipulator();
  }

  /**
   * Address: 0x0064A480 (FUN_0064A480, Moho::CThrustManipulator::dtr)
   * Slot: 0
   *
   * What it does:
   * Scalar-deleting destructor (vtable slot 0). Runs `CThrustManipulator`
   * teardown and frees the object storage when `deleteFlags & 1` is set.
   */
  void CThrustManipulatorSerializerRuntimeView::operator_delete(const std::int32_t deleteFlags)
  {
    this->~CThrustManipulatorSerializerRuntimeView();
    if ((deleteFlags & 1) != 0) {
      ::operator delete(this);
    }
  }

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

  /**
   * Address: 0x0064B6E0 (FUN_0064B6E0, CThrustManipulator serializer load body)
   *
   * What it does:
   * Deserializes one `CThrustManipulator` lane by loading `IAniManipulator`
   * base state, unit weak-pointer lane, label/state lanes, thrust-cap vectors,
   * turn scalars, direction lane, and orientation quaternion.
   */
  void DeserializeCThrustManipulatorSerializerState(
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
   * Address: 0x0064B890 (FUN_0064B890, CThrustManipulator serializer save body)
   *
   * IDA signature:
   * void __usercall sub_64B890(Moho::CThrustManipulator *object@<eax>, BinaryWriteArchive *archive@<esi>);
   *
   * What it does:
   * Line-for-line mirror of `DeserializeCThrustManipulatorSerializerState` on
   * the write side: saves `IAniManipulator` base state, unit weak-pointer lane,
   * label/state/enabled lanes, thrust-cap vectors, turn scalars, direction lane,
   * and the orientation quaternion, in the same field order.
   */
  void SerializeCThrustManipulatorSerializerState(
    const CThrustManipulatorSerializerRuntimeView* const object,
    gpg::WriteArchive* const archive
  )
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(
      CachedIAniManipulatorType(),
      static_cast<const moho::IAniManipulator*>(object),
      owner
    );
    archive->Write(CachedWeakPtrUnitType(), &object->mUnit, owner);
    archive->WriteString(const_cast<msvc8::string*>(&object->mLabel));
    archive->WriteInt(object->mStateLane);
    archive->WriteBool(object->mEnabledLane);
    archive->Write(CachedVector3fType(), &object->mCapMin, owner);
    archive->Write(CachedVector3fType(), &object->mCapMax, owner);
    archive->WriteFloat(object->mTurnForceMult);
    archive->WriteFloat(object->mTurnSpeed);
    archive->Write(CachedVector3fType(), &object->mDirectionLane, owner);
    archive->Write(CachedQuaternionfType(), &object->mOrientation, owner);
  }

} // namespace

namespace moho
{
  /**
   * Minimal RTTI-identity completion for `moho::CThrustManipulator`
   * (forward-declared in `Reflection.h`, used everywhere else in this file
   * only as an incomplete pointer type for `reinterpret_cast`/`typeid`
   * purposes). Real member layout is already fully known and modeled by
   * `CThrustManipulatorSerializerRuntimeView` above (which already properly
   * derives from `IAniManipulator`) -- this stub exists only so
   * `typeid(CThrustManipulator)` is legal for `CThrustManipulatorTypeInfo`'s
   * RTTI preregistration below, and produces the same mangled
   * `??_R0?AVCThrustManipulator@Moho@@@8` RTTI descriptor identity as the
   * binary regardless of which fields are modeled on it. Folding
   * `CThrustManipulatorSerializerRuntimeView` into this class (and renaming
   * it) is a follow-up, not required for the reflection wiring recovered
   * here.
   */
  class CThrustManipulator : public IAniManipulator
  {
  public:
    CThrustManipulator() = default;

    CThrustManipulator(Sim* const sim, CAniActor* const ownerActor, const int precedence)
      : IAniManipulator(sim, ownerActor, precedence)
    {}

    /**
     * Address: 0x0064B6E0 (FUN_0064B6E0, Moho::CThrustManipulator::MemberDeserialize)
     *
     * What it does:
     * Reinterprets `this` as the full `CThrustManipulatorSerializerRuntimeView`
     * layout and forwards to the already-recovered
     * `DeserializeCThrustManipulatorSerializerState` body.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0064B890 (FUN_0064B890, Moho::CThrustManipulator::MemberSerialize)
     *
     * What it does:
     * Reinterprets `this` as the full `CThrustManipulatorSerializerRuntimeView`
     * layout and forwards to the already-recovered
     * `SerializeCThrustManipulatorSerializerState` body.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  /**
   * VFTABLE: 0x00E23224
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CThrustManipulator>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_CThrustManipulatorSerializer`):
   *    0x00BD37A0 (__xc_a-reachable; exactly one xref on the real
   *    `??_7CThrustManipulatorSerializer@Moho@@6B@` vtable). Dead zero-xref
   *    duplicate ctor that installs a distinct byte-identical copy of the
   *    template's own vtable instead: 0x0064B120 (already `skip`).
   *  - dtor: 0x00BFB420 (`??1CThrustManipulatorSerializer@Moho@@QAE@@Z`;
   *    exactly one xref, from the real ctor's atexit push)
   *  - Init(): 0x0064B150
   *  - Deserialize(): 0x0064A330 (tail-calls `MemberDeserialize` at
   *    0x0064B6E0; old source cited a nonexistent 0x0064A2C0 for this slot --
   *    no such function exists in this namespace's export set, the real
   *    stored callback address decodes straight out of the ctor's raw asm)
   *  - Serialize(): 0x0064A340 (tail-calls `MemberSerialize` at 0x0064B890;
   *    this address was already correctly cited by the old source)
   *
   * Prior recovery modeled this as a `CThrustManipulatorSerializerHelperNode`
   * raw struct (`gpg::SerHelperBase* mNext/mPrev` fields, no real base) plus
   * a hand-written `register_CThrustManipulatorSerializer()` that wrote the
   * load/save callbacks onto that orphan struct's own fields instead of onto
   * `CThrustManipulator::sType`'s `serLoadFunc_`/`serSaveFunc_` slots -- the
   * reflection callbacks were never actually installed. This template
   * instantiation fixes both defects.
   */
  using CThrustManipulatorSerializer = gpg::SerSaveLoadHelper<CThrustManipulator>;

  /**
   * Address: 0x0064B6E0 (FUN_0064B6E0, gpg::SerSaveLoadHelper<Moho::CThrustManipulator>::Deserialize thunk target)
   */
  void CThrustManipulator::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    DeserializeCThrustManipulatorSerializerState(
      reinterpret_cast<CThrustManipulatorSerializerRuntimeView*>(this), archive
    );
  }

  /**
   * Address: 0x0064B890 (FUN_0064B890, gpg::SerSaveLoadHelper<Moho::CThrustManipulator>::Serialize thunk target)
   */
  void CThrustManipulator::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    SerializeCThrustManipulatorSerializerState(
      reinterpret_cast<const CThrustManipulatorSerializerRuntimeView*>(this), archive
    );
  }

  [[nodiscard]] gpg::RType* CachedIAniManipulatorTypeForThrustManipulatorTypeInfo()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  gpg::RRef* BuildNewCThrustManipulatorRef(gpg::RRef* outRef);
  gpg::RRef* ConstructCThrustManipulatorRefInPlaceRuntime(
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
  CThrustManipulatorSerializerRuntimeView* InitializeCThrustManipulatorDefaultRuntime(
    CThrustManipulatorSerializerRuntimeView* const runtime
  ) noexcept
  {
    if (runtime == nullptr) {
      return nullptr;
    }

    (void)new (static_cast<void*>(runtime)) CThrustManipulator();

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
  void InitCThrustManipulatorTypeInfo(gpg::RType* const typeInfo);

  /**
   * Address: 0x0064A4A0 (FUN_0064A4A0, Moho::CThrustManipulator::CThrustManipulator)
   *
   * What it does:
   * Builds one thrust manipulator bound to `{unit, bone}`, initializes weak
   * unit/link + label/state/cap defaults, creates Lua object lanes, and seeds
   * thrust direction/orientation from the watched bone local orientation.
   */
  CThrustManipulatorSerializerRuntimeView* ConstructCThrustManipulatorRuntime(
    CThrustManipulatorSerializerRuntimeView* const runtime,
    const char* const label,
    moho::Unit* const unit,
    const std::int32_t boneIndex
  )
  {
    if (runtime == nullptr || unit == nullptr) {
      return runtime;
    }

    (void)new (static_cast<void*>(runtime)) CThrustManipulator(unit->SimulationRef, unit->AniActor, 0);

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
   * Address: 0x0064ABC0 (FUN_0064ABC0, cfunc_CreateThrustControllerL)
   *
   * IDA signature:
   * int __thiscall cfunc_CreateThrustControllerL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Reads `(unit, label, thrustBone)`, requires the unit to have a skeleton,
   * resolves the thrust bone via `CAniActor::ResolveBoneIndex`, allocates and
   * constructs one thrust manipulator bound to that unit, and pushes the
   * manipulator's Lua userdata as the return value.
   */
  int cfunc_CreateThrustControllerL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected %d args, but got %d", "CreateThrustController(unit, label, thrustBone)", 3, argumentCount
      );
    }

    const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    Unit* const unit = SCR_FromLua_Unit(unitObject);

    LuaPlus::LuaStackObject labelArg(state, 2);
    const char* const label = lua_tostring(rawState, 2);
    if (label == nullptr) {
      labelArg.TypeError("string");
    }

    CAniActor* const actor = unit->AniActor;
    if (actor == nullptr) {
      LuaPlus::LuaState::Error(state, "Unit has no skeleton.");
    }

    LuaPlus::LuaStackObject boneArg(state, 3);
    const int boneIndex = actor->ResolveBoneIndex(boneArg);

    // The binary allocates the full manipulator and constructs it in place; the
    // runtime-view type + constructor helper are file-private to this TU, so the
    // allocation size is taken from the modeled runtime-view size.
    auto* const runtime = static_cast<CThrustManipulatorSerializerRuntimeView*>(
      ::operator new(sizeof(CThrustManipulatorSerializerRuntimeView))
    );
    (void)ConstructCThrustManipulatorRuntime(runtime, label, unit, boneIndex);

    static_cast<CScriptObject*>(reinterpret_cast<IAniManipulator*>(runtime))->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0064AB40 (FUN_0064AB40, cfunc_CreateThrustController)
   *
   * IDA signature:
   * int __cdecl cfunc_CreateThrustController(lua_State *a1);
   *
   * What it does:
   * Unwraps the raw Lua callback context and forwards to
   * `cfunc_CreateThrustControllerL`.
   */
  // The parameter is deliberately NOT `lua_State* const`: MSVC encodes a
  // top-level pointer-parameter const in the decorated name (`QAUlua_State@@`
  // instead of `PAUlua_State@@`), and no header declares this thunk, so the
  // `const` form emitted a symbol that `ManipulatorLuaFunctionThunks.cpp`'s
  // own `int cfunc_CreateThrustController(lua_State*)` declaration could never
  // resolve against.
  int cfunc_CreateThrustController(lua_State* luaContext)
  {
    return cfunc_CreateThrustControllerL(moho::SCR_ResolveBindingState(luaContext));
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
    // 0x004EB830, shared with CSlaveManipulator::ManipulatorUpdate - the
    // max-rate-limited reorientation step, called here exactly as the binary
    // calls it rather than through a local forwarder.
    (void)moho::BlendOrientationDeltaByMaxAngle(
      runtime->mOrientation, targetOrientation, runtime->mTurnSpeed, nullptr, &blendedOrientation
    );

    watchedBone->Rotate(blendedOrientation);
    runtime->mOrientation = blendedOrientation;
  }

  /**
   * Address: 0x0064B260 (FUN_0064B260, Moho::CThrustManipulatorTypeInfo::Delete)
   *
   * What it does:
   * Runs scalar-deleting destructor slot `0` with delete flag `1` when object
   * storage is non-null.
   */
  void DeleteCThrustManipulatorStorageRuntime(void* const objectStorage)
  {
    if (objectStorage == nullptr) {
      return;
    }

    reinterpret_cast<CThrustManipulatorSerializerRuntimeView*>(objectStorage)->operator_delete(1);
  }

  /**
   * Address: 0x0064B2F0 (FUN_0064B2F0, Moho::CThrustManipulatorTypeInfo::Destruct)
   *
   * What it does:
   * Runs scalar-deleting destructor slot `0` with delete flag `0`.
   */
  void DestructCThrustManipulatorStorageRuntime(void* const objectStorage)
  {
    reinterpret_cast<CThrustManipulatorSerializerRuntimeView*>(objectStorage)->operator_delete(0);
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

  /**
   * Address: 0x0064B300 (FUN_0064B300, ?AddBase_IAniManipulator@CThrustManipulatorTypeInfo@Moho@@SGXPAVRType@gpg@@@Z)
   *
   * IDA signature:
   * void __stdcall Moho::CThrustManipulatorTypeInfo::AddBase_IAniManipulator(gpg::RType* typeInfo);
   *
   * What it does:
   * Registers `IAniManipulator` as a zero-offset base of the thrust-manipulator
   * type, resolving the base descriptor through the cached RTTI lookup on first
   * use. Called from `CThrustManipulatorTypeInfo::Init` (0x0064A230).
   */
  void AddBaseIAniManipulatorToCThrustManipulatorTypeInfo(gpg::RType* const typeInfo)
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

  // NOTE: 0x0064B100 (5-instruction field-write body, zero incoming xrefs of
  // any kind in the callgraph index) is not called by the real
  // `CThrustManipulatorTypeInfo::Init` (0x0064A230) -- that function writes
  // its four lifecycle-callback fields inline (see the shared
  // `gpg::BindRTypeLifecycleCallbacks` template below, which already cites
  // ~40 identically-shaped inline bodies) rather than calling out to a
  // separate helper. A prior pass here wrote a local
  // `BindCThrustManipulatorTypeInfoLifecycleCallbacks` duplicate and claimed
  // it was "wired" to 0x0064B100 without any citation evidence; removed.

  /**
   * Address: 0x0064A230 (FUN_0064A230, Moho::CThrustManipulatorTypeInfo::Init)
   */
  void InitCThrustManipulatorTypeInfo(gpg::RType* const typeInfo)
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->size_ = sizeof(CThrustManipulatorSerializerRuntimeView);
    (void)gpg::BindRTypeLifecycleCallbacks(
      typeInfo,
      &NewCThrustManipulatorRefForTypeInfo,
      &ConstructCThrustManipulatorRefForTypeInfo,
      &DeleteCThrustManipulatorStorageRuntime,
      &DestructCThrustManipulatorStorageRuntime
    );
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
  gpg::RRef* BuildNewCThrustManipulatorRef(gpg::RRef* const outRef)
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
  gpg::RRef* ConstructCThrustManipulatorRefInPlaceRuntime(
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

namespace moho
{
  /**
   * Owns reflected metadata for `CThrustManipulator`.
   */
  class CThrustManipulatorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0064A1D0 (FUN_0064A1D0, ctor lane)
     *
     * What it does:
     * Preregisters the `CThrustManipulator` RTTI descriptor during startup.
     * In the binary this constructor body is inlined into the `.CRT$XCL`
     * provider wrapper (`register_CThrustManipulatorTypeInfo`, 0x00BD3780)
     * that constructs the file-scope singleton, rather than being emitted as
     * a standalone `__thiscall` symbol.
     */
    CThrustManipulatorTypeInfo();

    /**
     * Address: 0x0064A280 (FUN_0064A280, Moho::CThrustManipulatorTypeInfo::dtr)
     *
     * What it does:
     * Frees the `RType` base's two `msvc8::vector<RField>` storage lanes and
     * restores the `gpg::RObject` vftable. Defaulted in source: the
     * compiler-generated `~RType()` reproduces this behavior, matching every
     * other manipulator TypeInfo dtor in this family.
     */
    ~CThrustManipulatorTypeInfo() override = default;

    /**
     * Address: 0x0064A270 (FUN_0064A270, Moho::CThrustManipulatorTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0064A230 (FUN_0064A230, Moho::CThrustManipulatorTypeInfo::Init)
     *
     * What it does:
     * Forwards to the already-recovered `InitCThrustManipulatorTypeInfo` free
     * helper, which sets `size_`, binds the NewRef/CtrRef/Delete/Destruct
     * lifecycle callbacks, registers `IAniManipulator` as the reflected base,
     * and finalizes the type descriptor.
     */
    void Init() override;
  };

  static_assert(sizeof(CThrustManipulatorTypeInfo) == 0x64, "CThrustManipulatorTypeInfo size must be 0x64");

  /**
   * Address: 0x0064A1D0 (FUN_0064A1D0, ctor lane)
   */
  CThrustManipulatorTypeInfo::CThrustManipulatorTypeInfo()
  {
    gpg::PreRegisterRType(typeid(CThrustManipulator), this);
  }

  /**
   * Address: 0x0064A270 (FUN_0064A270, Moho::CThrustManipulatorTypeInfo::GetName)
   */
  const char* CThrustManipulatorTypeInfo::GetName() const
  {
    return "CThrustManipulator";
  }

  /**
   * Address: 0x0064A230 (FUN_0064A230, Moho::CThrustManipulatorTypeInfo::Init)
   */
  void CThrustManipulatorTypeInfo::Init()
  {
    InitCThrustManipulatorTypeInfo(this);
  }
} // namespace moho

namespace
{
  alignas(moho::CThrustManipulatorTypeInfo)
  unsigned char gCThrustManipulatorTypeInfoStorage[sizeof(moho::CThrustManipulatorTypeInfo)] = {};
  bool gCThrustManipulatorTypeInfoConstructed = false;

  // Address: 0x00BD37A0 (dynamic initializer for the global
  // `CThrustManipulatorSerializer` singleton, __xc_a-reachable) -- MSVC's own
  // compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<CThrustManipulator>` ctor (calls
  // `gpg::SerHelperBase::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback`
  // to the template's `Deserialize`/`Serialize`, installs the vtable) and
  // registers the real mangled destructor
  // (`??1CThrustManipulatorSerializer@Moho@@QAE@@Z`, 0x00BFB420) via
  // `atexit`. See the Doxygen comment on the declaration above (next to the
  // `CThrustManipulator` class) for the full per-instantiation address list.
  moho::CThrustManipulatorSerializer gCThrustManipulatorSerializer;

  [[nodiscard]] moho::CThrustManipulatorTypeInfo* AcquireCThrustManipulatorTypeInfo()
  {
    if (!gCThrustManipulatorTypeInfoConstructed) {
      new (gCThrustManipulatorTypeInfoStorage) moho::CThrustManipulatorTypeInfo();
      gCThrustManipulatorTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CThrustManipulatorTypeInfo*>(gCThrustManipulatorTypeInfoStorage);
  }

  /**
   * Address: 0x00BFB3C0 (FUN_00BFB3C0, cleanup_CThrustManipulatorTypeInfo)
   *
   * What it does:
   * Tears down static `CThrustManipulatorTypeInfo` storage at process exit.
   */
  void cleanup_CThrustManipulatorTypeInfo()
  {
    if (!gCThrustManipulatorTypeInfoConstructed) {
      return;
    }

    AcquireCThrustManipulatorTypeInfo()->~CThrustManipulatorTypeInfo();
    gCThrustManipulatorTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD3780 (FUN_00BD3780, register_CThrustManipulatorTypeInfo)
   *
   * What it does:
   * Constructs the startup-owned `CThrustManipulatorTypeInfo` singleton and
   * installs process-exit cleanup. Dispatched from `.CRT$XCL` (`__xc_a`); the
   * binary has exactly one call site and no reentry guard, matching the
   * guarded-singleton idiom used throughout this manipulator family.
   */
  void register_CThrustManipulatorTypeInfo()
  {
    (void)AcquireCThrustManipulatorTypeInfo();
    (void)std::atexit(&cleanup_CThrustManipulatorTypeInfo);
  }
} // namespace moho

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CThrustManipulatorTypeInfo_9f14be, moho::register_CThrustManipulatorTypeInfo)
