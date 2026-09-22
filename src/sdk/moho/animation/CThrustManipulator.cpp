#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
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
#include "moho/animation/CThrustManipulator.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakPtr.h"
#include "moho/render/camera/VTransform.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/ManipulatorLuaFunctionThunks.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace
{
  /// The four constructor defaults, read straight out of the constant pool:
  /// 0x00E4F9B8, 0x00E4F744, 0x00DFEC20 and 0x00E4F9B4.
  constexpr float kThrustCapMin = -100.0f;
  constexpr float kThrustCapMax = 100.0f;
  constexpr float kThrustDefaultTurnForceMult = 1.0f;
  constexpr float kThrustDefaultTurnSpeed = 0.30000001f;

  /// World up, the reference `targetNormal` the rest orientation is measured
  /// against (stored to the stack at 0x0064A70B-0x0064A71D as `{0, 1, 0}`).
  constexpr Wm3::Vector3f kWorldUp{0.0f, 1.0f, 0.0f};

  /// Fraction of the way the thrust direction eases toward its target each
  /// tick is not a constant here -- see `mTurnSpeed`, which bounds the step in
  /// radians rather than blending.
  ///
  /// Every reflected descriptor below is one process-global filled on first
  /// use, exactly as the binary does it: a plain pointer plus a null test, no
  /// guard variable. `Wm3::Vector3f` is 0x010C6330 and `Wm3::Quaternionf` is
  /// 0x010C6D38; `IAniManipulator`, `WeakPtr<Unit>` and `CThrustManipulator`
  /// each own theirs as a class static (0x010C738C, 0x010C6FB0, 0x010C73E0).
  gpg::RType* gVector3fType = nullptr;
  gpg::RType* gQuaternionfType = nullptr;

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    if (!gVector3fType) {
      gVector3fType = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return gVector3fType;
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    if (!gQuaternionfType) {
      gQuaternionfType = gpg::LookupRType(typeid(Wm3::Quaternionf));
    }
    return gQuaternionfType;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    if (!moho::WeakPtr<moho::Unit>::sType) {
      moho::WeakPtr<moho::Unit>::sType = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
    }
    return moho::WeakPtr<moho::Unit>::sType;
  }

  /**
   * The shared body behind `CThrustManipulator::GetClass` (0x0064A190): read
   * the cache at 0x010C73E0, and on a miss pass the type descriptor at
   * 0x00F73B00 to `gpg::LookupRType` (0x008E0750). It carries no address of
   * its own -- the address belongs to the member.
   */
  [[nodiscard]] gpg::RType* CachedCThrustManipulatorType()
  {
    if (!moho::CThrustManipulator::sType) {
      moho::CThrustManipulator::sType = gpg::LookupRType(typeid(moho::CThrustManipulator));
    }
    return moho::CThrustManipulator::sType;
  }

  /**
   * The watched-bone lookup both the constructor (0x0064A654-0x0064A683) and
   * `ManipulatorUpdate` (0x0064A82F-0x0064A85E) inline: take the first watched
   * binding's bone index and resolve it against the owner actor's pose.
   *
   * The binary range-checks the index and leaves the pointer null when it is
   * out of range, but then dereferences it anyway (`xor edi, edi` falls
   * straight into `movss xmm2, [edi+0x24]`). The null returns here stop short
   * of that read; every other branch is the binary's.
   */
  [[nodiscard]] moho::CAniPoseBone* ResolveWatchedThrustBone(moho::IAniManipulator* const manipulator) noexcept
  {
    if (manipulator == nullptr || manipulator->mOwnerActor == nullptr ||
        manipulator->mWatchBones.begin() == manipulator->mWatchBones.end()) {
      return nullptr;
    }

    moho::CAniPose* const pose = manipulator->mOwnerActor->mPose.px;
    if (pose == nullptr || pose->mBones.begin() == nullptr || pose->mBones.end() == nullptr) {
      return nullptr;
    }

    const std::int32_t boneIndex = manipulator->mWatchBones.begin()->mBoneIndex;
    const std::ptrdiff_t boneCount = pose->mBones.end() - pose->mBones.begin();
    if (boneIndex < 0 || static_cast<std::ptrdiff_t>(boneIndex) >= boneCount) {
      return nullptr;
    }

    return &pose->mBones.begin()[boneIndex];
  }

  /**
   * The bone-local +Z axis of `orientation`, i.e. the third column of the
   * rotation matrix it expands to. Written out by hand in both the
   * constructor (0x0064A683-0x0064A706) and nowhere else, so it stays a local
   * helper rather than joining `QuaternionMath`.
   */
  [[nodiscard]] Wm3::Vector3f ForwardAxisOf(const Wm3::Quaternionf& orientation) noexcept
  {
    return Wm3::Vector3f{
      ((orientation.x * orientation.z) + (orientation.w * orientation.y)) * 2.0f,
      ((orientation.y * orientation.z) - (orientation.w * orientation.x)) * 2.0f,
      1.0f - (((orientation.x * orientation.x) + (orientation.y * orientation.y)) * 2.0f),
    };
  }
} // namespace

namespace moho
{
  /// Binary global 0x010C73E0.
  gpg::RType* CThrustManipulator::sType = nullptr;

  /**
   * Address: 0x0064A3E0 (FUN_0064A3E0, ??0CThrustManipulator@Moho@@QAE@XZ)
   */
  CThrustManipulator::CThrustManipulator()
    : mUnit()
    , mLabel()
    , mThrusting(false)
    , mCapMin{kThrustCapMin, kThrustCapMin, kThrustCapMin}
    , mCapMax{kThrustCapMax, kThrustCapMax, kThrustCapMax}
    , mTurnForceMult(kThrustDefaultTurnForceMult)
    , mTurnSpeed(kThrustDefaultTurnSpeed)
  {
    // `mThrustBoneIndex`, `mRestDirection` and `mOrientation` are left alone
    // on purpose: 0x0064A3E0 writes +0x80/+0x84, the string lanes, +0xA8 and
    // +0xAC through +0xC8, and touches nothing else. Reflection only ever
    // builds an instance through this path to deserialize into it.
  }

  /**
   * Address: 0x0064A4A0 (FUN_0064A4A0, ??0CThrustManipulator@Moho@@QAE@@Z)
   */
  CThrustManipulator::CThrustManipulator(const char* const label, Unit* const unit, const int thrustBoneIndex)
    : IAniManipulator(unit->SimulationRef, unit->AniActor, 0)
    , mUnit(unit)
    , mLabel(label)
    , mThrusting(false)
    , mCapMin{kThrustCapMin, kThrustCapMin, kThrustCapMin}
    , mCapMax{kThrustCapMax, kThrustCapMax, kThrustCapMax}
    , mTurnForceMult(kThrustDefaultTurnForceMult)
    , mTurnSpeed(kThrustDefaultTurnSpeed)
  {
    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject object;
    (void)func_CreateLuaCThrustManipulator(&object, unit->SimulationRef ? unit->SimulationRef->mLuaState : nullptr);
    CreateLuaObject(object, arg1, arg2, arg3);

    mThrustBoneIndex = thrustBoneIndex;
    (void)AddWatchBone(thrustBoneIndex);

    const CAniPoseBone* const watchedBone = ResolveWatchedThrustBone(this);
    if (watchedBone == nullptr) {
      return;
    }

    mRestDirection = ForwardAxisOf(watchedBone->mLocalTransform.orient_);
    (void)BuildTiltShortestArcDelta(kWorldUp, &mOrientation, mRestDirection);
  }

  /**
   * Address: 0x0064A190 (FUN_0064A190)
   */
  gpg::RType* CThrustManipulator::GetClass() const
  {
    return CachedCThrustManipulatorType();
  }

  /**
   * Address: 0x0064A1B0 (FUN_0064A1B0, ?GetDerivedObjectRef@CThrustManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef CThrustManipulator::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x0064A800 (FUN_0064A800, Moho::CThrustManipulator::MoveManipulator)
   *
   * VFTable SLOT: 1
   *
   * This was a free `UpdateCThrustManipulatorRuntime` over the runtime view,
   * carrying `[[maybe_unused]]` because nothing could call it -- it is the
   * class's only overridden virtual, and leaving it off the class left slot 1
   * of 0xE231CC resolving to `IAniManipulator::ManipulatorUpdate`, whose whole
   * body is `return false`. Thrust nozzles never swivelled.
   */
  bool CThrustManipulator::ManipulatorUpdate()
  {
    Unit* const unit = mUnit.GetObjectPtr();
    if (unit == nullptr || unit->IsBeingBuilt()) {
      return false;
    }

    CAniPoseBone* const watchedBone = ResolveWatchedThrustBone(this);
    if (watchedBone == nullptr || unit->UnitMotion == nullptr) {
      return false;
    }

    Wm3::Vector3f desiredDirection = unit->UnitMotion->mForce;

    // The unit's yaw swings the nozzle bone through an arc; the thrust has to
    // account for where the bone is being swung to, scaled by mTurnForceMult.
    // `mTorque.y` is the body-local yaw lane `ComputeAirControl` stashes
    // before inertia scaling -- see the field's comment in CUnitMotion.h, the
    // frame it carries depends on who wrote it last.
    Wm3::Quaternionf yawRotation{};
    (void)EulerRollToQuat(&kWorldUp, &yawRotation, unit->UnitMotion->mTorque.y);

    const VTransform& unitTransform = unit->GetTransform();
    const VTransform boneWorldTransform = unit->GetBoneWorldTransform(mThrustBoneIndex);
    Wm3::Vector3f boneOffset{
      boneWorldTransform.pos_.x - unitTransform.pos_.x,
      boneWorldTransform.pos_.y - unitTransform.pos_.y,
      boneWorldTransform.pos_.z - unitTransform.pos_.z,
    };

    Wm3::Vector3f swungOffset{};
    (void)MultQuadVec(&swungOffset, &boneOffset, &yawRotation);
    desiredDirection.x += (swungOffset.x - boneOffset.x) * mTurnForceMult;
    desiredDirection.y += (swungOffset.y - boneOffset.y) * mTurnForceMult;
    desiredDirection.z += (swungOffset.z - boneOffset.z) * mTurnForceMult;

    // Into bone-local space, where the caps are expressed.
    const VTransform& compositeTransform = watchedBone->GetCompositeTransform();
    Wm3::Vector3f localDesired{};
    const Wm3::Quaternionf inverseComposite = ConjugateQuat(compositeTransform.orient_);
    (void)MultQuadVec(&localDesired, &desiredDirection, &inverseComposite);

    // Deliberately not `std::clamp`: the binary raises to `mCapMin` and then
    // lowers to `mCapMax` as two independent comparisons per lane
    // (0x0064AA2F and 0x0064AA74 for x), which keeps defined behaviour if a
    // Lua caller ever passes an inverted pair. `std::clamp` with `lo > hi` is
    // undefined.
    localDesired.x = std::min(mCapMax.x, std::max(mCapMin.x, localDesired.x));
    localDesired.y = std::min(mCapMax.y, std::max(mCapMin.y, localDesired.y));
    localDesired.z = std::min(mCapMax.z, std::max(mCapMin.z, localDesired.z));
    (void)Wm3::Vector3f::Normalize(&localDesired);

    Wm3::Quaternionf targetOrientation{};
    (void)BuildTiltShortestArcDelta(localDesired, &targetOrientation, mRestDirection);

    Wm3::Quaternionf blendedOrientation{};
    (void)BlendOrientationDeltaByMaxAngle(mOrientation, targetOrientation, mTurnSpeed, nullptr, &blendedOrientation);

    watchedBone->Rotate(blendedOrientation);
    mOrientation = blendedOrientation;
    return true;
  }

  /**
   * Address: 0x0064B6E0 (FUN_0064B6E0, Moho::CThrustManipulator::MemberDeserialize)
   */
  void CThrustManipulator::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(IAniManipulator::StaticGetClass(), this, owner);
    archive->Read(CachedWeakPtrUnitType(), &mUnit, owner);
    archive->ReadString(&mLabel);
    archive->ReadInt(&mThrustBoneIndex);
    archive->ReadBool(&mThrusting);
    archive->Read(CachedVector3fType(), &mCapMin, owner);
    archive->Read(CachedVector3fType(), &mCapMax, owner);
    archive->ReadFloat(&mTurnForceMult);
    archive->ReadFloat(&mTurnSpeed);
    archive->Read(CachedVector3fType(), &mRestDirection, owner);
    archive->Read(CachedQuaternionfType(), &mOrientation, owner);
  }

  /**
   * Address: 0x0064B890 (FUN_0064B890, Moho::CThrustManipulator::MemberSerialize)
   */
  void CThrustManipulator::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(IAniManipulator::StaticGetClass(), this, owner);
    archive->Write(CachedWeakPtrUnitType(), &mUnit, owner);
    archive->WriteString(const_cast<msvc8::string*>(&mLabel));
    archive->WriteInt(mThrustBoneIndex);
    archive->WriteBool(mThrusting);
    archive->Write(CachedVector3fType(), &mCapMin, owner);
    archive->Write(CachedVector3fType(), &mCapMax, owner);
    archive->WriteFloat(mTurnForceMult);
    archive->WriteFloat(mTurnSpeed);
    archive->Write(CachedVector3fType(), &mRestDirection, owner);
    archive->Write(CachedQuaternionfType(), &mOrientation, owner);
  }

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
   *  - Init(): 0x0064B150 -- and this is what made `CThrustManipulator::sType`
   *    load bearing. The body reads and fills 0x010C73E0, then stores the two
   *    callbacks at `+0x1C`/`+0x14` of *that* descriptor. While the class was
   *    an empty stub it had no `sType` of its own, so `T::sType` resolved to
   *    the inherited `IAniManipulator::sType` (0x010C738C) and the template
   *    bound this class's load/save callbacks onto the base's reflected type,
   *    where `IAniManipulator`'s own serializer had already put its own.
   *  - Deserialize(): 0x0064A330 (tail-calls `MemberDeserialize` at 0x0064B6E0)
   *  - Serialize(): 0x0064A340 (tail-calls `MemberSerialize` at 0x0064B890)
   */
  using CThrustManipulatorSerializer = gpg::SerSaveLoadHelper<CThrustManipulator>;

  /**
   * Address: 0x0064B300 (FUN_0064B300, ?AddBase_IAniManipulator@CThrustManipulatorTypeInfo@Moho@@SGXPAVRType@gpg@@@Z)
   *
   * What it does:
   * Registers `IAniManipulator` as a zero-offset base of the thrust-manipulator
   * type, resolving the base descriptor through the cached RTTI lookup on first
   * use. Called from `CThrustManipulatorTypeInfo::Init` (0x0064A230).
   */
  void AddBaseIAniManipulatorToCThrustManipulatorTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = IAniManipulator::StaticGetClass();
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
   * Address: 0x0064ABC0 (FUN_0064ABC0, cfunc_CreateThrustControllerL)
   *
   * IDA signature:
   * int __thiscall cfunc_CreateThrustControllerL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Reads `(unit, label, thrustBone)`, requires the unit to have a skeleton,
   * resolves the thrust bone via `CAniActor::ResolveBoneIndex`, constructs one
   * thrust manipulator bound to that unit, and pushes the manipulator's Lua
   * userdata as the return value.
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

    // Plain `new`: the allocation at 0x0064ACAF and the constructor call at
    // 0x0064ACCF are twenty bytes apart with only MSVC8's own null test
    // between them, so unlike `CStorageManipulator` there is no argument
    // evaluation to sequence in the gap.
    CThrustManipulator* const manipulator = new CThrustManipulator(label, unit, boneIndex);
    manipulator->mLuaObj.PushStack(state);
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
     * Sets `size_` to 0xE8, binds the four lifecycle callbacks below, registers
     * `IAniManipulator` as the reflected base, then finalizes the descriptor.
     */
    void Init() override;

    /**
     * Address: 0x0064B1E0 (FUN_0064B1E0, Moho::CThrustManipulatorTypeInfo::NewRef)
     *
     * What it does:
     * Builds one default-constructed thrust manipulator on the heap and wraps
     * it in a reflected reference.
     */
    [[nodiscard]] static gpg::RRef NewRef();

    /**
     * Address: 0x0064B280 (FUN_0064B280, Moho::CThrustManipulatorTypeInfo::CtrRef)
     *
     * What it does:
     * Default-constructs one thrust manipulator into caller-owned storage and
     * wraps it in a reflected reference. Null storage yields a null reference:
     * MSVC8 compiles `new (p) T` as `if (p) T::T(p)`, and 0x0064B2A3's
     * `xor eax, eax` / `cmp esi, eax` / `je` is that test.
     */
    [[nodiscard]] static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0064B260 (FUN_0064B260, Moho::CThrustManipulatorTypeInfo::Delete)
     *
     * What it does:
     * `delete` on the reflected object. The null test plus `push 1` through
     * vtable slot 0 is exactly what `delete p` compiles to.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0064B2F0 (FUN_0064B2F0, Moho::CThrustManipulatorTypeInfo::Destruct)
     *
     * What it does:
     * Destroys in place without freeing -- `push 0` through the same slot, and
     * no null test, which is what `p->~T()` compiles to.
     */
    static void Destruct(void* objectStorage);
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
   * Address: 0x0064B1E0 (FUN_0064B1E0, Moho::CThrustManipulatorTypeInfo::NewRef)
   */
  gpg::RRef CThrustManipulatorTypeInfo::NewRef()
  {
    gpg::RRef reflected{};
    (void)gpg::RRef_CThrustManipulator(&reflected, new CThrustManipulator());
    return reflected;
  }

  /**
   * Address: 0x0064B280 (FUN_0064B280, Moho::CThrustManipulatorTypeInfo::CtrRef)
   */
  gpg::RRef CThrustManipulatorTypeInfo::CtrRef(void* const objectStorage)
  {
    CThrustManipulator* const manipulator =
      objectStorage ? std::construct_at(static_cast<CThrustManipulator*>(objectStorage)) : nullptr;

    gpg::RRef reflected{};
    (void)gpg::RRef_CThrustManipulator(&reflected, manipulator);
    return reflected;
  }

  /**
   * Address: 0x0064B260 (FUN_0064B260, Moho::CThrustManipulatorTypeInfo::Delete)
   */
  void CThrustManipulatorTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CThrustManipulator*>(objectStorage);
  }

  /**
   * Address: 0x0064B2F0 (FUN_0064B2F0, Moho::CThrustManipulatorTypeInfo::Destruct)
   */
  void CThrustManipulatorTypeInfo::Destruct(void* const objectStorage)
  {
    static_cast<CThrustManipulator*>(objectStorage)->~CThrustManipulator();
  }

  /**
   * Address: 0x0064A230 (FUN_0064A230, Moho::CThrustManipulatorTypeInfo::Init)
   */
  void CThrustManipulatorTypeInfo::Init()
  {
    size_ = sizeof(CThrustManipulator);
    (void)gpg::BindRTypeLifecycleCallbacks(this, &NewRef, &CtrRef, &Delete, &Destruct);
    AddBaseIAniManipulatorToCThrustManipulatorTypeInfo(this);
    gpg::RType::Init();
    Finish();
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
  // `atexit`. See the Doxygen comment on the alias above for the full
  // per-instantiation address list.
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
