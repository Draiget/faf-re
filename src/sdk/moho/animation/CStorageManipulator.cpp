#include "moho/animation/CStorageManipulator.h"

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "moho/ai/EEconResourceTypeInfo.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/Sim.h"
#include "moho/task/CTaskEvent.h"
#include "moho/unit/core/Unit.h"
#include "lua/LuaObject.h"
#include "Wm3Vector3.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <typeinfo>

namespace moho
{
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace
{
  constexpr std::uint32_t kWatchBoneActiveFlag = 0x00008000u;
  constexpr float kStorageBlendFactor = 0.1f;
  constexpr float kStoragePreserveFactor = 0.9f;

  /**
   * The shared body behind `CStorageManipulator::StaticGetClass` (0x006498C0)
   * and `CStorageManipulator::GetClass` (0x00648D70), which are two out-of-line
   * copies of exactly this: read the cache at 0x010C73DC, and on a miss pass
   * the type descriptor at 0x00F7394C to `gpg::LookupRType` (0x008E0750). It
   * carries no address of its own for that reason -- the addresses belong to
   * the two members, the same way `CachedIAniManipulatorType` relates to
   * `IAniManipulator`'s pair.
   */
  [[nodiscard]] gpg::RType* CachedCStorageManipulatorType()
  {
    if (!moho::CStorageManipulator::sType) {
      moho::CStorageManipulator::sType = gpg::LookupRType(typeid(moho::CStorageManipulator));
    }
    return moho::CStorageManipulator::sType;
  }

  /// The binary reads and fills one global for this descriptor (0x010C6330)
  /// before each of the three vector reads/writes in the serializers.
  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedEEconResourceType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EEconResource));
    }
    return type;
  }

  [[nodiscard]] moho::CAniPoseBone* ResolveWatchedBoneForStorageManipulator(
    moho::IAniManipulator* const manipulator
  ) noexcept
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

  void ApplyStorageOffsetToWatchedBone(moho::CAniPoseBone* const watchedBone, const Wm3::Vector3f& localOffset)
  {
    if (watchedBone == nullptr) {
      return;
    }

    Wm3::Vector3f rotatedOffset{};
    (void)moho::MultQuadVec(&rotatedOffset, &localOffset, &watchedBone->mLocalTransform.orient_);

    moho::VTransform updatedLocal = watchedBone->mLocalTransform;
    updatedLocal.pos_.x += rotatedOffset.x;
    updatedLocal.pos_.y += rotatedOffset.y;
    updatedLocal.pos_.z += rotatedOffset.z;
    watchedBone->SetLocalTransform(updatedLocal);
  }

} // namespace

namespace moho
{
  gpg::RType* CStorageManipulator::sType = nullptr;

  /**
   * VFTABLE: 0x00E230B4
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CStorageManipulator>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_CStorageManipulatorSerializer`):
   *    0x00BD3660 (__xc_a-reachable; exactly one xref on the real
   *    `??_7CStorageManipulatorSerializer@Moho@@6B@` vtable). Dead zero-xref
   *    duplicate ctor that installs a distinct byte-identical copy of the
   *    template's own vtable instead: 0x00649900 (already `skip`).
   *  - dtor: 0x00BFB370 (`??1CStorageManipulatorSerializer@Moho@@QAE@@Z`;
   *    exactly one xref, from the real ctor's atexit push)
   *  - Init(): 0x00649930
   *  - Deserialize(): 0x00648F10 (tail-calls `MemberDeserialize` at 0x00649DB0)
   *  - Serialize(): 0x00648F20 (tail-calls `MemberSerialize` at 0x00649EF0)
   *
   * Prior recovery modeled this as a `CStorageManipulatorSerializerHelperNode`
   * raw struct (`gpg::SerHelperBase* mNext/mPrev` fields, no real base) wired
   * through `InstallCStorageManipulatorSerializerCallbackStorage`, a
   * fabricated bootstrap function with no address citation of its own that
   * only stored the load/save callbacks on that orphan struct's own fields
   * -- `CStorageManipulator::sType`'s `serLoadFunc_`/`serSaveFunc_` slots
   * were never actually written. This template instantiation fixes both
   * defects.
   */
  using CStorageManipulatorSerializer = gpg::SerSaveLoadHelper<CStorageManipulator>;

  LuaPlus::LuaObject* func_CreateLuaCStorageManipulator(
    LuaPlus::LuaObject* object,
    LuaPlus::LuaState* state
  );

  /**
   * Address: 0x006498C0 (FUN_006498C0)
   *
   * What it does:
   * Reads the cached reflected `CStorageManipulator` descriptor, resolving it
   * through `LookupRType` on first use.
   *
   * This used to be a free `LookupCachedCStorageManipulatorTypeRuntime` that
   * resolved the type by calling `RRef_CStorageManipulator` with a null object
   * and taking `mType` out of the result, caching into a file-scope
   * `gCStorageManipulatorCachedType`, with nothing calling it. The binary does
   * neither: it reads and fills 0x010C73DC directly, which is this class's own
   * `sType`.
   */
  gpg::RType* CStorageManipulator::StaticGetClass()
  {
    return CachedCStorageManipulatorType();
  }

  /**
   * Address: 0x00648D70 (FUN_00648D70)
   *
   * VFTable SLOT: 0 (`CScriptObject` subobject at +0x10)
   */
  gpg::RType* CStorageManipulator::GetClass() const
  {
    return CachedCStorageManipulatorType();
  }

  /**
   * Address: 0x00648FC0 (FUN_00648FC0, ??0CStorageManipulator@Moho@@QAE@XZ)
   *
   * What it does:
   * Chains to `IAniManipulator`, publishes both vftables, and clears the bound
   * unit, all three offsets and the resource type.
   */
  CStorageManipulator::CStorageManipulator()
    : IAniManipulator()
    , mUnit(nullptr)
    , mMax(0.0f, 0.0f, 0.0f)
    , mMin(0.0f, 0.0f, 0.0f)
    , mCur(0.0f, 0.0f, 0.0f)
    , mResourceType(ECON_ENERGY)
  {
  }

  /**
   * Address: 0x00649060 (FUN_00649060, Moho::CStorageManipulator::CStorageManipulator)
   *
   * What it does:
   * Builds one storage manipulator bound to `{unit, watchedBoneIndex}`,
   * initializes min/max/current resource offsets, creates the Lua object lane,
   * and applies the initial current offset to the watched local bone
   * transform.
   *
   * The base is constructed from the unit's own sim and actor: the binary
   * reads `[unit+0x150]` and `[unit+0x540]` and pushes them with a zero
   * precedence straight into `IAniManipulator::IAniManipulator` at 0x0063B640.
   */
  CStorageManipulator::CStorageManipulator(
    Unit* const unit,
    const int watchedBoneIndex,
    const Wm3::Vector3f& minOffset,
    const Wm3::Vector3f& maxOffset,
    const EEconResource resourceType
  )
    : IAniManipulator(unit->SimulationRef, unit->AniActor, 0)
    , mUnit(unit)
    , mMax(maxOffset)
    , mMin(minOffset)
    , mCur(maxOffset)
    , mResourceType(resourceType)
  {
    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject object;
    (void)func_CreateLuaCStorageManipulator(&object, unit->SimulationRef ? unit->SimulationRef->mLuaState : nullptr);

    CreateLuaObject(object, arg1, arg2, arg3);

    (void)AddWatchBone(watchedBoneIndex);
    mTriggered = false;

    if (CAniPoseBone* const watchedBone = ResolveWatchedBoneForStorageManipulator(this); watchedBone != nullptr) {
      ApplyStorageOffsetToWatchedBone(watchedBone, mCur);
    }
  }

  /**
   * Address: 0x006494C0 (FUN_006494C0, cfunc_CreateStorageManipL)
   *
   * IDA signature:
   * int __thiscall cfunc_CreateStorageManipL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Reads `(unit, bone, resourceName, minX, minY, minZ, maxX, maxY, maxZ)`,
   * forces the unit skeleton to load, resolves the watched bone, parses the
   * resource enum, allocates and constructs one storage manipulator bound to the
   * unit, and pushes the manipulator's Lua userdata.
   *
   * NOTE: the binary passes the Lua `min*` args (stack 4-6) as the constructor's
   * max-offset and the `max*` args (stack 7-9) as the min-offset; this inversion
   * is preserved 1:1.
   */
  int cfunc_CreateStorageManipL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 2 || argumentCount > 9) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        "CreateStorageManip(unit, bone, resouceName, minX, minY, minZ, maxX, maxY, maxZ)",
        2,
        9,
        argumentCount
      );
    }

    const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    Unit* const unit = SCR_FromLua_Unit(unitObject);

    CAniActor* const actor = unit->AniActor;
    // Force the skeleton to load (fetched then released), matching the binary.
    (void)actor->GetSkeleton();

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = actor->ResolveBoneIndex(boneArg);
    if (boneIndex < 0) {
      LuaPlus::LuaState::Error(state, "A valid bone is required");
    }

    moho::EEconResource resourceType{};
    gpg::RRef resourceRef;
    (void)gpg::RRef_EEconResource(&resourceRef, &resourceType);
    const char* const resourceName = lua_tostring(rawState, 3);
    if (resourceName == nullptr) {
      LuaPlus::LuaStackObject resourceArg(state, 3);
      resourceArg.TypeError("string");
    }
    SCR_GetEnum(state, resourceName, resourceRef);

    // The binary allocates before validating the six coordinate args (leaking on
    // a Lua type error, which longjmps).
    void* const rawStorage = ::operator new(sizeof(CStorageManipulator));

    const auto readNumberArg = [&](const int stackIndex) -> float {
      LuaPlus::LuaStackObject numberArg(state, stackIndex);
      if (lua_type(rawState, stackIndex) != LUA_TNUMBER) {
        numberArg.TypeError("number");
      }
      return static_cast<float>(lua_tonumber(rawState, stackIndex));
    };

    // Validation/error precedence is stack 9 -> 4, matching the binary.
    const float coord9 = readNumberArg(9);
    const float coord8 = readNumberArg(8);
    const float coord7 = readNumberArg(7);
    const float coord6 = readNumberArg(6);
    const float coord5 = readNumberArg(5);
    const float coord4 = readNumberArg(4);

    const Wm3::Vector3f minOffset{coord7, coord8, coord9};
    const Wm3::Vector3f maxOffset{coord4, coord5, coord6};
    auto* const manipulator =
      new (rawStorage) CStorageManipulator(unit, boneIndex, minOffset, maxOffset, resourceType);

    manipulator->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00649440 (FUN_00649440, cfunc_CreateStorageManip)
   *
   * IDA signature:
   * int __cdecl cfunc_CreateStorageManip(lua_State *a1);
   *
   * What it does:
   * Unwraps the raw Lua callback context and forwards to
   * `cfunc_CreateStorageManipL`.
   */
  // See the note on `cfunc_CreateThrustController`: a top-level `const` on this
  // pointer parameter changes the decorated name to `QAUlua_State@@`, which the
  // declaration in `ManipulatorLuaFunctionThunks.cpp` cannot resolve.
  int cfunc_CreateStorageManip(lua_State* luaContext)
  {
    return cfunc_CreateStorageManipL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00649260 (FUN_00649260, Moho::CStorageManipulator::MoveManipulator)
   *
   * VFTable SLOT: 1
   *
   * What it does:
   * Updates current storage-offset smoothing from army economy ratio (unless
   * the unit is still being built), applies the rotated offset to the watched
   * bone local transform, and signals the manipulator event lane.
   *
   * This was a free `UpdateCStorageManipulatorRuntime` over the runtime view,
   * carrying `[[maybe_unused]]` because nothing could call it -- it is the
   * class's only overridden virtual, and leaving it off the class left slot 1
   * of 0xE2305C resolving to `IAniManipulator`'s `_purecall`.
   */
  bool CStorageManipulator::ManipulatorUpdate()
  {
    if (mWatchBones.begin() == mWatchBones.end() ||
        (mWatchBones.begin()->mFlags & kWatchBoneActiveFlag) == 0u) {
      return false;
    }

    CAniPoseBone* const watchedBone = ResolveWatchedBoneForStorageManipulator(this);
    if (watchedBone == nullptr) {
      return false;
    }

    if (mUnit == nullptr || mUnit->IsBeingBuilt()) {
      ApplyStorageOffsetToWatchedBone(watchedBone, mCur);
      EventSetSignaled(true);
      return true;
    }

    float storageRatio = 0.0f;
    if (CArmyImpl* const army = mUnit->ArmyRef; army != nullptr) {
      if (CSimArmyEconomyInfo* const economyInfo = army->GetEconomy(); economyInfo != nullptr) {
        const double maxStorage = economyInfo->economy.MaxStorageOf(mResourceType);
        if (maxStorage > 0.0) {
          const float storedValue =
            (mResourceType == ECON_MASS) ? economyInfo->economy.mStored.MASS : economyInfo->economy.mStored.ENERGY;
          storageRatio = storedValue / static_cast<float>(maxStorage);
        }
      }
    }

    const float inverseRatio = 1.0f - storageRatio;
    const float targetX = (mMax.x * inverseRatio) + (mMin.x * storageRatio);
    const float targetY = (mMax.y * inverseRatio) + (mMin.y * storageRatio);
    const float targetZ = (mMax.z * inverseRatio) + (mMin.z * storageRatio);

    mCur.x = (mCur.x * kStoragePreserveFactor) + (targetX * kStorageBlendFactor);
    mCur.y = (mCur.y * kStoragePreserveFactor) + (targetY * kStorageBlendFactor);
    mCur.z = (mCur.z * kStoragePreserveFactor) + (targetZ * kStorageBlendFactor);

    ApplyStorageOffsetToWatchedBone(watchedBone, mCur);
    EventSetSignaled(true);
    return true;
  }

  /**
   * Address: 0x00649AE0 (FUN_00649AE0, Moho::CStorageManipulatorTypeInfo::AddBase_IAniManipulator)
   *
   * What it does:
   * Adds `IAniManipulator` as a zero-offset base record on one
   * `CStorageManipulator` type descriptor.
   */
  void AddBaseIAniManipulatorToCStorageManipulatorTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = IAniManipulator::StaticGetClass();
    if (!baseType) {
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
   * Owns reflected metadata for `CStorageManipulator`.
   *
   * The four lifecycle callbacks are static members rather than free helpers
   * because that is what the binary's own symbols call them -- `NewRef`,
   * `CtrRef`, `Delete` and `Destruct` on `Moho::CStorageManipulatorTypeInfo` --
   * and `Init` installs exactly those four addresses.
   */
  class CStorageManipulatorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00648DB0 (FUN_00648DB0, ctor lane)
     *
     * What it does:
     * Preregisters the `CStorageManipulator` RTTI descriptor during startup.
     * In the binary this constructor body is inlined into the `.CRT$XCL`
     * provider wrapper (`register_CStorageManipulatorTypeInfo`, 0x00BD3640)
     * that constructs the file-scope singleton, rather than being emitted as
     * a standalone `__thiscall` symbol.
     */
    CStorageManipulatorTypeInfo();

    /**
     * Address: 0x00648E60 (FUN_00648E60, Moho::CStorageManipulatorTypeInfo::dtr)
     *
     * What it does:
     * Frees the `RType` base's two `msvc8::vector<RField>` storage lanes and
     * restores the `gpg::RObject` vftable. Defaulted in source: the
     * compiler-generated `~RType()` reproduces this behavior, matching every
     * other manipulator TypeInfo dtor in this family.
     */
    ~CStorageManipulatorTypeInfo() override = default;

    /**
     * Address: 0x00648E50 (FUN_00648E50, Moho::CStorageManipulatorTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00648E10 (FUN_00648E10, Moho::CStorageManipulatorTypeInfo::Init)
     *
     * What it does:
     * Sets the reflected object size, binds the four lifecycle callbacks,
     * registers `IAniManipulator` as the reflected base, then runs the base
     * `RType::Init` and finalizes field/base metadata. The binary's first
     * store, `mov [esi+8], 0xB0`, is what pins `sizeof(CStorageManipulator)`.
     */
    void Init() override;

    /**
     * Address: 0x006499C0 (FUN_006499C0, Moho::CStorageManipulatorTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CStorageManipulator`, default-constructs it, and returns
     * its reflected `RRef`. The `unique_ptr` is the binary's own EH funclet
     * (0x00BB9C1B): the allocation goes back to `::operator delete` if the
     * constructor throws.
     */
    [[nodiscard]] static gpg::RRef NewRef();

    /**
     * Address: 0x00649A60 (FUN_00649A60, Moho::CStorageManipulatorTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one `CStorageManipulator` into caller storage and
     * returns the resulting reflected reference.
     */
    [[nodiscard]] static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00649A40 (FUN_00649A40, Moho::CStorageManipulatorTypeInfo::Delete)
     *
     * What it does:
     * `delete` through the slot-0 deleting destructor. `test ecx,ecx; je;
     * mov eax,[ecx]; mov edx,[eax]; push 1; call edx` is exactly what MSVC
     * emits for `delete p` on a class with a virtual destructor; it used to be
     * spelled here as a hand-rolled `ScalarDeletingDtorFn` vtable index.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00649AD0 (FUN_00649AD0, Moho::CStorageManipulatorTypeInfo::Destruct)
     *
     * What it does:
     * Destroys in place without freeing. `p->~T()` on a virtual destructor is
     * a slot-0 dispatch with the free bit clear, which is this whole function.
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(CStorageManipulatorTypeInfo) == 0x64, "CStorageManipulatorTypeInfo size must be 0x64");

  /**
   * Address: 0x00648DB0 (FUN_00648DB0, ctor lane)
   */
  CStorageManipulatorTypeInfo::CStorageManipulatorTypeInfo()
  {
    gpg::PreRegisterRType(typeid(CStorageManipulator), this);
  }

  /**
   * Address: 0x00648E50 (FUN_00648E50, Moho::CStorageManipulatorTypeInfo::GetName)
   */
  const char* CStorageManipulatorTypeInfo::GetName() const
  {
    return "CStorageManipulator";
  }

  /**
   * Address: 0x006499C0 (FUN_006499C0, Moho::CStorageManipulatorTypeInfo::NewRef)
   */
  gpg::RRef CStorageManipulatorTypeInfo::NewRef()
  {
    auto releaseStorage = [](CStorageManipulator* const storage) noexcept {
      ::operator delete(static_cast<void*>(storage));
    };
    std::unique_ptr<CStorageManipulator, decltype(releaseStorage)> ownedStorage(nullptr, releaseStorage);

    auto* const rawStorage = static_cast<CStorageManipulator*>(::operator new(sizeof(CStorageManipulator)));
    ownedStorage.reset(rawStorage);

    CStorageManipulator* const manipulator =
      rawStorage ? new (static_cast<void*>(rawStorage)) CStorageManipulator() : nullptr;

    gpg::RRef reflected{};
    (void)gpg::RRef_CStorageManipulator(&reflected, manipulator);
    ownedStorage.release();
    return reflected;
  }

  /**
   * Address: 0x00649A60 (FUN_00649A60, Moho::CStorageManipulatorTypeInfo::CtrRef)
   */
  gpg::RRef CStorageManipulatorTypeInfo::CtrRef(void* const objectStorage)
  {
    CStorageManipulator* const manipulator =
      objectStorage ? new (objectStorage) CStorageManipulator() : nullptr;

    gpg::RRef reflected{};
    (void)gpg::RRef_CStorageManipulator(&reflected, manipulator);
    return reflected;
  }

  /**
   * Address: 0x00649A40 (FUN_00649A40, Moho::CStorageManipulatorTypeInfo::Delete)
   */
  void CStorageManipulatorTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CStorageManipulator*>(objectStorage);
  }

  /**
   * Address: 0x00649AD0 (FUN_00649AD0, Moho::CStorageManipulatorTypeInfo::Destruct)
   */
  void CStorageManipulatorTypeInfo::Destruct(void* const objectStorage)
  {
    static_cast<CStorageManipulator*>(objectStorage)->~CStorageManipulator();
  }

  // NOTE: 0x006498E0 (field-write shape identical to the other ~39 manipulator
  // TypeInfo Init bodies) is recovered as the shared `gpg::BindRTypeLifecycleCallbacks`
  // helper (Reflection.h/.cpp) -- not as a per-type duplicate here. This file's
  // prior `InstallCStorageManipulatorTypeLifecycleCallbacksRuntime` was an
  // unwired [[maybe_unused]] duplicate of that same mechanic; removed in favor
  // of the `BindRTypeLifecycleCallbacks` call below, which is the single
  // canonical, actually-called citation.

  /**
   * Address: 0x00648E10 (FUN_00648E10, Moho::CStorageManipulatorTypeInfo::Init)
   */
  void CStorageManipulatorTypeInfo::Init()
  {
    size_ = sizeof(CStorageManipulator);
    (void)gpg::BindRTypeLifecycleCallbacks(this, &NewRef, &CtrRef, &Delete, &Destruct);
    AddBaseIAniManipulatorToCStorageManipulatorTypeInfo(this);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

namespace
{
  alignas(moho::CStorageManipulatorTypeInfo)
  unsigned char gCStorageManipulatorTypeInfoStorage[sizeof(moho::CStorageManipulatorTypeInfo)] = {};
  bool gCStorageManipulatorTypeInfoConstructed = false;

  [[nodiscard]] moho::CStorageManipulatorTypeInfo* AcquireCStorageManipulatorTypeInfo()
  {
    if (!gCStorageManipulatorTypeInfoConstructed) {
      new (gCStorageManipulatorTypeInfoStorage) moho::CStorageManipulatorTypeInfo();
      gCStorageManipulatorTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CStorageManipulatorTypeInfo*>(gCStorageManipulatorTypeInfoStorage);
  }

  /**
   * Address: 0x00BFB310 (FUN_00BFB310, cleanup_CStorageManipulatorTypeInfo)
   *
   * What it does:
   * Tears down static `CStorageManipulatorTypeInfo` storage at process exit.
   */
  void cleanup_CStorageManipulatorTypeInfo()
  {
    if (!gCStorageManipulatorTypeInfoConstructed) {
      return;
    }

    AcquireCStorageManipulatorTypeInfo()->~CStorageManipulatorTypeInfo();
    gCStorageManipulatorTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD3640 (FUN_00BD3640, register_CStorageManipulatorTypeInfo)
   *
   * What it does:
   * Constructs the startup-owned `CStorageManipulatorTypeInfo` singleton and
   * installs process-exit cleanup. Dispatched from `.CRT$XCL` (`__xc_a`); the
   * binary has exactly one call site and no reentry guard, matching the
   * guarded-singleton idiom used throughout this manipulator family.
   */
  void register_CStorageManipulatorTypeInfo()
  {
    (void)AcquireCStorageManipulatorTypeInfo();
    (void)std::atexit(&cleanup_CStorageManipulatorTypeInfo);
  }

  /**
   * Address: 0x00649EF0 (FUN_00649EF0, Moho::CStorageManipulator::MemberSerialize)
   *
   * IDA signature:
   * void __usercall sub_649EF0(
   *     Moho::CStorageManipulator *a1@<eax>, BinaryWriteArchive *a2@<edi>);
   *
   * What it does:
   * Serializes this manipulator into a binary write archive:
   *   1) writes the base `IAniManipulator` subobject payload;
   *   2) writes the owning `Moho::Unit` as an unowned raw-pointer RRef;
   *   3) writes `mMax`, `mMin`, `mCur` as `Wm3::Vector3f` values;
   *   4) writes `mResourceType` as an `EEconResource` enum value.
   *
   * All reflected type lookups go through cached singletons matching the
   * binary's idiom (0x010C738C for the base, 0x010C6330 for `Wm3::Vector3f`,
   * each filled with `LookupRType` on first use). The three vectors are handed
   * over by address -- `lea edx, [ebx + 0x84]` at 0x00649F7D, no temporary --
   * which is exactly what the pair of `Wm3::Vector3f` <-> runtime-view
   * converters this file used to carry stood in the way of.
   */
  void CStorageManipulator::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};

    archive->Write(IAniManipulator::StaticGetClass(), this, ownerRef);

    gpg::RRef unitRef{};
    (void)gpg::RRef_Unit(&unitRef, mUnit);
    gpg::WriteRawPointer(archive, unitRef, gpg::TrackedPointerState::Unowned, ownerRef);

    gpg::RType* const vector3Type = CachedVector3fType();
    archive->Write(vector3Type, &mMax, ownerRef);
    archive->Write(vector3Type, &mMin, ownerRef);
    archive->Write(vector3Type, &mCur, ownerRef);

    archive->Write(CachedEEconResourceType(), &mResourceType, ownerRef);
  }

  /**
   * Address: 0x00649DB0 (FUN_00649DB0, Moho::CStorageManipulator::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall sub_649DB0(
   *     Moho::Unit **obj@<ecx>, gpg::ReadArchive *a2@<eax>);
   *
   * What it does:
   * Exact mirror of `MemberSerialize` (0x00649EF0): base payload, the owning
   * unit as a tracked pointer, the three offsets, then the resource type. Each
   * read passes a fresh zeroed owner `RRef`, exactly as the binary rebuilds
   * the temporary before every call.
   */
  void CStorageManipulator::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    gpg::RRef ownerRef{};

    archive->Read(IAniManipulator::StaticGetClass(), this, ownerRef);

    archive->ReadPointer_Unit(&mUnit, &ownerRef);

    gpg::RType* const vector3Type = CachedVector3fType();
    archive->Read(vector3Type, &mMax, ownerRef);
    archive->Read(vector3Type, &mMin, ownerRef);
    archive->Read(vector3Type, &mCur, ownerRef);

    archive->Read(CachedEEconResourceType(), &mResourceType, ownerRef);
  }

  /**
   * Address: 0x00649B60 (FUN_00649B60, func_CreateLuaCStorageManipulator)
   *
   * What it does:
   * Writes the `CStorageManipulator` metatable Lua object into `object` and
   * returns the same destination pointer.
   */
  LuaPlus::LuaObject*
  func_CreateLuaCStorageManipulator(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = CScrLuaMetatableFactory<CStorageManipulator>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x00649BB0 (FUN_00649BB0)
   *
   * What it does:
   * Rebinds the startup metatable-factory index lane for
   * `CScrLuaMetatableFactory<CStorageManipulator>` and returns that singleton.
   *
   * Seven instructions, and all seven are a constructor: `[0x010A63A8] += 1`
   * is `CScrLuaObjectFactory::AllocateFactoryObjectIndex`, and the two stores
   * that follow put that index at `[0xF8D768]` and the instantiation's vftable
   * 0xE2307C at `[0xF8D764]` -- i.e. `+0x04` and `+0x00` of the singleton at
   * 0xF8D764, which is then returned. So this is
   * `CScrLuaMetatableFactory<CStorageManipulator>::CScrLuaMetatableFactory()`,
   * emitted out of line and inlined into its `.CRT$XCL` provider
   * (`register_CScrLuaMetatableFactory_CStorageManipulator_Index`, 0x00BD36B0,
   * in ManipulatorStartupRegistrations.cpp), which is why it has zero callers.
   *
   * It stays `[[maybe_unused]]` here on purpose: the address belongs on the
   * template's constructor in the `CScrLuaMetatableFactory` header, and ~40
   * manipulator families carry the identical stand-in. Moving one without the
   * rest would be the per-type copy RULE ONE forbids.
   */
  [[maybe_unused]] CScrLuaMetatableFactory<CStorageManipulator>*
  startup_CScrLuaMetatableFactory_CStorageManipulator_Index()
  {
    auto& instance = CScrLuaMetatableFactory<CStorageManipulator>::Instance();
    instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }
} // namespace moho

namespace
{
  // Address: 0x00BD3660 (dynamic initializer for the global
  // `CStorageManipulatorSerializer` singleton, __xc_a-reachable) -- MSVC's
  // own compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<CStorageManipulator>` ctor (calls
  // `gpg::SerHelperBase::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback`
  // to the template's `Deserialize`/`Serialize`, installs the vtable) and
  // registers the real mangled destructor
  // (`??1CStorageManipulatorSerializer@Moho@@QAE@@Z`, 0x00BFB370) via
  // `atexit`. See the Doxygen comment on the alias above for the full
  // per-instantiation address list.
  moho::CStorageManipulatorSerializer gCStorageManipulatorSerializer;

  struct CStorageManipulatorTypeInfoStartupBootstrap
  {
    CStorageManipulatorTypeInfoStartupBootstrap()
    {
      moho::register_CStorageManipulatorTypeInfo();
    }
  };

  [[maybe_unused]] CStorageManipulatorTypeInfoStartupBootstrap gCStorageManipulatorTypeInfoStartupBootstrap;
} // namespace

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CStorageManipulatorTypeInfo_7d3a2f, moho::register_CStorageManipulatorTypeInfo)
