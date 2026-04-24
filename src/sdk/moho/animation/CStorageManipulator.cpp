#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/EEconResourceTypeInfo.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/lua/CScrLuaObjectFactory.h"
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

  struct CStorageManipulatorVector3RuntimeView
  {
    float x = 0.0f; // +0x00
    float y = 0.0f; // +0x04
    float z = 0.0f; // +0x08
  };
  static_assert(sizeof(CStorageManipulatorVector3RuntimeView) == 0x0C, "CStorageManipulatorVector3RuntimeView size must be 0x0C");

  struct CStorageManipulatorRuntimeView
  {
    void* mPrimaryVTable = nullptr;                                // +0x00
    std::uint8_t mPad04_0F[0x0C]{};                                // +0x04
    void* mScriptObjectVTable = nullptr;                           // +0x10
    std::uint8_t mPad14_7F[0x6C]{};                                // +0x14
    moho::Unit* mUnit = nullptr;                                   // +0x80
    CStorageManipulatorVector3RuntimeView mMax;                    // +0x84
    CStorageManipulatorVector3RuntimeView mMin;                    // +0x90
    CStorageManipulatorVector3RuntimeView mCur;                    // +0x9C
    moho::EEconResource mResourceType = moho::ECON_ENERGY;         // +0xA8
    std::uint8_t mPadAC_AF[0x04]{};                                // +0xAC
  };
  static_assert(offsetof(CStorageManipulatorRuntimeView, mPrimaryVTable) == 0x00, "CStorageManipulatorRuntimeView::mPrimaryVTable offset must be 0x00");
  static_assert(
    offsetof(CStorageManipulatorRuntimeView, mScriptObjectVTable) == 0x10,
    "CStorageManipulatorRuntimeView::mScriptObjectVTable offset must be 0x10"
  );
  static_assert(offsetof(CStorageManipulatorRuntimeView, mUnit) == 0x80, "CStorageManipulatorRuntimeView::mUnit offset must be 0x80");
  static_assert(offsetof(CStorageManipulatorRuntimeView, mMax) == 0x84, "CStorageManipulatorRuntimeView::mMax offset must be 0x84");
  static_assert(offsetof(CStorageManipulatorRuntimeView, mMin) == 0x90, "CStorageManipulatorRuntimeView::mMin offset must be 0x90");
  static_assert(offsetof(CStorageManipulatorRuntimeView, mCur) == 0x9C, "CStorageManipulatorRuntimeView::mCur offset must be 0x9C");
  static_assert(
    offsetof(CStorageManipulatorRuntimeView, mResourceType) == 0xA8,
    "CStorageManipulatorRuntimeView::mResourceType offset must be 0xA8"
  );
  static_assert(sizeof(CStorageManipulatorRuntimeView) == 0xB0, "CStorageManipulatorRuntimeView size must be 0xB0");

  /**
   * Address: 0x00648FC0 (FUN_00648FC0, ??0CStorageManipulator@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Builds one default `CStorageManipulator` lane on top of
   * `IAniManipulator`, installs storage-manipulator vtable lanes, clears
   * tracked min/max/current vectors, and defaults resource type to energy.
   */
  [[maybe_unused]] CStorageManipulatorRuntimeView* InitializeCStorageManipulatorDefaultRuntime(
    CStorageManipulatorRuntimeView* const runtime
  ) noexcept
  {
    if (runtime == nullptr) {
      return nullptr;
    }

    (void)new (static_cast<void*>(runtime)) moho::IAniManipulator();

    static std::uint8_t sCStorageManipulatorPrimaryVTableTag = 0;
    static std::uint8_t sCStorageManipulatorScriptObjectVTableTag = 0;
    runtime->mPrimaryVTable = &sCStorageManipulatorPrimaryVTableTag;
    runtime->mScriptObjectVTable = &sCStorageManipulatorScriptObjectVTableTag;

    runtime->mUnit = nullptr;
    runtime->mMax = CStorageManipulatorVector3RuntimeView{};
    runtime->mMin = CStorageManipulatorVector3RuntimeView{};
    runtime->mCur = CStorageManipulatorVector3RuntimeView{};
    runtime->mResourceType = moho::ECON_ENERGY;
    return runtime;
  }

  struct CStorageManipulatorSerializerHelperNode
  {
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(sizeof(CStorageManipulatorSerializerHelperNode) == 0x10, "CStorageManipulatorSerializerHelperNode size must be 0x10");

  CStorageManipulatorSerializerHelperNode gCStorageManipulatorSerializer;
  gpg::RType* gCStorageManipulatorCachedType = nullptr;

  struct CStorageManipulatorTypeLifecycleSlotsRuntimeView
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
    offsetof(CStorageManipulatorTypeLifecycleSlotsRuntimeView, mNewRefFunc) == 0x48,
    "CStorageManipulatorTypeLifecycleSlotsRuntimeView::mNewRefFunc offset must be 0x48"
  );
  static_assert(
    offsetof(CStorageManipulatorTypeLifecycleSlotsRuntimeView, mDeleteFunc) == 0x50,
    "CStorageManipulatorTypeLifecycleSlotsRuntimeView::mDeleteFunc offset must be 0x50"
  );
  static_assert(
    offsetof(CStorageManipulatorTypeLifecycleSlotsRuntimeView, mCtorRefFunc) == 0x54,
    "CStorageManipulatorTypeLifecycleSlotsRuntimeView::mCtorRefFunc offset must be 0x54"
  );
  static_assert(
    offsetof(CStorageManipulatorTypeLifecycleSlotsRuntimeView, mDestructFunc) == 0x5C,
    "CStorageManipulatorTypeLifecycleSlotsRuntimeView::mDestructFunc offset must be 0x5C"
  );
#endif

  using ScalarDeletingDtorFn = int(__thiscall*)(void* self, int deleteFlag);

  [[nodiscard]] CStorageManipulatorVector3RuntimeView ToStorageVectorRuntime(const Wm3::Vector3f& value) noexcept
  {
    return CStorageManipulatorVector3RuntimeView{value.x, value.y, value.z};
  }

  [[nodiscard]] Wm3::Vector3f ToStorageVector(const CStorageManipulatorVector3RuntimeView& value) noexcept
  {
    return Wm3::Vector3f{value.x, value.y, value.z};
  }

  [[nodiscard]] moho::CAniPoseBone* ResolveWatchedBoneForStorageManipulator(
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

  /**
   * Address: 0x00648F60 (FUN_00648F60)
   *
   * What it does:
   * Startup cleanup variant that unlinks and self-resets the global
   * CStorageManipulator serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CStorageManipulatorSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(gCStorageManipulatorSerializer);
  }

  /**
   * Address: 0x00648F90 (FUN_00648F90)
   *
   * What it does:
   * Secondary startup cleanup variant that unlinks and self-resets the global
   * CStorageManipulator serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CStorageManipulatorSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(gCStorageManipulatorSerializer);
  }
} // namespace

namespace moho
{
  LuaPlus::LuaObject* func_CreateLuaCStorageManipulator(
    LuaPlus::LuaObject* object,
    LuaPlus::LuaState* state
  );

  [[nodiscard]] gpg::RType* CachedIAniManipulatorTypeForStorageManipulatorTypeInfo()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x006498C0 (FUN_006498C0)
   *
   * What it does:
   * Returns cached reflected `CStorageManipulator` type lane; on first use,
   * resolves and caches it through `RRef_CStorageManipulator`.
   */
  [[maybe_unused]] gpg::RType* LookupCachedCStorageManipulatorTypeRuntime()
  {
    if (gCStorageManipulatorCachedType == nullptr) {
      gpg::RRef reflected{};
      (void)gpg::RRef_CStorageManipulator(&reflected, nullptr);
      gCStorageManipulatorCachedType = reflected.mType;
    }
    return gCStorageManipulatorCachedType;
  }

  /**
   * Address: 0x00649060 (FUN_00649060, Moho::CStorageManipulator::CStorageManipulator)
   *
   * What it does:
   * Builds one storage manipulator bound to `{unit, bone}`, initializes
   * min/max/current resource offsets, creates the Lua object lane, and applies
   * the initial current offset to the watched local bone transform.
   */
  [[maybe_unused]] CStorageManipulatorRuntimeView* ConstructCStorageManipulatorRuntime(
    CStorageManipulatorRuntimeView* const runtime,
    moho::Unit* const unit,
    const std::int32_t boneIndex,
    const Wm3::Vector3f* const minOffset,
    const Wm3::Vector3f* const maxOffset,
    const moho::EEconResource resourceType
  )
  {
    if (runtime == nullptr || unit == nullptr || minOffset == nullptr || maxOffset == nullptr) {
      return runtime;
    }

    (void)new (static_cast<void*>(runtime)) moho::IAniManipulator(unit->SimulationRef, unit->AniActor, 0);

    static std::uint8_t sCStorageManipulatorPrimaryVTableTag = 0;
    static std::uint8_t sCStorageManipulatorScriptObjectVTableTag = 0;
    runtime->mPrimaryVTable = &sCStorageManipulatorPrimaryVTableTag;
    runtime->mScriptObjectVTable = &sCStorageManipulatorScriptObjectVTableTag;

    runtime->mUnit = unit;
    runtime->mMax = ToStorageVectorRuntime(*maxOffset);
    runtime->mMin = ToStorageVectorRuntime(*minOffset);
    runtime->mCur = ToStorageVectorRuntime(*maxOffset);
    runtime->mResourceType = resourceType;

    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject object;
    (void)func_CreateLuaCStorageManipulator(&object, unit->SimulationRef ? unit->SimulationRef->mLuaState : nullptr);

    auto* const manipulator = reinterpret_cast<moho::IAniManipulator*>(runtime);
    auto* const scriptObject = static_cast<moho::CScriptObject*>(manipulator);
    scriptObject->CreateLuaObject(object, arg1, arg2, arg3);

    (void)manipulator->AddWatchBone(boneIndex);
    reinterpret_cast<moho::CTaskEvent*>(runtime)->mTriggered = false;

    if (moho::CAniPoseBone* const watchedBone = ResolveWatchedBoneForStorageManipulator(manipulator); watchedBone != nullptr) {
      ApplyStorageOffsetToWatchedBone(watchedBone, ToStorageVector(runtime->mCur));
    }

    return runtime;
  }

  /**
   * Address: 0x00649260 (FUN_00649260, Moho::CStorageManipulator::MoveManipulator)
   *
   * What it does:
   * Updates current storage-offset smoothing from army economy ratio (unless
   * the unit is still being built), applies the rotated offset to the watched
   * bone local transform, and signals the manipulator event lane.
   */
  [[maybe_unused]] void UpdateCStorageManipulatorRuntime(CStorageManipulatorRuntimeView* const runtime)
  {
    if (runtime == nullptr) {
      return;
    }

    auto* const manipulator = reinterpret_cast<moho::IAniManipulator*>(runtime);
    if (manipulator->mWatchBones.mBegin == manipulator->mWatchBones.mEnd ||
        (manipulator->mWatchBones.mBegin->mFlags & kWatchBoneActiveFlag) == 0u) {
      return;
    }

    moho::CAniPoseBone* const watchedBone = ResolveWatchedBoneForStorageManipulator(manipulator);
    if (watchedBone == nullptr) {
      return;
    }

    if (runtime->mUnit == nullptr || runtime->mUnit->IsBeingBuilt()) {
      ApplyStorageOffsetToWatchedBone(watchedBone, ToStorageVector(runtime->mCur));
      reinterpret_cast<moho::CTaskEvent*>(runtime)->EventSetSignaled(true);
      return;
    }

    float storageRatio = 0.0f;
    if (moho::CArmyImpl* const army = runtime->mUnit->ArmyRef; army != nullptr) {
      if (moho::CSimArmyEconomyInfo* const economyInfo = army->GetEconomy(); economyInfo != nullptr) {
        const double maxStorage = economyInfo->economy.MaxStorageOf(runtime->mResourceType);
        if (maxStorage > 0.0) {
          const float storedValue =
            (runtime->mResourceType == moho::ECON_MASS) ? economyInfo->economy.mStored.MASS : economyInfo->economy.mStored.ENERGY;
          storageRatio = storedValue / static_cast<float>(maxStorage);
        }
      }
    }

    const float inverseRatio = 1.0f - storageRatio;
    const float targetX = (runtime->mMax.x * inverseRatio) + (runtime->mMin.x * storageRatio);
    const float targetY = (runtime->mMax.y * inverseRatio) + (runtime->mMin.y * storageRatio);
    const float targetZ = (runtime->mMax.z * inverseRatio) + (runtime->mMin.z * storageRatio);

    runtime->mCur.x = (runtime->mCur.x * kStoragePreserveFactor) + (targetX * kStorageBlendFactor);
    runtime->mCur.y = (runtime->mCur.y * kStoragePreserveFactor) + (targetY * kStorageBlendFactor);
    runtime->mCur.z = (runtime->mCur.z * kStoragePreserveFactor) + (targetZ * kStorageBlendFactor);

    ApplyStorageOffsetToWatchedBone(watchedBone, ToStorageVector(runtime->mCur));
    reinterpret_cast<moho::CTaskEvent*>(runtime)->EventSetSignaled(true);
  }

  /**
   * Address: 0x006499C0 (FUN_006499C0, Moho::CStorageManipulatorTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CStorageManipulator` runtime object, runs default
   * constructor lanes, and writes its reflected `RRef` into caller storage.
   */
  [[maybe_unused]] gpg::RRef* BuildNewCStorageManipulatorRef(gpg::RRef* const outRef)
  {
    auto deleteRuntime = [](CStorageManipulatorRuntimeView* const runtime) noexcept {
      ::operator delete(static_cast<void*>(runtime));
    };
    std::unique_ptr<CStorageManipulatorRuntimeView, decltype(deleteRuntime)> ownedRuntime(nullptr, deleteRuntime);

    CStorageManipulatorRuntimeView* const allocated =
      static_cast<CStorageManipulatorRuntimeView*>(::operator new(sizeof(CStorageManipulatorRuntimeView)));
    ownedRuntime.reset(allocated);

    CStorageManipulatorRuntimeView* const runtime =
      allocated ? InitializeCStorageManipulatorDefaultRuntime(allocated) : nullptr;

    gpg::RRef reflected{};
    (void)gpg::RRef_CStorageManipulator(&reflected, reinterpret_cast<moho::CStorageManipulator*>(runtime));
    ownedRuntime.release();

    outRef->mObj = reflected.mObj;
    outRef->mType = reflected.mType;
    return outRef;
  }

  /**
   * Address: 0x00649A40 (FUN_00649A40, Moho::CStorageManipulatorTypeInfo::Delete)
   *
   * What it does:
   * Runs scalar-deleting destructor slot `0` with delete flag `1` when object
   * storage is non-null.
   */
  [[maybe_unused]] void DeleteCStorageManipulatorStorageRuntime(void* const objectStorage)
  {
    if (objectStorage == nullptr) {
      return;
    }

    auto* const vtable = *reinterpret_cast<ScalarDeletingDtorFn**>(objectStorage);
    (void)vtable[0](objectStorage, 1);
  }

  /**
   * Address: 0x00649A60 (FUN_00649A60, Moho::CStorageManipulatorTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CStorageManipulator` into caller storage and
   * writes the resulting reflected reference into `outRef`.
   */
  [[maybe_unused]] gpg::RRef* ConstructCStorageManipulatorRefInPlaceRuntime(
    gpg::RRef* const outRef,
    void* const objectStorage
  )
  {
    auto* const runtimeStorage = static_cast<CStorageManipulatorRuntimeView*>(objectStorage);
    CStorageManipulatorRuntimeView* const runtime =
      runtimeStorage ? InitializeCStorageManipulatorDefaultRuntime(runtimeStorage) : nullptr;

    gpg::RRef reflected{};
    (void)gpg::RRef_CStorageManipulator(&reflected, reinterpret_cast<moho::CStorageManipulator*>(runtime));
    outRef->mObj = reflected.mObj;
    outRef->mType = reflected.mType;
    return outRef;
  }

  /**
   * Address: 0x00649AD0 (FUN_00649AD0, Moho::CStorageManipulatorTypeInfo::Destruct)
   *
   * What it does:
   * Runs scalar-deleting destructor slot `0` with delete flag `0`.
   */
  [[maybe_unused]] void DestructCStorageManipulatorStorageRuntime(void* const objectStorage)
  {
    auto* const vtable = *reinterpret_cast<ScalarDeletingDtorFn**>(objectStorage);
    (void)vtable[0](objectStorage, 0);
  }

  /**
   * Address: 0x006498E0 (FUN_006498E0)
   *
   * What it does:
   * Installs `CStorageManipulator` type lifecycle callback lanes (new/ctor/
   * delete/destruct) on one reflected type descriptor.
   */
  [[maybe_unused]] gpg::RType* InstallCStorageManipulatorTypeLifecycleCallbacksRuntime(
    gpg::RType* const reflectedType
  )
  {
    auto* const slots = reinterpret_cast<CStorageManipulatorTypeLifecycleSlotsRuntimeView*>(reflectedType);
    slots->mNewRefFunc = reinterpret_cast<void*>(&BuildNewCStorageManipulatorRef);
    slots->mCtorRefFunc = reinterpret_cast<void*>(&ConstructCStorageManipulatorRefInPlaceRuntime);
    slots->mDeleteFunc = reinterpret_cast<void*>(&DeleteCStorageManipulatorStorageRuntime);
    slots->mDestructFunc = reinterpret_cast<void*>(&DestructCStorageManipulatorStorageRuntime);
    return reflectedType;
  }

  [[nodiscard]] gpg::RRef NewCStorageManipulatorRefForTypeInfo()
  {
    gpg::RRef out{};
    (void)BuildNewCStorageManipulatorRef(&out);
    return out;
  }

  [[nodiscard]] gpg::RRef ConstructCStorageManipulatorRefForTypeInfo(void* const objectStorage)
  {
    gpg::RRef out{};
    (void)ConstructCStorageManipulatorRefInPlaceRuntime(&out, objectStorage);
    return out;
  }

  /**
   * Address: 0x00649AE0 (FUN_00649AE0, Moho::CStorageManipulatorTypeInfo::AddBase_IAniManipulator)
   *
   * What it does:
   * Adds `IAniManipulator` as a zero-offset base record on one
   * `CStorageManipulator` type descriptor.
   */
  [[maybe_unused]] void AddBaseIAniManipulatorToCStorageManipulatorTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedIAniManipulatorTypeForStorageManipulatorTypeInfo();
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
   * Address: 0x00648E10 (FUN_00648E10, Moho::CStorageManipulatorTypeInfo::Init)
   *
   * What it does:
   * Initializes one storage-manipulator type descriptor size/lifecycle callback
   * lanes, registers `IAniManipulator` base ownership, initializes base RTTI,
   * and finalizes field/base metadata.
   */
  [[maybe_unused]] void InitCStorageManipulatorTypeInfo(gpg::RType* const typeInfo)
  {
    typeInfo->size_ = sizeof(CStorageManipulatorRuntimeView);
    (void)gpg::BindRTypeLifecycleCallbacks(
      typeInfo,
      &NewCStorageManipulatorRefForTypeInfo,
      &ConstructCStorageManipulatorRefForTypeInfo,
      &DeleteCStorageManipulatorStorageRuntime,
      &DestructCStorageManipulatorStorageRuntime
    );
    AddBaseIAniManipulatorToCStorageManipulatorTypeInfo(typeInfo);
    typeInfo->gpg::RType::Init();
    typeInfo->Finish();
  }

  /**
   * Address: 0x00649EF0 (FUN_00649EF0, Moho::CStorageManipulator::MemberSerialize)
   *
   * IDA signature:
   * void __usercall sub_649EF0(
   *     Moho::CStorageManipulator *a1@<eax>, BinaryWriteArchive *a2@<edi>);
   *
   * What it does:
   * Serializes a `CStorageManipulator` runtime lane into a binary write archive:
   *   1) writes the base `IAniManipulator` subobject payload;
   *   2) writes the owning `Moho::Unit` as an unowned raw-pointer RRef;
   *   3) writes `mMax`, `mMin`, `mCur` as `Wm3::Vector3f` values;
   *   4) writes `mResourceType` as an `EEconResource` enum value.
   *
   * All reflected type lookups go through cached `sType` singletons (lazy
   * `LookupRType` via RTTI descriptor) matching the binary's idiom.
   */
  [[maybe_unused]] void SerializeCStorageManipulatorRuntime(
    CStorageManipulatorRuntimeView* const runtime,
    gpg::WriteArchive* const archive
  )
  {
    if (runtime == nullptr || archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const aniManipulatorType = CachedIAniManipulatorTypeForStorageManipulatorTypeInfo();
    archive->Write(aniManipulatorType, runtime, ownerRef);

    gpg::RRef unitRef{};
    (void)gpg::RRef_Unit(&unitRef, runtime->mUnit);
    gpg::WriteRawPointer(archive, unitRef, gpg::TrackedPointerState::Unowned, ownerRef);

    gpg::RType* const vector3Type = gpg::LookupRType(typeid(Wm3::Vector3f));

    const Wm3::Vector3f maxValue = ToStorageVector(runtime->mMax);
    archive->Write(vector3Type, &maxValue, ownerRef);

    const Wm3::Vector3f minValue = ToStorageVector(runtime->mMin);
    archive->Write(vector3Type, &minValue, ownerRef);

    const Wm3::Vector3f curValue = ToStorageVector(runtime->mCur);
    archive->Write(vector3Type, &curValue, ownerRef);

    gpg::RType* const resourceType = gpg::LookupRType(typeid(moho::EEconResource));
    archive->Write(resourceType, &runtime->mResourceType, ownerRef);
  }

  /**
   * Address: 0x00649B60 (FUN_00649B60, func_CreateLuaCStorageManipulator)
   *
   * What it does:
   * Writes the `CStorageManipulator` metatable Lua object into `object` and
   * returns the same destination pointer.
   */
  [[maybe_unused]] LuaPlus::LuaObject*
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
   */
  [[maybe_unused]] CScrLuaMetatableFactory<CStorageManipulator>*
  startup_CScrLuaMetatableFactory_CStorageManipulator_Index()
  {
    auto& instance = CScrLuaMetatableFactory<CStorageManipulator>::Instance();
    instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }
} // namespace moho
