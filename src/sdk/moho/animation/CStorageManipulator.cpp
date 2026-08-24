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
  CStorageManipulatorRuntimeView* InitializeCStorageManipulatorDefaultRuntime(
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
  /**
   * Minimal RTTI-identity completion for `moho::CStorageManipulator`
   * (forward-declared in `Reflection.h`, used everywhere else in this file
   * only as an incomplete pointer type for `reinterpret_cast`/`typeid`
   * purposes). Real member layout (`mUnit`/`mMax`/`mMin`/`mCur`/
   * `mResourceType` past the `IAniManipulator` base at `+0x80`) is already
   * fully known and modeled by `CStorageManipulatorRuntimeView` above --
   * this stub exists only so `typeid(CStorageManipulator)` is legal for
   * `CStorageManipulatorTypeInfo`'s RTTI preregistration below, and produces
   * the same mangled `??_R0?AVCStorageManipulator@Moho@@@8` RTTI descriptor
   * identity as the binary regardless of which fields are modeled on it.
   * Promoting this to the full field-typed class (folding
   * `CStorageManipulatorRuntimeView` into it) is a follow-up, not required
   * for the reflection wiring recovered here.
   */
  class CStorageManipulator : public IAniManipulator
  {
  };

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
  CStorageManipulatorRuntimeView* ConstructCStorageManipulatorRuntime(
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
    // a Lua type error, which longjmps); the runtime-view type + constructor
    // helper are file-private to this TU.
    auto* const runtime =
      static_cast<CStorageManipulatorRuntimeView*>(::operator new(sizeof(CStorageManipulatorRuntimeView)));

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
    (void)ConstructCStorageManipulatorRuntime(runtime, unit, boneIndex, &minOffset, &maxOffset, resourceType);

    static_cast<CScriptObject*>(reinterpret_cast<IAniManipulator*>(runtime))->mLuaObj.PushStack(state);
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
  int cfunc_CreateStorageManip(lua_State* const luaContext)
  {
    return cfunc_CreateStorageManipL(moho::SCR_ResolveBindingState(luaContext));
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
  gpg::RRef* BuildNewCStorageManipulatorRef(gpg::RRef* const outRef)
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
  void DeleteCStorageManipulatorStorageRuntime(void* const objectStorage)
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
  void DestructCStorageManipulatorStorageRuntime(void* const objectStorage)
  {
    auto* const vtable = *reinterpret_cast<ScalarDeletingDtorFn**>(objectStorage);
    (void)vtable[0](objectStorage, 0);
  }

  // NOTE: 0x006498E0 (field-write shape identical to the other ~39 manipulator
  // TypeInfo Init bodies) is recovered as the shared `gpg::BindRTypeLifecycleCallbacks`
  // helper (Reflection.h/.cpp) -- not as a per-type duplicate here. This file's
  // prior `InstallCStorageManipulatorTypeLifecycleCallbacksRuntime` was an
  // unwired [[maybe_unused]] duplicate of that same mechanic; removed in favor
  // of `InitCStorageManipulatorTypeInfo`'s existing `BindRTypeLifecycleCallbacks`
  // call below, which is the single canonical, actually-called citation.

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
  void AddBaseIAniManipulatorToCStorageManipulatorTypeInfo(gpg::RType* const typeInfo)
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
  void InitCStorageManipulatorTypeInfo(gpg::RType* const typeInfo)
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
} // namespace moho

namespace moho
{
  /**
   * Owns reflected metadata for `CStorageManipulator`.
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
     * Forwards to the already-recovered `InitCStorageManipulatorTypeInfo`
     * free helper, which sets `size_`, binds the NewRef/CtrRef/Delete/Destruct
     * lifecycle callbacks, registers `IAniManipulator` as the reflected base,
     * and finalizes the type descriptor.
     */
    void Init() override;
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
   * Address: 0x00648E10 (FUN_00648E10, Moho::CStorageManipulatorTypeInfo::Init)
   */
  void CStorageManipulatorTypeInfo::Init()
  {
    InitCStorageManipulatorTypeInfo(this);
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
   * Serializes a `CStorageManipulator` runtime lane into a binary write archive:
   *   1) writes the base `IAniManipulator` subobject payload;
   *   2) writes the owning `Moho::Unit` as an unowned raw-pointer RRef;
   *   3) writes `mMax`, `mMin`, `mCur` as `Wm3::Vector3f` values;
   *   4) writes `mResourceType` as an `EEconResource` enum value.
   *
   * All reflected type lookups go through cached `sType` singletons (lazy
   * `LookupRType` via RTTI descriptor) matching the binary's idiom.
   */
  void SerializeCStorageManipulatorRuntime(
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
   * Address: 0x00649DB0 (FUN_00649DB0, Moho::CStorageManipulator::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall sub_649DB0(
   *     Moho::Unit **obj@<ecx>, gpg::ReadArchive *a2@<eax>);
   *
   * What it does:
   * Deserializes a `CStorageManipulator` runtime lane from a binary read archive
   * (exact mirror of `SerializeCStorageManipulatorRuntime`, FUN_00649EF0):
   *   1) reads the base `IAniManipulator` subobject payload;
   *   2) reads the owning `Moho::Unit` tracked pointer into `mUnit`;
   *   3) reads `mMax`, `mMin`, `mCur` as `Wm3::Vector3f` values;
   *   4) reads `mResourceType` as an `EEconResource` enum value.
   *
   * All reflected type lookups go through cached `sType` singletons (lazy
   * `LookupRType` via RTTI descriptor) matching the binary's idiom. Each read
   * passes a fresh zeroed owner `RRef`, exactly as the binary rebuilds the
   * temporary before every call.
   */
  void DeserializeCStorageManipulatorRuntime(
    CStorageManipulatorRuntimeView* const runtime,
    gpg::ReadArchive* const archive
  )
  {
    if (runtime == nullptr || archive == nullptr) {
      return;
    }

    gpg::RRef ownerRef{};

    gpg::RType* const aniManipulatorType = CachedIAniManipulatorTypeForStorageManipulatorTypeInfo();
    archive->Read(aniManipulatorType, runtime, ownerRef);

    archive->ReadPointer_Unit(&runtime->mUnit, &ownerRef);

    gpg::RType* const vector3Type = gpg::LookupRType(typeid(Wm3::Vector3f));

    Wm3::Vector3f maxValue{};
    archive->Read(vector3Type, &maxValue, ownerRef);
    runtime->mMax = ToStorageVectorRuntime(maxValue);

    Wm3::Vector3f minValue{};
    archive->Read(vector3Type, &minValue, ownerRef);
    runtime->mMin = ToStorageVectorRuntime(minValue);

    Wm3::Vector3f curValue{};
    archive->Read(vector3Type, &curValue, ownerRef);
    runtime->mCur = ToStorageVectorRuntime(curValue);

    gpg::RType* const resourceType = gpg::LookupRType(typeid(moho::EEconResource));
    archive->Read(resourceType, &runtime->mResourceType, ownerRef);
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

namespace
{
  /**
   * Source-level wiring for the `CStorageManipulator` reflected serializer.
   *
   * The binary stores the address of the load callback (0x00649DB0,
   * `DeserializeCStorageManipulatorRuntime`) and the save callback
   * (0x00649EF0, `SerializeCStorageManipulatorRuntime`) into the global
   * `SerSaveLoadHelper_Moho_CStorageManipulator` helper node's callback
   * lanes, exactly as the archive-serialization helper nodes bind their
   * load/save pairs (see `InitializeSPathNeighborSerializerHelperStorage`).
   * `InstallMohoCStorageManipulatorSerializerCallbacks` (0x00649930) later
   * copies these lanes into the reflected `Moho::CStorageManipulator` type's
   * `serLoadFunc_` / `serSaveFunc_` slots. Taking the address of each callback
   * here is the source-level invocation (evidence class 2, function-pointer
   * table) that keeps both callbacks linked into the engine binary.
   */
  CStorageManipulatorSerializerHelperNode* InstallCStorageManipulatorSerializerCallbackStorage() noexcept
  {
    (void)UnlinkSerializerNode(gCStorageManipulatorSerializer);
    gCStorageManipulatorSerializer.mSerLoadFunc =
      reinterpret_cast<gpg::RType::load_func_t>(&moho::DeserializeCStorageManipulatorRuntime);
    gCStorageManipulatorSerializer.mSerSaveFunc =
      reinterpret_cast<gpg::RType::save_func_t>(&moho::SerializeCStorageManipulatorRuntime);
    return &gCStorageManipulatorSerializer;
  }

  struct CStorageManipulatorSerializerBootstrap
  {
    CStorageManipulatorSerializerBootstrap()
    {
      (void)InstallCStorageManipulatorSerializerCallbackStorage();
      moho::register_CStorageManipulatorTypeInfo();
    }
  };

  [[maybe_unused]] CStorageManipulatorSerializerBootstrap gCStorageManipulatorSerializerBootstrap;
} // namespace

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CStorageManipulatorTypeInfo_7d3a2f, moho::register_CStorageManipulatorTypeInfo)
