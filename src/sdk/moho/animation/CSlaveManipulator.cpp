#include "moho/animation/CSlaveManipulator.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <typeinfo>

#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kSlaveLuaClassName = "CSlaveManipulator";
  constexpr const char* kSetMaxRateName = "SetMaxRate";
  constexpr const char* kSetMaxRateHelpText = "SlaveManipulator:SetMaxRate(self, degrees_per_second)";
  constexpr const char* kCreateSlaverMethodName = "CreateSlaver";
  constexpr const char* kCreateSlaverClassName = "<global>";
  constexpr const char* kCreateSlaverHelpText =
    "manip = CreateSlaver(unit, dest_bone, src_bone)\n"
    "Create a manipulator which copies the motion of src_bone onto dst_bone. Priority matters! Only manipulators "
    "which come before the slave manipulator will be copied.";
  constexpr float kDegreesPerSecondToRadians = 0.0017453292f;

  [[nodiscard]] gpg::RType* CachedCSlaveManipulatorType()
  {
    gpg::RType* type = moho::CSlaveManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CSlaveManipulator));
      moho::CSlaveManipulator::sType = type;
    }
    return type;
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

  alignas(moho::CSlaveManipulatorTypeInfo)
  unsigned char gCSlaveManipulatorTypeInfoStorage[sizeof(moho::CSlaveManipulatorTypeInfo)] = {};
  bool gCSlaveManipulatorTypeInfoConstructed = false;

  [[nodiscard]] moho::CSlaveManipulatorTypeInfo* AcquireCSlaveManipulatorTypeInfo()
  {
    if (!gCSlaveManipulatorTypeInfoConstructed) {
      new (gCSlaveManipulatorTypeInfoStorage) moho::CSlaveManipulatorTypeInfo();
      gCSlaveManipulatorTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CSlaveManipulatorTypeInfo*>(gCSlaveManipulatorTypeInfoStorage);
  }

  [[nodiscard]] moho::CSlaveManipulatorTypeInfo* PeekCSlaveManipulatorTypeInfo() noexcept
  {
    if (!gCSlaveManipulatorTypeInfoConstructed) {
      return nullptr;
    }
    return reinterpret_cast<moho::CSlaveManipulatorTypeInfo*>(gCSlaveManipulatorTypeInfoStorage);
  }

  /**
   * Address: 0x00645D60 (FUN_00645D60)
   *
   * What it does:
   * Constructs and preregisters startup reflection metadata for
   * `CSlaveManipulator`.
   */
  [[nodiscard]] gpg::RType* preregister_CSlaveManipulatorTypeInfo()
  {
    moho::CSlaveManipulatorTypeInfo* const typeInfo = AcquireCSlaveManipulatorTypeInfo();
    gpg::PreRegisterRType(typeid(moho::CSlaveManipulator), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BFB1B0 (FUN_00BFB1B0)
   *
   * What it does:
   * Tears down startup-owned `CSlaveManipulator` type-info storage.
   */
  void cleanup_CSlaveManipulatorTypeInfo()
  {
    moho::CSlaveManipulatorTypeInfo* const typeInfo = PeekCSlaveManipulatorTypeInfo();
    if (!typeInfo) {
      return;
    }

    typeInfo->~CSlaveManipulatorTypeInfo();
    gCSlaveManipulatorTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD31D0 (FUN_00BD31D0)
   *
   * What it does:
   * Registers startup `CSlaveManipulator` type-info preregistration and
   * process-exit teardown.
   */
  int register_CSlaveManipulatorTypeInfoStartup()
  {
    (void)preregister_CSlaveManipulatorTypeInfo();
    return std::atexit(&cleanup_CSlaveManipulatorTypeInfo);
  }

  struct CSlaveManipulatorTypeInfoStartupBootstrap
  {
    CSlaveManipulatorTypeInfoStartupBootstrap()
    {
      (void)register_CSlaveManipulatorTypeInfoStartup();
    }
  };

  CSlaveManipulatorTypeInfoStartupBootstrap gCSlaveManipulatorTypeInfoStartupBootstrap;

  /**
   * Address: 0x006468E0 (FUN_006468E0, func_CreateCSlaveManipulatorObject)
   *
   * What it does:
   * Returns the cached metatable object used for `CSlaveManipulator` Lua
   * userdata.
   */
  [[nodiscard]] LuaPlus::LuaObject func_CreateCSlaveManipulatorObject(LuaPlus::LuaState* const state)
  {
    return moho::CScrLuaMetatableFactory<moho::CSlaveManipulator>::Instance().Get(state);
  }
} // namespace

namespace moho
{
  gpg::RType* CSlaveManipulator::sType = nullptr;
  CScrLuaMetatableFactory<CSlaveManipulator> CScrLuaMetatableFactory<CSlaveManipulator>::sInstance{};
} // namespace moho

/**
 * Address: 0x10015880 (constructor shape)
 *
 * What it does:
 * Stores one metatable-factory index used by `CScrLuaObjectFactory::Get`.
 */
moho::CScrLuaMetatableFactory<moho::CSlaveManipulator>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

moho::CScrLuaMetatableFactory<moho::CSlaveManipulator>&
moho::CScrLuaMetatableFactory<moho::CSlaveManipulator>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00646610 (FUN_00646610, ?Create@?$CScrLuaMetatableFactory@VCSlaveManipulator@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
 *
 * What it does:
 * Creates the default metatable used by `CSlaveManipulator` Lua userdata.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CSlaveManipulator>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x00645F80 (FUN_00645F80, ??0CSlaveManipulator@Moho@@QAE@XZ)
 *
 * What it does:
 * Builds detached/default slave-manipulator state used by reflection allocator
 * lanes.
 */
moho::CSlaveManipulator::CSlaveManipulator()
  : IAniManipulator()
{
  mSourceBoneIndex = 0;
  mCurrentRotation = Wm3::Quaternionf::Identity();
  mMaxRate = 0.0f;
}

/**
 * Address: 0x00646010 (FUN_00646010, ??0CSlaveManipulator@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes the base manipulator state, creates the Lua script object, and
 * registers the watched bone.
 */
moho::CSlaveManipulator::CSlaveManipulator(
  moho::Sim* const sim,
  moho::CAniActor* const ownerActor,
  const int watchedBoneIndex,
  const int sourceBoneIndex
)
  : IAniManipulator(sim, ownerActor, 0)
{
  mSourceBoneIndex = sourceBoneIndex;
  mCurrentRotation = Wm3::Quaternionf::Identity();
  mMaxRate = -1.0f;

  LuaPlus::LuaObject arg3{};
  LuaPlus::LuaObject arg2{};
  LuaPlus::LuaObject arg1{};
  LuaPlus::LuaObject scriptFactory = func_CreateCSlaveManipulatorObject(sim->mLuaState);
  CreateLuaObject(scriptFactory, arg1, arg2, arg3);

  AddWatchBone(watchedBoneIndex);
}

/**
 * Address: 0x00646140 (FUN_00646140, Moho::CSlaveManipulator::MoveManipulator)
 *
 * What it does:
 * Updates the destination bone orientation from the configured source bone and
 * marks task-event completion when no smoothing step remains.
 */
bool moho::CSlaveManipulator::ManipulatorUpdate()
{
  const SAniManipBinding* const watchedBinding = mWatchBones.mBegin;
  if (watchedBinding == nullptr || (watchedBinding->mFlags & 0x8000) == 0) {
    return false;
  }

  CAniPoseBone* const sourceBone = ResolvePoseBone(mOwnerActor, mSourceBoneIndex);
  CAniPoseBone* const destinationBone = ResolvePoseBone(mOwnerActor, watchedBinding->mBoneIndex);
  if (sourceBone == nullptr || destinationBone == nullptr) {
    return false;
  }

  const Wm3::Quaternionf targetRotation = sourceBone->mLocalTransform.orient_;
  bool reachedTarget = true;
  if (mMaxRate >= 0.0f) {
    const float absDot = std::fabs(Wm3::Quaternionf::Dot(mCurrentRotation, targetRotation));
    const float clampedDot = absDot > 1.0f ? 1.0f : absDot;
    const float angularDistance = 2.0f * std::acos(clampedDot);
    if (angularDistance > mMaxRate && angularDistance > 1e-6f) {
      const float stepFraction = mMaxRate / angularDistance;
      mCurrentRotation = Wm3::Quaternionf::Slerp(mCurrentRotation, targetRotation, stepFraction);
      reachedTarget = false;
    } else {
      mCurrentRotation = targetRotation;
    }
  } else {
    mCurrentRotation = targetRotation;
  }

  destinationBone->mLocalTransform.orient_ = mCurrentRotation;
  destinationBone->mCompositeDirty = 1;
  EventSetSignaled(reachedTarget);
  return true;
}

/**
 * Address: 0x006462B0 (FUN_006462B0, cfunc_CreateSlaver)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CreateSlaverL`.
 */
int moho::cfunc_CreateSlaver(lua_State* const luaContext)
{
  return cfunc_CreateSlaverL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00646330 (FUN_00646330, cfunc_CreateSlaverL)
 *
 * What it does:
 * Reads `(unit, dest_bone, src_bone)`, constructs one slave manipulator, and
 * returns it to Lua.
 */
int moho::cfunc_CreateSlaverL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateSlaverHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  moho::Unit* const unit = SCR_FromLua_Unit(unitObject);

  LuaPlus::LuaStackObject destBoneArg(state, 2);
  const int destBoneIndex = unit->AniActor->ResolveBoneIndex(destBoneArg);
  if (destBoneIndex < 0) {
    LuaPlus::LuaState::Error(destBoneArg.m_state, "A valid bone is required");
  }

  LuaPlus::LuaStackObject sourceBoneArg(state, 3);
  const int sourceBoneIndex = unit->AniActor->ResolveBoneIndex(sourceBoneArg);
  if (sourceBoneIndex < 0) {
    LuaPlus::LuaState::Error(sourceBoneArg.m_state, "A valid bone is required");
  }

  moho::CSlaveManipulator* const manipulator =
    new moho::CSlaveManipulator(unit->SimulationRef, unit->AniActor, destBoneIndex, sourceBoneIndex);
  manipulator->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006462D0 (FUN_006462D0, func_CreateSlaver_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `CreateSlaver(unit, dest_bone, src_bone)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CreateSlaver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCreateSlaverMethodName,
    &moho::cfunc_CreateSlaver,
    nullptr,
    kCreateSlaverClassName,
    kCreateSlaverHelpText
  );
  return &binder;
}

/**
 * Address: 0x00646490 (FUN_00646490, cfunc_CSlaveManipulatorSetMaxRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CSlaveManipulatorSetMaxRateL`.
 */
int moho::cfunc_CSlaveManipulatorSetMaxRate(lua_State* const luaContext)
{
  return cfunc_CSlaveManipulatorSetMaxRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006464B0 (FUN_006464B0, func_CSlaveManipulatorSetMaxRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CSlaveManipulator:SetMaxRate(self, degrees_per_second)` Lua
 * binder.
 */
moho::CScrLuaInitForm* moho::func_CSlaveManipulatorSetMaxRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kSetMaxRateName,
    &moho::cfunc_CSlaveManipulatorSetMaxRate,
    &CScrLuaMetatableFactory<CSlaveManipulator>::Instance(),
    kSlaveLuaClassName,
    kSetMaxRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00646510 (FUN_00646510, cfunc_CSlaveManipulatorSetMaxRateL)
 *
 * What it does:
 * Resolves one `CSlaveManipulator`, converts degrees/second to radians, and
 * updates the manipulator max-rate lane.
 */
int moho::cfunc_CSlaveManipulatorSetMaxRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetMaxRateHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
  CSlaveManipulator* const manipulator = SCR_FromLua_CSlaveManipulator(manipulatorObject, state);

  const LuaPlus::LuaStackObject maxRateArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    maxRateArg.TypeError("number");
  }

  manipulator->mMaxRate = static_cast<float>(lua_tonumber(rawState, 2)) * kDegreesPerSecondToRadians;

  lua_settop(rawState, 1);
  return 1;
}

/**
 * Address: 0x00646740 (FUN_00646740, Moho::CSlaveManipulatorTypeInfo::NewRef)
 *
 * What it does:
 * Allocates one `CSlaveManipulator`, runs detached default construction, and
 * returns the typed reflection reference.
 */
gpg::RRef moho::CSlaveManipulatorTypeInfo::NewRef()
{
  auto* const storage = static_cast<CSlaveManipulator*>(::operator new(sizeof(CSlaveManipulator), std::nothrow));
  CSlaveManipulator* object = nullptr;
  if (storage) {
    object = new (storage) CSlaveManipulator();
  }

  gpg::RRef out{};
  gpg::RRef_CSlaveManipulator(&out, object);
  return out;
}

/**
 * Address: 0x006467E0 (FUN_006467E0, Moho::CSlaveManipulatorTypeInfo::CtrRef)
 *
 * What it does:
 * Constructs one detached `CSlaveManipulator` in caller-owned storage and
 * returns its typed reflection reference.
 */
gpg::RRef moho::CSlaveManipulatorTypeInfo::CtrRef(void* const objectStorage)
{
  CSlaveManipulator* object = nullptr;
  if (objectStorage) {
    object = new (objectStorage) CSlaveManipulator();
  }

  gpg::RRef out{};
  gpg::RRef_CSlaveManipulator(&out, object);
  return out;
}

/**
 * Address: 0x006467C0 (FUN_006467C0, Moho::CSlaveManipulatorTypeInfo::Delete)
 *
 * What it does:
 * Deletes one heap-owned `CSlaveManipulator`.
 */
void moho::CSlaveManipulatorTypeInfo::Delete(void* const objectStorage)
{
  delete static_cast<CSlaveManipulator*>(objectStorage);
}

/**
 * Address: 0x00646850 (FUN_00646850, Moho::CSlaveManipulatorTypeInfo::Destruct)
 *
 * What it does:
 * Runs non-deleting in-place destructor logic for `CSlaveManipulator`.
 */
void moho::CSlaveManipulatorTypeInfo::Destruct(void* const objectStorage)
{
  if (!objectStorage) {
    return;
  }

  static_cast<CSlaveManipulator*>(objectStorage)->~CSlaveManipulator();
}

/**
 * Address: 0x00646860 (FUN_00646860, Moho::CSlaveManipulatorTypeInfo::AddBase_IAniManipulator)
 *
 * What it does:
 * Registers `IAniManipulator` as reflected base at offset `0`.
 */
void moho::CSlaveManipulatorTypeInfo::AddBase_IAniManipulator(gpg::RType* const typeInfo)
{
  if (!typeInfo) {
    return;
  }

  gpg::RType* baseType = IAniManipulator::sType;
  if (!baseType) {
    baseType = gpg::LookupRType(typeid(IAniManipulator));
    IAniManipulator::sType = baseType;
  }
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
 * Address: 0x00646720 (FUN_00646720)
 *
 * What it does:
 * Installs allocation and placement-construction callback lanes.
 */
moho::CSlaveManipulatorTypeInfo*
moho::CSlaveManipulatorTypeInfo::ConfigureCtorCallbacks(CSlaveManipulatorTypeInfo* const typeInfo)
{
  typeInfo->newRefFunc_ = &CSlaveManipulatorTypeInfo::NewRef;
  typeInfo->ctorRefFunc_ = &CSlaveManipulatorTypeInfo::CtrRef;
  return typeInfo;
}

/**
 * Address: 0x00646730 (FUN_00646730)
 *
 * What it does:
 * Installs deletion and in-place destruction callback lanes.
 */
moho::CSlaveManipulatorTypeInfo*
moho::CSlaveManipulatorTypeInfo::ConfigureDtorCallbacks(CSlaveManipulatorTypeInfo* const typeInfo)
{
  typeInfo->deleteFunc_ = &CSlaveManipulatorTypeInfo::Delete;
  typeInfo->dtrFunc_ = &CSlaveManipulatorTypeInfo::Destruct;
  return typeInfo;
}

/**
 * Address: 0x00646660 (FUN_00646660)
 *
 * What it does:
 * Installs all reflection lifecycle callbacks on one type-info instance.
 */
moho::CSlaveManipulatorTypeInfo*
moho::CSlaveManipulatorTypeInfo::ConfigureLifecycleCallbacks(CSlaveManipulatorTypeInfo* const typeInfo)
{
  ConfigureCtorCallbacks(typeInfo);
  ConfigureDtorCallbacks(typeInfo);
  return typeInfo;
}

/**
 * Address: 0x00645DC0 (FUN_00645DC0, Moho::CSlaveManipulatorTypeInfo::Init)
 *
 * What it does:
 * Sets reflected size/callback lanes for `CSlaveManipulator`, registers
 * `IAniManipulator` base metadata, then finalizes type initialization.
 */
void moho::CSlaveManipulatorTypeInfo::Init()
{
  size_ = sizeof(CSlaveManipulator);
  ConfigureLifecycleCallbacks(this);
  AddBase_IAniManipulator(this);
  gpg::RType::Init();
  Finish();
}

namespace gpg
{
  /**
   * Address: 0x00646A90 (FUN_00646A90, gpg::RRef_CSlaveManipulator)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CSlaveManipulator*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CSlaveManipulator(gpg::RRef* const outRef, moho::CSlaveManipulator* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCSlaveManipulatorType());
    return outRef;
  }
} // namespace gpg
