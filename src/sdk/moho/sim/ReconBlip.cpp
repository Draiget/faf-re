#include "moho/sim/ReconBlip.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "lua/LuaObject.h"
#include "moho/animation/CAniPose.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/Stats.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/render/camera/VTransform.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace moho
{
  int cfunc_ReconBlipGetBlueprint(lua_State* luaState);
  int cfunc_ReconBlipGetBlueprintL(LuaPlus::LuaState* state);
  int cfunc_ReconBlipGetSource(lua_State* luaState);
  int cfunc_ReconBlipGetSourceL(LuaPlus::LuaState* state);
  int cfunc_ReconBlipIsSeenEver(lua_State* luaState);
  int cfunc_ReconBlipIsSeenEverL(LuaPlus::LuaState* state);
  int cfunc_ReconBlipIsSeenNow(lua_State* luaState);
  int cfunc_ReconBlipIsSeenNowL(LuaPlus::LuaState* state);
  int cfunc_ReconBlipIsMaybeDead(lua_State* luaState);
  int cfunc_ReconBlipIsMaybeDeadL(LuaPlus::LuaState* state);
  int cfunc_ReconBlipIsOnOmni(lua_State* luaState);
  int cfunc_ReconBlipIsOnOmniL(LuaPlus::LuaState* state);
  int cfunc_ReconBlipIsOnSonar(lua_State* luaState);
  int cfunc_ReconBlipIsOnSonarL(LuaPlus::LuaState* state);
  int cfunc_ReconBlipIsOnRadar(lua_State* luaState);
  int cfunc_ReconBlipIsOnRadarL(LuaPlus::LuaState* state);
  int cfunc_ReconBlipIsKnownFake(lua_State* luaState);
  int cfunc_ReconBlipIsKnownFakeL(LuaPlus::LuaState* state);
  CScrLuaInitForm* func_ReconBlipGetBlueprint_LuaFuncDef();
  CScrLuaInitForm* func_ReconBlipGetSource_LuaFuncDef();
  CScrLuaInitForm* func_ReconBlipIsSeenEver_LuaFuncDef();
  CScrLuaInitForm* func_ReconBlipIsSeenNow_LuaFuncDef();
  CScrLuaInitForm* func_ReconBlipIsMaybeDead_LuaFuncDef();
  CScrLuaInitForm* func_ReconBlipIsOnOmni_LuaFuncDef();
  CScrLuaInitForm* func_ReconBlipIsOnSonar_LuaFuncDef();
  CScrLuaInitForm* func_ReconBlipIsOnRadar_LuaFuncDef();
  CScrLuaInitForm* func_ReconBlipIsKnownFake_LuaFuncDef();
} // namespace moho

namespace
{
  constexpr const char* kReconBlipLuaClassName = "ReconBlip";
  constexpr const char* kReconBlipGetBlueprintName = "GetBlueprint";
  constexpr const char* kReconBlipGetBlueprintHelpText = "blueprint = ReconBlip:GetBlueprint()";
  constexpr const char* kReconBlipGetSourceName = "GetSource";
  constexpr const char* kReconBlipGetSourceHelpText = "unit = ReconBlip:GetSource()";
  constexpr const char* kReconBlipIsSeenEverName = "IsSeenEver";
  constexpr const char* kReconBlipIsSeenEverHelpText = "bool = ReconBlip:IsSeenEver()";
  constexpr const char* kReconBlipIsSeenNowName = "IsSeenNow";
  constexpr const char* kReconBlipIsSeenNowHelpText = "bool = ReconBlip:IsSeenNow()";
  constexpr const char* kReconBlipIsMaybeDeadName = "IsMaybeDead";
  constexpr const char* kReconBlipIsMaybeDeadHelpText = "bool = ReconBlip:IsMaybeDead()";
  constexpr const char* kReconBlipIsOnOmniName = "IsOnOmni";
  constexpr const char* kReconBlipIsOnOmniHelpText = "bool = ReconBlip:IsOnOmni()";
  constexpr const char* kReconBlipIsOnSonarName = "IsOnSonar";
  constexpr const char* kReconBlipIsOnSonarHelpText = "bool = ReconBlip:IsOnSonar()";
  constexpr const char* kReconBlipIsOnRadarName = "IsOnRadar";
  constexpr const char* kReconBlipIsOnRadarHelpText = "bool = ReconBlip:IsOnRadar()";
  constexpr const char* kReconBlipIsKnownFakeName = "IsKnownFake";
  constexpr const char* kReconBlipIsKnownFakeHelpText = "bool = ReconBlip:IsKnownFake()";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";

  constexpr std::uint32_t kUnitCollisionBucketFlags = 0x100u;
  constexpr std::uint32_t kReconEntityFamilyPrefix = 0x300u;
  gpg::RType* gSimType = nullptr;
  gpg::RType* gRMeshBlueprintType = nullptr;
  gpg::RType* gRScmResourceType = nullptr;
  gpg::RType* gCAniPoseType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* ResolveRMeshBlueprintType()
  {
    return CachedType<RMeshBlueprint>(gRMeshBlueprintType);
  }

  [[nodiscard]] gpg::RType* ResolveSimType()
  {
    return CachedType<Sim>(gSimType);
  }

  [[nodiscard]] gpg::RType* ResolveRScmResourceType()
  {
    return CachedType<RScmResource>(gRScmResourceType);
  }

  [[nodiscard]] gpg::RType* ResolveCAniPoseType()
  {
    return CachedType<CAniPose>(gCAniPoseType);
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  int PushReconFlagFromLuaState(
    LuaPlus::LuaState* const state, const char* const helpText, const std::uint32_t flagMask
  )
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, helpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject blipObject(LuaPlus::LuaStackObject(state, 1));
    ReconBlip* const blip = SCR_FromLua_ReconBlip(blipObject, state);

    const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
    CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
    const std::int32_t armyIndex = army->ArmyId;
    const std::uint32_t reconFlags = blip->mReconDat[armyIndex].mReconFlags;
    lua_pushboolean(rawState, (reconFlags & flagMask) != 0u ? 1 : 0);
    (void)lua_gettop(rawState);
    return 1;
  }

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  struct ReflectedObjectDeleter
  {
    gpg::RType::delete_func_t deleteFunc = nullptr;

    void operator()(void* const object) const noexcept
    {
      if (deleteFunc) {
        deleteFunc(object);
      }
    }
  };

  [[nodiscard]] bool IsPointerCompatibleWithExpectedType(
    const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType
  )
  {
    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    return gpg::REF_UpcastPtr(source, expectedType).mObj != nullptr;
  }

  void EnsureTrackedPointerSharedOwnership(gpg::TrackedPointerInfo& tracked)
  {
    if (tracked.state == gpg::TrackedPointerState::Unowned) {
      if (!tracked.type || !tracked.type->deleteFunc_) {
        throw gpg::SerializationError("Ownership conflict while loading archive");
      }

      auto* const control = new boost::detail::sp_counted_impl_pd<void*, ReflectedObjectDeleter>(
        tracked.object, ReflectedObjectDeleter{tracked.type->deleteFunc_}
      );
      tracked.sharedObject = tracked.object;
      tracked.sharedControl = control;
      tracked.state = gpg::TrackedPointerState::Shared;
      return;
    }

    if (tracked.state != gpg::TrackedPointerState::Shared || !tracked.sharedObject || !tracked.sharedControl) {
      throw gpg::SerializationError("Can't mix boost::shared_ptr with other shared pointers.");
    }
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadPointerUnowned(
    gpg::ReadArchive* const archive, const gpg::RRef& ownerRef, gpg::RType* const expectedType, const char* const typeName
  )
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
      throw gpg::SerializationError(typeName ? typeName : "Archive pointer type mismatch");
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    return static_cast<TObject*>(gpg::REF_UpcastPtr(source, expectedType).mObj);
  }

  template <typename TObject>
  void ReadPointerShared(
    boost::SharedPtrRaw<TObject>& outPointer,
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef,
    gpg::RType* const expectedType,
    const char* const typeName
  )
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      outPointer.release();
      return;
    }

    EnsureTrackedPointerSharedOwnership(tracked);
    if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
      throw gpg::SerializationError(typeName ? typeName : "Archive shared-pointer type mismatch");
    }

    boost::SharedPtrRaw<TObject> source{};
    source.px = static_cast<TObject*>(tracked.sharedObject);
    source.pi = tracked.sharedControl;
    outPointer.assign_retain(source);
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* const object, gpg::RType* const staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  template <typename TObject>
  void WritePointerWithType(
    gpg::WriteArchive* const archive,
    TObject* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, ownerRef);
  }

  [[nodiscard]] EntId ReserveReconBlipId(Sim* const sim, Unit* const sourceUnit)
  {
    if (!sim || !sim->mEntityDB) {
      return static_cast<EntId>(0);
    }

    const std::uint32_t sourceArmyId = (sourceUnit && sourceUnit->ArmyRef && sourceUnit->ArmyRef->ArmyId >= 0)
      ? static_cast<std::uint32_t>(sourceUnit->ArmyRef->ArmyId)
      : 0u;
    const std::uint32_t requestBits = (sourceArmyId | kReconEntityFamilyPrefix) << 20u;
    return static_cast<EntId>(sim->mEntityDB->DoReserveId(requestBits));
  }

  [[nodiscard]] Wm3::Vec3f ComputeJamOffset(Unit* const sourceUnit, Sim* const sim)
  {
    if (!sourceUnit || !sim || !sim->mRngState) {
      return {};
    }

    const auto* const blueprint = reinterpret_cast<const RUnitBlueprint*>(sourceUnit->BluePrint);
    if (!blueprint) {
      return {};
    }

    auto& rng = *sim->mRngState;
    const std::uint32_t minRadius = blueprint->Intel.JamRadius.min;
    const std::uint32_t maxRadius = blueprint->Intel.JamRadius.max;
    const std::uint32_t range = maxRadius > minRadius ? (maxRadius - minRadius) : 0u;
    const std::uint32_t radiusWord = rng.twister.NextUInt32();
    const std::uint32_t radiusStep = static_cast<std::uint32_t>((static_cast<std::uint64_t>(range) * radiusWord) >> 32u);
    const float radius = static_cast<float>(minRadius + radiusStep);

    Wm3::Vec3f direction{rng.FRandGaussian(), 0.0f, rng.FRandGaussian()};
    Wm3::Vec3f::Normalize(direction);

    const float randomScale = CMersenneTwister::ToUnitFloat(rng.twister.NextUInt32()) * radius;
    return {direction.x * randomScale, direction.y * randomScale, direction.z * randomScale};
  }

  [[nodiscard]] gpg::RRef MakeReconBlipRef(ReconBlip* const object) noexcept
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = object ? ReconBlip::StaticGetClass() : nullptr;
    return ref;
  }
} // namespace

gpg::RType* SPerArmyReconInfo::sType = nullptr;
gpg::RType* ReconBlip::sType = nullptr;
gpg::RType* ReconBlip::sPointerType = nullptr;

/**
 * Address: 0x005C5390 (FUN_005C5390, Moho::InstanceCounter<Moho::ReconBlip>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for ReconBlip
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::ReconBlip>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::ReconBlip).name());
  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

gpg::RType* ReconBlip::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(ReconBlip));
  }
  return sType;
}

/**
 * Address: 0x005C6470 (FUN_005C6470, Moho::ReconBlip::GetPointerType)
 *
 * What it does:
 * Lazily resolves and caches the reflection descriptor for `ReconBlip*`.
 */
gpg::RType* ReconBlip::GetPointerType()
{
  gpg::RType* cached = sPointerType;
  if (!cached) {
    cached = gpg::LookupRType(typeid(ReconBlip*));
    sPointerType = cached;
  }
  return cached;
}

/**
 * Address: 0x005C29D0 (FUN_005C29D0, cfunc_ReconBlipGetBlueprint)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ReconBlipGetBlueprintL`.
 */
int moho::cfunc_ReconBlipGetBlueprint(lua_State* const luaContext)
{
  return cfunc_ReconBlipGetBlueprintL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005C2A50 (FUN_005C2A50, cfunc_ReconBlipGetBlueprintL)
 *
 * What it does:
 * Reads one blip object and pushes its blueprint Lua object.
 */
int moho::cfunc_ReconBlipGetBlueprintL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kReconBlipGetBlueprintHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject blipObject(LuaPlus::LuaStackObject(state, 1));
  ReconBlip* const blip = SCR_FromLua_ReconBlip(blipObject, state);
  LuaPlus::LuaObject luaBlueprint = blip->GetBlueprint()->GetLuaBlueprint(state);
  luaBlueprint.PushStack(state);
  return 1;
}

/**
 * Address: 0x005C2B30 (FUN_005C2B30, cfunc_ReconBlipGetSource)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ReconBlipGetSourceL`.
 */
int moho::cfunc_ReconBlipGetSource(lua_State* const luaContext)
{
  return cfunc_ReconBlipGetSourceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005C2BB0 (jump target from FUN_005C2B30, cfunc_ReconBlipGetSourceL)
 *
 * What it does:
 * Reads one blip object and pushes its source unit, or `nil` when detached.
 */
int moho::cfunc_ReconBlipGetSourceL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kReconBlipGetSourceHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject blipObject(LuaPlus::LuaStackObject(state, 1));
  ReconBlip* const blip = SCR_FromLua_ReconBlip(blipObject, state);
  if (Unit* const sourceUnit = blip->GetCreator(); sourceUnit != nullptr) {
    sourceUnit->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }
  return 1;
}

/**
 * Address: 0x005C2C90 (FUN_005C2C90, cfunc_ReconBlipIsSeenEver)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ReconBlipIsSeenEverL`.
 */
int moho::cfunc_ReconBlipIsSeenEver(lua_State* const luaContext)
{
  return cfunc_ReconBlipIsSeenEverL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005C2D10 (jump target from FUN_005C2C90, cfunc_ReconBlipIsSeenEverL)
 *
 * What it does:
 * Returns `RECON_LOSEver` flag state for `(blip, army)` pair.
 */
int moho::cfunc_ReconBlipIsSeenEverL(LuaPlus::LuaState* const state)
{
  return PushReconFlagFromLuaState(state, kReconBlipIsSeenEverHelpText, static_cast<std::uint32_t>(RECON_LOSEver));
}

/**
 * Address: 0x005C2E00 (cfunc_ReconBlipIsSeenNow)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ReconBlipIsSeenNowL`.
 */
int moho::cfunc_ReconBlipIsSeenNow(lua_State* const luaContext)
{
  return cfunc_ReconBlipIsSeenNowL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005C2E80 (jump target from 0x005C2E00, cfunc_ReconBlipIsSeenNowL)
 *
 * What it does:
 * Returns `RECON_LOSNow` flag state for `(blip, army)` pair.
 */
int moho::cfunc_ReconBlipIsSeenNowL(LuaPlus::LuaState* const state)
{
  return PushReconFlagFromLuaState(state, kReconBlipIsSeenNowHelpText, static_cast<std::uint32_t>(RECON_LOSNow));
}

/**
 * Address: 0x005C2F70 (FUN_005C2F70, cfunc_ReconBlipIsMaybeDead)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ReconBlipIsMaybeDeadL`.
 */
int moho::cfunc_ReconBlipIsMaybeDead(lua_State* const luaContext)
{
  return cfunc_ReconBlipIsMaybeDeadL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005C2FF0 (jump target from FUN_005C2F70, cfunc_ReconBlipIsMaybeDeadL)
 *
 * What it does:
 * Returns `RECON_MaybeDead` flag state for `(blip, army)` pair.
 */
int moho::cfunc_ReconBlipIsMaybeDeadL(LuaPlus::LuaState* const state)
{
  return PushReconFlagFromLuaState(state, kReconBlipIsMaybeDeadHelpText, static_cast<std::uint32_t>(RECON_MaybeDead));
}

/**
 * Address: 0x005C30E0 (FUN_005C30E0, cfunc_ReconBlipIsOnOmni)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ReconBlipIsOnOmniL`.
 */
int moho::cfunc_ReconBlipIsOnOmni(lua_State* const luaContext)
{
  return cfunc_ReconBlipIsOnOmniL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005C3160 (cfunc_ReconBlipIsOnOmniL)
 *
 * What it does:
 * Returns `RECON_Omni` flag state for `(blip, army)` pair.
 */
int moho::cfunc_ReconBlipIsOnOmniL(LuaPlus::LuaState* const state)
{
  return PushReconFlagFromLuaState(state, kReconBlipIsOnOmniHelpText, static_cast<std::uint32_t>(RECON_Omni));
}

/**
 * Address: 0x005C3250 (FUN_005C3250, cfunc_ReconBlipIsOnSonar)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ReconBlipIsOnSonarL`.
 */
int moho::cfunc_ReconBlipIsOnSonar(lua_State* const luaContext)
{
  return cfunc_ReconBlipIsOnSonarL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005C32D0 (cfunc_ReconBlipIsOnSonarL)
 *
 * What it does:
 * Returns `RECON_Sonar` flag state for `(blip, army)` pair.
 */
int moho::cfunc_ReconBlipIsOnSonarL(LuaPlus::LuaState* const state)
{
  return PushReconFlagFromLuaState(state, kReconBlipIsOnSonarHelpText, static_cast<std::uint32_t>(RECON_Sonar));
}

/**
 * Address: 0x005C33C0 (FUN_005C33C0, cfunc_ReconBlipIsOnRadar)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ReconBlipIsOnRadarL`.
 */
int moho::cfunc_ReconBlipIsOnRadar(lua_State* const luaContext)
{
  return cfunc_ReconBlipIsOnRadarL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005C3440 (cfunc_ReconBlipIsOnRadarL)
 *
 * What it does:
 * Returns `RECON_Radar` flag state for `(blip, army)` pair.
 */
int moho::cfunc_ReconBlipIsOnRadarL(LuaPlus::LuaState* const state)
{
  return PushReconFlagFromLuaState(state, kReconBlipIsOnRadarHelpText, static_cast<std::uint32_t>(RECON_Radar));
}

/**
 * Address: 0x005C3530 (FUN_005C3530, cfunc_ReconBlipIsKnownFake)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ReconBlipIsKnownFakeL`.
 */
int moho::cfunc_ReconBlipIsKnownFake(lua_State* const luaContext)
{
  return cfunc_ReconBlipIsKnownFakeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005C35B0 (FUN_005C35B0, cfunc_ReconBlipIsKnownFakeL)
 *
 * What it does:
 * Returns `RECON_KnownFake` flag state for `(blip, army)` pair.
 */
int moho::cfunc_ReconBlipIsKnownFakeL(LuaPlus::LuaState* const state)
{
  return PushReconFlagFromLuaState(state, kReconBlipIsKnownFakeHelpText, static_cast<std::uint32_t>(RECON_KnownFake));
}

/**
 * Address: 0x005C29F0 (FUN_005C29F0, func_ReconBlipGetBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes `ReconBlip:GetBlueprint()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_ReconBlipGetBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kReconBlipGetBlueprintName,
    &moho::cfunc_ReconBlipGetBlueprint,
    &CScrLuaMetatableFactory<ReconBlip>::Instance(),
    kReconBlipLuaClassName,
    kReconBlipGetBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x005C2B50 (FUN_005C2B50, func_ReconBlipGetSource_LuaFuncDef)
 *
 * What it does:
 * Publishes `ReconBlip:GetSource()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_ReconBlipGetSource_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kReconBlipGetSourceName,
    &moho::cfunc_ReconBlipGetSource,
    &CScrLuaMetatableFactory<ReconBlip>::Instance(),
    kReconBlipLuaClassName,
    kReconBlipGetSourceHelpText
  );
  return &binder;
}

/**
 * Address: 0x005C2CB0 (FUN_005C2CB0, func_ReconBlipIsSeenEver_LuaFuncDef)
 *
 * What it does:
 * Publishes `ReconBlip:IsSeenEver()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_ReconBlipIsSeenEver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kReconBlipIsSeenEverName,
    &moho::cfunc_ReconBlipIsSeenEver,
    &CScrLuaMetatableFactory<ReconBlip>::Instance(),
    kReconBlipLuaClassName,
    kReconBlipIsSeenEverHelpText
  );
  return &binder;
}

/**
 * Address: 0x005C2E20 (FUN_005C2E20, func_ReconBlipIsSeenNow_LuaFuncDef)
 *
 * What it does:
 * Publishes `ReconBlip:IsSeenNow()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_ReconBlipIsSeenNow_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kReconBlipIsSeenNowName,
    &moho::cfunc_ReconBlipIsSeenNow,
    &CScrLuaMetatableFactory<ReconBlip>::Instance(),
    kReconBlipLuaClassName,
    kReconBlipIsSeenNowHelpText
  );
  return &binder;
}

/**
 * Address: 0x005C2F90 (FUN_005C2F90, func_ReconBlipIsMaybeDead_LuaFuncDef)
 *
 * What it does:
 * Publishes `ReconBlip:IsMaybeDead()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_ReconBlipIsMaybeDead_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kReconBlipIsMaybeDeadName,
    &moho::cfunc_ReconBlipIsMaybeDead,
    &CScrLuaMetatableFactory<ReconBlip>::Instance(),
    kReconBlipLuaClassName,
    kReconBlipIsMaybeDeadHelpText
  );
  return &binder;
}

/**
 * Address: 0x005C3100 (FUN_005C3100, func_ReconBlipIsOnOmni_LuaFuncDef)
 *
 * What it does:
 * Publishes `ReconBlip:IsOnOmni()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_ReconBlipIsOnOmni_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kReconBlipIsOnOmniName,
    &moho::cfunc_ReconBlipIsOnOmni,
    &CScrLuaMetatableFactory<ReconBlip>::Instance(),
    kReconBlipLuaClassName,
    kReconBlipIsOnOmniHelpText
  );
  return &binder;
}

/**
 * Address: 0x005C3270 (FUN_005C3270, func_ReconBlipIsOnSonar_LuaFuncDef)
 *
 * What it does:
 * Publishes `ReconBlip:IsOnSonar()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_ReconBlipIsOnSonar_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kReconBlipIsOnSonarName,
    &moho::cfunc_ReconBlipIsOnSonar,
    &CScrLuaMetatableFactory<ReconBlip>::Instance(),
    kReconBlipLuaClassName,
    kReconBlipIsOnSonarHelpText
  );
  return &binder;
}

/**
 * Address: 0x005C33E0 (FUN_005C33E0, func_ReconBlipIsOnRadar_LuaFuncDef)
 *
 * What it does:
 * Publishes `ReconBlip:IsOnRadar()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_ReconBlipIsOnRadar_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kReconBlipIsOnRadarName,
    &moho::cfunc_ReconBlipIsOnRadar,
    &CScrLuaMetatableFactory<ReconBlip>::Instance(),
    kReconBlipLuaClassName,
    kReconBlipIsOnRadarHelpText
  );
  return &binder;
}

/**
 * Address: 0x005C3550 (FUN_005C3550, func_ReconBlipIsKnownFake_LuaFuncDef)
 *
 * What it does:
 * Publishes `ReconBlip:IsKnownFake()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_ReconBlipIsKnownFake_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kReconBlipIsKnownFakeName,
    &moho::cfunc_ReconBlipIsKnownFake,
    &CScrLuaMetatableFactory<ReconBlip>::Instance(),
    kReconBlipLuaClassName,
    kReconBlipIsKnownFakeHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BED70 (FUN_005BED70, Moho::ReconBlip::ReconBlip)
 *
 * Sim *
 *
 * IDA signature:
 * Moho::ReconBlip *__stdcall Moho::ReconBlip::ReconBlip(Moho::ReconBlip *this, Moho::Sim *sim);
 *
 * What it does:
 * Constructs serializer-load baseline state for `ReconBlip`.
 */
ReconBlip::ReconBlip(Sim* const sim) :
    Entity(
      nullptr,
      sim,
      static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid)),
      kUnitCollisionBucketFlags
    ),
    mCreator{},
    mDeleteWhenStale(0u),
    mPad279{0, 0, 0},
    mJamOffset{},
    mUnitConstDat{},
    mUnitVarDat{},
    mReconDat{}
{
}

/**
 * Address: 0x005C4F50 (FUN_005C4F50, Moho::SPerArmyReconInfo::~SPerArmyReconInfo)
 *
 * What it does:
 * Releases per-army recon shared ownership lanes in binary destruction order.
 */
SPerArmyReconInfo::~SPerArmyReconInfo()
{
  mPose.release();
  mPriorPose.release();
  mMesh.release();
}

/**
 * Address: 0x005C8DE0 (FUN_005C8DE0, Moho::SPerArmyReconInfo::MemberDeserialize)
 */
void SPerArmyReconInfo::MemberDeserialize(gpg::ReadArchive* const archive, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version.");
  }

  archive->ReadUInt(&mReconFlags);
  archive->ReadBool(reinterpret_cast<bool*>(&mNeedsFlush));
  if (mNeedsFlush == 0u) {
    return;
  }

  const gpg::RRef ownerRef{};
  mStiMesh = ReadPointerUnowned<RMeshBlueprint>(archive, ownerRef, ResolveRMeshBlueprintType(), "RMeshBlueprint");
  ReadPointerShared<RScmResource>(mMesh, archive, ownerRef, ResolveRScmResourceType(), "RScmResource");
  ReadPointerShared<CAniPose>(mPriorPose, archive, ownerRef, ResolveCAniPoseType(), "CAniPose");
  ReadPointerShared<CAniPose>(mPose, archive, ownerRef, ResolveCAniPoseType(), "CAniPose");
  archive->ReadFloat(&mHealth);
  archive->ReadFloat(&mHealth);
  archive->ReadFloat(&mFractionComplete);
  archive->ReadBool(reinterpret_cast<bool*>(&mMaybeDead));
}

/**
 * Address: 0x005C8ED0 (FUN_005C8ED0, Moho::SPerArmyReconInfo::MemberSerialize)
 */
void SPerArmyReconInfo::MemberSerialize(gpg::WriteArchive* const archive, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version.");
  }

  archive->WriteUInt(mReconFlags);
  archive->WriteBool(mNeedsFlush != 0u);
  if (mNeedsFlush == 0u) {
    return;
  }

  const gpg::RRef ownerRef{};
  WritePointerWithType(archive, mStiMesh, ResolveRMeshBlueprintType(), gpg::TrackedPointerState::Unowned, ownerRef);
  WritePointerWithType(archive, mMesh.px, ResolveRScmResourceType(), gpg::TrackedPointerState::Shared, ownerRef);
  WritePointerWithType(archive, mPriorPose.px, ResolveCAniPoseType(), gpg::TrackedPointerState::Shared, ownerRef);
  WritePointerWithType(archive, mPose.px, ResolveCAniPoseType(), gpg::TrackedPointerState::Shared, ownerRef);
  archive->WriteFloat(mHealth);
  archive->WriteFloat(mHealth);
  archive->WriteFloat(mFractionComplete);
  archive->WriteBool(mMaybeDead != 0u);
}

/**
 * Address: 0x005BE6E0 (FUN_005BE6E0)
 *
 * Unit *,Sim *,bool
 *
 * IDA signature:
 * Moho::ReconBlip *__userpurge Moho::ReconBlip::ReconBlip@<eax>(
 *   Moho::Unit *unit@<ebx>, Moho::ReconBlip *this, Moho::Sim *sim, char fake);
 *
 * What it does:
 * Constructs a recon blip from `unit`, allocates a 0x3xx-family entity id,
 * initializes per-army recon state storage, and performs an initial refresh.
 */
ReconBlip::ReconBlip(Unit* const sourceUnit, Sim* const sim, const bool fake) :
    Entity(
      sourceUnit ? reinterpret_cast<REntityBlueprint*>(sourceUnit->BluePrint) : nullptr,
      sim,
      ReserveReconBlipId(sim, sourceUnit),
      kUnitCollisionBucketFlags
    ),
    mCreator{},
    mDeleteWhenStale(static_cast<std::uint8_t>((sourceUnit && sourceUnit->IsMobile()) ? 1u : 0u)),
    mPad279{0, 0, 0},
    mJamOffset{},
    mUnitConstDat{},
    mUnitVarDat{},
    mReconDat{}
{
  mCreator.ResetFromObject(sourceUnit);
  mQueueRelinkBlocked = 1u;

  if (fake) {
    mJamOffset = ComputeJamOffset(sourceUnit, sim);
  } else {
    mJamOffset = {};
    if (sourceUnit) {
      mMeshRef = sourceUnit->mMeshRef;
      mMeshTypeClassId = sourceUnit->mMeshTypeClassId;
    }
  }

  if (sourceUnit) {
    BluePrint = const_cast<REntityBlueprint*>(reinterpret_cast<const REntityBlueprint*>(sourceUnit->GetBlueprint()));
    mCurrentLayer = sourceUnit->mCurrentLayer;
  }
  mUnitConstDat.mFake = static_cast<std::uint8_t>(fake ? 1u : 0u);

  const std::size_t armyCount = (sim && sim->mArmiesList.begin())
    ? static_cast<std::size_t>(sim->mArmiesList.end() - sim->mArmiesList.begin())
    : 0u;
  mReconDat.resize(armyCount, SPerArmyReconInfo{});
  Refresh();
}

/**
 * Address: 0x005BFBE0 (FUN_005BFBE0, Moho::ReconBlip::MemberConstruct)
 *
 * gpg::ReadArchive &,int,gpg::RRef const &,gpg::SerConstructResult &
 *
 * What it does:
 * Reads serializer construct args (`Sim*`), allocates one `ReconBlip`, and
 * returns it as an unowned construct result.
 */
void ReconBlip::MemberConstruct(
  gpg::ReadArchive& archive, const int, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
)
{
  Sim* const sim = ReadPointerUnowned<Sim>(&archive, ownerRef, ResolveSimType(), "Sim");
  ReconBlip* const object = new (std::nothrow) ReconBlip(sim);
  result.SetUnowned(MakeReconBlipRef(object), 0u);
}

/**
 * Address: 0x005BDE70 (FUN_005BDE70, Moho::ReconBlip::GetDerivedObjectRef)
 *
 * What it does:
 * Returns one typed reflection reference for this recon blip instance.
 */
gpg::RRef ReconBlip::GetDerivedObjectRef()
{
  gpg::RRef objectRef{};
  objectRef.mObj = this;
  objectRef.mType = GetClass();
  return objectRef;
}

/**
 * Address: 0x005BDE90 (FUN_005BDE90)
 */
ReconBlip* ReconBlip::IsReconBlip()
{
  return this;
}

/**
 * Address: 0x005BEE80 (FUN_005BEE80)
 */
const RUnitBlueprint* ReconBlip::GetBlueprint() const
{
  return reinterpret_cast<const RUnitBlueprint*>(BluePrint);
}

/**
 * Address: 0x005BF5F0 (FUN_005BF5F0, Moho::ReconBlip::GetTargetPoint)
 *
 * What it does:
 * Resolves one blip target point: source-unit target point plus jam offset
 * when linked, otherwise root-bone position with blueprint collision-y offset.
 */
Wm3::Vec3f ReconBlip::GetTargetPoint(const std::int32_t targetPoint)
{
  if (Unit* const sourceUnit = mCreator.GetObjectPtr(); sourceUnit != nullptr) {
    const Wm3::Vec3f sourceTargetPoint = sourceUnit->GetTargetPoint(targetPoint);
    return {
      sourceTargetPoint.x + mJamOffset.x,
      sourceTargetPoint.y + mJamOffset.y,
      sourceTargetPoint.z + mJamOffset.z,
    };
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const float blueprintLift = blueprint ? (blueprint->mCollisionOffsetY + blueprint->mSizeY * 0.5f) : 0.0f;
  const VTransform rootTransform = GetBoneWorldTransform(-1);
  return {
    rootTransform.pos_.x,
    rootTransform.pos_.y + blueprintLift,
    rootTransform.pos_.z,
  };
}

/**
 * Address: 0x005BF4F0 (FUN_005BF4F0, Moho::ReconBlip::PickTargetPointAboveWater)
 *
 * What it does:
 * Selects one above-water target-point lane by delegating to source unit
 * when linked, otherwise by comparing blip elevation against water level.
 */
bool ReconBlip::PickTargetPointAboveWater(std::int32_t& outTargetPoint) const
{
  if (Unit* const sourceUnit = GetSourceUnit(); sourceUnit != nullptr) {
    return sourceUnit->PickTargetPointAboveWater(outTargetPoint);
  }

  outTargetPoint = -1;
  const STIMap* const mapData = SimulationRef->mMapData;
  const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;
  return GetPositionWm3().y > waterElevation;
}

/**
 * Address: 0x005BF570 (FUN_005BF570, Moho::ReconBlip::PickTargetPointBelowWater)
 *
 * What it does:
 * Selects one below-water target-point lane by delegating to source unit
 * when linked, otherwise by comparing blip elevation against water level.
 */
bool ReconBlip::PickTargetPointBelowWater(std::int32_t& outTargetPoint) const
{
  if (Unit* const sourceUnit = GetSourceUnit(); sourceUnit != nullptr) {
    return sourceUnit->PickTargetPointBelowWater(outTargetPoint);
  }

  outTargetPoint = -1;
  const STIMap* const mapData = SimulationRef->mMapData;
  const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;
  return GetPositionWm3().y <= waterElevation;
}

/**
 * Address: 0x005BF810 (FUN_005BF810)
 *
 * What it does:
 * Refreshes cached transform/visual words from the linked source unit.
 */
void ReconBlip::Refresh()
{
  Unit* const sourceUnit = GetSourceUnit();
  if (!sourceUnit || sourceUnit->DestroyQueued()) {
    return;
  }

  EntityTransformPayload pending = ReadEntityTransformPayload(sourceUnit->PendingOrientation, sourceUnit->PendingPosition);
  pending.posX += mJamOffset.x;
  pending.posY += mJamOffset.y;
  pending.posZ += mJamOffset.z;
  WriteEntityTransformPayload(PendingOrientation, PendingPosition, pending);
  mPendingVelocityScale = sourceUnit->mPendingVelocityScale;

  if (SimulationRef && mCoordNode.ListIsSingleton()) {
    mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
  }

  const EntityTransformPayload sourceTransform = ReadEntityTransformPayload(sourceUnit->GetTransform());
  Orientation = {sourceTransform.quatW, sourceTransform.quatX, sourceTransform.quatY, sourceTransform.quatZ};
  Position = {sourceTransform.posX + mJamOffset.x, sourceTransform.posY + mJamOffset.y, sourceTransform.posZ + mJamOffset.z};
  mVelocityScale = sourceUnit->mVelocityScale;
  SetCurrentLayer(sourceUnit->mCurrentLayer);

  mUnitVarDat.mHasLinkedSource = sourceUnit->mAttachInfo.HasAttachTarget() ? 1u : 0u;

  const UnitAttributes& sourceAttributes = sourceUnit->GetAttributes();
  mUnitVarDat.mBlueprintState0 = sourceAttributes.GetReconBlipBlueprintState0();
  mUnitVarDat.mBlueprintState1 = sourceAttributes.GetReconBlipBlueprintState1();
  BeingBuilt = sourceUnit->IsBeingBuilt() ? 1u : 0u;
}

/**
 * Address: 0x005BF6F0 (FUN_005BF6F0)
 *
 * What it does:
 * Destroys this blip once no army still tracks it and source retention rules
 * are no longer satisfied.
 */
void ReconBlip::DestroyIfUnused()
{
  Unit* const sourceUnit = GetSourceUnit();
  if (sourceUnit && !sourceUnit->DestroyQueued() && !IsFake()) {
    return;
  }

  for (const SPerArmyReconInfo& perArmy : mReconDat) {
    if (perArmy.mNeedsFlush != 0u) {
      return;
    }
  }

  if (sourceUnit) {
    for (ReconBlip** it = sourceUnit->mReconBlips.begin(); it != sourceUnit->mReconBlips.end();) {
      if (*it == this) {
        it = sourceUnit->mReconBlips.erase(it);
      } else {
        ++it;
      }
    }
  }

  Destroy();
}

Unit* ReconBlip::GetSourceUnit() const noexcept
{
  return GetCreator();
}

/**
 * Address: 0x00579670 (FUN_00579670, Moho::ReconBlip::GetCreator)
 *
 * What it does:
 * Returns the linked source-unit pointer from `mCreator` or null when this
 * blip is detached.
 */
Unit* ReconBlip::GetCreator() const noexcept
{
  return mCreator.GetObjectPtr();
}

/**
 * Address: 0x005BDF00 (FUN_005BDF00, Moho::ReconBlip::GetFlags)
 *
 * What it does:
 * Returns one army-local recon bitmask by direct army-index lane lookup.
 */
EReconFlags ReconBlip::GetFlags(const std::int32_t armyIndex) const
{
  return static_cast<EReconFlags>(static_cast<std::int32_t>(mReconDat[armyIndex].mReconFlags));
}

/**
 * Address: 0x005BDF10 (FUN_005BDF10, Moho::ReconBlip::GetFlags)
 *
 * What it does:
 * Returns one army-local recon bitmask by owning army object.
 */
EReconFlags ReconBlip::GetFlags(CArmyImpl* const army) const
{
  return GetFlags(army->ArmyId);
}

/**
 * Address: 0x005BDF30 (FUN_005BDF30, Moho::ReconBlip::IsKnownFake)
 *
 * What it does:
 * Returns whether this blip is marked `RECON_KnownFake` for the queried army
 * lane.
 */
bool ReconBlip::IsKnownFake(CArmyImpl* const army) const
{
  return (static_cast<std::uint32_t>(GetFlags(army)) & static_cast<std::uint32_t>(RECON_KnownFake)) != 0u;
}

/**
 * Address: 0x005BDF50 (FUN_005BDF50, Moho::ReconBlip::IsOnRadar)
 *
 * What it does:
 * Returns whether this blip is currently radar-visible for the queried army
 * lane.
 */
bool ReconBlip::IsOnRadar(CArmyImpl* const army) const
{
  return (static_cast<std::uint32_t>(GetFlags(army)) & static_cast<std::uint32_t>(RECON_Radar)) != 0u;
}

/**
 * Address: 0x005BDF70 (FUN_005BDF70, Moho::ReconBlip::IsOnSonar)
 *
 * What it does:
 * Returns whether this blip is currently sonar-visible for the queried army
 * lane.
 */
bool ReconBlip::IsOnSonar(CArmyImpl* const army) const
{
  return (static_cast<std::uint32_t>(GetFlags(army)) & static_cast<std::uint32_t>(RECON_Sonar)) != 0u;
}

/**
 * Address: 0x005BDF90 (FUN_005BDF90, Moho::ReconBlip::IsOnOmni)
 *
 * What it does:
 * Returns whether this blip is currently omni-visible for the queried army
 * lane.
 */
bool ReconBlip::IsOnOmni(CArmyImpl* const army) const
{
  return (static_cast<std::uint32_t>(GetFlags(army)) & static_cast<std::uint32_t>(RECON_Omni)) != 0u;
}

/**
 * Address: 0x005BDFB0 (FUN_005BDFB0, Moho::ReconBlip::IsSeenEver)
 *
 * What it does:
 * Returns whether this blip has ever been seen (`RECON_LOSEver`) by the
 * queried army lane.
 */
bool ReconBlip::IsSeenEver(CArmyImpl* const army) const
{
  return (static_cast<std::uint32_t>(GetFlags(army)) & static_cast<std::uint32_t>(RECON_LOSEver)) != 0u;
}

/**
 * Address: 0x005BDFD0 (FUN_005BDFD0, Moho::ReconBlip::IsSeenNow)
 *
 * What it does:
 * Returns whether this blip is currently seen (`RECON_LOSNow`) by the queried
 * army lane.
 */
bool ReconBlip::IsSeenNow(CArmyImpl* const army) const
{
  return (static_cast<std::uint32_t>(GetFlags(army)) & static_cast<std::uint32_t>(RECON_LOSNow)) != 0u;
}

/**
 * Address: 0x005BDFF0 (FUN_005BDFF0, Moho::ReconBlip::IsMaybeDead)
 *
 * What it does:
 * Returns whether this blip is marked `RECON_MaybeDead` for the queried army
 * lane.
 */
bool ReconBlip::IsMaybeDead(CArmyImpl* const army) const
{
  return (static_cast<std::uint32_t>(GetFlags(army)) & static_cast<std::uint32_t>(RECON_MaybeDead)) != 0u;
}

bool ReconBlip::IsFake() const noexcept
{
  return mUnitConstDat.mFake != 0u;
}

SPerArmyReconInfo* ReconBlip::GetPerArmyReconInfo(const std::int32_t armyIndex) noexcept
{
  if (armyIndex < 0 || mReconDat.begin() == nullptr || mReconDat.end() == nullptr) {
    return nullptr;
  }

  const std::ptrdiff_t count = mReconDat.end() - mReconDat.begin();
  if (armyIndex >= count) {
    return nullptr;
  }

  return mReconDat.begin() + armyIndex;
}

const SPerArmyReconInfo* ReconBlip::GetPerArmyReconInfo(const std::int32_t armyIndex) const noexcept
{
  if (armyIndex < 0 || mReconDat.begin() == nullptr || mReconDat.end() == nullptr) {
    return nullptr;
  }

  const std::ptrdiff_t count = mReconDat.end() - mReconDat.begin();
  if (armyIndex >= count) {
    return nullptr;
  }

  return mReconDat.begin() + armyIndex;
}

/**
 * Address: 0x005BEE90 (FUN_005BEE90)
 * Mangled: ?CreateInterface@ReconBlip@Moho@@MAEXPAUSSyncData@2@@Z
 *
 * What it does:
 * Packs `mUnitConstDat` + entity identity fields into a `SCreateUnitParams`
 * and appends it to `syncData->mNewUnits`, then marks `mInterfaceCreated = 1`.
 */
void ReconBlip::CreateInterface(SSyncData* const syncData)
{
  SCreateUnitParams createParams{};
  createParams.mEntityId = id_;
  createParams.mBlueprint = BluePrint;
  createParams.mTickCreated = mTickCreated;
  createParams.mConstDat.mBuildStateTag = mUnitConstDat.mBuildStateTag;
  createParams.mConstDat.mStatsRoot = mUnitConstDat.mStatsRoot;
  createParams.mConstDat.mFake = mUnitConstDat.mFake;
  syncData->mNewUnits.push_back(createParams);
  mInterfaceCreated = 1u;
}

/**
 * Address: 0x005BEE40 (FUN_005BEE40, Moho::ReconBlip::UpdateVisibility)
 *
 * What it does:
 * Recomputes base entity visibility lanes, then applies focused-army recon
 * flush gating to the blip visibility state.
 */
void ReconBlip::UpdateVisibility()
{
  Entity::UpdateVisibility();
  const std::int32_t focusArmy = SimulationRef->mSyncFilter.focusArmy;
  mVisibilityState = static_cast<std::uint8_t>(
    focusArmy != -1 && mReconDat[static_cast<std::size_t>(focusArmy)].mNeedsFlush != 0u
  );
}
