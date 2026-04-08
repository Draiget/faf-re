#include "moho/console/CConAlias.h"
#include "moho/console/CConCommand.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/render/CDecalHandle.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/EBeamParam.h"
#include "moho/render/EEmitterCurve.h"
#include "moho/render/EEmitterParam.h"
#include "moho/resource/RResId.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"

#include "gpg/core/utils/Global.h"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

namespace moho
{
  extern float efx_WaterOffset;
  extern bool dbg_EfxBeams;
  extern bool dbg_Emitter;
  extern bool dbg_Trail;

  int ExecuteAddBeamSimCommand(
    Sim* sim,
    CSimConCommand::ParsedCommandArgs* commandArgs,
    Wm3::Vector3f* worldPos,
    CArmyImpl* focusArmy,
    SEntitySetTemplateUnit* selectedUnits
  );
}

namespace
{
  std::int32_t gRecoveredCScrLuaMetatableFactoryIEffectIndex = 0;
  constexpr const char* kCreateBeamEmitterHelpText = "emitter = CreateBeamEmitter(blueprint,army)";
  constexpr const char* kCreateEmitterAtEntityHelpText = "CreateEmitterAtEntity(entity,army,emitter_bp_name)";
  constexpr const char* kCreateEmitterOnEntityHelpText = "CreateEmitterOnEntity(entity,army,emitter_bp_name)";
  constexpr const char* kCreateEmitterAtBoneHelpText = "CreateEmitterAtBone(entity, bone, army, emitter_blueprint)";
  constexpr const char* kCreateAttachedEmitterHelpText = "CreateAttachedEmitter(entity, bone, army, emitter_blueprint)";
  constexpr const char* kCreateTrailHelpText = "CreateTrail(entity, bone, army, trail_blueprint)";
  constexpr const char* kCreateDecalHelpText =
    "handle = CreateDecal(position, heading, textureName1, textureName2, type, sizeX, sizeZ, lodParam, duration, "
    "army, fidelity)";
  constexpr const char* kCreateSplatHelpText =
    "CreateSplat(position, heading, textureName, sizeX, sizeZ, lodParam, duration, army, fidelity)";
  constexpr const char* kCreateSplatOnBoneHelpText =
    "CreateSplatOnBone(boneName, offset, textureName, sizeX, sizeZ, lodParam, duration, army)\n"
    "Add a splat to the game at an entity bone position and heading.";
  constexpr const char* kCreateBeamEmitterOnEntityHelpText =
    "emitter = CreateBeamEmitterOnEntity(entity, tobone, army, blueprint )";
  constexpr const char* kCreateBeamEntityToEntityHelpText =
    "CreateBeamEntityToEntity(entity, bone, other, bone, army, blueprint)";
  constexpr const char* kCreateAttachedBeamHelpText =
    "CreateAttachedBeam(entity, bone, army, length, thickness, texture_filename)";
  constexpr const char* kCreateBeamToEntityBoneHelpText =
    "CreateBeamToEntityBone(entity, bone, other, bone, army, thickness, texture_filename)";
  constexpr const char* kAttachBeamEntityToEntityHelpText =
    "AttachBeamEntityToEntity(self, bone, other, bone, army, blueprint)";
  constexpr const char* kAttachBeamToEntityHelpText =
    "AttachBeamToEntity(emitter, entity, tobone, army )";
  constexpr const char* kCreateLightParticleHelpText =
    "CreateLightParticle(entity, bone, army, size, lifetime, textureName, rampName)";
  constexpr const char* kCreateLightParticleIntelHelpText =
    "CreateLightParticle(entity, bone, army, size, lifetime, textureName, rampName)";
  constexpr const char* kIEffectSetBeamParamHelpText = "effect:SetBeamParam('name', value)";
  constexpr const char* kIEffectSetEmitterParamHelpText =
    "effect:SetEmitterParam('name', value)returns the effect so you can chain calls like:\n"
    "    effect:SetEmitterParam('x',1):ScaleEmitter(3.7)";
  constexpr const char* kIEffectScaleEmitterHelpText = "effect:ScaleEmitter(param, scale)\n"
                                                        "returns the effect so you can chain calls like:\n"
                                                        "    effect:SetEmitterParam('x',1):ScaleEmitter(3.7)";
  constexpr const char* kIEffectResizeEmitterCurveHelpText =
    "Effect:ResizeEmitterCurve(parameter, time_in_ticks)Resize the emitter curve to the number of ticks passed in.\n"
    "This is so if we change the lifetime of the emitter we can rescale some of the curves to match if needed.\n"
    "Arguably this should happen automatically to all curves but the original design was screwed up.\n"
    "\n"
    "returns the effect so you can chain calls like:\n"
    "    effect:SetEmitterParam('x',1):ScaleEmitter(3.7)";
  constexpr const char* kIEffectSetEmitterCurveParamHelpText =
    "Effect:SetEmitterCurveParam(param_name, height, size)";
  constexpr const char* kIEffectOffsetEmitterHelpText = "Effect:OffsetEmitter(x,y,z)";
  constexpr const char* kIEffectDestroyHelpText = "Effect:Destroy()";
  constexpr const char* kCDecalHandleDestroyHelpText = "DecalHandle:Destroy()";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedArgRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kInvalidEffectParameterErrorText = "Invalid Effect Parameter %s";
  constexpr const char* kInvalidEmitterCurveParameterErrorText = "Invalid Emitter Curve Parameter %s";
  constexpr const char* kUnknownBeamKindErrorText = "Unknown beam kind: %s";
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrevious = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor = nullptr;
  alignas(moho::CSimConFunc) unsigned char gSimConFunc_efx_NewEmitterStorage[sizeof(moho::CSimConFunc)] = {};
  bool gSimConFunc_efx_NewEmitterConstructed = false;
  alignas(moho::CSimConFunc) unsigned char gSimConFunc_efx_AttachEmitterStorage[sizeof(moho::CSimConFunc)] = {};
  bool gSimConFunc_efx_AttachEmitterConstructed = false;
  alignas(moho::CSimConFunc) unsigned char gSimConFunc_AddLightParticleStorage[sizeof(moho::CSimConFunc)] = {};
  bool gSimConFunc_AddLightParticleConstructed = false;
  alignas(moho::CSimConFunc) unsigned char gSimConFunc_AddBeamStorage[sizeof(moho::CSimConFunc)] = {};
  bool gSimConFunc_AddBeamConstructed = false;
  Wm3::Vector3f gAddBeamStartPoint{};
  bool gAddBeamCaptureStartPending = true;

  [[nodiscard]] moho::CScrLuaInitFormSet* FindSimLuaInitFormSet() noexcept
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
    if (moho::CScrLuaInitFormSet* const set = FindSimLuaInitFormSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] moho::Sim* ResolveGlobalSim(lua_State* const luaContext) noexcept
  {
    if (!luaContext || !luaContext->l_G) {
      return nullptr;
    }
    return luaContext->l_G->globalUserData;
  }

  [[nodiscard]] Wm3::Vec3f NormalizeXZ(const Wm3::Vec3f& value) noexcept
  {
    const float lengthXZ = std::sqrt((value.x * value.x) + (value.z * value.z));
    if (lengthXZ <= 0.0f) {
      return {0.0f, 0.0f, 0.0f};
    }

    const float invLength = 1.0f / lengthXZ;
    return {value.x * invLength, 0.0f, value.z * invLength};
  }

  [[nodiscard]] std::uint32_t ComputeDecalStartTick(const moho::Sim* const sim, const float duration) noexcept
  {
    if (!sim || duration <= 0.0f) {
      return 0u;
    }

    const auto durationTicks = static_cast<std::uint32_t>(std::floor(duration * 10.0f));
    return sim->mCurTick + durationTicks;
  }

  [[nodiscard]] moho::VTransform BuildHeadingTransform(const Wm3::Vec3f& position, const float heading) noexcept
  {
    const float halfHeading = heading * 0.5f;
    const float sinHalf = std::sin(halfHeading);
    const float cosHalf = std::cos(halfHeading);

    moho::VTransform transform{};
    transform.orient_.w = cosHalf;
    transform.orient_.x = 0.0f;
    transform.orient_.y = sinHalf;
    transform.orient_.z = 0.0f;
    transform.pos_ = position;
    return transform;
  }

  /**
   * Address: 0x0066D360 (FUN_0066D360, Moho::CDecal::CDecal)
   *
   * What it does:
   * Converts transform/size inputs into `SDecalInfo`, computes start tick + yaw,
   * and creates one tracked decal handle via the sim decal buffer.
   */
  [[nodiscard]] moho::CDecalHandle* CreateDecalFromTransform(
    const moho::VTransform& transform,
    const Wm3::Vec3f& size,
    moho::Sim* const sim,
    const float duration,
    const msvc8::string& textureNamePrimary,
    const msvc8::string& textureNameSecondary,
    const float lodParam,
    const bool isSplat,
    const msvc8::string& typeName,
    const std::uint32_t armyIndex,
    const std::uint32_t fidelity
  )
  {
    if (!sim || !sim->mDecalBuffer) {
      return nullptr;
    }

    const std::uint32_t startTick = ComputeDecalStartTick(sim, duration);

    const Wm3::Vec3f forwardXZ = NormalizeXZ(transform.orient_.Rotate({0.0f, 0.0f, 1.0f}));
    const Wm3::Vec3f rightXZ = NormalizeXZ(transform.orient_.Rotate({1.0f, 0.0f, 0.0f}));

    Wm3::Vec3f position{};
    position.x = transform.pos_.x - ((rightXZ.x * size.x) * 0.5f) - ((forwardXZ.x * size.z) * 0.5f);
    position.y = transform.pos_.y - ((rightXZ.y * size.x) * 0.5f) - ((forwardXZ.y * size.z) * 0.5f);
    position.z = transform.pos_.z - ((rightXZ.z * size.x) * 0.5f) - ((forwardXZ.z * size.z) * 0.5f);

    Wm3::Vec3f rotation{};
    const float headingNumerator =
      2.0f * ((transform.orient_.x * transform.orient_.z) + (transform.orient_.w * transform.orient_.y));
    const float headingDenominator =
      1.0f - (2.0f * ((transform.orient_.z * transform.orient_.z) + (transform.orient_.y * transform.orient_.y)));
    rotation.y = -std::atan2(headingNumerator, headingDenominator);

    const moho::SDecalInfo info(
      size,
      position,
      rotation,
      textureNamePrimary,
      textureNameSecondary,
      isSplat,
      lodParam,
      startTick,
      typeName,
      armyIndex,
      fidelity
    );

    return sim->mDecalBuffer->CreateHandle(info);
  }

  [[nodiscard]] const gpg::REnumType* ResolveEBeamParamType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(moho::EBeamParam));
    }

    return sCachedType ? sCachedType->IsEnumType() : nullptr;
  }

  [[nodiscard]] const gpg::REnumType* ResolveEEmitterParamType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(moho::EEmitterParam));
    }

    return sCachedType ? sCachedType->IsEnumType() : nullptr;
  }

  [[nodiscard]] const gpg::REnumType* ResolveEEmitterCurveType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(moho::EEmitterCurve));
    }

    return sCachedType ? sCachedType->IsEnumType() : nullptr;
  }

  [[nodiscard]] int ResolveEmitterCurveParamIndexOrThrow(lua_State* const rawState, const char* const paramName)
  {
    int paramIndex = 0;
    const gpg::REnumType* const enumType = ResolveEEmitterCurveType();
    if (!enumType || !enumType->GetEnumValue(paramName, &paramIndex)) {
      lua_pushstring(rawState, gpg::STR_Printf(kInvalidEmitterCurveParameterErrorText, paramName).c_str());
      (void)lua_gettop(rawState);
      lua_error(rawState);
    }
    return paramIndex;
  }

  void RecomputeEmitterCurveYBounds(moho::SEfxCurve& curve)
  {
    curve.mBoundsMin.y = std::numeric_limits<float>::infinity();
    curve.mBoundsMax.y = -std::numeric_limits<float>::infinity();

    for (Wm3::Vector3f* key = curve.mKeys.begin(); key != curve.mKeys.end(); ++key) {
      if (curve.mBoundsMin.y > key->y) {
        curve.mBoundsMin.y = key->y;
      }
      if (key->y > curve.mBoundsMax.y) {
        curve.mBoundsMax.y = key->y;
      }
    }
  }

  void InsertEmitterCurveKeySortedByX(moho::SEfxCurve& curve, const Wm3::Vector3f& key)
  {
    Wm3::Vector3f* insertPosition = curve.mKeys.end();
    for (Wm3::Vector3f* it = curve.mKeys.begin(); it != curve.mKeys.end(); ++it) {
      if (it->x > key.x) {
        insertPosition = it;
        break;
      }
    }

    curve.mKeys.InsertAt(insertPosition, &key, &key + 1);
    RecomputeEmitterCurveYBounds(curve);
  }

  [[nodiscard]] moho::SEfxCurve* ResolveCurveStorage(const std::int32_t curveParamAddress) noexcept
  {
    return reinterpret_cast<moho::SEfxCurve*>(static_cast<std::uintptr_t>(curveParamAddress));
  }

  /**
   * Address: 0x0066D6E0 (FUN_0066D6E0, shared IEffect named-float-param lane)
   *
   * What it does:
   * Resolves one optional `IEffect*`, maps one enum token name from arg #2,
   * applies arg #3 as float via `IEffect::SetFloatParam`, and returns the
   * effect Lua object for call chaining.
   */
  int ApplyIEffectNamedFloatParam(LuaPlus::LuaState* const state, const gpg::REnumType* const enumType)
  {
    lua_State* const rawState = state->m_state;
    LuaPlus::LuaObject effectObject(LuaPlus::LuaStackObject(state, 1));
    moho::IEffect* const effect = moho::SCR_FromLua_IEffectOpt(effectObject, state);
    if (!effect) {
      return 1;
    }

    LuaPlus::LuaStackObject paramNameArg(state, 2);
    const char* const paramName = lua_tostring(rawState, 2);
    if (!paramName) {
      paramNameArg.TypeError("string");
    }

    int paramIndex = 0;
    if (!enumType || !enumType->GetEnumValue(paramName, &paramIndex)) {
      lua_pushstring(rawState, gpg::STR_Printf(kInvalidEffectParameterErrorText, paramName).c_str());
      (void)lua_gettop(rawState);
      lua_error(rawState);
    }

    LuaPlus::LuaStackObject valueArg(state, 3);
    const float value = valueArg.GetNumber();
    effect->SetFloatParam(paramIndex, value);
    effect->mLuaObj.PushStack(state);
    return 1;
  }

  template <std::int32_t* TargetIndex>
  int RegisterRecoveredFactoryIndex() noexcept
  {
    const int index = moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    *TargetIndex = index;
    return index;
  }

  template <moho::CScrLuaInitForm** PrevLane, moho::CScrLuaInitForm** AnchorLane>
  [[nodiscard]] moho::CScrLuaInitForm* RegisterRecoveredSimInitLinkerLane() noexcept
  {
    moho::CScrLuaInitFormSet* const simSet = FindSimLuaInitFormSet();
    if (simSet == nullptr) {
      *PrevLane = nullptr;
      return nullptr;
    }

    moho::CScrLuaInitForm* const result = simSet->mForms;
    *PrevLane = result;
    simSet->mForms = reinterpret_cast<moho::CScrLuaInitForm*>(AnchorLane);
    return result;
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardEffectLuaThunk() noexcept
  {
    return Target();
  }

  template <void (*Cleanup)()>
  void RegisterAtexitCleanup() noexcept
  {
    (void)std::atexit(Cleanup);
  }

  [[nodiscard]] moho::CConAlias& ConAlias_efx_NewEmitter()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_efx_AttachEmitter()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AddLightParticle()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AddBeam()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc& SimConFunc_efx_NewEmitter()
  {
    return *reinterpret_cast<moho::CSimConFunc*>(gSimConFunc_efx_NewEmitterStorage);
  }

  [[nodiscard]] moho::CSimConFunc& ConstructSimConFunc_efx_NewEmitter()
  {
    if (!gSimConFunc_efx_NewEmitterConstructed) {
      new (gSimConFunc_efx_NewEmitterStorage) moho::CSimConFunc(false, "efx_NewEmitter", &moho::Sim::efx_NewEmitter);
      gSimConFunc_efx_NewEmitterConstructed = true;
    }
    return SimConFunc_efx_NewEmitter();
  }

  [[nodiscard]] moho::CSimConFunc& SimConFunc_efx_AttachEmitter()
  {
    return *reinterpret_cast<moho::CSimConFunc*>(gSimConFunc_efx_AttachEmitterStorage);
  }

  [[nodiscard]] moho::CSimConFunc& ConstructSimConFunc_efx_AttachEmitter()
  {
    if (!gSimConFunc_efx_AttachEmitterConstructed) {
      new (gSimConFunc_efx_AttachEmitterStorage)
        moho::CSimConFunc(false, "efx_AttachEmitter", &moho::Sim::efx_AttachEmitter);
      gSimConFunc_efx_AttachEmitterConstructed = true;
    }
    return SimConFunc_efx_AttachEmitter();
  }

  [[nodiscard]] moho::CSimConFunc& SimConFunc_AddLightParticle()
  {
    return *reinterpret_cast<moho::CSimConFunc*>(gSimConFunc_AddLightParticleStorage);
  }

  [[nodiscard]] moho::CSimConFunc& ConstructSimConFunc_AddLightParticle()
  {
    if (!gSimConFunc_AddLightParticleConstructed) {
      new (gSimConFunc_AddLightParticleStorage)
        moho::CSimConFunc(false, "AddLightParticle", &moho::Sim::AddLightParticle);
      gSimConFunc_AddLightParticleConstructed = true;
    }
    return SimConFunc_AddLightParticle();
  }

  [[nodiscard]] moho::CSimConFunc& SimConFunc_AddBeam()
  {
    return *reinterpret_cast<moho::CSimConFunc*>(gSimConFunc_AddBeamStorage);
  }

  [[nodiscard]] moho::CSimConFunc& ConstructSimConFunc_AddBeam()
  {
    if (!gSimConFunc_AddBeamConstructed) {
      new (gSimConFunc_AddBeamStorage) moho::CSimConFunc(false, "AddBeam", &moho::ExecuteAddBeamSimCommand);
      gSimConFunc_AddBeamConstructed = true;
    }
    return SimConFunc_AddBeam();
  }

  [[nodiscard]] moho::TConVar<float>& GetEfxWaterOffsetConVar()
  {
    static moho::TConVar<float> conVar(
      "efx_WaterOffset",
      "Offsets emitter particles from the waterline height",
      &moho::efx_WaterOffset
    );
    return conVar;
  }

  [[nodiscard]] moho::TConVar<bool>& GetDbgEmitterConVar()
  {
    static moho::TConVar<bool> conVar(
      "dbg_Emitter",
      "Enable emitter debug diagnostics",
      &moho::dbg_Emitter
    );
    return conVar;
  }

  [[nodiscard]] moho::TConVar<bool>& GetDbgTrailConVar()
  {
    static moho::TConVar<bool> conVar(
      "dbg_Trail",
      "Enable trail debug diagnostics",
      &moho::dbg_Trail
    );
    return conVar;
  }

  [[nodiscard]] moho::TConVar<bool>& GetDbgEfxBeamsConVar()
  {
    static moho::TConVar<bool> conVar(
      "dbg_EfxBeams",
      "Enable beam effect debug diagnostics",
      &moho::dbg_EfxBeams
    );
    return conVar;
  }

  void cleanup_TConVar_efx_WaterOffset_atexit()
  {
    moho::TeardownConCommandRegistration(GetEfxWaterOffsetConVar());
  }

  void cleanup_TConVar_dbg_Emitter_atexit()
  {
    moho::TeardownConCommandRegistration(GetDbgEmitterConVar());
  }

  void cleanup_TConVar_dbg_Trail_atexit()
  {
    moho::TeardownConCommandRegistration(GetDbgTrailConVar());
  }

  void cleanup_TConVar_dbg_EfxBeams_atexit()
  {
    moho::TeardownConCommandRegistration(GetDbgEfxBeamsConVar());
  }
} // namespace

namespace moho
{
  float efx_WaterOffset = 0.0f;
  bool dbg_EfxBeams = false;
  bool dbg_Emitter = false;
  bool dbg_Trail = false;

  CScrLuaInitForm* func_IEffectSetBeamParam_LuaFuncDef();
  CScrLuaInitForm* func_IEffectSetEmitterParam_LuaFuncDef();
  CScrLuaInitForm* func_IEffectScaleEmitter_LuaFuncDef();
  CScrLuaInitForm* func_IEffectResizeEmitterCurve_LuaFuncDef();
  CScrLuaInitForm* func_IEffectSetEmitterCurveParam_LuaFuncDef();
  CScrLuaInitForm* func_IEffectOffsetEmitter_LuaFuncDef();
  CScrLuaInitForm* func_IEffectDestroy_LuaFuncDef();
  CScrLuaInitForm* func_CDecalHandleDestroy_LuaFuncDef();
  CScrLuaInitForm* func_CreateDecal_LuaFuncDef();
  CScrLuaInitForm* func_CreateSplat_LuaFuncDef();
  CScrLuaInitForm* func_CreateSplatOnBone_LuaFuncDef();
  CScrLuaInitForm* func_CreateEmitterAtEntity_LuaFuncDef();
  CScrLuaInitForm* func_CreateEmitterOnEntity_LuaFuncDef();
  CScrLuaInitForm* func_CreateLightParticle_LuaFuncDef();
  CScrLuaInitForm* func_CreateLightParticleIntel_LuaFuncDef();
  CScrLuaInitForm* func_CreateAttachedEmitter_LuaFuncDef();
  CScrLuaInitForm* func_CreateTrail_LuaFuncDef();
  CScrLuaInitForm* func_CreateAttachedBeam_LuaFuncDef();
  CScrLuaInitForm* func_CreateBeamToEntityBone_LuaFuncDef();
  CScrLuaInitForm* func_CreateEmitterAtBone_LuaFuncDef();
  int cfunc_CreateEmitterAtEntity(lua_State* luaContext);
  int cfunc_CreateEmitterAtEntityL(LuaPlus::LuaState* state);
  int cfunc_CreateEmitterOnEntity(lua_State* luaContext);
  int cfunc_CreateEmitterOnEntityL(LuaPlus::LuaState* state);
  int cfunc_CreateEmitterAtBone(lua_State* luaContext);
  int cfunc_CreateEmitterAtBoneL(LuaPlus::LuaState* state);
  int cfunc_CreateAttachedEmitter(lua_State* luaContext);
  int cfunc_CreateAttachedEmitterL(LuaPlus::LuaState* state);
  int cfunc_CreateTrail(lua_State* luaContext);
  int cfunc_CreateTrailL(LuaPlus::LuaState* state);
  int cfunc_CreateAttachedBeam(lua_State* luaContext);
  int cfunc_CreateAttachedBeamL(LuaPlus::LuaState* state);
  int cfunc_CreateBeamToEntityBone(lua_State* luaContext);
  int cfunc_CreateBeamToEntityBoneL(LuaPlus::LuaState* state);
  int cfunc_CreateBeamEmitter(lua_State* luaContext);
  int cfunc_CreateBeamEmitterL(LuaPlus::LuaState* state);
  int cfunc_CreateBeamEmitterOnEntity(lua_State* luaContext);
  int cfunc_CreateBeamEmitterOnEntityL(LuaPlus::LuaState* state);
  int cfunc_CreateBeamEntityToEntity(lua_State* luaContext);
  int cfunc_CreateBeamEntityToEntityL(LuaPlus::LuaState* state);
  int cfunc_AttachBeamEntityToEntity(lua_State* luaContext);
  int cfunc_AttachBeamEntityToEntityL(LuaPlus::LuaState* state);
  int cfunc_AttachBeamToEntity(lua_State* luaContext);
  int cfunc_AttachBeamToEntityL(LuaPlus::LuaState* state);
  int cfunc_CreateLightParticle(lua_State* luaContext);
  int cfunc_CreateLightParticleL(LuaPlus::LuaState* state);
  int cfunc_CreateLightParticleIntel(lua_State* luaContext);
  int cfunc_CreateLightParticleIntelL(LuaPlus::LuaState* state);
  int cfunc_IEffectSetBeamParam(lua_State* luaContext);
  int cfunc_IEffectSetBeamParamL(LuaPlus::LuaState* state);
  int cfunc_IEffectSetEmitterParam(lua_State* luaContext);
  int cfunc_IEffectSetEmitterParamL(LuaPlus::LuaState* state);
  int cfunc_IEffectScaleEmitter(lua_State* luaContext);
  int cfunc_IEffectScaleEmitterL(LuaPlus::LuaState* state);
  int cfunc_IEffectResizeEmitterCurve(lua_State* luaContext);
  int cfunc_IEffectResizeEmitterCurveL(LuaPlus::LuaState* state);
  int cfunc_IEffectSetEmitterCurveParam(lua_State* luaContext);
  int cfunc_IEffectSetEmitterCurveParamL(LuaPlus::LuaState* state);
  int cfunc_IEffectOffsetEmitter(lua_State* luaContext);
  int cfunc_IEffectOffsetEmitterL(LuaPlus::LuaState* state);
  int cfunc_IEffectDestroy(lua_State* luaContext);
  int cfunc_IEffectDestroyL(LuaPlus::LuaState* state);
  int cfunc_CDecalHandleDestroy(lua_State* luaContext);
  int cfunc_CDecalHandleDestroyL(LuaPlus::LuaState* state);
  int cfunc_CreateDecal(lua_State* luaContext);
  int cfunc_CreateDecalL(LuaPlus::LuaState* state);
  int cfunc_CreateSplat(lua_State* luaContext);
  int cfunc_CreateSplatL(LuaPlus::LuaState* state);
  int cfunc_CreateSplatOnBone(lua_State* luaContext);
  int cfunc_CreateSplatOnBoneL(LuaPlus::LuaState* state);
  CScrLuaInitForm* func_CreateBeamEmitter_LuaFuncDef();
  CScrLuaInitForm* func_CreateBeamEmitterOnEntity_LuaFuncDef();
  CScrLuaInitForm* func_CreateBeamEntityToEntity_LuaFuncDef();
  CScrLuaInitForm* func_AttachBeamEntityToEntity_LuaFuncDef();
  CScrLuaInitForm* func_AttachBeamToEntity_LuaFuncDef();

  /**
   * Address: 0x00656450 (FUN_00656450, cfunc_CreateBeamEmitter)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to `cfunc_CreateBeamEmitterL`.
   */
  int cfunc_CreateBeamEmitter(lua_State* const luaContext)
  {
    return cfunc_CreateBeamEmitterL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006564D0 (FUN_006564D0, cfunc_CreateBeamEmitterL)
   *
   * What it does:
   * Validates `(blueprintName, armyIndex)`, resolves one beam blueprint id,
   * creates the beam effect instance, and pushes the effect Lua object.
   */
  int cfunc_CreateBeamEmitterL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateBeamEmitterHelpText, 2, argumentCount);
    }

    LuaPlus::LuaStackObject blueprintArg(state, 1);
    const char* const blueprintName = lua_tostring(rawState, 1);
    if (blueprintName == nullptr) {
      blueprintArg.TypeError("string");
    }

    Sim* const sim = ResolveGlobalSim(rawState);
    RResId beamId{};
    gpg::STR_InitFilename(&beamId.name, blueprintName);
    RBeamBlueprint* const beamBlueprint = sim->mRules->GetBeamBlueprint(beamId);
    if (beamBlueprint == nullptr) {
      LuaPlus::LuaState::Error(state, kUnknownBeamKindErrorText, blueprintName);
    }

    LuaPlus::LuaStackObject armyArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      armyArg.TypeError("integer");
    }

    const int armyIndex = static_cast<int>(lua_tonumber(rawState, 2));
    IEffect* const effect = sim->mEffectManager->CreateBeam(beamBlueprint, armyIndex);
    if (effect == nullptr) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00656470 (FUN_00656470, func_CreateBeamEmitter_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for `CreateBeamEmitter`.
   */
  CScrLuaInitForm* func_CreateBeamEmitter_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateBeamEmitter",
      &cfunc_CreateBeamEmitter,
      nullptr,
      "<global>",
      kCreateBeamEmitterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00656650 (FUN_00656650, cfunc_CreateBeamEmitterOnEntity)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateBeamEmitterOnEntityL`.
   */
  int cfunc_CreateBeamEmitterOnEntity(lua_State* const luaContext)
  {
    return cfunc_CreateBeamEmitterOnEntityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00656670 (FUN_00656670, func_CreateBeamEmitterOnEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for
   * `CreateBeamEmitterOnEntity`.
   */
  CScrLuaInitForm* func_CreateBeamEmitterOnEntity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateBeamEmitterOnEntity",
      &cfunc_CreateBeamEmitterOnEntity,
      nullptr,
      "<global>",
      kCreateBeamEmitterOnEntityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006566D0 (FUN_006566D0, cfunc_CreateBeamEmitterOnEntityL)
   *
   * What it does:
   * Reads `(entity, tobone, army, beamBlueprint)`, creates one beam-emitter
   * effect from blueprint/army, attaches it to entity-or-bone, and pushes the
   * effect Lua object on success.
   */
  int cfunc_CreateBeamEmitterOnEntityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateBeamEmitterOnEntityHelpText, 4, argumentCount);
    }

    Sim* const sim = ResolveGlobalSim(rawState);

    LuaPlus::LuaStackObject blueprintArg(state, 4);
    const char* const blueprintName = lua_tostring(rawState, 4);
    if (!blueprintName) {
      blueprintArg.TypeError("string");
    }

    RResId beamId{};
    gpg::STR_InitFilename(&beamId.name, blueprintName);
    RBeamBlueprint* const beamBlueprint = sim->mRules->GetBeamBlueprint(beamId);
    if (!beamBlueprint) {
      LuaPlus::LuaState::Error(state, kUnknownBeamKindErrorText, blueprintName);
    }

    LuaPlus::LuaStackObject armyArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      armyArg.TypeError("integer");
    }
    const int armyIndex = static_cast<int>(lua_tonumber(rawState, 3));

    IEffect* const effect = sim->mEffectManager->CreateBeam(beamBlueprint, armyIndex);
    if (!effect) {
      return 0;
    }

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, true);
    if (boneIndex == -1) {
      effect->SetEntity(entity);
    } else {
      effect->SetBone(entity, boneIndex);
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006568E0 (FUN_006568E0, cfunc_CreateBeamEntityToEntity)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateBeamEntityToEntityL`.
   */
  int cfunc_CreateBeamEntityToEntity(lua_State* const luaContext)
  {
    return cfunc_CreateBeamEntityToEntityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00656900 (FUN_00656900, func_CreateBeamEntityToEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for
   * `CreateBeamEntityToEntity`.
   */
  CScrLuaInitForm* func_CreateBeamEntityToEntity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateBeamEntityToEntity",
      &cfunc_CreateBeamEntityToEntity,
      nullptr,
      "<global>",
      kCreateBeamEntityToEntityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00656960 (FUN_00656960, cfunc_CreateBeamEntityToEntityL)
   *
   * What it does:
   * Reads `(sourceEntity, sourceBone, targetEntity, targetBone, army, beam)`,
   * resolves one beam blueprint, creates one beam between both entity lanes,
   * and pushes the effect Lua object on success.
   */
  int cfunc_CreateBeamEntityToEntityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 6) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateBeamEntityToEntityHelpText, 6, argumentCount);
    }

    Sim* const sim = ResolveGlobalSim(rawState);

    LuaPlus::LuaObject sourceEntityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const sourceEntity = SCR_FromLua_Entity(sourceEntityObject, state);

    LuaPlus::LuaStackObject sourceBoneArg(state, 2);
    const int sourceBoneIndex = ENTSCR_ResolveBoneIndex(sourceEntity, sourceBoneArg, true);

    LuaPlus::LuaObject targetEntityObject(LuaPlus::LuaStackObject(state, 3));
    Entity* const targetEntity = SCR_FromLua_Entity(targetEntityObject, state);

    LuaPlus::LuaStackObject targetBoneArg(state, 4);
    const int targetBoneIndex = ENTSCR_ResolveBoneIndex(targetEntity, targetBoneArg, true);

    LuaPlus::LuaStackObject armyArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      armyArg.TypeError("integer");
    }
    const int armyIndex = static_cast<int>(lua_tonumber(rawState, 5));

    LuaPlus::LuaStackObject blueprintArg(state, 6);
    const char* const blueprintName = lua_tostring(rawState, 6);
    if (!blueprintName) {
      blueprintArg.TypeError("string");
    }

    RResId beamId{};
    gpg::STR_InitFilename(&beamId.name, blueprintName);
    RBeamBlueprint* const beamBlueprint = sim->mRules->GetBeamBlueprint(beamId);
    if (!beamBlueprint) {
      const char* const beamNameForError = lua_tostring(rawState, 6);
      if (!beamNameForError) {
        blueprintArg.TypeError("string");
      }
      LuaPlus::LuaState::Error(state, kUnknownBeamKindErrorText, beamNameForError);
    }

    IEffect* const effect = sim->mEffectManager->CreateBeamEntityToEntity(
      sourceEntity,
      sourceBoneIndex,
      targetEntity,
      targetBoneIndex,
      beamBlueprint,
      armyIndex
    );
    if (!effect) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00656C30 (FUN_00656C30, cfunc_AttachBeamEntityToEntity)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_AttachBeamEntityToEntityL`.
   */
  int cfunc_AttachBeamEntityToEntity(lua_State* const luaContext)
  {
    return cfunc_AttachBeamEntityToEntityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00656C50 (FUN_00656C50, func_AttachBeamEntityToEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for
   * `AttachBeamEntityToEntity`.
   */
  CScrLuaInitForm* func_AttachBeamEntityToEntity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "AttachBeamEntityToEntity",
      &cfunc_AttachBeamEntityToEntity,
      nullptr,
      "<global>",
      kAttachBeamEntityToEntityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00656CB0 (FUN_00656CB0, cfunc_AttachBeamEntityToEntityL)
   *
   * What it does:
   * Reads `(sourceEntity, sourceBone, targetEntity, targetBone, army, beamBp)`,
   * resolves the beam blueprint, attaches one beam between both entity lanes,
   * and pushes the resulting effect Lua object on success.
   */
  int cfunc_AttachBeamEntityToEntityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 6) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAttachBeamEntityToEntityHelpText, 6, argumentCount);
    }

    Sim* const sim = ResolveGlobalSim(rawState);

    LuaPlus::LuaObject sourceEntityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const sourceEntity = SCR_FromLua_Entity(sourceEntityObject, state);

    LuaPlus::LuaStackObject sourceBoneArg(state, 2);
    const int sourceBoneIndex = ENTSCR_ResolveBoneIndex(sourceEntity, sourceBoneArg, true);

    LuaPlus::LuaObject targetEntityObject(LuaPlus::LuaStackObject(state, 3));
    Entity* const targetEntity = SCR_FromLua_Entity(targetEntityObject, state);

    LuaPlus::LuaStackObject targetBoneArg(state, 4);
    const int targetBoneIndex = ENTSCR_ResolveBoneIndex(targetEntity, targetBoneArg, true);

    LuaPlus::LuaStackObject armyArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      armyArg.TypeError("integer");
    }
    const int armyIndex = static_cast<int>(lua_tonumber(rawState, 5));

    LuaPlus::LuaStackObject blueprintArg(state, 6);
    const char* const blueprintName = lua_tostring(rawState, 6);
    if (!blueprintName) {
      blueprintArg.TypeError("string");
    }

    RResId beamId{};
    gpg::STR_InitFilename(&beamId.name, blueprintName);
    const RBeamBlueprint* const beamBlueprint = sim->mRules->GetBeamBlueprint(beamId);
    if (!beamBlueprint) {
      LuaPlus::LuaState::Error(state, kUnknownBeamKindErrorText, blueprintName);
    }

    IEffect* const effect = sim->mEffectManager
      ->AttachBeamEntityToEntity(sourceEntity, sourceBoneIndex, targetEntity, targetBoneIndex, beamBlueprint, armyIndex);
    if (!effect) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00656F80 (FUN_00656F80, cfunc_AttachBeamToEntity)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to `cfunc_AttachBeamToEntityL`.
   */
  int cfunc_AttachBeamToEntity(lua_State* const luaContext)
  {
    return cfunc_AttachBeamToEntityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00656FA0 (FUN_00656FA0, func_AttachBeamToEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for `AttachBeamToEntity`.
   */
  CScrLuaInitForm* func_AttachBeamToEntity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "AttachBeamToEntity",
      &cfunc_AttachBeamToEntity,
      nullptr,
      "<global>",
      kAttachBeamToEntityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00657000 (FUN_00657000, cfunc_AttachBeamToEntityL)
   *
   * What it does:
   * Validates `(effect, entity, targetBone, army)`, then retargets the beam to
   * either the entity root or one specific target bone lane.
   */
  int cfunc_AttachBeamToEntityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAttachBeamToEntityHelpText, 4, argumentCount);
    }

    LuaPlus::LuaObject effectObject(LuaPlus::LuaStackObject(state, 1));
    IEffect* const effect = SCR_FromLua_IEffect(effectObject, state);

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const targetEntity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject targetBoneArg(state, 3);
    const int targetBoneIndex = ENTSCR_ResolveBoneIndex(targetEntity, targetBoneArg, true);

    LuaPlus::LuaStackObject armyArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      armyArg.TypeError("integer");
    }
    (void)lua_tonumber(rawState, 4);

    if (targetBoneIndex == -1) {
      effect->SetEntity(targetEntity);
    } else {
      effect->SetBone(targetEntity, targetBoneIndex);
    }
    return 0;
  }

  /**
   * Address: 0x00670240 (FUN_00670240, cfunc_CreateAttachedEmitter)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateAttachedEmitterL`.
   */
  int cfunc_CreateAttachedEmitter(lua_State* const luaContext)
  {
    return cfunc_CreateAttachedEmitterL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00670260 (FUN_00670260, func_CreateAttachedEmitter_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for
   * `CreateAttachedEmitter`.
   */
  CScrLuaInitForm* func_CreateAttachedEmitter_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateAttachedEmitter",
      &cfunc_CreateAttachedEmitter,
      nullptr,
      "<global>",
      kCreateAttachedEmitterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006702C0 (FUN_006702C0, cfunc_CreateAttachedEmitterL)
   *
   * What it does:
   * Reads `(entity, boneIndexOrName, army, emitterBlueprint)`, resolves the
   * effect manager lane, creates one attached emitter effect, and pushes the
   * resulting Lua object.
   */
  int cfunc_CreateAttachedEmitterL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateAttachedEmitterHelpText, 4, argumentCount);
    }

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, true);

    LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 3));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    LuaPlus::LuaStackObject blueprintArg(state, 4);
    const char* const blueprintName = lua_tostring(rawState, 4);
    if (!blueprintName) {
      blueprintArg.TypeError("string");
    }

    Sim* const sim = ResolveGlobalSim(rawState);
    IEffect* const effect = sim->mEffectManager->CreateAttachedEmitter(entity, boneIndex, blueprintName, armyIndex);
    if (!effect) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00670420 (FUN_00670420, cfunc_CreateTrail)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to `cfunc_CreateTrailL`.
   */
  int cfunc_CreateTrail(lua_State* const luaContext)
  {
    return cfunc_CreateTrailL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00670440 (FUN_00670440, func_CreateTrail_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for `CreateTrail`.
   */
  CScrLuaInitForm* func_CreateTrail_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateTrail",
      &cfunc_CreateTrail,
      nullptr,
      "<global>",
      kCreateTrailHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006704A0 (FUN_006704A0, cfunc_CreateTrailL)
   *
   * What it does:
   * Reads `(entity, boneIndexOrName, army, trailBlueprint)`, resolves the
   * effect manager lane, creates one attached trail effect, and pushes the
   * resulting Lua object.
   */
  int cfunc_CreateTrailL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateTrailHelpText, 4, argumentCount);
    }

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, true);

    LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 3));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    LuaPlus::LuaStackObject blueprintArg(state, 4);
    const char* const blueprintName = lua_tostring(rawState, 4);
    if (!blueprintName) {
      blueprintArg.TypeError("string");
    }

    Sim* const sim = ResolveGlobalSim(rawState);
    IEffect* const effect = sim->mEffectManager->CreateTrail(entity, boneIndex, blueprintName, armyIndex);
    if (!effect) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00670600 (FUN_00670600, cfunc_CreateAttachedBeam)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateAttachedBeamL`.
   */
  int cfunc_CreateAttachedBeam(lua_State* const luaContext)
  {
    return cfunc_CreateAttachedBeamL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00670620 (FUN_00670620, func_CreateAttachedBeam_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for `CreateAttachedBeam`.
   */
  CScrLuaInitForm* func_CreateAttachedBeam_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateAttachedBeam",
      &cfunc_CreateAttachedBeam,
      nullptr,
      "<global>",
      kCreateAttachedBeamHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00670680 (FUN_00670680, cfunc_CreateAttachedBeamL)
   *
   * What it does:
   * Reads `(entity, boneIndexOrName, army, length, thickness, texturePath)`,
   * builds one attached-beam create payload, spawns the effect, and pushes its
   * Lua object on success.
   */
  int cfunc_CreateAttachedBeamL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 6) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateAttachedBeamHelpText, 6, argumentCount);
    }

    SCreateBeamParams params{};
    params.mAttachEntity = nullptr;
    params.mAttachArmyIndex = -1;
    params.mAttachBoneIndex = -1;
    params.mStart = Wm3::Vector3f(0.0f, 0.0f, 0.0f);
    params.mEnd = Wm3::Vector3f(0.0f, 0.0f, 0.0f);
    params.mLifetime = 1.0f;
    params.mWidth = 1.0f;
    params.mTextureScale = 1.0f;
    params.mColorLanes = {1.0f, 1.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    params.mBlendMode = 3;

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    params.mAttachEntity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    params.mAttachBoneIndex = ENTSCR_ResolveBoneIndex(params.mAttachEntity, boneArg, true);

    LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 3));
    params.mAttachArmyIndex = ARMY_IndexFromLuaState(state, armyObject);

    LuaPlus::LuaStackObject lengthArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      lengthArg.TypeError("number");
    }
    params.mTextureScale = static_cast<float>(lua_tonumber(rawState, 4));

    LuaPlus::LuaStackObject thicknessArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      thicknessArg.TypeError("number");
    }
    params.mWidth = static_cast<float>(lua_tonumber(rawState, 5));

    LuaPlus::LuaStackObject textureArg(state, 6);
    const char* const textureName = lua_tostring(rawState, 6);
    if (!textureName) {
      textureArg.TypeError("string");
    }
    params.mTexture.assign_owned(textureName);

    Sim* const sim = ResolveGlobalSim(rawState);
    IEffect* const effect = sim->mEffectManager->CreateBeam(params);
    if (!effect) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006708C0 (FUN_006708C0, cfunc_CreateBeamToEntityBone)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateBeamToEntityBoneL`.
   */
  int cfunc_CreateBeamToEntityBone(lua_State* const luaContext)
  {
    return cfunc_CreateBeamToEntityBoneL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006708E0 (FUN_006708E0, func_CreateBeamToEntityBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for
   * `CreateBeamToEntityBone`.
   */
  CScrLuaInitForm* func_CreateBeamToEntityBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateBeamToEntityBone",
      &cfunc_CreateBeamToEntityBone,
      nullptr,
      "<global>",
      kCreateBeamToEntityBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00670940 (FUN_00670940, cfunc_CreateBeamToEntityBoneL)
   *
   * What it does:
   * Reads `(sourceEntity, sourceBone, targetEntity, targetBone, army,
   * thickness, texture)`, resolves both bone world-space lanes, spawns one
   * beam, and pushes the effect Lua object on success.
   */
  int cfunc_CreateBeamToEntityBoneL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 7) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateBeamToEntityBoneHelpText, 7, argumentCount);
    }

    LuaPlus::LuaObject sourceEntityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const sourceEntity = SCR_FromLua_Entity(sourceEntityObject, state);

    LuaPlus::LuaStackObject sourceBoneArg(state, 2);
    const int sourceBoneIndex = ENTSCR_ResolveBoneIndex(sourceEntity, sourceBoneArg, true);

    LuaPlus::LuaObject targetEntityObject(LuaPlus::LuaStackObject(state, 3));
    Entity* const targetEntity = SCR_FromLua_Entity(targetEntityObject, state);

    LuaPlus::LuaStackObject targetBoneArg(state, 4);
    const int targetBoneIndex = ENTSCR_ResolveBoneIndex(targetEntity, targetBoneArg, true);

    LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 5));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    LuaPlus::LuaStackObject thicknessArg(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      thicknessArg.TypeError("number");
    }
    const float thickness = static_cast<float>(lua_tonumber(rawState, 6));

    LuaPlus::LuaStackObject textureArg(state, 7);
    const char* const textureName = lua_tostring(rawState, 7);
    if (!textureName) {
      textureArg.TypeError("string");
    }

    SCreateBeamParams params{};
    params.mAttachEntity = nullptr;
    params.mAttachArmyIndex = -1;
    params.mAttachBoneIndex = -1;
    params.mStart = Wm3::Vector3f(0.0f, 0.0f, 0.0f);
    params.mEnd = Wm3::Vector3f(0.0f, 0.0f, 0.0f);
    params.mLifetime = 1.0f;
    params.mWidth = 1.0f;
    params.mTextureScale = 1.0f;
    params.mColorLanes = {1.0f, 1.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    params.mBlendMode = 3;

    const VTransform sourceBoneTransform = sourceEntity->GetBoneWorldTransform(sourceBoneIndex);
    params.mStart = sourceBoneTransform.pos_;

    const VTransform targetBoneTransform = targetEntity->GetBoneWorldTransform(targetBoneIndex);
    params.mEnd = targetBoneTransform.pos_;

    params.mWidth = thickness;
    params.mAttachArmyIndex = armyIndex;
    params.mTexture.assign_owned(textureName);

    Sim* const sim = ResolveGlobalSim(rawState);
    IEffect* const effect = sim->mEffectManager->CreateBeam(params);
    if (!effect) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0066F6E0 (FUN_0066F6E0, cfunc_CreateEmitterAtEntity)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateEmitterAtEntityL`.
   */
  int cfunc_CreateEmitterAtEntity(lua_State* const luaContext)
  {
    return cfunc_CreateEmitterAtEntityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066F760 (FUN_0066F760, cfunc_CreateEmitterAtEntityL)
   *
   * What it does:
   * Reads `(entity, army, emitterBlueprint)`, creates one emitter anchored to
   * an entity, and pushes the effect Lua object on success.
   */
  int cfunc_CreateEmitterAtEntityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateEmitterAtEntityHelpText, 3, argumentCount);
    }

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    LuaPlus::LuaStackObject blueprintArg(state, 3);
    const char* const blueprintName = lua_tostring(rawState, 3);
    if (!blueprintName) {
      blueprintArg.TypeError("string");
    }

    Sim* const sim = ResolveGlobalSim(rawState);
    IEffect* const effect = sim->mEffectManager->CreateEmitterAtEntity(entity, blueprintName, armyIndex);
    if (!effect) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0066F700 (FUN_0066F700, func_CreateEmitterAtEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for
   * `CreateEmitterAtEntity`.
   */
  CScrLuaInitForm* func_CreateEmitterAtEntity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateEmitterAtEntity",
      &cfunc_CreateEmitterAtEntity,
      nullptr,
      "<global>",
      kCreateEmitterAtEntityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066F8A0 (FUN_0066F8A0, cfunc_CreateEmitterOnEntity)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateEmitterOnEntityL`.
   */
  int cfunc_CreateEmitterOnEntity(lua_State* const luaContext)
  {
    return cfunc_CreateEmitterOnEntityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066F920 (FUN_0066F920, cfunc_CreateEmitterOnEntityL)
   *
   * What it does:
   * Reads `(entity, army, emitterBlueprint)`, creates one emitter attached to
   * an entity lane, and pushes the effect Lua object on success.
   */
  int cfunc_CreateEmitterOnEntityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateEmitterOnEntityHelpText, 3, argumentCount);
    }

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    LuaPlus::LuaStackObject blueprintArg(state, 3);
    const char* const blueprintName = lua_tostring(rawState, 3);
    if (!blueprintName) {
      blueprintArg.TypeError("string");
    }

    Sim* const sim = ResolveGlobalSim(rawState);
    IEffect* const effect = sim->mEffectManager->CreateEmitterOnEntity(entity, blueprintName, armyIndex);
    if (!effect) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0066F8C0 (FUN_0066F8C0, func_CreateEmitterOnEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for
   * `CreateEmitterOnEntity`.
   */
  CScrLuaInitForm* func_CreateEmitterOnEntity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateEmitterOnEntity",
      &cfunc_CreateEmitterOnEntity,
      nullptr,
      "<global>",
      kCreateEmitterOnEntityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066FA60 (FUN_0066FA60, cfunc_CreateLightParticle)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to `cfunc_CreateLightParticleL`.
   */
  int cfunc_CreateLightParticle(lua_State* const luaContext)
  {
    return cfunc_CreateLightParticleL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066FA80 (FUN_0066FA80, func_CreateLightParticle_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for `CreateLightParticle`.
   */
  CScrLuaInitForm* func_CreateLightParticle_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateLightParticle",
      &cfunc_CreateLightParticle,
      nullptr,
      "<global>",
      kCreateLightParticleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066FAE0 (FUN_0066FAE0, cfunc_CreateLightParticleL)
   *
   * What it does:
   * Reads `(entity, bone, army, size, lifetime, texture, ramp)`, resolves one
   * bone world position lane, and emits one light particle through the active
   * effect manager.
   */
  int cfunc_CreateLightParticleL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 7) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateLightParticleHelpText, 7, argumentCount);
    }

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, true);
    const VTransform boneTransform = entity->GetBoneWorldTransform(boneIndex);
    const Wm3::Vector3f bonePosition = boneTransform.pos_;

    LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 3));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    LuaPlus::LuaStackObject sizeArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      sizeArg.TypeError("number");
    }
    const float size = lua_tonumber(rawState, 4);

    LuaPlus::LuaStackObject lifetimeArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      lifetimeArg.TypeError("number");
    }
    const float lifetime = lua_tonumber(rawState, 5);

    msvc8::string texturePrimary{};
    if (lua_isstring(rawState, 6)) {
      LuaPlus::LuaStackObject textureArg(state, 6);
      const char* const textureName = lua_tostring(rawState, 6);
      if (!textureName) {
        textureArg.TypeError("string");
      }
      texturePrimary.assign_owned(textureName);
    }

    msvc8::string textureSecondary{};
    if (lua_isstring(rawState, 7)) {
      LuaPlus::LuaStackObject rampArg(state, 7);
      const char* const rampName = lua_tostring(rawState, 7);
      if (!rampName) {
        rampArg.TypeError("string");
      }
      textureSecondary.assign_owned(rampName);
    }

    Sim* const sim = ResolveGlobalSim(rawState);
    sim->mEffectManager->CreateLightParticle(bonePosition, texturePrimary, textureSecondary, size, lifetime, armyIndex);
    return 0;
  }

  /**
   * Address: 0x0066FE20 (FUN_0066FE20, cfunc_CreateLightParticleIntel)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateLightParticleIntelL`.
   */
  int cfunc_CreateLightParticleIntel(lua_State* const luaContext)
  {
    return cfunc_CreateLightParticleIntelL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066FE40 (FUN_0066FE40, func_CreateLightParticleIntel_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for
   * `CreateLightParticleIntel`.
   */
  CScrLuaInitForm* func_CreateLightParticleIntel_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateLightParticleIntel",
      &cfunc_CreateLightParticleIntel,
      nullptr,
      "<global>",
      kCreateLightParticleIntelHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066FEA0 (FUN_0066FEA0, cfunc_CreateLightParticleIntelL)
   *
   * What it does:
   * Resolves one `(entity, bone)` world lane and only emits a light particle
   * when the focus army (if any) has LOS detection for that probe position.
   */
  int cfunc_CreateLightParticleIntelL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 7) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateLightParticleIntelHelpText, 7, argumentCount);
    }

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, true);
    const VTransform boneTransform = entity->GetBoneWorldTransform(boneIndex);
    const Wm3::Vector3f bonePosition = boneTransform.pos_;

    LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 3));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    LuaPlus::LuaStackObject sizeArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      sizeArg.TypeError("number");
    }
    const float size = lua_tonumber(rawState, 4);

    LuaPlus::LuaStackObject lifetimeArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      lifetimeArg.TypeError("number");
    }
    const float lifetime = lua_tonumber(rawState, 5);

    msvc8::string texturePrimary{};
    if (lua_isstring(rawState, 6)) {
      LuaPlus::LuaStackObject textureArg(state, 6);
      const char* const textureName = lua_tostring(rawState, 6);
      if (!textureName) {
        textureArg.TypeError("string");
      }
      texturePrimary.assign_owned(textureName);
    }

    msvc8::string textureSecondary{};
    if (lua_isstring(rawState, 7)) {
      LuaPlus::LuaStackObject rampArg(state, 7);
      const char* const rampName = lua_tostring(rawState, 7);
      if (!rampName) {
        rampArg.TypeError("string");
      }
      textureSecondary.assign_owned(rampName);
    }

    Sim* const sim = ResolveGlobalSim(rawState);
    bool emitParticle = true;
    const int focusArmyIndex = sim->mSyncFilter.focusArmy;
    if (focusArmyIndex > -1) {
      CArmyImpl* focusArmy = nullptr;
      CArmyImpl** const armiesBegin = sim->mArmiesList.begin();
      if (armiesBegin != nullptr && focusArmyIndex < static_cast<int>(sim->mArmiesList.size())) {
        focusArmy = armiesBegin[focusArmyIndex];
      }

      CAiReconDBImpl* const reconDb = focusArmy->GetReconDB();
      emitParticle = reconDb->ReconCanDetect(bonePosition, RECON_LOSNow) != RECON_None;
    }

    if (emitParticle) {
      sim->mEffectManager
        ->CreateLightParticle(bonePosition, texturePrimary, textureSecondary, size, lifetime, armyIndex);
    }
    return 0;
  }

  /**
   * Address: 0x00670CF0 (FUN_00670CF0, cfunc_CreateEmitterAtBone)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateEmitterAtBoneL`.
   */
  int cfunc_CreateEmitterAtBone(lua_State* const luaContext)
  {
    return cfunc_CreateEmitterAtBoneL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00670D70 (FUN_00670D70, cfunc_CreateEmitterAtBoneL)
   *
   * What it does:
   * Reads `(entity, boneIndexOrName, army, emitterBlueprint)`, resolves one
   * effect manager lane, creates one emitter-at-bone effect, and pushes the
   * resulting Lua object.
   */
  int cfunc_CreateEmitterAtBoneL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateEmitterAtBoneHelpText, 4, argumentCount);
    }

    LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, true);

    LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 3));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    LuaPlus::LuaStackObject blueprintArg(state, 4);
    const char* const blueprintName = lua_tostring(rawState, 4);
    if (!blueprintName) {
      blueprintArg.TypeError("string");
    }

    Sim* const sim = ResolveGlobalSim(rawState);
    IEffect* const effect = sim->mEffectManager->CreateEmitterAtBone(entity, boneIndex, blueprintName, armyIndex);
    if (!effect) {
      return 0;
    }

    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00670D10 (FUN_00670D10, func_CreateEmitterAtBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for
   * `CreateEmitterAtBone`.
   */
  CScrLuaInitForm* func_CreateEmitterAtBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateEmitterAtBone",
      &cfunc_CreateEmitterAtBone,
      nullptr,
      "<global>",
      kCreateEmitterAtBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066D860 (FUN_0066D860, cfunc_IEffectSetBeamParam)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_IEffectSetBeamParamL`.
   */
  int cfunc_IEffectSetBeamParam(lua_State* const luaContext)
  {
    return cfunc_IEffectSetBeamParamL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066D8E0 (FUN_0066D8E0, cfunc_IEffectSetBeamParamL)
   *
   * What it does:
   * Validates `IEffect:SetBeamParam(name, value)`, resolves one `EBeamParam`
   * token from arg #2, and applies arg #3 as float through the shared
   * named-param lane.
   */
  int cfunc_IEffectSetBeamParamL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIEffectSetBeamParamHelpText, 3, argumentCount);
    }

    return ApplyIEffectNamedFloatParam(state, ResolveEBeamParamType());
  }

  /**
   * Address: 0x0066D880 (FUN_0066D880, func_IEffectSetBeamParam_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IEffect:SetBeamParam` Lua binder definition in the sim
   * init-form set.
   */
  CScrLuaInitForm* func_IEffectSetBeamParam_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetBeamParam",
      &cfunc_IEffectSetBeamParam,
      nullptr,
      "IEffect",
      kIEffectSetBeamParamHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066D940 (FUN_0066D940, cfunc_IEffectSetEmitterParam)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_IEffectSetEmitterParamL`.
   */
  int cfunc_IEffectSetEmitterParam(lua_State* const luaContext)
  {
    return cfunc_IEffectSetEmitterParamL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066D9C0 (FUN_0066D9C0, cfunc_IEffectSetEmitterParamL)
   *
   * What it does:
   * Validates `IEffect:SetEmitterParam(name, value)`, resolves one
   * `EEmitterParam` token from arg #2, and applies arg #3 as float through the
   * shared named-param lane.
   */
  int cfunc_IEffectSetEmitterParamL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIEffectSetEmitterParamHelpText, 3, argumentCount);
    }

    return ApplyIEffectNamedFloatParam(state, ResolveEEmitterParamType());
  }

  /**
   * Address: 0x0066D960 (FUN_0066D960, func_IEffectSetEmitterParam_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IEffect:SetEmitterParam` Lua binder definition in the sim
   * init-form set.
   */
  CScrLuaInitForm* func_IEffectSetEmitterParam_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetEmitterParam",
      &cfunc_IEffectSetEmitterParam,
      nullptr,
      "IEffect",
      kIEffectSetEmitterParamHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066DA20 (FUN_0066DA20, cfunc_IEffectScaleEmitter)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_IEffectScaleEmitterL`.
   */
  int cfunc_IEffectScaleEmitter(lua_State* const luaContext)
  {
    return cfunc_IEffectScaleEmitterL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066DAA0 (FUN_0066DAA0, cfunc_IEffectScaleEmitterL)
   *
   * What it does:
   * Validates `IEffect:ScaleEmitter(scale)`, writes the numeric scale value to
   * emitter-float parameter lane `18`, and returns the effect Lua object for
   * chaining.
   */
  int cfunc_IEffectScaleEmitterL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIEffectScaleEmitterHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject effectObject(LuaPlus::LuaStackObject(state, 1));
    IEffect* const effect = SCR_FromLua_IEffectOpt(effectObject, state);
    if (!effect) {
      return 1;
    }

    LuaPlus::LuaStackObject scaleArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      scaleArg.TypeError("number");
    }

    const float scale = lua_tonumber(state->m_state, 2);
    effect->SetFloatParam(18, scale);
    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0066DBA0 (FUN_0066DBA0, cfunc_IEffectResizeEmitterCurve)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_IEffectResizeEmitterCurveL`.
   */
  int cfunc_IEffectResizeEmitterCurve(lua_State* const luaContext)
  {
    return cfunc_IEffectResizeEmitterCurveL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066DC20 (FUN_0066DC20, cfunc_IEffectResizeEmitterCurveL)
   *
   * What it does:
   * Validates `IEffect:ResizeEmitterCurve(name, newTicks)`, resolves one
   * `EEmitterCurve` lane by name, rescales all key X positions from `[0,old]`
   * to `[0,newTicks]`, recomputes Y bounds, writes the curve back, and returns
   * the effect Lua object for chaining.
   */
  int cfunc_IEffectResizeEmitterCurveL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIEffectResizeEmitterCurveHelpText, 3, argumentCount);
    }

    lua_State* const rawState = state->m_state;
    LuaPlus::LuaObject effectObject(LuaPlus::LuaStackObject(state, 1));
    IEffect* const effect = SCR_FromLua_IEffectOpt(effectObject, state);
    if (!effect) {
      return 1;
    }

    LuaPlus::LuaStackObject curveNameArg(state, 2);
    const char* const curveName = lua_tostring(rawState, 2);
    if (!curveName) {
      curveNameArg.TypeError("string");
    }

    const int curveParamIndex = ResolveEmitterCurveParamIndexOrThrow(rawState, curveName);
    LuaPlus::LuaStackObject newCurveLengthArg(state, 3);
    const float newCurveLength = newCurveLengthArg.GetNumber();

    SEfxCurve curve = *ResolveCurveStorage(effect->GetCurveParam(curveParamIndex));
    const float oldCurveLength = curve.mBoundsMax.x - curve.mBoundsMin.x;
    const float xScale = (newCurveLength - 0.0f) / oldCurveLength;
    for (Wm3::Vector3f* key = curve.mKeys.begin(); key != curve.mKeys.end(); ++key) {
      key->x *= xScale;
    }

    curve.mBoundsMin.x = 0.0f;
    curve.mBoundsMax.x = newCurveLength;
    RecomputeEmitterCurveYBounds(curve);
    effect->SetCurveParam(curveParamIndex, &curve);
    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0066DE70 (FUN_0066DE70, cfunc_IEffectSetEmitterCurveParam)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_IEffectSetEmitterCurveParamL`.
   */
  int cfunc_IEffectSetEmitterCurveParam(lua_State* const luaContext)
  {
    return cfunc_IEffectSetEmitterCurveParamL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066DEF0 (FUN_0066DEF0, cfunc_IEffectSetEmitterCurveParamL)
   *
   * What it does:
   * Validates `IEffect:SetEmitterCurveParam(name, height, size)`, resolves one
   * `EEmitterCurve` lane by name, builds a one-key curve `(x=0,height,size)`,
   * writes it to the effect, and returns the effect Lua object for chaining.
   */
  int cfunc_IEffectSetEmitterCurveParamL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIEffectSetEmitterCurveParamHelpText, 4, argumentCount);
    }

    lua_State* const rawState = state->m_state;
    LuaPlus::LuaObject effectObject(LuaPlus::LuaStackObject(state, 1));
    IEffect* const effect = SCR_FromLua_IEffectOpt(effectObject, state);
    if (!effect) {
      return 1;
    }

    LuaPlus::LuaStackObject curveNameArg(state, 2);
    const char* const curveName = lua_tostring(rawState, 2);
    if (!curveName) {
      curveNameArg.TypeError("string");
    }

    const int curveParamIndex = ResolveEmitterCurveParamIndexOrThrow(rawState, curveName);

    LuaPlus::LuaStackObject heightArg(state, 3);
    const float height = heightArg.GetNumber();

    LuaPlus::LuaStackObject sizeArg(state, 4);
    const float size = sizeArg.GetNumber();

    SEfxCurve curve{};
    const Wm3::Vector3f key{0.0f, height, size};
    InsertEmitterCurveKeySortedByX(curve, key);
    effect->SetCurveParam(curveParamIndex, &curve);
    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0066E150 (FUN_0066E150, cfunc_IEffectOffsetEmitter)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_IEffectOffsetEmitterL`.
   */
  int cfunc_IEffectOffsetEmitter(lua_State* const luaContext)
  {
    return cfunc_IEffectOffsetEmitterL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066E1D0 (FUN_0066E1D0, cfunc_IEffectOffsetEmitterL)
   *
   * What it does:
   * Validates `IEffect:OffsetEmitter(x,y,z)`, adds the numeric deltas to
   * current float params `(0,1,2)`, writes the updated vector through
   * `SetNParam(0, ..., 3)`, and returns the effect Lua object for chaining.
   */
  int cfunc_IEffectOffsetEmitterL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIEffectOffsetEmitterHelpText, 4, argumentCount);
    }

    lua_State* const rawState = state->m_state;
    LuaPlus::LuaObject effectObject(LuaPlus::LuaStackObject(state, 1));
    IEffect* const effect = SCR_FromLua_IEffectOpt(effectObject, state);
    if (!effect) {
      return 1;
    }

    LuaPlus::LuaStackObject xArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      xArg.TypeError("number");
    }
    float x = lua_tonumber(rawState, 2);

    LuaPlus::LuaStackObject yArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      yArg.TypeError("number");
    }
    float y = lua_tonumber(rawState, 3);

    LuaPlus::LuaStackObject zArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      zArg.TypeError("number");
    }
    float z = lua_tonumber(rawState, 4);

    x += effect->GetFloatParam(0);
    y += effect->GetFloatParam(1);
    z += effect->GetFloatParam(2);

    const float values[3] = {x, y, z};
    effect->SetNParam(0, values, 3);
    effect->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0066E3A0 (FUN_0066E3A0, cfunc_IEffectDestroy)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to `cfunc_IEffectDestroyL`.
   */
  int cfunc_IEffectDestroy(lua_State* const luaContext)
  {
    return cfunc_IEffectDestroyL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066E420 (FUN_0066E420, cfunc_IEffectDestroyL)
   *
   * What it does:
   * Validates `IEffect:Destroy()`, resolves one optional effect object, and
   * dispatches destroy through the owning effect manager.
   */
  int cfunc_IEffectDestroyL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIEffectDestroyHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject effectObject(LuaPlus::LuaStackObject(state, 1));
    IEffect* const effect = SCR_FromLua_IEffectOpt(effectObject, state);
    if (effect) {
      Sim* const sim = ResolveGlobalSim(state->m_state);
      if (sim != nullptr && sim->mEffectManager != nullptr) {
        sim->mEffectManager->DestroyEffect(effect);
      }
    }
    return 0;
  }

  /**
   * Address: 0x0066E4D0 (FUN_0066E4D0, cfunc_CDecalHandleDestroy)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CDecalHandleDestroyL`.
   */
  int cfunc_CDecalHandleDestroy(lua_State* const luaContext)
  {
    return cfunc_CDecalHandleDestroyL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066E550 (FUN_0066E550, cfunc_CDecalHandleDestroyL)
   *
   * What it does:
   * Validates `CDecalHandle:Destroy()`, resolves one optional decal handle,
   * and destroys it through the sim-owned decal buffer lane.
   */
  int cfunc_CDecalHandleDestroyL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCDecalHandleDestroyHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject decalHandleObject(LuaPlus::LuaStackObject(state, 1));
    CDecalHandle* const decalHandle = SCR_FromLua_CDecalHandleOpt(decalHandleObject, state);
    if (decalHandle) {
      Sim* const sim = lua_getglobaluserdata(state->m_state);
      sim->mDecalBuffer->DestroyHandle(decalHandle);
    }
    return 0;
  }

  /**
   * Address: 0x0066DA40 (FUN_0066DA40, func_IEffectScaleEmitter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IEffect:ScaleEmitter` Lua binder definition in the sim
   * init-form set.
   */
  CScrLuaInitForm* func_IEffectScaleEmitter_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "ScaleEmitter",
      &cfunc_IEffectScaleEmitter,
      nullptr,
      "IEffect",
      kIEffectScaleEmitterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066DBC0 (FUN_0066DBC0, func_IEffectResizeEmitterCurve_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IEffect:ResizeEmitterCurve` Lua binder definition in the
   * sim init-form set.
   */
  CScrLuaInitForm* func_IEffectResizeEmitterCurve_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "ResizeEmitterCurve",
      &cfunc_IEffectResizeEmitterCurve,
      nullptr,
      "IEffect",
      kIEffectResizeEmitterCurveHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066DE90 (FUN_0066DE90, func_IEffectSetEmitterCurveParam_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IEffect:SetEmitterCurveParam` Lua binder definition in the
   * sim init-form set.
   */
  CScrLuaInitForm* func_IEffectSetEmitterCurveParam_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetEmitterCurveParam",
      &cfunc_IEffectSetEmitterCurveParam,
      nullptr,
      "IEffect",
      kIEffectSetEmitterCurveParamHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066E170 (FUN_0066E170, func_IEffectOffsetEmitter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IEffect:OffsetEmitter` Lua binder definition in the sim
   * init-form set.
   */
  CScrLuaInitForm* func_IEffectOffsetEmitter_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "OffsetEmitter",
      &cfunc_IEffectOffsetEmitter,
      nullptr,
      "IEffect",
      kIEffectOffsetEmitterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066E3C0 (FUN_0066E3C0, func_IEffectDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IEffect:Destroy` Lua binder definition in the sim init-form
   * set.
   */
  CScrLuaInitForm* func_IEffectDestroy_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Destroy",
      &cfunc_IEffectDestroy,
      nullptr,
      "IEffect",
      kIEffectDestroyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066E4F0 (FUN_0066E4F0, func_CDecalHandleDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CDecalHandle:Destroy()` Lua binder definition in the sim
   * init-form set.
   */
  CScrLuaInitForm* func_CDecalHandleDestroy_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Destroy",
      &cfunc_CDecalHandleDestroy,
      &CScrLuaMetatableFactory<CDecalHandle>::Instance(),
      "CDecalHandle",
      kCDecalHandleDestroyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066E610 (FUN_0066E610, cfunc_CreateDecal)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to `cfunc_CreateDecalL`.
   */
  int cfunc_CreateDecal(lua_State* const luaContext)
  {
    return cfunc_CreateDecalL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066E630 (FUN_0066E630, func_CreateDecal_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for `CreateDecal`.
   */
  CScrLuaInitForm* func_CreateDecal_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateDecal",
      &cfunc_CreateDecal,
      nullptr,
      "<global>",
      kCreateDecalHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066E690 (FUN_0066E690, cfunc_CreateDecalL)
   *
   * What it does:
   * Reads decal construction arguments from Lua, creates one tracked decal
   * handle in the sim decal buffer, and returns the handle Lua object (or nil).
   */
  int cfunc_CreateDecalL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 9 || argumentCount > 11) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgRangeWarning, kCreateDecalHelpText, 9, 11, argumentCount);
    }
    lua_settop(rawState, 11);

    const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 1));
    const Wm3::Vec3f position = SCR_FromLuaCopy<Wm3::Vec3f>(positionObject);

    LuaPlus::LuaStackObject headingArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      headingArg.TypeError("number");
    }
    const float heading = lua_tonumber(rawState, 2);

    LuaPlus::LuaStackObject primaryTextureArg(state, 3);
    const char* const primaryTexture = lua_tostring(rawState, 3);
    if (primaryTexture == nullptr) {
      primaryTextureArg.TypeError("string");
    }
    msvc8::string textureNamePrimary{};
    textureNamePrimary.assign_owned(primaryTexture);

    LuaPlus::LuaStackObject secondaryTextureArg(state, 4);
    const char* const secondaryTexture = lua_tostring(rawState, 4);
    if (secondaryTexture == nullptr) {
      secondaryTextureArg.TypeError("string");
    }
    msvc8::string textureNameSecondary{};
    textureNameSecondary.assign_owned(secondaryTexture);

    LuaPlus::LuaStackObject typeArg(state, 5);
    const char* const typeNameRaw = lua_tostring(rawState, 5);
    if (typeNameRaw == nullptr) {
      typeArg.TypeError("string");
    }
    msvc8::string typeName{};
    typeName.assign_owned(typeNameRaw);

    LuaPlus::LuaStackObject sizeXArg(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      sizeXArg.TypeError("number");
    }
    const float sizeX = lua_tonumber(rawState, 6);

    LuaPlus::LuaStackObject sizeZArg(state, 7);
    if (lua_type(rawState, 7) != LUA_TNUMBER) {
      sizeZArg.TypeError("number");
    }
    const float sizeZ = lua_tonumber(rawState, 7);
    const Wm3::Vec3f size{sizeX, 1.0f, sizeZ};

    LuaPlus::LuaStackObject lodArg(state, 8);
    if (lua_type(rawState, 8) != LUA_TNUMBER) {
      lodArg.TypeError("number");
    }
    const float lodParam = lua_tonumber(rawState, 8);

    LuaPlus::LuaStackObject durationArg(state, 9);
    if (lua_type(rawState, 9) != LUA_TNUMBER) {
      durationArg.TypeError("number");
    }
    const float duration = lua_tonumber(rawState, 9);

    const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 10));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    std::uint32_t fidelity = 1u;
    if (lua_type(rawState, 11) != LUA_TNIL) {
      LuaPlus::LuaStackObject fidelityArg(state, 11);
      if (lua_type(rawState, 11) != LUA_TNUMBER) {
        fidelityArg.TypeError("integer");
      }
      fidelity = static_cast<std::uint32_t>(lua_tonumber(rawState, 11));
    }

    const VTransform transform = BuildHeadingTransform(position, heading);
    Sim* const sim = ResolveGlobalSim(rawState);
    CDecalHandle* const handle = CreateDecalFromTransform(
      transform,
      size,
      sim,
      duration,
      textureNamePrimary,
      textureNameSecondary,
      lodParam,
      false,
      typeName,
      static_cast<std::uint32_t>(armyIndex),
      fidelity
    );

    if (handle != nullptr) {
      handle->mLuaObj.PushStack(state);
      return 1;
    }

    gpg::Warnf("Failed to create a %s decal", textureNamePrimary.raw_data_unsafe());
    lua_pushnil(rawState);
    return 1;
  }

  /**
   * Address: 0x0066EC10 (FUN_0066EC10, cfunc_CreateSplat)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to `cfunc_CreateSplatL`.
   */
  int cfunc_CreateSplat(lua_State* const luaContext)
  {
    return cfunc_CreateSplatL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066EC30 (FUN_0066EC30, func_CreateSplat_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for `CreateSplat`.
   */
  CScrLuaInitForm* func_CreateSplat_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateSplat",
      &cfunc_CreateSplat,
      nullptr,
      "<global>",
      kCreateSplatHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066EC90 (FUN_0066EC90, cfunc_CreateSplatL)
   *
   * What it does:
   * Reads splat parameters from Lua and enqueues one non-handle splat decal in
   * the active sim decal buffer.
   */
  int cfunc_CreateSplatL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 8 || argumentCount > 9) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgRangeWarning, kCreateSplatHelpText, 8, 9, argumentCount);
    }
    lua_settop(rawState, 9);

    const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 1));
    const Wm3::Vec3f position = SCR_FromLuaCopy<Wm3::Vec3f>(positionObject);

    LuaPlus::LuaStackObject headingArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      headingArg.TypeError("number");
    }
    const float heading = lua_tonumber(rawState, 2);

    LuaPlus::LuaStackObject textureArg(state, 3);
    const char* const textureNameRaw = lua_tostring(rawState, 3);
    if (textureNameRaw == nullptr) {
      textureArg.TypeError("string");
    }
    msvc8::string textureNamePrimary{};
    textureNamePrimary.assign_owned(textureNameRaw);

    LuaPlus::LuaStackObject sizeXArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      sizeXArg.TypeError("number");
    }
    const float sizeX = lua_tonumber(rawState, 4);

    LuaPlus::LuaStackObject sizeZArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      sizeZArg.TypeError("number");
    }
    const float sizeZ = lua_tonumber(rawState, 5);
    const Wm3::Vec3f size{sizeX, 1.0f, sizeZ};

    LuaPlus::LuaStackObject lodArg(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      lodArg.TypeError("number");
    }
    const float lodParam = lua_tonumber(rawState, 6);

    LuaPlus::LuaStackObject durationArg(state, 7);
    if (lua_type(rawState, 7) != LUA_TNUMBER) {
      durationArg.TypeError("number");
    }
    const float duration = lua_tonumber(rawState, 7);

    const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 8));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    std::uint32_t fidelity = 1u;
    if (lua_type(rawState, 9) != LUA_TNIL) {
      LuaPlus::LuaStackObject fidelityArg(state, 9);
      if (lua_type(rawState, 9) != LUA_TNUMBER) {
        fidelityArg.TypeError("integer");
      }
      fidelity = static_cast<std::uint32_t>(lua_tonumber(rawState, 9));
    }

    const VTransform transform = BuildHeadingTransform(position, heading);
    const msvc8::string textureNameSecondary{};
    const msvc8::string typeName{};

    Sim* const sim = ResolveGlobalSim(rawState);
    (void)CreateDecalFromTransform(
      transform,
      size,
      sim,
      duration,
      textureNamePrimary,
      textureNameSecondary,
      lodParam,
      true,
      typeName,
      static_cast<std::uint32_t>(armyIndex),
      fidelity
    );
    return 0;
  }

  /**
   * Address: 0x0066F1A0 (FUN_0066F1A0, cfunc_CreateSplatOnBone)
   *
   * What it does:
   * Unwraps the Lua callback context and forwards to
   * `cfunc_CreateSplatOnBoneL`.
   */
  int cfunc_CreateSplatOnBone(lua_State* const luaContext)
  {
    return cfunc_CreateSplatOnBoneL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0066F1C0 (FUN_0066F1C0, func_CreateSplatOnBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the global sim-lane binder definition for `CreateSplatOnBone`.
   */
  CScrLuaInitForm* func_CreateSplatOnBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateSplatOnBone",
      &cfunc_CreateSplatOnBone,
      nullptr,
      "<global>",
      kCreateSplatOnBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0066F220 (FUN_0066F220, cfunc_CreateSplatOnBoneL)
   *
   * What it does:
   * Builds one splat transform from entity bone world transform plus optional
   * local offset, then enqueues one splat decal in the sim decal buffer.
   */
  int cfunc_CreateSplatOnBoneL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 9) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateSplatOnBoneHelpText, 9, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    Entity* const entity = SCR_FromLua_Entity(entityObject, state);

    Wm3::Vec3f localOffset{0.0f, 0.0f, 0.0f};
    if (lua_type(rawState, 2) != LUA_TNIL) {
      const LuaPlus::LuaObject offsetObject(LuaPlus::LuaStackObject(state, 2));
      localOffset = SCR_FromLuaCopy<Wm3::Vec3f>(offsetObject);
    }

    LuaPlus::LuaStackObject boneArg(state, 3);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, true);

    LuaPlus::LuaStackObject textureArg(state, 4);
    const char* const textureNameRaw = lua_tostring(rawState, 4);
    if (textureNameRaw == nullptr) {
      textureArg.TypeError("string");
    }
    msvc8::string textureNamePrimary{};
    textureNamePrimary.assign_owned(textureNameRaw);

    LuaPlus::LuaStackObject sizeXArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      sizeXArg.TypeError("number");
    }
    const float sizeX = lua_tonumber(rawState, 5);

    LuaPlus::LuaStackObject sizeZArg(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      sizeZArg.TypeError("number");
    }
    const float sizeZ = lua_tonumber(rawState, 6);
    const Wm3::Vec3f size{sizeX, 1.0f, sizeZ};

    LuaPlus::LuaStackObject lodArg(state, 7);
    if (lua_type(rawState, 7) != LUA_TNUMBER) {
      lodArg.TypeError("number");
    }
    const float lodParam = lua_tonumber(rawState, 7);

    LuaPlus::LuaStackObject durationArg(state, 8);
    if (lua_type(rawState, 8) != LUA_TNUMBER) {
      durationArg.TypeError("number");
    }
    const float duration = lua_tonumber(rawState, 8);

    const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 9));
    const int armyIndex = ARMY_IndexFromLuaState(state, armyObject);

    VTransform transform = entity->GetBoneWorldTransform(boneIndex);
    const Wm3::Vec3f worldOffset = transform.orient_.Rotate(localOffset);
    transform.pos_.x += worldOffset.x;
    transform.pos_.y += worldOffset.y;
    transform.pos_.z += worldOffset.z;

    const msvc8::string textureNameSecondary{};
    const msvc8::string typeName{};

    Sim* const sim = ResolveGlobalSim(rawState);
    (void)CreateDecalFromTransform(
      transform,
      size,
      sim,
      duration,
      textureNamePrimary,
      textureNameSecondary,
      lodParam,
      true,
      typeName,
      static_cast<std::uint32_t>(armyIndex),
      1u
    );
    return 0;
  }

  /**
   * Address: 0x00BD3EF0 (FUN_00BD3EF0, register_TConVar_dbg_EfxBeams)
   *
   * What it does:
   * Registers startup `dbg_EfxBeams` convar and installs process-exit teardown.
   */
  void register_TConVar_dbg_EfxBeams()
  {
    RegisterConCommand(GetDbgEfxBeamsConVar());
    RegisterAtexitCleanup<&cleanup_TConVar_dbg_EfxBeams_atexit>();
  }

  /**
   * Address: 0x00BD4210 (FUN_00BD4210, register_TConVar_efx_WaterOffset)
   *
   * What it does:
   * Registers startup `efx_WaterOffset` convar and installs process-exit teardown.
   */
  void register_TConVar_efx_WaterOffset()
  {
    RegisterConCommand(GetEfxWaterOffsetConVar());
    RegisterAtexitCleanup<&cleanup_TConVar_efx_WaterOffset_atexit>();
  }

  /**
   * Address: 0x00BD4250 (FUN_00BD4250, register_TConVar_dbg_Emitter)
   *
   * What it does:
   * Registers startup `dbg_Emitter` convar and installs process-exit teardown.
   */
  void register_TConVar_dbg_Emitter()
  {
    RegisterConCommand(GetDbgEmitterConVar());
    RegisterAtexitCleanup<&cleanup_TConVar_dbg_Emitter_atexit>();
  }

  /**
   * Address: 0x00BFB940 (FUN_00BFB940, cleanup_AddBeam_ConAlias)
   *
   * What it does:
   * Clears startup-owned `AddBeam` alias payload and unregisters command
   * binding.
   */
  void cleanup_AddBeam_ConAlias()
  {
    ConAlias_AddBeam().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD3FE0 (FUN_00BD3FE0, register_AddBeam_ConAliasDef)
   *
   * What it does:
   * Registers the `AddBeam` alias and arms startup teardown.
   */
  void register_AddBeam_ConAliasDef()
  {
    ConAlias_AddBeam().InitializeRecovered(
      "Add a test beam into the world",
      "AddBeam",
      "DoSimCommand AddBeam"
    );
    RegisterAtexitCleanup<&cleanup_AddBeam_ConAlias>();
  }

  /**
   * Address: 0x00657170 (FUN_00657170, func_AddBeam_SimConFunc)
   *
   * What it does:
   * Captures a start point on first call, then spawns one debug beam on second
   * call using optional `width`, `texture`, and `lifetime` command args.
   */
  int ExecuteAddBeamSimCommand(
    Sim* const sim,
    CSimConCommand::ParsedCommandArgs* const commandArgs,
    Wm3::Vector3f* const worldPos,
    CArmyImpl* const focusArmy,
    SEntitySetTemplateUnit* const selectedUnits
  )
  {
    (void)focusArmy;
    (void)selectedUnits;

    if (!worldPos || !Wm3::Vector3f::IsntNaN(worldPos)) {
      return 0;
    }

    if (gAddBeamCaptureStartPending) {
      gAddBeamStartPoint = *worldPos;
      gAddBeamCaptureStartPending = false;
      return 0;
    }

    float width = 1.0f;
    float lifetime = 2.0f;
    std::string texture{};

    if (commandArgs && commandArgs->size() > 1u) {
      for (std::size_t i = 1u; i < commandArgs->size(); ++i) {
        const std::string& key = commandArgs->at(i);
        const std::string* const value = (i + 1u < commandArgs->size()) ? &commandArgs->at(i + 1u) : nullptr;
        if (!value) {
          continue;
        }

        if (key == "width") {
          width = static_cast<float>(std::atof(value->c_str()));
        } else if (key == "texture") {
          texture = *value;
        } else if (key == "lifetime") {
          lifetime = static_cast<float>(std::atof(value->c_str()));
        }
      }
    }

    if (sim && sim->mEffectManager) {
      SCreateBeamParams params{};
      params.mAttachEntity = nullptr;
      params.mAttachArmyIndex = -1;
      params.mAttachBoneIndex = -1;
      params.mStart = gAddBeamStartPoint;
      params.mEnd = *worldPos;
      params.mLifetime = lifetime;
      params.mWidth = width;
      params.mTextureScale = 1.0f;
      if (!texture.empty()) {
        params.mTexture.assign_owned(texture.c_str());
      }
      params.mColorLanes = {1.0f, 1.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f};
      params.mBlendMode = 3;
      sim->mEffectManager->CreateBeam(params);
    }

    gAddBeamCaptureStartPending = true;
    return 0;
  }

  /**
   * Address: 0x00BFB990 (FUN_00BFB990, cleanup_AddBeam_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `AddBeam` sim-console callback storage.
   */
  void cleanup_AddBeam_SimConFunc()
  {
    if (!gSimConFunc_AddBeamConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(SimConFunc_AddBeam()).~CSimConCommand();
    gSimConFunc_AddBeamConstructed = false;
  }

  /**
   * Address: 0x00BD4010 (FUN_00BD4010, register_AddBeam_SimConFuncDef)
   *
   * What it does:
   * Registers the `AddBeam` sim-console callback and arms startup teardown.
   */
  void register_AddBeam_SimConFuncDef()
  {
    (void)ConstructSimConFunc_AddBeam();
    RegisterAtexitCleanup<&cleanup_AddBeam_SimConFunc>();
  }

  /**
   * Address: 0x00BD3F90 (FUN_00BD3F90, register_CreateBeamEmitter_LuaFuncDef)
   */
  CScrLuaInitForm* register_CreateBeamEmitter_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateBeamEmitter_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3FA0 (FUN_00BD3FA0, j_func_CreateBeamEmitterOnEntity_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateBeamEmitterOnEntity_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateBeamEmitterOnEntity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3FB0 (FUN_00BD3FB0, register_CreateBeamEntityToEntity_LuaFuncDef)
   */
  CScrLuaInitForm* register_CreateBeamEntityToEntity_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateBeamEntityToEntity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3FC0 (FUN_00BD3FC0, j_func_AttachBeamEntityToEntity_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_AttachBeamEntityToEntity_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_AttachBeamEntityToEntity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3FD0 (FUN_00BD3FD0, register_AttachBeamToEntity_LuaFuncDef)
   */
  CScrLuaInitForm* register_AttachBeamToEntity_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_AttachBeamToEntity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BFBDE0 (FUN_00BFBDE0, cleanup_efx_NewEmitter_ConAlias)
   *
   * What it does:
   * Clears startup-owned `efx_NewEmitter` alias payload and unregisters command
   * binding.
   */
  void cleanup_efx_NewEmitter_ConAlias()
  {
    ConAlias_efx_NewEmitter().ShutdownRecovered();
  }

  /**
   * Address: 0x00BFBE30 (FUN_00BFBE30, cleanup_efx_NewEmitter_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `efx_NewEmitter` sim-console callback storage.
   */
  void cleanup_efx_NewEmitter_SimConFunc()
  {
    if (!gSimConFunc_efx_NewEmitterConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(SimConFunc_efx_NewEmitter()).~CSimConCommand();
    gSimConFunc_efx_NewEmitterConstructed = false;
  }

  /**
   * Address: 0x00BD4350 (FUN_00BD4350, register_efx_NewEmitter_ConAliasDef)
   *
   * What it does:
   * Registers the `efx_NewEmitter` alias and arms startup teardown.
   */
  void register_efx_NewEmitter_ConAliasDef()
  {
    ConAlias_efx_NewEmitter().InitializeRecovered(
      "Create an emitter, must specify blueprint",
      "efx_NewEmitter",
      "DoSimCommand efx_NewEmitter"
    );
    RegisterAtexitCleanup<&cleanup_efx_NewEmitter_ConAlias>();
  }

  /**
   * Address: 0x00BD4380 (FUN_00BD4380, register_efx_NewEmitter_SimConFuncDef)
   *
   * What it does:
   * Registers the `efx_NewEmitter` sim-console callback and arms startup teardown.
   */
  void register_efx_NewEmitter_SimConFuncDef()
  {
    (void)ConstructSimConFunc_efx_NewEmitter();
    RegisterAtexitCleanup<&cleanup_efx_NewEmitter_SimConFunc>();
  }

  /**
   * Address: 0x00BFBE40 (FUN_00BFBE40, cleanup_efx_AttachEmitter_ConAlias)
   *
   * What it does:
   * Clears startup-owned `efx_AttachEmitter` alias payload and unregisters command
   * binding.
   */
  void cleanup_efx_AttachEmitter_ConAlias()
  {
    ConAlias_efx_AttachEmitter().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD43C0 (FUN_00BD43C0, register_efx_AttachEmitter_ConAliasDef)
   *
   * What it does:
   * Registers the `efx_AttachEmitter` alias and arms startup teardown.
   */
  void register_efx_AttachEmitter_ConAliasDef()
  {
    ConAlias_efx_AttachEmitter().InitializeRecovered(
      "Attach an emitter to selected unit, must specify bone name and blueprint",
      "efx_AttachEmitter",
      "DoSimCommand efx_AttachEmitter"
    );
    RegisterAtexitCleanup<&cleanup_efx_AttachEmitter_ConAlias>();
  }

  /**
   * Address: 0x00BFBE90 (FUN_00BFBE90, cleanup_efx_AttachEmitter_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `efx_AttachEmitter` sim-console callback storage.
   */
  void cleanup_efx_AttachEmitter_SimConFunc()
  {
    if (!gSimConFunc_efx_AttachEmitterConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(SimConFunc_efx_AttachEmitter()).~CSimConCommand();
    gSimConFunc_efx_AttachEmitterConstructed = false;
  }

  /**
   * Address: 0x00BD43F0 (FUN_00BD43F0, register_efx_AttachEmitter_SimConFuncDef)
   *
   * What it does:
   * Registers the `efx_AttachEmitter` sim-console callback and arms startup
   * teardown.
   */
  void register_efx_AttachEmitter_SimConFuncDef()
  {
    (void)ConstructSimConFunc_efx_AttachEmitter();
    RegisterAtexitCleanup<&cleanup_efx_AttachEmitter_SimConFunc>();
  }

  /**
   * Address: 0x00BFC090 (FUN_00BFC090, cleanup_AddLightParticle_ConAlias)
   *
   * What it does:
   * Clears startup-owned `AddLightParticle` alias payload and unregisters command
   * binding.
   */
  void cleanup_AddLightParticle_ConAlias()
  {
    ConAlias_AddLightParticle().ShutdownRecovered();
  }

  /**
   * Address: 0x00BFC0E0 (FUN_00BFC0E0, cleanup_AddLightParticle_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `AddLightParticle` sim-console callback storage.
   */
  void cleanup_AddLightParticle_SimConFunc()
  {
    if (!gSimConFunc_AddLightParticleConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(SimConFunc_AddLightParticle()).~CSimConCommand();
    gSimConFunc_AddLightParticleConstructed = false;
  }

  /**
   * Address: 0x00BD4640 (FUN_00BD4640, register_AddLightParticle_ConAliasDef)
   *
   * What it does:
   * Registers the `AddLightParticle` alias and arms startup teardown.
   */
  void register_AddLightParticle_ConAliasDef()
  {
    ConAlias_AddLightParticle().InitializeRecovered(
      "Add a light to the world under the cursor",
      "AddLightParticle",
      "DoSimCommand AddLightParticle"
    );
    RegisterAtexitCleanup<&cleanup_AddLightParticle_ConAlias>();
  }

  /**
   * Address: 0x00BD4670 (FUN_00BD4670, register_AddLightParticle_SimConFuncDef)
   *
   * What it does:
   * Registers the `AddLightParticle` sim-console callback and arms startup teardown.
   */
  void register_AddLightParticle_SimConFuncDef()
  {
    (void)ConstructSimConFunc_AddLightParticle();
    RegisterAtexitCleanup<&cleanup_AddLightParticle_SimConFunc>();
  }

  /**
   * Address: 0x00BD4720 (FUN_00BD4720, register_sim_SimInitFormListAnchor)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59EE4`.
   */
  CScrLuaInitForm* register_sim_SimInitFormListAnchor()
  {
    return RegisterRecoveredSimInitLinkerLane<
      &gRecoveredSimLuaInitFormPrevious,
      &gRecoveredSimLuaInitFormAnchor>();
  }

  /**
   * Address: 0x00BD4740 (FUN_00BD4740, j_func_IEffectSetBeamParam_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_IEffectSetBeamParam_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_IEffectSetBeamParam_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4750 (FUN_00BD4750, j_func_IEffectSetEmitterParam_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_IEffectSetEmitterParam_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_IEffectSetEmitterParam_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4760 (FUN_00BD4760, register_IEffectScaleEmitter_LuaFuncDef)
   */
  CScrLuaInitForm* register_IEffectScaleEmitter_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_IEffectScaleEmitter_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4770 (FUN_00BD4770, register_IEffectResizeEmitterCurve_LuaFuncDef)
   */
  CScrLuaInitForm* register_IEffectResizeEmitterCurve_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_IEffectResizeEmitterCurve_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4780 (FUN_00BD4780, j_func_IEffectSetEmitterCurveParam_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_IEffectSetEmitterCurveParam_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_IEffectSetEmitterCurveParam_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4790 (FUN_00BD4790, j_func_IEffectOffsetEmitter_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_IEffectOffsetEmitter_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_IEffectOffsetEmitter_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD47A0 (FUN_00BD47A0, register_IEffectDestroy_LuaFuncDef)
   */
  CScrLuaInitForm* register_IEffectDestroy_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_IEffectDestroy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD47B0 (FUN_00BD47B0, j_func_CDecalHandleDestroy_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CDecalHandleDestroy_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CDecalHandleDestroy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD47C0 (FUN_00BD47C0, register_CreateDecal_LuaFuncDef)
   */
  CScrLuaInitForm* register_CreateDecal_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateDecal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD47D0 (FUN_00BD47D0, j_func_CreateSplat_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateSplat_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateSplat_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD47E0 (FUN_00BD47E0, j_func_CreateSplatOnBone_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateSplatOnBone_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateSplatOnBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD47F0 (FUN_00BD47F0, register_CreateEmitterAtEntity_LuaFuncDef)
   */
  CScrLuaInitForm* register_CreateEmitterAtEntity_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateEmitterAtEntity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4800 (FUN_00BD4800, register_CreateEmitterOnEntity_LuaFuncDef)
   */
  CScrLuaInitForm* register_CreateEmitterOnEntity_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateEmitterOnEntity_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4810 (FUN_00BD4810, j_func_CreateLightParticle_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateLightParticle_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateLightParticle_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4820 (FUN_00BD4820, register_CreateLightParticleIntel_LuaFuncDef)
   */
  CScrLuaInitForm* register_CreateLightParticleIntel_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateLightParticleIntel_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4830 (FUN_00BD4830, j_func_CreateAttachedEmitter_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateAttachedEmitter_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateAttachedEmitter_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4840 (FUN_00BD4840, j_func_CreateTrail_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateTrail_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateTrail_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4850 (FUN_00BD4850, register_CreateAttachedBeam_LuaFuncDef)
   */
  CScrLuaInitForm* register_CreateAttachedBeam_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateAttachedBeam_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4860 (FUN_00BD4860, j_func_CreateBeamToEntityBone_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateBeamToEntityBone_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateBeamToEntityBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4870 (FUN_00BD4870, j_func_CreateEmitterAtBone_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateEmitterAtBone_LuaFuncDef()
  {
    return ForwardEffectLuaThunk<&func_CreateEmitterAtBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCEB40 (FUN_00BCEB40, register_CScrLuaMetatableFactory_IEffect_Index)
   *
   * What it does:
   * Allocates and stores the recovered startup Lua factory index lane for
   * `CScrLuaMetatableFactory<IEffect>`.
   */
  int register_CScrLuaMetatableFactory_IEffect_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryIEffectIndex>();
  }

  /**
   * Address: 0x00BD4880 (FUN_00BD4880, register_CScrLuaMetatableFactory_CDecalHandle_Index)
   *
   * What it does:
   * Allocates and stores the recovered startup Lua factory index lane for
   * `CScrLuaMetatableFactory<CDecalHandle>`.
   */
  int register_CScrLuaMetatableFactory_CDecalHandle_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<CDecalHandle>::Instance().SetFactoryObjectIndexForRecovery(index);
    return index;
  }

  /**
   * Address: 0x00BD4910 (FUN_00BD4910, register_TConVar_dbg_Trail)
   *
   * What it does:
   * Registers startup `dbg_Trail` convar and installs process-exit teardown.
   */
  void register_TConVar_dbg_Trail()
  {
    RegisterConCommand(GetDbgTrailConVar());
    (void)std::atexit(&cleanup_TConVar_dbg_Trail_atexit);
  }
} // namespace moho

namespace
{
  struct EffectLuaStartupRegistrationsBootstrap
  {
    EffectLuaStartupRegistrationsBootstrap()
    {
      (void)moho::register_CreateBeamEmitter_LuaFuncDef();
      (void)moho::j_func_CreateBeamEmitterOnEntity_LuaFuncDef();
      (void)moho::register_CreateBeamEntityToEntity_LuaFuncDef();
      (void)moho::j_func_AttachBeamEntityToEntity_LuaFuncDef();
      (void)moho::register_AttachBeamToEntity_LuaFuncDef();
      moho::register_AddBeam_ConAliasDef();
      moho::register_AddBeam_SimConFuncDef();
      moho::register_TConVar_dbg_EfxBeams();
      moho::register_TConVar_efx_WaterOffset();
      moho::register_TConVar_dbg_Emitter();
      moho::register_efx_NewEmitter_ConAliasDef();
      moho::register_efx_NewEmitter_SimConFuncDef();
      moho::register_efx_AttachEmitter_ConAliasDef();
      moho::register_efx_AttachEmitter_SimConFuncDef();
      moho::register_AddLightParticle_ConAliasDef();
      moho::register_AddLightParticle_SimConFuncDef();
      (void)moho::register_sim_SimInitFormListAnchor();
      (void)moho::j_func_IEffectSetBeamParam_LuaFuncDef();
      (void)moho::j_func_IEffectSetEmitterParam_LuaFuncDef();
      (void)moho::register_IEffectScaleEmitter_LuaFuncDef();
      (void)moho::register_IEffectResizeEmitterCurve_LuaFuncDef();
      (void)moho::j_func_IEffectSetEmitterCurveParam_LuaFuncDef();
      (void)moho::j_func_IEffectOffsetEmitter_LuaFuncDef();
      (void)moho::register_IEffectDestroy_LuaFuncDef();
      (void)moho::j_func_CDecalHandleDestroy_LuaFuncDef();
      (void)moho::register_CreateDecal_LuaFuncDef();
      (void)moho::j_func_CreateSplat_LuaFuncDef();
      (void)moho::j_func_CreateSplatOnBone_LuaFuncDef();
      (void)moho::register_CreateEmitterAtEntity_LuaFuncDef();
      (void)moho::register_CreateEmitterOnEntity_LuaFuncDef();
      (void)moho::j_func_CreateLightParticle_LuaFuncDef();
      (void)moho::register_CreateLightParticleIntel_LuaFuncDef();
      (void)moho::j_func_CreateAttachedEmitter_LuaFuncDef();
      (void)moho::j_func_CreateTrail_LuaFuncDef();
      (void)moho::register_CreateAttachedBeam_LuaFuncDef();
      (void)moho::j_func_CreateBeamToEntityBone_LuaFuncDef();
      (void)moho::j_func_CreateEmitterAtBone_LuaFuncDef();
      (void)moho::register_CScrLuaMetatableFactory_IEffect_Index();
      (void)moho::register_CScrLuaMetatableFactory_CDecalHandle_Index();
      moho::register_TConVar_dbg_Trail();
    }
  };

  [[maybe_unused]] EffectLuaStartupRegistrationsBootstrap gEffectLuaStartupRegistrationsBootstrap;
} // namespace
