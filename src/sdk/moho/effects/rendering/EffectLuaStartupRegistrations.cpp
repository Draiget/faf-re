#include "moho/console/CConAlias.h"
#include "moho/console/CConCommand.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/resource/RResId.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <new>

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
  std::int32_t gRecoveredCScrLuaMetatableFactoryCDecalHandleIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryIEffectIndex = 0;
  constexpr const char* kCreateBeamEmitterHelpText = "emitter = CreateBeamEmitter(blueprint,army)";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
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
  int cfunc_CreateBeamEmitter(lua_State* luaContext);
  int cfunc_CreateBeamEmitterL(LuaPlus::LuaState* state);
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
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCDecalHandleIndex>();
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
