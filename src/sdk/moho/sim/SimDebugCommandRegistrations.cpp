#include "moho/sim/SimDebugCommandRegistrations.h"

#include <cstdlib>
#include <new>

#include "moho/console/CConAlias.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/Sim.h"

namespace
{
  alignas(moho::CConAlias) unsigned char gDbgConAliasStorage[sizeof(moho::CConAlias)] = {};
  bool gDbgConAliasConstructed = false;

  alignas(moho::CSimConFunc) unsigned char gDbgSimConFuncStorage[sizeof(moho::CSimConFunc)] = {};
  bool gDbgSimConFuncConstructed = false;

  [[nodiscard]] moho::CConAlias& DbgConAlias()
  {
    return *std::launder(reinterpret_cast<moho::CConAlias*>(gDbgConAliasStorage));
  }

  [[nodiscard]] moho::CConAlias& ConstructDbgConAlias()
  {
    if (!gDbgConAliasConstructed) {
      new (gDbgConAliasStorage) moho::CConAlias{};
      gDbgConAliasConstructed = true;
    }

    return DbgConAlias();
  }

  [[nodiscard]] moho::CSimConFunc& DbgSimConFunc()
  {
    return *std::launder(reinterpret_cast<moho::CSimConFunc*>(gDbgSimConFuncStorage));
  }

  [[nodiscard]] moho::CSimConFunc& ConstructDbgSimConFunc()
  {
    if (!gDbgSimConFuncConstructed) {
      new (gDbgSimConFuncStorage) moho::CSimConFunc(false, "dbg", &moho::Sim::dbg);
      gDbgSimConFuncConstructed = true;
    }

    return DbgSimConFunc();
  }

  [[nodiscard]] moho::CConAlias& ConAlias_Purge()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_NoDamage()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AI_RunOpponentAI()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AI_DebugArmyIndex()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AI_RenderDebugAttackVectors()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AI_RenderDebugPlayableRect()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AI_DebugCollision()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AI_DebugIgnorePlayableRect()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_ai_InstaBuild()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_ai_FreeBuild()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_ai_SteeringAirTolerance()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::TConVar<bool>& ConVar_ren_Steering()
  {
    static moho::TConVar<bool> conVar(
      "ren_Steering",
      "",
      reinterpret_cast<bool*>(&moho::ren_Steering)
    );
    return conVar;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_NeedRefuelThresholdRatio()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_NeedRepairThresholdRatio()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_SallyShears_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_SallyShears_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_BlingBling_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_BlingBling_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_ZeroExtraStorage_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_ZeroExtraStorage_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_DamageUnit_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_AddImpulse_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_AddImpulse_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::TSimConVar<bool>*& SimConVar_NoDamage_slot()
  {
    static moho::TSimConVar<bool>* sConVar = nullptr;
    return sConVar;
  }

  [[nodiscard]] moho::TSimConVar<bool>*& SimConVar_ai_InstaBuild_slot()
  {
    static moho::TSimConVar<bool>* sConVar = nullptr;
    return sConVar;
  }

  [[nodiscard]] moho::TSimConVar<bool>*& SimConVar_ai_FreeBuild_slot()
  {
    static moho::TSimConVar<bool>* sConVar = nullptr;
    return sConVar;
  }

  alignas(moho::TSimConVar<bool>)
  unsigned char gAiRunOpponentAISimConVarStorage[sizeof(moho::TSimConVar<bool>)] = {};
  bool gAiRunOpponentAISimConVarConstructed = false;

  alignas(moho::TSimConVar<int>) unsigned char gAiDebugArmyIndexSimConVarStorage[sizeof(moho::TSimConVar<int>)] = {};
  bool gAiDebugArmyIndexSimConVarConstructed = false;

  alignas(moho::TSimConVar<bool>)
  unsigned char gAiRenderDebugAttackVectorsSimConVarStorage[sizeof(moho::TSimConVar<bool>)] = {};
  bool gAiRenderDebugAttackVectorsSimConVarConstructed = false;

  alignas(moho::TSimConVar<bool>)
  unsigned char gAiRenderDebugPlayableRectSimConVarStorage[sizeof(moho::TSimConVar<bool>)] = {};
  bool gAiRenderDebugPlayableRectSimConVarConstructed = false;

  alignas(moho::TSimConVar<bool>)
  unsigned char gAiDebugCollisionSimConVarStorage[sizeof(moho::TSimConVar<bool>)] = {};
  bool gAiDebugCollisionSimConVarConstructed = false;

  alignas(moho::TSimConVar<bool>)
  unsigned char gAiDebugIgnorePlayableRectSimConVarStorage[sizeof(moho::TSimConVar<bool>)] = {};
  bool gAiDebugIgnorePlayableRectSimConVarConstructed = false;

  [[nodiscard]] moho::TSimConVar<bool>& AiRunOpponentAISimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<bool>*>(gAiRunOpponentAISimConVarStorage));
  }

  [[nodiscard]] moho::TSimConVar<bool>& ConstructAiRunOpponentAISimConVar()
  {
    if (!gAiRunOpponentAISimConVarConstructed) {
      new (gAiRunOpponentAISimConVarStorage) moho::TSimConVar<bool>(true, "AI_RunOpponentAI", true);
      gAiRunOpponentAISimConVarConstructed = true;
    }

    return AiRunOpponentAISimConVar();
  }

  [[nodiscard]] moho::TSimConVar<int>& AiDebugArmyIndexSimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<int>*>(gAiDebugArmyIndexSimConVarStorage));
  }

  [[nodiscard]] moho::TSimConVar<int>& ConstructAiDebugArmyIndexSimConVar()
  {
    if (!gAiDebugArmyIndexSimConVarConstructed) {
      new (gAiDebugArmyIndexSimConVarStorage) moho::TSimConVar<int>(true, "AI_DebugArmyIndex", -1);
      gAiDebugArmyIndexSimConVarConstructed = true;
    }

    return AiDebugArmyIndexSimConVar();
  }

  [[nodiscard]] moho::TSimConVar<bool>& AiRenderDebugAttackVectorsSimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<bool>*>(gAiRenderDebugAttackVectorsSimConVarStorage));
  }

  [[nodiscard]] moho::TSimConVar<bool>& ConstructAiRenderDebugAttackVectorsSimConVar()
  {
    if (!gAiRenderDebugAttackVectorsSimConVarConstructed) {
      new (gAiRenderDebugAttackVectorsSimConVarStorage) moho::TSimConVar<bool>(true, "AI_RenderDebugAttackVectors", false);
      gAiRenderDebugAttackVectorsSimConVarConstructed = true;
    }

    return AiRenderDebugAttackVectorsSimConVar();
  }

  [[nodiscard]] moho::TSimConVar<bool>& AiRenderDebugPlayableRectSimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<bool>*>(gAiRenderDebugPlayableRectSimConVarStorage));
  }

  [[nodiscard]] moho::TSimConVar<bool>& ConstructAiRenderDebugPlayableRectSimConVar()
  {
    if (!gAiRenderDebugPlayableRectSimConVarConstructed) {
      new (gAiRenderDebugPlayableRectSimConVarStorage) moho::TSimConVar<bool>(true, "AI_RenderDebugPlayableRect", false);
      gAiRenderDebugPlayableRectSimConVarConstructed = true;
    }

    return AiRenderDebugPlayableRectSimConVar();
  }

  [[nodiscard]] moho::TSimConVar<bool>& AiDebugCollisionSimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<bool>*>(gAiDebugCollisionSimConVarStorage));
  }

  [[nodiscard]] moho::TSimConVar<bool>& ConstructAiDebugCollisionSimConVar()
  {
    if (!gAiDebugCollisionSimConVarConstructed) {
      new (gAiDebugCollisionSimConVarStorage) moho::TSimConVar<bool>(false, "AI_DebugCollision", false);
      gAiDebugCollisionSimConVarConstructed = true;
    }

    return AiDebugCollisionSimConVar();
  }

  [[nodiscard]] moho::TSimConVar<bool>& AiDebugIgnorePlayableRectSimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<bool>*>(gAiDebugIgnorePlayableRectSimConVarStorage));
  }

  [[nodiscard]] moho::TSimConVar<bool>& ConstructAiDebugIgnorePlayableRectSimConVar()
  {
    if (!gAiDebugIgnorePlayableRectSimConVarConstructed) {
      new (gAiDebugIgnorePlayableRectSimConVarStorage) moho::TSimConVar<bool>(false, "AI_DebugIgnorePlayableRect", false);
      gAiDebugIgnorePlayableRectSimConVarConstructed = true;
    }

    return AiDebugIgnorePlayableRectSimConVar();
  }

  alignas(moho::TSimConVar<float>)
  unsigned char gAiSteeringAirToleranceStorage[sizeof(moho::TSimConVar<float>)] = {};
  bool gAiSteeringAirToleranceConstructed = false;

  [[nodiscard]] moho::TSimConVar<float>& AiSteeringAirToleranceSimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<float>*>(gAiSteeringAirToleranceStorage));
  }

  [[nodiscard]] moho::TSimConVar<float>& ConstructAiSteeringAirToleranceSimConVar()
  {
    if (!gAiSteeringAirToleranceConstructed) {
      new (gAiSteeringAirToleranceStorage) moho::TSimConVar<float>(false, "ai_SteeringAirTolerance", 4.0f);
      gAiSteeringAirToleranceConstructed = true;
    }

    return AiSteeringAirToleranceSimConVar();
  }

  [[nodiscard]] moho::CConAlias& ConAlias_WeaponTerrainBlockageTest()
  {
    static moho::CConAlias sAlias{};
    return sAlias;
  }

  alignas(moho::TSimConVar<bool>)
  unsigned char gWeaponTerrainBlockageTestStorage[sizeof(moho::TSimConVar<bool>)] = {};
  bool gWeaponTerrainBlockageTestConstructed = false;

  [[nodiscard]] moho::TSimConVar<bool>& WeaponTerrainBlockageTestSimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<bool>*>(gWeaponTerrainBlockageTestStorage));
  }

  [[nodiscard]] moho::TSimConVar<bool>& ConstructWeaponTerrainBlockageTestSimConVar()
  {
    if (!gWeaponTerrainBlockageTestConstructed) {
      new (gWeaponTerrainBlockageTestStorage) moho::TSimConVar<bool>(false, "WeaponTerrainBlockageTest", true);
      gWeaponTerrainBlockageTestConstructed = true;
    }

    return WeaponTerrainBlockageTestSimConVar();
  }

  alignas(moho::TSimConVar<float>) unsigned char gNeedRefuelThresholdRatioStorage[sizeof(moho::TSimConVar<float>)] = {};
  bool gNeedRefuelThresholdRatioConstructed = false;

  alignas(moho::TSimConVar<float>) unsigned char gNeedRepairThresholdRatioStorage[sizeof(moho::TSimConVar<float>)] = {};
  bool gNeedRepairThresholdRatioConstructed = false;

  [[nodiscard]] moho::TSimConVar<float>& NeedRefuelThresholdRatioSimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<float>*>(gNeedRefuelThresholdRatioStorage));
  }

  [[nodiscard]] moho::TSimConVar<float>& ConstructNeedRefuelThresholdRatioSimConVar()
  {
    if (!gNeedRefuelThresholdRatioConstructed) {
      new (gNeedRefuelThresholdRatioStorage) moho::TSimConVar<float>(false, "NeedRefuelThresholdRatio", 0.2f);
      gNeedRefuelThresholdRatioConstructed = true;
    }

    return NeedRefuelThresholdRatioSimConVar();
  }

  [[nodiscard]] moho::TSimConVar<float>& NeedRepairThresholdRatioSimConVar()
  {
    return *std::launder(reinterpret_cast<moho::TSimConVar<float>*>(gNeedRepairThresholdRatioStorage));
  }

  [[nodiscard]] moho::TSimConVar<float>& ConstructNeedRepairThresholdRatioSimConVar()
  {
    if (!gNeedRepairThresholdRatioConstructed) {
      new (gNeedRepairThresholdRatioStorage) moho::TSimConVar<float>(false, "NeedRepairThresholdRatio", 0.75f);
      gNeedRepairThresholdRatioConstructed = true;
    }

    return NeedRepairThresholdRatioSimConVar();
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_DebugAIStatesOff_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugAIStatesOff_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_DebugAIStatesOn_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugAIStatesOn_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_TrackStats_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_TrackStats_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_DumpUnits_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DumpUnits_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_DebugSetProductionInActive_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugSetProductionInActive_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_DebugSetProductionActive_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugSetProductionActive_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_DebugSetConsumptionInActive_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugSetConsumptionInActive_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_DebugSetConsumptionActive_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugSetConsumptionActive_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_Purge_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_KillAll_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_KillAll_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CConAlias*& ConAlias_DestroyAll_slot()
  {
    static moho::CConAlias* sAlias = nullptr;
    return sAlias;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DestroyAll_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  template <void (*Cleanup)()>
  void RegisterAtexitCleanup()
  {
    (void)std::atexit(Cleanup);
  }

  template <int (*Callback)(
              moho::Sim*,
              moho::CSimConCommand::ParsedCommandArgs*,
              Wm3::Vector3f*,
              moho::CArmyImpl*,
              moho::SEntitySetTemplateUnit*)>
  void EnsureSimConFuncRegistration(moho::CSimConFunc*& slot, const char* const commandName)
  {
    if (slot == nullptr) {
      slot = new moho::CSimConFunc(false, commandName, Callback);
    }
  }

  void EnsureConAliasRegistration(
    moho::CConAlias*& slot,
    const char* const description,
    const char* const aliasName,
    const char* const aliasCommand
  )
  {
    if (slot == nullptr) {
      slot = new moho::CConAlias();
      slot->InitializeRecovered(description, aliasName, aliasCommand);
    }
  }

  struct SimDebugCommandRegistrationsBootstrap
  {
    SimDebugCommandRegistrationsBootstrap()
    {
      moho::register_NeedRefuelThresholdRatio_ConAliasDef();
      moho::register_NeedRefuelThresholdRatio_SimConVarDef();
      moho::register_NeedRepairThresholdRatio_ConAliasDef();
      moho::register_NeedRepairThresholdRatio_SimConVarDef();
      moho::register_SallyShears_ConAliasDef();
      moho::register_SallyShears_SimConFuncDef();
      moho::register_BlingBling_ConAlias();
      moho::register_BlingBling_SimConFunc();
      moho::register_ZeroExtraStorage_ConAliasDef();
      moho::register_ZeroExtraStorage_SimConFuncDef();
      moho::register_DamageUnit_ConAlias();
      moho::register_AddImpulse_ConAliasDef();
      moho::register_AddImpulse_SimConFuncDef();
      moho::register_WeaponTerrainBlockageTest_ConAliasDef();
      moho::register_WeaponTerrainBlockageTest_SimConVarDef();
      moho::register_dbg_ConAlias();
      moho::register_dbg_SimConFunc();
      moho::register_NoDamage_ConAliasDef();
      moho::register_NoDamage_SimConVarDef();
      moho::register_AI_RunOpponentAI_ConAlias();
      moho::register_AI_RunOpponentAI_SimConVarDef();
      moho::register_AI_DebugArmyIndex_ConAlias();
      moho::register_AI_DebugArmyIndex_SimConDef();
      moho::register_AI_RenderDebugAttackVectors_ConAlias();
      moho::register_AI_RenderDebugAttackVectors_SimConVarDef();
      moho::register_AI_RenderDebugPlayableRect_ConAlias();
      moho::register_AI_RenderDebugPlayableRect_SimConVarDef();
      moho::register_AI_DebugCollision_ConAlias();
      moho::register_AI_DebugCollision_SimConVarDef();
      moho::register_AI_DebugIgnorePlayableRect_ConAlias();
      moho::register_AI_DebugIgnorePlayableRect_SimConVarDef();
      moho::register_ai_InstaBuild_ConAliasDef();
      moho::register_ai_InstaBuild_SimConVarDef();
      moho::register_ai_FreeBuild_ConAliasDef();
      moho::register_ai_FreeBuild_SimConVarDef();
      moho::register_ai_SteeringAirTolerance_ConAliasDef();
      moho::register_ai_SteeringAirTolerance_SimConVarDef();
      moho::register_TConVar_ren_Steering();
      moho::register_Purge_ConAliasDef();
      moho::register_Purge_SimConFuncDef();
      moho::register_KillAll_ConAliasDef();
      moho::register_KillAll_SimConFuncDef();
      moho::register_DestroyAll_ConAliasDef();
      moho::register_DestroyAll_SimConFuncDef();
      moho::register_DebugSetConsumptionActive_ConAliasDef();
      moho::register_DebugSetConsumptionActive_SimConFuncDef();
      moho::register_DebugSetConsumptionInActive_ConAliasDef();
      moho::register_DebugSetConsumptionInActive_SimConFuncDef();
      moho::register_DebugSetProductionActive_ConAliasDef();
      moho::register_DebugSetProductionActive_SimConFuncDef();
      moho::register_DebugSetProductionInActive_ConAliasDef();
      moho::register_DebugSetProductionInActive_SimConFuncDef();
      moho::register_DebugAIStatesOn_ConAlias();
      moho::register_DebugAIStatesOn_SimConFunc();
      moho::register_DebugAIStatesOff_ConAlias();
      moho::register_DebugAIStatesOff_SimConFunc();
      moho::register_TrackStats_ConAliasDef();
      moho::register_TrackStats_SimConFuncDef();
      moho::register_DumpUnits_ConAliasDef();
      moho::register_DumpUnits_SimConFuncDef();
    }
  };

  [[maybe_unused]] SimDebugCommandRegistrationsBootstrap gSimDebugCommandRegistrationsBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BFB7D0 (FUN_00BFB7D0, cleanup_dbg_ConAlias)
   *
   * What it does:
   * Tears down the startup-owned `dbg` alias payload and unregisters the
   * command binding.
   */
  void cleanup_dbg_ConAlias()
  {
    if (!gDbgConAliasConstructed) {
      return;
    }

    DbgConAlias().ShutdownRecovered();
    DbgConAlias().~CConAlias();
    gDbgConAliasConstructed = false;
  }

  /**
   * Address: 0x00BFB820 (FUN_00BFB820, cleanup_dbg_SimConFunc)
   *
   * What it does:
   * Destroys the startup-owned `dbg` sim command callback object.
   */
  void cleanup_dbg_SimConFunc()
  {
    if (!gDbgSimConFuncConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(DbgSimConFunc()).~CSimConCommand();
    gDbgSimConFuncConstructed = false;
  }

  /**
   * Address: 0x00BD3D80 (FUN_00BD3D80, register_dbg_ConAlias)
   *
   * What it does:
   * Registers the startup-owned `dbg` console alias and installs exit cleanup.
   */
  void register_dbg_ConAlias()
  {
    ConstructDbgConAlias().InitializeRecovered(
      "Enable/Disable debug overlay",
      "dbg",
      "DoSimCommand dbg"
    );
    RegisterAtexitCleanup<&cleanup_dbg_ConAlias>();
  }

  /**
   * Address: 0x00BD3DB0 (FUN_00BD3DB0, register_dbg_SimConFunc)
   *
   * What it does:
   * Registers the startup-owned `dbg` sim command callback and installs exit
   * cleanup.
   */
  void register_dbg_SimConFunc()
  {
    (void)ConstructDbgSimConFunc();
    RegisterAtexitCleanup<&cleanup_dbg_SimConFunc>();
  }

  /**
   * Address: 0x00BFB470 (FUN_00BFB470, sub_BFB470)
   */
  void cleanup_SallyShears_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_SallyShears_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFB4C0 (FUN_00BFB4C0, sub_BFB4C0)
   */
  void cleanup_SallyShears_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_SallyShears_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BFB4D0 (FUN_00BFB4D0, sub_BFB4D0)
   */
  void cleanup_BlingBling_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_BlingBling_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFB520 (FUN_00BFB520, sub_BFB520)
   */
  void cleanup_BlingBling_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_BlingBling_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BFB530 (FUN_00BFB530, sub_BFB530)
   */
  void cleanup_ZeroExtraStorage_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_ZeroExtraStorage_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFB580 (FUN_00BFB580, sub_BFB580)
   */
  void cleanup_ZeroExtraStorage_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_ZeroExtraStorage_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BFB590 (FUN_00BFB590, sub_BFB590)
   */
  void cleanup_DamageUnit_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_DamageUnit_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFB5F0 (FUN_00BFB5F0, sub_BFB5F0)
   */
  void cleanup_AddImpulse_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_AddImpulse_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFB640 (FUN_00BFB640, sub_BFB640)
   */
  void cleanup_AddImpulse_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_AddImpulse_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BD3890 (FUN_00BD3890, register_SallyShears_ConAliasDef)
   *
   * What it does:
   * Registers the `SallyShears` console alias and installs startup cleanup.
   */
  void register_SallyShears_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_SallyShears_slot(),
      "Reveal entire map.",
      "SallyShears",
      "DoSimCommand SallyShears"
    );
    RegisterAtexitCleanup<&cleanup_SallyShears_ConAlias>();
  }

  /**
   * Address: 0x00BD38C0 (FUN_00BD38C0, register_SallyShears_SimConFuncDef)
   *
   * What it does:
   * Registers the `SallyShears` sim command callback and installs startup
   * cleanup.
   */
  void register_SallyShears_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::SallyShears>(SimConFunc_SallyShears_slot(), "SallyShears");
    RegisterAtexitCleanup<&cleanup_SallyShears_SimConFunc>();
  }

  /**
   * Address: 0x00BD3900 (FUN_00BD3900, register_BlingBling_ConAlias)
   *
   * What it does:
   * Registers the `BlingBling` console alias and installs startup cleanup.
   */
  void register_BlingBling_ConAlias()
  {
    EnsureConAliasRegistration(
      ConAlias_BlingBling_slot(),
      "Cash money yo",
      "BlingBling",
      "DoSimCommand BlingBling"
    );
    RegisterAtexitCleanup<&cleanup_BlingBling_ConAlias>();
  }

  /**
   * Address: 0x00BD3930 (FUN_00BD3930, register_BlingBling_SimConFunc)
   *
   * What it does:
   * Registers the `BlingBling` sim command callback and installs startup
   * cleanup.
   */
  void register_BlingBling_SimConFunc()
  {
    EnsureSimConFuncRegistration<&Sim::BlingBling>(SimConFunc_BlingBling_slot(), "BlingBling");
    RegisterAtexitCleanup<&cleanup_BlingBling_SimConFunc>();
  }

  /**
   * Address: 0x00BD3970 (FUN_00BD3970, register_ZeroExtraStorage_ConAliasDef)
   *
   * What it does:
   * Registers the `ZeroExtraStorage` console alias and installs startup
   * cleanup.
   */
  void register_ZeroExtraStorage_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_ZeroExtraStorage_slot(),
      "Set energy and mass extra storage to 0",
      "ZeroExtraStorage",
      "DoSimCommand ZeroExtraStorage"
    );
    RegisterAtexitCleanup<&cleanup_ZeroExtraStorage_ConAlias>();
  }

  /**
   * Address: 0x00BD39A0 (FUN_00BD39A0, func_ZeroExtraStorage_SimConFuncDef)
   *
   * What it does:
   * Registers the `ZeroExtraStorage` sim command callback and installs startup
   * cleanup.
   */
  void register_ZeroExtraStorage_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::ZeroExtraStorage>(SimConFunc_ZeroExtraStorage_slot(), "ZeroExtraStorage");
    RegisterAtexitCleanup<&cleanup_ZeroExtraStorage_SimConFunc>();
  }

  /**
   * Address: 0x00BD39E0 (FUN_00BD39E0, register_DamageUnit_ConAlias)
   *
   * What it does:
   * Registers the `DamageUnit` console alias and installs startup cleanup.
   */
  void register_DamageUnit_ConAlias()
  {
    EnsureConAliasRegistration(
      ConAlias_DamageUnit_slot(),
      "Damage the selected unit (negative values heal)",
      "DamageUnit",
      "DoSimCommand DamageUnit"
    );
    RegisterAtexitCleanup<&cleanup_DamageUnit_ConAlias>();
  }

  /**
   * Address: 0x00BD3A50 (FUN_00BD3A50, register_AddImpulse_ConAliasDef)
   *
   * What it does:
   * Registers the `AddImpulse` console alias and installs startup cleanup.
   */
  void register_AddImpulse_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_AddImpulse_slot(),
      "AddImpulse (x,y,z)",
      "AddImpulse",
      "DoSimCommand AddImpulse"
    );
    RegisterAtexitCleanup<&cleanup_AddImpulse_ConAlias>();
  }

  /**
   * Address: 0x00BD3A80 (FUN_00BD3A80, register_AddImpulse_SimConFuncDef)
   *
   * What it does:
   * Registers the `AddImpulse` sim command callback and installs startup
   * cleanup.
   */
  void register_AddImpulse_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::AddImpulse>(SimConFunc_AddImpulse_slot(), "AddImpulse");
    RegisterAtexitCleanup<&cleanup_AddImpulse_SimConFunc>();
  }

  /**
   * Address: 0x00BFA720 (FUN_00BFA720, cleanup_NeedRefuelThresholdRatio_ConAlias)
   *
   * What it does:
   * Tears down the startup-owned `NeedRefuelThresholdRatio` alias storage.
   */
  void cleanup_NeedRefuelThresholdRatio_ConAlias()
  {
    ConAlias_NeedRefuelThresholdRatio().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD1F60 (FUN_00BD1F60, register_NeedRefuelThresholdRatio_ConAliasDef)
   *
   * What it does:
   * Registers the `NeedRefuelThresholdRatio` console alias and installs
   * startup cleanup.
   */
  void register_NeedRefuelThresholdRatio_ConAliasDef()
  {
    ConAlias_NeedRefuelThresholdRatio().InitializeRecovered(
      "Start looking for refueling platform when fuel ratio drops below this point",
      "NeedRefuelThresholdRatio",
      "DoSimCommand NeedRefuelThresholdRatio"
    );
    RegisterAtexitCleanup<&cleanup_NeedRefuelThresholdRatio_ConAlias>();
  }

  /**
   * Address: 0x00BFA770 (FUN_00BFA770, cleanup_NeedRefuelThresholdRatio_SimConVar)
   *
   * What it does:
   * Destroys the startup-owned `NeedRefuelThresholdRatio` sim-convar storage.
   */
  void cleanup_NeedRefuelThresholdRatio_SimConVar()
  {
    if (!gNeedRefuelThresholdRatioConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(NeedRefuelThresholdRatioSimConVar()).~CSimConCommand();
    gNeedRefuelThresholdRatioConstructed = false;
  }

  /**
   * Address: 0x00BD1F90 (FUN_00BD1F90, register_NeedRefuelThresholdRatio_SimConVarDef)
   *
   * What it does:
   * Constructs the `NeedRefuelThresholdRatio` sim convar and registers
   * process-exit cleanup.
   */
  void register_NeedRefuelThresholdRatio_SimConVarDef()
  {
    (void)ConstructNeedRefuelThresholdRatioSimConVar();
    RegisterAtexitCleanup<&cleanup_NeedRefuelThresholdRatio_SimConVar>();
  }

  /**
   * Address: 0x00BFA780 (FUN_00BFA780, cleanup_NeedRepairThresholdRatio_ConAlias)
   *
   * What it does:
   * Tears down the startup-owned `NeedRepairThresholdRatio` alias storage.
   */
  void cleanup_NeedRepairThresholdRatio_ConAlias()
  {
    ConAlias_NeedRepairThresholdRatio().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD1FE0 (FUN_00BD1FE0, register_NeedRepairThresholdRatio_ConAliasDef)
   *
   * What it does:
   * Registers the `NeedRepairThresholdRatio` console alias and installs
   * startup cleanup.
   */
  void register_NeedRepairThresholdRatio_ConAliasDef()
  {
    ConAlias_NeedRepairThresholdRatio().InitializeRecovered(
      "Start looking for refueling platform when health ratio drops below this point",
      "NeedRepairThresholdRatio",
      "DoSimCommand NeedRepairThresholdRatio"
    );
    RegisterAtexitCleanup<&cleanup_NeedRepairThresholdRatio_ConAlias>();
  }

  /**
   * Address: 0x00BFA7D0 (FUN_00BFA7D0, cleanup_NeedRepairThresholdRatio_SimConVar)
   *
   * What it does:
   * Destroys the startup-owned `NeedRepairThresholdRatio` sim-convar storage.
   */
  void cleanup_NeedRepairThresholdRatio_SimConVar()
  {
    if (!gNeedRepairThresholdRatioConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(NeedRepairThresholdRatioSimConVar()).~CSimConCommand();
    gNeedRepairThresholdRatioConstructed = false;
  }

  /**
   * Address: 0x00BD2010 (FUN_00BD2010, register_NeedRepairThresholdRatio_SimConVarDef)
   *
   * What it does:
   * Constructs the `NeedRepairThresholdRatio` sim convar and registers
   * process-exit cleanup.
   */
  void register_NeedRepairThresholdRatio_SimConVarDef()
  {
    (void)ConstructNeedRepairThresholdRatioSimConVar();
    RegisterAtexitCleanup<&cleanup_NeedRepairThresholdRatio_SimConVar>();
  }

  /**
   * Address: 0x00BFC630 (FUN_00BFC630, sub_BFC630)
   *
   * What it does:
   * Clears startup-owned `NoDamage` alias payload and unregisters command binding.
   */
  void cleanup_NoDamage_ConAlias()
  {
    ConAlias_NoDamage().ShutdownRecovered();
  }

  /**
   * Address: 0x00BFC680 (FUN_00BFC680, sub_BFC680)
   *
   * What it does:
   * Destroys startup-owned `NoDamage` sim-convar command object.
   */
  void cleanup_NoDamage_SimConVar()
  {
    if (TSimConVar<bool>*& conVar = SimConVar_NoDamage_slot(); conVar != nullptr) {
      delete conVar;
      conVar = nullptr;
    }
  }

  /**
   * Address: 0x00BD4E80 (FUN_00BD4E80, register_NoDamage_ConAliasDef)
   *
   * What it does:
   * Registers the `NoDamage` console alias and installs startup cleanup.
   */
  void register_NoDamage_ConAliasDef()
  {
    ConAlias_NoDamage().InitializeRecovered(
      "Disables all damage to units when set.",
      "NoDamage",
      "DoSimCommand NoDamage"
    );
    RegisterAtexitCleanup<&cleanup_NoDamage_ConAlias>();
  }

  /**
   * Address: 0x00BD4EB0 (FUN_00BD4EB0, register_NoDamage_SimConVarDef)
   *
   * What it does:
   * Registers the `NoDamage` sim convar definition and installs startup cleanup.
   */
  void register_NoDamage_SimConVarDef()
  {
    if (TSimConVar<bool>*& conVar = SimConVar_NoDamage_slot(); conVar == nullptr) {
      conVar = new TSimConVar<bool>(false, "NoDamage", false);
    }
    RegisterAtexitCleanup<&cleanup_NoDamage_SimConVar>();
  }

  /**
   * Address: 0x00BF5F80 (FUN_00BF5F80, sub_BF5F80)
   *
   * What it does:
   * Clears startup-owned `AI_RunOpponentAI` alias payload and unregisters
   * command binding.
   */
  void cleanup_AI_RunOpponentAI_ConAlias()
  {
    ConAlias_AI_RunOpponentAI().ShutdownRecovered();
  }

  /**
   * Address: 0x00BF5FD0 (FUN_00BF5FD0, sub_BF5FD0)
   *
   * What it does:
   * Destroys startup-owned `AI_RunOpponentAI` sim-convar command object.
   */
  void cleanup_AI_RunOpponentAI_SimConVarDef()
  {
    if (!gAiRunOpponentAISimConVarConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(AiRunOpponentAISimConVar()).~CSimConCommand();
    gAiRunOpponentAISimConVarConstructed = false;
  }

  /**
   * Address: 0x00BCB050 (FUN_00BCB050, register_AI_RunOpponentAI_ConAlias)
   *
   * What it does:
   * Registers the `AI_RunOpponentAI` console alias and installs startup
   * cleanup.
   */
  void register_AI_RunOpponentAI_ConAlias()
  {
    ConAlias_AI_RunOpponentAI().InitializeRecovered(
      "Turns on or off Opponent AI",
      "AI_RunOpponentAI",
      "DoSimCommand AI_RunOpponentAI"
    );
    RegisterAtexitCleanup<&cleanup_AI_RunOpponentAI_ConAlias>();
  }

  /**
   * Address: 0x00BCB080 (FUN_00BCB080, register_AI_RunOpponentAI_SimConVarDef)
   *
   * What it does:
   * Registers `AI_RunOpponentAI` sim convar and installs startup cleanup.
   */
  void register_AI_RunOpponentAI_SimConVarDef()
  {
    (void)ConstructAiRunOpponentAISimConVar();
    RegisterAtexitCleanup<&cleanup_AI_RunOpponentAI_SimConVarDef>();
  }

  CSimConVarBase* GetAI_RunOpponentAI_SimConVarDef()
  {
    return &ConstructAiRunOpponentAISimConVar();
  }

  /**
   * Address: 0x00BF5FE0 (FUN_00BF5FE0, sub_BF5FE0)
   *
   * What it does:
   * Clears startup-owned `AI_DebugArmyIndex` alias payload and unregisters
   * command binding.
   */
  void cleanup_AI_DebugArmyIndex_ConAlias()
  {
    ConAlias_AI_DebugArmyIndex().ShutdownRecovered();
  }

  /**
   * Address: 0x00BF6030 (FUN_00BF6030, sub_BF6030)
   *
   * What it does:
   * Destroys startup-owned `AI_DebugArmyIndex` sim-convar command object.
   */
  void cleanup_AI_DebugArmyIndex_SimConDef()
  {
    if (!gAiDebugArmyIndexSimConVarConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(AiDebugArmyIndexSimConVar()).~CSimConCommand();
    gAiDebugArmyIndexSimConVarConstructed = false;
  }

  /**
   * Address: 0x00BCB0D0 (FUN_00BCB0D0, register_AI_DebugArmyIndex_ConAlias)
   *
   * What it does:
   * Registers the `AI_DebugArmyIndex` console alias and installs startup
   * cleanup.
   */
  void register_AI_DebugArmyIndex_ConAlias()
  {
    ConAlias_AI_DebugArmyIndex().InitializeRecovered(
      "Set up a army index for debugging purposes",
      "AI_DebugArmyIndex",
      "DoSimCommand AI_DebugArmyIndex"
    );
    RegisterAtexitCleanup<&cleanup_AI_DebugArmyIndex_ConAlias>();
  }

  /**
   * Address: 0x00BCB100 (FUN_00BCB100, register_AI_DebugArmyIndex_SimConDef)
   *
   * What it does:
   * Registers `AI_DebugArmyIndex` sim convar and installs startup cleanup.
   */
  void register_AI_DebugArmyIndex_SimConDef()
  {
    (void)ConstructAiDebugArmyIndexSimConVar();
    RegisterAtexitCleanup<&cleanup_AI_DebugArmyIndex_SimConDef>();
  }

  /**
   * Address: 0x00BF6040 (FUN_00BF6040, sub_BF6040)
   *
   * What it does:
   * Clears startup-owned `AI_RenderDebugAttackVectors` alias payload and
   * unregisters command binding.
   */
  void cleanup_AI_RenderDebugAttackVectors_ConAlias()
  {
    ConAlias_AI_RenderDebugAttackVectors().ShutdownRecovered();
  }

  /**
   * Address: 0x00BF6090 (FUN_00BF6090, sub_BF6090)
   *
   * What it does:
   * Destroys startup-owned `AI_RenderDebugAttackVectors` sim-convar command
   * object.
   */
  void cleanup_AI_RenderDebugAttackVectors_SimConVarDef()
  {
    if (!gAiRenderDebugAttackVectorsSimConVarConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(AiRenderDebugAttackVectorsSimConVar()).~CSimConCommand();
    gAiRenderDebugAttackVectorsSimConVarConstructed = false;
  }

  /**
   * Address: 0x00BCB150 (FUN_00BCB150, register_AI_RenderDebugAttackVectors_ConAlias)
   *
   * What it does:
   * Registers the `AI_RenderDebugAttackVectors` console alias and installs
   * startup cleanup.
   */
  void register_AI_RenderDebugAttackVectors_ConAlias()
  {
    ConAlias_AI_RenderDebugAttackVectors().InitializeRecovered(
      "Toggle on/off rendering of debug base attack vectors",
      "AI_RenderDebugAttackVectors",
      "DoSimCommand AI_RenderDebugAttackVectors"
    );
    RegisterAtexitCleanup<&cleanup_AI_RenderDebugAttackVectors_ConAlias>();
  }

  /**
   * Address: 0x00BCB180 (FUN_00BCB180, register_AI_RenderDebugAttackVectors_SimConVarDef)
   *
   * What it does:
   * Registers `AI_RenderDebugAttackVectors` sim convar and installs startup
   * cleanup.
   */
  void register_AI_RenderDebugAttackVectors_SimConVarDef()
  {
    (void)ConstructAiRenderDebugAttackVectorsSimConVar();
    RegisterAtexitCleanup<&cleanup_AI_RenderDebugAttackVectors_SimConVarDef>();
  }

  /**
   * Address: 0x00BF60A0 (FUN_00BF60A0, sub_BF60A0)
   *
   * What it does:
   * Clears startup-owned `AI_RenderDebugPlayableRect` alias payload and
   * unregisters command binding.
   */
  void cleanup_AI_RenderDebugPlayableRect_ConAlias()
  {
    ConAlias_AI_RenderDebugPlayableRect().ShutdownRecovered();
  }

  /**
   * Address: 0x00BF60F0 (FUN_00BF60F0, sub_BF60F0)
   *
   * What it does:
   * Destroys startup-owned `AI_RenderDebugPlayableRect` sim-convar command
   * object.
   */
  void cleanup_AI_RenderDebugPlayableRect_SimConVarDef()
  {
    if (!gAiRenderDebugPlayableRectSimConVarConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(AiRenderDebugPlayableRectSimConVar()).~CSimConCommand();
    gAiRenderDebugPlayableRectSimConVarConstructed = false;
  }

  /**
   * Address: 0x00BCB1D0 (FUN_00BCB1D0, register_AI_RenderDebugPlayableRect_ConAlias)
   *
   * What it does:
   * Registers the `AI_RenderDebugPlayableRect` console alias and installs
   * startup cleanup.
   */
  void register_AI_RenderDebugPlayableRect_ConAlias()
  {
    ConAlias_AI_RenderDebugPlayableRect().InitializeRecovered(
      "Toggle on/off rendering of debug playable rect",
      "AI_RenderDebugPlayableRect",
      "DoSimCommand AI_RenderDebugPlayableRect"
    );
    RegisterAtexitCleanup<&cleanup_AI_RenderDebugPlayableRect_ConAlias>();
  }

  /**
   * Address: 0x00BCB200 (FUN_00BCB200, register_AI_RenderDebugPlayableRect_SimConVarDef)
   *
   * What it does:
   * Registers `AI_RenderDebugPlayableRect` sim convar and installs startup
   * cleanup.
   */
  void register_AI_RenderDebugPlayableRect_SimConVarDef()
  {
    (void)ConstructAiRenderDebugPlayableRectSimConVar();
    RegisterAtexitCleanup<&cleanup_AI_RenderDebugPlayableRect_SimConVarDef>();
  }

  /**
   * Address: 0x00BF6100 (FUN_00BF6100, sub_BF6100)
   *
   * What it does:
   * Clears startup-owned `AI_DebugCollision` alias payload and unregisters
   * command binding.
   */
  void cleanup_AI_DebugCollision_ConAlias()
  {
    ConAlias_AI_DebugCollision().ShutdownRecovered();
  }

  /**
   * Address: 0x00BF6150 (FUN_00BF6150, sub_BF6150)
   *
   * What it does:
   * Destroys startup-owned `AI_DebugCollision` sim-convar command object.
   */
  void cleanup_AI_DebugCollision_SimConVarDef()
  {
    if (!gAiDebugCollisionSimConVarConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(AiDebugCollisionSimConVar()).~CSimConCommand();
    gAiDebugCollisionSimConVarConstructed = false;
  }

  /**
   * Address: 0x00BCB250 (FUN_00BCB250, register_AI_DebugCollision_ConAlias)
   *
   * What it does:
   * Registers the `AI_DebugCollision` console alias and installs startup
   * cleanup.
   */
  void register_AI_DebugCollision_ConAlias()
  {
    ConAlias_AI_DebugCollision().InitializeRecovered(
      "Toggle on/off collision detection",
      "AI_DebugCollision",
      "DoSimCommand AI_DebugCollision"
    );
    RegisterAtexitCleanup<&cleanup_AI_DebugCollision_ConAlias>();
  }

  /**
   * Address: 0x00BCB280 (FUN_00BCB280, register_AI_DebugCollision_SimConVarDef)
   *
   * What it does:
   * Registers `AI_DebugCollision` sim convar and installs startup cleanup.
   */
  void register_AI_DebugCollision_SimConVarDef()
  {
    (void)ConstructAiDebugCollisionSimConVar();
    RegisterAtexitCleanup<&cleanup_AI_DebugCollision_SimConVarDef>();
  }

  /**
   * Address: 0x00BF6160 (FUN_00BF6160, sub_BF6160)
   *
   * What it does:
   * Clears startup-owned `AI_DebugIgnorePlayableRect` alias payload and
   * unregisters command binding.
   */
  void cleanup_AI_DebugIgnorePlayableRect_ConAlias()
  {
    ConAlias_AI_DebugIgnorePlayableRect().ShutdownRecovered();
  }

  /**
   * Address: 0x00BF61B0 (FUN_00BF61B0, sub_BF61B0)
   *
   * What it does:
   * Destroys startup-owned `AI_DebugIgnorePlayableRect` sim-convar command
   * object.
   */
  void cleanup_AI_DebugIgnorePlayableRect_SimConVarDef()
  {
    if (!gAiDebugIgnorePlayableRectSimConVarConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(AiDebugIgnorePlayableRectSimConVar()).~CSimConCommand();
    gAiDebugIgnorePlayableRectSimConVarConstructed = false;
  }

  /**
   * Address: 0x00BCB2D0 (FUN_00BCB2D0, register_AI_DebugIgnorePlayableRect_ConAlias)
   *
   * What it does:
   * Registers the `AI_DebugIgnorePlayableRect` console alias and installs
   * startup cleanup.
   */
  void register_AI_DebugIgnorePlayableRect_ConAlias()
  {
    ConAlias_AI_DebugIgnorePlayableRect().InitializeRecovered(
      "Toggle on/off ignore playable rect",
      "AI_DebugIgnorePlayableRect",
      "DoSimCommand AI_DebugIgnorePlayableRect"
    );
    RegisterAtexitCleanup<&cleanup_AI_DebugIgnorePlayableRect_ConAlias>();
  }

  /**
   * Address: 0x00BCB300 (FUN_00BCB300, register_AI_DebugIgnorePlayableRect_SimConVarDef)
   *
   * What it does:
   * Registers `AI_DebugIgnorePlayableRect` sim convar and installs startup
   * cleanup.
   */
  void register_AI_DebugIgnorePlayableRect_SimConVarDef()
  {
    (void)ConstructAiDebugIgnorePlayableRectSimConVar();
    RegisterAtexitCleanup<&cleanup_AI_DebugIgnorePlayableRect_SimConVarDef>();
  }

  /**
   * Address: 0x00BF9180 (FUN_00BF9180, cleanup_ai_InstaBuild_ConAlias)
   *
   * What it does:
   * Clears startup-owned `ai_InstaBuild` alias payload and unregisters command
   * binding.
   */
  void cleanup_ai_InstaBuild_ConAlias()
  {
    ConAlias_ai_InstaBuild().ShutdownRecovered();
  }

  /**
   * Address: 0x00BF91D0 (FUN_00BF91D0, cleanup_ai_InstaBuild_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `ai_InstaBuild` sim-convar command object.
   */
  void cleanup_ai_InstaBuild_SimConVar()
  {
    if (TSimConVar<bool>*& conVar = SimConVar_ai_InstaBuild_slot(); conVar != nullptr) {
      delete conVar;
      conVar = nullptr;
    }
  }

  /**
   * Address: 0x00BF91E0 (FUN_00BF91E0, cleanup_ai_FreeBuild_ConAlias)
   *
   * What it does:
   * Clears startup-owned `ai_FreeBuild` alias payload and unregisters command
   * binding.
   */
  void cleanup_ai_FreeBuild_ConAlias()
  {
    ConAlias_ai_FreeBuild().ShutdownRecovered();
  }

  /**
   * Address: 0x00BF9230 (FUN_00BF9230, cleanup_ai_FreeBuild_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `ai_FreeBuild` sim-convar command object.
   */
  void cleanup_ai_FreeBuild_SimConVar()
  {
    if (TSimConVar<bool>*& conVar = SimConVar_ai_FreeBuild_slot(); conVar != nullptr) {
      delete conVar;
      conVar = nullptr;
    }
  }

  /**
   * Address: 0x00BCF710 (FUN_00BCF710, register_ai_InstaBuild_ConAliasDef)
   *
   * What it does:
   * Registers the `ai_InstaBuild` console alias and installs startup cleanup.
   */
  void register_ai_InstaBuild_ConAliasDef()
  {
    ConAlias_ai_InstaBuild().InitializeRecovered(
      "Units build instantly.",
      "ai_InstaBuild",
      "DoSimCommand ai_InstaBuild"
    );
    RegisterAtexitCleanup<&cleanup_ai_InstaBuild_ConAlias>();
  }

  /**
   * Address: 0x00BCF740 (FUN_00BCF740, register_ai_InstaBuild_SimConVarDef)
   *
   * What it does:
   * Registers the `ai_InstaBuild` sim convar definition and installs startup
   * cleanup.
   */
  void register_ai_InstaBuild_SimConVarDef()
  {
    if (TSimConVar<bool>*& conVar = SimConVar_ai_InstaBuild_slot(); conVar == nullptr) {
      conVar = new TSimConVar<bool>(false, "ai_InstaBuild", false);
    }
    RegisterAtexitCleanup<&cleanup_ai_InstaBuild_SimConVar>();
  }

  /**
   * Address: 0x00BCF790 (FUN_00BCF790, register_ai_FreeBuild_ConAliasDef)
   *
   * What it does:
   * Registers the `ai_FreeBuild` console alias and installs startup cleanup.
   */
  void register_ai_FreeBuild_ConAliasDef()
  {
    ConAlias_ai_FreeBuild().InitializeRecovered(
      "Unit build costs are 0",
      "ai_FreeBuild",
      "DoSimCommand ai_FreeBuild"
    );
    RegisterAtexitCleanup<&cleanup_ai_FreeBuild_ConAlias>();
  }

  /**
   * Address: 0x00BCF7C0 (FUN_00BCF7C0, register_ai_FreeBuild_SimConVarDef)
   *
   * What it does:
   * Registers the `ai_FreeBuild` sim convar definition and installs startup
   * cleanup.
   */
  void register_ai_FreeBuild_SimConVarDef()
  {
    if (TSimConVar<bool>*& conVar = SimConVar_ai_FreeBuild_slot(); conVar == nullptr) {
      conVar = new TSimConVar<bool>(false, "ai_FreeBuild", false);
    }
    RegisterAtexitCleanup<&cleanup_ai_FreeBuild_SimConVar>();
  }

  /**
   * Address: 0x00BF8040 (FUN_00BF8040, cleanup_ai_SteeringAirTolerance_ConAlias)
   *
   * What it does:
   * Clears startup-owned `ai_SteeringAirTolerance` alias payload and unregisters
   * command binding.
   */
  void cleanup_ai_SteeringAirTolerance_ConAlias()
  {
    ConAlias_ai_SteeringAirTolerance().ShutdownRecovered();
  }

  /**
   * Address: 0x00BF8090 (FUN_00BF8090, cleanup_ai_SteeringAirTolerance_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `ai_SteeringAirTolerance` sim-convar command object.
   */
  void cleanup_ai_SteeringAirTolerance_SimConVar()
  {
    if (!gAiSteeringAirToleranceConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(AiSteeringAirToleranceSimConVar()).~CSimConCommand();
    gAiSteeringAirToleranceConstructed = false;
  }

  /**
   * Address: 0x00BF80A0 (FUN_00BF80A0, cleanup_TConVar_ren_Steering)
   *
   * What it does:
   * Tears down startup-owned `ren_Steering` console convar registration.
   */
  void cleanup_TConVar_ren_Steering()
  {
    TeardownConCommandRegistration(ConVar_ren_Steering());
  }

  /**
   * Address: 0x00BCE3A0 (FUN_00BCE3A0, register_ai_SteeringAirTolerance_ConAliasDef)
   *
   * What it does:
   * Registers `ai_SteeringAirTolerance` console alias and installs startup
   * cleanup.
   */
  void register_ai_SteeringAirTolerance_ConAliasDef()
  {
    ConAlias_ai_SteeringAirTolerance().InitializeRecovered(
      "Tolerance used to detect whether an aircraft has reached its destination.",
      "ai_SteeringAirTolerance",
      "DoSimCommand ai_SteeringAirTolerance"
    );
    RegisterAtexitCleanup<&cleanup_ai_SteeringAirTolerance_ConAlias>();
  }

  /**
   * Address: 0x00BCE3D0 (FUN_00BCE3D0, register_ai_SteeringAirTolerance_SimConVarDef)
   *
   * What it does:
   * Registers `ai_SteeringAirTolerance` sim convar and installs startup
   * cleanup.
   */
  void register_ai_SteeringAirTolerance_SimConVarDef()
  {
    (void)ConstructAiSteeringAirToleranceSimConVar();
    RegisterAtexitCleanup<&cleanup_ai_SteeringAirTolerance_SimConVar>();
  }

  /**
   * Address: 0x00BCE420 (FUN_00BCE420, register_TConVar_ren_Steering)
   *
   * What it does:
   * Registers startup `ren_Steering` convar and installs startup cleanup.
   */
  void register_TConVar_ren_Steering()
  {
    RegisterConCommand(ConVar_ren_Steering());
    RegisterAtexitCleanup<&cleanup_TConVar_ren_Steering>();
  }

  /**
   * Address: 0x00BF81E0 (FUN_00BF81E0, cleanup_WeaponTerrainBlockageTest_ConAlias)
   *
   * What it does:
   * Clears startup-owned `WeaponTerrainBlockageTest` alias payload and
   * unregisters command binding.
   */
  void cleanup_WeaponTerrainBlockageTest_ConAlias()
  {
    ConAlias_WeaponTerrainBlockageTest().ShutdownRecovered();
  }

  /**
   * Address: 0x00BCE6D0 (FUN_00BCE6D0, register_WeaponTerrainBlockageTest_ConAliasDef)
   *
   * What it does:
   * Registers the `WeaponTerrainBlockageTest` console alias and installs
   * startup cleanup.
   */
  void register_WeaponTerrainBlockageTest_ConAliasDef()
  {
    ConAlias_WeaponTerrainBlockageTest().InitializeRecovered(
      "Toggle on/off wepaon collision tests against terrain blockages",
      "WeaponTerrainBlockageTest",
      "DoSimCommand WeaponTerrainBlockageTest"
    );
    RegisterAtexitCleanup<&cleanup_WeaponTerrainBlockageTest_ConAlias>();
  }

  /**
   * Address: 0x00BF8230 (FUN_00BF8230, cleanup_WeaponTerrainBlockageTest_SimConVar)
   *
   * What it does:
   * Destroys startup-owned `WeaponTerrainBlockageTest` sim-convar storage.
   */
  void cleanup_WeaponTerrainBlockageTest_SimConVar()
  {
    if (!gWeaponTerrainBlockageTestConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(WeaponTerrainBlockageTestSimConVar()).~CSimConCommand();
    gWeaponTerrainBlockageTestConstructed = false;
  }

  /**
   * Address: 0x00BCE700 (FUN_00BCE700, register_WeaponTerrainBlockageTest_SimConVarDef)
   *
   * What it does:
   * Registers the `WeaponTerrainBlockageTest` sim convar and installs startup
   * cleanup.
   */
  void register_WeaponTerrainBlockageTest_SimConVarDef()
  {
    (void)ConstructWeaponTerrainBlockageTestSimConVar();
    RegisterAtexitCleanup<&cleanup_WeaponTerrainBlockageTest_SimConVar>();
  }

  /**
   * Address: 0x00BFCB00 (FUN_00BFCB00, sub_BFCB00)
   *
   * What it does:
   * Clears startup-owned `Purge` alias payload and unregisters command binding.
   */
  void cleanup_Purge_ConAlias()
  {
    ConAlias_Purge().ShutdownRecovered();
  }

  /**
   * Address: 0x00BFCB50 (FUN_00BFCB50, cleanup_Purge_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `Purge` sim-command callback object.
   */
  void cleanup_Purge_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_Purge_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
    * Alias of FUN_00BFE370 (non-canonical helper lane).
   *
   * What it does:
   * Tears down `DebugAIStatesOff` alias registration and frees startup-owned
   * alias storage.
   */
  void cleanup_DebugAIStatesOff_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_DebugAIStatesOff_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFE3C0 (FUN_00BFE3C0, sub_BFE3C0)
   *
   * What it does:
   * Destroys startup-owned `DebugAIStatesOff` sim-command callback object.
   */
  void cleanup_DebugAIStatesOff_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DebugAIStatesOff_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BFE310 (FUN_00BFE310, sub_BFE310)
   */
  void cleanup_DebugAIStatesOn_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_DebugAIStatesOn_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFE360 (FUN_00BFE360, sub_BFE360)
   */
  void cleanup_DebugAIStatesOn_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DebugAIStatesOn_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00C01390 (FUN_00C01390, cleanup_TrackStats_ConAlias)
   *
   * What it does:
   * Clears startup-owned `TrackStats` alias payload and unregisters command
   * binding.
   */
  void cleanup_TrackStats_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_TrackStats_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00C013E0 (FUN_00C013E0, cleanup_TrackStats_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `TrackStats` sim-command callback object.
   */
  void cleanup_TrackStats_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_TrackStats_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00C013F0 (FUN_00C013F0, cleanup_DumpUnits_ConAlias)
   *
   * What it does:
   * Clears startup-owned `DumpUnits` alias payload and unregisters command
   * binding.
   */
  void cleanup_DumpUnits_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_DumpUnits_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00C01440 (FUN_00C01440, cleanup_DumpUnits_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `DumpUnits` sim-command callback object.
   */
  void cleanup_DumpUnits_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DumpUnits_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BFE2B0 (FUN_00BFE2B0, sub_BFE2B0)
   */
  void cleanup_DebugSetProductionInActive_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_DebugSetProductionInActive_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFE300 (FUN_00BFE300, sub_BFE300)
   */
  void cleanup_DebugSetProductionInActive_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DebugSetProductionInActive_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BFE250 (FUN_00BFE250, sub_BFE250)
   */
  void cleanup_DebugSetProductionActive_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_DebugSetProductionActive_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFE2A0 (FUN_00BFE2A0, sub_BFE2A0)
   */
  void cleanup_DebugSetProductionActive_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DebugSetProductionActive_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BFE1F0 (FUN_00BFE1F0, sub_BFE1F0)
   */
  void cleanup_DebugSetConsumptionInActive_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_DebugSetConsumptionInActive_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFE240 (FUN_00BFE240, sub_BFE240)
   */
  void cleanup_DebugSetConsumptionInActive_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DebugSetConsumptionInActive_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BFE190 (FUN_00BFE190, sub_BFE190)
   */
  void cleanup_DebugSetConsumptionActive_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_DebugSetConsumptionActive_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFE1E0 (FUN_00BFE1E0, sub_BFE1E0)
   */
  void cleanup_DebugSetConsumptionActive_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DebugSetConsumptionActive_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BD8380 (FUN_00BD8380, register_DebugAIStatesOff_ConAlias)
   *
   * What it does:
   * Registers `DebugAIStatesOff` console alias and installs matching cleanup
   * thunk in startup `atexit` lane.
   */
  void register_DebugAIStatesOff_ConAlias()
  {
    EnsureConAliasRegistration(
      ConAlias_DebugAIStatesOff_slot(),
      "debug function to show some AI states",
      "DebugAIStatesOff",
      "DoSimCommand DebugAIStatesOff"
    );
    RegisterAtexitCleanup<&cleanup_DebugAIStatesOff_ConAlias>();
  }

  /**
   * Address: 0x00BD83B0 (FUN_00BD83B0, register_DebugAIStatesOff_SimConFunc)
   */
  void register_DebugAIStatesOff_SimConFunc()
  {
    EnsureSimConFuncRegistration<&Sim::DebugAIStatesOff>(
      SimConFunc_DebugAIStatesOff_slot(),
      "DebugAIStatesOff"
    );
    RegisterAtexitCleanup<&cleanup_DebugAIStatesOff_SimConFunc>();
  }

  /**
   * Address: 0x00BD8310 (FUN_00BD8310, register_DebugAIStatesOn_ConAlias)
   */
  void register_DebugAIStatesOn_ConAlias()
  {
    EnsureConAliasRegistration(
      ConAlias_DebugAIStatesOn_slot(),
      "debug function to show some AI states",
      "DebugAIStatesOn",
      "DoSimCommand DebugAIStatesOn"
    );
    RegisterAtexitCleanup<&cleanup_DebugAIStatesOn_ConAlias>();
  }

  /**
   * Address: 0x00BD8340 (FUN_00BD8340, register_DebugAIStatesOn_SimConFunc)
   */
  void register_DebugAIStatesOn_SimConFunc()
  {
    EnsureSimConFuncRegistration<&Sim::DebugAIStatesOn>(
      SimConFunc_DebugAIStatesOn_slot(),
      "DebugAIStatesOn"
    );
    RegisterAtexitCleanup<&cleanup_DebugAIStatesOn_SimConFunc>();
  }

  /**
   * Address: 0x00BDC350 (FUN_00BDC350, register_TrackStats_ConAliasDef)
   *
   * What it does:
   * Registers the `TrackStats` console alias and installs startup cleanup.
   */
  void register_TrackStats_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_TrackStats_slot(),
      "Begin/End tracking stats of selected units.",
      "TrackStats",
      "DoSimCommand TrackStats"
    );
    RegisterAtexitCleanup<&cleanup_TrackStats_ConAlias>();
  }

  /**
   * Address: 0x00BDC380 (FUN_00BDC380, register_TrackStats_SimConFuncDef)
   *
   * What it does:
   * Registers the `TrackStats` sim command callback and installs startup
   * cleanup.
   */
  void register_TrackStats_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::TrackStats>(
      SimConFunc_TrackStats_slot(),
      "TrackStats"
    );
    RegisterAtexitCleanup<&cleanup_TrackStats_SimConFunc>();
  }

  /**
   * Address: 0x00BDC3C0 (FUN_00BDC3C0, register_DumpUnits_ConAliasDef)
   *
   * What it does:
   * Registers the `DumpUnits` console alias and installs startup cleanup.
   */
  void register_DumpUnits_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_DumpUnits_slot(),
      "Print out units in play",
      "DumpUnits",
      "DoSimCommand DumpUnits"
    );
    RegisterAtexitCleanup<&cleanup_DumpUnits_ConAlias>();
  }

  /**
   * Address: 0x00BDC3F0 (FUN_00BDC3F0, register_DumpUnits_SimConFuncDef)
   *
   * What it does:
   * Registers the `DumpUnits` sim command callback and installs startup
   * cleanup.
   */
  void register_DumpUnits_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::DumpUnits>(
      SimConFunc_DumpUnits_slot(),
      "DumpUnits"
    );
    RegisterAtexitCleanup<&cleanup_DumpUnits_SimConFunc>();
  }

  /**
   * Address: 0x00BD82A0 (FUN_00BD82A0, register_DebugSetProductionInActive_ConAliasDef)
   */
  void register_DebugSetProductionInActive_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_DebugSetProductionInActive_slot(),
      "debug function to turn selected units production of resources into inactive state",
      "DebugSetProductionInActive",
      "DoSimCommand DebugSetProductionInActive"
    );
    RegisterAtexitCleanup<&cleanup_DebugSetProductionInActive_ConAlias>();
  }

  /**
   * Address: 0x00BD82D0 (FUN_00BD82D0, register_DebugSetProductionInActive_SimConFuncDef)
   */
  void register_DebugSetProductionInActive_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::DebugSetProductionInActive>(
      SimConFunc_DebugSetProductionInActive_slot(),
      "DebugSetProductionInActive"
    );
    RegisterAtexitCleanup<&cleanup_DebugSetProductionInActive_SimConFunc>();
  }

  /**
   * Address: 0x00BD8230 (FUN_00BD8230, register_DebugSetProductionActive_ConAliasDef)
   */
  void register_DebugSetProductionActive_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_DebugSetProductionActive_slot(),
      "debug function to turn selected units production of resources into active state",
      "DebugSetProductionActive",
      "DoSimCommand DebugSetProductionActive"
    );
    RegisterAtexitCleanup<&cleanup_DebugSetProductionActive_ConAlias>();
  }

  /**
   * Address: 0x00BD8260 (FUN_00BD8260, register_DebugSetProductionActive_SimConFuncDef)
   */
  void register_DebugSetProductionActive_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::DebugSetProductionActive>(
      SimConFunc_DebugSetProductionActive_slot(),
      "DebugSetProductionActive"
    );
    RegisterAtexitCleanup<&cleanup_DebugSetProductionActive_SimConFunc>();
  }

  /**
   * Address: 0x00BD81C0 (FUN_00BD81C0, register_DebugSetConsumptionInActive_ConAliasDef)
   */
  void register_DebugSetConsumptionInActive_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_DebugSetConsumptionInActive_slot(),
      "debug function to turn selected units consumption of resources into inactive state",
      "DebugSetConsumptionInActive",
      "DoSimCommand DebugSetConsumptionInActive"
    );
    RegisterAtexitCleanup<&cleanup_DebugSetConsumptionInActive_ConAlias>();
  }

  /**
   * Address: 0x00BD81F0 (FUN_00BD81F0, register_DebugSetConsumptionInActive_SimConFuncDef)
   */
  void register_DebugSetConsumptionInActive_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::DebugSetConsumptionInActive>(
      SimConFunc_DebugSetConsumptionInActive_slot(),
      "DebugSetConsumptionInActive"
    );
    RegisterAtexitCleanup<&cleanup_DebugSetConsumptionInActive_SimConFunc>();
  }

  /**
   * Address: 0x00BD8150 (FUN_00BD8150, register_DebugSetConsumptionActive_ConAliasDef)
   */
  void register_DebugSetConsumptionActive_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_DebugSetConsumptionActive_slot(),
      "debug function to turn selected units consumption of resources into active state",
      "DebugSetConsumptionActive",
      "DoSimCommand DebugSetConsumptionActive"
    );
    RegisterAtexitCleanup<&cleanup_DebugSetConsumptionActive_ConAlias>();
  }

  /**
   * Address: 0x00BD8180 (FUN_00BD8180, register_DebugSetConsumptionActive_SimConFuncDef)
   */
  void register_DebugSetConsumptionActive_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::DebugSetConsumptionActive>(
      SimConFunc_DebugSetConsumptionActive_slot(),
      "DebugSetConsumptionActive"
    );
    RegisterAtexitCleanup<&cleanup_DebugSetConsumptionActive_SimConFunc>();
  }

  /**
   * Address: 0x00BD51E0 (FUN_00BD51E0, register_Purge_ConAliasDef)
   *
   * What it does:
   * Registers the `Purge` console alias and installs its startup cleanup thunk.
   */
  void register_Purge_ConAliasDef()
  {
    ConAlias_Purge().InitializeRecovered(
      "Purge all entities of a specified type <shield|projectile|unit|all>.  If any optional army indices are supplied, destroy those army's entities.",
      "Purge",
      "DoSimCommand Purge"
    );
    RegisterAtexitCleanup<&cleanup_Purge_ConAlias>();
  }

  /**
   * Address: 0x00BD5210 (FUN_00BD5210, register_Purge_SimConFuncDef)
   *
   * What it does:
   * Registers the `Purge` sim command callback and installs startup cleanup.
   */
  void register_Purge_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::Purge>(SimConFunc_Purge_slot(), "Purge");
    RegisterAtexitCleanup<&cleanup_Purge_SimConFunc>();
  }

  /**
   * Address: 0x00BFDD50 (FUN_00BFDD50, cleanup_KillAll_ConAlias)
   *
   * What it does:
   * Tears down `KillAll` alias registration and frees startup-owned alias
   * storage.
   */
  void cleanup_KillAll_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_KillAll_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFDDA0 (FUN_00BFDDA0, cleanup_KillAll_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `KillAll` sim-command callback object.
   */
  void cleanup_KillAll_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_KillAll_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BFDDB0 (FUN_00BFDDB0, cleanup_DestroyAll_ConAlias)
   *
   * What it does:
   * Tears down `DestroyAll` alias registration and frees startup-owned alias
   * storage.
   */
  void cleanup_DestroyAll_ConAlias()
  {
    if (CConAlias*& alias = ConAlias_DestroyAll_slot(); alias != nullptr) {
      alias->ShutdownRecovered();
      delete alias;
      alias = nullptr;
    }
  }

  /**
   * Address: 0x00BFDE00 (FUN_00BFDE00, cleanup_DestroyAll_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `DestroyAll` sim-command callback object.
   */
  void cleanup_DestroyAll_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DestroyAll_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BD6C90 (FUN_00BD6C90, register_KillAll_ConAliasDef)
   *
   * What it does:
   * Registers the `KillAll` console alias and attaches startup cleanup.
   */
  void register_KillAll_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_KillAll_slot(),
      "Kill all units",
      "KillAll",
      "DoSimCommand KillAll"
    );
    RegisterAtexitCleanup<&cleanup_KillAll_ConAlias>();
  }

  /**
   * Address: 0x00BD6CC0 (FUN_00BD6CC0, register_KillAll_SimConFuncDef)
   *
   * What it does:
   * Registers the `KillAll` sim command callback and attaches startup cleanup.
   */
  void register_KillAll_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::KillAll>(SimConFunc_KillAll_slot(), "KillAll");
    RegisterAtexitCleanup<&cleanup_KillAll_SimConFunc>();
  }

  /**
   * Address: 0x00BD6D00 (FUN_00BD6D00, register_DestroyAll_ConAliasDef)
   *
   * What it does:
   * Registers the `DestroyAll` console alias and attaches startup cleanup.
   */
  void register_DestroyAll_ConAliasDef()
  {
    EnsureConAliasRegistration(
      ConAlias_DestroyAll_slot(),
      "Destroy all units.  If any optional army indices are supplied, destroy those army's units.",
      "DestroyAll",
      "DoSimCommand DestroyAll"
    );
    RegisterAtexitCleanup<&cleanup_DestroyAll_ConAlias>();
  }

  /**
   * Address: 0x00BD6D30 (FUN_00BD6D30, register_DestroyAll_SimConFuncDef)
   *
   * What it does:
   * Registers the `DestroyAll` sim command callback and attaches startup cleanup.
   */
  void register_DestroyAll_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::DestroyAll>(SimConFunc_DestroyAll_slot(), "DestroyAll");
    RegisterAtexitCleanup<&cleanup_DestroyAll_SimConFunc>();
  }
} // namespace moho
