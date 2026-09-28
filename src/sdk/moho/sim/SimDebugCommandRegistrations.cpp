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

  alignas(moho::CSimConFunc) unsigned char gDbgSimConFuncStorage[sizeof(moho::CSimConFunc)] = {};
  bool gDbgSimConFuncConstructed = false;

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

  /**
   * Address: 0x00BCE420 (FUN_00BCE420, dynamic initializer for `gTConVar_ren_Steering`)
   * Address: 0x00BF80A0 (FUN_00BF80A0, dynamic atexit destructor for `gTConVar_ren_Steering`)
   */
  moho::TConVar<bool> gTConVar_ren_Steering("ren_Steering", "", reinterpret_cast<bool*>(&moho::ren_Steering));

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_SallyShears_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_BlingBling_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_ZeroExtraStorage_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DamageUnit_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_AddImpulse_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  // `path_GeneratePreview` is constructed in-place (matching the binary's
  // 0x00BDC850 call shape: base `CSimConCommand` ctor invoked directly on
  // static storage, then `__vftable`/`mFunc` assigned by hand, exactly what
  // `CSimConFunc`'s own constructor does) rather than heap-allocated, so it
  // uses the placement-storage pattern below (matching `dbg`'s), not the
  // `SimConFunc_*_slot()`/`EnsureSimConFuncRegistration` heap pattern.
  alignas(moho::CSimConFunc) unsigned char gPathGeneratePreviewSimConFuncStorage[sizeof(moho::CSimConFunc)] = {};
  bool gPathGeneratePreviewSimConFuncConstructed = false;

  [[nodiscard]] moho::CSimConFunc& PathGeneratePreviewSimConFunc()
  {
    return *std::launder(reinterpret_cast<moho::CSimConFunc*>(gPathGeneratePreviewSimConFuncStorage));
  }

  [[nodiscard]] moho::CSimConFunc& ConstructPathGeneratePreviewSimConFunc()
  {
    if (!gPathGeneratePreviewSimConFuncConstructed) {
      new (gPathGeneratePreviewSimConFuncStorage) moho::CSimConFunc(true, "path_GeneratePreview", &moho::Sim::path_GeneratePreview);
      gPathGeneratePreviewSimConFuncConstructed = true;
    }

    return PathGeneratePreviewSimConFunc();
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

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugAIStatesOff_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugAIStatesOn_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_TrackStats_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DumpUnits_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugSetPlayableRect_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugDumpArmyStats_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugSetProductionInActive_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugSetProductionActive_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugSetConsumptionInActive_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
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

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_KillAll_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
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

  /**
   * Address: 0x00BDB130 (FUN_00BDB130, dynamic initializer for `gConAlias_sim_TestVarBool`)
   * Address: 0x00C00670 (FUN_00C00670, dynamic atexit destructor for `gConAlias_sim_TestVarBool`)
   */
  moho::CConAlias gConAlias_sim_TestVarBool("sim_TestVarBool", "Test variable - not used.", "DoSimCommand sim_TestVarBool");

  /**
   * Address: 0x00BDB1B0 (FUN_00BDB1B0, dynamic initializer for `gConAlias_sim_TestVar`)
   * Address: 0x00C006D0 (FUN_00C006D0, dynamic atexit destructor for `gConAlias_sim_TestVar`)
   */
  moho::CConAlias gConAlias_sim_TestVar("sim_TestVar", "Test variable - not used.", "DoSimCommand sim_TestVar");

  /**
   * Address: 0x00BDB230 (FUN_00BDB230, dynamic initializer for `gConAlias_sim_TestVarUByte`)
   * Address: 0x00C00730 (FUN_00C00730, dynamic atexit destructor for `gConAlias_sim_TestVarUByte`)
   */
  moho::CConAlias gConAlias_sim_TestVarUByte("sim_TestVarUByte", "Test variable - not used.", "DoSimCommand sim_TestVarUByte");

  /**
   * Address: 0x00BDB2B0 (FUN_00BDB2B0, dynamic initializer for `gConAlias_sim_TestVarFloat`)
   * Address: 0x00C00790 (FUN_00C00790, dynamic atexit destructor for `gConAlias_sim_TestVarFloat`)
   */
  moho::CConAlias gConAlias_sim_TestVarFloat("sim_TestVarFloat", "Test variable - not used.", "DoSimCommand sim_TestVarFloat");

  /**
   * Address: 0x00BDB330 (FUN_00BDB330, dynamic initializer for `gConAlias_sim_TestVarStr`)
   * Address: 0x00C007F0 (FUN_00C007F0, dynamic atexit destructor for `gConAlias_sim_TestVarStr`)
   */
  moho::CConAlias gConAlias_sim_TestVarStr("sim_TestVarStr", "Test variable - not used.", "DoSimCommand sim_TestVarStr");

  /**
   * Address: 0x00BDB3A0 (FUN_00BDB3A0, dynamic initializer for `gConAlias_sim_TestFunc`)
   * Address: 0x00C00880 (FUN_00C00880, dynamic atexit destructor for `gConAlias_sim_TestFunc`)
   */
  moho::CConAlias gConAlias_sim_TestFunc("sim_TestFunc", "Test function - not used.", "DoSimCommand sim_TestFunc");

  /**
   * Address: 0x00BDB410 (FUN_00BDB410, dynamic initializer for `gConAlias_SimLog`)
   * Address: 0x00C008E0 (FUN_00C008E0, dynamic atexit destructor for `gConAlias_SimLog`)
   */
  moho::CConAlias gConAlias_SimLog("SimLog", "Log a string (for debugging purposes)", "DoSimCommand SimLog");

  /**
   * Address: 0x00BDB480 (FUN_00BDB480, dynamic initializer for `gConAlias_SimWarn`)
   * Address: 0x00C00940 (FUN_00C00940, dynamic atexit destructor for `gConAlias_SimWarn`)
   */
  moho::CConAlias gConAlias_SimWarn("SimWarn", "Log a warning string (for debugging purposes)", "DoSimCommand SimWarn");

  /**
   * Address: 0x00BDB4F0 (FUN_00BDB4F0, dynamic initializer for `gConAlias_SimError`)
   * Address: 0x00C009A0 (FUN_00C009A0, dynamic atexit destructor for `gConAlias_SimError`)
   */
  moho::CConAlias gConAlias_SimError("SimError", "Log an error string (for debugging purposes)", "DoSimCommand SimError");

  /**
   * Address: 0x00BDB560 (FUN_00BDB560, dynamic initializer for `gConAlias_SimAssert`)
   * Address: 0x00C00A00 (FUN_00C00A00, dynamic atexit destructor for `gConAlias_SimAssert`)
   */
  moho::CConAlias gConAlias_SimAssert("SimAssert", "Fail an assertion (for debugging purposes)", "DoSimCommand SimAssert");

  /**
   * Address: 0x00BDB5D0 (FUN_00BDB5D0, dynamic initializer for `gConAlias_SimCrash`)
   * Address: 0x00C00A60 (FUN_00C00A60, dynamic atexit destructor for `gConAlias_SimCrash`)
   */
  moho::CConAlias gConAlias_SimCrash("SimCrash", "Cause a crash (for debugging purposes)", "DoSimCommand SimCrash");

  /**
   * Address: 0x00BDBAD0 (FUN_00BDBAD0, dynamic initializer for `gConAlias_path_BackgroundUpdate`)
   * Address: 0x00C00D40 (FUN_00C00D40, dynamic atexit destructor for `gConAlias_path_BackgroundUpdate`)
   */
  moho::CConAlias gConAlias_path_BackgroundUpdate("path_BackgroundUpdate", "Update pathfinding tables in background", "DoSimCommand path_BackgroundUpdate");

  /**
   * Address: 0x00BDBB50 (FUN_00BDBB50, dynamic initializer for `gConAlias_path_BackgroundBudget`)
   * Address: 0x00C00DA0 (FUN_00C00DA0, dynamic atexit destructor for `gConAlias_path_BackgroundBudget`)
   */
  moho::CConAlias gConAlias_path_BackgroundBudget("path_BackgroundBudget", "Maximum number of steps to run pathfinder in background", "DoSimCommand path_BackgroundBudget");

  /**
   * Address: 0x00BDBBD0 (FUN_00BDBBD0, dynamic initializer for `gConAlias_sim_ChecksumPeriod`)
   * Address: 0x00C00E00 (FUN_00C00E00, dynamic atexit destructor for `gConAlias_sim_ChecksumPeriod`)
   */
  moho::CConAlias gConAlias_sim_ChecksumPeriod("sim_ChecksumPeriod", "How many beats between checksums.", "DoSimCommand sim_ChecksumPeriod");

  /**
   * Address: 0x00BDBD50 (FUN_00BDBD50, dynamic initializer for `gConAlias_sim_DebugCrash`)
   * Address: 0x00C00F50 (FUN_00C00F50, dynamic atexit destructor for `gConAlias_sim_DebugCrash`)
   */
  moho::CConAlias gConAlias_sim_DebugCrash("sim_DebugCrash", "Crash the sim.", "DoSimCommand sim_DebugCrash");

  /**
   * Address: 0x00BDBF10 (FUN_00BDBF10, dynamic initializer for `gConAlias_SimLua`)
   * Address: 0x00C01210 (FUN_00C01210, dynamic atexit destructor for `gConAlias_SimLua`)
   */
  moho::CConAlias gConAlias_SimLua("SimLua", "Run some lua code in the sim's Lua.", "DoSimCommand SimLua");

  /**
   * Address: 0x00BDC220 (FUN_00BDC220, dynamic initializer for `gConAlias_DebugMoveCamera`)
   * Address: 0x00C01330 (FUN_00C01330, dynamic atexit destructor for `gConAlias_DebugMoveCamera`)
   */
  moho::CConAlias gConAlias_DebugMoveCamera("DebugMoveCamera", "Debug function for moving the camera in sim script.", "DoSimCommand DebugMoveCamera");

  /**
   * Address: 0x00BDC7A0 (FUN_00BDC7A0, dynamic initializer for `gConAlias_path_TimeoutPreview`)
   * Address: 0x00C01970 (FUN_00C01970, dynamic atexit destructor for `gConAlias_path_TimeoutPreview`)
   */
  moho::CConAlias gConAlias_path_TimeoutPreview("path_TimeoutPreview", "Maximum number of ticks to allow pathfinder preview to take", "DoSimCommand path_TimeoutPreview");

  /**
   * Address: 0x00BDC820 (FUN_00BDC820, dynamic initializer for `gConAlias_path_GeneratePreview`)
   * Address: 0x00C019D0 (FUN_00C019D0, dynamic atexit destructor for `gConAlias_path_GeneratePreview`)
   */
  moho::CConAlias gConAlias_path_GeneratePreview("path_GeneratePreview", "Do a pathfind for the UI preview", "DoSimCommand path_GeneratePreview");

  struct SimDebugCommandRegistrationsBootstrap
  {
    SimDebugCommandRegistrationsBootstrap()
    {
      moho::register_NeedRefuelThresholdRatio_SimConVarDef();
      moho::register_NeedRepairThresholdRatio_SimConVarDef();
      moho::register_SallyShears_SimConFuncDef();
      moho::register_BlingBling_SimConFunc();
      moho::register_ZeroExtraStorage_SimConFuncDef();
      moho::register_DamageUnit_SimConFunc();
      moho::register_AddImpulse_SimConFuncDef();
      moho::register_WeaponTerrainBlockageTest_SimConVarDef();
      moho::register_dbg_SimConFunc();
      moho::register_NoDamage_SimConVarDef();
      moho::register_AI_RunOpponentAI_SimConVarDef();
      moho::register_AI_DebugArmyIndex_SimConDef();
      moho::register_AI_RenderDebugAttackVectors_SimConVarDef();
      moho::register_AI_RenderDebugPlayableRect_SimConVarDef();
      moho::register_AI_DebugCollision_SimConVarDef();
      moho::register_AI_DebugIgnorePlayableRect_SimConVarDef();
      moho::register_ai_InstaBuild_SimConVarDef();
      moho::register_ai_FreeBuild_SimConVarDef();
      moho::register_ai_SteeringAirTolerance_SimConVarDef();
      moho::register_Purge_SimConFuncDef();
      moho::register_KillAll_SimConFuncDef();
      moho::register_DestroyAll_SimConFuncDef();
      moho::register_DebugSetConsumptionActive_SimConFuncDef();
      moho::register_DebugSetConsumptionInActive_SimConFuncDef();
      moho::register_DebugSetProductionActive_SimConFuncDef();
      moho::register_DebugSetProductionInActive_SimConFuncDef();
      moho::register_DebugAIStatesOn_SimConFunc();
      moho::register_DebugAIStatesOff_SimConFunc();
      moho::register_TrackStats_SimConFuncDef();
      moho::register_DumpUnits_SimConFuncDef();
      moho::register_DebugSetPlayableRect_SimConFuncDef();
      moho::register_DebugDumpArmyStats_SimConFuncDef();
      moho::register_path_GeneratePreview_SimConFuncDef();
    }
  };

  [[maybe_unused]] SimDebugCommandRegistrationsBootstrap gSimDebugCommandRegistrationsBootstrap;
} // namespace

namespace moho
{
  /**
   * The process-wide `AI_DebugCollision` sim convar (statically constructed in
   * the shipped exe at .data 0x010AD5F8). `Sim::DoCollisionsFor` reads it to
   * skip physical collision resolution while the collision overlay is on.
   */
  TSimConVar<bool>& AI_DebugCollisionConVar()
  {
    return ConstructAiDebugCollisionSimConVar();
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
   * Address: 0x00BD3D80 (FUN_00BD3D80, dynamic initializer for `gConAlias_dbg`)
   * Address: 0x00BFB7D0 (FUN_00BFB7D0, dynamic atexit destructor for `gConAlias_dbg`)
   */
  moho::CConAlias gConAlias_dbg("dbg", "Enable/Disable debug overlay", "DoSimCommand dbg");

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
   * Address: 0x00BFB5A0 (FUN_00BFB5A0)
   */
  void cleanup_DamageUnit_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DamageUnit_slot(); command != nullptr) {
      delete command;
      command = nullptr;
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
   * Address: 0x00BD3890 (FUN_00BD3890, dynamic initializer for `gConAlias_SallyShears`)
   * Address: 0x00BFB470 (FUN_00BFB470, dynamic atexit destructor for `gConAlias_SallyShears`)
   */
  moho::CConAlias gConAlias_SallyShears("SallyShears", "Reveal entire map.", "DoSimCommand SallyShears");

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
   * Address: 0x00BD3900 (FUN_00BD3900, dynamic initializer for `gConAlias_BlingBling`)
   * Address: 0x00BFB4D0 (FUN_00BFB4D0, dynamic atexit destructor for `gConAlias_BlingBling`)
   */
  moho::CConAlias gConAlias_BlingBling("BlingBling", "Cash money yo", "DoSimCommand BlingBling");

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
   * Address: 0x00BD3970 (FUN_00BD3970, dynamic initializer for `gConAlias_ZeroExtraStorage`)
   * Address: 0x00BFB530 (FUN_00BFB530, dynamic atexit destructor for `gConAlias_ZeroExtraStorage`)
   */
  moho::CConAlias gConAlias_ZeroExtraStorage("ZeroExtraStorage", "Set energy and mass extra storage to 0", "DoSimCommand ZeroExtraStorage");

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
   * Address: 0x00BD39E0 (FUN_00BD39E0, dynamic initializer for `gConAlias_DamageUnit`)
   * Address: 0x00BFB590 (FUN_00BFB590, dynamic atexit destructor for `gConAlias_DamageUnit`)
   */
  moho::CConAlias gConAlias_DamageUnit("DamageUnit", "Damage the selected unit (negative values heal)", "DoSimCommand DamageUnit");

  /**
   * Address: 0x00BD3A10 (FUN_00BD3A10, register_DamageUnit_SimConFunc)
   *
   * What it does:
   * Registers the `DamageUnit` sim command callback and installs startup
   * cleanup. The store at 0x00BD3A31 is the only reference to
   * `Moho::Sim::DamageUnit` anywhere in the image.
   */
  void register_DamageUnit_SimConFunc()
  {
    EnsureSimConFuncRegistration<&Sim::DamageUnit>(SimConFunc_DamageUnit_slot(), "DamageUnit");
    RegisterAtexitCleanup<&cleanup_DamageUnit_SimConFunc>();
  }

  /**
   * Address: 0x00C01A20 (FUN_00C01A20, sub_C01A20)
   *
   * What it does:
   * `atexit`-installed cleanup callback for the `path_GeneratePreview`
   * `CSimConFunc` registration. The binary destroys the static-storage
   * `SimConFunc_path_GeneratePreview` object in place
   * (`Moho::CSimConCommand::~CSimConCommand(&SimConFunc_path_GeneratePreview)`),
   * not a heap `delete`.
   */
  void cleanup_path_GeneratePreview_SimConFunc()
  {
    if (!gPathGeneratePreviewSimConFuncConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(PathGeneratePreviewSimConFunc()).~CSimConCommand();
    gPathGeneratePreviewSimConFuncConstructed = false;
  }

  /**
   * Address: 0x00BDC850 (FUN_00BDC850, register_path_GeneratePreview_SimConFuncDef)
   *
   * What it does:
   * Registers the `path_GeneratePreview` sim command callback (drag-to-move
   * pathfind preview) and installs startup cleanup. Cheat-gated
   * (`requiresCheat=true`), matching the binary's inlined
   * `CSimConCommand(1, &SimConFunc_path_GeneratePreview, "path_GeneratePreview")`
   * base-construction call.
   */
  void register_path_GeneratePreview_SimConFuncDef()
  {
    (void)ConstructPathGeneratePreviewSimConFunc();
    RegisterAtexitCleanup<&cleanup_path_GeneratePreview_SimConFunc>();
  }

  /**
   * Address: 0x00BD3A50 (FUN_00BD3A50, dynamic initializer for `gConAlias_AddImpulse`)
   * Address: 0x00BFB5F0 (FUN_00BFB5F0, dynamic atexit destructor for `gConAlias_AddImpulse`)
   */
  moho::CConAlias gConAlias_AddImpulse("AddImpulse", "AddImpulse (x,y,z)", "DoSimCommand AddImpulse");

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
   * Address: 0x00BD1F60 (FUN_00BD1F60, dynamic initializer for `gConAlias_NeedRefuelThresholdRatio`)
   * Address: 0x00BFA720 (FUN_00BFA720, dynamic atexit destructor for `gConAlias_NeedRefuelThresholdRatio`)
   */
  moho::CConAlias gConAlias_NeedRefuelThresholdRatio("NeedRefuelThresholdRatio", "Start looking for refueling platform when fuel ratio drops below this point", "DoSimCommand NeedRefuelThresholdRatio");

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
   * Address: 0x00BD1FE0 (FUN_00BD1FE0, dynamic initializer for `gConAlias_NeedRepairThresholdRatio`)
   * Address: 0x00BFA780 (FUN_00BFA780, dynamic atexit destructor for `gConAlias_NeedRepairThresholdRatio`)
   */
  moho::CConAlias gConAlias_NeedRepairThresholdRatio("NeedRepairThresholdRatio", "Start looking for refueling platform when health ratio drops below this point", "DoSimCommand NeedRepairThresholdRatio");

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
   * Address: 0x00BD4E80 (FUN_00BD4E80, dynamic initializer for `gConAlias_NoDamage`)
   * Address: 0x00BFC630 (FUN_00BFC630, dynamic atexit destructor for `gConAlias_NoDamage`)
   */
  moho::CConAlias gConAlias_NoDamage("NoDamage", "Disables all damage to units when set.", "DoSimCommand NoDamage");

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
   * Cross-TU accessor for the `NoDamage` sim convar. The binary references the
   * `SimConVar_NoDamage` global directly from engine code (Entity::AdjustHealth);
   * this forwards to the startup-owned registration slot, upcasting the concrete
   * TSimConVar<bool>* to the CSimConVarBase* that Sim::GetSimVar expects.
   */
  CSimConVarBase* GetNoDamageSimConVar()
  {
    return SimConVar_NoDamage_slot();
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
   * Address: 0x00BCB050 (FUN_00BCB050, dynamic initializer for `gConAlias_AI_RunOpponentAI`)
   * Address: 0x00BF5F80 (FUN_00BF5F80, dynamic atexit destructor for `gConAlias_AI_RunOpponentAI`)
   */
  moho::CConAlias gConAlias_AI_RunOpponentAI("AI_RunOpponentAI", "Turns on or off Opponent AI", "DoSimCommand AI_RunOpponentAI");

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

  CSimConVarBase* GetNeedRefuelThresholdRatioSimConVarDef()
  {
    return &ConstructNeedRefuelThresholdRatioSimConVar();
  }

  CSimConVarBase* GetNeedRepairThresholdRatioSimConVarDef()
  {
    return &ConstructNeedRepairThresholdRatioSimConVar();
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
   * Address: 0x00BCB0D0 (FUN_00BCB0D0, dynamic initializer for `gConAlias_AI_DebugArmyIndex`)
   * Address: 0x00BF5FE0 (FUN_00BF5FE0, dynamic atexit destructor for `gConAlias_AI_DebugArmyIndex`)
   */
  moho::CConAlias gConAlias_AI_DebugArmyIndex("AI_DebugArmyIndex", "Set up a army index for debugging purposes", "DoSimCommand AI_DebugArmyIndex");

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
   * Address: 0x00BCB150 (FUN_00BCB150, dynamic initializer for `gConAlias_AI_RenderDebugAttackVectors`)
   * Address: 0x00BF6040 (FUN_00BF6040, dynamic atexit destructor for `gConAlias_AI_RenderDebugAttackVectors`)
   */
  moho::CConAlias gConAlias_AI_RenderDebugAttackVectors("AI_RenderDebugAttackVectors", "Toggle on/off rendering of debug base attack vectors", "DoSimCommand AI_RenderDebugAttackVectors");

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
   * Address: 0x00BCB1D0 (FUN_00BCB1D0, dynamic initializer for `gConAlias_AI_RenderDebugPlayableRect`)
   * Address: 0x00BF60A0 (FUN_00BF60A0, dynamic atexit destructor for `gConAlias_AI_RenderDebugPlayableRect`)
   */
  moho::CConAlias gConAlias_AI_RenderDebugPlayableRect("AI_RenderDebugPlayableRect", "Toggle on/off rendering of debug playable rect", "DoSimCommand AI_RenderDebugPlayableRect");

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
   * Address: 0x00BCB250 (FUN_00BCB250, dynamic initializer for `gConAlias_AI_DebugCollision`)
   * Address: 0x00BF6100 (FUN_00BF6100, dynamic atexit destructor for `gConAlias_AI_DebugCollision`)
   */
  moho::CConAlias gConAlias_AI_DebugCollision("AI_DebugCollision", "Toggle on/off collision detection", "DoSimCommand AI_DebugCollision");

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
   * Address: 0x00BCB2D0 (FUN_00BCB2D0, dynamic initializer for `gConAlias_AI_DebugIgnorePlayableRect`)
   * Address: 0x00BF6160 (FUN_00BF6160, dynamic atexit destructor for `gConAlias_AI_DebugIgnorePlayableRect`)
   */
  moho::CConAlias gConAlias_AI_DebugIgnorePlayableRect("AI_DebugIgnorePlayableRect", "Toggle on/off ignore playable rect", "DoSimCommand AI_DebugIgnorePlayableRect");

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
   * Address: 0x00BCF710 (FUN_00BCF710, dynamic initializer for `gConAlias_ai_InstaBuild`)
   * Address: 0x00BF9180 (FUN_00BF9180, dynamic atexit destructor for `gConAlias_ai_InstaBuild`)
   */
  moho::CConAlias gConAlias_ai_InstaBuild("ai_InstaBuild", "Units build instantly.", "DoSimCommand ai_InstaBuild");

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
   * Address: 0x00BCF790 (FUN_00BCF790, dynamic initializer for `gConAlias_ai_FreeBuild`)
   * Address: 0x00BF91E0 (FUN_00BF91E0, dynamic atexit destructor for `gConAlias_ai_FreeBuild`)
   */
  moho::CConAlias gConAlias_ai_FreeBuild("ai_FreeBuild", "Unit build costs are 0", "DoSimCommand ai_FreeBuild");

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
   * Address: 0x00BCE3A0 (FUN_00BCE3A0, dynamic initializer for `gConAlias_ai_SteeringAirTolerance`)
   * Address: 0x00BF8040 (FUN_00BF8040, dynamic atexit destructor for `gConAlias_ai_SteeringAirTolerance`)
   */
  moho::CConAlias gConAlias_ai_SteeringAirTolerance("ai_SteeringAirTolerance", "Tolerance used to detect whether an aircraft has reached its destination.", "DoSimCommand ai_SteeringAirTolerance");

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
   * Address: 0x00BCE6D0 (FUN_00BCE6D0, dynamic initializer for `gConAlias_WeaponTerrainBlockageTest`)
   * Address: 0x00BF81E0 (FUN_00BF81E0, dynamic atexit destructor for `gConAlias_WeaponTerrainBlockageTest`)
   */
  moho::CConAlias gConAlias_WeaponTerrainBlockageTest("WeaponTerrainBlockageTest", "Toggle on/off wepaon collision tests against terrain blockages", "DoSimCommand WeaponTerrainBlockageTest");

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
   * Address: 0x00C012C0 (FUN_00C012C0, sub_C012C0)
   *
   * What it does:
   * Destroys the startup-owned `DebugSetPlayableRect` sim-command callback
   * object. `_atexit`-installed by `register_DebugSetPlayableRect_SimConFuncDef`
   * at 0x00BDC182.
   */
  void cleanup_DebugSetPlayableRect_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DebugSetPlayableRect_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00C01320 (FUN_00C01320, cleanup_DebugDumpArmyStats_SimConFunc)
   *
   * What it does:
   * Destroys the startup-owned `DebugDumpArmyStats` sim-command callback
   * object.
   */
  void cleanup_DebugDumpArmyStats_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DebugDumpArmyStats_slot(); command != nullptr) {
      delete command;
      command = nullptr;
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
   * Address: 0x00BD8380 (FUN_00BD8380, dynamic initializer for `gConAlias_DebugAIStatesOff`)
   * Address: 0x00BFE370 (FUN_00BFE370, dynamic atexit destructor for `gConAlias_DebugAIStatesOff`)
   */
  moho::CConAlias gConAlias_DebugAIStatesOff("DebugAIStatesOff", "debug function to show some AI states", "DoSimCommand DebugAIStatesOff");

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
   * Address: 0x00BD8310 (FUN_00BD8310, dynamic initializer for `gConAlias_DebugAIStatesOn`)
   * Address: 0x00BFE310 (FUN_00BFE310, dynamic atexit destructor for `gConAlias_DebugAIStatesOn`)
   */
  moho::CConAlias gConAlias_DebugAIStatesOn("DebugAIStatesOn", "debug function to show some AI states", "DoSimCommand DebugAIStatesOn");

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
   * Address: 0x00BDC350 (FUN_00BDC350, dynamic initializer for `gConAlias_TrackStats`)
   * Address: 0x00C01390 (FUN_00C01390, dynamic atexit destructor for `gConAlias_TrackStats`)
   */
  moho::CConAlias gConAlias_TrackStats("TrackStats", "Begin/End tracking stats of selected units.", "DoSimCommand TrackStats");

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
   * Address: 0x00BDC3C0 (FUN_00BDC3C0, dynamic initializer for `gConAlias_DumpUnits`)
   * Address: 0x00C013F0 (FUN_00C013F0, dynamic atexit destructor for `gConAlias_DumpUnits`)
   */
  moho::CConAlias gConAlias_DumpUnits("DumpUnits", "Print out units in play", "DoSimCommand DumpUnits");

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
   * Address: 0x00BDC140 (FUN_00BDC140, dynamic initializer for `gConAlias_DebugSetPlayableRect`)
   * Address: 0x00C01270 (FUN_00C01270, dynamic atexit destructor for `gConAlias_DebugSetPlayableRect`)
   */
  moho::CConAlias gConAlias_DebugSetPlayableRect("DebugSetPlayableRect", "Set the playable rect of the map (minX, minZ, maxX, maxZ).", "DoSimCommand DebugSetPlayableRect");

  /**
   * Address: 0x00BDC170 (FUN_00BDC170, register_DebugSetPlayableRect_SimConFuncDef)
   *
   * What it does:
   * Registers the `DebugSetPlayableRect` sim command callback and installs
   * startup cleanup. 0x00BDC191 stores `Moho::Sim::DebugSetPlayableRect`
   * (0x0075D5D0) into the descriptor's `mFunc` slot and is the only reference
   * to that function anywhere in the image.
   */
  void register_DebugSetPlayableRect_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::DebugSetPlayableRect>(
      SimConFunc_DebugSetPlayableRect_slot(),
      "DebugSetPlayableRect"
    );
    RegisterAtexitCleanup<&cleanup_DebugSetPlayableRect_SimConFunc>();
  }

  /**
   * Address: 0x00BDC1B0 (FUN_00BDC1B0, dynamic initializer for `gConAlias_DebugDumpArmyStats`)
   * Address: 0x00C012D0 (FUN_00C012D0, dynamic atexit destructor for `gConAlias_DebugDumpArmyStats`)
   */
  moho::CConAlias gConAlias_DebugDumpArmyStats("DebugDumpArmyStats", "Dump current stats for army index.", "DoSimCommand DebugDumpArmyStats");

  /**
   * Address: 0x00BDC1E0 (FUN_00BDC1E0, register_DebugDumpArmyStats_SimConFunc)
   *
   * What it does:
   * Registers the `DebugDumpArmyStats` sim command callback and installs
   * startup cleanup. 0x00BDC201 stores `Moho::Sim::DebugDumpArmyStats`
   * (0x0075D7A0) into the descriptor's `mFunc` slot.
   */
  void register_DebugDumpArmyStats_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::DebugDumpArmyStats>(
      SimConFunc_DebugDumpArmyStats_slot(),
      "DebugDumpArmyStats"
    );
    RegisterAtexitCleanup<&cleanup_DebugDumpArmyStats_SimConFunc>();
  }

  /**
   * Address: 0x00BD82A0 (FUN_00BD82A0, dynamic initializer for `gConAlias_DebugSetProductionInActive`)
   * Address: 0x00BFE2B0 (FUN_00BFE2B0, dynamic atexit destructor for `gConAlias_DebugSetProductionInActive`)
   */
  moho::CConAlias gConAlias_DebugSetProductionInActive("DebugSetProductionInActive", "debug function to turn selected units production of resources into inactive state", "DoSimCommand DebugSetProductionInActive");

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
   * Address: 0x00BD8230 (FUN_00BD8230, dynamic initializer for `gConAlias_DebugSetProductionActive`)
   * Address: 0x00BFE250 (FUN_00BFE250, dynamic atexit destructor for `gConAlias_DebugSetProductionActive`)
   */
  moho::CConAlias gConAlias_DebugSetProductionActive("DebugSetProductionActive", "debug function to turn selected units production of resources into active state", "DoSimCommand DebugSetProductionActive");

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
   * Address: 0x00BD81C0 (FUN_00BD81C0, dynamic initializer for `gConAlias_DebugSetConsumptionInActive`)
   * Address: 0x00BFE1F0 (FUN_00BFE1F0, dynamic atexit destructor for `gConAlias_DebugSetConsumptionInActive`)
   */
  moho::CConAlias gConAlias_DebugSetConsumptionInActive("DebugSetConsumptionInActive", "debug function to turn selected units consumption of resources into inactive state", "DoSimCommand DebugSetConsumptionInActive");

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
   * Address: 0x00BD8150 (FUN_00BD8150, dynamic initializer for `gConAlias_DebugSetConsumptionActive`)
   * Address: 0x00BFE190 (FUN_00BFE190, dynamic atexit destructor for `gConAlias_DebugSetConsumptionActive`)
   */
  moho::CConAlias gConAlias_DebugSetConsumptionActive("DebugSetConsumptionActive", "debug function to turn selected units consumption of resources into active state", "DoSimCommand DebugSetConsumptionActive");

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
   * Address: 0x00BD51E0 (FUN_00BD51E0, dynamic initializer for `gConAlias_Purge`)
   * Address: 0x00BFCB00 (FUN_00BFCB00, dynamic atexit destructor for `gConAlias_Purge`)
   */
  moho::CConAlias gConAlias_Purge("Purge", "Purge all entities of a specified type <shield|projectile|unit|all>.  If any optional army indices are supplied, destroy those army's entities.", "DoSimCommand Purge");

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
   * Address: 0x00BD6C90 (FUN_00BD6C90, dynamic initializer for `gConAlias_KillAll`)
   * Address: 0x00BFDD50 (FUN_00BFDD50, dynamic atexit destructor for `gConAlias_KillAll`)
   */
  moho::CConAlias gConAlias_KillAll("KillAll", "Kill all units", "DoSimCommand KillAll");

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
   * Address: 0x00BD6D00 (FUN_00BD6D00, dynamic initializer for `gConAlias_DestroyAll`)
   * Address: 0x00BFDDB0 (FUN_00BFDDB0, dynamic atexit destructor for `gConAlias_DestroyAll`)
   */
  moho::CConAlias gConAlias_DestroyAll("DestroyAll", "Destroy all units.  If any optional army indices are supplied, destroy those army's units.", "DoSimCommand DestroyAll");

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

namespace
{
  [[nodiscard]] moho::CSimConFunc*& SimConFunc_SimLog_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_SimWarn_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_SimError_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_SimAssert_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_SimCrash_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_SimLua_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }

  [[nodiscard]] moho::CSimConFunc*& SimConFunc_DebugMoveCamera_slot()
  {
    static moho::CSimConFunc* sCommand = nullptr;
    return sCommand;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00C00930 (FUN_00C00930, cleanup_SimLog_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `SimLog` sim-command callback object.
   */
  void cleanup_SimLog_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_SimLog_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BDB440 (FUN_00BDB440, register_SimLog_SimConFuncDef)
   *
   * What it does:
   * Registers the `SimLog` sim command callback (bound to the already-recovered
   * `Sim::Log`) and attaches startup cleanup.
   */
  void register_SimLog_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::Log>(SimConFunc_SimLog_slot(), "SimLog");
    RegisterAtexitCleanup<&cleanup_SimLog_SimConFunc>();
  }

  /**
   * Address: 0x00C00990 (FUN_00C00990, cleanup_SimWarn_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `SimWarn` sim-command callback object.
   */
  void cleanup_SimWarn_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_SimWarn_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BDB4B0 (FUN_00BDB4B0, register_SimWarn_SimConFuncDef)
   *
   * What it does:
   * Registers the `SimWarn` sim command callback and attaches startup cleanup.
   */
  void register_SimWarn_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::SimWarn>(SimConFunc_SimWarn_slot(), "SimWarn");
    RegisterAtexitCleanup<&cleanup_SimWarn_SimConFunc>();
  }

  /**
   * Address: 0x00C009F0 (FUN_00C009F0, cleanup_SimError_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `SimError` sim-command callback object.
   */
  void cleanup_SimError_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_SimError_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BDB520 (FUN_00BDB520, register_SimError_SimConFuncDef)
   *
   * What it does:
   * Registers the `SimError` sim command callback and attaches startup cleanup.
   */
  void register_SimError_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::SimError>(SimConFunc_SimError_slot(), "SimError");
    RegisterAtexitCleanup<&cleanup_SimError_SimConFunc>();
  }

  /**
   * Address: 0x00C00A50 (FUN_00C00A50, cleanup_SimAssert_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `SimAssert` sim-command callback object.
   */
  void cleanup_SimAssert_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_SimAssert_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BDB590 (FUN_00BDB590, register_SimAssert_SimConFuncDef)
   *
   * What it does:
   * Registers the `SimAssert` sim command callback and attaches startup cleanup.
   */
  void register_SimAssert_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::SimAssert>(SimConFunc_SimAssert_slot(), "SimAssert");
    RegisterAtexitCleanup<&cleanup_SimAssert_SimConFunc>();
  }

  /**
   * Address: 0x00C00AB0 (FUN_00C00AB0, cleanup_SimCrash_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `SimCrash` sim-command callback object.
   */
  void cleanup_SimCrash_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_SimCrash_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BDB600 (FUN_00BDB600, register_SimCrash_SimConFuncDef)
   *
   * What it does:
   * Registers the `SimCrash` sim command callback and attaches startup cleanup.
   */
  void register_SimCrash_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::SimCrash>(SimConFunc_SimCrash_slot(), "SimCrash");
    RegisterAtexitCleanup<&cleanup_SimCrash_SimConFunc>();
  }

  /**
   * Address: 0x00C01260 (FUN_00C01260, cleanup_SimLua_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `SimLua` sim-command callback object.
   */
  void cleanup_SimLua_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_SimLua_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BDBF40 (FUN_00BDBF40, register_SimLua_SimConFuncDef)
   *
   * What it does:
   * Registers the `SimLua` sim command callback (bound to the already-recovered
   * `Sim::SimLua`) and attaches startup cleanup.
   */
  void register_SimLua_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::SimLua>(SimConFunc_SimLua_slot(), "SimLua");
    RegisterAtexitCleanup<&cleanup_SimLua_SimConFunc>();
  }

  /**
   * Address: 0x00C01380 (FUN_00C01380, cleanup_DebugMoveCamera_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `DebugMoveCamera` sim-command callback object.
   */
  void cleanup_DebugMoveCamera_SimConFunc()
  {
    if (CSimConFunc*& command = SimConFunc_DebugMoveCamera_slot(); command != nullptr) {
      delete command;
      command = nullptr;
    }
  }

  /**
   * Address: 0x00BDC250 (FUN_00BDC250, register_DebugMoveCamera_SimConFuncDef)
   *
   * What it does:
   * Registers the `DebugMoveCamera` sim command callback (bound to the
   * already-recovered `Sim::DebugMoveCamera`) and attaches startup cleanup.
   */
  void register_DebugMoveCamera_SimConFuncDef()
  {
    EnsureSimConFuncRegistration<&Sim::DebugMoveCamera>(SimConFunc_DebugMoveCamera_slot(), "DebugMoveCamera");
    RegisterAtexitCleanup<&cleanup_DebugMoveCamera_SimConFunc>();
  }
} // namespace moho

namespace
{
  struct SimConFuncMiscBootstrap
  {
    SimConFuncMiscBootstrap()
    {
      moho::register_SimLog_SimConFuncDef();
      moho::register_SimWarn_SimConFuncDef();
      moho::register_SimError_SimConFuncDef();
      moho::register_SimAssert_SimConFuncDef();
      moho::register_SimCrash_SimConFuncDef();
      moho::register_SimLua_SimConFuncDef();
      moho::register_DebugMoveCamera_SimConFuncDef();
    }
  };

  [[maybe_unused]] SimConFuncMiscBootstrap gSimConFuncMiscBootstrap;
} // namespace
