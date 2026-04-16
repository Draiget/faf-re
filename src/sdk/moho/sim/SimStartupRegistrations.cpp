#include "moho/sim/SimStartupRegistrations.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>

#include "moho/console/CConAlias.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/Sim.h"

namespace
{
  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane21 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane21 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane22 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane22 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane23 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane23 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane24 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane24 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane25 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane25 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane26 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane26 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane27 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane27 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane28 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane28 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevMohoWeaponMethodsFactory = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorMohoWeaponMethodsFactory = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane30 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane30 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormPrevReconBlipAnchorA = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorReconBlipAnchorA = nullptr;

  struct SimLuaInitReconBlipAnchorB
  {
    std::uint8_t pad_00_0F[0x10]{};
    moho::CScrLuaInitForm* mPrevDef = nullptr;
  };

  SimLuaInitReconBlipAnchorB gSimLuaInitReconBlipAnchorB{};

  int gRecoveredCScrLuaMetatableFactoryReconBlipIndex = 0;
  int gRecoveredCScrLuaMetatableFactoryEntityIndex = 0;

  [[nodiscard]] moho::CConAlias& ConAlias_path_ArmyBudget()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_path_MaxInstantWorkUnits()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_path_UnreachableTimeoutSearchSteps()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AirLookAheadMult()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_RandomElevationOffset()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_ShowRaisedPlatforms()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_tree_AccelFactor()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_tree_SpringFactor()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_tree_DampFactor()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_tree_UprootFactor()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::TSimConVar<int>& SimConVar_path_ArmyBudget()
  {
    static moho::TSimConVar<int> sVar(false, "path_ArmyBudget", 2500);
    return sVar;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_AI_RenderBombDropZone()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::TSimConVar<bool>& SimConVar_AI_RenderBombDropZone()
  {
    static moho::TSimConVar<bool> sVar(false, "AI_RenderBombDropZone", false);
    return sVar;
  }

  /**
   * Address: 0x007353C0 (FUN_007353C0)
   *
   * What it does:
   * Constructs one startup `TSimConVar<uint8_t>` lane for
   * `"sim_TestVarUByte"` with default value `0`.
   */
  [[maybe_unused]] [[nodiscard]] moho::TSimConVar<std::uint8_t>& SimConVar_sim_TestVarUByte()
  {
    static moho::TSimConVar<std::uint8_t> sVar(false, "sim_TestVarUByte", static_cast<std::uint8_t>(0));
    return sVar;
  }

  /**
   * Address owner: startup sim-convar registration lane near 0x007353C0.
   *
   * What it does:
   * Constructs one startup `TSimConVar<msvc8::string>` lane for
   * `"sim_TestVarStr"` with default value `"string"`.
   */
  [[maybe_unused]] [[nodiscard]] moho::TSimConVar<msvc8::string>& SimConVar_sim_TestVarStr()
  {
    static moho::TSimConVar<msvc8::string> sVar(false, "sim_TestVarStr", msvc8::string("string"));
    return sVar;
  }

  /**
   * Address: 0x00736830 (FUN_00736830)
   *
   * What it does:
   * Returns one raw storage pointer for the per-sim `sim_TestVarUByte`
   * runtime convar instance.
   */
  [[maybe_unused]] [[nodiscard]] void* GetSimTestVarUByteStorage(moho::Sim* const sim)
  {
    if (sim == nullptr) {
      return nullptr;
    }

    moho::CSimConVarInstanceBase* const instance = sim->GetSimVar(&SimConVar_sim_TestVarUByte());
    return instance != nullptr ? instance->GetValueStorage() : nullptr;
  }

  /**
   * Address: 0x00736850 (FUN_00736850)
   *
   * What it does:
   * Returns one raw storage pointer for the per-sim `sim_TestVarStr`
   * runtime convar instance.
   */
  [[maybe_unused]] [[nodiscard]] void* GetSimTestVarStrStorage(moho::Sim* const sim)
  {
    if (sim == nullptr) {
      return nullptr;
    }

    moho::CSimConVarInstanceBase* const instance = sim->GetSimVar(&SimConVar_sim_TestVarStr());
    return instance != nullptr ? instance->GetValueStorage() : nullptr;
  }

  alignas(moho::CConAlias) unsigned char gReconFlushConAliasStorage[sizeof(moho::CConAlias)] = {};
  bool gReconFlushConAliasConstructed = false;

  alignas(moho::CSimConFunc) unsigned char gReconFlushSimConFuncStorage[sizeof(moho::CSimConFunc)] = {};
  bool gReconFlushSimConFuncConstructed = false;

  alignas(moho::CConAlias) unsigned char gScenarioMethodConAliasStorage[sizeof(moho::CConAlias)] = {};
  bool gScenarioMethodConAliasConstructed = false;

  alignas(moho::CSimConFunc) unsigned char gScenarioMethodSimConFuncStorage[sizeof(moho::CSimConFunc)] = {};
  bool gScenarioMethodSimConFuncConstructed = false;

  template <typename T>
  struct SimConVarStartupStorage
  {
    alignas(moho::TSimConVar<T>) unsigned char storage[sizeof(moho::TSimConVar<T>)]{};
    bool constructed = false;
  };

  SimConVarStartupStorage<float> gTreeAccelFactorSimConVarSlot{}; // Original startup slot offset: 0x10B5220
  SimConVarStartupStorage<float> gTreeSpringFactorSimConVarSlot{}; // Original startup slot offset: 0x10B5104
  SimConVarStartupStorage<float> gTreeDampFactorSimConVarSlot{}; // Original startup slot offset: 0x10B5238
  SimConVarStartupStorage<float> gTreeUprootFactorSimConVarSlot{}; // Original startup slot offset: 0x10B5094
  SimConVarStartupStorage<float> gRandomElevationOffsetSimConVarSlot{}; // Original startup slot offset: 0x10B60AC
  SimConVarStartupStorage<float> gAirLookAheadMultSimConVarSlot{}; // Original startup slot offset: 0x10B61C4
  SimConVarStartupStorage<bool> gShowRaisedPlatformsSimConVarSlot{}; // Original startup slot offset: 0x10B5B20
  SimConVarStartupStorage<int> gPathMaxInstantWorkUnitsSimConVarSlot{}; // Original startup slot offset: 0x10AEDB4
  SimConVarStartupStorage<int> gPathUnreachableTimeoutSearchStepsSimConVarSlot{}; // Original startup slot offset: 0x10AEDCC

  [[nodiscard]] moho::CConAlias& ReconFlushConAlias()
  {
    return *std::launder(reinterpret_cast<moho::CConAlias*>(gReconFlushConAliasStorage));
  }

  [[nodiscard]] moho::CConAlias& ConstructReconFlushConAlias()
  {
    if (!gReconFlushConAliasConstructed) {
      new (gReconFlushConAliasStorage) moho::CConAlias();
      gReconFlushConAliasConstructed = true;
    }

    return ReconFlushConAlias();
  }

  [[nodiscard]] moho::CSimConFunc& ReconFlushSimConFunc()
  {
    return *std::launder(reinterpret_cast<moho::CSimConFunc*>(gReconFlushSimConFuncStorage));
  }

  [[nodiscard]] moho::CSimConFunc& ConstructReconFlushSimConFunc()
  {
    if (!gReconFlushSimConFuncConstructed) {
      new (gReconFlushSimConFuncStorage) moho::CSimConFunc(false, "ReconFlush", &moho::Sim::ReconFlush);
      gReconFlushSimConFuncConstructed = true;
    }

    return ReconFlushSimConFunc();
  }

  [[nodiscard]] moho::CConAlias& ScenarioMethodConAlias()
  {
    return *std::launder(reinterpret_cast<moho::CConAlias*>(gScenarioMethodConAliasStorage));
  }

  [[nodiscard]] moho::CConAlias& ConstructScenarioMethodConAlias()
  {
    if (!gScenarioMethodConAliasConstructed) {
      new (gScenarioMethodConAliasStorage) moho::CConAlias();
      gScenarioMethodConAliasConstructed = true;
    }

    return ScenarioMethodConAlias();
  }

  [[nodiscard]] moho::CSimConFunc& ScenarioMethodSimConFunc()
  {
    return *std::launder(reinterpret_cast<moho::CSimConFunc*>(gScenarioMethodSimConFuncStorage));
  }

  [[nodiscard]] moho::CSimConFunc& ConstructScenarioMethodSimConFunc()
  {
    if (!gScenarioMethodSimConFuncConstructed) {
      new (gScenarioMethodSimConFuncStorage) moho::CSimConFunc(true, "ScenarioMethod", &moho::Sim::ScenarioMethod);
      gScenarioMethodSimConFuncConstructed = true;
    }

    return ScenarioMethodSimConFunc();
  }

  template <typename T>
  [[nodiscard]] moho::TSimConVar<T>& ConstructRecoveredSimConVar(
    SimConVarStartupStorage<T>& slot,
    const char* const name,
    const T defaultValue
  ) noexcept
  {
    if (!slot.constructed) {
      new (slot.storage) moho::TSimConVar<T>(false, name, defaultValue);
      slot.constructed = true;
    }

    return *std::launder(reinterpret_cast<moho::TSimConVar<T>*>(slot.storage));
  }

  template <typename T>
  void DestroyRecoveredSimConVarBase(SimConVarStartupStorage<T>& slot) noexcept
  {
    if (!slot.constructed) {
      return;
    }

    auto& simConVar = *std::launder(reinterpret_cast<moho::TSimConVar<T>*>(slot.storage));
    static_cast<moho::CSimConCommand&>(simConVar).~CSimConCommand();
    slot.constructed = false;
  }

  template <void (*Cleanup)()>
  void RegisterAtexitCleanup() noexcept
  {
    (void)std::atexit(Cleanup);
  }

  template <int* TargetIndex>
  int RegisterRecoveredFactoryIndex() noexcept
  {
    const int index = moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    *TargetIndex = index;
    return index;
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardSimStartupLuaThunk() noexcept
  {
    return Target();
  }

  struct SimStartupRegistrationsBootstrapA
  {
    SimStartupRegistrationsBootstrapA()
    {
      moho::register_tree_AccelFactor_ConAliasDef();
      moho::register_tree_AccelFactor_SimConVarDef();
      moho::register_tree_SpringFactor_ConAliasDef();
      moho::register_tree_SpringFactor_SimConVarDef();
      moho::register_tree_DampFactor_ConAliasDef();
      moho::register_tree_DampFactor_SimConVarDef();
      moho::register_tree_UprootFactor_ConAliasDef();
      moho::register_tree_UprootFactor_SimConVarDef();
      moho::register_ShowRaisedPlatforms_ConAlias();
      moho::register_ShowRaisedPlatforms_SimConVar();
      moho::register_RandomElevationOffset_ConAlias();
      moho::register_RandomElevationOffset_SimConVarDef();
      moho::register_AirLookAheadMult_ConAlias();
      moho::register_AirLookAheadMult_SimConVarDef();
      moho::register_path_MaxInstantWorkUnits_ConAliasDef();
      moho::register_path_MaxInstantWorkUnits_SimConVarDef();
      moho::register_path_UnreachableTimeoutSearchSteps_ConAliasDef();
      moho::register_path_UnreachableTimeoutSearchSteps_SimConVarDef();
      (void)moho::register_sim_SimInits_mForms_reconBlipAnchorA();
      (void)moho::register_sim_SimInits_mForms_reconBlipAnchorB();
      (void)moho::register_CScrLuaMetatableFactory_ReconBlip_Index();
      (void)moho::register_CScrLuaMetatableFactory_Entity_Index();
      (void)moho::register_ReconBlipGetBlueprint_LuaFuncDef();
      (void)moho::register_ReconBlipGetSource_LuaFuncDef();
      (void)moho::register_ReconBlipIsSeenEver_LuaFuncDef();
      (void)moho::register_ReconBlipIsSeenNow_LuaFuncDef();
      (void)moho::register_ReconBlipIsMaybeDead_LuaFuncDef();
      (void)moho::register_ReconBlipIsOnOmni_LuaFuncDef();
      (void)moho::register_ReconBlipIsOnSonar_LuaFuncDef();
      (void)moho::register_ReconBlipIsOnRadar_LuaFuncDef();
      (void)moho::register_ReconBlipIsKnownFake_LuaFuncDef();
      moho::register_ReconFlush_ConAliasDef();
      moho::register_ReconFlush_SimConFuncDef();
      moho::register_CConAlias_ScenarioMethod();
      moho::register_ScenarioMethod_SimConFuncDef();
    }
  };

  [[maybe_unused]] SimStartupRegistrationsBootstrapA gSimStartupRegistrationsBootstrapA;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BFCFB0 (FUN_00BFCFB0, cleanup_tree_AccelFactor_ConAlias)
   *
   * What it does:
   * Tears down recovered `tree_AccelFactor` alias startup storage.
   */
  void cleanup_tree_AccelFactor_ConAlias()
  {
    ConAlias_tree_AccelFactor().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD59E0 (FUN_00BD59E0, register_tree_AccelFactor_ConAliasDef)
   *
   * What it does:
   * Initializes recovered `tree_AccelFactor` console alias and registers
   * process-exit cleanup.
   */
  void register_tree_AccelFactor_ConAliasDef()
  {
    ConAlias_tree_AccelFactor().InitializeRecovered(
      "How quickly falling trees accelerate",
      "tree_AccelFactor",
      "DoSimCommand tree_AccelFactor"
    );
    RegisterAtexitCleanup<&cleanup_tree_AccelFactor_ConAlias>();
  }

  /**
   * Address: 0x00BFD000 (FUN_00BFD000, cleanup_tree_AccelFactor_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `tree_AccelFactor` sim-convar startup storage.
   */
  void cleanup_tree_AccelFactor_SimConVarDef()
  {
    DestroyRecoveredSimConVarBase(gTreeAccelFactorSimConVarSlot);
  }

  /**
   * Address: 0x00BD5A10 (FUN_00BD5A10, register_tree_AccelFactor_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `tree_AccelFactor` float sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_tree_AccelFactor_SimConVarDef()
  {
    (void)ConstructRecoveredSimConVar(gTreeAccelFactorSimConVarSlot, "tree_AccelFactor", 0.1f);
    RegisterAtexitCleanup<&cleanup_tree_AccelFactor_SimConVarDef>();
  }

  /**
   * Address: 0x00BFD010 (FUN_00BFD010, cleanup_tree_SpringFactor_ConAlias)
   *
   * What it does:
   * Tears down recovered `tree_SpringFactor` alias startup storage.
   */
  void cleanup_tree_SpringFactor_ConAlias()
  {
    ConAlias_tree_SpringFactor().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD5A60 (FUN_00BD5A60, register_tree_SpringFactor_ConAliasDef)
   *
   * What it does:
   * Initializes recovered `tree_SpringFactor` console alias and registers
   * process-exit cleanup.
   */
  void register_tree_SpringFactor_ConAliasDef()
  {
    ConAlias_tree_SpringFactor().InitializeRecovered(
      "How quickly swaying trees spring back",
      "tree_SpringFactor",
      "DoSimCommand tree_SpringFactor"
    );
    RegisterAtexitCleanup<&cleanup_tree_SpringFactor_ConAlias>();
  }

  /**
   * Address: 0x00BFD060 (FUN_00BFD060, cleanup_tree_SpringFactor_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `tree_SpringFactor` sim-convar startup storage.
   */
  void cleanup_tree_SpringFactor_SimConVarDef()
  {
    DestroyRecoveredSimConVarBase(gTreeSpringFactorSimConVarSlot);
  }

  /**
   * Address: 0x00BD5A90 (FUN_00BD5A90, register_tree_SpringFactor_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `tree_SpringFactor` float sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_tree_SpringFactor_SimConVarDef()
  {
    (void)ConstructRecoveredSimConVar(gTreeSpringFactorSimConVarSlot, "tree_SpringFactor", 0.5f);
    RegisterAtexitCleanup<&cleanup_tree_SpringFactor_SimConVarDef>();
  }

  /**
   * Address: 0x00BFD070 (FUN_00BFD070, cleanup_tree_DampFactor_ConAlias)
   *
   * What it does:
   * Tears down recovered `tree_DampFactor` alias startup storage.
   */
  void cleanup_tree_DampFactor_ConAlias()
  {
    ConAlias_tree_DampFactor().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD5AE0 (FUN_00BD5AE0, register_tree_DampFactor_ConAliasDef)
   *
   * What it does:
   * Initializes recovered `tree_DampFactor` console alias and registers
   * process-exit cleanup.
   */
  void register_tree_DampFactor_ConAliasDef()
  {
    ConAlias_tree_DampFactor().InitializeRecovered(
      "Damping on swaying trees (0 to 1)",
      "tree_DampFactor",
      "DoSimCommand tree_DampFactor"
    );
    RegisterAtexitCleanup<&cleanup_tree_DampFactor_ConAlias>();
  }

  /**
   * Address: 0x00BFD0C0 (FUN_00BFD0C0, cleanup_tree_DampFactor_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `tree_DampFactor` sim-convar startup storage.
   */
  void cleanup_tree_DampFactor_SimConVarDef()
  {
    DestroyRecoveredSimConVarBase(gTreeDampFactorSimConVarSlot);
  }

  /**
   * Address: 0x00BD5B10 (FUN_00BD5B10, register_tree_DampFactor_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `tree_DampFactor` float sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_tree_DampFactor_SimConVarDef()
  {
    (void)ConstructRecoveredSimConVar(gTreeDampFactorSimConVarSlot, "tree_DampFactor", 0.5f);
    RegisterAtexitCleanup<&cleanup_tree_DampFactor_SimConVarDef>();
  }

  /**
   * Address: 0x00BFD0D0 (FUN_00BFD0D0, cleanup_tree_UprootFactor_ConAlias)
   *
   * What it does:
   * Tears down recovered `tree_UprootFactor` alias startup storage.
   */
  void cleanup_tree_UprootFactor_ConAlias()
  {
    ConAlias_tree_UprootFactor().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD5B60 (FUN_00BD5B60, register_tree_UprootFactor_ConAliasDef)
   *
   * What it does:
   * Initializes recovered `tree_UprootFactor` console alias and registers
   * process-exit cleanup.
   */
  void register_tree_UprootFactor_ConAliasDef()
  {
    ConAlias_tree_UprootFactor().InitializeRecovered(
      "How far to raise falling trees up out of the ground",
      "tree_UprootFactor",
      "DoSimCommand tree_UprootFactor"
    );
    RegisterAtexitCleanup<&cleanup_tree_UprootFactor_ConAlias>();
  }

  /**
   * Address: 0x00BFD120 (FUN_00BFD120, cleanup_tree_UprootFactor_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `tree_UprootFactor` sim-convar startup storage.
   */
  void cleanup_tree_UprootFactor_SimConVarDef()
  {
    DestroyRecoveredSimConVarBase(gTreeUprootFactorSimConVarSlot);
  }

  /**
   * Address: 0x00BD5B90 (FUN_00BD5B90, register_tree_UprootFactor_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `tree_UprootFactor` float sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_tree_UprootFactor_SimConVarDef()
  {
    (void)ConstructRecoveredSimConVar(gTreeUprootFactorSimConVarSlot, "tree_UprootFactor", 0.1f);
    RegisterAtexitCleanup<&cleanup_tree_UprootFactor_SimConVarDef>();
  }

  CSimConVarBase* GetTreeAccelFactorSimConVarDef()
  {
    return &ConstructRecoveredSimConVar(gTreeAccelFactorSimConVarSlot, "tree_AccelFactor", 0.1f);
  }

  CSimConVarBase* GetTreeSpringFactorSimConVarDef()
  {
    return &ConstructRecoveredSimConVar(gTreeSpringFactorSimConVarSlot, "tree_SpringFactor", 0.5f);
  }

  CSimConVarBase* GetTreeDampFactorSimConVarDef()
  {
    return &ConstructRecoveredSimConVar(gTreeDampFactorSimConVarSlot, "tree_DampFactor", 0.5f);
  }

  CSimConVarBase* GetTreeUprootFactorSimConVarDef()
  {
    return &ConstructRecoveredSimConVar(gTreeUprootFactorSimConVarSlot, "tree_UprootFactor", 0.1f);
  }

  /**
   * Address: 0x00BFD880 (FUN_00BFD880, cleanup_ShowRaisedPlatforms_ConAlias)
   *
   * What it does:
   * Tears down recovered `ShowRaisedPlatforms` alias startup storage.
   */
  void cleanup_ShowRaisedPlatforms_ConAlias()
  {
    ConAlias_ShowRaisedPlatforms().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD69F0 (FUN_00BD69F0, register_ShowRaisedPlatforms_ConAlias)
   *
   * What it does:
   * Registers the `ShowRaisedPlatforms` alias used by sim debug rendering.
   */
  void register_ShowRaisedPlatforms_ConAlias()
  {
    ConAlias_ShowRaisedPlatforms().InitializeRecovered(
      "Turns on or off rendering of raised platform for tweaking and setting up purposes",
      "ShowRaisedPlatforms",
      "DoSimCommand ShowRaisedPlatforms"
    );
    RegisterAtexitCleanup<&cleanup_ShowRaisedPlatforms_ConAlias>();
  }

  /**
   * Address: 0x00BFD8D0 (FUN_00BFD8D0, cleanup_ShowRaisedPlatforms_SimConVar)
   *
   * What it does:
   * Tears down recovered `ShowRaisedPlatforms` sim-convar startup storage.
   */
  void cleanup_ShowRaisedPlatforms_SimConVar()
  {
    DestroyRecoveredSimConVarBase(gShowRaisedPlatformsSimConVarSlot);
  }

  /**
   * Address: 0x00BD6A20 (FUN_00BD6A20, register_ShowRaisedPlatforms_SimConVar)
   *
   * What it does:
   * Registers/initializes the `ShowRaisedPlatforms` bool sim-convar.
   */
  void register_ShowRaisedPlatforms_SimConVar()
  {
    (void)ConstructRecoveredSimConVar(gShowRaisedPlatformsSimConVarSlot, "ShowRaisedPlatforms", false);
    RegisterAtexitCleanup<&cleanup_ShowRaisedPlatforms_SimConVar>();
  }

  CSimConVarBase* GetShowRaisedPlatformsSimConVarDef()
  {
    return &ConstructRecoveredSimConVar(gShowRaisedPlatformsSimConVarSlot, "ShowRaisedPlatforms", false);
  }

  /**
   * Address: 0x00BFDE30 (FUN_00BFDE30, cleanup_RandomElevationOffset_ConAlias)
   *
   * What it does:
   * Tears down recovered `RandomElevationOffset` alias startup storage.
   */
  void cleanup_RandomElevationOffset_ConAlias()
  {
    ConAlias_RandomElevationOffset().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD6F60 (FUN_00BD6F60, register_RandomElevationOffset_ConAlias)
   *
   * What it does:
   * Initializes recovered `RandomElevationOffset` console alias and registers
   * process-exit cleanup.
   */
  void register_RandomElevationOffset_ConAlias()
  {
    ConAlias_RandomElevationOffset().InitializeRecovered(
      "Alter random non-combat elevation offset so plane don't all stick on the same plane",
      "RandomElevationOffset",
      "DoSimCommand RandomElevationOffset"
    );
    RegisterAtexitCleanup<&cleanup_RandomElevationOffset_ConAlias>();
  }

  /**
   * Address: 0x00BFDE80 (FUN_00BFDE80, cleanup_RandomElevationOffset_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `RandomElevationOffset` sim-convar startup storage.
   */
  void cleanup_RandomElevationOffset_SimConVarDef()
  {
    DestroyRecoveredSimConVarBase(gRandomElevationOffsetSimConVarSlot);
  }

  /**
   * Address: 0x00BD6F90 (FUN_00BD6F90, register_RandomElevationOffset_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `RandomElevationOffset` sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_RandomElevationOffset_SimConVarDef()
  {
    (void)ConstructRecoveredSimConVar(gRandomElevationOffsetSimConVarSlot, "RandomElevationOffset", 1.0f);
    RegisterAtexitCleanup<&cleanup_RandomElevationOffset_SimConVarDef>();
  }

  /**
   * Address: 0x00BFE0F0 (FUN_00BFE0F0, cleanup_AirLookAheadMult_ConAlias)
   *
   * What it does:
   * Tears down recovered `AirLookAheadMult` alias startup storage.
   */
  void cleanup_AirLookAheadMult_ConAlias()
  {
    ConAlias_AirLookAheadMult().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD74B0 (FUN_00BD74B0, register_AirLookAheadMult_ConAlias)
   *
   * What it does:
   * Initializes recovered `AirLookAheadMult` console alias and registers
   * process-exit cleanup.
   */
  void register_AirLookAheadMult_ConAlias()
  {
    ConAlias_AirLookAheadMult().InitializeRecovered(
      "Alter the air units look ahead distance",
      "AirLookAheadMult",
      "DoSimCommand AirLookAheadMult"
    );
    RegisterAtexitCleanup<&cleanup_AirLookAheadMult_ConAlias>();
  }

  /**
   * Address: 0x00BFE140 (FUN_00BFE140, cleanup_AirLookAheadMult_SimConVarDef)
   *
   * What it does:
   * Tears down recovered `AirLookAheadMult` sim-convar startup storage.
   */
  void cleanup_AirLookAheadMult_SimConVarDef()
  {
    DestroyRecoveredSimConVarBase(gAirLookAheadMultSimConVarSlot);
  }

  /**
   * Address: 0x00BD74E0 (FUN_00BD74E0, register_AirLookAheadMult_SimConVarDef)
   *
   * What it does:
   * Initializes recovered `AirLookAheadMult` sim-convar definition and
   * registers process-exit cleanup.
   */
  void register_AirLookAheadMult_SimConVarDef()
  {
    (void)ConstructRecoveredSimConVar(gAirLookAheadMultSimConVarSlot, "AirLookAheadMult", 1.0f);
    RegisterAtexitCleanup<&cleanup_AirLookAheadMult_SimConVarDef>();
  }

  /**
   * Address: 0x00BD4BE0 (FUN_00BD4BE0, register_sim_SimInits_mForms_prependStartupLane21)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane21`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane21()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane21 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane21 = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane21);
    return result;
  }

  /**
   * Address: 0x00BD4C00 (FUN_00BD4C00, register_sim_SimInits_mForms_prependStartupLane22)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane22`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane22()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane22 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane22 = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane22);
    return result;
  }

  /**
   * Address: 0x00BD5300 (FUN_00BD5300, register_sim_SimInits_mForms_prependStartupLane23)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane23`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane23()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane23 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane23 = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane23);
    return result;
  }

  /**
   * Address: 0x00BD5C90 (FUN_00BD5C90, register_sim_SimInits_mForms_prependStartupLane24)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane24`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane24()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane24 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane24 = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane24);
    return result;
  }

  /**
   * Address: 0x00BD65E0 (FUN_00BD65E0, register_sim_SimInits_mForms_prependStartupLane25)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane25`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane25()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane25 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane25 = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane25);
    return result;
  }

  /**
   * Address: 0x00BD6600 (FUN_00BD6600, register_sim_SimInits_mForms_prependStartupLane26)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane26`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane26()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane26 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane26 = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane26);
    return result;
  }

  /**
   * Address: 0x00BD7910 (FUN_00BD7910, sub_BD7910)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane27`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane27()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane27 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane27 = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane27);
    return result;
  }

  /**
   * Address: 0x00BD7930 (FUN_00BD7930, sub_BD7930)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane28`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane28()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane28 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane28 = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane28);
    return result;
  }

  /**
   * Address: 0x00BC8E40 (FUN_00BC8E40, register_SpecFootprints_LuaFUncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SpecFootprints_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SpecFootprints_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_SpecFootprints_LuaFuncDef>();
  }

  /**
   * Address: 0x00BC97F0 (FUN_00BC97F0, register_CreateResourceDeposit_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_CreateResourceDeposit_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateResourceDeposit_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_CreateResourceDeposit_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9800 (FUN_00BD9800, sub_BD9800)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered `moho_weapon_methods.mFactory` startup lane anchor.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependMohoWeaponMethodsFactoryLane()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevMohoWeaponMethodsFactory = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevMohoWeaponMethodsFactory = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorMohoWeaponMethodsFactory);
    return result;
  }

  /**
   * Address: 0x00BD9A30 (FUN_00BD9A30, sub_BD9A30)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane30`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane30()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane30 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane30 = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane30);
    return result;
  }

  /**
   * Address: 0x00BD9A70 (FUN_00BD9A70, register_EntityCreatePropAtBone_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_EntityCreatePropAtBone_LuaFuncDef` to `func_EntityCreatePropAtBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCreatePropAtBone_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_EntityCreatePropAtBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9A80 (FUN_00BD9A80, register_SplitProp_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SplitProp_LuaFuncDef` to `func_SplitProp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SplitProp_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_SplitProp_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9A90 (FUN_00BD9A90, register_EntityPushOver_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_EntityPushOver_LuaFuncDef` to `func_EntityPushOver_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityPushOver_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_EntityPushOver_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9AA0 (FUN_00BD9AA0, register_PropAddBoundedProp_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_PropAddBoundedProp_LuaFuncDef` to `func_PropAddBoundedProp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_PropAddBoundedProp_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_PropAddBoundedProp_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9A50 (FUN_00BD9A50, j_func_CreatePropHPR_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CreatePropHPR_LuaFuncDef` to `func_CreatePropHPR_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreatePropHPR_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_CreatePropHPR_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9A60 (FUN_00BD9A60, register_CreateProp_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CreateProp_LuaFuncDef` to `func_CreateProp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateProp_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_CreateProp_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9CF0 (FUN_00BD9CF0, j_func_ShouldCreateInitialArmyUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_ShouldCreateInitialArmyUnits_LuaFuncDef` to `func_ShouldCreateInitialArmyUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_ShouldCreateInitialArmyUnits_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ShouldCreateInitialArmyUnits_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBDE0 (FUN_00BDBDE0, register_EndGame_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_EndGame_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EndGame_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_EndGame_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBDF0 (FUN_00BDBDF0, register_IsGameOver_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_IsGameOver_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IsGameOver_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_IsGameOver_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBE00 (FUN_00BDBE00, register_GetEntityById_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetEntityById_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetEntityById_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetEntityById_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBE10 (FUN_00BDBE10, register_GetUnitByIdSim_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetUnitByIdSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetUnitByIdSim_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetUnitByIdSim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D10 (FUN_00BE4D10, register_ClearBuildTemplates_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ClearBuildTemplates_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ClearBuildTemplates_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ClearBuildTemplates_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D20 (FUN_00BE4D20, j_func_RenderOverlayMilitary_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_RenderOverlayMilitary_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_RenderOverlayMilitary_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_RenderOverlayMilitary_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D30 (FUN_00BE4D30, register_RenderOverlayIntel_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_RenderOverlayIntel_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RenderOverlayIntel_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_RenderOverlayIntel_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D40 (FUN_00BE4D40, register_RenderOverlayEconomy_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_RenderOverlayEconomy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RenderOverlayEconomy_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_RenderOverlayEconomy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D50 (FUN_00BE4D50, j_func_TeamColorModeUser_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_TeamColorMode_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_TeamColorModeUser_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_TeamColorMode_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE4D60 (FUN_00BE4D60, register_GetUnitByIdUser_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetUnitByIdUser_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetUnitByIdUser_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetUnitByIdUser_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBF00 (FUN_00BDBF00, register_SimConExecute_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SimConExecute_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SimConExecute_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_SimConExecute_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBF90 (FUN_00BDBF90, register_EntityCategoryContains_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_EntityCategoryContainsSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryContains_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_EntityCategoryContainsSim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBFA0 (FUN_00BDBFA0, register_EntityCategoryFilterDownSim_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_EntityCategoryFilterDownSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryFilterDownSim_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_EntityCategoryFilterDownSim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBFB0 (FUN_00BDBFB0, register_EntityCategoryCount_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_EntityCategoryCount_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryCount_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_EntityCategoryCount_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBFD0 (FUN_00BDBFD0, register_GenerateRandomOrientation_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GenerateRandomOrientation_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GenerateRandomOrientation_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GenerateRandomOrientation_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBFE0 (FUN_00BDBFE0, register_GetGameTimeSecondsSim_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetGameTimeSecondsSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetGameTimeSecondsSim_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetGameTimeSecondsSim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDBFF0 (FUN_00BDBFF0, register_GetGameTick_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetGameTick_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetGameTick_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetGameTick_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC000 (FUN_00BDC000, register_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC050 (FUN_00BDC050, register_Warp_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_Warp_LuaFuncDef`.
   */
  CScrLuaInitForm* register_Warp_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_Warp_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC070 (FUN_00BDC070, register_GetTerrainHeight_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetTerrainHeight_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetTerrainHeight_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetTerrainHeight_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC080 (FUN_00BDC080, register_GetSurfaceHeight_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetSurfaceHeight_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetSurfaceHeight_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetSurfaceHeight_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC090 (FUN_00BDC090, register_GetTerrainTypeOffset_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetTerrainTypeOffset_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetTerrainTypeOffset_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetTerrainTypeOffset_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC0A0 (FUN_00BDC0A0, register_GetTerrainType_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetTerrainType_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetTerrainType_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetTerrainType_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC0B0 (FUN_00BDC0B0, register_SetTerrainType_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SetTerrainType_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetTerrainType_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_SetTerrainType_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC0C0 (FUN_00BDC0C0, register_SetTerrainTypeRect_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SetTerrainTypeRect_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetTerrainTypeRect_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_SetTerrainTypeRect_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC0D0 (FUN_00BDC0D0, register_SetPlayableRect_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SetPlayableRect_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetPlayableRect_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_SetPlayableRect_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC0E0 (FUN_00BDC0E0, register_FlushIntelInRect_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_FlushIntelInRect_LuaFuncDef`.
   */
  CScrLuaInitForm* register_FlushIntelInRect_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_FlushIntelInRect_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC0F0 (FUN_00BDC0F0, register_GetUnitBlueprintByName_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_GetUnitBlueprintByName_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetUnitBlueprintByName_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_GetUnitBlueprintByName_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC290 (FUN_00BDC290, register_SetArmyStatsSyncArmy_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_SetArmyStatsSyncArmy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyStatsSyncArmy_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_SetArmyStatsSyncArmy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC2B0 (FUN_00BDC2B0, register_DrawLine_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_DrawLine_LuaFuncDef`.
   */
  CScrLuaInitForm* register_DrawLine_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_DrawLine_LuaFuncDef>();
  }

  /**
   * Address: 0x00BDC2D0 (FUN_00BDC2D0, register_DrawCircle_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_DrawCircle_LuaFuncDef`.
   */
  CScrLuaInitForm* register_DrawCircle_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_DrawCircle_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9B20 (FUN_00BD9B20, register_path_ArmyBudget_ConAliasDef)
   *
   * What it does:
   * Registers the `path_ArmyBudget` console alias text for sim-command dispatch.
   */
  void register_path_ArmyBudget_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_path_ArmyBudget().InitializeRecovered(
      "Budget for each army to do pathfinding each tick",
      "path_ArmyBudget",
      "DoSimCommand path_ArmyBudget"
    );
  }

  /**
   * Address: 0x00BD9B50 (FUN_00BD9B50, register_path_ArmyBudget_SimConVarDef)
   *
   * What it does:
   * Initializes the `path_ArmyBudget` sim convar with default value 2500.
   */
  void register_path_ArmyBudget_SimConVarDef()
  {
    (void)SimConVar_path_ArmyBudget();
  }

  /**
   * Address: 0x00BF70E0 (FUN_00BF70E0, sub_BF70E0)
   *
   * What it does:
   * Tears down startup-owned alias payload for `path_MaxInstantWorkUnits`.
   */
  void cleanup_path_MaxInstantWorkUnits_ConAliasDef()
  {
    ConAlias_path_MaxInstantWorkUnits().ShutdownRecovered();
  }

  /**
   * Address: 0x00BCCBF0 (FUN_00BCCBF0, register_path_MaxInstantWorkUnits_ConAliasDef)
   *
   * What it does:
   * Registers the `path_MaxInstantWorkUnits` console alias.
   */
  void register_path_MaxInstantWorkUnits_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_path_MaxInstantWorkUnits().InitializeRecovered(
      "Budget for instant pathfinds by the AI",
      "path_MaxInstantWorkUnits",
      "DoSimCommand path_MaxInstantWorkUnits"
    );
    RegisterAtexitCleanup<&cleanup_path_MaxInstantWorkUnits_ConAliasDef>();
  }

  /**
   * Address: 0x00BF7130 (FUN_00BF7130, sub_BF7130)
   *
   * What it does:
   * Tears down startup-owned sim-convar payload for `path_MaxInstantWorkUnits`.
   */
  void cleanup_path_MaxInstantWorkUnits_SimConVarDef()
  {
    DestroyRecoveredSimConVarBase(gPathMaxInstantWorkUnitsSimConVarSlot);
  }

  /**
   * Address: 0x00BCCC20 (FUN_00BCCC20, register_path_MaxInstantWorkUnits_SimConVarDef)
   *
   * What it does:
   * Registers/initializes the `path_MaxInstantWorkUnits` sim convar (default
   * `500`).
   */
  void register_path_MaxInstantWorkUnits_SimConVarDef()
  {
    (void)ConstructRecoveredSimConVar(gPathMaxInstantWorkUnitsSimConVarSlot, "path_MaxInstantWorkUnits", 500);
    RegisterAtexitCleanup<&cleanup_path_MaxInstantWorkUnits_SimConVarDef>();
  }

  /**
   * Address: 0x00BF7140 (FUN_00BF7140, sub_BF7140)
   *
   * What it does:
   * Tears down startup-owned alias payload for
   * `path_UnreachableTimeoutSearchSteps`.
   */
  void cleanup_path_UnreachableTimeoutSearchSteps_ConAliasDef()
  {
    ConAlias_path_UnreachableTimeoutSearchSteps().ShutdownRecovered();
  }

  /**
   * Address: 0x00BCCC70 (FUN_00BCCC70, register_path_UnreachableTimeoutSearchSteps_ConAliasDef)
   *
   * What it does:
   * Registers the `path_UnreachableTimeoutSearchSteps` console alias.
   */
  void register_path_UnreachableTimeoutSearchSteps_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_path_UnreachableTimeoutSearchSteps().InitializeRecovered(
      "Maximum number of ticks to allow a single pathfind to take for an unreachable path",
      "path_UnreachableTimeoutSearchSteps",
      "DoSimCommand path_UnreachableTimeoutSearchSteps"
    );
    RegisterAtexitCleanup<&cleanup_path_UnreachableTimeoutSearchSteps_ConAliasDef>();
  }

  /**
   * Address: 0x00BF7190 (FUN_00BF7190, sub_BF7190)
   *
   * What it does:
   * Tears down startup-owned sim-convar payload for
   * `path_UnreachableTimeoutSearchSteps`.
   */
  void cleanup_path_UnreachableTimeoutSearchSteps_SimConVarDef()
  {
    DestroyRecoveredSimConVarBase(gPathUnreachableTimeoutSearchStepsSimConVarSlot);
  }

  /**
   * Address: 0x00BCCCA0 (FUN_00BCCCA0, register_path_UnreachableTimeoutSearchSteps_SimConVarDef)
   *
   * What it does:
   * Registers/initializes the `path_UnreachableTimeoutSearchSteps` sim convar
   * (default `1000`).
   */
  void register_path_UnreachableTimeoutSearchSteps_SimConVarDef()
  {
    (void)ConstructRecoveredSimConVar(gPathUnreachableTimeoutSearchStepsSimConVarSlot, "path_UnreachableTimeoutSearchSteps", 1000);
    RegisterAtexitCleanup<&cleanup_path_UnreachableTimeoutSearchSteps_SimConVarDef>();
  }

  /**
   * Address: 0x00BD8710 (FUN_00BD8710, register_AI_RenderBombDropZone_ConAliasDef)
   *
   * What it does:
   * Registers the `AI_RenderBombDropZone` console alias text for sim-command
   * dispatch.
   */
  void register_AI_RenderBombDropZone_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_AI_RenderBombDropZone().InitializeRecovered(
      "Toggle on/off rendering of bomb drop zone",
      "AI_RenderBombDropZone",
      "DoSimCommand AI_RenderBombDropZone"
    );
  }

  /**
   * Address: 0x00BD8740 (FUN_00BD8740, register_AI_RenderBombDropZone_SimConVarDef)
   *
   * What it does:
   * Initializes the `AI_RenderBombDropZone` sim convar with default value
   * `false`.
   */
  void register_AI_RenderBombDropZone_SimConVarDef()
  {
    (void)SimConVar_AI_RenderBombDropZone();
  }

  /**
   * Address: 0x00BD8790 (FUN_00BD8790, register_moho_weapon_methods)
   *
   * What it does:
   * Prepends recovered moho-weapon Lua-init anchor to the active `sim` init
   * chain and returns the previous chain head.
   */
  CScrLuaInitForm* register_moho_weapon_methods()
  {
    return register_sim_SimInits_mForms_prependMohoWeaponMethodsFactoryLane();
  }

  /**
   * Address: 0x00BCDC10 (FUN_00BCDC10, register_sim_SimInits_mForms_reconBlipAnchorA)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the chain to the
   * recovered recon-blip anchor-A lane.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_reconBlipAnchorA()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (!simSet) {
      gSimLuaInitFormPrevReconBlipAnchorA = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevReconBlipAnchorA = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorReconBlipAnchorA);
    return result;
  }

  /**
   * Address: 0x00BCDC30 (FUN_00BCDC30, register_sim_SimInits_mForms_reconBlipAnchorB)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the chain to the
   * recovered recon-blip anchor-B lane.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_reconBlipAnchorB()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
    if (!simSet) {
      gSimLuaInitReconBlipAnchorB.mPrevDef = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitReconBlipAnchorB.mPrevDef = result;
    simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitReconBlipAnchorB);
    return result;
  }

  /**
   * Address: 0x00BCDF20 (FUN_00BCDF20, register_CScrLuaMetatableFactory_ReconBlip_Index)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<ReconBlip>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_ReconBlip_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryReconBlipIndex>();
  }

  /**
   * Address: 0x00BCDF40 (FUN_00BCDF40, register_CScrLuaMetatableFactory_Entity_Index)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<Entity>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_Entity_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryEntityIndex>();
  }

  /**
   * Address: 0x00BCDE00 (FUN_00BCDE00, register_ReconBlipGetBlueprint_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipGetBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipGetBlueprint_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ReconBlipGetBlueprint_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCDE10 (FUN_00BCDE10, register_ReconBlipGetSource_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipGetSource_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipGetSource_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ReconBlipGetSource_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCDE20 (FUN_00BCDE20, register_ReconBlipIsSeenEver_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsSeenEver_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsSeenEver_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ReconBlipIsSeenEver_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCDE30 (FUN_00BCDE30, register_ReconBlipIsSeenNow_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsSeenNow_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsSeenNow_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ReconBlipIsSeenNow_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCDE40 (FUN_00BCDE40, register_ReconBlipIsMaybeDead_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsMaybeDead_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsMaybeDead_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ReconBlipIsMaybeDead_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCDE50 (FUN_00BCDE50, register_ReconBlipIsOnOmni_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsOnOmni_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsOnOmni_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ReconBlipIsOnOmni_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCDE60 (FUN_00BCDE60, register_ReconBlipIsOnSonar_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsOnSonar_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsOnSonar_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ReconBlipIsOnSonar_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCDE70 (FUN_00BCDE70, register_ReconBlipIsOnRadar_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsOnRadar_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsOnRadar_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ReconBlipIsOnRadar_LuaFuncDef>();
  }

  /**
   * Address: 0x00BCDE80 (FUN_00BCDE80, register_ReconBlipIsKnownFake_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ReconBlipIsKnownFake_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ReconBlipIsKnownFake_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ReconBlipIsKnownFake_LuaFuncDef>();
  }

  /**
   * Address: 0x00BF7AE0 (FUN_00BF7AE0, cleanup_ReconFlush_ConAliasDef)
   *
   * What it does:
   * Tears down startup-owned `ReconFlush` console alias payload.
   */
  void cleanup_ReconFlush_ConAliasDef()
  {
    if (!gReconFlushConAliasConstructed) {
      return;
    }

    ReconFlushConAlias().ShutdownRecovered();
    gReconFlushConAliasConstructed = false;
  }

  /**
   * Address: 0x00BF7B30 (FUN_00BF7B30, cleanup_ReconFlush_SimConFuncDef)
   *
   * What it does:
   * Destroys startup-owned `ReconFlush` sim-command callback object.
   */
  void cleanup_ReconFlush_SimConFuncDef()
  {
    if (!gReconFlushSimConFuncConstructed) {
      return;
    }

    auto& command = ReconFlushSimConFunc();
    static_cast<CSimConCommand&>(command).~CSimConCommand();
    gReconFlushSimConFuncConstructed = false;
  }

  /**
   * Address: 0x00BCDE90 (FUN_00BCDE90, register_ReconFlush_ConAliasDef)
   *
   * What it does:
   * Registers startup-owned `ReconFlush` console alias.
   */
  void register_ReconFlush_ConAliasDef()
  {
    static bool sRegistered = false;
    if (sRegistered) {
      return;
    }

    sRegistered = true;
    ConstructReconFlushConAlias().InitializeRecovered(
      "Flush all recon databases (destroys all blips)",
      "ReconFlush",
      "DoSimCommand ReconFlush"
    );
    RegisterAtexitCleanup<&cleanup_ReconFlush_ConAliasDef>();
  }

  /**
   * Address: 0x00BCDEC0 (FUN_00BCDEC0, register_ReconFlush_SimConFuncDef)
   *
   * What it does:
   * Registers startup-owned `ReconFlush` sim-command callback.
   */
  void register_ReconFlush_SimConFuncDef()
  {
    static bool sRegistered = false;
    if (sRegistered) {
      return;
    }

    sRegistered = true;
    (void)ConstructReconFlushSimConFunc();
    RegisterAtexitCleanup<&cleanup_ReconFlush_SimConFuncDef>();
  }

  /**
   * Address: 0x00C00EF0 (FUN_00C00EF0, CConAlias_ScenarioMethod cleanup)
   *
   * What it does:
   * Tears down startup-owned `ScenarioMethod` console alias payload.
   */
  void cleanup_CConAlias_ScenarioMethod()
  {
    if (!gScenarioMethodConAliasConstructed) {
      return;
    }

    ScenarioMethodConAlias().ShutdownRecovered();
    gScenarioMethodConAliasConstructed = false;
  }

  /**
   * Address: 0x00C00F40 (FUN_00C00F40, cleanup_ScenarioMethod_SimConFuncDef)
   *
   * What it does:
   * Destroys startup-owned `ScenarioMethod` sim-command callback object.
   */
  void cleanup_ScenarioMethod_SimConFuncDef()
  {
    if (!gScenarioMethodSimConFuncConstructed) {
      return;
    }

    auto& command = ScenarioMethodSimConFunc();
    static_cast<CSimConCommand&>(command).~CSimConCommand();
    gScenarioMethodSimConFuncConstructed = false;
  }

  /**
   * Address: 0x00BDBCD0 (FUN_00BDBCD0, register_CConAlias_ScenarioMethod)
   *
   * What it does:
   * Registers startup-owned `ScenarioMethod` command alias.
   */
  void register_CConAlias_ScenarioMethod()
  {
    static bool sRegistered = false;
    if (sRegistered) {
      return;
    }

    sRegistered = true;
    ConstructScenarioMethodConAlias().InitializeRecovered(
      "Run a scenario-specific command",
      "ScenarioMethod",
      "DoSimCommand ScenarioMethod"
    );
    RegisterAtexitCleanup<&cleanup_CConAlias_ScenarioMethod>();
  }

  /**
   * Address: 0x00BDBD00 (FUN_00BDBD00, register_ScenarioMethod_SimConFuncDef)
   *
   * What it does:
   * Registers startup-owned `ScenarioMethod` sim-command callback.
   */
  void register_ScenarioMethod_SimConFuncDef()
  {
    static bool sRegistered = false;
    if (sRegistered) {
      return;
    }

    sRegistered = true;
    (void)ConstructScenarioMethodSimConFunc();
    RegisterAtexitCleanup<&cleanup_ScenarioMethod_SimConFuncDef>();
  }

} // namespace moho


