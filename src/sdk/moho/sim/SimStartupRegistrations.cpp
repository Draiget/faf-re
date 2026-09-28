#include "moho/sim/SimStartupRegistrations.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>

#include "moho/console/CConAlias.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/MotorFallDown.h"
#include "moho/lua/CScrLuaBaseClassSpec.h"
#include "moho/lua/CScrLuaClassBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDebugCommandRegistrations.h"

namespace
{
  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("Sim");
    return fallbackSet;
  }

  moho::CScrLuaInitForm* gSimLuaInitFormPrevStartupLane21 = nullptr;
  moho::CScrLuaInitForm* gSimLuaInitFormAnchorStartupLane21 = nullptr;

  int gRecoveredCScrLuaMetatableFactoryReconBlipIndex = 0;
  int gRecoveredCScrLuaMetatableFactoryEntityIndex = 0;

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

    moho::CSimConVarInstanceBase* const instance = sim->GetSimVar(&moho::gSimConVar_sim_TestVarUByte);
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

    moho::CSimConVarInstanceBase* const instance = sim->GetSimVar(&moho::gSimConVar_sim_TestVarStr);
    return instance != nullptr ? instance->GetValueStorage() : nullptr;
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
      (void)moho::register_sim_SimInits_mForms_reconBlipAnchorA();
      (void)moho::register_ReconBlipLuaBaseClass();
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
    }
  };

  [[maybe_unused]] SimStartupRegistrationsBootstrapA gSimStartupRegistrationsBootstrapA;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD59E0 (FUN_00BD59E0, dynamic initializer for `gConAlias_tree_AccelFactor`)
   * Address: 0x00BFCFB0 (FUN_00BFCFB0, dynamic atexit destructor for `gConAlias_tree_AccelFactor`)
   */
  moho::CConAlias gConAlias_tree_AccelFactor("tree_AccelFactor", "How quickly falling trees accelerate", "DoSimCommand tree_AccelFactor");

  /**
   * Address: 0x00BD5A10 (FUN_00BD5A10, dynamic initializer for `gSimConVar_tree_AccelFactor`)
   * Address: 0x00BFD000 (FUN_00BFD000, dynamic atexit destructor for `gSimConVar_tree_AccelFactor`)
   */
  TSimConVar<float> gSimConVar_tree_AccelFactor(false, "tree_AccelFactor", 0.1f);

  /**
   * Address: 0x00BD5A60 (FUN_00BD5A60, dynamic initializer for `gConAlias_tree_SpringFactor`)
   * Address: 0x00BFD010 (FUN_00BFD010, dynamic atexit destructor for `gConAlias_tree_SpringFactor`)
   */
  moho::CConAlias gConAlias_tree_SpringFactor("tree_SpringFactor", "How quickly swaying trees spring back", "DoSimCommand tree_SpringFactor");

  /**
   * Address: 0x00BD5A90 (FUN_00BD5A90, dynamic initializer for `gSimConVar_tree_SpringFactor`)
   * Address: 0x00BFD060 (FUN_00BFD060, dynamic atexit destructor for `gSimConVar_tree_SpringFactor`)
   */
  TSimConVar<float> gSimConVar_tree_SpringFactor(false, "tree_SpringFactor", 0.5f);

  /**
   * Address: 0x00BD5AE0 (FUN_00BD5AE0, dynamic initializer for `gConAlias_tree_DampFactor`)
   * Address: 0x00BFD070 (FUN_00BFD070, dynamic atexit destructor for `gConAlias_tree_DampFactor`)
   */
  moho::CConAlias gConAlias_tree_DampFactor("tree_DampFactor", "Damping on swaying trees (0 to 1)", "DoSimCommand tree_DampFactor");

  /**
   * Address: 0x00BD5B10 (FUN_00BD5B10, dynamic initializer for `gSimConVar_tree_DampFactor`)
   * Address: 0x00BFD0C0 (FUN_00BFD0C0, dynamic atexit destructor for `gSimConVar_tree_DampFactor`)
   */
  TSimConVar<float> gSimConVar_tree_DampFactor(false, "tree_DampFactor", 0.5f);

  /**
   * Address: 0x00BD5B60 (FUN_00BD5B60, dynamic initializer for `gConAlias_tree_UprootFactor`)
   * Address: 0x00BFD0D0 (FUN_00BFD0D0, dynamic atexit destructor for `gConAlias_tree_UprootFactor`)
   */
  moho::CConAlias gConAlias_tree_UprootFactor("tree_UprootFactor", "How far to raise falling trees up out of the ground", "DoSimCommand tree_UprootFactor");

  /**
   * Address: 0x00BD5B90 (FUN_00BD5B90, dynamic initializer for `gSimConVar_tree_UprootFactor`)
   * Address: 0x00BFD120 (FUN_00BFD120, dynamic atexit destructor for `gSimConVar_tree_UprootFactor`)
   */
  TSimConVar<float> gSimConVar_tree_UprootFactor(false, "tree_UprootFactor", 0.1f);

  /**
   * Address: 0x00BD69F0 (FUN_00BD69F0, dynamic initializer for `gConAlias_ShowRaisedPlatforms`)
   * Address: 0x00BFD880 (FUN_00BFD880, dynamic atexit destructor for `gConAlias_ShowRaisedPlatforms`)
   */
  moho::CConAlias gConAlias_ShowRaisedPlatforms("ShowRaisedPlatforms", "Turns on or off rendering of raised platform for tweaking and setting up purposes", "DoSimCommand ShowRaisedPlatforms");

  /**
   * Address: 0x00BD6A20 (FUN_00BD6A20, dynamic initializer for `gSimConVar_ShowRaisedPlatforms`)
   * Address: 0x00BFD8D0 (FUN_00BFD8D0, dynamic atexit destructor for `gSimConVar_ShowRaisedPlatforms`)
   */
  TSimConVar<bool> gSimConVar_ShowRaisedPlatforms(true, "ShowRaisedPlatforms", false);

  /**
   * Address: 0x00BD6F60 (FUN_00BD6F60, dynamic initializer for `gConAlias_RandomElevationOffset`)
   * Address: 0x00BFDE30 (FUN_00BFDE30, dynamic atexit destructor for `gConAlias_RandomElevationOffset`)
   */
  moho::CConAlias gConAlias_RandomElevationOffset("RandomElevationOffset", "Alter random non-combat elevation offset so plane don't all stick on the same plane", "DoSimCommand RandomElevationOffset");

  /**
   * Address: 0x00BD6F90 (FUN_00BD6F90, dynamic initializer for `gSimConVar_RandomElevationOffset`)
   * Address: 0x00BFDE80 (FUN_00BFDE80, dynamic atexit destructor for `gSimConVar_RandomElevationOffset`)
   */
  TSimConVar<float> gSimConVar_RandomElevationOffset(false, "RandomElevationOffset", 1.0f);

  /**
   * Address: 0x00BD74B0 (FUN_00BD74B0, dynamic initializer for `gConAlias_AirLookAheadMult`)
   * Address: 0x00BFE0F0 (FUN_00BFE0F0, dynamic atexit destructor for `gConAlias_AirLookAheadMult`)
   */
  moho::CConAlias gConAlias_AirLookAheadMult("AirLookAheadMult", "Alter the air units look ahead distance", "DoSimCommand AirLookAheadMult");

  /**
   * Address: 0x00BD74E0 (FUN_00BD74E0, dynamic initializer for `gSimConVar_AirLookAheadMult`)
   * Address: 0x00BFE140 (FUN_00BFE140, dynamic atexit destructor for `gSimConVar_AirLookAheadMult`)
   */
  TSimConVar<float> gSimConVar_AirLookAheadMult(false, "AirLookAheadMult", 1.0f);

  /**
   * Address: 0x00BD4BE0 (FUN_00BD4BE0, register_sim_SimInits_mForms_prependStartupLane21)
   *
   * What it does:
   * Saves the current `sim` Lua-init form chain head and replaces it with the
   * recovered startup lane anchor for `startupLane21`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_prependStartupLane21()
  {
    CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("Sim");
    if (simSet == nullptr) {
      gSimLuaInitFormPrevStartupLane21 = nullptr;
      return nullptr;
    }

    CScrLuaInitForm* const result = simSet->mForms;
    gSimLuaInitFormPrevStartupLane21 = result;
    // Prepend suppressed: the binary's anchor is a statically initialised
    // form object in .data with no constructor, so it patches the list by
    // hand. Our equivalent is a real C++ object whose constructor already
    // calls AddInit, and re-doing it here published the address of a
    // CScrLuaInitForm* variable as the list head - a null vtable pointer
    // that crashed RunLuaInitFormSetIfPresent. See CPrefetchSet.cpp.
    // simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gSimLuaInitFormAnchorStartupLane21);
    return result;
  }

  /**
   * Address: 0x00BD4C00 (FUN_00BD4C00, sub_BD4C00) -- record at 0x00F59F34
   *
   * What it does:
   * Declares `CollisionBeamEntity` as deriving from `Entity` for the Lua
   * class system, so `moho.CollisionBeamEntity` carries `moho.entity_methods`
   * in its array part.
   */
  CScrLuaInitForm* register_CollisionBeamEntityLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      SimLuaInitSet(),
      &CScrLuaMetatableFactory<CollisionBeamEntity>::Instance(),
      &CScrLuaMetatableFactory<Entity>::Instance(),
      "CollisionBeamEntity",
      "derived from Entity"
    );
    return &spec;
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
    static CScrLuaClassBinder binder(
      SimLuaInitSet(), "moho.entity_methods", &CScrLuaMetatableFactory<Entity>::Instance(), "Entity", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD5C90 (FUN_00BD5C90, sub_BD5C90) -- record at 0x00F59F68
   *
   * What it does:
   * Publishes `MotorFallDown`'s method table as `moho.MotorFallDown`.
   */
  CScrLuaInitForm* register_moho_MotorFallDown()
  {
    static CScrLuaClassBinder binder(
      SimLuaInitSet(),
      "moho.MotorFallDown",
      &CScrLuaMetatableFactory<MotorFallDown>::Instance(),
      "MotorFallDown",
      ""
    );
    return &binder;
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
    static CScrLuaClassBinder binder(
      SimLuaInitSet(), "moho.projectile_methods", &CScrLuaMetatableFactory<Projectile>::Instance(), "Projectile", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD6600 (FUN_00BD6600, sub_BD6600) -- record at 0x00F59FA8
   *
   * What it does:
   * Declares `Projectile` as deriving from `Entity` for the Lua class system.
   */
  CScrLuaInitForm* register_ProjectileLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      SimLuaInitSet(),
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      &CScrLuaMetatableFactory<Entity>::Instance(),
      "Projectile",
      "derived from Entity"
    );
    return &spec;
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
    static CScrLuaClassBinder binder(
      SimLuaInitSet(), "moho.unit_methods", &CScrLuaMetatableFactory<Unit>::Instance(), "Unit", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD7930 (FUN_00BD7930, sub_BD7930) -- record at 0x00F59FDC
   *
   * What it does:
   * Declares `Unit` as deriving from `Entity` for the Lua class system.
   * Without it `moho.unit_methods` is a flat table, `class.lua`'s `Flatten`
   * has no base to walk, and every inherited entity method - `DisableIntel`
   * first among them - is nil on a unit.
   */
  CScrLuaInitForm* register_UnitLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      SimLuaInitSet(),
      &CScrLuaMetatableFactory<Unit>::Instance(),
      &CScrLuaMetatableFactory<Entity>::Instance(),
      "Unit",
      "derived from Entity"
    );
    return &spec;
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
   * Address: 0x00BD9800 (FUN_00BD9800, sub_BD9800) -- record at 0x00F5A010
   *
   * What it does:
   * Declares `Prop` as deriving from `Entity` for the Lua class system.
   *
   * IDA names the record `moho_weapon_methods.mFactory` because it sits one
   * object past the `moho.weapon_methods` binder at 0x00F59FF8; the record's
   * own fields say `base` / `Prop` / "derived from Entity".
   */
  CScrLuaInitForm* register_PropLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      SimLuaInitSet(),
      &CScrLuaMetatableFactory<Prop>::Instance(),
      &CScrLuaMetatableFactory<Entity>::Instance(),
      "Prop",
      "derived from Entity"
    );
    return &spec;
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
    static CScrLuaClassBinder binder(
      SimLuaInitSet(), "moho.prop_methods", &CScrLuaMetatableFactory<Prop>::Instance(), "Prop", ""
    );
    return &binder;
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
   * Address: 0x00BDBEE0 (FUN_00BDBEE0, register_FlattenMapRect_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_FlattenMapRect_LuaFuncDef`.
   */
  CScrLuaInitForm* register_FlattenMapRect_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_FlattenMapRect_LuaFuncDef>();
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
   * Address: 0x00BDC040 (FUN_00BDC040, register_ChangeUnitArmy_LuaFuncDef)
   *
   * What it does:
   * Forwards startup thunk into `func_ChangeUnitArmy_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ChangeUnitArmy_LuaFuncDef()
  {
    return ForwardSimStartupLuaThunk<&func_ChangeUnitArmy_LuaFuncDef>();
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
   * Address: 0x00BD9B20 (FUN_00BD9B20, dynamic initializer for `gConAlias_path_ArmyBudget`)
   * Address: 0x00BFE530 (FUN_00BFE530, dynamic atexit destructor for `gConAlias_path_ArmyBudget`)
   */
  moho::CConAlias gConAlias_path_ArmyBudget("path_ArmyBudget", "Budget for each army to do pathfinding each tick", "DoSimCommand path_ArmyBudget");

  /**
   * Address: 0x00BD9B50 (FUN_00BD9B50, dynamic initializer for `gSimConVar_path_ArmyBudget`)
   * Address: 0x00BFF310 (FUN_00BFF310, dynamic atexit destructor for `gSimConVar_path_ArmyBudget`)
   */
  TSimConVar<int> gSimConVar_path_ArmyBudget(false, "path_ArmyBudget", 2500);

  /**
   * Address: 0x00BCCBF0 (FUN_00BCCBF0, dynamic initializer for `gConAlias_path_MaxInstantWorkUnits`)
   * Address: 0x00BF70E0 (FUN_00BF70E0, dynamic atexit destructor for `gConAlias_path_MaxInstantWorkUnits`)
   */
  moho::CConAlias gConAlias_path_MaxInstantWorkUnits("path_MaxInstantWorkUnits", "Budget for instant pathfinds by the AI", "DoSimCommand path_MaxInstantWorkUnits");

  /**
   * Address: 0x00BCCC20 (FUN_00BCCC20, dynamic initializer for `gSimConVar_path_MaxInstantWorkUnits`)
   * Address: 0x00BF7130 (FUN_00BF7130, dynamic atexit destructor for `gSimConVar_path_MaxInstantWorkUnits`)
   */
  TSimConVar<int> gSimConVar_path_MaxInstantWorkUnits(false, "path_MaxInstantWorkUnits", 500);

  /**
   * Address: 0x00BCCC70 (FUN_00BCCC70, dynamic initializer for `gConAlias_path_UnreachableTimeoutSearchSteps`)
   * Address: 0x00BF7140 (FUN_00BF7140, dynamic atexit destructor for `gConAlias_path_UnreachableTimeoutSearchSteps`)
   */
  moho::CConAlias gConAlias_path_UnreachableTimeoutSearchSteps("path_UnreachableTimeoutSearchSteps", "Maximum number of ticks to allow a single pathfind to take for an unreachable path", "DoSimCommand path_UnreachableTimeoutSearchSteps");

  /**
   * Address: 0x00BCCCA0 (FUN_00BCCCA0, dynamic initializer for `gSimConVar_path_UnreachableTimeoutSearchSteps`)
   * Address: 0x00BF7190 (FUN_00BF7190, dynamic atexit destructor for `gSimConVar_path_UnreachableTimeoutSearchSteps`)
   */
  TSimConVar<int> gSimConVar_path_UnreachableTimeoutSearchSteps(false, "path_UnreachableTimeoutSearchSteps", 1000);

  /**
   * Address: 0x00BD8710 (FUN_00BD8710, dynamic initializer for `gConAlias_AI_RenderBombDropZone`)
   * Address: 0x00BFF2C0 (FUN_00BFF2C0, dynamic atexit destructor for `gConAlias_AI_RenderBombDropZone`)
   */
  moho::CConAlias gConAlias_AI_RenderBombDropZone("AI_RenderBombDropZone", "Toggle on/off rendering of bomb drop zone", "DoSimCommand AI_RenderBombDropZone");

  /**
   * Address: 0x00BD8740 (FUN_00BD8740, dynamic initializer for `gSimConVar_AI_RenderBombDropZone`)
   * Address: 0x00BFE580 (FUN_00BFE580, dynamic atexit destructor for `gSimConVar_AI_RenderBombDropZone`)
   */
  TSimConVar<bool> gSimConVar_AI_RenderBombDropZone(false, "AI_RenderBombDropZone", false);

  /**
   * Address: 0x00BD8790 (FUN_00BD8790, register_moho_weapon_methods) -- record at 0x00F59FF8
   *
   * What it does:
   * Publishes `UnitWeapon`'s method table as `moho.weapon_methods`.
   * `UnitWeapon` has no base spec of its own - it is not an entity.
   */
  CScrLuaInitForm* register_moho_weapon_methods()
  {
    static CScrLuaClassBinder binder(
      SimLuaInitSet(), "moho.weapon_methods", &CScrLuaMetatableFactory<UnitWeapon>::Instance(), "UnitWeapon", ""
    );
    return &binder;
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
    static CScrLuaClassBinder binder(
      SimLuaInitSet(), "moho.blip_methods", &CScrLuaMetatableFactory<ReconBlip>::Instance(), "ReconBlip", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BCDC30 (FUN_00BCDC30, sub_BCDC30) -- record at 0x00F599BC
   *
   * What it does:
   * Declares `ReconBlip` as deriving from `Entity` for the Lua class system.
   */
  CScrLuaInitForm* register_ReconBlipLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      SimLuaInitSet(),
      &CScrLuaMetatableFactory<ReconBlip>::Instance(),
      &CScrLuaMetatableFactory<Entity>::Instance(),
      "ReconBlip",
      "derived from Entity"
    );
    return &spec;
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
   * Address: 0x00BCDE90 (FUN_00BCDE90, dynamic initializer for `gConAlias_ReconFlush`)
   * Address: 0x00BF7AE0 (FUN_00BF7AE0, dynamic atexit destructor for `gConAlias_ReconFlush`)
   */
  moho::CConAlias gConAlias_ReconFlush("ReconFlush", "Flush all recon databases (destroys all blips)", "DoSimCommand ReconFlush");

  /**
   * Address: 0x00BCDEC0 (FUN_00BCDEC0, dynamic initializer for `gSimConFunc_ReconFlush`)
   * Address: 0x00BF7B30 (FUN_00BF7B30, dynamic atexit destructor for `gSimConFunc_ReconFlush`)
   */
  CSimConFunc gSimConFunc_ReconFlush(false, "ReconFlush", &Sim::ReconFlush);

  /**
   * Address: 0x00BDBCD0 (FUN_00BDBCD0, dynamic initializer for `gConAlias_ScenarioMethod`)
   * Address: 0x00C00EF0 (FUN_00C00EF0, dynamic atexit destructor for `gConAlias_ScenarioMethod`)
   */
  moho::CConAlias gConAlias_ScenarioMethod("ScenarioMethod", "Run a scenario-specific command", "DoSimCommand ScenarioMethod");

  /**
   * Address: 0x00BDBD00 (FUN_00BDBD00, dynamic initializer for `gSimConFunc_ScenarioMethod`)
   * Address: 0x00C00F40 (FUN_00C00F40, dynamic atexit destructor for `gSimConFunc_ScenarioMethod`)
   */
  CSimConFunc gSimConFunc_ScenarioMethod(true, "ScenarioMethod", &Sim::ScenarioMethod);

} // namespace moho

namespace
{
  /**
   * Drives this file's Lua binder registrations.
   *
   * In the shipped binary each `register_*_LuaFuncDef` thunk is a
   * compiler-generated dynamic initializer, so the CRT's static-init array
   * calls every one of them before `main`. Nothing in this tree reproduces
   * that array, so a recovered thunk that no source line names is simply
   * never run - the binder is never constructed, the form never joins its
   * init-form set, and the global it publishes is missing at runtime with no
   * diagnostic beyond FAF's own "access to nonexistent global variable".
   *
   * This object is that call, and it is also the source-level invocation
   * that keeps the thunks out of the linker's dead-strip.
   */
  struct SimStartupRegistrationsLuaBinderBootstrap
  {
    SimStartupRegistrationsLuaBinderBootstrap()
    {
      (void)::moho::register_SpecFootprints_LuaFuncDef();
      (void)::moho::register_CreateResourceDeposit_LuaFuncDef();
      (void)::moho::register_EntityCreatePropAtBone_LuaFuncDef();
      (void)::moho::register_SplitProp_LuaFuncDef();
      (void)::moho::register_EntityPushOver_LuaFuncDef();
      (void)::moho::register_PropAddBoundedProp_LuaFuncDef();
      (void)::moho::register_CreateProp_LuaFuncDef();
      (void)::moho::register_EndGame_LuaFuncDef();
      (void)::moho::register_IsGameOver_LuaFuncDef();
      (void)::moho::register_GetEntityById_LuaFuncDef();
      (void)::moho::register_GetUnitByIdSim_LuaFuncDef();
      (void)::moho::register_ClearBuildTemplates_LuaFuncDef();
      (void)::moho::register_RenderOverlayIntel_LuaFuncDef();
      (void)::moho::register_RenderOverlayEconomy_LuaFuncDef();
      (void)::moho::register_GetUnitByIdUser_LuaFuncDef();
      (void)::moho::register_SimConExecute_LuaFuncDef();
      (void)::moho::register_FlattenMapRect_LuaFuncDef();
      (void)::moho::register_EntityCategoryContains_LuaFuncDef();
      (void)::moho::register_EntityCategoryFilterDownSim_LuaFuncDef();
      (void)::moho::register_EntityCategoryCount_LuaFuncDef();
      (void)::moho::register_GenerateRandomOrientation_LuaFuncDef();
      (void)::moho::register_GetGameTimeSecondsSim_LuaFuncDef();
      (void)::moho::register_GetGameTick_LuaFuncDef();
      (void)::moho::register_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef();
      (void)::moho::register_Warp_LuaFuncDef();
      (void)::moho::register_ChangeUnitArmy_LuaFuncDef();
      (void)::moho::register_GetTerrainHeight_LuaFuncDef();
      (void)::moho::register_GetSurfaceHeight_LuaFuncDef();
      (void)::moho::register_GetTerrainTypeOffset_LuaFuncDef();
      (void)::moho::register_GetTerrainType_LuaFuncDef();
      (void)::moho::register_SetTerrainType_LuaFuncDef();
      (void)::moho::register_SetTerrainTypeRect_LuaFuncDef();
      (void)::moho::register_SetPlayableRect_LuaFuncDef();
      (void)::moho::register_FlushIntelInRect_LuaFuncDef();
      (void)::moho::register_GetUnitBlueprintByName_LuaFuncDef();
      (void)::moho::register_SetArmyStatsSyncArmy_LuaFuncDef();
      (void)::moho::register_DrawLine_LuaFuncDef();
      (void)::moho::register_DrawCircle_LuaFuncDef();

      // The class binders. Each publishes one `moho.<x>_methods` table, which
      // is what the matching Lua module builds its class from - without them
      // /lua/sim/Unit.lua and friends fail on their first line and every
      // engine-side fallback ("Can't find AIBrain, using CAiBrain directly")
      // fires for the rest of the session.
      (void)::moho::register_sim_SimInits_mForms_prependStartupLane23();
      (void)::moho::register_sim_SimInits_mForms_prependStartupLane25();
      (void)::moho::register_sim_SimInits_mForms_prependStartupLane27();
      (void)::moho::register_sim_SimInits_mForms_prependStartupLane30();
      (void)::moho::register_moho_weapon_methods();
      (void)::moho::register_moho_MotorFallDown();
      (void)::moho::register_sim_SimInits_mForms_reconBlipAnchorA();

      // The base-class specs. Each appends one base method table into the
      // array part of its derived class table; `/lua/system/class.lua`'s
      // `Flatten` is what walks that array when `globalInit.lua` converts the
      // C classes. Without them a unit has no entity method - `DisableIntel`
      // is nil and `InitializeArmies` dies on the first army.
      (void)::moho::register_ReconBlipLuaBaseClass();
      (void)::moho::register_CollisionBeamEntityLuaBaseClass();
      (void)::moho::register_ProjectileLuaBaseClass();
      (void)::moho::register_UnitLuaBaseClass();
      (void)::moho::register_PropLuaBaseClass();
    }
  };

  const SimStartupRegistrationsLuaBinderBootstrap gSimStartupRegistrationsLuaBinderBootstrap{};
} // namespace
