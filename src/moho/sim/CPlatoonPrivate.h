#pragma once

// Private to moho/sim: helpers the pieces of the former CPlatoon.cpp share.

#include "moho/sim/CPlatoon.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/math/X87Math.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/algorithms/Sort.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaClassBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/EntityCategorySetVectorReflection.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/ECompareType.h"
#include "moho/ai/IAiTransport.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/entity/Entity.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/IArmy.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/CUnitCommand.h"

namespace moho
{

  template <>
  class CScrLuaMetatableFactory<CPlatoon> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CPlatoon>) == 0x08, "CScrLuaMetatableFactory<CPlatoon> size must be 0x08"
  );
}

namespace
{
  using moho::ESquadClass;
  using moho::CSquad;
  using moho::EntityCategorySet;
  using moho::Unit;

  // One past SQUADCLASS_Scout: the "every assigned class" selector the Lua
  // bindings default to. ESquadClassTypeInfo registers no name for it.
  constexpr ESquadClass kAllSquadClasses = static_cast<ESquadClass>(6);

  struct PlatoonUnitSearchEntry
  {
    moho::Unit* unit = nullptr; // +0x00
    float distanceSq = 0.0f; // +0x04
  };
  static_assert(sizeof(PlatoonUnitSearchEntry) == 0x8, "PlatoonUnitSearchEntry size must be 0x8");

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("Sim");
    return fallbackSet;
  }
}

namespace moho
{

  int cfunc_CPlatoonGetPersonality(lua_State* luaContext);
  int cfunc_CPlatoonGetBrain(lua_State* luaContext);
  int cfunc_CPlatoonGetFactionIndex(lua_State* luaContext);
  int cfunc_CPlatoonGetPersonalityL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGetBrainL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGetFactionIndexL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUniquelyNamePlatoon(lua_State* luaContext);
  int cfunc_CPlatoonGetPlatoonUniqueName(lua_State* luaContext);
  int cfunc_CPlatoonGetAIPlan(lua_State* luaContext);
  int cfunc_CPlatoonSwitchAIPlan(lua_State* luaContext);
  int cfunc_CPlatoonGetPlatoonPosition(lua_State* luaContext);
  int cfunc_CPlatoonGetSquadPosition(lua_State* luaContext);
  int cfunc_CPlatoonGetSquadUnits(lua_State* luaContext);

  int cfunc_CPlatoonGetPlatoonUnitsL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonCanFormPlatoonL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFormPlatoonL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonSetPrioritizedTargetListL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindPrioritizedUnitL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindClosestUnitL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindClosestUnitToBaseL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindFurthestUnitL(LuaPlus::LuaState* state);
  /**
   * Address: 0x0072F790 (FUN_0072F790, cfunc_CPlatoonCanAttackTargetL)
   *
   * What it does:
   * Resolves `(platoon, squadClass, targetUnit)` from Lua, locates the
   * matching squad, and returns whether that squad can attack the
   * requested unit.
   */
  int cfunc_CPlatoonCanAttackTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonAttackTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonMoveToTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindHighestValueUnitL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonStopL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonMoveToLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonAggressiveMoveToLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFerryToLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUnloadUnitsAtLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUnloadAllAtLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonPatrolL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGuardTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonDestroyL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGetFerryBeaconsL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUseFerryBeaconL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUseTeleporterL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonSetPlatoonFormationOverrideL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGetPlatoonLifetimeStatsL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindPrioritizedUnit(lua_State* luaContext);
  int cfunc_CPlatoonFindClosestUnit(lua_State* luaContext);
  int cfunc_CPlatoonFindFurthestUnit(lua_State* luaContext);
  int cfunc_CPlatoonGuardTarget(lua_State* luaContext);
  int cfunc_CPlatoonDestroy(lua_State* luaContext);
  int cfunc_CPlatoonGetFerryBeacons(lua_State* luaContext);
  int cfunc_CPlatoonUseFerryBeacon(lua_State* luaContext);
  int cfunc_CPlatoonUseTeleporter(lua_State* luaContext);
  int cfunc_CPlatoonSetPlatoonFormationOverride(lua_State* luaContext);
  int cfunc_CPlatoonGetPlatoonLifetimeStats(lua_State* luaContext);
  int cfunc_CPlatoonCalculatePlatoonThreatL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonPlatoonCategoryCountAroundPositionL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonPlatoonCategoryCountL(LuaPlus::LuaState* state);
}

namespace moho
{
  LuaPlus::LuaObject* func_LoadPlatoon(LuaPlus::LuaState* state, LuaPlus::LuaObject* outObject);
}
