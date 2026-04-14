#include "moho/ai/CAiPersonality.h"

#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/Sim.h"

using namespace moho;

namespace moho
{
  CScrLuaInitForm* func_CAiPersonalityGetPersonalityName_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetChatPersonality_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetDifficulty_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetArmySize_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetPlatoonSize_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetAttackFrequency_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetRepeatAttackFrequency_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetCounterForces_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetIntelGathering_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetCoordinatedAttacks_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetExpansionDriven_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetTechAdvancement_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetUpgradesDriven_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetDefenseDriven_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetEconomyDriven_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetFactoryTycoon_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetIntelBuildingTycoon_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSuperWeaponTendency_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetFavouriteStructures_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetAirUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetTankUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetBotUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSeaUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSpecialtyForcesEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSupportUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetDirectDamageEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetInDirectDamageEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetFavouriteUnits_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSurvivalEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetTeamSupport_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetFormationUse_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetTargetSpread_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetQuittingTendency_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetChatFrequency_LuaFuncDef();
} // namespace moho

namespace
{
  constexpr const char* kAiPersonalityModulePath = "/lua/aipersonality.lua";
  constexpr const char* kAiPersonalityClassName = "AIPersonality";
  constexpr const char* kAiPersonalityTemplateName = "AIPersonalityTemplate";
  constexpr const char* kDefaultPersonalityName = "AverageJoe";
  constexpr const char* kAiPersonalityLuaClassName = "CAiPersonality";
  constexpr const char* kAiPersonalityAdjustDelayName = "AdjustDelay";
  constexpr const char* kAiPersonalityAdjustDelayHelpText = "CAiPersonality:AdjustDelay()";

  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kAiPersonalityGetPersonalityNameName = "GetPersonalityName";
  constexpr const char* kAiPersonalityGetPersonalityNameHelpText = "CAiPersonality:GetPersonalityName()";
  constexpr const char* kAiPersonalityGetChatPersonalityName = "GetChatPersonality";
  constexpr const char* kAiPersonalityGetChatPersonalityHelpText = "CAiPersonality:GetChatPersonality()";
  constexpr const char* kAiPersonalityGetDifficultyName = "GetDifficulty";
  constexpr const char* kAiPersonalityGetDifficultyHelpText = "CAiPersonality:GetDifficulty()";
  constexpr const char* kAiPersonalityGetArmySizeName = "GetArmySize";
  constexpr const char* kAiPersonalityGetArmySizeHelpText = "CAiPersonality:GetArmySize()";
  constexpr const char* kAiPersonalityGetPlatoonSizeName = "GetPlatoonSize";
  constexpr const char* kAiPersonalityGetPlatoonSizeHelpText = "CAiPersonality:GetPlatoonSize()";
  constexpr const char* kAiPersonalityGetAttackFrequencyName = "GetAttackFrequency";
  constexpr const char* kAiPersonalityGetAttackFrequencyHelpText = "CAiPersonality:GetAttackFrequency()";
  constexpr const char* kAiPersonalityGetRepeatAttackFrequencyName = "GetRepeatAttackFrequency";
  constexpr const char* kAiPersonalityGetRepeatAttackFrequencyHelpText = "CAiPersonality:GetRepeatAttackFrequency()";
  constexpr const char* kAiPersonalityGetCounterForcesName = "GetCounterForces";
  constexpr const char* kAiPersonalityGetCounterForcesHelpText = "CAiPersonality:GetCounterForces()";
  constexpr const char* kAiPersonalityGetIntelGatheringName = "GetIntelGathering";
  constexpr const char* kAiPersonalityGetIntelGatheringHelpText = "CAiPersonality:GetIntelGathering()";
  constexpr const char* kAiPersonalityGetCoordinatedAttacksName = "GetCoordinatedAttacks";
  constexpr const char* kAiPersonalityGetCoordinatedAttacksHelpText = "CAiPersonality:GetCoordinatedAttacks()";
  constexpr const char* kAiPersonalityGetExpansionDrivenName = "GetExpansionDriven";
  constexpr const char* kAiPersonalityGetExpansionDrivenHelpText = "CAiPersonality:GetExpansionDriven()";
  constexpr const char* kAiPersonalityGetTechAdvancementName = "GetTechAdvancement";
  constexpr const char* kAiPersonalityGetTechAdvancementHelpText = "CAiPersonality:GetTechAdvancement()";
  constexpr const char* kAiPersonalityGetUpgradesDrivenName = "GetUpgradesDriven";
  constexpr const char* kAiPersonalityGetUpgradesDrivenHelpText = "CAiPersonality:GetUpgradesDriven()";
  constexpr const char* kAiPersonalityGetDefenseDrivenName = "GetDefenseDriven";
  constexpr const char* kAiPersonalityGetDefenseDrivenHelpText = "CAiPersonality:GetDefenseDriven()";
  constexpr const char* kAiPersonalityGetEconomyDrivenName = "GetEconomyDriven";
  constexpr const char* kAiPersonalityGetEconomyDrivenHelpText = "CAiPersonality:GetEconomyDriven()";
  constexpr const char* kAiPersonalityGetFactoryTycoonName = "GetFactoryTycoon";
  constexpr const char* kAiPersonalityGetFactoryTycoonHelpText = "CAiPersonality:GetFactoryTycoon()";
  constexpr const char* kAiPersonalityGetIntelBuildingTycoonName = "GetIntelBuildingTycoon";
  constexpr const char* kAiPersonalityGetIntelBuildingTycoonHelpText = "CAiPersonality:GetIntelBuildingTycoon()";
  constexpr const char* kAiPersonalityGetSuperWeaponTendencyName = "GetSuperWeaponTendency";
  constexpr const char* kAiPersonalityGetSuperWeaponTendencyHelpText = "CAiPersonality:GetSuperWeaponTendency()";
  constexpr const char* kAiPersonalityGetFavouriteStructuresName = "GetFavouriteStructures";
  constexpr const char* kAiPersonalityGetFavouriteStructuresHelpText = "CAiPersonality:GetFavouriteStructures()";
  constexpr const char* kAiPersonalityGetAirUnitsEmphasisName = "GetAirUnitsEmphasis";
  constexpr const char* kAiPersonalityGetAirUnitsEmphasisHelpText = "CAiPersonality:GetAirUnitsEmphasis()";
  constexpr const char* kAiPersonalityGetTankUnitsEmphasisName = "GetTankUnitsEmphasis";
  constexpr const char* kAiPersonalityGetTankUnitsEmphasisHelpText = "CAiPersonality:GetTankUnitsEmphasis()";
  constexpr const char* kAiPersonalityGetBotUnitsEmphasisName = "GetBotUnitsEmphasis";
  constexpr const char* kAiPersonalityGetBotUnitsEmphasisHelpText = "CAiPersonality:GetBotUnitsEmphasis()";
  constexpr const char* kAiPersonalityGetSeaUnitsEmphasisName = "GetSeaUnitsEmphasis";
  constexpr const char* kAiPersonalityGetSeaUnitsEmphasisHelpText = "CAiPersonality:GetSeaUnitsEmphasis()";
  constexpr const char* kAiPersonalityGetSpecialtyForcesEmphasisName = "GetSpecialtyForcesEmphasis";
  constexpr const char* kAiPersonalityGetSpecialtyForcesEmphasisHelpText = "CAiPersonality:GetSpecialtyForcesEmphasis()";
  constexpr const char* kAiPersonalityGetSupportUnitsEmphasisName = "GetSupportUnitsEmphasis";
  constexpr const char* kAiPersonalityGetSupportUnitsEmphasisHelpText = "CAiPersonality:GetSupportUnitsEmphasis()";
  constexpr const char* kAiPersonalityGetDirectDamageEmphasisName = "GetDirectDamageEmphasis";
  constexpr const char* kAiPersonalityGetDirectDamageEmphasisHelpText = "CAiPersonality:GetDirectDamageEmphasis()";
  constexpr const char* kAiPersonalityGetInDirectDamageEmphasisName = "GetInDirectDamageEmphasis";
  constexpr const char* kAiPersonalityGetInDirectDamageEmphasisHelpText = "CAiPersonality:GetInDirectDamageEmphasis()";
  constexpr const char* kAiPersonalityGetFavouriteUnitsName = "GetFavouriteUnits";
  constexpr const char* kAiPersonalityGetFavouriteUnitsHelpText = "CAiPersonality:GetFavouriteUnits()";
  constexpr const char* kAiPersonalityGetSurvivalEmphasisName = "GetSurvivalEmphasis";
  constexpr const char* kAiPersonalityGetSurvivalEmphasisHelpText = "CAiPersonality:GetSurvivalEmphasis()";
  constexpr const char* kAiPersonalityGetTeamSupportName = "GetTeamSupport";
  constexpr const char* kAiPersonalityGetTeamSupportHelpText = "CAiPersonality:GetTeamSupport()";
  constexpr const char* kAiPersonalityGetFormationUseName = "GetFormationUse";
  constexpr const char* kAiPersonalityGetFormationUseHelpText = "CAiPersonality:GetFormationUse()";
  constexpr const char* kAiPersonalityGetTargetSpreadName = "GetTargetSpread";
  constexpr const char* kAiPersonalityGetTargetSpreadHelpText = "CAiPersonality:GetTargetSpread()";
  constexpr const char* kAiPersonalityGetQuittingTendencyName = "GetQuittingTendency";
  constexpr const char* kAiPersonalityGetQuittingTendencyHelpText = "CAiPersonality:GetQuittingTendency()";
  constexpr const char* kAiPersonalityGetChatFrequencyName = "GetChatFrequency";
  constexpr const char* kAiPersonalityGetChatFrequencyHelpText = "CAiPersonality:GetChatFrequency()";
  constexpr std::int32_t kTemplateFieldCount = 33;
  constexpr float kDefaultDifficulty = 0.5f;

  gpg::RType* gCScriptObjectType = nullptr;
  gpg::RType* gSimType = nullptr;
  gpg::RType* gAiPersonalityRangeType = nullptr;
  gpg::RType* gStringVectorType = nullptr;
  EngineStats* gRecoveredAiPersonalityStartupStatsSlot = nullptr;

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

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    if (!CScriptObject::sType) {
      CScriptObject::sType = CachedType<CScriptObject>(gCScriptObjectType);
    }
    return CScriptObject::sType;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!Sim::sType) {
      Sim::sType = CachedType<Sim>(gSimType);
    }
    return Sim::sType;
  }

  [[nodiscard]] gpg::RType* CachedPersonalityRangeType()
  {
    return CachedType<SAiPersonalityRange>(gAiPersonalityRangeType);
  }

  [[nodiscard]] gpg::RType* CachedStringVectorType()
  {
    return CachedType<msvc8::vector<msvc8::string>>(gStringVectorType);
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadPointerWithType(gpg::ReadArchive* const archive, const gpg::RRef& owner, gpg::RType* expectedType)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<TObject*>(upcast.mObj);
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
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
    const gpg::RRef& owner
  )
  {
    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, owner);
  }

  [[nodiscard]] const char* SafeCString(const char* value)
  {
    return value ? value : "";
  }

  /**
   * Address: 0x005B7220 (FUN_005B7220, func_LuaAiPersonality)
   * Address: 0x005B9600 (FUN_005B9600, func_CreateCAiPersonalityLuaObject)
   *
   * What it does:
   * Loads `/lua/aipersonality.lua` and returns `AIPersonality` metatable,
   * falling back to `CScrLuaMetatableFactory<CAiPersonality>::sInstance`.
   */
  [[nodiscard]] LuaPlus::LuaObject LoadAiPersonalityMetatable(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject metatable;

    LuaPlus::LuaObject moduleObj = SCR_ImportLuaModule(state, kAiPersonalityModulePath);
    if (!moduleObj.IsNil()) {
      metatable = SCR_GetLuaTableField(state, moduleObj, kAiPersonalityClassName);
    }

    if (metatable.IsNil()) {
      gpg::Logf("Can't find AIPersonality, using CAiPersonality directly");
      metatable = CScrLuaMetatableFactory<CAiPersonality>::Instance().Get(state);
    }
    return metatable;
  }

  [[nodiscard]] LuaPlus::LuaObject FindTemplateRow(const LuaPlus::LuaObject& templateTable, const char* rowName)
  {
    const std::int32_t rowCount = templateTable.GetN();
    for (std::int32_t rowIndex = 1; rowIndex <= rowCount; ++rowIndex) {
      LuaPlus::LuaObject row = templateTable.GetByIndex(rowIndex);
      if (!row.IsTable() || row.GetN() != kTemplateFieldCount) {
        continue;
      }

      LuaPlus::LuaObject rowNameValue = row.GetByIndex(1);
      if (gpg::STR_EqualsNoCase(SafeCString(rowNameValue.GetString()), rowName)) {
        return row;
      }
    }
    return {};
  }

  void LoadRangeField(const LuaPlus::LuaObject& row, const std::int32_t fieldIndex, SAiPersonalityRange& outRange)
  {
    LuaPlus::LuaObject rangeObj = row.GetByIndex(fieldIndex);
    if (!rangeObj.IsTable()) {
      outRange = {};
      return;
    }

    outRange.mMinValue = static_cast<float>(rangeObj.GetByIndex(1).GetNumber());
    outRange.mMaxValue = static_cast<float>(rangeObj.GetByIndex(2).GetNumber());
  }

  void LoadStringListField(
    const LuaPlus::LuaObject& row, const std::int32_t fieldIndex, msvc8::vector<msvc8::string>& outList
  )
  {
    outList.clear();

    LuaPlus::LuaObject listObj = row.GetByIndex(fieldIndex);
    const std::int32_t count = listObj.GetN();
    if (count <= 0) {
      return;
    }

    outList.reserve(static_cast<std::size_t>(count));
    for (std::int32_t i = 1; i <= count; ++i) {
      LuaPlus::LuaObject itemObj = listObj.GetByIndex(i);
      msvc8::string value;
      value.assign_owned(SafeCString(itemObj.GetString()));
      outList.push_back(value);
    }
  }

  /**
   * Address: 0x00BF7770 (FUN_00BF7770, cleanup_CAiPersonalityStartup)
   *
   * What it does:
   * Tears down one startup-owned AI personality stats slot.
   */
  void cleanup_CAiPersonalityStartup()
  {
    if (!gRecoveredAiPersonalityStartupStatsSlot) {
      return;
    }

    delete gRecoveredAiPersonalityStartupStatsSlot;
    gRecoveredAiPersonalityStartupStatsSlot = nullptr;
  }
} // namespace

gpg::RType* CAiPersonality::sType = nullptr;
CScrLuaMetatableFactory<CAiPersonality> CScrLuaMetatableFactory<CAiPersonality>::sInstance{};

/**
 * Address: 0x005BA9F0 (FUN_005BA9F0, cfunc_CAiPersonalityAdjustDelayL)
 *
 * What it does:
 * Reads one personality and two integer delay parameters, applies
 * difficulty-scaled adjustment, and returns one integer delay result.
 */
int moho::cfunc_CAiPersonalityAdjustDelayL(LuaPlus::LuaState* const state)
{
  const LuaPlus::LuaObject personalityObject(LuaPlus::LuaStackObject(state, 1));
  CAiPersonality* const personality = SCR_FromLua_CAiPersonality(personalityObject, state);

  const LuaPlus::LuaStackObject delayArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    delayArg.TypeError("integer");
  }
  const int delay = static_cast<int>(lua_tonumber(state->m_state, 2));

  const LuaPlus::LuaStackObject spreadArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    spreadArg.TypeError("integer");
  }
  const int spread = static_cast<int>(lua_tonumber(state->m_state, 3));

  const float scaledAdjustment = (1.0f - personality->mDifficulty) * static_cast<float>(delay * spread);
  const int adjustedDelay = delay + static_cast<int>(scaledAdjustment);
  lua_pushnumber(state->m_state, static_cast<float>(adjustedDelay));
  return 1;
}

/**
 * Address: 0x005BA970 (FUN_005BA970, cfunc_CAiPersonalityAdjustDelay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiPersonalityAdjustDelayL`.
 */
int moho::cfunc_CAiPersonalityAdjustDelay(lua_State* const luaContext)
{
  return cfunc_CAiPersonalityAdjustDelayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005BA990 (FUN_005BA990, func_CAiPersonalityAdjustDelay_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:AdjustDelay()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_CAiPersonalityAdjustDelay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityAdjustDelayName,
    &moho::cfunc_CAiPersonalityAdjustDelay,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityAdjustDelayHelpText
  );
  return &binder;
}

namespace
{
  [[nodiscard]] CAiPersonality* ResolveAiPersonalityLuaSelf(
    lua_State* const luaContext, const char* const helpText
  )
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    if (state == nullptr) {
      return nullptr;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, helpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject personalityObject(LuaPlus::LuaStackObject(state, 1));
    return SCR_FromLua_CAiPersonality(personalityObject, state);
  }

  [[nodiscard]] float ComputeDifficultyScaledRange(
    const CAiPersonality* const personality, const SAiPersonalityRange& range
  ) noexcept
  {
    return ((1.0f - personality->mDifficulty) * range.mMinValue)
         + (range.mMaxValue * personality->mDifficulty);
  }

  int PushStringVectorTable(LuaPlus::LuaState* const state, const msvc8::vector<msvc8::string>& values)
  {
    LuaPlus::LuaObject resultTable;
    resultTable.AssignNewTable(state, static_cast<int>(values.size()), 0);

    int luaIndex = 1;
    for (const msvc8::string& value : values) {
      resultTable.SetString(luaIndex++, value.c_str());
    }

    resultTable.PushStack(state);
    return 1;
  }

  template <SAiPersonalityRange CAiPersonality::*RangeMember>
  [[nodiscard]] int PushDifficultyScaledPersonalityRange(LuaPlus::LuaState* const state)
  {
    const LuaPlus::LuaObject personalityObject(LuaPlus::LuaStackObject(state, 1));
    CAiPersonality* const personality = SCR_FromLua_CAiPersonality(personalityObject, state);

    lua_State* const rawState = state->m_state;
    lua_pushnumber(rawState, ComputeDifficultyScaledRange(personality, personality->*RangeMember));
    (void)lua_gettop(rawState);
    return 1;
  }

  int LuaCallback_CAiPersonalityGetPersonalityName(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetPersonalityNameL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetChatPersonality(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetChatPersonalityL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetDifficulty(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetDifficultyL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetRepeatAttackFrequency(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetRepeatAttackFrequencyL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetCounterForces(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetCounterForcesL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetIntelGathering(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetIntelGatheringL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetCoordinatedAttacks(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetCoordinatedAttacksL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetExpansionDriven(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetExpansionDrivenL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetTechAdvancement(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetTechAdvancementL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetUpgradesDriven(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetUpgradesDrivenL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetDefenseDriven(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetDefenseDrivenL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetEconomyDriven(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetEconomyDrivenL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetFactoryTycoon(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetFactoryTycoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetIntelBuildingTycoon(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetIntelBuildingTycoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetSuperWeaponTendency(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetSuperWeaponTendencyL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetFavouriteStructures(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetFavouriteStructures(luaContext);
  }

  int LuaCallback_CAiPersonalityGetAirUnitsEmphasis(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetAirUnitsEmphasisL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetTankUnitsEmphasis(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetTankUnitsEmphasisL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetBotUnitsEmphasis(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetBotUnitsEmphasisL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetSeaUnitsEmphasis(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetSeaUnitsEmphasisL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetSpecialtyForcesEmphasis(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetSpecialtyForcesEmphasisL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetSupportUnitsEmphasis(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetSupportUnitsEmphasisL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetDirectDamageEmphasis(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetDirectDamageEmphasisL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetInDirectDamageEmphasis(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetInDirectDamageEmphasisL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetFavouriteUnits(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetFavouriteUnits(luaContext);
  }

  int LuaCallback_CAiPersonalityGetSurvivalEmphasis(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetSurvivalEmphasisL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetTeamSupport(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetTeamSupportL(moho::SCR_ResolveBindingState(luaContext));
  }

  int LuaCallback_CAiPersonalityGetFormationUse(lua_State* const luaContext)
  {
    return moho::cfunc_CAiPersonalityGetFormationUseL(moho::SCR_ResolveBindingState(luaContext));
  }

} // namespace

/**
 * Address: 0x005BA690 (FUN_005BA690, cfunc_CAiPersonalityGetPersonalityNameL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the personality-name string.
 */
int moho::cfunc_CAiPersonalityGetPersonalityNameL(LuaPlus::LuaState* const state)
{
  const LuaPlus::LuaObject personalityObject(LuaPlus::LuaStackObject(state, 1));
  CAiPersonality* const personality = SCR_FromLua_CAiPersonality(personalityObject, state);

  lua_State* const rawState = state->m_state;
  lua_pushstring(rawState, personality->mPersonalityName.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005BA7B0 (FUN_005BA7B0, cfunc_CAiPersonalityGetChatPersonalityL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the chat-personality string.
 */
int moho::cfunc_CAiPersonalityGetChatPersonalityL(LuaPlus::LuaState* const state)
{
  const LuaPlus::LuaObject personalityObject(LuaPlus::LuaStackObject(state, 1));
  CAiPersonality* const personality = SCR_FromLua_CAiPersonality(personalityObject, state);

  lua_State* const rawState = state->m_state;
  lua_pushstring(rawState, personality->mChatPersonality.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005BA8D0 (FUN_005BA8D0, cfunc_CAiPersonalityGetDifficultyL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the current difficulty value.
 */
int moho::cfunc_CAiPersonalityGetDifficultyL(LuaPlus::LuaState* const state)
{
  const LuaPlus::LuaObject personalityObject(LuaPlus::LuaStackObject(state, 1));
  CAiPersonality* const personality = SCR_FromLua_CAiPersonality(personalityObject, state);

  lua_State* const rawState = state->m_state;
  lua_pushnumber(rawState, personality->mDifficulty);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005BABC0 (FUN_005BABC0, cfunc_CAiPersonalityGetArmySizeL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * army-size value.
 */
int moho::cfunc_CAiPersonalityGetArmySizeL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mArmySize>(state);
}

/**
 * Address: 0x005BAD00 (FUN_005BAD00, cfunc_CAiPersonalityGetPlatoonSizeL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * platoon-size value.
 */
int moho::cfunc_CAiPersonalityGetPlatoonSizeL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mPlatoonSize>(state);
}

/**
 * Address: 0x005BAE40 (FUN_005BAE40, cfunc_CAiPersonalityGetAttackFrequencyL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * attack-frequency value.
 */
int moho::cfunc_CAiPersonalityGetAttackFrequencyL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mAttackFrequency>(state);
}

/**
 * Address: 0x005BAB40 (FUN_005BAB40, cfunc_CAiPersonalityGetArmySize)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiPersonalityGetArmySizeL`.
 */
int moho::cfunc_CAiPersonalityGetArmySize(lua_State* const luaContext)
{
  return cfunc_CAiPersonalityGetArmySizeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005BAC80 (FUN_005BAC80, cfunc_CAiPersonalityGetPlatoonSize)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiPersonalityGetPlatoonSizeL`.
 */
int moho::cfunc_CAiPersonalityGetPlatoonSize(lua_State* const luaContext)
{
  return cfunc_CAiPersonalityGetPlatoonSizeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005BADC0 (FUN_005BADC0, cfunc_CAiPersonalityGetAttackFrequency)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiPersonalityGetAttackFrequencyL`.
 */
int moho::cfunc_CAiPersonalityGetAttackFrequency(lua_State* const luaContext)
{
  return cfunc_CAiPersonalityGetAttackFrequencyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005BAF80 (FUN_005BAF80, cfunc_CAiPersonalityGetRepeatAttackFrequencyL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * repeat-attack frequency.
 */
int moho::cfunc_CAiPersonalityGetRepeatAttackFrequencyL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mRepeatAttackFrequency>(state);
}

/**
 * Address: 0x005BB0C0 (FUN_005BB0C0, cfunc_CAiPersonalityGetCounterForcesL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * counter-forces value.
 */
int moho::cfunc_CAiPersonalityGetCounterForcesL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mCounterForces>(state);
}

/**
 * Address: 0x005BB200 (FUN_005BB200, cfunc_CAiPersonalityGetIntelGatheringL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * intel-gathering value.
 */
int moho::cfunc_CAiPersonalityGetIntelGatheringL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mIntelGathering>(state);
}

/**
 * Address: 0x005BB340 (FUN_005BB340, cfunc_CAiPersonalityGetCoordinatedAttacksL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * coordinated-attacks value.
 */
int moho::cfunc_CAiPersonalityGetCoordinatedAttacksL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mCoordinatedAttacks>(state);
}

/**
 * Address: 0x005BB480 (FUN_005BB480, cfunc_CAiPersonalityGetExpansionDrivenL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * expansion-driven value.
 */
int moho::cfunc_CAiPersonalityGetExpansionDrivenL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mExpansionDriven>(state);
}

/**
 * Address: 0x005BB5C0 (FUN_005BB5C0, cfunc_CAiPersonalityGetTechAdvancementL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * tech-advancement value.
 */
int moho::cfunc_CAiPersonalityGetTechAdvancementL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mTechAdvancement>(state);
}

/**
 * Address: 0x005BB700 (FUN_005BB700, cfunc_CAiPersonalityGetUpgradesDrivenL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * upgrades-driven value.
 */
int moho::cfunc_CAiPersonalityGetUpgradesDrivenL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mUpgradesDriven>(state);
}

/**
 * Address: 0x005BB840 (FUN_005BB840, cfunc_CAiPersonalityGetDefenseDrivenL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * defense-driven value.
 */
int moho::cfunc_CAiPersonalityGetDefenseDrivenL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mDefenseDriven>(state);
}

/**
 * Address: 0x005BB980 (FUN_005BB980, cfunc_CAiPersonalityGetEconomyDrivenL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * economy-driven value.
 */
int moho::cfunc_CAiPersonalityGetEconomyDrivenL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mEconomyDriven>(state);
}

/**
 * Address: 0x005BBAC0 (FUN_005BBAC0, cfunc_CAiPersonalityGetFactoryTycoonL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * factory-tycoon value.
 */
int moho::cfunc_CAiPersonalityGetFactoryTycoonL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mFactoryTycoon>(state);
}

/**
 * Address: 0x005BBC00 (FUN_005BBC00, cfunc_CAiPersonalityGetIntelBuildingTycoonL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * intel-building-tycoon value.
 */
int moho::cfunc_CAiPersonalityGetIntelBuildingTycoonL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mIntelBuildingTycoon>(state);
}

/**
 * Address: 0x005BBD40 (FUN_005BBD40, cfunc_CAiPersonalityGetSuperWeaponTendencyL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * super-weapon-tendency value.
 */
int moho::cfunc_CAiPersonalityGetSuperWeaponTendencyL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mSuperWeaponTendency>(state);
}

/**
 * Address: 0x005BC050 (FUN_005BC050, cfunc_CAiPersonalityGetAirUnitsEmphasisL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * air-units-emphasis value.
 */
int moho::cfunc_CAiPersonalityGetAirUnitsEmphasisL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mAirUnitsEmphasis>(state);
}

/**
 * Address: 0x005BC190 (FUN_005BC190, cfunc_CAiPersonalityGetTankUnitsEmphasisL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * tank-units-emphasis value.
 */
int moho::cfunc_CAiPersonalityGetTankUnitsEmphasisL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mTankUnitsEmphasis>(state);
}

/**
 * Address: 0x005BC2D0 (FUN_005BC2D0, cfunc_CAiPersonalityGetBotUnitsEmphasisL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * bot-units-emphasis value.
 */
int moho::cfunc_CAiPersonalityGetBotUnitsEmphasisL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mBotUnitsEmphasis>(state);
}

/**
 * Address: 0x005BC410 (FUN_005BC410, cfunc_CAiPersonalityGetSeaUnitsEmphasisL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted sea
 * units emphasis value.
 */
int moho::cfunc_CAiPersonalityGetSeaUnitsEmphasisL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mSeaUnitsEmphasis>(state);
}

/**
 * Address: 0x005BC550 (FUN_005BC550, cfunc_CAiPersonalityGetSpecialtyForcesEmphasisL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * specialty-forces emphasis value.
 */
int moho::cfunc_CAiPersonalityGetSpecialtyForcesEmphasisL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mSpecialtyForcesEmphasis>(state);
}

/**
 * Address: 0x005BC690 (FUN_005BC690, cfunc_CAiPersonalityGetSupportUnitsEmphasisL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * support-units emphasis value.
 */
int moho::cfunc_CAiPersonalityGetSupportUnitsEmphasisL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mSupportUnitsEmphasis>(state);
}

/**
 * Address: 0x005BC7D0 (FUN_005BC7D0, cfunc_CAiPersonalityGetDirectDamageEmphasisL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * direct-damage-emphasis value.
 */
int moho::cfunc_CAiPersonalityGetDirectDamageEmphasisL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mDirectDamageEmphasis>(state);
}

/**
 * Address: 0x005BC910 (FUN_005BC910, cfunc_CAiPersonalityGetInDirectDamageEmphasisL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * indirect-damage-emphasis value.
 */
int moho::cfunc_CAiPersonalityGetInDirectDamageEmphasisL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mIndirectDamageEmphasis>(state);
}

/**
 * Address: 0x005BCC20 (FUN_005BCC20, cfunc_CAiPersonalityGetSurvivalEmphasisL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * survival-emphasis value.
 */
int moho::cfunc_CAiPersonalityGetSurvivalEmphasisL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mSurvivalEmphasis>(state);
}

/**
 * Address: 0x005BCD60 (FUN_005BCD60, cfunc_CAiPersonalityGetTeamSupportL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * team-support value.
 */
int moho::cfunc_CAiPersonalityGetTeamSupportL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mTeamSupport>(state);
}

/**
 * Address: 0x005BCEA0 (FUN_005BCEA0, cfunc_CAiPersonalityGetFormationUseL)
 *
 * What it does:
 * Reads one `CAiPersonality` from Lua and pushes the difficulty-weighted
 * formation-use value.
 */
int moho::cfunc_CAiPersonalityGetFormationUseL(LuaPlus::LuaState* const state)
{
  return PushDifficultyScaledPersonalityRange<&CAiPersonality::mFormationUse>(state);
}

/**
 * Address: 0x005BA630 (FUN_005BA630, func_CAiPersonalityGetPersonalityName_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetPersonalityName()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetPersonalityName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetPersonalityNameName,
    &LuaCallback_CAiPersonalityGetPersonalityName,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetPersonalityNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BA750 (FUN_005BA750, func_CAiPersonalityGetChatPersonality_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetChatPersonality()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetChatPersonality_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetChatPersonalityName,
    &LuaCallback_CAiPersonalityGetChatPersonality,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetChatPersonalityHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BA870 (FUN_005BA870, func_CAiPersonalityGetDifficulty_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetDifficulty()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetDifficulty_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetDifficultyName,
    &LuaCallback_CAiPersonalityGetDifficulty,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetDifficultyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BAB60 (FUN_005BAB60, func_CAiPersonalityGetArmySize_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetArmySize()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetArmySize_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetArmySizeName,
    &moho::cfunc_CAiPersonalityGetArmySize,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetArmySizeHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BACA0 (FUN_005BACA0, func_CAiPersonalityGetPlatoonSize_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetPlatoonSize()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetPlatoonSize_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetPlatoonSizeName,
    &moho::cfunc_CAiPersonalityGetPlatoonSize,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetPlatoonSizeHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BADE0 (FUN_005BADE0, func_CAiPersonalityGetAttackFrequency_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetAttackFrequency()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetAttackFrequency_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetAttackFrequencyName,
    &moho::cfunc_CAiPersonalityGetAttackFrequency,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetAttackFrequencyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BAF20 (FUN_005BAF20, func_CAiPersonalityGetRepeatAttackFrequency_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetRepeatAttackFrequency()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetRepeatAttackFrequency_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetRepeatAttackFrequencyName,
    &LuaCallback_CAiPersonalityGetRepeatAttackFrequency,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetRepeatAttackFrequencyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BB060 (FUN_005BB060, func_CAiPersonalityGetCounterForces_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetCounterForces()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetCounterForces_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetCounterForcesName,
    &LuaCallback_CAiPersonalityGetCounterForces,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetCounterForcesHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BB1A0 (FUN_005BB1A0, func_CAiPersonalityGetIntelGathering_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetIntelGathering()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetIntelGathering_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetIntelGatheringName,
    &LuaCallback_CAiPersonalityGetIntelGathering,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetIntelGatheringHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BB2E0 (FUN_005BB2E0, func_CAiPersonalityGetCoordinatedAttacks_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetCoordinatedAttacks()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetCoordinatedAttacks_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetCoordinatedAttacksName,
    &LuaCallback_CAiPersonalityGetCoordinatedAttacks,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetCoordinatedAttacksHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BB420 (FUN_005BB420, func_CAiPersonalityGetExpansionDriven_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetExpansionDriven()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetExpansionDriven_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetExpansionDrivenName,
    &LuaCallback_CAiPersonalityGetExpansionDriven,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetExpansionDrivenHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BB560 (FUN_005BB560, func_CAiPersonalityGetTechAdvancement_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetTechAdvancement()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetTechAdvancement_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetTechAdvancementName,
    &LuaCallback_CAiPersonalityGetTechAdvancement,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetTechAdvancementHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BB6A0 (FUN_005BB6A0, func_CAiPersonalityGetUpgradesDriven_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetUpgradesDriven()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetUpgradesDriven_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetUpgradesDrivenName,
    &LuaCallback_CAiPersonalityGetUpgradesDriven,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetUpgradesDrivenHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BB7E0 (FUN_005BB7E0, func_CAiPersonalityGetDefenseDriven_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetDefenseDriven()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetDefenseDriven_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetDefenseDrivenName,
    &LuaCallback_CAiPersonalityGetDefenseDriven,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetDefenseDrivenHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BB920 (FUN_005BB920, func_CAiPersonalityGetEconomyDriven_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetEconomyDriven()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetEconomyDriven_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetEconomyDrivenName,
    &LuaCallback_CAiPersonalityGetEconomyDriven,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetEconomyDrivenHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BBA60 (FUN_005BBA60, func_CAiPersonalityGetFactoryTycoon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetFactoryTycoon()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetFactoryTycoon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetFactoryTycoonName,
    &LuaCallback_CAiPersonalityGetFactoryTycoon,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetFactoryTycoonHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BBBA0 (FUN_005BBBA0, func_CAiPersonalityGetIntelBuildingTycoon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetIntelBuildingTycoon()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetIntelBuildingTycoon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetIntelBuildingTycoonName,
    &LuaCallback_CAiPersonalityGetIntelBuildingTycoon,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetIntelBuildingTycoonHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BBCE0 (FUN_005BBCE0, func_CAiPersonalityGetSuperWeaponTendency_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetSuperWeaponTendency()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetSuperWeaponTendency_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetSuperWeaponTendencyName,
    &LuaCallback_CAiPersonalityGetSuperWeaponTendency,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetSuperWeaponTendencyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BBE20 (FUN_005BBE20, func_CAiPersonalityGetFavouriteStructures_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetFavouriteStructures()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetFavouriteStructures_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetFavouriteStructuresName,
    &moho::cfunc_CAiPersonalityGetFavouriteStructures,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetFavouriteStructuresHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BBFF0 (FUN_005BBFF0, func_CAiPersonalityGetAirUnitsEmphasis_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetAirUnitsEmphasis()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetAirUnitsEmphasis_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetAirUnitsEmphasisName,
    &LuaCallback_CAiPersonalityGetAirUnitsEmphasis,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetAirUnitsEmphasisHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BC130 (FUN_005BC130, func_CAiPersonalityGetTankUnitsEmphasis_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetTankUnitsEmphasis()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetTankUnitsEmphasis_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetTankUnitsEmphasisName,
    &LuaCallback_CAiPersonalityGetTankUnitsEmphasis,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetTankUnitsEmphasisHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BC270 (FUN_005BC270, func_CAiPersonalityGetBotUnitsEmphasis_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetBotUnitsEmphasis()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetBotUnitsEmphasis_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetBotUnitsEmphasisName,
    &LuaCallback_CAiPersonalityGetBotUnitsEmphasis,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetBotUnitsEmphasisHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BC3B0 (FUN_005BC3B0, func_CAiPersonalityGetSeaUnitsEmphasis_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetSeaUnitsEmphasis()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetSeaUnitsEmphasis_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetSeaUnitsEmphasisName,
    &LuaCallback_CAiPersonalityGetSeaUnitsEmphasis,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetSeaUnitsEmphasisHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BC4F0 (FUN_005BC4F0, func_CAiPersonalityGetSpecialtyForcesEmphasis_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetSpecialtyForcesEmphasis()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetSpecialtyForcesEmphasis_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetSpecialtyForcesEmphasisName,
    &LuaCallback_CAiPersonalityGetSpecialtyForcesEmphasis,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetSpecialtyForcesEmphasisHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BC630 (FUN_005BC630, func_CAiPersonalityGetSupportUnitsEmphasis_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetSupportUnitsEmphasis()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetSupportUnitsEmphasis_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetSupportUnitsEmphasisName,
    &LuaCallback_CAiPersonalityGetSupportUnitsEmphasis,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetSupportUnitsEmphasisHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BC770 (FUN_005BC770, func_CAiPersonalityGetDirectDamageEmphasis_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetDirectDamageEmphasis()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetDirectDamageEmphasis_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetDirectDamageEmphasisName,
    &LuaCallback_CAiPersonalityGetDirectDamageEmphasis,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetDirectDamageEmphasisHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BC8B0 (FUN_005BC8B0, func_CAiPersonalityGetInDirectDamageEmphasis_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetInDirectDamageEmphasis()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetInDirectDamageEmphasis_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetInDirectDamageEmphasisName,
    &LuaCallback_CAiPersonalityGetInDirectDamageEmphasis,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetInDirectDamageEmphasisHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BC9F0 (FUN_005BC9F0, func_CAiPersonalityGetFavouriteUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetFavouriteUnits()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetFavouriteUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetFavouriteUnitsName,
    &moho::cfunc_CAiPersonalityGetFavouriteUnits,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetFavouriteUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BCBC0 (FUN_005BCBC0, func_CAiPersonalityGetSurvivalEmphasis_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetSurvivalEmphasis()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetSurvivalEmphasis_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetSurvivalEmphasisName,
    &LuaCallback_CAiPersonalityGetSurvivalEmphasis,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetSurvivalEmphasisHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BCD00 (FUN_005BCD00, func_CAiPersonalityGetTeamSupport_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetTeamSupport()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetTeamSupport_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetTeamSupportName,
    &LuaCallback_CAiPersonalityGetTeamSupport,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetTeamSupportHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BCE40 (FUN_005BCE40, func_CAiPersonalityGetFormationUse_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetFormationUse()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetFormationUse_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetFormationUseName,
    &LuaCallback_CAiPersonalityGetFormationUse,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetFormationUseHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BBE80 (FUN_005BBE80, cfunc_CAiPersonalityGetFavouriteStructuresL)
 *
 * What it does:
 * Reads one `CAiPersonality` and pushes `mFavouriteStructures` as Lua array
 * elements.
 */
int moho::cfunc_CAiPersonalityGetFavouriteStructuresL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  CAiPersonality* const personality =
    ResolveAiPersonalityLuaSelf(state->m_state, kAiPersonalityGetFavouriteStructuresHelpText);
  if (personality == nullptr) {
    return 0;
  }

  return PushStringVectorTable(state, personality->mFavouriteStructures);
}

/**
 * Address: 0x005BBE00 (FUN_005BBE00, cfunc_CAiPersonalityGetFavouriteStructures)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiPersonalityGetFavouriteStructuresL`.
 */
int moho::cfunc_CAiPersonalityGetFavouriteStructures(lua_State* const luaContext)
{
  return cfunc_CAiPersonalityGetFavouriteStructuresL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005BCA50 (FUN_005BCA50, cfunc_CAiPersonalityGetFavouriteUnitsL)
 *
 * What it does:
 * Reads one `CAiPersonality` and pushes `mFavouriteUnits` as Lua array
 * elements.
 */
int moho::cfunc_CAiPersonalityGetFavouriteUnitsL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  CAiPersonality* const personality = ResolveAiPersonalityLuaSelf(state->m_state, kAiPersonalityGetFavouriteUnitsHelpText);
  if (personality == nullptr) {
    return 0;
  }

  return PushStringVectorTable(state, personality->mFavouriteUnits);
}

/**
 * Address: 0x005BC9D0 (FUN_005BC9D0, cfunc_CAiPersonalityGetFavouriteUnits)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiPersonalityGetFavouriteUnitsL`.
 */
int moho::cfunc_CAiPersonalityGetFavouriteUnits(lua_State* const luaContext)
{
  return cfunc_CAiPersonalityGetFavouriteUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005BCFE0 (FUN_005BCFE0, cfunc_CAiPersonalityGetTargetSpreadL)
 *
 * What it does:
 * Reads one `CAiPersonality` and pushes difficulty-scaled target spread.
 */
int moho::cfunc_CAiPersonalityGetTargetSpreadL(LuaPlus::LuaState* const state)
{
  const LuaPlus::LuaObject personalityObject(LuaPlus::LuaStackObject(state, 1));
  CAiPersonality* const personality = SCR_FromLua_CAiPersonality(personalityObject, state);

  lua_State* const rawState = state->m_state;
  lua_pushnumber(rawState, ComputeDifficultyScaledRange(personality, personality->mTargetSpread));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005BCF60 (FUN_005BCF60, cfunc_CAiPersonalityGetTargetSpread)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiPersonalityGetTargetSpreadL`.
 */
int moho::cfunc_CAiPersonalityGetTargetSpread(lua_State* const luaContext)
{
  return cfunc_CAiPersonalityGetTargetSpreadL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005BCF80 (FUN_005BCF80, func_CAiPersonalityGetTargetSpread_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetTargetSpread()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetTargetSpread_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetTargetSpreadName,
    &moho::cfunc_CAiPersonalityGetTargetSpread,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetTargetSpreadHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BD120 (FUN_005BD120, cfunc_CAiPersonalityGetQuittingTendencyL)
 *
 * What it does:
 * Reads one `CAiPersonality` and pushes difficulty-scaled quitting tendency.
 */
int moho::cfunc_CAiPersonalityGetQuittingTendencyL(LuaPlus::LuaState* const state)
{
  const LuaPlus::LuaObject personalityObject(LuaPlus::LuaStackObject(state, 1));
  CAiPersonality* const personality = SCR_FromLua_CAiPersonality(personalityObject, state);

  lua_State* const rawState = state->m_state;
  lua_pushnumber(rawState, ComputeDifficultyScaledRange(personality, personality->mQuittingTendency));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005BD0A0 (FUN_005BD0A0, cfunc_CAiPersonalityGetQuittingTendency)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiPersonalityGetQuittingTendencyL`.
 */
int moho::cfunc_CAiPersonalityGetQuittingTendency(lua_State* const luaContext)
{
  return cfunc_CAiPersonalityGetQuittingTendencyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005BD0C0 (FUN_005BD0C0, func_CAiPersonalityGetQuittingTendency_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetQuittingTendency()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetQuittingTendency_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetQuittingTendencyName,
    &moho::cfunc_CAiPersonalityGetQuittingTendency,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetQuittingTendencyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005BD260 (FUN_005BD260, cfunc_CAiPersonalityGetChatFrequencyL)
 *
 * What it does:
 * Reads one `CAiPersonality` and pushes difficulty-scaled chat frequency.
 */
int moho::cfunc_CAiPersonalityGetChatFrequencyL(LuaPlus::LuaState* const state)
{
  const LuaPlus::LuaObject personalityObject(LuaPlus::LuaStackObject(state, 1));
  CAiPersonality* const personality = SCR_FromLua_CAiPersonality(personalityObject, state);

  lua_State* const rawState = state->m_state;
  lua_pushnumber(rawState, ComputeDifficultyScaledRange(personality, personality->mChatFrequency));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005BD1E0 (FUN_005BD1E0, cfunc_CAiPersonalityGetChatFrequency)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiPersonalityGetChatFrequencyL`.
 */
int moho::cfunc_CAiPersonalityGetChatFrequency(lua_State* const luaContext)
{
  return cfunc_CAiPersonalityGetChatFrequencyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005BD200 (FUN_005BD200, func_CAiPersonalityGetChatFrequency_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiPersonality:GetChatFrequency()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiPersonalityGetChatFrequency_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiPersonalityGetChatFrequencyName,
    &moho::cfunc_CAiPersonalityGetChatFrequency,
    &CScrLuaMetatableFactory<CAiPersonality>::Instance(),
    kAiPersonalityLuaClassName,
    kAiPersonalityGetChatFrequencyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005B93F0 (FUN_005B93F0, Moho::InstanceCounter<Moho::CAiPersonality>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for CAiPersonality
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CAiPersonality>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CAiPersonality).name());
  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x00BCD6A0 (FUN_00BCD6A0)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * `CAiPersonality`.
 */
int moho::register_CScrLuaMetatableFactory_CAiPersonality_Index()
{
  const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
  CScrLuaMetatableFactory<CAiPersonality>::Instance().SetFactoryObjectIndexForRecovery(index);
  return index;
}

/**
 * Address: 0x00BCD6C0 (FUN_00BCD6C0)
 *
 * What it does:
 * Installs process-exit cleanup for one startup-owned AI reflection slot.
 */
int moho::register_CAiPersonalityStartupCleanup()
{
  return std::atexit(&cleanup_CAiPersonalityStartup);
}

CScrLuaMetatableFactory<CAiPersonality>& CScrLuaMetatableFactory<CAiPersonality>::Instance()
{
  return sInstance;
}

namespace
{
  struct CAiPersonalityStartupBootstrap
  {
    CAiPersonalityStartupBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_CAiPersonality_Index();
      (void)moho::register_CAiPersonalityStartupCleanup();
    }
  };

  [[maybe_unused]] CAiPersonalityStartupBootstrap gCAiPersonalityStartupBootstrap;
} // namespace

/**
 * Address: 0x005B9620 (FUN_005B9620, ?Create@?$CScrLuaMetatableFactory@VCAiPersonality@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
 */
LuaPlus::LuaObject CScrLuaMetatableFactory<CAiPersonality>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x005B6DC0 (FUN_005B6DC0, ctor body)
 */
CAiPersonality::CAiPersonality(Sim* const sim)
  : mSim(sim)
  , mPersonalityName()
  , mChatPersonality()
  , mArmySize{}
  , mPlatoonSize{}
  , mAttackFrequency{}
  , mRepeatAttackFrequency{}
  , mCounterForces{}
  , mIntelGathering{}
  , mCoordinatedAttacks{}
  , mExpansionDriven{}
  , mTechAdvancement{}
  , mUpgradesDriven{}
  , mDefenseDriven{}
  , mEconomyDriven{}
  , mFactoryTycoon{}
  , mIntelBuildingTycoon{}
  , mSuperWeaponTendency{}
  , mFavouriteStructures()
  , mAirUnitsEmphasis{}
  , mTankUnitsEmphasis{}
  , mBotUnitsEmphasis{}
  , mSeaUnitsEmphasis{}
  , mSpecialtyForcesEmphasis{}
  , mSupportUnitsEmphasis{}
  , mDirectDamageEmphasis{}
  , mIndirectDamageEmphasis{}
  , mFavouriteUnits()
  , mSurvivalEmphasis{}
  , mTeamSupport{}
  , mFormationUse{}
  , mTargetSpread{}
  , mQuittingTendency{}
  , mChatFrequency{}
  , mDifficulty(kDefaultDifficulty)
{
  if (mSim && mSim->mLuaState) {
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject metatable = LoadAiPersonalityMetatable(mSim->mLuaState);
    CreateLuaObject(metatable, arg1, arg2, arg3);
  }

  mPersonalityName.assign_owned("None");
  mChatPersonality.assign_owned("None");
}

/**
 * Address: 0x005B6DA0 (FUN_005B6DA0, scalar deleting thunk)
 * Address: 0x005B7120 (FUN_005B7120, core dtor)
 */
CAiPersonality::~CAiPersonality() = default;

/**
 * Address: 0x005B65A0 (FUN_005B65A0, ?GetClass@CAiPersonality@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CAiPersonality::GetClass() const
{
  gpg::RType* type = sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiPersonality));
    sType = type;
  }
  return type;
}

/**
 * Address: 0x005B65C0 (FUN_005B65C0, ?GetDerivedObjectRef@CAiPersonality@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CAiPersonality::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

/**
 * Address: 0x005B7340 (FUN_005B7340, Moho::CAiPersonality::ReadData)
 */
void CAiPersonality::ReadData()
{
  if (!mSim || !mSim->mLuaState) {
    return;
  }

  LuaPlus::LuaObject moduleObj = SCR_ImportLuaModule(mSim->mLuaState, kAiPersonalityModulePath);
  LuaPlus::LuaObject templateTable = SCR_GetLuaTableField(mSim->mLuaState, moduleObj, kAiPersonalityTemplateName);
  if (templateTable.IsNil()) {
    gpg::Logf("Can't find AIPersonalityTemplate");
    return;
  }

  LuaPlus::LuaObject personalityTemplateRow = FindTemplateRow(templateTable, kDefaultPersonalityName);
  if (personalityTemplateRow.IsNil()) {
    gpg::Logf("Can't find the template for personality %s", kDefaultPersonalityName);
    return;
  }

  mPersonalityName.assign_owned(SafeCString(personalityTemplateRow.GetByIndex(1).GetString()));
  mChatPersonality.assign_owned(SafeCString(personalityTemplateRow.GetByIndex(2).GetString()));

  LoadRangeField(personalityTemplateRow, 3, mArmySize);
  LoadRangeField(personalityTemplateRow, 4, mPlatoonSize);
  LoadRangeField(personalityTemplateRow, 5, mAttackFrequency);
  LoadRangeField(personalityTemplateRow, 6, mRepeatAttackFrequency);
  LoadRangeField(personalityTemplateRow, 7, mCounterForces);
  LoadRangeField(personalityTemplateRow, 8, mIntelGathering);
  LoadRangeField(personalityTemplateRow, 9, mCoordinatedAttacks);
  LoadRangeField(personalityTemplateRow, 10, mExpansionDriven);
  LoadRangeField(personalityTemplateRow, 11, mTechAdvancement);
  LoadRangeField(personalityTemplateRow, 12, mUpgradesDriven);
  LoadRangeField(personalityTemplateRow, 13, mDefenseDriven);
  LoadRangeField(personalityTemplateRow, 14, mEconomyDriven);
  LoadRangeField(personalityTemplateRow, 15, mFactoryTycoon);
  LoadRangeField(personalityTemplateRow, 16, mIntelBuildingTycoon);
  LoadRangeField(personalityTemplateRow, 17, mSuperWeaponTendency);
  LoadStringListField(personalityTemplateRow, 18, mFavouriteStructures);
  LoadRangeField(personalityTemplateRow, 19, mAirUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 20, mTankUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 21, mBotUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 22, mSeaUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 23, mSpecialtyForcesEmphasis);
  LoadRangeField(personalityTemplateRow, 24, mSupportUnitsEmphasis);
  LoadRangeField(personalityTemplateRow, 25, mDirectDamageEmphasis);
  LoadRangeField(personalityTemplateRow, 26, mIndirectDamageEmphasis);
  LoadStringListField(personalityTemplateRow, 27, mFavouriteUnits);
  LoadRangeField(personalityTemplateRow, 28, mSurvivalEmphasis);
  LoadRangeField(personalityTemplateRow, 29, mTeamSupport);
  LoadRangeField(personalityTemplateRow, 30, mFormationUse);
  LoadRangeField(personalityTemplateRow, 31, mTargetSpread);
  LoadRangeField(personalityTemplateRow, 32, mQuittingTendency);
  LoadRangeField(personalityTemplateRow, 33, mChatFrequency);
}

/**
 * Address: 0x005B96A0 (FUN_005B96A0, Moho::CAiPersonality::MemberDeserialize)
 */
void CAiPersonality::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  archive->Read(CachedCScriptObjectType(), this, owner);
  mSim = ReadPointerWithType<Sim>(archive, owner, CachedSimType());
  archive->ReadString(&mPersonalityName);
  archive->ReadString(&mChatPersonality);

  gpg::RType* const rangeType = CachedPersonalityRangeType();
  GPG_ASSERT(rangeType != nullptr);
  gpg::RType* const stringVectorType = CachedStringVectorType();
  GPG_ASSERT(stringVectorType != nullptr);

  archive->Read(rangeType, &mArmySize, owner);
  archive->Read(rangeType, &mPlatoonSize, owner);
  archive->Read(rangeType, &mAttackFrequency, owner);
  archive->Read(rangeType, &mRepeatAttackFrequency, owner);
  archive->Read(rangeType, &mCounterForces, owner);
  archive->Read(rangeType, &mIntelGathering, owner);
  archive->Read(rangeType, &mCoordinatedAttacks, owner);
  archive->Read(rangeType, &mExpansionDriven, owner);
  archive->Read(rangeType, &mTechAdvancement, owner);
  archive->Read(rangeType, &mUpgradesDriven, owner);
  archive->Read(rangeType, &mDefenseDriven, owner);
  archive->Read(rangeType, &mEconomyDriven, owner);
  archive->Read(rangeType, &mFactoryTycoon, owner);
  archive->Read(rangeType, &mIntelBuildingTycoon, owner);
  archive->Read(rangeType, &mSuperWeaponTendency, owner);
  archive->Read(stringVectorType, &mFavouriteStructures, owner);
  archive->Read(rangeType, &mAirUnitsEmphasis, owner);
  archive->Read(rangeType, &mTankUnitsEmphasis, owner);
  archive->Read(rangeType, &mBotUnitsEmphasis, owner);
  archive->Read(rangeType, &mSeaUnitsEmphasis, owner);
  archive->Read(rangeType, &mSpecialtyForcesEmphasis, owner);
  archive->Read(rangeType, &mSupportUnitsEmphasis, owner);
  archive->Read(rangeType, &mDirectDamageEmphasis, owner);
  archive->Read(rangeType, &mIndirectDamageEmphasis, owner);
  archive->Read(stringVectorType, &mFavouriteUnits, owner);
  archive->Read(rangeType, &mSurvivalEmphasis, owner);
  archive->Read(rangeType, &mTeamSupport, owner);
  archive->Read(rangeType, &mFormationUse, owner);
  archive->Read(rangeType, &mTargetSpread, owner);
  archive->Read(rangeType, &mQuittingTendency, owner);
  archive->Read(rangeType, &mChatFrequency, owner);
  archive->ReadFloat(&mDifficulty);
}

/**
 * Address: 0x005B9DD0 (FUN_005B9DD0, Moho::CAiPersonality::MemberSerialize)
 */
void CAiPersonality::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  archive->Write(CachedCScriptObjectType(), const_cast<CAiPersonality*>(this), owner);
  WritePointerWithType(archive, mSim, CachedSimType(), gpg::TrackedPointerState::Unowned, owner);
  archive->WriteString(const_cast<msvc8::string*>(&mPersonalityName));
  archive->WriteString(const_cast<msvc8::string*>(&mChatPersonality));

  gpg::RType* const rangeType = CachedPersonalityRangeType();
  GPG_ASSERT(rangeType != nullptr);
  gpg::RType* const stringVectorType = CachedStringVectorType();
  GPG_ASSERT(stringVectorType != nullptr);

  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mArmySize), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mPlatoonSize), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mAttackFrequency), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mRepeatAttackFrequency), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mCounterForces), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mIntelGathering), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mCoordinatedAttacks), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mExpansionDriven), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mTechAdvancement), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mUpgradesDriven), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mDefenseDriven), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mEconomyDriven), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mFactoryTycoon), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mIntelBuildingTycoon), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSuperWeaponTendency), owner);
  archive->Write(stringVectorType, const_cast<msvc8::vector<msvc8::string>*>(&mFavouriteStructures), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mAirUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mTankUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mBotUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSeaUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSpecialtyForcesEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSupportUnitsEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mDirectDamageEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mIndirectDamageEmphasis), owner);
  archive->Write(stringVectorType, const_cast<msvc8::vector<msvc8::string>*>(&mFavouriteUnits), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mSurvivalEmphasis), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mTeamSupport), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mFormationUse), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mTargetSpread), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mQuittingTendency), owner);
  archive->Write(rangeType, const_cast<SAiPersonalityRange*>(&mChatFrequency), owner);
  archive->WriteFloat(mDifficulty);
}
