#include "moho/sim/CPlatoon.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/IArmy.h"
#include "moho/sim/Sim.h"
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
} // namespace moho

namespace
{
  using moho::ESquadClass;
  using moho::EUnitState;
  using moho::SEntitySetTemplateUnit;
  using moho::Unit;

  constexpr ESquadClass kAllSquadsClass = static_cast<ESquadClass>(6);
  constexpr ESquadClass kUnassignedSquadClass = static_cast<ESquadClass>(0);
  constexpr std::uintptr_t kSquadUnitOwnerBias = 0x8;
  constexpr int kLuaNumberTypeTag = 3;

  constexpr const char* kCanConsiderFormingPlatoonHelpText = "CPlatoon:CanConsiderFormingPlatoon()";
  constexpr const char* kGetPlatoonUnitsHelpText = "platoon:GetPlatoonUnits()";
  constexpr const char* kCanFormPlatoonHelpText = "CPlatoon:CanFormPlatoon()";
  constexpr const char* kFormPlatoonHelpText = "CPlatoon:FormPlatoon()";
  constexpr const char* kSetPrioritizedTargetListHelpText = "CPlatoon:SetPrioritizedTargetList()";
  constexpr const char* kFindClosestUnitToBaseHelpText = "CPlatoon:FindClosestUnitToBase()";
  constexpr const char* kCanAttackTargetHelpText = "CPlatoon:CanAttackTarget()";
  constexpr const char* kAttackTargetHelpText = "CPlatoon:AttackTarget()";
  constexpr const char* kMoveToTargetHelpText = "CPlatoon:MoveToTarget()";
  constexpr const char* kLoadUnitsHelpText = "CPlatoon:LoadUnits()";
  constexpr const char* kFindPrioritizedUnitHelpText = "CPlatoon:FindPrioritizedUnit()";
  constexpr const char* kFindClosestUnitHelpText = "CPlatoon:FindClosestUnit()";
  constexpr const char* kFindFurthestUnitHelpText = "CPlatoon:FindFurthestUnit()";
  constexpr const char* kIsOpponentAIRunningHelpText = "CPlatoon:IsOpponentAIRunning()";
  constexpr const char* kGetPersonalityHelpText = "CPlatoon:GetPersonality()";
  constexpr const char* kGetBrainHelpText = "CPlatoon:GetBrain()";
  constexpr const char* kGetFactionIndexHelpText = "CPlatoon:GetFactionIndex()";
  constexpr const char* kUniquelyNamePlatoonHelpText = "CPlatoon:UniquelyNamePlatoon()";
  constexpr const char* kGetPlatoonUniqueNameHelpText = "CPlatoon:GetPlatoonUniqueName()";
  constexpr const char* kGetAIPlanHelpText = "CPlatoon:GetAIPlan()";
  constexpr const char* kSwitchAIPlanHelpText = "CPlatoon:SwitchAIPlan()";
  constexpr const char* kGetPlatoonPositionHelpText = "CPlatoon:GetPlatoonPosition()";
  constexpr const char* kGetSquadPositionHelpText = "CPlatoon:GetSquadPosition()";
  constexpr const char* kGetSquadUnitsHelpText = "CPlatoon:GetSquadUnits()";
  constexpr const char* kIsAttackingHelpText = "CPlatoon:IsAttacking()";
  constexpr const char* kIsMovingHelpText = "CPlatoon:IsMoving()";
  constexpr const char* kIsPatrollingHelpText = "CPlatoon:IsPatrolling()";
  constexpr const char* kIsFerryingHelpText = "CPlatoon:IsFerrying()";
  constexpr const char* kDisbandOnIdleHelpText = "CPlatoon:DisbandOnIdle()";
  constexpr const char* kIsCommandsActiveHelpText = "CPlatoon:IsCommandsActive()";
  constexpr const char* kFindHighestValueUnitHelpText = "CPlatoon:FindHighestValueUnit()";
  constexpr const char* kStopHelpText = "CPlatoon:Stop()";
  constexpr const char* kMoveToLocationHelpText = "CPlatoon:MoveToLocation()";
  constexpr const char* kAggressiveMoveToLocationHelpText = "CPlatoon:AggressiveMoveToLocation()";
  constexpr const char* kFerryToLocationHelpText = "CPlatoon:FerryToLocation()";
  constexpr const char* kUnloadUnitsAtLocationHelpText = "CPlatoon:UnloadUnitsAtLocation()";
  constexpr const char* kUnloadAllAtLocationHelpText = "CPlatoon:UnloadAllAtLocation()";
  constexpr const char* kPatrolHelpText = "CPlatoon:Patrol()";
  constexpr const char* kGuardTargetHelpText = "CPlatoon:GuardTarget()";
  constexpr const char* kDestroyHelpText = "CPlatoon:Destroy()";
  constexpr const char* kGetFerryBeaconsHelpText = "CPlatoon:GetFerryBeacons()";
  constexpr const char* kUseFerryBeaconHelpText = "CPlatoon:UseFerryBeacon()";
  constexpr const char* kUseTeleporterHelpText = "CPlatoon:UseTeleporter()";
  constexpr const char* kSetPlatoonFormationOverrideHelpText = "CPlatoon:SetPlatoonFormationOverride()";
  constexpr const char* kGetPlatoonLifetimeStatsHelpText = "CPlatoon:GetPlatoonLifetimeStats()";
  constexpr const char* kCalculatePlatoonThreatHelpText = "CPlatoon:CalculatePlatoonThreat()";
  constexpr const char* kCalculatePlatoonThreatAroundPositionHelpText =
    "CPlatoon:CalculatePlatoonThreatAroundPosition()";
  constexpr const char* kPlatoonCategoryCountAroundPositionHelpText =
    "Count how many units fit the specified category around a position";
  constexpr const char* kPlatoonCategoryCountHelpText = "Count how many units fit the specified category";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

  struct CSquadRuntimeView
  {
    std::uint8_t pad_0000_0010[0x10];
    void** mUnitSlotBegin;
    void** mUnitSlotEnd;
    std::uint8_t pad_0018_0030[0x18];
    ESquadClass mSquadClass;
  };
  static_assert(offsetof(CSquadRuntimeView, mUnitSlotBegin) == 0x10, "CSquadRuntimeView::mUnitSlotBegin offset");
  static_assert(offsetof(CSquadRuntimeView, mUnitSlotEnd) == 0x14, "CSquadRuntimeView::mUnitSlotEnd offset");
  static_assert(offsetof(CSquadRuntimeView, mSquadClass) == 0x30, "CSquadRuntimeView::mSquadClass offset");

  struct CPlatoonRuntimeView
  {
    std::uint8_t pad_0000_0038[0x38];
    moho::IArmy* mArmy;
    std::uint8_t pad_003C_0040[0x04];
    CSquadRuntimeView** mSquadStart;
    CSquadRuntimeView** mSquadEnd;
    std::uint8_t pad_0048_008C[0x44];
    msvc8::string mPlan;
    msvc8::string mUniqueName;
    std::uint8_t pad_00C4_00E0[0x1C];
    std::uint8_t mDisbandOnIdle;
    std::uint8_t pad_00E1_00E4[0x03];
    std::int32_t mLifetimeStat1;
    std::int32_t mLifetimeStat2;
    float mLifetimeStat3;
    float mLifetimeStat4;
    LuaPlus::LuaObject mLuaUnitList;
    std::uint8_t mHasLuaList;
  };
  static_assert(offsetof(CPlatoonRuntimeView, mArmy) == 0x38, "CPlatoonRuntimeView::mArmy offset");
  static_assert(offsetof(CPlatoonRuntimeView, mSquadStart) == 0x40, "CPlatoonRuntimeView::mSquadStart offset");
  static_assert(offsetof(CPlatoonRuntimeView, mSquadEnd) == 0x44, "CPlatoonRuntimeView::mSquadEnd offset");
  static_assert(offsetof(CPlatoonRuntimeView, mPlan) == 0x8C, "CPlatoonRuntimeView::mPlan offset");
  static_assert(offsetof(CPlatoonRuntimeView, mUniqueName) == 0xA8, "CPlatoonRuntimeView::mUniqueName offset");
  static_assert(
    offsetof(CPlatoonRuntimeView, mDisbandOnIdle) == 0xE0, "CPlatoonRuntimeView::mDisbandOnIdle offset"
  );
  static_assert(offsetof(CPlatoonRuntimeView, mLifetimeStat1) == 0xE4, "CPlatoonRuntimeView::mLifetimeStat1 offset");
  static_assert(offsetof(CPlatoonRuntimeView, mLifetimeStat2) == 0xE8, "CPlatoonRuntimeView::mLifetimeStat2 offset");
  static_assert(offsetof(CPlatoonRuntimeView, mLifetimeStat3) == 0xEC, "CPlatoonRuntimeView::mLifetimeStat3 offset");
  static_assert(offsetof(CPlatoonRuntimeView, mLifetimeStat4) == 0xF0, "CPlatoonRuntimeView::mLifetimeStat4 offset");
  static_assert(offsetof(CPlatoonRuntimeView, mLuaUnitList) == 0xF4, "CPlatoonRuntimeView::mLuaUnitList offset");
  static_assert(offsetof(CPlatoonRuntimeView, mHasLuaList) == 0x108, "CPlatoonRuntimeView::mHasLuaList offset");

  [[nodiscard]] moho::Unit* DecodeSquadUnit(void* const slotValue) noexcept
  {
    const auto raw = reinterpret_cast<std::uintptr_t>(slotValue);
    if (raw <= kSquadUnitOwnerBias) {
      return nullptr;
    }

    return reinterpret_cast<moho::Unit*>(raw - kSquadUnitOwnerBias);
  }

  [[nodiscard]] CSquadRuntimeView* FindSquadByClass(
    CPlatoonRuntimeView& platoonRuntime,
    const ESquadClass squadClass
  ) noexcept
  {
    for (CSquadRuntimeView** squadLane = platoonRuntime.mSquadStart; squadLane != platoonRuntime.mSquadEnd; ++squadLane) {
      CSquadRuntimeView* const squadView = *squadLane;
      if (!squadView || squadView->mSquadClass != squadClass) {
        continue;
      }

      return squadView;
    }

    return nullptr;
  }

  [[nodiscard]] bool SquadContainsUnit(const CSquadRuntimeView* const squad, const Unit* const targetUnit) noexcept
  {
    if (!squad || !targetUnit) {
      return false;
    }

    for (void** unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
      if (DecodeSquadUnit(*unitSlot) == targetUnit) {
        return true;
      }
    }

    return false;
  }

  void BuildPlatoonUnitSet(const CPlatoonRuntimeView& platoonRuntime, SEntitySetTemplateUnit& outSet);

  [[nodiscard]] bool ComputeSquadCenter(const CSquadRuntimeView* const squad, Wm3::Vector3f& outCenter) noexcept
  {
    if (!squad) {
      return false;
    }

    reinterpret_cast<const moho::CSquad*>(squad)->GetCenter(&outCenter);
    return true;
  }

  [[nodiscard]] bool ComputePlatoonCenter(const CPlatoonRuntimeView& platoonRuntime, Wm3::Vector3f& outCenter) noexcept
  {
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(platoonRuntime, platoonUnits);

    float sumX = 0.0f;
    float sumY = 0.0f;
    float sumZ = 0.0f;
    std::uint32_t unitCount = 0u;

    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!unit) {
        continue;
      }

      const Wm3::Vec3f& unitPosition = unit->GetPosition();
      sumX += unitPosition.x;
      sumY += unitPosition.y;
      sumZ += unitPosition.z;
      ++unitCount;
    }

    if (unitCount == 0u) {
      return false;
    }

    const float inverseCount = 1.0f / static_cast<float>(unitCount);
    outCenter.x = sumX * inverseCount;
    outCenter.y = sumY * inverseCount;
    outCenter.z = sumZ * inverseCount;
    return true;
  }

  /**
   * Address: 0x00725770 (FUN_00725770, sub_725770)
   *
   * What it does:
   * Rebuilds one sorted unique unit-entity set by merging all squad unit lanes
   * currently referenced by the platoon.
   */
  void BuildPlatoonUnitSet(const CPlatoonRuntimeView& platoonRuntime, SEntitySetTemplateUnit& outSet)
  {
    outSet.Clear();
    outSet.ListResetLinks();

    for (CSquadRuntimeView* const* squadLane = platoonRuntime.mSquadStart; squadLane != platoonRuntime.mSquadEnd; ++squadLane) {
      const CSquadRuntimeView* const squad = *squadLane;
      if (!squad || squad->mUnitSlotBegin == squad->mUnitSlotEnd) {
        continue;
      }

      for (void* const* unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
        (void)outSet.AddUnit(DecodeSquadUnit(*unitSlot));
      }
    }
  }

  enum class PlatoonThreatType : std::int32_t
  {
    Air = 0,
    Surface = 1,
    Sub = 2,
    Economy = 3,
    Unknown = -1,
  };

  [[nodiscard]] PlatoonThreatType ParsePlatoonThreatType(const char* const threatTypeName) noexcept
  {
    if (threatTypeName == nullptr) {
      return PlatoonThreatType::Unknown;
    }

    if (::_stricmp(threatTypeName, "Air") == 0) {
      return PlatoonThreatType::Air;
    }
    if (::_stricmp(threatTypeName, "Surface") == 0) {
      return PlatoonThreatType::Surface;
    }
    if (::_stricmp(threatTypeName, "Sub") == 0) {
      return PlatoonThreatType::Sub;
    }
    if (::_stricmp(threatTypeName, "Economy") == 0) {
      return PlatoonThreatType::Economy;
    }

    return PlatoonThreatType::Unknown;
  }

  [[nodiscard]] bool BlueprintMatchesCategory(
    const moho::RUnitBlueprint* const blueprint,
    const moho::EntityCategorySet* const categorySet
  ) noexcept
  {
    if (!blueprint || !categorySet) {
      return false;
    }
    return categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  }

  [[nodiscard]] float ResolveBlueprintThreatValue(
    const moho::RUnitBlueprint& blueprint,
    const PlatoonThreatType threatType
  ) noexcept
  {
    switch (threatType) {
      case PlatoonThreatType::Air:
        return blueprint.Defense.AirThreatLevel;
      case PlatoonThreatType::Surface:
        return blueprint.Defense.SurfaceThreatLevel;
      case PlatoonThreatType::Sub:
        return blueprint.Defense.SubThreatLevel;
      case PlatoonThreatType::Economy:
        return blueprint.Defense.EconomyThreatLevel;
      case PlatoonThreatType::Unknown:
      default:
        return blueprint.Defense.AirThreatLevel + blueprint.Defense.SurfaceThreatLevel + blueprint.Defense.SubThreatLevel
          + blueprint.Defense.EconomyThreatLevel;
    }
  }

  [[nodiscard]] bool IsThreatCandidateUnit(const moho::Unit* const unit) noexcept
  {
    return unit && !unit->IsDead() && !unit->DestroyQueued();
  }

  void DestroyOwnedSquad(moho::CSquad* const squad) noexcept
  {
    if (squad == nullptr) {
      return;
    }

    auto** const vtable = *reinterpret_cast<void***>(squad);
    if (vtable == nullptr || vtable[2] == nullptr) {
      operator delete(squad);
      return;
    }

    using DeletingDtor = void(__thiscall*)(void*, int);
    const auto deletingDtor = reinterpret_cast<DeletingDtor>(vtable[2]);
    deletingDtor(squad, 1);
  }

  [[nodiscard]] float ReadSquaredRadiusArg(LuaPlus::LuaState* const state, const int stackIndex)
  {
    LuaPlus::LuaStackObject radiusArg(state, stackIndex);
    if (lua_type(state->m_state, stackIndex) != kLuaNumberTypeTag) {
      LuaPlus::LuaStackObject::TypeError(&radiusArg, "number");
    }

    const float radius = static_cast<float>(lua_tonumber(state->m_state, stackIndex));
    return radius * radius;
  }

  /**
   * Address: 0x00724820 (FUN_00724820, Moho::CSquad::Stop)
   *
   * What it does:
   * Iterates one squad's unit slot vector and stops each live unit by clearing
   * its command queue and stopping its attacker controller when present.
   */
  void StopSquad(CSquadRuntimeView* const squad)
  {
    if (!squad) {
      return;
    }

    for (void** unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
      moho::Unit* const unit = DecodeSquadUnit(*unitSlot);
      if (!unit || unit->IsDead()) {
        continue;
      }

      if (moho::CUnitCommandQueue* const commandQueue = unit->CommandQueue; commandQueue) {
        commandQueue->ClearCommandQueue();
      }

      if (moho::CAiAttackerImpl* const attacker = unit->AiAttacker; attacker) {
        attacker->Stop();
      }
    }
  }

  /**
   * Address: 0x00724150 (FUN_00724150, Moho::CSquad::RemoveUnit)
   *
   * What it does:
   * Searches one squad's unit slot vector for a matching entity, removes the
   * matched slot by compacting trailing entries, and preserves first-match
   * behavior.
   */
  void RemoveUnitFromSquad(CSquadRuntimeView* const squad, const moho::Entity* const entity)
  {
    if (!squad || !entity) {
      return;
    }

    void** const begin = squad->mUnitSlotBegin;
    void** const end = squad->mUnitSlotEnd;
    if (begin == end) {
      return;
    }

    void** match = begin;
    for (; match != end; ++match) {
      const moho::Unit* const unit = DecodeSquadUnit(*match);
      if (unit != nullptr && static_cast<const moho::Entity*>(unit) == entity) {
        break;
      }
    }

    if (match == end) {
      return;
    }

    const std::ptrdiff_t tailCount = end - (match + 1);
    if (tailCount > 0) {
      const std::size_t byteCount = static_cast<std::size_t>(tailCount) * sizeof(void*);
      memmove_s(match, byteCount, match + 1, byteCount);
    }

    squad->mUnitSlotEnd = end - 1;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandType()
  {
    return moho::CUnitCommand::StaticGetClass();
  }

  [[nodiscard]] gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int stackTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, stackTop);
    return out;
  }

  [[nodiscard]] moho::CScriptObject** ExtractScriptObjectSlot(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, moho::CScriptObject::GetPointerType());
    return static_cast<moho::CScriptObject**>(upcast.mObj);
  }

  /**
   * Address: 0x006F8D80 (FUN_006F8D80, func_GetCUnitCommandOpt)
   *
   * What it does:
   * Resolves one Lua game-object handle to an optional `CUnitCommand*`,
   * raising Lua type errors on invalid/non-command userdata.
   */
  [[nodiscard]] moho::CUnitCommand* func_GetCUnitCommandOpt(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* const state
  )
  {
    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlot(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCUnitCommandType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CUnitCommand*>(upcast.mObj);
  }
} // namespace

namespace moho
{
  CScrLuaMetatableFactory<CPlatoon> CScrLuaMetatableFactory<CPlatoon>::sInstance{};

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
   * matching squad lane, and returns whether that squad can attack the
   * requested unit.
   */
  int cfunc_CPlatoonCanAttackTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonAttackTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonMoveToTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonLoadUnitsL(LuaPlus::LuaState* state);
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

  /**
   * Address: 0x0072A780 (FUN_0072A780, Moho::InstanceCounter<Moho::CPlatoon>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for CPlatoon instance
   * counting (`Instance Counts_<type-name-without-underscores>`).
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::CPlatoon>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::CPlatoon).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  CScrLuaMetatableFactory<CPlatoon>& CScrLuaMetatableFactory<CPlatoon>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CPlatoon>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x00723AC0 (FUN_00723AC0, Moho::CPlatoon::GetClass)
   */
  gpg::RType* CPlatoon::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CPlatoon));
    }
    return sType;
  }

  /**
   * Address: 0x00723AE0 (FUN_00723AE0, Moho::CPlatoon::GetDerivedObjectRef)
   */
  gpg::RRef CPlatoon::GetDerivedObjectRef()
  {
    gpg::RRef objectRef{};
    objectRef.mObj = this;
    objectRef.mType = GetClass();
    return objectRef;
  }

  /**
   * Address: 0x0072A300 (FUN_0072A300, Moho::CPlatoon::operator new)
   */
  CPlatoon* CPlatoon::Create(
    Sim* const sim,
    CArmyImpl* const army,
    const char* const platoonName,
    const char* const aiPlan
  )
  {
    return new (std::nothrow) CPlatoon(sim, army, platoonName, aiPlan);
  }

  /**
   * Address: 0x00724CC0 (FUN_00724CC0, Moho::CPlatoon::CPlatoon)
   */
  CPlatoon::CPlatoon(Sim* const sim, CArmyImpl* const army, const char* const platoonName, const char* const aiPlan)
    : CScriptObject(
      CScrLuaMetatableFactory<CPlatoon>::Instance().Get(sim ? sim->mLuaState : nullptr),
      LuaPlus::LuaObject{},
      LuaPlus::LuaObject{},
      LuaPlus::LuaObject{}
    )
    , mSim(sim)
    , mArmy(army)
    , mUnknown_0x03C(0u)
    , mSquadList()
    , mName()
    , mPlan()
    , mUniqueName()
    , mFormation()
    , mDisbandOnIdle(0u)
    , mPad_0x0E1{0u, 0u, 0u}
    , mLifetimeStat1(0)
    , mLifetimeStat2(0)
    , mLifetimeStat3(0.0f)
    , mLifetimeStat4(0.0f)
    , mLuaUnitList()
    , mHasLuaList(0u)
    , mPad_0x109{0u, 0u, 0u, 0u, 0u, 0u, 0u}
  {
    if (StatItem* const statItem = InstanceCounter<CPlatoon>::GetStatItem(); statItem != nullptr) {
#if defined(_WIN32)
      InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), 1);
#else
      statItem->mPrimaryValueBits += 1;
#endif
    }

    if (platoonName != nullptr) {
      mName.assign(platoonName);
    }

    if (aiPlan != nullptr) {
      mPlan.assign(aiPlan);
    }

    const char* planArg = mPlan.c_str();
    CallbackStr("OnCreate", &planArg);
  }

  /**
   * Address: 0x00724EB0 (FUN_00724EB0, Moho::CPlatoon::~CPlatoon)
   */
  CPlatoon::~CPlatoon()
  {
    for (CSquad** squadIt = mSquadList.begin(); squadIt != mSquadList.end(); ++squadIt) {
      DestroyOwnedSquad(*squadIt);
    }
    mSquadList.ResetStorageToInline();

    if (StatItem* const statItem = InstanceCounter<CPlatoon>::GetStatItem(); statItem != nullptr) {
#if defined(_WIN32)
      InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), -1);
#else
      statItem->mPrimaryValueBits -= 1;
#endif
    }
  }

  /**
   * Address: 0x00725630 (FUN_00725630, Moho::CPlatoon::GetSquad)
   *
   * What it does:
   * Returns the first squad lane matching `squadClass`, or null when absent.
   */
  CSquad* CPlatoon::GetSquad(const ESquadClass squadClass)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    CSquadRuntimeView* const squadView = FindSquadByClass(runtimeView, squadClass);
    return reinterpret_cast<CSquad*>(squadView);
  }

  /**
   * Address: 0x00725660 (FUN_00725660, Moho::CPlatoon::CountUnassignedUnitsWithBP)
   *
   * What it does:
   * Returns the count of live unassigned-squad units whose blueprint id
   * matches `blueprintId`, or zero when no unassigned squad exists.
   */
  int CPlatoon::CountUnassignedUnitsWithBP(const char* const blueprintId)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    CSquadRuntimeView* const squadView = FindSquadByClass(runtimeView, ESquadClass::Unassigned);
    if (squadView == nullptr) {
      return 0;
    }

    return reinterpret_cast<CSquad*>(squadView)->CountUnitsWithBP(blueprintId);
  }

  /**
   * Address: 0x007256A0 (FUN_007256A0, Moho::CPlatoon::CountUnassignedUnitsInCategory)
   *
   * What it does:
   * Returns the count of live unassigned-squad units matching `categorySet`,
   * or zero when no unassigned squad exists.
   */
  int CPlatoon::CountUnassignedUnitsInCategory(const EntityCategorySet* const categorySet)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    CSquadRuntimeView* const squadView = FindSquadByClass(runtimeView, ESquadClass::Unassigned);
    if (squadView == nullptr) {
      return 0;
    }

    return reinterpret_cast<CSquad*>(squadView)->CountUnitsInCategory(categorySet);
  }

  /**
   * Address: 0x007256E0 (FUN_007256E0, Moho::CPlatoon::GetUnassignedUnitsInCategory)
   *
   * What it does:
   * Walks platoon squad lanes to find the first `SQUADCLASS_Unassigned` squad
   * and forwards category-filtered appends into `outUnits`.
   */
  void CPlatoon::GetUnassignedUnitsInCategory(
    const EntityCategorySet* const categorySet, const int maxCount, SEntitySetTemplateUnit& outUnits
  )
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    for (CSquadRuntimeView** squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      CSquadRuntimeView* const squadView = *squadLane;
      if (squadView == nullptr || squadView->mSquadClass != ESquadClass::Unassigned) {
        continue;
      }

      reinterpret_cast<CSquad*>(squadView)->AppendUnitsInCategory(categorySet, maxCount, outUnits);
      return;
    }
  }

  /**
   * Address: 0x00725730 (FUN_00725730, Moho::CPlatoon::GetUnassignedUnitsWithBP)
   *
   * What it does:
   * Looks up this platoon's `SQUADCLASS_Unassigned` squad (if any) and
   * forwards the blueprint-id filter and `maxCount` cap to
   * `CSquad::AppendUnitsWithBP`, which appends the matching live units into
   * `outUnits`. No-op when the platoon has no unassigned squad.
   */
  void CPlatoon::GetUnassignedUnitsWithBP(
    const char* const blueprintId, const int maxCount, SEntitySetTemplateUnit& outUnits
  )
  {
    CSquad* const unassignedSquad = GetSquad(ESquadClass::Unassigned);
    if (unassignedSquad == nullptr) {
      return;
    }
    unassignedSquad->AppendUnitsWithBP(blueprintId, maxCount, outUnits);
  }

  /**
   * Address: 0x007253B0 (FUN_007253B0, Moho::CPlatoon::RemoveUnit)
   *
   * What it does:
   * Clears the platoon Lua unit cache flag, walks each squad lane, and removes
   * the first matching entity from the owning squad.
   */
  void CPlatoon::RemoveUnit(Entity* const unit)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    runtimeView.mHasLuaList = 0u;

    for (CSquadRuntimeView** squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      CSquadRuntimeView* const squadView = *squadLane;
      if (!squadView) {
        continue;
      }

      for (void** unitSlot = squadView->mUnitSlotBegin; unitSlot != squadView->mUnitSlotEnd; ++unitSlot) {
        const moho::Unit* const squadUnit = DecodeSquadUnit(*unitSlot);
        if (squadUnit != nullptr && static_cast<const moho::Entity*>(squadUnit) == unit) {
          RemoveUnitFromSquad(squadView, unit);
          return;
        }
      }
    }
  }

  /**
   * Address: 0x007251D0 (FUN_007251D0, Moho::CPlatoon::IsInPlatoon)
   *
   * What it does:
   * Returns whether the provided unit pointer is currently present in any
   * squad lane of this platoon.
   */
  bool CPlatoon::IsInPlatoon(const Unit* const unit) const
  {
    if (!unit) {
      return false;
    }

    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (CSquadRuntimeView* const* squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      if (SquadContainsUnit(*squadLane, unit)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00725220 (FUN_00725220, Moho::CPlatoon::GetSquadClass)
   *
   * What it does:
   * Scans all squad lanes and returns the class of the first squad containing
   * the provided unit; otherwise returns `SQUADCLASS_Unassigned`.
   */
  ESquadClass CPlatoon::GetSquadClass(const Unit* const unit) const
  {
    if (!unit) {
      return kUnassignedSquadClass;
    }

    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (CSquadRuntimeView* const* squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      const CSquadRuntimeView* const squadView = *squadLane;
      if (SquadContainsUnit(squadView, unit)) {
        return squadView->mSquadClass;
      }
    }

    return kUnassignedSquadClass;
  }

  /**
   * Address: 0x00729F90 (FUN_00729F90, Moho::CPlatoon::SquadHasState)
   *
   * What it does:
   * Returns whether the requested squad class has at least one unit in the
   * requested state (`SQUADCLASS_all` checks all assigned classes 1..5).
   */
  bool CPlatoon::SquadHasState(const ESquadClass squadClass, CPlatoon* const platoon, const EUnitState state)
  {
    if (!platoon) {
      return false;
    }

    for (std::int32_t checkedClass = 1; checkedClass < static_cast<std::int32_t>(kAllSquadsClass); ++checkedClass) {
      if (squadClass != kAllSquadsClass && static_cast<std::int32_t>(squadClass) != checkedClass) {
        continue;
      }

      // Preserve original call lane: this method always queries GetSquad using
      // the incoming squadClass token, even during SQUADCLASS_all scanning.
      CSquad* const squad = platoon->GetSquad(squadClass);
      if (squad != nullptr && squad->HasUnitWithState(state)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x007261B0 (FUN_007261B0, Moho::CPlatoon::Stop)
   *
   * What it does:
   * Stops all non-unassigned squads when `squadClass == 6`, otherwise stops the
   * first squad matching the requested class.
   */
  void CPlatoon::Stop(const ESquadClass squadClass)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    if (squadClass == kAllSquadsClass) {
      for (CSquadRuntimeView** squad = runtimeView.mSquadStart; squad != runtimeView.mSquadEnd; ++squad) {
        CSquadRuntimeView* const squadView = *squad;
        if (squadView && squadView->mSquadClass != kUnassignedSquadClass) {
          StopSquad(squadView);
        }
      }
      return;
    }

    for (CSquadRuntimeView** squad = runtimeView.mSquadStart; squad != runtimeView.mSquadEnd; ++squad) {
      CSquadRuntimeView* const squadView = *squad;
      if (!squadView || squadView->mSquadClass != squadClass) {
        continue;
      }

      StopSquad(squadView);
      return;
    }
  }

  /**
   * Address: 0x007247A0 (FUN_007247A0, Moho::CSquad::UnitHasOrder)
   *
   * What it does:
   * Returns true when the squad has no live unit with an active command at
   * queue-head; returns false as soon as one active queued command is found.
   */
  [[nodiscard]] bool SquadHasNoActiveOrders(const CSquadRuntimeView* const squad) noexcept
  {
    if (!squad) {
      return true;
    }

    for (void** unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
      Unit* const unit = DecodeSquadUnit(*unitSlot);
      if (!unit || unit->IsDead()) {
        continue;
      }

      const CUnitCommandQueue* const commandQueue = unit->CommandQueue;
      if (!commandQueue || commandQueue->mCommandVec.empty()) {
        continue;
      }

      const WeakPtr<CUnitCommand>& commandLink = commandQueue->mCommandVec.front();
      if (commandLink.GetObjectPtr() != nullptr) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x00729FE0 (FUN_00729FE0, Moho::CPlatoon::SquadsHaveOrders)
   *
   * What it does:
   * Scans assigned squad classes (1..5) and returns true only when each
   * present squad has no active orders.
   */
  bool CPlatoon::AssignedSquadsAreIdle() const
  {
    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(this);

    for (std::int32_t squadClass = 1; squadClass < static_cast<std::int32_t>(kAllSquadsClass); ++squadClass) {
      CSquadRuntimeView* matchingSquad = nullptr;
      for (CSquadRuntimeView** squad = runtimeView.mSquadStart; squad != runtimeView.mSquadEnd; ++squad) {
        CSquadRuntimeView* const squadView = *squad;
        if (!squadView || static_cast<std::int32_t>(squadView->mSquadClass) != squadClass) {
          continue;
        }

        matchingSquad = squadView;
        break;
      }

      if (matchingSquad && !SquadHasNoActiveOrders(matchingSquad)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x00725150 (FUN_00725150, Moho::CPlatoon::SwitchAIPlan)
   *
   * What it does:
   * Replaces platoon plan string and dispatches script `OnDestroy/OnCreate`
   * when the plan text changes.
   */
  void CPlatoon::SwitchAIPlan(const char* const planName)
  {
    const char* const normalizedPlan = (planName != nullptr) ? planName : "";
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    if (runtimeView.mPlan == normalizedPlan) {
      return;
    }

    auto* const scriptObject = reinterpret_cast<CScriptObject*>(this);
    scriptObject->RunScript("OnDestroy");

    runtimeView.mPlan.assign(normalizedPlan);

    const char* callbackArg = normalizedPlan;
    scriptObject->CallbackStr("OnCreate", &callbackArg);
  }

  /**
   * Address: 0x0072B730 (FUN_0072B730, Moho::CPlatoon::SetPlatoonFormationOverride)
   *
   * What it does:
   * Replaces the platoon formation override string lane.
   */
  void CPlatoon::SetPlatoonFormationOverride(const msvc8::string& formationName)
  {
    mFormation = formationName;
  }

  /**
   * Address: 0x00725410 (FUN_00725410, Moho::CPlatoon::PullUnassignedUnitsFrom)
   *
   * What it does:
   * Moves this platoon's current unit set into the army-pool platoon
   * unassigned lane and invalidates Lua unit-list caches on both platoons.
   */
  void CPlatoon::PullUnassignedUnitsFrom(CPlatoon* const armyPool)
  {
    constexpr const char* kArmyPoolName = "ArmyPool";

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    runtimeView.mHasLuaList = 0u;

    if (armyPool == nullptr || runtimeView.mArmy == nullptr) {
      return;
    }

    auto& armyPoolRuntimeView = *reinterpret_cast<CPlatoonRuntimeView*>(armyPool);
    if (FindSquadByClass(armyPoolRuntimeView, kUnassignedSquadClass) == nullptr) {
      return;
    }

    SEntitySetTemplateUnit unitsToTransfer{};
    BuildPlatoonUnitSet(runtimeView, unitsToTransfer);
    if (unitsToTransfer.mVec.empty()) {
      return;
    }

    runtimeView.mArmy->AssignUnitsToPlatoon(&unitsToTransfer, kArmyPoolName);
    runtimeView.mHasLuaList = 0u;
    armyPoolRuntimeView.mHasLuaList = 0u;
  }

  /**
   * Address: 0x00BDAE70 (FUN_00BDAE70, register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards startup registration to `func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef()
  {
    return func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();
  }

  /**
   * Address: 0x0072B810 (FUN_0072B810, cfunc_CPlatoonIsOpponentAIRunning)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonIsOpponentAIRunningL`.
   */
  int cfunc_CPlatoonIsOpponentAIRunning(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsOpponentAIRunningL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072B830 (FUN_0072B830, func_CPlatoonIsOpponentAIRunning_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsOpponentAIRunning()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsOpponentAIRunning_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsOpponentAIRunning",
      &cfunc_CPlatoonIsOpponentAIRunning,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsOpponentAIRunningHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072B970 (FUN_0072B970, cfunc_CPlatoonGetPersonality)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPersonalityL`.
   */
  int cfunc_CPlatoonGetPersonality(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPersonalityL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072B9F0 (FUN_0072B9F0, cfunc_CPlatoonGetPersonalityL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning brain personality object, or
   * `nil` when no personality exists.
   */
  int cfunc_CPlatoonGetPersonalityL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetPersonalityHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    CAiPersonality* const personality = runtimeView.mArmy->GetArmyBrain()->mPersonality;

    if (personality != nullptr) {
      personality->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
    }

    return 1;
  }

  /**
   * Address: 0x0072B990 (FUN_0072B990, func_CPlatoonGetPersonality_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPersonality()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPersonality_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPersonality",
      &cfunc_CPlatoonGetPersonality,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPersonalityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BAD0 (FUN_0072BAD0, cfunc_CPlatoonGetBrain)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetBrainL`.
   */
  int cfunc_CPlatoonGetBrain(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetBrainL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BB50 (FUN_0072BB50, cfunc_CPlatoonGetBrainL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning army-brain Lua object.
   */
  int cfunc_CPlatoonGetBrainL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetBrainHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    runtimeView.mArmy->GetArmyBrain()->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072BAF0 (FUN_0072BAF0, func_CPlatoonGetBrain_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetBrain()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetBrain_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetBrain",
      &cfunc_CPlatoonGetBrain,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetBrainHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BC10 (FUN_0072BC10, cfunc_CPlatoonGetFactionIndex)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetFactionIndexL`.
   */
  int cfunc_CPlatoonGetFactionIndex(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetFactionIndexL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BC90 (FUN_0072BC90, cfunc_CPlatoonGetFactionIndexL)
   *
   * What it does:
   * Resolves one platoon and returns one-based faction index from the owning
   * army brain.
   */
  int cfunc_CPlatoonGetFactionIndexL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetFactionIndexHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    const CAiBrain* const brain = runtimeView.mArmy->GetArmyBrain();

    lua_pushnumber(state->m_state, static_cast<float>(brain->mArmy->FactionIndex + 1));
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072BC30 (FUN_0072BC30, func_CPlatoonGetFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetFactionIndex()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetFactionIndex_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetFactionIndex",
      &cfunc_CPlatoonGetFactionIndex,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetFactionIndexHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BD60 (FUN_0072BD60, cfunc_CPlatoonUniquelyNamePlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonUniquelyNamePlatoonL`.
   */
  int cfunc_CPlatoonUniquelyNamePlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUniquelyNamePlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BD80 (FUN_0072BD80, func_CPlatoonUniquelyNamePlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UniquelyNamePlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUniquelyNamePlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UniquelyNamePlatoon",
      &cfunc_CPlatoonUniquelyNamePlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUniquelyNamePlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BDE0 (FUN_0072BDE0, cfunc_CPlatoonUniquelyNamePlatoonL)
   *
   * What it does:
   * Resolves `(platoon, uniqueName)` and stores the provided platoon unique
   * name when argument #2 is a string.
   */
  int cfunc_CPlatoonUniquelyNamePlatoonL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kUniquelyNamePlatoonHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject uniqueNameObject(LuaPlus::LuaStackObject(state, 2));
    if (platoon != nullptr && uniqueNameObject.IsString()) {
      auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
      runtimeView.mUniqueName.assign(uniqueNameObject.GetString());
    }

    return 1;
  }

  /**
   * Address: 0x0072BEF0 (FUN_0072BEF0, cfunc_CPlatoonGetPlatoonUniqueName)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetPlatoonUniqueNameL`.
   */
  int cfunc_CPlatoonGetPlatoonUniqueName(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonUniqueNameL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BF10 (FUN_0072BF10, func_CPlatoonGetPlatoonUniqueName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonUniqueName()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonUniqueName_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonUniqueName",
      &cfunc_CPlatoonGetPlatoonUniqueName,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonUniqueNameHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BF70 (FUN_0072BF70, cfunc_CPlatoonGetPlatoonUniqueNameL)
   *
   * What it does:
   * Resolves one platoon and pushes its unique-name string.
   */
  int cfunc_CPlatoonGetPlatoonUniqueNameL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kGetPlatoonUniqueNameHelpText,
        1,
        argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(platoon);

    lua_pushstring(state->m_state, runtimeView.mUniqueName.c_str());
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072C040 (FUN_0072C040, cfunc_CPlatoonGetAIPlan)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetAIPlanL`.
   */
  int cfunc_CPlatoonGetAIPlan(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetAIPlanL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C060 (FUN_0072C060, func_CPlatoonGetAIPlan_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetAIPlan()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetAIPlan_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetAIPlan",
      &cfunc_CPlatoonGetAIPlan,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetAIPlanHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C0C0 (FUN_0072C0C0, cfunc_CPlatoonGetAIPlanL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning army-brain AI-plan string.
   */
  int cfunc_CPlatoonGetAIPlanL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetAIPlanHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(platoon);
    const CAiBrain* const armyBrain = runtimeView.mArmy->GetArmyBrain();

    lua_pushstring(state->m_state, armyBrain->mCurrentPlan.c_str());
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072C190 (FUN_0072C190, cfunc_CPlatoonSwitchAIPlan)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonSwitchAIPlanL`.
   */
  int cfunc_CPlatoonSwitchAIPlan(lua_State* const luaContext)
  {
    return cfunc_CPlatoonSwitchAIPlanL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C1B0 (FUN_0072C1B0, func_CPlatoonSwitchAIPlan_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SwitchAIPlan()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSwitchAIPlan_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SwitchAIPlan",
      &cfunc_CPlatoonSwitchAIPlan,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kSwitchAIPlanHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C210 (FUN_0072C210, cfunc_CPlatoonSwitchAIPlanL)
   *
   * What it does:
   * Resolves `(platoon, planName)` and switches AI plan when argument #2 is
   * a string.
   */
  int cfunc_CPlatoonSwitchAIPlanL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSwitchAIPlanHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject aiPlanObject(LuaPlus::LuaStackObject(state, 2));
    if (aiPlanObject.IsString()) {
      platoon->SwitchAIPlan(aiPlanObject.GetString());
    }

    return 1;
  }

  /**
   * Address: 0x0072C300 (FUN_0072C300, cfunc_CPlatoonGetPlatoonPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetPlatoonPositionL`.
   */
  int cfunc_CPlatoonGetPlatoonPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C380 (FUN_0072C380, cfunc_CPlatoonGetPlatoonPositionL)
   *
   * What it does:
   * Resolves one platoon and returns the average world position of all units
   * currently present in its squad lanes.
   */
  int cfunc_CPlatoonGetPlatoonPositionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetPlatoonPositionHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(platoon);

    Wm3::Vector3f platoonCenter{};
    if (!ComputePlatoonCenter(runtimeView, platoonCenter)) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3<float>>(state, platoonCenter);
    centerObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072C320 (FUN_0072C320, func_CPlatoonGetPlatoonPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonPosition",
      &cfunc_CPlatoonGetPlatoonPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C5C0 (FUN_0072C5C0, cfunc_CPlatoonGetSquadPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetSquadPositionL`.
   */
  int cfunc_CPlatoonGetSquadPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetSquadPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C640 (FUN_0072C640, cfunc_CPlatoonGetSquadPositionL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns the average world position
   * of units currently present in the selected squad.
   */
  int cfunc_CPlatoonGetSquadPositionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetSquadPositionHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    CSquadRuntimeView* const squad = FindSquadByClass(runtimeView, squadClass);
    if (!squad) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    if (runtimeView.mArmy != nullptr) {
      (void)runtimeView.mArmy->GetArmyBrain();
    }

    Wm3::Vector3f squadCenter{};
    if (!ComputeSquadCenter(squad, squadCenter)) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3<float>>(state, squadCenter);
    centerObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072C5E0 (FUN_0072C5E0, func_CPlatoonGetSquadPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetSquadPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetSquadPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetSquadPosition",
      &cfunc_CPlatoonGetSquadPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetSquadPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C7D0 (FUN_0072C7D0, cfunc_CPlatoonGetSquadUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetSquadUnitsL`.
   */
  int cfunc_CPlatoonGetSquadUnits(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetSquadUnitsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C850 (FUN_0072C850, cfunc_CPlatoonGetSquadUnitsL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns a Lua array of unit objects
   * for members currently present in the selected squad.
   */
  int cfunc_CPlatoonGetSquadUnitsL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetSquadUnitsHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    CSquadRuntimeView* const squad = FindSquadByClass(runtimeView, squadClass);
    if (!squad) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    LuaPlus::LuaObject unitTable{};
    unitTable.AssignNewTable(state, 0, 0u);

    int unitIndex = 1;
    for (void** unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
      Unit* const unit = DecodeSquadUnit(*unitSlot);
      if (!unit) {
        continue;
      }

      LuaPlus::LuaObject unitObject = unit->GetLuaObject();
      unitTable.Insert(unitIndex, unitObject);
      ++unitIndex;
    }

    unitTable.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072C7F0 (FUN_0072C7F0, func_CPlatoonGetSquadUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetSquadUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetSquadUnits_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetSquadUnits",
      &cfunc_CPlatoonGetSquadUnits,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetSquadUnitsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072B890 (FUN_0072B890, cfunc_CPlatoonIsOpponentAIRunningL)
   *
   * What it does:
   * Resolves one platoon and returns the `AI_RunOpponentAI` sim-convar state.
   */
  int cfunc_CPlatoonIsOpponentAIRunningL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kIsOpponentAIRunningHelpText,
        1,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);

    IArmy* const army = runtimeView.mArmy;
    Sim* const sim = army ? army->GetSim() : nullptr;

    CSimConVarBase* const runOpponentAiConVar = GetAI_RunOpponentAI_SimConVarDef();
    CSimConVarInstanceBase* const runOpponentAiVar = (sim && runOpponentAiConVar) ? sim->GetSimVar(runOpponentAiConVar)
                                                                                   : nullptr;
    const void* const runOpponentAiStorage = runOpponentAiVar ? runOpponentAiVar->GetValueStorage() : nullptr;
    const bool shouldRunOpponentAi =
      runOpponentAiStorage && (*reinterpret_cast<const std::uint8_t*>(runOpponentAiStorage) != 0u);

    lua_pushboolean(state->m_state, shouldRunOpponentAi ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072CC00 (FUN_0072CC00, cfunc_CPlatoonCanConsiderFormingPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanConsiderFormingPlatoonL`.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanConsiderFormingPlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072CC80 (FUN_0072CC80, cfunc_CPlatoonCanConsiderFormingPlatoonL)
   *
   * What it does:
   * Validates one `CPlatoon` method call and returns whether arg#3 matches
   * the first element of arg#2 case-insensitively.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoonL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kCanConsiderFormingPlatoonHelpText,
        3,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    (void)SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaObject compareTable(LuaPlus::LuaStackObject(state, 2));
    const char* inputString = lua_tostring(state->m_state, 3);
    if (!inputString) {
      LuaPlus::LuaStackObject typeErrorArg(state, 3);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }

    std::string inputText(inputString ? inputString : "");
    LuaPlus::LuaObject compareObject = compareTable[1];
    const char* compareString = compareObject.GetString();

    const int compareResult = _memicmp(inputText.c_str(), compareString, inputText.size());
    lua_pushboolean(state->m_state, compareResult ? 0 : 1);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x00731690 (FUN_00731690, cfunc_CPlatoonDisbandOnIdle)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonDisbandOnIdleL`.
   */
  int cfunc_CPlatoonDisbandOnIdle(lua_State* const luaContext)
  {
    return cfunc_CPlatoonDisbandOnIdleL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731710 (FUN_00731710, cfunc_CPlatoonDisbandOnIdleL)
   *
   * What it does:
   * Resolves one `CPlatoon` object from Lua and sets its disband-on-idle flag.
   */
  int cfunc_CPlatoonDisbandOnIdleL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kDisbandOnIdleHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    runtimeView.mDisbandOnIdle = 1;
    return 0;
  }

  /**
   * Address: 0x007316B0 (FUN_007316B0, func_CPlatoonDisbandOnIdle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:DisbandOnIdle()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonDisbandOnIdle_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "DisbandOnIdle",
      &cfunc_CPlatoonDisbandOnIdle,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kDisbandOnIdleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731F00 (FUN_00731F00, cfunc_CPlatoonIsCommandsActive)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsCommandsActiveL`.
   */
  int cfunc_CPlatoonIsCommandsActive(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsCommandsActiveL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731F80 (FUN_00731F80, cfunc_CPlatoonIsCommandsActiveL)
   *
   * What it does:
   * Resolves `(platoon, commandsTable)` and returns true when any listed
   * command object is currently live.
   */
  int cfunc_CPlatoonIsCommandsActiveL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kIsCommandsActiveHelpText,
        2,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    (void)SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaObject commandsObject(LuaPlus::LuaStackObject(state, 2));
    const int commandCount = commandsObject.GetCount();
    for (int commandIndex = 1; commandIndex <= commandCount; ++commandIndex) {
      const LuaPlus::LuaObject commandObject = commandsObject[commandIndex];
      if (func_GetCUnitCommandOpt(commandObject, state)) {
        lua_pushboolean(state->m_state, 1);
        (void)lua_gettop(state->m_state);
        return 1;
      }
    }

    lua_pushboolean(state->m_state, 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x00731F20 (FUN_00731F20, func_CPlatoonIsCommandsActive_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsCommandsActive()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsCommandsActive_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsCommandsActive",
      &cfunc_CPlatoonIsCommandsActive,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsCommandsActiveHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E240 (FUN_0072E240, cfunc_CPlatoonIsAttacking)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsAttackingL`.
   */
  int cfunc_CPlatoonIsAttacking(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsAttackingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E260 (FUN_0072E260, func_CPlatoonIsAttacking_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsAttacking()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsAttacking_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsAttacking",
      &cfunc_CPlatoonIsAttacking,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsAttackingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E2C0 (FUN_0072E2C0, cfunc_CPlatoonIsAttackingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Attacking`.
   */
  int cfunc_CPlatoonIsAttackingL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIsAttackingHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Attacking);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072E3E0 (FUN_0072E3E0, cfunc_CPlatoonIsMoving)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsMovingL`.
   */
  int cfunc_CPlatoonIsMoving(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsMovingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E400 (FUN_0072E400, func_CPlatoonIsMoving_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsMoving()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsMoving_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsMoving",
      &cfunc_CPlatoonIsMoving,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsMovingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E460 (FUN_0072E460, cfunc_CPlatoonIsMovingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Moving`.
   */
  int cfunc_CPlatoonIsMovingL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIsMovingHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Moving);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072E580 (FUN_0072E580, cfunc_CPlatoonIsPatrolling)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsPatrollingL`.
   */
  int cfunc_CPlatoonIsPatrolling(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsPatrollingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E5A0 (FUN_0072E5A0, func_CPlatoonIsPatrolling_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsPatrolling()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsPatrolling_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsPatrolling",
      &cfunc_CPlatoonIsPatrolling,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsPatrollingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E600 (FUN_0072E600, cfunc_CPlatoonIsPatrollingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Patrolling`.
   */
  int cfunc_CPlatoonIsPatrollingL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIsPatrollingHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Patrolling);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072E720 (FUN_0072E720, cfunc_CPlatoonIsFerrying)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsFerryingL`.
   */
  int cfunc_CPlatoonIsFerrying(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsFerryingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E740 (FUN_0072E740, func_CPlatoonIsFerrying_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsFerrying()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsFerrying_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsFerrying",
      &cfunc_CPlatoonIsFerrying,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsFerryingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E7A0 (FUN_0072E7A0, cfunc_CPlatoonIsFerryingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Ferrying`.
   */
  int cfunc_CPlatoonIsFerryingL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIsFerryingHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Ferrying);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072C9B0 (FUN_0072C9B0, cfunc_CPlatoonGetPlatoonUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPlatoonUnitsL`.
   */
  int cfunc_CPlatoonGetPlatoonUnits(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonUnitsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C9D0 (FUN_0072C9D0, func_CPlatoonGetPlatoonUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonUnits_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonUnits",
      &cfunc_CPlatoonGetPlatoonUnits,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonUnitsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072CA30 (FUN_0072CA30, cfunc_CPlatoonGetPlatoonUnitsL)
   *
   * What it does:
   * Resolves one platoon and returns a cached Lua table containing all
   * currently tracked platoon units.
   */
  int cfunc_CPlatoonGetPlatoonUnitsL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetPlatoonUnitsHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      LuaPlus::LuaObject emptyUnits{};
      emptyUnits.AssignNewTable(state, 0, 0);
      emptyUnits.PushStack(state);
      return 1;
    }

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    if (runtimeView.mHasLuaList == 0u) {
      SEntitySetTemplateUnit platoonUnits{};
      BuildPlatoonUnitSet(runtimeView, platoonUnits);

      runtimeView.mLuaUnitList.AssignNewTable(state, static_cast<int>(platoonUnits.Size()), 0);
      std::int32_t luaIndex = 1;
      for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
        Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
        if (!unit) {
          continue;
        }

        LuaPlus::LuaObject unitObject = unit->GetLuaObject();
        runtimeView.mLuaUnitList.Insert(luaIndex, unitObject);
        ++luaIndex;
      }

      runtimeView.mHasLuaList = 1u;
    }

    runtimeView.mLuaUnitList.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072CC20 (FUN_0072CC20, func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanConsiderFormingPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanConsiderFormingPlatoon",
      &cfunc_CPlatoonCanConsiderFormingPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanConsiderFormingPlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072CE70 (FUN_0072CE70, cfunc_CPlatoonCanFormPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanFormPlatoonL`.
   */
  int cfunc_CPlatoonCanFormPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanFormPlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072CE90 (FUN_0072CE90, func_CPlatoonCanFormPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanFormPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanFormPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanFormPlatoon",
      &cfunc_CPlatoonCanFormPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanFormPlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072D870 (FUN_0072D870, cfunc_CPlatoonFormPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFormPlatoonL`.
   */
  int cfunc_CPlatoonFormPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFormPlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072D890 (FUN_0072D890, func_CPlatoonFormPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FormPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFormPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FormPlatoon",
      &cfunc_CPlatoonFormPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFormPlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E8C0 (FUN_0072E8C0, cfunc_CPlatoonSetPrioritizedTargetList)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonSetPrioritizedTargetListL`.
   */
  int cfunc_CPlatoonSetPrioritizedTargetList(lua_State* const luaContext)
  {
    return cfunc_CPlatoonSetPrioritizedTargetListL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E8E0 (FUN_0072E8E0, func_CPlatoonSetPrioritizedTargetList_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SetPrioritizedTargetList()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSetPrioritizedTargetList_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetPrioritizedTargetList",
      &cfunc_CPlatoonSetPrioritizedTargetList,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kSetPrioritizedTargetListHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072EB30 (FUN_0072EB30, cfunc_CPlatoonFindPrioritizedUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindPrioritizedUnitL`.
   */
  int cfunc_CPlatoonFindPrioritizedUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindPrioritizedUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072EB50 (FUN_0072EB50, func_CPlatoonFindPrioritizedUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindPrioritizedUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindPrioritizedUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindPrioritizedUnit",
      &cfunc_CPlatoonFindPrioritizedUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindPrioritizedUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072EDE0 (FUN_0072EDE0, cfunc_CPlatoonFindClosestUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindClosestUnitL`.
   */
  int cfunc_CPlatoonFindClosestUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindClosestUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072EE00 (FUN_0072EE00, func_CPlatoonFindClosestUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindClosestUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindClosestUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindClosestUnit",
      &cfunc_CPlatoonFindClosestUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindClosestUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F020 (FUN_0072F020, cfunc_CPlatoonFindClosestUnitToBase)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindClosestUnitToBaseL`.
   */
  int cfunc_CPlatoonFindClosestUnitToBase(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindClosestUnitToBaseL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F040 (FUN_0072F040, func_CPlatoonFindClosestUnitToBase_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindClosestUnitToBase()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindClosestUnitToBase_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindClosestUnitToBase",
      &cfunc_CPlatoonFindClosestUnitToBase,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindClosestUnitToBaseHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F290 (FUN_0072F290, cfunc_CPlatoonFindFurthestUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindFurthestUnitL`.
   */
  int cfunc_CPlatoonFindFurthestUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindFurthestUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F2B0 (FUN_0072F2B0, func_CPlatoonFindFurthestUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindFurthestUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindFurthestUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindFurthestUnit",
      &cfunc_CPlatoonFindFurthestUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindFurthestUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F4D0 (FUN_0072F4D0, cfunc_CPlatoonFindHighestValueUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindHighestValueUnitL`.
   */
  int cfunc_CPlatoonFindHighestValueUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindHighestValueUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F4F0 (FUN_0072F4F0, func_CPlatoonFindHighestValueUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindHighestValueUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindHighestValueUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindHighestValueUnit",
      &cfunc_CPlatoonFindHighestValueUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindHighestValueUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F790 (FUN_0072F790, cfunc_CPlatoonCanAttackTargetL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonCanAttackTargetL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, squadClass, targetUnit)`, finds the first squad in
   * the requested class, and forwards the target to `CSquad::CanAttackTarget`.
   * When the class is absent the Lua callback returns no values.
   */
  int cfunc_CPlatoonCanAttackTargetL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCanAttackTargetHelpText, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    CSquadRuntimeView* const squadView = FindSquadByClass(runtimeView, squadClass);
    if (squadView == nullptr) {
      return 0;
    }

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 3));
    Unit* const targetUnit = SCR_FromLua_Unit(targetObject);
    const bool canAttack = reinterpret_cast<CSquad*>(squadView)->CanAttackTarget(targetUnit);

    lua_pushboolean(state->m_state, canAttack ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072F710 (FUN_0072F710, cfunc_CPlatoonCanAttackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanAttackTargetL`.
   */
  int cfunc_CPlatoonCanAttackTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanAttackTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F730 (FUN_0072F730, func_CPlatoonCanAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanAttackTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanAttackTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanAttackTarget",
      &cfunc_CPlatoonCanAttackTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanAttackTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F940 (FUN_0072F940, cfunc_CPlatoonStop)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonStopL`.
   */
  int cfunc_CPlatoonStop(lua_State* const luaContext)
  {
    return cfunc_CPlatoonStopL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F9C0 (FUN_0072F9C0, cfunc_CPlatoonStopL)
   *
   * What it does:
   * Resolves `(platoon [, squadClass])` and dispatches `CPlatoon::Stop` with
   * default squad class `6` (all squads) when arg#2 is omitted.
   */
  int cfunc_CPlatoonStopL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kStopHelpText,
        1,
        2,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = kAllSquadsClass;
    if (argumentCount > 1) {
      gpg::RRef enumRef{};
      gpg::RRef_ESquadClass(&enumRef, &squadClass);

      const char* squadClassName = lua_tostring(state->m_state, 2);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 2);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }

      SCR_GetEnum(state, squadClassName, enumRef);
    }

    platoon->Stop(squadClass);
    return 0;
  }

  /**
   * Address: 0x0072F960 (FUN_0072F960, func_CPlatoonStop_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Stop()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonStop_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Stop",
      &cfunc_CPlatoonStop,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kStopHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072FAE0 (FUN_0072FAE0, cfunc_CPlatoonAttackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonAttackTargetL`.
   */
  int cfunc_CPlatoonAttackTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonAttackTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072FB00 (FUN_0072FB00, func_CPlatoonAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:AttackTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonAttackTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "AttackTarget",
      &cfunc_CPlatoonAttackTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kAttackTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072FDB0 (FUN_0072FDB0, cfunc_CPlatoonMoveToTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonMoveToTargetL`.
   */
  int cfunc_CPlatoonMoveToTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonMoveToTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072FDD0 (FUN_0072FDD0, func_CPlatoonMoveToTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:MoveToTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonMoveToTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "MoveToTarget",
      &cfunc_CPlatoonMoveToTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kMoveToTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007300A0 (FUN_007300A0, cfunc_CPlatoonMoveToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonMoveToLocationL`.
   */
  int cfunc_CPlatoonMoveToLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonMoveToLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007300C0 (FUN_007300C0, func_CPlatoonMoveToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:MoveToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonMoveToLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "MoveToLocation",
      &cfunc_CPlatoonMoveToLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kMoveToLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007303A0 (FUN_007303A0, cfunc_CPlatoonAggressiveMoveToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonAggressiveMoveToLocationL`.
   */
  int cfunc_CPlatoonAggressiveMoveToLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonAggressiveMoveToLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007303C0 (FUN_007303C0, func_CPlatoonAggressiveMoveToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:AggressiveMoveToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonAggressiveMoveToLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "AggressiveMoveToLocation",
      &cfunc_CPlatoonAggressiveMoveToLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kAggressiveMoveToLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00730680 (FUN_00730680, cfunc_CPlatoonFerryToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFerryToLocationL`.
   */
  int cfunc_CPlatoonFerryToLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFerryToLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007306A0 (FUN_007306A0, func_CPlatoonFerryToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FerryToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFerryToLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FerryToLocation",
      &cfunc_CPlatoonFerryToLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFerryToLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007308F0 (FUN_007308F0, cfunc_CPlatoonLoadUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonLoadUnitsL`.
   */
  int cfunc_CPlatoonLoadUnits(lua_State* const luaContext)
  {
    return cfunc_CPlatoonLoadUnitsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00730910 (FUN_00730910, func_CPlatoonLoadUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:LoadUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonLoadUnits_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "LoadUnits",
      &cfunc_CPlatoonLoadUnits,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kLoadUnitsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00730B10 (FUN_00730B10, cfunc_CPlatoonUnloadUnitsAtLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUnloadUnitsAtLocationL`.
   */
  int cfunc_CPlatoonUnloadUnitsAtLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUnloadUnitsAtLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00730B30 (FUN_00730B30, func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UnloadUnitsAtLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UnloadUnitsAtLocation",
      &cfunc_CPlatoonUnloadUnitsAtLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUnloadUnitsAtLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00730DB0 (FUN_00730DB0, cfunc_CPlatoonUnloadAllAtLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUnloadAllAtLocationL`.
   */
  int cfunc_CPlatoonUnloadAllAtLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUnloadAllAtLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00730DD0 (FUN_00730DD0, func_CPlatoonUnloadAllAtLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UnloadAllAtLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUnloadAllAtLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UnloadAllAtLocation",
      &cfunc_CPlatoonUnloadAllAtLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUnloadAllAtLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007312F0 (FUN_007312F0, cfunc_CPlatoonPatrol)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonPatrolL`.
   */
  int cfunc_CPlatoonPatrol(lua_State* const luaContext)
  {
    return cfunc_CPlatoonPatrolL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731310 (FUN_00731310, func_CPlatoonPatrol_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Patrol()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPatrol_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Patrol",
      &cfunc_CPlatoonPatrol,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kPatrolHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731020 (FUN_00731020, cfunc_CPlatoonGuardTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGuardTargetL`.
   */
  int cfunc_CPlatoonGuardTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGuardTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731040 (FUN_00731040, func_CPlatoonGuardTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GuardTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGuardTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GuardTarget",
      &cfunc_CPlatoonGuardTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGuardTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007314F0 (FUN_007314F0, cfunc_CPlatoonDestroy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonDestroyL`.
   */
  int cfunc_CPlatoonDestroy(lua_State* const luaContext)
  {
    return cfunc_CPlatoonDestroyL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731510 (FUN_00731510, func_CPlatoonDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Destroy()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonDestroy_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Destroy",
      &cfunc_CPlatoonDestroy,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kDestroyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007317C0 (FUN_007317C0, cfunc_CPlatoonGetFerryBeacons)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetFerryBeaconsL`.
   */
  int cfunc_CPlatoonGetFerryBeacons(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetFerryBeaconsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007317E0 (FUN_007317E0, func_CPlatoonGetFerryBeacons_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetFerryBeacons()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetFerryBeacons_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetFerryBeacons",
      &cfunc_CPlatoonGetFerryBeacons,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetFerryBeaconsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007319B0 (FUN_007319B0, cfunc_CPlatoonUseFerryBeacon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUseFerryBeaconL`.
   */
  int cfunc_CPlatoonUseFerryBeacon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUseFerryBeaconL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007319D0 (FUN_007319D0, func_CPlatoonUseFerryBeacon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UseFerryBeacon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUseFerryBeacon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UseFerryBeacon",
      &cfunc_CPlatoonUseFerryBeacon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUseFerryBeaconHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731C30 (FUN_00731C30, cfunc_CPlatoonUseTeleporter)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUseTeleporterL`.
   */
  int cfunc_CPlatoonUseTeleporter(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUseTeleporterL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731C50 (FUN_00731C50, func_CPlatoonUseTeleporter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UseTeleporter()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUseTeleporter_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UseTeleporter",
      &cfunc_CPlatoonUseTeleporter,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUseTeleporterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00732140 (FUN_00732140, cfunc_CPlatoonSetPlatoonFormationOverrideL)
   *
   * What it does:
   * Resolves `(platoon, formationName)` from Lua, maps `"None"` to empty text,
   * and stores the formation override lane.
   */
  int cfunc_CPlatoonSetPlatoonFormationOverrideL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kSetPlatoonFormationOverrideHelpText,
        2,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaStackObject formationArg(state, 2);
    const char* formationText = lua_tostring(state->m_state, 2);
    if (formationText == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&formationArg, "string");
      formationText = "";
    }

    msvc8::string formationOverride{};
    if (_stricmp(formationText, "None") != 0) {
      formationOverride.assign(formationText);
    }

    platoon->SetPlatoonFormationOverride(formationOverride);
    return 0;
  }

  /**
   * Address: 0x007320C0 (FUN_007320C0, cfunc_CPlatoonSetPlatoonFormationOverride)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonSetPlatoonFormationOverrideL`.
   */
  int cfunc_CPlatoonSetPlatoonFormationOverride(lua_State* const luaContext)
  {
    return cfunc_CPlatoonSetPlatoonFormationOverrideL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007320E0 (FUN_007320E0, func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SetPlatoonFormationOverride()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetPlatoonFormationOverride",
      &cfunc_CPlatoonSetPlatoonFormationOverride,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kSetPlatoonFormationOverrideHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007322D0 (FUN_007322D0, cfunc_CPlatoonGetPlatoonLifetimeStats)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPlatoonLifetimeStatsL`.
   */
  int cfunc_CPlatoonGetPlatoonLifetimeStats(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonLifetimeStatsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732350 (FUN_00732350, cfunc_CPlatoonGetPlatoonLifetimeStatsL)
   *
   * What it does:
   * Resolves one platoon and pushes its four persisted lifetime stat lanes, or
   * `nil` when the platoon object is absent.
   */
  int cfunc_CPlatoonGetPlatoonLifetimeStatsL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetPlatoonLifetimeStatsHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (platoon == nullptr) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    lua_pushnumber(state->m_state, static_cast<float>(runtimeView.mLifetimeStat1));
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, static_cast<float>(runtimeView.mLifetimeStat2));
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, runtimeView.mLifetimeStat3);
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, runtimeView.mLifetimeStat4);
    (void)lua_gettop(state->m_state);
    return 4;
  }

  /**
   * Address: 0x007322F0 (FUN_007322F0, func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonLifetimeStats()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonLifetimeStats",
      &cfunc_CPlatoonGetPlatoonLifetimeStats,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonLifetimeStatsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007324A0 (FUN_007324A0, cfunc_CPlatoonCalculatePlatoonThreat)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCalculatePlatoonThreatL`.
   */
  int cfunc_CPlatoonCalculatePlatoonThreat(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCalculatePlatoonThreatL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732520 (FUN_00732520, cfunc_CPlatoonCalculatePlatoonThreatL)
   *
   * What it does:
   * Resolves `(platoon, threatType, category)` and returns total threat across
   * live platoon units matching the requested category.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCalculatePlatoonThreatHelpText, 3, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaStackObject threatTypeArg(state, 2);
    const char* const threatTypeName = lua_tostring(state->m_state, 2);
    if (threatTypeName == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&threatTypeArg, "string");
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 3));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);
    const PlatoonThreatType threatType = ParsePlatoonThreatType(threatTypeName);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(runtimeView, platoonUnits);

    float totalThreat = 0.0f;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (!BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        continue;
      }

      totalThreat += ResolveBlueprintThreatValue(*unitBlueprint, threatType);
    }

    lua_pushnumber(state->m_state, totalThreat);
    return 1;
  }

  /**
   * Address: 0x007324C0 (FUN_007324C0, func_CPlatoonCalculatePlatoonThreat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CalculatePlatoonThreat()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCalculatePlatoonThreat_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CalculatePlatoonThreat",
      &cfunc_CPlatoonCalculatePlatoonThreat,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCalculatePlatoonThreatHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007328E0 (FUN_007328E0, cfunc_CPlatoonCalculatePlatoonThreatAroundPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL`.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732960 (FUN_00732960, cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL)
   *
   * What it does:
   * Resolves `(platoon, threatType, category, position, radius)` and returns
   * category-filtered threat from live platoon units within 2D radius.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 5) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kCalculatePlatoonThreatAroundPositionHelpText,
        5,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaStackObject threatTypeArg(state, 2);
    const char* const threatTypeName = lua_tostring(state->m_state, 2);
    if (threatTypeName == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&threatTypeArg, "string");
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 3));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 4));
    const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);
    const float radiusSq = ReadSquaredRadiusArg(state, 5);
    const PlatoonThreatType threatType = ParsePlatoonThreatType(threatTypeName);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(runtimeView, platoonUnits);

    float totalThreat = 0.0f;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const Wm3::Vector3f& unitPosition = unit->GetPosition();
      const float dx = position.x - unitPosition.x;
      const float dz = position.z - unitPosition.z;
      if ((dx * dx + dz * dz) > radiusSq) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (!BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        continue;
      }

      totalThreat += ResolveBlueprintThreatValue(*unitBlueprint, threatType);
    }

    lua_pushnumber(state->m_state, totalThreat);
    return 1;
  }

  /**
   * Address: 0x00732900 (FUN_00732900, func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CalculatePlatoonThreatAroundPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CalculatePlatoonThreatAroundPosition",
      &cfunc_CPlatoonCalculatePlatoonThreatAroundPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCalculatePlatoonThreatAroundPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00732E40 (FUN_00732E40, cfunc_CPlatoonPlatoonCategoryCountAroundPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonPlatoonCategoryCountAroundPositionL`.
   */
  int cfunc_CPlatoonPlatoonCategoryCountAroundPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonPlatoonCategoryCountAroundPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732EC0 (FUN_00732EC0, cfunc_CPlatoonPlatoonCategoryCountAroundPositionL)
   *
   * What it does:
   * Resolves `(platoon, category, position, radius)` and counts live platoon
   * units matching the category within 2D radius.
   */
  int cfunc_CPlatoonPlatoonCategoryCountAroundPositionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kPlatoonCategoryCountAroundPositionHelpText,
        4,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);
    LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 3));
    const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);
    const float radiusSq = ReadSquaredRadiusArg(state, 4);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(runtimeView, platoonUnits);

    int matchingCount = 0;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const Wm3::Vector3f& unitPosition = unit->GetPosition();
      const float dx = position.x - unitPosition.x;
      const float dz = position.z - unitPosition.z;
      if ((dx * dx + dz * dz) > radiusSq) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        ++matchingCount;
      }
    }

    lua_pushnumber(state->m_state, static_cast<float>(matchingCount));
    return 1;
  }

  /**
   * Address: 0x00732E60 (FUN_00732E60, func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:PlatoonCategoryCountAroundPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "PlatoonCategoryCountAroundPosition",
      &cfunc_CPlatoonPlatoonCategoryCountAroundPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kPlatoonCategoryCountAroundPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007331C0 (FUN_007331C0, cfunc_CPlatoonPlatoonCategoryCount)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonPlatoonCategoryCountL`.
   */
  int cfunc_CPlatoonPlatoonCategoryCount(lua_State* const luaContext)
  {
    return cfunc_CPlatoonPlatoonCategoryCountL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00733240 (FUN_00733240, cfunc_CPlatoonPlatoonCategoryCountL)
   *
   * What it does:
   * Resolves `(platoon, category)` and counts live platoon units matching
   * that category.
   */
  int cfunc_CPlatoonPlatoonCategoryCountL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kPlatoonCategoryCountHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(runtimeView, platoonUnits);

    int matchingCount = 0;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        ++matchingCount;
      }
    }

    lua_pushnumber(state->m_state, static_cast<float>(matchingCount));
    return 1;
  }

  /**
   * Address: 0x007331E0 (FUN_007331E0, func_CPlatoonPlatoonCategoryCount_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:PlatoonCategoryCount()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPlatoonCategoryCount_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "PlatoonCategoryCount",
      &cfunc_CPlatoonPlatoonCategoryCount,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kPlatoonCategoryCountHelpText
    );
    return &binder;
  }
} // namespace moho

namespace
{
  struct CPlatoonLuaBindingBootstrap
  {
    CPlatoonLuaBindingBootstrap()
    {
      (void)moho::register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();
      (void)moho::func_CPlatoonGetPlatoonUnits_LuaFuncDef();
      (void)moho::func_CPlatoonCanFormPlatoon_LuaFuncDef();
      (void)moho::func_CPlatoonFormPlatoon_LuaFuncDef();
      (void)moho::func_CPlatoonIsOpponentAIRunning_LuaFuncDef();
      (void)moho::func_CPlatoonDisbandOnIdle_LuaFuncDef();
      (void)moho::func_CPlatoonIsCommandsActive_LuaFuncDef();
      (void)moho::func_CPlatoonIsAttacking_LuaFuncDef();
      (void)moho::func_CPlatoonIsMoving_LuaFuncDef();
      (void)moho::func_CPlatoonIsPatrolling_LuaFuncDef();
      (void)moho::func_CPlatoonIsFerrying_LuaFuncDef();
      (void)moho::func_CPlatoonSetPrioritizedTargetList_LuaFuncDef();
      (void)moho::func_CPlatoonFindPrioritizedUnit_LuaFuncDef();
      (void)moho::func_CPlatoonFindClosestUnit_LuaFuncDef();
      (void)moho::func_CPlatoonFindClosestUnitToBase_LuaFuncDef();
      (void)moho::func_CPlatoonFindFurthestUnit_LuaFuncDef();
      (void)moho::func_CPlatoonFindHighestValueUnit_LuaFuncDef();
      (void)moho::func_CPlatoonCanAttackTarget_LuaFuncDef();
      (void)moho::func_CPlatoonStop_LuaFuncDef();
      (void)moho::func_CPlatoonAttackTarget_LuaFuncDef();
      (void)moho::func_CPlatoonMoveToTarget_LuaFuncDef();
      (void)moho::func_CPlatoonMoveToLocation_LuaFuncDef();
      (void)moho::func_CPlatoonAggressiveMoveToLocation_LuaFuncDef();
      (void)moho::func_CPlatoonFerryToLocation_LuaFuncDef();
      (void)moho::func_CPlatoonLoadUnits_LuaFuncDef();
      (void)moho::func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef();
      (void)moho::func_CPlatoonUnloadAllAtLocation_LuaFuncDef();
      (void)moho::func_CPlatoonPatrol_LuaFuncDef();
      (void)moho::func_CPlatoonGuardTarget_LuaFuncDef();
      (void)moho::func_CPlatoonDestroy_LuaFuncDef();
      (void)moho::func_CPlatoonGetFerryBeacons_LuaFuncDef();
      (void)moho::func_CPlatoonUseFerryBeacon_LuaFuncDef();
      (void)moho::func_CPlatoonUseTeleporter_LuaFuncDef();
      (void)moho::func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef();
      (void)moho::func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef();
      (void)moho::func_CPlatoonCalculatePlatoonThreat_LuaFuncDef();
      (void)moho::func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef();
      (void)moho::func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef();
      (void)moho::func_CPlatoonPlatoonCategoryCount_LuaFuncDef();
    }
  };

  [[maybe_unused]] CPlatoonLuaBindingBootstrap gCPlatoonLuaBindingBootstrap;
} // namespace
