#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/ArmyUnitSet.h"

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus
struct lua_State;

namespace gpg
{
  class RRef;
  class RType;
} // namespace gpg

namespace moho
{
  class CArmyImpl;
  class CScrLuaInitForm;
  class CSquad;
  class Entity;
  class IArmy;
  class Sim;
  class Unit;
  enum class ESquadClass : std::int32_t;
  enum EUnitState : std::int32_t;

  /**
   * Recovered `CPlatoon` runtime object.
   */
  class CPlatoon : public CScriptObject
  {
  public:
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x0072A300 (FUN_0072A300, Moho::CPlatoon::operator new)
     *
     * What it does:
     * Allocates one 0x110-byte platoon object and runs constructor lane
     * (`FUN_00724CC0`) with the provided ownership/plan names.
     */
    static CPlatoon* Create(Sim* sim, CArmyImpl* army, const char* platoonName, const char* aiPlan);

    /**
     * Address: 0x00724CC0 (FUN_00724CC0, Moho::CPlatoon::CPlatoon)
     *
     * What it does:
     * Constructs one script-backed platoon object, initializes squad/name
     * lanes, and dispatches script `OnCreate(plan)`.
     */
    CPlatoon(Sim* sim, CArmyImpl* army, const char* platoonName, const char* aiPlan);

    /**
     * Address: 0x00724EB0 (FUN_00724EB0, Moho::CPlatoon::~CPlatoon)
     *
     * What it does:
     * Destroys owned squad objects, clears dynamic squad storage back to inline
     * lanes, and decrements platoon instance counters.
     */
    ~CPlatoon() override;

    /**
     * Address: 0x00723AC0 (FUN_00723AC0, Moho::CPlatoon::GetClass)
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x00723AE0 (FUN_00723AE0, Moho::CPlatoon::GetDerivedObjectRef)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00729F90 (FUN_00729F90, Moho::CPlatoon::SquadHasState)
     *
     * What it does:
     * Returns whether the selected squad class (or all squads) contains at
     * least one unit with the requested unit state.
     */
    static bool SquadHasState(ESquadClass squadClass, CPlatoon* platoon, EUnitState state);

    /**
     * Address: 0x007251D0 (FUN_007251D0, Moho::CPlatoon::IsInPlatoon)
     *
     * What it does:
     * Returns whether the provided unit pointer is currently present in any
     * squad lane of this platoon.
     */
    bool IsInPlatoon(const Unit* unit) const;

    /**
     * Address: 0x00725220 (FUN_00725220, Moho::CPlatoon::GetSquadClass)
     *
     * What it does:
     * Scans all squad lanes and returns the class of the first squad
     * containing the provided unit; otherwise returns `SQUADCLASS_Unassigned`.
     */
    ESquadClass GetSquadClass(const Unit* unit) const;

    /**
     * Address: 0x00725630 (FUN_00725630, Moho::CPlatoon::GetSquad)
     *
     * What it does:
     * Returns the first squad lane matching `squadClass`, or null when absent.
     */
    CSquad* GetSquad(ESquadClass squadClass);

    /**
     * Address: 0x00725730 (FUN_00725730, Moho::CPlatoon::GetUnassignedUnitsWithBP)
     *
     * What it does:
     * Locates this platoon's `SQUADCLASS_Unassigned` squad and forwards to
     * `CSquad::AppendUnitsWithBP` to collect up to `maxCount` live units
     * matching `blueprintId` into `outUnits`. No-op when there is no
     * unassigned squad.
     */
    void GetUnassignedUnitsWithBP(const char* blueprintId, int maxCount, SEntitySetTemplateUnit& outUnits);

    /**
     * Address: 0x007261B0 (FUN_007261B0, Moho::CPlatoon::Stop)
     *
     * What it does:
     * Stops one requested squad lane (or all lanes) by clearing queued unit
     * commands and stopping active attacker controllers.
     */
    void Stop(ESquadClass squadClass);

    /**
     * Address: 0x00729FE0 (FUN_00729FE0, Moho::CPlatoon::SquadsHaveOrders)
     *
     * What it does:
     * Returns true when all assigned squad classes (1..5) are idle
     * (no active unit command in those lanes).
     */
    bool AssignedSquadsAreIdle() const;

    /**
     * Address: 0x00725150 (FUN_00725150, Moho::CPlatoon::SwitchAIPlan)
     *
     * What it does:
     * Replaces the active platoon AI plan string and dispatches
     * `OnDestroy/OnCreate` script callbacks when the plan actually changes.
     */
    void SwitchAIPlan(const char* planName);

    /**
     * Address: 0x00725410 (FUN_00725410, Moho::CPlatoon::PullUnassignedUnitsFrom)
     *
     * What it does:
     * Moves this platoon's currently owned unit set into the army-pool
     * unassigned lane and invalidates cached Lua unit lists.
     */
    void PullUnassignedUnitsFrom(CPlatoon* armyPool);

    /**
     * Address: 0x007253B0 (FUN_007253B0, Moho::CPlatoon::RemoveUnit)
     *
     * What it does:
     * Clears the cached Lua unit list flag, finds the squad that owns the
     * requested entity, and removes that unit from the first matching squad.
     */
    void RemoveUnit(Entity* unit);

  public:
    Sim* mSim;                                  // +0x34
    IArmy* mArmy;                               // +0x38
    std::uint32_t mUnknown_0x03C;               // +0x3C
    gpg::fastvector_n<CSquad*, 8> mSquadList;   // +0x40
    msvc8::string mName;                        // +0x70
    msvc8::string mPlan;                        // +0x8C
    msvc8::string mUniqueName;                  // +0xA8
    msvc8::string mFormation;                   // +0xC4
    std::uint8_t mDisbandOnIdle;                // +0xE0
    std::uint8_t mPad_0x0E1[3];                 // +0xE1
    std::int32_t mLifetimeStat1;                // +0xE4
    std::int32_t mLifetimeStat2;                // +0xE8
    float mLifetimeStat3;                       // +0xEC
    float mLifetimeStat4;                       // +0xF0
    LuaPlus::LuaObject mLuaUnitList;            // +0xF4
    std::uint8_t mHasLuaList;                   // +0x108
    std::uint8_t mPad_0x109[7];                 // +0x109
  };
  static_assert(offsetof(CPlatoon, mSim) == 0x34, "CPlatoon::mSim offset must be 0x34");
  static_assert(offsetof(CPlatoon, mArmy) == 0x38, "CPlatoon::mArmy offset must be 0x38");
  static_assert(offsetof(CPlatoon, mSquadList) == 0x40, "CPlatoon::mSquadList offset must be 0x40");
  static_assert(offsetof(CPlatoon, mName) == 0x70, "CPlatoon::mName offset must be 0x70");
  static_assert(offsetof(CPlatoon, mPlan) == 0x8C, "CPlatoon::mPlan offset must be 0x8C");
  static_assert(offsetof(CPlatoon, mUniqueName) == 0xA8, "CPlatoon::mUniqueName offset must be 0xA8");
  static_assert(offsetof(CPlatoon, mFormation) == 0xC4, "CPlatoon::mFormation offset must be 0xC4");
  static_assert(offsetof(CPlatoon, mDisbandOnIdle) == 0xE0, "CPlatoon::mDisbandOnIdle offset must be 0xE0");
  static_assert(offsetof(CPlatoon, mLifetimeStat1) == 0xE4, "CPlatoon::mLifetimeStat1 offset must be 0xE4");
  static_assert(offsetof(CPlatoon, mLifetimeStat2) == 0xE8, "CPlatoon::mLifetimeStat2 offset must be 0xE8");
  static_assert(offsetof(CPlatoon, mLifetimeStat3) == 0xEC, "CPlatoon::mLifetimeStat3 offset must be 0xEC");
  static_assert(offsetof(CPlatoon, mLifetimeStat4) == 0xF0, "CPlatoon::mLifetimeStat4 offset must be 0xF0");
  static_assert(offsetof(CPlatoon, mLuaUnitList) == 0xF4, "CPlatoon::mLuaUnitList offset must be 0xF4");
  static_assert(offsetof(CPlatoon, mHasLuaList) == 0x108, "CPlatoon::mHasLuaList offset must be 0x108");
  static_assert(sizeof(CPlatoon) == 0x110, "CPlatoon size must be 0x110");

  /**
   * Address: 0x00BDAE70 (FUN_00BDAE70, register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards startup registration to `func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();

  /**
   * Address: 0x0072B810 (FUN_0072B810, cfunc_CPlatoonIsOpponentAIRunning)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonIsOpponentAIRunningL`.
   */
  int cfunc_CPlatoonIsOpponentAIRunning(lua_State* luaContext);

  /**
   * Address: 0x0072B890 (FUN_0072B890, cfunc_CPlatoonIsOpponentAIRunningL)
   *
   * What it does:
   * Resolves one platoon and returns the `AI_RunOpponentAI` sim-convar state.
   */
  int cfunc_CPlatoonIsOpponentAIRunningL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072B830 (FUN_0072B830, func_CPlatoonIsOpponentAIRunning_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsOpponentAIRunning()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsOpponentAIRunning_LuaFuncDef();

  /**
   * Address: 0x0072B970 (FUN_0072B970, cfunc_CPlatoonGetPersonality)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPersonalityL`.
   */
  int cfunc_CPlatoonGetPersonality(lua_State* luaContext);

  /**
   * Address: 0x0072B9F0 (FUN_0072B9F0, cfunc_CPlatoonGetPersonalityL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning brain personality object, or
   * `nil` when personality is missing.
   */
  int cfunc_CPlatoonGetPersonalityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072B990 (FUN_0072B990, func_CPlatoonGetPersonality_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPersonality()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPersonality_LuaFuncDef();

  /**
   * Address: 0x0072BAD0 (FUN_0072BAD0, cfunc_CPlatoonGetBrain)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetBrainL`.
   */
  int cfunc_CPlatoonGetBrain(lua_State* luaContext);

  /**
   * Address: 0x0072BB50 (FUN_0072BB50, cfunc_CPlatoonGetBrainL)
   *
   * What it does:
   * Resolves one platoon and pushes its owning army-brain Lua object.
   */
  int cfunc_CPlatoonGetBrainL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072BAF0 (FUN_0072BAF0, func_CPlatoonGetBrain_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetBrain()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetBrain_LuaFuncDef();

  /**
   * Address: 0x0072BC10 (FUN_0072BC10, cfunc_CPlatoonGetFactionIndex)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetFactionIndexL`.
   */
  int cfunc_CPlatoonGetFactionIndex(lua_State* luaContext);

  /**
   * Address: 0x0072BC90 (FUN_0072BC90, cfunc_CPlatoonGetFactionIndexL)
   *
   * What it does:
   * Resolves one platoon and returns one-based faction index from the owning
   * army.
   */
  int cfunc_CPlatoonGetFactionIndexL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072BC30 (FUN_0072BC30, func_CPlatoonGetFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetFactionIndex()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetFactionIndex_LuaFuncDef();

  /**
   * Address: 0x0072BD60 (FUN_0072BD60, cfunc_CPlatoonUniquelyNamePlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonUniquelyNamePlatoonL`.
   */
  int cfunc_CPlatoonUniquelyNamePlatoon(lua_State* luaContext);

  /**
   * Address: 0x0072BD80 (FUN_0072BD80, func_CPlatoonUniquelyNamePlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UniquelyNamePlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUniquelyNamePlatoon_LuaFuncDef();

  /**
   * Address: 0x0072BDE0 (FUN_0072BDE0, cfunc_CPlatoonUniquelyNamePlatoonL)
   *
   * What it does:
   * Resolves `(platoon, uniqueName)` and stores the provided platoon unique
   * name when argument #2 is a string.
   */
  int cfunc_CPlatoonUniquelyNamePlatoonL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072BEF0 (FUN_0072BEF0, cfunc_CPlatoonGetPlatoonUniqueName)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetPlatoonUniqueNameL`.
   */
  int cfunc_CPlatoonGetPlatoonUniqueName(lua_State* luaContext);

  /**
   * Address: 0x0072BF10 (FUN_0072BF10, func_CPlatoonGetPlatoonUniqueName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonUniqueName()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonUniqueName_LuaFuncDef();

  /**
   * Address: 0x0072BF70 (FUN_0072BF70, cfunc_CPlatoonGetPlatoonUniqueNameL)
   *
   * What it does:
   * Resolves one platoon and pushes its unique-name string.
   */
  int cfunc_CPlatoonGetPlatoonUniqueNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072C040 (FUN_0072C040, cfunc_CPlatoonGetAIPlan)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetAIPlanL`.
   */
  int cfunc_CPlatoonGetAIPlan(lua_State* luaContext);

  /**
   * Address: 0x0072C060 (FUN_0072C060, func_CPlatoonGetAIPlan_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetAIPlan()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetAIPlan_LuaFuncDef();

  /**
   * Address: 0x0072C0C0 (FUN_0072C0C0, cfunc_CPlatoonGetAIPlanL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning army-brain AI-plan string.
   */
  int cfunc_CPlatoonGetAIPlanL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072C190 (FUN_0072C190, cfunc_CPlatoonSwitchAIPlan)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonSwitchAIPlanL`.
   */
  int cfunc_CPlatoonSwitchAIPlan(lua_State* luaContext);

  /**
   * Address: 0x0072C1B0 (FUN_0072C1B0, func_CPlatoonSwitchAIPlan_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SwitchAIPlan()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSwitchAIPlan_LuaFuncDef();

  /**
   * Address: 0x0072C210 (FUN_0072C210, cfunc_CPlatoonSwitchAIPlanL)
   *
   * What it does:
   * Resolves `(platoon, planName)` and switches AI plan when argument #2 is
   * a string.
   */
  int cfunc_CPlatoonSwitchAIPlanL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072C300 (FUN_0072C300, cfunc_CPlatoonGetPlatoonPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetPlatoonPositionL`.
   */
  int cfunc_CPlatoonGetPlatoonPosition(lua_State* luaContext);

  /**
   * Address: 0x0072C380 (FUN_0072C380, cfunc_CPlatoonGetPlatoonPositionL)
   *
   * What it does:
   * Resolves one platoon and returns the average world position of all units
   * currently present in its squad lanes.
   */
  int cfunc_CPlatoonGetPlatoonPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072C320 (FUN_0072C320, func_CPlatoonGetPlatoonPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonPosition_LuaFuncDef();

  /**
   * Address: 0x0072C5C0 (FUN_0072C5C0, cfunc_CPlatoonGetSquadPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetSquadPositionL`.
   */
  int cfunc_CPlatoonGetSquadPosition(lua_State* luaContext);

  /**
   * Address: 0x0072C640 (FUN_0072C640, cfunc_CPlatoonGetSquadPositionL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns the average world position
   * of units currently present in the selected squad.
   */
  int cfunc_CPlatoonGetSquadPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072C5E0 (FUN_0072C5E0, func_CPlatoonGetSquadPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetSquadPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetSquadPosition_LuaFuncDef();

  /**
   * Address: 0x0072C7D0 (FUN_0072C7D0, cfunc_CPlatoonGetSquadUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetSquadUnitsL`.
   */
  int cfunc_CPlatoonGetSquadUnits(lua_State* luaContext);

  /**
   * Address: 0x0072C850 (FUN_0072C850, cfunc_CPlatoonGetSquadUnitsL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns a Lua array of unit objects
   * for members currently present in the selected squad.
   */
  int cfunc_CPlatoonGetSquadUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072C7F0 (FUN_0072C7F0, func_CPlatoonGetSquadUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetSquadUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetSquadUnits_LuaFuncDef();

  /**
   * Address: 0x0072C9B0 (FUN_0072C9B0, cfunc_CPlatoonGetPlatoonUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPlatoonUnitsL`.
   */
  int cfunc_CPlatoonGetPlatoonUnits(lua_State* luaContext);

  /**
   * Address: 0x0072CA30 (FUN_0072CA30, cfunc_CPlatoonGetPlatoonUnitsL)
   *
   * What it does:
   * Resolves one platoon and returns a cached Lua table containing all
   * currently tracked platoon units.
   */
  int cfunc_CPlatoonGetPlatoonUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072CC00 (FUN_0072CC00, cfunc_CPlatoonCanConsiderFormingPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanConsiderFormingPlatoonL`.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoon(lua_State* luaContext);

  /**
   * Address: 0x0072CC80 (FUN_0072CC80, cfunc_CPlatoonCanConsiderFormingPlatoonL)
   *
   * What it does:
   * Validates one `CPlatoon` method call and returns whether arg#3 matches
   * the first element of arg#2 case-insensitively.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoonL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00731690 (FUN_00731690, cfunc_CPlatoonDisbandOnIdle)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonDisbandOnIdleL`.
   */
  int cfunc_CPlatoonDisbandOnIdle(lua_State* luaContext);

  /**
   * Address: 0x00731710 (FUN_00731710, cfunc_CPlatoonDisbandOnIdleL)
   *
   * What it does:
   * Resolves one `CPlatoon` object from Lua and sets its disband-on-idle flag.
   */
  int cfunc_CPlatoonDisbandOnIdleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007316B0 (FUN_007316B0, func_CPlatoonDisbandOnIdle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:DisbandOnIdle()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonDisbandOnIdle_LuaFuncDef();

  /**
   * Address: 0x00731F00 (FUN_00731F00, cfunc_CPlatoonIsCommandsActive)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsCommandsActiveL`.
   */
  int cfunc_CPlatoonIsCommandsActive(lua_State* luaContext);

  /**
   * Address: 0x00731F80 (FUN_00731F80, cfunc_CPlatoonIsCommandsActiveL)
   *
   * What it does:
   * Resolves `(platoon, commandsTable)` and returns whether any command object
   * in the table is currently live.
   */
  int cfunc_CPlatoonIsCommandsActiveL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00731F20 (FUN_00731F20, func_CPlatoonIsCommandsActive_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsCommandsActive()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsCommandsActive_LuaFuncDef();

  /**
   * Address: 0x0072E240 (FUN_0072E240, cfunc_CPlatoonIsAttacking)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsAttackingL`.
   */
  int cfunc_CPlatoonIsAttacking(lua_State* luaContext);

  /**
   * Address: 0x0072E2C0 (FUN_0072E2C0, cfunc_CPlatoonIsAttackingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` from Lua and returns whether the selected
   * squad has any unit currently in `UNITSTATE_Attacking`.
   */
  int cfunc_CPlatoonIsAttackingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072E260 (FUN_0072E260, func_CPlatoonIsAttacking_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsAttacking()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsAttacking_LuaFuncDef();

  /**
   * Address: 0x0072E3E0 (FUN_0072E3E0, cfunc_CPlatoonIsMoving)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsMovingL`.
   */
  int cfunc_CPlatoonIsMoving(lua_State* luaContext);

  /**
   * Address: 0x0072E460 (FUN_0072E460, cfunc_CPlatoonIsMovingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` from Lua and returns whether the selected
   * squad has any unit currently in `UNITSTATE_Moving`.
   */
  int cfunc_CPlatoonIsMovingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072E400 (FUN_0072E400, func_CPlatoonIsMoving_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsMoving()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsMoving_LuaFuncDef();

  /**
   * Address: 0x0072E580 (FUN_0072E580, cfunc_CPlatoonIsPatrolling)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsPatrollingL`.
   */
  int cfunc_CPlatoonIsPatrolling(lua_State* luaContext);

  /**
   * Address: 0x0072E600 (FUN_0072E600, cfunc_CPlatoonIsPatrollingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` from Lua and returns whether the selected
   * squad has any unit currently in `UNITSTATE_Patrolling`.
   */
  int cfunc_CPlatoonIsPatrollingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072E5A0 (FUN_0072E5A0, func_CPlatoonIsPatrolling_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsPatrolling()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsPatrolling_LuaFuncDef();

  /**
   * Address: 0x0072E720 (FUN_0072E720, cfunc_CPlatoonIsFerrying)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsFerryingL`.
   */
  int cfunc_CPlatoonIsFerrying(lua_State* luaContext);

  /**
   * Address: 0x0072E7A0 (FUN_0072E7A0, cfunc_CPlatoonIsFerryingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` from Lua and returns whether the selected
   * squad has any unit currently in `UNITSTATE_Ferrying`.
   */
  int cfunc_CPlatoonIsFerryingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072E740 (FUN_0072E740, func_CPlatoonIsFerrying_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsFerrying()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsFerrying_LuaFuncDef();

  /**
   * Address: 0x0072E8C0 (FUN_0072E8C0, cfunc_CPlatoonSetPrioritizedTargetList)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonSetPrioritizedTargetListL`.
   */
  int cfunc_CPlatoonSetPrioritizedTargetList(lua_State* luaContext);

  /**
   * Address: 0x0072E8E0 (FUN_0072E8E0, func_CPlatoonSetPrioritizedTargetList_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SetPrioritizedTargetList()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSetPrioritizedTargetList_LuaFuncDef();

  /**
   * Address: 0x0072EB30 (FUN_0072EB30, cfunc_CPlatoonFindPrioritizedUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindPrioritizedUnitL`.
   */
  int cfunc_CPlatoonFindPrioritizedUnit(lua_State* luaContext);

  /**
   * Address: 0x0072EB50 (FUN_0072EB50, func_CPlatoonFindPrioritizedUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindPrioritizedUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindPrioritizedUnit_LuaFuncDef();

  /**
   * Address: 0x0072EDE0 (FUN_0072EDE0, cfunc_CPlatoonFindClosestUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindClosestUnitL`.
   */
  int cfunc_CPlatoonFindClosestUnit(lua_State* luaContext);

  /**
   * Address: 0x0072EE00 (FUN_0072EE00, func_CPlatoonFindClosestUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindClosestUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindClosestUnit_LuaFuncDef();

  /**
   * Address: 0x0072F020 (FUN_0072F020, cfunc_CPlatoonFindClosestUnitToBase)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindClosestUnitToBaseL`.
  */
  int cfunc_CPlatoonFindClosestUnitToBase(lua_State* luaContext);

  /**
   * Address: 0x0072F040 (FUN_0072F040, func_CPlatoonFindClosestUnitToBase_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindClosestUnitToBase()` Lua binder form.
  */
  CScrLuaInitForm* func_CPlatoonFindClosestUnitToBase_LuaFuncDef();

  /**
   * Address: 0x0072F290 (FUN_0072F290, cfunc_CPlatoonFindFurthestUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindFurthestUnitL`.
   */
  int cfunc_CPlatoonFindFurthestUnit(lua_State* luaContext);

  /**
   * Address: 0x0072F2B0 (FUN_0072F2B0, func_CPlatoonFindFurthestUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindFurthestUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindFurthestUnit_LuaFuncDef();

  /**
   * Address: 0x0072CC20 (FUN_0072CC20, func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanConsiderFormingPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();

  /**
   * Address: 0x0072C9D0 (FUN_0072C9D0, func_CPlatoonGetPlatoonUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonUnits_LuaFuncDef();

  /**
   * Address: 0x0072CE90 (FUN_0072CE90, func_CPlatoonCanFormPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanFormPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanFormPlatoon_LuaFuncDef();

  /**
   * Address: 0x0072D890 (FUN_0072D890, func_CPlatoonFormPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FormPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFormPlatoon_LuaFuncDef();

  /**
   * Address: 0x0072F4D0 (FUN_0072F4D0, cfunc_CPlatoonFindHighestValueUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindHighestValueUnitL`.
   */
  int cfunc_CPlatoonFindHighestValueUnit(lua_State* luaContext);

  /**
   * Address: 0x0072F4F0 (FUN_0072F4F0, func_CPlatoonFindHighestValueUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindHighestValueUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindHighestValueUnit_LuaFuncDef();

  /**
   * Address: 0x0072F710 (FUN_0072F710, cfunc_CPlatoonCanAttackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanAttackTargetL`.
   */
  int cfunc_CPlatoonCanAttackTarget(lua_State* luaContext);

  /**
   * Address: 0x0072F730 (FUN_0072F730, func_CPlatoonCanAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanAttackTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanAttackTarget_LuaFuncDef();

  /**
   * Address: 0x0072FAE0 (FUN_0072FAE0, cfunc_CPlatoonAttackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonAttackTargetL`.
   */
  int cfunc_CPlatoonAttackTarget(lua_State* luaContext);

  /**
   * Address: 0x0072FB00 (FUN_0072FB00, func_CPlatoonAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:AttackTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonAttackTarget_LuaFuncDef();

  /**
   * Address: 0x0072FDB0 (FUN_0072FDB0, cfunc_CPlatoonMoveToTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonMoveToTargetL`.
   */
  int cfunc_CPlatoonMoveToTarget(lua_State* luaContext);

  /**
   * Address: 0x0072FDD0 (FUN_0072FDD0, func_CPlatoonMoveToTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:MoveToTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonMoveToTarget_LuaFuncDef();

  /**
   * Address: 0x0072F940 (FUN_0072F940, cfunc_CPlatoonStop)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonStopL`.
   */
  int cfunc_CPlatoonStop(lua_State* luaContext);

  /**
   * Address: 0x0072F960 (FUN_0072F960, func_CPlatoonStop_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Stop()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonStop_LuaFuncDef();

  /**
   * Address: 0x007300A0 (FUN_007300A0, cfunc_CPlatoonMoveToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonMoveToLocationL`.
   */
  int cfunc_CPlatoonMoveToLocation(lua_State* luaContext);

  /**
   * Address: 0x007300C0 (FUN_007300C0, func_CPlatoonMoveToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:MoveToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonMoveToLocation_LuaFuncDef();

  /**
   * Address: 0x007303A0 (FUN_007303A0, cfunc_CPlatoonAggressiveMoveToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonAggressiveMoveToLocationL`.
   */
  int cfunc_CPlatoonAggressiveMoveToLocation(lua_State* luaContext);

  /**
   * Address: 0x007303C0 (FUN_007303C0, func_CPlatoonAggressiveMoveToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:AggressiveMoveToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonAggressiveMoveToLocation_LuaFuncDef();

  /**
   * Address: 0x00730680 (FUN_00730680, cfunc_CPlatoonFerryToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFerryToLocationL`.
   */
  int cfunc_CPlatoonFerryToLocation(lua_State* luaContext);

  /**
   * Address: 0x007306A0 (FUN_007306A0, func_CPlatoonFerryToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FerryToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFerryToLocation_LuaFuncDef();

  /**
   * Address: 0x007308F0 (FUN_007308F0, cfunc_CPlatoonLoadUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonLoadUnitsL`.
   */
  int cfunc_CPlatoonLoadUnits(lua_State* luaContext);

  /**
   * Address: 0x00730910 (FUN_00730910, func_CPlatoonLoadUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:LoadUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonLoadUnits_LuaFuncDef();

  /**
   * Address: 0x00730B10 (FUN_00730B10, cfunc_CPlatoonUnloadUnitsAtLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUnloadUnitsAtLocationL`.
   */
  int cfunc_CPlatoonUnloadUnitsAtLocation(lua_State* luaContext);

  /**
   * Address: 0x00730B30 (FUN_00730B30, func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UnloadUnitsAtLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef();

  /**
   * Address: 0x00730DB0 (FUN_00730DB0, cfunc_CPlatoonUnloadAllAtLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUnloadAllAtLocationL`.
   */
  int cfunc_CPlatoonUnloadAllAtLocation(lua_State* luaContext);

  /**
   * Address: 0x00730DD0 (FUN_00730DD0, func_CPlatoonUnloadAllAtLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UnloadAllAtLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUnloadAllAtLocation_LuaFuncDef();

  /**
   * Address: 0x007312F0 (FUN_007312F0, cfunc_CPlatoonPatrol)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonPatrolL`.
   */
  int cfunc_CPlatoonPatrol(lua_State* luaContext);

  /**
   * Address: 0x00731310 (FUN_00731310, func_CPlatoonPatrol_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Patrol()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPatrol_LuaFuncDef();

  /**
   * Address: 0x00731020 (FUN_00731020, cfunc_CPlatoonGuardTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGuardTargetL`.
   */
  int cfunc_CPlatoonGuardTarget(lua_State* luaContext);

  /**
   * Address: 0x00731040 (FUN_00731040, func_CPlatoonGuardTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GuardTarget()` Lua binder form.
  */
  CScrLuaInitForm* func_CPlatoonGuardTarget_LuaFuncDef();

  /**
   * Address: 0x007314F0 (FUN_007314F0, cfunc_CPlatoonDestroy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonDestroyL`.
   */
  int cfunc_CPlatoonDestroy(lua_State* luaContext);

  /**
   * Address: 0x00731510 (FUN_00731510, func_CPlatoonDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Destroy()` Lua binder form.
  */
  CScrLuaInitForm* func_CPlatoonDestroy_LuaFuncDef();

  /**
   * Address: 0x007317C0 (FUN_007317C0, cfunc_CPlatoonGetFerryBeacons)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetFerryBeaconsL`.
   */
  int cfunc_CPlatoonGetFerryBeacons(lua_State* luaContext);

  /**
   * Address: 0x007317E0 (FUN_007317E0, func_CPlatoonGetFerryBeacons_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetFerryBeacons()` Lua binder form.
  */
  CScrLuaInitForm* func_CPlatoonGetFerryBeacons_LuaFuncDef();

  /**
   * Address: 0x007319B0 (FUN_007319B0, cfunc_CPlatoonUseFerryBeacon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUseFerryBeaconL`.
   */
  int cfunc_CPlatoonUseFerryBeacon(lua_State* luaContext);

  /**
   * Address: 0x007319D0 (FUN_007319D0, func_CPlatoonUseFerryBeacon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UseFerryBeacon()` Lua binder form.
  */
  CScrLuaInitForm* func_CPlatoonUseFerryBeacon_LuaFuncDef();

  /**
   * Address: 0x00731C30 (FUN_00731C30, cfunc_CPlatoonUseTeleporter)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUseTeleporterL`.
   */
  int cfunc_CPlatoonUseTeleporter(lua_State* luaContext);

  /**
   * Address: 0x00731C50 (FUN_00731C50, func_CPlatoonUseTeleporter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UseTeleporter()` Lua binder form.
  */
  CScrLuaInitForm* func_CPlatoonUseTeleporter_LuaFuncDef();

  /**
   * Address: 0x007320C0 (FUN_007320C0, cfunc_CPlatoonSetPlatoonFormationOverride)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonSetPlatoonFormationOverrideL`.
   */
  int cfunc_CPlatoonSetPlatoonFormationOverride(lua_State* luaContext);

  /**
   * Address: 0x007320E0 (FUN_007320E0, func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SetPlatoonFormationOverride()` Lua binder form.
  */
  CScrLuaInitForm* func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef();

  /**
   * Address: 0x007322D0 (FUN_007322D0, cfunc_CPlatoonGetPlatoonLifetimeStats)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPlatoonLifetimeStatsL`.
   */
  int cfunc_CPlatoonGetPlatoonLifetimeStats(lua_State* luaContext);

  /**
   * Address: 0x00732350 (FUN_00732350, cfunc_CPlatoonGetPlatoonLifetimeStatsL)
   *
   * What it does:
   * Resolves one platoon and pushes its four lifetime stat lanes.
   */
  int cfunc_CPlatoonGetPlatoonLifetimeStatsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007322F0 (FUN_007322F0, func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonLifetimeStats()` Lua binder form.
  */
  CScrLuaInitForm* func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef();

  /**
   * Address: 0x007324A0 (FUN_007324A0, cfunc_CPlatoonCalculatePlatoonThreat)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCalculatePlatoonThreatL`.
   */
  int cfunc_CPlatoonCalculatePlatoonThreat(lua_State* luaContext);

  /**
   * Address: 0x00732520 (FUN_00732520, cfunc_CPlatoonCalculatePlatoonThreatL)
   *
   * What it does:
   * Resolves `(platoon, threatType, category)` and returns total threat across
   * live platoon units matching the requested category.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007324C0 (FUN_007324C0, func_CPlatoonCalculatePlatoonThreat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CalculatePlatoonThreat()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCalculatePlatoonThreat_LuaFuncDef();

  /**
   * Address: 0x007328E0 (FUN_007328E0, cfunc_CPlatoonCalculatePlatoonThreatAroundPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL`.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPosition(lua_State* luaContext);

  /**
   * Address: 0x00732960 (FUN_00732960, cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL)
   *
   * What it does:
   * Resolves `(platoon, threatType, category, position, radius)` and returns
   * category-filtered threat from live platoon units within 2D radius.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00732900 (FUN_00732900, func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CalculatePlatoonThreatAroundPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef();

  /**
   * Address: 0x00732E40 (FUN_00732E40, cfunc_CPlatoonPlatoonCategoryCountAroundPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonPlatoonCategoryCountAroundPositionL`.
   */
  int cfunc_CPlatoonPlatoonCategoryCountAroundPosition(lua_State* luaContext);

  /**
   * Address: 0x00732EC0 (FUN_00732EC0, cfunc_CPlatoonPlatoonCategoryCountAroundPositionL)
   *
   * What it does:
   * Resolves `(platoon, category, position, radius)` and counts live platoon
   * units matching the category within 2D radius.
   */
  int cfunc_CPlatoonPlatoonCategoryCountAroundPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00732E60 (FUN_00732E60, func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:PlatoonCategoryCountAroundPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef();

  /**
   * Address: 0x007331C0 (FUN_007331C0, cfunc_CPlatoonPlatoonCategoryCount)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonPlatoonCategoryCountL`.
   */
  int cfunc_CPlatoonPlatoonCategoryCount(lua_State* luaContext);

  /**
   * Address: 0x00733240 (FUN_00733240, cfunc_CPlatoonPlatoonCategoryCountL)
   *
   * What it does:
   * Resolves `(platoon, category)` and counts live platoon units matching
   * that category.
   */
  int cfunc_CPlatoonPlatoonCategoryCountL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007331E0 (FUN_007331E0, func_CPlatoonPlatoonCategoryCount_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:PlatoonCategoryCount()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPlatoonCategoryCount_LuaFuncDef();
} // namespace moho
