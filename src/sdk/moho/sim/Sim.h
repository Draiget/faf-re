#pragma once

#include "../../gpg/core/reflection/Reflection.h"
#include "../../legacy/containers/String.h"
#include "../../legacy/containers/Vector.h"
#include "../command/ICommandSink.h"
#include "../resource/ISimResources.h"
#include "CDebugCanvas.h"
#include "CSimConVarInstanceBase.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/Rect2.h"
#include "legacy/containers/Deque.h"
#include "lua/LuaObject.h"
#include "moho/entity/Entity.h"
#include "moho/render/RDebugOverlay.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/task/CTaskThread.h"
#include "SDesyncInfo.h"
#include "SSyncFilter.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace moho
{
  class Shield;
  struct SPhysConstants;
  struct SSyncData;
  struct SUnitConstructionParams;
  class CDecalBuffer;
  class CCommandDb;
  class CEntityDb;
  class CAiFormationDBImpl;
  class CSimConVarBase;
  class Unit;
} // namespace moho

namespace moho
{
  // Keep local id aliases visible even when transitive Entity typedef visibility
  // is disrupted during partial IntelliSense parses.
  typedef std::int32_t EntId;
  typedef std::int32_t EntIdUniverse;

  class PathTables;
  class COGrid;
  class LuaState;
  class RRuleGameRules;
  class CSimResources;
  class STIMap;
  class SimArmy;
  class CArmyImpl;
  class CEffectManagerImpl;
  class CSimSoundManager;
  struct SParticleBuffer;
  struct SEntitySetTemplateUnit;
  class CScrLuaInitForm;

  class Sim final : public ICommandSink
  {
  public:
    // Destruction through base is expected to be possible.
    // Implemented in .cpp (even if empty), because base dtor is pure.
    ~Sim() = default;

    /**
     * Address: 0x00748650
     * @param sourceId
     */
    void SetCommandSource(CommandSourceId sourceId) override;

    /**
     * Address:0x007486B0
     */
    void OnCommandSourceTerminated() override;

    /**
     * Address: 0x007487C0 (FUN_007487C0, ?VerifyChecksum@Sim@Moho@@UAEXABVMD5Digest@gpg@@H@Z)
     *
     * What it does:
     * Validates one remote beat checksum against the local rolling hash ring,
     * records desync details on mismatch, and clears the cached desync log list.
     */
    void VerifyChecksum(const gpg::MD5Digest&, CSeqNo) override;

    /**
     * Address: 0x00748960
     */
    void RequestPause() override;

    /**
     * Address: 0x007489A0
     */
    void Resume() override;

    /**
     * Address: 0x007489C0
     */
    void SingleStep() override;

    /**
     * Address: 0x00748AA0 (FUN_00748AA0)
     *
     * unsigned int, Moho::RResId const &, Moho::SCoordsVec2 const &, float
     *
     * What it does:
     * Cheat-gated unit creation entrypoint that resolves blueprint and builds
     * `SUnitConstructionParams` for the internal construction path.
     */
    void CreateUnit(uint32_t, const RResId& blueprintId, const SCoordsVec2&, float) override;

    /**
     * Address: 0x00748C00 (FUN_00748C00)
     *
     * gpg::StrArg, Wm3::Vector3<float> const &
     *
     * IDA signature:
     * void __thiscall Moho::Sim::CreateProp(Moho::Sim *this, const char *blueprint, Wm3::Vector3f *pos);
     *
     * What it does:
     * Cheat-gated prop creation entry point. Builds identity transform at
     * the requested world position and forwards into PROP_Create chain.
     */
    void CreateProp(const char*, const Wm3::Vec3f&) override;

    /**
     * Address: 0x00748C80 (FUN_00748C80)
     *
     * What it does:
     * Looks up entity by id, validates command-source permissions, then invokes
     * `Entity::Destroy()` on the target.
     */
    void DestroyEntity(EntId) override;

    /**
     * Address: 0x00748CD0
     */
    void WarpEntity(EntId, const VTransform&) override;

    /**
     * Address: 0x00748D50 (FUN_00748D50, ?ProcessInfoPair@Sim@Moho@@UAEXVEntId@2@VStrArg@gpg@@1@Z)
     *
     * What it does:
     * Applies one UI/info key-value command to a controllable live unit.
     */
    void ProcessInfoPair(void* id, const char* key, const char* val) override;

    /**
     * Address: 0x00749290 (FUN_00749290)
     *
     * Moho::BVSet<Moho::EntId,Moho::EntIdUniverse> const &,Moho::SSTICommandIssueData const &,bool
     *
     * IDA signature:
     * char __userpurge Moho__Sim__IssueCommand@<al>(Moho::Sim *this@<ecx>, int esi0@<esi>, int *a3,
     * Moho::SSTICommandIssueData *commandIssueData, BOOL flag);
     *
     * What it does:
     * Validates command-id ownership, collects controllable units, and forwards
     * through UNIT_IssueCommand dispatch closure.
     */
    void
    IssueCommand(const BVSet<EntId, EntIdUniverse>&, const SSTICommandIssueData& commandIssueData, bool flag) override;

    /**
     * Address: 0x007494B0 (FUN_007494B0)
     *
     * What it does:
     * Validates command-id ownership, collects controllable factories, and
     * emits one shared command through the factory-dispatch lane.
     */
    void IssueFactoryCommand(
      const BVSet<EntId, EntIdUniverse>&, const SSTICommandIssueData& commandIssueData, bool
    ) override;

    /**
     * Address: 0x00749680
     */
    void IncreaseCommandCount(CmdId, int) override;

    /**
     * Address: 0x007496E0
     */
    void DecreaseCommandCount(CmdId, int) override;

    /**
     * Address: 0x00749740
     */
    void SetCommandTarget(CmdId, const SSTITarget&) override;

    /**
     * Address: 0x00749800
     */
    void SetCommandType(CmdId, EUnitCommandType) override;

    /**
     * Address: 0x00749860
     */
    void SetCommandCells(CmdId, gpg::core::FastVector<SOCellPos> const&, Wm3::Vector3<float> const&) override;

    /**
     * Address: 0x00749970
     */
    void RemoveCommandFromUnitQueue(CmdId, EntId) override;

    /**
     * Address: 0x00749A70
     */
    void ExecuteLuaInSim(const char*, const LuaPlus::LuaObject&) override;

    /**
     * Address: 0x00749B60 (FUN_00749B60, ?LuaSimCallback@Sim@Moho@@UAEXPBDABVLuaObject@LuaPlus@@ABV?$BVSet@HUEntIdUniverse@Moho@@@2@@Z)
     *
     * What it does:
     * Imports `/lua/SimCallbacks.lua` and invokes `DoCallback(name,args,units)`
     * with an optional selected-unit Lua table payload.
     */
    void LuaSimCallback(const char*, const LuaPlus::LuaObject&, const BVSet<EntId, EntIdUniverse>&) override;

    /**
     * Address: 0x00749DA0 (FUN_00749DA0)
     *
     * What it does:
     * Builds a temporary selected-unit entity set and forwards the command line
     * to the sim debug-command parser/dispatcher.
     */
    void
    ExecuteDebugCommand(const char*, Wm3::Vector3<float> const&, uint32_t, BVSet<EntId, EntIdUniverse> const&) override;

    /**
     * Address: 0x0070A4C0 (FUN_0070A4C0, Moho::Sim::SetArmyColor)
     *
     * IDA signature:
     * int __cdecl Moho::Sim::SetArmyColor(
     *   Moho::Sim* sim,
     *   std::vector<std::string>* commandArgs,
     *   Wm3::Vector3<float>* worldPos,
     *   Moho::CArmyImpl* focusArmy,
     *   Moho::SEntitySetTemplateUnit* selectedUnits);
     *
     * What it does:
     * Parses `SetArmyColor` sim-command args and writes packed color lanes
     * into the selected army's player/army color fields.
     */
    static int SetArmyColor(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x00651B00 (FUN_00651B00, Moho::Sim::dbg)
     *
     * What it does:
     * Toggles one debug overlay by name, or prints available overlays and
     * prefix-match diagnostics when selection is omitted/ambiguous.
     */
    static int dbg(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x006D17B0 (FUN_006D17B0, Moho::Sim::DebugSetConsumptionActive)
     *
     * What it does:
     * Enables upkeep consumption for each currently selected unit.
     */
    static int DebugSetConsumptionActive(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x006D17F0 (FUN_006D17F0, Moho::Sim::DebugSetConsumptionInActive)
     *
     * What it does:
     * Disables upkeep consumption for each currently selected unit.
     */
    static int DebugSetConsumptionInActive(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x006D1830 (FUN_006D1830, Moho::Sim::DebugSetProductionActive)
     *
     * What it does:
     * Marks selected units as production-active and dispatches
     * `OnProductionActive`.
     */
    static int DebugSetProductionActive(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x006D1880 (FUN_006D1880, Moho::Sim::DebugSetProductionInActive)
     *
     * What it does:
     * Marks selected units as production-inactive and dispatches
     * `OnProductionInActive`.
     */
    static int DebugSetProductionInActive(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x006D18D0 (FUN_006D18D0, Moho::Sim::DebugAIStatesOn)
     *
     * What it does:
     * Enables per-unit AI debug-state display for currently selected units.
     */
    static int DebugAIStatesOn(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x006D1900 (FUN_006D1900, Moho::Sim::DebugAIStatesOff)
     *
     * What it does:
     * Disables per-unit AI debug-state display for currently selected units and
     * clears published AI debug stats.
     */
    static int DebugAIStatesOff(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0075ED00 (FUN_0075ED00, Moho::Sim::TrackStats)
     *
     * What it does:
     * Parses `TrackStats <true|false|reset>` and either toggles selected-unit
     * tracking for the focus army or clears `RealTimeStats` for all armies.
     */
    static int TrackStats(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0075EE50 (FUN_0075EE50, Moho::Sim::DumpUnits)
     *
     * What it does:
     * Aggregates live units by `RUnitBlueprint*`, sorts by descending count,
     * and logs one `"<blueprintId> <count>"` line per entry.
     */
    static int DumpUnits(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0064BB80 (FUN_0064BB80, Moho::Sim::SallyShears)
     *
     * What it does:
     * Toggles fog-of-war visibility for every army recon database.
     */
    static int SallyShears(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0064BBE0 (FUN_0064BBE0, Moho::Sim::BlingBling)
     *
     * What it does:
     * Increases focus-army extra storage and credits current stored resources.
     */
    static int BlingBling(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0064BCA0 (FUN_0064BCA0, Moho::Sim::ZeroExtraStorage)
     *
     * What it does:
     * Resets focus-army extra storage deltas back to zero.
     */
    static int ZeroExtraStorage(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0064BF00 (FUN_0064BF00, Moho::Sim::AddImpulse)
     *
     * What it does:
     * Parses three impulse components, applies the impulse to each selected
     * unit's motion controller, and forces each unit into `LAYER_Air`.
     */
    static int AddImpulse(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x005C37B0 (FUN_005C37B0, Moho::Sim::ReconFlush)
     *
     * What it does:
     * Flushes recon databases for every army currently present in the sim.
     */
    static int ReconFlush(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x006B6B40 (FUN_006B6B40, Moho::Sim::KillAll)
     *
     * What it does:
     * Kills every unit in the requested armies, or every army when no army
     * indexes are supplied.
     */
    static int KillAll(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x006B6DC0 (FUN_006B6DC0, Moho::Sim::DestroyAll)
     *
     * What it does:
     * Destroys every unit in the requested armies, or every army when no army
     * indexes are supplied.
     */
    static int DestroyAll(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x00684D00 (FUN_00684D00, Moho::Sim::Purge)
     *
     * What it does:
     * Purges entities by category token (`all`, `entity`, `projectile`, `unit`,
     * `shield`, `other`, `prop`) and optional army index.
     */
    static int Purge(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0065E9D0 (FUN_0065E9D0, Moho::Sim::efx_NewEmitter)
     *
     * What it does:
     * Creates one emitter at the current world cursor when the command
     * includes a blueprint argument.
     */
    static int efx_NewEmitter(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0065EA50 (FUN_0065EA50, Moho::Sim::efx_AttachEmitter)
     *
     * What it does:
     * Resolves one bone name + emitter blueprint token list and attaches each
     * emitter token to every selected unit.
     */
    static int efx_AttachEmitter(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0066BD90 (FUN_0066BD90, func_AddLightParticle_SimConFunc)
     *
     * What it does:
     * Parses optional light-particle command args and dispatches
     * `IEffectManager::CreateLightParticle` at the cursor position.
     */
    static int AddLightParticle(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x00734F50 (FUN_00734F50, Moho::Sim::Log)
     *
     * What it does:
     * Joins command args #1..N with spaces and sends the joined text to
     * `gpg::Logf("%s", ...)`.
     */
    static int Log(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x00734FF0 (FUN_00734FF0, Moho::Sim::SimWarn)
     *
     * What it does:
     * Joins command args #1..N with spaces and sends the joined text to
     * `gpg::Warnf("%s", ...)`.
     */
    static int SimWarn(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x00735090 (FUN_00735090, Moho::Sim::SimError)
     *
     * What it does:
     * Joins command args #1..N with spaces and terminates via
     * `gpg::Die("%s", ...)`.
     */
    // Returns int (Lua C function ABI) but body always exits via gpg::Die.
    // Cannot be [[noreturn]] (C4646) — the attribute requires a void return.
    static int SimError(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x00699D20 (FUN_00699D20, Moho::Sim::sim_Gravity)
     *
     * Moho::Sim *, std::vector<msvc8::string> *
     *
     * What it does:
     * Prints the current gravity value, or parses a new scalar and writes it
     * into `mPhysConstants->mGravity.y` as a downward acceleration.
     */
    static int sim_Gravity(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x00735110 (FUN_00735110, Moho::Sim::SimAssert)
     *
     * What it does:
     * No-op debug command callback lane.
     */
    static int SimAssert(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x00735120 (FUN_00735120, Moho::Sim::SimCrash)
     *
     * What it does:
     * Triggers an intentional null-write crash for debug fault testing.
     */
    static int SimCrash(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0074B610 (FUN_0074B610, Moho::Sim::sim_DebugCrash)
     *
     * What it does:
     * Triggers an intentional null-write crash for debug fault testing.
     */
    static int sim_DebugCrash(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0074B3F0 (FUN_0074B3F0, Moho::Sim::ScenarioMethod)
     *
     * What it does:
     * Resolves one scenario script callback name from command args and calls
     * `ScenarioInfo.Env[name]` if present; warns when the callback is missing.
     */
    static int ScenarioMethod(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x007595C0 (FUN_007595C0, Moho::Sim::SimLua)
     *
     * What it does:
     * Builds one Lua expression from sim-command args #1..N, exposes the first
     * selected unit as global `__selected_unit`, executes the expression, then
     * clears `__selected_unit`.
     */
    static int SimLua(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x0075D860 (FUN_0075D860, Moho::Sim::DebugMoveCamera)
     *
     * What it does:
     * Builds and executes `DebugMoveCamera(x0,y0,x1,y1)` in Sim Lua using
     * command args #1..#4.
     */
    static int DebugMoveCamera(
      Sim* sim,
      CSimConCommand::ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    /**
     * Address: 0x00749F40
     */
    void AdvanceBeat(int) override;

    /**
     * Address: 0x0074B100 (FUN_0074B100, ?EndGame@Sim@Moho@@UAEXXZ)
     *
     * What it does:
     * Sets the game-ended latch used by sim-side game-over checks.
     */
    void EndGame() override;

    /**
     * Address: 0x005859B0 (FUN_005859B0, Moho::Sim::ArmyCount)
     *
     * What it does:
     * Returns the number of army slots currently present in `mArmiesList`.
     */
    [[nodiscard]] int ArmyCount() const;

    /**
     * Address: 0x007473B0 (FUN_007473B0, ?OkayToMessWith@Sim@Moho@@QAE_NPAVCUnitCommand@2@@Z)
     *
     * What it does:
     * Validates every unit in a command unit-set against command-source access
     * rules, with cheat fallback for invalid/forbidden entries.
     */
    bool OkayToMessWith(CUnitCommand* cmd);

    /**
     * Address: 0x00747320 (FUN_00747320, ?OkayToMessWith@Sim@Moho@@QAE_NPAVSimArmy@2@@Z)
     *
     * What it does:
     * Allows access to one army when it is in-game and the current command
     * source is whitelisted; otherwise defers to cheat gating.
     */
    bool OkayToMessWith(SimArmy* army);

    /**
     * Address: 0x00747360 (FUN_00747360, ?OkayToMessWith@Sim@Moho@@QAE_NPAVEntity@2@@Z)
     *
     * What it does:
     * Resolves entity owner army and applies the same command-source policy as
     * `OkayToMessWith(SimArmy*)`.
     */
    bool OkayToMessWith(Entity* entity);

    /**
     * Address: 0x00747460 (FUN_00747460)
     *
     * Moho::CSimConVarBase *
     *
     * IDA signature:
     * Moho::CSimConVarInstanceBase *__usercall Moho::Sim::GetSimVar@<eax>(Moho::Sim *this@<edi>, Moho::CSimConVarBase
     * *var@<ebx>);
     *
     * What it does:
     * Resolves (and lazily allocates) the Sim convar instance slot indexed by `var->mIndex`.
     */
    CSimConVarInstanceBase* GetSimVar(CSimConVarBase* var);

    [[nodiscard]]
    LuaPlus::LuaState* GetLuaState() const noexcept;

    /**
     * Address: 0x00545A40 (FUN_00545A40, ?GetResources@Sim@Moho@@QBEPBVISimResources@2@XZ)
     *
     * What it does:
     * Returns the currently bound simulation resources interface lane.
     */
    [[nodiscard]] const ISimResources* GetResources() const;

    /**
     * Address: 0x00746280 (FUN_00746280, ?Logf@Sim@Moho@@QAAXPBDZZ)
     *
     * What it does:
     * Writes formatted text to the current sim log file when logging is enabled.
     */
    void Logf(const char* fmt, ...);

    /**
     * Address: 0x007462A0 (FUN_007462A0, ?Printf@Sim@Moho@@QAAXPBDZZ)
     *
     * What it does:
     * Formats a message and appends it to the pending sim print-line buffer.
     */
    void Printf(const char* fmt, ...);

    /**
     * Address: 0x007464D0 (FUN_007464D0, ?PostInitialize@Sim@Moho@@QAEXABVLuaObject@LuaPlus@@@Z)
     *
     * What it does:
     * Checks launch option `PrebuiltUnits`; when enabled (`"On"`), calls the
     * global Lua function `InitializePrebuiltUnits` once for each non-civilian
     * army using the army name string.
     */
    void PostInitialize(const LuaPlus::LuaObject& launchOptions);

    /**
     * Address: 0x00746720 (FUN_00746720, ?GetDebugCanvas@Sim@Moho@@QAEPAVCDebugCanvas@2@XZ)
     *
     * What it does:
     * Returns the active beat debug canvas, allocating it lazily on first use.
     */
    CDebugCanvas* GetDebugCanvas();

    /**
     * Address: 0x007467F0 (FUN_007467F0, ?RegisterEntitySet@Sim@Moho@@QAEXPAVEntitySetBase@2@@Z)
     *
     * What it does:
     * Registers one entity-set intrusive node in the sim EntityDB set registry.
     */
    void RegisterEntitySet(EntitySetBase* set);

    /**
     * Address: 0x00746820 (FUN_00746820, ?GetParticleBuffer@Sim@Moho@@QAEPAUSParticleBuffer@2@XZ)
     *
     * What it does:
     * Returns the shared particle buffer, allocating and binding it lazily on
     * first use.
     */
    SParticleBuffer* GetParticleBuffer();

    /**
     * Address: 0x007474B0 (FUN_007474B0)
     *
     * What it does:
     * Produces one sync packet for the current frame using the supplied sync filter.
     *
     * Recovery status:
     * Partial lift. Current implementation preserves filter-transfer semantics and
     * publishes minimal beat packet data until full sync-body recovery.
     */
    void Sync(const SSyncFilter& filter, SSyncData*& outSyncData);

    /**
     * Address: 0x0074AFB0 (FUN_0074AFB0, ?SaveState@Sim@Moho@@QAEXAAVWriteArchive@gpg@@@Z)
     *
     * What it does:
     * Verifies save mode is allowed and serializes this `Sim` into the provided write archive.
     */
    void SaveState(gpg::WriteArchive* archive);

    /**
     * Address: 0x007457F0 (FUN_007457F0, ?Shutdown@Sim@Moho@@QAEXXZ)
     *
     * What it does:
     * Destroys live units, drains the deferred deletion queue, shuts down the
     * sim sound manager, and latches `mDidProcess`.
     */
    void Shutdown();

    /**
     * Runtime bridge for recovered Lua registration paths that need unit
     * construction through `SUnitConstructionParams`.
     */
    [[nodiscard]] Unit* CreateUnitForScript(const SUnitConstructionParams& params, bool doCallback);

  private:
    /**
     * Address: 0x0074ADB0 (FUN_0074ADB0, ?FlushLog@Sim@Moho@@AAEXXZ)
     *
     * What it does:
     * Rotates the active sim checksum log file, trims stale retained log files,
     * and opens the beat-scoped log file for the current beat.
     */
    void FlushLog();

    /**
     * Address: 0x007489E0 (FUN_007489E0)
     *
     * Moho::SUnitConstructionParams const &, bool
     *
     * IDA signature:
     * Moho::Unit *__userpurge Moho::Sim::CreateUnit@<eax>(Moho::SUnitConstructionParams *params@<esi>, char
     * doCallback);
     *
     * What it does:
     * Applies unit-cap checks and constructs the runtime Unit object.
     */
    Unit* CreateUnit(const SUnitConstructionParams& params, bool doCallback);

  public:
    /**
     * Address: 0x00747180
     */
    bool CheatsEnabled();

    /**
     * Address: 0x007466D0 (FUN_007466D0, ?GetCurrentCommandSource@Sim@Moho@@QBEPBUSSTICommandSource@2@XZ)
     *
     * What it does:
     * Returns the current command-source lane, or `nullptr` for sentinel id.
     */
    [[nodiscard]] const SSTICommandSource* GetCurrentCommandSource() const;

    /**
     * Address: 0x007466F0 (FUN_007466F0, ?GetCurrentCommandSourceName@Sim@Moho@@QBEPBDXZ)
     *
     * What it does:
     * Returns current command-source display name, or `"???"` when the source
     * sentinel is active.
     */
    const char* GetCurrentCommandSourceName() const;

    /**
     * Address: 0x0062CBD0 (FUN_0062CBD0, ?CenterOfMap@Sim@Moho@@QBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns the terrain-grid center of the current map using the backing
     * heightfield dimensions, with zero Y.
     */
    [[nodiscard]] Wm3::Vec3f CenterOfMap() const;

  private:
    /**
     * Address: 0x007491C0
     */
    bool ValidateNewCommandId(CmdId cmdId, const char* callsiteName) const;

    /**
     * Address: 0x00734870 (FUN_00734870, func_TryParseSimCommand)
     *
     * What it does:
     * Parses one or more sim debug command segments, resolves each segment
     * through the sim-console registry, applies cheat gating, and dispatches
     * command handlers.
     */
    void TryParseSimCommand(
      const char* command,
      const Wm3::Vector3<float>& worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit& selectedUnits
    );

    /**
     * Address: 0x005C3710 (FUN_005C3710)
     *
     * What it does:
     * Refreshes command/visibility blips for the active sim frame.
     */
    void RefreshBlips();

    /**
     * Address: 0x0074A640 (FUN_0074A640)
     *
     * What it does:
     * Rebuilds the per-beat simulation checksum digest.
     */
    void UpdateChecksum();

    /**
     * Address: 0x00754C60 (FUN_00754C60, sub_754C60)
     *
     * What it does:
     * Core Sim load-serialization routine used by Sim serializer callback.
     */
    void SerializeLoadBody(gpg::ReadArchive* archive);

    /**
     * Address: 0x00745020 (FUN_00745020, ?SerMapData@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
     *
     * What it does:
     * Serializes `mMapData->mPlayableRect`, then writes the internal loaded
     * `Rect2i` vector lane as count + element records.
     */
    void SerMapData(gpg::WriteArchive* archive);

    /**
     * Address: 0x00745120 (FUN_00745120, ?SerMapData@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
     *
     * What it does:
     * Reads playable map rectangle data from archive, applies it to `mMapData`,
     * and refreshes the two internal cached `Rect2i` vector lanes.
     */
    void SerMapData(gpg::ReadArchive* archive);

    /**
     * Address: 0x007452B0 (FUN_007452B0, ?SerArmies@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
     *
     * What it does:
     * Serializes owned army pointers from `mArmiesList` as count + owned
     * `SimArmy` raw-pointer entries.
     */
    void SerArmies(gpg::WriteArchive* archive);

    /**
     * Address: 0x00745330 (FUN_00745330, ?SerArmies@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
     *
     * What it does:
     * Reads owned army pointers from archive into `mArmiesList` using
     * archive-count resize + per-entry owned pointer load.
     */
    void SerArmies(gpg::ReadArchive* archive);

    /**
     * Address: 0x007456D0 (FUN_007456D0, ?SerDirtyEnts@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
     *
     * What it does:
     * Writes one unowned entity-pointer chain from `mCoordEntities` and
     * terminates the stream with a null entity sentinel.
     */
    void SerDirtyEnts(gpg::WriteArchive* archive);

    /**
     * Address: 0x00745760 (FUN_00745760, ?SerDirtyEnts@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
     *
     * What it does:
     * Reads one unowned entity-pointer chain and relinks each entity's
     * `mCoordNode` into `mCoordEntities` until a null sentinel is reached.
     */
    void SerDirtyEnts(gpg::ReadArchive* archive);

    /**
     * Address: 0x00745390 (FUN_00745390, ?SerVars@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
     *
     * What it does:
     * Serializes active sim-convar pairs as `(name, lexical value)` strings,
     * followed by an empty-name sentinel.
     */
    void SerVars(gpg::WriteArchive* archive);

    /**
     * Address: 0x007551C0 (FUN_007551C0)
     *
     * What it does:
     * Core Sim save-serialization routine used by Sim serializer callback.
     */
    void SerializeSaveBody(gpg::WriteArchive* archive);

    // CArmyImpl binary methods read several Sim internals directly (same pattern as retail layout codepaths).
    friend class CArmyImpl;
    friend void SimSerializerLoadThunk(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*);
    friend void SimSerializerSaveThunk(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*);

  public:
    static gpg::RType* sType;

    msvc8::string mLogFilePrefix;
    std::FILE* mLog;
    msvc8::string mDesyncLogLine;
    msvc8::list<msvc8::string> mDesyncLogLines;
    bool mIsDesyncFree; // 0x4C

    gpg::MD5Context mContext;
    gpg::MD5Digest mSimHashes[128];
    msvc8::vector<SDesyncInfo> mDesyncs;
    CEffectManagerImpl* mEffectManager; // 0x08C0
    CSimSoundManager* mSoundManager;    // 0x08C4
    RRuleGameRules* mRules;             // 0x08C8
    STIMap* mMapData;                   // 0x08CC

    boost::SharedPtrRaw<CSimResources> mSimResources; // 0x08D0..0x08D7 (px, pi)
    LuaPlus::LuaState* mLuaState;
    bool mGameEnded;
    bool mGameOver;
    int32_t mPausedByCommandSource;
    bool mSingleStep;       // 0x8E4
    bool mAdvancedThisTick; // 0x8E5
    bool mCheatsEnabled;    // 0x8E6
    bool mReserved8E7;
    msvc8::vector<int> mCheaters;
    uint32_t mCurBeat; // 0x08F8
    // +0x08FC in binary: set in AdvanceBeat, cleared in Sync.
    // Acts as a "processed this beat" latch rather than beat counter state.
    bool mDidProcess;
    uint32_t mCurTick;                                // 0x0900
    CRandomStream* mRngState;                         // 0x0904
    COGrid* mOGrid;                                   // 0x0908
    msvc8::vector<CArmyImpl*> mArmiesList;            // 0x090C
    msvc8::vector<SSTICommandSource> mCommandSources; // 0x091C
    int32_t mCurCommandSource;                        // 0x092C
    CTaskStage mTaskStageA;
    CTaskStage mDiskWatcherTaskStage;
    CTaskStage mTaskStageB;
    boost::shared_ptr<CDebugCanvas> mDebugCanvas1;
    boost::shared_ptr<CDebugCanvas> mDebugCanvas2;
    PathTables* mPathTables;
    CAiFormationDBImpl* mFormationDB; // 0x0980
    CCommandDb* mCommandDB;           // 0x0984
    CEntityDb* mEntityDB;             // 0x0988
    uint32_t mReserved98C;
    uint32_t mReserved990;
    boost::shared_ptr<SParticleBuffer> mParticleBuffer;
    CDecalBuffer* mDecalBuffer;
    TDatList<RDebugOverlay, void> mDebugOverlays;
    msvc8::vector<CSimConVarInstanceBase*> mSimVars;
    msvc8::vector<void*> mSyncSerializeGroup0;
    msvc8::vector<void*> mSyncSerializeGroup1;
    msvc8::vector<void*> mSyncSerializeGroup3;
    msvc8::vector<void*> mSyncSerializeGroup4;
    gpg::Rect2i mPlayableRect1;
    gpg::Rect2i mPlayableRect2;
    msvc8::vector<msvc8::string> mPrintField;
    msvc8::vector<void*> mSyncSerializeGroup2;
    SPhysConstants* mPhysConstants;
    msvc8::list<Shield*> mShields;
    msvc8::deque<void*> mDeletionQueue;
    // 0x0A5C..0x0A63 intrusive list head (`mPrev` @ 0x0A5C, `mNext` @ 0x0A60).
    TDatList<Entity, void> mCoordEntities;
    bool mRequestXMLArmyStatsSubmit; // 0x0A64
    // 0x0A65..0x0A67: padding (int32 alignment)
    int32_t mSyncArmy; // 0x0A68
    bool mDidSync;     // 0x0A6C
    // 0x0A6D..0x0A6F: padding (int32 alignment)
    // Sync packing reservation counters captured from the previous frame.
    // Used by helper calls from Sim::Sync (0x00560A00 / 0x00560940).
    int32_t mSyncReserveCounts[5]; // 0x0A70..0x0A83 (elements at +0x0A70,+0x0A74,+0x0A78,+0x0A7C,+0x0A80)
    int32_t mSyncReserveUnused;    // 0x0A84 (observed initialized, not yet referenced)
    SSyncFilter mSyncFilter;       // 0x0A88..0x0AF7
  };

  /**
   * Address: 0x0074B570 (FUN_0074B570, cfunc_printSim)
   *
   * lua_State *
   *
   * What it does:
   * Concatenates Lua print arguments and emits one line into sim print/log
   * output.
   */
  int cfunc_printSim(lua_State* luaContext);

  /**
   * Address: 0x0074B590 (FUN_0074B590, func_printSim_LuaFuncDef)
   *
   * What it does:
   * Publishes global `print(...)` Lua binder in the sim init set.
   */
  CScrLuaInitForm* func_printSim_LuaFuncDef();

  /**
   * Address: 0x0074B620 (FUN_0074B620, cfunc_CheatsEnabled)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CheatsEnabledL`.
   */
  int cfunc_CheatsEnabled(lua_State* luaContext);

  /**
   * Address: 0x0074B640 (FUN_0074B640, func_CheatsEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes global `CheatsEnabled()` Lua binder in the sim init set.
   */
  CScrLuaInitForm* func_CheatsEnabled_LuaFuncDef();

  /**
   * Address: 0x0074B6A0 (FUN_0074B6A0, cfunc_CheatsEnabledL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates no Lua args and returns `Sim::CheatsEnabled()` as a boolean.
   */
  int cfunc_CheatsEnabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0074B710 (FUN_0074B710, cfunc_GetCurrentCommandSource)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_GetCurrentCommandSourceL`.
   */
  int cfunc_GetCurrentCommandSource(lua_State* luaContext);

  /**
   * Address: 0x0074B730 (FUN_0074B730, func_GetCurrentCommandSource_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetCurrentCommandSource()` Lua binder in the sim init
   * set.
   */
  CScrLuaInitForm* func_GetCurrentCommandSource_LuaFuncDef();

  /**
   * Address: 0x0074B790 (FUN_0074B790, cfunc_GetCurrentCommandSourceL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns the current command source index as 1-based Lua number, or nil
   * when no source is active.
   */
  int cfunc_GetCurrentCommandSourceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0074B830 (FUN_0074B830, cfunc_EndGame)
   * Address: 0x0128F085 (FUN_0128F085 thunk)
   *
   * lua_State *
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_EndGameL`.
   */
  int cfunc_EndGame(lua_State* luaContext);

  /**
   * Address: 0x0128C8F0 (FUN_0128C8F0, cfunc_EndGameL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates argument count, then marks the active sim as ended.
   */
  int cfunc_EndGameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0074B900 (FUN_0074B900, cfunc_IsGameOver)
   *
   * lua_State *
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_IsGameOverL`.
   */
  int cfunc_IsGameOver(lua_State* luaContext);

  /**
   * Address: 0x0074B980 (FUN_0074B980, cfunc_IsGameOverL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes whether the active sim has entered end-game state.
   */
  int cfunc_IsGameOverL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075A600 (FUN_0075A600, cfunc_GenerateRandomOrientationL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Samples four Gaussian random lanes from `Sim::mRandom`, normalizes the
   * quaternion, and returns it to Lua.
   */
  int cfunc_GenerateRandomOrientationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075A5A0 (FUN_0075A5A0, func_GenerateRandomOrientation_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GenerateRandomOrientation()` Lua binder.
   */
  CScrLuaInitForm* func_GenerateRandomOrientation_LuaFuncDef();

  /**
   * Address: 0x0075A580 (FUN_0075A580, cfunc_GenerateRandomOrientation)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GenerateRandomOrientationL`.
   */
  int cfunc_GenerateRandomOrientation(lua_State* luaContext);

  /**
   * Address: 0x0075A770 (FUN_0075A770, cfunc_GetGameTimeSecondsSim)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetGameTimeSecondsSimL`.
   */
  int cfunc_GetGameTimeSecondsSim(lua_State* luaContext);

  /**
   * Address: 0x0075A790 (FUN_0075A790, func_GetGameTimeSecondsSim_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetGameTimeSeconds()` Lua binder in the sim init set.
   */
  CScrLuaInitForm* func_GetGameTimeSecondsSim_LuaFuncDef();

  /**
   * Address: 0x0075A7F0 (FUN_0075A7F0, cfunc_GetGameTimeSecondsSimL)
   *
   * What it does:
   * Validates no Lua args and returns simulation time in seconds.
   */
  int cfunc_GetGameTimeSecondsSimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075A860 (FUN_0075A860, cfunc_GetGameTick)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetGameTickL`.
   */
  int cfunc_GetGameTick(lua_State* luaContext);

  /**
   * Address: 0x0075A880 (FUN_0075A880, func_GetGameTick_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetGameTick()` Lua binder in the sim init set.
   */
  CScrLuaInitForm* func_GetGameTick_LuaFuncDef();

  /**
   * Address: 0x0075A8E0 (FUN_0075A8E0, cfunc_GetGameTickL)
   *
   * What it does:
   * Validates no Lua args and returns simulation tick count.
   */
  int cfunc_GetGameTickL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075A950 (FUN_0075A950, cfunc_GetSystemTimeSecondsOnlyForProfileUse)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetSystemTimeSecondsOnlyForProfileUseL`.
   */
  int cfunc_GetSystemTimeSecondsOnlyForProfileUse(lua_State* luaContext);

  /**
   * Address: 0x0075A970 (FUN_0075A970, func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetSystemTimeSecondsOnlyForProfileUse()` Lua binder in
   * the sim init set.
   */
  CScrLuaInitForm* func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef();

  /**
   * Address: 0x0075A9D0 (FUN_0075A9D0, cfunc_GetSystemTimeSecondsOnlyForProfileUseL)
   *
   * What it does:
   * Validates no Lua args and returns system timer elapsed seconds.
   */
  int cfunc_GetSystemTimeSecondsOnlyForProfileUseL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075AE00 (FUN_0075AE00, cfunc_GetUnitsInRect)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetUnitsInRectL`.
   */
  int cfunc_GetUnitsInRect(lua_State* luaContext);

  /**
   * Address: 0x0075AE20 (FUN_0075AE20, func_GetUnitsInRect_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetUnitsInRect(...)` Lua binder.
   */
  CScrLuaInitForm* func_GetUnitsInRect_LuaFuncDef();

  /**
   * Address: 0x0075AE80 (FUN_0075AE80, cfunc_GetUnitsInRectL)
   *
   * What it does:
   * Reads one rectangle (`rect` or `x0,z0,x1,z1`) and returns a Lua table of
   * unit objects inside the query rectangle.
   */
  int cfunc_GetUnitsInRectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075B200 (FUN_0075B200, cfunc_GetReclaimablesInRect)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetReclaimablesInRectL`.
   */
  int cfunc_GetReclaimablesInRect(lua_State* luaContext);

  /**
   * Address: 0x0075B220 (FUN_0075B220, func_GetReclaimablesInRect_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetReclaimablesInRect(...)` Lua binder.
   */
  CScrLuaInitForm* func_GetReclaimablesInRect_LuaFuncDef();

  /**
   * Address: 0x0075B280 (FUN_0075B280, cfunc_GetReclaimablesInRectL)
   *
   * What it does:
   * Reads one rectangle (`rect` or `x0,z0,x1,z1`) and returns a Lua table of
   * reclaimable entity objects (units/props) inside the query rectangle.
   */
  int cfunc_GetReclaimablesInRectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075BBE0 (FUN_0075BBE0, cfunc_GetMapSize)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetMapSizeL`.
   */
  int cfunc_GetMapSize(lua_State* luaContext);

  /**
   * Address: 0x0075BC00 (FUN_0075BC00, func_GetMapSize_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetMapSize()` Lua binder.
   */
  CScrLuaInitForm* func_GetMapSize_LuaFuncDef();

  /**
   * Address: 0x0075BC60 (FUN_0075BC60, cfunc_GetMapSizeL)
   *
   * What it does:
   * Validates no Lua args and returns map width/height extents in terrain
   * grid coordinates.
   */
  int cfunc_GetMapSizeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075BD10 (FUN_0075BD10, func_GetTerrainHeight_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetTerrainHeight(x,z)` Lua binder.
   */
  CScrLuaInitForm* func_GetTerrainHeight_LuaFuncDef();

  /**
   * Address: 0x0075BCF0 (FUN_0075BCF0, cfunc_GetTerrainHeight)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetTerrainHeightL`.
   */
  int cfunc_GetTerrainHeight(lua_State* luaContext);

  /**
   * Address: 0x0075BD70 (FUN_0075BD70, cfunc_GetTerrainHeightL)
   *
   * What it does:
   * Reads `(x, z)` and returns terrain elevation sampled from map heightfield.
   */
  int cfunc_GetTerrainHeightL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075BE90 (FUN_0075BE90, func_GetSurfaceHeight_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetSurfaceHeight(x,z)` Lua binder.
   */
  CScrLuaInitForm* func_GetSurfaceHeight_LuaFuncDef();

  /**
   * Address: 0x0075BE70 (FUN_0075BE70, cfunc_GetSurfaceHeight)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetSurfaceHeightL`.
   */
  int cfunc_GetSurfaceHeight(lua_State* luaContext);

  /**
   * Address: 0x0075BEF0 (FUN_0075BEF0, cfunc_GetSurfaceHeightL)
   *
   * What it does:
   * Reads `(x, z)` and returns max(terrainHeight, waterElevation) when water
   * is enabled, otherwise terrain height.
   */
  int cfunc_GetSurfaceHeightL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075C050 (FUN_0075C050, func_GetTerrainTypeOffset_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetTerrainTypeOffset(x,z)` Lua binder.
   */
  CScrLuaInitForm* func_GetTerrainTypeOffset_LuaFuncDef();

  /**
   * Address: 0x0075C030 (FUN_0075C030, cfunc_GetTerrainTypeOffset)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetTerrainTypeOffsetL`.
   */
  int cfunc_GetTerrainTypeOffset(lua_State* luaContext);

  /**
   * Address: 0x0075C0B0 (FUN_0075C0B0, cfunc_GetTerrainTypeOffsetL)
   *
   * What it does:
   * Reads `(x, z)` and returns terrain texture offset value at map position.
   */
  int cfunc_GetTerrainTypeOffsetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075C1D0 (FUN_0075C1D0, func_GetTerrainType_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetTerrainType(x,z)` Lua binder.
   */
  CScrLuaInitForm* func_GetTerrainType_LuaFuncDef();

  /**
   * Address: 0x0075C1B0 (FUN_0075C1B0, cfunc_GetTerrainType)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetTerrainTypeL`.
   */
  int cfunc_GetTerrainType(lua_State* luaContext);

  /**
   * Address: 0x0075C230 (FUN_0075C230, cfunc_GetTerrainTypeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(x, z)` from Lua and returns `STIMap::GetTerrainType(x, z)`.
   */
  int cfunc_GetTerrainTypeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075C3D0 (FUN_0075C3D0, func_SetTerrainType_LuaFuncDef)
   *
   * What it does:
   * Publishes global `SetTerrainType(x,z,type)` Lua binder.
   */
  CScrLuaInitForm* func_SetTerrainType_LuaFuncDef();

  /**
   * Address: 0x0075C3B0 (FUN_0075C3B0, cfunc_SetTerrainType)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_SetTerrainTypeL`.
   */
  int cfunc_SetTerrainType(lua_State* luaContext);

  /**
   * Address: 0x0075C430 (FUN_0075C430, cfunc_SetTerrainTypeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(x, z, terrainTypeTable)` from Lua and applies
   * `terrainTypeTable["TypeCode"]` through `STIMap::SetTerrainType`.
   */
  int cfunc_SetTerrainTypeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075C5F0 (FUN_0075C5F0, func_SetTerrainTypeRect_LuaFuncDef)
   *
   * What it does:
   * Publishes global `SetTerrainTypeRect(rect,type)` Lua binder.
   */
  CScrLuaInitForm* func_SetTerrainTypeRect_LuaFuncDef();

  /**
   * Address: 0x0075C5D0 (FUN_0075C5D0, cfunc_SetTerrainTypeRect)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_SetTerrainTypeRectL`.
   */
  int cfunc_SetTerrainTypeRect(lua_State* luaContext);

  /**
   * Address: 0x0075C650 (FUN_0075C650, cfunc_SetTerrainTypeRectL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(rectTable, terrainTypeTable)` from Lua and applies
   * `terrainTypeTable["TypeCode"]` over the clamped map rectangle.
   */
  int cfunc_SetTerrainTypeRectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075C7B0 (FUN_0075C7B0, cfunc_SetPlayableRect)
   *
   * lua_State *
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_SetPlayableRectL`.
   */
  int cfunc_SetPlayableRect(lua_State* luaContext);

  /**
   * Address: 0x0075C830 (FUN_0075C830, cfunc_SetPlayableRectL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(minX, minZ, maxX, maxZ)` and updates `STIMap::mPlayableRect`.
   */
  int cfunc_SetPlayableRectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075C9D0 (FUN_0075C9D0, cfunc_FlushIntelInRect)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_FlushIntelInRectL`.
   */
  int cfunc_FlushIntelInRect(lua_State* luaContext);

  /**
   * Address: 0x0075C9F0 (FUN_0075C9F0, func_FlushIntelInRect_LuaFuncDef)
   *
   * What it does:
   * Publishes global `FlushIntelInRect(minX,minZ,maxX,maxZ)` Lua binder.
   */
  CScrLuaInitForm* func_FlushIntelInRect_LuaFuncDef();

  /**
   * Address: 0x0075CA50 (FUN_0075CA50, cfunc_FlushIntelInRectL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Flushes recon blips in one rectangle for every active army recon
   * database.
   */
  int cfunc_FlushIntelInRectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075D970 (FUN_0075D970, cfunc_SetArmyStatsSyncArmy)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyStatsSyncArmyL`.
   */
  int cfunc_SetArmyStatsSyncArmy(lua_State* luaContext);

  /**
   * Address: 0x0075D990 (FUN_0075D990, func_SetArmyStatsSyncArmy_LuaFuncDef)
   *
   * What it does:
   * Publishes global `SetArmyStatsSyncArmy(army)` Lua binder.
   */
  CScrLuaInitForm* func_SetArmyStatsSyncArmy_LuaFuncDef();

  /**
   * Address: 0x0075D9F0 (FUN_0075D9F0, cfunc_SetArmyStatsSyncArmyL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads one army index and stores it in `Sim::mSyncArmy`.
   */
  int cfunc_SetArmyStatsSyncArmyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075CC40 (FUN_0075CC40, func_GetUnitBlueprintByName_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetUnitBlueprintByName(bpName)` Lua binder.
   */
  CScrLuaInitForm* func_GetUnitBlueprintByName_LuaFuncDef();

  /**
   * Address: 0x0075CC20 (FUN_0075CC20, cfunc_GetUnitBlueprintByName)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetUnitBlueprintByNameL`.
   */
  int cfunc_GetUnitBlueprintByName(lua_State* luaContext);

  /**
   * Address: 0x0075CCA0 (FUN_0075CCA0, cfunc_GetUnitBlueprintByNameL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads one unit blueprint id string and returns the blueprint Lua table
   * when found, otherwise returns `nil`.
   */
  int cfunc_GetUnitBlueprintByNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075E0D0 (FUN_0075E0D0, func_DrawCircle_LuaFuncDef)
   *
   * What it does:
   * Publishes global `DrawCircle(a,s,c)` Lua binder.
   */
  CScrLuaInitForm* func_DrawCircle_LuaFuncDef();

  /**
   * Address: 0x0075E0B0 (FUN_0075E0B0, cfunc_DrawCircle)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_DrawCircleL`.
   */
  int cfunc_DrawCircle(lua_State* luaContext);

  /**
   * Address: 0x0075E130 (FUN_0075E130, cfunc_DrawCircleL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(centerVec3, sizeNumber, color)` and emits one wireframe debug
   * circle on the current sim debug canvas.
   */
  int cfunc_DrawCircleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075DBA0 (FUN_0075DBA0, func_DrawLine_LuaFuncDef)
   *
   * What it does:
   * Publishes global `DrawLine(a,b,c)` Lua binder.
   */
  CScrLuaInitForm* func_DrawLine_LuaFuncDef();

  /**
   * Address: 0x0075DB80 (FUN_0075DB80, cfunc_DrawLine)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_DrawLineL`.
   */
  int cfunc_DrawLine(lua_State* luaContext);

  /**
   * Address: 0x0075DC00 (FUN_0075DC00, cfunc_DrawLineL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(startVec3, endVec3, color)` and emits one debug line segment on
   * the current sim debug canvas.
   */
  int cfunc_DrawLineL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075DDA0 (FUN_0075DDA0, cfunc_DrawLinePop)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_DrawLinePopL`.
   */
  int cfunc_DrawLinePop(lua_State* luaContext);

  /**
   * Address: 0x0075DDC0 (FUN_0075DDC0, func_DrawLinePop_LuaFuncDef)
   *
   * What it does:
   * Publishes global `DrawLinePop(a,b,c)` Lua binder.
   */
  CScrLuaInitForm* func_DrawLinePop_LuaFuncDef();

  /**
   * Address: 0x0075DE20 (FUN_0075DE20, cfunc_DrawLinePopL)
   *
   * What it does:
   * Reads `(startVec3, endVec3, color)`, draws the line, and emits one
   * wire-circle "pop" marker just past the line end.
   */
  int cfunc_DrawLinePopL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0128B140 (FUN_0128B140, func_CallbackPacketRecv)
   *
   * What it does:
   * Emits the patch diagnostics log line used by packet-callback sync exit flow.
   */
  void func_CallbackPacketRecv();

  /**
   * Address: 0x0128B160 (FUN_0128B160, func_CheckDiscard)
   *
   * What it does:
   * Checks whether a candidate client pointer is in the current patch client
   * list and marks/displays discard diagnostics when matched.
   */
  void func_CheckDiscard(const void* clientPointer);

  /**
   * Address: 0x0128B2C0 (FUN_0128B2C0, func_LogRecv)
   *
   * What it does:
   * Logs the received pointer used by patch packet-debug tracing.
   */
  void func_LogRecv(const void* receivedPointer);

  /**
   * Address: 0x008D4010 (FUN_008D4010, funcl_SC_CreateEntityDialog)
   *
   * What it does:
   * Thunk entry that routes SC create-entity dialog callback through patch gate.
   */
  void funcl_SC_CreateEntityDialog();

  /**
   * Address: 0x0128BEF0 (FUN_0128BEF0, patch_SC_CreateEntityDialog)
   *
   * What it does:
   * Applies cheat-enable gate before opening create-entity debug dialog.
   */
  void patch_SC_CreateEntityDialog();

  /**
   * Address: 0x0128BF00 (FUN_0128BF00, func_original_SC_CreateEntityDialog)
   *
   * What it does:
   * Calls original create-entity dialog body after patch gate passes.
   */
  void func_original_SC_CreateEntityDialog();

  /**
   * Address: 0x008D4016 (FUN_008D4016, func_SC_CreateEntityDialog_chunk)
   *
   * What it does:
   * Resolves first selected unit and opens blueprint edit dialog for that unit.
   */
  void func_SC_CreateEntityDialog_chunk();

  /**
   * Address: 0x0128B0BF (FUN_0128B0BF, cfunc_GetTimeForProfileSim)
   *
   * lua_State *
   *
   * What it does:
   * Reads a start-time argument and returns elapsed profile time in seconds.
   */
  int cfunc_GetTimeForProfileSim(lua_State* luaContext);

  /**
   * Address: 0x0128B2F9 (FUN_0128B2F9, cfunc_SetInvertMidMouseButton)
   *
   * lua_State *
   *
   * What it does:
   * Reads one boolean from Lua and toggles the middle-mouse scrub opcode patch.
   */
  int cfunc_SetInvertMidMouseButton(lua_State* luaContext);

  /**
   * Address: 0x00758F90 (FUN_00758F90, cfunc_RandomSim)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_RandomSimL`.
   */
  int cfunc_RandomSim(lua_State* luaContext);

  /**
   * Address: 0x00758FB0 (FUN_00758FB0, func_RandomSim_LuaFuncDef)
   *
   * What it does:
   * Publishes the sim-lane Lua binder definition for global `Random`.
   */
  CScrLuaInitForm* func_RandomSim_LuaFuncDef();

  /**
   * Address: 0x00759010 (FUN_00759010, cfunc_RandomSimL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Produces one random float or integer range sample from the active sim
   * random stream for `Random([[min,] max])`.
   */
  int cfunc_RandomSimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007593D0 (FUN_007593D0, cfunc_SelectedUnit)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SelectedUnitL`.
   */
  int cfunc_SelectedUnit(lua_State* luaContext);

  /**
   * Address: 0x007593F0 (FUN_007593F0, func_SelectedUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the sim-lane global Lua binder for `SelectedUnit()`.
   */
  CScrLuaInitForm* func_SelectedUnit_LuaFuncDef();

  /**
   * Address: 0x00759450 (FUN_00759450, cfunc_SelectedUnitL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes the current `__selected_unit` global value.
   */
  int cfunc_SelectedUnitL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007594C0 (FUN_007594C0, cfunc_SimConExecute)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SimConExecuteL`.
   */
  int cfunc_SimConExecute(lua_State* luaContext);

  /**
   * Address: 0x007594E0 (FUN_007594E0, func_SimConExecute_LuaFuncDef)
   *
   * What it does:
   * Publishes the sim-lane global Lua binder for `SimConExecute`.
   */
  CScrLuaInitForm* func_SimConExecute_LuaFuncDef();

  /**
   * Address: 0x00759540 (FUN_00759540, cfunc_SimConExecuteL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Executes one console command string argument via `CON_Execute`.
   */
  int cfunc_SimConExecuteL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00759810 (FUN_00759810, cfunc_ParseEntityCategorySim)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_ParseEntityCategorySimL`.
   */
  int cfunc_ParseEntityCategorySim(lua_State* luaContext);

  /**
   * Address: 0x00759830 (FUN_00759830, func_ParseEntityCategorySim_LuaFuncDef)
   *
   * What it does:
   * Publishes the sim-lane global Lua binder for `ParseEntityCategory`.
   */
  CScrLuaInitForm* func_ParseEntityCategorySim_LuaFuncDef();

  /**
   * Address: 0x00759890 (FUN_00759890, cfunc_ParseEntityCategorySimL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Parses one category expression string and returns a new entity-category
   * userdata object.
   */
  int cfunc_ParseEntityCategorySimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00759990 (FUN_00759990, cfunc_EntityCategoryContainsSim)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryContainsSimL`.
   */
  int cfunc_EntityCategoryContainsSim(lua_State* luaContext);

  /**
   * Address: 0x00759A10 (FUN_00759A10, cfunc_EntityCategoryContainsSimL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns whether arg#1 category contains arg#2 entity/blueprint category.
   */
  int cfunc_EntityCategoryContainsSimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007599B0 (FUN_007599B0, func_EntityCategoryContainsSim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EntityCategoryContains`.
   */
  CScrLuaInitForm* func_EntityCategoryContainsSim_LuaFuncDef();

  /**
   * Address: 0x00759BD0 (FUN_00759BD0, cfunc_EntityCategoryFilterDownSim)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterDownSimL`.
   */
  int cfunc_EntityCategoryFilterDownSim(lua_State* luaContext);

  /**
   * Address: 0x00759BF0 (FUN_00759BF0, func_EntityCategoryFilterDownSim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EntityCategoryFilterDown`.
   */
  CScrLuaInitForm* func_EntityCategoryFilterDownSim_LuaFuncDef();

  /**
   * Address: 0x00759C50 (FUN_00759C50, cfunc_EntityCategoryFilterDownSimL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Filters table entries to those whose resolved blueprint category bits are
   * present in arg#1 category set.
   */
  int cfunc_EntityCategoryFilterDownSimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00759EF0 (FUN_00759EF0, cfunc_EntityCategoryCount)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryCountL`.
   */
  int cfunc_EntityCategoryCount(lua_State* luaContext);

  /**
   * Address: 0x00759F70 (FUN_00759F70, cfunc_EntityCategoryCountL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Counts arg#2 list entries whose resolved blueprint category bit is present
   * in arg#1 category set.
   */
  int cfunc_EntityCategoryCountL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00759F10 (FUN_00759F10, func_EntityCategoryCount_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EntityCategoryCount`.
  */
  CScrLuaInitForm* func_EntityCategoryCount_LuaFuncDef();

  /**
   * Address: 0x0075A1D0 (FUN_0075A1D0, cfunc_EntityCategoryCountAroundPosition)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to
   * `cfunc_EntityCategoryCountAroundPositionL`.
   */
  int cfunc_EntityCategoryCountAroundPosition(lua_State* luaContext);

  /**
   * Address: 0x0075A1F0 (FUN_0075A1F0, func_EntityCategoryCountAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for
   * `EntityCategoryCountAroundPosition`.
   */
  CScrLuaInitForm* func_EntityCategoryCountAroundPosition_LuaFuncDef();

  /**
   * Address: 0x0075A250 (FUN_0075A250, cfunc_EntityCategoryCountAroundPositionL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Counts table entries whose entity category matches arg#1 and whose
   * horizontal distance from arg#3 is within arg#4.
   */
  int cfunc_EntityCategoryCountAroundPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075B940 (FUN_0075B940, cfunc_Warp)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_WarpL`.
   */
  int cfunc_Warp(lua_State* luaContext);

  /**
   * Address: 0x0075B9C0 (FUN_0075B9C0, cfunc_WarpL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, location [, orientation])` and warps the entity to the
   * target location while preserving current orientation when arg#3 is nil.
   */
  int cfunc_WarpL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075B960 (FUN_0075B960, func_Warp_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `Warp`.
   */
  CScrLuaInitForm* func_Warp_LuaFuncDef();

  /**
   * Address: 0x0075E2A0 (FUN_0075E2A0, cfunc_DebugGetSelection)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_DebugGetSelectionL`.
   */
  int cfunc_DebugGetSelection(lua_State* luaContext);

  /**
   * Address: 0x0075E2C0 (FUN_0075E2C0, func_DebugGetSelection_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `DebugGetSelection`.
   */
  CScrLuaInitForm* func_DebugGetSelection_LuaFuncDef();

  /**
   * Address: 0x0075E320 (FUN_0075E320, cfunc_DebugGetSelectionL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Builds a Lua array of script objects for current debug-selection ids from
   * the active sim sync-filter selection mask.
   */
  int cfunc_DebugGetSelectionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075E4E0 (FUN_0075E4E0, cfunc_IsEntity)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsEntityL`.
   */
  int cfunc_IsEntity(lua_State* luaContext);

  /**
   * Address: 0x0075E500 (FUN_0075E500, func_IsEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsEntity`.
   */
  CScrLuaInitForm* func_IsEntity_LuaFuncDef();

  /**
   * Address: 0x0075E560 (FUN_0075E560, cfunc_IsEntityL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns whether arg#1 resolves to an entity userdata lane.
   */
  int cfunc_IsEntityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075E620 (FUN_0075E620, cfunc_IsUnit)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsUnitL`.
   */
  int cfunc_IsUnit(lua_State* luaContext);

  /**
   * Address: 0x0075E640 (FUN_0075E640, func_IsUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsUnit`.
   */
  CScrLuaInitForm* func_IsUnit_LuaFuncDef();

  /**
   * Address: 0x0075E6A0 (FUN_0075E6A0, cfunc_IsUnitL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns arg#1 as unit Lua object when the entity is a unit; otherwise nil.
   */
  int cfunc_IsUnitL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075E780 (FUN_0075E780, cfunc_IsProp)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsPropL`.
   */
  int cfunc_IsProp(lua_State* luaContext);

  /**
   * Address: 0x0075E7A0 (FUN_0075E7A0, func_IsProp_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsProp`.
   */
  CScrLuaInitForm* func_IsProp_LuaFuncDef();

  /**
   * Address: 0x0075E800 (FUN_0075E800, cfunc_IsPropL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns arg#1 as prop Lua object when the entity is a prop; otherwise nil.
   */
  int cfunc_IsPropL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075E8E0 (FUN_0075E8E0, cfunc_IsBlip)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsBlipL`.
   */
  int cfunc_IsBlip(lua_State* luaContext);

  /**
   * Address: 0x0075E900 (FUN_0075E900, func_IsBlip_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsBlip`.
   */
  CScrLuaInitForm* func_IsBlip_LuaFuncDef();

  /**
   * Address: 0x0075E960 (FUN_0075E960, cfunc_IsBlipL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns arg#1 as recon-blip Lua object when the entity is a blip;
   * otherwise nil.
   */
  int cfunc_IsBlipL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075EA40 (FUN_0075EA40, cfunc_IsProjectile)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsProjectileL`.
   */
  int cfunc_IsProjectile(lua_State* luaContext);

  /**
   * Address: 0x0075EA60 (FUN_0075EA60, func_IsProjectile_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsProjectile`.
   */
  CScrLuaInitForm* func_IsProjectile_LuaFuncDef();

  /**
   * Address: 0x0075EAC0 (FUN_0075EAC0, cfunc_IsProjectileL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns arg#1 as projectile Lua object when the entity is a projectile;
   * otherwise nil.
   */
  int cfunc_IsProjectileL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075EBA0 (FUN_0075EBA0, cfunc_IsCollisionBeam)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsCollisionBeamL`.
   */
  int cfunc_IsCollisionBeam(lua_State* luaContext);

  /**
   * Address: 0x0075EBC0 (FUN_0075EBC0, func_IsCollisionBeam_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsCollisionBeam`.
   */
  CScrLuaInitForm* func_IsCollisionBeam_LuaFuncDef();

  /**
   * Address: 0x0075EC20 (FUN_0075EC20, cfunc_IsCollisionBeamL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns arg#1 as collision-beam Lua object when the entity is a collision
   * beam; otherwise nil.
   */
  int cfunc_IsCollisionBeamL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0088D8F0 (FUN_0088D8F0, cfunc_EjectSessionClient)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_EjectSessionClientL`.
   */
  int cfunc_EjectSessionClient(lua_State* luaContext);

  /**
   * Address: 0x0088D970 (FUN_0088D970, cfunc_EjectSessionClientL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates one client index argument and ejects the selected non-local
   * client from the active session.
   */
  int cfunc_EjectSessionClientL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0088D910 (FUN_0088D910, func_EjectSessionClient_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EjectSessionClient`.
   */
  CScrLuaInitForm* func_EjectSessionClient_LuaFuncDef();

  /**
   * Address: 0x0088DED0 (FUN_0088DED0, cfunc_WorldIsLoading)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_WorldIsLoadingL`.
   */
  int cfunc_WorldIsLoading(lua_State* luaContext);

  /**
   * Address: 0x0088DEF0 (FUN_0088DEF0, func_WorldIsLoading_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `WorldIsLoading`.
   */
  CScrLuaInitForm* func_WorldIsLoading_LuaFuncDef();

  /**
   * Address: 0x0088DF50 (FUN_0088DF50, cfunc_WorldIsLoadingL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns whether the current world frame action is loading or preload.
   */
  int cfunc_WorldIsLoadingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0088DFB0 (FUN_0088DFB0, cfunc_WorldIsPlaying)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_WorldIsPlayingL`.
   */
  int cfunc_WorldIsPlaying(lua_State* luaContext);

  /**
   * Address: 0x0088DFD0 (FUN_0088DFD0, func_WorldIsPlaying_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `WorldIsPlaying`.
   */
  CScrLuaInitForm* func_WorldIsPlaying_LuaFuncDef();

  /**
   * Address: 0x0088E030 (FUN_0088E030, cfunc_WorldIsPlayingL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns whether the current world frame action is actively playing.
   */
  int cfunc_WorldIsPlayingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0088E1E0 (FUN_0088E1E0, cfunc_GetGameSpeed)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GetGameSpeedL`.
   */
  int cfunc_GetGameSpeed(lua_State* luaContext);

  /**
   * Address: 0x0088E200 (FUN_0088E200, func_GetGameSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetGameSpeed`.
   */
  CScrLuaInitForm* func_GetGameSpeed_LuaFuncDef();

  /**
   * Address: 0x0088E260 (FUN_0088E260, cfunc_GetGameSpeedL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns the current requested sim speed from the active client manager.
   */
  int cfunc_GetGameSpeedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0088E2E0 (FUN_0088E2E0, cfunc_SetGameSpeed)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetGameSpeedL`.
   */
  int cfunc_SetGameSpeed(lua_State* luaContext);

  /**
   * Address: 0x0088E300 (FUN_0088E300, func_SetGameSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetGameSpeed`.
   */
  CScrLuaInitForm* func_SetGameSpeed_LuaFuncDef();

  /**
   * Address: 0x0088E360 (FUN_0088E360, cfunc_SetGameSpeedL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates one requested speed and forwards it to the active client manager.
   */
  int cfunc_SetGameSpeedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008B9B00 (FUN_008B9B00, cfunc_ParseEntityCategoryUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_ParseEntityCategoryUserL`.
   */
  int cfunc_ParseEntityCategoryUser(lua_State* luaContext);

  /**
   * Address: 0x008B9B20 (FUN_008B9B20, func_ParseEntityCategoryUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ParseEntityCategory`.
   */
  CScrLuaInitForm* func_ParseEntityCategoryUser_LuaFuncDef();

  /**
   * Address: 0x008B9B80 (FUN_008B9B80, cfunc_ParseEntityCategoryUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Parses one category expression string and returns a new entity-category
   * userdata object.
   */
  int cfunc_ParseEntityCategoryUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008ADFF0 (FUN_008ADFF0, cfunc_AudioSetLanguageUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_AudioSetLanguageUserL`.
   */
  int cfunc_AudioSetLanguageUser(lua_State* luaContext);

  /**
   * Address: 0x008AE010 (FUN_008AE010, func_AudioSetLanguageUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane global Lua binder definition for
   * `AudioSetLanguage(name)`.
   */
  CScrLuaInitForm* func_AudioSetLanguageUser_LuaFuncDef();

  /**
   * Address: 0x008AE070 (FUN_008AE070, cfunc_AudioSetLanguageUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates one language code, rebuilds localized voice/tutorial engines
   * when language changes, and stores the normalized tag.
   */
  int cfunc_AudioSetLanguageUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008AE280 (FUN_008AE280, cfunc_HasLocalizedVOUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_HasLocalizedVOUserL`.
   */
  int cfunc_HasLocalizedVOUser(lua_State* luaContext);

  /**
   * Address: 0x008AE2A0 (FUN_008AE2A0, func_HasLocalizedVOUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `HasLocalizedVO`.
   */
  CScrLuaInitForm* func_HasLocalizedVOUser_LuaFuncDef();

  /**
   * Address: 0x008AE300 (FUN_008AE300, cfunc_HasLocalizedVOUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns whether the requested localized voice directory exists.
   */
  int cfunc_HasLocalizedVOUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BDE40 (FUN_008BDE40, cfunc_AddToSessionExtraSelectList)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to
   * `cfunc_AddToSessionExtraSelectListL`.
   */
  int cfunc_AddToSessionExtraSelectList(lua_State* luaContext);

  /**
   * Address: 0x008BDE60 (FUN_008BDE60, func_AddToSessionExtraSelectList_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for
   * `AddToSessionExtraSelectList`.
   */
  CScrLuaInitForm* func_AddToSessionExtraSelectList_LuaFuncDef();

  /**
   * Address: 0x008BDEC0 (FUN_008BDEC0, cfunc_AddToSessionExtraSelectListL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads one user-unit argument and adds it to session extra selection.
   */
  int cfunc_AddToSessionExtraSelectListL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BDF70 (FUN_008BDF70, cfunc_RemoveFromSessionExtraSelectList)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to
   * `cfunc_RemoveFromSessionExtraSelectListL`.
   */
  int cfunc_RemoveFromSessionExtraSelectList(lua_State* luaContext);

  /**
   * Address: 0x008BDF90 (FUN_008BDF90, func_RemoveFromSessionExtraSelectList_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for
   * `RemoveFromSessionExtraSelectList`.
   */
  CScrLuaInitForm* func_RemoveFromSessionExtraSelectList_LuaFuncDef();

  /**
   * Address: 0x008BDFF0 (FUN_008BDFF0, cfunc_RemoveFromSessionExtraSelectListL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads one user-unit argument and removes it from session extra selection.
   */
  int cfunc_RemoveFromSessionExtraSelectListL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BE850 (FUN_008BE850, cfunc_SyncPlayableRect)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SyncPlayableRectL`.
   */
  int cfunc_SyncPlayableRect(lua_State* luaContext);

  /**
   * Address: 0x008BE870 (FUN_008BE870, func_SyncPlayableRect_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SyncPlayableRect`.
   */
  CScrLuaInitForm* func_SyncPlayableRect_LuaFuncDef();

  /**
   * Address: 0x008BE8D0 (FUN_008BE8D0, cfunc_SyncPlayableRectL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads one rect table and synchronizes playable bounds + entity visibility.
   */
  int cfunc_SyncPlayableRectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BE0D0 (FUN_008BE0D0, cfunc_ClearSessionExtraSelectList)
   *
   * lua_State *
   *
   * What it does:
   * Validates zero-argument call shape and clears the session extra-select list
   * when an active world session exists.
   */
  int cfunc_ClearSessionExtraSelectList(lua_State* luaContext);

  /**
   * Address: 0x008BE120 (FUN_008BE120, func_ClearSessionExtraSelectList_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for
   * `ClearSessionExtraSelectList`.
   */
  CScrLuaInitForm* func_ClearSessionExtraSelectList_LuaFuncDef();

  /**
   * Address: 0x008BE1C0 (FUN_008BE1C0, cfunc_CurrentTime)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_CurrentTimeL`.
   */
  int cfunc_CurrentTime(lua_State* luaContext);

  /**
   * Address: 0x008BE1E0 (FUN_008BE1E0, func_CurrentTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `CurrentTime`.
   */
  CScrLuaInitForm* func_CurrentTime_LuaFuncDef();

  /**
   * Address: 0x008BE240 (FUN_008BE240, cfunc_CurrentTimeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates zero-argument call shape and returns wall-clock elapsed seconds.
   */
  int cfunc_CurrentTimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BE2A0 (FUN_008BE2A0, cfunc_GameTime)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GameTimeL`.
   */
  int cfunc_GameTime(lua_State* luaContext);

  /**
   * Address: 0x008BE2C0 (FUN_008BE2C0, func_GameTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GameTime`.
   */
  CScrLuaInitForm* func_GameTime_LuaFuncDef();

  /**
   * Address: 0x008BE320 (FUN_008BE320, cfunc_GameTimeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns current game time in seconds from the active world session.
   */
  int cfunc_GameTimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BE3A0 (FUN_008BE3A0, cfunc_GameTick)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GameTickL`.
   */
  int cfunc_GameTick(lua_State* luaContext);

  /**
   * Address: 0x008BE3C0 (FUN_008BE3C0, func_GameTick_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GameTick`.
   */
  CScrLuaInitForm* func_GameTick_LuaFuncDef();

  /**
   * Address: 0x008BE420 (FUN_008BE420, cfunc_GameTickL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns current game time in ticks from the active world session.
   */
  int cfunc_GameTickL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BE490 (FUN_008BE490, cfunc_IsAllyUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsAllyUserL`.
   */
  int cfunc_IsAllyUser(lua_State* luaContext);

  /**
   * Address: 0x008BE4B0 (FUN_008BE4B0, func_IsAllyUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for global `IsAlly`.
   */
  CScrLuaInitForm* func_IsAllyUser_LuaFuncDef();

  /**
   * Address: 0x008BE510 (FUN_008BE510, cfunc_IsAllyUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Resolves `(army1, army2)` and returns whether army1 treats army2 as ally.
   */
  int cfunc_IsAllyUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BE5D0 (FUN_008BE5D0, cfunc_IsEnemyUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsEnemyUserL`.
   */
  int cfunc_IsEnemyUser(lua_State* luaContext);

  /**
   * Address: 0x008BE5F0 (FUN_008BE5F0, func_IsEnemyUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for global `IsEnemy`.
   */
  CScrLuaInitForm* func_IsEnemyUser_LuaFuncDef();

  /**
   * Address: 0x008BE650 (FUN_008BE650, cfunc_IsEnemyUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Resolves `(army1, army2)` and returns whether army1 treats army2 as enemy.
   */
  int cfunc_IsEnemyUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BE710 (FUN_008BE710, cfunc_IsNeutral)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsNeutralL`.
   */
  int cfunc_IsNeutral(lua_State* luaContext);

  /**
   * Address: 0x008BE730 (FUN_008BE730, func_IsNeutral_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for global `IsNeutral`.
   */
  CScrLuaInitForm* func_IsNeutral_LuaFuncDef();

  /**
   * Address: 0x008BE790 (FUN_008BE790, cfunc_IsNeutralL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Resolves `(army1, army2)` and returns whether army1 treats army2 as neutral.
   */
  int cfunc_IsNeutralL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BE980 (FUN_008BE980, cfunc_RandomUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_RandomUserL`.
   */
  int cfunc_RandomUser(lua_State* luaContext);

  /**
   * Address: 0x008BE9A0 (FUN_008BE9A0, func_RandomUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for global `Random`.
   */
  CScrLuaInitForm* func_RandomUser_LuaFuncDef();

  /**
   * Address: 0x008BEA00 (FUN_008BEA00, cfunc_RandomUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Produces one random float or integer range sample from the process-wide
   * random stream for `Random([[min,] max])`.
   */
  int cfunc_RandomUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008B9C90 (FUN_008B9C90, cfunc_EntityCategoryContainsUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryContainsUserL`.
   */
  int cfunc_EntityCategoryContainsUser(lua_State* luaContext);

  /**
   * Address: 0x008B9D10 (FUN_008B9D10, cfunc_EntityCategoryContainsUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns whether arg#1 category contains arg#2 unit/blueprint category.
   */
  int cfunc_EntityCategoryContainsUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008B9CB0 (FUN_008B9CB0, func_EntityCategoryContainsUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `EntityCategoryContains`.
   */
  CScrLuaInitForm* func_EntityCategoryContainsUser_LuaFuncDef();

  /**
   * Address: 0x008B9EF0 (FUN_008B9EF0, cfunc_EntityCategoryFilterDownUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterDownUserL`.
   */
  int cfunc_EntityCategoryFilterDownUser(lua_State* luaContext);

  /**
   * Address: 0x008B9F70 (FUN_008B9F70, cfunc_EntityCategoryFilterDownUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Filters arg#2 list entries, keeping only entries whose resolved unit
   * blueprint category bit is present in arg#1 category set.
   */
  int cfunc_EntityCategoryFilterDownUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008B9F10 (FUN_008B9F10, func_EntityCategoryFilterDownUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EntityCategoryFilterDown`.
   */
  CScrLuaInitForm* func_EntityCategoryFilterDownUser_LuaFuncDef();

  /**
   * Address: 0x008BA220 (FUN_008BA220, cfunc_EntityCategoryFilterOut)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterOutL`.
   */
  int cfunc_EntityCategoryFilterOut(lua_State* luaContext);

  /**
   * Address: 0x008BA2A0 (FUN_008BA2A0, cfunc_EntityCategoryFilterOutL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Filters arg#2 list entries, keeping only entries whose resolved unit
   * blueprint category bit is not present in arg#1 category set.
   */
  int cfunc_EntityCategoryFilterOutL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BA240 (FUN_008BA240, func_EntityCategoryFilterOut_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EntityCategoryFilterOut`.
   */
  CScrLuaInitForm* func_EntityCategoryFilterOut_LuaFuncDef();

  /**
   * Address: 0x008BA540 (FUN_008BA540, cfunc_ExecLuaInSim)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback state and dispatches to `cfunc_ExecLuaInSimL`.
   */
  int cfunc_ExecLuaInSim(lua_State* luaContext);

  /**
   * Address: 0x008BA560 (FUN_008BA560, func_ExecLuaInSim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ExecLuaInSim`.
   */
  CScrLuaInitForm* func_ExecLuaInSim_LuaFuncDef();

  /**
   * Address: 0x008BA5C0 (FUN_008BA5C0, cfunc_ExecLuaInSimL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(functionName, args)` from Lua and forwards one
   * `ExecuteLuaInSim(functionName,args)` request to the active sim driver.
   */
  int cfunc_ExecLuaInSimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BA6F0 (FUN_008BA6F0, cfunc_SimCallback)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and dispatches to `cfunc_SimCallbackL`.
   */
  int cfunc_SimCallback(lua_State* luaContext);

  /**
   * Address: 0x008BA770 (FUN_008BA770, cfunc_SimCallbackL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads callback payload (`Func`,`Args`) and optional selection gate, then
   * forwards one `CMDST_LuaSimCallback` request to the active sim driver.
   */
  int cfunc_SimCallbackL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BA710 (FUN_008BA710, func_SimCallback_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SimCallback`.
   */
  CScrLuaInitForm* func_SimCallback_LuaFuncDef();

  /**
   * Address: 0x00840840 (FUN_00840840, cfunc_GetUnitCommandFromCommandCap)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to
   * `cfunc_GetUnitCommandFromCommandCapL`.
   */
  int cfunc_GetUnitCommandFromCommandCap(lua_State* luaContext);

  /**
   * Address: 0x00840860 (FUN_00840860, func_GetUnitCommandFromCommandCap_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for
   * `GetUnitCommandFromCommandCap`.
   */
  CScrLuaInitForm* func_GetUnitCommandFromCommandCap_LuaFuncDef();

  /**
   * Address: 0x00821F50 (FUN_00821F50, Moho::UnitCommandCapToCommandType)
   *
   * What it does:
   * Converts one `RULEUCC_*` capability enum value into its corresponding
   * `UNITCOMMAND_*` command type.
   */
  EUnitCommandType UnitCommandCapToCommandType(ERuleBPUnitCommandCaps commandCap);

  /**
   * Address: 0x008408C0 (FUN_008408C0, cfunc_GetUnitCommandFromCommandCapL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Converts one `RULEUCC` lexical token to its corresponding
   * `UNITCOMMAND` lexical token and returns it as a Lua string.
   */
  int cfunc_GetUnitCommandFromCommandCapL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BAD60 (FUN_008BAD60, cfunc_SetAutoMode)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetAutoModeL`.
   */
  int cfunc_SetAutoMode(lua_State* luaContext);

  /**
   * Address: 0x008BADE0 (FUN_008BADE0, cfunc_SetAutoModeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(unitTable, enabled)` and emits `SetAutoMode` info-pairs for each
   * live user-unit entry.
   */
  int cfunc_SetAutoModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BAD80 (FUN_008BAD80, func_SetAutoMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `SetAutoMode`.
   */
  CScrLuaInitForm* func_UnitSetAutoMode_LuaFuncDef();

  /**
   * Address: 0x008BB2E0 (FUN_008BB2E0, cfunc_SetAutoSurfaceMode)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetAutoSurfaceModeL`.
   */
  int cfunc_SetAutoSurfaceMode(lua_State* luaContext);

  /**
   * Address: 0x008BB360 (FUN_008BB360, cfunc_SetAutoSurfaceModeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(unitTable, enabled)` and emits `SetAutoSurfaceMode` info-pairs
   * for each live user-unit entry.
   */
  int cfunc_SetAutoSurfaceModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BB300 (FUN_008BB300, func_SetAutoSurfaceMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `SetAutoSurfaceMode`.
   */
  CScrLuaInitForm* func_SetAutoSurfaceMode_LuaFuncDef();

  /**
   * Address: 0x008BBDE0 (FUN_008BBDE0, cfunc_ToggleScriptBit)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_ToggleScriptBitL`.
   */
  int cfunc_ToggleScriptBit(lua_State* luaContext);

  /**
   * Address: 0x008BBE60 (FUN_008BBE60, cfunc_ToggleScriptBitL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(unitTable, bit, currentState)` and emits `ToggleScriptBit`
   * info-pairs for live units that expose the toggle-cap lane and currently
   * match the requested script-bit state.
   */
  int cfunc_ToggleScriptBitL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BBE00 (FUN_008BBE00, func_ToggleScriptBit_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `ToggleScriptBit`.
   */
  CScrLuaInitForm* func_ToggleScriptBit_LuaFuncDef();

  /**
   * Address: 0x008BC080 (FUN_008BC080, cfunc_SetPaused)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetPausedL`.
   */
  int cfunc_SetPaused(lua_State* luaContext);

  /**
   * Address: 0x008BC100 (FUN_008BC100, cfunc_SetPausedL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(unitTable, paused)` and emits one `SetPaused` info-pair per
   * live user-unit entry when callback dispatch is not globally blocked.
   */
  int cfunc_SetPausedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BC0A0 (FUN_008BC0A0, func_SetPaused_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `SetPaused`.
   */
  CScrLuaInitForm* func_SetPaused_LuaFuncDef();

  /**
   * Address: 0x008BC280 (FUN_008BC280, cfunc_GetAttachedUnitsList)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and dispatches to `cfunc_GetAttachedUnitsListL`.
   */
  int cfunc_GetAttachedUnitsList(lua_State* luaContext);

  /**
   * Address: 0x008BC2A0 (FUN_008BC2A0, func_GetAttachedUnitsList_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `GetAttachedUnitsList`.
   */
  CScrLuaInitForm* func_GetAttachedUnitsList_LuaFuncDef();

  /**
   * Address: 0x008BC300 (FUN_008BC300, cfunc_GetAttachedUnitsListL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Builds one Lua list of currently alive attached user-unit script objects
   * for each source unit in the input table.
   */
  int cfunc_GetAttachedUnitsListL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BC570 (FUN_008BC570, cfunc_ValidateUnitsList)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback state and dispatches to `cfunc_ValidateUnitsListL`.
   */
  int cfunc_ValidateUnitsList(lua_State* luaContext);

  /**
   * Address: 0x008BC5F0 (FUN_008BC5F0, cfunc_ValidateUnitsListL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Filters one input unit table down to alive, non-destroy-queued unit Lua
   * objects and returns the filtered table.
   */
  int cfunc_ValidateUnitsListL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BC590 (FUN_008BC590, func_ValidateUnitsList_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `ValidateUnitsList`.
   */
  CScrLuaInitForm* func_ValidateUnitsList_LuaFuncDef();

  /**
   * Address: 0x008BC7A0 (FUN_008BC7A0, cfunc_GetAssistingUnitsList)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetAssistingUnitsListL`.
   */
  int cfunc_GetAssistingUnitsList(lua_State* luaContext);

  /**
   * Address: 0x008BC7C0 (FUN_008BC7C0, func_GetAssistingUnitsList_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `GetAssistingUnitsList`.
   */
  CScrLuaInitForm* func_GetAssistingUnitsList_LuaFuncDef();

  /**
   * Address: 0x008BC820 (FUN_008BC820, cfunc_GetAssistingUnitsListL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns one Lua array of assisting units for the supplied source list.
   */
  int cfunc_GetAssistingUnitsListL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BCC30 (FUN_008BCC30, cfunc_GetArmyAvatars)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetArmyAvatarsL`.
   */
  int cfunc_GetArmyAvatars(lua_State* luaContext);

  /**
   * Address: 0x008BCC50 (FUN_008BCC50, func_GetArmyAvatars_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `GetArmyAvatars`.
   */
  CScrLuaInitForm* func_GetArmyAvatars_LuaFuncDef();

  /**
   * Address: 0x008BCCB0 (FUN_008BCCB0, cfunc_GetArmyAvatarsL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns one Lua array of focus-army avatar unit script objects.
   */
  int cfunc_GetArmyAvatarsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BCE70 (FUN_008BCE70, cfunc_GetIdleEngineers)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetIdleEngineersL`.
   */
  int cfunc_GetIdleEngineers(lua_State* luaContext);

  /**
   * Address: 0x008BCE90 (FUN_008BCE90, func_GetIdleEngineers_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `GetIdleEngineers`.
   */
  CScrLuaInitForm* func_GetIdleEngineers_LuaFuncDef();

  /**
   * Address: 0x008BCEF0 (FUN_008BCEF0, cfunc_GetIdleEngineersL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns one Lua array of focus-army idle engineer unit script objects.
   */
  int cfunc_GetIdleEngineersL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BD100 (FUN_008BD100, cfunc_GetIdleFactories)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetIdleFactoriesL`.
   */
  int cfunc_GetIdleFactories(lua_State* luaContext);

  /**
   * Address: 0x008BD120 (FUN_008BD120, func_GetIdleFactories_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `GetIdleFactories`.
   */
  CScrLuaInitForm* func_GetIdleFactories_LuaFuncDef();

  /**
   * Address: 0x008BD180 (FUN_008BD180, cfunc_GetIdleFactoriesL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns one Lua array of focus-army idle factory unit script objects.
   */
  int cfunc_GetIdleFactoriesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BD600 (FUN_008BD600, cfunc_GetSelectedUnits)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetSelectedUnitsL`.
   */
  int cfunc_GetSelectedUnits(lua_State* luaContext);

  /**
   * Address: 0x008BD680 (FUN_008BD680, cfunc_GetSelectedUnitsL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Builds and returns a Lua array containing currently selected unit script objects.
   */
  int cfunc_GetSelectedUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BD620 (FUN_008BD620, func_GetSelectedUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSelectedUnits`.
   */
  CScrLuaInitForm* func_GetSelectedUnits_LuaFuncDef();

  /**
   * Address: 0x008BD870 (FUN_008BD870, cfunc_SelectUnits)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_SelectUnitsL`.
   */
  int cfunc_SelectUnits(lua_State* luaContext);

  /**
   * Address: 0x008BD890 (FUN_008BD890, func_SelectUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `SelectUnits`.
   */
  CScrLuaInitForm* func_SelectUnits_LuaFuncDef();

  /**
   * Address: 0x008BD8F0 (FUN_008BD8F0, cfunc_SelectUnitsL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Builds one validated unit selection from Lua input, applies it to the
   * world session, and returns a Lua array of accepted input units.
   */
  int cfunc_SelectUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008BDC30 (FUN_008BDC30, cfunc_AddSelectUnits)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_AddSelectUnitsL`.
   */
  int cfunc_AddSelectUnits(lua_State* luaContext);

  /**
   * Address: 0x008BDC50 (FUN_008BDC50, func_AddSelectUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the user-lane Lua binder definition for `AddSelectUnits`.
   */
  CScrLuaInitForm* func_AddSelectUnits_LuaFuncDef();

  /**
   * Address: 0x008BDCB0 (FUN_008BDCB0, cfunc_AddSelectUnitsL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Adds validated selectable user units from Lua input to current selection.
   */
  int cfunc_AddSelectUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068BD90 (FUN_0068BD90, cfunc_EntityAttachTo)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntityAttachToL`.
   */
  int cfunc_EntityAttachTo(lua_State* luaContext);

  /**
   * Address: 0x0068BE10 (FUN_0068BE10, cfunc_EntityAttachToL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(selfEntity, parentEntity, parentBone)`, builds one attach-info
   * payload, applies `Entity::AttachTo`, and raises a Lua error when attach
   * validation fails.
   */
  int cfunc_EntityAttachToL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068BDB0 (FUN_0068BDB0, func_EntityAttachTo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AttachTo()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityAttachTo_LuaFuncDef();

  /**
   * Address: 0x0068F660 (FUN_0068F660, cfunc_EntitySetOrientation)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EntitySetOrientationL`.
   */
  int cfunc_EntitySetOrientation(lua_State* luaContext);

  /**
   * Address: 0x0068F6E0 (FUN_0068F6E0, cfunc_EntitySetOrientationL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, orientation, immediate)`, writes pending orientation while
   * preserving current position, then optionally commits coords immediately.
   */
  int cfunc_EntitySetOrientationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068F680 (FUN_0068F680, func_EntitySetOrientation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetOrientation()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntitySetOrientation_LuaFuncDef();

  /**
   * Address: 0x0068FA10 (FUN_0068FA10, cfunc_EntitySetPosition)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntitySetPositionL`.
   */
  int cfunc_EntitySetPosition(lua_State* luaContext);

  /**
   * Address: 0x0068FA90 (FUN_0068FA90, cfunc_EntitySetPositionL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, position[, immediate])`, writes pending position while
   * preserving current orientation, then optionally commits coords immediately.
   */
  int cfunc_EntitySetPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068FA30 (FUN_0068FA30, func_EntitySetPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetPosition()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntitySetPosition_LuaFuncDef();

  /**
   * Address: 0x0068FC10 (FUN_0068FC10, cfunc_EntityGetPosition)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntityGetPositionL`.
   */
  int cfunc_EntityGetPosition(lua_State* luaContext);

  /**
   * Address: 0x0068FC90 (FUN_0068FC90, cfunc_EntityGetPositionL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity[, boneName])` and returns one Lua vector table with the
   * entity world position or resolved bone world position.
   */
  int cfunc_EntityGetPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068FC30 (FUN_0068FC30, func_EntityGetPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetPosition()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityGetPosition_LuaFuncDef();

  /**
   * Address: 0x0068FEE0 (FUN_0068FEE0, cfunc_EntityGetPositionXYZ)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EntityGetPositionXYZL`.
   */
  int cfunc_EntityGetPositionXYZ(lua_State* luaContext);

  /**
   * Address: 0x0068FF60 (FUN_0068FF60, cfunc_EntityGetPositionXYZL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity[, boneName])` and returns three Lua numbers `(x, y, z)` for
   * entity or resolved bone world position.
   */
  int cfunc_EntityGetPositionXYZL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068FF00 (FUN_0068FF00, func_EntityGetPositionXYZ_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetPositionXYZ()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityGetPositionXYZ_LuaFuncDef();

  /**
   * Address: 0x0068CA80 (FUN_0068CA80, cfunc_EntityGetCollisionExtentsL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads one entity argument and returns a `{Min, Max}` collision-extents
   * table when the entity has an active collision primitive.
   */
  int cfunc_EntityGetCollisionExtentsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068DE80 (FUN_0068DE80, cfunc_EntityIsIntelEnabled)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EntityIsIntelEnabledL`.
   */
  int cfunc_EntityIsIntelEnabled(lua_State* luaContext);

  /**
   * Address: 0x0068DEA0 (FUN_0068DEA0, func_EntityIsIntelEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:IsIntelEnabled()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityIsIntelEnabled_LuaFuncDef();

  /**
   * Address: 0x0068DF00 (FUN_0068DF00, cfunc_EntityIsIntelEnabledL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, intelType)` and returns one Lua boolean reporting whether
   * the selected intel lane is currently enabled.
   */
  int cfunc_EntityIsIntelEnabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068E050 (FUN_0068E050, cfunc_EntityEnableIntel)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntityEnableIntelL`.
   */
  int cfunc_EntityEnableIntel(lua_State* luaContext);

  /**
   * Address: 0x0068E070 (FUN_0068E070, func_EntityEnableIntel_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:EnableIntel()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityEnableIntel_LuaFuncDef();

  /**
   * Address: 0x0068E0D0 (FUN_0068E0D0, cfunc_EntityEnableIntelL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, intelType)`, enables that intel lane, and requeues the
   * entity into sim coord updates.
   */
  int cfunc_EntityEnableIntelL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068E2F0 (FUN_0068E2F0, cfunc_EntityDisableIntel)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EntityDisableIntelL`.
   */
  int cfunc_EntityDisableIntel(lua_State* luaContext);

  /**
   * Address: 0x0068E310 (FUN_0068E310, func_EntityDisableIntel_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:DisableIntel()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityDisableIntel_LuaFuncDef();

  /**
   * Address: 0x0068E370 (FUN_0068E370, cfunc_EntityDisableIntelL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, intelType)`, disables that intel lane, and requeues the
   * entity into sim coord updates.
   */
  int cfunc_EntityDisableIntelL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068E590 (FUN_0068E590, cfunc_EntitySetIntelRadius)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EntitySetIntelRadiusL`.
   */
  int cfunc_EntitySetIntelRadius(lua_State* luaContext);

  /**
   * Address: 0x0068E5B0 (FUN_0068E5B0, func_EntitySetIntelRadius_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:SetIntelRadius()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntitySetIntelRadius_LuaFuncDef();

  /**
   * Address: 0x0068E610 (FUN_0068E610, cfunc_EntitySetIntelRadiusL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, intelType, radius)`, updates intel handle radius and synced
   * intel-attribute radius, then requeues coord updates.
   */
  int cfunc_EntitySetIntelRadiusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068E7D0 (FUN_0068E7D0, cfunc_EntityGetIntelRadius)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EntityGetIntelRadiusL`.
   */
  int cfunc_EntityGetIntelRadius(lua_State* luaContext);

  /**
   * Address: 0x0068E7F0 (FUN_0068E7F0, func_EntityGetIntelRadius_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:GetIntelRadius()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityGetIntelRadius_LuaFuncDef();

  /**
   * Address: 0x0068E850 (FUN_0068E850, cfunc_EntityGetIntelRadiusL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, intelType)`, validates intel initialization, and returns
   * the selected intel radius as one Lua number.
   */
  int cfunc_EntityGetIntelRadiusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068E9A0 (FUN_0068E9A0, cfunc_EntityInitIntel)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntityInitIntelL`.
   */
  int cfunc_EntityInitIntel(lua_State* luaContext);

  /**
   * Address: 0x0068E9C0 (FUN_0068E9C0, func_EntityInitIntel_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:InitIntel()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityInitIntel_LuaFuncDef();

  /**
   * Address: 0x0068EA20 (FUN_0068EA20, cfunc_EntityInitIntelL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, army, intelType[, radius])`, initializes/updates one intel
   * lane, refreshes handle positions, and requeues coord updates.
   */
  int cfunc_EntityInitIntelL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068ED50 (FUN_0068ED50, cfunc_EntityAddShooter)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntityAddShooterL`.
   */
  int cfunc_EntityAddShooter(lua_State* luaContext);

  /**
   * Address: 0x0068ED70 (FUN_0068ED70, func_EntityAddShooter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AddShooter()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityAddShooter_LuaFuncDef();

  /**
   * Address: 0x0068EDD0 (FUN_0068EDD0, cfunc_EntityAddShooterL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, shooter)` and inserts `shooter` into the entity shooter set.
   */
  int cfunc_EntityAddShooterL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0068EEC0 (FUN_0068EEC0, cfunc_EntityRemoveShooter)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntityRemoveShooterL`.
   */
  int cfunc_EntityRemoveShooter(lua_State* luaContext);

  /**
   * Address: 0x0068EEE0 (FUN_0068EEE0, func_EntityRemoveShooter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:RemoveShooter()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityRemoveShooter_LuaFuncDef();

  /**
   * Address: 0x0068EF40 (FUN_0068EF40, cfunc_EntityRemoveShooterL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(entity, shooter)` and removes `shooter` from the entity shooter set.
   */
  int cfunc_EntityRemoveShooterL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006FC3B0 (FUN_006FC3B0, cfunc_CreateProp)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CreatePropL`.
   */
  int cfunc_CreateProp(lua_State* luaContext);

  /**
   * Address: 0x006FC430 (FUN_006FC430, cfunc_CreatePropL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(location, prop_blueprint_id)`, creates one prop in sim space, and
   * returns the created prop Lua object.
   */
  int cfunc_CreatePropL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006FC3D0 (FUN_006FC3D0, func_CreateProp_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `CreateProp`.
   */
  CScrLuaInitForm* func_CreateProp_LuaFuncDef();

  /**
   * Address: 0x006FC590 (FUN_006FC590, cfunc_EntityCreatePropAtBone)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_EntityCreatePropAtBoneL`.
   */
  int cfunc_EntityCreatePropAtBone(lua_State* luaContext);

  /**
   * Address: 0x006FC610 (FUN_006FC610, cfunc_EntityCreatePropAtBoneL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Creates one prop attached to an entity bone and returns the prop Lua object.
   */
  int cfunc_EntityCreatePropAtBoneL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006FC5B0 (FUN_006FC5B0, func_EntityCreatePropAtBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:CreatePropAtBone()` Lua binder definition.
   */
  CScrLuaInitForm* func_EntityCreatePropAtBone_LuaFuncDef();

  /**
   * Address: 0x007B5170 (FUN_007B5170, cfunc_CreateUnitAtMouse)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CreateUnitAtMouseL`.
   */
  int cfunc_CreateUnitAtMouse(lua_State* luaContext);

  /**
   * Address: 0x007B5190 (FUN_007B5190, func_CreateUnitAtMouse_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `CreateUnitAtMouse`.
   */
  CScrLuaInitForm* func_CreateUnitAtMouse_LuaFuncDef();

  /**
   * Address: 0x007B51E0 (FUN_007B51E0, cfunc_CreateUnitAtMouseL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(blueprintId, armyIndex, offsetX, offsetZ, rotation)`, resolves one
   * unit blueprint, snaps non-mobile units to footprint-aligned map cells, and
   * submits one create-unit command through the active sim driver.
   */
  int cfunc_CreateUnitAtMouseL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00547030 (FUN_00547030, cfunc_CreateResourceDeposit)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CreateResourceDepositL`.
   */
  int cfunc_CreateResourceDeposit(lua_State* luaContext);

  /**
   * Address: 0x005470B0 (FUN_005470B0, cfunc_CreateResourceDepositL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(type, x, y, z, size)` from Lua and creates one resource deposit.
   */
  int cfunc_CreateResourceDepositL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00547050 (FUN_00547050, func_CreateResourceDeposit_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `CreateResourceDeposit`.
   */
  CScrLuaInitForm* func_CreateResourceDeposit_LuaFuncDef();

  /**
   * Address: 0x0083F000 (FUN_0083F000, func_EngineStartSplashScreens)
   *
   * lua_State *
   *
   * What it does:
   * Casts Lua callback state, validates zero args, and starts splash-screen UI.
   */
  int func_EngineStartSplashScreens(lua_State* luaContext);

  /**
   * Address: 0x0083F040 (FUN_0083F040, func_EngineStartSplashScreens_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EngineStartSplashScreens`.
   */
  CScrLuaInitForm* func_EngineStartSplashScreens_LuaFuncDef();

  /**
   * Address: 0x0083F0E0 (FUN_0083F0E0, cfunc_EngineStartFrontEndUI)
   *
   * lua_State *
   *
   * What it does:
   * Casts Lua callback state, validates zero args, and starts front-end UI.
   */
  int cfunc_EngineStartFrontEndUI(lua_State* luaContext);

  /**
   * Address: 0x0083F120 (FUN_0083F120, func_EngineStartFrontEndUI_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EngineStartFrontEndUI`.
   */
  CScrLuaInitForm* func_EngineStartFrontEndUI_LuaFuncDef();

  /**
   * Address: 0x0083F1C0 (FUN_0083F1C0, cfunc_ExitApplication)
   *
   * lua_State *
   *
   * What it does:
   * Casts Lua callback state, validates zero args, and requests app shutdown.
   */
  int cfunc_ExitApplication(lua_State* luaContext);

  /**
   * Address: 0x0083F210 (FUN_0083F210, func_ExitApplication_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ExitApplication`.
   */
  CScrLuaInitForm* func_ExitApplication_LuaFuncDef();

  /**
   * Address: 0x0083F2B0 (FUN_0083F2B0, cfunc_ExitGame)
   *
   * lua_State *
   *
   * What it does:
   * Casts Lua callback state, validates zero args, and requests sim exit.
   */
  int cfunc_ExitGame(lua_State* luaContext);

  /**
   * Address: 0x0083F300 (FUN_0083F300, func_ExitGame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ExitGame`.
   */
  CScrLuaInitForm* func_ExitGame_LuaFuncDef();

  /**
   * Address: 0x0083F3A0 (FUN_0083F3A0, cfunc_RestartSession)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_RestartSessionL`.
   */
  int cfunc_RestartSession(lua_State* luaContext);

  /**
   * Address: 0x0083F420 (FUN_0083F420, cfunc_RestartSessionL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates zero arguments and requests world-frame action `CreateSession`
   * when restart prerequisites are present.
   */
  int cfunc_RestartSessionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0083F3C0 (FUN_0083F3C0, func_RestartSession_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `RestartSession`.
   */
  CScrLuaInitForm* func_RestartSession_LuaFuncDef();

  /**
   * Address: 0x0083F470 (FUN_0083F470, cfunc_GetFrame)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetFrameL`.
   */
  int cfunc_GetFrame(lua_State* luaContext);

  /**
   * Address: 0x0083F4F0 (FUN_0083F4F0, cfunc_GetFrameL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Resolves one root UI frame index and pushes the corresponding Lua frame
   * object when it belongs to the same root Lua state.
   */
  int cfunc_GetFrameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0083F490 (FUN_0083F490, func_GetFrame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetFrame`.
   */
  CScrLuaInitForm* func_GetFrame_LuaFuncDef();

  /**
   * Address: 0x0083F5D0 (FUN_0083F5D0, cfunc_ClearFrame)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_ClearFrameL`.
   */
  int cfunc_ClearFrame(lua_State* luaContext);

  /**
   * Address: 0x0083F650 (FUN_0083F650, cfunc_ClearFrameL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Clears one frame by index or all frames when the optional argument is nil.
   */
  int cfunc_ClearFrameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0083F5F0 (FUN_0083F5F0, func_ClearFrame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ClearFrame`.
   */
  CScrLuaInitForm* func_ClearFrame_LuaFuncDef();

  /**
   * Address: 0x0083F700 (FUN_0083F700, cfunc_GetNumRootFrames)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetNumRootFramesL`.
   */
  int cfunc_GetNumRootFrames(lua_State* luaContext);

  /**
   * Address: 0x0083F780 (FUN_0083F780, cfunc_GetNumRootFramesL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes the current root-frame count as a Lua number.
   */
  int cfunc_GetNumRootFramesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0083F720 (FUN_0083F720, func_GetNumRootFrames_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetNumRootFrames`.
   */
  CScrLuaInitForm* func_GetNumRootFrames_LuaFuncDef();

  /**
   * Address: 0x0083F800 (FUN_0083F800, cfunc_GetEconomyTotals)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetEconomyTotalsL`.
   */
  int cfunc_GetEconomyTotals(lua_State* luaContext);

  /**
   * Address: 0x0083F880 (FUN_0083F880, cfunc_GetEconomyTotalsL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Builds and returns one table containing focus-army economy totals.
   */
  int cfunc_GetEconomyTotalsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0083F820 (FUN_0083F820, func_GetEconomyTotals_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetEconomyTotals`.
   */
  CScrLuaInitForm* func_GetEconomyTotals_LuaFuncDef();

  /**
   * Address: 0x0083FED0 (FUN_0083FED0, cfunc_GetResourceSharing)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetResourceSharingL`.
   */
  int cfunc_GetResourceSharing(lua_State* luaContext);

  /**
   * Address: 0x0083FEF0 (FUN_0083FEF0, func_GetResourceSharing_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetResourceSharing`.
   */
  CScrLuaInitForm* func_GetResourceSharing_LuaFuncDef();

  /**
   * Address: 0x0083FF50 (FUN_0083FF50, cfunc_GetResourceSharingL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes whether the focused user army has resource sharing enabled.
   */
  int cfunc_GetResourceSharingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0083FFE0 (FUN_0083FFE0, cfunc_GetSimTicksPerSecond)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to
   * `cfunc_GetSimTicksPerSecondL`.
   */
  int cfunc_GetSimTicksPerSecond(lua_State* luaContext);

  /**
   * Address: 0x00840000 (FUN_00840000, func_GetSimTicksPerSecond_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSimTicksPerSecond`.
   */
  CScrLuaInitForm* func_GetSimTicksPerSecond_LuaFuncDef();

  /**
   * Address: 0x00840060 (FUN_00840060, cfunc_GetSimTicksPerSecondL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes fixed simulation ticks-per-second (10.0) as a Lua number.
   */
  int cfunc_GetSimTicksPerSecondL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00897780 (FUN_00897780, cfunc_SessionRequestPause)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to
   * `cfunc_SessionRequestPauseL`.
   */
  int cfunc_SessionRequestPause(lua_State* luaContext);

  /**
   * Address: 0x008977A0 (FUN_008977A0, func_SessionRequestPause_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionRequestPause`.
   */
  CScrLuaInitForm* func_SessionRequestPause_LuaFuncDef();

  /**
   * Address: 0x00897800 (FUN_00897800, cfunc_SessionRequestPauseL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Requests world-session pause from Lua after validating active session.
   */
  int cfunc_SessionRequestPauseL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00897850 (FUN_00897850, cfunc_SessionResume)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_SessionResumeL`.
   */
  int cfunc_SessionResume(lua_State* luaContext);

  /**
   * Address: 0x00897870 (FUN_00897870, func_SessionResume_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionResume`.
   */
  CScrLuaInitForm* func_SessionResume_LuaFuncDef();

  /**
   * Address: 0x008978D0 (FUN_008978D0, cfunc_SessionResumeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Requests world-session resume from Lua after validating active session.
   */
  int cfunc_SessionResumeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00897920 (FUN_00897920, cfunc_SessionIsPaused)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_SessionIsPausedL`.
   */
  int cfunc_SessionIsPaused(lua_State* luaContext);

  /**
   * Address: 0x00897940 (FUN_00897940, func_SessionIsPaused_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionIsPaused`.
   */
  CScrLuaInitForm* func_SessionIsPaused_LuaFuncDef();

  /**
   * Address: 0x008979A0 (FUN_008979A0, cfunc_SessionIsPausedL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes the current world-session paused state.
   */
  int cfunc_SessionIsPausedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00897A00 (FUN_00897A00, cfunc_SessionIsGameOver)
   *
   * lua_State *
   *
   * What it does:
   * Pushes whether the active world-session game-over flag is set.
   */
  int cfunc_SessionIsGameOver(lua_State* luaContext);

  /**
   * Address: 0x00897A50 (FUN_00897A50, func_SessionIsGameOver_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionIsGameOver`.
   */
  CScrLuaInitForm* func_SessionIsGameOver_LuaFuncDef();

  /**
   * Address: 0x00897C70 (FUN_00897C70, cfunc_SessionGetLocalCommandSource)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to
   * `cfunc_SessionGetLocalCommandSourceL`.
   */
  int cfunc_SessionGetLocalCommandSource(lua_State* luaContext);

  /**
   * Address: 0x00897C90 (FUN_00897C90, func_SessionGetLocalCommandSource_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for
   * `SessionGetLocalCommandSource`.
   */
  CScrLuaInitForm* func_SessionGetLocalCommandSource_LuaFuncDef();

  /**
   * Address: 0x00897CF0 (FUN_00897CF0, cfunc_SessionGetLocalCommandSourceL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes local command-source id as a one-based Lua number (`0` when none).
   */
  int cfunc_SessionGetLocalCommandSourceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00897D70 (FUN_00897D70, cfunc_SessionIsReplayUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_SessionIsReplayUserL`.
   */
  int cfunc_SessionIsReplayUser(lua_State* luaContext);

  /**
   * Address: 0x00897D90 (FUN_00897D90, func_SessionIsReplayUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionIsReplay`.
   */
  CScrLuaInitForm* func_SessionIsReplayUser_LuaFuncDef();

  /**
   * Address: 0x00897DF0 (FUN_00897DF0, cfunc_SessionIsReplayUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes whether the active world-session is replay-backed.
   */
  int cfunc_SessionIsReplayUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00897E60 (FUN_00897E60, cfunc_SessionIsBeingRecorded)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to
   * `cfunc_SessionIsBeingRecordedL`.
   */
  int cfunc_SessionIsBeingRecorded(lua_State* luaContext);

  /**
   * Address: 0x00897E80 (FUN_00897E80, func_SessionIsBeingRecorded_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionIsBeingRecorded`.
   */
  CScrLuaInitForm* func_SessionIsBeingRecorded_LuaFuncDef();

  /**
   * Address: 0x00897EE0 (FUN_00897EE0, cfunc_SessionIsBeingRecordedL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes whether the active world-session is currently being recorded.
   */
  int cfunc_SessionIsBeingRecordedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00897F50 (FUN_00897F50, cfunc_SessionIsMultiplayer)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to
   * `cfunc_SessionIsMultiplayerL`.
   */
  int cfunc_SessionIsMultiplayer(lua_State* luaContext);

  /**
   * Address: 0x00897F70 (FUN_00897F70, func_SessionIsMultiplayer_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionIsMultiplayer`.
   */
  CScrLuaInitForm* func_SessionIsMultiplayer_LuaFuncDef();

  /**
   * Address: 0x00897FD0 (FUN_00897FD0, cfunc_SessionIsMultiplayerL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes whether the active world-session is multiplayer.
   */
  int cfunc_SessionIsMultiplayerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00898040 (FUN_00898040, cfunc_SessionIsObservingAllowed)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to
   * `cfunc_SessionIsObservingAllowedL`.
   */
  int cfunc_SessionIsObservingAllowed(lua_State* luaContext);

  /**
   * Address: 0x00898060 (FUN_00898060, func_SessionIsObservingAllowed_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionIsObservingAllowed`.
   */
  CScrLuaInitForm* func_SessionIsObservingAllowed_LuaFuncDef();

  /**
   * Address: 0x008980C0 (FUN_008980C0, cfunc_SessionIsObservingAllowedL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes whether observing is enabled for the active world-session.
   */
  int cfunc_SessionIsObservingAllowedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00898130 (FUN_00898130, cfunc_SessionCanRestart)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_SessionCanRestartL`.
   */
  int cfunc_SessionCanRestart(lua_State* luaContext);

  /**
   * Address: 0x00898150 (FUN_00898150, func_SessionCanRestart_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionCanRestart`.
   */
  CScrLuaInitForm* func_SessionCanRestart_LuaFuncDef();

  /**
   * Address: 0x008981B0 (FUN_008981B0, cfunc_SessionCanRestartL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes whether restart data is available for the active world-session.
   */
  int cfunc_SessionCanRestartL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00898220 (FUN_00898220, cfunc_SessionIsActive)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_SessionIsActiveL`.
   */
  int cfunc_SessionIsActive(lua_State* luaContext);

  /**
   * Address: 0x00898240 (FUN_00898240, func_SessionIsActive_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionIsActive`.
   */
  CScrLuaInitForm* func_SessionIsActive_LuaFuncDef();

  /**
   * Address: 0x008982A0 (FUN_008982A0, cfunc_SessionIsActiveL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes whether any world-session is currently active.
   */
  int cfunc_SessionIsActiveL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008982F0 (FUN_008982F0, cfunc_SessionGetScenarioInfo)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to
   * `cfunc_SessionGetScenarioInfoL`.
   */
  int cfunc_SessionGetScenarioInfo(lua_State* luaContext);

  /**
   * Address: 0x00898310 (FUN_00898310, func_SessionGetScenarioInfo_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SessionGetScenarioInfo`.
   */
  CScrLuaInitForm* func_SessionGetScenarioInfo_LuaFuncDef();

  /**
   * Address: 0x00898370 (FUN_00898370, cfunc_SessionGetScenarioInfoL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates user-lua state ownership and pushes the active session
   * `ScenarioInfo` table.
   */
  int cfunc_SessionGetScenarioInfoL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008420A0 (FUN_008420A0, cfunc_GetCurrentUIState)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetCurrentUIStateL`.
   */
  int cfunc_GetCurrentUIState(lua_State* luaContext);

  /**
   * Address: 0x008420C0 (FUN_008420C0, func_GetCurrentUIState_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetCurrentUIState`.
   */
  CScrLuaInitForm* func_GetCurrentUIState_LuaFuncDef();

  /**
   * Address: 0x00842120 (FUN_00842120, cfunc_GetCurrentUIStateL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes current UI-state lexical value (`splash`, `frontend`, or `game`).
   */
  int cfunc_GetCurrentUIStateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00842BB0 (FUN_00842BB0, cfunc_GetMouseWorldPos)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetMouseWorldPosL`.
   */
  int cfunc_GetMouseWorldPos(lua_State* luaContext);

  /**
   * Address: 0x00842BD0 (FUN_00842BD0, func_GetMouseWorldPosUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetMouseWorldPos`.
   */
  CScrLuaInitForm* func_GetMouseWorldPosUser_LuaFuncDef();

  /**
   * Address: 0x00842C30 (FUN_00842C30, cfunc_GetMouseWorldPosL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes current world-space mouse position as one Lua vector.
   */
  int cfunc_GetMouseWorldPosL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00842D10 (FUN_00842D10, cfunc_GetMouseScreenPos)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetMouseScreenPosL`.
   */
  int cfunc_GetMouseScreenPos(lua_State* luaContext);

  /**
   * Address: 0x00842D30 (FUN_00842D30, func_GetMouseScreenPos_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetMouseScreenPos`.
   */
  CScrLuaInitForm* func_GetMouseScreenPos_LuaFuncDef();

  /**
   * Address: 0x00842D90 (FUN_00842D90, cfunc_GetMouseScreenPosL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes current screen-space mouse position as one Lua vector.
   */
  int cfunc_GetMouseScreenPosL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00842E60 (FUN_00842E60, cfunc_SetFocusArmyUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_SetFocusArmyUserL`.
   */
  int cfunc_SetFocusArmyUser(lua_State* luaContext);

  /**
   * Address: 0x00842E80 (FUN_00842E80, func_SetFocusArmyUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetFocusArmy`.
   */
  CScrLuaInitForm* func_SetFocusArmyUser_LuaFuncDef();

  /**
   * Address: 0x00842EE0 (FUN_00842EE0, cfunc_SetFocusArmyUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates one-based army index input and requests focus-army update.
   */
  int cfunc_SetFocusArmyUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00842FD0 (FUN_00842FD0, cfunc_GetFocusArmyUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetFocusArmyUserL`.
   */
  int cfunc_GetFocusArmyUser(lua_State* luaContext);

  /**
   * Address: 0x00842FF0 (FUN_00842FF0, func_GetFocusArmyUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetFocusArmy`.
   */
  CScrLuaInitForm* func_GetFocusArmyUser_LuaFuncDef();

  /**
   * Address: 0x00843050 (FUN_00843050, cfunc_GetFocusArmyUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes the focused army as a one-based Lua index (`-1` when unset).
   */
  int cfunc_GetFocusArmyUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008430D0 (FUN_008430D0, cfunc_IsObserver)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_IsObserverL`.
   */
  int cfunc_IsObserver(lua_State* luaContext);

  /**
   * Address: 0x008430F0 (FUN_008430F0, func_IsObserver_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsObserver`.
   */
  CScrLuaInitForm* func_IsObserver_LuaFuncDef();

  /**
   * Address: 0x00843150 (FUN_00843150, cfunc_IsObserverL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes whether the active focus army has no owning `UserArmy` entry.
   */
  int cfunc_IsObserverL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008431D0 (FUN_008431D0, cfunc_GetGameTime)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetGameTimeL`.
   */
  int cfunc_GetGameTime(lua_State* luaContext);

  /**
   * Address: 0x008431F0 (FUN_008431F0, func_GetGameTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetGameTime`.
   */
  CScrLuaInitForm* func_GetGameTime_LuaFuncDef();

  /**
   * Address: 0x00843250 (FUN_00843250, cfunc_GetGameTimeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads active session game time and pushes formatted `HH:MM:SS` text.
   */
  int cfunc_GetGameTimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00843380 (FUN_00843380, cfunc_GetGameTimeSecondsUser)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetGameTimeSecondsUserL`.
   */
  int cfunc_GetGameTimeSecondsUser(lua_State* luaContext);

  /**
   * Address: 0x008433A0 (FUN_008433A0, func_GetGameTimeSecondsUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetGameTimeSeconds`.
   */
  CScrLuaInitForm* func_GetGameTimeSecondsUser_LuaFuncDef();

  /**
   * Address: 0x00843400 (FUN_00843400, cfunc_GetGameTimeSecondsUserL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes active-session elapsed game time in seconds as a Lua number.
   */
  int cfunc_GetGameTimeSecondsUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00843480 (FUN_00843480, cfunc_GetSystemTime)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetSystemTimeL`.
   */
  int cfunc_GetSystemTime(lua_State* luaContext);

  /**
   * Address: 0x008434A0 (FUN_008434A0, func_GetSystemTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSystemTime`.
   */
  CScrLuaInitForm* func_GetSystemTime_LuaFuncDef();

  /**
   * Address: 0x00843500 (FUN_00843500, cfunc_GetSystemTimeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads process-system timer seconds and pushes formatted `HH:MM:SS` text.
   */
  int cfunc_GetSystemTimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008435F0 (FUN_008435F0, cfunc_GetSystemTimeSeconds)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetSystemTimeSecondsL`.
   */
  int cfunc_GetSystemTimeSeconds(lua_State* luaContext);

  /**
   * Address: 0x00843610 (FUN_00843610, func_GetSystemTimeSeconds_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSystemTimeSeconds`.
   */
  CScrLuaInitForm* func_GetSystemTimeSeconds_LuaFuncDef();

  /**
   * Address: 0x00843670 (FUN_00843670, cfunc_GetSystemTimeSecondsL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes process-system elapsed time in seconds as a Lua number.
   */
  int cfunc_GetSystemTimeSecondsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008436D0 (FUN_008436D0, cfunc_FormatTime)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_FormatTimeL`.
   */
  int cfunc_FormatTime(lua_State* luaContext);

  /**
   * Address: 0x00843750 (FUN_00843750, cfunc_FormatTimeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads one seconds value and pushes `HH:MM:SS` formatted text.
   */
  int cfunc_FormatTimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008436F0 (FUN_008436F0, func_FormatTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `FormatTime`.
   */
  CScrLuaInitForm* func_FormatTime_LuaFuncDef();

  /**
   * Address: 0x008438A0 (FUN_008438A0, cfunc_GetSimRate)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetSimRateL`.
   */
  int cfunc_GetSimRate(lua_State* luaContext);

  /**
   * Address: 0x008438C0 (FUN_008438C0, func_GetSimRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSimRate`.
   */
  CScrLuaInitForm* func_GetSimRate_LuaFuncDef();

  /**
   * Address: 0x00843920 (FUN_00843920, cfunc_GetSimRateL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Pushes the current client-manager simulation rate as a Lua number.
   */
  int cfunc_GetSimRateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008439A0 (FUN_008439A0, cfunc_GetArmiesTable)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetArmiesTableL`.
   */
  int cfunc_GetArmiesTable(lua_State* luaContext);

  /**
   * Address: 0x008439C0 (FUN_008439C0, func_GetArmiesTable_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetArmiesTable`.
   */
  CScrLuaInitForm* func_GetArmiesTable_LuaFuncDef();

  /**
   * Address: 0x00843A20 (FUN_00843A20, cfunc_GetArmiesTableL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Builds and returns one Lua table describing session armies and command
   * source authorization lanes.
   */
  int cfunc_GetArmiesTableL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00843E50 (FUN_00843E50, cfunc_GetArmyScore)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetArmyScoreL`.
   */
  int cfunc_GetArmyScore(lua_State* luaContext);

  /**
   * Address: 0x00843E70 (FUN_00843E70, func_GetArmyScore_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetArmyScore`.
   */
  CScrLuaInitForm* func_GetArmyScore_LuaFuncDef();

  /**
   * Address: 0x00843ED0 (FUN_00843ED0, cfunc_GetArmyScoreL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Validates one argument and active-session precondition for the
   * `GetArmyScore` global Lua callback lane.
   */
  int cfunc_GetArmyScoreL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00843F20 (FUN_00843F20, cfunc_DeleteCommand)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_DeleteCommandL`.
   */
  int cfunc_DeleteCommand(lua_State* luaContext);

  /**
   * Address: 0x00843F40 (FUN_00843F40, func_DeleteCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `DeleteCommand`.
   */
  CScrLuaInitForm* func_DeleteCommand_LuaFuncDef();

  /**
   * Address: 0x00843FA0 (FUN_00843FA0, cfunc_DeleteCommandL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Resolves one command id in the session command-issue map and marshals one
   * command-count decrement through the active sim driver.
   */
  int cfunc_DeleteCommandL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008440A0 (FUN_008440A0, cfunc_GetSpecialFiles)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFilesL`.
   */
  int cfunc_GetSpecialFiles(lua_State* luaContext);

  /**
   * Address: 0x008440C0 (FUN_008440C0, func_GetSpecialFiles_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSpecialFiles`.
   */
  CScrLuaInitForm* func_GetSpecialFiles_LuaFuncDef();

  /**
   * Address: 0x00844120 (FUN_00844120, cfunc_GetSpecialFilesL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Resolves one special-file-type selector and builds the Lua result table
   * with grouped filenames plus directory/extension metadata.
   */
  int cfunc_GetSpecialFilesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00844540 (FUN_00844540, cfunc_GetSpecialFilePath)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFilePathL`.
   */
  int cfunc_GetSpecialFilePath(lua_State* luaContext);

  /**
   * Address: 0x00844560 (FUN_00844560, func_GetSpecialFilePath_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSpecialFilePath`.
   */
  CScrLuaInitForm* func_GetSpecialFilePath_LuaFuncDef();

  /**
   * Address: 0x008445C0 (FUN_008445C0, cfunc_GetSpecialFilePathL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Resolves profile/file/type Lua args and returns one absolute special-file
   * path using user-directory and extension helpers.
   */
  int cfunc_GetSpecialFilePathL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00844C30 (FUN_00844C30, cfunc_GetSpecialFolder)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFolderL`.
   */
  int cfunc_GetSpecialFolder(lua_State* luaContext);

  /**
   * Address: 0x00844C50 (FUN_00844C50, func_GetSpecialFolder_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSpecialFolder`.
   */
  CScrLuaInitForm* func_GetSpecialFolder_LuaFuncDef();

  /**
   * Address: 0x00844CB0 (FUN_00844CB0, cfunc_GetSpecialFolderL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Resolves one special-file type and pushes the matching root folder path.
   */
  int cfunc_GetSpecialFolderL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00844F10 (FUN_00844F10, cfunc_RemoveSpecialFile)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_RemoveSpecialFileL`.
   */
  int cfunc_RemoveSpecialFile(lua_State* luaContext);

  /**
   * Address: 0x00844F30 (FUN_00844F30, func_RemoveSpecialFile_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `RemoveSpecialFile`.
   */
  CScrLuaInitForm* func_RemoveSpecialFile_LuaFuncDef();

  /**
   * Address: 0x00844F90 (FUN_00844F90, cfunc_RemoveSpecialFileL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Builds one profile-scoped special-file path and recycles it from disk.
   */
  int cfunc_RemoveSpecialFileL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00845540 (FUN_00845540, cfunc_GetSpecialFileInfo)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFileInfoL`.
   */
  int cfunc_GetSpecialFileInfo(lua_State* luaContext);

  /**
   * Address: 0x00845560 (FUN_00845560, func_GetSpecialFileInfo_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetSpecialFileInfo`.
   */
  CScrLuaInitForm* func_GetSpecialFileInfo_LuaFuncDef();

  /**
   * Address: 0x008455C0 (FUN_008455C0, cfunc_GetSpecialFileInfoL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Returns metadata table for one profile-scoped special file, or `nil` when
   * the file does not exist.
   */
  int cfunc_GetSpecialFileInfoL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00845DF0 (FUN_00845DF0, cfunc_RemoveProfileDirectories)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to
   * `cfunc_RemoveProfileDirectoriesL`.
   */
  int cfunc_RemoveProfileDirectories(lua_State* luaContext);

  /**
   * Address: 0x00845E10 (FUN_00845E10, func_RemoveProfileDirectories_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for
   * `RemoveProfileDirectories`.
   */
  CScrLuaInitForm* func_RemoveProfileDirectories_LuaFuncDef();

  /**
   * Address: 0x00845E70 (FUN_00845E70, cfunc_RemoveProfileDirectoriesL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Recycles replay/save profile-scoped directories and companion lanes for
   * one profile string.
   */
  int cfunc_RemoveProfileDirectoriesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00846200 (FUN_00846200, cfunc_CopyCurrentReplay)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_CopyCurrentReplayL`.
   */
  int cfunc_CopyCurrentReplay(lua_State* luaContext);

  /**
   * Address: 0x00846220 (FUN_00846220, func_CopyCurrentReplay_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `CopyCurrentReplay`.
   */
  CScrLuaInitForm* func_CopyCurrentReplay_LuaFuncDef();

  /**
   * Address: 0x00846280 (FUN_00846280, cfunc_CopyCurrentReplayL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Copies the localized `LastGame` replay from one profile lane to a new
   * replay filename in that profile.
   */
  int cfunc_CopyCurrentReplayL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00846F70 (FUN_00846F70, cfunc_SetOverlayFilters)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_SetOverlayFiltersL`.
   */
  int cfunc_SetOverlayFilters(lua_State* luaContext);

  /**
   * Address: 0x00846F90 (FUN_00846F90, func_SetOverlayFilters_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetOverlayFilters`.
   */
  CScrLuaInitForm* func_SetOverlayFilters_LuaFuncDef();

  /**
   * Address: 0x00846FF0 (FUN_00846FF0, cfunc_SetOverlayFiltersL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads one Lua table of filter strings and replaces
   * `CWldSession::mOverlayFilters`.
   */
  int cfunc_SetOverlayFiltersL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00847A20 (FUN_00847A20, cfunc_ClearBuildTemplates)
   *
   * What it does:
   * Clears user-session build-template state when a world session is active.
   */
  int cfunc_ClearBuildTemplates(lua_State* luaContext);

  /**
   * Address: 0x00847A50 (FUN_00847A50, func_ClearBuildTemplates_LuaFuncDef)
   *
   * What it does:
   * Publishes the global user-Lua binder definition for `ClearBuildTemplates`.
   */
  CScrLuaInitForm* func_ClearBuildTemplates_LuaFuncDef();

  /**
   * Address: 0x00847AD0 (FUN_00847AD0, cfunc_RenderOverlayMilitary)
   *
   * What it does:
   * Retains legacy `RenderOverlayMilitary(bool)` argument validation and emits
   * a deprecation warning.
   */
  int cfunc_RenderOverlayMilitary(lua_State* luaContext);

  /**
   * Address: 0x00847B20 (FUN_00847B20, func_RenderOverlayMilitary_LuaFuncDef)
   *
   * What it does:
   * Publishes the global user-Lua binder definition for `RenderOverlayMilitary`.
   */
  CScrLuaInitForm* func_RenderOverlayMilitary_LuaFuncDef();

  /**
   * Address: 0x00847BC0 (FUN_00847BC0, cfunc_RenderOverlayIntel)
   *
   * What it does:
   * Retains legacy `RenderOverlayIntel(bool)` argument validation and emits a
   * deprecation warning.
   */
  int cfunc_RenderOverlayIntel(lua_State* luaContext);

  /**
   * Address: 0x00847C10 (FUN_00847C10, func_RenderOverlayIntel_LuaFuncDef)
   *
   * What it does:
   * Publishes the global user-Lua binder definition for `RenderOverlayIntel`.
   */
  CScrLuaInitForm* func_RenderOverlayIntel_LuaFuncDef();

  /**
   * Address: 0x00847CB0 (FUN_00847CB0, cfunc_RenderOverlayEconomy)
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to
   * `cfunc_RenderOverlayEconomyL`.
   */
  int cfunc_RenderOverlayEconomy(lua_State* luaContext);

  /**
   * Address: 0x00847CD0 (FUN_00847CD0, func_RenderOverlayEconomy_LuaFuncDef)
   *
   * What it does:
   * Publishes the global user-Lua binder definition for `RenderOverlayEconomy`.
   */
  CScrLuaInitForm* func_RenderOverlayEconomy_LuaFuncDef();

  /**
   * Address: 0x00847D30 (FUN_00847D30, cfunc_RenderOverlayEconomyL)
   *
   * What it does:
   * Reads one Lua bool and updates the active user session economy-overlay flag.
   */
  int cfunc_RenderOverlayEconomyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00847D90 (FUN_00847D90, cfunc_TeamColorMode)
   *
   * What it does:
   * Unwraps Lua callback context and dispatches to `cfunc_TeamColorModeL`.
   */
  int cfunc_TeamColorMode(lua_State* luaContext);

  /**
   * Address: 0x00847DB0 (FUN_00847DB0, func_TeamColorMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the global user-Lua binder definition for `TeamColorMode`.
   */
  CScrLuaInitForm* func_TeamColorMode_LuaFuncDef();

  /**
   * Address: 0x00847E10 (FUN_00847E10, cfunc_TeamColorModeL)
   *
   * What it does:
   * Validates one Lua bool and updates the active user session team-color mode.
   */
  int cfunc_TeamColorModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00847E70 (FUN_00847E70, cfunc_GetUnitByIdUser)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GetUnitByIdUserL`.
   */
  int cfunc_GetUnitByIdUser(lua_State* luaContext);

  /**
   * Address: 0x00847E90 (FUN_00847E90, func_GetUnitByIdUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global user-Lua binder definition for `GetUnitById`.
   */
  CScrLuaInitForm* func_GetUnitByIdUser_LuaFuncDef();

  /**
   * Address: 0x00847EF0 (FUN_00847EF0, cfunc_GetUnitByIdUserL)
   *
   * What it does:
   * Resolves one entity-id string through user session map lanes and returns
   * the unit Lua object when the id maps to a user unit.
   */
  int cfunc_GetUnitByIdUserL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0128B884 (FUN_0128B884, cfunc_GetDepositsAroundPoint)
   *
   * lua_State *
   *
   * What it does:
   * Builds and returns a Lua array of deposits near (`x`,`z`) within `radius`.
   */
  int cfunc_GetDepositsAroundPoint(lua_State* luaContext);

  /**
   * Address: 0x0128BB27 (FUN_0128BB27, cfunc_SessionIsReplaySim)
   *
   * lua_State *
   *
   * What it does:
   * Pushes whether the active world session is running replay mode.
   */
  int cfunc_SessionIsReplaySim(lua_State* luaContext);

  /**
   * Address: 0x0128BBFC (FUN_0128BBFC, cfunc_SetFocusArmySim)
   *
   * lua_State *
   *
   * What it does:
   * Updates the active driver pending focus-army index from Lua arg #1.
   */
  int cfunc_SetFocusArmySim(lua_State* luaContext);

  /**
   * Address: 0x0128BB51 (FUN_0128BB51, cfunc_SetCommandSourceSim)
   *
   * lua_State *
   *
   * What it does:
   * Updates one bit in the target army's valid-command-source set.
   */
  int cfunc_SetCommandSourceSim(lua_State* luaContext);

  /**
   * Address: 0x005284D0 (FUN_005284D0, cfunc_SpecFootprints)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_SpecFootprintsL`.
   */
  int cfunc_SpecFootprints(lua_State* luaContext);

  /**
   * Address: 0x00528550 (FUN_00528550, cfunc_SpecFootprintsL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Loads one Lua table-array of footprint specs into the rules footprint list.
   */
  int cfunc_SpecFootprintsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005284F0 (FUN_005284F0, func_SpecFootprints_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SpecFootprints`.
   */
  CScrLuaInitForm* func_SpecFootprints_LuaFuncDef();

  /**
   * Address: 0x00528AF0 (FUN_00528AF0, cfunc_RegisterUnitBlueprint)
   *
   * lua_State *
   *
   * What it does:
   * Lua callback lane for `RegisterUnitBlueprint`.
   */
  int cfunc_RegisterUnitBlueprint(lua_State* luaContext);

  /**
   * Address: 0x00528B30 (FUN_00528B30, func_RegisterUnitBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-Lua binder definition for `RegisterUnitBlueprint`.
   */
  CScrLuaInitForm* func_RegisterUnitBlueprint_LuaFuncDef();

  /**
   * Address: 0x00528BC0 (FUN_00528BC0, cfunc_RegisterPropBlueprint)
   *
   * lua_State *
   *
   * What it does:
   * Lua callback lane for `RegisterPropBlueprint`.
   */
  int cfunc_RegisterPropBlueprint(lua_State* luaContext);

  /**
   * Address: 0x00528C00 (FUN_00528C00, func_RegisterPropBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-Lua binder definition for `RegisterPropBlueprint`.
   */
  CScrLuaInitForm* func_RegisterPropBlueprint_LuaFuncDef();

  /**
   * Address: 0x00528C90 (FUN_00528C90, cfunc_RegisterProjectileBlueprint)
   *
   * lua_State *
   *
   * What it does:
   * Lua callback lane for `RegisterProjectileBlueprint`.
   */
  int cfunc_RegisterProjectileBlueprint(lua_State* luaContext);

  /**
   * Address: 0x00528CD0 (FUN_00528CD0, func_RegisterProjectileBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-Lua binder definition for `RegisterProjectileBlueprint`.
   */
  CScrLuaInitForm* func_RegisterProjectileBlueprint_LuaFuncDef();

  /**
   * Address: 0x00528D60 (FUN_00528D60, cfunc_RegisterMeshBlueprint)
   *
   * lua_State *
   *
   * What it does:
   * Lua callback lane for `RegisterMeshBlueprint`.
   */
  int cfunc_RegisterMeshBlueprint(lua_State* luaContext);

  /**
   * Address: 0x00528D90 (FUN_00528D90, func_RegisterMeshBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-Lua binder definition for `RegisterMeshBlueprint`.
   */
  CScrLuaInitForm* func_RegisterMeshBlueprint_LuaFuncDef();

  /**
   * Address: 0x00528E20 (FUN_00528E20, cfunc_RegisterTrailEmitterBlueprint)
   *
   * lua_State *
   *
   * What it does:
   * Lua callback lane for `RegisterTrailEmitterBlueprint`.
   */
  int cfunc_RegisterTrailEmitterBlueprint(lua_State* luaContext);

  /**
   * Address: 0x00528E50 (FUN_00528E50, func_RegisterTrailEmitterBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-Lua binder definition for `RegisterTrailEmitterBlueprint`.
   */
  CScrLuaInitForm* func_RegisterTrailEmitterBlueprint_LuaFuncDef();

  /**
   * Address: 0x00528ED0 (FUN_00528ED0, cfunc_RegisterEmitterBlueprint)
   *
   * lua_State *
   *
   * What it does:
   * Lua callback lane for `RegisterEmitterBlueprint`.
   */
  int cfunc_RegisterEmitterBlueprint(lua_State* luaContext);

  /**
   * Address: 0x00528F00 (FUN_00528F00, func_RegisterEmitterBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-Lua binder definition for `RegisterEmitterBlueprint`.
   */
  CScrLuaInitForm* func_RegisterEmitterBlueprint_LuaFuncDef();

  /**
   * Address: 0x00528F80 (FUN_00528F80, cfunc_RegisterBeamBlueprint)
   *
   * lua_State *
   *
   * What it does:
   * Lua callback lane for `RegisterBeamBlueprint`.
   */
  int cfunc_RegisterBeamBlueprint(lua_State* luaContext);

  /**
   * Address: 0x00528FB0 (FUN_00528FB0, func_RegisterBeamBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-Lua binder definition for `RegisterBeamBlueprint`.
   */
  CScrLuaInitForm* func_RegisterBeamBlueprint_LuaFuncDef();

  /**
   * Address: 0x00529030 (FUN_00529030, cfunc_BlueprintLoaderUpdateProgress)
   *
   * lua_State *
   *
   * What it does:
   * Lua callback lane for `BlueprintLoaderUpdateProgress`.
   */
  int cfunc_BlueprintLoaderUpdateProgress(lua_State* luaContext);

  /**
   * Address: 0x00529060 (FUN_00529060, func_BlueprintLoaderUpdateProgress_LuaFuncDef)
   *
   * What it does:
   * Publishes the core-Lua binder definition for `BlueprintLoaderUpdateProgress`.
   */
  CScrLuaInitForm* func_BlueprintLoaderUpdateProgress_LuaFuncDef();

  /**
   * Address: 0x00BC8E50 (FUN_00BC8E50, register_RegisterUnitBlueprint_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_RegisterUnitBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RegisterUnitBlueprint_LuaFuncDef();

  /**
   * Address: 0x00BC8E60 (FUN_00BC8E60, register_RegisterPropBlueprint_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_RegisterPropBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RegisterPropBlueprint_LuaFuncDef();

  /**
   * Address: 0x00BC8E70 (FUN_00BC8E70, register_RegisterProjectileBlueprint_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_RegisterProjectileBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RegisterProjectileBlueprint_LuaFuncDef();

  /**
   * Address: 0x00BC8E80 (FUN_00BC8E80, register_RegisterMeshBlueprint_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_RegisterMeshBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RegisterMeshBlueprint_LuaFuncDef();

  /**
   * Address: 0x00BC8E90 (FUN_00BC8E90, register_RegisterTrailEmitterBlueprint_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_RegisterTrailEmitterBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RegisterTrailEmitterBlueprint_LuaFuncDef();

  /**
   * Address: 0x00BC8EA0 (FUN_00BC8EA0, register_RegisterEmitterBlueprint_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_RegisterEmitterBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RegisterEmitterBlueprint_LuaFuncDef();

  /**
   * Address: 0x00BC8EB0 (FUN_00BC8EB0, j_func_RegisterBeamBlueprint_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_RegisterBeamBlueprint_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_RegisterBeamBlueprint_LuaFuncDef();

  /**
   * Address: 0x00BC8EC0 (FUN_00BC8EC0, j_func_BlueprintLoaderUpdateProgress_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_BlueprintLoaderUpdateProgress_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_BlueprintLoaderUpdateProgress_LuaFuncDef();

  /**
   * Address: 0x0074B110 (FUN_0074B110, ?SIM_FromLuaState@Moho@@YAPAVSim@1@PAVLuaState@LuaPlus@@@Z)
   *
   * What it does:
   * Returns the global `Sim*` bound to one Lua state's global user-data lane.
   */
  Sim* SIM_FromLuaState(LuaPlus::LuaState* state);

  /**
   * Address: 0x00707D60 (FUN_00707D60, ?ARMY_FromLuaState@Moho@@YAPAVSimArmy@1@PAVLuaState@LuaPlus@@VLuaObject@4@@Z)
   *
   * What it does:
   * Resolves a Lua army selector (1-based number or army name string) to
   * `CArmyImpl*`, raising Lua errors for invalid selectors.
   */
  CArmyImpl* ARMY_FromLuaState(LuaPlus::LuaState* state, const LuaPlus::LuaObject& armyObject);

  /**
   * Address: 0x00707F40 (FUN_00707F40, ?ARMY_IndexFromLuaState@Moho@@YAHPAVLuaState@LuaPlus@@VLuaObject@3@@Z)
   *
   * What it does:
   * Resolves a Lua army selector into a zero-based army index.
   */
  int ARMY_IndexFromLuaState(LuaPlus::LuaState* state, const LuaPlus::LuaObject& armyObject);

  /**
   * Address: 0x007080B0 (FUN_007080B0, cfunc_ShouldCreateInitialArmyUnits)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_ShouldCreateInitialArmyUnitsL`.
   */
  int cfunc_ShouldCreateInitialArmyUnits(lua_State* luaContext);

  /**
   * Address: 0x00708130 (FUN_00708130, cfunc_ShouldCreateInitialArmyUnitsL)
   *
   * What it does:
   * Returns whether startup should spawn initial army units for this run.
   */
  int cfunc_ShouldCreateInitialArmyUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007080D0 (FUN_007080D0, func_ShouldCreateInitialArmyUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ShouldCreateInitialArmyUnits`.
   */
  CScrLuaInitForm* func_ShouldCreateInitialArmyUnits_LuaFuncDef();

  /**
   * Address: 0x007081A0 (FUN_007081A0, cfunc_ListArmies)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_ListArmiesL`.
   */
  int cfunc_ListArmies(lua_State* luaContext);

  /**
   * Address: 0x00708220 (FUN_00708220, cfunc_ListArmiesL)
   *
   * What it does:
   * Returns a Lua table of army names in simulation order.
   */
  int cfunc_ListArmiesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007081C0 (FUN_007081C0, func_ListArmies_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ListArmies`.
   */
  CScrLuaInitForm* func_ListArmies_LuaFuncDef();

  /**
   * Address: 0x00708310 (FUN_00708310, cfunc_GetArmyBrain)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GetArmyBrainL`.
   */
  int cfunc_GetArmyBrain(lua_State* luaContext);

  /**
   * Address: 0x00708390 (FUN_00708390, cfunc_GetArmyBrainL)
   *
   * What it does:
   * Resolves one army selector and returns the army brain Lua object.
   */
  int cfunc_GetArmyBrainL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708330 (FUN_00708330, func_GetArmyBrain_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetArmyBrain`.
   */
  CScrLuaInitForm* func_GetArmyBrain_LuaFuncDef();

  /**
   * Address: 0x00708460 (FUN_00708460, cfunc_SetArmyStart)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyStartL`.
   */
  int cfunc_SetArmyStart(lua_State* luaContext);

  /**
   * Address: 0x007084E0 (FUN_007084E0, cfunc_SetArmyStartL)
   *
   * What it does:
   * Reads `(army, x, z)` from Lua and updates the army start-position lane.
   */
  int cfunc_SetArmyStartL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708480 (FUN_00708480, func_SetArmyStart_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyStart`.
   */
  CScrLuaInitForm* func_SetArmyStart_LuaFuncDef();

  /**
   * Address: 0x007085E0 (FUN_007085E0, cfunc_GenerateArmyStart)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GenerateArmyStartL`.
   */
  int cfunc_GenerateArmyStart(lua_State* luaContext);

  /**
   * Address: 0x00708660 (FUN_00708660, cfunc_GenerateArmyStartL)
   *
   * What it does:
   * Reads one army selector and triggers `CArmyImpl::GenerateArmyStart`.
   */
  int cfunc_GenerateArmyStartL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708600 (FUN_00708600, func_GenerateArmyStart_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GenerateArmyStart`.
   */
  CScrLuaInitForm* func_GenerateArmyStart_LuaFuncDef();

  /**
   * Address: 0x00708970 (FUN_00708970, cfunc_ArmyInitializePrebuiltUnits)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_ArmyInitializePrebuiltUnitsL`.
   */
  int cfunc_ArmyInitializePrebuiltUnits(lua_State* luaContext);

  /**
   * Address: 0x007089F0 (FUN_007089F0, cfunc_ArmyInitializePrebuiltUnitsL)
   *
   * What it does:
   * Resolves one army selector and runs the prebuilt-unit init script hook.
   */
  int cfunc_ArmyInitializePrebuiltUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708990 (FUN_00708990, func_ArmyInitializePrebuiltUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ArmyInitializePrebuiltUnits`.
   */
  CScrLuaInitForm* func_ArmyInitializePrebuiltUnits_LuaFuncDef();

  /**
   * Address: 0x007090A0 (FUN_007090A0, cfunc_SetIgnoreArmyUnitCap)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetIgnoreArmyUnitCapL`.
   */
  int cfunc_SetIgnoreArmyUnitCap(lua_State* luaContext);

  /**
   * Address: 0x00709120 (FUN_00709120, cfunc_SetIgnoreArmyUnitCapL)
   *
   * What it does:
   * Reads `(army, flag)` from Lua and updates army unit-cap ignore mode.
   */
  int cfunc_SetIgnoreArmyUnitCapL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007090C0 (FUN_007090C0, func_SetIgnoreArmyUnitCap_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetIgnoreArmyUnitCap`.
   */
  CScrLuaInitForm* func_SetIgnoreArmyUnitCap_LuaFuncDef();

  /**
   * Address: 0x007091B0 (FUN_007091B0, cfunc_SetIgnorePlayableRect)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetIgnorePlayableRectL`.
   */
  int cfunc_SetIgnorePlayableRect(lua_State* luaContext);

  /**
   * Address: 0x00709230 (FUN_00709230, cfunc_SetIgnorePlayableRectL)
   *
   * What it does:
   * Reads `(army, flag)` from Lua and updates playable-rect ignore mode.
   */
  int cfunc_SetIgnorePlayableRectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007091D0 (FUN_007091D0, func_SetIgnorePlayableRect_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetIgnorePlayableRect`.
   */
  CScrLuaInitForm* func_SetIgnorePlayableRect_LuaFuncDef();

  /**
   * Address: 0x007099C0 (FUN_007099C0, cfunc_IsAllySim)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsAllySimL`.
   */
  int cfunc_IsAllySim(lua_State* luaContext);

  /**
   * Address: 0x007099E0 (FUN_007099E0, func_IsAllySim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsAlly`.
   */
  CScrLuaInitForm* func_IsAllySim_LuaFuncDef();

  /**
   * Address: 0x00709A40 (FUN_00709A40, cfunc_IsAllySimL)
   *
   * What it does:
   * Reads `(army1, army2)` and returns whether army1 treats army2 as allied.
   */
  int cfunc_IsAllySimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00709AF0 (FUN_00709AF0, cfunc_IsEnemySim)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsEnemySimL`.
   */
  int cfunc_IsEnemySim(lua_State* luaContext);

  /**
   * Address: 0x00709B10 (FUN_00709B10, func_IsEnemySim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsEnemy`.
   */
  CScrLuaInitForm* func_IsEnemySim_LuaFuncDef();

  /**
   * Address: 0x00709B70 (FUN_00709B70, cfunc_IsEnemySimL)
   *
   * What it does:
   * Reads `(army1, army2)` and returns whether army1 treats army2 as enemy.
   */
  int cfunc_IsEnemySimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00709C20 (FUN_00709C20, cfunc_IsNeutralSim)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_IsNeutralSimL`.
   */
  int cfunc_IsNeutralSim(lua_State* luaContext);

  /**
   * Address: 0x00709C40 (FUN_00709C40, func_IsNeutralSim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsNeutral`.
   */
  CScrLuaInitForm* func_IsNeutralSim_LuaFuncDef();

  /**
   * Address: 0x00709CA0 (FUN_00709CA0, cfunc_IsNeutralSimL)
   *
   * What it does:
   * Reads `(army1, army2)` and returns whether army1 treats army2 as neutral.
   */
  int cfunc_IsNeutralSimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00709D50 (FUN_00709D50, cfunc_ArmyIsCivilian)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_ArmyIsCivilianL`.
   */
  int cfunc_ArmyIsCivilian(lua_State* luaContext);

  /**
   * Address: 0x00709D70 (FUN_00709D70, func_ArmyIsCivilian_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ArmyIsCivilian`.
   */
  CScrLuaInitForm* func_ArmyIsCivilian_LuaFuncDef();

  /**
   * Address: 0x00709DD0 (FUN_00709DD0, cfunc_ArmyIsCivilianL)
   *
   * What it does:
   * Returns whether the selected army is civilian.
   */
  int cfunc_ArmyIsCivilianL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00709FB0 (FUN_00709FB0, cfunc_SetArmyFactionIndex)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyFactionIndexL`.
   */
  int cfunc_SetArmyFactionIndex(lua_State* luaContext);

  /**
   * Address: 0x00709FD0 (FUN_00709FD0, func_SetArmyFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyFactionIndex`.
   */
  CScrLuaInitForm* func_SetArmyFactionIndex_LuaFuncDef();

  /**
   * Address: 0x0070A030 (FUN_0070A030, cfunc_SetArmyFactionIndexL)
   *
   * What it does:
   * Reads `(army, index)` and updates the army faction index lane.
   */
  int cfunc_SetArmyFactionIndexL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0070A920 (FUN_0070A920, cfunc_OkayToMessWithArmy)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_OkayToMessWithArmyL`.
   */
  int cfunc_OkayToMessWithArmy(lua_State* luaContext);

  /**
   * Address: 0x0070A940 (FUN_0070A940, func_OkayToMessWithArmy_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `OkayToMessWithArmy`.
   */
  CScrLuaInitForm* func_OkayToMessWithArmy_LuaFuncDef();

  /**
   * Address: 0x0070A9A0 (FUN_0070A9A0, cfunc_OkayToMessWithArmyL)
   *
   * What it does:
   * Returns true when current command source is valid for that army or cheats
   * are enabled.
   */
  int cfunc_OkayToMessWithArmyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0070AA60 (FUN_0070AA60, cfunc_ArmyIsOutOfGame)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_ArmyIsOutOfGameL`.
   */
  int cfunc_ArmyIsOutOfGame(lua_State* luaContext);

  /**
   * Address: 0x0070AA80 (FUN_0070AA80, func_ArmyIsOutOfGame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ArmyIsOutOfGame`.
   */
  CScrLuaInitForm* func_ArmyIsOutOfGame_LuaFuncDef();

  /**
   * Address: 0x0070AAE0 (FUN_0070AAE0, cfunc_ArmyIsOutOfGameL)
   *
   * What it does:
   * Returns whether the selected army has been marked out-of-game.
   */
  int cfunc_ArmyIsOutOfGameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0070AB60 (FUN_0070AB60, cfunc_SetArmyOutOfGame)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyOutOfGameL`.
   */
  int cfunc_SetArmyOutOfGame(lua_State* luaContext);

  /**
   * Address: 0x0070AB80 (FUN_0070AB80, func_SetArmyOutOfGame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyOutOfGame`.
   */
  CScrLuaInitForm* func_SetArmyOutOfGame_LuaFuncDef();

  /**
   * Address: 0x0070ABE0 (FUN_0070ABE0, cfunc_SetArmyOutOfGameL)
   *
   * What it does:
   * Marks one selected army as out-of-game.
   */
  int cfunc_SetArmyOutOfGameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708B90 (FUN_00708B90, cfunc_SetArmyEconomy)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyEconomyL`.
   */
  int cfunc_SetArmyEconomy(lua_State* luaContext);

  /**
   * Address: 0x00708C10 (FUN_00708C10, cfunc_SetArmyEconomyL)
   *
   * What it does:
   * Reads `(army, mass, energy)` and applies stored-economy deltas.
   */
  int cfunc_SetArmyEconomyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708BB0 (FUN_00708BB0, func_SetArmyEconomy_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyEconomy`.
   */
  CScrLuaInitForm* func_SetArmyEconomy_LuaFuncDef();

  /**
   * Address: 0x00708D60 (FUN_00708D60, cfunc_GetArmyUnitCostTotal)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GetArmyUnitCostTotalL`.
   */
  int cfunc_GetArmyUnitCostTotal(lua_State* luaContext);

  /**
   * Address: 0x00708DE0 (FUN_00708DE0, cfunc_GetArmyUnitCostTotalL)
   *
   * What it does:
   * Resolves one army selector and returns total unit cost as Lua number.
   */
  int cfunc_GetArmyUnitCostTotalL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708D80 (FUN_00708D80, func_GetArmyUnitCostTotal_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetArmyUnitCostTotal`.
   */
  CScrLuaInitForm* func_GetArmyUnitCostTotal_LuaFuncDef();

  /**
   * Address: 0x00708A70 (FUN_00708A70, cfunc_ArmyGetHandicap)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_ArmyGetHandicapL`.
   */
  int cfunc_ArmyGetHandicap(lua_State* luaContext);

  /**
   * Address: 0x00708AF0 (FUN_00708AF0, cfunc_ArmyGetHandicapL)
   *
   * What it does:
   * Reads one army selector and returns configured handicap or zero.
   */
  int cfunc_ArmyGetHandicapL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708A90 (FUN_00708A90, func_ArmyGetHandicap_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ArmyGetHandicap`.
   */
  CScrLuaInitForm* func_ArmyGetHandicap_LuaFuncDef();

  /**
   * Address: 0x00708E60 (FUN_00708E60, cfunc_GetArmyUnitCap)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GetArmyUnitCapL`.
   */
  int cfunc_GetArmyUnitCap(lua_State* luaContext);

  /**
   * Address: 0x00708EE0 (FUN_00708EE0, cfunc_GetArmyUnitCapL)
   *
   * What it does:
   * Resolves one army selector and returns that army unit cap as a Lua number.
   */
  int cfunc_GetArmyUnitCapL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708E80 (FUN_00708E80, func_GetArmyUnitCap_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetArmyUnitCap`.
   */
  CScrLuaInitForm* func_GetArmyUnitCap_LuaFuncDef();

  /**
   * Address: 0x00708F70 (FUN_00708F70, cfunc_SetArmyUnitCap)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyUnitCapL`.
   */
  int cfunc_SetArmyUnitCap(lua_State* luaContext);

  /**
   * Address: 0x00708FF0 (FUN_00708FF0, cfunc_SetArmyUnitCapL)
   *
   * What it does:
   * Reads `(army, unitCap)` from Lua and updates the army unit-cap lane.
   */
  int cfunc_SetArmyUnitCapL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708F90 (FUN_00708F90, func_SetArmyUnitCap_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyUnitCap`.
   */
  CScrLuaInitForm* func_SetArmyUnitCap_LuaFuncDef();

  /**
   * Address: 0x0070A100 (FUN_0070A100, cfunc_SetArmyAIPersonality)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyAIPersonalityL`.
   */
  int cfunc_SetArmyAIPersonality(lua_State* luaContext);

  /**
   * Address: 0x0070A180 (FUN_0070A180, cfunc_SetArmyAIPersonalityL)
   *
   * What it does:
   * Reads `(army, personality)` from Lua and updates the army personality lane.
   */
  int cfunc_SetArmyAIPersonalityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0070A120 (FUN_0070A120, func_SetArmyAIPersonality_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyAIPersonality`.
   */
  CScrLuaInitForm* func_SetArmyAIPersonality_LuaFuncDef();

  /**
   * Address: 0x0070A5E0 (FUN_0070A5E0, cfunc_SetArmyShowScore)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyShowScoreL`.
   */
  int cfunc_SetArmyShowScore(lua_State* luaContext);

  /**
   * Address: 0x0070A660 (FUN_0070A660, cfunc_SetArmyShowScoreL)
   *
   * What it does:
   * Reads `(army, showScore)` and stores that score-visibility bit in army
   * runtime variable data.
   */
  int cfunc_SetArmyShowScoreL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0070A600 (FUN_0070A600, func_SetArmyShowScore_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyShowScore`.
   */
  CScrLuaInitForm* func_SetArmyShowScore_LuaFuncDef();

  /**
   * Address: 0x007086D0 (FUN_007086D0, cfunc_SetArmyPlans)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyPlansL`.
   */
  int cfunc_SetArmyPlans(lua_State* luaContext);

  /**
   * Address: 0x00708750 (FUN_00708750, cfunc_SetArmyPlansL)
   *
   * What it does:
   * Reads `(army, plans)` from Lua and writes the plans string to the army.
   */
  int cfunc_SetArmyPlansL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007086F0 (FUN_007086F0, func_SetArmyPlans_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyPlans`.
   */
  CScrLuaInitForm* func_SetArmyPlans_LuaFuncDef();

  /**
   * Address: 0x00708870 (FUN_00708870, cfunc_InitializeArmyAI)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_InitializeArmyAIL`.
   */
  int cfunc_InitializeArmyAI(lua_State* luaContext);

  /**
   * Address: 0x007088F0 (FUN_007088F0, cfunc_InitializeArmyAIL)
   *
   * What it does:
   * Resolves one army selector and initializes that army's script brain lane.
   */
  int cfunc_InitializeArmyAIL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00708890 (FUN_00708890, func_InitializeArmyAI_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `InitializeArmyAI`.
   */
  CScrLuaInitForm* func_InitializeArmyAI_LuaFuncDef();

  /**
   * Address: 0x0070A2A0 (FUN_0070A2A0, cfunc_SetArmyColor)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetArmyColorL`.
   */
  int cfunc_SetArmyColor(lua_State* luaContext);

  /**
   * Address: 0x0070A320 (FUN_0070A320, cfunc_SetArmyColorL)
   *
   * What it does:
   * Reads `(army, r, g, b)` from Lua and applies packed color to the army.
   */
  int cfunc_SetArmyColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0070A2C0 (FUN_0070A2C0, func_SetArmyColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyColor`.
   */
  CScrLuaInitForm* func_SetArmyColor_LuaFuncDef();

  /**
   * Address: 0x00709590 (FUN_00709590, cfunc_SetAlliance)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetAllianceL`.
   */
  int cfunc_SetAlliance(lua_State* luaContext);

  /**
   * Address: 0x007095B0 (FUN_007095B0, func_SetAlliance_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetAlliance`.
   */
  CScrLuaInitForm* func_SetAlliance_LuaFuncDef();

  /**
   * Address: 0x00709610 (FUN_00709610, cfunc_SetAllianceL)
   *
   * What it does:
   * Reads `(army1, army2, relation)` and writes symmetric alliance relation
   * lanes on both armies.
   */
  int cfunc_SetAllianceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00709720 (FUN_00709720, cfunc_SetAllianceOneWay)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetAllianceOneWayL`.
   */
  int cfunc_SetAllianceOneWay(lua_State* luaContext);

  /**
   * Address: 0x00709740 (FUN_00709740, func_SetAllianceOneWay_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetAllianceOneWay`.
   */
  CScrLuaInitForm* func_SetAllianceOneWay_LuaFuncDef();

  /**
   * Address: 0x007097A0 (FUN_007097A0, cfunc_SetAllianceOneWayL)
   *
   * What it does:
   * Reads `(army1, army2, relation)` and writes one-way alliance relation on
   * the first army only.
   */
  int cfunc_SetAllianceOneWayL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007098A0 (FUN_007098A0, cfunc_SetAlliedVictory)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_SetAlliedVictoryL`.
   */
  int cfunc_SetAlliedVictory(lua_State* luaContext);

  /**
   * Address: 0x00709920 (FUN_00709920, cfunc_SetAlliedVictoryL)
   *
   * What it does:
   * Reads `(army, enabled)` and writes `RequestingAlliedVictory` on the army
   * brain script object.
   */
  int cfunc_SetAlliedVictoryL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007098C0 (FUN_007098C0, func_SetAlliedVictory_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetAlliedVictory`.
   */
  CScrLuaInitForm* func_SetAlliedVictory_LuaFuncDef();

  /**
   * Address: 0x0074B9F0 (FUN_0074B9F0, cfunc_GetEntityById)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GetEntityByIdL`.
   */
  int cfunc_GetEntityById(lua_State* luaContext);

  /**
   * Address: 0x0074BA10 (FUN_0074BA10, func_GetEntityById_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetEntityById`.
   */
  CScrLuaInitForm* func_GetEntityById_LuaFuncDef();

  /**
   * Address: 0x0074BA70 (FUN_0074BA70, cfunc_GetEntityByIdL)
   *
   * What it does:
   * Resolves one string entity-id argument and returns matching entity Lua
   * object (or nil).
   */
  int cfunc_GetEntityByIdL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0074BB40 (FUN_0074BB40, cfunc_GetUnitByIdSim)
   *
   * What it does:
   * Unwraps Lua callback state and forwards to `cfunc_GetUnitByIdSimL`.
   */
  int cfunc_GetUnitByIdSim(lua_State* luaContext);

  /**
   * Address: 0x0074BB60 (FUN_0074BB60, func_GetUnitByIdSim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetUnitById`.
   */
  CScrLuaInitForm* func_GetUnitByIdSim_LuaFuncDef();

  /**
   * Address: 0x0074BBC0 (FUN_0074BBC0, cfunc_GetUnitByIdSimL)
   *
   * What it does:
   * Resolves one string entity-id argument and returns the matching unit Lua
   * object when that id is a unit (or nil).
   */
  int cfunc_GetUnitByIdSimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0074B850 (FUN_0074B850, func_EndGame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EndGame`.
   */
  CScrLuaInitForm* func_EndGame_LuaFuncDef();

  /**
   * Address: 0x0074B920 (FUN_0074B920, func_IsGameOver_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsGameOver`.
   */
  CScrLuaInitForm* func_IsGameOver_LuaFuncDef();

  /**
   * Address: 0x0075C7D0 (FUN_0075C7D0, func_SetPlayableRect_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetPlayableRect`.
   */
  CScrLuaInitForm* func_SetPlayableRect_LuaFuncDef();

  /**
   * Address: 0x0075CDD0 (FUN_0075CDD0, cfunc_GetFocusArmySim)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_GetFocusArmySimL`.
   */
  int cfunc_GetFocusArmySim(lua_State* luaContext);

  /**
   * Address: 0x0075CDF0 (FUN_0075CDF0, func_GetFocusArmySim_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GetFocusArmy()` Lua binder for sim state.
   */
  CScrLuaInitForm* func_GetFocusArmySim_LuaFuncDef();

  /**
   * Address: 0x0075CE50 (FUN_0075CE50, cfunc_GetFocusArmySimL)
   *
   * What it does:
   * Validates no Lua args and returns current focused army index (1-based, or
   * `-1` when unset).
   */
  int cfunc_GetFocusArmySimL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0075CEC0 (FUN_0075CEC0, cfunc_AudioSetLanguageSim)
   *
   * What it does:
   * Validates `AudioSetLanguage(name)` argument count for sim Lua lane.
   */
  int cfunc_AudioSetLanguageSim(lua_State* luaContext);

  /**
   * Address: 0x0075CF00 (FUN_0075CF00, func_AudioSetLanguageSim_LuaFuncDef)
   *
   * What it does:
   * Publishes global `AudioSetLanguage(name)` Lua binder in the sim init set.
   */
  CScrLuaInitForm* func_AudioSetLanguageSim_LuaFuncDef();

  /**
   * Address: 0x0075CF90 (FUN_0075CF90, cfunc_HasLocalizedVOSim)
   *
   * What it does:
   * Validates `HasLocalizedVO(language)` argument count on the sim Lua lane.
   */
  int cfunc_HasLocalizedVOSim(lua_State* luaContext);

  /**
   * Address: 0x0075CFD0 (FUN_0075CFD0, func_HasLocalizedVOSim_LuaFuncDef)
   *
   * What it does:
   * Publishes global `HasLocalizedVO(language)` Lua binder in the sim init
   * set.
   */
  CScrLuaInitForm* func_HasLocalizedVOSim_LuaFuncDef();

  /**
   * Address: 0x0075DA80 (FUN_0075DA80, cfunc_SubmitXMLArmyStats)
   *
   * What it does:
   * Validates no args and raises the sim-side XML army-stats submit request
   * flag.
   */
  int cfunc_SubmitXMLArmyStats(lua_State* luaContext);

  /**
   * Address: 0x0075DAD0 (FUN_0075DAD0, func_SubmitXMLArmyStats_LuaFuncDef)
   *
   * What it does:
   * Publishes global `SubmitXMLArmyStats()` Lua binder in the sim init set.
   */
  CScrLuaInitForm* func_SubmitXMLArmyStats_LuaFuncDef();

  /**
   * Address: 0x00761570 (FUN_00761570, cfunc_PlayLoop)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_PlayLoopL`.
   */
  int cfunc_PlayLoop(lua_State* luaContext);

  /**
   * Address: 0x00761590 (FUN_00761590, func_PlayLoop_LuaFuncDef)
   *
   * What it does:
   * Publishes global `PlayLoop(sndParams)` Lua binder in the sim init set.
   */
  CScrLuaInitForm* func_PlayLoop_LuaFuncDef();

  /**
   * Address: 0x007615F0 (FUN_007615F0, cfunc_PlayLoopL)
   *
   * What it does:
   * Builds one `HSound` loop handle from `CSndParams`, queues it in sim sound
   * manager, binds Lua userdata, and returns the handle object.
   */
  int cfunc_PlayLoopL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00761700 (FUN_00761700, cfunc_StopLoop)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_StopLoopL`.
   */
  int cfunc_StopLoop(lua_State* luaContext);

  /**
   * Address: 0x00761720 (FUN_00761720, func_StopLoop_LuaFuncDef)
   *
   * What it does:
   * Publishes global `StopLoop(handle)` Lua binder in the sim init set.
   */
  CScrLuaInitForm* func_StopLoop_LuaFuncDef();

  /**
   * Address: 0x00761780 (FUN_00761780, cfunc_StopLoopL)
   *
   * What it does:
   * Resolves one `HSound` loop handle and either requests stop on sim sound
   * manager or destroys the unbound handle when no manager exists.
   */
  int cfunc_StopLoopL(LuaPlus::LuaState* state);

  /**
   * Address: 0x010A6395 (ren_Steering)
   *
   * What it does:
   * Enables steering debug overlay rendering during `CAiSteeringImpl::Execute`.
   */
  extern std::uint8_t ren_Steering;

  /**
   * Address: 0x010A63D7 (?sim_KeepAllLogFiles@Moho@@3_NA)
   *
   * What it does:
   * Keeps all per-beat sim checksum log files when enabled.
   */
  extern bool sim_KeepAllLogFiles;

  /**
   * VFTABLE: 0x00E3481C
   * COL:  0x00E8DF18
   */
  class SimSerializer
  {
  public:
    /**
     * Address: 0x0074CFB0 (FUN_0074CFB0, sub_74CFB0)
     * Slot: 0
     *
     * What it does:
     * Binds Sim RTTI serializer callbacks (`serLoadFunc_` / `serSaveFunc_`).
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    // Set by Sim serializer init helpers (0x0074CF80 / 0x00744F90) to 0x00744F70.
    gpg::RType::load_func_t mSerLoadFunc;
    // Set by Sim serializer init helpers (0x0074CF80 / 0x00744F90) to 0x00744F80.
    gpg::RType::save_func_t mSerSaveFunc;
  };

  /**
   * VFTABLE: 0x00E347EC
   * COL:  0x00E8DFB0
   *
   * Source hints:
   * - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  class SimTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x007432C0 (FUN_007432C0, sub_7432C0)
     * Slot: 2
     * Demangled: SimTypeInfo scalar deleting destructor thunk.
     */
    ~SimTypeInfo() override;

    /**
     * Address: 0x007432B0 (FUN_007432B0, sub_7432B0)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for Sim.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00743290 (FUN_00743290, sub_743290)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for Sim, then performs base-init/finalization.
     * (Calls 0x008D8680 nullsub_45 in retail, then Finish()).
     */
    void Init() override;
  };

#if defined(_M_IX86)
  static_assert(sizeof(SimSerializer) == 0x14, "SimSerializer size must be 0x14");
  static_assert(sizeof(SimTypeInfo) == 0x64, "SimTypeInfo size must be 0x64");
  static_assert(sizeof(CRandomStream) == 0x9CC, "CRandomStream size must be 0x9CC");
  static_assert(offsetof(Sim, mLog) == 0x20, "Sim::mLog offset must be 0x20");
  static_assert(offsetof(Sim, mDesyncLogLine) == 0x24, "Sim::mDesyncLogLine offset must be 0x24");
  static_assert(offsetof(Sim, mDesyncLogLines) == 0x40, "Sim::mDesyncLogLines offset must be 0x40");
  static_assert(offsetof(Sim, mIsDesyncFree) == 0x4C, "Sim::mIsDesyncFree offset must be 0x4C");
  static_assert(offsetof(Sim, mCoordEntities) == 0x0A5C, "Sim::mCoordEntities offset must be 0x0A5C");
  static_assert(
    offsetof(Sim, mRequestXMLArmyStatsSubmit) == 0x0A64, "Sim::mRequestXMLArmyStatsSubmit offset must be 0x0A64"
  );
  static_assert(offsetof(Sim, mSyncArmy) == 0x0A68, "Sim::mSyncArmy offset must be 0x0A68");
  static_assert(offsetof(Sim, mDidSync) == 0x0A6C, "Sim::mDidSync offset must be 0x0A6C");
  static_assert(offsetof(Sim, mSyncReserveCounts) == 0x0A70, "Sim::mSyncReserveCounts offset must be 0x0A70");
  static_assert(offsetof(Sim, mSyncReserveUnused) == 0x0A84, "Sim::mSyncReserveUnused offset must be 0x0A84");
  static_assert(offsetof(Sim, mSyncFilter) == 0x0A88, "Sim::mSyncFilter offset must be 0x0A88");
  static_assert(sizeof(Sim) == 0xAF8, "Sim size must be 0xAF8");
#endif
} // namespace moho
