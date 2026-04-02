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
#include "moho/render/SParticleBuffer.h"
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
     * Address: 0x007487C0
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
     * Address: 0x00748D50
     */
    void ProcessInfoPair(void* id, const char* key, const char* val) override;

    /**
     * Address: 0x00749290
     *
     * Moho::BVSet<Moho::EntId,Moho::EntIdUniverse> const &,Moho::SSTICommandIssueData const &,bool
     *
     * IDA signature:
     * char __userpurge Moho__Sim__IssueCommand@<al>(Moho::Sim *this@<ecx>, int esi0@<esi>, int *a3,
     * Moho::SSTICommandIssueData *commandIssueData, BOOL flag);
     */
    void
    IssueCommand(const BVSet<EntId, EntIdUniverse>&, const SSTICommandIssueData& commandIssueData, bool flag) override;

    /**
     * Address: 0x007494B0
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
     * Address: 0x00749B60
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
     * Address: 0x00749F40
     */
    void AdvanceBeat(int) override;

    /**
     * Address: 0x0074B100
     */
    void EndGame() override;

    /**
     * Address: 0x007473B0
     * @param cmd
     * @return
     */
    bool OkayToMessWith(CUnitCommand* cmd);

    /**
     * Address: 0x00747320
     */
    bool OkayToMessWith(SimArmy* army);

    /**
     * Address: 0x00747360
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
     * Address: 0x00746280 (FUN_00746280, ?Logf@Sim@Moho@@QAAXPBDZZ)
     *
     * What it does:
     * Writes formatted text to the current sim log file when logging is enabled.
     */
    std::FILE* Logf(const char* fmt, ...);

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

    /**
     * Address: 0x00747180
     */
    bool CheatsEnabled();

    /**
     * Address: 0x007466F0
     */
    const char* GetCurrentCommandSourceName() const;

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
   * Address: 0x00843250 (FUN_00843250, cfunc_GetGameTimeL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads active session game time and pushes formatted `HH:MM:SS` text.
   */
  int cfunc_GetGameTimeL(LuaPlus::LuaState* state);

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
