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
    msvc8::list<void*> mDesyncLogLines;
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
   * Address: 0x010A6395 (ren_Steering)
   *
   * What it does:
   * Enables steering debug overlay rendering during `CAiSteeringImpl::Execute`.
   */
  extern std::uint8_t ren_Steering;

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
