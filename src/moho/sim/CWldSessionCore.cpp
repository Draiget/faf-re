#include "moho/net/CClientManagerImpl.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimKeyframe.h"
#include "moho/sim/CWldSessionPrivate.h"
#include "moho/ui/CUIWorldMesh.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/render/WRenViewport.h"

namespace moho
{

  // Beat-scoped console toggles, defined in `moho/misc/RuntimeTuningGlobals.cpp`.
  extern bool ren_FogOfWar;
  extern bool dbg_Metronome;
  extern bool wld_RunWithTheWind;

  /// Lazily-bound engine-stat handles. `DoBeat` publishes how many units it
  /// ticked; `SessionFrame` publishes how many beats the drain consumed.
  StatItem* sEngineStat_UserSync_SessionTick_NumTickers = nullptr;
  StatItem* sEngineStat_Sync_Count = nullptr;

  /// Engine addition (wld_FrameClock): whether the current session has shown a tick yet, and
  /// whether the app should start its frame-time window afresh (`WLD_TakeFrameClockReset`).
  /// Main thread only.
  bool gSessionShowedTick = false;
  bool gFrameClockResetPending = false;

  /// Engine addition: this client's ready message waits for the frame after the one that built the
  /// game interface (WLD_DoPostInitializing). Main thread only.
  bool gReadyAfterFirstFrame = false;

  bool WLD_TakeFrameClockReset() noexcept
  {
    const bool pending = gFrameClockResetPending;
    gFrameClockResetPending = false;
    return pending;
  }
  bool UI_SelectAnything = false;
  // Engine addition (`ui_IconRecords`): counts applied sync beats on the user side, so the
  // strategic-icon pass can tell that no entity changed since it last looked. Main thread only.
  std::uint64_t gUserSyncBeats = 0u;
namespace
{


    // `DestroyBuildTemplateInfo` (0x00823E10, per-element blueprint-id string
    // release) and `DestroyBuildTemplateRange` (0x00823DD0, the loop over it)
    // are the compiler's per-element/range release for `SBuildTemplateInfo`'s
    // `fa::string mBlueprintId` member -- the same release
    // `SBuildTemplateInfo`'s implicit destructor already performs. Now that
    // `gpg::fastvector_n<SBuildTemplateInfo, 16>` is `gpg::fastvector_n<SBuildTemplateInfo, 16>`
    // (CWldSession.h), that release happens through the container's own
    // element lifetime (array-new/delete[] on the heap arm, implicit dtor on
    // scope exit / overwrite-by-assignment on the inline arm -- see
    // `FastVectorN::ResetInline_`/`GrowInsertDeepCopy` in FastVector.h) rather
    // than a hand-rolled per-type free function; there is no separate body to
    // recover them into.

    void SortBuildTemplateRangeByOrder(SBuildTemplateInfo* const begin, SBuildTemplateInfo* const end)
    {
      if (begin == nullptr || end == nullptr || begin == end || begin + 1 == end) {
        return;
      }

      // The binary's whole sort instantiation for this element hangs off this
      // one line -- twelve emitted bodies, catalogued on the members of
      // legacy/algorithms/Sort.h. `fa::sort` rather than `std::sort`
      // because only the former models VC8's introsort exactly: the same
      // 32-element insertion-sort cutoff, the same 40-element ninther
      // threshold in the median pick, and the same three-quarters recursion
      // budget before it falls back to heapsort.
      fa::sort(
        begin,
        end,
        [](const SBuildTemplateInfo& lhs, const SBuildTemplateInfo& rhs) noexcept { return lhs.mBuildOrder < rhs.mBuildOrder; }
      );
    }

    void BuildSelectionSyncMask(const WeakSet<UserEntity>& selection, SSyncFilterMaskBlock& outMask)
    {
      BVIntSet selectionIds{};
      for (UserEntity* const entity : selection) {
        if (entity->IsUserUnit() != nullptr) {
          (void)selectionIds.Add(static_cast<unsigned int>(entity->mParams.mEntityId));
        }
      }

      outMask = selectionIds;
    }

    [[nodiscard]] bool ApplyTerrainPlayableRect(IWldTerrainRes* const terrainRes, const gpg::Rect2i& playableRect)
    {
      if (terrainRes == nullptr) {
        return false;
      }
      return terrainRes->SetPlayableMapRect(VisibilityRect::FromRect2i(playableRect));
    }
}


  MouseInfo& CWldSession::CursorInfo() noexcept
  {
    static_assert(
      offsetof(CWldSession, CursorWorldPos) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mMouseWorldPos),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    static_assert(
      offsetof(CWldSession, mCursorUnitHover) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mUnitHover),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    static_assert(
      offsetof(CWldSession, HighlightCommandId) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mIsDragger),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    static_assert(
      offsetof(CWldSession, CursorScreenPos) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mMouseScreenPos),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    return *reinterpret_cast<MouseInfo*>(&mCursorWorldState[0]);
  }

  const MouseInfo& CWldSession::CursorInfo() const noexcept
  {
    return *reinterpret_cast<const MouseInfo*>(&mCursorWorldState[0]);
  }

  /**
   * Address: 0x00893160 (FUN_00893160,
   * ??0CWldSession@Moho@@QAE@AAV?$auto_ptr@VLuaState@LuaPlus@@@std@@AAV?$auto_ptr@VRRuleGameRules@Moho@@@3@AAV?$auto_ptr@VCWldMap@Moho@@@3@AAUSWldSessionInfo@1@@Z)
   */
  CWldSession::CWldSession(
    fa::auto_ptr<LuaPlus::LuaState>& state,
    fa::auto_ptr<RRuleGameRules>& rulesOwner,
    fa::auto_ptr<CWldMap>& wldMap,
    SWldSessionInfo& sessionInfo
  )
  {
    // Partial lift of 0x00893160: ownership transfers + proven field initialization.
    // Remaining helper-heavy initialization chain (vision/task/lua options/spatial builders)
    // is tracked for subsequent recovery pass.
    mState = state.release();
    mCurThread = nullptr;
    mRules = static_cast<RRuleGameRulesImpl*>(rulesOwner.release());
    mWldMap = wldMap.release();
    mLaunchInfo = sessionInfo.mLaunchInfo;

    mMapName = sessionInfo.mMapName;

    // 0x00893160 line 84: `SpatialDB_MeshInstance::SpatialDB_MeshInstance(&mSpatialDB)`
    // (0x00501D80) runs right after the entity map's head sentinel is built.
    // It allocates the map-tree head sentinel and the root shard-data lane;
    // without it every `Register` from a UserEntity ctor finds a null tree
    // head and silently drops the entry, so unit picking, band-box
    // selection and every area query see an empty database. That is
    // `mEntitySpatialDb`'s own constructor, run as a member in that order.
    // 0x00893214-0x0089323D, immediately after that ctor, is `mExtraSelection`'s
    // own constructor (the head bought through 0x007B08D0, self-linked, count
    // zero).
    // mBuildTemplates (gpg::fastvector_n<SBuildTemplateInfo, 16>) already rebound
    // itself to inline storage via its own default constructor, which runs
    // implicitly before this body -- matching the binary's per-member subobject
    // construction ahead of the constructor body. No manual lane wiring needed.
    mBuildTemplateArg1 = 0.0f;
    mBuildTemplateArg2 = 0.0f;

    // Address: 0x008B58A0 (FUN_008B58A0, CommandManager ctor - IdPool +
    //   command-map head sentinel allocation). The manager type is modeled
    //   now (moho/command/CommandManager.h) but its constructor is not lifted
    //   yet, so the field is still left null here.
    // 0x008932C0: the session owns one command manager, stamped with the
    // command source it issues under.
    mCommandManager = new CommandManager(sessionInfo.mSourceId);

    // Current build/move formation (0x00893529: `new CFormation` @0x64). The
    // session frame calls into it unconditionally through
    // `CFormation::UpdateOrientation`, so leaving it null faults on the first
    // frame after the session starts playing.
    mCurFormation = new CFormation();
    // 0x00893576/0x00893581: the renderer draws this session's map from here on (`sWldMap = mWldMap`).
    sWldMap = mWldMap;
    mUnknownShared40C = {};
    mDebugCanvas = {};
    mBeatDebugCanvas = {};
    mSimResources = {};
    // `mOrphans` and `mVizUpdates` are constructed as members (0x00893358 /
    // 0x0089338C).

    mGameTick = 0;
    mLastBeatWasTick = 0;
    mTimeSinceLastTick = 0.0f;
    gSessionShowedTick = false;
    mSessionPauseStateA = 0;
    mRequestingPauseState = 0;
    mRequestingPause = 0;
    mPauseRequester = 0;
    mReplayIsPaused = 0;

    ourCmdSource = static_cast<std::int32_t>(sessionInfo.mSourceId);
    IsReplay = sessionInfo.mIsReplay;
    IsBeingRecorded = sessionInfo.mIsBeingRecorded;
    IsMultiplayer = sessionInfo.mIsMultiplayer;
    IsGameOver = 0;

    // Engine addition (issues #216, #218): the desync dump's header names the map, the game mods
    // and the session kind; telemetry is sent for live multiplayer games only.
    CDesyncRecorder::SetSessionInfo(
      mMapName.c_str(), mLaunchInfo.get() != nullptr ? mLaunchInfo->mGameMods.c_str() : "", IsReplay, IsMultiplayer
    );

    if (const LaunchInfoBase* const launchInfo = mLaunchInfo.get(); launchInfo != nullptr) {
      // One null army slot per launch-info army (0x008932A7): the run has to
      // exist before the first beat, because `DoBeat` addresses it by army
      // index (`userArmies[army->mArmyIndex] = army`) rather than appending,
      // and every consumer indexes it the same way - `cfunc_IsObserverL`
      // dereferences `userArmies[FocusArmy]` the moment the in-game UI asks
      // whether the local player is an observer.
      // FUN_00899880 / FUN_00898EC0 are the two halves of
      // fa::vector<UserArmy*>::assign(count, nullptr) -- see the address
      // block on that member in legacy/containers/Vector.h.
      userArmies.assign(launchInfo->mArmyLaunchInfo.size(), nullptr);

      // Command sources and the focus army come off the same launch info.
      (void)CopyConstructCommandSourceVector(launchInfo->mCommandSources.mSrcs, &cmdSources);
      FocusArmy = launchInfo->mCommandSources.mOriginalSource;
      IsCheatsEnabled = launchInfo->mCheatsEnabled;
    } else {
      FocusArmy = -1;
      IsCheatsEnabled = false;
    }

    // `mSelection` is constructed as a member (0x00893465..0x00893491); the
    // word after it is zeroed at 0x00893497.
    mSelectionSize = 0;

    // 0x0089349D..0x008934D9 is `MouseInfo`'s default constructor, inlined
    // over the cursor lane this class still spells out field by field
    // (`mCursorWorldState` / `CursorWorldPos` / `mCursorUnitHover` /
    // `HighlightCommandId` / `CursorScreenPos` - see `CursorInfo()`):
    //
    //   0x0089349D  mov  [ebp+4B0h], bl    ; mHitValid   = 0
    //   0x008934A3  movss [ebp+4B4h], xmm0 ; mMouseWorldPos = (0,0,0)
    //   0x008934BB  mov  [ebp+4C0h], ebx   ; mUnitHover.ownerLinkSlot = null
    //   0x008934C1  mov  [ebp+4C4h], ebx   ; mUnitHover.nextInOwner   = null
    //   0x008934C7  mov  [ebp+4C8h], -1    ; mIsDragger  = -1
    //   0x008934D1  movss [ebp+4CCh], xmm0 ; mMouseScreenPos = (0,0)
    //
    // The two weak-link stores were missing, so the cursor's hovered-unit
    // `WeakPtr` began life pointing at whatever heap bytes this allocation
    // happened to contain. The first thing to touch it is
    // `CWldSession::GetLeftMouseButtonAction`'s `mode.mMouseDragStart =
    // *mouseInfo`, which relinks through `other.ownerLinkSlot` - so on any
    // run where those bytes were not already zero, the very first frame
    // walked a garbage owner chain and faulted in
    // `WeakPtr<UserEntity>::ResetFromOwnerLinkSlot`. Whether a given build
    // survived startup came down to heap layout. The two stores are now
    // `mCursorUnitHover`'s own default constructor, run as a member.
    mCursorWorldState[0] = 0u;

    // 0x00893160 line ~288-293: seeds the initial cursor world position from
    // the map's own bounds midpoint, not the origin - matters because
    // nothing else writes CursorWorldPos until the first real mouse-move
    // event, so any UI/camera code reading it on the first frame otherwise
    // sees world-origin instead of a point actually on the map.
    if (const STIMap* const stiMap = GetSTIMap(); stiMap != nullptr) {
      const Wm3::AxisAlignedBox3f mapBounds = stiMap->GetBounds3D();
      CursorWorldPos.x = (mapBounds.Min.x + mapBounds.Max.x) * 0.5f;
      CursorWorldPos.y = (mapBounds.Min.y + mapBounds.Max.y) * 0.5f;
      CursorWorldPos.z = (mapBounds.Min.z + mapBounds.Max.z) * 0.5f;
    } else {
      CursorWorldPos.x = 0.0f;
      CursorWorldPos.y = 0.0f;
      CursorWorldPos.z = 0.0f;
    }
    CursorScreenPos.x = 0.0f;
    CursorScreenPos.y = 0.0f;
    HighlightCommandId = -1;

    // 0x008934F1: `mov byte ptr [ebp+4D5h], 1`. Shipping this false made
    // `SelectBuildPreviewColor` return the valid colour unconditionally, so a
    // placement ghost stayed green everywhere -- a mass extractor looked
    // buildable on bare ground, and the per-node gate in the build-drag
    // preview (`canBuild || !mShowInvalidBuildPlacementPreview`) kept every
    // rejected node visible too.
    mShowInvalidBuildPlacementPreview = true;
    DisplayEconomyOverlay = false;
    mTeamColorMode = false;

    // Session task stage. The binary allocates it, swaps it into `mCurThread`
    // destroying whatever was there, and then publishes it on the session Lua
    // state (`LuaState::m_taskStage`, the root-state meaning of the slot that
    // holds a thread's `CLuaTask`), where `cfunc_ForkThreadL` reads it back. Without this, every session script calling `ForkThread` dies
    // with "Lua state has not been set up for multiple threads".
    {
      auto* const sessionStage = new CTaskStage();
      CTaskStage* const previousStage = mCurThread;
      mCurThread = sessionStage;
      delete previousStage;
    }
    mState->m_taskStage = mCurThread;

    // Disk-watcher task, staged on the session task stage so reloaded script
    // files reach the session state's `__diskwatch` callbacks.
    (void)CTask::CreateTaskThread(new ScrDiskWatcherTask(mState), mCurThread, true);

    ClearBuildTemplates();

    // Scenario table. The lobby hands the session its scenario as a serialized
    // Lua value on the launch info (`LaunchInfoBase::mScenarioInfo`, +0x28) and
    // the session parses it into its own Lua universe. Leaving `mScenarioInfo`
    // default-constructed gives it a null owning state, so every
    // `SessionGetScenarioInfo` call from the in-game UI throws inside
    // `LuaObject::PushStack` before it can even compare global states.
    if (const LaunchInfoBase* const launchInfo = mLaunchInfo.get(); launchInfo != nullptr) {
      LuaPlus::LuaObject parsedScenario;
      (void)SCR_FromString(&parsedScenario, launchInfo->mScenarioInfo, mState);
      mScenarioInfo = parsedScenario;
    }

    // Engine addition (water bodies, .plans/water-levels/PLAN.md): the session's own map gets
    // the bodies the sim fills from the same scenario under the same game version
    // (FAF_BeginSession ran before this), so the water is drawn and queried where the sim has it.
    // The water map was built at load with the sea only; it is built again with the bodies.
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr && mWldMap->mTerrainRes->mMap != nullptr) {
      IWldTerrainRes* const terrainRes = mWldMap->mTerrainRes;
      const bool hadBodies = terrainRes->mMap->HasWaterBodies();
      terrainRes->mMap->InstallWaterBodies(mScenarioInfo);
      if (hadBodies || terrainRes->mMap->HasWaterBodies()) {
        // As the map load does: edit mode holds the water map's pixel buffer, and entering it
        // rebuilds the whole water map (now with the bodies); leaving it uploads that.
        CBackgroundTaskControl loadControl{};
        terrainRes->EnterEditMode(loadControl);
        terrainRes->ExitEditMode();
      }
    }

    // Observers are unconditionally allowed while watching a replay; otherwise
    // the scenario's own Options table decides, and a scenario without one
    // means no observers.
    if (IsReplay) {
      IsObservingAllowed = true;
    } else if (mScenarioInfo.IsTable()) {
      const LuaPlus::LuaObject options = mScenarioInfo["Options"];
      IsObservingAllowed = options.IsTable() && options["AllowObservers"].GetBoolean();
    } else {
      IsObservingAllowed = false;
    }

    // 0x00893160 line ~317: size the vision quadtree from the height field.
    //
    //     v36    = this->mWldMap->mTerrainRes->mMap;
    //     field  = v36->mHeightField.field;
    //     Moho::VisionDB::Init(&this->mVisionDB,
    //                          (float)(field->width  - 1),
    //                          (float)(field->height - 1));
    //
    // `VisionDB::Init` is what allocates `rootNode_`, and neither
    // `VisionDB::Entry::TryAdd` (0x0081B490) nor its caller
    // `func_ren_FogOfWar` (0x0081C660) null-checks that root -- the binary
    // relies on this call having run. Without it every fog-of-war frame
    // dereferenced a null root: `TryAdd` read `entry->mCurCircle` at +0x1C
    // off nullptr, faulting at address 0x1C in
    // `Cartographic::Render -> RenderFogOfWar`.
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      if (const STIMap* const stiMap = GetSTIMap(); stiMap != nullptr) {
        if (const CHeightField* const heightField = stiMap->mHeightField.get(); heightField != nullptr) {
          mVisionDb.Init(
            static_cast<float>(heightField->Width() - 1),
            static_cast<float>(heightField->Height() - 1)
          );
        }
      }
    }

    // 0x00893160 line ~301-304: size the session's own entity spatial
    // database from the same height field, immediately after VisionDB. The
    // ctor is Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance(height,
    // this, width) - already recovered as ResizeStorageForMap(width, height)
    // (Mesh.cpp:4161, address 0x00501F50, confirmed via that function's own
    // parameter names in its ground-truth signature). Ground truth's single
    // call here never touches SpatialShardData, so this one call is the
    // complete, faithful construction - matching the memset above, which is
    // what a fresh, never-before-sized SpatialDB_MeshInstance's storage
    // already looks like going in. Without this, every spatial query
    // (CollectInBox/CollectInSphere/CollectInView/CollectAllInVolume, used by
    // area-effect weapons, unit-selection-by-area, AI target-finding) reads
    // an object that was only memset to zero, never actually built.
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      if (const STIMap* const stiMap = GetSTIMap(); stiMap != nullptr) {
        if (const CHeightField* const heightField = stiMap->mHeightField.get(); heightField != nullptr) {
          GetEntitySpatialDbStorage()
            ->ResizeForMap(heightField->Width() - 1, heightField->Height() - 1);
        }
      }
    }

    // 0x00893160 line ~324-326 (" CWldSession create 5" -> "create 6"): the
    // global MeshRenderer singleton's own spatial db gets resized to the
    // same map dimensions right after the session's. Ground truth's
    // Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance(height,
    // &Instance->bd, width) is the SAME 0x00501F50 body as the call above,
    // already recovered and NAMED (not orphaned as a raw constructor) as
    // MeshRenderer::UpdateMapSize(width, height) (Mesh.cpp:5992, address
    // 0x007DF510) - a real, fully-recovered method with zero callers
    // anywhere in src until this one.
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      if (const STIMap* const stiMap = GetSTIMap(); stiMap != nullptr) {
        if (const CHeightField* const heightField = stiMap->mHeightField.get(); heightField != nullptr) {
          MeshRenderer::GetInstance()->UpdateMapSize(heightField->Width() - 1, heightField->Height() - 1);
        }
      }
    }

    gActiveWldSession = this;
  }

  /**
   * Address: 0x00893A60 (FUN_00893A60, ??1CWldSession@Moho@@QAE@XZ)
   */
  CWldSession::~CWldSession()
  {
    // Partial lift of 0x00893A60: core owner releases + recovered shared/weak cleanup.

    // 0x00893A88..0x00893A99: viewport-owned border meshes borrow the
    // session's blueprints and must be retired before any session owners.
    if (ren_Viewport != nullptr) {
      ren_Viewport->mMapImager.ClearBorder();
    }

    // 0x00893A9E..0x00893AEE: the very first thing the session unwinds is its
    // army-mirror table. Every populated slot is deleted - `~UserArmy`
    // (0x008B1650) followed by `operator delete` (0x00893AD4) - and every slot
    // is then blanked, occupied or not.
    for (std::size_t armyIndex = 0; armyIndex < userArmies.size(); ++armyIndex) {
      if (UserArmy* const army = userArmies[armyIndex]; army != nullptr) {
        delete army;
      }
      userArmies[armyIndex] = nullptr;
    }

    // 0x00893AF0..0x00893B85: orphan entities still own render instances.
    // Advance before deletion because the entity destructor removes its weak
    // registration. These instances must die while their blueprints are live.
    for (auto orphan = mOrphans.begin(); orphan != mOrphans.end();) {
      UserEntity* const entity = *orphan;
      ++orphan;
      delete entity;
    }

    mSimResources.release();
    mBeatDebugCanvas.release();
    mDebugCanvas.release();
    mUnknownShared40C.release();
    // 0x00893BE6: the renderer has no map from here on.
    sWldMap = nullptr;
    ClearBuildTemplates();

    // Drop every formation-preview ghost still parked in the session-global
    // preview vector. The binary runs the whole-range erase (FUN_0085A130)
    // here, which is exactly what `clear` compiles to.
    gFormationPreviews.clear();

    if (mWldMap) {
      delete mWldMap;
      mWldMap = nullptr;
    }

    // 0x0089404E..0x00894078: map ownership ends before the rules that
    // supply its mesh blueprints.
    if (mRules) {
      // Engine addition (RULE_SetKeepBetweenSessions): the editor keeps them for its next play.
      if (!RULE_KeepAfterSession(mRules, mState)) {
        delete mRules;
      }
      mRules = nullptr;
    }

    // Tear the session task stage down before the Lua state it is published
    // on: the stage owns the disk-watcher task and every ForkThread coroutine
    // still parked on it, and those hold `mState`.
    delete mCurThread;
    mCurThread = nullptr;

    if (mState) {
      // Engine addition: world meshes the game UI's Lua never destroyed would outlive the state.
      if (const int meshes = CUIWorldMesh::DestroyAllOf(mState); meshes > 0) {
        gpg::Logf("Session: %d world meshes the UI left were deleted with its Lua state", meshes);
      }
      delete mState;
      mState = nullptr;
    }

    if (mCurFormation) {
      delete mCurFormation;
      mCurFormation = nullptr;
    }
    mLaunchInfo.reset();
    // 0x00893A60 line 297: `~SpatialDB_MeshInstance(&mSpatialDB)` (0x00501E50)
    // runs after the extra-selection set is torn down and before the entity
    // map's storage is released -- member destruction in reverse declaration
    // order: `mExtraSelection`, then `mEntitySpatialDb`, then `mEntities`.

    if (gActiveWldSession == this) {
      gActiveWldSession = nullptr;
    }
  }

  /**
    * Alias of FUN_008B9580 (non-canonical helper lane).
   */
  bool CWldSession::TryGetPlayableMapRect(VisibilityRect& outRect) const
  {
    if (!mWldMap) {
      return false;
    }
    IWldTerrainRes* const terrainRes = mWldMap->mTerrainRes;
    if (!terrainRes) {
      return false;
    }
    (void)terrainRes->GetPlayableMapRect(outRect);
    return true;
  }

  /**
   * Address: 0x007A6360 (FUN_007A6360, ?GetFocusArmy@CWldSession@Moho@@QBEPAVUserArmy@2@XZ)
   *
   * What it does:
   * Returns the focused army slot when focus is active, otherwise `nullptr`.
   */
  UserArmy* CWldSession::GetFocusArmy() const
  {
    const int focusArmy = FocusArmy;
    if (focusArmy < 0) {
      return nullptr;
    }

    return userArmies[static_cast<std::size_t>(focusArmy)];
  }

  /**
   * Address: 0x00896590 (FUN_00896590, ?IsObserver@CWldSession@Moho@@QBE_NXZ)
   *
   * What it does:
   * Returns true when focus army is disabled (`FocusArmy < 0`) or when the
   * focused army lane has no live `UserArmy*` owner.
   */
  bool CWldSession::IsObserver() const
  {
    const int focusArmy = FocusArmy;
    return focusArmy < 0 || userArmies[static_cast<std::size_t>(focusArmy)] == nullptr;
  }

  /**
   * Address: 0x00896570 (FUN_00896570, ?SetCursorInfo@CWldSession@Moho@@QAEXABUUICursorInfo@2@@Z)
   *
   * What it does:
   * Copies one cursor-info payload into the session cursor-info lane.
   */
  void CWldSession::SetCursorInfo(const MouseInfo& cursorInfo)
  {
    CursorInfo() = cursorInfo;
  }

  /**
   * Address: 0x00895FF0 (FUN_00895FF0, ?GetSelection@CWldSession@Moho@@QBEABV?$WeakSet@VUserEntity@Moho@@@2@XZ)
   *
   * What it does:
   * Returns the current world-session selection weak-set.
   */
  const WeakSet<UserEntity>& CWldSession::GetSelection() const
  {
    return mSelection;
  }

  /**
   * Address: 0x00896730 (FUN_00896730, ?GetExtraSelectList@CWldSession@Moho@@QBE?AV?$WeakSet@VUserEntity@Moho@@@2@XZ)
   *
   * What it does:
   * A copy of the extra-select list: `WeakSet`'s copy constructor inlined,
   * `begin()` pruning the source and the set's range constructor (0x00822C50)
   * adding the live entries.
   */
  WeakSet<UserEntity> CWldSession::GetExtraSelectList() const
  {
    return mExtraSelection;
  }

  /**
   * Address: 0x00896580 (FUN_00896580, ?GetCursorInfo@CWldSession@Moho@@QBEABUUICursorInfo@2@XZ)
   *
   * What it does:
   * Returns the current cursor-info payload stored by this world session.
   */
  const MouseInfo& CWldSession::GetCursorInfo() const
  {
    return CursorInfo();
  }
namespace
{

  /**
   * Not a distinct binary function - every caller inlines the same
   * `mCursorInfo.mUnitHover` weak-link decode (0x0086ECE8's own body plus
   * three call sites already in this file). Promoted to a public accessor
   * so callers outside this TU (`sub_8281E0`'s recovered form in the
   * command-graph render pass) don't need their own copy.
   *
   * `MouseInfo::mUnitHover` is the intrusive `WeakPtr<UserEntity>` the binary
   * stores there, so the decode is `MouseInfo::HoveredEntity()`.
   */
      // Engine test hook (`ui_TestHover`): an entity that stands in for the one under the cursor,
    // so the hovered-unit paths can be exercised without moving the mouse.
    WeakPtr<UserEntity> sTestHoveredEntity;
    bool sTestHoverActive = false;

    void UiTestHover(const fa::vector<fa::string>& args)
    {
      const std::string mode = args.size() >= 2U ? std::string(args[1].c_str()) : std::string();
      if (mode == "off") {
        sTestHoverActive = false;
        sTestHoveredEntity.ResetFromObject(nullptr);
        CON_Printf("ui_TestHover: off");
        return;
      }
      CWldSession* const session = WLD_GetActiveSession();
      if ((mode != "selected" && mode != "id") || session == nullptr) {
        CON_Printf("syntax: ui_TestHover selected|id <entity id>|off (hover that unit until 'off')");
        return;
      }
      UserEntity* first = nullptr;
      if (mode == "id") {
        first = args.size() >= 3U ? session->LookupEntityId(std::atoi(args[2].c_str())) : nullptr;
      } else {
        for (UserEntity* const entity : session->mSelection) {
          first = entity;
          break;
        }
      }
      sTestHoveredEntity.ResetFromObject(first);
      sTestHoverActive = first != nullptr;
      CON_Printf("ui_TestHover: %s", first != nullptr ? "hovering a unit" : "no such unit");
      gpg::Logf("ui_TestHover: %s", first != nullptr ? "hovering a unit" : "no such unit");
    }

    CConFunc gCConFunc_ui_TestHover(
      "ui_TestHover",
      "Test hook: 'ui_TestHover selected' makes the first selected unit the hovered one (whatever the "
      "mouse is over) until 'ui_TestHover off'.",
      &UiTestHover
    );
}


  UserEntity* CWldSession::GetHoveredUserEntity() const noexcept
  {
    if (sTestHoverActive) {
      return sTestHoveredEntity.GetObjectPtr();
    }
    return GetCursorInfo().HoveredEntity();
  }

  /**
   * Address: 0x008965C0 (FUN_008965C0, ?BecomeObserver@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Validates observer focus request (`-1`) and applies it to the active sim
   * driver when allowed.
   */
  void CWldSession::BecomeObserver()
  {
    if (!ValidateFocusArmyRequest(-1)) {
      return;
    }

    if (ISTIDriver* const activeDriver = sSimDriver.get()) {
      activeDriver->SetArmyIndex(-1);
    }
  }

  /**
   * Address context: compatibility wrapper lane used by recovered callsites.
   */
  UserArmy* CWldSession::GetFocusUserArmy()
  {
    return GetFocusArmy();
  }

  /**
   * Address context: compatibility wrapper lane used by recovered callsites.
   */
  const UserArmy* CWldSession::GetFocusUserArmy() const
  {
    return GetFocusArmy();
  }

  /**
   * Address: 0x008965E0 (FUN_008965E0, ?RequestFocusArmy@CWldSession@Moho@@QAEXH@Z)
   *
   * What it does:
   * Validates one zero-based focus-army index (`-1` allowed) and forwards
   * accepted changes to the active sim driver.
   */
  void CWldSession::RequestFocusArmy(const int index)
  {
    const int maxArmyIndex = static_cast<int>(userArmies.size()) - 1;
    if (index < -1 || index > maxArmyIndex) {
      gpg::Logf(
        "CWldSession::RequestFocusArmy(): invalid army index %d.  Must be between -1 and %d inclusive",
        index,
        maxArmyIndex
      );
      return;
    }

    if (!ValidateFocusArmyRequest(index)) {
      return;
    }

    if (ISTIDriver* const activeDriver = sSimDriver.get()) {
      activeDriver->SetArmyIndex(index);
    }
  }

  /**
   * Address: 0x00896670 (FUN_00896670, ?ValidateFocusArmyRequest@CWldSession@Moho@@AAE_NH@Z)
   *
   * What it does:
   * Returns whether one focus-army switch is allowed for the current command
   * source/session observation state.
   */
  bool CWldSession::ValidateFocusArmyRequest(const int index)
  {
    const unsigned int localCommandSource = static_cast<unsigned int>(ourCmdSource);

    bool hasDirectCommandSourceAccess = false;
    if (index != -1 && index >= 0) {
      const std::size_t focusIndex = static_cast<std::size_t>(index);
      if (focusIndex < userArmies.size()) {
        const UserArmy* const targetArmy = userArmies[focusIndex];
        if (targetArmy != nullptr) {
          hasDirectCommandSourceAccess = targetArmy->mVarDat.mValidCommandSources.Contains(localCommandSource);
        }
      }
    }

    if (localCommandSource == 0xFFu || IsCheatsEnabled || hasDirectCommandSourceAccess || IsGameOver != 0u) {
      return true;
    }

    if (!IsObservingAllowed) {
      return false;
    }

    for (UserArmy* const army : userArmies) {
      if (army == nullptr) {
        continue;
      }

      // FAF hot-patch (FA-Binary-Patches ObserverFix): 0x0089671A `jz` became `jmp`, so any army
      // the local source commands refuses the switch; the stock binary refused only while that
      // army was still in the game (`cmp byte ptr [edx+1B8h], 0`, now unused).
      if (army->mVarDat.mValidCommandSources.Contains(localCommandSource)) {
        return false;
      }
    }

    return true;
  }

  /**
    * Alias of FUN_008B97C0 (non-canonical helper lane).
   */
  EntityCategoryLookupResolver* CWldSession::GetCategoryLookupResolver()
  {
    return const_cast<EntityCategoryLookupResolver*>(
      static_cast<const CWldSession*>(this)->GetCategoryLookupResolver()
    );
  }

  /**
    * Alias of FUN_008B97C0 (non-canonical helper lane).
   */
  const EntityCategoryLookupResolver* CWldSession::GetCategoryLookupResolver() const
  {
    if (!mRules) {
      return nullptr;
    }

    // RRuleGameRulesImpl exposes the category-lookup contract in the same primary
    // vtable; this is a typed interface view, not a separate base subobject.
    return reinterpret_cast<const EntityCategoryLookupResolver*>(mRules);
  }

  /**
    * Alias of FUN_008B85E0 (non-canonical helper lane).
   */
  SpatialDB<UserEntity>* CWldSession::GetEntitySpatialDbStorage()
  {
    return &mEntitySpatialDb;
  }

  /**
    * Alias of FUN_008B85E0 (non-canonical helper lane).
   */
  const SpatialDB<UserEntity>* CWldSession::GetEntitySpatialDbStorage() const
  {
    return &mEntitySpatialDb;
  }

  /**
   * Address: 0x00896780 (FUN_00896780, ?AddToExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Starts transport order command mode and inserts one entity into the
   * world-session extra-selection weak-set.
   */
  void CWldSession::AddToExtraSelectList(UserEntity* const entity)
  {
    UICommandModeData commandModeData{};
    commandModeData.mMode = fa::string("order", 5u);
    commandModeData.mPayload.AssignNewTable(mState, 0, 0);
    commandModeData.mPayload.SetString("name", "RULEUCC_Transport");
    UI_StartCommandMode(commandModeData);

    (void)mExtraSelection.Add(entity);
  }

  /**
   * Address: 0x00896830 (FUN_00896830, ?RemoveFromExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity from the world-session extra-selection weak-set and
   * exits command mode when the set becomes empty.
   */
  void CWldSession::RemoveFromExtraSelectList(UserEntity* const entity)
  {
    // 0x00896844 `call sub_8676E0` -- the erase's result is pushed nowhere and
    // never tested. The emptiness re-check that follows is unconditional:
    //
    //   0x00896849: mov  ebx, [esi+4]      ; head
    //   0x0089684C: mov  eax, [ebx]        ; head->left
    //   0x00896853: call find
    //   0x00896858: cmp  [eax], ebx
    //   0x0089685A: jnz  ret               ; still non-empty -> keep the mode
    //   0x0089685C: call UI_EndCommandMode
    //
    // Returning early when the erase reports "not found" strands the
    // RULEUCC_Transport command mode `AddToExtraSelectList` started: every
    // later right-click then issues a transport order instead of the default
    // attack/move, which is why clicking an enemy unit appeared to do nothing.
    (void)mExtraSelection.Remove(entity);

    if (mExtraSelection.Empty()) {
      UI_EndCommandMode();
    }
  }

  /**
   * Address: 0x00896870 (FUN_00896870, ?ClearExtraSelectList@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Clears world-session extra selection weak-set and exits command mode when
   * any entries were present.
   */
  void CWldSession::ClearExtraSelectList()
  {
    // 0x00896881-0x00896896: `Empty()`, which prunes, so a set holding only
    // dead entries counts as empty. Then the whole-tree erase (0x008968A1..)
    // and the end of command mode. The word after the set (+0xEC) is not
    // touched; this used to store the count there.
    if (mExtraSelection.Empty()) {
      return;
    }

    mExtraSelection.Clear();
    UI_EndCommandMode();
  }

  /**
   * Address: 0x0081DC70 (FUN_0081DC70, Moho::CWldSession::UnitFirstInSelection)
   *
   * What it does:
   * Returns true when selection is empty or every live selected entity
   * resolves to the supplied user-unit pointer.
   */
  bool CWldSession::UnitFirstInSelection(const UserUnit* const unit) const
  {
    for (UserEntity* const selectedEntity : mSelection) {
      if (selectedEntity->IsUserUnit() != unit) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x00894120 (FUN_00894120, ?GetTerrainRes@CWldSession@Moho@@QBEPAVIWldTerrainRes@2@XZ)
   *
   * What it does:
   * Returns the world-map terrain resource lane owned by this world session.
   */
  IWldTerrainRes* CWldSession::GetTerrainRes() const
  {
    return mWldMap->mTerrainRes;
  }

  /**
   * Address: 0x00894130 (FUN_00894130, ?GetSTIMap@CWldSession@Moho@@QBEPAVSTIMap@2@XZ)
   *
   * What it does:
   * Returns the terrain STI map lane from the world-map terrain resource.
   */
  STIMap* CWldSession::GetSTIMap() const
  {
    return mWldMap->mTerrainRes->mMap;
  }

  /**
   * Address: 0x00894140 (FUN_00894140, ?AddEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Inserts one `(entityId, entity*)` mapping into the world-session entity map.
   */
  void CWldSession::AddEntity(UserEntity* const entity)
  {
    if (entity == nullptr) {
      return;
    }

    (void)mEntities.insert({static_cast<std::uint32_t>(entity->mParams.mEntityId), entity});
  }

  /**
   * Address: 0x00894170 (FUN_00894170, ?RemoveEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity-id mapping from the world-session entity map.
   */
  void CWldSession::RemoveEntity(UserEntity* const entity)
  {
    if (entity == nullptr) {
      return;
    }

    (void)mEntities.erase(static_cast<std::uint32_t>(entity->mParams.mEntityId));
  }

  /**
   * Address: 0x008941B0 (FUN_008941B0, ?OrphanEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity-id mapping from the session entity map, marks the
   * entity as pending deletion, and inserts it into the orphan weak-set lane.
   */
  void CWldSession::OrphanEntity(UserEntity* const entity)
  {
    if (entity == nullptr) {
      return;
    }

    (void)mEntities.erase(static_cast<std::uint32_t>(entity->mParams.mEntityId));

    // The flag is what keeps the render side from treating the entity as live
    // while it finishes its death animation; 0x008941FA writes it right before
    // the weak-set insert.
    entity->mMarkedForDeletion = 1;

    (void)mOrphans.Add(entity);
  }

  /**
   * Address: 0x00894210 (FUN_00894210, ?AddToVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * `WeakSet<UserEntity>::Add` (0x007AE1B0) of `entity` into the visibility
   * set at `this+0x438` -- the same insert `OrphanEntity` runs on the orphan
   * set.
   */
  void CWldSession::AddToVizUpdate(UserEntity* const entity)
  {
    if (!entity) {
      return;
    }

    (void)mVizUpdates.Add(entity);
  }

  /**
   * Address: 0x00894230 (FUN_00894230, ?RemoveFromVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Finds `entity` in the visibility set under the owner-link guard
   * (0x00867780) and, when present, erases that node (0x0066A550) and prunes
   * forward from the successor (0x0066A330) -- `set.erase(set.find(entity))`.
   */
  void CWldSession::RemoveFromVizUpdate(UserEntity* const entity)
  {
    if (!entity) {
      return;
    }

    const WeakSet<UserEntity>::iterator found = mVizUpdates.Find(entity);
    if (found != mVizUpdates.end()) {
      (void)mVizUpdates.Erase(found);
    }
  }

  /**
   * Address: 0x008942B0 (FUN_008942B0, ?RequestPause@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::RequestPause()
  {
    std::int32_t commandCookie = 0;
    ISTIDriver* const simDriver = sSimDriver.get();
    if (IsReplay) {
      if (mReplayIsPaused == 0u) {
        mReplayIsPaused = 1;
        simDriver->IncrementOutstandingRequests();
      }
    } else {
      simDriver->RequestPause(&commandCookie);
      mRequestingPauseState = 1;
      mRequestingPause = 1;
      mPauseRequester = commandCookie;
    }

    mPauseBroadcaster.BroadcastEvent(SPauseEvent{true});
  }

  /**
   * Address: 0x00894330 (FUN_00894330, ?Resume@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::Resume()
  {
    std::int32_t commandCookie = 0;
    ISTIDriver* const simDriver = sSimDriver.get();
    if (IsReplay) {
      if (mReplayIsPaused != 0u) {
        mReplayIsPaused = 0;
        simDriver->DecrementOutstandingRequestsAndSignal();
      }
    } else {
      simDriver->Resume(&commandCookie);
      mRequestingPauseState = 1;
      mRequestingPause = 0;
      mPauseRequester = commandCookie;
    }

    mPauseBroadcaster.BroadcastEvent(SPauseEvent{false});
  }

  /**
   * Address: 0x008943E0 (FUN_008943E0, ?CheckForNecessaryUIRefresh@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Rebuilds the current selection when stale/dead weak entries are detected
   * or selected entities requested a UI refresh during beat processing.
   */
  void CWldSession::CheckForNecessaryUIRefresh()
  {
    const std::size_t selectionSize = mSelection.Size();
    bool needsRefresh = false;

    // Every live, not-dead entry is kept; an entry that asks for a UI refresh
    // (vtable +0x2C) or decodes to nothing flags one.
    WeakSet<UserEntity> keptSelection;
    for (UserEntity* const entity : mSelection) {
      if (entity == nullptr) {
        needsRefresh = true;
        continue;
      }
      if (entity->RequiresUIRefresh()) {
        needsRefresh = true;
      }
      if (entity->mVariableData.mIsDead == 0u) {
        (void)keptSelection.Add(entity);
      }
    }

    // 0x008944BC..0x008944DB, then `SetSelection` 0x008944E7. `SetSelection`
    // works out what changed and broadcasts it; this only decides whether to
    // call it.
    if (needsRefresh || selectionSize < mSelectionSize || keptSelection.Size() < selectionSize) {
      SetSelection(keptSelection);
    }
  }

  /**
   * Address: 0x00896A40 (FUN_00896A40, ?GetActiveBuildTemplate@CWldSession@Moho@@QBE?AV?$fastvector_n@USBuildTemplateInfo@Moho@@$0BA@@gpg@@AAH0@Z)
   *
   * IDA signature:
   * gpg::fastvector_n16_SBuildTemplateInfo *__thiscall sub_896A40(
   *     Moho::CWldSession *this, float *a2, float *a3,
   *     gpg::fastvector_n16_SBuildTemplateInfo *a4);
   *
   * What it does:
   * Copies the active build-template buffer into one caller-owned inline
   * fastvector lane and returns the current template X/Z extents. The
   * binary's hidden-return-slot ABI copy-constructs directly into `a4`
   * (`sub_898E50(&this->mBuildTemplate, a4)`, cited on `FastVectorN`'s copy
   * ctor in FastVector.h at 0x00898E50) because at the true ABI level `a4` is
   * raw, not-yet-constructed return-slot storage. Every recovered caller in
   * this tree instead declares `result` as an ordinary local first (so it is
   * already a live, default-constructed `gpg::fastvector_n<SBuildTemplateInfo, 16>` by the time
   * this runs) -- placement-constructing over that would skip its destructor.
   * Assignment (`ResetFrom`, the same machinery the copy ctor delegates to)
   * gives the identical end state without that hazard.
   */
  gpg::fastvector_n<SBuildTemplateInfo, 16>* CWldSession::GetActiveBuildTemplate(
    float* const outTemplateSpanZ,
    float* const outTemplateSpanX,
    gpg::fastvector_n<SBuildTemplateInfo, 16>* const result
  ) const
  {
    *outTemplateSpanX = mBuildTemplateArg1;
    *outTemplateSpanZ = mBuildTemplateArg2;
    *result = mBuildTemplates;
    return result;
  }

  /**
   * Address: 0x00896AA0 (FUN_00896AA0, ?GenerateBuildTemplates@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::GenerateBuildTemplates()
  {
    std::int32_t selectableTemplateUnitCount = 0;

    for (UserEntity* const selectedEntity : mSelection) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      const IUnit* const selectedBridge = GetIUnitBridge(selectedUnit);
      if (selectedBridge != nullptr && !selectedBridge->IsMobile() && !selectedBridge->IsDead()) {
        ++selectableTemplateUnitCount;
      }
    }

    if (selectableTemplateUnitCount <= 0) {
      return;
    }

    ClearBuildTemplates();

    float minX = 10000.0f;
    float minY = 10000.0f;
    float maxX = -10000.0f;
    float maxY = -10000.0f;

    for (UserEntity* const selectedEntity : mSelection) {
      UserUnit* const selectedUnit = selectedEntity->IsUserUnit();
      IUnit* const selectedBridge = GetIUnitBridge(selectedUnit);
      if (selectedBridge != nullptr && !selectedBridge->IsMobile() && !selectedBridge->IsDead()) {
        SBuildTemplateInfo templateInfo{};

        const auto& position = selectedBridge->GetPosition();
        templateInfo.mPos.x = position.x;
        templateInfo.mPos.y = 0.0f;
        templateInfo.mPos.z = position.z;
        templateInfo.mBuildOrder = selectedUnit->mUnitVarDat.mCreationTick;

        const RUnitBlueprint* const blueprint = selectedBridge->GetBlueprint();
        templateInfo.mBlueprintId.assign(blueprint->mBlueprintId, 0u, 0xFFFFFFFFu);

        const SCoordsVec2 unitCoords{
          selectedEntity->mVariableData.mCurTransform.pos_.x,
          selectedEntity->mVariableData.mCurTransform.pos_.z
        };
        const gpg::Rect2f skirtRect = blueprint->GetSkirtRect(unitCoords);
        minX = std::min(minX, skirtRect.x0);
        minY = std::min(minY, skirtRect.z0);
        maxX = std::max(maxX, skirtRect.x1);
        maxY = std::max(maxY, skirtRect.z1);

        mBuildTemplates.push_back(templateInfo);
      }
    }

    SortBuildTemplateRangeByOrder(mBuildTemplates.begin(), mBuildTemplates.end());
    mBuildTemplateArg1 = maxX - minX;
    mBuildTemplateArg2 = maxY - minY;

    const Wm3::Vector3f origin = mBuildTemplates.front().mPos;
    for (SBuildTemplateInfo& entry : mBuildTemplates) {
      entry.mPos.x -= origin.x;
      entry.mPos.y -= origin.y;
      entry.mPos.z -= origin.z;
    }
  }

  /**
   * Address: 0x008969E0 (FUN_008969E0, ?ClearBuildTemplates@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Destroys every build-template entry and rebinds storage back to the
   * inline buffer, discarding any spilled heap allocation --
   * `FastVectorN::ResetStorageToInline` (FastVector.h), the same lane every
   * `gpg::fastvector_n<T, N>` instantiation resets through.
   */
  void CWldSession::ClearBuildTemplates()
  {
    mBuildTemplates.ResetStorageToInline();
    mBuildTemplateArg1 = 0.0f;
    mBuildTemplateArg2 = 0.0f;
  }

  /**
   * Address: 0x00896A70 (FUN_00896A70,
   *   ?SetActiveBuildTemplate@CWldSession@Moho@@QAEXABV?$fastvector_n@USBuildTemplateInfo@Moho@@$0BA@@gpg@@HH@Z)
   *
   * What it does:
   * Replaces the active build-template fastvector buffer with `templates`
   * and records the placement preview anchor as (`templateSpanX`,
   * `templateSpanZ`). The buffer copy is
   * `gpg::fastvector_n<SBuildTemplateInfo, 16>::operator=`, cited at
   * 0x00899790 on `FastVectorN::operator=` in FastVector.h.
   */
  void CWldSession::SetActiveBuildTemplate(
    const gpg::fastvector_n<SBuildTemplateInfo, 16>& templates,
    const float templateSpanX,
    const float templateSpanZ
  )
  {
    mBuildTemplates = templates;
    mBuildTemplateArg1 = templateSpanX;
    mBuildTemplateArg2 = templateSpanZ;
  }

  /**
   * Address: 0x00895EB0 (FUN_00895EB0,
   * ?GetCommandGraph@CWldSession@Moho@@QAE?AV?$shared_ptr@VUICommandGraph@Moho@@@boost@@_N@Z)
   *
   * What it does:
   * `lock()` into the return slot (0x00895EE5); when that is empty and
   * `allowCreate` is set, `new UICommandGraph(this)` (0x00895F05, 0x00895F20),
   * `reset` onto it (0x00895F2D) and the weak reference re-pointed at it
   * (0x00895F34). The three calls are boost's own `weak_ptr::lock`,
   * `shared_ptr::reset(Y*)` and `weak_ptr::operator=`, emitted for
   * `UICommandGraph` (cited in BoostWrappers.h).
   */
  boost::shared_ptr<UICommandGraph> CWldSession::GetCommandGraph(const bool allowCreate)
  {
    boost::shared_ptr<UICommandGraph> graph = mCommandGraph.lock();
    if (!graph && allowCreate) {
      graph.reset(new UICommandGraph(this));
      mCommandGraph = graph;
    }
    return graph;
  }

  /**
   * Address: 0x00895DC0 (FUN_00895DC0, ?HandleFogEdge@CWldSession@Moho@@AAEXABV?$Rect2@H@gpg@@HH@Z)
   *
   * What it does:
   * Clears edge-fog rows when focus army is invalid and marks every edge lane
   * outside the visible rectangle as blocked (`0xFF`).
   */
  void CWldSession::HandleFogEdge(const gpg::Rect2i& visibleRect, const int width, const int height)
  {
    if (FocusArmy < 0 || userArmies[static_cast<std::size_t>(FocusArmy)] == nullptr) {
      char* row = mEdgeFog.GetPtr(0u, 0u);
      for (int y = 0; y < height; ++y) {
        std::memset(row, 0, static_cast<std::size_t>(width));
        row += width;
      }
    }

    if (visibleRect.x0 > 0 || visibleRect.z0 > 0 || visibleRect.x1 < width || visibleRect.z1 < height) {
      char* row = mEdgeFog.GetPtr(0u, 0u);
      for (int y = 0; y < height; ++y, row += width) {
        if (y < visibleRect.z0 || y >= visibleRect.z1) {
          std::memset(row, 0xFF, static_cast<std::size_t>(width));
          continue;
        }

        if (visibleRect.x0 <= 0) {
          *row = static_cast<char>(0xFF);
        } else {
          std::memset(row, 0xFF, static_cast<std::size_t>(visibleRect.x0));
        }

        if (visibleRect.x1 >= (width - 1)) {
          row[width - 1] = static_cast<char>(0xFF);
        } else {
          std::memset(row + visibleRect.x1, 0xFF, static_cast<std::size_t>(width - visibleRect.x1));
        }
      }
    }
  }

  /**
   * Address: 0x00895F70 (FUN_00895F70, ?DirtyCommandGraph@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * `lock()` on the weak reference (0x00895F7F), a byte store into the graph's
   * dirty flag when one is alive (0x00895F8C), and the temporary's release.
   */
  void CWldSession::DirtyCommandGraph()
  {
    if (const boost::shared_ptr<UICommandGraph> graph = mCommandGraph.lock()) {
      graph->MarkDirty();
    }
  }

  /**
   * Address: 0x008958B0 (FUN_008958B0, ?ApplyPendingSaveData@CWldSession@Moho@@AAEXXZ)
   *
   * What it does:
   * Replays save-data selection-set labels onto live user units, groups those
   * units by selection-set name in Lua, calls
   * `/lua/ui/game/selection.lua:ResetSelectionSets`, then releases the pending
   * save-data shared pointer.
   */
  void CWldSession::ApplyPendingSaveData()
  {
    LuaPlus::LuaObject selectionSetsByName;
    selectionSetsByName.AssignNewTable(mState, 0, 0);

    SSessionSaveData& saveData = *mPendingSaveData;
    for (const auto& label : saveData.mNodeMap) {
      UserEntity* const entity = LookupEntityId(label.first);
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const unit = entity->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      const char* const selectionSetName = label.second.c_str();
      unit->AddSelectionSet(selectionSetName);

      LuaPlus::LuaObject setUnits = selectionSetsByName[selectionSetName];
      if (setUnits.IsNil()) {
        setUnits.AssignNewTable(mState, 0, 0);
        selectionSetsByName.SetObject(selectionSetName, setUnits);
      }

      IUnit* const iunitBridge = GetIUnitBridge(unit);
      LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
      setUnits.Insert(setUnits.GetN() + 1, unitObject);
    }

    try {
      LuaPlus::LuaObject selectionModule = SCR_Import(mState, "/lua/ui/game/selection.lua");
      LuaPlus::LuaFunction<> resetSelectionSets(selectionModule["ResetSelectionSets"]);
      resetSelectionSets.Call_Object(selectionSetsByName);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Unable to reset selection sets: %s",
        exception.what() != nullptr ? exception.what() : ""
      );
    }

    mPendingSaveData.reset();
  }
namespace
{
    /**
     * Address: 0x008945C1..0x008945D8 (inside FUN_00894530)
     *
     * What it does:
     * Resolves one army slot for the sound listener, treating a negative focus
     * army (observer, or not yet assigned) as "no listener".
     */
    [[nodiscard]] UserArmy* ArmyAtIndexOrNull(const fa::vector<UserArmy*>& armies, const std::int32_t index)
    {
      if (index < 0 || static_cast<std::size_t>(index) >= armies.size()) {
        return nullptr;
      }
      return armies[static_cast<std::size_t>(index)];
    }

    /**
     * Address: 0x00895097..0x0089511F and three siblings (inside FUN_00894530)
     *
     * What it does:
     * Re-seats one raw shared-pointer lane onto the beat payload's owner. The
     * raw pointer is copied unconditionally; the control block is only swapped
     * when it actually changes, taking the new reference before dropping the
     * old one so a self-assignment cannot free what it is about to keep.
     *
     * (Stranded note: the helper this documented is no longer in this file.
     * The pruning cursor that sat under it, 0x008955F2..0x00895667, is now
     * `WeakSet<UserEntity>::begin()` over `mOrphans`/`mVizUpdates`.)
     */

    /// Engine addition: `wld_ParallelSync`, user-side. Apply each beat's unit/entity updates with
    /// their per-entity copies on CUserWorkerPool.
    bool wld_ParallelSync = true;

    TConVar<bool> gTConVar_wld_ParallelSync(
      "wld_ParallelSync",
      "Apply each beat's unit and entity updates with the per-entity copies on user worker threads "
      "(see user_Workers). Lua, selection and spatial-database work stays on the main thread in "
      "packet order, so the result is the serial one.",
      &wld_ParallelSync
    );

    // Below this many updates a beat applies serially; chunk size for the parallel part.
    constexpr std::size_t kParallelSyncMinUpdates = 256u;
    constexpr std::size_t kParallelSyncGrain = 64u;

    [[nodiscard]] bool UseParallelSync(const std::size_t count)
    {
      return wld_ParallelSync && count >= kParallelSyncMinUpdates && CUserWorkerPool::ConfiguredWorkerCount() != 0u;
    }

    /**
     * Engine addition (`wld_ParallelSync`): resolves the update records' entity ids into
     * `targets`. False when an id is unknown or names the same entity twice; the caller then
     * takes the serial loop, which is the binary's.
     */
    template <class Entry>
    [[nodiscard]] bool ResolveSyncTargets(
      CWldSession& session, const fa::vector<Entry>& entries, std::vector<UserEntity*>& targets
    )
    {
      targets.resize(entries.size());
      CUserWorkerPool::Get().ParallelFor(entries.size(), 1024u, [&](const std::size_t begin, const std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          targets[i] = session.LookupEntityId(entries[i].mEntityId);
        }
      });

      std::vector<UserEntity*> sorted(targets);
      std::sort(sorted.begin(), sorted.end());
      return (sorted.empty() || sorted.front() != nullptr) && std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end();
    }

    /**
     * Engine addition (`wld_ParallelSync`): one packet loop applied in segments.
     *
     * The binary applies record after record, each one whole. Records that may run UI Lua
     * (`isBarrier`) still do: each runs whole (`applyWhole`) with every earlier record applied and
     * every later one untouched, so Lua sees exactly the serial state. Between barriers, the
     * records `isLocal` accepts have their local part - which writes only that record's own
     * entity - applied on user workers, then every record of the segment gets its main-thread part
     * in packet order: `finish` for the local ones, `applyWhole` for the rest. The main-thread
     * parts (spatial relinks, selection, sound and vision handles) never read another record's
     * entity, so running them after the segment's local parts gives the serial result.
     */
    template <class IsBarrier, class IsLocal, class ApplyLocal, class Finish, class ApplyWhole>
    void ApplyPacketInSegments(
      const std::size_t count,
      const IsBarrier& isBarrier,
      const IsLocal& isLocal,
      const ApplyLocal& applyLocal,
      const Finish& finish,
      const ApplyWhole& applyWhole
    )
    {
      std::vector<std::uint8_t> local;
      std::size_t begin = 0;
      while (begin < count) {
        std::size_t end = begin;
        while (end < count && !isBarrier(end)) {
          ++end;
        }

        const std::size_t segmentSize = end - begin;
        if (segmentSize >= kParallelSyncMinUpdates) {
          local.assign(segmentSize, 0u);
          for (std::size_t i = 0; i < segmentSize; ++i) {
            local[i] = isLocal(begin + i) ? 1u : 0u;
          }
          CUserWorkerPool::Get().ParallelFor(segmentSize, kParallelSyncGrain, [&](const std::size_t from, const std::size_t to) {
            for (std::size_t i = from; i < to; ++i) {
              if (local[i] != 0u) {
                applyLocal(begin + i);
              }
            }
          });
          for (std::size_t i = 0; i < segmentSize; ++i) {
            if (local[i] != 0u) {
              finish(begin + i);
            } else {
              applyWhole(begin + i);
            }
          }
        } else {
          for (std::size_t i = begin; i < end; ++i) {
            applyWhole(i);
          }
        }

        if (end < count) {
          applyWhole(end);
          begin = end + 1u;
        } else {
          begin = end;
        }
      }
    }

    /// Engine addition (`wld_ParallelSync`): `DoBeat`'s unit-update loop. False: run the serial loop.
    [[nodiscard]] bool ApplyUnitUpdatesParallel(CWldSession& session, const fa::vector<SUnitVariableUpdateEntry>& updates)
    {
      if (!UseParallelSync(updates.size())) {
        return false;
      }
      static std::vector<UserEntity*> sTargets;
      if (!ResolveSyncTargets(session, updates, sTargets)) {
        return false;
      }

      const auto unitAt = [](const std::size_t i) { return static_cast<UserUnit*>(sTargets[i]); };
      ApplyPacketInSegments(
        updates.size(),
        [&](const std::size_t i) { return unitAt(i)->UnitDataUpdateRunsLua(updates[i].mVariableData); },
        [](std::size_t) { return true; },
        [&](const std::size_t i) {
          // Not a barrier, so the unit does not go busy here and no deselect sits between these.
          (void)unitAt(i)->ApplyUnitPayload(updates[i].mVariableData, updates[i].mReconFlags);
          unitAt(i)->ApplyUnitPoses();
        },
        [&](const std::size_t i) { unitAt(i)->FinishUnitDataLinks(); },
        [&](const std::size_t i) { unitAt(i)->UpdateUnitData(updates[i].mVariableData, updates[i].mReconFlags); }
      );
      return true;
    }

    /// Engine addition (`wld_ParallelSync`): `DoBeat`'s entity-update loop. False: run the serial loop.
    [[nodiscard]] bool ApplyEntityUpdatesParallel(
      CWldSession& session, const fa::vector<SEntityVariableUpdateEntry>& updates
    )
    {
      if (!UseParallelSync(updates.size())) {
        return false;
      }
      static std::vector<UserEntity*> sTargets;
      static std::vector<UserEntity::SEntityDataUpdate> sSteps;
      if (!ResolveSyncTargets(session, updates, sTargets)) {
        return false;
      }
      sSteps.resize(updates.size());

      ApplyPacketInSegments(
        updates.size(),
        [&](const std::size_t i) { return sTargets[i]->EntityDataUpdateRunsLua(updates[i].mVariableData); },
        [&](const std::size_t i) { return sTargets[i]->EntityDataUpdateIsLocal(updates[i].mVariableData); },
        [&](const std::size_t i) {
          sSteps[i] = sTargets[i]->BeginEntityDataUpdate(updates[i].mVariableData);
          sTargets[i]->ApplyEntityDataUpdate(updates[i].mVariableData, sSteps[i]);
        },
        [&](const std::size_t i) { sTargets[i]->FinishEntityDataUpdate(updates[i].mVariableData, sSteps[i]); },
        [&](const std::size_t i) { sTargets[i]->UpdateEntityData(updates[i].mVariableData); }
      );
      return true;
    }
}


  /**
   * Address: 0x007F6390 (FUN_007F6390, Moho::CWldSession::GetTickDebugCanvas)
   *
   * IDA signature:
   * boost::shared_ptr_CDebugCanvas *__usercall Moho::CWldSession::GetTickDebugCanvas(
   *   boost::shared_ptr_CDebugCanvas *result, Moho::CWldSession *this);
   *
   * What it does:
   * Returns a retained copy of `mDebugCanvas` (+0x0414/+0x0418) - the tick
   * debug canvas `DoBeat` re-seats every beat from `beat.mTickDebugCanvas`.
   */
  boost::SharedPtrRaw<CDebugCanvas> CWldSession::GetTickDebugCanvas() const
  {
    return mDebugCanvas.clone_retained();
  }

  /**
   * Address: 0x007F63C0 (FUN_007F63C0, Moho::CWldSession::GetBeatDebugCanvas)
   *
   * IDA signature:
   * boost::shared_ptr_CDebugCanvas *__usercall Moho::CWldSession::GetBeatDebugCanvas(
   *   boost::shared_ptr_CDebugCanvas *result, Moho::CWldSession *this);
   *
   * What it does:
   * Returns a retained copy of `mBeatDebugCanvas` (+0x041C/+0x0420).
   */
  boost::SharedPtrRaw<CDebugCanvas> CWldSession::GetBeatDebugCanvas() const
  {
    return mBeatDebugCanvas.clone_retained();
  }

#if FAF_SERVER_MODE
  namespace
  {
    CWldSession::BeatObserver sBeatObserver = nullptr;
    void* sBeatObserverContext = nullptr;
  } // namespace

  void CWldSession::SetBeatObserver(const BeatObserver observer, void* const context) noexcept
  {
    sBeatObserverContext = context;
    sBeatObserver = observer;
  }
#endif

  /**
   * Engine addition (replay timeline): drops everything the last sim published, just before the
   * opening sync of the sim that replaces it.
   */
  void CWldSession::ResetForNewReplaySim()
  {
    // The timeline that made the bar: FAF's Lua's own copy when it carries one (issue #327), else the engine's.
    (void)SCR_LuaDoString(
      "local path = '/lua/ui/game/replay_timeline.lua' "
      "if not DiskGetFileInfo(path) then path = '/fafengine/modules/lua/ui/game/replay_timeline.lua' end "
      "import(path).OnSimReplaced()",
      mState
    );
    SetSelection(WeakSet<UserEntity>());
    USER_GetSound()->StopAllSounds();
    USER_GetSound()->SetListenerArmy(nullptr);
    sWorldParticles.ClearRenderBuckets();
    gFormationPreviews.clear();

    while (!mEntities.empty()) {
      UserEntity* const entity = mEntities.begin()->second;
      RemoveEntity(entity);
      delete entity;
    }
    for (auto orphan = mOrphans.begin(); orphan != mOrphans.end();) {
      UserEntity* const entity = *orphan;
      ++orphan;
      delete entity;
    }
    while (!mCommandManager->mCommands.empty()) {
      delete mCommandManager->mCommands.begin()->second;
    }
    for (std::size_t armyIndex = 0; armyIndex < userArmies.size(); ++armyIndex) {
      delete userArmies[armyIndex];
      userArmies[armyIndex] = nullptr;
    }
    mDebugCanvas.release();
    mBeatDebugCanvas.release();
    IsGameOver = 0u;
    mLastBeatWasTick = 0;
    mTimeSinceLastTick = 0.0f;

    // The terrain flattened since the keyframe has to go back, and the sim's heights are the truth.
    IWldTerrainRes* const terrainRes = mWldMap->mTerrainRes;
    static_cast<CDecalManager*>(terrainRes->GetDecalManager())->RemoveAllDecals();
    const CHeightField* const field = mWldMap->mTerrainRes->mMap->mHeightField.get();
    terrainRes->NotifyMapChange(gpg::Rect2i{0, 0, field->width - 1, field->height - 1});
  }

  /**
   * Address: 0x00894530 (FUN_00894530,
   * ?DoBeat@CWldSession@Moho@@QAEXV?$auto_ptr@USSyncData@Moho@@@std@@@Z)
   *
   * IDA signature:
   * void __stdcall Moho::CWldSession::DoBeat(Moho::CWldSession *this, std::auto_ptr<SSyncData> sdata);
   *
   * What it does:
   * Applies one sim beat to the client world, in the packet's own lane order.
   * This is the sole consumer of the driver's sync queue - without it the queue
   * fills, the issue thread stops issuing, and the game clock never advances.
   */
  void CWldSession::DoBeat(fa::auto_ptr<SSyncData> syncData)
  {
    const CTimeBarSection beatSection("Sync");

    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const worldCamera = cameraManager->GetCamera("WorldCamera");
    IWldTerrainRes* const terrainRes = mWldMap->mTerrainRes;

    const SSyncData& beat = *syncData;
    ++gUserSyncBeats; // engine addition, see its declaration

    mGameTick = beat.mCurTick;
    mLastBeatWasTick = beat.mAdvanced;

    // A focus-army change moves the listener, and the outgoing selection belongs
    // to an army we may no longer be allowed to see - so it is dropped wholesale.
    if (beat.mFocusArmy != FocusArmy) {
      FocusArmy = beat.mFocusArmy;
      USER_GetSound()->SetListenerArmy(ArmyAtIndexOrNull(userArmies, FocusArmy));

      SetSelection(WeakSet<UserEntity>());
    }

    ApplyBeatEffects(beat, worldCamera, terrainRes);

    ApplyBeatArmies(beat);

    CreateBeatEntities(beat);

    PublishBeatCommandDescriptors(beat);

    UpdateBeatEntities(beat);

    ApplyBeatCommandPackets(beat);

    // The command graph only gets marked here (`DirtyCommandGraph`, inlined:
    // the `lock()` at 0x00894F02 and the byte store at 0x00894F17); the mesh
    // rebuild it implies runs back in `SessionFrame`.
    DirtyCommandGraph();

    if (worldCamera != nullptr) {
      for (const SCamFollowParams& follow : beat.mFollowCameras) {
        worldCamera->CameraFollow(follow);
      }
    }

    HandSyncToUi(beat);
    (void)SCR_LuaDoString("OnSync()", mState);

    mSessionPauseStateA = static_cast<std::uint8_t>(beat.mPausedBy != -1);
    mDebugCanvas.reset_from(beat.mTickDebugCanvas);
    mBeatDebugCanvas.reset_from(beat.mBeatDebugCanvas);
    ren_FogOfWar = beat.mFogOfWar;
    terrainRes->SyncTerrain(beat.mTerrainUpdate.px);
    mSimResources.reset_from(beat.mSimResources);

    // `fa::vector<SExtraUnitData>::operator=` (0x00895214, FUN_007530C0,
    // `legacy/containers/Vector.h`). Previously mis-wired through
    // `AssignSyncInlineVectors` (a per-element `SyncInlineVector` scratch-run
    // copy) at this exact call site -- `FUN_007530C0`'s callee chain
    // (`FUN_00755DE0`/`FUN_00750A80`, `>>3` nested 8-byte-pair-vector copy at
    // +0x00 plus one trailing scalar dword at +0x18) only matches
    // `SExtraUnitData::pairs`/`unitEntityId`, never a flat `int32_t[4]`
    // element; removed the wrong helper and call directly.
    mSyncExtraUnitData = beat.mSyncExtraUnitData;

    for (const fa::string& printLine : beat.mPrintField) {
      CON_Printf("%s", printLine.c_str());
    }

    ReportBeatDesyncs(beat);

#if FAF_SERVER_MODE
    // Engine addition, server mode: `/sessionsummary` (WP11.6 check). Without it, nothing.
    faf::remote::client::NoteSessionBeat(*this, beat);
#endif

    if (beat.mGameOver && IsGameOver == 0u) {
      IsGameOver = 1u;
      UI_NoteGameOver();
      if (CFG_GetArgOption("/exitongameover", 0u, nullptr)) {
        wxTheApp->ExitMainLoop();
      }
    }

    ExitAtTickIfAsked();

    if (mPendingSaveData) {
      ApplyPendingSaveData();
    }

    TickBeatUnits(beat);

    UpdateOrphansAndVisibility();
#if FAF_SERVER_MODE
    if (sBeatObserver != nullptr) {
      sBeatObserver(*this, beat.mCurBeat, sBeatObserverContext);
    }
#endif

    AdvanceCommandIssueHelpersToBeat(*mCommandManager, beat.mCurBeat);

    if (mRequestingPauseState != 0u && beat.mCurBeat - mPauseRequester >= 0) {
      mRequestingPauseState = 0u;
    }

    CheckForNecessaryUIRefresh();

    if (IUIManager* const uiManager = UI_GetManager(); uiManager != nullptr) {
      (void)uiManager->DoBeat();
    }

    if (!beat.mSubmitArmyStats.empty()) {
      GPGNET_SubmitArmyStats(beat.mSubmitArmyStats);
    }

    if (dbg_Metronome && USER_GetSound() != nullptr) {
      USER_GetSound()->Play(fa::string("Tick", 4u), fa::string("TestBank", 8u));
    }
  }

  // Part of DoBeat (0x00894530).
  // Sounds, particles, decals, camera shakes, waves and playable-area changes.
  void CWldSession::ApplyBeatEffects(const SSyncData& beat, CameraImpl* const worldCamera, IWldTerrainRes* const terrainRes)
  {
    USER_GetSound()->UpdateSoundRequests(beat.mAudioRequests);

    if (beat.mAdvanced) {
      sWorldParticles.AdvancementBeat();
    }
    if (beat.mParticleBuffer) {
      sWorldParticles.AddParticles(*static_cast<const SParticleBuffer*>(beat.mParticleBuffer.get()));
    }

    auto* const decalManager = static_cast<CDecalManager*>(terrainRes->GetDecalManager());
    decalManager->AddDecals(beat.mAddDecals);
    decalManager->RemoveDecals(beat.mRemoveDecals);
    decalManager->ProcessRemovals(beat.mCurTick);

    // Camera shakes reach every live camera, not just the world one.
    {
      const fa::vector<CameraImpl*> allCameras = CAM_GetAllRCamCameras();
      for (const SCamShakeParams& shake : beat.mCamShakeParams) {
        for (CameraImpl* const camera : allCameras) {
          if (camera != nullptr) {
            camera->CameraShake(shake);
          }
        }
      }
    }

    if (worldCamera != nullptr) {
      terrainRes->UpdateWaveSystem(worldCamera->CameraGetView(), worldCamera->CameraGetTargetZoom(), mGameTick);
    }

    // Engine addition: all of the beat's map changes in one call, the same as `NotifyMapChange` for
    // each in order (IWldTerrainRes::NotifyMapChanges); SCMP_021's first beat carries 3584.
    terrainRes->NotifyMapChanges(beat.mPlayableRectUpdates.begin(), beat.mPlayableRectUpdates.size());
  }

  // Part of DoBeat (0x00894530).
  // A new army grid means new armies; each lands in its own index slot, and
  // the listener is re-seated afterwards because the focus army may now exist.
  void CWldSession::ApplyBeatArmies(const SSyncData& beat)
  {
    if (!beat.mNewGrids.empty()) {
      for (const SSTIArmyConstantData& armyConstantData : beat.mNewGrids) {
        UserArmy* const army = new UserArmy(this, armyConstantData);
        userArmies[static_cast<std::size_t>(army->mArmyIndex)] = army;
      }
      USER_GetSound()->SetListenerArmy(ArmyAtIndexOrNull(userArmies, FocusArmy));
    }

    // Army updates are positional: the Nth record belongs to the Nth army.
    {
      std::size_t armyIndex = 0;
      for (const SSTIArmyVariableData& armyUpdate : beat.mArmyUpdates) {
        (void)AssignArmyVariableData(armyUpdate, &userArmies[armyIndex]->mVarDat);
        ++armyIndex;
      }
    }
  }

  // Part of DoBeat (0x00894530).
  // New entities, then new units.
  void CWldSession::CreateBeatEntities(const SSyncData& beat)
  {
    for (const SCreateEntityParams& createParams : beat.mNewEntities) {
      AddEntity(new UserEntity(*this, createParams));
    }

    for (const SCreateUnitParams& createParams : beat.mNewUnits) {
      AddEntity(new UserUnit(this, createParams));
    }
  }

  // Part of DoBeat (0x00894530).
  // A helper for every command the sim published this beat.
  void CWldSession::PublishBeatCommandDescriptors(const SSyncData& beat)
  {
    for (const SSTICommandConstantData& commandConstantData : beat.mPublishedCommandDescriptors) {
      (void)FindOrCreateCommandIssueHelper(*mCommandManager, commandConstantData, 0u, 0);
    }

    // Engine addition (issue #275): orders this client gave before it restarted
    // keep their ids, and `Sim::ValidateNewCommandId` refuses an id in use.
    if (CClientManagerImpl* const clients = sSimDriver != nullptr ? sSimDriver->GetClientManager() : nullptr;
        clients != nullptr && clients->mRejoinFeed != nullptr) {
      for (const SSTICommandConstantData& commandConstantData : beat.mPublishedCommandDescriptors) {
        const auto commandId = static_cast<std::uint32_t>(commandConstantData.cmd);
        const std::int32_t lowId = static_cast<std::int32_t>(commandId & 0x00FFFFFFu);
        if ((commandId >> 24u) == mCommandManager->mSourceId && lowId >= mCommandManager->mIdPool.mNextLowId) {
          mCommandManager->mIdPool.mNextLowId = lowId + 1;
        }
      }
    }
  }

  // Part of DoBeat (0x00894530).
  // Unit and entity updates, erases, poses and deletes, in that order.
  void CWldSession::UpdateBeatEntities(const SSyncData& beat)
  {
    if (!ApplyUnitUpdatesParallel(*this, beat.mUnitUpdates)) {
      for (const SUnitVariableUpdateEntry& unitUpdate : beat.mUnitUpdates) {
        auto* const unit = static_cast<UserUnit*>(LookupEntityId(unitUpdate.mEntityId));
        unit->UpdateUnitData(unitUpdate.mVariableData, unitUpdate.mReconFlags);
      }
    }

    if (!ApplyEntityUpdatesParallel(*this, beat.mEntityUpdates)) {
      for (const SEntityVariableUpdateEntry& entityUpdate : beat.mEntityUpdates) {
        LookupEntityId(entityUpdate.mEntityId)->UpdateEntityData(entityUpdate.mVariableData);
      }
    }

    // Erase means "the sim is done with this entity but the client may still be
    // animating it": drop it from the id map and park it in the orphan set.
    for (const EntId erasedId : beat.mEraseIds) {
      OrphanEntity(LookupEntityId(erasedId));
    }

    for (const SEntityPoseUpdateEntry& poseUpdate : beat.mPoseUpdates) {
      UserEntity* const entity = LookupEntityId(poseUpdate.mEntityId);
      if (entity == nullptr) {
        gpg::Logf("CWldSession::DoBeat() unknown entity id (0x%08x) supplied in a pose update.", poseUpdate.mEntityId);
        continue;
      }
      entity->SetPose(poseUpdate.mPose);
    }

    // Delete means gone for good.
    for (const EntId deletedId : beat.mDeleteIds) {
      UserEntity* const entity = LookupEntityId(deletedId);
      RemoveEntity(entity);
      delete entity;
    }
  }

  // Part of DoBeat (0x00894530).
  // Command variable data, then removed and released commands.
  void CWldSession::ApplyBeatCommandPackets(const SSyncData& beat)
  {
    for (const SSyncPublishedCommandPacket& commandPacket : beat.mPublishedCommandPackets) {
      UserCommandIssueHelper* const helper = FindCommandIssueHelper(*mCommandManager, commandPacket.commandId);
      helper->mVariableData = commandPacket.variableData;
      helper->mVariableDataDirty = 1u;
    }

    for (const CmdId removedCommandId : beat.mPendingCommandEventRemovals) {
      delete FindCommandIssueHelper(*mCommandManager, removedCommandId);
    }

    DeleteCommandIssueHelpers(*mCommandManager, beat.mPendingReleasedCommandIds);
  }

  // Part of DoBeat (0x00894530).
  // Hand the sim's Lua payload to the UI: last beat's table becomes
  // `PreviousSync`, this beat's stream becomes `Sync`, then `OnSync()` runs.
  void CWldSession::HandSyncToUi(const SSyncData& beat)
  {
    const LuaPlus::LuaObject previousSync = SCR_Copy(mState->GetGlobal("Sync"), mState);
    mState->GetGlobals().SetObject("PreviousSync", previousSync);

    // The binary takes the stream by reference and never checks it: every
    // beat carries one, because `Sim::Sync` installs a fresh
    // `MemBufferStream` before serialising the table into it. That tail was
    // an unrecovered gap here, which left `mStream` null and forced a guard
    // that skipped the deserialize on every single beat - the sim wrote the
    // `Sync` table and the UI never saw any of it. The tail is recovered
    // now and `Sim::Sync` is the only producer of an `SSyncData`, so the
    // guard is dead and the unchecked binary shape is restored.
    gpg::BinaryReader syncReader(beat.mStream);
    LuaPlus::LuaObject currentSync;
    // Engine addition: decoded without the network decode's nesting cap
    // (see SCR_FromLocalByteStream); the binary calls SCR_FromByteStream.
    currentSync.SCR_FromLocalByteStream(currentSync, mState, &syncReader);
    mState->GetGlobals().SetObject("Sync", currentSync);
    SIM_AddRestoredUiData(currentSync, mState, IsReplay != 0); // engine addition (replay keyframes)
  }

  // Part of DoBeat (0x00894530).
  // Desyncs the sim found this beat: reported to FAF and shown, unless the orders were altered.
  void CWldSession::ReportBeatDesyncs(const SSyncData& beat)
  {
    if (!beat.mDesyncs.empty()) {
      fa::vector<fa::string> desyncArmyNames;
      desyncArmyNames.reserve(beat.mDesyncs.size());

      // Engine addition: a checksum from a player whose orders reached this
      // client differently from what it acknowledged sending says nothing
      // about this game (CommandStreamCheck). It is logged, not reported.
      ISTIDriver* const driver = sSimDriver.get();
      CClientManagerImpl* const clientManager = driver != nullptr ? driver->GetClientManager() : nullptr;

      for (const SDesyncInfo& desync : beat.mDesyncs) {
        const fa::string& armyName = cmdSources[static_cast<std::size_t>(desync.army)].mName;
        if (clientManager != nullptr && clientManager->OrdersAlteredFrom(static_cast<CommandSourceId>(desync.army))) {
          gpg::Warnf(
            "Desync with %s at beat %d not reported to FAF: %s's orders reached this client differently from "
            "what it acknowledged sending (see the NET warning).",
            armyName.c_str(),
            desync.beat,
            armyName.c_str()
          );
          CDesyncRecorder::AddNote(gpg::STR_Printf(
            "beat %d, %s: orders reached this client differently from what %s acknowledged sending", desync.beat,
            armyName.c_str(), armyName.c_str()
          ).c_str());
          CDesyncRecorder::NoteOrdersAltered(desync.army); // issue #218: faf.orders_altered
          continue;
        }
        desyncArmyNames.push_back(armyName);
        GPGNET_ReportDesync(desync.beat, desync.army, desync.hash2.ToString(), desync.hash1.ToString());
      }

      if (!desyncArmyNames.empty()) {
        // Engine addition (issue #216): the dialog's diagnostic lines name the recorder's dump.
        if (const std::string dumpPath = CDesyncRecorder::DumpPath(); !dumpPath.empty()) {
          desyncArmyNames.push_back(fa::string(("Desync dump: " + dumpPath).c_str()));
        }
        UI_ShowDesyncDialog(mGameTick, desyncArmyNames);
      }
    }
  }

  // Part of DoBeat (0x00894530).
  // Engine addition (issue #218), test only: `/exitattick N` quits the app at game tick N the
  // way /exitongameover does, so a scenario ends its games cleanly (the game-end telemetry
  // record is sent on that path; mpemu's kill would skip it).
  void CWldSession::ExitAtTickIfAsked()
  {
    static int sExitAtTick = -2;
    if (sExitAtTick == -2) {
      fa::vector<fa::string> args;
      sExitAtTick = CFG_GetArgOption("/exitattick", 1u, &args) && !args.empty() ? std::atoi(args[0].c_str()) : -1;
    }
    if (sExitAtTick >= 0 && static_cast<int>(mGameTick) >= sExitAtTick) {
      sExitAtTick = -1;
      gpg::Logf("exitattick: quitting at game tick %d", static_cast<int>(mGameTick));
      wxTheApp->ExitMainLoop();
    }
  }

  // Part of DoBeat (0x00894530).
  // Every registered unit gets its beat. The stat is what the profiler reads
  // as "how much work is one beat", so it is published even for an empty list.
  void CWldSession::TickBeatUnits(const SSyncData& beat)
  {
    // Heap-backed on purpose. `Collect` takes the vector by its
    // `gpg::fastvector<T>` base, and the base's grow path frees `start_`
    // unconditionally - it has no `originalVec_` word to test against. Hand
    // it an inline `FastVectorN` and the first push past the inline capacity
    // calls `delete[]` on the inline buffer, which here would be a stack
    // address. The binary gets away with an inline lane because its collect
    // family is templated on the concrete vector type, so the grow helper it
    // emits (sub_505BA0) reads `originalVec_` at +0x0C and skips the free.
    // Until that template is restored, the base-typed API must be handed a
    // vector that really does own its storage.
    gpg::fastvector<UserEntity*> tickers;
    auto* const spatialDb = GetEntitySpatialDbStorage();
    (void)spatialDb->Collect(tickers, ENTITYTYPE_Unit);

    const auto tickerCount = static_cast<std::int32_t>(tickers.size());
    if (sEngineStat_UserSync_SessionTick_NumTickers == nullptr) {
      sEngineStat_UserSync_SessionTick_NumTickers =
        GetEngineStats()->GetItem("UserSync_SessionTick_NumTickers", true);
      (void)sEngineStat_UserSync_SessionTick_NumTickers->Release(0);
    }
    (void)sEngineStat_UserSync_SessionTick_NumTickers->SetInt(&tickerCount);

    for (std::int32_t i = 0; i < tickerCount; ++i) {
      UserEntity* const ticker = tickers[static_cast<std::size_t>(i)];
      ticker->Tick(beat.mCurBeat);
    }
  }

  // Part of DoBeat (0x00894530).
  // Both weak-set drains prune as they go. The orphan walk steps the cursor
  // before it calls out, because `OrphanUpdate` can unlink the entity it was
  // just handed; the visibility walk steps after, because `UpdateVisibility`
  // leaves the set alone.
  //
  // 0x008955F2..0x00895641: `find` from `mOrphans.mHead->mLeft`, then per
  // entry decode (0x0066A300), advance (0x007AE7E0) and `OrphanUpdate`.
  // 0x0089564A..0x008956D8: the same walk over `mVizUpdates`, with the
  // successor step inlined after the `UpdateVisibility` call.
  void CWldSession::UpdateOrphansAndVisibility()
  {
    for (auto orphan = mOrphans.begin(); orphan != mOrphans.end();) {
      UserEntity* const entity = *orphan;
      ++orphan;
      if (entity != nullptr) {
        entity->OrphanUpdate();
      }
    }

    for (UserEntity* const entity : mVizUpdates) {
      if (entity != nullptr) {
        entity->UpdateVisibility();
      }
    }
  }

  /**
   * Address: 0x00895B40 (FUN_00895B40, ?SessionFrame@CWldSession@Moho@@QAEXM@Z)
   */
  void CWldSession::SessionFrame(const float deltaSeconds)
  {
    static_cast<RRuleGameRules*>(mRules)->UpdateLuaState(mState);

    ISTIDriver* const simDriver = sSimDriver.get();

    // Interpolation between ticks. Running with the wind means "do not
    // interpolate, just consume beats", so the fraction is pinned at a whole
    // tick and the drain below never waits for the clock.
    const std::int32_t fastForwardTarget = REPLAY_FastForwardTarget(); // engine addition (replay timeline)
    if (mLastBeatWasTick == 0 || wld_RunWithTheWind || fastForwardTarget >= 0) {
      mTimeSinceLastTick = 1.0f;
    } else {
      mTimeSinceLastTick += WLD_GetSimRate() * deltaSeconds * 10.0f;
    }

    CFormation::UpdateOrientation(CursorInfo().mMouseWorldPos, mCurFormation);

    const std::int32_t tickAtFrameStart = mGameTick;
    const std::int32_t targetTick = mGameTick + fa::FloorToIntX87(mTimeSinceLastTick); // 0x00895BEA..0x00895BFD

    // Engine addition (issue #275): a client catching up shows nothing worth
    // waiting for, and its driver needs the queue to have room at the handover.
    CClientManagerImpl* const frameClients = simDriver->GetClientManager();
    const bool rejoinCatchingUp = frameClients != nullptr && frameClients->RejoinCatchingUp();

    // Drain the driver's sync queue. Bounded at 100 beats so a burst after a
    // stall cannot make one frame arbitrarily long.
    std::int32_t beatsApplied = 0;
    // Engine addition (replay timeline): a fast-forward takes what the sim has ready for most of a frame, so the
    // UI stays responsive, and a paused replay moves too.
    if (fastForwardTarget >= 0) {
      constexpr std::chrono::milliseconds kFastForwardFrameBudget{15};
      const auto frameStart = std::chrono::steady_clock::now();
      while (mGameTick < fastForwardTarget && IsGameOver == 0 && simDriver->HasSyncData()) {
        SSyncData* packet = nullptr;
        simDriver->GetSyncData(packet);
        DoBeat(fa::auto_ptr<SSyncData>(packet));
        ++beatsApplied;
        if (std::chrono::steady_clock::now() - frameStart >= kFastForwardFrameBudget) {
          break;
        }
      }
      REPLAY_AfterFastForwardFrame(*this, beatsApplied);
    } else
    for (; beatsApplied < 100 && !WLD_IsReplaySimSwapping(); ++beatsApplied) {
      if (mReplayIsPaused) {
        // A paused replay still applies beats until it lands on a tick.
        if (mLastBeatWasTick != 0) {
          break;
        }
      } else if (mGameTick >= targetTick && !wld_RunWithTheWind && !rejoinCatchingUp) {
        break;
      }

      if (!simDriver->HasSyncData()) {
        break;
      }

      SSyncData* packet = nullptr;
      simDriver->GetSyncData(packet);
      DoBeat(fa::auto_ptr<SSyncData>(packet));
    }

    if (sEngineStat_Sync_Count == nullptr) {
      sEngineStat_Sync_Count = GetEngineStats()->GetItem("Sync_Count", true);
      (void)sEngineStat_Sync_Count->Release(0);
    }
    (void)sEngineStat_Sync_Count->SetInt(&beatsApplied);

    // Engine addition (wld_FrameClock): the session's first tick reached the screen. The frames
    // before it include the long first frame of play, which would hold up the frame clock's
    // average for the next frames and rush the opening ticks out a few milliseconds apart.
    if (!gSessionShowedTick && mGameTick != tickAtFrameStart) {
      gSessionShowedTick = true;
      gFrameClockResetPending = true;
    }

    // Whatever the drain consumed comes back off the interpolation fraction, so
    // the render clock does not run ahead of the sim clock.
    if (fastForwardTarget >= 0) {
      mTimeSinceLastTick = 0.0f;
    } else if (!wld_RunWithTheWind) {
      const float remainder = mTimeSinceLastTick - static_cast<float>(mGameTick - tickAtFrameStart);
      mTimeSinceLastTick = std::max(0.0f, std::min(remainder, 1.0f));
    }

    if (const boost::shared_ptr<UICommandGraph> commandGraph = GetCommandGraph(false)) {
      commandGraph->CreateMeshes();
    }

    // 0x00409AC0 - the binary names this `CTaskStage::DoFrame`; it is the same
    // body the rest of the tree already calls `UserFrame`.
    mCurThread->UserFrame();
  }

  /**
   * Address: 0x00896000 (FUN_00896000, ?GetSelectionUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   */
  void CWldSession::GetSelectionUnits(fa::vector<UserUnit*>& outUnits) const
  {
    outUnits.clear();

    // The selection is a set, so every unit appears once: no duplicate check (with one, a
    // selection of n units cost n^2/2 compares, per caller, per frame).
    for (UserEntity* const entity : mSelection) {
      if (UserUnit* const userUnit = entity->IsUserUnit(); userUnit != nullptr) {
        outUnits.push_back(userUnit);
      }
    }
  }

  /**
   * Address: 0x00896000 (FUN_00896000, ?GetSelectionUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   *
   * What it does:
   * Adds every selected unit to `outUnits` (`WeakSet<UserUnit>::Add`
   * 0x00822270). The walk prunes the selection's dead entries as it goes, so
   * this `QBE` (const) member does change the tree.
   */
  void CWldSession::GetSelectionUnits(WeakSet<UserUnit>& outUnits) const
  {
    for (UserEntity* const entity : mSelection) {
      if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
        (void)outUnits.Add(unit);
      }
    }
  }

  /**
   * Address: 0x00896090 (FUN_00896090, ?GetValidAttackingUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   *
   * What it does:
   * Walks selected units and keeps only those that can attack the currently
   * hovered entity.
   */
  void CWldSession::GetValidAttackingUnits(fa::vector<UserUnit*>& outUnits) const
  {
    outUnits.clear();

    const UserEntity* const hoveredTarget = this->GetHoveredUserEntity();
    for (UserEntity* const entity : mSelection) {
      UserUnit* const userUnit = entity->IsUserUnit();
      if (!userUnit) {
        continue;
      }

      if (userUnit->CanAttackTarget(hoveredTarget, true)) {
        AppendUnitUnique(outUnits, userUnit);
      }
    }

  }

  /**
   * Address: 0x00894280 (FUN_00894280, ?LookupEntityId@CWldSession@Moho@@QAEPAVUserEntity@2@VEntId@2@@Z)
   *
   * What it does:
   * Performs one ordered entity-id lookup in the world-session entity map and
   * returns the live `UserEntity*` when the key is present.
   */
  UserEntity* CWldSession::LookupEntityId(const EntId entityId)
  {
    // 0x00894282..0x0089429C: `find`, compare against `end()` (+0x48), return
    // the mapped value.
    const auto it = mEntities.find(static_cast<std::uint32_t>(entityId));
    return it != mEntities.end() ? it->second : nullptr;
  }

  /**
   * Address: 0x00896140 (FUN_00896140, ?SetSelection@CWldSession@Moho@@QAEXABV?$WeakSet@VUserEntity@Moho@@@2@@Z)
   *
   * What it does:
   * Replaces the active selection set from `selection`, broadcasts one
   * `{previous,current,added,removed}` selection-event payload, updates
   * max-selection bookkeeping, and refreshes sync-filter mask B when changed.
   */
  void CWldSession::SetSelection(const WeakSet<UserEntity>& selection)
  {
    bool selectionChanged = false;

    // What the new selection adds (`Find` 0x00867780 on the current one) and
    // what it drops (`Find` 0x007FDD50 on the new one).
    WeakSet<UserEntity> addedEntities;
    for (UserEntity* const entity : selection) {
      if (mSelection.Find(entity) == mSelection.end()) {
        selectionChanged = true;
        (void)addedEntities.Add(entity);
      }
    }

    WeakSet<UserEntity> removedEntities;
    for (UserEntity* const entity : mSelection) {
      if (selection.Find(entity) == selection.end()) {
        selectionChanged = true;
        (void)removedEntities.Add(entity);
      }
    }

    mSelectionBroadcaster.BroadcastEvent(SSelectionEvent{&mSelection, &selection, &addedEntities, &removedEntities});

    // 0x00896357..0x00896370: the set's assignment (self test, whole-tree
    // erase 0x007AF740, `_Copy` 0x00867B20), then the live count at +0x4AC.
    mSelection = selection;
    mSelectionSize = static_cast<std::uint32_t>(mSelection.Size());

    if (selectionChanged) {
      if (ISTIDriver* const activeDriver = sSimDriver.get(); activeDriver != nullptr) {
        SSyncFilterMaskBlock selectionMask{};
        BuildSelectionSyncMask(mSelection, selectionMask);
        activeDriver->SetSyncFilterMaskB(selectionMask);
      }

      UI_EndCommandMode();
    }
  }

  void CWldSession::SetSelectionUnits(const fa::vector<UserUnit*>& units)
  {
    WeakSet<UserEntity> nextSelection;
    for (UserUnit* const unit : units) {
      if (unit != nullptr) {
        (void)nextSelection.Add(unit);
      }
    }

    SetSelection(nextSelection);
  }

  /**
   * Address: 0x00865830 (FUN_00865830, ?CanSelectUnit@CWldSession@Moho@@QBE_NPAVUserUnit@2@@Z)
   */
  bool CWldSession::CanSelectUnit(UserUnit* const unit) const
  {
    const UserEntity* const entity = reinterpret_cast<const UserEntity*>(unit);
    const bool selectableByArmy = entity != nullptr && entity->IsSelectable() && entity->mArmy == GetFocusUserArmy();
    return selectableByArmy || (UI_SelectAnything && static_cast<const void*>(this) != nullptr && IsCheatsEnabled);
  }

  /**
   * Address: 0x00896900 (FUN_00896900, ?GetDelayToNextBeat@CWldSession@Moho@@QBEMXZ)
   */
  float CWldSession::GetDelayToNextBeat() const
  {
    if (mReplayIsPaused != 0u && mLastBeatWasTick != 0) {
      return (std::numeric_limits<float>::infinity)();
    }

    if (mTimeSinceLastTick < 1.0f) {
      return (1.0f - mTimeSinceLastTick) / (WLD_GetSimRate() * 10.0f);
    }

    return 0.0f;
  }

  /**
   * Address: 0x00895FD0 (FUN_00895FD0, ?GetGameTime@CWldSession@Moho@@QBEMXZ)
   *
   * What it does:
   * Returns current game time in seconds.
   */
  float CWldSession::GetGameTime() const
  {
    return (static_cast<float>(mGameTick) + mTimeSinceLastTick) * 0.1f;
  }

  /**
   * Address: 0x00896960 (FUN_00896960, ?SyncPlayableRect@CWldSession@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * Applies one playable rectangle to terrain and updates user-entity mesh
   * hidden flags to match whether each entity lies inside that rectangle.
   */
  void CWldSession::SyncPlayableRect(const gpg::Rect2i& playableRect)
  {
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      (void)ApplyTerrainPlayableRect(mWldMap->mTerrainRes, playableRect);
    }

    for (const auto& [entityId, entity] : mEntities) {
      if (entity == nullptr) {
        continue;
      }

      MeshInstance* const meshInstance = entity->mMeshInstance;
      if (meshInstance == nullptr) {
        continue;
      }

      const int mapX = static_cast<int>(entity->mVariableData.mCurTransform.pos_.x);
      const int mapZ = static_cast<int>(entity->mVariableData.mCurTransform.pos_.z);
      const bool insidePlayableRect = mapX >= playableRect.x0 && mapX < playableRect.x1 && mapZ >= playableRect.z0 &&
        mapZ < playableRect.z1;
      meshInstance->isHidden = insidePlayableRect ? 0u : 1u;
    }
  }

  /**
    * Alias of FUN_00896F00 (non-canonical helper lane).
   * ?GetSaveData@CWldSession@Moho@@QBE?AV?$shared_ptr@USSessionSaveData@Moho@@@boost@@XZ)
   */
  boost::shared_ptr<SSessionSaveData> CWldSession::GetSaveData() const
  {
    boost::shared_ptr<SSessionSaveData> saveData{new SSessionSaveData()};
    // Every unit's named selection sets, keyed by the unit's entity id. This
    // walked the entity map through a third private node layout, called
    // vtable +0x0C through an invented `ISessionSaveSourceProvider` -- that
    // slot is `UserEntity::IsUserUnit` -- and read a tree head at +0x3D4 of the
    // result through `SessionSaveNodeOwnerView`, which is
    // `UserUnit::mSelectionSets` (+0x3D0, head at +0x3D4, 0x2C string nodes).
    for (const auto& [entityId, entity] : mEntities) {
      UserUnit* const unit = entity != nullptr ? entity->IsUserUnit() : nullptr;
      if (unit == nullptr) {
        continue;
      }

      for (const fa::string& selectionSet : unit->mSelectionSets) {
        saveData->mNodeMap.insert(std::make_pair(entityId, selectionSet));
      }
    }

    return saveData;
  }

  /**
   * Address: 0x0087FC90 (FUN_0087FC90,
   * ?GetScenarioInfo@CWldSession@Moho@@QBE?AVLuaObject@LuaPlus@@XZ)
   *
   * What it does:
   * Returns one value-copy of the session scenario-info Lua object.
   */
  LuaPlus::LuaObject CWldSession::GetScenarioInfo() const
  {
    return LuaPlus::LuaObject(mScenarioInfo);
  }
}

