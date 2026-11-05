#include "moho/sim/SimPrivate2.h"

namespace
{

  /// sim_ReconOverlap: the light refreshes still running next to the heavy ReconTick.
  struct SReconOverlap
  {
    Sim* mSim = nullptr;
    std::size_t mEnd = 0;  // armies [0, mEnd) are being refreshed
    bool mPending = false;
    std::uint64_t mStarted = 0;
    std::uint64_t mEndedEarly = 0;
  } sReconOverlap;
}

namespace
{
  // Placeholder owner id stamped into a freshly appended extra-data record
  // before the unit fills it in; the engine-wide "no entity" EntId marker.
  constexpr EntId kUnsetExtraUnitDataOwnerId = static_cast<EntId>(0xF0000000u);

  /**
   * Address: 0x00528180 (FUN_00528180)
   *
   * What it does:
   * Updates one MD5 context with a nullable C-string lane, hashing either the
   * source text including terminator or the literal `"<NULL>"` fallback.
   *
   * Templated on the byte sink so `Sim::UpdateChecksum` can feed it through
   * its `MD5UpdateBatch`; the bytes handed to `Update` are unchanged.
   */
  template <class TChecksumSink>
  void UpdateChecksumWithNullableCString(TChecksumSink& context, const char* const text)
  {
    if (text != nullptr) {
      context.Update(text, std::strlen(text) + 1u);
    } else {
      context.Update("<NULL>", 6u);
    }
  }
  bool IsDebugWindowEnabled()
  {
    return moho::SCR_IsDebugWindowActive();
  }

  lua_Hook GetDebugLuaHook()
  {
    return &moho::DebugLuaHook;
  }

  void RulesUpdateLuaState(RRuleGameRules* rules, LuaPlus::LuaState* luaState)
  {
    if (!rules) {
      return;
    }

    rules->UpdateLuaState(luaState);
  }

  void TickTaskStage(CTaskStage* stage)
  {
    if (!stage) {
      return;
    }

    stage->UserFrame();
  }

  void UpdatePaths(PathTables* pathTables, const int budget)
  {
    if (!pathTables) {
      return;
    }

    int pathBudget = budget;
    pathTables->UpdateBackground(&pathBudget);
  }

  void TickEffectManager(CEffectManagerImpl* effectManager)
  {
    if (!effectManager) {
      return;
    }

    effectManager->Tick();
  }

  void PurgeDestroyedEffects(CEffectManagerImpl* effectManager)
  {
    if (!effectManager) {
      return;
    }

    effectManager->PurgeDestroyedEffects();
  }

  void UpdateFormationDb(CAiFormationDBImpl* formationDb)
  {
    if (!formationDb) {
      return;
    }

    formationDb->Update();
  }

  /**
   * Engine addition (`sim_ParallelCoords`): the coordinate pass over `mCoordEntities` with each
   * entity's own half (`Entity::AdvanceCoordsOwn`: transform copies, position history, collision
   * primitive and bounds) on the sim workers, then the shared half (`AdvanceCoordsShared`: grid
   * relink, intel rasters, list link) on the sim thread in list order. No entity's own half reads
   * another entity or anything the shared halves write, so the result is the serial loop's.
   * Returns false (nothing done) when the serial loop should run.
   */
  bool AdvanceCoordsParallel(Sim& sim)
  {
    constexpr std::size_t kMinParallelEntities = 256u;
    constexpr std::size_t kGrain = 64u;
    if (!sim_ParallelCoords || !CSimWorkerPool::ParallelEnabled()) {
      return false;
    }

    static std::vector<Entity*> sEntities;
    static std::vector<CollisionShapeBase::DeferredRelink> sRelinks;
    sEntities.clear();
    for (auto* entity : sim.mCoordEntities.owners()) {
      sEntities.push_back(entity);
    }
    if (sEntities.size() < kMinParallelEntities) {
      for (Entity* const entity : sEntities) {
        AdvanceCoords(entity);
      }
      return true;
    }

    sRelinks.resize(sEntities.size());
    CSimWorkerPool::Get().ParallelFor(sEntities.size(), kGrain, [](const std::size_t begin, const std::size_t end) {
      for (std::size_t index = begin; index < end; ++index) {
        if (sEntities[index] != nullptr) {
          sEntities[index]->AdvanceCoordsOwn(sRelinks[index]);
        }
      }
    });
    for (std::size_t index = 0; index < sEntities.size(); ++index) {
      if (sEntities[index] != nullptr) {
        sEntities[index]->AdvanceCoordsShared(sRelinks[index]);
      }
    }
    return true;
  }

  /**
   * Engine addition (`sim_ParallelUnitSyncRefresh`): `Unit::RefreshSyncBlock` for every unit the
   * sync walk is about to reach, on the sim workers, before the walk. The walk reaches every entity
   * it starts with (an entity's Sync unlinks only itself), the refresh reads nothing the walk writes
   * and writes only the unit's own block, which only the unit's own SyncInterface reads, and the
   * walk's own refresh then finds nothing left to do. So the packet is the serial one.
   */
  void RefreshUnitSyncBlocksParallel(std::vector<Unit*>& units)
  {
    constexpr std::size_t kMinParallelUnits = 128u;
    constexpr std::size_t kGrain = 32u;
    if (units.size() < kMinParallelUnits) {
      return; // the walk refreshes them as it goes
    }
    // The pose handles each refresh replaces, dropped below on this thread in unit order.
    struct SReleasedPoses
    {
      boost::shared_ptr<CAniPose> mPose;
      boost::shared_ptr<CAniPose> mPriorPose;
    };
    static std::vector<SReleasedPoses> sReleased;
    if (sReleased.size() < units.size()) {
      sReleased.resize(units.size());
    }
    CSimWorkerPool::Get().ParallelFor(units.size(), kGrain, [&units](const std::size_t begin, const std::size_t end) {
      for (std::size_t index = begin; index < end; ++index) {
        units[index]->RefreshSyncBlock(&sReleased[index].mPose, &sReleased[index].mPriorPose);
      }
    });
    for (std::size_t index = 0; index < units.size(); ++index) {
      sReleased[index].mPose.reset();
      sReleased[index].mPriorPose.reset();
    }
  }

  void CleanupDecals(CDecalBuffer* decalBuffer)
  {
    if (decalBuffer) {
      decalBuffer->CleanupTick();
    }
  }

  void TickDebugOverlay(RDebugOverlay* overlay, Sim* sim)
  {
    if (!overlay || !sim) {
      return;
    }
    overlay->Tick(sim);
  }
  void AppendLegacyStringToStd(std::string& out, const fa::string& value)
  {
    out.append(value.c_str(), value.size());
  }

  /**
   * Address: 0x00747954..0x007479C8 (inside FUN_007474B0, Moho::Sim::Sync)
   *
   * What it does:
   * Publishes how many entities the beat's sync walk visited. The stat handle
   * is looked up once and cached in a file static, released to zero on first
   * acquisition, and the count is then stored through `StatItem::SetInt` -
   * which is the interlocked compare-exchange loop on `mPrimaryValueBits`
   * (+0x24) the binary open-codes here.
   */
  void StoreSyncEntityCountStat(const std::int32_t syncedEntityCount)
  {
    static moho::StatItem* sEngineStatSyncEntityCount = nullptr;
    if (sEngineStatSyncEntityCount == nullptr) {
      if (moho::EngineStats* const stats = moho::GetEngineStats(); stats != nullptr) {
        sEngineStatSyncEntityCount = stats->GetItem2("Sync_Entity_Count");
        if (sEngineStatSyncEntityCount != nullptr) {
          (void)sEngineStatSyncEntityCount->Release(0);
        }
      }
    }

    if (sEngineStatSyncEntityCount != nullptr) {
      (void)sEngineStatSyncEntityCount->SetInt(&syncedEntityCount);
    }
  }
}


/**
 * Address: 0x007474B0 (FUN_007474B0)
 *
 * What it does:
 * Produces one sync packet from current Sim state and requested filter values.
 *
 * Recovery status:
 * Partial lift. Keeps filter-transfer behavior and minimal beat packet publication
 * so CSimDriver queue/event flow stays consistent while full body recovery is pending.
 */
void Sim::Sync(const SSyncFilter& filter, SSyncData*& outSyncData)
{
  // 0x007474EC..0x00747506: the focus army is compared BEFORE the incoming
  // filter is adopted - `a3a[0] = mFocusArmy != v4` reads the old value off
  // `mSyncfilter` and the new one off the argument, then `SSyncFilter::
  // SSyncFilter(&this->mSyncfilter, that)` overwrites it. Copying first would
  // make the two always equal and the flag permanently false.
  const std::int32_t previousFocusArmy = mSyncFilter.focusArmy;
  mSyncFilter.CopyFrom(filter);
  const bool focusArmyChanged = previousFocusArmy != filter.focusArmy;

  if (focusArmyChanged) {
    // 0x00747512..0x00747560: Lua is told about the switch with 1-based army
    // indices, except that "no focus army" stays -1 rather than becoming 0.
    const auto toLuaArmyIndex = [](const std::int32_t index) {
      return index == -1 ? -1 : index + 1;
    };
    // Argument order is (new, old): ground truth computes `v6` from the
    // incoming filter and `v5` from the old value and calls `Call_Int2(v6, v5)`,
    // matching `function NoteFocusArmyChanged(new, old)` in lua/SimSync.lua.
    // A script failure, or a missing global (LuaFunction's own "call" type
    // error), is logged rather than propagated (FuncInfo 0x00F1A0CC,
    // std::exception handler 0x00747574).
    try {
      const LuaPlus::LuaFunction<> noteFocusArmyChanged(mLuaState->GetGlobal("NoteFocusArmyChanged"));
      noteFocusArmyChanged.Call_Int2(toLuaArmyIndex(filter.focusArmy), toLuaArmyIndex(previousFocusArmy));
    } catch (const std::exception& error) {
      gpg::Warnf("NoteFocusArmyChanged() puked:\n%s", error.what());
    }
  }

  delete outSyncData;
  outSyncData = new SSyncData{};
  // 0x00747605: pre-size the packet from the previous beat's.
  outSyncData->ReserveSizes(mSyncSizes);
  // The four scalars the client reads its clocks off. Without `mCurTick` the
  // session's `mGameTick` never moves, which is what froze the game clock.
  outSyncData->mCurBeat = static_cast<int32_t>(mCurBeat);
  outSyncData->mCurTick = static_cast<int32_t>(mCurTick);
  outSyncData->mAdvanced = mAdvancedThisTick;
  outSyncData->mFocusArmy = mSyncFilter.focusArmy;

  // 0x007479C6..0x007479FC. The camera-follow records the beat accumulated are
  // handed to the packet by SWAPPING the two vectors, not by copying: the sim
  // comes back owning whatever storage the previous packet had, which is how
  // the lane re-uses its allocation every beat. The decompile shows this as
  // three pointer exchanges because MSVC inlined `std::vector::swap`.
  //
  // `Sim.h`'s note on this member has been saying "the beat-copy site that
  // drains this lane into `mFollowCameras` is not yet recovered" -- this is
  // that site. `CWldSession::DoBeat` already replays the packet side through
  // `CameraImpl::CameraFollow`, so until now it replayed an always-empty lane.
  // 0x00747693..0x007476DB. The particle buffer is *handed over*, not shared:
  // the packet takes the pointer and the sim is left with none, so the next
  // beat starts a fresh buffer. The decompile spells this out as a raw px copy,
  // an add-ref on the incoming control block, a weak_release of the outgoing
  // one, and then `[ebx+994h] = 0` / `[ebx+998h] = 0` with a full release --
  // which is an assignment followed by a reset.
  outSyncData->mParticleBuffer = mParticleBuffer;
  mParticleBuffer.reset();

  // 0x007476EF: the decal buffer publishes both of its lanes in one call --
  // visible decals into `mAddDecals`, pending hide ids into `mRemoveDecals` --
  // by swapping, same as the lanes below. `CDecalBuffer::SwapVectors`
  // (0x00779BB0) was recovered with no caller anywhere in the tree; this is it,
  // and `CWldSession::DoBeat` already feeds both lanes to
  // `CDecalManager::AddDecals` / `RemoveDecals`.
  if (mDecalBuffer != nullptr) {
    mDecalBuffer->SwapVectors(&outSyncData->mAddDecals, &outSyncData->mRemoveDecals);
  }

  // 0x00747700..0x00747724: the camera-shake requests the beat accumulated,
  // swapped over like the lanes below. `Sim::mSyncCamShake` (Sim+0x09C8) was
  // declared `fa::vector<void*> mSyncSerializeGroup1` and had no users at
  // all; the `ShakeCamera` Lua binding reached the same storage through a
  // `reinterpret_cast<the deleted owner-overlay*>(sim)` whose
  // `pad_0000[0x09C8]` pinned the offset. Both sides are `SCamShakeParams` now.
  mSyncCamShake.swap(outSyncData->mCamShakeParams);

  // 0x00747740..0x00747782: the map rectangles flattened this beat.
  // `[ebx+9FCh/0A00h/0A04h]` is `mCachedMapRects` (Sim+0x09F8) against
  // `[eax+234h/238h/23Ch]`, `SSyncData::mPlayableRectUpdates` (+0x230); both
  // are already `fa::vector<gpg::Rect2i>`. `FlattenMapRect` pushes each
  // clamped rect into this vector and into `mLoadedMapRects`, and only this
  // one is drained -- the loaded run is the cumulative record that stays.
  mCachedMapRects.swap(outSyncData->mPlayableRectUpdates);

  // 0x007480A4..0x007480EC: the beat's accumulated print lines.
  // `[esi+0A1Ch/0A20h/0A24h]` is `mPrintField` (Sim+0x0A18) against
  // `[eax+288h/28Ch/290h]`, `SSyncData::mPrintField` (+0x284); both are
  // `fa::vector<fa::string>`. `Sim::Printf` appends into the sim side
  // every time sim script writes a line, and nothing was carrying them across.
  mPrintField.swap(outSyncData->mPrintField);

  // 0x007480EE..0x00748136: the two debug canvases, published by shared
  // ownership rather than swapped. Wired by offset, because the names on the
  // two sides do not line up and only the offsets are provable:
  //
  //   [esi+974h] -> [ebx+2A4h]   mDebugCanvas2 -> SSyncData::mTickDebugCanvas
  //   [esi+96Ch] -> [ebx+2ACh]   mDebugCanvas1 -> SSyncData::mBeatDebugCanvas
  //
  // `Sim+0x096C` is pinned by `GetDebugCanvas` (FUN_00746720), whose whole body
  // is `add edi, 96Ch` then a lazy `new CDebugCanvas`; that is the canvas sim
  // script draws into. `AdvanceBeat` rolls it into `mDebugCanvas2` and clears
  // slot 1, so slot 2 holds the finished beat. The crossing is what the binary
  // does; the packet-side field names are recovered guesses and are left alone.
  outSyncData->mTickDebugCanvas.reset_from_owner(mDebugCanvas2);
  outSyncData->mBeatDebugCanvas.reset_from_owner(mDebugCanvas1);

  mSyncSerializeGroup0.swap(outSyncData->mFollowCameras);

  // 0x00747A16..0x00747A58, the same swap idiom for the per-beat extra-unit-data
  // records: Sim+0x0A28 (`[ebx+0A2Ch/0A30h/0A34h]`) against SSyncData+0x294
  // (`[eax+298h/29Ch/2A0h]`). `CWldSession::DoBeat` copies the packet side
  // wholesale onto `CWldSession::mSyncExtraUnitData`, so this lane was being
  // copied every beat and had never been filled.
  mSyncSerializeGroup2.swap(outSyncData->mSyncExtraUnitData);

  // 0x00747A60 and 0x00747AAA, the last two of the four. Both were blocked on
  // the same duplicate-layout problem until SimDriver.h took ownership of
  // SUpgradeNotifyPair and SEntityPoseUpdateEntry: a three-pointer swap is only
  // well-formed between identical types.
  mAllyUpgradeNotifications.swap(outSyncData->mAllyUpgradeNotifications);
  mPendingPoseCopies.swap(outSyncData->mPoseUpdates);


  // 0x00747635..0x0074764C: hand the beat's queued audio requests to the
  // packet and reset the sim-side queue back to its inline storage. Without
  // this the packet's audio lane stayed empty for every beat, so nothing the
  // sim played ever reached `CUserSoundManager::UpdateSoundRequests`.
  if (mSoundManager != nullptr) {
    mSoundManager->DrainRequests(outSyncData->mAudioRequests);
  }


  // 0x00747A54: the army roster is published exactly once, on the first sync.
  // `CWldSession::DoBeat` turns each entry into a `UserArmy` and files it by
  // army index, so until this runs the client's army run stays all-null and
  // anything reading it - `GetArmiesTable`, `IsObserver`, the score and
  // diplomacy panels - has nothing to read.
  if (!mDidSync) {
    const std::size_t armyCount = mArmiesList.size();
    outSyncData->mNewGrids.resize(armyCount);
    for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
      (void)mArmiesList[armyIndex]->CopyArmyConstantData(&outSyncData->mNewGrids[armyIndex]);
    }
    mDidSync = true;
  }

  // 0x00747AE9: the variable half goes out every beat, positionally - the Nth
  // record belongs to the Nth army, which is how `DoBeat` reads it back.
  {
    const std::size_t armyCount = mArmiesList.size();
    outSyncData->mArmyUpdates.resize(armyCount);
    for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
      (void)mArmiesList[armyIndex]->CopyArmyVariableData(&outSyncData->mArmyUpdates[armyIndex]);
    }
  }

  // 0x007478A4..0x00747952: publish every entity that needs it into the packet.
  // This is what turns sim entities into client-side ones at all: `Entity::Sync`
  // calls `CreateInterface` the first time it sees an entity whose interface is
  // not yet created, and that is the only producer of `mNewEntities` /
  // `mNewUnits`. Without this walk the packet's entity lanes are empty forever,
  // so `CWldSession::DoBeat` never constructs a `UserEntity`/`UserUnit`,
  // `UserArmy::mAvatars` stays empty, and `GetArmyAvatars` returns nothing.
  //
  // Two lanes, selected by whether the focus army just changed:
  //   changed -> every unit in the DB is resynced, because visibility is
  //              computed against the focus army and all of it just became
  //              stale (0x007478C2 walks `mEntityDB->mAllUnits`);
  //   otherwise -> only the dirty run threaded through the entities' dirty-list node
  //              (0x0074791E walks `mCoordEntities`).
  //
  // Both dispatch the same virtual, vtable slot 12 (`mov eax, [edx+30h]`), and
  // both count into `Sync_Entity_Count`. The incremental walk advances to the
  // successor BEFORE dispatching (`mov esi, [esi+4]` precedes the call),
  // because `Entity::Sync` unlinks the node it was reached through.
  std::int32_t syncedEntityCount = 0;
  // sim_ParallelSync: the walk leaves the allocation-free half of each unit-update copy to
  // workers, which finish it before anything else touches the packet.
  CUnitUpdateFills unitUpdateFills(outSyncData);
  if (sim_ParallelUnitSyncRefresh && CSimWorkerPool::ParallelEnabled()) {
    static std::vector<Unit*> sSyncUnits;
    sSyncUnits.clear();
    if (focusArmyChanged) {
      for (const auto& idAndEntity : mEntityDB->mAllUnits) {
        if (Entity* const entity = idAndEntity.second; entity != nullptr) {
          if (Unit* const unit = entity->IsUnit(); unit != nullptr) {
            sSyncUnits.push_back(unit);
          }
        }
      }
    } else {
      for (Entity* const entity : mCoordEntities.owners()) {
        if (entity != nullptr) {
          if (Unit* const unit = entity->IsUnit(); unit != nullptr) {
            sSyncUnits.push_back(unit);
          }
        }
      }
    }
    RefreshUnitSyncBlocksParallel(sSyncUnits);
  }
#if FAF_SERVER_MODE
  std::unique_lock<std::mutex> observerLock(sSyncObserverLock);
  CSyncObserver* const observer = sSyncObserver;
#endif
  if (focusArmyChanged) {
    // 0x007478AA..0x0074791A walks the entity DB's whole id map -- every
    // entity, not only units -- and dispatches Sync on each node's value.
    // That also drains the dirty list for props, projectiles and script
    // entities; walking units only left those linked into the next beat, so a
    // replay viewer switching focus army changed the sim checksum.
    for (const auto& idAndEntity : mEntityDB->mAllUnits) {
      if (Entity* const entity = idAndEntity.second; entity != nullptr) {
#if FAF_SERVER_MODE
        if (observer != nullptr) {
          observer->OnEntityWillSync(*entity);
        }
#endif
        entity->Sync(outSyncData);
        ++syncedEntityCount;
#if FAF_SERVER_MODE
        if (observer != nullptr) {
          observer->OnEntitySynced(*entity);
        }
#endif
      }
    }
  } else {
    auto dirtyEntities = mCoordEntities.owners();
    for (auto it = dirtyEntities.begin(); it != dirtyEntities.end();) {
      Entity* const entity = *it;
      ++it;
      if (entity != nullptr) {
#if FAF_SERVER_MODE
        if (observer != nullptr) {
          observer->OnEntityWillSync(*entity);
        }
#endif
        entity->Sync(outSyncData);
        ++syncedEntityCount;
#if FAF_SERVER_MODE
        if (observer != nullptr) {
          observer->OnEntitySynced(*entity);
        }
#endif
      }
    }
  }
  unitUpdateFills.Finish();
  StoreSyncEntityCountStat(syncedEntityCount);
#if FAF_SERVER_MODE
  if (observer != nullptr) {
    observer->OnSyncWalkDone(*this, *outSyncData);
  }
  observerLock.unlock();
#endif

  if (mRequestXMLArmyStatsSubmit) {
    mRequestXMLArmyStatsSubmit = false;

    std::string armyStatsXml;
    armyStatsXml.append("<?xml version=\"1.0\" ?>\n");
    armyStatsXml.append(
      "<GameStats xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n"
    );

    const fa::string armyIndent("  ");
    for (auto it = mArmiesList.begin(); it != mArmiesList.end(); ++it) {
      CArmyImpl* const army = *it;
      CArmyStats* const armyStats = army->GetArmyStats();
      AppendLegacyStringToStd(armyStatsXml, armyStats->ArmyXmlStatsNode(armyIndent));
    }
    armyStatsXml.append("</GameStats>\n");

    outSyncData->mSubmitArmyStats.assign_owned(std::string_view(armyStatsXml.data(), armyStatsXml.size()));
  }

  // 0x00747AF2..0x00747B0C: drain the entity DB's pending-destroy queue, then
  // publish the command DB's per-beat events. Ground truth runs these back to
  // back with `forceRefresh` = the same focus-army-changed byte that selected
  // the entity walk above:
  //
  //     mov  eax, [ebx+984h]   ; mEntityDB
  //     call EntityDB::Purge
  //     mov  ecx, [edi]        ; syncData
  //     mov  edx, [ebp+a3]     ; forceRefresh
  //     mov  eax, [ebx+988h]   ; mCommandDb  (NOT +0x984 - adjacent to it)
  //     call CCommandDB::PublishSyncData
  //
  // `EntityDB::Purge` (0x00684560) has exactly one caller in the binary and
  // this is it, so nothing destroyed the queued entities before this; and
  // `PublishSyncData` had no source-level caller at all, so per-command sync
  // events never reached the client.
  if (mEntityDB != nullptr) {
    mEntityDB->Purge();
  }
  if (mCommandDB != nullptr) {
    mCommandDB->PublishSyncData(outSyncData, focusArmyChanged);
  }

  // 0x00747B23 onward: republish the per-beat state Lua reads off the global
  // `Sync` table. lua/SimSync.lua consumes these every beat; nothing wrote
  // them, so the table's pause and cheater lanes were permanently stale.
  //
  //     LuaState::GetGlobal(mLuaState, &syncTable, "Sync");
  //     if (mPausedBy == -1) { SetNil("PausedBy"); SetNil("TimeoutsRemaining"); }
  //     else { SetInteger("PausedBy", mPausedBy + 1);
  //            SetInteger("TimeoutsRemaining",
  //                       mCommandSources[mPausedBy].mTimeouts); }
  //     ... if (mCheaters non-empty) { t[i+1] = mCheaters[i] + 1;
  //                                    SetObject("Cheaters", t);
  //                                    mCheaters._Mylast = _Myfirst; }
  //
  // Both index lanes are published 1-based, matching every other army/source
  // index handed to Lua; the cheater run is cleared after publication so each
  // entry is reported exactly once.
  if (mLuaState != nullptr) {
    LuaPlus::LuaObject syncTable = mLuaState->GetGlobal("Sync");
    if (syncTable.IsTable()) {
      const std::int32_t pausedBy = mPausedByCommandSource;
      if (pausedBy == -1) {
        syncTable.SetNil("PausedBy");
        syncTable.SetNil("TimeoutsRemaining");
      } else {
        syncTable.SetInteger("PausedBy", pausedBy + 1);
        if (static_cast<std::size_t>(pausedBy) < mCommandSources.size()) {
          syncTable.SetInteger("TimeoutsRemaining", mCommandSources[static_cast<std::size_t>(pausedBy)].mTimeouts);
        }
      }

      // 0x00747B8x..: the focused army's stat tree goes out as `__ArmyStats`
      // with the current tick stamped on it. Ground truth reads the root item
      // as `*(StatItem **)(v68 + 4)` off the CArmyStats - that is
      // `Stats<CArmyStatItem>::mItem` (+0x04, asserted in Stats.h), and
      // CArmyStatItem derives from StatItem, so the read is a plain upcast.
      if (mSyncArmy > -1 && static_cast<std::size_t>(mSyncArmy) < mArmiesList.size()) {
        if (CArmyImpl* const syncArmy = mArmiesList[static_cast<std::size_t>(mSyncArmy)]; syncArmy != nullptr) {
          if (CArmyStats* const armyStats = syncArmy->GetArmyStats(); armyStats != nullptr) {
            LuaPlus::LuaObject armyStatsTable{};
            STAT_GetLuaTable(mLuaState, armyStats->mItem.get(), armyStatsTable);
            armyStatsTable.SetInteger("Tick", static_cast<std::int32_t>(mCurTick));
            syncTable.SetObject("__ArmyStats", armyStatsTable);
          }
        }
      }

      if (!mCheaters.empty()) {
        LuaPlus::LuaObject cheaters(mLuaState);
        cheaters.AssignNewTable(mLuaState, 0, 0u);
        std::int32_t luaIndex = 1;
        for (auto it = mCheaters.begin(); it != mCheaters.end(); ++it, ++luaIndex) {
          cheaters.SetInteger(luaIndex, *it + 1);
        }
        // The flag rides on the same table as the cheater run, not on `Sync`.
        cheaters.SetBoolean("CheatsEnabled", mCheatsEnabled);
        syncTable.SetObject("Cheaters", cheaters);
        mCheaters.clear();
      }
    }

    // 0x00747BF1..0x00747C3x: flatten the table just written into the beat's
    // packet. This is the sim -> UI data channel - everything set on `Sync`
    // above only reaches the client because it is serialised here, so a beat
    // that skips this step publishes an empty payload no matter what the
    // table holds.
    //
    //     v79 = new MemBufferStream(256);
    //     if (v79 != dataPtr->mStream && dataPtr->mStream)
    //         dataPtr->mStream->dtr_Stream(dataPtr->mStream, 1);
    //     dataPtr->mStream = v79;
    //     SCR_ToByteStream(&syncTable, dataPtr->mStream);
    //
    // The serialisation runs on the same object the setters above wrote, and
    // is not guarded by the table check: a non-table `Sync` still emits its
    // tagged payload. The previous stream is released only when it is not the
    // one being installed; the packet is freshly built each beat so it is
    // normally null, but that is the shape the binary has.
#if FAF_SERVER_MODE
    if (sSyncRouting != nullptr) {
      sSyncRouting->OnSyncTable(*this, syncTable, *outSyncData);
    }
#endif
    auto* const beatStream = new gpg::MemBufferStream(256u);
    if (beatStream != outSyncData->mStream && outSyncData->mStream != nullptr) {
      delete outSyncData->mStream;
    }
    outSyncData->mStream = beatStream;

    (void)syncTable.ToByteStream(*outSyncData->mStream);

    // 0x00747E9F-0x00747EAE: the table is emptied the instant it has been
    // published, by running the sim-side Lua helper.
    //
    //     *(_DWORD *)esp = "ResetSyncTable()";
    //     SCR_LuaDoString(this->mLuaState, ...);
    //
    // Nothing in lua/ clears `Sync` per beat - `ResetSyncTable` is called from
    // `SetupSession` exactly once and otherwise only from here. Without this
    // call every entry ever written to `Sync` is re-serialised on every
    // subsequent beat: `CWldSession::DoBeat` keeps handing the UI the same
    // `Sync.Voice` cue, so a single "commander under attack" VO replays every
    // beat forever, and the table grows without bound for the whole session.
    (void)SCR_LuaDoString("ResetSyncTable()", mLuaState);
  }

  // The desync run is moved, not copied: the sim hands its accumulated
  // reports to the packet and takes the packet's (empty) run in exchange, so
  // each report is published exactly once.
  if (!mDesyncs.empty()) {
    mDesyncs.swap(outSyncData->mDesyncs);
  }

  // 0x0074820x onward: the remaining per-beat packet fields. `CWldSession::
  // DoBeat` reads every one of these each beat -- `mPausedBy` into
  // `mSessionPauseStateA`, `mFogOfWar` into `ren_FogOfWar`, `mSimResources`
  // through `ReseatSharedLane` -- but nothing here wrote them, so they were
  // pinned at their default-constructed values for the whole session.
  //
  //     (*dataPtr)->mPausedBy = this->mPausedBy;
  //     (*dataPtr)->mGameOver = this->mGameOver;
  //     if (mArmiesList non-empty)
  //         v88 = mArmiesList[0]->GetReconDB()->ReconGetFogOfWar();
  //     else v88 = 0;
  //     (*dataPtr)->mFogOfWar = v88;
  //     ... mTerrainUpdate ...
  //     (*dataPtr)->mSimResources = this->mSimResources;
  outSyncData->mPausedBy = mPausedByCommandSource;
  outSyncData->mGameOver = mGameOver;

  // Fog of war is read off the FIRST army only, not the focused one, and is
  // false when there are no armies at all. `GetReconDB` is the virtual at
  // vtable +0x20 that the binary dispatches through.
  bool fogOfWar = false;
  if (!mArmiesList.empty()) {
    if (CArmyImpl* const firstArmy = mArmiesList[0]; firstArmy != nullptr) {
      if (CAiReconDBImpl* const reconDb = firstArmy->GetReconDB(); reconDb != nullptr) {
        fogOfWar = reconDb->ReconGetFogOfWar();
      }
    }
  }
  outSyncData->mFogOfWar = fogOfWar;

  // The terrain the client renders. `sub_743180` in the decompile is the
  // shared_ptr copy the compiler materialises for the assignment's right-hand
  // side; the body after it is the inlined `operator=`. `DoBeat` feeds this
  // straight to `terrainRes->SyncTerrain(beat.mTerrainUpdate.px)`, so leaving
  // it unset handed the terrain renderer a null height field every beat.
  if (mMapData != nullptr) {
    outSyncData->mTerrainUpdate.reset_from_owner(mMapData->mHeightField);
  }

  // The decompiled body here is the inlined `shared_ptr::operator=` -- copy the
  // pointer, add a reference to the incoming control block, release the
  // outgoing one. `reset_from` is that mechanic on the wrapper itself.
  outSyncData->mSimResources.reset_from(mSimResources);

  // 0x0074820E..0x00748310: close this beat's checksum. On a checksum beat
  // (the same `sim_ChecksumPeriod` test `AdvanceBeat` used to feed `mContext`)
  // the digest goes into the 128-beat ring and the context restarts; any other
  // beat stores a zero digest, which `SimDriver` treats as "nothing to send".
  // `VerifyChecksum` compares every peer's report against this ring.
  const std::uint32_t beat = mCurBeat;
  gpg::MD5Digest& beatHash = mSimHashes[beat & 0x7Fu];
  const int checksumPeriod = ReadSimConVarInt(this, &gSimConVar_sim_ChecksumPeriod, 1);
  if ((beat % static_cast<std::uint32_t>(checksumPeriod)) == 0u) {
    beatHash = mContext.Digest();
    mContext.Reset();
  } else {
    beatHash = gpg::MD5Digest{};
  }
  Logf("beat %d final checksum: %s\n", static_cast<int>(beat), beatHash.ToString().c_str());

  // 0x00748311..0x00748336: the beat is published, so retire it. The
  // advanced-this-tick latch is consumed with it, and the game-over flag the
  // rules layer raised becomes the one the client is told about.
  mDidProcess = false;
  ++mCurBeat;
  FlushLog();
  mAdvancedThisTick = false;
  mGameOver = mGameEnded;

  // 0x00748341: remember this packet's sizes for the next beat's reserve.
  mSyncSizes = outSyncData->GetSizes();
}
namespace
{
  /**
   * What it does:
   * Collects consecutive checksum byte spans bound for one `gpg::MD5Context`
   * and hands them to `MD5Context::Update` in large runs.
   *
   * Exact: MD5 digests a byte stream, and `MD5Context::Update` carries partial
   * blocks across calls, so feeding the same bytes in the same order through
   * fewer, larger `Update` calls leaves the context in the identical state
   * (`size`, `pos`, block bytes and digest words). `Flush` must run before
   * anything reads the context (`Digest`) or updates it directly.
   */
  class MD5UpdateBatch
  {
  public:
    explicit MD5UpdateBatch(gpg::MD5Context& context) noexcept
      : mContext(context)
    {}

    MD5UpdateBatch(const MD5UpdateBatch&) = delete;
    MD5UpdateBatch& operator=(const MD5UpdateBatch&) = delete;

    ~MD5UpdateBatch()
    {
      Flush();
    }

    void Update(const void* const data, const std::size_t size)
    {
      if (!sim_ChecksumBatching) {
        Flush();
        mContext.Update(data, size);
        return;
      }
      if (size > mBytes.size() - mUsed) {
        Flush();
        if (size > mBytes.size()) {
          mContext.Update(data, size);
          return;
        }
      }

      // Raw hash byte IO: append the span to the pending run.
      std::memcpy(mBytes.data() + mUsed, data, size);
      mUsed += size;
    }

    void Flush()
    {
      if (mUsed != 0u) {
        mContext.Update(mBytes.data(), mUsed);
        mUsed = 0u;
      }
    }

  private:
    gpg::MD5Context& mContext;
    std::size_t mUsed = 0u;
    std::array<std::uint8_t, 1024> mBytes;
  };
}


/**
 * Address: 0x0074A640 (FUN_0074A640, sub_74A640)
 *
 * What it does:
 * Rebuilds the per-beat simulation checksum digest.
 */
void Sim::UpdateChecksum()
{
  // Engine addition (issue #216): read once; the binary tested `mLog` at each line.
  const bool syncLog = IsSyncLogOn();
  // Engine addition (sim_DesyncDump): the hashed values, framed, also go into the desync recorder's
  // memory ring (CDesyncRecorder::StateTap documents the records); copied, nothing formatted.
  CDesyncRecorder* const recorder = CDesyncRecorder::For(this);
  std::string* const stateTap = recorder != nullptr ? recorder->StateTap() : nullptr;
  const auto tap = [stateTap](const void* const data, const std::size_t size) {
    stateTap->append(static_cast<const char*>(data), size);
  };
  auto logChecksumDigest = [this, syncLog]() {
    if (!syncLog) {
      return;
    }

    const fa::string digestText = mContext.Digest().ToString();
    Logf("      %s\n", digestText.c_str());
  };

  const bool shouldUpdateReconChecksum = (mCurBeat % 100u) == 0u;

  Logf("Armies\n");
  for (auto it = mArmiesList.begin(); it != mArmiesList.end(); ++it) {
    CArmyImpl* const army = *it;
    Logf("  \"%s\" [%s]\n", army->mConstDat.mPlayerName.raw_data_unsafe(), army->mConstDat.mArmyName.raw_data_unsafe());

    const SEconTotals& economy = army->GetEconomy()->economy;
    mContext.Update(&economy, sizeof(economy));
    if (stateTap != nullptr) {
      const std::int32_t armyIndex = army->mConstDat.mArmyIndex;
      stateTap->push_back('A');
      tap(&armyIndex, sizeof(armyIndex));
      tap(&economy, sizeof(economy));
    }
    if (syncLog) {
      Logf("    mStored=%.1f,%.1f\n", economy.mStored.ENERGY, economy.mStored.MASS);
      Logf("    mIncome=%.1f,%.1f\n", economy.mIncome.ENERGY, economy.mIncome.MASS);
      Logf("    mReclaimed=%.1f,%.1f\n", economy.mReclaimed.ENERGY, economy.mReclaimed.MASS);
      Logf("    mLastUseRequested=%.1f,%.1f\n", economy.mLastUseRequested.ENERGY, economy.mLastUseRequested.MASS);
      Logf("    mLastUseActual=%.1f,%.1f\n", economy.mLastUseActual.ENERGY, economy.mLastUseActual.MASS);
      // 0x0074A780: one line per resource, index first; the binary's format is
      // "%I64" with no conversion letter, so the shipped trace prints nothing
      // after '='. Engine addition (dedicated-server plan WPL.21): that text is
      // written out here, since glibc's printf prints a malformed "%I64" as it is.
      for (int resource = 0; resource < 2; ++resource) {
        Logf("    mMaxStorage[%d]=\n", resource);
      }
      logChecksumDigest();
    }

    if (shouldUpdateReconChecksum) {
      Logf("    CAiReconDBImpl::UpdateSimChecksum()\n");
      army->GetReconDB()->UpdateSimChecksum();
    }

    logChecksumDigest();
  }

  Logf("Dirty Entities\n");
  // The per-entity spans go through one batch (see MD5UpdateBatch): the same
  // bytes in the same order, read from the entity at the same points, reach
  // mContext in fewer Update calls. Every digest log line flushes first.
  MD5UpdateBatch entityChecksum(mContext);
  for (Entity* entity : mCoordEntities.owners()) {
    const std::uint32_t entityId = static_cast<std::uint32_t>(entity->id_);
    entityChecksum.Update(&entityId, sizeof(entityId));
    if (syncLog) {
      Logf("  0x%08x\n", entityId);
      entityChecksum.Flush();
      logChecksumDigest();
    }

    const float health = entity->mVarDat.mHealth;
    entityChecksum.Update(&health, sizeof(health));
    if (syncLog) {
      Logf("    health: %.1f 0x%08x\n", health, FloatBits(health));
      entityChecksum.Flush();
      logChecksumDigest();
    }

    const char* blueprintId = ResolveBlueprintIdCString(entity);
    UpdateChecksumWithNullableCString(entityChecksum, blueprintId);
    if (syncLog) {
      Logf("    bp:%s\n", blueprintId ? blueprintId : "");
      entityChecksum.Flush();
      logChecksumDigest();
    }

    entityChecksum.Update(&entity->mVarDat.mCurTransform.orient_, 0x1Cu);
    if (syncLog) {
      const float* const pos = reinterpret_cast<const float*>(&entity->mVarDat.mCurTransform.pos_);
      const float* const rot = reinterpret_cast<const float*>(&entity->mVarDat.mCurTransform.orient_);
      Logf(
        "    pos: <%7.2f,%7.2f,%7.2f> [0x%08x 0x%08x 0x%08x]\n",
        pos[0],
        pos[1],
        pos[2],
        FloatBits(pos[0]),
        FloatBits(pos[1]),
        FloatBits(pos[2])
      );
      Logf(
        "    rot: <%7.4f,%7.4f,%7.4f,%7.4f> [0x%08x 0x%08x 0x%08x 0x%08x]\n",
        rot[0],
        rot[1],
        rot[2],
        rot[3],
        FloatBits(rot[0]),
        FloatBits(rot[1]),
        FloatBits(rot[2]),
        FloatBits(rot[3])
      );
      entityChecksum.Flush();
      logChecksumDigest();
    }

    Wm3::Vec3f velocity{};
    ReadEntityVelocity(entity, &velocity);
    entityChecksum.Update(&velocity, sizeof(velocity));
    if (syncLog) {
      Logf(
        "   vel: <%7.2f,%7.2f,%7.2f> [0x%08x 0x%08x 0x%08x]\n",
        velocity.x,
        velocity.y,
        velocity.z,
        FloatBits(velocity.x),
        FloatBits(velocity.y),
        FloatBits(velocity.z)
      );
      entityChecksum.Flush();
      logChecksumDigest();
    }
    if (stateTap != nullptr) {
      const std::uint16_t blueprintLength = blueprintId != nullptr
        ? static_cast<std::uint16_t>(std::min<std::size_t>(std::strlen(blueprintId), 0xFFFEu))
        : std::uint16_t{0xFFFFu};
      stateTap->push_back('E');
      tap(&entityId, sizeof(entityId));
      tap(&health, sizeof(health));
      tap(&blueprintLength, sizeof(blueprintLength));
      if (blueprintId != nullptr) {
        tap(blueprintId, blueprintLength);
      }
      tap(&entity->mVarDat.mCurTransform.orient_, 0x1Cu);
      tap(&velocity, sizeof(velocity));
    }
  }
  entityChecksum.Flush();

  constexpr std::size_t kRngMtBytes = sizeof(CMersenneTwister::StateWords);
  static_assert(kRngMtBytes == 0x9C0u, "Mt19937 payload must remain 0x9C0 bytes");
  mContext.Update(&mRngState->twister.state[0], static_cast<unsigned int>(kRngMtBytes));
  mContext.Update(&mRngState->hasMarsagliaPair, 1u);
  if (mRngState->hasMarsagliaPair) {
    mContext.Update(&mRngState->marsagliaPair, 4u);
  }
  if (stateTap != nullptr) {
    std::uint32_t pair = 0;
    if (mRngState->hasMarsagliaPair) {
      std::memcpy(&pair, &mRngState->marsagliaPair, sizeof(pair));
    }
    stateTap->push_back('G');
    tap(&mRngState->twister.state[0], kRngMtBytes);
    tap(&mRngState->hasMarsagliaPair, 1u);
    tap(&pair, sizeof(pair));
  }
}

bool Sim::IsSyncLogOn() const noexcept
{
  if (mLog != nullptr) {
    return true;
  }
  const CDesyncRecorder* const recorder = CDesyncRecorder::For(this);
  return recorder != nullptr && recorder->IsRecording();
}

/**
 * Address: 0x00748600 (FUN_00748600, ?GetBeatChecksum@Sim@Moho@@QBE_NVCSeqNo@2@AAUMD5Digest@gpg@@@Z)
 *
 * What it does:
 * Copies one retained beat checksum out of the 128-entry rolling ring when
 * the requested beat is still available.
 */
bool Sim::GetBeatChecksum(gpg::MD5Digest* const outChecksum, const CSeqNo beat) const
{
  const int delta = static_cast<int>(beat) - static_cast<int>(mCurBeat);
  if (delta + 128 < 0 || delta >= 0) {
    return false;
  }

  *outChecksum = mSimHashes[static_cast<std::uint32_t>(beat) & 0x7Fu];
  return true;
}
namespace
{
  // Engine addition, not in the binary: the recon phase of AdvanceBeat on CSimWorkerPool.
  constexpr std::size_t kMaxParallelReconArmies = 32u;

  // One fixup list per army slot; static so that no worker allocates (see SRefreshFixups).
  CAiReconDBImpl::SRefreshFixups sReconRefreshFixups[kMaxParallelReconArmies];

  /// Refreshes the recon DBs of armies [begin, end) on the pool, then applies their deferred
  /// handle assignments on this thread in army order, exactly where the serial loop would have.
  void RefreshReconArmyRange(Sim& sim, const std::size_t begin, const std::size_t end)
  {
    if (begin >= end) {
      return;
    }
    CSimWorkerPool::Get().ParallelFor(end - begin, 1u, [&sim, begin](const std::size_t first, const std::size_t last) {
      for (std::size_t i = begin + first; i < begin + last; ++i) {
        CArmyImpl* const army = sim.mArmiesList[i];
        if (CAiReconDBImpl* const reconDb = army ? army->GetReconDB() : nullptr; reconDb != nullptr) {
          reconDb->RefreshDeferringHandles(sReconRefreshFixups[i]);
        }
      }
    });
    for (std::size_t i = begin; i < end; ++i) {
      CArmyImpl* const army = sim.mArmiesList[i];
      if (CAiReconDBImpl* const reconDb = army ? army->GetReconDB() : nullptr; reconDb != nullptr) {
        reconDb->ApplyRefreshFixups(sReconRefreshFixups[i]);
      }
    }
  }

  /// Waits for the overlapped refreshes and drops their displaced handles, in army order. Called
  /// before Lua can reach engine state, and when the heavy tick returns.
  void FinishReconOverlap()
  {
    if (!sReconOverlap.mPending) {
      return;
    }
    sReconOverlap.mPending = false;
    LUA_SetCallGate(nullptr);
    RECON_StopQueryCache();
    CSimWorkerPool::Get().FinishAsync();
    for (std::size_t i = 0; i < sReconOverlap.mEnd; ++i) {
      CArmyImpl* const army = sReconOverlap.mSim->mArmiesList[i];
      if (CAiReconDBImpl* const reconDb = army ? army->GetReconDB() : nullptr; reconDb != nullptr) {
        reconDb->ApplyRefreshFixups(sReconRefreshFixups[i]);
      }
    }
  }

  /// The heavy tick's Lua is about to call `function` (null: collect garbage). The Lua libraries
  /// touch only Lua values and ReconBlip:GetSource only reads the blip, so those calls keep the
  /// overlap; anything else may reach what the refreshes read, so they finish first.
  void ReconOverlapGate(const LuaCFunctionPtr function)
  {
    if (function != nullptr && (function == &cfunc_ReconBlipGetSource || LUA_IsLibraryCFunction(function))) {
      return;
    }
    ++sReconOverlap.mEndedEarly;
    FinishReconOverlap();
  }

  /// The serial loop refreshes every army except `mCurTick % armyCount`, which runs ReconTick
  /// instead, in army order. ReconTick calls Lua, so it stays on this thread between the two
  /// parallel groups: armies before it see the state before it, armies after it the state after.
  ///
  /// sim_ReconOverlap: the armies before it are refreshed next to it instead of before it. Its own
  /// C++ writes nothing a refresh reads (its army's recon slots, its maps, grids, blip creation,
  /// queued blip destroys, the checksum), and a refresh writes only its army's slots, so the two
  /// commute. Its Lua could change what a refresh reads only through an engine C function, and
  /// the call gate finishes the refreshes before any such call or collection runs.
  ///
  /// sim_ReconQueryCache: the same job also computes its main loop's unit queries ahead (chunks
  /// after the armies), and the gate stops serving them the same way.
  void RunReconPhaseParallel(Sim& sim)
  {
    const std::size_t armyCount = sim.mArmiesList.size();
    const std::size_t reconTickIndex = static_cast<std::size_t>(sim.mCurTick) % armyCount;
    CAiReconDBImpl* const heavyDb =
      sim.mArmiesList[reconTickIndex] != nullptr ? sim.mArmiesList[reconTickIndex]->GetReconDB() : nullptr;

    const std::size_t queryChunks = (sim_ReconOverlap && heavyDb != nullptr) ? RECON_StartQueryCache(heavyDb) : 0u;
    if (sim_ReconOverlap && reconTickIndex + queryChunks > 0u && heavyDb != nullptr) {
      sReconOverlap.mSim = &sim;
      sReconOverlap.mEnd = reconTickIndex;
      const bool running = CSimWorkerPool::Get().StartAsync(
        reconTickIndex + queryChunks, 1u,
        [](void* const context, const std::size_t first, const std::size_t last) {
          Sim& owner = *static_cast<Sim*>(context);
          for (std::size_t i = first; i < last; ++i) {
            if (i >= sReconOverlap.mEnd) {
              RECON_FillQueryCache(i - sReconOverlap.mEnd, i - sReconOverlap.mEnd + 1u);
              continue;
            }
            CArmyImpl* const army = owner.mArmiesList[i];
            if (CAiReconDBImpl* const reconDb = army ? army->GetReconDB() : nullptr; reconDb != nullptr) {
              reconDb->RefreshDeferringHandles(sReconRefreshFixups[i]);
            }
          }
        },
        &sim
      );
      sReconOverlap.mPending = true;
      if (running) {
        if ((++sReconOverlap.mStarted % 5000u) == 0u) {
          gpg::Logf(
            "sim_ReconOverlap: %llu overlaps, %llu finished early by the heavy tick's Lua",
            static_cast<unsigned long long>(sReconOverlap.mStarted),
            static_cast<unsigned long long>(sReconOverlap.mEndedEarly)
          );
        }
        LUA_SetCallGate(&ReconOverlapGate);
      } else {
        FinishReconOverlap(); // ran serially: the fixups go before the heavy tick, as serial
      }

      struct SFinishOnExit
      {
        ~SFinishOnExit()
        {
          try {
            FinishReconOverlap();
          } catch (...) {
          }
        }
      } finishOnExit;
      heavyDb->ReconTick(static_cast<int>(armyCount));
      FinishReconOverlap();
    } else {
      RefreshReconArmyRange(sim, 0u, reconTickIndex);
      if (heavyDb != nullptr) {
        heavyDb->ReconTick(static_cast<int>(armyCount));
      }
    }
    RefreshReconArmyRange(sim, reconTickIndex + 1u, armyCount);
  }
}



/**
 * Address: 0x00749F40 (FUN_00749F40)
 *
 * int
 *
 * IDA signature:
 * void __thiscall Moho::Sim::AdvanceBeat(Moho::Sim *this, int amt);
 *
 * What it does:
 * Advances one simulation beat: updates rules/lua hooks, ticks armies/tasks,
 * advances coord entities, drains deferred destroys, and runs periodic
 * checksum/GC maintenance.
 *
 * Recovery status:
 * Partial high-fidelity lift. Core beat staging is restored, with one
 * additional sync-filter packing pass still tracked for follow-up evidence.
 */
void Sim::AdvanceBeat(const int amt)
{
  (void)amt; // Binary implementation does not consume this parameter at 0x00749F40.

  Logf("********** beat %u **********\n", mCurBeat);
  {
    FAF_PROFILE_ZONE_NAMED("Sim::RulesUpdate");
    RulesUpdateLuaState(mRules, mLuaState);
  }

  if (IsDebugWindowEnabled() && mLuaState && mLuaState->m_state) {
    lua_sethook(mLuaState->m_state, GetDebugLuaHook(), 4, 0);
  }

  if (!mGameOver && (mPausedByCommandSource == -1 || mSingleStep)) {
    ++mCurTick;
    Logf("  tick number %u\n", mCurTick);

    if (ReadSimConVarBool(this, &gSimConVar_path_BackgroundUpdate, false)) {
      FAF_PROFILE_ZONE_NAMED("Sim::PathUpdate");
      const int pathBudget = ReadSimConVarInt(this, &gSimConVar_path_BackgroundBudget, 0);
      UpdatePaths(mPathTables, pathBudget);
    }

    ForEachAllArmyUnit(this, [](Unit* unit) {
      if (!unit || unit->IsDead()) {
        return;
      }

      unit->ClearBeatResourceAccumulators();
    });

    {
      FAF_PROFILE_ZONE_NAMED("Sim::ArmiesTick");
      for (CArmyImpl* army : mArmiesList) {
        if (army) {
          army->OnTick();
        }
      }
    }

    // 0x0074A10A / 0x0074A115 / 0x0074A120: `lea ecx,[ebp+958h]`, `[ebp+944h]`,
    // `[ebp+930h]`, each followed by `call 0x409AC0` (CTaskStage::UserFrame).
    // Stage B (unit command threads) runs first and stage A (entity TaskTick /
    // MotionTick) last, so a goal set by a command task is acted on by motion
    // within the same beat. Ticking A first reversed that and let the air
    // navigator declare arrival from stale state (see IAiCommandDispatchImpl).
    {
      FAF_PROFILE_ZONE_NAMED("Sim::TaskStages");
      {
        FAF_PROFILE_ZONE_NAMED("Sim::TaskStageB");
        TickTaskStage(&mTaskStageB);
      }
      {
        // The sim Lua state's m_luaTask is this stage (Sim::Setup), so its Lua threads run here too.
        FAF_PROFILE_ZONE_NAMED("Sim::LuaThreadsAndDiskWatcher");
        TickTaskStage(&mDiskWatcherTaskStage);
      }
      {
        FAF_PROFILE_ZONE_NAMED("Sim::TaskStageA");
        TickTaskStage(&mTaskStageA);
        POSE_FinishStage(); // engine addition (sim_ParallelPose): every queued pose update done here
      }
    }
    {
      FAF_PROFILE_ZONE_NAMED("Sim::Recon");
      {
        FAF_PROFILE_ZONE_NAMED("Recon::RefreshBlips");
        RefreshBlips();
      }

    if (!mArmiesList.empty() && sim_ParallelRecon && mArmiesList.size() <= kMaxParallelReconArmies &&
        CSimWorkerPool::ParallelEnabled()) {
      FAF_PROFILE_ZONE_NAMED("Recon::Parallel");
      RunReconPhaseParallel(*this);
    } else if (!mArmiesList.empty()) {
      FAF_PROFILE_ZONE_NAMED("Recon::Serial");
      const std::size_t armyCount = mArmiesList.size();
      const std::size_t reconTickIndex = static_cast<std::size_t>(mCurTick) % armyCount;
      for (std::size_t i = 0; i < armyCount; ++i) {
        CArmyImpl* army = mArmiesList[i];
        if (!army) {
          continue;
        }

        CAiReconDBImpl* reconDb = army->GetReconDB();
        if (!reconDb) {
          continue;
        }

        if (i == reconTickIndex) {
          reconDb->ReconTick(static_cast<int>(armyCount));
        } else {
          reconDb->ReconRefresh();
        }
      }
    }

    }

    {
      FAF_PROFILE_ZONE_NAMED("Sim::EffectManager");
      TickEffectManager(mEffectManager);
    }
    {
      FAF_PROFILE_ZONE_NAMED("Sim::FormationDb");
      UpdateFormationDb(mFormationDB);
    }

    {
      FAF_PROFILE_ZONE_NAMED("Sim::KillCleanup");
      ForEachAllArmyUnit(this, [](Unit* unit) {
        if (unit->NeedsKillCleanup()) {
          unit->KillCleanup();
        }
      });
    }

    {
      FAF_PROFILE_ZONE_NAMED("Sim::AdvanceCoords");
      if (!AdvanceCoordsParallel(*this)) {
        for (auto* entity : mCoordEntities.owners()) {
          AdvanceCoords(entity);
        }
      }
    }

    // Sync-filter extra-data packing pass. Every id in the outgoing sync
    // filter that still resolves to a live unit contributes one record.
    // `push_back(SExtraUnitData())` is `fa::vector<SExtraUnitData>::
    // push_back` (FUN_0074C160, Vector.h) -- the `.asm`-confirmed shape:
    // the record is copy-constructed in (default `pairs`, zero tag) and
    // then filled in place through the returned `back()` reference, so its
    // inline pair storage is anchored inside the vector element rather
    // than aliasing a temporary that could be relocated by a later grow.
    FAF_PROFILE_ZONE_NAMED("Sim::ExtraUnitData");
    mSyncFilter.maskA.ForEachValue([this](const unsigned int entityId) {
      Entity* const entity = mEntityDB->FindEntityById(entityId);
      if (entity == nullptr) {
        return;
      }

      Unit* const unit = entity->IsUnit();
      if (unit == nullptr) {
        return;
      }

      mSyncSerializeGroup2.push_back(SExtraUnitData());
      SExtraUnitData& record = mSyncSerializeGroup2.back();
      record.unitEntityId = kUnsetExtraUnitDataOwnerId;
      unit->GetExtraData(&record);
    });

    mDebugCanvas2 = mDebugCanvas1;
    mDebugCanvas1.reset();

    mAdvancedThisTick = true;
    mSingleStep = false;
  }

  {
    FAF_PROFILE_ZONE_NAMED("Sim::DeletionQueue");
    while (!mDeletionQueue.empty()) {
      void* queuedObject = mDeletionQueue.front();
      mDeletionQueue.pop_front();
      RunQueuedDestroy(queuedObject);
    }
  }

  {
    FAF_PROFILE_ZONE_NAMED("Sim::EffectDecalCleanup");
    PurgeDestroyedEffects(mEffectManager);
    CleanupDecals(mDecalBuffer);
  }

  const int checksumPeriod = ReadSimConVarInt(this, &gSimConVar_sim_ChecksumPeriod, 1);
  if (checksumPeriod > 0 && (mCurBeat % static_cast<uint32_t>(checksumPeriod)) == 0u) {
    FAF_PROFILE_ZONE_NAMED("Sim::Checksum");
    SIM_ApplyDesyncTestNudge(*this); // engine addition (issue #216), test only, off by default
    UpdateChecksum();
  }

  // 0x0074A5A2: forward from the head's +0x04 slot.
  for (RDebugOverlay* const overlay : mDebugOverlays.owners()) {
    TickDebugOverlay(overlay, this);
  }

  if (mLuaState && mLuaState->m_state && (mCurTick % 70u) == 0u) {
    FAF_PROFILE_ZONE_NAMED("Sim::LuaGC");
    lua_setgcthreshold(mLuaState->m_state, 0);
  }

  // +0x08FC latch: set here in AdvanceBeat, cleared in Sim::Sync.
  mDidProcess = true;
}
