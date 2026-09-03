---
name: project_unit_publication_producer_chain_is_sound
description: NEGATIVE RESULT for the "commander does not spawn" goal. The entire sim-side chain that publishes a unit to the client was audited end to end against the binary and is intact. If units still do not appear, the defect is on the CONSUMER side (CWldSession::DoBeat), not the producer.
metadata:
  type: project
---

## Audited end to end, all faithful -- do NOT re-walk this

```
Sim::Sync                       FUN_007474B0   entity walk, 0x007478A1
  -> Entity::Sync               Entity.cpp:3407
       -> Entity::UpdateVisibility   FUN_00678A70
       -> Unit::CreateInterface      FUN_006AC2C0   (overrides Entity's)
            -> QueueCreateUnitParams SimDriver.cpp:344
                 -> syncData->mNewUnits.push_back(params)
       -> Unit::SyncInterface        FUN_006AC3A0
            -> SSyncData::mUnitUpdates (+0x158)
       -> Entity::DestroyInterface   FUN_0067A260  (the not-visible arm)
```

Every link is present and recovered. Specifically checked:

- **The entity walk exists** and picks its set from the focus-army-changed flag.
  It was already there before I touched `Sim::Sync` -- see
  [[project_sim_sync_partial_lift_hid_every_unit]], where I duplicated it by
  mistake and had to revert.
- **`Entity::Sync`** gates on `mVisibilityState`: zero routes to
  `DestroyInterface`, non-zero to `CreateInterface` + `SyncInterface`. It also
  unlinks `mCoordNode` unless `mQueueRelinkBlocked`.
- **`Entity::UpdateVisibility`** (`FUN_00678A70`) is faithful line for line, and
  all four fields it touches cross-check against `Entity.h`'s asserts:
  `mVisibilityState` `0x0110`, `mFootprintLayer` `0x0114`, `ArmyRef` `0x014C`,
  `mVizToNeutrals` `0x01E8`. The unowned-entity arm sets the flag to **1**
  unconditionally (`0x00678A89: mov byte ptr [edi+110h], 1`), with no
  `VIZMODE_Never` test -- its comment claimed the opposite until `5218df53`.
- **`Unit::CreateInterface`** really does override the base and queue a
  `SCreateUnitParams` (with `mBuildStateTag` / `mStatsRoot` / `mFake`), not a
  bare `SCreateEntityParams`.
- **`QueueCreateUnitParams`** really does `push_back` onto `mNewUnits`.

## What this leaves

If a unit still never appears on the client, the remaining candidates are:

1. **The consumer.** `CWldSession::DoBeat` reads `mNewUnits` / `mNewEntities` /
   `mUnitUpdates` and is what constructs `UserUnit` / `UserEntity` and fills
   `UserArmy::mAvatars`. That file was peer-locked for this whole session, so it
   was never audited.
2. ~~`mVisibilityState` being 0 because the viz-mode fields were never set~~
   **CLEARED.** Nothing outside `Entity.cpp` calls `SetVizToFocusPlayer` or
   writes `mVizToFocusPlayer`, which looked damning -- but it does not matter,
   because the `Entity` constructor seeds all four fields to `2`
   (`Entity.cpp:2833-2836`), and `VIZMODE_Always == 2` while
   `VIZMODE_Never == 1` (`EVisibilityModeTypeInfo.h`). So
   `mVisibilityState = (viz != VIZMODE_Never)` is **1** by default and every
   entity is visible unless something explicitly hides it. Do not re-chase the
   missing setters.
3. ~~The sync packet reaching the client at all~~ **CLEARED.**
   `CSimDriver::FinalizeSyncDispatchLocked` (`FUN_0073DAD0`,
   `SimDriver.cpp:881`) is complete: it drops the lock, calls
   `mSim->Sync(mActiveSyncFilter, syncData)`, relocks, verifies the historical
   checksum, then `mSyncDataQueue.PushBack(syncData)` and
   `SetEvent(mSyncDataAvailableEvent)`. The packet is produced, queued and
   signalled.

Check (1) first, and check it by reading `DoBeat`, not by re-reading the
producer.

Related: [[reference_retail_engine_ab_oracle]] -- retail's `GpgNetSend JsonStats`
dump at tick 121 is the cheapest ground truth for whether units exist
(`"cdr":{"built":1}`, `currentunits`), and we still emit none.
