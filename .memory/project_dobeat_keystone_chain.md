---
name: project-dobeat-keystone-chain
description: The game clock is frozen because nothing drains the sim's sync queue; CWldSession::DoBeat is the consumer and needs three constructors recovered first.
metadata:
  type: project
---

As of 2026-08-12 a skirmish loads, reaches `EWldFrameAction::Playing`, builds
the in-game UI and runs to the harness deadline with **no crash**. The session
heartbeat logs, but `Game time` stays at `00:00:00`.

## Why the clock is frozen

`CSimDriver::ThreadRun` (the "Issue" thread) will only issue beats while

    mLastSyncCycleTime != 0 && mOutstandingRequests == 0
      && mSyncDataQueue.size < kMaxQueuedSyncPacketsBeforeStalling   // 10

`Sim::Sync` pushes one packet per beat. **The only consumer of `GetSyncData` in
the whole tree is the single startup call in `WLD_DoInitializing`**, so the
queue reaches 10 and the Issue thread stops issuing, permanently.

The consumer is `CWldSession::DoBeat` (`FUN_00894530`, 1475 instructions, 933
lines of decompile, 69 callees). The binary calls it from two places, both of
which are partial lifts here that omit the call:

- `WLD_DoInitializing` (0x0088C3F0) - once, with the first sync packet, and
  crucially **before** `CreateGameInterface`.
- `CWldSession::SessionFrame` (0x00895B40) - every frame.

## Progress (2026-08-13)

- `1696894` — `UserUnit::AddToSelectionSet` (FUN_008BFF30) recovered, wired
  into the selection-inheritance block `~UserUnit` (0x008BF9B0) elides at
  0x008BFA49..0x008BFB1A. Also gave `msvc8::set`/`map` a real copy ctor on the
  shared `rb_tree` (that is FUN_008C5B10) instead of an open-coded copy.
- `aa59682` — one weak-set head builder (`AllocateWeakEntitySetHead`) and one
  scoped holder (`moho::ScopedLocalSelectionSet`), replacing four mirrors.
- `ab9c940` — `SSelectionSetUserEntity::Erase` (FUN_008676E0) recovered once,
  with the weak-owner guard both open-coded copies were missing. The tree
  mechanics are widened to the 12-byte base so army registries share them.
- `e58f32a` — `SSTIUnitVariableData+0x40` named `mSelectionInheritorId`.
- `3866fcb` — **the UserUnit layout gate is open.** UserUnit now holds
  `SSTIUnitVariableData mUnitVarDat` at +0x198 by value instead of flattening
  it; `UpdateUnitData` finally has something to assign onto. Fixed three
  mis-named fields (+0x1A2 is `mIsBusy`, +0x3A8 is the low byte of
  `mScriptbits`, +0x290/+0x294 are `mWeaponInfo` begin/end).
- `f50588f` — **the second layout gate is open.** `UserUnitManager` is a real
  type in `moho/unit/core/UserUnitManager.h` (0x68) instead of a
  reinterpret view over an opaque forward declaration, so `FUN_008B6C50` has
  named fields: `primaryLinks` +0x08, `issueQueue` +0x28, `resolvedLinks`
  +0x40, `resolvedLinksDirty` +0x60.
- `bc240dc` — **the last layout gate is open.** `CommandManager` is a type
  (`moho/command/CommandManager.h`, 0xCC0, `mCommands` map at +0x0CB4) and
  `CWldSession::mSessionRes1` is now `CommandManager* mCommandManager`.
  `UserUnit` also holds `SCreateUnitConstantData mUnitConstDat` at +0x184 and
  `WeakPtr<UserEntity> mCreator` at +0x3C0, and both `UserUnit::UserUnit` and
  `UpdateUnitData` are declared.

## 2026-08-13 progress

**Resume point: the seven finished bodies are held out of the tree.** They
compile and are saved at
`<scratchpad>/UserUnit.cpp.with-ctor-chain` (whole file) and
`<scratchpad>/userunit-ctor-chain.patch`. They were removed before committing
because `UserUnit::UserUnit` and `UpdateUnitData` have no caller until DoBeat
lands, and everything else in the group is called only by them - committing
them would have been seven orphans. Re-apply, then write DoBeat, then commit
the lot together.

### The decal record (`SSyncData::mAddDecals` element), resolved

From `FUN_00878650`: the loop stride is 36 dwords, and the two texture-name
lanes are 28-byte `msvc8::string`s reached as `v6-1` / `v6+6`:

| Off | Field |
|---|---|
| 0x00 | `Wm3::Vector3f mPosition` |
| 0x0C | `Wm3::Vector3f mScale` |
| 0x18 | `Wm3::Vector3f mOrientation` |
| 0x24 | `msvc8::string mTexture1` |
| 0x40 | `msvc8::string mTexture2` |
| 0x5C | `std::uint8_t mIsSplat` |
| 0x60 | `float mCutoffLOD` (<= 0 means "compute it") |
| 0x64 | `std::int32_t mRemoveTick` |
| 0x68 | `msvc8::string mTypeName` (matched against `CWldTerrainDecal::sTypeDesc`) |
| 0x84 | `std::int32_t mHandle` |
| 0x88, 0x8C | two more int lanes copied onto the splat |

Size 0x90. A name that is UNC or has a drive/leading slash is used as-is;
otherwise it is prefixed with `/env/common/splats/` or `/env/common/decals/`
and suffixed `.dds`. Every dependency (`NewSplat`, `LoadDecal`, `sTypeDesc`,
`FILE_HasUNC`/`HasDrive`, `STR_Compare`, `ComputeCutoffLOD`) is recovered.

**Newly found blocker the call-graph missed:** DoBeat reaches the decal
manager through vtable slots (+0x58 AddDecals, +0x5C RemoveDecals, +0x60
ProcessRemovals), so those edges are absent from `call_edges` and the
"69 callees, 2 non-terminal" count was optimistic. `CDecalManager::AddDecals`
is `FUN_00878650` (323 instrs, IDA calls it `Func20`, still `blocked`) - the
address comes from CDecalManager vtable slot 22 in the RTTI dump minus the
0xFBC40F0 rebase that maps slots 23/24 onto the recovered RemoveDecals
(0x00878A40) and ProcessRemovals (0x00878A90). Recover it first; it builds
CWldSplat objects from the decal records, so the record type needs naming
too. Check the other vtable-dispatched calls in DoBeat the same way before
assuming the closure is complete.


- `e481912` — **UserUnit is a real derived class now**: `public UserEntity,
  public IUnit, public CScriptObject`. Its offsets were fiction before (first
  member at 0x04, asserts parked behind an undefined `MOHO_STRICT_LAYOUT_ASSERTS`).
  RTTI proves the vtable is UserEntity's extended by 9 and the secondary base
  records sit at 0x148/0x150. Six vtable slots were mis-modelled: the
  const/non-const command-queue overloads were swapped, slot 12 is
  `IsSelectable() const` not `Select()`, slot 15 takes `forUnitPose`, slot 0 is
  the destructor. `UserEntity` was 4 bytes too big (it restated its
  `WeakObject` base's link head). `UserUnitManager` is really
  `moho::UserCommandQueue` (from the accessors' mangled names) and moved to
  `moho/command/UserCommandQueue.h`.
- WRITTEN, COMPILES, NOT YET COMMITTED (needs DoBeat to have a caller):
  `AddArmyAvatar` (FUN_008B2300), `DeselectFromSessionSelection` (FUN_008C06A0),
  `ResizeQueueLinkVector`/`ShrinkQueueLinkVectorTo` (FUN_008B7590/8B7900),
  `ResyncUserCommandQueueLinks` (FUN_008B6C50), `CreateUserCommandQueue`,
  `UserUnit::UserUnit` (FUN_008BF420), `UserUnit::UpdateUnitData` (FUN_008C0750).
- Also landed on the way: `CommandManager` absorbed `IdPool`+`mSourceId` and the
  three `SessionCommandManagerRuntimeView` duplicates collapsed onto it;
  `FindOrCreateCommandIssueHelper`/`DeleteCommandIssueHelpers`/
  `AdvanceCommandIssueHelpersToBeat` promoted out of Sim.cpp's anon namespace
  into `moho/command/CommandManager.h` (DoBeat needs all three);
  `SCreateUnitParams` now derives from `SCreateEntityParams` (moved to
  `SSTIEntityVariableData.h`); `SUnitVariableUpdateEntry` moved to `Unit.h`;
  eight `SSyncData` byte lanes retyped to their real record types.
- `WeakPtrOwnerLinkOffset<UserEntity>`/`<UserUnit>` specialised to 8.

**Only DoBeat itself is left.** Its 69 callees are all terminal now except the
two UserUnit bodies above. Useful session API: `AddEntity`, `RemoveEntity`,
`OrphanEntity` (= the mEraseIds phase exactly), `LookupEntityId`,
`SetSelection`, `CheckForNecessaryUIRefresh`, `ApplyPendingSaveData`,
`GetCommandGraph`. Field map confirmed from the asm: entity map at 0x44,
`mNonLocalPause`=`mSessionPauseStateA`@0x464, tick canvas {0x414,0x418},
beat canvas {0x41C,0x420}, sim resources {0x424,0x428}, focus army @0x488,
orphan set @0x42C, viz tree @0x438.

### Every layout gate is now open; only bodies are left

The closure is exactly 8 functions (~2760 instrs) and they must land as ONE
commit - none has a caller outside the group:

  `sub_8B2770` push_back / `sub_8B2B70` insert  -> `msvc8::vector` ops on
      `UserArmy::mAvatars`; use `InsertWeakPtrVectorObjectAt` (WeakPtr.h).
  `sub_8B2300` -> sorted avatar insert, ascending `QuickSelectPriority`,
      skipping dead slots; appends when nothing outranks the new unit.
  `FUN_008BF420` UserUnit ctor -> UserEntity base, IUnit + CScriptObject
      subobjects, copy `mUnitConstDat`, allocate the primary manager (and a
      second one when "FACTORY"; sets mIsFactory when also "STRUCTURE"), then
      either `AddArmyAvatar` (QuickSelectPriority > 0) or the engineer test
      (ENGINEER && !COMMAND && !SCOUT && !UNTARGETABLE).
  `sub_8C06A0` -> snapshot selection, erase this unit, re-publish. All deps
      are public already.
  `sub_8B7590` resize + `sub_8B7900` shrink + `sub_8B7CC0` grow -> resize of
      `UserUnitManager::primaryLinks`, filling new slots with a NULL weak node.
  `sub_8B6C50` -> resize the run to the command-id count, rebind each slot to
      `mCommandManager->mCommands[id]` (null when absent), then invalidate the
      resolved run back onto inline storage and raise `resolvedLinksDirty`.
      Entries are WeakPtr-shaped with the owner-link at helper+0.
  `FUN_008C0750` UpdateUnitData -> `mUnitVarDat.AssignFrom(payload)`, store the
      sync mask at +0x3E0, re-seat both poses, re-resolve `mCreator`, and on
      `mDidRefresh` resync both managers.
  `FUN_00894530` DoBeat -> 25 sequential phases over the packet.

`SessionFrame` (0x00895B40) is ALSO wrong beyond the missing drain: it uses
`delta * 10` instead of `WLD_GetSimRate() * delta * 10`, ignores
`wld_RunWithTheWind` and `mReplayIsPaused`, never calls
`UICommandGraph::CreateMeshes`, and calls `mCurThread->UserFrame()` where the
binary calls `CTaskStage::DoFrame`. The drain loop is bounded at 100 beats.

## What is left for the clock

None of these can land alone — their only callers are each other and DoBeat,
so the whole set is one atomic paired commit:

| Token | Symbol | Instrs | Blocking need |
|---|---|---|---|
| `FUN_008C06A0` | busy-transition deselect | 54 | none left — all deps public now |
| `FUN_008B6C50` | manager command-list resync | 140 | `UserUnitManager` layout + the WeakPtr-vector resize family (`FUN_008B7590` 55, `FUN_008B7900`, `FUN_008B7CC0`) |
| `FUN_008C0750` | `UserUnit::UpdateUnitData` | 185 | the two above, plus a real `WeakPtr<UserEntity> mCreator` at UserUnit+0x3C0 (still pad) and the +0x3E0 field, which UpdateUnitData writes a **pointer** to — it is not `mIntelStateFlags` |
| `FUN_008B2300` | avatar add | 133 | none known |
| `FUN_008BF420` | `UserUnit::UserUnit` | 472 | the +0x148/+0x150 subobjects still are not base classes |
| `FUN_00894530` | `CWldSession::DoBeat` | 1475 | all of the above |

`FUN_008B7590` is marked `external_dependency` in the progress DB. It is not —
it is an engine-instantiated WeakPtr-vector resize. Fix the flag when recovering.

## Two things DoBeat can reuse instead of recovering

- `std::map_EntId_UserEntity::find` (FUN_00898DC0) needs no recovery:
  `CWldSession::LookupEntityId` (FUN_00894280) already walks the same tree
  and returns null for the sentinel, which is exactly the
  `find(); if (node == head) null` shape DoBeat open-codes eight times.
- `func_CopyArmyData` (FUN_00700280) is now `moho::AssignArmyVariableData`,
  promoted and wired to `CArmyImpl::CopyArmyVariableData` in `7704f84`.
  DoBeat's army-update loop calls it by name.

## The remaining gate: `UserUnit`'s 0x148..0x198 bridge

`UserUnit::UserUnit` (FUN_008BF420, 472 instrs) cannot be written faithfully
yet because everything it initialises between +0x148 and +0x198 is one
opaque `mIUnitAndScriptBridge[0x148..0x190]` byte array in UserUnit.h.
Resolved from the ctor asm:

| Offset | What |
|---|---|
| 0x148 | `IUnit` subobject vtable (`??_7UserUnit@Moho@@6BIUnit@Moho@@@`) |
| 0x14C | the `IUnit` `WeakObject` head (`mNextUse`), zeroed |
| 0x150 | `CScriptObject` subobject — `sizeof(CScriptObject) == 0x34`, so it ends exactly at 0x184 |
| 0x184 | `SCreateUnitConstantData mUnitConstDat` (0x10) copied from `SCreateUnitParams::mConstDat` |
| 0x190 | `mUnitConstDat.mFake` — the same byte the header already calls `mIsFake` |
| 0x194 | one byte zeroed |
| 0x198 | `SSTIUnitVariableData mUnitVarDat` (ctor call at 0x008BF596) |

The clean model is `class UserUnit : public UserEntity, public IUnit, public
CScriptObject`, which is what the RTTI says, but UserUnit.cpp is ~7800 lines
reaching the subobjects through `GetIUnitBridge(self)` reinterpret casts.
Budget a dedicated pass for it.

`UserUnit::Tick` also shows the class is otherwise in good shape — its idle
registry wiring was already correct once `UserArmy`'s offsets were fixed.

## Naming lead (not acted on)

`CWldSession`'s `mUnknownOwner44` / `mSaveSourceTreeHead` /
`mSaveSourceTreeSize` at +0x44..+0x4C are the **entity map** — that is what
`GetSessionEntityMap` and `LookupEntityId` read them as, and what DoBeat
calls `mEntityMap`. 26 use sites across 7 files. Check whether anything
genuinely reads that lane as a save-source tree before renaming.

## Bottom-up order (about 2500 instructions total)

| Token | Symbol | Instrs | State |
|---|---|---|---|
| `FUN_00700280` | `func_CopyArmyData` | 91 | already recovered (SSTIArmyVariableData.cpp) |
| `FUN_008B1520` | `UserArmy::UserArmy(CWldSession*, SSTIArmyConstantData*)` | 141 | RECOVERED 6d95589 |
| `FUN_008C0750` | `UserUnit::UpdateUnitData` | 185 | missing |
| `FUN_008BF420` | `UserUnit::UserUnit()` | 472 | missing |
| `FUN_008B85E0` | `UserEntity::UserEntity(CWldSession&, const SCreateEntityParams&)` | 160 | recovered |
| `FUN_00894530` | `CWldSession::DoBeat` | 1475 | missing |

Everything else `DoBeat` calls is already in `src/sdk/**` (`SetSelection`,
`CheckForNecessaryUIRefresh`, `ApplyPendingSaveData`, `UserEntity::SetPose` /
`OrphanUpdate`, `SCR_Copy`, the command-manager helpers).

**UserArmy layout (resolved, no longer a gate):** `SSTIArmyConstantData`
base at +0x00, `mVarDat` at +0x80, `WeakObject mWeakRefs` at +0x1E0,
`mSession` at +0x1E4, `msvc8::vector<WeakPtr<UserUnit>> mAvatars` at +0x1E8
(`sub_8B2500` does a literal `add ecx, 1E8h`), `mEngineers` at +0x1F8 and
`mFactories` at +0x204, both 12-byte `WeakEntitySetUserEntity`.

**Still missing for DoBeat**, bottom-up: `sub_8B2300` (avatar add, 133,
called by the UserUnit ctor), `sub_8B6C50` (140), `UserUnit::AddToSelectionSet`
(FUN_008BFF30, 133), `sub_8C06A0` (54), then `UserUnit::UpdateUnitData` (185)
and `UserUnit::UserUnit` (472) behind the bridge gate above, then DoBeat
itself. `FUN_00898DC0` is covered by `LookupEntityId`.

## Related gate

`userArmies` is deliberately **not** sized in the `CWldSession` constructor
even though the binary sizes it there, because the slots stay null until
`DoBeat` fills them and `cfunc_GetArmiesTableL` dereferences the first one.
The resize belongs in the same commit as `DoBeat`. See
[[project-session-task-stage-and-ready]].

`~SSyncData` was not safe on a live payload — the constructor never ran the
constructors of the owning lanes (they lived inside padding) while the
teardown view released them. Fixed in `0558f78`: every lane is a real member
with a member initializer now.

**Do not collapse `UserCommandQueueEntry` onto `CommandIssueObserverLink`
by including `CommandIssueHelper.h` into `UserUnitManager.h`** - that single
include crashes startup on its own. See
[[project-include-order-static-init-landmine]].


## 2026-08-13 (session 2): DoBeat is WRITTEN; one gate left

`66aef8d` landed: `CWldTerrainDecal` +0x20 was a byte named `mRuntimeActive`
but the ctor stores a **dword** there (0x0089CABB) and `AddDecals` copies
`SDecalInfo::mFidelity` into it -> now `std::int32_t mFidelity`. +0x9C
`mUnknown9C` is the owning army (`SDecalInfo::mArmy`, 0x0087899B) -> `mArmy`.

**Everything below is written and in the working tree, uncommitted:**

- `CDecalManager::AddDecals` (FUN_00878650) in `CWldSplat.cpp` + the two
  file-static helpers `ResolveDecalTexturePath` / `ApplyDecalRecordTransform`.
  The record type needed no invention: it is the existing `moho::SDecalInfo`
  (0x90, `CDecalTypes.h`) field-for-field. TU gates clean.
- `SSyncData` lanes retyped: `mAddDecals`->`vector<SDecalInfo>`,
  `mRemoveDecals`->`vector<int32>`, `mAudioRequests`->`FastVectorN<SAudioRequest,8>`,
  `mInlineScratchVectors`->`vector<SyncInlineVector>` (new
  `moho/sim/SyncInlineVector.h` = `gpg::core::FastVectorN<int32,4>`, 0x20),
  `mTerrainUpdate`/`mSimResources`/`mTickDebugCanvas`/`mBeatDebugCanvas` ->
  typed `boost::SharedPtrRaw<...>`.
- `CWldSession::mSyncInlineVectors` @0x490 added (DoBeat's only writer).
  `mUnknownShared41C` renamed `mBeatDebugCanvas`.
- `UserEntity` +0x145 was `mHasRuntimePose` (nothing read it); `OrphanEntity`
  writes 1 there at 0x008941ED -> renamed `mMarkedForDeletion`, and
  `CWldSession::OrphanEntity` was **missing that store** - fixed.
- Three cvars added to `RuntimeTuningGlobals.cpp`, values read out of the PE:
  `ren_FogOfWar=true` (0x00F57DC3=1), `dbg_Metronome=false`,
  `wld_RunWithTheWind=false` (both zero-fill .bss).
- **`CWldSession::DoBeat` written in full** (~250 lines, all 25 phases) plus
  helpers `ArmyAtIndexOrNull`, `FindCommandIssueHelper`,
  `OpenLiveWeakSetCursor`, `ReseatSharedLane`, and a
  `CWldSessionVizUpdateRuntimeView` for the +0x438 lane (it cannot share the
  orphan view: the sets are 12-byte bases 12 bytes apart).
- **`SessionFrame` rewritten faithfully**: `WLD_GetSimRate() * delta * 10`,
  `wld_RunWithTheWind` / `mReplayIsPaused` gates, the 100-beat drain calling
  `DoBeat`, the `Sync_Count` stat, the end-of-frame clamp against the
  *frame-start* tick, `UICommandGraph::CreateMeshes`, `CTaskStage::DoFrame`.
- `DoBeat` wired into `WLD_DoInitializing` before `CreateGameInterface`.
- `userArmies.resize(launchInfo->mArmyLaunchInfo.size(), nullptr)` restored in
  the ctor.

**The one remaining blocker: `UserUnit` is still abstract.**
`e481912` gave it `public IUnit, public CScriptObject` but never declared the
overrides, so `new UserUnit(...)` in DoBeat will not compile. 19 pure virtuals
are unimplemented (17 on IUnit, 2 on CScriptObject: `GetClass`,
`GetDerivedObjectRef`).

The IUnit sub-object vtable is RTTI col.offset 328, 22 slots, rebase
-0xFBC1960:

    0/1 0x0056D420 / 0x0056D410  IUnit::IsUnit (const/non-const)
    2   0x008C5D20    3   0x008C5D30    4   0x008BEF40    5   0x008BEF50
    6   0x008BEF60    7   0x008BEF70    8   0x008BEFA0    9   0x008BEFC0
    10  0x008BEFD0   11  0x008BEFE0   12  0x008C0390   13  0x008C5D40
    14  0x008BF000   15  0x008BF050   16  0x008BEF90   17  0x008BEF80
    18  0x008BF0F0   19  0x008BF0E0   20  0x008BF0D0   21  0x008BF0B0

Five already have bodies in `UserUnit.cpp` as `[[maybe_unused]]` file-static
bridge helpers taking an `IUnit*` (`IUnitBridgeCopyLuaObjectToOut` 0x008BEF60,
`IUnitBridgeCalcTransportLoadFactor` 0x008BEF80, `IUnitBridgeDestroyQueued`
0x008BEFA0, `IUnitBridgeIsNavigatorIdle` 0x008BEFC0, `IUnitBridgeIsUnitState`
0x008BF020). Convert those to real overrides and recover the rest - they are a
dense block of tiny accessors at 0x008BEF40..0x008BF0F0.

Do that, then `tucheck moho/sim/CWldSession.cpp`, then build + run and check
`Game time` moves off 00:00:00.


### CORRECTION: IUnit.h's virtual order was fine

The earlier claim in this note that `IUnit.h`'s declaration order disagreed
with the binary was WRONG, and it came from a bad rebase. The RTTI dump's slot
EAs for `UserUnit`'s secondary vtables do not rebase with the 0xFBC1960 constant
that works for the primary one - several land mid-function. **Read the vtable
out of the PE instead**, via the address the constructor stores:

    0x008BF53D  mov [ebp+148h], offset ??_7UserUnit@Moho@@6BIUnit@Moho@@@   -> 0x00E4D9AC
    0x008BF547  mov [esi],      offset ??_7UserUnit@Moho@@6BCScriptObject@..-> 0x00E4DA08

With the real slots, `IUnit`'s declaration order matches exactly. The base
`IUnit` vtable at 0x00E2A514 has `_purecall` (0x00A82547) in slots 4..21,
confirming 18 pure virtuals and 4 concrete.

## LANDED 2a03e00 - the sync queue is drained

`CWldSession::DoBeat` + `SessionFrame` + `WLD_DoInitializing` wiring, all 20
`UserUnit` overrides, `CDecalManager::AddDecals`, `CommandManager`'s ctor, the
weak-set head allocation in the session ctor, `OrphanEntity`'s missing
`mMarkedForDeletion` store, and eight `SSyncData` lane retypes. Build clean,
runs to the harness deadline with **no crash**.

## The clock STILL does not move - and now it is one function

`Sim::Sync` (**0x007474B0**, ~1130 instrs, 703 lines of decompile) is a partial
lift. Ours sets only `mCurBeat`, snapshots reserve counts and handles the army
-stats XML. It never sets `mCurTick` or `mAdvanced`, and never fills any lane -
so `DoBeat` runs every frame over an empty packet and `mGameTick` stays 0.

Real signature: `std::auto_ptr<SSyncData> Sync(const SSyncFilter&)` - returns
by value. Ours is `void Sync(const SSyncFilter&, SSyncData*&)`; fix that too.

Two things are deliberately held back in `CWldSession.cpp` until `Sim::Sync`
lands, both commented in place:
  - the Lua sync deserialize is guarded on `beat.mStream != nullptr` (the
    binary never checks - it always publishes a stream);
  - `userArmies` is NOT sized in the session ctor, because `cfunc_GetArmiesTableL`
    dereferences slot 0 and `DoBeat` has no `mNewGrids` to fill it from.
Restore both in the `Sim::Sync` commit.

### `Sim::Sync` (0x007474B0) - the full phase list, read out of the decompile

Real signature `std::auto_ptr<SSyncData> Sync(const SSyncFilter&)`; sret, so
the decompile shows it as `(SSyncFilter* that, Sim* this, SSyncData** dataPtr)`.

 1. `SSyncFilter::SSyncFilter(&mSyncfilter, that)` - copy the incoming filter,
    remembering whether `mFocusArmy` changed (call it `focusChanged`).
 2. If it changed: Lua `NoteFocusArmyChanged(oldArmy+1, newArmy+1)`, with -1
    passed through unchanged.
 3. `new SSyncData` (0x2B8), delete the caller's previous packet, store it.
 4. `SSyncData::ReserveSizes(&mSyncSizes, data)` - pre-size every lane from the
    sizes remembered at the end of the previous beat.
 5. `mCurBeat`, **`mCurTick`**, **`mAdvanced = mNeedsToSyncMaybe`**, `mFocusArmy`.
 6. `mSoundManager->GetRequests(&data->mAudioRequests)` when the manager exists.
 7. Move `mParticleBuffer` into `mPartBuff` and null the sim's side.
 8. `CDecalBuffer::SwapVectors(mDecalBuffer, &mAddDecals, &mRemoveDecals)`.
 9. Swap `mSyncCamShake` <-> `mCamShakeParams`, `mPlayableRect1` <->
    `mPlayableRectUpdates`, `syncVec1` <-> `mFollowCameras`, `syncVec3` <->
    `mVec25`, `syncVec4` <-> `mVec17`, `syncVec5` <-> `mPoseUpdates`.
10. First sync only (`!mDidSync`): reserve `mNewGrids` to the army count and
    `GetConstDat` each army into it; set `mDidSync`.
11. Every sync: reserve `mArmyUpdates` and `GetVarDat` each army.
12. If `focusChanged`: walk `mEntityDB->mAllUnits` and call **vtable +0x30** on
    every unit with the packet (full resync). Otherwise walk the
    `mUpdateEntities` intrusive list and call `Entity::Sync(data)`; the list
    node sits 12 dwords before the entity (`&n[-12]`).
13. `Sync_Entity_Count` stat = the number walked.
14. `EntityDB::Purge(mEntityDB)`; `sub_6E0F50(mCommandDB, data, focusChanged)`.
15. Lua `Sync` table: `PausedBy` / `TimeoutsRemaining` (nil when `mPausedBy` is
    -1, else +1 and the source's timeout count); `__ArmyStats` from
    `STAT_GetLuaTable` plus a `Tick` field when `mSyncArmy` is in range; the
    army-stats XML when `mRequestXMLArmyStatsSubmit`; a `Cheaters` table (1-based
    army ids plus `CheatsEnabled`) which then clears `mCheaters`.
16. `new gpg::MemBufferStream(256)` into `data->mStream`, deleting any previous;
    `SCR_ToByteStream(syncTable, data->mStream)`;
    `SCR_LuaDoString("ResetSyncTable()", mLuaState)`.
17. Swap `mDesyncs` across when non-empty; copy `mPausedBy`, `mGameOver`;
    `mFogOfWar` from army 0's recon db (`ReconGetFogOfWar`).
18. Share `mMapData->mHeightField` into `mTerrainUpdate` and `mSimResources`
    into `mSimResources`; swap `mPrintField`.
19. **The debug canvases cross over**: sim `mBeatDebugCanvas` -> packet
    `mTickDebugCanvas`, sim `mTickDebugCanvas` -> packet `mBeatDebugCanvas`,
    then the sim's tick canvas is released.
20. Checksum: every `sim_ChecksumPeriod` beats take `MD5Context::Digest` into
    `mSimHashes[mCurBeat & 0x7F]` and reset the context, else zero the slot;
    log `"beat %d final checksum: %s"`.
21. `mDidProcess = 0; ++mCurBeat; FlushLog(); mNeedsToSyncMaybe = 0;
    mGameOver = mGameEnded;` then `sub_560940(data, &mSyncSizes.mAudioRequests)`
    remembers this packet's lane sizes for the next `ReserveSizes`.

Ours currently does 3 (partly), 5 (only `mCurBeat`) and 15's XML branch. Step 5
alone is what makes `mGameTick` move.

### Where this stands (end of 2026-08-13 session 2)

`2a03e00` and `0d97c5f` are landed and the committed tree **builds and runs
clean** (skirmish to the harness deadline, no crash).

UNCOMMITTED in `Sim.cpp`: the four scalar publications (`mCurTick`,
`mAdvanced` = `mAdvancedThisTick`, `mFocusArmy` = `mSyncFilter.focusArmy`,
alongside the existing `mCurBeat`) plus the beat retirement at the end
(`++mCurBeat`, `FlushLog()`, `mAdvancedThisTick = false`,
`mGameOver = mGameEnded`). Field offsets verified: 0x8F8 beat, 0x900 tick,
0x8E5 advanced-this-tick, 0xA88 filter focus army, 0x8DC/0x8DD game-ended/over.
It compiles.

**With those in, the run crashes in `CUserSoundManager::UpdateSoundRequests`**
(CUserSoundManager.cpp:1519) reading `requests.start_[1].requestType` off a
null `start_` - so `Size()` reported >= 2 while `start_` was null. `Size()` is
`(end_ - start_)/elem`, so the audio lane got an `end_` without a `start_`.

Prime suspect: `SnapshotSyncReserveCounts` in our `Sim::Sync` - it stands in for
the binary's `SSyncData::ReserveSizes` (called at 0x00747605) and is presumably
pre-sizing the audio lane by writing the end pointer directly. Check it against
the real `ReserveSizes` before doing anything else; the lane is
`gpg::core::FastVectorN<SAudioRequest, 8>` now (0x10 head + eight 0x1C requests
= 0xF0), and the sim is supposed to fill it via
`mSoundManager->GetRequests(&data->mAudioRequests)`, which we do not call yet.

Once that is sorted, re-run and look for `tick number` lines in the log - our
`Sim::AdvanceBeat` already logs one per tick, and there were **zero** in
sk_beat6.sclog, so the sim was not advancing ticks at all yet either. That is
worth checking independently of the client side: `AdvanceBeat` only ticks when
`!mGameOver && (mPausedByCommandSource == -1 || mSingleStep)`.
