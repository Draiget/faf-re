---
name: project_sim_sync_partial_lift_hid_every_unit
description: CORRECTED. Sim::Sync's army publication and Entity::Sync walk were ALREADY recovered by a concurrent session (fefcc20d) before I touched it - I duplicated them and had to revert (9388960f). What was genuinely missing was the six tail lanes. Keeps the offset table, which is solid, and the truncated-grep lesson that caused the duplication.
metadata:
  type: project
---

## READ THIS FIRST - the headline claim was wrong

I concluded that `Sim::Sync` never published army data and never ran the
per-entity `Entity::Sync` walk, and that this was why no unit reached the
client. **It was already doing both.** A concurrent session had committed that
work (`fefcc20d` and neighbours) before I started, further down the same
function. My `b24f0bdb` added a second copy of it and `8140ce59` added a second
`CEntityDb::Purge()`; both reverted in `9388960f`.

The duplication was not harmless: `Entity::Sync` was being dispatched twice per
beat per entity, and the focus-army-changed arm walks `mEntityDB->mAllUnits`
unconditionally, so every unit would have been published twice into
`mNewEntities` / `mUnitUpdates` on that path.

**Cause of the mistake, and the rule that follows from it:** I checked for an
existing implementation with

    grep -n "mArmyUpdates|mNewGrids|CopyArmy...|mCoordEntities" Sim.cpp | head -20

and read the empty tail as proof of absence. The existing block starts at line
**8668**, well past where `head -20` stopped. **An empty tail in a truncated
listing is not absence.** Run `grep -c` first, or drop the `head`. This is the
second time this exact failure has cost real work - see
[[project_issue_setcommandtarget_next_target]], where the same truncation had me
plan a 141-line recovery of a function that was already fully recovered.

**Also:** another session commits into `Sim.cpp` concurrently. Before adding a
call there, run `git log -S "<exact call>" -- src/sdk/moho/sim/Sim.cpp`.

## What WAS genuinely missing, and landed

## The four tail swaps, fully resolved from the disassembly

The packet lanes are handed over by **swapping** the vectors, not copying, so the
sim comes back owning the previous packet's storage. MSVC inlined
`std::vector::swap`, which is why the decompile shows three pointer exchanges
each. Every offset below is read off `FUN_007474B0.asm` (`_Myfirst` is base+4):

| addr | Sim member | -> | SSyncData target | commit |
|---|---|---|---|---|
| `0x00747693` | `mParticleBuffer` `+0x0994` | -> | `mParticleBuffer` `+0x1C8` (handover, not swap) | `a965d68b` |
| `0x007476EF` | `mDecalBuffer` `+0x099C` | -> | `mAddDecals` / `mRemoveDecals` via `CDecalBuffer::SwapVectors` | `a965d68b` |
| `0x007479C6` | `mSyncSerializeGroup0` `+0x09B8` | -> | `mFollowCameras` `+0x200` | `8140ce59` |
| `0x00747A16` | `mSyncSerializeGroup2` `+0x0A28` | -> | `mSyncExtraUnitData` `+0x294` | `053e814f` |
| `0x00747A60` | `mAllyUpgradeNotifications` `+0x09D8` | -> | `+0x210` | `dbcb18e1` |
| `0x00747AAA` | `mPendingPoseCopies` `+0x09E8` | -> | `mPoseUpdates` `+0x220` | `dbcb18e1` |

All six were genuinely absent (each verified to appear exactly once afterwards).
Two of them, `CDecalBuffer::SwapVectors` (`0x00779BB0`) and
`CCommandDb::PublishSyncData` (`0x006E0F50`), were **fully recovered functions
with no caller anywhere in the tree** -- `Sim::Sync` is their only caller in the
binary. `PublishSyncData` had already been wired by the other session.

### Two duplicate-layout defects the swaps exposed

A three-pointer vector swap is only well-formed between identical types, so the
binary swapping A into B is *proof* that A and B are one type. That settled two
long-standing mismodellings:

- `SPendingPoseCopy` (`Sim.h`) and `SEntityPoseUpdateEntry` (`SimDriver.h`) were
  byte-identical declarations of one struct -- `{ EntId; boost::shared_ptr<CAniPose> }`,
  `sizeof 0x0C`. `SimDriver.h` now owns it, `Sim.h` aliases it.
- `SSyncData+0x210`, declared `msvc8::vector<std::byte> mAuxiliaryVector17` and
  described as "untouched by `CWldSession::DoBeat`", is the allied-upgrade lane.
- Separately, `mRemoveDecals` signedness: the value is `std::uint32_t` at its
  source (`SDecalInfo::mObj` `+0x84`) and at every producer, so the two
  consumer-side `std::int32_t` declarations were the mistyped ones.

## Verify addresses against the .asm, never the .c

My first two commits here cited addresses taken from **line positions in the
decompiler output**, which are not instruction addresses at all -- `0x007476AA`
for a block that really begins at `0x0074785E`. Corrected in `a3500def`.
Cross-check every citation against a field offset already asserted in the
headers: `mArmiesList` at `Sim+0x090C` means `[ebx+910h]` is its `_Myfirst`,
`mEntityDB` at `+0x0984` means `[ebx+984h]`, and `add esi, 160h` is
`sizeof(SSTIArmyVariableData)`.

## Still open in this function

`mCamShakeParams` (its source `mSyncCamShake` is not a `Sim` member in our model
-- it is reached through a `SimCameraShakeQueueRuntimeView` reach-in at `+0x04`,
itself a RULE ONE violation to unpick), the `mPlayableRectUpdates` swap (source
member not yet mapped), `mStream`, `mRequestXMLArmyStatsSubmit`, `mPrintField`,
and the `mTickDebugCanvas` / `mBeatDebugCanvas` pair. `mDesyncs`, `mPausedBy`,
`mGameOver`, `mFogOfWar`, `mTerrainUpdate` and `mSimResources` are all already
done by the other session.

Related: [[project_scriptmodule_never_populated_prop_throw_storm]],
[[reference_retail_engine_ab_oracle]].
