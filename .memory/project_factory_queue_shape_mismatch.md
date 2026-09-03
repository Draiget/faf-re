---
name: project-factory-queue-shape-mismatch
description: RebuildCurrentFactoryBuildQueue (UserUnit.cpp:3519) cites 0x00835DF0 but its clean-typed body doesn't match that address's raw decompile (weak-link -8 decode, category-bitset test, sub_836B90, struct_UserUnitManager::Get, sub_8B4140 filtering) - needs re-verification before UI_FactoryCommandQueueHandlerBeat is built on top of it.
metadata:
  type: project
---

Picked up [[project-factory-queue-ui-stub]]'s "single blocker: sub_836C80"
plan to un-stub `moho::UI_FactoryCommandQueueHandlerBeat()`
(`UiRuntimeTypes.cpp:25850`, still `{}`) and found the foundation under it
is shakier than that note assumes.

## Two different "current build queue" globals exist, not one

- `sCurrentFactoryBuildQueue` (`UserUnit.cpp`) - a real
  `msvc8::vector<FactoryQueueDisplayItemRuntime>` of coalesced
  `{blueprintId, count, commandId}` rows, rebuilt by
  `RebuildCurrentFactoryBuildQueue(UserUnit*)` and read by
  `BuildFactoryQueueLuaTable` (=`func_AddScriptUIBuildQueueItem`,
  0x00836080) to build the Lua display table.
- `sCurrentBuildQueue` (`UiRuntimeTypes.cpp:25733`) - a raw
  `CurrentBuildQueueRuntimeView{start,end}` pointer pair over
  `FactoryCommandQueueItemRuntimeView` elements (48-byte stride, richer -
  each item owns its own legacy `commandData` vector of queued command ids,
  per `CurrentBuildQueueItemCommands`'s doc comment). This is what
  `CompareBuildQueueSnapshotRuntime` (=sub_837750, 0x00837750,
  `[[maybe_unused]]` in `SimRecoveryRuntime.cpp:10130`) compares a snapshot
  against, and what `sub_836C80` (still unrecovered) would assign into.

These are NOT duplicates of each other - different element shape, different
role (Lua-display summary vs. legacy per-item command-id storage). The
original plan's pseudocode conflated them (`sub_835DF0(&snapshot, ...)`
writing to a stack-local `BuildQueueItem` snapshot) in a way that doesn't
match either recovered global cleanly.

## The real problem: RebuildCurrentFactoryBuildQueue may not BE 0x00835DF0

Read `decomp/recovery/disasm/fa_full_2026_03_26/FUN_00835DF0.c` directly.
Its actual shape:

    void callcnv_F3 sub_835DF0(int a1@<ebx>, int a2, int a3)
    {
      // a2 decoded via the standard weak-link "-8" trick to a UserUnit*
      // (or walked as a self-linked sentinel when a2==8)
      v6 = sWldSession->mRules->GetEntityCategory("SHOWQUEUE");
      BlueprintOrdinal = unit->GetBlueprint()->mBlueprintOrdinal;
      // tests BlueprintOrdinal against v6's category bitset before doing
      // anything else - a gate RebuildCurrentFactoryBuildQueue never checks
      v17 = unit->GetCommandQueue2(...);
      sub_836B90(&sCurrentBuildFactory, &a2);   // publish the weak owner link
      for (i in struct_UserUnitManager::Get(v17)) {
        v12 = *i;
        if (*i && (sub_8B4140(v12) == UNITCOMMAND_BuildFactory
                || sub_8B4140(v12) == UNITCOMMAND_BuildMobile
                || sub_8B4140(v12) == UNITCOMMAND_Upgrade)) { ... }
      }
    }

That is a completely different shape from the currently-recovered
`RebuildCurrentFactoryBuildQueue(UserUnit* userUnit)`
(`UserUnit.cpp:3519`), which:
  - never checks the "SHOWQUEUE" entity-category bit on the unit's
    blueprint,
  - never calls `sub_836B90`/touches `sCurrentBuildFactory` at all,
  - filters via `ResolveHelperCommandType`/`IsFactoryQueueCommandType`
    rather than the three explicit `UNITCOMMAND_BuildFactory/BuildMobile/
    Upgrade` checks via `sub_8B4140` (`= ResolveHelperCommandType`, so this
    part may be an equivalent modernization - but the category-bit gate and
    the `sCurrentBuildFactory` link publish are missing entirely, not just
    renamed).

**Do not build `UI_FactoryCommandQueueHandlerBeat` on top of
`RebuildCurrentFactoryBuildQueue` until this is resolved.** Either:
  1. `RebuildCurrentFactoryBuildQueue` is a real but INCOMPLETE recovery of
     0x00835DF0 (missing the category gate + `sCurrentBuildFactory` link
     publish) and needs a follow-up pass, or
  2. it was recovered against the wrong address entirely and the doc
     comment's `0x00835DF0` citation is wrong - check `git blame` /
     `git log -p` on that function for who added it and what evidence they
     cited, before assuming either way.

Did not chase this further - it's a distinct correctness question from the
CRenderWorldView vtable chain in flight this session ([[project-black-screen-is-renderworldview-vtable]]),
and taking on a second deep verification thread at the same time risks
rushing both. Flagging it here so the next pass through unit-queue UI work
starts from this, not from re-discovering it.

## Second pass (same session, later): `a1` is not `sCurrentFactoryBuildQueue` directly

Read the rest of `FUN_00835DF0.c` (the whole function, ~101 lines). The
per-command inner loop, once a helper passes the
`UNITCOMMAND_BuildFactory/BuildMobile/Upgrade` filter (via `sub_8B4140` =
`ResolveHelperCommandType`, confirmed matching) and resolves a non-null
blueprint pointer through `helper->mDat.mOri.w` (a `Quaternion.w` slot
reused to stash the build blueprint pointer - a real, if odd, type-pun;
not yet checked whether `RebuildCurrentFactoryBuildQueue` reproduces this
exact access path or gets the blueprint some other, cleaner way):

    if (coalesce test fails - sub_836E80(a1) || !sub_40D500(cmpBuf, &v18))
    {
      // build + append a new FactoryQueueDisplayItem-equivalent
      sub_835D50(&v19, &v18 /*blueprint id string*/, sub_8B4220(v12) /*count*/);
      sub_6E1A10(&a1a /*=helper->mDat.mCmdId*/, v20);
      sub_836EF0(a1, &v19);            // = AppendFactoryQueueDisplayItem(a1, item) - CONFIRMED, this address already recovered
    }
    // UNCONDITIONAL, every matching command regardless of new-vs-coalesced:
    *(DWORD*)(*(DWORD*)(a1+8) - 20) += sub_8B4220(v12);   // some OTHER counter, incremented every time
    a1a = v12->mDat.mCmdId;
    sub_6E1A10(&a1a, (DWORD*)(*(DWORD*)(a1+8) - 16));      // pushes the raw command id into ANOTHER lane

`sub_836EF0` is confirmed = `AppendFactoryQueueDisplayItem` (address
0x00836EF0, `UserUnit.cpp:3504`, signature
`(msvc8::vector<FactoryQueueDisplayItemRuntime>&, const
FactoryQueueDisplayItemRuntime&)`). It is called as `sub_836EF0(a1, &v19)`
- meaning **`a1` itself must be (or contain, by reference) the
destination vector**, not `sCurrentFactoryBuildQueue` read from a file-static
global the way the currently-recovered `RebuildCurrentFactoryBuildQueue`
does it.

But the two unconditional lines right after read `*(DWORD*)(a1+8) - 20` and
`- 16` as SEPARATE counters/lanes that live *before* whatever `a1+8` points
at - i.e. `a1` is not simply `&sCurrentFactoryBuildQueue`, it looks like a
pointer to a **wrapper object** that embeds the display-item vector at
`+8` with two more bookkeeping fields (a running total command count, and a
raw-command-id append lane) immediately preceding it. This wrapper is not
`CurrentBuildQueueRuntimeView` (`UiRuntimeTypes.cpp:25733`, that one is a
plain `{start,end}` pointer pair, no room for extra counters) - it's
something else, not yet identified, and not currently modelled anywhere in
`src/sdk/**`.

**This means `RebuildCurrentFactoryBuildQueue(UserUnit*)`'s current shape
(no destination-vector parameter, writes only to the global
`sCurrentFactoryBuildQueue`, no equivalent of the two extra unconditional
counter updates) is very likely an INCOMPLETE recovery, not just a
"missing category gate" issue as the first pass above found.** Two
separate real gaps now, not one:
  1. missing "SHOWQUEUE" category-bitset gate + `sCurrentBuildFactory` weak-link
     publish (first pass, above),
  2. missing wrapper-object destination + the two extra per-command counter
     updates (this pass) - and the wrapper's own type/owner is still unknown.

Next step for whoever picks this up: read `sub_836EF0`'s (0x00836EF0)
OWN raw asm/decompile to see what it actually indexes at `a1+8` internally
- does it treat `a1` as `this` of a class whose `+8` member is the vector,
or as a plain `vector*` where `+8` is itself a vector-internal field
(`_Mylast` for instance, which would flip this whole reading)? That
resolves whether "a1+8-20/-16" are sibling fields of a wrapper class or
something inside the vector's own layout that got misread. Do not assume
either without checking - this note itself is not yet fully resolved.
