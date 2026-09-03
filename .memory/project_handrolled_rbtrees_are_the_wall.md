---
name: project-handrolled-rbtrees-are-the-wall
description: "Three subsystems hand-roll per-type red-black trees instead of using msvc8::map, and that is what blocks the largest remaining closures of map emissions"
metadata:
  node_type: project
  type: project
---

Synthesised 2026-08-21 (batches 42-46) after three separate closures dead-ended
the same way. This is the single biggest structural blocker left in the
container work, and it is one problem wearing three hats.

## The shape

A subsystem models its map as a bare header plus hand-written node helpers,
instead of using `msvc8::map` / `RbTree.h`. The emitted tree bodies in the
binary -- insert, hinted insert, erase-with-rebalance, the two rotates -- then
have **no source-level home**, because nothing instantiates the real container.
Citing them would be paperwork: the linker keeps none of it.

| subsystem | file | hand-rolled surface | blocked closure |
|---|---|---|---|
| ~~game rules~~ **DONE 18210e05** | `moho/sim/RRuleGameRules.cpp` | `RRuleGameRulesBlueprintMap` = bare `{proxy, head, size}`; `DestroyBlueprintObjectsFromMap` walks nodes by hand | 18 fns / ~2350 instr under `0x00529700`, see [[project-rrulegamerules-blueprint-map-migration]] |
| ~~animation~~ **DONE 3634c87c** | `moho/animation/CAniSkel.cpp` | (was) `AniSkeletonVisitedBoneNodeLanes` + a fabricated static-init "bootstrap" -- deleted outright, not migrated | 5 fns under `0x007B22B0`, see [[project-ani-dumpskeleton-partial-root]] |
| ~~army stats~~ **DONE c6805783 + 1f3038d7** | `moho/sim/CArmyStats.cpp` | `FindOrInsertBlueprintStatNode` open-codes the descent, node build and linking; `RotateBlueprintLeft` / `RotateBlueprintRight` are per-type rotate helpers | `FUN_0070F6C0` (116, VC8's hinted `insert(iterator, const value_type&)` -- the three-way empty / hint==begin / hint==end check falling back to the general insert) |

Each node layout is *already correct and static_asserted*; the offsets match
the disassembly exactly. **There is no layout research left in any of the
three** -- the work is type migration, which is why these keep surfacing as
"landable" and keep not landing.

## Why it matters more than the individual tokens

The same handful of VC8 members (`_Insert`, hinted `insert`, `erase` with
rebalance, `_Lrotate`, `_Rrotate`, `_Buynode`) is emitted once per
instantiation. Every hand-rolled tree strands a full set. Migrating one
subsystem to `msvc8::map` lands its whole closure at once and makes the next
one cheaper, because `RbTree.h` accumulates the citations.

`RbTree.h` was leased for many batches and is **now free** -- that lease is
what deferred this work originally.

## Status: seven of seven known instances done, 100+ addresses landed

  - **CArmyStats** -- both trees migrated (c6805783 blueprint-stat, 1f3038d7
    name-index, which also fixed a 0x10-vs-0x0C header layout error). 21
    addresses.
  - **RRuleGameRules** -- landed 18210e05, 49 addresses, 962 lines removed.
    See [[project-rrulegamerules-blueprint-map-migration]] for the ordering
    trick that made it work after two reverts.
  - **CAniSkel** -- **DONE 3634c87c**, verified 2026-09-02 (session
    claude-anidumpskeleton-verify). Not actually a migration in the same
    sense as the other four: the "hand-rolled" `AniSkeletonVisitedBoneNodeLanes`
    was never a working implementation (its own doc block admitted the
    rotation/insertion logic wasn't written), so the fix deleted it outright
    and rewrote `Moho::ANI_DumpSkeleton` to build its dedup structure as a
    real `msvc8::map<uint32_t, msvc8::set<uint32_t>>` from the start. All
    five tokens (`FUN_007B22B0`/`FUN_007B2B30`/`FUN_007B3590`/`FUN_007B3610`/
    `FUN_007B46A0`) independently register-traced against `RbTree.h`'s
    canonical `insert_at`/`link_and_rebalance`/`rotate_left`/`rotate_right`/
    `erase_node` this pass -- all matched branch-for-branch, no bug found.
    Fixed two citation gaps (a genuinely uncited `FUN_007B2B30` emission, and
    a wrong-file claim on the `FUN_007B3590`/`FUN_007B3610` ICF-twin notes)
    in commit `486a0102`. Full trail:
    `.memory/project_ani_dumpskeleton_partial_root.md`.
  - **CDecalManager** (`moho/terrain/splat/CWldSplat.cpp`) -- **DONE
    e6efef00** (2026-09-02, session faf-main-f7). Two trees
    (`msvc8::map<uint32_t, CWldTerrainDecal*>` /
    `msvc8::map<uint32_t, CDecalGroup*>`) migrated off a hand-rolled
    `DecalGroupLookupTree`/17 free functions, ~30 addresses cited across
    `RbTree.h`/`Map.h`. Found the SAME class of bug this pattern keeps
    hiding: the hand-rolled insert had no rebalance step at all (real binary
    delegates to a genuine hinted-insert dispatcher that does full
    rotate/recolor). Also found a value-type misnomer (mapped type was
    `int32_t` "group index", really the decal/group pointer) and a 4-byte
    layout error (forgot `msvc8::vector<T>`'s default `HasDebugProxy=true`
    proxy word, same class as [[feedback_bespoke_buffer_is_real_container_pattern]]).
    Full trail: `.memory/project_cdecalmanager_lookup_tree_msvc8_map_migration.md`.
  - **AudioMap1** (`moho/audio/AudioEngine.cpp`/`.h`, `AudioMap1CategoryNode`)
    -- **DONE `2817eef2`** (2026-09-02, same session as the diagnosis and the
    CDecalManager migration). Migrated `AudioEngineImpl::mMap1` (renamed
    `mPausedCategoryNames`) to a real `msvc8::set<msvc8::string>` member.
    Re-register-traced the diagnosis from scratch rather than trusting it:
    confirmed `FUN_004DB600` (`InsertPausedCategoryName`) is genuinely
    `insert_unique` (single-comparator descent, leftmost fast path,
    `rb_decrement` predecessor check, tail-calls `insert_at` either way),
    and `FUN_004DBE30` is genuinely `insert_at` -- its `max_size()-1` guard
    constant (`0x9249248`) is exactly `0xFFFFFFFF/sizeof(msvc8::string)`,
    independently confirming `value_type == msvc8::string` (a **set**, not a
    map -- the node has no separate mapped value). The insert side's missing
    rebalance was real and exactly as diagnosed: `InsertPausedCategoryName`'s
    recovered body built and linked nodes directly, never reaching
    `insert_at`/`link_and_rebalance` at all. Deleted the full hand-rolled
    surface (~30 free functions) and rewired `AudioEngine::SetPaused`/
    `GetPaused` through the real container's `insert`/`erase`/`count`.
    ~20 addresses register-traced and cited across `RbTree.h` (`insert_unique`,
    `insert_at`, both rotates, `buy_node`, two `alloc_raw` shapes, `rb_min`/
    `rb_max`, `rb_increment`/`rb_decrement`, `erase_node`, `erase_range`,
    `erase(key)`, `lower_bound_node`/`upper_bound_node`, `destroy_subtree`,
    three `~rb_tree()` emissions).

    Found a SECOND, independent bug beyond the diagnosed one while tracing
    `~AudioEngineImpl` (`FUN_004DA2A0`): the real binary tears down `mMap2`
    before `mMap1` (true reverse-declaration order -- `mMap2` is declared
    after `mPausedCategoryNames`), but the previously-recovered destructor
    called `ResetMap1(mMap1)` *before* `ResetCategoryMap(mMap2)` -- backwards.
    Making `mPausedCategoryNames` a real typed member fixes this for free:
    its destructor now runs implicitly at the true end of `~AudioEngineImpl`,
    after the explicit `mMap2` teardown that stays hand-written (`mMap2`
    itself is not yet migrated -- see below).

    Also found a THIRD, independent instance of the exact same missing-
    rebalance bug class one level over: `AudioEngineImpl::mMap2`
    (`AudioCategoryVolumeNode`, `uint16_t category -> float volume`) is
    *also* a hand-rolled tree backing the SAME `AudioMapStorage` struct, and
    its insert path (`FindOrInsertCategoryVolumeNode`, `AudioEngine.cpp`)
    has zero rebalancing calls even though standalone `RotateCategoryVolumeNodeLeft`/
    `Right` free functions already exist in the same file and ARE correctly
    called from the erase-fixup path -- exactly mirroring `AudioMap1`'s own
    shape before this fix. **Not migrated in this pass** (out of the assigned
    scope, flagged here as the next instance in this family). **DONE,
    see below -- and the diagnosis in this paragraph needed a real
    correction, not just a migration.** Full trail:
    `.memory/project_audiomap1_missing_rebalance_bug.md`.
  - **AudioMap2 / `AudioCategoryVolumeNode`** (`moho/audio/AudioEngine.cpp`/
    `.h`, `AudioEngineImpl::mMap2`) -- **DONE `fd2ff48f`** (2026-09-02, same
    session as the AudioMap1 fix, follow-up pass). Migrated
    `AudioEngineImpl::mMap2` (renamed `mCategoryVolumes`) to a real
    `msvc8::map<std::uint16_t, float>` member, per this file's own tracking
    as the seventh and (per the original-diagnosis-writing agent's own
    tracking) final known hand-rolled-tree instance.

    Re-register-traced from scratch per this project's standing distrust-
    but-verify culture, rather than trusting either the task brief or the
    "Next instance found" paragraph above (both of which had propagated the
    same unverified claim forward). **The diagnosis needed a real
    correction**: `FUN_004DC080` -- the address the deleted
    `FindOrInsertCategoryVolumeNode` claimed, and the address the
    forward-flagging note above and the `insert_unique` citation in
    `RbTree.h` both cited as "no rebalancing at all" -- is actually
    `RbTree.h`'s own `insert_hint` (the genuine VC8 hinted-`insert(iterator,
    value)` dispatcher, same family as `FUN_0070F6C0`/CArmyStats), and it
    **does** fully rebalance, through `insert_at`/`insert_unique`
    underneath it. Branch-for-branch register trace against `insert_hint`'s
    existing C++ body (leftmost/rightmost/predecessor-straddle/successor-
    straddle/fallback) matched exactly, including a compiler tail-merge
    quirk (two branches jump into the middle of a third branch's shared
    `push key; push node; push 1; push out; call insert_at` argument
    sequence rather than duplicating it) that took real register-level work
    to untangle. The `max_size()-1` guard constant independently confirmed
    `value_type == std::pair<const uint16_t, float>` (`0x1FFFFFFE ==
    0xFFFFFFFF/8 - 1`), the same style of independent confirmation
    AudioMap1's `insert_at` guard constant gave for `msvc8::string`.

    So the real bug was not "the binary's insert path skips rebalancing" --
    it was that the **previously-recovered `FindOrInsertCategoryVolumeNode`
    was never actually a body of the address it claimed at all**: a plain,
    unhinted root-to-leaf BST descent with no hint parameter, no
    leftmost/rightmost/straddle branches, and no call to `insert_at`/
    `insert_unique` of any kind -- fabricated scaffolding that happened to
    look plausible, not a decompile of `0x004DC080`. This is the same
    "recovered code that looks complete is a standing false signal" lesson
    the "Pattern confirmed" paragraph above already states, but the
    mechanism is a new variant worth recording: **a wrong address citation
    can manufacture a fake instance of this bug class**, distinct from the
    four confirmed cases where the real binary's algorithm genuinely
    skipped rebalancing. Always check that the claimed function's own body
    shape (parameter count, branch structure) matches the cited address's
    real disassembly before trusting *any* characterization of what that
    address does -- "the insert path has no rebalancing calls" needs the
    same skepticism as "the insert path looks complete."

    Also found two smaller fidelity gaps while tracing the real callers:
    `AudioEngine::GetVolume` (`FUN_004D9E50`) is not a pure read in the real
    binary -- it calls the same `FindOrInsertCategoryVolume` helper
    `SetVolume` does, so querying a category for the first time silently
    persists a defaulted `1.0f` entry; the previous recovery used a
    read-only `FindCategoryVolume` that never mutated the map. And
    `destroy_subtree`'s previous free-function duplicate
    (`DestroyCategoryMapSubtree`) used a fully dual-recursive shape where
    the real binary (and `RbTree.h`'s own `destroy_subtree`) uses the
    iterative-left-spine/recurse-right form -- output-equivalent, not what
    the compiler emitted, same divergence class as `AudioMap1`'s own
    `DestroyMap1Subtree` had.

    Deleted the entire hand-rolled surface (node struct, both rotates,
    insert/erase/find, iterator step helpers, subtree teardown, map
    init/reset free functions) plus twelve genuinely orphaned pointer-lane
    helpers with zero incoming xrefs of any kind in the real binary
    (confirmed via the callgraph index, not just "no caller found in this
    file" -- `0x004DC250`/`0x004DC260`/`0x004DC2A0`/`0x004DC320`/
    `0x004DC340`/`0x004DC380`/`0x004DC760`/`0x004DC770`/`0x004DC7E0`/
    `0x004DC7F0`/`0x004DC830`/`0x004DCDC0`, marked `skip`), plus a
    thirteenth orphan (`FUN_004DDBA0`) that the fabricated recovery had
    wired into `buy_node`'s allocation chain even though the real `buy_node`
    emission (`FUN_004DD8F0`) calls the checked allocator directly and never
    reaches `FUN_004DDBA0` at all. ~17 real addresses register-traced and
    cited across `RbTree.h`: `insert_hint`, `insert_at`, `insert_unique`,
    both rotates, `rb_increment`/`rb_decrement`, `rb_min`/`rb_max`,
    `buy_node`, `destroy_subtree`, two `alloc_raw` shapes, `erase_node`,
    `erase_range`, and two `~rb_tree()` emissions (one EH-unwind-only,
    reached only from the constructor's and destructor's own SEH funclets;
    one a genuine zero-caller duplicate). Also corrected a stale
    forward-reference note the AudioMap1 pass had left in `insert_unique`'s
    own citation block, which had misattributed this instantiation to
    `Unit::ArmorMultipliers`.

    Left one item explicitly open rather than asserted: `buy_head`'s
    alloc-raw half (`FUN_004DD8B0`) has four real callers per the callgraph
    index -- the confirmed `AudioEngineImpl` constructor, plus three
    addresses (`0x004DB7B0`/`0x004DC040`/`0x004DCF60`) that land in
    untokenized gaps between IDA-recognised functions rather than at a
    function start of their own. Consistent in shape with additional
    inlined `buy_head()` bootstraps for the same instantiation reached from
    different construction contexts, but not confirmed -- flagged in
    `RbTree.h`'s `alloc_raw` citation as a deferred item, not a blocker
    (`msvc8::map`'s own default constructor already reproduces the one call
    path this recovery needs regardless of how many bootstrap copies the
    real compiler emitted elsewhere). Worth a dedicated untokenized-gap pass
    if anyone picks this file back up, following the technique in
    `.memory/project_wildmagic_untokenized_gap_technique_2026_08_26.md` /
    `.memory/project_zlib_untokenized_gap_technique_2026_08_26.md`.

    `tucheck` clean on `AudioEngine.cpp` plus `CWldSplat.cpp`/`CAniSkel.cpp`
    as unrelated-consumer sanity checks against the `RbTree.h` edit, same
    verification pattern as the AudioMap1 pass.

**Pattern confirmed 4-for-4 on in-place migrations of a working (if wrong)
hand-rolled tree finding a real bug, plus a 5th confirmed-but-different-
mechanism instance**: CArmyStats' name-index tree had a layout error;
CDecalManager's insert had no rebalance; AudioMap1's insert had no rebalance;
AudioMap2's insert genuinely had no rebalance too, but not because the real
binary's insert path skips it -- because the previously-recovered function
was never actually a body of the address it claimed, so it never reached the
real (fully-rebalancing) `insert_hint`/`insert_at` at all. **CAniSkel is the
outlier and does NOT continue the streak** -- but it isn't a counterexample
either, because it wasn't the same kind of migration. Its hand-rolled struct
was never a working implementation to migrate (the doc block openly admitted
the rebalance logic was unwritten); the fix deleted it and recovered
straight from the real container, so there was no wrong algorithm for a bug
to hide in. Read the streak as: **every migration that started from bespoke
code someone believed already worked has hidden a real defect, though not
always the exact defect the existing diagnosis named.** Treat "the recovered
`.c`/notes for a hand-rolled tree in this codebase look complete" AND "this
address definitely has no rebalancing calls" as standing false signals --
always register-trace the real address, and check that its own body shape
actually matches what is claimed about it, before trusting an existing
hand-rolled recovery of one of these, even one already marked `recovered`.

All seven known instances of this pattern are now migrated. If an eighth
surfaces, document it here the same way rather than assuming the family is
closed.

## Original order (kept for reference)

1. **CArmyStats** -- smallest surface, one map, rotates already isolated as
   named helpers so the migration is mostly deleting them.
2. **RRuleGameRules** -- largest payoff (18 fns) but 217 references across 4
   files, two frequently leased. Take file leases first.
3. **CAniSkel** -- needs `ANI_DumpSkeleton` (212 instr) recovered first
   anyway, and carries the fabricated bootstrap that must be deleted in the
   same pass. **DONE, see Status above** -- landed as a from-scratch
   `msvc8::map`/`msvc8::set` recovery rather than an in-place migration.

Do not cite any of these emissions before the owning subsystem uses the real
container.
