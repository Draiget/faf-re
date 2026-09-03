---
name: project_audiomap1_missing_rebalance_bug
description: "RESOLVED 2026-09-02, commit 2817eef2. AudioEngineImpl::mMap1 (renamed mPausedCategoryNames) migrated from a hand-rolled AudioMap1CategoryNode tree to a real msvc8::set<msvc8::string>, fixing the diagnosed missing-rebalance bug on insert. Full worked trail below kept for reference; see .memory/project_handrolled_rbtrees_are_the_wall.md for the up-to-date cross-instance status. The sibling AudioEngineImpl::mMap2 bug flagged below is ALSO now RESOLVED, commit fd2ff48f -- see that file's own entry for the corrected diagnosis (the real bug was a wrong address citation, not a real-binary missing-rebalance path)."
metadata:
  type: project
---

## RESOLVED 2026-09-02 (commit `2817eef2`, same session as the diagnosis below)

Migrated `AudioEngineImpl::mMap1` (renamed `mPausedCategoryNames`) to a real
`msvc8::set<msvc8::string>` member, following the `CDecalManager` precedent
this doc's own "what's needed" section pointed at. Before writing any code,
re-register-traced the diagnosis below from scratch rather than trusting it
(per this project's own standing distrust-but-verify culture) and confirmed
it exactly: `FUN_004DB600` (`InsertPausedCategoryName`) is genuinely
`insert_unique`, `FUN_004DBE30` is genuinely `insert_at` (confirmed
independently via its `max_size()-1` guard constant, which is exactly
`0xFFFFFFFF/sizeof(msvc8::string)` -- proof `value_type == msvc8::string`,
i.e. this is a **set**, not a map: the node carries no separate mapped
value), and the recovered `InsertPausedCategoryName` never called
`insert_at` at all -- it built and linked nodes itself with no
rotation/recolor step, exactly as diagnosed.

Deleted the entire hand-rolled surface identified in "What's needed" below
(~30 free functions across construct/insert/erase/find/iterate/reset) and
rewired `AudioEngine::SetPaused`/`GetPaused` through the real container's
`insert`/`erase`/`count`. ~20 addresses register-traced and cited across
`RbTree.h`: `insert_unique` (0x004DB600), `insert_at` (0x004DBE30), both
rotates (0x004DCBE0/0x004DCC40), `buy_node` (0x004DCC90), two `alloc_raw`
shapes (0x004DE060/0x004DD460), `rb_min`/`rb_max` (0x004DD3F0/0x004DD3D0),
`rb_increment`/`rb_decrement` (0x004DDD30/0x004DD950), `erase_node`
(0x004DC850), `erase_range` (0x004DBD30), `erase(key)` (0x004DB710),
`lower_bound_node`/`upper_bound_node` (0x004DD380/0x004DD410),
`destroy_subtree` (0x004DD320), and three `~rb_tree()` emissions
(0x004DA220/0x004DB5D0/0x004DBFF0).

**A second, independent bug found in the process** (beyond the diagnosed
one): `~AudioEngineImpl` (`FUN_004DA2A0`)'s real instruction stream tears
down `mMap2` before `mMap1` (true reverse-declaration order), but the
previously-recovered destructor called `ResetMap1(mMap1)` *before*
`ResetCategoryMap(mMap2)` -- backwards. Making `mPausedCategoryNames` a real
typed member fixes this for free: its destructor now runs implicitly at the
true end of `~AudioEngineImpl`, after the explicit `mMap2` teardown.

**A third bug/gap found, NOT fixed in this pass -- RESOLVED 2026-09-02,
commit `fd2ff48f`, follow-up session**: `AudioEngineImpl::mMap2`
(`AudioCategoryVolumeNode`, a `uint16_t category -> float volume` tree
backing the SAME `AudioMapStorage` struct) showed the identical missing-
rebalance *shape* on its own insert path (`FindOrInsertCategoryVolumeNode`,
claiming `FUN_004DC080`) -- rotates existed in the file and were correctly
wired on the erase side, but insert never called them. Migrated to a real
`msvc8::map<std::uint16_t, float>` member (renamed `mCategoryVolumes`),
following this exact precedent as the template.

**The diagnosis above turned out to need a correction, not just a repeat of
this fix.** Re-register-tracing `FUN_004DC080` from scratch (rather than
trusting this paragraph) found it is not a plain unhinted insert at all --
it is the genuine VC8 hinted-`insert(iterator, value)` dispatcher
(`insert_hint` in `RbTree.h`), which fully rebalances through
`insert_at`/`insert_unique` underneath it, confirmed branch-for-branch
against `RbTree.h`'s existing `insert_hint` body. The real bug was that the
previously-recovered `FindOrInsertCategoryVolumeNode` was never actually a
body of `0x004DC080` at all -- a fabricated, plausible-looking plain BST
descent with no hint parameter, wrongly cited on that address. Same
end-state fix (migrate to the real container), different root cause than
this paragraph originally described. Full trail:
`.memory/project_handrolled_rbtrees_are_the_wall.md`'s `AudioMap2` entry.
This is a new, seventh (and, per that file's own tracking, final known)
instance of the whole-project pattern documented in
`.memory/project_handrolled_rbtrees_are_the_wall.md`.

Also confirmed a shape divergence unrelated to correctness: the real
`erase_node` emission (`FUN_004DC850`) uses the "lift the in-order successor
into the erased slot" surgery directly inline (no generic transplant
helper), where the previously-recovered `ErasePausedCategoryNodeAndStoreNext`
used an explicit `TransplantPausedCategoryNode` helper modelled on the CLRS
textbook `TRANSPLANT` subroutine -- both are correct red-black deletions,
but only the inline-lift shape is what the compiler actually emitted. Now
moot: that function is deleted and `RbTree.h`'s own `erase_node` (which
already used the correct inline-lift shape) is the recovery.

`tucheck` clean on `AudioEngine.cpp` plus two unrelated consumers of
`RbTree.h`/`Map.h`/`Set.h` (`CWldSplat.cpp`, `CAniSkel.cpp`) as a sanity
check that the new `rb_tree<Traits>::count()` member (added in this pass --
see below) didn't disturb anything else; grepped the whole `src/sdk` tree
and confirmed `mPausedCategoryNames.count()` is the *only* call site of
`.count()` on any `msvc8::map`/`msvc8::set` anywhere, so that change carries
zero risk to other translation units.

### Bonus fix: `rb_tree<Traits>` never had a real `count()`

While citing `FUN_004DB770` (the real address `CountPausedCategoryMatches`
claimed), confirmed it is a genuine `equal_range`-based counting loop --
matching classic Dinkumware `_Tree::count(key)` -- not the `find(k) != end()
? 1u : 0u` shortcut `Map.h`/`Set.h`'s `count()` wrappers previously used.
Numerically identical for these unique-key containers, but not what the
binary actually runs. Added a real `count()` member to `rb_tree<Traits>` in
`RbTree.h` (equal_range + `rb_increment` counting loop, no `erase_range`
tail call) and pointed both wrappers at it, mirroring the precedent
`erase(const key_type&)`'s own citation already documented for this exact
"map/set share one real shape, existing wrapper had a hand-rolled shortcut"
pattern.

## Original diagnosis (kept for reference; fully confirmed and acted on above)

## How this was found

While auditing the ~3,558 still-open "recovered status but no source_paths"
tokens ([[project_null_srcpath_bulk_audit_2026_09_02]]), sampled
`FUN_004DBE30` (empty note, `last_worker=codex-main-batch-20260417f-throw`).
Its raw `.asm` (0x004DBE30-0x004DBFDC, ~460 bytes) is a real
`msvc8::map<K,V>::insert`-shaped body: a `"map/set<T> too long"` max_size
guard at the top, then real red-black rotation/rebalance logic (color-bit
writes at `+0x28`, calls to `sub_4DCC90`/`sub_4DCBE0`/`sub_4DCC40`).

Its confirmed caller (`fa-find-callers`) is `FUN_004DB600` = the ALREADY
`recovered` `InsertPausedCategoryName` in `src/sdk/moho/audio/AudioEngine.cpp`
(~line 2380), operating on `AudioMap1CategoryNode`/`AudioMapStorage` (a
bespoke typed RB-tree model for a "paused audio category" set, keyed by
category name string).

## The actual gap

`sub_4DCC90` is independently confirmed (already cited, `AudioEngine.cpp`
~line 1762) as `ConstructPausedCategoryNode` — and `FUN_004DBE30` calls it as
part of its own body. So `FUN_004DBE30` is essentially "construct the node,
link it in, THEN rebalance" — the full real insert operation.

But `InsertPausedCategoryName`'s CURRENT recovered body (read directly,
lines 2380-2430) does: walk the tree by string comparison, call
`ConstructPausedCategoryNode` directly itself, link the new node in with
plain `parent->mLeft/mRight = inserted`, bump `map.mSize`, call
`RefreshMap1Bounds(head)` (a bounds/min-max-pointer fixup, not a rebalance —
needs independent confirmation of what it actually does), and return. **No
rotation, no recolor, no rebalance step at all.** `FUN_004DBE30`'s own
address is not cited anywhere in `src/sdk` (confirmed via full-tree grep).

This means the CURRENT recovered code models a plain (unbalanced) BST
insert, not the real self-balancing RB-tree the binary implements. Not a
crash bug — a behavioral/complexity fidelity gap: with enough distinct
paused-category names inserted without ever rebalancing, tree operations
degrade toward O(n) instead of staying O(log n), and the tree SHAPE itself
would diverge from what the real binary produces (irrelevant for gameplay
correctness here almost certainly, but still a real fidelity gap per this
project's own contract).

## UPDATE 2026-09-02 (same session, later): fully traced, fix attempt blocked by the guard — correctly

Did the full register-trace steps 1-2 below myself. Both confirmed with high
confidence:

- **`sub_4DCBE0` = rotate_left, `sub_4DCC40` = rotate_right**, verified TWO
  independent ways: (a) each function's own body matches CLRS
  LEFT-ROTATE/RIGHT-ROTATE exactly (pivot on x's right/left child, swap
  subtree, three-way transplant checking `head->mParent`/parent's
  left/right slot), and (b) `FUN_004DBE30`'s fixup loop calls them at
  EXACTLY the two call sites `RbTree.h`'s own `link_and_rebalance` member
  calls `rotate_left`/`rotate_right` — traced `FUN_004DBE30` instruction-by-
  instruction against `link_and_rebalance`'s C++ body (`RbTree.h:7223-7284`)
  and they match line for line (uncle-red recolor branch, uncle-black
  rotate+recolor branch, both mirrored halves, final `root()->color=black`).
- **`AudioMap1CategoryNode`'s layout is byte-identical to `rb_tree<Traits>`'s
  canonical node shape**: `left@0x00, parent@0x04, right@0x08,
  value@0x0C, color@0x28, isNil@0x29` — and `0x0C + sizeof(msvc8::string,
  0x1C) = 0x28` lands the color byte exactly where the asm reads it. This
  is a `msvc8::set<msvc8::string>`-shaped instantiation of the SAME
  canonical `rb_tree<Traits>` template already used throughout `RbTree.h`
  for many other `K`/`V` combinations, just never identified as one.

Attempted the direct fix: two small, domain-specifically-named helper
functions (`RotatePausedCategoryTreeLeft`/`Right`) replicating the rotation
bodies, called from a corrected `InsertPausedCategoryName` with the full
fixup loop added. **`container_lane_guard.py` correctly denied this** —
despite the domain-specific naming, two rotate-around-a-node functions
duplicating `rb_tree<Traits>::rotate_left`/`rotate_right`'s logic ARE
exactly the "per-type container operation" RULE ONE forbids. This is
correct: the guard caught a real instance of the exact mistake the palette
buffer investigation ([[feedback_bespoke_buffer_is_real_container_pattern]])
already taught — a "bespoke-looking" type that's actually a canonical
container instantiation needs the FIX to go through the canonical
container, not a hand-copy of its algorithm under a friendlier name.

**Not done, deliberately, given the scope**: `rotate_left`/`rotate_right`
are private members of `rb_tree<Traits>` — using them requires either making
`AudioMapStorage` literally a `rb_tree<Traits>` instantiation (like
`MeshShaderPaletteBuffer` became `msvc8::vector<SkinPaletteEntry>`), or
finding another sanctioned access path. A full migration would touch every
function in `AudioEngine.cpp` that operates on this tree — construct
(`InitMap1Head`), insert (this function), erase
(`ErasePausedCategoryNodeAndStoreNext`), iterate/collect
(`CollectRetainedPausedCategoryNames`), and whatever else references
`AudioMap1CategoryNode`/`AudioMapStorage` by name — a genuinely large,
multi-function refactor, not a quick fix, and riskier to rush than the
palette buffer was (more call sites, less margin for a mistake in
red-black tree invariants to go unnoticed).

## What's needed to actually land the fix (next session — this is now fully scoped, just not executed)

1. Enumerate every function touching `AudioMap1CategoryNode*`/
   `moho::AudioMapStorage&` in `AudioEngine.cpp` (grep both type names) —
   this is the full migration surface.
2. Decide: make `AudioMapStorage` genuinely wrap/derive from
   `msvc8::rb_tree<Traits>` for `Traits::value_type = msvc8::string`
   (cleanest, matches the palette-buffer precedent), or find whatever
   narrower sanctioned mechanism the container homes use elsewhere for
   "give one specific external caller access to `rotate_left`/`rotate_right`
   for a confirmed-matching instantiation" (check whether `RbTree.h` already
   exposes anything like this for a similar case before inventing one).
3. Add the `Address:` citations for `FUN_004DCBE0`/`FUN_004DCC40` on
   `rotate_left`/`rotate_right` and `FUN_004DBE30` on `link_and_rebalance`
   in `RbTree.h`, matching this file's own extensive existing multi-address
   citation style (see the many examples already in that file for the
   pattern to follow).
4. Rewrite `InsertPausedCategoryName` (and likely `InitMap1Head`,
   `ErasePausedCategoryNodeAndStoreNext`, and the collect/iterate helpers)
   to go through the real container's API once `AudioMapStorage` is properly
   typed, matching how `Mesh.h`'s `MeshRendererMeshCacheTree` migration
   (commit `1d9c2e6c`) replaced hand-rolled tree functions with
   `msvc8::map<K,V,Compare>`'s own `try_get`/`insert`/`erase`.
5. `RefreshMap1Bounds` still needs independent verification of its own
   correctness, but the erase side is CONFIRMED NOT affected by this bug:
   `ErasePausedCategoryNodeAndStoreNext` (`AudioEngine.cpp` ~line 2169)
   already tracks `removedNodeWasBlack`/`fixupNode`/`fixupParent` and calls
   a real `FixupPausedCategoryMapAfterErase(map, fixupNode, fixupParent)`
   (line 2216) when needed — this path looks like a materially more careful
   recovery pass than the insert path got, and needs no fix. Scope is
   `InsertPausedCategoryName` only.

## Why this wasn't fixed in the same pass that found it

Found at the tail of an already very large session segment (11+ direct
commits, a 8,203+338-token DB-integrity bulk audit, 4 dispatched background
agents already in flight). Real RB-tree rebalance-logic verification
deserves the same unhurried, register-level care the palette buffer cluster
got, not a rushed fix appended to an overloaded turn. Good next-session
starting point — the caller, the callee (`ConstructPausedCategoryNode`), and
the exact missing behavior are all already pinned down here.
