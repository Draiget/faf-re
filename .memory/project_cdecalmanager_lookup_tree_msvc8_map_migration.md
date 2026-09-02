---
name: project_cdecalmanager_lookup_tree_msvc8_map_migration
description: CWldSplat.cpp's CDecalManager DecalGroupLookupTree hand-rolled RB-tree (RULE ONE violation, and a real missing-rebalance bug like AudioMap1) migrated to two real msvc8::map<uint32_t,T*> members. FULLY LANDED, not deferred. ~30 addresses register-traced and cited on RbTree.h/Map.h; also fixed a genuine CDecalManager layout bug (three fields off by 4 bytes) and a fabricated destructor-callsite citation.
metadata:
  type: project
---

## What this was

`Moho::CDecalManager` (`src/sdk/moho/terrain/splat/CWldSplat.cpp`/`.h`) owned
two keyed lookup maps (`mDecalGroupLookupByDecalIndex`,
`mDecalGroupLookupBySplatIndex`) modelled as a hand-rolled `DecalGroupLookupTree`/
`DecalGroupLookupNode` struct pair, walked by ~17 free functions
(`FindLookupNodeByKey`, `ResolveLookupValueSlotForKey`,
`EraseLookupEntriesByKey`, `ClearDecalLookupTree`, `ResetDecalLookupTreePrimary`/
`Secondary`, and ~11 more) -- exactly RULE ONE's "container verb glued to
container noun" shape, duplicating `legacy::containers::rb_tree<Traits>`
(`msvc8::map<K,V>`) that this codebase already uses successfully for a dozen+
other maps.

## The correctness bug this was hiding

Register-traced `ResolveLookupValueSlotForKey`'s real address (0x00879120) and
found it does NOT itself insert -- it descends (a `lower_bound`-shaped walk)
and, on a miss, delegates to `sub_879B10` (0x00879B10), which is a real MSVC8
hinted-insert dispatcher (`insert_hint`) with predecessor/successor straddle
checks falling through to `insert_unique`/`insert_at` -- i.e. the REAL binary
runs the full self-balancing red-black insert algorithm. The CURRENT hand-
rolled `ResolveLookupValueSlotForKey`, by contrast, linked a freshly-allocated
node straight onto its BST-descent parent with **no rotation/recolor step at
all** -- a plain unbalanced BST insert. This is the exact same missing-
rebalance shape already documented on `AudioMap1CategoryNode` in
[[project_audiomap1_missing_rebalance_bug]], found independently here via the
CLAUDE.md-mandated "read the raw .asm, don't trust the existing recovered
shape" check, not by cross-referencing that note.

## What landed (commit — see `git log` for `CWldSplat.cpp`/`.h`/`RbTree.h`/`Map.h`)

1. **Value-type correction.** Both trees were previously typed as `uint32_t ->
   std::int32_t` ("group index"). Register-tracing `LoadDecal`/`LoadDecalGroup`'s
   write sides (0x008780A0/0x008782D0) showed the mapped value stored is
   actually the **decal/group pointer itself** (`mov [eax],esi` storing the
   live `CWldTerrainDecal*`/`CDecalGroup*`, not an index). Retyped to
   `msvc8::map<std::uint32_t, CWldTerrainDecal*>` and
   `msvc8::map<std::uint32_t, CDecalGroup*>` respectively, and renamed/retyped
   the two accessors: `FindGroupByDecalIndex` (a "group" misnomer, returned
   `std::int32_t`) -> `FindDecalByIndex` returning `CWldTerrainDecal*`;
   `FindGroupBySplatIndex` kept its name (accurate) but fixed its return type
   to `CDecalGroup*`.
2. **CDecalManager layout bug fixed.** The pre-existing `DecalGroupLookupTree`
   struct claimed 0x10 bytes (`mUnknown00`/`mHead`/`mNodeCount`/`mUnknown0C`)
   and `CDecalManager` carried a phantom `mUnknown0C_0F[4]` pad before
   `mDecals`. Both were wrong: `msvc8::vector<T>` defaults `HasDebugProxy=true`
   (a real leading proxy word this struct never accounted for) and the
   canonical `rb_tree<Traits>` is the well-established 0x0C-byte
   `{proxy_,head_,size_}` footprint (confirmed against dozens of other
   instantiations already cited in `RbTree.h`). Net effect: `mDecals`/
   `mDecalGroups`/`mSplats` were each declared 4 bytes too high. Proved via
   THREE independent sources -- the ctor's (0x00877A60) per-member zero-writes,
   the dtor's (0x00877B70) per-member teardown reads, and the `0x00BAF6xx`
   SEH-unwind-funclet thunk table (`add eax,0xNN; jmp <member-reset>`), which
   spells out every sub-object's exact offset directly. Corrected offsets:
   `mDecals`@0x0C (was 0x10), `mDecalGroupLookupByDecalIndex`@0x1C (unchanged),
   `mDecalGroups`@0x28 (was 0x2C), `mDecalGroupLookupBySplatIndex`@0x38
   (unchanged), `mSplats`@0x44 (was 0x48); `sizeof(CDecalManager)` stays 0x114
   (everything from `mSpatialDbOwnerStorage`@0x54 onward was already right).
   The `#if defined(MOHO_ABI_MSVC8_COMPAT)` gate around these asserts was
   removed (that macro is defined nowhere in this tree -- the asserts were
   dead code, never actually checked, which is almost certainly *why* the
   4-byte error went unnoticed).
3. **Fabricated destructor-callsite citation fixed.** The hand-rolled
   `ResetDecalLookupTreePrimary`/`Secondary` (cited 0x00878D30/0x00878D60) were
   modelled as explicit calls from `~CDecalManager`'s body. Checking
   `incoming_xrefs` for both addresses: **neither is ever called from
   `CDecalManager::CDecalManager`/`~CDecalManager`'s ordinary instruction
   stream** -- both callers are `0x00BAF6xx` EH-unwind-funclet dispatch
   entries, reached only if an exception propagates through a later member's
   construction (ctor) or through the dtor's own body. This is CLAUDE.md RULE
   ONE's "EH unwind funclets... are not source at all" case, independently
   discovered here (the citation -- what the address does -- was correct; the
   claimed caller was fabricated). Fixed by deleting both free functions
   entirely and citing 0x00878D30/0x00878D60 on `~rb_tree()` in `RbTree.h` as
   its EH-funclet emission. The real "happy path" teardown these two SEH
   funclets shadow (`erase_range` + `operator delete(head)` + zero) is
   automatic C++ member destruction now that both maps are real typed members
   -- confirmed via the dtor's actual reverse-declaration-order teardown
   sequence (mSplats, tree2, mDecalGroups, tree1, mDecals), which the
   remaining explicit code (three raw-pointer delete loops +
   `DestroyStorage()`) now relies on implicitly, matching the `MeshRenderer`
   precedent's own destructor-ordering fix exactly.
4. **~30 addresses register-traced and cited** across `RbTree.h`'s
   `operator[]`(`Map.h`)/`insert_hint`/`insert_unique`/`insert_at`/
   `rb_decrement`/`rb_increment`/`find_node`/`equal_range`/
   `erase(const key_type&)`/`erase_range`/`~rb_tree()` for BOTH tree
   instantiations. Traced instruction-by-instruction against each canonical
   member's C++ body before citing (branch structure, not just "looks similar" --
   e.g. `insert_hint`'s five accepted branches each matched field for field,
   including a compiler code-sharing quirk where the predecessor-straddle
   guard's failure edge jumps into the middle of the successor-straddle
   guard's own test rather than to a dedicated fallback -- both land on the
   same observable `insert_unique` call the source-level `if`/`else-if` chain
   produces). Found and recorded that several members are genuinely SHARED
   between the two instantiations (`erase(key)`, `erase_range`, one
   `rb_increment` emission, `equal_range`) since those members' own bodies
   never touch the `mapped_type` at all -- only `uint32_t` keys and node
   pointers -- while `operator[]`/`insert_hint`/`insert_unique`/`insert_at`/
   `rb_decrement`/`find_node` each got separate per-tree emissions.

## DB-integrity issues found and fixed along the way

Querying `recovered_progress.json` for all ~30 touched addresses before
marking anything surfaced (all fixed via `recovered_progress.py mark`, worker
`claude-cdecal-rbtree-migration`):

- **`FUN_00879450`/`FUN_00879B10`** (tree2's `operator[]`, tree1's
  `insert_hint`) -- wrongly `skip` (agent-a908, no note, no source). Both are
  real, distinct, live engine template instantiations.
- **`FUN_0087AB70`/`FUN_0087B4F0`** (tree1/tree2 `insert_unique`) -- wrongly
  `external_dependency` (claude-batch, no note). Per CLAUDE.md, engine-
  instantiated template bodies for engine types are never
  `external_dependency`.
- **`FUN_00879F60`** (tree2's `insert_hint`) -- `blocked`, no note/source. No
  actual blocker; fully resolved by this pass.
- **`FUN_0087A080`** (`erase_range`, shared) -- wrongly `skip` (orch-tier1c, no
  note, no source). Live, heavily-used shared engine code.
- **`FUN_0087AF70`/`FUN_0087B8F0`** (`insert_at` x2) -- `recovered` with
  **null `source_paths`**, the same contamination class as
  [[project_null_source_paths_recovered_12294]].
- **`FUN_00879120`/`FUN_00879510`/`FUN_008791E0`/`FUN_00879C30`/
  `FUN_00878D30`/`FUN_00878D60`** -- `recovered` but `source_paths` pointed at
  the now-deleted hand-rolled `CWldSplat.cpp` free functions; repointed to
  `RbTree.h` (the two `~rb_tree()` funclet addresses also got the fabricated-
  caller fix described above).
- **`FUN_0087CCB0`/`FUN_0087CD70`/`FUN_0087CD10`/`FUN_0087CDD0`/
  `FUN_008792A0`/`FUN_008795D0`/`FUN_0087A1A0`/`FUN_00879D50`** -- already
  `recovered` and legitimately attributed to `SimRecoveryRuntime.cpp`/
  `EntityDb.cpp` (real, independent instantiations sharing these ICF-adjacent
  canonical-member addresses). Not overwritten -- `RbTree.h` added as an
  *additional* `--source`, preserving the existing attribution alongside the
  new evidence, since both are genuinely true at once.

## Verification

Every touched TU (`CWldSplat.cpp`, transitively `CWldSplat.h`/`RbTree.h`/
`Map.h`) passed `tucheck` (`EXITCODE=0`) after each substantive edit, including
after all RbTree.h/Map.h citation additions (pure Doxygen-comment insertions --
no executable-code changes to either shared header, so zero blast radius on
any other translation unit). Grepped the whole `src/sdk` tree afterward to
confirm zero remaining references to `DecalGroupLookupNode`/`DecalGroupLookupTree`/
`FindGroupByDecalIndex` outside explanatory comments, and zero external callers
of the renamed/retyped accessors (both were declared but never called from any
other file).

## Nothing deferred

Unlike [[project_audiomap1_missing_rebalance_bug]] (deliberately deferred --
that migration's blast radius spans ~5+ functions across a whole other file
and needed its own dedicated pass), this one was small enough (one file, two
sibling instantiations, ~30 addresses) to land completely in one pass: no
open TODOs, no half-migrated member, no remaining hand-rolled tree code in
`CWldSplat.cpp`.
