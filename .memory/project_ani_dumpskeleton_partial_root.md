---
name: project-ani-dumpskeleton-partial-root
description: "RESOLVED 2026-09-02. The 0x007B22B0 closure was landed by commit 3634c87c via a better approach than this note's own plan (real msvc8::map/msvc8::set instead of a rotate/rebalance migration) and independently verified clean, no bug found -- see the RESOLVED section below. Historical analysis (the 0x20-node-family distinction) kept for reference."
metadata:
  node_type: project
  type: project
---

## RESOLVED 2026-09-02 (session claude-anidumpskeleton-verify)

Dispatched to execute this note's own "resolved bottom-up (do this next)"
plan below. Found it already moot: commit `3634c87c` ("Recover
Moho::ANI_DumpSkeleton and delete its fabricated bootstrap") had already
landed, and did something better than the plan this note describes.

Instead of migrating `AniSkeletonVisitedBoneNodeLanes` in place and citing
standalone rotate/rebalance recoveries, the real fix **deleted the
fabricated stopgap outright** (`AniSkeletonVisitedBoneBootstrap`,
`StageAniSkeletonVisitedBoneNode`, and the struct itself) and rewrote
`Moho::ANI_DumpSkeleton` (`CAniSkel.cpp`) to build its per-parent-bone dedup
structure as a real `msvc8::map<std::uint32_t, msvc8::set<std::uint32_t>>`
directly. That is a strictly better resolution than this note's plan (which
would have kept a bespoke node type alive) -- it routes through the actual
canonical container from the start, per RULE ONE.

Independently register-traced all five real tokens against `RbTree.h`'s
canonical members this pass (not just trusted the DB `recovered`/`skip`
marks, since this project's own `.memory/project_handrolled_rbtrees_are_the_wall.md`
umbrella note warns "recovered"/notes for a hand-rolled tree are a standing
false signal):

| token | is | verified against | result |
|---|---|---|---|
| `FUN_007B22B0` | `Moho::ANI_DumpSkeleton` | its own recovered body, `CAniSkel.cpp` | matches; real caller `register_CConFunc_ANI_DumpSkeleton` (`CConCommand.cpp:5243`), `.data` init at 0x00BDF8F0 is the sole xref |
| `FUN_007B2B30` | `msvc8::set<uint32_t>::insert_at` fused with `link_and_rebalance` | `RbTree.h` `link_and_rebalance` (~line 7541) | matches branch-for-branch: max_size guard, buy_node head_/where/head_ fusion, 3-case link, full CLRS insert-fixup (case 1/2/3 both mirrored), calls the two rotates at the exact CLRS points, trailing `root()->color=black` |
| `FUN_007B3590` | `rotate_left` | `RbTree.h` `rotate_left` (~line 6942) | matches branch-for-branch; also byte-identical (`function_sha256`) ICF twin of `FUN_00498010`, an 8-way group |
| `FUN_007B3610` | `rotate_right` | `RbTree.h` `rotate_right` (~line 7178) | matches; ICF twin of `FUN_004980C0`, mirrored 8-way group |
| `FUN_007B46A0` | `erase_node`-equivalent single-node erase-and-rebalance | `RbTree.h` `erase_node` citation (~line 3687) | isNil@+0x11 confirmed directly from `.asm`, throw shape matches |

**No missing-rebalance bug here**, unlike the CArmyStats/CDecalManager/
AudioMap1 migrations this project's umbrella note tracks. See
[[project-handrolled-rbtrees-are-the-wall]] for why: those three all
started from a *working* (if wrong) hand-rolled BST that someone later
migrated in place, and the bug was always "the migration/hand-rolled
version forgot to rebalance." CAniSkel's hand-rolled code was never a
working implementation to begin with -- `StageAniSkeletonVisitedBoneNode`
was an explicit stub whose own doc block said the rotation/insertion logic
was NOT yet written. There was no wrong algorithm for a missing-rebalance
bug to hide in; the recovery skipped straight to the correct canonical
container. Treat this as the pattern's boundary case, not a counterexample
to its warning: still register-trace before trusting a `recovered`/`skip`
mark, but a from-scratch canonical-container recovery (vs. an in-place
migration of pre-existing bespoke logic) is a different risk profile.

Fixed two real DB/citation gaps found during verification (not correctness
bugs, documentation debt): `FUN_007B2B30` was `skip`-tagged citing "RbTree.h
+ Map.h" as its canonical home but had **zero** `Address:` lines anywhere in
`src/sdk` (confirmed by full-tree grep) -- added one to `insert_at`'s
docblock. `FUN_007B3590`/`FUN_007B3610`'s `skip` notes claimed the ICF twin
was "address-cited at ParticleRenderBuckets.cpp" -- wrong file (it's
`RbTree.h`); the twin fact itself was correct (confirmed via
`function_icf_twins` and independently via register trace). Also corrected
both tokens' `source_paths` (were wrongly `CrtRuntimeHelpers.cpp`, itself a
flagged contamination-prone file). Landed in commit `486a0102`, comment-only
change to `RbTree.h`, `tucheck` clean on `CAniSkel.cpp`.

This closure is done. Nothing left to migrate in `CAniSkel.cpp` for this
family. The historical analysis below (written 2026-08-21, before the real
fix landed) is kept for the 0x20-node-family distinction, which is still
correct and still relevant if that *other*, unrelated map ever gets
scoped.

---

## Historical analysis (2026-08-21, superseded by the RESOLVED section above)

`CAniSkel.cpp` is free; this is blocked on completeness, not on lease.

## The root is partial and says so

`CAniSkel.cpp:853` carries `Address: 0x007B22B0 (**partial**, FUN_007B22B0 /
Moho::ANI_DumpSkeleton)` on `StageAniSkeletonVisitedBoneNode`, whose own doc
block states the rotation and insertion logic "is owned by the broader
ANI_DumpSkeleton recovery and will link this node once that function lands."

That is the [[project-elided-caller-false-positives]] trap wearing prose: the
address grep finds it, the closure ranking treats it as a recovered root, and
the eight bodies underneath look landable when they are not. **A doc block
that says "partial" is a stub with better manners.**

Audited tree-wide the same day: `rg -n 'Address: 0x[0-9A-Fa-f]{8} \(partial'
src/sdk` returns **exactly one hit -- this one** -- and the "will land later"
prose markers return only its two companion lines. So this is a single case,
not a vein; no follow-up sweep needed.

It also allocates with plain `new` rather than the tree allocator, and its
comment calls the node 20 bytes.

## The bodies below it

| token | instr | is |
|---|---|---|
| `FUN_007B4040` | 252 | the rebalancing `_Tree::erase(iterator)` |
| `FUN_007B4360` | 28 | `_Lrotate` -- takes `[node+8]`, moves its `[left]` up |
| `FUN_007B43C0` | 28 | `_Rrotate` -- takes `[node]`, moves its `[right]` up |
| `FUN_007B2050` `FUN_007B27D0` `FUN_007B2DF0` `FUN_007B3820` `FUN_007B4A50` | 169/99/123/74/16 | unidentified |

**The node is 0x20, not 0x1C.** Both rotates test the nil flag at `[+0x1D]`,
so the layout is `{left@0, parent@4, right@8, value@0x0C (0x10 bytes),
color@0x1C, isnil@0x1D}`. That is *not* `SSelectionNodeUserEntity` (0x1C, nil
at +0x19) -- do not file these with the weak-entity-set tree work in
`WeakEntitySet.h`, and note the 20-byte claim in the existing comment
disagrees with the rotates.

Same erase+two-rotates shape as the blueprint map in
[[project-rrulegamerules-blueprint-map-migration]], for a third node size.
The canonical home for all of them is `RbTree.h`, which is currently free.

## The CAniSkel chain, resolved bottom-up (do this next)

The two 28-instruction helpers the partial doc names as missing are the
rotates for the node type **already modelled in that file**:

| token | instr | is | status |
|---|---|---|---|
| `FUN_007B3590` | 28 | `_Lrotate` -- takes `[node+8]`, moves its `[left]` up | blocked |
| `FUN_007B3610` | 28 | `_Rrotate` -- takes `[node]`, moves its `[right]` up | blocked |
| `FUN_007B2B30` | 144 | the insert rebalance; sole caller of both rotates | **was falsely `recovered`, reverted 2026-08-21** |
| `FUN_007B22B0` | 212 | `ANI_DumpSkeleton` itself | partial |

Both rotates test the sentinel byte at `[node+0x11]`, which matches
`AniSkeletonVisitedBoneNodeLanes` (0x14: left@0, parent@4, right@8,
value@0x0C, color@0x10, isSentinel@0x11) exactly -- the layout and its
static_asserts are already in `CAniSkel.cpp:788`. So no layout work is needed;
this is 212 + 144 + 28 + 28 instructions of body against a known node.

`FUN_007B2B30` was marked `recovered` with **no citation anywhere in src/sdk**
-- same contamination class as the 2026-08-21 citation audit. Reverted.

Order: rotates and rebalance are leaves, but none can land alone (no
source-level caller), so recover `ANI_DumpSkeleton` and all four commit
together. `CAniSkel.cpp` is free and `FUN_007B46A0` is a *second* rebalance
sharing the same two rotates -- expect to cite them twice.

## The other, unrelated 0x20-node family

`FUN_007B4040` (252, rebalancing erase) with `FUN_007B4360`/`FUN_007B43C0`
(28 each, rotates) test their nil flag at `[+0x1D]`, so they belong to a
**0x20** node `{left@0, parent@4, right@8, value@0x0C (0x10 bytes),
color@0x1C, isnil@0x1D}` -- a different map. Do not file them with the
CAniSkel work or with the 0x1C weak-entity set. Canonical home `RbTree.h`,
currently free.
