---
name: project-cdecalbuffer-tree-chain
description: CDecalBuffer start-tick bucket RB-tree FULLY LANDED - 90e6ffa (15 fns) + 5c40545 (DestroyHandle mStartTick-gate fix) + 18c486f (insert chain + CreateHandle wiring). Both CreateHandle and DestroyHandle now correctly maintain mStartTickBuckets. Nothing deferred in this subsystem.
metadata:
  type: project
---

## Landed 2026-08-19/20, commit `90e6ffa`

The originally-scoped 5-function chain grew to 15 once tracing began: the
background agent's report undercounted because several "already recovered"
dependencies (`FUN_0077C5E0`/`C640`/`B0B0`/`B160` rotate helpers,
`FUN_0077C740`/`FUN_0077CE50` successor-advance) turned out to be
[[fake_recovered_status_contamination]] - see that memory, it's the more
important finding from this session.

Final function set, all in `src/sdk/moho/render/CDecalBuffer.cpp`:

**Map tree** (`std::map<uint32_t /*startTick*/, DecalBucketTreeStorage>`):
`RotateMapNodeLeft/Right` (B0B0/B160) · `AllocateDecalMapValueNode` (CAE0,
fuses the allocator lane DC40) · `LinkMapNodeAndRebalance` (BE80,
`_Tree::_Insert`) · `FindStartTickBucketNode` (BCD0, `_Tree::insert_unique` -
this REPLACED a prior committed body that only did the lower-bound descend
half and was orphaned) · `AdvanceMapNodeToSuccessor` (CE50) ·
`ResolveStartTickInsertPosition` (AF40, `_Tree::insert(hint,v)`) ·
`FindOrCreateStartTickBucket` (A250, `operator[]`-equivalent, the public
entry point).

**Bucket tree** (per-tick set of decal handles): `RotateBucketNodeLeft/Right`
(C5E0/C640) · `AdvanceBucketNodeToSuccessor` (C740) · `EraseBucketNode`
(C270, `_Tree::erase(iterator)`) · `EraseBucketNodeRange` (B4F0,
`_Tree::erase(first,last)`) · `EraseBucketNodesByKey` (A9F0,
`_Tree::erase(key)`, the other public entry point).

`DestroyHandle` now calls `FindOrCreateStartTickBucket` +
`EraseBucketNodesByKey` (previously `mStartTickBuckets` was 100% dead
storage - constructed/torn down, never read or written).

## Technique: verify against `RbTree.h`, not hand-transcribed asm

`legacy/containers/RbTree.h` has a generic, address-cited, proven
`msvc8::detail::rb_tree<Traits>` template (`link_and_rebalance`,
`erase_node`, `rotate_left/right`, `insert_hint`, `insert_unique` - all of
it) that is the SAME MSVC8 Dinkumware `_Tree` algorithm as this chain, just
a different instantiation. `FUN_0077BE80` (insert fixup) and `FUN_0077C270`
(erase transplant+fixup) are dense, register-reused decompiler output where
hand-deriving every branch risks a swapped left/right or parent/child. I
matched their overall shape against the decompiled `.c` (confirmed every
branch condition, e.g. uncle-color direction, matches) but wrote the actual
C++ as a careful adaptation of RbTree.h's already-proven methods rather than
a literal transcription. This is the right call whenever a candidate is
plausibly an instantiation of an already-recovered generic template - check
for one before hand-transcribing dense fixup/rebalance logic.

## Follow-up landed: CreateHandle's insert-side wiring (18c486f)

Added `RetreatBucketNodeIterator` (CD80, rb_decrement) + `LinkBucketNode-
AndRebalance` (B600, `_Tree::_Insert`, reuses the already-recovered
`AllocateClonedDecalBucketNode`) + `FindOrInsertBucketNode` (A930,
`_Tree::insert_unique`, byte-identical shape to BCD0). Wired into
`CreateHandle` right after the flat-list link, gated on
`mInfo.mStartTick != 0` - confirmed via `FUN_007793D0`'s real body
(read directly, not inferred) that the binary gates `sub_77A250`/
`sub_77A930` the same way.

**Bug caught in the same pass**: the FIRST commit (90e6ffa) wired
`DestroyHandle` to call the erase pair *unconditionally*. Reading
`FUN_00779680`'s real body showed it ALSO gates on `mStartTick != 0` and
erases *before* the `mVisibleInFocus` pending-hide push_back, not after.
Fixed in 5c40545, separately from the insert-chain landing, before writing
any new code - always read the REAL caller body before trusting a
"probably symmetric with the sibling" assumption.

`FUN_00779D70` (save/replay decal-list deserialization) still calls
`FindOrCreateStartTickBucket`-equivalent + `FUN_0077A930` and remains
unwired - it's `blocked`, not part of the two handle-lifecycle entry
points, and was out of scope for this pass. If picked up later, the same
gate-and-order-from-the-real-body discipline applies.
