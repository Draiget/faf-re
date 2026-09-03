---
name: project-lua-gc-string-table-corruption
description: SOLVED (2026-08-14, commit 7f6bc1d). The Sim::Setup crash in PushHeapBlock was UnitAttributes' constructor delete[]-ing a block it never owned. Keeps the eight ruled-out items and the probe recipe that found it.
metadata:
  type: project
---

**SOLVED** 2026-08-14 by commit 7f6bc1d. Everything below the fix section is
kept because the ruled-out list cost several sessions and the probe recipe
is reusable for the next heap bug.

## The bug

`moho::UnitAttributes::UnitAttributes` (0x006A4760) copied the rule-empty
category by assigning the three pointer lanes of its `FastVectorN<uint,2>`:

    mWords.start_ = empty.mWords.start_;   // and end_, capacity_

The binary calls `gpg::fastvector_uint::cpy` there - a real copy into the
destination's own storage. Assigning the lanes left `mWords` aliasing the
empty category's buffer while `originalVec_` still pointed at our inline
buffer, so the `ResetStorageToInline()` two lines later saw
`start_ != originalVec_` and `delete[]`-ed memory the vector never owned.

Fix: `restrictionCategory.mBits.mWords.ResetFrom(emptyCategory->mBits.mWords)`.

**Every unit constructed freed one arbitrary live block.** The ones landing
on interned Lua strings were the visible failure: the freed block stayed
linked in the string table, `newlstr` got it straight back, and it ended up
heading several buckets at once. The next collection swept the same node
from two chains, double-freed it, and left the 28-byte lane list shorter
than its own `count` - so `TrimThreadCache` popped a null and
`PushHeapBlock` read `[0+0x20]`.

`FastVector.h` already warned about exactly this shape (the `SCondition`
comment: "Assigning instead would ... `delete[]` an uninitialised pointer").
**When recovering a `cpy` call, never substitute lane assignment.**

## The probe that found it (reusable)

All in a `probe` namespace in `Global.cpp`, raw `CreateFileA`/`WriteFile` so
it is safe inside `malloc`/`free`, plus `extern "C"` bridges into
`LuaObject.cpp`. Per-tag report budgets are essential - one noisy tag
starves the others.

The decisive chain was:
1. `VerifyLane` on every class-6 alloc/free - proved `lane.count` disagreed
   with the real list length.
2. Whole-string-table audit before and after `sweepstrings` - proved the
   table was already corrupt *before* the sweep (48 duplicates), so the
   sweep was a victim.
3. Recomputing each node's hash from its own bytes - proved the node was
   intact and the bucket entry was stale, not scribbled.
4. A `linked` bit set in `newlstr` and cleared in `sweeplist`, checked at
   the single `free()` choke point. **This is the one that named the
   culprit** - anything still flagged is being freed by code that does not
   own it. All 16 hits came from `UnitAttributes::UnitAttributes`.

A hardware write watchpoint (DR0 + `AddVectoredExceptionHandler`) on one
bucket slot also works and is cheap; it proved *no* foreign write hit the
bucket array, which is what redirected the hunt to the free path.

Two traps worth remembering:
- Marking a block "freed" in `freeobj` only, and clearing it only in
  `newlstr`, gives false positives when the block is reused for a Table or
  Closure. Track at the `luaM_realloc` choke point instead.
- Never `break` out of `sweeplist` from a probe. It aborts the GC sweep and
  cascades into unrelated failures (it broke VFS/FX loading and looked like
  a completely different bug).

## Ruled out - do not re-audit

- The allocator. `malloc_0`, `free`, `PushHeapBlock`, `TrimThreadCache`,
  `PopLaneNode`, `PushLaneNode`, `AllocateSmallBlocksAmount`,
  `SplitHeapRecord`, `ReleaseHeapRecord`, `FlushCurrentThreadHeapCache` and
  `GetOrCreateThreadHeapCache` all match their decompiles. `TrimThreadCache`
  really does call `PushHeapBlock(nullptr)` when the lane underflows - the
  binary does too, which is why the null pop was a symptom, not the bug.
- Stale non-null page-owner entries for decommitted pages are normal.
- `luaS_resize`. Audited after every rehash: `totalNodes == nuse` exactly,
  no duplicates, at every size up to 65536.
- Thread-cache sharing. Each thread gets its own `ThreadHeapCache`; the
  `thread_local` works. No allocation ever overlapped a live cache block.
- Anything writing into the string-table bucket array. A watchpoint on the
  corrupted slot caught only legitimate `newlstr`/`sweeplist` writes.
- Strings in `rootgc`. `luaC_link` is only called for tables, closures,
  protos and upvalues.
- Thin-class-plus-runtime-view heap smashes.

## Fixed on the way (commit 7e6031a)

- `sweeplist` masked the mark byte with `0xF9` before the limit comparison;
  0x00915A11 does not mask.
- `freeobj` charged `sizeof(TString) + len + 1`; the binary charges
  `len + 21` (0x00915950).

Neither stopped the crash, but both are 1:1 corrections worth keeping.

Related: [[project-lua-gc-upvalue-corruption]], [[project-units-build-again]],
[[reference-crlf-binary-blob-hazard]] (UnitAttributes.cpp has a stray lone CR;
a normalising edit turns a 10-line diff into a whole-file rewrite).

## Second confirmed instance of this bug class (2026-09-01, commit `00d79258`)

`CDecoder::DecodeCells` (`CDecoder.cpp`) — same family, different concrete
shape: not a lane-assignment this time, but an **unconditional `delete[]`
on a `FastVectorN<T,2>`'s inline SBO buffer**, reached via a parameter
silently narrowed to the base `FastVector<T>&` type (dropping
`originalVec_`/inline-buffer awareness at the call boundary, rather than
via a cross-object pointer copy). Fires on every decoded issue-command
(any player order carrying a cell list), not just at unit construction.
Full writeup: [[project_createui_corruptor_ruled_out]]. Confirms this is a
real, recurring RECOVERY bug shape in this codebase — "an SBO container's
inline-vs-heap invariant gets silently dropped/violated by code outside
the container's own template" — worth checking for a third instance if
this general bug class ever needs to be hunted again: look for any
function taking a base `FastVector<T>&`/similar type-erased container
reference that then does raw pointer manipulation (delete/reassign
start_/end_/capacity_) rather than calling the container's own typed API.
