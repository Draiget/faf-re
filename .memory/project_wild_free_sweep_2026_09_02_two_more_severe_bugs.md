---
name: project_wild_free_sweep_2026_09_02_two_more_severe_bugs
description: Systematic 6-batch sweep for the array-cookie wild-free bug class (peer's Unit.cpp root-cause fix) came back clean beyond the one already-known landmine, but surfaced two unrelated, severe, previously-unknown bugs — CPlatoon.cpp fake-vtable dispatch and Unit::mBlipsInRange freeing its own inline SBO buffer. Both fixed and committed.
metadata:
  type: project
---

## Context

Peer session `faf-main-2c` found and fixed the actual crash-causing heap
corruption this session (`Unit.cpp`, commit `3cd159aa`): a raw
`::operator delete[](ptr)` call on a `new UnitWeaponInfo[n]`-allocated
array frees `base+4` instead of `base` (MSVC writes a 4-byte element-count
cookie before the returned pointer for non-trivial-dtor T; only the
`delete[]` *expression* knows to back up over it). Runtime-verified fix:
commander confirmed spawning correctly (HUD, correct ACU resource values,
stable multi-minute run). I independently found and fixed one more
landmine of the exact same shape in `FastVector.h`'s `ResetStorageToInline`
free-function duplicate (commit `db7d7469`).

Dispatched a 6-way-parallel background sweep of the whole `src/sdk` tree
(~600 real call sites total) for the SAME pattern: `new T[n]`
(cookie-writing, T non-trivially-destructible) freed via a raw
`::operator delete[]`/`::operator delete` CALL instead of the
`delete[]`/`delete` EXPRESSION. Result: clean. No further instances of
this exact bug shape exist. The two already-fixed ones (Unit.cpp,
FastVector.h) were the only live cases.

## Two unrelated, severe bugs found instead (different mechanism, same severity)

1. **`CPlatoon.cpp`'s `DestroyOwnedSquad`** (fixed, commit `7d5a7d90`) —
   fabricated vtable dispatch: `*reinterpret_cast<void***>(squad)` reads
   `squad->mSim` (CSquad's real first field, a `Sim*` — CSquad has NO
   vtable at all) and calls 8 bytes *inside the Sim object* as a function
   pointer whenever `mSim != nullptr`, i.e. on essentially every live
   squad reaching platoon teardown (normal gameplay, not an edge case).
   The real binary (`FUN_00724EB0.asm`, `~CPlatoon`) shows no such
   dispatch at all — plain null check, direct non-virtual
   `call CSquad::~CSquad()`, `operator delete`. The buggy function had NO
   `Address:` citation, consistent with never having been checked against
   disassembly — a fabricated recovery, not a binary-faithful one.

2. **`UnitFastVectorReflection.cpp`'s `mBlipsInRange` deserialization**
   (fixed, commit `37704be3`) — `ResizeFastVectorWeakPtrRuntime` reached
   into `Unit::mBlipsInRange` via `AsFastVectorRuntimeView<WeakPtr<T>>`, a
   type-erased view over the BASE (non-SBO) `FastVector<T>` shape. The
   real declared type is `gpg::core::FastVectorN<SWeakRefSlot,20>` — a
   20-element array embedded INLINE, directly inside the `Unit` object.
   The growth path did `::operator delete(view.begin)` unconditionally,
   with no check for "is begin still the inline buffer" — deserializing a
   unit with >20 tracked recon blips while still on inline storage (the
   common case) frees memory that was never a heap allocation at all,
   corrupting the allocator's free-list. Fixed by rewriting to operate on
   the real `FastVectorN<SWeakRefSlot,20>&` directly via its named public
   fields (`start_`/`end_`/`capacity_`/`originalVec_`) instead of the
   type-erased view — see [[feedback_sbo_reach_in_bug_class_and_fix_pattern]]
   for the reusable fix pattern and the follow-up sweep that confirmed no
   other instances exist.

## Lesson

The array-cookie bug and the SBO-reach-in bug are BOTH invisible to a
naive "grep for `ptr + n` near a delete" search — in both cases the
dangerous offset/aliasing is either compiler-inserted (the cookie) or
happens through a completely different object's memory (the inline
buffer), not through any arithmetic visible in the source. When hunting
one shape of "wild free," it's worth explicitly considering whether a
structurally-similar-but-mechanistically-different bug class could
produce the same class of symptom (heap corruption presenting as
unrelated crashes elsewhere) — that's exactly how both of these were
found: by reading real code for unrelated reasons, not by pattern-
matching the original bug's specific signature.
