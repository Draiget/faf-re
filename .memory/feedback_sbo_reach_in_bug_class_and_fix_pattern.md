---
name: feedback_sbo_reach_in_bug_class_and_fix_pattern
description: Reusable bug class and fix pattern — a field whose real type is an SBO gpg::core::FastVectorN<T,N> (inline buffer embedded in the owning object) accessed through a type-erased AsFastVectorRuntimeView<T>/AsWeakPtrVectorRuntimeView<T> reach-in that unconditionally frees .begin. A follow-up whole-tree sweep (79 sites, 13 files) confirmed only one live instance existed (Unit::mBlipsInRange, already fixed) — the generic reflection path is already SBO-safe; only bespoke hand-written resize code was vulnerable.
metadata:
  type: feedback
---

## The bug shape

A class field is declared as `gpg::core::FastVectorN<T,N>` (small-buffer
optimized: an N-element `T inlineVec_[N]` array embedded directly inside
the owning object, plus `originalVec_` marking whether `start_` currently
points at that inline array or at a separately heap-allocated buffer).
Some OTHER piece of code — typically reflection/serialization glue that
only has a type-erased `void*`/`int objectPtr` to the field, not its real
static type — reinterprets it through `gpg::AsFastVectorRuntimeView<T>`
(or the WeakPtr-vector sibling `moho::AsWeakPtrVectorRuntimeView<T>`,
though that one is only used over `msvc8::vector<WeakPtr<T>>`, which has
no SBO and is safe by construction). This produces a
`fastvector_runtime_view<T>{begin,end,capacityEnd,metadata}` — the same
4-word layout as `FastVectorN`'s `{start_,end_,capacity_,originalVec_}` —
and if the code then does `::operator delete(view.begin)` (or
`delete[]`) WITHOUT checking `view.begin != view.metadata` first, growing
the vector while it's still on its own inline storage frees memory that
was never a heap allocation — it's embedded inside the owning C++ object.
This is corruption, not a leak: it scribbles a free-list link into live
object memory and later hands out a block that overlaps it.

## Why this is easy to miss

No `new T[]`/cookie is involved (unlike the sibling
[[project_wild_free_sweep_2026_09_02_two_more_severe_bugs]] bug class), so
grepping for `new T[n]`/cookie mismatches won't find it. The tell is
structural: a function receiving a type-erased pointer/reference,
constructing an `AsFastVectorRuntimeView`/similar type-punned view over
it, and freeing `.begin` without ever reading the view's 4th word.

## Where it actually lives vs. where it's safe

**The generic reflection growth path is ALREADY SBO-safe**:
`FastVectorRuntimeResizeFill` → `FastVectorRuntimeEnsureCapacity` →
`FastVectorRuntimeReallocateInsert` (`FastVector.h`) reads `view.metadata`
and only frees when `oldBegin != inlineBegin` — this is what nearly every
`RFastVectorType<T>::SetCount`/`Load*` function in
`FastVectorUIntReflection.cpp`/`FastVectorSOCellPosReflection.cpp`/
`FastVectorEntIdReflection.cpp` routes through, so all of those (35+ call
sites, many different element types including `UnitWeaponInfo`) are safe.

**The bug only lives in BESPOKE, hand-written resize/relocate code** that
reimplements grow-and-relink logic itself instead of calling the shared
path — because it needs element-specific behavior the generic path
doesn't know about (e.g. `WeakPtr<T>`'s intrusive owner-chain relink on
every relocated/dropped slot, which a memcpy-based generic grow can't
express). `UnitFastVectorReflection.cpp`'s `AdjustBlipsInRangeCount`
(originally `ResizeFastVectorWeakPtrRuntime`, fixed in `37704be3`) is the
one confirmed live instance. A whole-tree follow-up sweep (79 sites, 13
files, see [[project_wild_free_sweep_2026_09_02_two_more_severe_bugs]])
found zero others — one other bespoke reimplementation
(`CAiFormationInstance.cpp`'s lane-entry insert/rebind, backing two
different SBO `FastVectorN`s) already carries the correct guard.

## Fix pattern (worked example: `AdjustBlipsInRangeCount`)

Don't try to make the type-erased view itself safer — rewrite the
function to operate on the REAL concrete type directly, via its named
PUBLIC fields, so it can see the SBO marker at all:

1. Change the function's parameter type from the type-erased view/base
   reference to `gpg::core::FastVectorN<RealElementType, N>&` (the
   field's actual declared type — check the owning class's header, don't
   guess from the reflected element type, which may itself be a
   layout-compatible "shadow" type like `SWeakRefSlot` rather than the
   literal reflected type; if so, use that shadow type's own official
   conversion method, e.g. `SWeakRefSlot::AsWeakPtr<T>()` — verified via
   its own `static_assert`s — rather than reinterpret_casting blindly).
2. Update every call site to reinterpret/static_cast its incoming
   type-erased pointer to that real type instead.
3. Access `.start_`/`.end_`/`.capacity_` (public on the base
   `FastVector<T>`) and `.originalVec_` (public on `FastVectorN<T,N>`
   itself) by name. Guard every free with
   `if (vec.start_ != vec.originalVec_) { delete[]/::operator delete(vec.start_); }`
   — matching allocation form to deallocation form (check whether the
   existing code allocates via a `new T[n]` expression or a raw
   `::operator new(bytes)` call, and keep the free consistent).
4. **Expect `container_lane_guard.py` to deny an edit that still calls
   `AsFastVectorRuntimeView`/`AsWeakPtrVectorRuntimeView`, or whose
   function name matches a "container verb (Resize/Destroy/Fill/Insert/
   Compact/Reset/Allocate/Assign) + container noun" shape** — this is
   correct, not a false positive (see
   [[feedback_container_lane_guard_name_shape_workaround]] for when it
   IS a false positive vs. this case, which is a genuine per-type reach-in
   the guard is right to block). Rename to something domain-specific tied
   to the actual field (e.g. `AdjustBlipsInRangeCount` for
   `mBlipsInRange`) rather than a generic container-verb name — this is
   not a workaround, it's a MORE ACCURATE name once the function operates
   on the real type instead of a generic view.
