---
name: project_pathpreviewfinder_dispose_skips_destructor_bug
description: RESOLVED 2026-09-02 (commit 4cd5f2b71075b99e45f03dbc25f6666eaa8796e1). SpCountedImplPDisposePathPreviewFinder (BoostWrappers.cpp) used to never invoke PathPreviewFinder's real destructor -- it hand-replicated the ONE side effect that destructor happens to have (intrusive mPathQueueNode unlink) via a bespoke type-erased reach-in, then called raw ::operator delete(). Now calls the real, properly-typed moho::DeletePathPreviewFinder(PathPreviewFinder*) helper (Sim.cpp), declared in a new small dedicated header (moho/sim/PathPreviewFinder.h), matching the sibling-header pattern already used for CDebugCanvas/CIntelGrid/STIMap in that file.
metadata:
  type: project
---

## RESOLUTION (2026-09-02)

Fixed in commit `4cd5f2b71075b99e45f03dbc25f6666eaa8796e1`,
"Route PathPreviewFinder disposal through its real destructor chain".

Re-verified the whole diagnosis before touching anything (line numbers below
are current as of the fix, not the original ~line citations above, which had
drifted slightly):

- Re-read `FUN_007657D0.asm` directly: `mov [esi], offset
  ??_7PathPreviewFinder@Moho@@6B@` (deleting-destructor vtable republish),
  then the unlink at `+0x04`/`+0x08`, `call operator delete`, `mov eax,esi;
  retn`. Confirms the original diagnosis 1:1.
- Went one step further than the original diagnosis and cross-checked TWO
  additional independent emissions of the identical sequence via the
  callgraph SQLite index and raw `.asm`: `0x007657A0` (sits at
  `??_7PathPreviewFinder@Moho@@6B@+0x8`, already cited by
  `IPathTraveler::~IPathTraveler()`'s own address comment in
  `IPathTraveler.cpp`) and the copy inlined directly into
  `sp_counted_impl_p<PathPreviewFinder>::dispose` at `0x00765720` (the
  function actually being edited). All three agree byte-for-byte on the
  vtable-write + unlink + `operator delete` shape. Note: `0x007657D0` itself
  shows zero incoming xrefs/call-edges/data-refs in the callgraph index
  (`_callgraph_index.sqlite`) -- genuinely odd for this project's usual
  "no orphan functions" invariant, most likely an EH-unwind cleanup funclet
  for some as-yet-unlocated try-block, per CLAUDE.md's "known linker-emitted
  bridge" evidence class. Did not chase that down further since it wasn't
  needed for THIS fix (the 0x00765720 emission being edited has its own
  complete, already-established evidence chain) -- flagging in case anyone
  later needs `FUN_007657D0` itself as a standalone recovered token.
- Re-confirmed `PathPreviewFinder`'s layout in `Sim.cpp` (~line 6580):
  `class PathPreviewFinder final : public IPathTraveler`, single inheritance,
  all members plain POD/pointers (no other non-trivial destructors), no
  explicit destructor declared. `IPathTraveler::~IPathTraveler()` is
  `virtual` but since `finder` is statically typed as the exact most-derived
  `PathPreviewFinder*` (not a base pointer), `delete finder` resolves
  non-virtually at compile time regardless -- standard C++ semantics, not
  something needing a manual vtable-slot citation.

### The fix, as landed

1. New header `src/sdk/moho/sim/PathPreviewFinder.h`: forward-declares
   `moho::PathPreviewFinder` and declares
   `void DeletePathPreviewFinder(PathPreviewFinder* finder) noexcept;`,
   with a Doxygen block citing `0x007657D0` plus the two sibling emissions.
2. `Sim.cpp`: `#include "moho/sim/PathPreviewFinder.h"`; defined
   `DeletePathPreviewFinder` right after `PathPreviewFinder`'s constructor
   (same `namespace moho { ... }` re-opened block) as a one-line
   `delete finder;`.
3. `BoostWrappers.cpp`: `#include "moho/sim/PathPreviewFinder.h"`;
   `SpCountedImplPDisposePathPreviewFinder` now calls
   `moho::DeletePathPreviewFinder(countedImpl->px)` instead of the bespoke
   reach-in.
4. Removed `PathPreviewFinderDisposeRuntimeView` and
   `DestroyPathPreviewFinderRuntime` from `BoostWrappers.cpp` -- confirmed
   fully orphaned (grepped the whole file and `src/sdk` tree; their only
   caller was the dispose function just rewired).
5. Registered the new header in `main.vcxproj` / `main.vcxproj.filters`
   (`Header Files` filter, next to `CDebugCanvas.h`).
6. `tucheck` clean (`EXITCODE=0`) on both `gpg/core/utils/BoostWrappers.cpp`
   and `moho/sim/Sim.cpp` -- the Sim.cpp compile succeeding is itself direct
   proof `delete finder;` is well-formed (public, accessible, non-deleted
   destructor chain).

### Header question: resolved as option (b), with reasoning

Checked option (a) (declare in `Sim.h`) first, as the open question asked.
Rejected it: `Sim.h` is 7230 lines and transitively includes
`moho/entity/Entity.h`, `moho/entity/EntityCollisionUpdater.h`,
`lua/LuaObject.h` (a guardrail file under concurrent edit by another agent
this same session), `moho/render/RDebugOverlay.h`, `moho/task/CTaskThread.h`,
and more -- wildly disproportionate for declaring one helper function, versus
the sibling dedicated headers actually used by `BoostWrappers.cpp` today
(`CDebugCanvas.h` 235 lines, `CIntelGrid.h` 463 lines, `STIMap.h` 1120
lines). Went with option (b), a new small dedicated header, which is both
lighter and more consistent with this exact file's own established
convention. Did NOT move `PathPreviewFinder`'s full class body out of
`Sim.cpp` -- the new header only forward-declares the class and declares the
helper, exactly as scoped in the original task instructions; the full
definition stays in `Sim.cpp` untouched.

Nothing deferred. `PathPreviewFinderDisposeRuntimeView`/
`DestroyPathPreviewFinderRuntime` orphan cleanup was folded into the same
commit rather than left for later, since it was a direct, immediate
consequence of the rewire (matches this session's established orphan-cleanup
pattern, e.g. `0d32a518`, `9ef340ba`, `377f68f4`).

## How this was found

Flagged by a dispatched agent's sp_counted_impl_p cleanup pass as needing
"dedicated investigation" (unlike every sibling type it processed, whose
dispose bodies were the generic `DisposeSpCountedImplPointeeViaVirtualDelete`
shape). Investigated directly.

## The bug

`SpCountedImplPDisposePathPreviewFinder` (`BoostWrappers.cpp` ~line 3270)
casts `countedImpl->px` to a bespoke `PathPreviewFinderDisposeRuntimeView`
(`{void* vftable; ...* next; ...* prev;}`) and calls
`DestroyPathPreviewFinderRuntime`, which:
```cpp
finder->prev->next = finder->next;
finder->next->prev = finder->prev;
finder->next = finder;
finder->prev = finder;
::operator delete(static_cast<void*>(finder));   // raw call, NOT `delete finder;`
```
Raw `::operator delete()` is a plain deallocation call -- it does **not**
invoke any destructor. `PathPreviewFinder::~PathPreviewFinder()` (implicit,
never explicitly declared) never runs.

## Why this looked worse than it is, and why it's still wrong

Raw `.asm` for the real address (`0x007657D0`, `decomp/recovery/disasm/
fa_full_2026_03_26/FUN_007657D0.asm`) opens with
`mov [esi], offset PathPreviewFinder::vftable` -- the classic MSVC
"deleting destructor" prologue (re-publish this class's own vtable before
touching bases, so virtual calls during unwind resolve correctly), then the
same unlink, then `call operator delete(void*)`. This IS genuinely
`PathPreviewFinder`'s real compiled deleting-destructor body -- not evidence
of intentionally skipping the destructor at the SOURCE level. The compiler
inlined the WHOLE destructor chain (own body -- empty, no explicit dtor --
plus `IPathTraveler::~IPathTraveler()`, which is ALREADY recovered,
`IPathTraveler.cpp:30-32`, and does exactly `mPathQueueNode.ListUnlink();`)
into one destructor body, because `PathPreviewFinder final` + a concrete,
non-polymorphic-beyond-`IPathTraveler`shape lets MSVC devirtualize/inline
the whole thing at this one call site.

So the CURRENT recovered code happens to be behaviorally correct today
(same net effect) but is the WRONG ABSTRACTION per the reconstruction
fidelity contract: it hand-duplicates one side effect of a destructor chain
that already exists elsewhere in recovered source (`IPathTraveler`'s dtor),
via a type-erased struct reach-in, instead of just calling `delete` on a
properly-typed pointer and letting the REAL (already-recovered) destructor
chain run. It is fragile: if `PathPreviewFinder` or `IPathTraveler` ever
gain other cleanup logic, this dispose path silently won't include it.

## Why every OTHER type's dispose function is fine (do not over-generalize this finding)

The generic `DisposeSpCountedImplPointeeViaVirtualDeleteSlot(countedImpl,
vtableSlot)` used by most other types in this file ALSO looks like a
type-erased vtable reach-in at first glance, but it is a deliberate,
justified workaround: `BoostWrappers.h` only forward-declares every wrapped
type (`class TextureD3D9;`, `class Mesh;`, etc. -- confirmed, lines
~11-60+), never `#include`s their full definitions, so `BoostWrappers.cpp`
cannot call `delete` on them directly (incomplete-type UB/compile error).
Manually invoking the known vtable slot is the correct workaround given
that architectural constraint, and `SpCountedImplStorage<PointeeT>::px` is
ALREADY properly typed as `PointeeT*` (not `void*`, confirmed
`BoostWrappers.h` ~line 890-896) -- there's no separate incomplete-type
issue there. `PathPreviewFinder`'s dispose is the outlier specifically
because it bypasses even THIS pattern with a fully bespoke, destructor-free
reach-in.

## The fix (not implemented this session -- do this next)

1. `PathPreviewFinder` is declared in `Sim.cpp` (NOT a locked file at time
   of writing -- reverify lock state before touching), where it IS a
   complete type. Add a small helper there, e.g.
   `void DeletePathPreviewFinder(PathPreviewFinder* finder) noexcept { delete finder; }`,
   citing `0x007657D0` (the real deleting-destructor address), declared in
   whatever header `BoostWrappers.cpp` can include for `Sim.cpp`'s helpers
   (check what's already used for this file's other cross-TU exports).
2. Change `SpCountedImplPDisposePathPreviewFinder` to call that new helper
   instead of `DestroyPathPreviewFinderRuntime`/the bespoke
   `PathPreviewFinderDisposeRuntimeView` reach-in.
3. Verify `tucheck` on both `Sim.cpp` and `BoostWrappers.cpp`.
4. Check whether `PathPreviewFinderDisposeRuntimeView`/
   `DestroyPathPreviewFinderRuntime` (`BoostWrappers.cpp` ~line 2342-2380)
   become fully orphaned after this change (likely yes, since
   `SpCountedImplPDisposePathPreviewFinder` was their only caller per the
   original investigation) -- remove them too if so, same pattern as this
   session's many orphan cleanups.
5. Before committing: confirm `delete finder;` on a complete
   `PathPreviewFinder*` actually compiles to the exact same vtable-slot
   dispatch as `0x007657D0` shows (i.e., the destructor really is
   effectively at a stable, single vtable slot from the `IPathTraveler`
   base, not something requiring a manual slot number) -- this should be
   automatic given normal C++ destructor semantics, but verify rather than
   assume, per this project's own standing rule.

## Extra scoping note (checked, same session): the header question is real, not trivial

`PathPreviewFinder` is unusual among this file's wrapped types: every OTHER
type (`CDebugCanvas`, `CIntelGrid`, `STIMap`'s `CHeightField`, etc.) has its
own small dedicated header that `BoostWrappers.cpp` already includes
(confirmed: lines ~29-32 include `CDebugCanvas.h`/`CIntelGrid.h`/
`STIMap.h`/etc for exactly this reason). `PathPreviewFinder` has NO
dedicated header -- its full class declaration lives directly inline in
`Sim.cpp`, and `Sim.h` (which DOES exist separately) is NOT currently
included by `BoostWrappers.cpp`. `Sim.cpp`/`Sim.h` are large files; blindly
adding `#include "moho/sim/Sim.h"` to `BoostWrappers.cpp` risks pulling in
far more than needed and possible circular-include issues, not yet checked.

Two real options for the next pass to choose between (not decided here):
(a) add the new tiny `DeletePathPreviewFinder` helper's declaration to
`Sim.h` and check whether `Sim.h` alone (without dragging in everything
`Sim.cpp` needs) is safe for `BoostWrappers.cpp` to include, or (b) give
`PathPreviewFinder` its own small dedicated header matching every sibling
type's pattern (a bigger change -- moving the class -- but more consistent
with this file's own established convention). Check option (a) first before
committing to (b)'s larger footprint.

## Why not fixed in the same pass that found it

Needs a genuinely cross-TU change (a new helper in `Sim.cpp`, a header
`BoostWrappers.cpp` doesn't currently include for this purpose) plus
careful verification that the compiled vtable dispatch matches exactly --
not a large refactor like the AudioMap1 RB-tree bug, but still deserves a
clean, unhurried pass rather than being squeezed into an already very long
session segment.
