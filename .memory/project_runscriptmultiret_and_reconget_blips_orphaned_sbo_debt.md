---
name: project_runscriptmultiret_and_reconget_blips_orphaned_sbo_debt
description: RunScriptMultiRet finding RETRACTED 2026-09-02 (self-correction) — a sweep agent claimed it was mistyped (should take FastVectorN, takes base FastVector), but reading RunScriptMultiRet's OWN ground truth (FUN_004C7580.c) directly shows `this->finish`/`this->capacity` field access with no `originalVector`/inline-buffer reference anywhere — the base FastVector<LuaObject>& signature is very likely already correct. Do not "fix" this without new evidence. ReconGetBlips finding still stands (separately verified: genuinely zero callers, unrelated to this retraction).
metadata:
  type: project
---

## RETRACTION (2026-09-02, same session, self-correction)

The `RunScriptMultiRet` finding below was NOT independently verified before being
recorded — it rested entirely on a sweep agent's inference from `FUN_004C7CC0`/
`FUN_004C7EB0`'s shape (a Reserve-style capacity check with 20-byte elements),
without reading `RunScriptMultiRet` (`FUN_004C7580`) itself. Doing that now:

```c
char __thiscall Moho::CScriptObject::RunScriptMultiRet(
    gpg::fastvector_LuaObject *this, ...)
{
  ...
  finish = this->finish;
  if ( finish == this->capacity )
  {
    sub_4C7EB0((int)this, (int)finish, (int)&v32, (int)v33);
  }
  ...
}
```

Only `this->finish`/`this->capacity` (and, elsewhere, `this->start`/`start_`-
equivalent via `std::vector_LuaObject::clear(this)`) — the plain 3-pointer
base `FastVector<T>` field set. **No `originalVector`/inline-buffer field is
referenced anywhere in this function.** If the real parameter type were an
SBO `FastVectorN<LuaObject,N>`, this function — which directly manipulates
the vector's internals rather than going through a higher-level API — would
need to reference `originalVec_` somewhere to stay SBO-safe, exactly as
`FastVectorN::Reserve` does (see the `CUnitCommand`/`SCommandUnitSet` fix's
own note on why static-type preservation matters). It doesn't. This is a
strong signal the ORIGINAL 2007 signature genuinely took the base type, and
`FUN_004C7CC0`/`FUN_004C7EB0`'s superficial resemblance to the
`FastVectorN<LuaObject,N>` family (matching element size, matching
Reserve-shape control flow) is most likely coincidental or ICF-adjacent —
plenty of *different* 20-byte-element instantiations could produce
similar-looking capacity-check bodies without being SBO-aware at all.

**Lesson for next time**: when a sweep agent's evidence is about a callee's
shape, always also read the CALLER's own ground truth before recording the
finding — the caller's field-access pattern is the more direct evidence for
what type it was actually written against.

Do not spend further effort "fixing" `RunScriptMultiRet`'s signature without
new, decisive evidence (e.g., locating a genuine `FastVectorN<LuaObject,N>`
construction site feeding into this parameter somewhere in the binary).

# Two more instances of the FastVector-base-type SBO bug, neither currently firing

Found by the same sweep agent that found `UICommandGraph::RebuildCommandQueueNodes`
(CWldSession.cpp, live/hot-path, peer's to fix) and the already-fixed
`WaveSystem::mGeneratorCache` (8e45698c). See
[[project_lua_gc_string_table_corruption]] for the bug class and
[[project_createui_corruptor_ruled_out]]/`CDecoder::DecodeCells` (00d79258)
for the established shape: a function taking the BASE `gpg::core::FastVector<T>&`
where the real/expected caller holds an SBO `FastVectorN<T,N>`, calling
unguarded `Reserve`/`PushBack` that `delete[]`s inline storage.

## `CScriptObject::RunScriptMultiRet` — proven mistyped, currently safe

`src/sdk/moho/script/CScriptObject.h:118-126` /
`src/sdk/moho/script/CScriptObject.cpp:868-935`. Signature takes
`gpg::core::FastVector<LuaPlus::LuaObject>& out` (base). Callgraph proof
(`_callgraph_index.sqlite`): this function (`FUN_004C7580`) is the sole
caller of `FUN_004C7CC0`/`FUN_004C7EB0`, and `FUN_004C7CC0`'s decompile
(`(a2[2] - *a2) / 20`, a Reserve-style capacity check, 20 =
`sizeof(LuaPlus::LuaObject)`) matches the `FastVectorN<LuaPlus::LuaObject,N>`
family's own Reserve shape — meaning the ORIGINAL 2007 signature took the
SBO type, not the base one. `FUN_004C7EB0` is harder to pin down: its own
decompile references `TerrainTypes::ttvec` — almost certainly an ICF twin
(same 20-byte-element machine code shared across multiple `FastVectorN<T,N>`
instantiations with 20-byte T), not evidence this specific caller is about
terrain. **N (the real inline capacity) was not extracted this pass** —
would need either a constructor site for the SBO type or a fixed local
array size in one of these decompiles, and neither was found quickly enough
to justify the dig without a live trigger.

All 6 current call sites checked (`CUnitCaptureTask.cpp:403,435`,
`CUnitReclaimTask.cpp:106`, `CUnitMobileBuildTask.cpp:440`,
`UiRuntimeTypes.cpp:24667`, `CScriptObject.cpp:2747`) declare a genuinely
heap-backed plain `gpg::core::FastVector<LuaPlus::LuaObject>` local — safe
today. No `FastVectorN<LuaPlus::LuaObject,...>` exists anywhere in
recovered source yet, so the mistyped signature can't currently be
exercised unsafely. **Landmine for the next caller** who reasonably assumes
the signature accepts an SBO vector (since that's genuinely more efficient
for a small multi-return count) and gets bitten.

## `CAiReconDBImpl::ReconGetBlips` — same shape, fully orphaned

`src/sdk/moho/ai/CAiReconDBImpl.cpp:2229-2266` (declared
`CAiReconDBImpl.h:189,195`, `IAiReconDB.h:113,120`). Both overloads take
`gpg::core::FastVector<Entity*>*` (base) and call `PushBack`. Zero
source-level callers anywhere in `src/sdk/**` — only the unrelated
zero-arg `ReconGetBlips()` (returns `msvc8::vector<ReconBlip*>&`, a
completely different method) is actually called
(`CAiBrain.cpp:2130`, `CPlatoon.cpp:4405`). Fully dead code today.

## Why not fixed this pass

Neither is live. Fixing `RunScriptMultiRet` properly requires nailing down
N first (real investigative work, not just a mechanical edit) and then
updating all 6 call sites' local variable types to match — a real but
not urgent task. `ReconGetBlips` is genuinely unreachable, so there's
nothing to fix except the type signature itself (lower priority than a
function anything actually calls).

## If resuming

1. For `RunScriptMultiRet`: find `FUN_004C7580`'s OWN caller context or a
   sibling `FastVectorN<LuaPlus::LuaObject,N>` instantiation elsewhere in
   the binary to pin N, then change the signature and all 6 call sites
   together in one pass (mirroring the `CDecoder::DecodeCells`/
   `CUnitCommand::SCommandUnitSet` fix shape).
2. For `ReconGetBlips`: lower priority given zero callers; fix only if/when
   a real caller is recovered that would need it, per the source-level
   invocation rule (CLAUDE.md) — don't wire it up speculatively.
