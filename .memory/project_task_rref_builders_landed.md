---
name: project-task-rref-builders-landed
description: 11 gpg::RRef_C<Task> builders landed (cf4a925); the vein is now drained and the elided-inline-RRef pattern it fixed.
metadata:
  type: project
---

Landed `cf4a925` (+ README `891e6ac`): eleven `gpg::RRef_C<T>` reflection-reference
builders — CFactoryBuildTask, CUnitCaptureTask, CUnitCarrierLand/Launch/Retrieve,
CUnitGuardTask, CUnitMobileBuildTask, CUnitRepairTask, CUnitSacrificeTask,
CUnitTeleportTask, CUnitUpgradeTask.

**The pattern worth remembering.** Each `C<T>TypeInfo::NewRef`/`::CtrRef` was
"recovered" building its `gpg::RRef` inline from a file-local
`Cached<T>Type()` helper:

```cpp
return gpg::RRef{task, CachedCUnitRepairTaskType()};   // WRONG
```

The binary does not do that — it pushes the object and a stack RRef and
`call gpg::RRef_C<T>`, a separate function the linker kept. Inlining it silently
dropped the whole builder: the exact-type fast path, the TLS three-slot
`type_info -> RType*` MRU cache, and — the real bug — the
`IsDerivedFrom(runtime, declared, &off)` base-offset adjustment plus its
`isDer` assert (`reflection.h:458`). A reflected ref to a *derived* task
therefore carried an unadjusted object pointer.

**Where these live.** In `Reflection.cpp`, alongside 221 existing `RRef_*`
siblings, on the shared anon-namespace `BuildTypedRefWithCache<T>` template
(~line 780) with a `gC<T>RRefType` + `thread_local TypeInfoCache3 gC<T>RRefCache`
pair. That template is the faithful one. Do **not** copy the lossy local
`MakeDerivedRef` template found in `CUnitRefuel.cpp` — it has no fast path, no
MRU cache, and swallows the non-derived case instead of asserting.

**Vein status: drained.** One `gpg::RRef_*` token remains open,
`FUN_00705320 RRef_EntitySetTemplate_Unit`, and it is correctly blocked — both
its callers (`sub_701850`, `sub_7042E0`) are themselves blocked with no source,
so recovering it would orphan it.

Two traps hit while doing this:

- **`PackRRef_*` lanes have zero xrefs.** The `sub_*` third caller of each
  builder is a `__usercall` pack lane with `xrefs_total: 0`. They are not
  recoverable under the callsite rule; the two that already exist in
  `Reflection.cpp` are pre-existing orphans, not a precedent.
- **CRLF byte quirk.** Ten of the eleven `*TypeInfo.cpp` blobs carry exactly one
  lone `\r` and one bare `\n` in the include block, which makes git treat them as
  binary. A scripted edit that normalizes them turns a 15-line diff into a
  400-line whole-file rewrite. Preserve the quirk. See
  [[reference_crlf_binary_blob_hazard]].
