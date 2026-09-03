---
name: project_meshbatchkey_lod_lane_bug
description: RESOLVED (commit 3dff30e6). MeshBatchKey +0x08 carries the selected MeshLOD*, but MeshRenderer::Batch stored the collect vector's heap base there instead, so every mesh render pass read its material and hardware batch out of a fastvector<UserEntity*> buffer - untextured meshes flickering as the camera panned.
metadata:
  type: project
---

## RESOLVED — commit `3dff30e6`

`MeshBatchKey` +0x08 is the bucket's `MeshLOD*`. All four render passes
dereference it (`MeshBatchEntryLod` → `lod->mat`, `lod->GetStaticBatch` /
`GetSkinnedBatch`), but `MeshRenderer::Batch` (`0x007DFA00`) was writing
`collected.begin()` — the collect vector's heap base — into it.

Consequences, both matching operator-reported symptoms:

  - every bucket resolved its material and textures from whatever bytes sat in
    a `fastvector<UserEntity*>` buffer ⇒ **untextured / grey meshes**;
  - that address moves whenever the vector reallocates ⇒ **flicker while
    panning**;
  - the lane is also part of the map key, so with it constant every LOD of
    every mesh sharing a sort order collapsed into one bucket.

### Why the wrong value looked right

IDA split **one** stack slot into `var_1D0` and `var_1D4`, so the decompile
read `v29.lod = v26` where `v26` was a loop-invariant set before the loop. The
frame-base drift and the esp-balance test that exposes it are written up in
[[feedback_ida_frame_base_drift_splits_one_stack_slot]] — that technique is the
reusable part.

Settled by the raw displacements: `0x007DFBED  mov [esp+20h], eax` (the
`ComputeLOD` result) and `0x007DFCDC  mov eax, [esp+20h]` (the key store) are
the same slot once esp is tracked correctly, with exactly one writer and one
reader. The pre-loop `0x007DFB0D  mov [esp+18h], edx` that IDA credited to the
key is a *different* slot (E-0x1D4 vs E-0x1CC).

### Shape of the fix

The lane is now `MeshLOD* mLod` (`MeshBatchKey.h`), so `MeshBatchEntryLod` is a
plain field read and the comparator compares `std::uintptr_t`. The one writer
in `Batch` does `key.mLod = const_cast<MeshLOD*>(lod)` — `Mesh::ComputeLOD` is
`PBVMeshLOD` (pointer-to-const) but the render passes need it non-const, so the
cast has to live somewhere; the single assignment site is the cheapest place.

### Verified faithful in the same pass — do NOT re-audit

`Mesh::ComputeLOD` (`0x007DDA50`), `Mesh::GetMaxCutoff` (`0x007DDA20`, cutoff
at `MeshLOD` +0x08, `Mesh::lods` at +0x30), the `hasStanceUpdatePending`
(`v41a`) gate in `UpdateInterpolatedFields`, `RenderPlayableBoundary`
(wired from both `Cartographic.cpp` and `WxRuntimeTypes.cpp`), and
`ConfigureShader`'s water lane — `TerrainWaterResourceView::mMap` +0x04,
`mWaterEnabled` +0x1534, `mWaterElevation` +0x1538 all match the asm, and the
two fallback constants are byte-verified from the PE (`dword_E4F6E4` =
`00 40 1C C6` = -10000.0f, `dword_E4F8D8` = `00 00 7A C4` = -1000.0f).

Also closed this pass: the mesh+render subsystem has **one** open callee across
its whole annotated address set (`FUN_00815A00`, zero callers). Remaining
defects there are fidelity bugs in already-"recovered" bodies, not missing
functions — audit against ground truth, don't go looking for unrecovered
tokens.
