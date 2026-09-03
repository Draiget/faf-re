---
name: project-silhouette-render-pair
description: STALE/DONE (confirmed 2026-08-18) - Silhouette::Render + MeshRenderer::RenderSilhouette are both recovered (Silhouette.cpp:118, Mesh.cpp:7000) and wired into WRenViewport::Render (WxRuntimeTypes.cpp:65240, gated by ren_UnitSilhouette). Nothing left to do here; landed by another agent in this shared tree after this note was written.
metadata:
  type: project
---

**CONFIRMED DONE 2026-08-18.** Both functions exist in source and the call
site is wired (`silhouetteHost->mSilhouetteRenderer.Render(*silhouetteHost->mCam,
silhouetteHost->mHead)`, `WxRuntimeTypes.cpp:65240`). Checked while looking
for independent work during the CRenderWorldView/terrain recovery session -
do not re-investigate this target, it's finished. Original note preserved
below for archaeology only.

A clean, goal-aligned rendering target found by filtering the candidate pool
for named engine calls rather than address ranges.

| Function | Address | Instrs | State |
|---|---|---|---|
| `Moho::Silhouette::Render` | 0x00814820 | 80 | ABSENT |
| `Moho::MeshRenderer::RenderSilhouette` | 0x007E0830 | 369 | ABSENT |

**Both are fully unblocked on the callee side**: `RenderSilhouette`'s
unrecovered closure is **1** (itself), and `Silhouette::Render`'s only other
callees - `D3D_GetDevice` (0x00430590) and `MeshRenderer::GetInstance`
(0x007E16C0) - are already recovered.

The caller is real: `WRenViewport::Render` (0x007F90D0), a genuine recovered
body at `WxRuntimeTypes.cpp:64862`, and `WRenViewport` already carries a
`moho::Silhouette mSilhouetteRenderer` member at +0x2134. `Silhouette.h`
exists.

## Silhouette::Render body (decoded)

    renderer = MeshRenderer::GetInstance();
    device   = D3D_GetDevice();
    // camera.mViewport row 3 holds (x, y, w, h)
    device->SetRenderTarget2(target, 0, 0, 1.0f, 0);
    device->SetViewport({x, y}, {w, h}, 0.0f, 1.0f);
    renderer->RenderSilhouette(camera);
    device->SelectFxFile("frame");
    device->SelectTechnique("TSilhouette");
    device->Func12({this->v1, 0, 0, 3}, {5});

**Watch the argument order**: IDA prints
`RenderSilhouette((MeshRenderer *)a1, (GeomCamera3 *)Instance)` with the two
swapped - `a1` is the camera (in `edi`), `Instance` is the renderer. The real
call is `renderer->RenderSilhouette(camera)`. Likewise `this` is the *stack*
argument `a2`, not `edi`.

## Why it is not landed yet

`RenderSilhouette` is a full mesh-batch pass (237 decompiled lines): sets the
environment matrices, selects the `"mesh"` fx file and the `"Occlude"`
technique, walks mesh LODs drawing skinned/static batches, then switches to the
`"Silhouette"` technique and draws again.

It calls `struct_ShaderVar::GetTexture`, which
[[project-shadow-layout-resolved]] lists as having a wrong signature. **That
note is stale**: `ShaderVar.h:44-58` now declares
`GetTexture(const boost::shared_ptr<ID3DTextureSheet>&)` and documents at
length why the parameter is the interface rather than IDA's concrete-type
guess, including that the old `weak_ptr<TextureD3D9>` modelling was replaced.
Treat the API as sound and re-check the shadow-layout note's open item before
acting on it.

So the only thing left is the size of the job: 369 instructions of mesh-batch
rendering, which needs a run with room to verify the surrounding
MeshLOD/MeshBatch API rather than the tail of one.

**Order of work:** land the pair bottom-up - `RenderSilhouette`, then
`Silhouette::Render`, then the call from `WRenViewport::Render`.

## How this candidate was found (reusable)

The plain closure-ranked pool is swamped by compiler emissions. Filtering the
decompiled `.c` works much better:

  - reject if it matches `sp_counted_base|_InterlockedExchangeAdd|fastvector|
    _Myfirst|_Mylast|std::_Tree|_Isnil|weak_release` more than once
    (shared_ptr/vector/tree emissions),
  - require at least 2-3 distinct `Moho::X::Y` / `gpg::X::Y` / `func_*`
    references (real engine calls),
  - 55-350 instructions, address in 0x00500000-0x00A00000, with a recovered
    code xref.

That reduced ~460 raw candidates to 12 genuinely behavioural ones. Note the
raw-arithmetic container lanes (`/ 60`, `/ 0xFFFFFFFC` element strides) slip
past the marker regex - check the body before writing.

## RenderSilhouette decoded (2026-08-17) - write it against RenderCartographic

**`MeshRenderer::RenderCartographic` (`Mesh.cpp:6843`) is the template.** It is
the adjacent emission (0x007E0380 vs 0x007E0830), already recovered to a high
standard, and `RenderDepth` (0x007E03B0) is documented there as "structurally
the same RB-tree walk" with a different gate/technique/samplers. Silhouette is
the third member of that family.

**IDA swaps `this` and `a2` in this function too** (same trap as
`Silhouette::Render`). The signature is
`RenderSilhouette(MeshRenderer *this, const GeomCamera3 *a2)` but the body uses
`this` for camera fields and `a2` for renderer fields. Proof: `(int)this + 660`
= 0x294 = `GeomCamera3::viewport.r[1]`, which is exactly what
`RenderCartographic` passes to `sv.lodBasis`; and
`a2->mViewProjection.d[0].d[2]` is the batch tree, i.e.
`MeshRenderer::meshes` (`MeshBatchBucketTree` at **+0xA0**, `Mesh.h:1341`).

Pass head - identical to RenderCartographic's, minus the elevation/time lanes:

    if (sv.lodBasis.Exists())    SetShaderVarMem(sv.lodBasis, 4, &camera.viewport.r[1].x);
    if (sv.viewMatrix.Exists())  sv.viewMatrix.SetMatrix4x4(&camera.view);        // IDA: mEnvironment.v22
    if (sv.projMatrix.Exists())  sv.projMatrix.SetMatrix4x4(&camera.projection);  // IDA: mEnvironment.mName._Mysize
    device->SelectFxFile("mesh");        // vtbl +80
    device->SelectTechnique("Occlude");  // vtbl +84

Then **two** walks of `meshes` (`head->left` .. `head`, via the same
`MeshBatchTreeSuccessor` helper RenderCartographic uses):

  1. **Occlude pass** - per node: `lod = MeshBatchEntryLod(node)`, gated on a
     MeshLOD byte (IDA `v7->v26b` - resolve which field before writing; it is
     on the LOD, not the material, unlike Cartographic's
     `mAuxTag0.size()`), binds **only** the albedo sampler
     (`tv.albedoTexture.GetTexture(material.mAlbedoSheet)`), then draws via
     `GetSkinnedBatch`/`GetStaticBatch` chosen by `MeshBatchEntryIsSkinned(node)`.
  2. `device->SelectTechnique("Silhouette")`, then the **same walk again**.

The ~120 lines of `_InterlockedExchangeAdd` / vtable-slot-4/8 noise between the
two walks is `boost::shared_ptr<MeshBatch>` retain/release around each draw -
it disappears entirely in C++, exactly as it does in RenderCartographic's
`boost::shared_ptr<MeshBatch> batchHandle`.

**Remaining lookups before writing:** the MeshLOD gate field behind `v26b`, the
`Silhouette` class's `v1` member used by `Silhouette::Render`'s final
`Func12({v1,0,0,3},{5})` call, and whether `WRenViewport::Render` already has a
silhouette pass slot to wire into.

### The two gates are DIFFERENT bytes (the decompile hides this)

`FUN_007E0830.c` shows `if (v7->v26b)` for both walks, which reads as one flag.
The asm disagrees:

    0x007E0913  cmp byte ptr [esi+0ADh], 0    <- Occlude pass gate
    0x007E0A93  cmp byte ptr [esi+0AEh], 0    <- Silhouette pass gate

Two adjacent, independent bytes. Writing one flag for both would silently draw
the wrong set of meshes in one of the passes.

`esi` is the `MeshLOD`, and `MeshMaterial mMat` sits at **LOD+0x0C** - derived
from the `RenderDepth` note already in `Mesh.cpp`, which records
`mAlbedoSheet at esi+0x2C = mMat+0x20` (so 0x2C - 0x20 = 0x0C). That puts the
two gates at **mMat+0xA1 and mMat+0xA2**, siblings of the existing
`mRuntimeFlag0` (cartographic) and `mRuntimeFlag1` (depth) lanes. Confirm both
against `MeshMaterial`'s current field list and name them for their passes
before writing.

Unlike the cartographic/depth passes there is no lazily-resolved technique
string here: the techniques are the literals `"Occlude"` and `"Silhouette"`,
selected once per walk, and the per-LOD byte is used directly as the draw gate.

### Silhouette::Render's final draw

`Silhouette` has exactly one member, `boost::shared_ptr<ID3DVertexSheet>
mQuadVertexSheet` at **+0x04** (`Silhouette.h:81`), so the emission's
`v15 = a2->v1` is that sheet's pointer word and the trailing
`Func12({sheet, 0, 0, 3}, {5})` draws the fullscreen quad through it.

