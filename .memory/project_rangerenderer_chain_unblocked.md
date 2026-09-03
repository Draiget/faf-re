---
name: project-rangerenderer-chain-unblocked
description: RangeRenderer.cpp holds 19 orphan helpers because its three top-level drivers were never recovered. Everything beneath them exists and is typed - all layouts verified 2026-08-17. It is a transcription job, but must land atomically.
metadata:
  type: project
---

`src/sdk/moho/render/RangeRenderer.cpp` carries **19 `[[maybe_unused]]`
helpers**. They are orphans for one reason: the three functions that would
call them were never recovered.

    0x007EEA00  ???  RangeRenderer::Render     <- NOT in source (comment only)
    0x007EF5A0  326  func_RenderRings          <- only the geometry head, as
                                                  PrepareRenderRingsGeometryPass (orphan)
    0x007EF9B0  274  func_Draw_Rings           <- absent

The chain is strict: `Draw_Rings` is the **only** caller of
`func_GetRangeEffect` (0x007EC320, in source as
`AcquireRangeRingBaseEffect`, orphaned), and `RenderRings` is the only
caller of `Draw_Rings`. So no single one of them can land without adding
another orphan. **All three go together or none do.**

## Everything underneath is present and typed (verified)

This was previously thought blocked on the GAL effect API. It is not -
see the retraction in [[project-gal-effect-api-gate]]. Confirmed present:

    EffectD3D9::SetTechnique(const char*)   -> shared_ptr<EffectTechniqueD3D9>
    EffectD3D9::SetMatrix(const char*)      -> shared_ptr<EffectVariableD3D9>
    EffectVariableD3D9::SetMatrix4x4(const void*)      (vtable slot 5)
    EffectTechniqueD3D9::BeginTechnique/BeginPass/EndPass/EndTechnique
    DeviceD3D9::SetVertexDeclaration(shared_ptr<VertexFormatD3D9>)
    DeviceD3D9::SetVertexBuffer(slot, buffer, streamFrequencyToken, streamOffsetMultiplier)
    DeviceD3D9::SetBufferIndices(shared_ptr<IndexBufferD3D9>)
    DeviceD3D9::DrawIndexedPrimitive(const void*)
    DrawIndexedContext(int topology, int numVertices, int primCount, int startIndex, int baseVertIndex)

## The two parameter structs, pinned by offset

`func_Draw_Rings(a1@<ecx>, a2@<edi>, ...)`:

**`a1` is `GeomCamera3*`.** It reads `a1+0x1C` and `a1+0x5C`, and
`GeomCamera3` declares `projection // +0x01C` and `view // +0x05C` -
exact match, and they are 0x40 apart as two contiguous matrices.

**`a2` is `RangeRenderer*`.** Every field lines up:

    a2[8]  = +0x20  mIndexCount
    a2[9]  = +0x24  mVertexCount
    a2[10] = +0x28  mGeometry.mVertexFormat   (RenderGeometryBuffers +0x00)
    a2[12] = +0x30  mGeometry.mVertexBuffer   (             "        +0x08)
    a2[14] = +0x38  mGeometry.mIndexBuffer    (             "        +0x10)
    a2[17] = +0x44  mDynamicVertexBuffer
                    +0x4C  mFrame (CRenFrame) - matches `a3+76` in RenderRings

Only `a7`/`a8` of the invented `__userpurge` parameter list are actually
used; `a3`-`a6` are never referenced in the body.

## The body, decoded

    device   = Device::GetInstance()
    effect   = GetRangeEffect()
    technique = effect->SetTechnique("Cast")
    viewVar   = effect->SetMatrix("viewMatrix")
    projVar   = effect->SetMatrix("projMatrix")
    viewVar->SetMatrix4x4(&camera.view)          // a1+0x5C
    projVar->SetMatrix4x4(&camera.projection)    // a1+0x1C
    device->SetVertexDeclaration(mGeometry.mVertexFormat)
    device->SetVertexBuffer(0, mGeometry.mVertexBuffer, a7, 0)
    device->SetVertexBuffer(1, mDynamicVertexBuffer,     1, a8)
    device->SetBufferIndices(mGeometry.mIndexBuffer)
    for (pass in 0 .. technique->BeginTechnique())
        technique->BeginPass(pass)
        DrawIndexedContext ctx(D3DPT_TRIANGLELIST, mVertexCount, mIndexCount, 0, 0)
        device->DrawIndexedPrimitive(&ctx)
        technique->EndPass()
    technique->EndTechnique()

Both variables are fetched **before** either is set - keep that order.

The stream-0/stream-1 split with frequency `a7` on stream 0 and `1` on
stream 1 is hardware instancing: stream 0 the ring mesh, stream 1 the
per-ring data, `a8` the chunk's start offset. `RenderRings` calls
`Draw_Rings` in a **1000-ring chunk loop**, which is where a7/a8 come
from - confirm their exact provenance from that loop before naming them.

## IDA stack-slot reuse trap in this function

`SetMatrix(eff, &a1a, "viewMatrix")` writes the variable handle into the
same stack slot that held the effect shared_ptr, so the decompile then
shows `a1a.eff->OnReset(a1a.eff, a1+92)`. That is **not** `OnReset` - it
is the *variable's* slot 5, `SetMatrix4x4`, exactly matching the sibling
line `(*(v33+20))(v33, a1+28)` (20/4 = slot 5). Do not transcribe the
literal `OnReset`.
