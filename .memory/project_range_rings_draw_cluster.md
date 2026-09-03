---
name: project-range-rings-draw-cluster
description: func_Draw_Rings (274 instrs) + the unrecovered tail of func_RenderRings - a visible range-ring render feature, fully decoded except the identity of the GPU bundle passed in edi.
metadata:
  type: project
---

A tight, goal-aligned cluster (visible rendering): `func_Draw_Rings`
(**FUN_007EF9B0**, 274 instrs, absent) plus the unrecovered tail of
`func_RenderRings` (**FUN_007EF5A0**, 326 instrs). Only other missing callee is
`std::string::string` (CRT). Closure is otherwise 1.

## Callsite evidence (verified, evidence class 1)

Two `kind=code` incoming xrefs at **0x007EF7E5** and **0x007EF8C7**, both
*inside* `func_RenderRings` - real mid-function call sites, not the
function-start pattern that makes `call_edges.src_ea` untrustworthy. Called
twice: once for the fill rings, once for the edge rings.

**But the caller is only half recovered.** `RangeRenderer.cpp:370` has
`PrepareRenderRingsGeometryPass`, a `[[maybe_unused]]` **orphan** that covers
only the geometry-preparation head and says outright that "the downstream
dynamic-buffer draw/stencil frame passes remain in the unrecovered tail lane".
Both call sites live in that tail. So this is a **paired** recovery: land the
tail of `func_RenderRings` and `func_Draw_Rings` together, or the new body is
another orphan.

Note `RangeRenderer.cpp` is the file with the fabrication history
([[project-fabricated-recovery-and-container-dup]]) - re-verify what is already
there rather than building on it.

## func_Draw_Rings body (decoded; mirrors Cartographic.cpp:1104-1137)

    device   = gal::Device::GetInstance()
    effect   = func_GetRangeEffect()                  // shared_ptr<EffectD3D9>
    tech     = effect->SetTechnique("Cast")
    effect->SetMatrix("viewMatrix")->SetMatrix4x4(&camera.view)         // a1+0x5C
    effect->SetMatrix("projMatrix")->SetMatrix4x4(&camera.projection)   // a1+0x1C
    device->SetVertexDeclaration(bundle@0x28)
    device->SetVertexBuffer(0, bundle@0x30, a7, 0)
    device->SetVertexBuffer(1, bundle@0x44, 1, a8)
    device->SetBufferIndices(bundle@0x38)
    for (i = 0; i < tech->BeginTechnique(); ++i) {
      tech->BeginPass(i);
      DrawIndexedContext ctx(D3DPT_TRIANGLELIST, bundle@0x24, bundle@0x20, 0, 0);
      device->DrawIndexedPrimitive(&ctx);
      tech->EndPass();
    }
    tech->EndTechnique();

`a1@<ecx>` is **`const GeomCamera3*`** - confirmed, `projection` is at +0x01C and
`view` at +0x05C in `GeomCamera3.h`, exactly the two offsets the body loads.
The bulk of the 165 decompiled lines is `shared_ptr` release boilerplate that
disappears in C++.

## The one open question: what is `a2@<edi>`?

It is `func_RenderRings`' own `arg_0`, forwarded (`mov edi,[esp+70h+arg_0]` at
0x007EF791). Field use implies:

    +0x20 uint32   primitive-count input   -> DrawIndexedContext arg 3
    +0x24 uint32   vertex count            -> DrawIndexedContext arg 2
    +0x28 shared_ptr<VertexDeclaration>
    +0x30 shared_ptr<VertexBuffer>   (stream 0)
    +0x38 shared_ptr<IndexBuffer>
    +0x44 shared_ptr<VertexBuffer>   (stream 1)

**It is NOT `CRenFrame`.** IDA declares `Moho::CRenFrame *v28; // edi` in
`func_RenderRings`, which is tempting, but `CRenFrame` has `mWidth`/`mHeight`
floats at +0x20/+0x24 and `shared_ptr<ID3DRenderTarget>` at +0x28/+0x30/+0x38 -
incompatible with counts and vertex buffers. IDA just reused the register.

Identify the bundle before writing anything. `[edi+0x44]` also takes a virtual
call at slot +0x0C right before each `func_Draw_Rings` call
(0x007EF7CE-0x007EF7D9), which should pin the type.

## Refinements (same session)

**Call chain:** `Moho::RangeRenderer::Render` (FUN_007EEA00, the public entry
declared at `RangeRenderer.h:154`) -> `func_RenderRings` -> `func_Draw_Rings`.
Other `func_RenderRings` callers: `func_RenderBuildRings` (FUN_007EEE50),
`sub_7EF420`, and `sub_128E217`. So the bundle originates in
`RangeRenderer::Render` and is threaded down as `arg_0`.

**The bundle is the Cartographic geometry set, one for one.** Immediately before
each `func_Draw_Rings` call the caller does `memcpy` then a virtual call at
vtable slot 3 (+0x0C) on `[edi+0x44]` (0x007EF7CE-0x007EF7D9) - the standard
dynamic-vertex-buffer lock/fill/**Unlock** sequence. Combined with the field
map, `a2` holds exactly what `Cartographic` holds as members:

    +0x28  vertex declaration      <-> Cartographic::mVertexFormat
    +0x30  static VB, stream 0     <-> Cartographic::mQuadVertexBuffer
    +0x38  index buffer            <-> Cartographic::mIndexBuffer
    +0x44  dynamic VB, stream 1    <-> Cartographic::mInstanceVertexBuffer

and `Cartographic::RenderDecals` (`Cartographic.cpp:1104`) is the working
recovered template for the whole draw - same `SetVertexDeclaration` /
two `SetVertexBuffer` / `SetBufferIndices` / BeginTechnique-pass-loop shape.

**Still open:** the concrete C++ type of the bundle. `RangeRenderer` itself is
not it (the class carries no laid-out fields), and `CRenFrame` is ruled out
above. Next step is to read `RangeRenderer::Render` (FUN_007EEA00) and see what
it constructs/passes as the third `__fastcall` argument.

**Ruled out: `Cartographic` / `CartographicDecalBatch`.** `RangeRenderer::Render`
does take a `Moho::Cartographic*` (in `ebx`, forwarded to `func_RenderRings` as
`edx0`), so it is tempting - but `CartographicDecalBatch` puts the same four
resources at +0x44/+0x4C/+0x54/+0x5C, four consecutive 8-byte `shared_ptr`s,
whereas the bundle has decl/VB0/IB consecutive at +0x28/+0x30/+0x38, a gap at
+0x40, then the dynamic VB at +0x44. Same design, different type.

So the bundle is an **unmodelled range-ring render batch**, and it arrives as
`RangeRenderer::Render`'s third `__fastcall` argument, pushed from `ebp`
(`_DWORD *v5`) at 0x007EEAF3. Confirmed signature:

    void __userpurge Moho::RangeRenderer::Render(
        CWldSession *a1@<ecx>, Cartographic *a2@<ebx>,
        RangeRenderer *a3, unsigned int a4, float a5)

Best model so far:

    +0x20  uint32                              primitive-count input
    +0x24  uint32                              vertex count
    +0x28  shared_ptr<gal::VertexFormatD3D9>   vertex declaration
    +0x30  shared_ptr<gal::VertexBufferD3D9>   static ring geometry, stream 0
    +0x38  shared_ptr<gal::IndexBufferD3D9>    index buffer
    +0x40  ?                                   (4-8 bytes, unread by the draw)
    +0x44  shared_ptr<gal::VertexBufferD3D9>   dynamic instance VB, stream 1

**Resume here:** trace `ebp`/`v5` back through `RangeRenderer::Render`
(FUN_007EEA00) to its construction site to name the type, then land the pair.

## RESOLVED: the bundle is the `RangeRenderer` itself, and it is already modelled

`ebp` is `Render`'s own `arg_0` (`mov ebp,[esp+198h+arg_0]` at 0x007EEA1C),
which IDA types `Moho::RangeRenderer *`. Every derived offset matches the
existing declaration in `RangeRenderer.h` exactly:

    mIndexCount              +0x20   -> DrawIndexedContext arg 3
    mVertexCount             +0x24   -> DrawIndexedContext arg 2
    mGeometry                +0x28   RenderGeometryBuffers: decl +0x28, VB0 +0x30, IB +0x38
    mDynamicRingVertexCount  +0x40   (the "gap")
    mDynamicVertexBuffer     +0x44   dynamic instance VB, stream 1
    mFrame                   +0x4C   CRenFrame

That last field is also the source of the `CRenFrame *v28 // edi` red herring -
`CRenFrame` really is in there, just at +0x4C rather than at 0.

**So there is NO layout work left. The cluster is fully unblocked**: write
`func_Draw_Rings` as a `RangeRenderer` member against `mGeometry` /
`mDynamicVertexBuffer` / `mIndexCount` / `mVertexCount`, modelled on
`Cartographic::RenderDecals` (`Cartographic.cpp:1104-1137`), taking
`const GeomCamera3&`; then recover the tail of `func_RenderRings` so both call
sites (0x007EF7E5, 0x007EF8C7) invoke it by name and
`PrepareRenderRingsGeometryPass` stops being a `[[maybe_unused]]` orphan.
The two trailing stack args a7/a8 are the stride/offset operands of the two
`SetVertexBuffer` calls - read them off the call sites when writing.

### Two loose ends for the writing pass

- `func_GetRangeEffect` (0x007EC320) is **already recovered**
  (`RangeRenderer.cpp:45`), so the effect lookup is a direct call.
- The two trailing stack operands are the only ones the body reads (IDA's
  `arg_10` / `arg_14` at 0x007EFA98 / 0x007EFAD2); they feed
  `SetVertexBuffer(0, VB0, a7, 0)` and `SetVertexBuffer(1, VB1, 1, a8)`. The
  call sites push exactly two values (`push eax` = a saved count, `push esi` =
  a running offset that advances by `ebp` between the two draws - see
  `add esi, ebp` at 0x007EF8CC). **Do not trust IDA's `arg_0..arg_C` names in
  this frame** - it reuses `arg_0` as the EH state slot
  (`mov [esp+58h+arg_0], 1/2/3`). Recompute the frame offsets when writing.

## Attempt 1 (batch 59): body written, then backed out - read this before retrying

`DrawRangeRingBatch` was written against the confirmed layout and **is correct**
- patch saved at
`<scratchpad>/rangerenderer_drawbatch.patch` (reverse-applied cleanly, tree left
untouched). It was backed out because it would have been a **new orphan**, and
the chain needed to un-orphan it is bigger than it first looked:

  - `RangeRenderer::Render` (FUN_007EEA00, 196 instrs) is **not recovered**.
  - `func_RenderRings`' only src presence is the orphan prepare head.
  - `RangeRenderer.cpp` already contains **three** `[[maybe_unused]]` orphans in
    this exact lane - `PrepareRenderRingsGeometryPass`,
    `ReserveDynamicRingVertexSliceRuntime`, `AcquireRangeRingBaseEffect`. A real
    `func_RenderRings` wires up all three at once, which is the real prize here.

The connected root does exist: `WRenViewport::D3DWindowOnDeviceRender` ->
`WRenViewport::Render` (both genuinely recovered, `WxRuntimeTypes.cpp:64862`)
-> `RangeRenderer::Render`. So the atomic landing is **three** bodies:
`RangeRenderer::Render` + full `func_RenderRings` + `DrawRangeRingBatch`,
wired into `WRenViewport::Render`.

**The blocker to resolve first is `func_RenderRings`' signature.** From the call
site in `RangeRenderer::Render` (0x007EEADE-0x007EEAF6) the arguments are:

    ecx  = esi + 8            a1  (float* - ring radius params)
    edx  = ebx               edx0 (the Cartographic*)
    push ebp                 a3   (the RangeRenderer)
    push idx                      viewport head index
    push esi - 0x30          a5
    push esi                 result
    push &i                       (a pointer to a local)

Three of those are offsets off one unidentified `esi` object, so **identify
`esi` in `RangeRenderer::Render` before writing** - guessing the parameter roles
in a file with a fabrication history is exactly how bad recoveries get made.
Also note `edx0`'s vtable is used as: slot 2 -> the `GeomCamera3` passed to the
draw, slot 19 (+76) and slot 20 (+80) -> two floats whose ratio is the zoom
scale.

## BLOCKER RESOLVED: func_RenderRings' signature

`RangeRenderer::Render` iterates `mVisibleProfiles` with a **136-byte stride**,
and `sizeof(SRangeRenderProfile) == 0x88 == 136`. The "esi-relative" arguments
are simply interior references into one profile (`v10` = profile + 120):

    func_RenderRings(v10 + 8, a2, v5, v28, v10 - 48, v10, &v19)
      v10 + 8   = profile + 0x80  -> SRangeRenderProfile::mOuterRingParams
      a2                          -> Cartographic*
      v5                          -> RangeRenderer*
      v28                         -> viewport head index
      v10 - 48  = profile + 0x48  -> mBuildRingColor, first of the three
                                     consecutive RangeRingColor entries
                                     (build/selected/highlighted) - i.e. a
                                     3-element color array
      v10       = profile + 0x78  -> mInnerRingParams
      &v19                        -> the RangeExtractionPayloadVector that
                                     func_ExtractRanges just filled

So the C++ signature is:

    void RenderRings(
      const RangeRingRadiusParams& outerRingParams,
      Cartographic& cartographic,
      RangeRenderer& renderer,
      unsigned int viewportHeadIndex,
      const RangeRingColor* ringColors,          // 3 entries
      const RangeRingParams& innerRingParams,
      RangeExtractionPayloadVector& extractedRanges);

The enclosing loop in `RangeRenderer::Render` is:

    for (auto& profile : renderer.mVisibleProfiles) {
      func_ExtractRanges(&ctx, zoom, &profile, &extracted);
      RenderRings(profile.mOuterRingParams, cartographic, renderer, head,
                  &profile.mBuildRingColor, profile.mInnerRingParams, extracted);
    }

guarded by `mVisibleProfiles` being non-empty, and preceded by
`cartographic` vtable slot 2 plus `sub_7F03D0` context setup.

**Nothing is unknown now.** The next pass can write all three bodies
(`RangeRenderer::Render`, `func_RenderRings`, `DrawRangeRingBatch` - the last
one already written and saved as a patch), wire them into the recovered
`WRenViewport::Render`, and un-orphan the three existing `[[maybe_unused]]`
helpers in one commit.

## Final typings (nothing left unknown)

- **`edx0` is a `CameraImpl*`, not a `Cartographic*`.** IDA mistypes it; our
  header was right all along (`RangeRenderer::Render(CWldSession*, CameraImpl*,
  unsigned, float)`). Proof: the three vtable uses map exactly onto
  `CameraImpl.h` -

      slot 2  (+0x08)  const GeomCamera3& CameraGetView() const
      slot 19 (+0x4C)  float CameraGetTargetZoom() const
      slot 20 (+0x50)  float GetMaxZoom() const

  so `zoomScale = camera.CameraGetTargetZoom() / camera.GetMaxZoom()` - a
  normalised zoom fraction scaling the ring thickness, exactly what the existing
  `PrepareRenderRingsGeometryPass` already takes as its `zoomScale` parameter.
- `std::string::string(a3 + 76, "RangeMask", 9)` is **`renderer.mFrame.mName =
  "RangeMask"`** - `CRenFrame::mName` is at +0x00 and `mFrame` at +0x4C.
  The frame passes run in order: `RangeMask`, then the edge draws, then
  `RangeFill` (guarded by `moho::range_Fill`), then `RangeBurn`, then
  `device->Clear(0, 0, 1, -1, 1.0f, 0)`.
- The `ringColors` argument feeds
  `shaderVarFrameRangeColor->SetMem(4, colors)` when
  `ShaderVar::Exists(&shaderVarFrameRangeColor)` - 4 floats, i.e. the first
  `RangeRingColor`.
- Both chunked loops clamp to `kDynamicVertexCapacity` (1000) and copy
  `kDynamicVertexStrideBytes` (16) per entry - both constants already exist at
  the top of `RangeRenderer.cpp`. The edge loop runs over `2 * ringCount`
  entries (inner + outer edge per ring).

## Attempt 2 (2026-08-17): DrawRangeRingBatch compiles; tail structure decoded

`DrawRangeRingBatch` was written **as a RangeRenderer member** against the
confirmed layout and reaches `tucheck EXITCODE=0`. Patch saved at
`<scratchpad>/rangerenderer_drawbatch_v2.patch` (117 lines, reverse-applies
cleanly). Reverted again for the same reason as attempt 1 - it is still an
orphan until `func_RenderRings` lands - but two things are now settled that
were not before:

  - **`RangeRenderer.h` needs `struct GeomCamera3;` forward-declared.** It has
    only `CWldSession` and `CameraImpl`. Without it the whole member
    declaration fails to parse and the errors cascade into the body as
    "illegal reference to non-static member", which looks like a scoping bug
    and is not.
  - **`RangeRenderer.cpp` needs four more includes**: `gpg/gal/DrawIndexedContext.hpp`
    and the d3d9 `EffectD3D9` / `EffectTechniqueD3D9` / `EffectVariableD3D9`
    headers. It currently has only the device/buffer ones.
  - A `kRangeRingTopologyTriangleList = 4u` constant belongs next to the
    existing `kDynamicVertexCapacity` / `kDynamicVertexStrideBytes`.

### func_RenderRings tail - exact pass order (from the decompile)

    <geometry prep - already recovered as PrepareRenderRingsGeometryPass>
    fill loop over ringCount, chunked to kDynamicVertexCapacity:
        sub_7EEDC0(&slice)                    // reserve a dynamic VB slice
        memcpy(slice, &fillPayloads[16*i], 16*chunk)
        mDynamicVertexBuffer->Unlock()        // vtable slot 3 (+0x0C) on a3+68
        func_Draw_Rings(camera, renderer, chunk, sliceOffset, ...)
    CRenFrame::InitTransformedVerts(&renderer.mFrame, width, height)
    renderer.mFrame.mName = "RangeMask";  mFrame.Render(width, height)
    edge loop over 2*ringCount, same shape, over edgePayloads
    if (range_Fill) { mFrame.mName = "RangeFill"; mFrame.Render(w, h); }
    if (ShaderVar::Exists(&shaderVarFrameRangeColor))
        shaderVarFrameRangeColor->SetMem(4, ringColors)
    mFrame.mName = "RangeBurn";  mFrame.Render(w, h)
    device->Clear(0, 0, 1, -1, 1.0f, 0)

**Remaining unknowns for the next attempt** (all small, none layout):
`sub_7EEDC0` is the dynamic-slice reserve and should map onto the existing
`ReserveDynamicRingVertexSliceRuntime` orphan - confirm the mapping rather
than writing a second one; and `idxa`, the object supplying `mWidth`/`mHeight`
to `InitTransformedVerts` and `CRenFrame::Render`, still needs identifying
(it is indexed by the viewport head index argument).

## Attempt 3 (2026-08-17): two of three bodies compile; Render needs 2 more leaves

Saved at `<scratchpad>/rangerings_chain_v3.patch` (316 lines, reverse-applies
cleanly). Reverted only because `RenderRings` has no caller yet. What now
**compiles at EXITCODE=0**:

  - `RangeRenderer::DrawRangeRingBatch` (0x007EF9B0)
  - `RenderRings` (0x007EF5A0) - the full body, including both chunked
    streaming loops and all four frame passes
  - `moho::GetFrameRangeColorShaderVar()` - a new exported `frame/RangeColor`
    accessor in `CRenFrame.cpp`; the rest of that family is file-private, and
    `CRenFrame.h` is an **LF** file while `RangeRenderer.*` are CRLF.

### CORRECTION to this note: the colour argument is mSelectedRingColor

The earlier entry said `func_RenderRings`' 5th argument is
`profile.mBuildRingColor` at +0x48, read as "v10 - 48". That is **wrong**.
`RangeRenderer::Render` line 97 passes `v17 + 88` where `v17 = v16 + 48` is
the profile start (proved by line 96 handing `(std::string *)(v16 + 48)` to
the extractor, i.e. `mExtractorName` at profile+0x00). 88 = 0x58 =
**`mSelectedRingColor`**. Only one colour is bound, not a 3-element array.

### Render also walks a TREE, not the visible-profile vector

The earlier entry described a 136-byte-stride walk over `mVisibleProfiles`.
The decompile walks the `mRangeProfiles` RB-tree instead (`v5[2]` head,
`sub_7F2050` successor - already recovered in `RangeRenderer.cpp`), and then
makes a **second** `func_RenderRings` call with hardcoded constants:

    outerRingParams = {1.0f, 2.0f}
    innerRingParams = {0.1f, 1.0f}      // 1036831949, 1065353216
    ringColor       = {0.2f, 0.2f, 0.2f, 0.2f}   // 1045220557 x4

### The two remaining leaves

    0x007EF280  sub_7EF280  the per-profile range extractor  ABSENT
    0x007EF420  sub_7EF420  a further ring pass              ABSENT

(`sub_7EF1C0` and `sub_7F2050` are both already recovered.) Recover those two
first, then `RangeRenderer::Render` roots the whole chain and the v3 patch can
be re-applied and committed as one atomic landing.

### SCOPE: the whole remaining chain is ~626 engine instructions

`RangeRenderer::Render`'s full unrecovered closure is **8 fns / 703 instrs**,
and one of those is a CRT import (terminal):

    FUN_007EEA00  196  RangeRenderer::Render
    FUN_007EEE50  158  func_RenderBuildRings
    FUN_007EF280  126  sub_7EF280   (per-profile range extractor)
    FUN_007EF420  113  sub_7EF420   (further ring pass)
    FUN_007B4D90   28  std::map node emission
    FUN_007F0490   21  sub_7F0490
    FUN_007F0380   12  sub_7F0380
    FUN_0040A880   49  __imp_ operator+ for std::string  <- TERMINAL

This is much smaller than the "bigger than it first looked" note from attempt
1. With the v3 patch re-applied, landing these six is the whole job.

### Leaf classification (done - do not re-derive)

    FUN_007F0380   12  CONTAINER EMISSION. One-line forwarder to sub_7F0C50
                       (already recovered) - a payload-vector clear. Express
                       through the container API; no standalone body.
    FUN_007F0490   21  CONTAINER EMISSION. std::map iterator increment +
                       node step. Same treatment.
    FUN_007B4D90   28  std::map node emission. Same treatment.
    FUN_0040A880   49  __imp_ operator+ for std::string. TERMINAL.

    FUN_007EF280  126  REAL. Per-profile range extractor.
    FUN_007EF420  113  REAL but DEEPER THAN IT LOOKS - this is the
                       `range_RenderHighlighted` pass. It reaches
                       Moho::sBlueprintExtractors (a
                       std::map<string, RangeExtractor>), REntityBlueprint,
                       and at least four unmodelled CWldSession fields
                       (+1216, and v7[252] / v7[290] / v7[304] as dword
                       indices). Scope this one properly before writing.
    FUN_007EEE50  158  REAL. func_RenderBuildRings.
    FUN_007EEA00  196  REAL. RangeRenderer::Render - the root.

So the true remaining work is **4 bodies / 593 instrs**, of which only
`sub_7EF420` carries unresolved layout. Everything above it
(`RenderRings`, `DrawRangeRingBatch`, `GetFrameRangeColorShaderVar`) is
written and compiling in `<scratchpad>/rangerings_chain_v3.patch`.

**Next pass:** scope `sub_7EF420`'s CWldSession fields first, since it is the
only remaining unknown; the other three are straight transcription.

## Attempt 4 (2026-08-18, same session as the CRenderWorldView/terrain work)

Found `<scratchpad>/rangerings_chain_v3.patch` still present in this
session's scratchpad and confirmed it **still applies cleanly** to the
current tree (`git apply --check` = clean) and **still compiles**
(`tucheck` on `RangeRenderer.cpp` = `EXITCODE=0`). Applied it, read
`RangeRenderer::Render` (`FUN_007EEA00.c`) fully myself, then **reverted
the apply** (`git checkout --`) because `sub_7EF420` is genuinely not
landable yet - see below. The patch is still sitting at that scratchpad
path, still clean, ready for whoever resolves `sub_7EF420` next.

### `RangeRenderer::Render` - now fully decoded end to end

Confirmed `v5` (the mystery local assigned `v5 = v27` at function entry,
`v27` itself never visibly assigned - an elided register param) really is
`this` (`RangeRenderer*`), by direct offset arithmetic against the
**already-declared** `RangeRenderer.h` layout, not guesswork:

    v5[5]  = byte 0x14 = mVisibleProfiles.first  (msvc8::vector internal)
    v5[6]  = byte 0x18 = mVisibleProfiles.last
    v5[2]  = byte 0x08 = mRangeProfiles.mHead     (SRangeRenderCategoryTree)

(`mVisibleProfiles`@0x10, `mRangeProfiles`@0x04 with its own `mHead`@+0x04
relative = 0x08 absolute - both per `RangeRenderer.h:192-193`, matches
exactly.) The `(v5[6]-v5[7])/136` non-empty test uses 136 =
`sizeof(SRangeRenderProfile)` (confirmed elsewhere in this same note).

Full body, three phases, all three already-recovered-or-patched callees
confirmed by name:

    Device::GetInstance();                          // ensure GAL ready
    if (range_RenderBuild)
      func_RenderBuildRings(session, this, &scratch, cartographic, headIdx);

    // Phase 1: mVisibleProfiles VECTOR walk (stride 136)
    if (!mVisibleProfiles.empty()) {
      cartographic->vtable[2]();                     // some cartographic setup
      auto* candidatePool = cartographic->vtable[41]();
      sub_7F03D0(&candidatePoolFastVec, candidatePool, &candidatePoolFastVec);  // NOT YET IDENTIFIED - builds a fastvector, unclear if already recovered under another name
      for (auto& profile : mVisibleProfiles) {
        func_ExtractRanges(candidatePoolFastVec, /*alpha - see open Q below*/, profile, &scratch);
        func_RenderRings(profile.mOuterRingParams, cartographic, this, headIdx,
                          &profile.mBuildRingColor, profile.mInnerRingParams, &scratch);
      }
      <cleanup: releases/frees candidatePoolFastVec's node storage - looks like
       a std::map/tree node-release loop, not a plain vector free; needs its
       own scoping if it isn't sub_7B4D90/sub_7B4640 already covered by the
       container-lane exemption>
    }

    // Phase 2: mRangeProfiles TREE walk (RB-tree successor via sub_7F2050, already recovered)
    for (node in mRangeProfiles) {                    // sub_7F2050 = successor, already in RangeRenderer.cpp
      sub_7EF280(session, &scratch, &node->mProfile, interpolationAlpha /*=a5, the outer function's own 5th param*/);
      func_RenderRings(node->mProfile.mOuterRingParams, cartographic, this, headIdx,
                        &node->mProfile.mSelectedRingColor, node->mProfile.mInnerRingParams, &scratch);
    }

    sub_7EF420(???, &scratch, cartographic, interpolationAlpha, headIdx);  // BLOCKED, see below
    sub_7EF1C0(&scratch, session);                     // already recovered per earlier note

    // Phase 3: one hardcoded "default/global" ring pass, no profile object at all
    func_RenderRings({1.0f,2.0f} /*outer*/, cartographic, this, headIdx,
                      {0.2f,0.2f,0.2f,0.2f} /*color*/, {0.1f,1.0f} /*inner*/, &scratch);

    <release scratch's heap buffer if allocated>

The Phase-1 candidate-pool builder (`sub_7F03D0`) and its matching cleanup
loop are NOT YET IDENTIFIED against anything already in `src/sdk/**` -
check before assuming either needs a fresh recovery; they may already
exist under an intent-first name from unrelated work (search by the exact
vtable-slot-41-on-Cartographic shape, or by the "candidate pool built once
per Phase-1, walked by func_ExtractRanges" role, since `func_ExtractRanges`
already documents consuming an `SRangeProfileWeakRefCandidatePoolView` -
that type's OWN builder is probably `sub_7F03D0`, go look for it by that
type name first).

**Open Q not yet resolved:** what exactly feeds `func_ExtractRanges`'s
`interpolationAlpha` in Phase 1 (`*(float*)v29` in the raw decompile, read
BEFORE `v29` is ever visibly written earlier in this exact function - a
stack-slot-reuse read of a value established earlier via a path IDA
elided). Strong candidate: `a5` (the outer function's own float parameter),
spilled to that slot before the printed code begins - matches Phase 2's
`sub_7EF280` call, which unambiguously takes `a5` as its own last argument.
Don't assume without checking the raw asm at the top of `FUN_007EEA00.asm`
for an early spill of the incoming `a5` register/stack value to `v29`'s
stack slot.

### `sub_7EF280` (0x007EF280) - DECODED, ready to write, NOT blocked

This is the Phase-2 "selected units only" per-profile extractor - a
DIFFERENT function from `func_ExtractRanges` (Phase 1's "all
visible/relevant units" extractor), despite both feeding the same
`func_RenderRings` sink. Full body read and understood:

    void ExtractSelectedUnitRangesForProfile(         // naming candidate, not final
      CWldSession* session, SRangeExtractionPayloadVector& outPayload,
      const SRangeRenderProfile& profile, float interpolationAlpha)
    {
      ClearExtractionPayloadVector(outPayload);        // sub_7F0C50 - already used/named in func_ExtractRanges's own doc comment, reuse that name
      if (!range_RenderSelected) return;
      // Built-in "show for everyone" profiles are handled by Phase 1 instead -
      // skip them here to avoid double-extraction.
      if (profile.mExtractorName == "AllMilitary" || profile.mExtractorName == "AllIntel") return;
      if (session->FocusArmy < 0) return;
      UserArmy* const army = session->userArmies[session->FocusArmy];
      if (army == nullptr) return;
      RangeExtractor* const extractor = GetRangeExtractor(profile.mExtractorName);  // already recovered, used elsewhere in this file
      if (extractor == nullptr) return;

      WeakSet_UserEntity selection{};
      session->GetSelectionUnits(&selection);           // already recovered (CWldSession.h)
      for (UserEntity* entity : selection) {             // sub_7B25F0/sub_7F0490 = iteration begin/increment, check against already-recovered selection-walk idiom elsewhere in this codebase (CWldSession.cpp's SSelectionSetUserEntity walks) rather than re-deriving
        UserUnit* const unit = entity->IsUserUnit();
        if (unit == nullptr || unit->mArmy != army) continue;
        const RUnitBlueprint* const blueprint = unit->GetBlueprint();
        if (blueprint == nullptr) continue;
        if (!EntityCategory::HasBlueprint(blueprint, profile.mCategoryFilter)) continue;
        std::byte scratch[20];  // v16, exact payload shape unconfirmed - matches SRangeExtractionPayload probably, cross-check its size
        if (extractor->Extract(scratch, unit, interpolationAlpha)) {
          AppendExtractionPayload(scratch, outPayload);  // sub_7F0310, same appender func_ExtractRanges already uses under some name - reuse, don't reimplement
        }
      }
      sub_7B2530(&selection);   // selection-set teardown - check if this matches an already-recovered SSelectionSetUserEntity destructor/reset already used elsewhere
    }

Every callee here (`GetRangeExtractor`, `CWldSession::GetSelectionUnits`,
`EntityCategory::HasBlueprint`, the selection-walk idiom, `sub_7F0C50`) has
a strong precedent already recovered in this exact file or `CWldSession.cpp`
- this one really is straight transcription against existing patterns, per
the original note's classification. **Did not write it** only because
landing it alone (without `RangeRenderer::Render` as its real caller) would
be a fresh orphan - it must land together with the root.

### `sub_7EF420` (0x007EF420) - STILL BLOCKED, and the blocker is different than previously thought

Read the full 90-line decompile. The earlier note's framing ("4 unmodelled
CWldSession fields, +1216 and v7[252]/v7[290]/v7[304]") is **half right,
half wrong**: those ARE real field reads at those exact word/byte offsets
in the decompile, but I could not pin down what object they're actually
reads FROM with confidence this session - my first attempt to positionally
map the caller's 5-argument call (`sub_7EF420((int)v5, (int)&i, (int)a2,
a5, a4)`, where `v5` = confirmed `RangeRenderer* this`) onto the callee's
declared 6-parameter list (`result@<eax>, a3, a1, edx0, a5, idx`) produces
a contradiction: if `result`/`v7` (the value the function reads `+1216`
from) really is `v5` (RangeRenderer*, only `sizeof == 0x94 == 148` bytes
per `RangeRenderer.h:212`), reading at byte offset 1216 is 8x past the end
of the object - impossible. So either `v7` is NOT `v5`/RangeRenderer* (the
caller-side arg order doesn't map onto the callee's declared param order
1:1 - a known, recurring trap in this exact codebase all session), or one
of my other offset/size assumptions is wrong.

**Do not guess this mapping from the .c alone - it already fooled one
pass.** What's needed: read `FUN_007EF420.asm`'s actual register state at
entry (what's really in eax at the `call sub_7EF420` site in
`FUN_007EEA00.asm`, not just the decompile's printed arg list) and
cross-check against a real ~1216+-byte-sized class. `CWldSession` (13000+
line `.cpp`, easily large enough) is still the better-fitting candidate by
size alone; the earlier note's guess may well be right, but it needs
`this` genuinely proven to be a `CWldSession*` at the ASM level before any
of `v7[304]`/`v7[290]`/`v7[252]` get named as real `CWldSession` fields
(cross-reference against `CWldSession.h`'s already-extensive field list
from this same session's CRenderWorldView work first - offsets 0x4C0
(1216), and whatever `290*4=0x484` / `252*4=0x3F0` land on, might already
be named fields there under a different mental model of "which pointer is
`this`").

The function's OTHER half (once past the CWldSession-field gate) is
clearer: it walks `mRangeProfiles` (`a3+8` dereferenced as
`*(DWORD**)(a3+8)`, matching `SRangeRenderCategoryTree::mHead` pattern
again) doing effectively the SAME per-profile extraction shape as Phase 2's
`sub_7EF280`, but via `Moho::sBlueprintExtractors` (a DIFFERENT,
already-referenced global `std::map<string,RangeExtractor>` - this is the
"per-blueprint" extractor map, not the per-profile-name one
`GetRangeExtractor` looks up) and explicitly SKIPPING "AllMilitary"/
"AllIntel" the same way `sub_7EF280` does - this is very likely the
"range_RenderHighlighted" pass (gated by that exact global at the top of
the function), i.e. the THIRD of three parallel per-profile extraction
variants (Phase-1 = all-relevant-units, Phase-2 = selected-units-only,
this = highlighted-units-only via a per-blueprint extractor lookup instead
of per-profile-name). That structural understanding is solid; only the
`this`-pointer identity and the four field offsets hanging off it remain
open.

**Status: still not landable.** The patch
(`RenderRings`/`DrawRangeRingBatch`/`GetFrameRangeColorShaderVar`, all
compiling clean) stays in the scratchpad, unapplied to the tree, until
`sub_7EF420`'s `this` and 4 field offsets are pinned at the asm level.
`sub_7EF280` and the rest of `RangeRenderer::Render` (all three phases
except the `sub_7EF420` call itself) are now fully decoded and ready to
write in the same pass once that one gate clears - do not re-derive them,
the specs above are solid.

## Attempt 5 (same session, immediately after attempt 4) - `sub_7EF420` register mapping SOLVED

Went back and read the raw push sequence at the actual call site
(`FUN_007EEA00.asm:149-159`, the `call sub_7EF420` at 0x007EEBCE) instead
of trusting the decompile's arg order. Two things resolve the contradiction
from attempt 4:

1. **`edi` (which becomes `eax` right before the call, `mov eax,edi` at
   0x007EEBCC) is `CWldSession*`, not `RangeRenderer*`.** Proven from
   `RangeRenderer::Render`'s own prologue: `mov edi,ecx` at 0x007EEA25,
   and `Render`'s own established signature has `a1@<ecx> = CWldSession*`.
   `edi` is never reassigned anywhere in the function body (checked every
   `edi` occurrence in the .asm) - it's a pinned callee-saved copy of the
   incoming session pointer, held for the whole function. My attempt-4
   assumption that the eax-passed value was `v5`/`this` (RangeRenderer*)
   was simply wrong - `v5` is `ebp`, a completely different register.
2. **One of the "pushes" is a reserve-then-overwrite idiom, not a real
   integer argument.** `push ecx` at 0x007EEBC1 reserves a 4-byte stack
   slot with whatever garbage is in ecx; the very next instruction,
   `fstp [esp+8+var_8]` at 0x007EEBC2, immediately overwrites that same
   slot with the top of the FPU stack (which `fld [esp+arg_1A8]` loaded
   two instructions earlier - `arg_1A8` is `Render`'s own incoming `a5`
   float parameter). So that slot's real content is the float alpha, not
   ecx's value - a known MSVC codegen pattern (align/reserve via a spare
   register push, then `fstp` the real float into it) worth watching for
   elsewhere in this codebase.

Full push sequence, in program order, with real values:

    push esi                          ; idx (Render's own a4, viewport head index)
    push ecx  ; fstp overwrites  ->    ; alpha (Render's own a5, float)
    push ebx                          ; Cartographic* (Render's own a2)
    push (lea ecx,[esp+i])            ; &i  (the SRangeExtractionPayloadVector out-param)
    push ebp                          ; RangeRenderer* this (Render's own local v5)
    mov eax, edi                      ; CWldSession* session
    call sub_7EF420

Since x86 `push` order is right-to-left of the C argument list (last
pushed = first param after the return address), the callee's real
parameter order is:

    void sub_7EF420(
      CWldSession* session,                        // eax (register)
      RangeRenderer* rangeRenderer,                 // 1st stack (IDA's "a3")
      SRangeExtractionPayloadVector* outPayload,    // 2nd stack (IDA's "a1", DWORD*)
      Cartographic* cartographic,                   // 3rd stack (IDA's "edx0", mistyped int)
      float interpolationAlpha,                     // 4th stack (IDA's "a5")
      unsigned int viewportHeadIndex);               // 5th stack (IDA's "idx")

Every field type matches IDA's own declared type for that slot exactly
(DWORD* for the payload, float for alpha) - strong corroboration this
mapping is right, not just plausible.

### With `session` pinned, the CWldSession field offsets resolve to already-recovered accessors

    session + 0x4C0 (1216)  = CWldSession::mCursorInfo.mUnitHover
                               (CursorInfoRuntimeView + 0x10, and mCursorInfo
                               itself sits at CWldSession + 0x4B0 - both
                               already modelled, CWldSession.cpp:4694/4701).
                               The `-8` decode right after re-reading it is
                               the SAME weak-link decode
                               `CWldSession::GetHoveredUserEntity()`
                               (CWldSession.cpp:10114) already performs -
                               use that accessor directly, don't hand-decode
                               the weak-link a second time.
    session->FocusArmy      = v7[290] (290*4 = 0x488) - matches the FocusArmy
                               offset already confirmed this session (used
                               throughout the DrawPathPreview/
                               func_GetRightMouseButtonAction recovery).
    session->userArmies[i]  = v7[252] (252*4 = 0x3F0) dereferenced then
                               `+4*i` - the SAME `userArmies[FocusArmy]`
                               pattern already used verbatim in
                               `func_GetRightMouseButtonAction` and
                               `DrawPathPreview` this session. Use
                               `session->userArmies[session->FocusArmy]`
                               directly.

So **all four "unmodelled CWldSession fields" from the original note turn
out to be already-modelled, already-named** - the earlier notes (both the
original and my attempt-4 pass) were chasing a real gap that had already
been closed by unrelated work earlier this same session, they just hadn't
been cross-referenced yet.

### Full semantic decode of `sub_7EF420`

This is the **third parallel range-extraction variant**, gated on
`range_RenderHighlighted`: Phase 1 (`func_ExtractRanges`, already
recovered) = all visible/relevant units; Phase 2 (`sub_7EF280`, decoded
above) = only currently-selected units; this one = only the currently
**mouse-hovered** unit.

    void ExtractHighlightedUnitRangesForProfiles(   // naming candidate, not final
      CWldSession& session, RangeRenderer& renderer,
      SRangeExtractionPayloadVector& outPayload, Cartographic& cartographic,
      float interpolationAlpha, unsigned int viewportHeadIndex)
    {
      if (!range_RenderHighlighted) return;
      UserEntity* const hoveredEntity = session.GetHoveredUserEntity();  // reuse, don't re-decode
      if (hoveredEntity == nullptr) return;

      // vtable slot 3 (0x0C) on UserEntity - tentative IsUserUnit(), the
      // overwhelmingly common early-slot "concrete-cast" call used
      // throughout this exact recovery session; CONFIRM against
      // UserEntity's actual vtable slot map before writing, don't assume.
      UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit();
      if (hoveredUnit == nullptr) return;

      if (session.FocusArmy < 0) return;
      UserArmy* const focusArmy = session.userArmies[session.FocusArmy];
      if (focusArmy == nullptr) return;
      if (focusArmy != hoveredUnit->mArmy) return;   // only when the hovered unit is on your own army

      for (auto& node : renderer.mRangeProfiles) {    // sub_7F2050 successor, matches Render's own Phase-2 tree walk
        const SRangeRenderProfile& profile = node.mEntry.mProfile;   // node+0x30, confirmed by "result+48" - CommandGraphEdge-style consistency check against SRangeRenderCategoryEntry's own +0x24 (RangeRenderer.h:82-83)
        // sub_7F01D0(&profile.mExtractorName, &iterator) - a find into
        // Moho::sBlueprintExtractors (a DIFFERENT map than the
        // GetRangeExtractor() one used by Phase 1/2 - confirm its exact
        // key/value type and whether sub_7F01D0 is already recovered
        // under another name before writing; it is very likely an
        // already-modelled std::map::find wrapper given the container-lane
        // precedent everywhere else in this file).
        if (auto it = FindBlueprintExtractor(profile.mExtractorName); it != sBlueprintExtractors.end()) {
          RangeExtractor* const ext = it->second;    // a2->_Myval.ext
          if (ext == nullptr) continue;
          if (profile.mExtractorName == "AllMilitary" || profile.mExtractorName == "AllIntel") continue;
          const RUnitBlueprint* const blueprint = GetIUnitBridge(hoveredUnit)->GetBlueprint();  // a1a+328 pattern, matches the pervasive UserEntity+328=IUnit-bridge idiom used all session
          if (blueprint != nullptr && EntityCategory::HasBlueprint(blueprint, profile.mCategoryFilter)) {
            std::byte scratch[16];   // v18[16], one byte length different from sub_7EF280's v16[20] - re-check both against the real SRangeExtractionPayload size before writing either
            if (ext->Extract(scratch, hoveredUnit, interpolationAlpha)) {
              ClearExtractionPayloadVector(outPayload);  // sub_7F0380 - a DIFFERENT call than sub_7F0C50 (Phase 1/2's clear) - confirm whether this is really "clear" or something else (e.g. "reserve capacity for one entry") before assuming it's the same operation under a different name
              AppendExtractionPayload(scratch, outPayload);  // sub_7F0310, matches Phase-2's own use of the same address
              RenderRings(profile.mOuterRingParams, cartographic, renderer, viewportHeadIndex,
                          &profile.mSelectedRingColor /* "v12+104" = node+0x30+0x74... verify against mSelectedRingColor@+0x58 relative to profile - offset arithmetic doesn't obviously match, RE-CHECK this specific color field before writing, do not copy sub_7EF280's mSelectedRingColor assumption blindly */,
                          profile.mInnerRingParams, outPayload);
            }
          }
        }
      }
    }

**Remaining before this is writable** (small, mechanical, not layout
research): confirm `UserEntity` vtable slot 3 is really `IsUserUnit()`;
identify `sub_7F01D0`/`Moho::sBlueprintExtractors`'s real type (probably
already recovered under another name - search for `sBlueprintExtractors`
across `src/sdk/**` first); resolve the `v12+104` vs `mSelectedRingColor`
offset question (my quick arithmetic doesn't cleanly match - it needs the
same careful re-derivation `sub_7EF280`'s color field got, not a copy of
that answer); and read `func_RenderBuildRings` (0x007EEE50, 158 instrs,
NOT YET READ this session) - still needed to complete the set of 4.

**This was NOT written to source this pass** - out of caution given how
long this tangent has already run relative to the session's primary
thread (the CRenderWorldView/terrain camera recovery). The next pass has
everything it needs to finish this in well under an hour: read
`func_RenderBuildRings`, settle the four small opens above, write all
four bodies + wire `RangeRenderer::Render`'s three extraction phases +
`func_RenderBuildRings` into it, re-apply `<scratchpad>/rangerings_chain_v3.patch`
as the base, tucheck, commit.

## Attempt 6 (same session) - read `func_RenderBuildRings`; two of the four opens resolved, one NEW open surfaced

Read `FUN_007EEE50.c` in full (99 lines). High-level: this is a **fourth**
parallel ring pass, gated on the current UI command mode being
`COMMOD_Build`(2) or `COMMOD_BuildAnchored`(3) (via
`GetLeftMouseButtonAction`, matches `ECommandMode` exactly), showing a
range-ring PREVIEW for whatever blueprint is about to be placed at the
cursor - not a live unit at all. Confirms the general shape (walks
`mRangeProfiles` the same way, same `sBlueprintExtractors` lookup via
`sub_7F01D0`, same "AllMilitary"/"AllIntel" skip, same category-bitset
test - now against the *blueprint's* category, not a live unit's) but the
extract call itself takes `(scratch, blueprintWeakPtr, &cursorWorldPos)` -
position/blueprint, not unit/alpha.

**Two color-offset opens from attempt 5 are now resolved, cleanly, by
just converting decimal to hex correctly** (I previously flagged
"v12+104 doesn't cleanly match" without doing the arithmetic - it does):

    func_RenderBuildRings: "v8+72"  = profile+0x48 = mBuildRingColor    ✓ exact
    sub_7EF420 (attempt 5): "v12+104" = profile+0x68 = mHighlightedRingColor ✓ exact
    sub_7EF280 (already settled): "v17+88" = profile+0x58 = mSelectedRingColor ✓ exact

So the three per-profile colors map 1:1 onto the three extraction phases
by role (build-preview -> mBuildRingColor, selected-units -> 
mSelectedRingColor, highlighted-unit -> mHighlightedRingColor) - a clean,
sensible design that also cross-validates the profile-offset arithmetic
(all three land inside the same already-declared `SRangeRenderProfile`
layout, `RangeRenderer.h:44-51`).

**"New open" immediately resolved, false alarm** - checked
`src/sdk/moho/misc/RangeExtractor.h` (already exists, already fully
declared) before assuming this needed fresh research. `RangeExtractor` has
exactly two virtual methods, not one overloaded/ambiguous one:

    slot 1  Range(SRangeExtractionPayload*, const RUnitBlueprint*, const Wm3::Vec3f& center) const
    slot 2  Extract(SRangeExtractionPayload*, const UserEntity*, float interpolationAlpha) const

`func_RenderBuildRings` calls slot 1 (`v10+4` in its raw asm) with
`(blueprint, cursorWorldPos)` - **`Range`**, exactly matching its
signature. `sub_7EF420` calls `ext->Extract` - IDA already resolved this
one by name via RTTI/vtable propagation (it prints the real method name,
not a raw offset) - with `(unit, alpha)` - **`Extract`**, exactly matching
its signature. Two different, already-declared, already-typed virtual
methods on the same interface; no ambiguity, no signature conflict, my
"new open" was from not checking the header that already answers this
before flagging it as unresolved.

## STATUS: fully decoded, zero remaining research blockers

Every function in this 4-body cluster (`RangeRenderer::Render`,
`sub_7EF280`, `sub_7EF420`, `func_RenderBuildRings`) plus the already-patched
trio (`RenderRings`, `DrawRangeRingBatch`, `GetFrameRangeColorShaderVar`)
now has a complete, cross-checked spec above with every field offset,
every callee identity, and every argument shape resolved against either
raw `.asm` proof or an already-declared header. The only remaining work is
transcription: write the four bodies against the specs in attempts 4-6
above, re-apply `<scratchpad>/rangerings_chain_v3.patch` as the base (or
recreate it - the spec is now redundant with the patch content), wire
`RangeRenderer::Render`'s three extraction-phase calls plus
`func_RenderBuildRings` into it, confirm `UserEntity` vtable slot 3 really
is `IsUserUnit()` while writing (the one item not independently
re-verified this pass - low risk, it is the standard early-slot
concrete-cast idiom used everywhere else in this codebase, but check
before committing), tucheck, wire into the already-recovered
`WRenViewport::Render` call site, commit.

**Not written this session** - this cluster's research is complete but
writing+wiring+verifying four bodies plus the caller wire-up is its own
substantial pass, and this session's primary thread (the
CRenderWorldView/terrain-camera render-pipeline recovery) took priority
for actual commits. Pick this up fresh next time rather than re-deriving
any of the above - there is nothing left to investigate, only to write.

## CORRECTION - "zero remaining blockers" above was premature

While spot-checking callee identities before writing (good instinct, glad
I checked before committing to code), found `sub_7F03D0`
(0x007F03D0) is **already recovered** as `CopyRangeExtractionFastVectorN20`
(`RangeRenderer.cpp:151`, `[[maybe_unused]]` orphan) - but its real
signature is `(destination, source)`, TWO parameters, a payload-vector
COPY-CONSTRUCT operation. My attempt-4 read of `RangeRenderer::Render`'s
Phase 1 call site described it as `sub_7F03D0(&v23, v8, &v23)` - THREE
arguments, with `&v23` appearing twice, doing something I called
"candidate pool building". That does not match a 2-param copy-construct
at all. One of these readings is wrong - likely my Phase-1 transcription
(I did not re-verify that call site against the raw `.asm` the way I did
for `sub_7EF420`'s call site in attempt 5), but do not assume either way
without checking.

**This means Phase 1 of `RangeRenderer::Render` (the `mVisibleProfiles`
vector walk, and specifically what `sub_7F03D0` and its surrounding
"candidate pool" cleanup loop actually do) is LESS settled than attempts
4-6 claimed.** Phases 2/3 (`sub_7EF280`, `sub_7EF420`) and
`func_RenderBuildRings` are unaffected by this correction - their own
`sub_7F0310`/`sub_7F2050` callees were independently confirmed already-
recovered with matching signatures. Re-verify Phase 1's exact call
arguments against `FUN_007EEA00.asm` (around 0x007EEA50-0x007EEA80, the
Phase-1 setup before the vector-walk loop) before writing
`RangeRenderer::Render` - do not transcribe the attempt-4 pseudocode for
Phase 1 as settled fact the way the rest of the cluster now is.

General lesson worth keeping: cross-check every `sub_NNNNNN` callee
against `grep -rn "0xADDRESS" src/sdk/**` for an existing recovery BEFORE
finalizing a spec that assumes it's unrecovered/does-X - this cluster had
several near-misses (`sub_7F0310`, `sub_7F03D0`, `sub_7F2050` all already
existed under real names) and one real one (Phase 1's arg count).

