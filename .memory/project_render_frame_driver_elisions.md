---
name: project-render-frame-driver-elisions
description: WRenViewport::Render omits six direct callees the binary makes, including fog of war, the playable boundary and the cartographic pass. All six are blocked on the same unresolved thing - Render's second loop lane.
metadata:
  type: project
---

## STALE — all six landed and are wired (re-verified 2026-09-02)

Re-checked every one of the six by address. All are now recovered **and**
invoked from real call sites, so this file is history, not a work list:
`func_RenBoundary` 0x007D01C0 → `RenderPlayableBoundary`
(`BoundaryRenderer.cpp:179`, called from `WxRuntimeTypes.cpp:70731` and
`Cartographic.cpp:2352`); `func_ren_FogOfWar` 0x0081C660 →
`VisionRenderer.cpp:304`, called at `WxRuntimeTypes.cpp:70775`;
`func_RenUI` 0x007FD490 → `moho::RenUI` (`SelectionBracketRenderer.cpp:383`),
called at `WxRuntimeTypes.cpp:70738` and `Cartographic.cpp:2387` — matching
its own "both callers" citation; `WRenViewport::RenderCartographic`
0x007F8BA0 (`WxRuntimeTypes.cpp:69787`); `GetTickDebugCanvas` 0x007F6390 and
`GetBeatDebugCanvas` 0x007F63C0 (`CWldSession.cpp:15930`/`15946`).
The "Render has TWO loop lanes" problem described below was resolved along
the way. Do not re-investigate these as missing.

---

After the three terrain dispatches landed (see
[[project-terrain-vtable-15-slots]]), a callee-coverage sweep over the
frame path found `WRenViewport::Render` (0x007F90D0) itself still
missing **six direct callees**. Every other pass in the path is clean:

    RenderCopyForRefraction  OK (only a shared_ptr release emission)
    RenderEffects            OK
    RenderReflections        OK
    RenderMeshes             OK
    RenderUI                 OK

## The six

| Callee | Addr | Self | Closure | In src? |
|---|---|---|---|---|
| `func_ren_FogOfWar` | 0x0081C660 | 489 | 8 fns / 953 | no (only the `ren_FogOfWar` tuning global exists) |
| `WRenViewport::RenderCartographic` | 0x007F8BA0 | 435 | 28 fns / 6060 | no - do not confuse with `MeshRenderer::RenderCartographic` (0x007E0380), which *is* recovered |
| `func_RenUI` | 0x007FD490 | 419 | 6 fns / 1279 | no - distinct from `WRenViewport::RenderUI` (0x007F88B0), which is recovered |
| `func_RenBoundary` | 0x007D01C0 | 173 | 8 fns / 944 | no |
| `CWldSession::GetTickDebugCanvas` | 0x007F6390 | 10 | 1 | no |
| `CWldSession::GetBeatDebugCanvas` | 0x007F63C0 | 10 | 1 | no |

## SUPERSEDED - see "The session is a viewport member" below

## Why none of them landed yet: Render has TWO loop lanes

`Render` takes `std::vector<SWorldViewInfo>&` as a parameter *and*
walks `runtime->mWorldViews`. Our recovered body only walks the second.
All six missing calls sit in the first lane's scope:

    0x007F90D0 (decompile lines 250-253)
      Moho::WRenViewport::RenderWater(v35, viewport);
      v37 = (Moho::CDebugCanvas *)a4;              // a4 is really CWldSession*
      if ( Moho::ren_PlayableBoundary && (_DWORD)a4 && HIDWORD(a4) )
        func_RenBoundary(v81, &viewport->mBoundaryRenderer, a4, v65);

and later (lines 298-322) the debug-canvas block:

      if ( v37 ) {
        GetTickDebugCanvas(&tmp, v37);
        if (tmp) CDebugCanvas::Render(tmp, viewport->mPrimBatcher.batcher,
                                      viewport->mCam,
                                      viewport->mScreenSize.x,
                                      viewport->mScreenSize.z);
        GetBeatDebugCanvas(&tmp2, v37);
        if (tmp2) CDebugCanvas::Render(tmp2, ...same...);
      }

`a4` is a 64-bit local whose two halves are both tested - a
`{CWldSession*, STIMap*}` pair drawn from the `SWorldViewInfo` vector,
not from `mWorldViews`. `WRenViewportWorldViewParamRuntime` (view,
head, depth, terrain) has no session field, so there is nowhere correct
to hang these calls until that lane is modelled.

**This is the same gap the silhouette pass already documents** in
`WxRuntimeTypes.cpp` - its note says the binary additionally requires
`v72 == v74->mSTImap`, "a session-identity check between the world view
being drawn and its STI map", and that both operands are per-iteration
locals not modelled here. Same two locals. Resolving them once unblocks
the silhouette guard AND all six of these.

## Order of work

1. Model `SWorldViewInfo` and the `{CWldSession*, STIMap*}` pair, and
   restructure `Render`'s loop to walk the parameter vector the way the
   binary does. This is the keystone - do it first, alone.
2. Then the two debug-canvas accessors (10 instrs each, closure 1) fall
   out trivially, and the silhouette guard can be tightened.
3. `func_RenBoundary` next (944 closure) - it is gated on
   `ren_PlayableBoundary` and needs `viewport->mBoundaryRenderer`, which
   `moho/render/BoundaryRenderer.h` already models.
4. `func_ren_FogOfWar` (953 closure) is the highest gameplay value.
5. `RenderCartographic` (6060) last - it is a whole subsystem.

`CDebugCanvas::Render(CD3DPrimBatcher*, const GeomCamera3&, int, int)`
already exists (`sim/CDebugCanvas.h:165`), so step 2 needs no new
rendering code.

## Caution

Nothing in the terrain work or this note is runtime-verified - the
engine still cannot reach a map. These are dead-code-path findings from
static callee coverage, which is reliable for "the binary calls X and we
do not", and says nothing about whether the result renders.

## The shadow pass is never invoked (found 2026-08-17)

Reading `FUN_007F90D0.asm` around the terrain block turned up two more
things our `Render` loop was missing, both dispatched on the world view:

    0x007F93D9  mov edi, [esp+anonymous_1]   ; the IRenderWorldView
    0x007F93DF  mov edx, [eax+18h]           ; slot 6 CameraGetTargetZoom
    0x007F93F1  call RenderShadows(IRenTerrain *, float)
    0x007F93F8  mov edx, [eax+20h]           ; slot 8 CameraGetZoom
    0x007F9404  call FogOn(float)
    0x007F9409  call RenderCompositeTerrain

`FogOn` is fixed and both call sites are wired (`50462ee`) - it had been
`FogOn(1.0f)` at one site and absent at the other.

**`WRenViewport::RenderShadows` (0x007F7D10, 56 instrs) has no body.**
Its address appears in `Shadow.h:27` only as a doc-comment mention, which
is why the have-set reported it present - the same comment-match trap as
[[reference-have-set-detection-gap]], but for a function that really is
missing. So the shadow pass never runs at all.

Decoded:

    if (!ren_Shadows) return;
    fidelity = clamp(min(shadow_Fidelity, shadow_FidelitySupported), 0, ..)
    shadow_Fidelity = fidelity;
    if (fidelity != mShadowRenderer.shadow_Fidelity
        || ren_ShadowSize != mShadowRenderer.ren_ShadowSize
        || ren_ShadowBlur != mShadowRenderer.ren_ShadowBlur) {
      mShadowRenderer.Init(fidelity);
      <copy the three lanes back out of mShadowRenderer>
    }
    sunDir = sWldMap->mTerrainRes->GetSunDirection();
    sub_7FE940(&mCam->mTranform.orient, &mShadowRenderer, &sunDir, zoom);
    sub_7FEEA0(terrain, &mShadowRenderer, this, mCam, ...);

Its two helpers are **also** comment-only in `Shadow.h:26`:
`sub_7FE940` (310, light/camera setup) and `sub_7FEEA0` (434, the render
pass).

### Re-scoped 2026-08-17: 8 fns / 1528 instrs, not 31 / 3159

The 31-function count was wrong. `call_edges` claims `sub_7FE940` calls
`SelectionDragger::DragRelease` (0x00863870), which drags in the whole
0x868xxx selection cluster. Reading `FUN_007FE940.asm` shows its real
calls are only Normalize, `sub_4718F0`,
`CHeightField::ConvexIntersection`, `sub_9407D0`, `sub_7E9AD0`,
`gal::Math::mul`, the `VTransform` ctor and `GeomCamera3::Init` - no
selection code. The bogus edge comes from a chunk at 0x0046FF78 that IDA
merged into this listing. **Exclude FUN_00863870 when scoping this.**

True closure:

    FUN_007E9AD0  602  sub_7E9AD0        <- largest, from sub_7FE940
    FUN_007FEEA0  434  the render pass
    FUN_007FE940  310  light/camera setup
    FUN_007F7D10   56  RenderShadows
    FUN_007E9A10   54  sub_7E9A10
    FUN_00452AF0   51  Wm3::Vector3f::Normalize
    FUN_009407D0   13  sub_9407D0
    FUN_00452FC0    8  sqrtf                    <- CRT, terminal

so ~1470 instructions of engine code across 6 bodies. `sub_7FEEA0`'s own
callees are all already recovered (`MeshRenderer::Batch`,
`MeshRenderer::RenderDepth`, `GetInstance`, `D3D_GetDevice`,
`gal::RenderTargetContext`), which is why it does not expand further.

Worth doing: [[project-shadow-layout-resolved]] records that all seven
shadow lanes are already typed, so this is pass-writing, not layout.

### Shadow chain shrank again: 6 fns / 872 instrs (2026-08-17)

`55952b9` recovered `ProjectBoxByMatrix` (0x007E9AD0) and
`EncloseCornerSet` (0x007E9A10) - the AABB projection pair - because they
had a **second** caller outside the shadow chain:
`MeshThumbnailRenderer::PushRequest`, whose camera derivation was an
admitted approximation (`BuildApproximateThumbnailCamera`) that left every
matrix as identity. Both now live in
`moho/render/camera/GeomCamera3.{h,cpp}` as shared geometry helpers.

That takes the shadow pass down to:

    FUN_007FEEA0  434  the render pass
    FUN_007FE940  310  light/camera setup
    FUN_007F7D10   56  RenderShadows
    FUN_00452AF0   51  Wm3::Vector3f::Normalize
    FUN_009407D0   13  D3DXMatrixLookAtRH wrapper
    FUN_00452FC0    8  sqrtf                         <- CRT, terminal

So ~800 instructions across 4 engine bodies, all of whose other callees
are already recovered (`MeshRenderer::Batch`, `RenderDepth`,
`GetInstance`, `D3D_GetDevice`, `gal::RenderTargetContext`,
`GeomCamera3::Init`, `CHeightField::ConvexIntersection`,
`VTransform` ctor, `gal::Math::mul`). This is now a single-session job.

Lesson worth keeping: the chain looked 31/3159, then 8/1528, then
6/872. Two of those reductions came from checking whether a "shadow-only"
leaf had another caller elsewhere. **Always check the full caller set
before assuming a leaf is chain-locked** - it decides whether a body can
land standalone or has to wait for the whole tree.

### Light-camera half written and patch-saved (2026-08-17)

`<scratchpad>/shadow_lightcamera.patch` (242 lines, reverse-applies
cleanly) holds two bodies at `tucheck EXITCODE=0`:

  - `Shadow::PrepareLightCamera` (0x007FE940)
  - `MatrixLookAtRH` (0x009407D0)

plus the two tuning globals, whose defaults were read out of the shipped
image: `ren_ShadowCoeff` = 3.0f (0x00F57E00) and `ren_ShadowLOD` = 250.0f
(0x00F57E04).

Reverted only because `PrepareLightCamera`'s sole caller is
`RenderShadows`, which also needs the render pass - so it would land as
an orphan. **Re-apply the patch first** when picking this up.

Decoded behaviour of the light camera, for review when it lands:
builds the light basis around the sun direction using the camera forward
axis as reference up, falling back to (0,0,-1) when the two are within
0.99 of parallel; pulls the view frustum's far plane in to
`ren_ShadowCoeff * zoom`; clips that against the terrain height field;
lifts the box top 8 units; puts the eye 10000 units back along the light;
projects the volume and fits an orthographic matrix, with the near plane
pushed a further 25 units out.

### Gotchas paid for in that pass

  - `Shadow.h` and `Shadow.cpp` are **LF** files while most of
    `moho/render` is CRLF. Detect per file.
  - `gpg::gal::Matrix` **is** `moho::VMatrix4` - rows as `r[0..3]` with
    `.x/.y/.z/.w`. IDA prints `d[i].d[j]`; there is no `d` member.
  - The D3DX headers are not on the include path. Declare the entry point
    directly with `WINAPI` inside `extern "C"`, exactly as
    `gpg/gal/Matrix.cpp` already does for `D3DXMatrixMultiply` and
    friends. `VMatrix4` is layout-identical to `D3DXMATRIX`,
    `Wm3::Vector3f` to `D3DXVECTOR3`, so no casts are needed.
  - The height field is reached as
    `reinterpret_cast<TerrainWaterResourceView*>(terrainRes)->mMap->mHeightFieldObject`,
    the same route the terrain passes use - `IWldTerrainRes` exposes no
    map accessor, and `STIMap::mHeightField` is a `shared_ptr`.

Remaining: `sub_7FEEA0` (434, the render pass - 227 decompiled lines of
target setup, mesh batching, depth render and blur) and `RenderShadows`
(56). Then wire the call at `WRenViewport::Render` 0x007F93F1.

## SHADOW PASS DONE (0b02a3a, 2026-08-17)

All four bodies landed and wired at `WRenViewport::Render` 0x007F93F1:

    0x007F7D10  RenderFrameShadows
    0x007FE940  PrepareLightCamera
    0x007FEEA0  RenderShadowMap
    0x009407D0  MatrixLookAtRH

Plus a bonus that closed an older loop: `RenderShadowMap`'s terrain-depth
call is **vtable slot 6**, whose dispatcher had never been found. Slot 6
(`DrawTerrainDepth`) is now hoisted onto `TerrainCommon`, with the two
missing overrides recovered (0x00805A90 medium, 0x00801A50 high) to join
low fidelity's existing one. That is 4 of the 15 terrain slots dispatched
now (6, 8, 9, 12) - see [[project-terrain-vtable-15-slots]].

New tuning globals, defaults from the shipped image: `ren_ShadowCoeff`
0x00F57E00 = 3.0f, `ren_ShadowLOD` 0x00F57E04 = 250.0f. Added
`shadowSize` to the terrain shader-var block (no offset asserts there, so
appending is safe).

### API notes worth keeping

  - A render target's real extent is `target->GetSurface(handle)` then
    `handle->GetContext()->width_/height_` - there is no size accessor on
    `CD3DRenderTarget` itself.
  - `CD3DDevice::DrawPrimitiveList` is what IDA calls `Func12`.
  - `MeshRenderer::RenderDepth` is a **non-static** member despite IDA
    printing it `__stdcall`.
  - `runtime->mShadowRenderer` in `WxRuntimeTypes.cpp` is a local
    runtime-view overlay, not `moho::Shadow` - reinterpret_cast it, as
    the surrounding code already does.

### Still open in this note

The six `WRenViewport::Render` callees behind the `SWorldViewInfo` lane
(fog of war, playable boundary, cartographic, `func_RenUI`, the two
debug-canvas accessors) are untouched. The `a4` half of that puzzle is
solved - see the fog entry above - but the loop restructuring is not.

## The session is a viewport member, not a loop lane (9e3195d, 2026-08-17)

The "Render has TWO loop lanes" section above is **wrong** and is kept
only so the reasoning is traceable. The six callees are not blocked
behind an unmodelled `SWorldViewInfo` lane.

`WRenViewportRenderView` had `std::uint32_t mWorldViewState` at +0x2140.
That slot is a **`CWldSession*`**:

    0x007F9379  mov [ebp+2140h], ebx   ; store
    0x007F95CE  mov ecx, [ebp+2140h]   ; read
    0x007F9709  mov [ebp+2140h], edi   ; clear

and the fog-of-war guard runs on that same `ebx`:

    0x007F9563  cmp dword ptr [ebx+488h], 0FFFFFFFFh   ; FocusArmy != -1

`CWldSession::FocusArmy` is already modelled at +0x488, which is what
pins the type. Retyped in `9e3195d`.

### What is actually left

Only **populating** it. The value arrives through a frame argument IDA
mis-analyses - it prints `Clutter::GenerateNew` with two pushes against
the one-argument signature `GenerateNew(const GeomCamera3*)` at
0x007D6640, so `a1` in that frame cannot be trusted. Two ways forward:

  - Trace `ebx` back from 0x007F9317 / 0x007F9330 by hand through the
    prologue, ignoring IDA's `a1` naming.
  - Or check whether it is simply `WLD_GetActiveSession()` - our tree
    already has that accessor (`WxRuntimeTypes.cpp:63250`) and the value
    is per-frame, so a global lookup is plausible. Confirm before using;
    do not assume.

Once populated, the six unblock in the order already given, and the
silhouette pass's session-identity guard can be tightened too.

