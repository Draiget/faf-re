---
name: project-black-screen-is-renderworldview-vtable
description: CONFIRMED AT RUNTIME (2026-08-18) — with /map the engine loads the whole session fine and then faults every frame in RenderAllHeads on CUIWorldView's never-installed IRenderWorldView vtable at +0x11C. Names the exact fix and what still blocks it.
metadata:
  type: project
---

Symbolised fault, captured with `dbgrun` and `/map SCMP_009`:

```
[EXCEPTION] ACCESS_VIOLATION read from address 00000004  eax=00000000
  main!moho::WRenViewport::RenderAllHeads+0xDE  [WxRuntimeTypes.cpp:64990]
  main!moho::WD3DViewport::D3DWindowOnDeviceRender+0x14
  main!moho::CD3DDevice::Paint+0xF1
  main!moho::WD3DViewport::OnPaint+0x8B  -> ... -> wxWndProc -> DispatchMessageW
```

`WxRuntimeTypes.cpp:64990` is `worldView->view->Func1();` - slot 1, so the read
is `[null + 4]`. **This is the black screen.** Everything upstream is healthy.

## What the /map run actually proves (do not re-derive)

- The map loads: `Background task "Map loader /maps/scmp_009/scmp_009.scmap"
  running.` then `... finished.` (log lines 548/579 of 3535).
- The full in-game UI loads - mods, hooks, context templates, `Hooked
  /lua/ui/game/score.lua`.
- `WLD_Frame` / `WLD_DoPreload` / `WLD_DoLoading` / `CWldSessionLoaderImpl` are
  all recovered and working. The frame machine reaches `Playing`.
- Without a debugger the same run stalls at 488 log lines ("SHADERS COMPILED").
  Under `dbgrun` it reaches 3535. **Run `/map` under `dbgrun` (scratchpad
  `brkmap.bat`) when you need the real picture** - `runmap.bat` alone
  under-reports.

## The defect

`CUIWorldView` carries an `IRenderWorldView` sub-object at `+0x11C`. The binary
ctor `FUN_0086E480` installs its vtable twice - `??_7IRenderWorldView@Moho@@6B@`
(0x00E4054C) at 0x0086E4DF, then `??_7CUIWorldView@Moho@@6BIRenderWorldView@Moho@@@`
(0x00E490DC) at 0x0086E4EF - and hands out its address at 0x0086E825.

Our tree models that slot as a bare `void* mRenderVftable` in
`CUIWorldViewCtorRuntimeView` (UiRuntimeTypes.cpp:2500, asserted :2543) which is
**declared, read twice (:19226 AddWorldView, :19324 RemoveWorldView) and never
written.** So `AddWorldView` publishes a pointer to four zero bytes.

## The fix, and why it is not a one-liner

`moho::CRenderWorldView` (UiRuntimeTypes.h:3222) already models that sub-object
correctly: `public IRenderWorldView`, 13 slots, `sizeof == 0x18C`, and
`0x11C + 0x18C == 0x2A8 == sizeof(CUIWorldViewCtorRuntimeView)` - it *is* the
tail of CUIWorldView. `CUIWorldViewRuntimeView::mRenderWorldView` is already the
typed member other code uses (`cfunc_CUIWorldViewProjectL` calls
`mRenderWorldView.GetCamera()`).

So the fix is: placement-construct `CRenderWorldView` at `+0x11C` as the first
statement of the CUIWorldView ctor (that is what publishes the vtable), then pass
`&...->mRenderWorldView` at both AddWorldView/RemoveWorldView sites instead of
`reinterpret_cast<IRenderWorldView*>(&view->mRenderVftable)`.

**The blocker: instantiating it emits the vtable, and the vtable is not
resolvable yet.**

- `src/sdk/moho/ui/CRenderWorldView.cpp` is **untracked and NOT in
  `src/sdk/main.vcxproj`** - another agent wrote it 2026-08-14 and never wired
  it. It defines 9 of the 13 slots (GetCamera, GetCameraView, GetCameraOffset,
  CameraGetTargetZoom, GetMaxZoom, CameraGetZoom, IsMiniMap, SetOrthographic,
  CanShake) plus `SimplifyPathSpan` and `PickPathPreviewSubject`.
- Three slots have no body anywhere:

  | Slot | Addr | Lines | Needs |
  |---|---|---|---|
  | 0 `Render` | 0x0086EE00 | 40 | all callees present |
  | 1 `Func1` | 0x0086ECB0 | 8 | `sub_852C10` present (UiRuntimeTypes.h) |
  | 2 `RenderCommandGraph` | 0x0086ECD0 | 38 | `sub_85AF40` ABSENT, `DrawCommandGraph` undeclared |

  `Func1` is the one that faults and is trivial:
  `if (!mIsMiniMap) <sub_852C10>(&mSubobject);`

Order to land it: recover `sub_85AF40` + `DrawCommandGraph`, write the three
slots, wire `CRenderWorldView.cpp` into `main.vcxproj`, then do the ctor change.
All four vtable-visible pieces must land together or `/FORCE` just moves the
fault to a different slot.

Supersedes the "the black screen is the movie" framing for the `/map` path -
that note is about the no-map intro path, which is a different agent's lane
(`src/sdk/cri/sofdec/SofdecColorConvertRuntime.cpp` is their in-flight file).

Related: [[project-black-screen-root-cause]], [[project-cuiworldview-render-vtable-cluster]],
[[project-black-screen-is-the-movie]]

## Progress 2026-08-18

- `d4924e9` wired `src/sdk/moho/ui/CRenderWorldView.cpp` into `main.vcxproj` +
  `.filters` (it was untracked AND unlisted, so its ten slot bodies were dead)
  and landed **slot 1 `Func1` (0x0086ECB0)**:
  `if (!mIsMiniMap) mBuildDrag.UpdateDragPreview();` - `UpdateDragPreview` is the
  recovered name for `sub_852C10` on `CUIWorldViewBuildDragRuntimeView`.
  `tucheck EXITCODE=0`.
- Still missing before the ctor can install the vtable: **slot 0 `Render`
  (0x0086EE00)** and **slot 2 `RenderCommandGraph` (0x0086ECD0)**.

### Slot 2 chain (deeper than it looks)

`RenderCommandGraph` -> `sub_85AF40` (25 lines, sole caller 0x0086ECD0; gets the
session's primary command graph with `GetCommandGraph(&out, false)` and forwards
to `sub_829190`, then releases) -> **`sub_829190` (285 lines, 15 callees)** which
`CWldSession.cpp:3571` already flags as *"Remaining command-graph mesh build pass
(0x00829190 chain) is pending deep lift."* `DrawCommandGraph` has no declaration
anywhere yet either. Budget this as its own batch.

### Slot 0 `Render` - read the .asm, the decompile lies about arguments

Field offsets confirmed against `CRenderWorldView`: `[esi+15A]` mHideResources,
`[esi+1A]` mEnableResourceRendering, `[esi+4]` mCamera, `[esi+EC]` mWldSession.
Body order (0x0086EE0B..0x0086EF31):

    if (!mHideResources && !cam_Free) {
      if (mEnableResourceRendering) { v = mCamera->CameraGetView();
        if (UI_RenResources) session->RenderResources(v, batcher); }
      this->IsMiniMap();                      // slot 10, result DISCARDED
      session->RenderStrategicIcons(mCamera, batcher, map);
    }
    session->RenderProjectileIcons(mCamera, this, batcher, map, deltaSeconds);
    if (UI_RenProjectileArcs)
      CRenderWorldView::RenderProjectileArcs(batcher, this, session, mCamera->CameraGetView());
    mCamera->CameraGetView();                 // result DISCARDED
    session->RenderMeshPreviews();
    mCamera->CameraGetView();                 // result DISCARDED
    session->DrawCommandSplats();
    session->DrawEconomyOverlay(...);
    this->RenderCommandGraph(batcher, renderPass, map, deltaSeconds);  // virtual, slot 2

`JUMPOUT(0x86EF2C)` in the decompile is just the epilogue - not a real tail call.
The final `call [eax+8]` at 0x0086EF29 is the slot-2 virtual dispatch.

**Do not transcribe the argument lists from the decompile.** The raw call sites
shuffle ecx between the session and the camera view (e.g. 0x0086EE3A..0x0086EE44
loads mWldSession into ecx, pushes it, then overwrites ecx with the camera view
before calling `RenderResources`), and the `fld`/`fstp` pairs around `map` mean
IDA typed a `CWldMap*` frame slot as a float. Resolve each callee's real
prototype from its own prologue (or from the already-recovered declaration in
`CWldSession.h`) before writing the call.

### The one question that blocks writing slot 0

`RenderResources`, `RenderStrategicIcons` and `RenderProjectileIcons` all check
out - the mangled names in `CWldSession.h` are authoritative and the argument
lists in the decompile are right (only IDA's *register* comments mislead: e.g.
`FUN_00862A80.c` shows `RenderResources(CWldSession* arg0, GeomCamera3* a2@<ecx>,
CD3DPrimBatcher* a6)`, so MSVC put the camera in ecx, not `this`. Writing
`session->RenderResources(cameraView, batcher)` is correct - the register
assignment is our compiler's business). MSVC also copies plain 4-byte *pointer*
arguments with `fld`/`fstp` here, so an `fld` at a call site does NOT prove the
parameter is a float.

**SETTLED 2026-08-18, committed `0652678`.** The header was wrong; the caller
was right. `DrawEconomyOverlay` is
`(CameraImpl* camera /*ecx*/, CD3DPrimBatcher* batcher, CWldMap* map)` and
`map` is **unused by the body**. Raw displacements decide it:

    mov eax, [esp+0Ch+a1]     8B 44 24 10           -> [esp+10h]  a1 = +4
    mov ebp, [esp+198h+a6]    8B AC 24 A0 01 00 00  -> [esp+1A0h] a6 = +8

Only +4 (session) and +8 (batcher) are ever read; +0xC is dead. `ebp` is the
batcher, proven by the `[ebp+11Dh]` write landing inside
`sizeof(CD3DPrimBatcher) == 0x124` and by its use as `this` for
`DrawQuad`/`SetTexture`/`SetProjectionMatrix`.

There is **no float interpolant parameter**. `interpolant` is a frame LOCAL at
-4 (`0x19C - 0x1A0`), stored once from a zeroed `ebx` (`xor ebx,ebx` 0x00858DAF
-> `mov [esp+1A0h+interpolant], ebx` 0x00858E0E) and never rewritten, so the
overlay always samples at 0. The body now calls
`GetInterpolatedPosition(0.0f)`.

Two traps this burned, worth remembering:
  - **`fld`/`fstp` here really is MSVC copying a 4-byte POINTER.** All eight
    accesses to `Render`'s `[ebp+10h]`/`[ebp+14h]` are `fld`, which looks like
    proof they are floats - they are not. `RenderStrategicIcons`' mangled name
    (`...PAVCWldMap@2@@Z`) types that same slot as `CWldMap*` outright.
  - **`interpolant` is an analyst-applied IDB name, not IDA's.** The decompiled
    prototype never lists it. Names in this IDB are prior hypotheses; check
    whether a slot is *written* before treating it as an incoming argument.

**Still open, and it blocks writing slot 0 `Render`:** the
`RenderStrategicIcons` (0x0085B6E0) call at 0x0086EE69 pushes **five** dwords
and is caller-cleaned (`add esp, 14h`), which contradicts its `QAE`
(callee-cleaned, this + 3 args) mangled name. The extra push is the discarded
`IsMiniMap()` result from 0x0086EE56. Resolve that arity from 0x0085B6E0's own
prologue/epilogue before writing the call - IDA's `aN`/`argN` names in that
function are inconsistent and cannot be trusted for arity.

## Slot-2 chain fully decoded (2026-08-18, later)

The chain is **linear and must land whole** - every link has exactly one caller,
so landing any prefix produces orphans:

    CRenderWorldView::RenderCommandGraph (0x0086ECD0, 38 lines)
      -> sub_85AF40            (0x0085AF40,  28 lines)
           -> sub_829190       (0x00829190, 285 lines)   <- the "deep lift"
      -> DrawCommandGraph      (0x00853DC0, 168 lines)
           -> sub_854B70       (0x00854B70, 199 lines)
                -> sub_854A30  (0x00854A30,  29 lines)   <- leaf, fully decoded
      -> DrawAllUnitSkirts, MAUI_KeyIsDown, CWldSession::GetCommandGraph,
         WeakPtr_UICommandGraph ctor/dtor/Release  (all already present)

Callee availability checked address-by-address: the ONLY absent pieces are the
five above. `sub_7B4640` and `sub_7B4D90` show as absent but are
`std::map<uint, WeakPtr<UserEntity>>` `_Buynode` / iterator-`inc` emissions -
the container-lane trap family, already modelled by `msvc8::map`. Do not
recover them.

### sub_854A30 = `AreSkirtsAdjacent(const gpg::Rect2f&, const gpg::Rect2f&)`

Fully decoded, no ambiguity. `gpg::Rect2f` is `{x0, z0, x1, z1}`.

    if (|a.x0 - b.x1| < 1.0f || |a.x1 - b.x0| < 1.0f)      // edge-to-edge along X
      return (a.z0 >= b.z0 && b.z1 >= a.z1)                //   one Z span contains
          || (b.z0 >= a.z0 && a.z1 >= b.z1);               //   the other
    zFront = |a.z0 - b.z1|; zBack = |a.z1 - b.z0|;
    return ((zFront >= 0 && zFront < 1.0f) || (zBack >= 0 && zBack < 1.0f))
        && ((a.x0 >= b.x0 && b.x1 >= a.x1) || (b.x0 >= a.x0 && a.x1 >= b.x1));

The `>= 0.0f` tests on `fabs` results are NaN guards, not dead code - keep them.
The X branch does NOT fall through to the Z branch on failure. This is the
structure adjacency-bonus test; its caller calls
`UserUnit::DoOnDetectAdjacencyBonusFor` right after, which confirms it.

### sub_854B70 = build-drag adjacency highlighter

Decompile is flagged "local variable allocation has failed" - read the .asm for
the two loops. Shape:

    device = D3D_GetDevice(); SelectFxFile("primbatcher");
    SelectTechnique("TAlphaBlendLinearSampleNoDepth");
    batcher->mRebuildComposite = 0;                         // +0x11D
    batcher->SetViewProjMatrix(camera->CameraGetView());
    batcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFF));
    heightField = buildDrag->mSession->mWldMap->mTerrainRes->mMap->mHeightField;
    if (mMeshes.size() != mBlueprints.size()) return;       // parallel arrays
    for (unit in camera->GetArmyUnitsInFrustum()) {
      skip null / tombstone(==8) / !IsUserUnit / IsDead / DestroyQueued
           / blueprint->IsMobile()
      skip if view.viewport.ProjectViewportDepthRow1(pos)
              >= buildDrag->mActiveBuildMesh->mIconFadeInZoom   // +0x70
      colour = 0xD8000000;                                  // -671033344
      for (i = 0; i < previewCount; ++i) {
        if (mMeshes[i].mesh->color != 0xD8000000) continue;
        previewSkirt = mBlueprints[i]->GetSkirtRect({pos.x, pos.z});
        unit->GetSkirt(&unitSkirt);
        if (AreSkirtsAdjacent(previewSkirt, unitSkirt)
            && unit->DoOnDetectAdjacencyBonusFor(mBlueprints[i])) {
          colour = 0xFF00FF00; mMeshes[i].mesh->color = 0xFF00FF00; break;
        }
      }
      DrawUnitSkirt(heightField, unit->GetBlueprint(), camera->CameraGetView(),
                    unit->GetPosition(), session, batcher, colour);
    }
    for (i = 0; i < previewCount; ++i) {
      mMeshes[i].mesh->UpdateInterpolatedFields();
      DrawUnitSkirt(heightField, mBlueprints[i], camera->CameraGetView(),
                    mesh->interpolatedPosition, session, batcher, mesh->color);
    }
    batcher->Flush();

`CUIWorldViewBuildDragRuntimeView` is fully modelled (UiRuntimeTypes.h ~662):
`mSession`+0x00, `mActiveBuildMesh`+0x04, `mMeshes`+0x08, `mBlueprints`+0x18,
`mPreviewPositions`+0x28 (IDA's `mVec3`), `mPreviewInvalid`+0x5C (`byte5C`),
`mUnknown5D`+0x5D (`byte5D`). Every other callee is already recovered.

**Blocker for writing it in CRenderWorldView.cpp:** the frustum walk needs
`DecodeUserEntityWeakRef` (CWldSession.cpp:3884) and `ResolveIUnitBridge`, both
file-private anonymous-namespace helpers with no header declaration - the
cross-TU trap. Promote them to a header first (they are pure, 6-line
`mOwnerLinkSlot - offsetof(UserEntity, mIUnitChainHead)` decoders); do not
re-implement them locally, that is the duplicate-helper defect.

### DrawCommandGraph (0x00853DC0)

    GetCommandGraph(sWldSession, &graph, false);
    if (buildDrag->mUnknown5D != (graph != null)) {         // graph-active latch
      buildDrag->mUnknown5D = (graph != null);
      for (node : buildDrag->mPreviewPositions) node->value[+40] = mUnknown5D;
    }
    if (session->mCursorInfo.mInWorld && !buildDrag->mPreviewInvalid) {
      GetLeftMouseButtonAction(session, &mode, &session->mCursorInfo, 0);
      if (!MAUI_KeyIsDown(MKEY_SHIFT))
        DrawAllUnitSkirts(batcher, session, camera->CameraGetView());
      DrawBuildDragAdjacencyHighlights(buildDrag, batcher, camera);
      if (mode.mBlueprint == 3) {                          // build-range preview
        GetSelectionUnits(session, &selection);
        first selected unit with [+1380] > 0 ->
          radius = unit->GetBlueprint()->mEconomy.mMaxBuildDistance;
          if (radius > 0) { DRAW_Circle(batcher, unit->GetPosition(), up, radius);
                            batcher->Flush(); }
      }
      // then SCommandModeData's inlined dtor unlinks mMouseDragEnd/mMouseDragStart
    }
    // release the graph shared_ptr

## The trailing-`float interpolant` parameters - status

`CWldSession::DrawEconomyOverlay`'s third parameter is **not** a float. Proved
from the callee: `xor ebx, ebx` at 0x00858DAF, `mov [esp+1A0h+interpolant], ebx`
at 0x00858E0E, and `ebx` is only *read* in between - so IDA's `interpolant` is a
LOCAL hard-zeroed to 0.0f, and `GetInterpolatedPosition(0.0f)` is what the binary
calls. The slot the caller fills at that stack position is `Render`'s `CWldMap*`.

**Another agent is already fixing this** - `src/sdk/moho/sim/CWldSession.{h,cpp}`
were unstaged-modified mid-session with the signature changed to
`(CameraImpl*, CD3DPrimBatcher*, [[maybe_unused]] CWldMap* map)`. Do not touch
those files; wait for their commit, then slot 0 `Render` is writable.

`moho::RenderProjectileArcs` (ProjectileArcRenderer.h:149) has the same shape - a
trailing `float interpolant` feeding `GetInterpolatedTransform`. IDA's decompile
of FUN_008600E0 lists only `(batcher@edi, view@esi, session, cam)` with no fifth
argument, and the float is read as `[ebp+arg_0.mColor]` at 0x0086044B. **Not yet
proved either way** - check whether that slot is written inside the callee the
same way `DrawEconomyOverlay`'s was before changing anything.

Also inherited when `CRenderWorldView.cpp` was wired in: `SimplifyPathSpan`
(0x0082A120) and `PickPathPreviewSubject` (0x0082A2B0) are in that file with no
source-level caller. They are `sub_829190`'s neighbours - wire them up when that
lands rather than leaving them orphaned.

### RESOLVED: RenderProjectileArcs' 4th arg IS a real stack argument

`movss xmm1, [ebp+14h]` at 0x0086044B reads the **fourth** incoming stack
argument (args start at ebp+8), so unlike `DrawEconomyOverlay`'s `interpolant`
this one is genuinely a parameter. The `mov [esp+40h+arg_0.mColor], eax` at
0x00860AB3 is an unrelated esp-relative local that IDA gave the same name.

So `Render` hands `[ebp+10h]` to **both**:
  - `RenderProjectileIcons` slot 4, which its authoritative mangled name
    (`...PAVCWldMap@2@M@Z`) types `CWldMap*` - and the stack block is
    unambiguous: after `sub esp,8` / `fstp [esp+4]` (= ebp+14h) /
    `fstp [esp+0]` (= ebp+10h) / `push edi`, the args land
    [esp+0]=batcher, [esp+4]=ebp+10h, [esp+8]=ebp+14h, matching
    (batcher, map, float) exactly;
  - `RenderProjectileArcs` arg 4 and `DrawEconomyOverlay` arg 3, both of which
    the callee reads with `movss` as a float.

**That contradiction is the last thing blocking slot 0, and it cannot be settled
from inside `Render`.** Settle it from the DISPATCHER: find what calls
`IRenderWorldView::Render` (vtable slot 0) and what it actually passes as
arguments 3 and 4. Our `IRenderWorldView::Render(CD3DPrimBatcher*, int,
CWldMap*, float)` may simply have those two transposed relative to the binary.
Do not write slot 0 until that is answered - guessing picks one of two callees
to break.

## Slot 0 LANDED (ff687b8) - slot 2 is all that is left

`CRenderWorldView::Render` (0x0086EE00) is in. The argument contradiction that
blocked it resolved cleanly: **every `fld` in `Render` reads `[ebp+10h]`** (raw
`D9 45 10` at 0x0086EE58/EE84/EEAC/EED4/EEF2/EF16); `[ebp+14h]` (`D9 45 14`) is
loaded only for `RenderProjectileIcons` and the slot-2 tail. Since
`RenderProjectileIcons`' mangled name types `[ebp+10h]` as `CWldMap*`, both
`RenderProjectileArcs` and `DrawEconomyOverlay` take the **map** as their
trailing argument - neither has a `float interpolant`. Both were recovered with
one; `DrawEconomyOverlay` was fixed in 0652678 (another agent, same evidence)
and `RenderProjectileArcs` in ff687b8.

Why the shipped engine gets away with it: the callee reads that pointer back
with `movss` and feeds it to `GetInterpolated{Position,Transform}(float)`, and a
heap pointer's bit pattern denotes ~1e-13 as a float - i.e. zero. Both are
recovered as an explicit `0.0f`.

Also landed: `UI_RenResources` (0x00F57A8E, .data = 0x01 so it ships **on**) had
no definition anywhere, and `UI_RenProjectileArcs` is now declared in
`ProjectileArcRenderer.h` instead of only defined in the .cpp.

### Remaining: slot 2 only, and it is a subsystem

    RenderCommandGraph  0x0086ECD0   38 lines
      sub_85AF40        0x0085AF40   28
        sub_829190      0x00829190  285
          DisplayCommandNode 0x00828610  114
          sub_8288D0    0x008288D0  169
          DrawPathPreview 0x0082A380  595  (~40 callees of its own, unchecked)
      DrawCommandGraph  0x00853DC0  168
        sub_854B70      0x00854B70  199
          sub_854A30    0x00854A30   29   (AreSkirtsAdjacent, decoded above)

~1625 decompiled lines before `DrawPathPreview`'s own closure. Linear - every
link has exactly one caller - so no prefix can land without orphans. Budget 2-3
batches. `sub_8282B0` and `sub_828DD0` are already recovered.

`DrawPathPreview` is also what would give `SimplifyPathSpan` (0x0082A120) and
`PickPathPreviewSubject` (0x0082A2B0) - already sitting in CRenderWorldView.cpp -
their source-level caller.

### Build note

`CRenderWorldView.cpp` now compiles a virtual call to the still-undefined slot 2.
Nothing constructs `CRenderWorldView` yet, so no vtable is materialised and no
dispatch happens; under `/FORCE` this shows up as unresolved externals at most.
Land slot 2 **before** the ctor change, never after.
