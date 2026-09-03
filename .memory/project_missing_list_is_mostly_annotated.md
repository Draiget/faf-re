---
name: project-missing-list-is-mostly-annotated
description: Measured 2026-08-15 - about two thirds of "missing" tokens are already recovered but unannotated, so the backlog is far smaller than the progress DB implies.
metadata:
  type: project
---

**Measurement, not a guess.** Sampled 40 named non-CRT "missing" tokens and
checked whether each **bare member name** appears anywhere in `src/sdk`:

    28 checkable -> 18 already present in src, 10 genuinely absent

So **~2/3 of the "missing" list is already recovered, just unannotated.** The
same holds for the 306 missing `TypeInfo` members in
[[project_typeinfo_missing_members]] - mostly bookkeeping, not work.

Of the 10 genuinely absent in the sample, 7 were **wxWidgets** (vendored,
terminal per CLAUDE.md). Only 3 were engine code, all terrain renderers.

## Why this kept costing passes

Because the small-candidate pool is mostly already-done work, batches drawn
from it keep landing annotations rather than bodies, and three times I started
writing a duplicate before the compiler or a late grep stopped me. See the four
hiding shapes in [[reference_closure_candidate_query]].

**Prioritisation consequence:** stop mining the small-token pool. The real
remaining work is the known large clusters - `Unit::Sync` (465i, slot 12,
dependencies measured clean) and the CUIWorldView slot-2 tree (~2100i, atomic)
- plus the elision debt below.

## Terrain elision debt (found while sampling)

`LowFidelityTerrain`'s draw path is substantially elided, not merely missing
one function:

  - `DrawTerrainDepth` (0x00808F90) - **recovered `7b2ee35`**.
  - `DrawTerrainNormal` (0x00809B20) - empty stub in src.
  - `DrawDirtyTerrain` (0x00809D70) - empty stub in src.
  - `DrawTerrain` (0x00809D30) - only releases a refcount.
  - `DrawWaterTerrain` (0x00809B50, 63 lines) - absent, and the last one left
    in this vein. Shape (read 2026-08-15): it is a **forwarder**, not a draw.
    Two `boost::shared_ptr` parameters are add_ref'd on entry and released on
    exit (the usual dec-use / dispose / dec-weak / destroy sequence). Between
    them it makes two virtual calls:

        v10 = mTerrainResource->vtbl[260/4 = slot 65](4 args)
        ret = (*global dword_10BF730)->vtbl[16/4 = slot 4](global, a6, a7,
                                                          mCamera, v10)

    **Two of the three unknowns are resolved** from LowFidelityTerrain.h:204-208
    - `this+0x0C` is `mTerrainResource` (`TerrainWaterResourceView*`) and
    `this+0x1C` is `mCamera` (`GeomCamera3*`).

    **The global is RESOLVED**: `dword_10BF730` is `sTerrainWaterSurface`
    (`LowFidelityTerrain.cpp:170`, type `WaterSurface*`). Found via the
    callgraph `data_refs` on 0x010BF730 - the recovered sibling
    `LowFidelityTerrain::DrawWaterLine` (0x00809B30) uses the same global and
    already models it as
    `sTerrainWaterSurface->RenderWaterLayerAlphaMask(mCamera)`.

    Slot 4 of `WaterSurface` is **`RenderWaterSurface`** (dtor 0, InitVerts 1,
    Func2 2, RenderWaterLayerAlphaMask 3, RenderWaterSurface 4).

    **Still blocked on the argument mapping.** `RenderWaterSurface` takes six
    parameters:

        (int tick, float tickLerp, const GeomCamera3* camera,
         const CWaterShaderProperties* shaderProperties,
         const boost::shared_ptr<ID3DRenderTarget>& refraction,
         const boost::shared_ptr<ID3DRenderTarget>& reflection)

    **Argument order RESOLVED from the `.asm` (0x00809BDF-0x00809BFA):**

        call eax                  ; = mTerrainResource->vtbl[0x104/4 = 65]()
        fld  [esp+arg_14]         ; tickLerp (float)
        mov  ecx, [ebp+1Ch]       ; mCamera
        mov  edx, [esp+arg_10]    ; tick
        push eax                  ; shaderProperties   <- 4th param
        push ecx                  ; mCamera            <- 3rd param
        push ecx                  ; SLOT RESERVATION, not an argument
        fstp [esp]                ;   ...overwritten with tickLerp <- 2nd
        push edx                  ; tick               <- 1st param
        mov  ecx, ebx             ; this = sTerrainWaterSurface

    So the first four args are `(tick, tickLerp, camera, shaderProperties)`,
    and `shaderProperties` is the slot-65 result. **The duplicated `push ecx`
    is a float slot reservation, not a repeated camera** - a naive read of the
    decompile gets this wrong.

    **FULLY RESOLVED (0x00809BA2-0x00809BC4).** The two `shared_ptr`
    references are not pushed - they are **built as stack temporaries**:

        mov  edi, [esp+arg_C]     ; incoming pi
        mov  ecx, [esp+arg_8]     ; incoming px
        sub  esp, 8               ; room for a temporary shared_ptr {px, pi}
        mov  [eax],   ecx         ; temp.px
        mov  [eax+4], edi         ; temp.pi
        lock xadd [edi+4], 1      ; add_ref

    The temporary's *address* is the `const shared_ptr&` argument, which is why
    only 4 dwords are pushed. Slot 4 **is** `RenderWaterSurface`.

    So the shape is:

        void LowFidelityTerrain::DrawWaterTerrain(
            int tick, float tickLerp,
            ID3DRenderTarget* refractionPx, sp_counted_base* refractionPi,
            ID3DRenderTarget* reflectionPx, sp_counted_base* reflectionPi)
        {
            // reassemble both shared_ptrs, add_ref each
            sTerrainWaterSurface->RenderWaterSurface(
                tick, tickLerp, mCamera,
                mTerrainResource->vtbl_slot65(...),   // shaderProperties
                refraction, reflection);
            // release both on exit (dec-use / dispose / dec-weak / destroy)
        }

    **THE ACTUAL BLOCKER, after four passes: `TerrainWaterResourceView` is
    only forward-declared in src** (`HighFidelityTerrain.h:24`). There is no
    definition, so slot 65 cannot be called on it at all. Slot 65 is almost
    certainly `GetWaterShaderProperties` - `CWldTerrainRes::
    GetWaterShaderProperties` (0x008A6E40, CWldMap.h:775) returns exactly the
    `CWaterShaderProperties*` that RenderWaterSurface's 4th parameter wants -
    but confirming that and declaring it means modelling a type with 65+
    virtuals.

    **So this is a type-modelling job, not a function recovery.** Model
    `TerrainWaterResourceView` (or at least its vtable through slot 65) first;
    the body is then ~15 lines. Do not start it without a full context budget.

    Beware the frame drift while working here: IDA prints `arg_10`/`arg_14`
    against three different `esp+XXh` bases inside this one function, so
    normalise before trusting any two references to the "same" arg.

    Reminder while chasing that global: **never `rg` across
    `decomp/recovery/reports` or the namespace dir** - it times out at 120s and
    leaves a background task. Scope greps to `src/sdk` or a single known file.
  - `MediumFidelityTerrain::CondDrawTerrainTechnique` (0x00805B50) -
    **RECOVERED `78d1514`**, with a new `STerrainTechniqueDrawParams` model:

        msvc8::string mTechniqueName  +0x00   (28 bytes, ends 0x1C)
        VMatrix4      mProjection     +0x1C
        VMatrix4      mView           +0x5C

    Two traps this cost three wrong readings, both worth remembering:

    **`msvc8::string` is 28 bytes in this tree, not 24** (String.h:593 asserts
    it) - it carries a proxy word. So `_Myres` at +0x18 and an SSO buffer at
    +0x04 place the string at offset **0**, not 0x04. My first model had a
    spurious leading `u32` and the `static_assert`s caught it. This is the case
    for the size-guard rule.

    **Those offsets coincide with `GeomCamera3`** (projection +0x1C, view
    +0x5C) because a `VTransform` is also 0x1C bytes. Do not conclude "it's a
    camera" from the matrix offsets alone: +0x18 on a camera is `pos_.z`, and
    the binary tests that slot as an integer string length.

    Also: when IDA prints two loads as the same `arg_N` at *different*
    `esp+XXXh` bases, normalise before concluding they differ -
    `0x10-8 == 0x14-12 == 8`, i.e. one argument, not two.

The shader vars are all present as `GetTerrainShaderVars()` -> `viewMatrix`,
`projMatrix`, `heightScale`, each with an `Exists()` guard the binary also has.
