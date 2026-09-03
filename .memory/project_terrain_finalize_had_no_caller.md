---
name: project_terrain_finalize_had_no_caller
description: Terrain shaded near-black because IWldTerrainRes::Finalize had no caller - WRenViewport::Render owns the lazy dispatch, and MapLoad deliberately does not do it
metadata:
  type: project
---

Fixed 2026-09-03, commit `220b2c48`.

**Symptom:** geometry, meshes and the sun constants were all correct, but lit
terrain came out near-black.

**Chain:** `IWldTerrainRes::Finalize` (`0x008A2DD0`, `CWldTerrainRes` vtable
slot 75) builds the terrain's whole D3D-side runtime -- the two stratum-mask
sheets, the water-map sheet, and through `InitNormalMap` the normal-map tile
sheets. It had **no caller anywhere in `src/sdk`**, so
`GetNormalMapCount()` stayed 0, the `TTerrainBasis` tile loop in every
fidelity's `DrawTerrainNormals` never ran, the normals render target's B and A
channels stayed zero, and `frame.fx`'s `BasisPS` reconstructed
`baseNormal.y = sqrt(1 - x*x - z*z)` out of them.

**Where the dispatch lives, and why it is not where you would look.**
`CWldMap::MapLoad` (`0x00890DA0`) does *not* call it -- that function ends after
`CWldProps::Load`, because `Finalize` allocates D3D resources and the loader
runs on a background thread. The **render thread** does it, once, on the first
frame after a map load, inside `WRenViewport::Render`
(`0x007F9203..0x007F9231`):

```
mov  eax, sWldMap        ; jz skip
mov  esi, [eax+4]        ; mTerrainRes; jz skip     <- this is REN_GetTerrainRes
mov  eax, [esi]
mov  edx, [eax+4]        ; slot 1  -> GetBool   (0x008A1030)
call edx
test al, al
jnz  skip
mov  edx, [eax+12Ch]     ; slot 75 -> Finalize  (0x008A2DD0)
call edx
```

`GetBool` is the ready flag `Finalize` itself sets to 1 at its tail.

**How it was found -- reusable technique.** Diff the binary function's direct
call list against the recovered body:

```bash
grep -oE "call +[A-Za-z_?][A-Za-z0-9_?@$:.]*" FUN_XXXXXXXX.asm \
  | sed 's/call *//' | sort -u
```

then check each symbol appears somewhere in the recovered function. On
`WRenViewport::Render` (the whole frame) that surfaced two real gaps out of ~40
symbols: this one, and `Clutter::UpdateCurrent`/`GenerateNew` (commit
`a444d83d`, ground clutter never drawn). Watch for false positives where the
recovered name differs -- `RenderShadows` is `Shadow::RenderFrameShadows` here.

Note IDA types the world-view list's begin/end pair as
`mVertexSheets[0]`/`[1]`, so `v88 == v89->mVertexSheets[0]` in that decompile is
really `worldView == begin`, not a vertex-sheet comparison.

Also worth knowing: `Finalize`'s neighbours in that block were missing too --
`RangeRenderer::MoveCategories` fed from `sWldSession->mOverlayFilters`
(`+0x4D8`) into the viewport's own `RangeRenderer` (`+0x37C`), gated on
`ren_Ranges`. `RangeRendererStartupRegistrations.h` already documented
`FUN_007F90D0` as that flag's only consumer, which would have found it too.
