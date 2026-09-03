---
name: project-terrain-vtable-15-slots
description: The terrain render interface has 15 vtable slots; TerrainCommon declared only 2, so no terrain pass ever dispatched and the map never drew. Full slot map, plus the mistyped gameTick parameter on DrawNormals.
metadata:
  type: project
---

**Why the map never rendered.** `WRenViewport::Render` reaches all three
terrain passes and the terrain object *is* created
(`IRenTerrain::Create()`, `WxRuntimeTypes.cpp:63837`), but every pass
discarded its argument:

| Pass | Address | Missing dispatch |
|---|---|---|
| `RenderTerrainNormals` | 0x007F7F10 | slot 9 `DrawTerrainNormal(tick, delta)` |
| `RenderCompositeTerrain` | 0x007F81C0 | slot 8 `DrawNormals` + slot 12 `DrawTerrainSkirt` |
| `RenderWater` | 0x007F86F0 | slot 11 `DrawWaterTerrain(tick, delta, sp, sp)` |

Root cause: `TerrainCommon` declared only `~TerrainCommon` and `Create`,
while the binary's interface has **15 slots**. The three fidelity classes
declared their draw methods as *fresh* virtuals, not overrides, so a
`TerrainCommon*` had nothing to dispatch through. Slot 12 hoisted +
wired in `cd6fc49`.

## The 15 slots (cross-confirmed from all three vftables)

Low 0x00E41A94, Medium 0x00E41A54, High 0x00E41A14 - identical order.

| Slot | Method | Low | Medium | High |
|---|---|---|---|---|
| 0 | `~TerrainCommon` | 0x809D80 | 0x807990 | 0x803970 |
| 1 | `IsFidelity` | 0x808190 | 0x803BF0 | 0x7FFB70 |
| 2 | `Create` | 0x8081A0 | 0x803C00 | 0x7FFB80 |
| 3 | `Init` | 0x808240 | 0x803CE0 | 0x7FFC60 |
| 4 | `Destroy` | 0x808590 | 0x804350 | 0x8002E0 |
| 5 | `Func3` | 0x808640 | 0x804440 | 0x8003E0 |
| 6 | `DrawTerrainDepth` | 0x808F90 | 0x805A90 | 0x801A50 |
| 7 | `CondDrawTerrainTechnique` | 0x809050 | 0x805B50 | 0x801B10 |
| 8 | `DrawNormals` | 0x809120 | 0x805C20 | 0x801BE0 |
| 9 | `DrawTerrainNormal` | 0x809B20 | 0x806F50 | 0x802F20 |
| 10 | `DrawWaterLine` | 0x809B30 | 0x807410 | 0x8033E0 |
| 11 | `DrawWaterTerrain` | 0x809B50 | 0x807430 | 0x803410 |
| 12 | `DrawTerrainSkirt` | 0x809C80 | 0x805530 | 0x8014F0 |
| 13 | `DrawTerrain` | 0x809D30 | 0x807660 | 0x803640 |
| 14 | `DrawDirtyTerrain` | 0x809D70 | 0x805F10 | 0x801EE0 |

Slot 1 is a fidelity-match query: Low `return a1 == 0`, Medium `== 1`,
High `== 2`.

**15 bodies / ~3472 instrs are still missing** (Low 4, Medium 4,
High 6+1) - four landed 2026-08-17. A slot can only move onto the base once all three
classes implement it, otherwise the base declaration forces a stub.

## `DrawNormals` parameter 1 is an int game tick, NOT a MeshRenderer*

IDA types it `MeshRenderer *a2` in all three classes and the landed Low
and Medium recoveries copied that. The asm disproves it:

    0x007F826A  fld  sDeltaFrame
    0x007F8272  mov  eax, sCurGameTick
    0x007F827E  push eax              <- last push = parameter 1
    0x007F8281  call edx              <- slot 8

The tell in our own source is `LowFidelityTerrain.cpp:156`, which does
`static_cast<int>(reinterpret_cast<std::uintptr_t>(renderer))` to feed
`decal.GetTexture(slot, lod, ...)` - it wraps an int as a pointer and
immediately unwraps it. So decal texture animation is currently seeded
by a pointer value instead of the game tick. The real signature is
`(std::int32_t gameTick, float deltaSeconds,
boost::shared_ptr<ID3DRenderTarget> normalTarget, TerrainShadowContext*)`
- param 3 is by-value `shared_ptr` (retain on `use_count_`, release via
`dispose`+`destroy`), sourced from `mPrimaryTargetLocks[mHead]`
(`mLocks1`, +0x2164, 8-byte stride).

Fixing this means renaming `renderer` -> `gameTick` through ~29 sites in
`LowFidelityTerrain` / `MediumFidelityTerrain` (the `DrawDecalPass`,
`DrawGlowingDecals`, `DrawNormalMappedDecals`,
`BindLowFidelityDecalTexture` family).

## Landed so far (2026-08-17)

  - `cd6fc49` slot 12 `DrawTerrainSkirt` hoisted onto `TerrainCommon` and
    wired in `RenderCompositeTerrain`. No new body needed - all three
    classes already had one.
  - `30518a5` `RenderTerrainNormals` bound the head backbuffer via
    `SetRenderTarget2`; the binary binds `mSecondaryTargetLocks[head]` +
    `mDepthStencilTargets[head]` through `SetRenderTarget1` (slot 32).
    Guard is `ren_Terrain`, not a null-terrain test.
  - `ec1b1fa` `MediumFidelityTerrain::DrawTerrainNormals` (0x00806F50,
    slot 9). It was already *called* from Medium's `DrawNormals` but only
    declared - a latent unresolved external. Added
    `ren_bicubicnormals` (0x00F57DC1, initial byte 0x01 read from the
    shipped PE).

  - `448fcf4` **slot 9 done**. Recovered High's `LoadTerrainLighting`
    (0x008015C0, IDA `func_SetTerrainVariables`), `OverDrawDecals`
    (0x00802C30) and `DrawTerrainNormal` (0x00802F20), hoisted slot 9
    onto `TerrainCommon`, and wired `RenderTerrainNormals`. Also retyped
    Medium's decal family to `std::int32_t gameTick` (see below) and
    moved `GetActiveShadowTexture` (0x007FEE70) out of Medium's
    anonymous namespace into `namespace moho`.

  - `d032bb9` **slot 8 done**. Recovered High's `DrawDecalPass`
    (0x008025B0), `DrawSplatComposite` (0x00802830), `DrawGlowingDecals`
    (0x00802A20) and `DrawNormals` (0x00801BE0), hoisted slot 8, and
    wired `RenderCompositeTerrain` fully. Finished the `gameTick` retype
    across Low's decal family too.

**NOT RUNTIME-VERIFIED.** All of the above is static evidence only:
the binary dispatches these slots (asm-confirmed), our source did not,
and now it does and compiles. Nobody has launched the engine into a map
- we still cannot get that far - so "the terrain renders" is unproven.
What is proven is that three provably-dead code paths are no longer
dead. Do not restate this as a rendering result until a frame has been
captured.

  - `0b0730c` **slot 11 done**. Recovered `DrawWaterTerrain` in all three
    classes plus Medium's and High's `DrawWaterAlbedoDecals`, added the
    `water2/ViewportScaleOffset` shader var, and wired `RenderWater`.

**All three terrain dispatches are now present in source.** 13 functions
recovered across the session; every touched TU at `EXITCODE=0`. Still
**NOT runtime-verified** - see the marker above.

Remaining unrecovered slots (none of them dispatched from
`WRenViewport`, so they orphan until their own callers appear):
slot 1 `IsFidelity` (all three, 4 instrs each), slot 5 `Func3`
(658/681/694), slot 6 `DrawTerrainDepth` (Medium 60, High 61),
slot 7 `CondDrawTerrainTechnique` (Low 67, High 67), slot 13
`DrawTerrain` (High 69), slot 14 `DrawDirtyTerrain` (Medium 312,
High 312). Slots 6 and 7 take a params block whose first 0x1C bytes are
ambiguous between `GeomCamera3` and `STerrainTechniqueDrawParams` -
slot 7 definitively reads a string at +0, slot 6 only the matrices.

### Slot 11 groundwork already done

  - IDA's `Moho::CRenWater` is our **`moho::WaterSurface`**
    (`terrain/water/WaterSurface.h`). Its `Func3` = vtable slot 4 =
    `RenderWaterSurface(tick, tickLerp, camera, shaderProperties,
    refractionTexture, reflectionTexture)`.
  - IDA's `waterFidelity` / `dword_10BF730` / `dword_10BF734` are the
    per-fidelity `WaterSurface*` globals: `sTerrainWaterSurface`
    (Low, `LowFidelityTerrain.cpp:171`),
    `sMediumFidelityWaterSurface` (`MediumFidelityTerrain.cpp:38`), and
    High still needs one.
  - Closures are small: Low 113 instrs alone; Medium 174 + `sub_806370`
    (191); High 174 + `sub_802340` (191). `sub_4303C0` is just a
    shared_ptr release and disappears into scope exit.

**RESOLVED 2026-08-17.** Tracking the frame by hand through the three
`sub esp, 8` adjustments shows IDA's `arg_10`/`arg_14` at the
`fld`/`mov edx` sites are really `a2`/`a3`. At the slot-4 call the stack
holds eight dwords, low to high:

    [esp+00] a2            -> tick
    [esp+04] float a3      -> tickLerp
    [esp+08] mCamera       -> camera
    [esp+0C] eax           -> shaderProperties
    [esp+10] {a4, a5}      -> refraction   (by-value shared_ptr)
    [esp+18] {a6, a7}      -> reflection   (by-value shared_ptr)

which is an exact match for the modelled
`WaterSurface::RenderWaterSurface(tick, tickLerp, camera,
shaderProperties, refraction, reflection)`. The two "extra" temporaries
built at 0x00809B80 and 0x00809BAA are those by-value shared_ptrs,
constructed early and retained; nothing is missing from our signature.

`GetWaterShaderProperties` has **no** stack arguments - there are no
pushes between `mov ecx, [ebp+0Ch]` and its `call` - so the existing
zero-argument overload is correct. The decompiler's `v12..v15` in its
argument list are exception-unwind bookkeeping, not parameters.

So `DrawWaterTerrain(std::int32_t tick, float tickLerp,
boost::shared_ptr<ID3DRenderTarget> refraction,
boost::shared_ptr<ID3DRenderTarget> reflection)` is:

    props = mTerrainResource->GetWaterShaderProperties();
    waterSurface->RenderWaterSurface(tick, tickLerp, mCamera, props,
                                     refraction, reflection);

with `waterSurface` the per-fidelity global. From `RenderWater`
(0x007F86F0) the caller passes refraction = `mPrimaryTargetLocks[head]`
and reflection = `mSecondaryTargetLocks[head]`. Medium and High
additionally build a `water2` viewport scale/offset vector from the
terrain grid dims before the call, and end with `sub_806370` /
`sub_802340` (191 instrs each).

Related: [[project-mesh-render-elision-debt]],
[[project-frame-driver-refresh-stub]], [[project-shadow-layout-resolved]].
