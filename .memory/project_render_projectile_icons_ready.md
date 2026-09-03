---
name: project-render-projectile-icons-ready
description: FUN_008621B0 CWldSession::RenderProjectileIcons is fully analysed and fully closed (zero open callees) - write it straight from this note.
metadata:
  type: project
---

**LANDED 2026-08-14 as `4569f91`** (+ `ff86a66` README). Kept because the
sibling `RenderResources` is the same shape and the CVar/offset table below is
still the reference.

**Was: best committable target.** `CWldSession::RenderProjectileIcons`
(**FUN_008621B0**, 498 instrs) has **zero open behavioural callees** - every API
it needs is already recovered - and it *replaces the comment-only stub* at
`CWldSession.cpp:11419`, so it is a stub replacement, not a new orphan. Sibling
`RenderResources` (**FUN_00862A80**, 657) is also fully closed; do it next.

Signature (from the stub's mangled name):
`RenderProjectileIcons(CameraImpl*, CRenderWorldView*, CD3DPrimBatcher*, CWldMap*, float deltaT)`.

## Flow

1. `cam = camera->CameraGetView()`; return unless
   `camera->CameraGetTargetZoom() >= UI_StrategicProjectileLOD`.
2. Screen-space projection from the viewport - this is the **same matrix
   `GeomCamera3::MakeViewportPixelProjection` already builds** (landed with the
   economy overlay); reuse it, do not re-derive. Then
   `SetProjectionMatrix(proj)`, `SetViewMatrix(VMatrix4::sIdentity)`.
3. `D3D_GetDevice()->SelectFxFile("primbatcher")`,
   `SelectTechnique("TAlphaBlendLinearSampleNoDepth")`, `batcher->mRebuildComposite = 0`.
4. `category = mRules->GetEntityCategory("PROJECTILE")`;
   `focusArmy = mFocusArmy >= 0 ? mUserArmies[mFocusArmy] : nullptr`.
5. `SpatialDB_MeshInstance::CollectInView(cam, &entities, &mSpatialDB, 1024)`
   into a stack `gpg::fastvector` (inline buffer ~0x22A0 bytes).
6. Per entity, skip unless: non-null, `!mVarData.mIsDead`,
   `(mParams.mEntityId & 0xF0000000) == 0x10000000` (projectile id class),
   blueprint non-null, blueprint ordinal set in `category`'s bitset, and
   visible: `!focusArmy || IArmy::IsAlly(entity->mArmy->mConstDat.mIndex,
   focusArmy) || focusArmy->CanSeePoint(pos, (layer & LAYER_Underwater) ? 2 : 1)`.
   Position is `UserEntity::GetInterpolatedTransform(deltaT).pos`.
7. Texture + half-size:
   - icon-name string at **blueprint+0x140** (`_Mysize` +0x150, `_Myres` +0x154)
     non-empty **and** `UI_RenProjectileIcons` -> `CD3DBatchTexture::FromFile(name, 0)`;
     half-size = `tex->mWidth >> 1`, `tex->mHeight >> 1`; if `UI_RenProjectileGlow`
     then `Flush()` + `Setup("TAlphaBlendLinearSampleNoDepth")`.
   - otherwise army colour: `FromSolidColor(UI_forceWeaponsToYellow ? 0xFFFFFF00
     : army->mVarDat.mPlayerColor)`; half-size both =
     `*(float*)(blueprint+0x1CC) * 0.5f`.
   - a null texture skips the entity.
8. `SetTexture(tex)`; `GeomCamera3::Project(&screen, &worldPos, cam, 0, w, h, 0)`;
   **floor** both screen coords; quad of +/-halfW,+/-halfH at z=1, colour
   0xFFFFFFFF, uv (0,0)-(1,1); `DrawQuad`.
9. Glow pass, only when the file-texture path ran and `UI_RenProjectileGlow`:
   `Flush()`, `Setup("TCommandGlow")`, advance
   `UI_CurGlowTime = (UI_CurGlowTime <= UI_RenProjectileGlowPeriod) ? UI_CurGlowTime + deltaT : 0`,
   half = `UI_RenProjectileGlowPeriod * 0.5f`; in the first half lerp Max->Min,
   in the second Min->Max over `t - half`; alpha byte `<< 24` is the quad colour;
   second quad uses uv (0,0)-(1,1) mirrored; `Flush()`.
10. `Flush()`; free the fastvector if it spilled.

## CVars to declare (none exist in src yet; addresses from the .asm)

| symbol | address | type |
|---|---|---|
| `UI_StrategicProjectileLOD` | 0x00F57B20 | float |
| `UI_RenProjectileIcons` | 0x00F57A8F | bool |
| `UI_RenProjectileGlow` | 0x00F57B24 | bool |
| `UI_forceWeaponsToYellow` | 0x00F57B25 | bool |
| `UI_RenProjectileGlowMin` | 0x00F57B28 | float |
| `UI_RenProjectileGlowMax` | 0x00F57B2C | float |
| `UI_RenProjectileGlowPeriod` | 0x00F57B30 | float |
| `UI_CurGlowTime` | 0x010A6460 | float |

Same pattern as the seven `ui_*` command-graph CVars declared in efeb819.

## Blueprint fields - RESOLVED

IDA types the blueprint as `RUnitBlueprint*` here; it is **not** one - the
entity-id class check proves projectile, so it is `RProjectileBlueprint`
(`moho/resource/blueprints/RProjectileBlueprint.h`, sizeof 0x268).

- **+0x1CC** = `Display.StrategicIconSize` (Display is at +0x198, the field at
  +0x34). Exact match, no ambiguity.
- **+0x140** = the strategic icon name, in `REntityBlueprint`.

### Suspected 4-byte layout error in REntityBlueprint (verify before relying)

`REntityBlueprint.h` declares `msvc8::string mStrategicIconName; // +0x13C`.
The binary disagrees: FUN_008621B0 reads the SSO buffer at **+0x140**,
`_Mysize` at **+0x150** and `_Myres` at **+0x154**, which puts the string at
+0x140, not +0x13C.

The binary's reading is self-consistent and the header's is not: a 24-byte
`msvc8::string` at +0x140 ends at +0x158, exactly where the header's own
`mStrategicIconRuntimeWord // +0x158` starts. At +0x13C it would end at +0x154
and leave an unexplained 4-byte hole before +0x158. So there is very likely an
unmodelled 4 bytes at +0x13C and every field from `mStrategicIconName` onward
is declared 4 low.

Do NOT "fix" this from this note alone - `REntityBlueprint` is a widely used
base (`RUnitBlueprint` derives from it and asserts sizeof 0x17C). Confirm
against a second reader of the same field and against the reflection init
before touching it, then fix every sibling that mismodelled it.

Related: [[project_cuiworldview_render_vtable_cluster]].


## Landed - what actually worked

`4569f91`. tucheck EXITCODE=0. Corrections found while writing (the note above
had these wrong or missing):

  - `CD3DPrimBatcher` has no `mRebuildComposite`; go through
    `CD3DPrimBatcherRuntimeView::FromBatcher(batcher)->mRebuildComposite`.
  - `UserEntity::mVarData` is really `mVariableData`; the layer lane is
    `mVariableData.mLayerMask` (0xA0 into it = entity+0xF0, matching the asm).
  - "underwater" is `LAYER_Seabed | LAYER_Sub` - 0x008624F2 is literally
    `and al, 6`.
  - The category test is `mCategoryBitIndex` (`REntityBlueprint` +0x5C), not
    `mBlueprintOrdinal`; `BVIntSet::Contains` already does the word/bit math the
    binary inlines.
  - Army: `UserArmy::IsAlly(armyIndex)` with `entity->mArmy->mArmyIndex`
    (`SSTIArmyConstantData` +0x00, UserArmy derives from it), and the colour is
    `mVarDat.mPlayerColorBgra`.
  - The icon-name string is reached as `blueprint->mStrategicIconName` and it
    resolved fine, so **the suspected REntityBlueprint 4-byte offset error is
    NOT proven** - the header's +0x13C may be right and my +0x140 reading of the
    SSO buffer may just be IDA's framing. Leave it alone until a second reader
    confirms.

## Next: `RenderResources` (FUN_00862A80, 657) - structure mapped, WRITE FROM .asm

Also fully closed, also a comment-only stub (`CWldSession.cpp`, address
0x00862A80). Denser than the icon pass: 409 lines of decompile covering
`D3D_GetDevice()->SelectTechnique("TResourceIcon")`, a
`shaderVarPrimBatcherTime` push from `gpg::time::GetSystemTimer()`, the same
`MakeViewportPixelProjection` screen matrix, then playable-rect clamping from
`mWldMap->mTerrainRes->mMap->mPlayableRect`, heightfield elevation sampling, and
two splat passes -
`/env/common/splats/mass_strategic.dds` and `.../hydrocarbon_strategic.dds`.


### RenderResources decode notes + the hazard

Structure (from the .c, but see the warning):

1. `D3D_GetDevice()->SelectFxFile("primbatcher")` +
   `SelectTechnique("TResourceIcon")`; `mRebuildComposite = 0` (through the
   runtime view - see the corrections above).
2. Push elapsed time into the shader var: `gpg::time::GetSystemTimer()` ->
   `Timer::ElapsedSeconds`, then `if (ShaderVar::Exists(&shaderVarPrimBatcherTime))
   shaderVarPrimBatcherTime...SetFloat(t)`.
3. Playable rect from `mWldMap->mTerrainRes->mMap->mPlayableRect`
   (x0/z0/x1/z1) - used to reject deposits outside it.
4. Same `MakeViewportPixelProjection` screen matrix + `SetViewMatrix(Identity)`.
5. `mSimResources.resources->DepositCollides(&camera->mSolid2, heightField,
   &deposits, 0)`.
6. Per deposit - records are **20 bytes**: `x0,z0,x1,z1,type` - centre is the
   midpoint of x0..x1 / z0..z1; reject unless inside the playable rect;
   `elevation = CHeightField::GetElevation(cx, cz)`; depth-reject when
   `dot(viewport.r[1], (cx, elev, cz)) + viewport.r[1].w <= UI_ResourceLODCutoff`
   (**row 1** here, unlike tree C's row 2); project through `mViewProjection`,
   `floor` both screen coords; append to the **mass** point list when
   `type == 1`, otherwise to the **hydrocarbon** list.
7. Two splat passes, `/env/common/splats/mass_strategic.dds` then
   `/env/common/splats/hydrocarbon_strategic.dds`, both loaded with border=1.
   Half extents are `tex->mWidth >> 2` and `tex->mHeight >> 2` (note **>>2**,
   not >>1 as in the projectile icon pass). One quad per point, then `Flush`.

**HAZARD - do not write this one from the `.c`.** IDA has aliased the
hydrocarbon point vector onto the projection-matrix locals: the decompile
literally pushes points through `LODWORD(v66.d[3].d[1])` where `v66` is the
`VMatrix4`. The mass list (`v72`/`v73`/`v74`) is printed correctly, the second
one is not. Vertex ordering in both `DrawQuad` calls is likewise scrambled
across `a3`/`a4`/`v58`/`v60`. Take the point-list pushes and the two quad
orderings from `FUN_00862A80.asm`, the same way tree C's `sub_829190` has to be
done. `UI_ResourceLODCutoff` is another CVar that needs declaring.

Dependencies that are NOT yet in `src/sdk/**` (check before starting): the
`shaderVarPrimBatcherTime` shader-var lane, `UI_ResourceLODCutoff`,
`CSimResources::DepositCollides`, and `CHeightField::GetElevation` all returned
nothing from a header grep. `CWldSession::mSimResources`
(`boost::SharedPtrRaw<CSimResources>` @0x0424) and `mWldMap` (@0x001C) do exist.
So RenderResources is NOT the zero-dependency job RenderProjectileIcons was -
scope those four first.

### RenderResources: asm facts already extracted (do not re-derive)

All four "missing" dependencies **do exist** - my header-only grep was too
narrow. `CSimResources::DepositCollides(CGeomSolid3*, CHeightField*,
gpg::fastvector<ResourceDeposit>*, EDepositType)` (CSimResources.h:86),
`CHeightField::GetElevation(float x, float z)` (**STIMap.h:147**),
`ShaderVar` + the `GetPrimBatcher*ShaderVar()` accessors (ShaderVar.h:191-193).
`ResourceDeposit` is `{gpg::Rect2i footprintRect; EDepositType depositType;}`
= exactly the 20-byte stride, with the type at **+0x10**.

Lesson for the closure query: it counts *called functions* only. It rated this
"fully closed" while four globals/virtuals were unresolved. Referenced globals
and virtual dispatches are not in `call_edges`.

Still to declare: `UI_ResourceLODCutoff` @ **0x00F57B08** (float),
`shaderVarPrimBatcherTime` @ **0x010C4340** (its `.effectVar.var` at
0x010C4380) - there is no `GetPrimBatcherTimeShaderVar()` accessor yet, add one
next to the three existing ones.

**The two point lists are real and separate** (IDA aliased the second onto the
`VMatrix4`): both are 8-byte-element (`Wm3::Vector2f`) fastvectors pushed
through `sub_7A24B0`, at 0x00862FCD (mass) and 0x00863025 (hydro). The selector
is `cmp dword ptr [esi+eax+10h], 1` at 0x00862FA4 - i.e.
`deposit.depositType == 1` picks mass. The pushed pair is (flooredScreenX,
flooredScreenY).

**Quad ordering is still OPEN and is the one thing left to pin.** Before the
first `DrawQuad` (0x0086324A) there are only **three** pushes -
0x00863167, 0x00863193, 0x008631C2 - plus a `lea eax, [esp+924h+var_878]` at
0x008631C6 that is never pushed. So this is not a plain `__thiscall`: the
fourth vertex travels in **eax** (IDA names it `eax0`, and the decompile has a
matching `int eax0` local). Work out the mapping from the second pass
(0x0086344B) before writing, and do not trust the `.c`'s a3/a4/v58/v60 naming.

### RenderResources quad decode - progress + the exact recipe that works

`esptrace2.py` does not run on this function (its `CLEAN` table lacks these
calls) but it already encodes the key fact: **`('DrawQuad', 12)` - "4 args, one
in eax"**. Confirmed independently: before both `DrawQuad` calls there are only
three pushes plus a `lea eax, <vertex>` that is never pushed.

Working recipe for frame offsets in this listing - the invariant is
`encoded_disp32 - IDA's own "esp+XXXh" base`, NOT a hand-tracked esp (that
double-counts, because IDA's base already moves with each push):

    for each insn: find the byte after SIB `24`, read disp32 little-endian,
    subtract int(re.search(r'\[esp\+([0-9A-Fa-f]+)h\+', operand)), print.

Second pass (hydro, 0x00863370-0x00863450) yields, frame-relative:

    lea  -0x878  (pushed 1st -> LAST param)
    lea  -0x890  (pushed 2nd)
    lea  a3      (pushed 3rd -> first stack param)
    lea  a4      -> eax, the register param
    stores: -0x894 -0x890 -0x88C -0x888 -0x880 -0x87C
            -0x878 -0x874 -0x870 -0x868 -0x864
            -0x8A4 -0x8A0 -0x898

**OPEN:** those stores do not tile cleanly into 24-byte `Vertex` records at the
bases the `lea`s suggest - the -0x894 group would end exactly where -0x87C
begins, but the -0x878 group then starts 4 bytes late, and one slot per vertex
is never written in the window I scanned. Either a store sits outside
0x863370-0x863450 (widen the scan to the whole loop body, 0x00863100 onward,
and do BOTH passes) or `Vertex` is being written partly through a different
base register. Resolve that before writing - a wrong winding is a real
behavioural difference, not a cosmetic one.

Do not write this function until the four bases and all 24 stores are
accounted for.
