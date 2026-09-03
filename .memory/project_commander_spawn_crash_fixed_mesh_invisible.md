---
name: project_commander_spawn_crash_fixed_mesh_invisible
description: "2026-09-02: THE COMMANDER RENDERS. Three defects fixed and runtime-verified: ResolveMeshResourceForLod was a stub (the skirmish-start crash); SetStance never republished bounds so Batch collected 0 meshes forever; and CAniPoseBone::GetCompositeTransform had its arms swapped so every skinned mesh was posed at the world origin. Commits 3647beec, d3b63a97, bf70e211."
metadata:
  type: project
---

## Landed and runtime-verified

| commit | what |
|---|---|
| `3647beec` | Recovered `func_GetModel` (0x00539BA0) as `moho::GetModel`; collapsed **five** open-coded duplicates |
| `82070e9d` | Recovered `ResolveMaterialTextureSheet` -> `ID3DDeviceResources::GetTexture`; retyped the six `MeshMaterial` sheet lanes to `ID3DTextureSheet` |
| `1c04d583` | Collapsed `GetModelResourceByPath` |
| `484e32af` | Collapsed `ResolveModelResourceByPath` + `ResolveCommandFeedbackModelResource` |
| `d3b63a97` | **`SetStance` -> `db.UpdateBounds(GetSweptAlignedBox())`, both overloads** |

### 1. The crash (fixed)

`ResolveMeshResourceForLod` in `moho/mesh/Mesh.cpp` was a stub whose body was
`(void)args; return {};`. Every `MeshLOD::res` was null, so
`Mesh::GetResource(0)` faithfully returned null and
`UserEntity::CreateMeshInstance` dereferenced it. The real callee is
`func_GetModel` at **0x00539BA0**. Eight call sites, five of which had each
open-coded their own copy -- see the table in the commit message of `3647beec`.

`MeshRenderer::CreateMeshInstance` had also substituted an `.empty()` test for
the real front-LOD load probe at 0x007DF5AB/0x007DF5BC.

### 2. Mesh rendering was dead at the source (fixed)

`MeshInstance` registers into the mesh spatial DB in its ctor with a **NaN**
bounding box and nothing ever updated it, so `MeshRenderer::Batch`'s
`CollectAllInVolume` matched nothing: **`collected=0` on every frame, forever.**

Both `SetStance` overloads republish the bounds in the binary, right after
setting the dirty byte at `+0x15C`:

- `0x007DEA0B..0x007DEA1A` (plain)
- `0x007DEBD4..0x007DEBE4` (pose): set byte, `GetSweptAlignedBox`,
  `UpdateBounds` (0x00501C10) on `this + 0x0C` == `db`

Both calls were missing. After: `collected=13..20`, all accepted, zero
rejections at every gate, and unit models render in the portrait panel.

The pose overload also had an `UpdateInterpolatedFields()` the binary does not
make there (FUN_007DEA30 calls only GetSweptAlignedBox + UpdateBounds); removed.

## THE COMMANDER NOW RENDERS

`bf70e211` -- **`CAniPoseBone::GetCompositeTransform` had its two rebuild arms
swapped.** Skeleton bones never composed against the pose root, so every
skinned mesh was posed at the **world origin**. The commander was collected,
bucketed, had its material bound and was submitted to D3D every frame, and was
simply never anywhere near the camera.

Binary ground truth, FUN_0054BEC0 at 0x0054BED1:

- `mCompositeIsLocal` (+0x1D) **non-zero** -> local-only arm: 0x0054BED7 copies
  `mLocalTransform` (+0x20) into `mCompositeTransform` (+0x00), clears the
  dirty byte (+0x1C).
- `mCompositeIsLocal` **zero** -> `loc_54BF0C`: compose against the parent bone
  (+0x44), or with no parent against the pose root, reached as `[esi+40h]+0x0C`
  == `CAniPose::mLocalTransform`.

Skeleton bones carry the flag clear -- precisely the inverted case.

Evidence: pose root was already correct (`poseRoot=(672.5,18.7,346.5)` matching
`instPos`/`endPos`) while the palette held `(-0.0,0.0,0.0)` and
`(-0.0,-0.0,-0.1)`, i.e. raw bone-local offsets. After the fix a unit
silhouette with Cybran colouring renders on the map and the portrait shows a
detailed ACU.

### The GDI screenshot destabilises the D3D device -- do not blame the engine

Two of two runs that took a `CopyFromScreen` desktop grab threw the GPG
"Error Report" crash dialog within seconds of the capture. The run that did
**not** screenshot survived a full **150 s clean**. So `CopyFromScreen` over a
live D3D9 window is provoking a device-lost the engine does not survive; it is
the test harness doing it, not gameplay.

Consequences:
- Do not read a crash that lands right after a screenshot as a gameplay bug.
- Grab at most one screenshot per run, accept it may kill the process, and
  never use a screenshot run to judge stability -- use a separate no-capture
  run for that.
- This likely also explains earlier "process cannot access the file" incidents,
  where a screenshotted run left a wedged process holding `main.exe`.
- Handling D3D device-lost properly is a genuine (separate) robustness gap.

### Scale is CORRECT -- closed, negative result

The palette `w` lane read `0.02` and looked suspicious. It is not a bug:
`units/UAL0001/UAL0001_unit.bp` inside `gamedata/units.nx2` has
`UniformScale = 0.018`, and `0.02` was just my `%.2f` format rounding it. The
commander renders at exactly the blueprint scale.

(Reading blueprints directly is easy and worth doing before suspecting a value:
the `.nx2`/`.nx5` files in `C:\ProgramData\FAForever\gamedata` are plain zips,
openable with `System.IO.Compression.ZipFile`.)

### Still open: shadows render pure black (NOT a data bug) -- for the peer session

A hard-edged, opaque-black parallelogram lies flat on the ground, present in
**every** screenshot including ones from before this session's fixes. It is a
shadow being rendered fully opaque.

Measured, so the next person does not have to:

```
[FILL]      shadowFill=(0.5400,0.5400,0.7000)  sunAmbience=(0.0000,0.0000,0.0000)
[LIGHTDIAG] mult=1.540 sunDir=(0.616,0.559,0.555) sunColor=(1.380,1.290,1.140)
```

`ShadowFillColor` loads **correctly** and is bright, so shadowed pixels should
sit around 54-70% lit, nowhere near black. And because `ShadowFillColor` is read
*after* `SunColor` in the same `.scmap` lighting block
(`CWldMap.cpp` ~4755-4765) and comes out right, the stream alignment is sound
throughout -- this is **not** a loader/offset bug.

So the defect is in the shading: `shadowFill` is plumbed into both the mesh
(`Mesh.cpp:6004-6006`) and terrain (`HighFidelityTerrain.cpp:603-604`) shader
var sets, but shadowed pixels are not picking it up. Start at the shadow-map
sample and the fill blend, not at the map data.

**The MESH side is cleared** -- `MeshRenderer::ConfigureShader` (0x007E19D0) was
checked against the binary line by line: `shadowsEnabled`, `shadowMatrix`,
`shadowTexture`, `shadowBias`, `shadowSize`, `shadowBlur`, and crucially the
`else` arm that writes `shadowsEnabled = 0` when there is no shadow, are all
present and faithful. The artifact is on the terrain, and the terrain shading
path is where to look.

`sunAmbience = 0` is separately worth a sanity check against the real
`scmp_009.scmap`, but note the map file is **not** in FAForever's `gamedata`
tree -- it is mounted from the base FA install.

Both the terrain files and `CWldMap.cpp` were peer-locked (uncommitted work by
the concurrent session) for this whole run, so none of this was touched.

I briefly suspected the lighting reader was missing a `FogColor` (3 floats)
between `Bloom` and `FogStart`. **It is not** -- checked against the binary
(FUN_008A1700), which reads `mBloom` then exactly five fog floats
(`mFogInfo.v0..v4`) then the water-enabled byte and elevations, matching
`CWldMap.cpp` read for read. No bug; do not re-raise it.

### How this was found (method worth reusing)

Walk the pipeline stage by stage with **late-sampled** probes and check the
data at each hop: resource load -> spatial registration -> `CollectAllInVolume`
-> bucket -> material bind -> `DrawBatch` -> bone palette. The defect was in
the last hop, and every earlier stage looked healthy, so stopping early at any
of them would have produced a wrong diagnosis -- as it did twice here.

## Watch out

- `G:\tmp\tucheck.bat` and `dbgrun.exe` are **gone** from this machine. The gate
  used here is a plain incremental
  `msbuild G:\projects\faf-main\src\sdk\main.vcxproj /t:Build /p:Configuration=Debug /p:Platform=Win32`
  -- require `error C` count 0 and LNK2019+LNK2001 steady at 28+1.
- **Use an absolute project path.** The PowerShell tool's cwd drifts between
  calls; two builds silently failed with `MSB1009: Project file does not exist`
  and I read their stale-binary results as real evidence. Always check the tail
  of the build log for the `Staging main.exe` line before trusting a run.
- Screenshots need the DPI-aware helper (full 3840x2160 grab, then crop the
  game window at roughly `1108,250,1030,810`).
