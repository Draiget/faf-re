---
name: project-terraincommon-slot5-rendercontext-landed
description: TerrainCommon slot 5 (per-frame render-context update) landed and runtime-verified 2026-08-19 (fa0d3a2+d553c92) - fixes null-mCamera crash on scmp launch. Confirmed distinct from the earlier CRenderWorldView-vtable and SkyDome/ResourceManager bugs, both already fixed.
metadata:
  type: project
---

Landed and **runtime-verified** (not just compile-clean) a third, separate
render-pipeline blocker, after [[project-black-screen-is-renderworldview-vtable]]
(fixed `fdf0def`) and the SkyDome/`ResourceManager::ManageWatchedResources`
garbage-pointer bug from [[project-black-screen-fixed-skydome-next]] (fixed by
someone else's `0bb118a`, "Initialize SkyDome's watched-resource storage in
its constructor" - confirmed via `git log`, landed before this session's test
run).

## Root cause

`TerrainCommon` vtable slot 5 ("Func3"/`UpdateRenderContext`) was never called
anywhere in `src/sdk/**` - `WRenViewport::Render` never dispatched through it.
So `mCamera` (and the 6-int viewport block) stayed null/zero on all three
fidelity classes forever, and the first real terrain draw call dereferenced a
null `GeomCamera3*` (fault offset 0x5C = `GeomCamera3::view`).

## What landed (commit `fa0d3a2`, README `d553c92`)

- `CTesselator::Rebuild` (Func1) + `CollectClippedCollisionIndicesInRect`
  (Func6) + their quadtree/clip-polygon helper chain (12 fns total).
- `Low/Medium/HighFidelityTerrain::UpdateRenderContext` - each independently
  verified against its OWN disassembly, not copy-pasted between the three:
  they diverge in real ways. Medium/High gate the decal LOD-area-threshold
  check on `fidelity != 0` (fidelity 0 always passes); Low skips
  unconditionally on `fidelity > 0`. Only High stores the 6-int viewport
  block and owns a `Shoreline` member. Only High refreshes each visible
  splat's vertex positions every frame (`CWldSplat::UpdateVertices()`)
  before appending.
- `Shoreline::Update` (new, 0x00812E80) - confirmed byte-for-byte against
  raw asm, NOT trusted from the Hexrays pseudocode (which carried an
  explicit "local variable allocation has failed" reliability warning).
  Building a 24-byte-per-record shoreline mesh from `ShoreCell::mPoints`
  triples; the GPU-side semantic meaning of the record fields is NOT
  resolved (kept as an opaque byte blob, `ShorelineMeshRecord`), but the
  byte-level copy pattern (which `mPoints[i]` goes where, per record) is.
- `TerrainCommon::UpdateRenderContext` promoted to a base pure virtual now
  that all three fidelity classes implement it.
- `WRenViewport::Render` call site wired in right before
  `RenderTerrainNormals`, matching the binary's dispatch order
  (0x007F93A6-0x007F93C7).

## Runtime verification

Built `main.vcxproj` (MSBuild.exe direct invocation - see
[[reference_msvc_dev_shell_vswhere_broken]]), ran twice via
`.vscode\run-engine.bat nobuild map <name> for 40` (PowerShell, not Bash -
Git Bash mangles the leading-slash engine args). First attempt used the bare
map name `dualgap_adaptive`; `FixupMapName` did NOT resolve the versioned
folder despite `run-engine.bat`'s own doc comment claiming it would - had to
retry with the literal `dualgap_adaptive.v0014`. Second run: full session
launch (scmap mounted, 606 units/393 projectiles loaded, 11 AI armies
created, save/script loaded), ran the full 40s window, 28,139 lines of
`engine.log`, zero `CRASH:`/`violation`/`fault` (case-insensitive) anywhere,
zero Windows Application-Error events for `main.exe` in the run window
(`Get-WinEvent -FilterHashtable @{LogName='Application';
ProviderName='Application Error'; ...}` confirms). The old crash happened at
the very first terrain draw call, right after world-view creation - this run
got through map/blueprint/AI-army load and sustained per-frame execution for
40 continuous seconds without it.

## How to apply

The terrain render pipeline plus SkyDome plus the command-graph/vtable chain
are ALL now believed functional end-to-end for a `/map` skirmish launch. If
a future session sees a NEW terrain or render crash, do not assume this
keystone regressed without checking first - `git log` on `TerrainCommon.h` /
`{Low,Medium,High}FidelityTerrain.cpp` / `Shoreline.cpp` for what changed
since `fa0d3a2`, and re-run the same `run-engine.bat ... map
dualgap_adaptive.v0014 for 40` recipe to reproduce before diagnosing further.
