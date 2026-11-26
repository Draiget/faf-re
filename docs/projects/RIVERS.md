# Rivers: moving water with a sloped surface, foam and splashes, and waterfalls that block units

Status (2026-11-12): **design, user decisions taken (section 8: all twelve recommendations accepted); S1 and S2 (PR A, the sim part) built on branch `rivers/sim`** (section 10); **S3 and S4 (PR B part 1, the sloped surface and the flow) built on branch `rivers/render`** (section 11); **S6 (waterfall look, splash, spray, foam) built on `rivers/falls`** (section 12). Both are merged in `visuals-all`. S5, S7 and S8 (simulation foam, editor) are not built.
Base: branch `visuals` (`fdd72cb77`), which carries upstream's water bodies and our water simulation. Every statement about the code in sections 1 to 9 was read from the tree named at the top of each section, and what is a guess says so.

Request: "real moving rivers with height based flow rate, splash particles and foam as well as waterfalls (they should block unit movement too)".

## 0. Summary of the recommendation

| Question | Recommendation |
|---|---|
| Data model | A river is a **water body with a centreline** (`River = { Points = { {x, z, level, halfWidth}, ... } }`, a few lines in `_scenario.lua`, and the same data in a new `RIVR` sim chunk of the Extended map format). The engine **derives** a per-vertex level field and a flow direction from it, at map load, with float code that has no library maths (the way the outline spline is derived). Not a baked texture, not a plane per body, not derived from the heightfield. |
| Waterfall | A point of the centreline marked `Fall` where the level steps from `level` (above) to `Below`. The level **step** is the definition; the sim blocks every cell whose wet corners differ by at least 0.75 units. |
| Rendering | Sloped surface = per-block water mesh with its own y (same `WaterBodySurfaces` meshes, one patched line in the vertex shader); flow = a flow texture (direction + speed per 2 x 2 block) read by the patched `water2.fx` pixel shader with the two-phase scrolled normals; foam = static white-water pattern in the pixel shader from a turbulence channel plus an advected, source-fed foam channel in the existing compute simulation. |
| Particles | Render only, in the style of `WaveGenerator` (`WaveSystem.cpp`): a client module that calls `sWorldParticles.AddWorldParticle` / `AddBeam` from the camera's view, with global random and the system clock. The sim never sees them. |
| Waterfall look (v1) | A curtain of vertical beams (the existing `SWorldBeam` ribbons) + mist and splash particles + a foam source at the base. A geometric sheet through the patched water pass is the upgrade, behind a spike (section 4.2). |
| Blocking | Derived rule inside `STIMap::OccupancyCapsOfFootprintAt` and `OCCUPY_MobileCheck` (both read the same data): a footprint that touches a fall cell has no capability. A steep bed alone is **not** enough (section 4.1). Air is not affected. |
| Sim risk | Gated by a new `EFafSimFix::WaterRivers` (`sim_FixRivers`, unreleased, default off). Without a `River` key every code path is the one that exists today. All sim data is derived from the map, so every client and every replay gets the same bytes. |
| PRs | Two, both after the water PR: **A, sim** (data model, level field, falls, occupancy; `Sim behaviour changes`, replay table needed) and **B, render** (sloped surface, flow, foam, particles, falls; no `src/moho/sim` path except the accessors A already added). |

## 1. What exists today (evidence)

* **Water bodies are upstream's, flat, and written in the scenario.** `src/moho/sim/WaterBodies.{h,cpp}` (`CWaterBodies`: a body number per vertex and per cell, at most 255,
  `SWaterBody::elevation` one float per body), `src/moho/sim/STIMapWaterBodies.cpp` (`STIMap::InstallWaterBodies` reads `ScenarioInfo.WaterBodies`), `docs/WATER_BODIES.md`
  ("Levels are flat. A sloping river or a waterfall is several bodies, each at its own level."). The player-facing switch is `sim_FixWaterBodies`
  (`EFafSimFix::WaterBodies`, `kFafGameVersionUnreleased`, `src/moho/sim/FafGameVersion.{h,cpp}`), constant for a session, taken from the replay header or game version.
* **Every sim reader already asks per position.** `STIMap::GetWaterElevationAt(x, z)` and `GetWaterElevationAtVertex(x, z)` (`STIMap.h:856-872`) return the level of the place; about 60 call sites
  (`Entity.cpp`, `Projectile.cpp`, `CPlatoon.cpp`, `CAiPathSpline.cpp`, `ReconBlip.cpp`, `SimLuaGetters.cpp` ...) use them. A sloped level changes the numbers they get and nothing else about them.
  Direct readers of the sea level that are *not* per position (to audit in stage S1): `STIMap::SurfaceIntersectionWithWaterBodies` (`STIMap.cpp:3284`, one plane per body level),
  `MostVisibleWaterBody` and the reflection level (`WRenViewport.cpp:3226-3301`), `CTesselator.cpp:75` (`WaterBodyCrossesTile`), `Cartographic.cpp:1773`, `MeshRenderer.cpp:672`, `ClientConCommands.cpp:1601`.
* **Passability** is `STIMap::OccupancyCapsOfFootprintAt` (`STIMap.cpp:2940`) and the multi-cell `OCCUPY_MobileCheck` (`STIMap.cpp:3520-3600`): `IsBlockingTerrain` (a `Blocking` terrain type byte per cell, `TerrainTypes.lua`) -> 0;
  then the water depth range of the footprint's vertices, each under its own level (`WaterDepthUnder`, `ApplyWaterDepthRange`); then `mMaxSlope`, which strips **LAND and SEABED only**.
  The flow-field pathing of the `pathing` branch builds its grids "with the engine's own rule (`STIMap::OccupancyCapsOfFootprintAt`)" (`docs/PATHING_DESIGN.md` in `faf-re-pathing`), so one rule serves both movement systems.
* **Footprints** (`faf_repo/fa/lua/footprints.lua`): land `MaxWaterDepth 0.05, MaxSlope 0.75`; amphibious `LAND|SEABED, 25, 0.75`; hover `LAND|WATER, MaxWaterDepth 1..5, MinWaterDepth 0..0.1, 0.75`;
  naval `WATER, MinWaterDepth 0.25..1.5` (no slope entry); surfacing sub `SUB|WATER`.
* **Our water**: `docs/WATER_SIMULATION.md`. A 1024 x 1024 wave-equation window of half-unit cells (512 units) following the view centre, state `float4 (height, last height, foam, land flag)`, compute
  shader `SimCS` in `WaterSimulation.cpp` (`kSource`), `SimAddSource(x, z, radius, strength, foam, shown, kind)`, **one domain per water** (`WaterDomains.h`: a table with the level and domain of every 2 x 2 block,
  appended to the shore buffer; a neighbour of another domain is a wall), a projected 255 x 255 grid per water that shoots each vertex onto the plane `y = WaterElevation` (`FafWaterGridPosition`, patched into `WaterVS`),
  and meshes per water (`WaterBodySurfaces.cpp`: runs of 2 x 2 blocks, vertices `{x, y, z, u, v}`, the vertex shader overwrites `y` with `WaterElevation`). The sim is **render only** and "nothing here reads game state back".
* **The block is already the unit of everything that draws water**: `WaterOfBlock(map, x, z)` (level, deep, abyss, body) feeds the baked water map (`CWldTerrainRes.cpp:472`), the owner texture, the domain table, the shoreline cut
  (`Shoreline.cpp:844`) and the meshes. A level that differs per block flows through all of them without a new concept. Upstream's water doc already names the missing piece for the terrain shader:
  "a level texture (one half-float texel per block ...)" (`WATER_SIMULATION.md`, "What is left").
* **Client particles without the sim**: `WaveGenerator::Update` (`WaveSystem.cpp:~820`) builds an `SWorldParticle` and calls `sWorldParticles.AddWorldParticle(particle, nullptr)` with `MathGlobalRandomRange` and the system
  timer, from `WaveSystem::Update(camera, elapsed, tick)`, which only sees generators in view (`CollectInView` every 5th tick). `CWorldParticles` also has `AddBeam`, `AddParticles(const SParticleBuffer&)`.
  Sim-made effects go through `IEffectManager` -> `sim->GetParticleBuffer()` -> `CWldSession::ApplyBeatEffects` (`CWldSessionCore.cpp:1760`); the effect manager is the wrong door for a render-only river.
* **The map-formats fork** (branches `map-formats-sim`, `map-formats-all`; not upstream, "no PR until told") has, in `docs/mapformat/EXTENDED.md`: `WBOD` with `kind 2 river` but a **flat** `f32 level`; render-class `WFLW` (flow map, i8 x 2, instance per index) and `WVIS.flowScale/flowMap`
  whose engine implementation "reduces a flow map to its mean vector" ("the per-pixel flow map [is] not used"); `SPLN kind 1 river` (render, "documents what the editor already baked"); `GPLY` surface flags `BLOCKING` and the `walk_*` masks.
  The container has feature bits, per-chunk versions and "additive revision" rules (`CONTAINER.md` sections 4 and 9), so a new sim chunk is a revision bump with a feature bit.
* **Floating point is already pinned**: `cmake/FafCodegen.cmake` builds with `-ffp-model=precise -ffp-contract=off` (clang) / `/fp:precise` (MSVC), so `+ - * / sqrt` in a fixed order are bit-identical on x86 and x64 builds.
* **CI**: `.github/scripts/pr-sim-impact.js` treats `src/moho/(sim|unit|ai|entity|command|collision|path|projectile|vision|script|math)/` as sim code; a PR touching it must tick one of "Sim code touched" / "Sim behaviour changes" / "Replay or network only"
  and list at least one played replay (ID and result) in the Testing table (`docs/PR_REPLAY_CHECK.md`: core set of 8 replays).

## 2. Data model (question 1)

### 2.1 Options

| | (a) per-body tilt | (b) authored per-cell level + flow texture | (c) derived from the heightfield | **(d) centreline profile (recommended)** |
|---|---|---|---|---|
| Authoring | `Slope`, `Dir` on a body | paint two images | a river mask | a polyline with a level and a half-width per point |
| Meanders | no (a plane): needs a chain of bodies, 255 max | yes | yes | yes (Catmull-Rom as the outline) |
| Surface quality | steps at body borders | exact | follows every bump of the bed: a river surface is *not* the bed + depth (pools and riffles ripple the surface, a ford becomes a hill) | smooth, monotone by construction |
| Falls | border between bodies | painted step | none | explicit point |
| Where it lives | scenario Lua | new chunk with megabytes (a 1 km river is 1000 x 100 cells x 4 B) or a PNG next to the map | scenario Lua | scenario Lua (hundreds of bytes) and `RIVR` chunk |
| Sim determinism | trivial | trivial (bytes) | an algorithm over the whole map, order-sensitive | a bounded algorithm of `+ - * / sqrt` (section 2.3) |
| Tool/engine skew | none | the tool's algorithm is the truth, the engine just reads | engine only | engine only: the editor links the same `WaterRivers.cpp` for its preview |

(b) is the most general and the least editable; (c) cannot express a waterfall or a straight-ish smooth surface; (a) cannot follow a river. **(d) keeps the authored data small and human-readable, keeps one derivation (one source of truth), and still ends in a per-vertex table the sim reads.**
A derived cache (`DRVD kind river_field`, keyed by the SHA-256 of the input, already in the container spec) can be added later for load time; it is never required.

### 2.2 Authoring format

Inside `ScenarioInfo.WaterBodies` (`docs/WATER_BODIES.md`), a body with a `River` key:

```lua
{
    Name = 'Silverrun',                       -- optional, log and editor only
    River = {
        -- downstream order. x, z in map units; Level = water surface where the point is; HalfWidth = half the channel width at it.
        Points = {
            { 200, 100, Level = 48.0, HalfWidth = 6 },
            { 230, 140, Level = 46.5, HalfWidth = 7 },
            { 260, 150, Level = 40.0, HalfWidth = 7, Fall = true, Below = 33.5 },   -- surface above the lip 40.0, below it 33.5
            { 300, 200, Level = 32.0, HalfWidth = 9 },
        },
        Steps = 8,           -- polyline segments per span (default kWaterBodyOutlineSteps = 8)
        Margin = 2,          -- units of field kept beyond the half width (default 2; needed for the bilinear lookup)
        FlowScale = 1.0,     -- render only: multiplies the visual speed
    },
    Elevation = 40.0,        -- optional: with sim_FixRivers off (or an engine without rivers) the body is a flat lake here
    Seed = { 200, 100 },     -- optional: the first point
    Deep = ..., Abyss = ..., -- as for every body; default relative to the local level
}
```

Rules (all validated at load, a failing body is skipped with a log line as today): at least 2 points; levels are non-increasing along the points except across a `Fall` (`Below <= Level`); `HalfWidth` in [1, 64];
a point may carry `Fall` only if it is not the first or last; at most 16 falls per river; the river's vertex rectangle is at most 1/4 of the map or 4M vertices.

### 2.3 Derivation (pure, in `src/moho/sim/WaterRivers.{h,cpp}`)

Pure functions on plain values (no engine includes), so the headless lab, the host tests and the editor link the same file (as `WaterBodies.cpp` is linked by `faf_water_bodies_tests`).

1. **Polyline.** Open Catmull-Rom through the points (end points duplicated), `Steps` per span, using the code of `WaterBodyOutlinePolygon` (all in float, no library maths). Each polyline vertex gets the cumulative length `s`
   (accumulated with `sqrt` of squared segment lengths), a level and a half-width (linear in the span parameter), and the segment tangent. A `Fall` point is a break: the span before it ends at `Level`, the span after it starts at `Below`.
2. **Field.** For every height-field vertex inside the padded bounding box of each polyline segment (padding `HalfWidth + Margin`), compute the nearest point on the segment by projection (`dot / dot`, clamped); the vertex takes the segment with the smallest squared
   distance (ties: lower segment index), its level `L(v)` (linear along the segment), and the unit tangent. No `atan2`/`sin`/`cos`: the flow direction is stored as `i8 x, i8 z = floor(t * 127 + 0.5)`.
   Support of the field: `d^2 <= (halfWidth + Margin)^2`. Cost is the sum of segment area, linear in the river's area.
3. **Extent.** A vertex belongs to the river when `d^2 <= halfWidth^2` and `terrain(v) < L(v)` (strictly, like the fill). There is **no flood fill and no seed**: the channel width bounds the water, so a river cannot leak into a basin behind a ridge. Several rivers and
   ordinary bodies share vertices by the existing rule (the lowest body number owns a vertex); a confluence needs the two rivers to agree on the level where they meet (a loader warning when two bodies own neighbouring vertices whose levels differ by more than 0.25).
4. **Fall cells.** A cell whose corners include two river-wet vertices of that river with `|L(a) - L(b)| >= kRiverFallDrop` (0.75 units, a constant of the sim) is a *fall cell*. One bit per cell.

Storage per river (`CWaterRiver`, owned by `CWaterBodies`, one per river body):

```cpp
struct SRiverFall { float x, z, tx, tz, halfWidth, top, bottom; };   // from the Fall points, for the renderer and the lab
class CWaterRiver {
  std::int32_t x0, z0, x1, z1;          // vertex rectangle of the support, inclusive
  float baseLevel;                      // the lowest level of the river minus 1
  std::vector<std::uint16_t> level;     // per vertex of the rectangle: round((L - baseLevel) * 128), 0xFFFF outside the support
  std::vector<std::int8_t>   flow;      // per vertex: tx*127, tz*127 (2 bytes); 0,0 outside the support
  std::vector<std::uint8_t>  fallBits;  // per cell of the rectangle, bit packed
  std::vector<SRiverFall>    falls;
  std::vector<float>         centre;    // polyline x, z, level, halfWidth, s (the renderer's emitters and the editor)
};
```

Memory: 4 bytes per vertex of the rectangle + 1 bit per cell. A river 60 x 800 units: 48k vertices, 192 KB; a diagonal river whose rectangle is 800 x 800: 2.5 MB. Rivers larger than the limits of 2.2 are refused. 1/128 unit quantisation is the height field's own.

`CWaterBodies` gains (the existing `Build` stays as it is; a second build step adds the river fields):

```cpp
bool  HasRivers() const noexcept;  bool HasFalls() const noexcept;
float LevelAt(float x, float z, float sea) const noexcept;        // river cell: bilinear over the 4 corner levels (a corner without a value takes the nearest valid one); else as today
float LevelOfVertex(int x, int z, float sea) const noexcept;      // river vertex: its field value
float HighestLevel() const noexcept;                              // max over river levels too
bool  IsFallCell(int cx, int cz) const noexcept;                  // one lookup, false for a map without falls
bool  FlowAt(float x, float z, float& fx, float& fz) const;       // render (and the optional push of stage S8)
const CWaterRiver* River(std::uint8_t body) const noexcept;
```

`SWaterBody::elevation` of a river body = its highest level (so every consumer that reads it as "the body's level" stays inside the body's range); consumers that need the *range* (tessellator tile test, reflection) get `levelMin` / `levelMax`
added to `SWaterBody`. The `WaterBodies` summary line in the log grows `river, N points, M falls`.

### 2.4 Map format carrier (map-formats fork)

A new sim chunk `RIVR` v1 (class S, feature bit `WATER_RIVERS`, revision +1; `WBOD` unchanged): `array<river>` {`u16 bodyId` (of `WBOD`, `kind 2`), `u8 steps`, `u8 margin`, `array<point>` (2..256) {`fx32 x, z`, `f32 level, halfWidth`, `u8 flags` (bit0 FALL), `f32 below` if FALL}}.
The same data, the same derivation, hashed into `simHash` because it is S. `WFLW` stays what it is (render, optional hand-painted flow override, later); the spec text "WBOD kind 2 = river" becomes "needs a `RIVR` entry". This is a spec change in the fork only and does not block PR A, which uses the Lua carrier.

### 2.5 Fallbacks

* No `River` key: not one line of the new code runs (`HasRivers()` is false). The tests of section 7 compare the sim hash of the core replays.
* `sim_FixRivers` off but `sim_FixWaterBodies` on: a river body with an `Elevation` is a flat lake (today's behaviour); one without is skipped with a warning.
* Another engine or the original game: the map plays as sea only, as for any body (documented in `WATER_BODIES.md`).

## 3. Rendering (question 2)

### 3.1 Sloped surface

* `WaterOfBlock` returns the **block's own level** for a river: the average of the four corner levels of the block (corner = even vertex; the field exists there), `deep/abyss` relative to that level (default 2.5 and 15 below, as for every body). Everything that is per block follows: the baked water map
  (depth shading, shore mask), the domain table of the simulation (`levelRaw` per block), the shoreline cut. `CTesselator::WaterBodyCrossesTile` and `Cartographic` use `levelMin/levelMax`.
* **Meshes, not the projected grid, for rivers.** The grid shoots rays onto `y = const` and draws the whole screen window of the body's rectangle; a thin diagonal river wastes most of it, and the ray/plane step has no answer on a sloped surface (it would need a per-vertex march against a level texture, converging only
  for slopes below about 1 / tan(view angle)). `WaterBodySurfaces::BuildChunk` writes one quad per block for a river with the four corner levels as the vertices' `y` (the vertex format already has `y`), and the vertex shader patch becomes
  `inPos.y = waterLevelParams.z > 0.5 ? inPos.y : WaterElevation;` (one more line in `PatchWaterSimulation`, the anchor `inPos.y = WaterElevation;` already exists and is checked to occur once). 12,000 quads for a 60 x 800 river. The ripples of the simulation bend the normals
  as they do for any mesh; a lift of the vertices by `FafWaterRipple` is optional (2-unit vertices carry waves of 8 units and more).
* **Normal tilt from the slope**: the pixel shader adds the surface gradient (from the flow texture's slope channel, section 3.2) to `N` - a 5 percent grade is 3 degrees, so this is a polish item.
* **Reflection**: the planar mirror stays the sea's and the most-visible-lake's (`WRenViewport.cpp:3226`); a sloped river is not a mirror plane (a 5 unit drop over the view would displace the reflection by 10 units). Rivers use the sky cube and, when on, the screen-space reflections of `WATER_REFLECTIONS.md`, which do not need a plane.
* **Terrain**: `WaterBodyTerrainShaderLevel` is the highest level of the map, unchanged. The `FafSunUnder` limitation of `WATER_SIMULATION.md` ("What is left") applies to rivers as it does to lakes; a per-block level texture for the terrain effect fixes both and is **not** part of this design (it is upstream's open item).

### 3.2 Flow field and flow rate from the height gradient

A **flow texture**, one RGBA8 texel per 2 x 2 block (the owner texture's layout, `CreateDynamicTextureSheet2(sheet, texelsX, texelsZ, 2)`; 512 x 512 x 4 B = 1 MB for a 20 km map), rebuilt with the levels when `CWaterBodies::Generation()` changes:

| channel | content |
|---|---|
| R, G | unit flow direction (x, z), snorm in unorm: `0.5 + 0.5 d` |
| B | speed / `kRiverMaxSpeed` (6 units/s) |
| A | turbulence 0..1, 0 means "no river here" (the pixel shader branches on it, so a map or a pixel without river costs one tap) |

Speed from the height gradient and the depth, Manning's relation for open channels:

```
S   = |dL/ds|   along the centreline (central difference of the polyline levels over 2 units; 0 for a Fall segment, which is not a channel)
d   = max(L - terrain, 0.05)               per block, from the heightfield
v   = min(kRiverMaxSpeed, kFlowScale * (1 / n) * d^(2/3) * sqrt(S))     n = 0.04 (natural channel), kFlowScale = ren_RiverFlow / 100
T   = smoothstep(0.04, 0.10, S) + shallow(d)           shallow(d) = 1 - smoothstep(0.1, 0.8, d), only where v > 1: rapids, riffles and the water over a bump of the bed
```

Examples (units/s): S 0.01, d 1: 2.5; S 0.05, d 0.5: 3.5; S 0.002 (a pool): 0.4. `d^(2/3)` and `sqrt` live on the CPU in the texture builder (render only; no determinism issue). `ren_RiverFlow` 0 stops the visual flow; the sim never sees any of this.

**Pixel shader** (patched `HighFidelityPS`, same patcher, same "anchor appears exactly once" discipline as the existing patches): the four normal layers are computed in the *vertex* shader as `(xz + movement * Time) * repeat` and interpolated, which cannot be blended by phase.
For a pixel with flow alpha > 0 the pixel shader recomputes the layer coordinates from the world position it already reconstructs (`ViewPosition.xz - inV.mViewVec.xz`, as the existing patch does for the ripples) and uses the two-phase flow-map technique:
`t0 = frac(Time / P)`, `t1 = frac(Time / P + 0.5)`, `w = abs(1 - 2 * t0)`, `uv_i = (xz - flow * speed * t_i * P) * repeat + phaseOffset_i`, `W = lerp(tex(uv_1), tex(uv_0), w)` per layer (P about 3 s; 8 taps instead of 4, only for river pixels).
Foam: a noise-thresholded pattern (`kWaterFoamLookHlsl`, the same function the simulation foam uses) sampled on the same scrolled coordinates with threshold lowered by `T`, so rapids are white water and pools are clean, **independent of the 512-unit simulation window**.

### 3.3 Where the GPU wave simulation comes in

Three levels, each shippable alone; the lab (`tools/watersimlab`) is the test bed before any game run.

* **L1, shading only (stage S4).** Section 3.2. No change to `SimCS`. Cost: pixels of river only.
* **L2, foam in the simulation (stage S5).** The flow field is appended to the shore buffer as two more segments (the way the domain table was: "all four read-buffer slots of a dispatch are in use"), `StructuredBuffer<float> Shore` at the next offset. In `SimCS`:
  1. **foam advection**: `foam_prev = bilinear(Cur.z, cell - v * dt / cellSize)` (semi-Lagrangian, `dt` = 1/90 s; the shift is 0.02 to 0.07 cells per step, diffusion is fine for foam, which already blurs);
  2. **turbulence term**: `foam += T(block) * noise * 0.01` per step (rapids, riffles, fall run-out) - no sources, so no 4096-source budget; the bump foam of a rock or ford comes from `groundDepth` (already computed per cell from `Heights`) and `v`: `foam += v * (1 - smoothstep(0.05, 0.6, groundDepth)) * noise * k`;
  3. the **domain table**: blocks that contain a fall cell are written as "no water" (`kDryLevelRaw`) so a wave stops at the lip like at a beach; `DomainLevels` (the level of a domain = its first block) becomes per block for river domains in `ComputeShoreDistanceDomains` (`ShoreField.h`: it classifies a sample as land by comparing with the domain's *one* level).
  Rivers have a short wind fetch (narrow channel), so `calm` makes them quiet; the waves are the ones the flow makes.
* **L3, advecting the height (research, not committed).** The wave equation of a moving medium has a transport term; the explicit central-difference version is only conditionally stable when `v` approaches the wave speed (2.5 units/s: a mountain river at 3-6 is *supercritical*, ripples cannot go upstream, which is physically right). Semi-Lagrangian advection of `h` and `h_prev` is stable but
  bleeds 2 to 7 percent of the amplitude per step through bilinear diffusion; bicubic or a limiter costs 4x the taps. A lab experiment decides: a wave packet in a uniform 1, 3 and 6 units/s current, measured packet speed (must be `c +/- v`) and amplitude after 5 s. If it fails, L3 is dropped and the river keeps L1 + L2; nothing else depends on it.
* **Obstacles**: static meshes in the batch (rocks, props, bridge piers, a stopped ship) currently make no wake because the feed derives a wake from the hull's speed (`WaterMeshFeed.cpp`); with a flow the *relative* speed `|v_hull - v_flow|` is what matters, so the feed subtracts `FlowAt(position)` from the hull velocity - a rock in a current gets a bow wave and a wake. One line in the feed plus the flow lookup.

Per-API: the patched `water2.fx` is compiled on D3D11, D3D12 and Vulkan (the stage-1 requirement is the same as the existing patches; the effect source is translated per API); `SimCS` runs where `kGpuFeatureCompute` is set (all three targets; an API without compute keeps the shipped water and gets L1 only, which needs no compute). D3D9 is out of scope. Texture formats used: R8 (6), RGBA8 (2) from `DxgiFormats.cpp`; nothing new.

Cost budget (estimates, **not measured**; `WATER_SIMULATION.md` says the same of the existing grids): L1 = one flow tap for every water pixel plus 4 extra taps on river pixels. L2 = 4 extra taps of `Cur` for the advected foam plus 1 bilinear of the flow segment, per simulated cell, about 10 percent of `SimCS`. Textures 1 to 4 MB.
Gate: 0.3 ms at 1080p on the reference machine measured with GPU timestamps on a quiet machine (section 7), else the cvar default drops one level.

Console variables (all render only, live; rows to go into `docs/SWITCHES.md`): `ren_River` 1 (master), `ren_RiverFlow` 100 (visual speed, percent), `ren_RiverFoam` 100, `ren_RiverFx` 2 (particles: 0 off, 1 mist only, 2 normal, 3 dense), `ren_RiverFall` 1; the sim switch `sim_FixRivers` -1.

## 4. Falls: blocking, geometry (question 4)

### 4.1 Is a steep drop enough? No.

* A steep **bed** blocks LAND and SEABED movers only: `mMaxSlope` is applied when `(capsMask & kOccLandSeabed) != 0` and strips just those bits (`STIMap.cpp:2982-2990`, `3569-3596`). A naval footprint (`Caps=WATER`, no slope) and a hover footprint (`LAND|WATER`: the slope strips LAND, WATER stays) see a waterfall as two water cells with enough depth, and the path crosses it
  (a ship would "sail" up 7 units; its y would jump because the surface height is per cell).
* The existing upstream mechanism for a step between two flat bodies (stacked bodies cut by an outline) has the same hole today; upstream's docs do not claim otherwise.
* Authoring a `Blocking` terrain type (`mBlocking[]`, `IsBlockingTerrain`) along the lip would block everything (`OccupancyCapsOfFootprintAt` returns 0 for it) and the Lua `NavGenerator` honours it (`PopulateCaches`: `not GetTerrainType(absX, absZ).Blocking`), but it is a second thing to author, it has to follow the river's exact line, and the byte layer belongs to the `.scmap`.

### 4.2 The rule

In both occupancy functions, after `IsBlockingTerrain` and before the depth range:

```cpp
if (mWaterBodies != nullptr && mWaterBodies->HasFalls() && FootprintTouchesFall(*mWaterBodies, x0, z0, x1, z1)) {
  return static_cast<EOccupancyCaps>(0u);   // land, hover, naval, amphibious, submarine: none
}
```

`FootprintTouchesFall` is one `IsFallCell` bit lookup per cell of the footprint's cell rectangle (footprint cells `[x0, x1)`), behind the `HasFalls()` test, so a map without falls pays one load and a branch. Why this is a complete barrier: a fall cell is any cell with two wet corners on different sides of the level step; a path from above the step to below it needs a footprint that
covers vertices of both sides, and every such footprint contains a cell with wet corners of both levels (two cells diagonally adjacent share one corner, which belongs to one side). Dry bank cells at the lip are *not* fall cells (they need two wet corners), so land units on the bank are not trapped, which is the point of a cliff.

* **Land / amphibious / hover / naval / sub**: blocked. **Air**: unaffected. **Structures**: the same capability function says no, so nothing is built *on* the fall (to be confirmed in the scenario test; naval and land structure checks both go through `OccupancyCapsOfFootprintAt` for `OC_ANY`).
* **Hover**: allowed on rivers (depth rules as for a lake, the river is just water), not across a fall (open question 3).
* **Projectiles/shots** are not affected; surface height at either side is the level there.
* **AI navigation**: the engine pathfinder, the flow-field pathing and `CanPathTo` all call the function, so they agree. The Lua `NavGenerator` (FAF code, not ours) only knows terrain height and the `Blocking` type; it will plan a naval route through a fall that the engine then refuses (the AI orders a move that finds no path). Mitigation in stage S2: `STIMap::GetTerrainType(x, z)` (the Lua `GetTerrainType`) reports the descriptor of a blocking type for a fall cell. Small, deterministic, and fixes the navmesh without a FAF Lua change; the choice of which blocking type code to return is open (question 9).
* **Pathing grids that cache caps** (the `pathing` branch's `fieldnav`): static, built from the function, so a river map needs no invalidation: levels do not change during a game.

### 4.3 Determinism and replays

* The inputs are the scenario's numbers and the heightfield; the derivation is `+ - * / sqrt` in a fixed order under `-ffp-contract=off`. A golden CRC of the level/flow/fall arrays for fixture rivers is a host test that runs in the x86 **and** the x64 build (the tree builds both; `2p-main-x86-vs-x64-*.yaml` pair them in a game).
* Nothing render-derived (the flow texture, `FlowAt` speed, foam) is read by the sim. `FlowAt` returns the direction from the stored `i8` pair; the speed formula with `pow(d, 2/3)` is **render only**. If stage S8 (push) is ever done it must use a table or integer maths.
* `sim_FixRivers` is part of `gFafSessionSimFixes` (set by `FAF_BeginSession`; a replay plays with the version it was recorded with), like `sim_FixWaterBodies`. A replay of a map without rivers is unchanged bit for bit; the proof is the core replay set with the switch on and off (`docs/PR_REPLAY_CHECK.md`, "Performance switches" procedure).
* Desync surface: the field is built at load on every client from the same scenario text. A 2-client scenario (`2p-waterrivers-sync.yaml`, modelled on `2p-desync-state.yaml`) plays a river map x64-x64 and x86-x64 and compares the state hashes.

### 4.4 Waterfall rendering

Geometry source: `CWaterRiver::falls[]` (exact line: centre, tangent, half-width, `top`, `bottom`), not the staircase of fall cells.

**v1 (recommended): beams + particles + foam, nothing new in the water pass.**
* *Curtain*: `ceil(2 * halfWidth / 1.5)` vertical `SWorldBeam` ribbons from `(lip, top)` to `(base, bottom)`, width 1.8 (overlap), `mTexture1` a streak texture (the effect set has `/textures/particles/water_splash_alpha_01.dds`; a dedicated streak is a content task), `mVShift` negative scrolling downward at `sqrt(2 g H)` scaled, colour from the water colour with alpha 0.55-0.8, soft-particle depth fade at the base. Beams are the one textured-ribbon primitive the particle renderer already sorts and blends on all three APIs.
  To verify in the spike: whether `AddBeam` entries live for a frame or for a beat (the sim re-pushes `mBeams` every tick, `CEfxBeam.cpp:731`, so per beat is likely; the river module then re-adds each frame).
* *Splash at the base*: particles along the base line, `TRampAnimateFlat`-style like `WaveGenerator`, textures and ramps from the shipped emitter blueprints (`destruction_water_splash_wash_01_emit.bp`: `water_splash_alpha_01.dds`, `ramp_water_01.dds`), rate `~0.8 * width * sqrt(H)` per second, lifetime 1.2-2.5 s, upward velocity `0.25 * sqrt(H)`; **mist**: large, slow, soft (the Large Particle Quality target of `fed9ab0ae` applies), rate `0.25 * width`, lifetime 2-4 s, drift with the wind and the flow.
* *Foam and ripples*: a foam source along the base each frame (`SimAddSource(x, z, r = 2.5, strength = 0, foam = 0.25 * W, shown = false, kind = 0)`, one per ~3 units of width, only for falls inside the simulation window and in view) and the fall blocks (section 3.3) so the pool below is turbulent and the foam runs downstream with the current.
* *Sound*: out of scope; the map script can place an ambient sound at the fall (`falls` exposed to Lua as `GetRiverFalls()` is cheap, not required).

**v2 (upgrade, behind a spike): a geometric sheet through the patched water pass.** A second chunk list in `WaterBodySurfaces` (strip of `{x, y, z, u, v}` per fall), drawn after the surfaces with `waterLevelParams.z = 2`; the patched vertex shader keeps `inPos`, the pixel shader replaces the normal by a vertical scroll of the shipped layers and the colour by foam streaks, and needs alpha blending where the water pass uses an alpha *test*. The spike (a day, throw-away) answers: can a draw of the water effect use a blend state, does it see the refraction target correctly, and does the planar reflection pass treat it right on all three APIs. If yes the sheet replaces the beam curtain.

## 5. Particles and foam emitters (question 3)

A module `src/moho/terrain/water/RiverFx.{h,cpp}` with the same shape as `WaveSystem`:

* **At map load** (when `CWaterBodies::Generation()` changes): build an emitter list from the river data and cache it in a coarse grid of 64-unit buckets. Kinds: *fall* (from `falls[]`), *rapid* (centreline samples every 6 units where `T > 0.6`, width = local width), *obstacle* (blocks with `shallow(d) > 0.7` and `v > 2`, thinned to one per 8 x 8 units; plus props/units are not included: static meshes appear in the batch only at render time, section 3.3).
* **Per frame** from `WRenViewport::RenderWorldView` next to `WaveSystem::Update` (same call signature `(camera, elapsed, tick)`): the buckets in the camera's near range (`ren_RiverFx` 1-3 -> 150, 250, 400 units); emission budget per frame and live particle cap (1500) by level; emission by an accumulator per emitter with the global random stream
  (`MathGlobalRandomRange`) and the system timer, exactly the `WaveGenerator` pattern. The pause: the system timer keeps running while the game is paused; river particles follow the water clock (`SimSourceWeight`/`gameTime` of the simulation, which stops with the pause) so a paused game does not keep spraying. Decision in question 11.
* **Placement of a particle**: position on the water surface (`LevelAt`), velocity = `FlowAt * speed` plus an emitter-specific burst, so rapids throw spray downstream. Pure functions (emitter rate, spawn position/velocity from a seed and a clock) in `RiverFx.h` so the lab and a host test can drive them without a device.
* **No sim contact**: it reads `CWaterBodies` and the clock only; it creates no `IEffect`, no entity, writes no sim state, and uses the process-global random stream (the one `WaveGenerator` and `CEfxEmitter` already use for visuals). Headless installs nothing.

Why not the effect manager: `CEfxEmitter::Tick` takes the sim (`mManager->GetSim()->mMapData`, `sim->GetParticleBuffer()`), pushes into the sim's submit buffer, and the effect set is replicated by the dedicated-server plan (`EffectOps.h`). Creating effects from the renderer would put render-time state into a sim object. The blueprint *content* (textures, ramps, size curves) is reused by reading the blueprint, not the machinery.

## 6. Staging (question 5)

Sizes are estimates of added lines (C++ / HLSL strings / tests+docs). "Replay" says what the PR's Testing table needs.

| # | Stage | Files | Size | Tests | PR |
|---|---|---|---|---|---|
| S0 | Spikes (throw-away, no commit): (1) a draw through the patched water pass with blending (v2 sheet); (2) `AddBeam` lifetime; (3) lab: advected foam and a wave packet in a current (L3); (4) vertex y kept for river meshes | scratch | - | notes in this document | - |
| S1 | **Sim data**: `WaterRivers.{h,cpp}` (polyline, field, falls, golden), `CWaterBodies` river storage and the new accessors, `STIMapWaterBodies.cpp` parse of `River` (+ log lines), `FafGameVersion.{h,cpp}` `EFafSimFix::WaterRivers` (7, `Count` 8), audit of the direct level readers (`SurfaceIntersectionWithWaterBodies` marches the river, `levelMin/Max`) | `src/moho/sim/WaterRivers.{h,cpp}` (new, ~700), `WaterBodies.{h,cpp}` (+200), `STIMapWaterBodies.cpp` (+150), `STIMap.cpp` (+60), `FafGameVersion.*` (+15), `docs/WATER_BODIES.md` (+60) | ~1,200 | `tests/sim/WaterRiversTests.cpp` (new target `faf_water_rivers_tests`, ~25 checks: polyline, nearest segment, quantisation, extent without leak, ties, golden CRC, fall bits, confluence warning, bounds/limits), `WaterBodiesMapTests.cpp` (+8: `GetWaterElevationAt` along a sloped river, vertex lookup, caps depth) | **A (sim)** |
| S2 | **Falls block**: `FootprintTouchesFall` in `OccupancyCapsOfFootprintAt` and `OCCUPY_MobileCheck`; `GetTerrainType` reports Blocking at a fall cell; docs | `STIMap.cpp` (+60), `STIMapWaterBodies.cpp`, `docs/WATER_BODIES.md` | ~150 | `WaterBodiesMapTests.cpp` (+10: every footprint class of `footprints.lua` against a fall, a ford next to it, a bank cell, a structure, a diagonal path, a map without falls unchanged); in game `1p-waterrivers-main.yaml` (below) | **A** |
| S3 | **Sloped surface**: `WaterOfBlock` per block; river meshes with per-vertex y; one patched VS line; baked water map and domain table per block; shoreline/tess/cartographic ranges; reflection policy; `ShoreField.h` per-block levels | `WaterBodySurfaces.{h,cpp}` (+250), `WaterSimulation.cpp` patch (+10), `WaterDomains.h`/`ShoreField.h` (+60), `CTesselator.cpp` (+20), `Cartographic.cpp` (+20), `WRenViewport.cpp` (+15) | ~450 | `tests/water/WaterDomainTests.cpp` (+6 per-block levels), lab `domains` (+1 check: a sloped basin), `faf_water_tests` (patch applies exactly once) | **B (render)** |
| S4 | **Flow**: flow texture builder, pixel-shader patch (two-phase layers, static rapid foam), Manning speed, cvars, registry entry (Options > Video), docs | `RiverFlow.{h,cpp}` (new, ~350, speed/turbulence pure and shared with the lab), `WaterSimulation.cpp`/`WaterEffectPatch.cpp` patch (+80 HLSL), `WaterShaderVars.cpp` (+30), `RenderFeatures` row, `docs/SWITCHES.md`, `docs/WATER_SIMULATION.md` | ~550 | host test of speed/turbulence formulas and the texel encoding; patch test on the real `water2.fx`; in-game flow-direction measurement (section 7) | B |
| S5 | **Foam in the simulation** (L2) + obstacle wakes relative to flow; fall pool cells as walls; L3 only if the lab says yes | `WaterSimulation.cpp` `kSource` (+60 HLSL), segment upload (+60), `WaterMeshFeed.cpp` (+25), `WaterSimParams.h` | ~250 | `watersimlab` new group `river` (4 checks: foam transported at v within 10 percent, no change on a map without rivers: **the `--dxbc` hash of `SimCS`/`SimCopyPS` of the non-river variant stays byte for byte**, wall at a fall, uniform current packet speed if L3); a river variant of `SimCS` behind a define like `FAF_DOMAINS` | B |
| S6 | **Falls and splashes**: `RiverFx.{h,cpp}` (emitters, particles, beams, foam sources), content (streak texture reference), spike result for v2 | `RiverFx.*` (new, ~600), `WRenViewport.cpp` (+10), `WaveSystem` untouched | ~650 | pure emitter tests; screenshots per API | B |
| S7 | **Authoring and content**: reader/writer of `River` in `EdWaterBodies.{h,cpp}` (round trip, unreadable-body rule as today), a polyline tool and fall markers in `EdWaterBodyView`, bed carve op, `make_map.py` river variant and the scenario | `src/editor/doc/EdWaterBodies.*` (+250), `src/editor/view/EdWaterBodyView.cpp` (+300), `tools/scenarios/water-rivers/make_map.py` (+350) | ~900 | `tests/editor/WaterBodiesEditTests.cpp` (+10), scenarios | B (editor is its own area; may go as C) |
| S8 | *(optional, sim)* current pushes units: speed modifier by `FlowAt` for non-air mobile units | `Unit::UpdateInfoCache` path, `WaterBodies` | ~150 | needs its own replay set | **only if the user asks** (question 4) |

Merge order: S1 -> S2 (PR A, sim, replay table required); S3 -> S4 -> S6 -> S5 (PR B, render, after A; `src/moho/sim` untouched except accessors A added); S7 with B or on its own. S0 runs first, before S3.

PR A needs "Sim behaviour changes" ticked? The behaviour changes only for maps with `River` and the switch on, so the honest box is "Sim code touched, no behaviour change for existing maps" plus the new-map scenario; list the core replay set (8 IDs) with the switch on and off, plus extended set because occupancy is pathfinding-relevant (`PR_REPLAY_CHECK.md`: "Run it as well for changes to pathfinding").

## 7. Test and verification plan

* **Host**: `faf_water_rivers_tests` (pure), `faf_water_bodies_map_tests` (+18, headless `STIMap` as the existing file builds one), golden CRC compared in the x86 and x64 build, `faf_water_domain_tests` and `faf_water_tests` extended. Counts reported with each stage.
* **Lab** (`tools/watersimlab`): `python tools/watersimlab.py river` (S5): foam advected by a current, wall at a fall, parity (the non-river variant of the shader compiles to the same bytes as today; `--dxbc`).
* **Scenario map**: `tools/scenarios/water-rivers/make_map.py` builds from SCMP_012 (as `water-levels` does): a 60 x 700 meandering river with a rapid (S 0.08), a pool (S 0.002), a 7 unit fall (`Fall = true`), a confluence with a tributary, a ford (bed raised to depth 0.04), and rocks (bed bumps). `1p-waterrivers-main.yaml` (modelled on `1p-waterlevels-main.yaml`, `sim_FixWaterBodies=1 sim_FixRivers=1`) prints `RIVERTEST PASS|FAIL`:
  `GetSurfaceHeight` along the centreline equals the profile within 0.02; a frigate spawned above the fall ordered below it stays above (move order result and position after 60 s); a hover tank likewise; an amphibious unit and a tank likewise; the tank crosses the 0.04 ford; a structure cannot be placed on the fall; air passes; with `sim_FixRivers=0` the control run: the body is a flat lake (or skipped) and the checks fail as `water-levels` documents.
  `2p-waterrivers-sync.yaml`: two clients, x64-x64 and x86-x64, state hashes equal after 5 min.
* **In game, per API** (D3D11, D3D12, Vulkan; windowed 1600 x 900; the scene runner of `scratchpad\featab_prl.ps1` with frame dumps via `FAF_GAL_DUMP_DIR`): camera at the rapid, the fall, the confluence, the ford; frames converted and viewed.
  *Flow check* (numeric, not by eye): two frames 0.5 s apart at the same camera, cross-correlation of the water's normal-map luminance along the flow direction; the shift must equal `v * 0.5 s` within 20 percent. *Slope check*: the water mesh edge at the two ends of a straight reach differs by the profile. *Particles*: count of live particles under the cap, none when `ren_RiverFx 0`.
  *Cost*: GPU timestamps with and without `ren_River` on a quiet machine (other sessions' games inflate GPU timings; the baseline repeated), reported per API.
* **No-regression**: a map without water bodies and a map with flat bodies: frames of the new build equal the old build's within the noise of two old runs (the method of `WATER_SIMULATION.md`, "Verified"), `SimCS` code hash unchanged for the non-river variant.

## 8. Open questions for the user (with my recommendation)

1. **Carrier**: Lua `River` in the scenario now, `RIVR` chunk in the map-formats fork later, no baked textures and no change to the `.scmap`? *Recommend yes.* (Alternative: a precomputed field texture, more general, much larger, and a second source of truth.)
2. **What a fall blocks**: land, amphibious, hover, naval, submarine, and structure placement on it; air free. *Recommend yes.* (Alternative: leave hover free, "hover skims a fall" - gameplay sneak; no.)
3. **Hover on rivers**: allowed (a river is water; depth rules as for a lake). *Recommend yes*, across a fall no.
4. **Does the current push units?** *Recommend no for the first release*: purely visual flow. It changes unit speeds and so the AIs' build/attack maths, needs its own balance and replay work, and the data (`FlowAt` direction) is already sim-grade so it can be added later as S8 (a bounded speed modifier for non-air movers, +/-15 percent along the current, table-driven).
5. **Switch**: a separate `sim_FixRivers` (unreleased, default off) beside `sim_FixWaterBodies`? *Recommend yes*; rivers degrade to flat bodies when it is off.
6. **Fall definition**: derived from a level step of at least 0.75 units between neighbouring wet vertices (also catches stacked flat bodies, but only inside a river's own cells), vs. only where the author wrote `Fall = true`. *Recommend the step rule with `Fall` as the authoring tool; the threshold is a sim constant (`kRiverFallDrop`).*
7. **Waterfall look in v1**: beam curtain + particles (works on all APIs, no new pass, lower fidelity) now, geometric sheet after the spike. *Recommend this order.*
8. **PR split**: A sim then B render, both after the water PR; editor tool separate. *Recommend yes.* The render PR does not touch the sim paths of the CI check.
9. **Navmesh**: report a Blocking terrain type for fall cells through `GetTerrainType` so FAF's Lua `NavGenerator` agrees with the engine? *Recommend yes*, which type code to return (e.g. the first `Blocking = true` entry in `TerrainTypes.lua`, `Dirt09` = 9, or `Lava01` = 230) is a content decision; or no change and accept AI orders that find no path.
10. **Scope of the simulation window**: the 512-unit window means ripple and L2 foam only near the view centre; far river keeps the shader-only flow and rapid foam (by design). Accept? *Recommend yes.*
11. **Pause**: river particles and the flow scroll follow the game clock (stop in pause, like the water simulation) rather than the system clock. *Recommend the game clock.*
12. **Precision of the level field**: 1/128 unit (the heightfield's own quantum) and bilinear lookup; rivers whose rectangle exceeds 4M vertices or 1/4 of the map are refused. *Recommend yes.*

## 9. Recommended order of implementation

1. **S0 spikes** (two days of throw-away probes): blend through the water pass, beam lifetime, the lab experiment for advection, per-vertex y in the patched VS. Their results change the waterfall decision (v1 vs v2) and L3.
2. **S1 + S2** (PR A): the sim part first, because it fixes the data model every other stage reads and is the part with replay obligations. Fixture tests and the golden hash first, then the parser, then the accessors, then the occupancy rule, then the scenario map (the map is also what S3-S6 are tested on).
3. **S3** sloped surface (visible result at once: a river that runs downhill and shades by its own depth), **S4** flow shading (the "moving" in moving rivers; L1 needs no compute), **S6** falls and splash (the visible features), **S5** simulation foam last (the only stage that touches the compute shader and needs the lab parity proof; if the budget is tight it is the one to cut or ship Off).
4. **S7** editor tool in parallel with S3-S6 (the editor links the same `WaterRivers.cpp`, so its preview is the engine's).
5. **S8** only on request.

Not verified in this design (marked where it matters): GPU costs; the water-pass blend for a sheet; `AddBeam` lifetime; whether structure placement goes through the changed function for every structure footprint class; the lab behaviour of an advected wave field; the x86 hash equality (expected from the pinned float model, to be tested in S1).

## 10. Status of PR A (S1 and S2, branch `rivers/sim`, 2026-11-12)

Built as designed, with these differences:

* **Files:** `src/moho/sim/WaterRivers.{h,cpp}` (pure: `ValidateRiver`, `RiverSegments`, `CWaterRiver`), `WaterBodies.{h,cpp}` (river bodies, `River`, `HasRivers`, `HasFalls`, `IsFallCell`, `FlowAt`, `levelMin` / `levelMax`), `STIMapWaterBodies.cpp` (parse of `River`), `FafGameVersion.{h,cpp}` (`EFafSimFix::WaterRivers` 7, `sim_FixRivers`), `STIMap.cpp` (occupancy, ray march, terrain type). Tests `tests/sim/WaterRiversTests.cpp` (12 checks, target `faf_water_rivers_tests`), `WaterBodiesMapTests.cpp` (+6), map `tools/scenarios/water-rivers`, scenarios `1p-waterrivers-main.yaml` and `-off.yaml`.
* **Fall cells** use the wet corners of the river itself (before another body's claim on a vertex). `Fall` needs `Below` at least `kRiverFallDrop` (0.75) under `Level`, else the body is skipped with a reason (a smaller step would not block). `HalfWidth` and `Level` are required for every point.
* **Level of a position**: bilinear over the four corners; a corner outside the field's support takes the mean of the corners that have a value (the doc said the nearest valid one).
* **Limits** as in 2.2, the vertex rectangle at most 4M vertices *and* a quarter of the map's (a 256 x 256 map allows rectangles of about 128 x 128 vertices; the test map's longest river is 190 long).
* **Ray picking** (`SurfaceIntersectionWithWaterBodies`): a river is no plane, so the line is followed over the river's cells in steps of half a unit with a 20 pass bisection, float arithmetic only. The sea and lakes keep their plane test.
* **Blocking terrain type at a fall:** `GetTerrainType(x, z)` returns the first blocking type of the loaded `TerrainTypes.lua` (`Dirt09`, code 9, in FAF's table); no descriptor change when no type is blocking. `IsBlockingTerrain` itself is not changed (the caps functions test the fall next to it).
* **Readers of a body's level**: `CTesselator` (tile test with `levelMin` / `levelMax`), `Cartographic` (depth under the vertex's own level), `WRenViewport` (a river is never the planar-reflection body). `WaterOfBlock`, `WaterBodySurfaces` and `WaterSimulation` still use `elevation` (the highest level), so **until PR B a river is drawn flat at its highest level**; every sim query has the sloped level.
* **Land units** cannot wade in a river at all (a land unit under any water is on the Seabed layer, which is invalid for it, and drowns at 10 percent of its health per second; engine behaviour, not changed). So a fall can only be the sole blocker for amphibious, hover, naval and submarine movers; for land units the water or the slope already stops them. The scenario map therefore uses an amphibious unit on a shallow river whose fall is exactly as steep as the slope limit allows (B, against B2 without a fall).

Two-client scenarios `2p-waterrivers-sync.yaml` (x64 against x64) and `2p-waterrivers-x86-vs-x64.yaml` (staged as `bin_x64_riversim` and `bin_x86_riversim`; run with `tools/bin/mpemu.exe run`) play the map on both clients with the switches on and expect no desync and 25 of 25 checks on each.

Evidence (headless and in game, D3D12): see the PR description; the control run with `sim_FixRivers=0` makes every river a flat lake and nothing is blocked.

## 11. Status of PR B part 1 (S3 sloped surface and S4 flow, branch `rivers/render`, 2026-11-12)

Built on `rivers/sim`, render only (no `src/moho/sim` file touched). Details of the code: [WATER_SIMULATION.md](../WATER_SIMULATION.md), "Rivers"; switches in [SWITCHES.md](../SWITCHES.md).

* **Files:** `src/moho/terrain/water/RiverFlow.{h,cpp}` (speed, turbulence, texel packing, phases, the flow texture), `RiverFlowBind.h`, `RiverFlowPatch.cpp` (the `water2.fx` patch `PatchWaterRivers`, tag `.waterriv1`, chained after the wave simulation patch in `CD3DEffectTechnique.cpp`), `WaterBodySurfaces.{h,cpp}` (`WaterOfBlock` per block, `RiverBlockVertices`, the river meshes), `HighFidelityWater.cpp` / `LowFidelityWater.cpp` (draw loops), `ShoreField.h` + `WaterSimulation.{h,cpp}` (sloped domains), `Shoreline.cpp` (cut-out level rounding). Tests: `tests/water/RiverFlowTests.cpp` (target `faf_river_flow_tests`), `tools/watersimlab/domains_cpu.h` check 9. Map: `tools/scenarios/water-rivers/make_junction_map.py` (river, lake, river, sea).
* **Differences from the design:**
  * The mesh is a quad per **cell** (4 per block), not per block, so the drawn surface is the level field the sim's `GetSurfaceHeight` bilinears (a block is only the unit of the level, the flow and the owner).
  * The two-phase weight of 3.2 was inverted (`abs(1 - 2 t0)` on phase 0 pops when the phase wraps); the built weight is `1 - abs(1 - 2 t0)` on phase 0, with the contrast of the blend put back. The white water uses the same two phases (a single phase sheared the pattern wherever the flow changes).
  * The patch is its own function (`PatchWaterRivers`), anchoring on stock lines the simulation patch leaves alone, so it works with or without it and is host-tested on the stock `water2.fx` and on a text shaped like the simulated one. The vertex change is `inPos.y = waterRiverParams.x > 0.5 ? inPos.y : WaterElevation;` (also in the low-fidelity vertex shader).
  * The speed formula is the design's. With it every reach of a river whose bed is 5 under the surface and whose slope is above about 0.006 saturates at the cap of 6 units a second (`d^(2/3)` of 5 is 2.9), and a perfectly level reach does not flow at all. Rivers whose depth is a unit or less (the doc's examples) vary over the whole range; `ren_RiverFlow` scales it.
  * White water amount is `turbulence^2 * 0.6 * ren_RiverFoam`; the shallow term of the turbulence was narrowed (depth below 0.5 and speed above 1) because with the first version every bank block was white.
  * Not built from the design: the surface-gradient tilt of the normal, the ripple lift of the river vertices (both polish), the foam in the simulation (S5), the particles and falls (S6).
* **Tests:** `faf_river_flow_tests` 10,797 checks, 0 failures (with `FAF_STOCK_FX_DIR` on the stock `water2.fx`: the patch applies once to the stock text and to a simulated-shaped text, refuses unknown text and a second patch); `faf_water_domain_tests` 19 checks, 0 failures (check 9: a sloped strip is water all along against land by the one level of its first block; flat domains are bit for bit the old fields); `faf_water_tests` 70, `faf_water_rivers_tests` 12, `faf_water_bodies_tests` 14, `faf_water_bodies_map_tests` 12, all passing; `python tools/watersimlab.py domains`, 33 checks (the shader runs on WARP), 0 failed. The compute shader's source (`kSource`) is not changed by this branch.
* **In game** (windowed 1600 x 900, test map `faf_re_waterrivers`, `sim_FixWaterBodies=1;sim_FixRivers=1`, the log shows the map and "water2 patched, the rivers slope and flow"; no compile fallback on any API):
  * *Slope:* frames along the bank (camera at heading +/- pi/2, pitch 0.3) show river A running down its canyon from 44 to 28; from above the lower reach (28 to 31) is a different, clean blue next to the rapids. D3D11, D3D12, Vulkan.
  * *Flow direction and speed*, numeric: the third normal layer (`ren_RiverDebug 9`) of two frames one second apart, cross-correlated in a 600 x 120 pixel window at the apex of river A where the flow is (1.00, 0.09), 29 pixels per world unit (from `ren_RiverDebug 10`, a ten-unit lattice). `ren_RiverFlow 15 / 30 / 60` gave, D3D12: 0.90 0.88 0.90 / 1.73 1.86 1.79 / 3.59 3.39 units a second (expected 0.90 / 1.80 / 3.60), direction +x with 0.06 to 0.11 in z; Vulkan 0.90 0.88 0.94 / 1.79 1.82 / 3.54 3.65 3.52; D3D11 the same where the frames of the step were stable (0.88, 0.90, 1.80). `ren_RiverFlow 0`: no shift (correlation 0.99 between identical frames). One window in several had an aliased peak (a shift of more than the window); those are not counted.
  * *Pause:* paused at game time 15 s, three frames up to 7 s apart in the flow view are identical pixel for pixel (the clock is the game's).
  * *White water:* only in the steep reach (slope 0.07, white 0.54 to 0.59 by the log of the flow texture), at the fall (1.0) and at the shallow fast reach of river B2's step; none in the rest (`ren_RiverFoam 0` removes it).
  * *Junctions* (`faf_re_waterrivers_junction`, D3D12): river D1 into the lake into D2 into the sea; frames at the lake's west and east shore and at the sea show one continuous water surface, no gap and no water over dry ground. The steep last reach of D1 (0.22) is white by design.
  * *No change without rivers:* a map with the sea only (`adaptive_acid_lakes`, nine views, the game paused at 14 s, same camera) and the flat-bodies map `faf_re_waterlevels` (three views) against the baseline build (`rivers/sim`) in the same run folder, same exe name: the water-coloured pixels that differ by more than 8 levels are 0.0 to 0.2 percent in seven of nine acid-lakes views (the same range as two baseline runs against each other), 0.5 percent in two (the commander's selection rings are in view, which are UI and differ between the runs), and 0.3 to 3.6 percent on the water-levels map against 0.25 to 1.7 percent for two baseline runs. They are not byte-identical (the sim's foam and the first frames differ run to run), and this proof was taken with the build before the last foam change, which touches river code only. The compiled water shader for a map without rivers differs by branches on a constant (`waterRiverParams.w`, 0).
* **Not verified / open:** low and medium fidelity (patched, not run); the fall is the sloped quad across one cell, so the cliff of the bed shows as terrain next to the water (the curtain is S6); cost (no GPU timestamps taken); x86 build of the new files (only the x64 build was made); the flow texture is rebuilt only when the bodies change (a river edited live would need the generation to move, which it does); the shore cut-outs of river blocks are drawn at an eighth-unit rounded level (a few dozen draws along a river); `ren_River 0` stops the flow and the sloped mesh at once (the river is then drawn flat at its highest level, as before this branch; this live switch was not looked at in a frame) and leaves the shader unpatched at the next map load.

Built on `rivers/sim` as stage S6 (v1, no new water pass), with these facts found on the way:

* **Files:** `src/moho/terrain/water/WaterfallPlan.{h,cpp}` (pure, no engine objects: emitters from a river's falls and steep reaches, the strips of a curtain, rates, spawns in metres and seconds, foam sources, nearest-first selection within a budget, the frustum test, the game clock, the live count; `tests/water/WaterfallTests.cpp`, target `faf_waterfall_tests`, 19 checks), `Waterfall.{h,cpp}` (the engine side: cvars, the three particle layers, beams, foam sources), the streak texture `data/fafengine/textures/particles/waterfall_streak_01.dds` made by `tools/waterfall/make_streak.py`. Two hooks: `WRenViewport::RenderWorldView` (once per frame of the first world view, before `StepWaterSimulation`, so the foam sources are taken by the next step) and `CWldSession::ApplyBeatEffects` (once per beat, right after `UpdateWaveSystem`).
* **Why two hooks.** The particle renderer clears its beams in `AdvancementBeat` (once per beat in which the game advanced) and keeps them over a pause, so the curtain is added once per advanced beat: that is the S0 spike answer for `AddBeam` (a beam lives for one beat; adding it per frame would pile up). Particles and foam sources are made per frame by the game clock.
* **Time.** `GameClock` is the rule of the water simulation's own clock (the wall time of the frame times the speed the game runs at, 0 when no tick came for a third of a second), so a paused game stops particles, beams and foam; it does not depend on `ren_WaterSim`. Particles are born with the fraction of the tick the frame is in (`mInterop`), so they do not come in bunches of ten a second. The renderer's units are ticks: velocities per tick, accelerations per tick squared, lifetimes in ticks; the plan works in seconds and `Waterfall.cpp` converts.
* **What a beam is.** `BeamVS` offsets both edges of the ribbon by `mWidth` (the field is a half width), scrolls the texture by `UShift / VShift` times the time in ticks, and the texture coordinate along the ribbon grows from the start to the end with `RepeatRate`. The curtain strips are camera facing ribbons: from the front they are one sheet, along the lip they pile up into a thick sheet. The streaks run at `5 + 0.7 * drop` metres a second.
* **Where particles are drawn.** The particle renderer draws buckets with a sort order of at least -101 (`efx_ParticleWaterSurface`) after the water and the beams with them; ours use -95 and -94, so they stand over the water and are depth tested against the scene.
* **Content.** Splash: `/textures/particles/water_splash_alpha_03.dds` with `ramp_water_01.dds`. Spray of rapids: `water_splash_alpha_04.dds` with the same ramp. Mist: `cloud_white_alpha_01.dds` with `ramp_white_04.dds`. Curtain: our own `waterfall_streak_01.dds` (64 x 256, DXT5, 16 KB; of the shipped textures with streaks, `rainfall_01` is nearly transparent and `dirt_spray_01` is brown), alpha blend. The shipped `water_splash_alpha_01` is a spiky star and looked like ice shards at this size.
* **Emitters.** A fall is one emitter (a curtain of `ceil(2 * halfWidth / spacing)` strips, splash and mist at its foot, foam discs across its foot); a rapid is one emitter every 6 units of a centreline segment that drops at least 5 percent per unit (spray, one foam disc), at most 256 a river. Rates: splash `0.8 * width * sqrt(drop)` a second, mist `0.22 * width * sqrt(drop)`, spray `0.9 * width * slope * 6`, times the level's density and a thinning with distance (1 within 40 percent of the range, 0.35 at its end).
* **Budgets (`ren_Waterfalls`).** Level 1: range 150, strips 2 units apart, at most 96 strips, 400 live particles, 12 new a frame, half rates, no rapid spray. Level 2 (default): 250, 1.5 apart, 192, 1000, 24, full rates. Level 3: 400, 1.2, 384, 1500, 48, 1.6 times the rates. Emitters are taken nearest first among those in range and in view (a sphere against the frustum); one that does not fit is skipped and a cheaper one behind it may be taken. The curtains are chosen at the beat, so a very fast pan can show a curtain 0.1 s late at the screen edge.
* **Foam.** `SimAddSource(x, z, radius, 0, foam * weight, true, 0)` per disc and frame (`weight` is the simulation's own `SimSourceWeight`, 0 in a pause): 0.003 a step at the foot of a fall (a steady white pool: the foam channel keeps 0.9965 a step, so a source of s settles at s / 0.0035) and 0.0008 to 0.0024 at a rapid; `ren_WaterfallFoam` scales both. Only inside the 512 unit window of the simulation, as every source. The first try with 0.012 and 0.004 filled the whole reach white.
* **Nothing without rivers.** `Refresh` finds no `CWaterBodies` river (a map without bodies, bodies without a `River`, or `sim_FixRivers` off, where the body is a flat lake) and nothing is made: no particle, no beam, no foam source; `ren_WaterfallLog` prints the counts. `FAF_NO_RENDER_ADDITIONS=1` keeps both hooks out.
* **Not done:** the geometric sheet (v2); rapids from shallow water and obstacles (only the slope of the centreline is used); sound; an Options > Video entry; wave simulation walls at the lip (S5); the surface of the river was drawn flat at its highest level (superseded in visuals-all: rivers/render slopes it, section 11) until the surface PR (`rivers/render`), so in game the curtain falls through a violet plane at the old level; the particles and the foam sit on the right levels (they use the river's own).

* **Curved curtain (branch `fix/falls2`, 2026-11-13).** The first curtain was a straight vertical sheet with a straight lip line and cut edges. A strip is now a polyline along the arc the water takes (`CurtainStrips` in `WaterfallPlan.cpp`): it leaves the lip horizontally at the speed of the river (`LipSpeed`, 0.55 to 1.1 units a second by the drop), falls under gravity (`y = top - drop * t^2`, `x = throw * t`, `t` the share of the fall time) and overshoots the lip by speed times fall time (`FootOffset`: 0.25 plus the throw, at most half the drop plus 0.5; about 2.4 for the 7.5 drop of the test map). The points are spaced by arc length (`ArcParam`, bisection on the closed form), `Quality::curtainSegments` of them (5, 8, 10 pieces at levels 1 to 3, at most 12): the beam renderer only draws straight beams, so the renderer chains one beam per piece, each with a whole number of streak repeats so the streaks meet at the joints, and the alpha runs smoothly from point to point. Per-strip profile from the channel's cross-section (`u` from -1 to 1 across the lip): the middle throws further (0.72 + 0.28 times `1 - u^2`) and the lip bows downstream by up to 0.6 there, ribbons are wider and denser in the middle than at the banks, edge strips narrow while they fall and fade (alpha down to 0.2 of the middle) so the edges end soft instead of in a cut, the sheet narrows by 7 percent mid-fall and spreads over the foot (wider ribbons, 0.35 more). Fray: a hash of the fall's place and the strip number (not a random stream, so the curtain is the same every time) varies each strip's throw (18 percent), end (up to 5 percent above the foot) and speed (15 percent), and a sideways undulation (0.25 units, coherent between neighbours) runs with the game time of the water, so it stands while the game is paused. The splash, mist and foam land at `FootOffset`, so they follow the curtain. Cvars `ren_WaterfallArc`, `ren_WaterfallBulge`, `ren_WaterfallFray` (SWITCHES.md). Budgets are unchanged (strips and live particles); a level-3 fall at most `384 * 10` beams. Tests: `tests/water/WaterfallTests.cpp` (arc geometry and endpoints, monotone arc with a flat start and a steep end, equal pieces, taper and thickness profile, fray determinism and time dependence, segment clamping, the foot follows the throw).

Verification (windowed 1600 x 900, map `faf_re_waterrivers`, `sim_FixWaterBodies=1 sim_FixRivers=1`, run folder `bin_x64_riverfalls`, frames every 250 ms with `FAF_GAL_DUMP_MS=250`): see the report of the branch. A pause freezes the effect: the mean difference between two frames 0.25 s apart in the curtain's region is 0.0 for the whole pause on Direct3D 11, 12 and Vulkan (a few isolated frames up to 2.9, not the curtain), 5 to 10 while the game runs and 3.8 with `ren_Waterfalls 0`. With `sim_FixRivers=0`, on `faf_re_waterlevels` (bodies, no rivers) and with `FAF_NO_RENDER_ADDITIONS=1` nothing is made (`Waterfalls: 0 served of 0, +0 particles ... 0 beams in all`; no curtain in the frames).

## 13. Banks (branch `fix/banks`, 2026-11-12)

The edge of a river at the ground was a staircase of 2 x 2 blocks (saw teeth along a diagonal bank, a tinted band of ground beyond the water). Two causes, both render side: the plane of a river ended at the sim's wet outline
(within the half width, terrain below the level) while the channel's terrain lay below the level further out, and the shoreline cut-out followed the block map and the block polygons, not the terrain. The cut-out mask of a
lake or a river is now the depth test alone and the mesh of a body grows over the pit beside its water up to the ground (`ren_WaterBanks`, `ren_WaterBankReach`); the sim is not touched, so ground that is shown as water
beside a river is dry for units. Details, switches and what was checked: [WATER_SIMULATION.md](../WATER_SIMULATION.md), "Banks".
