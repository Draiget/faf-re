# Full3D (container 4), revision 1

The "can do anything" format. A Full3D file is an Extended file (every chunk of [EXTENDED.md](EXTENDED.md) keeps its id, version and layout) plus a
streamed 3D world: mesh instances, collision, multi-layer navigation, volumes, lightmaps, large-world coordinates. Framing, codecs, hashing, limits
and conventions are in [CONTAINER.md](CONTAINER.md).

Design after industry practice for large 3D worlds: world partition into streamed cells with HLOD proxies; instanced static meshes with quantised
transforms; glTF 2.0 as the interchange mesh/material model; baked lightmaps + probes + the dynamic light pipeline; occluders and portals;
floating origin for precision; sim data separated, fixed-point and deterministic; derived caches; sublevels toggled by script.

## 1. Relation to Extended

- The ground plane is still a heightfield: `GRID HGHT PLAY GPLY WBOD` are required exactly as in Extended. A map with no ground uses a flat heightfield below the
  world and a blocking surface; `NAVS` provides everything walkable. This keeps tools, the minimap and the sim's existing queries working.
- Extended chunks may appear unchanged. `MRKR PROP AREA` positions are relative to the world origin of `WRLD` (see 2); `LEVL` is still read (its decks behave as `NAVS` patches).
- New chunks below are only valid in container 4. A reader of container 3 never sees them.
- `Full3D` adds feature bits 32..37 (CONTAINER.md section 4).

## 2. New chunks

| Id | Class | Req | Version | What |
|---|---|---|---|---|
| `WRLD` | S | yes | 1 | world definition: origin, bounds, cell grid |
| `CIDX` | R | | 1 | cell index: bounds, streaming, content flags |
| `MSHB` | R | | 1 | mesh library (instance = bundle) |
| `MATB` | R | | 1 | PBR material library for meshes |
| `INST` | R | | 1 | mesh instances (instance = cell, 0 if no cells) |
| `LODG` | R | | 1 | HLOD proxies (instance = cell) |
| `OCCL` | R | | 1 | occluders and portals |
| `LMAP` | R | | 1 | lightmap atlas (instance = atlas) |
| `PRBV` | R | | 1 | probe volume (instance = cell) |
| `ANIM` | R | | 1 | rigid-transform animation clips and players |
| `VOLR` | R | | 1 | render volumes (fog, post, reverb, light override) |
| `SLYR` | S | | 1 | sim layers toggled by script |
| `COLL` | S | | 1 | collision (instance = cell, 0 if no cells) |
| `NAVS` | S | | 1 | multi-layer navigation surfaces and links |
| `VOLS` | S | | 1 | trigger volumes |

Extended's `LAYR` (render sublevels) is allowed; `SLYR` is its sim counterpart (collision and navigation that scripts switch on and off; deterministic).

Common sub-structures:

- `fx10` = `i32` / 1024 (sim fixed point for 3D). `fx10vec3` = three `fx10`. `fx16` = `i32` / 65536.
- `shape3d` = `u8 kind` (0 box, 1 sphere, 2 convex hull, 3 extruded polygon, 4 capsule), then: box `fx10vec3 center, fx10vec3 halfExtents, i16[4] rot` (snorm quaternion); sphere `fx10vec3 center, fx10 radius`;
  convex `array<fx10vec3>` (4..256); extruded polygon `array<fxvec2>` (3..1024), `fx10 yMin, yMax`; capsule `fx10vec3 a, b, fx10 radius`.
  (Render volumes use the same layout with f32 inside `VOLR`, see below.)
- `meshRef` = `u16 bundle`, `u16 index` (into `MSHB` instance `bundle`, entry `index`).
- `qpos` = `u16[3]` position relative to the cell bounds (0..65535 spans the cell). `qrot` = `u32` smallest-three quaternion (2 bits index of largest, 3 x 10 bits snorm).

### WRLD v1
`f64 originX, originY, originZ` (world origin, exact; all other positions in sim and render chunks are relative to it, in f32), `vec3 boundsMin, boundsMax` (relative to the origin),
`f32 cellSize` (edge of a streaming cell, 32..4096), `u32 cellsX, cellsY, cellsZ` (product <= 2^22; `cellsY` = 1 for a ground world), `u8 upAxis` (1 = Y), `f32 unitsPerMeter` (informational),
`u8 flags` (bit0 LARGE_COORDS: origin is non-zero or bounds exceed 2^20 in any axis; sets feature `WORLD_LARGE_COORDS`).
Cell index `i = (cy * cellsZ + cz) * cellsX + cx`; cell `(cx,cy,cz)` spans `boundsMin + (cx,cy,cz)*cellSize` .. `+cellSize`. A world needs `WRLD`.

### CIDX v1
`array<cell>` (length `cellsX*cellsY*cellsZ`, one per cell, in index order) {`vec3 min, vec3 max` (tight bounds of content), `f32 loadDistance`, `f32 unloadDistance` (hysteresis, `unload >= load`),
`u8 priority`, `u8 flags` (bit0 ALWAYS_LOADED, bit1 HAS_INST, bit2 HAS_COLL, bit3 HAS_LODG, bit4 HAS_PRBV), `u16 layer`}.

### MSHB v1 (instance = bundle)
`array<mesh>` (<=65535) {`str name`, `u8 format` (0 = glTF 2.0 binary `.glb`, 1 = native), `f32[6] aabb`, `u32 byteCount`, bytes}.
Format 0 accepts glTF 2.0 with only these extensions: `KHR_mesh_quantization`, `EXT_meshopt_compression`, `KHR_materials_emissive_strength`, `KHR_texture_transform`, `KHR_materials_clearcoat`.
Textures in the glb are references (`uri` = VFS path) or `ASST` names; embedded buffers are not used for images. Skins/animations in the glb are ignored (see `ANIM`).
Format 1 (native, GPU-ready): `u32 vertexCount`, `u32 indexCount`, `u8 indexWidth` (2 or 4), `array<attr>` (<=8) {`u8 semantic` (0 position, 1 normal, 2 tangent, 3 uv0, 4 uv1/lightmap, 5 color, 6 joints, 7 weights),
`u8 component` (0 f32, 1 f16, 2 snorm16, 3 unorm8, 4 snorm8, 5 u8, 6 u16, 7 unorm16), `u8 count` (1..4)}, interleaved vertex data (`vertexCount * stride`, attributes in order, 4-byte aligned each), index data,
`array<submesh>` (<=256) {`u32 firstIndex, indexCount`, `u16 materialSlot`}, `array<lod>` (<=8) {`f32 screenSize`, `u32 firstSubmesh`, `u32 submeshCount`}.

### MATB v1
`array<material>` (<=4096) {`str name`, `f32[4] baseColor`, `color3 emissive`, `f32 emissiveStrength`, `f32 metallic, roughness, normalScale, occlusionStrength`, `u8 alphaMode` (0 opaque, 1 mask, 2 blend), `f32 alphaCutoff`,
`u16 flags` (bit0 DOUBLE_SIDED, bit1 UNLIT, bit2 CLEARCOAT, bit3 WIND_SWAY, bit4 CAST_SHADOW_OFF), `path baseColorTex, normalTex, ormTex, emissiveTex`, `vec2 uvOffset`, `vec2 uvScale`, `f32 uvRotation`,
`f32 clearcoat, clearcoatRoughness`, `f32 windAmount`}.

### INST v1 (instance = cell)
`vec3 cellOrigin` (the position `qpos` is relative to; normally the cell's `min`), `vec3 cellExtent`, `array<inst>` (<=1,000,000) {`meshRef mesh`, `qpos pos`, `qrot rot`, `f16x3 scale` (raw binary16),
`u32 flags` (bit0 STATIC, bit1 CAST_SHADOW, bit2 RECEIVE_SHADOW, bit3 CONTRIBUTE_GI, bit4 OCCLUDER, bit5 NO_LOD_FADE), `u16 lodBias`, `u16 layer`, `u16 cullDistance` (world units / 4; 0 = mesh default),
`u16 lightmap` (atlas index + 1, 0 none), `f16[4] lightmapScaleOffset`, `u8 overrideCount` (0..8), `u16[overrideCount] materialOverride` (index into `MATB`, per submesh slot)}.
The position is `cellOrigin + pos/65535 * cellExtent`.

### LODG v1 (instance = cell)
`array<proxy>` (<=65535) {`meshRef mesh`, `vec3 pos`, `quat rot`, `vec3 scale`, `f32 showBeyond`, `f32 fadeWidth`, `array<u32> replacesInstances` (<=65535; empty = replaces the whole cell content)}.

### OCCL v1
`array<occluder>` (<=4096) {`u8 kind` (0 box, 1 mesh), box: `vec3 center, vec3 halfExtents, quat rot`; mesh: `meshRef`, `vec3 pos, quat rot, vec3 scale`},
`array<room>` (<=1024) {`str name`, `vec3 min, max`}, `array<portal>` (<=4096) {`vec3[4] quad`, `u16 roomA, roomB`, `u8 flags` (bit0 OPEN)}.

### LMAP v1 (instance = atlas)
`u32 width, height`, `u8 format` (0 BC6H, 1 RGBM8, 2 RGBA16F), `u8 kind` (0 irradiance, 1 irradiance + dominant direction), `u32 byteCount`, bytes, and for kind 1 a second `u32 byteCount` + bytes (direction, RGBA8).
Sets feature `WORLD_LIGHTMAPS` when required (a map whose lighting is only correct with its lightmaps).

### PRBV v1 (instance = cell)
Same body as the probe grid in `PROB` (`vec3 gridOrigin, gridSpacing`, `u32 nx, ny, nz`, SH2 binary16 coefficients), for the cell.

### ANIM v1
`array<clip>` (<=1024) {`str name`, `f32 duration`, `u8 loop`, `array<channel>` (<=65535) {`u32 instanceCell`, `u32 instanceIndex`, `u8 target` (0 position, 1 rotation, 2 scale), `array<key>` (>=1, <=65535) {`f32 t`, `f32[4] value`}}},
`array<player>` (<=4096) {`str clip`, `f32 speed`, `f32 phase`, `u16 layer`, `u8 triggerKind` (0 always, 1 script-started)}. Time is the sim clock (tick / 10); the animation never feeds the sim.

### VOLR v1
`array<volume>` (<=4096) {`u8 kind` (0 fog, 1 post, 2 reverb, 3 light override), `u8 shapeKind` (0 box, 1 sphere), `vec3 center`, `vec3 halfExtents` (sphere: x = radius), `quat rot`, `f32 blendDistance`, `i16 priority`, `u16 layer`,
kind 0: `color3 color, f32 density, f32 heightFalloff`; kind 1: `f32 exposureEV, saturation, contrast, color3 tint`; kind 2: `str preset`; kind 3: `f32 ambientMul, color3 tint}`.

### SLYR v1
`array<layer>` (<=64) {`str name`, `u8 defaultOn`}. Referenced by `COLL.simLayer` and `NAVS.simLayer` (1-based, 0 = always). Lua (sim): `SetSimLayerEnabled(name, bool)`: collision and navigation of the layer switch together
and the pathfinder is told to invalidate the affected cells. The state is part of the sim (saved, replayed).

### COLL v1 (instance = cell)
`array<tri>` (<=4096) {`u32 vertexCount`, `array fx10vec3 vertices`, `u32 indexCount` (multiple of 3), `u32[] indices`, `u8 surfaceMode` (0 one surface id for all, 1 per triangle), `u16 surface`, per-triangle `u16[indexCount/3]`,
`u16 blocks` (bit0 GROUND, bit1 PROJECTILES, bit2 AIR, bit3 NAVAL, bit4 BUILD, bit5 VISION, bit6 BEAMS), `u16 simLayer`},
`array<hull>` (<=4096) {`array<fx10vec3>` (4..256), `u16 surface`, `u16 blocks`, `u16 simLayer`}, `array<prim>` (<=65535) {`shape3d`, `u16 surface`, `u16 blocks`, `u16 simLayer`}.
Spatial acceleration is built by the engine at load with a fixed algorithm (median split on the longest axis, leaves of at most 4 primitives, ties broken by index) so queries return the same results on every machine.
Feature `WORLD_COLLISION`.

### NAVS v1
`array<surface>` (<=4096) {`u16 id`, `str name`, `u8 kind` (0 height patch, 1 triangle mesh), `u8 moveMask` (bit0 land, bit1 hover, bit2 amphibious, bit3 foot/bot), `fx16 clearance` (0 = unlimited), `u16 simLayer`,
kind 0: `i32 x0 z0 x1 z1`, `plane<u16>(x1-x0+1, z1-z0+1)` heights (HGHT formula), bitmask walkable; kind 1: `array<fx10vec3> vertices`, `u32 indexCount`, `u32[] indices` (a triangle is walkable on its upward side)},
`array<link>` (<=65535) {`u16 fromSurface`, `fx10vec3 from`, `u16 toSurface`, `fx10vec3 to`, `u8 kind` (0 walk, 1 ladder, 2 jump, 3 teleport, 4 lift), `u8 moveMask`, `fx16 cost`, `u8 bidirectional`}.
The Extended heightfield is surface 0 implicitly. Feature `WORLD_NAV3D`.

### VOLS v1
`array<volume>` (<=4096) {`str name`, `shape3d`, `u32 flags` (bit0 TRIGGER_ON_ENTER, bit1 TRIGGER_ON_EXIT, bit2 BLOCK_BUILD, bit3 BLOCK_VISION), `i16 army` (-1 any), `array<str> tags` (<=16)}. Feature `WORLD_VOLUMES_SIM`.

## 3. Streaming and sim loading rules

- Render chunks of cells (`INST`, `LODG`, `PRBV`, `LMAP`, `MSHB` bundles) are streamed by camera distance with the hysteresis in `CIDX`. Chunk-level offsets make this one read each.
- Sim chunks (`COLL`, `NAVS`, `SLYR`, `VOLS`, `WRLD` and everything in Extended's S class) are loaded completely before the first tick, on every client and on a headless server. Nothing in the sim depends on camera or streaming state.
- Render chunks are optional for correctness: a server without a renderer skips all of them; the lobby check compares only `simHash`.
- Large coordinates: all f32 positions are relative to `WRLD.origin`; the renderer rebases the camera each frame (floating origin); the sim works in the relative frame, so replays are unaffected by the origin value.

## 4. What the engine does in revision 1 (honest scope)

The reader decodes and validates every chunk (`src/moho/sim/mapformat/`). Using them is staged:

| Stage | Engine behaviour |
|---|---|
| 1 (this stage; run in game on Direct3D 11, see `tests/mapformat/ingame/`) | `MapLoad` detects container 3 / 4, decodes the map, and **exports the Classic subset in memory** (`ClassicExport`): heights (1/128 steps), terrain types, the first global water body, lighting (`LITE`), up to 9 blended material layers (`MATL` + `SPLT`), props, preview. The unchanged Classic loaders run over those bytes, so every Extended map is playable and drawn with the stock renderer. The decoded map stays in `WLD_GetExtendedMap()`; `GetMapFormat()` (Sim and User Lua) reports the format. Maps that require a feature the engine does not honour yet are refused with its name (`EngineSupportedFeaturesMask`: not honoured are GRID_LARGE, PLAYABLE_POLYGON, MARKERS_BINARY, HINTS, SURFACE_LAYERS, WATER_BODIES, LEVELS and all WORLD_*) |
| 2 | Renderer: indexed splat + PBR materials, lighting, atmosphere, scatter, splines, decals, weather, time of day (Extended) |
| 3 | Renderer: mesh instances, HLOD, streaming, lightmaps, probes (Full3D) |
| 4 | Sim: multiple water bodies, `LEVL`, `GPLY` masks and speed multipliers, `COLL`, `NAVS`, `SLYR`, `VOLS`, binary markers |

Each stage is its own pull request, behind feature bits so unimplemented features refuse the map instead of misplaying it. The same exporter is the "export for older versions" of a map editor.
