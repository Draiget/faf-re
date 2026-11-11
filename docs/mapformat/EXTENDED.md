# Extended (container 3), revision 1

Heightfield world model, chunked, everything a modern ground RTS map needs. Framing, codecs, hashing, limits and conventions are in
[CONTAINER.md](CONTAINER.md); read section 3 there first (string, array, fixed point, planes, predictors).

Class column: **S** sim (hashed into `simHash`, deterministic), **R** render (never read by the sim), **M** metadata (neither), **D** derived cache.
"Req" = which chunks every Extended map must contain: `META GRID HGHT PLAY GPLY WBOD`. Everything else is optional.

| Id | Class | Req | Version | What |
|---|---|---|---|---|
| `META` | M | yes | 1 | identity, localisation, requirements |
| `PREV` | M | | 1 | lobby preview image |
| `GENR` | M | | 1 | generator recipe |
| `SIGN` | M | | 1 | signature |
| `ASST` | M | | 1 | embedded asset bundle |
| `GRID` | S | yes | 1 | dimensions, cell size |
| `HGHT` | S | yes | 1 | heightfield |
| `PLAY` | S | yes | 1 | playable area |
| `GPLY` | S | yes | 1 | surface ids, named gameplay masks |
| `WBOD` | S | yes | 1 | water bodies (level, extent) |
| `LEVL` | S | | 1 | decks / second walkable level |
| `MRKR` | S | | 1 | typed markers |
| `AREA` | S | | 1 | named areas |
| `PROP` | S | | 1 | props with collision (sim entities) |
| `HINT` | S | | 1 | strategic hints for AI and scripts |
| `LAYR` | R | | 1 | sublevel layers |
| `MATL` | R | | 1 | material library |
| `SPLT` | R | | 1 | splat weights |
| `NRML` | R | | 1 | baked normals (else derived) |
| `AOMP` | R | | 1 | baked AO / sky visibility |
| `HDET` | R | | 1 | render-only height detail |
| `HOLE` | R | | 1 | cut-out mask |
| `MACR` | R | | 1 | macro colour variation |
| `LITE` | R | | 1 | global lighting |
| `LLGT` | R | | 1 | local lights |
| `PROB` | R | | 1 | reflection probes, SH probe grid |
| `TODK` | R | | 1 | time-of-day keys |
| `ATMO` | R | | 1 | sky, atmosphere, clouds, volumetric fog |
| `WVIS` | R | | 1 | water visuals per body |
| `WFLW` | R | | 1 | water flow map (instance = index) |
| `SCAT` | R | | 1 | scatter layers (vegetation, rocks) |
| `SCDM` | R | | 1 | scatter density map (instance = index) |
| `SPLN` | R | | 1 | splines (roads, rivers, cliffs, fences) |
| `DECL` | R | | 1 | decals |
| `WTHR` | R | | 1 | weather zones and states |
| `AUDI` | R | | 1 | ambient audio, reverb, music cues |
| `CAMR` | R | | 1 | camera defaults, bookmarks, paths |
| `MINI` | R | | 1 | strategic / minimap |
| `POST` | R | | 1 | post-processing hints |
| `DRVD` | D | | 1 | derived caches |

Common sub-structures (used below):

- `shape` = `u8 kind` (0 rect, 1 polygon, 2 circle) then: rect `f32 x0 z0 x1 z1`; polygon `array<vec2>` (3..1024); circle `f32 cx cz r`.
- `pose` = `vec3 pos, f32 yawDeg, f32 pitchDeg, f32 fovDeg`.
- `fxvec2` = `fx32 x, fx32 z` (i32 / 256).
- `plane<T>(W,H)` = `u8 predictor` then `W*H` elements of T (row-major, z rows), predictor reversed on decode.

## Metadata chunks

### META v1 (raw max 1 MiB)
`str name`, `array<loc>` (<=64) {`str lang` (BCP-47), `str name`, `str description`}, `str author`, `str version`, `str license`, `str website`,
`array<str> tags` (<=64), `u8 mapType` (0 skirmish, 1 campaign, 2 coop, 3 sandbox), `u8 minPlayers`, `u8 maxPlayers`,
`array<req>` (<=64) {`str kind` ("mod" | "exe" | "feature"), `str id`, `str minVersion`}, `u64 createdUtc`, `u64 modifiedUtc`, `str toolName`, `str toolVersion`.

### PREV v1
`u8 kind` (0 PNG, 1 DDS), `u32 width`, `u32 height`, `u32 byteCount`, bytes. Width, height <= 2048. Decoded by the lobby only.

### GENR v1
`str generator`, `str generatorVersion`, `u64 seed`, `u32 jsonLen` + UTF-8 JSON (<= 256 KiB, parameters as the generator wants them),
`array<{str key, str value}>` notes (<=256).

### SIGN v1
`u8 algo` (1 = Ed25519), `u8[32] publicKey`, `u8[64] signature`, `str keyName`. Signed message = `simHash(32) || SHA-256(raw META)(32)`. Verification is
optional for the engine; a failed verification is a warning, never a refusal.

### ASST v1 (instance = bundle index)
`array<asset>` (<=65535) {`str name` (relative, below the map's embedded root, no `..`), `u8 kind` (0 DDS, 1 PNG, 2 TGA, 3 SCM, 4 SCA, 5 JSON data),
`u64 size`, bytes}. Policy in CONTAINER.md section 7.

## Sim chunks

### GRID v1 (29 bytes)
`u32 cellsX`, `u32 cellsZ` (1..65536, total samples <= 2^30), `f32 cellSize` (**1.0** in revision 1), `f32 originX`, `f32 originZ` (**0** in revision 1),
`f32 minElevation`, `f32 maxElevation` (informational, must bound all samples), `u8 reserved` (0).
Feature bits: `GRID_NONSQUARE` if `cellsX != cellsZ`, `GRID_LARGE` if either is above 4096.

### HGHT v1
`f32 minHeight`, `i8 stepLog2` (-16..0), `u8 predictor`, `u16 tileSize` (**0** in revision 1; reserved for tiled streaming), then
`(cellsX+1)*(cellsZ+1)` `u16` samples (predictor applies per row, element width 2).
`height(v) = minHeight + v * 2^stepLog2`, computed in binary32 (`ldexp(float(v), stepLog2) + minHeight`). Classic conversion: `minHeight = 0`, `stepLog2 = -7`
(identical to Classic's `v / 128`). Feature `HEIGHT_FINE` if `stepLog2 < -7`.

### PLAY v1
`i32 x0, z0, x1, z1` (cells, `x1 > x0`, `z1 > z0`, inside the grid), `u8 borderMode` (0 void, 1 FAF world border, 2 none), `array<fxvec2> polygon` (0 or 3..1024;
empty = the rectangle). With a polygon, the rectangle must bound it. Feature `PLAYABLE_POLYGON` if non-empty.

### GPLY v1
`u8 legacyTerrainIds` (1: surface ids are Classic terrain type codes and `/lua/TerrainTypes.lua` supplies their effects),
`array<surface>` (<=1024) {`u16 id`, `str name`, `u32 flags` (bit0 BLOCKING, bit1 NO_BUILD, bit2 NO_FOOTPRINT_DECALS, bit3 SHALLOW_LIQUID; others 0), `u16 speedMul` (fixed /256,
256 = 1.0; values != 256 need feature `SURFACE_LAYERS`), `str effectsKey` ("" = Default)},
`u8 idWidth` (1 or 2), `plane<u8|u16>(cellsX, cellsZ)` surface ids (every id must be in the table),
`array<mask>` (<=64) {`str name`, `u8 kind` (1 = bitmask, 8 = u8 plane), data: bitmask(cellsX,cellsZ) or `plane<u8>`}.
Well-known mask names (sim semantics defined, unknown names are ignored by the sim but hashed): `buildable_override`, `walk_land`, `walk_hover`, `walk_amphib`, `air_block`,
`no_fog`, `vision_block`, `reclaim_ok`. A set bit in `walk_*` allows, in `*_block`/`no_*` forbids; absent mask = no restriction.

### WBOD v1
`array<body>` (1..256) {`u16 id`, `str name`, `u8 kind` (0 sea, 1 lake, 2 river), `f32 level`, `u8 extentKind` (0 global, 1 mask, 2 polygon), extent data: none | bitmask(cellsX,cellsZ) | `array<fxvec2>` (3..4096)}.
A cell is water when some body covers it and the terrain at the cell is below that body's level; the cell's water level is the **highest** covering level (ties: lowest id).
One body with `kind 0, extentKind 0` is Classic's water. Anything else sets feature `WATER_BODIES`. An empty array is not allowed; "no water" is `level = -1e6` of a global body (kept so the chunk
is never absent). (`-1e6` exactly, `f32:c9742400`.)

### LEVL v1
`array<deck>` (<=1024) {`u16 id`, `str name`, `i32 x0 z0 x1 z1` (cells, inclusive), `u8 mode` (0 flat, 1 ramp, 2 patch), `f32 h0`, `f32 h1`, `u8 axis` (0 x, 1 z; used by ramp),
patch mode: `plane<u16>(x1-x0+1, z1-z0+1)` using HGHT's `minHeight`/`stepLog2`, `f32 clearanceBelow` (0 = unlimited), `u32 flags` (bit0 WALKABLE_LAND, bit1 WALKABLE_HOVER,
bit2 BLOCKS_PROJECTILES, bit3 BLOCKS_BUILD_BELOW), `array<portal>` (<=64) {`fxvec2 a`, `fxvec2 b`, `u16 targetDeck` (0xFFFF = ground)}}.
Flat: height `h0`; ramp: linear from `h0` to `h1` along the axis across the rectangle (same as the FlowBridge deck registry). Feature `LEVELS`.

### MRKR v1
`array<marker>` (<=65536) {`u8 type` (0 custom, 1 start, 2 mass, 3 hydro, 4 expansion, 5 naval_expansion, 6 rally, 7 path_land, 8 path_water, 9 path_air, 10 path_amphib,
11 combat_zone, 12 defensive_point, 13 camera, 14 spawn, 15 transport_landing, 16 naval_lane, 17 artillery_spot), `str name`, `vec3 pos`, `f32 yawDeg`, `i16 army` (-1 none),
`u32 flags` (0), `array<prop>` (<=32) {`str key`, `u8 vtype` (0 str, 1 i32, 2 f32, 3 bool), value}, `array<u32> links` (<=64, indices into this array)}.
Mass and hydro carry prop `amount` (f32). Feature `MARKERS_BINARY` when the save file's marker table is to be ignored.

### AREA v1
`array<area>` (<=4096) {`str name`, `shape`, `u8 flags` (bit0 HAS_Y_RANGE), `f32 yMin, yMax` if bit0, `array<str> tags` (<=16)}.

### PROP v1
`array<str> blueprints` (<=65535, lower case VFS), `array<prop>` (<=1,000,000) {`u32 blueprintIndex`, `vec3 pos`, `quat rot`, `vec3 scale`, `u32 flags` (0)}.
Props are sim entities (collision, reclaim); purely decorative things belong in `SCAT`. Feature `PROPS_BINARY`.

### HINT v1
`array<region>` (<=4096) {`u32 id`, `str name`, `u8 kind` (0 land region, 1 island, 2 water body, 3 plateau, 4 basin, 5 air lane), `f32 area`, `vec2 centroid`, `array<u32> neighbors` (<=64, ids)},
`array<choke>` (<=4096) {`vec2 pos`, `f32 width`, `u32 regionA`, `u32 regionB`, `u8 layerMask` (bit0 land, bit1 water, bit2 air, bit3 amphibious)},
`array<candidate>` (<=4096) {`vec2 pos`, `u8 layer`, `f32 score`, `array<u32> markerIds` (<=32)}. Feature `HINTS`.

## Render chunks

### LAYR v1
`array<layer>` (<=255) {`str name`, `u8 defaultVisible`, `u8 flags` (0)}. Layer index = position + 1; 0 means "always". Other render chunks reference layers by `u16 layer`. Lua: `SetMapLayerVisible(name, bool)`
(render only, in Extended).

### MATL v1
`array<material>` (<=1024) {`u16 id`, `str name`, `path albedo`, `path normal`, `path orm` (R occlusion, G roughness, B metalness), `path height`, `u16 flags` (bit0 TRIPLANAR_CLIFF, bit1 STOCHASTIC_TILING, bit2 PARALLAX,
bit3 HEIGHT_BLEND, bit4 ALBEDO_SRGB), `f32 tileSize` (world units per repeat), `f32 rotationDeg`, `f32 normalStrength`, `f32 roughnessScale`, `f32 metalness`, `f32 parallaxScale`, `f32 heightBlendSharpness`,
`f32 macroInfluence`, `u16 gameplaySurface` (0xFFFF none; links footprint/effects to GPLY)}. Empty paths use the renderer's neutral texture. Feature `RENDER_PBR_MATERIALS` when ORM or height are used.

### SPLT v1
`u32 width, height` (1..16384), `u8 mode` (0 indexed, 1 dense). Mode 0: `plane<u8>` of `width*height*4` indices (RGBA interleaved) and `plane<u8>` of `width*height*4` weights (sum 255 per texel).
Mode 1: `u8 layers` (<=32), `array<u16> materialIds` (length `layers`), `layers` x `plane<u8>(width,height)`. Resolution is independent of the heightfield. Feature `RENDER_INDEXED_SPLAT` for mode 0 when required.

### NRML v1
`u32 width, height`, `u8 format` (0 RG8 unorm, 1 BC5), bytes. Normals in tangent space of the terrain, Z reconstructed. Omitted: the renderer derives normals from `HGHT` (+ `HDET`).

### AOMP v1
`u32 width, height`, `u8 kind` (0 ambient occlusion, 1 sky visibility), `u8 format` (0 R8, 1 BC4), bytes.

### HDET v1
`u8 log2Mult` (1..3), `f32 lsb` (world units per LSB), `u8 predictor`, `i16` samples `(cellsX*m+1)*(cellsZ*m+1)` of **delta to bilinear interpolation of the base samples**; `m = 2^log2Mult`.

### HOLE v1
bitmask(cellsX, cellsZ): set = the cell is not drawn (terrain, shadow, decals), the sim is unaffected. For sim-visible caves use `LEVL`.

### MACR v1
`u32 width, height`, `u8 format` (0 RGB8 sRGB, 1 BC1), `f32 strength`, bytes.

### LITE v1
`vec3 sunDir` (surface to sun, normalised), `color3 sunColor`, `f32 sunIntensity` (1.0 = Classic `LightMultiplier` 1), `f32 sunAngularDeg`,
`u8 hasMoon` [`vec3 dir, color3 color, f32 intensity, f32 angularDeg`],
`u8 ambientMode` (0 flat, 1 hemisphere, 2 SH2), `color3 ambient` (sky), `color3 ground`, `f32 ambientIntensity`, SH2 mode: `f32[27]`,
`color3 shadowFill`, `f32 shadowDistance`, `u8 cascades` (1..4), `f32 shadowBias`, `f32 shadowStrength`,
`u8 fogMode` (0 none, 1 linear, 2 exp, 3 exp-height), `color3 fogColor`, `f32 fogStart, fogEnd, fogDensity, fogHeightFalloff, fogBaseHeight`,
`u8 toneMap` (0 stock, 1 filmic, 2 neutral), `f32 exposureEV, bloomIntensity, bloomThreshold`, `path lut` (3D colour grading, 32^3 DDS).

### LLGT v1
`array<light>` (<=8192) {`u8 type` (0 point, 1 spot), `vec3 pos`, `vec3 dir`, `color3 color`, `f32 intensity, range, innerDeg, outerDeg`, `u8 flags` (bit0 CAST_SHADOW, bit1 AFFECT_UNITS, bit2 AFFECT_TERRAIN,
bit3 NIGHT_ONLY), `f32 flickerAmp, flickerHz`, `u16 layer`}. Uses faf-re's dynamic light pipeline.

### PROB v1
`array<reflProbe>` (<=1024) {`vec3 pos`, `vec3 halfExtents`, `f32 blend`, `i16 priority`, `path cubemap`}, `vec3 gridOrigin`, `vec3 gridSpacing`, `u32 nx, ny, nz` (product <= 2^22, may be 0),
`nx*ny*nz*27` binary16 values (raw `u16`) = SH2 RGB per probe.

### TODK v1
`f32 cycleSeconds` (0 = static: only key 0 is used), `f32 startPhase` (0..1), `array<key>` (1..256, strictly increasing `t` in [0,1)) {`f32 t`, `vec3 sunDir`, `color3 sunColor`, `f32 sunIntensity`,
`color3 ambient`, `color3 ground`, `f32 ambientIntensity`, `color3 fogColor`, `f32 fogDensity`, `color3 skyTint`, `f32 exposureEV`, `f32 starIntensity`}. Time `t = frac(startPhase + simSeconds / cycleSeconds)`; interpolation is
linear and cyclic, directions by normalised lerp. `simSeconds` is the sim tick count / 10 (read-only). Feature `RENDER_TOD`.

### ATMO v1
`u8 skyModel` (0 cube map, 1 procedural atmosphere, 2 HDRI), `path cubemap`, `f32 skyIntensity`, `f32 rotationDeg`,
procedural: `f32 planetRadiusKm, atmosphereHeightKm`, `color3 rayleigh`, `f32 rayleighScaleHeightKm, mie, mieAnisotropy, mieScaleHeightKm`, `color3 ozone`, `f32 groundAlbedo`,
`u8 cloudMode` (0 none, 1 layered textures, 2 volumetric), `f32 coverage, density, baseAltitude, thickness`, `vec2 wind`, `path noiseShape`, `path noiseDetail`, `f32 cloudShadowStrength`,
`u8 volumetricFog`, `f32 scattering, anisotropy, extinction, maxDistance`,
`array<celestial>` (<=16) {`path texture`, `vec3 dir`, `f32 sizeDeg`, `color3 tint`, `f32 intensity`}, `f32 starIntensity`. Feature `RENDER_VOLUMETRICS` for cloud mode 2 / volumetric fog when required.

### WVIS v1
`array<bodyVis>` (<=256) {`u16 bodyId` (0xFFFF = default for all), `color3 shallow, deep, absorption`, `f32 clarityMeters, reflection, refraction`, `u8 waveModel` (0 stock normal maps, 1 Gerstner, 2 FFT),
model 0: `array<{path normalMap, f32 tiling, f32 speed, vec2 dir}>` (<=4); model 1: `array<{f32 amplitude, wavelength, steepness, dirDeg, speed}>` (<=16); model 2: `f32 windSpeed, windDirDeg, fetchKm, choppiness, patchSize`,
`f32 foamAmount`, `path foamTexture`, `f32 shoreFoamWidth`, `f32 causticStrength`, `path causticTexture`, `f32 flowScale`, `u32 flowMap` (WFLW instance, 0xFFFFFFFF none), `color3 underwaterFog`, `f32 underwaterDensity`}.

### WFLW v1 (instance = index)
`u32 width, height`, `f32 maxSpeed`, `plane<u8 x2>` interleaved signed-normalised (i8 x, i8 z) `width*height*2` bytes.

### SCAT v1 (placement algorithm is normative, section below)
`array<layer>` (<=256) {`str name`, `u64 seed`, `array<variant>` (1..64) {`u8 kind` (0 prop blueprint, 1 mesh path, 2 billboard texture), `path ref`, `f32 weight`, `f32 scaleMin, scaleMax`},
`f32 density` (instances per 1024 square world units), `f32 minSlopeDeg, maxSlopeDeg, minAltitude, maxAltitude`, `array<u16> allowedMaterials` (<=64, empty = any), `array<u16> forbiddenSurfaces` (<=64),
`i32 densityMap` (SCDM instance, -1 none), `f32 jitter`, `u16 flags` (bit0 ALIGN_TO_NORMAL, bit1 RANDOM_YAW, bit2 CAST_SHADOW, bit3 WIND, bit4 AVOID_STRUCTURES), `f32 cullDistance, windBend, windHz, tintVariation`,
`u16 layer`}.
Placement (identical on every machine): the world is cut into blocks of 32 x 32 world units. For block `(bx, bz)` of layer `L`: `rng = PCG32(seed = hash64(seed, L, bx, bz))` (PCG-XSH-RR 64/32, initseq 54;
`hash64` = SplitMix64 of `seed ^ (L << 48) ^ (bx << 24) ^ bz`). Candidate count `n = floor(density) + (next() < frac(density) * 2^32 ? 1 : 0)` where `density` has been multiplied by the density map
value (0..1, bilinear) at the block centre. For each candidate: x and z = block origin + `(next() >> 8) / 2^24 * 32`, variant = weighted pick with `next()`, then the attribute rejection tests (slope, altitude, material
via SPLT dominant index, surface id, density map at the point, `HOLE`), then scale, yaw, tint from further `next()` calls. A rejected candidate still consumes its random numbers (a fixed 6 per candidate).

### SCDM v1 (instance = index)
`u32 width, height`, `plane<u8>`.

### SPLN v1
`array<spline>` (<=4096) {`u8 kind` (0 road, 1 river, 2 cliff edge, 3 fence, 4 pipe, 5 shoreline, 6 custom), `str name`, `u16 flags` (bit0 CLOSED, bit1 CONFORM_TERRAIN, bit2 PAINT_MATERIAL, bit3 WRITES_SURFACE,
bit4 CAST_SHADOW), `array<point>` (2..65536) {`vec3 pos`, `vec3 tangentIn`, `vec3 tangentOut`, `f32 width`, `f32 rollDeg`}, `path decalTexture`, `path mesh`, `f32 uvTile`, `f32 paintWidth`, `u16 paintMaterial`,
`u16 writeSurface`, `f32 blendDistance`, `u16 layer`}. Hermite curves. `CONFORM_TERRAIN` and `WRITES_SURFACE` document what the editor already baked into `HGHT`/`GPLY`; the engine never modifies sim data from a spline.

### DECL v1
`array<path> textures` (<=65535), `array<decal>` (<=1,000,000) {`u8 type` (0 albedo, 1 normal, 2 glow, 3 alpha mask, 4 ORM), `u32 tex0`, `u32 tex1` (0xFFFFFFFF none), `vec3 pos`, `quat rot`, `vec3 size`,
`f32 lodMin, lodMax`, `f32[4] tint`, `f32 fadeDistance`, `i16 order`, `u16 layer`, `u8 blend` (0 alpha, 1 additive, 2 multiply)}.

### WTHR v1
`u16 defaultState`, `array<state>` (1..64) {`str name`, `f32 rain, snow, fogDensityMul, cloudCoverageAdd, windSpeed, windDirDeg, lightMul, wetness`},
`array<zone>` (<=1024) {`str name`, `shape`, `u16 state` (index), `f32 yMin, yMax`, `path effect`, `path sound`, `u16 layer`}. Lua: `SetWeatherState(name)`, render only.

### AUDI v1
`str ambientBed`, `f32 bedVolume`, `array<zone>` (<=1024) {`str name`, `shape`, `str loop`, `f32 volume, fade`, `i16 priority`, `str reverbPreset`},
`array<cue>` (<=64) {`str state`, `str cue`}.

### CAMR v1
`pose defaultPose`, `f32 minZoom, maxZoom, pitchMin, pitchMax`, `vec4 bounds` (x0 z0 x1 z1), `array<bookmark>` (<=64) {`str name`, `pose`},
`array<path>` (<=256) {`str name`, `f32 duration`, `array<key>` (2..4096) {`f32 t`, `vec3 pos`, `quat rot`, `f32 fovDeg`, `u8 ease` (0 linear, 1 smooth)}}.

### MINI v1
`u8 kind` (0 none, 1 embedded image {`u8 fmt` 0 PNG/1 DDS, `u32 w, h, byteCount`, bytes}, 2 generated), `f32 contourInterval`, `array<{f32 height, srgb8 color}>` ramp (<=64), `srgb8 borderColor`, `str strategicStyle`.

### POST v1
`u32 flags` (bit0 DOF_CINEMATIC), `f32 bloom, vignette, chromaticAberration, filmGrain, ssaoHint, ssrHint, dofFocus, dofAperture`. Hints: the user's graphics settings win.

### DRVD v1 (instance = index, any number)
`str kind`, `u8[32] inputHash` (SHA-256 of the raw bytes of the inputs, defined per kind), `u32 byteCount`, bytes. Kind `minmax_mips`: inputs = raw `HGHT`; payload: levels from 1 up to the
level whose block covers the grid; level `k` has blocks of `2^k` cells, `ceil((cellsX)/2^k) * ceil(cellsZ/2^k)` pairs of `u16 min, u16 max` (raw sample values, not heights), row-major.
Kind `nav_cache`: inputs = raw `GRID`, `HGHT`, `GPLY`, `WBOD`, `LEVL`, `PLAY` concatenated in that order; engine defined payload; a mismatch or an unknown kind is ignored.

## Required behaviour of a reader (engine)

1. All S chunks present and valid, else refuse. Missing `META`, bad `PREV`, unknown R/M/D chunks never refuse.
2. Cross-chunk checks (refuse): GPLY plane size and ids against table; every `WBOD.extent` inside the grid; `LEVL` rectangles inside the grid, `PROP` blueprint indices, `MRKR` links, `HGHT` sample count vs `GRID`.
3. Lenient mode (tools) downgrades render-chunk errors to warnings and drops the chunk.
4. Sim code only sees S chunks (`MapSimData`). Render code gets `MapRenderData` (R chunks decoded lazily on first use).

## Appendix A: clarifications fixed by the two implementations (normative)

The C++ reader and the Python reference were written independently from this text; where they had to choose, both now follow this list.

**Encoding**
- Counts of fixed-length arrays are still stored and must equal the expected length: `CIDX` cells, `SPLT` `materialIds` (= `layers`, 1..32).
  Counts that follow from an earlier field are not stored: `COLL` `vertices` (`vertexCount`) and `indices` (`indexCount`), `INST` `materialOverride`
  (`overrideCount`), `LITE` `sh` (27 floats when `ambientMode == 2`), `SPLT` mode 1 planes (`layers`).
- `ATMO`: the procedural block (`planetRadiusKm` .. `groundAlbedo`) is present only when `skyModel == 1`; the cloud, fog and celestial fields are always present.
- `LEVL`: `h0`, `h1`, `axis`, `clearanceBelow`, `flags` and `portals` are always present; patch mode adds the `plane<u16>` after `axis`. Rectangles are inclusive.
- `NRML`, `AOMP`, `MACR` store one mip level and no byte count: the rest of the chunk must equal the size of that level (RG8 `w*h*2`, BC5 16 bytes per 4x4 block,
  R8 `w*h`, BC4 8 bytes per block, RGB8 `w*h*3`, BC1 8 bytes per block).
- Image and plane dimensions are 1..16384 for `SPLT NRML AOMP MACR WFLW SCDM LMAP`, 1..2048 for `PREV`.
- `SPLT` weights sum to 255 per texel. Path strings are lower case with a leading `/`, or empty. `GRID.minElevation .. maxElevation` bound every `HGHT` sample.
- All floats in sim chunks are finite. Fixed-point values (`fx32`, `fx10`, `fx16`) are dumped as raw integers.
- Unknown enum values and unknown flag bits are errors in every chunk. Reserved fields must be zero.

**Cross-chunk rules** (refuse): everything in "Required behaviour of a reader", plus `HINT` `markerIds` index `MRKR`; `DECL` `tex0/tex1` index the texture table; `WTHR` state
indices; `COLL` instance below the `WRLD` cell count; `simLayer` at most the `SLYR` count. `COLL` surface ids are not checked against `GPLY`; `NAVS` patches need not lie inside the grid.
A sim feature the data uses (the mask `RequiredFeatureMaskFor` computes) must be declared in `requiredFeatures`.

**Scatter**: the density-map test at the point is `value <= 0` rejects (no seventh random number); the count draw is always consumed; `jitter` takes no part in placement;
the layer index is 0-based; block coordinates are masked to 24 bits and the layer to 16 bits in `hash64`; candidates per block are capped at 16384; a candidate outside the grid is rejected
after drawing its six numbers. The derivation of every float from the random bits is the comment block in `Scatter.h` and the module docstring of `tools/mapformat/mapfmt/scatter.py`.

**Dump** (CONTAINER.md section 8): the field names, plural array names and line sets are those of `tools/mapformat/DUMP_NAMES.md` (generated from the Python reference).

## Appendix B: markers in revision 1

The presence of `MRKR` or `AREA` declares `MARKERS_BINARY` (they are then the authoritative markers, `_save.lua` carries none). The engine does not read them yet (the Lua side still takes markers from `_save.lua`), so today's engine refuses a map with these chunks and revision-1 writers keep markers in `_save.lua` and **omit** `MRKR`/`AREA`. The chunks are fully specified and tested for the stage in which the Lua side reads them.
