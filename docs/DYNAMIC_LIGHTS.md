# Dynamic lights

Status: **in the engine** (Options > Video > Dynamic Lights, Off by default). Lighting for explosions, muzzle flashes, beams, trails, projectiles, fire and glowing units, lit **in the shaders of the materials**: the ground, the decals, the meshes and the water are shaded by one irradiance field, with shadows. It replaces the binary patch [FA-DynamicLights](https://github.com/UnsilentMarLo/FA-DynamicLights) on the Direct3D 11, 12 and Vulkan backends. The lights are **render only**: they read effect records and never touch the simulation, so replay parity is unaffected. The field itself is described in [LIGHTING_V2.md](LIGHTING_V2.md).

## Two systems, one at a time

The engine has two effect-light systems. They never run together.

| | Dynamic Lights (this document) | Explosion and weapon lights (`ren_DynamicLights`, `moho/render/DynamicLights.*`) |
|---|---|---|
| Option | Options > Video > Dynamic Lights, `dynlights_quality`, Off / Low / Medium / High / Ultra | Options > Video > Explosion and weapon lights, `dynamic_lights_optin`, On / Off |
| How | a world-fixed irradiance field (GPU compute), sampled once by `mesh.fx`, `terrain.fx` and `water2.fx` at the pixel's world position | a half-resolution screen-space pass that rebuilds position and normal from the depth buffer, sums at most 96 lights and brightens the colour |
| Shadows, material shading | yes: units, buildings, ridges and the sun's shadow of the terrain; albedo, normal map and specular | no (flat falloff, lights go through walls) |
| Cost | the size of the field, not the number of lights (about 2 ms with 2,500 lights, 100 v 100) | about 0.2 ms |
| APIs | Direct3D 11, 12, Vulkan | Direct3D 12, Vulkan |
| Touches the shaders | yes, the three effect files are patched as they load | no |

**Arbitration.** `lights::Enabled()` is true while Dynamic Lights is not Off *and* the mesh or terrain effect in use carries the light pass (`CD3DEffect::InitEffectFromFile` reports it through `lights::NoteEffectPatched`). While it is true, `DynamicLights::AddParticles` collects nothing and `DynamicLights::IsActive` is false, so the ground is never lit twice. When the patch is refused (a FAF update moved something it relies on; the log says `DynLights: <effect> not patched: <why>`) `Enabled()` stays false and the simpler system works as its own option says. The tip of both options says so.

The simple system's code is upstream's and stays as it is; the only changes are the two checks above. Its colour model (the ramp texture's alpha-weighted colour over the first 60 % of life) is its own; the field's lights take the texture's hue times the ramp at the particle age (below).

## What the binary patch could not do, and why the engine can

| Patch limit | Cause | In the engine |
|---|---|---|
| 16 lights on units, 28 on terrain | `ps_2_a` has 32 constant registers | the field has no cap: the compute pass walks every light of the frame |
| Mesh drawn 1+3 times, terrain 1+4 | one light array per additive pass | one pass (meshes) or none (the field is read in the material's own pass) |
| Colour inferred from pixels | the patch only sees the draw calls | the engine has the particle, beam and trail records and reads the effect textures |
| Unit lights from a table | no access to the unit's data | mesh glows are read from the albedo and specular maps with the pixel shader's rule |
| Lights go through walls | one sun shadow map | stochastic shadow rays against the height field and the casters of the field |

## Architecture

```
src/moho/render/lights/
  LightModel.h          importance classes, quality gate
  LightCollector.*      feeds -> Emission records -> pool, tracked envelopes -> the lights of the frame
  LightFeeds.*          option, console variables, BeginFrame / SetView, the live switch (ApplyLiveLevel)
  LightFeedSources.cpp  particle, glow, beam and trail feeds (per effect record)
  LightMeshFeed.cpp     unit and projectile mesh glows, the shadow casters (boxes of the batch)
  LightMeshEmission.*   what glows in a mesh (albedo / specular rule of each faction's pixel shader)
  LightTexture*.*       reads the effect DDS files (hue, ramp), cached per path
  SimLights.*           the sim-side registry of Lua lights (SWorldLight lane of SParticleBuffer)
  LightGrid.*           the old path: light data and grid textures (ren_DynLightsMode 0)
  LightField.*          the irradiance field: buffers, compute program, copy into the RGBA16F atlas
  LightBinding.*        owns the textures, binds them and the field to mesh, terrain and water2
  LightEffectPatch.*    the text patches of mesh.fx, terrain.fx and water2.fx
  LightCensus.*, LightDebugView.*   diagnostics
src/gpg/gal/DynLightPass.h          the flag the effect runtime reads to drop the light pass of a technique
src/moho/render/RenderFeatures.*    the registry that makes the Options > Video entry (docs/RENDERER_BACKENDS.md)
data/fafengine/lua/dynlights/light.lua   the Lua API
```

Frame order (`WRenViewport::RenderWorldView`): shadows, then `SetSunShadowCamera`, `lights::BeginFrame` (the pool for this frame, the light textures) and `lights::SetView` (the field for this view: compute, then a draw that copies the field buffer into the atlas), the terrain composite, the mesh batch, `lights::FeedMeshes` (glowing meshes and casters, used by the next frame), the water, the meshes. The beat's particle buffer is fed in `CWldSession::ApplyBeatEffects`, next to upstream's feed.

### Sources of light

| source | feed | colour | strength |
|---|---|---|---|
| `CreateLightParticle` flash | `FeedParticleBuffer` | texture hue x ramp curve | `FlashRadius/Intensity(size)` |
| additive / premodulated sprites (fire, plasma) | same, merged per 4-unit cell, tracked | texture hue x ramp | `GlowRadius/Energy(size)`; only textures with a glowing texel |
| poly trails (capsules) | same, tracked per head cell | texture hue x ramp head | `TrailRadius/Intensity(width)` |
| beams (capsules) | same, tracked per start/end/texture | texture hue x mean vertex colour | `TrailRadius/Intensity(width)` |
| unit and projectile meshes | `FeedMeshes` after `MeshRenderer::Batch`, tracked per instance | glow colour of the albedo, army colour where it glows | glow area of the albedo / specular maps (`LightMeshEmission.h`) |
| Lua lights | `SWorldLight` lane of the sim particle buffer | what the script gave | what the script gave |

The colour comes from the textures: `LightTexture.cpp` reads the DDS file itself (DXT1/3/5 and uncompressed 16/24/32 bit, the first mip that fits 256 x 256), `LightTextureCache.cpp` finds the file the way `InitEffectFromFile` does, on a worker thread (the first call for a texture queues it, a mesh has no glow and an effect source gives no light until it is read; `FAF_LIGHT_TEXTURES_SYNC=1` reads on the render thread). A light takes the hue of its texture (brightness-weighted mean colour, brightest channel 1) times the ramp at the particle age. Limits: 4096 lights per frame (the data texture), 16384 in the pool; beams and trails are capsules; spotlights have a direction and a cone.

### Quality levels

Off / Low / Medium / High / Ultra = `ren_DynLights` 0..4 (importance classes by power = intensity x radius squared: Low keeps the big explosions, Ultra everything including build beams and weak glows). The level changes apply at once; `ren_DynLightsGain` (percent) scales every light of the frame.

### The shader side

`LightEffectPatch.cpp` is a source-level patch: pure text in, text out. A source it does not recognise is left untouched and `error` says why, so the effect still compiles, without lights. The effect files are the game's own data and are never copied into this repository: the host test reads the stock files from `FAF_STOCK_FX_DIR` (extract `effects/mesh.fx`, `terrain.fx`, `water2.fx` from `gamedata/effects.nx2`).

- **mesh.fx:** the view distance goes into an unused interpolator of the lit techniques' vertex shaders, 19 single-pass techniques get `pass PDynLight` (additive, same vertex shader), the world position is `dynLightCamera - viewDir * distance`.
- **terrain.fx:** 33 composite techniques get a last pass; `CalculateLighting` adds the lights to the sun term, so decals and splats are lit. The terrain's shadow-map reads are multiplied by the field's sun visibility (`DynFieldSun`).
- **water2.fx:** `FafWaterLights` adds glints and the scattered light of the field to the water, and the sun reflection is cut by the field's sun visibility.
- **Pass control:** the techniques carry `int dynLightPasses = 1;`; `ProgramEffectTechnique::BeginTechnique` (Direct3D 12, Vulkan) drops that pass from the count while `gpg::gal::gDynLightPassActive` is false (no light this frame, or Off). Direct3D 11 draws it always (an empty field adds nothing).
- **Order of the patches on water2.fx:** the light patch first, then the wave simulation, then the water filter (Water Quality). Their anchors do not overlap (`tests/lights/LightEffectPatchTests.cpp` checks lights then filter on the stock file; the log line of each patch says whether it applied). The cache name carries one tag per patch applied (`.waterl1`, `.watersim1`, `.waterq1`) and the lit mesh and terrain effects `.dynlights3`, so every combination compiles to its own cached effect.
- **Fallbacks:** if the lit effect does not compile it is built again without the sun-shadow reads of the terrain's PBR shaders (Direct3D 11's 16 samplers: it never tries them), then without the light pass. The shipped effect is always the last resort.
- **Tessellated terrain** (`ren_TerrainTessellation`, Direct3D 12 and Vulkan): the tessellated twins of the terrain techniques are appended to the lit text and carry no light pass of their own. The combination compiles and loads (checked on Direct3D 12: `tessellated techniques loaded` and the three patched effects in one log), but the ground drawn by a twin is expected to miss the lights; a frame was not compared. Treat the two options as not meant to be used together until that is looked at.

### Switching on in a running game

The option can be turned on without a restart. `lights::ApplyLiveLevel` (called at the start of `WRenViewport::D3DWindowOnDeviceRender`) notices that the level went from Off to a level after the effects were built without the light pass and rebuilds `mesh`, `terrain` and `water2` once through `CD3DDeviceResources::ReloadEffectNamed`; then the terrain renderers of the world views are made again (they set the water and terrain variables once; the new effects have lost them). On Direct3D 12 and Vulkan the rebuild takes about 0.2 s. Direct3D 11 compiles with fxc: the three lit effects first compile on worker threads while the game goes on (about 20 to 30 s, FAF's `init_faf.lua` empties the shader cache at every launch; the log says `compiling the lit effects in the background` and `the background compile took N s`), and the swap, which takes the cache hit, takes under 0.1 s. Turning it Off again leaves the lit effects in place and drops the light pass of the techniques.

## Options and console variables

| Variable | Default | What |
|---|---|---|
| `ren_DynLights` | 0 | the level, 0..4 (the option sets it) |
| `ren_DynLightsGain` | 100 | strength in percent |
| `ren_DynLightsMode` | 1 | 1 the irradiance field, 0 the light grid with shader loops |
| `ren_DynLightsShadows` | 1 | buildings and units shade the lights (grid path) |
| `ren_DynLightsFieldShadows` | 1 | the same in the field |
| `ren_DynLightsSunShadows` | 1 | the terrain's shadow of the sun from the field (ridges shade units and water) |
| `ren_DynLightsTerrainSunShadow` | 0 | 1: the terrain itself also takes that march (the old look; hill faces got blocky, axis-aligned dark patches); 0: only meshes, props and water do |
| `ren_DynLightsTest N` | 0 | every N ticks a flash on the ground, or over the water that covers it, in the middle of the view. A flash lives by the sim's clock: on a paused game it stays lit after the switch goes back to 0, so a frame A/B across a test flash compares two lit scenes (measured 2026-11-13: mean 4.5 levels, and it looks like a dependence on whatever else was toggled) |
| `ren_DynLightsWaterLevels` | 1 | a map with water bodies: the field and the sun under water use the level of each cell's water (0: the sea level for all) |
| `ren_DynLightsLog N` | 0 | log the pool every N frames (`FAF_DYNLIGHT_DUMP=1` adds one line per light) |
| `ren_DynLightsCensus N` | 0 | log which textures, beams, trails and meshes the feeds saw and whether they became lights |
| `ren_DynLightsView` | 0 | debug view of the light grid |
| `/dynlights`, `/dynlightsflood`, `/dynlightsflood2` | | command line: build the effects lit whatever the option says; paint the light passes magenta / the world position as a checker |

## Lua lights (`data/fafengine/lua/dynlights/light.lua`)

```lua
local Light = import('/fafengine/lua/dynlights/light.lua')
local lamp = Light.Create(unit, 'Turret', 1.0, 0.8, 0.5, 30, 1.0)   -- entity (nil: world position), bone (name, number, nil), r, g, b, radius, intensity
lamp:SetOffset(0, 1.5, 0); lamp:SetColour(r, g, b); lamp:SetRadius(50); lamp:SetIntensity(1.5)
lamp:SetSpot(0, -0.1, 1, 35)        -- spotlight along a bone-space direction, 35 degrees half angle
lamp:SetPosition(x, y, z)           -- a light without an entity
lamp:Destroy()
Light.Headlight(unit)               -- a warm 32 degree spotlight at the front
```

The Lua globals `CreateLight`, `SetLight`, `SetLightOffset`, `SetLightPosition`, `SetLightSpot`, `DestroyLight` (`EffectLuaStartupRegistrations.cpp`) call the registry in `SimLights.cpp`. Every sim tick, after the effects, it writes one `SWorldLight` record per live light into `SParticleBuffer::mLights` (a lane the shipped binary does not have: the buffer grew from 0x30 to 0x40 bytes); the renderer tracks the lights by handle. **Determinism:** nothing reads the lights back, they are not in the checksum, and the functions always return a handle whatever the quality level or the camera, so scripts take the same branches on every client. A light ends with its entity. Lights are not saved with a game.

## Tests

- `faf_light_tests` (`tests/lights`, pure C++ on the host: pool, grid, texture reader, mesh emission, effect patches; `FAF_STOCK_FX_DIR` adds the stock-file checks of the three effect patches): `cmake --build --preset clang-x64-release --target faf_light_tests`.
- In-game (`tests/lights/ingame`, `tests/featab`): `dynlights_test.lua` and `dynlights_camera.lua` are scene scripts, run by the hooks in `tests/lights/ingame/hooks` (append them to `<exe folder>/fafengine/lua/simInit.lua` and `.../ui/game/gamemain.lua`; a normal install has neither). `tests/featab/featab.ps1` drives a scene and writes the back buffer as BMP per second; `steps_livelights.lua` switches the lights Off, On, Off, On and shows the live switch (`-Prefs Game_nolights.prefs -Scene static`). The log lines to look for: `DynLights: <effect> patched`, `DynLights: switched on in the running game, 3 effects rebuilt in N ms`.

## Not part of this change

Each of these is another change; where the lights code reaches for them it is guarded or absent.

- Screen-space reflections, the real-depth water thickness, caustics and the unit shadows on the water (`WaterReflections.*`): the lights patch of `water2.fx` does not need them.
- The shadow-map filter (PCF / PCSS) and its effect patch (`ShadowEffectPatch`): the field's sun-shadow term multiplies the shipped shadow lookup (`tex2D(ShadowSampler, ...)`); the wrapper for the filter's `ShadowLookup(...)` form is in the patch and applies when that change is present.
- Ambient occlusion, FXAA / SMAA / sharpening, render scale, low-resolution and soft particles. (The field reads no depth buffer and needs none of them.)
- The registry entries of other features: the registry holds Dynamic Lights only; the Lua blocks of `options.lua` are unchanged.

## Limits and open points

- A map with water bodies is lit with the level of each cell's water ([LIGHTING_V2.md](LIGHTING_V2.md), "Water bodies"); the cells are 0.5 to 16 units, so far out the level changes at a cell, not at a 2-unit block.
- Terrain tessellation and Dynamic Lights: see above.
- Direct3D 9 (32-bit build) has no Dynamic Lights.
- Cells of the field grow with the zoom (0.5 to 16 units): a light smaller than a cell is widened and weakened (`splat`), small shadows are soft blobs, and the casters are ellipsoids.
- A GPU page fault in `terrain.fx:TTerrain` on Direct3D 12 was seen in two real games on one map and was not reproduced afterwards; the water-march loop that hung the AMD driver is a fixed loop now ([LIGHTING_V2.md](LIGHTING_V2.md)).
