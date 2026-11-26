# Lighting V2: lights without caps, shadows from every light, cost independent of the light count

Status: **built (stages 1 to 5), in the engine since this change.** It is the default path of the dynamic lights (`ren_DynLightsMode 1`); the per-pixel light loops of the first version (grid + shader loops, `ren_DynLightsMode 0`) stay selectable. The text below is the design and the measurements of the stages as they were built.

## Why

Measured (`FEATAB_COUNT=100 tests/featab -Scene battle`, D3D12, 1600x900, about 2,500 lights on screen, GPU ms per frame): lights off 4.6; lights on without shadows 14.2; with shadows 38.5 before the steam-re port, 132.8 after it. Each pixel loops over every light of its cell and, per light, over the shadow casters: cost = pixels x lights x casters, and it is paid again in the ground pass, every decal/splat layer and the second draw of every mesh. A cap (fewer lights, fewer casters) only trades looks for speed. The cost has to stop depending on the light count.

## Architecture: a world-space irradiance field, sampled once by the material shaders

The first draft (depth + normal pre-pass, screen-space irradiance) was dropped after the survey of the frame: the renderer has **one colour target per pass (no MRT), no float render-target formats, mesh depth techniques that write colour-encoded depth and no normals, and the main mesh batch runs after the terrain**; a pre-pass would add a second mesh batch and a screen-space normal reconstruction, and its result would shimmer with the camera.

```
1  light buffer (GPU)       every light of the frame in one structured buffer (GpuBuffer), written by the CPU collector; no grid, no cap
2  tile culling (compute)   coarse world tiles (for example 8 x 8 field cells): exact light list per tile from an atomic pool
3  field pass (pixel program, one draw per layer set)
                            a world-fixed field over the visible ground: cells of 0.5 to 1 world unit in XZ, a few layers of height above
                            the terrain (0, 2, 5, 10, 20, 40). Per cell: irradiance RGB + dominant light direction from every light of
                            the cell's tile (RGBA16F atlas render target, first-order directional irradiance)
4  shadows                  per cell: K lights picked by contribution (stochastic, weights 1/p), one shadow ray each against the terrain
                            heightfield and the caster list of the tile (analytic ellipsoid / box), later DXR 1.1 ray queries;
                            temporal accumulation in world space (cells do not move with the camera: no reprojection, no disocclusion)
5  material shaders         terrain, decals, meshes (mesh.fx, terrain.fx) sample the field once at their world position
                            (bilinear + a lerp between two height layers) and combine it with their own albedo, normal map and
                            specular; no light loops, no second mesh pass
```

- **Cost is bounded by the field, not by the lights, casters or passes:** cells (about 160,000 to 640,000 x 6 layers) x lights of the cell's tile for step 3, cells x K for step 4, one texture read per pixel and pass in step 5. It is the same few hundred thousand cell evaluations whether 25 or 25,000 lights are on, and the old per-pixel loops (pixels x lights x casters, three or more passes) disappear.
- **World-fixed, not screen-fixed:** stable under camera motion, no depth buffer, no normal buffer, no MRT, no extra geometry pass; temporal accumulation is a plain blend of the cell with its previous value.
- **Honest limits:** detail below the cell size (0.5 to 1 unit) is blurred, so light shapes are soft and the shadow of a small unit is a soft blob; the field covers the visible area plus a margin (the clip region follows the camera in whole-cell steps); a fast flying unit samples the nearest height layers. Chosen cell size is a measured trade-off, not a fixed promise.
- **Particles, shields, water** read the same field at their world position.

## Stages (each ships only if it beats the previous path in the 100v100 scene; the old path stays selectable until the end)

| # | What | Done when |
|---|---|---|
| 0 | Baseline (done): the table above | recorded |
| 1 | Backend groundwork: RGBA16F render target format on D3D11, D3D12, Vulkan (the survey: one table row in `DxgiFormats.cpp` plus the D3D11 and Vulkan format maps); a test that creates, draws and reads it | the target exists on all three backends |
| 2 | Light buffer + tile culling + field pass without shadows; `terrain.fx` / `mesh.fx` patched to sample the field instead of looping (cvar `ren_DynLightsMode 1`) | 100v100 lights-on GPU time within 2 ms of lights-off; no squares, no cap |
| 3 | Shadows: stochastic selection + rays against terrain heightfield and casters, temporal accumulation; DXR ray queries afterwards | 100v100 with full shadows within 3 ms of lights-off |
| 4 | Directional irradiance for normal maps and specular, cell size and layer tuning, D3D11 / Vulkan parity (ray queries where the API has them), old path removed | per-API A/B pictures |

## Survey facts the stages rely on

- Frame order (`WRenViewport::Render`, `moho/app/WRenViewport.cpp`): SkyDome, TerrainContext, TerrainNormals, Shadows (sun shadow map), **Terrain (4086)**, Ranges, MeshBatch, FeedMeshes (4139), Reflections, Meshes 0x14, Effects(true), Meshes 0x18, Water, AmbientOcclusion (4175), WorldUi, Meshes 0x24, Effects(false), ... `lights::BeginFrame` / `SetView` run at 4081, before the terrain. The field passes belong right there.
- Render targets: single colour + depth per pass; formats of `kRenderTargetFormats` (`gpg/gal/backends/dxgi/DxgiFormats.cpp:55`) are R10G10B10A2, BGRA8, BGRX8, 5551, 565, R16G16_UNORM; float formats exist for textures only.
- A GPU program (`CreateGpuProgram`, `DrawGpuProgram`) reads up to four structured buffers (t0..t3), two textures or depth or render targets (t4, t5) and one constant block; compute writes only `GpuBuffer`s (u0..u1): compute output reaches a texture through a pixel-program draw that reads the buffer.
- Effects bind a render target with `ShaderVar::SetRenderTargetTexture` (water does); translated pixel shaders get the pixel position as `SV_Position` for both `POSITION` and `VPOS`.

## Stage 1 and 2 result (2026-10-31, no shadows yet)

Built: RGBA16F render target token 9 (`DxgiFormats.cpp`), `LightField.{h,cpp}` (compute: one 8x8x1 thread group per tile and layer, the lights culled against the tile in chunks of 1024 into group shared memory, so no list is ever cut; a fullscreen draw copies the field buffer into the atlas), `BindField` (`LightBinding.cpp`), `DynFieldSample` / `DynFieldDiffuse` / `DynFieldBRDF` in the injected HLSL (`LightEffectPatch.cpp`; the terrain composite, decal / splat layers and mesh light pass branch on `dynFieldParams2.x`). Switch: `ren_DynLightsMode 1` (default 0 = the old grid path).

Measured, same scene as the baseline (100v100, 2,500 lights, D3D12, 1600x900, `FAF_GPU_PROFILE=300`; lights off 4.6 ms; old path with shadows 132.8 ms; without shadows 14.2 ms):

| | GPU per frame | Terrain | Meshes | LightField |
|---|---|---|---|---|
| field (mode 1), no shadows | 6.3 ms | 0.29 ms | 0.21 ms | 0.27 ms |

The lights cost 1.7 ms over lights off, with every light of the frame in the sum (no cap, no cell borders). Pictures: the same fight, old path and field, light the ground alike. Open: shadows (stage 3), a light-only packer instead of the CPU grid build (`BuildLightGrid` still runs; its `image.data` feeds the compute), more than 4096 lights, D3D11 / Vulkan runs.

## Stage 3 result (2026-10-31): shadows in the field, default on

The compute pass also shades: per cell, four reservoirs pick lights with probability proportional to their light (weighted reservoir sampling over the chunked light stream, so no list is cut), each picked light is tested against the casters near the tile (also chunked), and the mean transmittance of the samples is the cell's visibility. Only the visibility is averaged over time (blend 0.25, history shifted with the window; the lights of the cell are exact every frame, so a flash is not delayed). Casters are the engine's boxes as ellipsoids at 0.8 of their half extents, the soft shape the steam-re session calibrated (60 % at most). Switch `ren_DynLightsFieldShadows` (default 1). `ren_DynLightsMode 1` is now the default; `0` brings back the grid path.

| 100v100, 2,500 lights, ~100 casters, 1600x900 | GPU per frame | LightField pass |
|---|---|---|
| lights off | 4.6 ms (D3D12) | |
| old path, shadows (before this work) | 132.8 ms | |
| field, no shadows, D3D12 | 6.3 ms | 0.27 ms |
| **field with shadows, D3D12** | **6.5 ms** | 0.34 ms |
| field with shadows, D3D11 | 4.1 ms total | 0.42 ms |
| field with shadows, Vulkan | 6.8 ms total | 0.38 ms |

Shadow scene (`steps_fshadow.lua`): shadows on vs off differ by 1.03 (mean pixel difference), two runs with shadows on differ by 0.009 (no flicker). Open: terrain height-field shadows (lights behind ridges), more than 4,096 lights and 1,024 casters (the CPU packer limits), real unit silhouettes (the casters are ellipsoids), directional specular quality, the cost of a zoomed-in view (cells of 0.5), a light-only packer without the CPU grid.

## Stage 4: terrain and water in the field (2026-11-01)

Survey facts (water2.fx, `WaterEffectPatch`, `STIMap`): the water is one quad at `WaterElevation` drawn by `HighFidelityPS` after the scene copy; its depth term is a baked half-resolution map (`UtilitySamplerC.g`); terrain and meshes tint by depth through `ApplyWaterColor` / the mesh equivalent; terrain is not in the sun shadow map; `CHeightField` gives raw uint16 samples at 1/128 unit; `STIMap` has `IsWaterEnabled()` / `GetWaterElevation()`.

Built:

- **Full-resolution terrain in the compute pass.** The map's raw height samples go to the GPU once (again when `HeightFieldRevision()` changes), two to a word; the pass reads them bilinear (it used a 129x129 lattice before). A log line checks the unit against `GetElevation` at start (19.000 against 19.000 on Adaptive Acid Lakes).
- **Ridge shadows for lights.** Each shadow sample marches its ray over the terrain (12 steps, soft penumbra widening along the ray) next to the caster test; a light behind a ridge no longer lights the ground behind it.
- **Water in the field.** Layers are now: 0 the terrain 0.5 above it (the sea bed under water), 1 to 4 the surface (water or terrain) 0.3, 3, 10, 30 above it; the alpha of layers 0 and 1 holds the terrain and the surface height. The shaders sample by height: a point under the surface blends the sea bed and surface layers, one above uses the layers above the surface.
- **Underwater lights and water depth.** Every light is weakened by the length of its path inside the water (`WaterTransmit`, Beer-Lambert, absorption 0.25 / 0.06 / 0.03 per unit for red / green / blue), for lights below the surface and for lights above it that reach a submerged point.
- **Lit water.** `lights::PatchWaterEffect` (chained with the water quality patch in `CD3DEffectTechnique.cpp`, cache tag `.waterl1`) adds `FafWaterLights` to `HighFidelityPS`: GGX glints of the combined light on the wave normal, and the light scattered back out of the water in the water colour. The field variables are bound to `water2` like to `mesh` and `terrain`.

Measured: 100v100, D3D12: GPU 6.47 ms, LightField pass 0.41 ms (0.34 before the terrain march). A lit lake (hover tanks with light particles, `-Scene waterlight`) lights the water, the sea bed and the shore; not yet compared against the old path by eye in a deep-water map (the test map's lake is 2.5 units deep).

Next: sun shadows of the terrain onto terrain, units and water (a part-2 plane in the atlas), per-pixel water depth from a full-resolution height texture, a height-field wave simulation feeding the water normals (units, projectiles and impacts as sources), then displaced water geometry.

## Stage 5: the terrain's shadow of the sun (2026-11-01)

The sun's light is marched over the same raw heights as the light rays: for each cell of layers 0 and 1 (the terrain and the surface), 40 samples along the direction to the sun with steps that grow with the distance (up to 500 units, long shadows of a low sun) and a penumbra that widens along the ray. The result is part 3 of the atlas (the atlas is now `3 * cells` high); `DynFieldSun(p)` reads it (a point under the surface blends the sea bed and surface values).

Consumers, all best effort and falling back to the unpatched text:

- **Terrain:** every read of the shadow map (`tex2D(ShadowSampler, X.mShadow.xy).g`, or `ShadowLookup(X.mShadow)` after the shadow filter patch) is multiplied by `DynFieldSun(X.mTexWT.xzy)`; `CalculateLighting`'s shadow too (decals and splats). The terrain knows its world position, so no matrix is needed. The terrain shaders only read the shadow map while `ShadowsEnabled` is set, which was `mShadowCameraValid`: it is now also set while the field carries the sun shadow (`lights::SunShadowActive()`), the map being cleared to lit when it has no casters.
- **Meshes:** `ComputeShadow` is wrapped (`ComputeShadowBase` keeps the old body); the pixel's shadow coordinates are mapped back to a clip position, and the inverse of the sun's shadow matrix (`dynShadowInv`, bound from `WRenViewport` after the shadow pass) gives the world position.
- **Water:** the sun reflection is multiplied by `DynFieldSun` at the water surface (a ridge or a shore wall cuts the glint).

Switch: `ren_DynLightsSunShadows` (default 1; 0 off; 2 a checker and 3 "no sun anywhere", both debug views to see that the term reaches the shaders). The field also runs when no light is on, for the sun shadow alone, while Dynamic Lights is not Off (the effect patches belong to that option).

**The terrain does not take it by default (`ren_DynLightsTerrainSunShadow`, default 0, live).** On a hilly map with the shadow filter and ambient occlusion at their top levels, the march was the one feature that put blocky, hard-edged, axis-aligned dark patches on hill faces (its cells are 0.5 to 16 units, the zoom, and its height samples are the engine's 1/128 raw lattice, so a face shows the cell grid; the shadow map, its filter, contact shadows and the occlusion kernel do not). The terrain's reads therefore go through `DynFieldSunTerrain(p)`, which is `DynFieldSun(p)` while `dynFieldWater.y` is 1 (the cvar) and 1 otherwise; `FafSunUnder` (sun dimming under water) still wraps the shadow. Meshes (`FieldSunVisibility`) and the water's sun reflection read `DynFieldSun` directly, so units, buildings, props and the glint keep the hills' shadow, and the light rays' own terrain march and caster shadows are untouched. `lights::SunShadowActive()` still says the field carries the sun; `lights::TerrainSunShadowActive()` (that and the cvar) is what the terrain's `ShadowsEnabled` and the `ren_TerrainShadows` bake look at, so with the cvar 0 the bake (default 0 itself) is not suppressed by a march the terrain no longer applies. The effect cache tag is `.dynlights4`.

Shader model limit: ps_4_1 allows 16 samplers and some terrain PBR techniques already use 15, so the extra field read does not compile on D3D11; the effect builder retries without the PBR reads (`PatchTerrainEffect(..., sunReads = false)`), keeping the sun shadow in `CalculateLighting` (decals, splats). D3D12 and Vulkan keep all seven terrain reads.

Measured (100v100, 2,500 lights): D3D12 GPU 6.69 ms (LightField 0.55 ms; it was 0.41 ms with ridge shadows for lights only), Vulkan 7.06 ms, D3D11 4.26 ms. Lake crater test (`steps_sun5.lua`): sun shadows on vs off differ by 0.66 (mean pixel difference), the difference is a shadow band from the crater rim and cut glints on the lake; the debug "no sun" view changes the image by 22.


## Dynamic lights: weak lights, build beams, the Titan


User report: a UEF Titan glows only up close, gunfire of a Fatboy is visible, weaker lights vanish, no build beams.
- Zoom: the cells of the light field grow with the zoom (0.5 units close up, 2 to 16 zoomed out). A light smaller than a cell fell between the cell centres and vanished. The compute pass now grows every light's footprint to at least 1.5 cells (also in the tile culling) and keeps the square root of the share of its radius as strength (`splat`): a small glow gets wider and dimmer instead of going out.
- Importance classes: `kPowerNormal` 9 -> 4. The build beams (intensity x radius^2 about 7), reclaim rays and weak unit glows were class Minor and only Ultra kept them. `kMinVisible` 0.035 -> 0.02. Beams: radius 4.5 + 10 x width (4.5 to 14), intensity 1.4 + 0.6 x width (1.4 to 1.9) before the colour of the texture. Mesh glows: intensity cap 0.85 (was 0.55), exponent 0.35 of the glow area (was 0.5; the assault bot with a few lamps got 0.046, at the edge of the drop limit, now 0.1), radius 2 x sphere + 2 (was 1.5 x + 1).
- The Titan (uel0303): its mesh material is `PhaseShield`, and a shader name with "shield" in it was taken for a shield bubble: no light at all. A unit with a shield-named shader and an albedo under `/units/` is a unit now (`GlowOf`). But the specular map of the Titan has no emissive channel in the rule of the UEF units (specular.b): its glow area is 0, so it still lights nothing itself; what the user saw up close is something else (its weapons, the unit's own emissive shading).
- Census (`ren_DynLightsCensus 240`, 4 factions building): the build beams are `ok:beam` (beam_white_02: 125 of 240 frames; beam_disruptor), so they were lights, but at power 7 below the Normal class. Measured light of the beams (difference of the frame with lights on and off, zooms 40 / 90 / 180, mean over the crop): old 0.057 / 0.016 / 0.033, then 0.051 / 0.028 / 0.023, 0.076 / 0.026 / 0.018 after the intensity change: the weak lights stay faint in absolute terms (the difference needs a tenfold amplification to be seen at zoom 90).
- `ren_DynLightsGain` (percent, default 100, 0 to 1000): scales the colour x intensity of every light of the frame after the collector (`BeginFrame`), so the grid and the field both see it. Measured on the build scene at zoom 40 (pixels that differ from the frame without lights by more than 2 levels): gain 0: 2,146 (the noise floor), 100: 2,995, 300: 4,228, 1000: 14,863; the mean difference saturates (0.25 / 0.26 / 0.32) because the light shaders soft-limit the sum. Console only; no entry in the options menu.


## What this document leaves out

The render-all history of this file also covers the water simulation (stages 6 to 9: wave simulation, wakes, reflections, thickness, caustics, unit shadows on the water) and the shadow-map filtering. They are other changes: the water simulation is in [WATER_SIMULATION.md](WATER_SIMULATION.md), and the screen-space reflections, the real-depth thickness, the caustics, the unit shadows on the water, the shadow filter and the ambient occlusion are not part of the Dynamic Lights change ([DYNAMIC_LIGHTS.md](DYNAMIC_LIGHTS.md), "Not part of this change"). Wherever a section above names one of them, read it as a pointer to that history.

## Water bodies (a map with lakes and pools at their own levels)

A map with water bodies (`sim_FixWaterBodies`, [WATER_BODIES.md](WATER_BODIES.md)) has the sea and each lake at its own level. The field and the sun under water use the level of the water over each cell, not one number for the map:

* **The table.** `LightWaterLevels.h` packs the level of each 2 x 2 block (a texel of the water map, `WaterOfBlock` of the water code: the unit the water is drawn and simulated in) to 16 bits (1/128 unit, 0xFFFF = no water, a dry body) and appends the words to the height buffer of the field (all four read-buffer slots of the pass are in use). It is rebuilt when the generation of the bodies changes (`CWaterBodies::Generation`), not with the heights.
* **The pass.** `FieldCS` has two variants, as the water simulation has: the text compiled for a map without bodies is the field as it was before (instruction for instruction, so a sea map's frames are what they were), and the variant with `FAF_WATER_LEVELS` is compiled the first time a map with bodies is lit. In it the surface of a cell is `max(ground, level of its block)`, so the layers above the surface hang from the water of that cell and the layer 0 / layer 1 blend of a point under water uses the right depth; the transmission of a light to a point is the water on the segment between the level over the point and the level over the light (a light 6 above a lake and a receiver on the sea bed beside it each see their own water: `WaterPathFraction`, tested). The level of each cell is also written to the third part of the atlas (`y`, a half float; `x` is the sun).
* **The sun under water.** `FafSunUnder` in the terrain effect dims the sun's shadow by the depth of the water above a point. It took the depth from the effect's `WaterElevation`, which upstream sets to the highest level of the map, so a sea bed beside a high lake counted as very deep (and a bank below the highest lake as under water). It reads `DynFieldWaterLevel` now: the level of the cell from the atlas, read at the texel centre (a lake never takes the level of the sea beside it), where the field carries levels (`dynFieldWater.x`, set only on a map with bodies); the effect's `WaterElevation` otherwise, as before. The terrain's function sits after the field block now (it reads it).
* **The water** needs nothing: the water shader reads the field at the `WaterElevation` of its own draw (the level of the lake it is drawing), and the layers it blends are now the lake's.
* **Switch** `ren_DynLightsWaterLevels` (default 1; 0 lights a map with bodies with the sea level for all waters, as before). No effect without bodies. `ren_DynLightsTest` puts its flash 6 units over the water that covers the ground in the middle of the view, not over the bed.
* **Resolution.** The level is that of the cell (0.5 to 16 units, the zoom): at a shore the cell that holds the lake border takes one level, so the sun dimming changes at cell steps, not at the block (2 units) when zoomed far out. Without the field (`ren_DynLightsMode 0`, or no light and no sun shadow) the sun under water has the effect's level as before.
