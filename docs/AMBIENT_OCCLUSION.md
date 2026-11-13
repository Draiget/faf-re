# Ambient occlusion

Screen-space ambient occlusion darkens the finished 3D world where geometry closes in: the feet of buildings, the gaps between units, the creases of a unit's own parts. Render only; nothing touches the simulation.

The engine has two occlusion kernels, and one option for both: **Options, Video, Ambient Occlusion** (render feature `ambient_occlusion`, console variable `ren_AmbientOcclusion`, `/ao off|standard|low|medium|high` on the command line). At most one kernel runs at a time, in one frame slot.

| Level | `ren_AmbientOcclusion` | Occlusion kernel | Extras | APIs |
|---|---|---|---|---|
| Off | 0 | none | none | all |
| Standard | 1 (the default on Direct3D 12 and Vulkan) | `ren_Ao`'s: 12 rise-biased taps, half resolution compute pass | contact shadows, terrain shadows, ray-traced occlusion | Direct3D 12, Vulkan; on Direct3D 11 Standard draws Low |
| Low | 2 | GTAO, 2 directions x 4 steps, half resolution | contact shadows, terrain shadows | Direct3D 11, 12, Vulkan |
| Medium | 3 | GTAO, 3 x 5, half resolution | same | same |
| High | 4 | GTAO, 3 x 6, full resolution | same | same |

Defaults: Standard on Direct3D 12 and Vulkan (what the engine did before this option existed, `ren_Ao -1`), Off on Direct3D 11, which had no occlusion. The keys the Options screen stores for Off and Standard are `0` and `-1`, the values the old On / Off toggle stored.

## What runs when

| Situation | Kernel | Contact and terrain shadows |
|---|---|---|
| Standard | `ren_Ao`'s compute kernel | yes |
| Low, Medium, High | GTAO (pixel shaders, three draws) | `ren_Ao`'s compute pass with its kernel switched off (`KernelOff`), only when contact or terrain shadows are on |
| Ray-traced shadows tracing, `ren_RayAo` on | traced occlusion (compute pass), whatever the level (not Off) | off (the rays shade both) |
| `ren_Ao 0` | Standard draws nothing; a GTAO level draws GTAO alone | no |
| Direct3D 11, Standard | GTAO Low | no (no compute path) |

So the picture is never darkened twice by two kernels. Contact shadows and terrain shadows are not occlusion, they darken the sun term; they stay where the engine had them (`ren_AoContact`, `ren_TerrainShadows`, the compute pass of `AmbientOcclusionRenderer`).

Terrain shadows beyond the shadow map's reach come from a baked march over the height field (`TerrainShadowCS`, once per map). **They are off by default** (`ren_TerrainShadows 0`: no bake, no buffers, the compute pass only runs for the contact shadows); with the cvar above 0 they are as described here. What shades the ground without them: the shadow map within its reach (and the shadow filter's terrain depth), the light field's sun shadow of the hills while Dynamic Lights is on, `ren_AoContact` at creases, and the occlusion kernel. The bake key holds the height field's pointer, size, sun **and its revision** (`HeightFieldRevision()`), so a map allocated at the same address and terraforming rebake. While the terrain takes Dynamic Lights' light-field march of the sun (`lights::TerrainSunShadowActive()`: the field carries it and `ren_DynLightsTerrainSunShadow` is 1, off by default) the bake is not applied, so the same hills are not darkened twice.

## Where it runs

`WRenViewport::Render` calls `AmbientOcclusionRenderer::Render` right after the opaque meshes (bucket 0x14) and before the effects, the 0x18 meshes and the water, in the colour and depth targets bound at that point, restricted to the view's pixel rectangle. Effects that are already drawn are not darkened, and render scale or any other redirect of the world's targets is followed because the pass uses the bound ones. Orthographic views (minimap, cartographic) are skipped by GTAO (logged once).

## GTAO (`src/gpg/gal/backends/common/AmbientOcclusion.h`, `gpg::gal::AmbientOcclusionPass`)

Ground-truth ambient occlusion (Jimenez et al. 2016) from the scene depth alone. The view-space normal comes from depth differences (the nearer neighbour on each axis, so silhouettes do not smear); per pixel `slices` screen directions (rotated inside a 4x4 Bayer pattern) are searched `steps` taps to each side up to `ren_AORadius` world units away (quadratic spacing, falloff towards the radius, capped at 6 % of the view height in pixels) and the horizons are integrated against the normal. Depth is `Load`-ed, never filtered by the hardware; the shader interpolates it itself (next paragraph). Two blur passes (5 taps, weights 0.5 1 1 1 0.5, one period of the noise pattern) whose weights drop at depth edges (relative depth difference above 2.5 %) remove the pattern; the second one runs at back buffer resolution and upsamples a half-resolution target depth-aware. The occlusion is stored as `ao / 1.25` and clamped only after the blur, see below. The result is blended as black with alpha = 1 - occlusion (colour x occlusion; the back buffer's alpha, which holds the glow amount and the water mask, is not written).

**Taps read the depth at their own position (`ren_AOTapInterp`, 2026-11-13).** A tap at a fractional screen offset used to read the texel it rounds to and take that texel's centre as its position. On a slanted plane that point is off the tap's slice plane (the plane through the pixel, the view ray and the search direction) by up to half a texel, and the horizon search reads the offset as geometry rising above the surface: open ground was darkened by 0.7 % (looking down) to 3.9 % (grazing, Low) depending on the view angle, and every mesh triangle carried its own error, which is the faceted pattern on hill faces. Now the tap's depth is interpolated between the four texels (`AoSampleZ`): the depth buffer value is affine in the inverse view depth, so over a plane it is affine in screen position and the interpolation is exact there; across an edge (the four disagree by more than 5 % of the inverse depth, or one is the sky) the nearest texel is taken, so no depth is invented between two surfaces. **Headroom:** a pixel's estimate of an open plane scatters around 1 (few slices), and clamping it at 1 before the blur turned the downward half of the scatter into darkening (up to 1.4 % at Low); the target now holds `ao / 1.25` (`AO_HEADROOM`) and the composite clamps after the blur.

**Smoothing over smooth ground (`ren_AOSmoothReach`, default 1.5 world units, 0 off).** What the interpolation leaves of a coarse terrain mesh (a triangle pair per world unit: every facet has its own tilt against the surface its neighbours lie on) is averaged away by two more draws after the core blurs: the vertical core blur back into the first target, then `AoWidePS`, which averages three tap pairs spread out to the reach (at most 32 occlusion pixels) along x; the last draw (the composite) adds the same taps along y. A pair counts while both its ends lie in the plane of the centre (the second difference of the inverse depth, expressed as the change of slope across the span, stays under `ren_AOPlaneTolerance`, 0.35: rolling ground and facets pass, a crease, an edge, a wall's foot do not) and its occlusion is within 1/32 of the centre's, so a real crease keeps its contrast. The wide taps read an input the core blurs have already cleaned of the noise pattern; run on the raw search result they brought the pattern back.

One implementation for all three APIs, written against public `Device` calls only (render targets, `SetViewport`, `ClearTarget`, `CreateGpuProgram`, `DrawGpuProgram`: the GPU-driven programs of `GpuDriven.h`). The backends contribute two binding additions: `GpuBindings::targets` (already there for Direct3D 12 and Vulkan, now also Direct3D 11) binds the occlusion target as `t4`, and `GpuBindings::depthTarget` binds a named depth target as `t6` (Vulkan binding 10), where `readBoundDepth` binds the *bound* one. GTAO's draws bind no depth target of their own, which is why the bound one cannot be used: a draw would read the target it also writes.

The head's depth target is created sampled on all three APIs (Direct3D 12 and Vulkan already did; Direct3D 11 now creates a typeless texture with an `R24_UNORM_X8_TYPELESS` view). Direct3D 9 draws with shader model 2 techniques that give no depth to read.

## Settings

| Variable | Default | |
|---|---|---|
| `ren_AmbientOcclusion` | 1 | the option, see above |
| `ren_AORadius`, `ren_AOIntensity`, `ren_AOPower`, `ren_AOHalfRes` | 1.5, 1, 1.6, -1 | GTAO: reach in world units, strength, contrast, -1 the level's choice of resolution / 0 full / 1 half |
| `ren_AOTapInterp`, `ren_AOSmoothReach`, `ren_AOPlaneTolerance` | 1, 1.5, 0.35 | GTAO: 1 reads the depth at each tap's own position (0: the texel it rounds to, the old behaviour); world units the last blur reaches over smooth ground (0: no smoothing, two draws less); how much the surface may bend inside that reach (change of slope) |
| `ren_Ao`, `ren_AoRadius`, `ren_AoIntensity`, `ren_AoBias`, `ren_AoFadeStart`, `ren_AoFadeEnd` | -1, 2, 1, 0.25, 120, 260 | Standard's kernel and the compute pass |
| `ren_AoContact`, `ren_AoContactLength`, `ren_TerrainShadows` | 0.35, 1.5, 0 | contact shadows and terrain shadows; the terrain shadows are off by default (2026-11-13: the baked march over the height field darkened hills in smears that did not look right; `ren_TerrainShadows 0.45` brings the old bake back) |
| `ren_RayAo`, `ren_RayAoRays`, `ren_RayAoLift` | 0, 6, 0.006 | traced occlusion while ray-traced shadows trace; off by default like every ray-traced option (Options > Video > Ray-traced ambient light, key `ray_traced_ao_optin`) |

## Tests

`tests/ao/AmbientOcclusionTests.cpp` (`faf_ao_tests`) runs the real GTAO shaders on a software Direct3D 11 device (WARP) over synthetic depth buffers: open ground stays unoccluded, the ground at a box's foot and a groove are darkened, the box's roof and the sky are not, half and full resolution agree. Two more scenes: a plane at three view angles stays unoccluded (under 0.6 %), and smooth hills drawn as a coarse mesh (two triangles per world unit) show no excess high-frequency pattern over the same hills without a mesh and darken no more than they do (`AO_LAB=<tolerance>,<reach>;...` prints the figures for other settings of the smoothing). The output is read back as float.

## Verified (2026-11-12, RX 7900 XTX, windowed 1600x900, staged static scene, game paused, profile with every render feature Off)

- Levels Off, Standard, Low, Medium, High switched live on Direct3D 12, Vulkan and Direct3D 11: the log shows the compute kernel available on Direct3D 12 and Vulkan only, and `Ambient occlusion (GTAO) quality n active` for the GTAO levels on all three. Mean difference to Off in the frame (staged scene, 3.8 to 7.2 % of the pixels above 8 levels): Standard 1.10 / 0.67 / 1.61, GTAO levels 1.5 to 2.7 (Direct3D 12 / Vulkan / Direct3D 11); the darkening sits at the feet of structures and in the creases of units. On Direct3D 11 Standard and Low give the same frame (Standard draws Low there).
- Registry entry from Lua (`GetOptionsData()`): `ambient_occlusion` with the states Off (`0`), Standard (`-1`), Low, Medium, High, default `-1` on Direct3D 12 and `0` on Direct3D 11; the old On / Off block of `options.lua` is gone, so the option shows once.
- Host test `faf_ao_tests` (WARP): passes (box foot 0.76, wall foot 0.64 against 0.996 higher up, half against full resolution 0.0018).
- Not verified: Standard plus a GTAO level with contact shadows visible on a long game, ray-traced occlusion against GTAO, split screen, exclusive full screen, the old numeric profile values (`-1`, `0`) read by the new entry: tested 2026-11-12, and they were **not** applied (a profile holding `ambient_occlusion = 0` left `ren_AmbientOcclusion` at its default 1: the options layer made the keys text, the stored number matched no state). Fixed in `optionslogic.lua` (a state key that is a whole number is a number; a text "0" still finds its state): with the fix `0` gives `ren_AmbientOcclusion 0` and `'medium'` gives 3, on Direct3D 11, 12 and Vulkan.

## Checked 2026-11-13: the occlusion does not depend on the light field's sun

Question: does GTAO darken the terrain more while `ren_DynLightsSunShadows` is 1? No. Staged paused frames of `adaptive_hilly_plateau.v0003` with a copy of the user's profile (Dynamic Lights Ultra, shadow filter Ultra, GTAO High), 1600x900, `ren_DynLightsSunShadows` 0 against 1, in this order and the reverse, with and without units: the two frames are **bit-identical** at every level (Off, Standard, Low, High; contact shadows on and off) on Direct3D 12 and, for the plateau without units, on Direct3D 11 and Vulkan. With the terrain taking the light field's march (`ren_DynLightsTerrainSunShadow 1`, Direct3D 12) the AO ratio frame (AO on / AO off, luminance) averages 0.9762 with the sun term on and 0.9761 with it off: the sun shadow changes the lit colour (-0.27 levels) and the occlusion multiplies that colour as before. There is no path between the two in the code: the occlusion passes read the depth and the shadow map only, and the one place that asks the light field (`lights::TerrainSunShadowActive()`) only decides whether the `ren_TerrainShadows` bake runs (off by default).

The 4.5-level difference that was seen (frames with the sun term 1 darker than 0, the AO darkening 5.2 against 1.6 levels) came from the test light: `ren_DynLightsTest 1` had spawned a flash earlier in the same paused session, and `ren_DynLightsTest 0` does not remove it while the sim is paused (a flash lives by the sim's clock). Frames taken before and after that step differ by 5.8 levels over the whole view whatever the sun or AO setting is.

How much the occlusion darkens the plateau (Direct3D 12, GTAO High, sun term 0, trees masked out): 1.1 % of the luminance in the shadow of the hills, 1.2 % in the penumbra, 0.8 % in the sunlit ground. It is multiplicative, so ground in shadow (ambient light only) loses the same share as lit ground; a rule that spared shadowed ground would be physically wrong, because the ambient light is all that is left there and the occlusion belongs to it. The faint faceted lines of the occlusion on hill faces follow the terrain mesh's triangles (the normal comes from the depth); a coarser or finer mesh changes them, not the sun. No code change.

## Checked 2026-11-13: terrain faceting and the occlusion of open ground (`fix/gtao`)

Complaint: the terrain's own occlusion looks wrong (not the units' or the contact shadows). The AO ratio of a frame (AO on / AO off, luminance) on `adaptive_hilly_plateau.v0003` showed faint lines along the mesh's triangles on hill faces, saw-tooth marks along ridges and a grey veil over open ground. Staged paused frames of the same scene as the sun diagnostic above (1600x900, the user's profile, GTAO High; zoom 70 at (112, 160) and zoom 32; a flat block at (136, 232) with a few units for the zoom 32 creases), AO off against Low, Medium and High, before (the code of `visuals-all`) and after, on Direct3D 11, 12 and Vulkan.

**Cause.** Not the normal (a wider, bend-aware normal and a slope bias were tried: the normal changed nothing measurable, the bias only removed darkening everywhere, creases included). The taps: a tap read the texel it rounds to and took that texel's centre as its position, which on a slanted plane is off the tap's slice plane and reads as geometry rising above the surface. A plane in the host test was darkened by 0.7 % (looking down) to 3.9 % (grazing, Low) depending on the view angle, and every mesh triangle has its own error. Also, the estimate of an open plane scatters around 1 and was clamped at 1 before the blur, which kept the downward half of the scatter as darkening (Low). See the GTAO section for the fix: interpolated taps, the headroom, and the smoothing over smooth ground.

**Host test (WARP, the game's projection).** Plane at pitch 0.5 / 0.9 / 1.3 rad, mean darkening (Low, Medium, High): before 3.9 / 1.4 / 0.7 %, 1.9 / 1.0 / 0.7 %, 1.9 / 1.1 / 0.7 %; after 0.15 / 0.20 / 0.33 %, 0.18 / 0.21 / 0.33 %, 0.19 / 0.20 / 0.32 %. Smooth hills drawn as a coarse mesh against the same hills without a mesh, excess high-frequency energy of the occlusion (mean absolute Laplacian): High 3.4e-4 before, 8e-5 with the interpolated taps, 2e-5 with the smoothing as well; the mesh darkens 1e-4 more than its surface.

**In the game (mean over crops, the three APIs agree to 0.002 in every darkening figure; Direct3D 12 shown).** Darkening is `1 - mean(ratio)`, band-pass is the mean absolute difference of the ratio image blurred at sigma 1.5 and 7 pixels (the lines along triangles and the scale of the pattern), speckle the mean absolute difference to the 3x3 median (single-pixel noise), p1 the darkening of the strongest 1 % of the pixels (how dark the creases get).

| crop (level) | darkening before / after | band-pass before / after | speckle before / after |
|---|---|---|---|
| plateau top, zoom 70 (High) | 0.0133 / 0.0006 | 0.00204 / 0.00040 | 0.00938 / 0.00072 |
| hill faces, zoom 70 (High) | 0.0163 / 0.0054 | 0.00444 / 0.00289 | 0.00921 / 0.00438 |
| hill faces, zoom 70 (Low) | 0.0246 / 0.0045 | 0.00386 / 0.00189 | 0.00920 / 0.00394 |
| open ground, zoom 32 (High / Medium / Low) | 0.0118 / 0.0012, 0.0123 / 0.0012, 0.0360 / 0.0010 | 0.00253 / 0.00063 | 0.00916 / 0.00097 |
| open ground with units, zoom 32 (High / Low) | 0.0106 / 0.0020, 0.0217 / 0.0019 | 0.00064 / 0.00020 | 0.00328 / 0.00085 |

The mean darkening of terrain falls by about two thirds (hill faces, High: 0.0163 to 0.0054) because most of it was the false occlusion above (the plateau: 1.3 % to 0.06 %); the figure is not kept within 10 %, and keeping it would keep the error. `ren_AOTapInterp 0` and `ren_AOSmoothReach 0` bring most of the old picture back for comparison (the headroom stays).

**Creases stay** (p1, High): ridge teeth 0.120 to 0.101, the fan of hill faces at zoom 32 0.156 to 0.142, the feet of three units at zoom 32 0.552 / 0.506 / 0.477 to 0.527 / 0.530 / 0.487; the mean darkening of the 130 x 110 pixel crops around those units: 0.0744 / 0.0617 / 0.0485 to 0.0677 / 0.0606 / 0.0488 (High), 0.0695 / 0.0658 / 0.0545 to 0.0627 / 0.0487 / 0.0412 (Low: the veil of the old Low was part of it). In the AO ratio images the lines along triangles and the hexagonal outlines on the plateau are gone, the ridge, the junctions of hill faces and the units' feet remain.

**Cost** (`FAF_GPU_PROFILE=60`, pass `AmbientOcclusion`, 1600x900, zoom 70, game paused, blocks of 60 frames, the median of a step's blocks, three repeats of each setting alternated in one run; other sessions may have used the GPU, the repeats agreed to within 0.01 ms on Direct3D 12 and Vulkan, Direct3D 11's timestamps are coarse and often 0 so only its non-zero blocks count). GPU ms, old behaviour (`ren_AOTapInterp 0`, `ren_AOSmoothReach 0`) / interpolated taps / interpolated taps and smoothing (the default): Direct3D 12 Low 0.116 / 0.128 / 0.160, Medium 0.144 / 0.174 / 0.208, High 0.384 / 0.467 / 0.558; Vulkan Low 0.059 / 0.072 / 0.095, Medium 0.081 / 0.106 / 0.134, High 0.225 / 0.299 / 0.340; Direct3D 11 Low 0.110 / 0.108 / 0.158, Medium 0.136 / 0.159 / 0.207, High 0.436 / 0.474 / 0.573. The interpolation reads four texels per tap (on the raw depth, one reciprocal per tap); the smoothing is two extra full-screen draws at the occlusion target's size.

Not verified: a played game (only staged paused frames), split screen and exclusive full screen with the new draws, Standard's compute kernel (not touched), `ren_RayAo`, maps other than the hilly plateau (heightmaps rougher than its hills keep more of their triangles' pattern: the smoothing gives way where the surface bends by more than `ren_AOPlaneTolerance`), a `GatherRed` version of the tap interpolation.

## Limits

It darkens the finished colour (sun, specular and emission too), so a strong setting looks like dirt in the creases rather than missing ambient light; translucent effects and the water surface are darkened by the occlusion of what is behind them only for what was drawn before the slot; thin objects get no special handling; the screen-space search sees nothing outside the screen or hidden behind objects (the traced occlusion does).
