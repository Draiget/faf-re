# Performance audit of the render stack

What the render features of the stack (`visuals-all`, 64499d718, on upstream 432a9df09) cost, against upstream, on one quiet
machine, on Direct3D 12, Vulkan and Direct3D 11. The harness that made every number is in
[tools/perf_audit](../tools/perf_audit/README.md); the method is below, the fixes this audit made are in section 7 and what it
found and left is in section 8.

## 1. Summary

Machine: Ryzen 7 5800X3D, Radeon RX 7900 XTX, 1600x900, vsync off, one game at a time (other sessions' CPU-only games ran
during the audit, no other game used the GPU). Numbers are per frame of the render thread; a game's frame is mostly the sim.

* **Parity.** With every render switch off the stack matches upstream on the GPU to +2 % on the lake, +4 to +8 % (0.05 to
  0.08 ms) on the river and -4 % in the strategic view; CPU is the same within the noise of the machine (-5 to +10 %, 0.05 to 0.12 ms). The one real difference is
  **+0.43 ms (+9 %) in the 80 against 80 battle**, from the particle effect, which is patched at load whatever the options say
  (section 3.1, 8.1; fixed in 7.5). Warm-cache startup is the same on Direct3D 12 and Vulkan.
* **Shipped defaults** cost +0.07 ms GPU on the lake, +0.5 ms in the battle (0.4 of it the patched particle effect),
  +0.24 to +0.38 ms GPU and +0.4 ms CPU on a river map (everything in view is water), +0.5 ms on Direct3D 11's lake
  (section 3.2). Uploads and draw calls per frame are unchanged except on the river map (+64 draws, +18 KB; the CPU of it is
  fixed in 7.6).
* **The user's profile** (Ultra lights and the rest) costs 1.6 to 2.0 times the baseline's GPU time on these scenes
  (3.06 against 1.61 ms on the lake, 7.83 against 5.00 ms in the battle, 4.63 against 2.31 ms strategic), 3.8 against 2.8 ms of CPU
  in the battle, +0.44 to +0.47 GB of process memory and +0.34 GB of video memory (Ultra lights 177 MB, shadow filtering Ultra 76 MB,
  AO High 14 MB of it). Before this audit's fixes it was 1.9 to 3.1 times.
* **Fixed** (2 perf commits and 2 profile-scope commits, section 7): the lights' cell table and its 3 MB upload were built every frame
  although the default path does not read them (Ultra lights CPU +4.45 -> +1.06 ms, GPU +3.22 -> +1.74 ms in the battle; High
  +4.28 -> +0.74 ms CPU); the large-particle estimate and 13 MB of low-resolution targets existed below the 5 megapixels where the
  path never runs (CPU +0.54 -> -0.13 ms at Half, the default).
* **Second round** (`perf/fix2`, sections 7.5 to 7.9, after the first version of this audit): the particle effect is patched only while
  Soft Particles or Large Particle Quality can run, so with them off it costs what upstream's does again (-0.7 ms GPU in the
  battle; 8.1); a body in the water that has not moved is only kept (`WaterFeed` 0.21 -> 0.013 ms on the river map, frame CPU
  -0.2 ms; 8.6); the light field is sized by the level (Low +181 -> +106 MB, Medium -> +137 MB of video memory; 8.5); the light
  textures are read on a worker thread (no frame of 36 to 59 ms on the render thread, 14 frames and 92 to 127 ms of reads
  before; 8.3); the lights' pool is ranked through compact keys (-0.08 ms; 8.2).
* **No leaks**: video memory is flat over a 4-minute battle (0.0 MB/min, two repeats), process memory falls at upstream's rate.

Ten largest per-frame costs of the switches (Direct3D 12, 80 against 80 battle, GPU / CPU ms over everything off, before the fixes;
after in brackets where the audit changed it; Vulkan within 10 %):

| # | cost | GPU ms | CPU ms | default |
|---|---|---|---|---|
| 1 | Ray tracing, all four rays with the sun angle (soft shadows) | +26.7 | +0.2 | off |
| 2 | Ray-traced shadows alone | +6.9 | -0.2 | off |
| 3 | Dynamic Lights Ultra | +3.2 (+1.7) | +4.5 (+1.0) | off |
| 4 | Dynamic Lights High | +3.0 (+1.55) | +4.3 (+0.7 to 0.95) | off |
| 5 | Dynamic Lights Medium | +2.1 (+0.9) | +0.8 (+0.3) | off |
| 6 | Shadow filtering Ultra | +0.47 | -0.3 | off (Low to High +0.0 to +0.2) |
| 7 | Ambient occlusion High (all three APIs) | +0.41 | +0.03 | Standard (+0.1) |
| 8 | The patched particle effect, always on | +0.4 | 0 | on |
| 9 | Large Particle Quality Half / Quarter (CPU) | 0 | +0.54 / +0.62 (-0.13 / -0.16) | Half |
| 10 | Water simulation (CPU) | +0.09 | +0.29 (river +0.23 of which `WaterFeed` 0.21) | on |

Loading and hitches: switching the lights on in a running game takes one frame of 170 ms (Vulkan 141 ms, Direct3D 11 2.5 s after a
13 to 24 s background compile); everything else is below 10 ms on Direct3D 12 and Vulkan except shadow filtering (about 110 ms)
and ray-traced shadows (28 and 46 ms). A first launch with an empty shader cache takes 1.2 s (Direct3D 12) to 3.5 s (Vulkan)
longer to reach the menu than upstream and has one frame of 2.3 s (Direct3D 12) or 5.1 s (Vulkan); Direct3D 11 compiles 6.4 s
longer (`water2.fx`) once, then loads from the cache. The lights read about 180 textures on the render thread in a battle (frames of
up to 14 ms, 25 to 40 ms in a live switch; now on a worker thread, 7.8).

## 2. Method

**Machine.** AMD Ryzen 7 5800X3D (8 cores, 16 threads), Radeon RX 7900 XTX (24 GB; Direct3D 12 driver 32.0.32015.7029, Vulkan 1.4.359 on the AMD proprietary driver 26.10.1, Direct3D 11 on the same driver), Windows 11 Pro 10.0.26100, 1600x900 windowed, vsync off, `sc_FrameTimeClamp 0`, `ren_FpsLimit 0` (the loop runs flat out; a frame of 0.5 ms is 2000 FPS). The user's own `Game.prefs` was never changed: the runs read copies (`Game_perf_*.prefs`, made by `tools/perf_audit/mk_prefs.py` from a copy of `Game_tsuser.prefs`).

**Builds.** `perf.exe`: branch `perf/audit` (the stack `visuals-all` at 64499d718 on upstream 432a9df09). `perfbase.exe`: upstream 432a9df09 itself, built with the same compiler and preset (clang-cl, Ninja, `clang-x64-release`) in its own worktree. Both run from one folder (`bin_x64_perf`) with the data folder `fafengine` of their own tree swapped in before each run (plus the same two test hooks), the same maps, the same seed.

**Measurement.** `FAF_GPU_PROFILE=<frames>` (120 to 500 frames per window, the engine's own per-pass GPU timestamps and CPU scopes). One window gives `ms/frame wall`, GPU ms (the `Frame` region: first to last timestamp of the frame), render-thread CPU ms (`Frame` CPU), frame wall p50/p99/max and the same for each pass. A step of a test lasts 3 s (10 s for the parity runs), the first 1.2 s of each step are dropped (a switch rebuilds effects), the step's value is the median of its windows. A feature is measured in the same session as its reference: `off, level 1, level 2, ..., off` repeated three times; the table shows the median of the three differences to the `off` step that precedes it and the range of the three. Everything else is at its off value while a feature is measured. Process private bytes, the GPU counter `GPU Process Memory` and `ren_Info` give memory.

**Scenes** (map `adaptive_acid_lakes`, seed 7, no AI, the test hooks of `tests/featab` create the content):

| Scene | What | Camera |
|---|---|---|
| lake | `static`: the structures of four factions and eight experimentals beside a lake, nothing moves | zoom 60 over the start position, the lake in view |
| battle | `battlestill`: 80 against 80 mobile units (T2 to experimentals, all factions), immortal and standing, firing at each other all the time (a steady particle, beam and light load) | zoom 70 |
| battle (parity) | `soak`: the same units walking into each other, structures, trees, a nuke every 25 s | zoom 70 |
| nuke | a strategic missile, game paused at the explosion | zoom 60 |
| river | map `faf_re_waterrivers` with `sim_FixWaterBodies` and `sim_FixRivers`, camera at the falls | zoom 38 |
| strategic | the battle scene from zoom 420 (strategic icons) | |

**Caveats.** Other sessions of this workspace ran headless (CPU-only) games during the whole audit: no other game used the GPU, so the GPU columns are not shared; the CPU columns of single runs moved by up to 20 % with that load (the parity tables take medians over repeated runs that alternate the two builds). Windows and the driver were not restarted. Frame times in the parity runs are very small (0.3 to 5 ms), which is the point: fixed per-frame costs show up clearly; a real game spends most of its time in the sim.

## 3. Parity with upstream

Two builds of the same compiler and preset: `perfbase` (upstream 432a9df09 alone) and `perf` (this stack). Every combination of
configuration, API and scene ran alternately (base, ours, base, ours, ...), 10 s steps, medians of the repeats. "Off" is the
stack with every render switch off (`Game_perf_off.prefs`: no lights, no filtering, no AA/AO/grade, no water additions, no soft
or low-resolution particles); the baseline is run with the same prefs file it understands. "Default" is the shipped defaults
(`Game_perf_default.prefs`) against the baseline's own defaults. A frame of 1 ms is 1000 FPS: relative numbers on such frames look
large, the absolute difference in ms is the number to read.

The "final build" below is the tree with the fixes of section 7. It was measured with the early-out of section 7.4 still in it (that
experiment is not in the commits; it moved `WaterFeed` by less than 0.015 ms); the tree of the commits was rebuilt and compiles.

### 3.1 Everything off (Direct3D 12, final build)

| scene / view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | frame wall ms base | ours | p99 ms base | ours | runs |
|---|---|---|---|---|---|---|---|---|---|
| lake, lake view | 1.445 | 1.473 (+2 %) | 1.191 | 1.306 (+10 %) | 1.520 | 1.598 | 1.82 | 2.21 | 3/4 |
| lake, close view | 1.020 | 1.040 (+2 %) | 0.754 | 0.803 (+6 %) | 1.110 | 1.132 | 1.40 | 1.46 | 3/4 |
| battle, battle view | 4.820 | 5.245 (+9 %) | 2.854 | 2.904 (+2 %) | 4.870 | 5.297 | 5.85 | 6.38 | 3/4 |
| battle, strategic view | 2.190 | 2.112 (-4 %) | 2.029 | 1.932 (-5 %) | 2.410 | 2.518 | 3.47 | 3.56 | 3/4 |
| river, falls view | 1.190 | 1.237 (+4 %) | 1.075 | 1.164 (+8 %) | 1.330 | 1.390 | 1.75 | 1.82 | 3/4 |
| river, wide view | 0.970 | 1.050 (+8 %) | 1.116 | 1.158 (+4 %) | 1.360 | 1.380 | 1.77 | 1.92 | 3/4 |

The GPU columns are the reliable ones: they come from GPU timestamps and moved by 0.003 ms between repeats. The CPU columns of
single runs moved by up to 0.3 ms (a lake run of the same build: 1.27 and 1.59 ms) because other sessions of this workspace ran
CPU-only games on the same machine. In the table above (three runs of upstream, four of the final build) the CPU is -5 to +10 %
(0.05 to 0.12 ms, battle +0.05 ms); the first parity run, with three repeats per build, gave -6 to +5 % in every scene:

| scene / view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | frame wall ms base | ours | p99 ms base | ours | runs |
|---|---|---|---|---|---|---|---|---|---|
| lake, lake view | 1.445 | 1.460 (+1 %) | 1.191 | 1.211 (+2 %) | 1.520 | 1.535 | 1.82 | 1.86 | 3/3 |
| lake, close view | 1.020 | 1.030 (+1 %) | 0.754 | 0.766 (+2 %) | 1.110 | 1.120 | 1.40 | 1.43 | 3/3 |
| battle, battle view | 4.820 | 5.250 (+9 %) | 2.854 | 2.812 (-1 %) | 4.870 | 5.345 | 5.85 | 6.14 | 3/3 |
| battle, strategic view | 2.190 | 2.130 (-3 %) | 2.029 | 1.899 (-6 %) | 2.410 | 2.510 | 3.47 | 3.52 | 3/3 |
| river, falls view | 1.190 | 1.240 (+4 %) | 1.075 | 1.132 (+5 %) | 1.330 | 1.370 | 1.75 | 1.68 | 3/3 |
| river, wide view | 0.970 | 1.040 (+7 %) | 1.116 | 1.171 (+5 %) | 1.360 | 1.400 | 1.77 | 1.75 | 3/3 |

With everything off the stack is the baseline to within 0.02 to 0.08 ms of GPU time per frame on the lake and the river, and
0.43 ms (+9 %) on the 80 against 80 battle. That difference is the particle effect: `particle.fx` is patched when it is loaded
(soft-fade pixel shader replacement, large-quad path), whatever the options say, and in a scene with a lot of particles the
patched effect is slower even with soft particles and low resolution off (EffParticles GPU 3.15 -> 3.52 ms in the battle; with
`/noparticlelowres` the effect is not patched and the pass is 3.10 ms, equal to the baseline; 3 repeats, ranges below 0.1 ms).
The strategic view of the same battle is not slower (-3 %): the pass is not drawn there. Section 8.1.

Vulkan and Direct3D 11 (first parity runs, two repeats):

| scene / view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | frame wall ms base | ours | p99 ms base | ours | runs |
|---|---|---|---|---|---|---|---|---|---|
| lake, lake view | 1.335 | 1.355 (+1 %) | 1.266 | 1.313 (+4 %) | 1.755 | 1.820 | 2.54 | 2.80 | 2/2 |
| lake, close view | 0.955 | 1.000 (+5 %) | 0.827 | 1.136 (+37 %) | 1.335 | 1.820 | 1.93 | 2.67 | 2/2 |
| battle, battle view | 4.650 | 4.985 (+7 %) | 2.953 | 2.920 (-1 %) | 5.127 | 5.425 | 6.73 | 6.78 | 2/2 |
| battle, strategic view | 2.155 | 1.992 (-8 %) | 2.266 | 1.917 (-15 %) | 2.900 | 2.652 | 4.67 | 4.32 | 2/2 |
| river, falls view | 1.220 | 1.230 (+1 %) | 1.265 | 1.282 (+1 %) | 1.755 | 1.782 | 2.61 | 2.72 | 2/2 |
| river, wide view | 0.980 | 1.045 (+7 %) | 1.255 | 1.265 (+1 %) | 1.745 | 1.763 | 2.52 | 2.61 | 2/2 |

| scene / view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | frame wall ms base | ours | p99 ms base | ours | runs |
|---|---|---|---|---|---|---|---|---|---|
| lake, lake view | 1.013 | 0.992 (-2 %) | 1.293 | 1.309 (+1 %) | 1.665 | 1.700 | 2.13 | 2.19 | 2/2 |
| lake, close view | 0.742 | 0.752 (+1 %) | 0.747 | 0.817 (+9 %) | 1.155 | 1.342 | 1.58 | 2.05 | 2/2 |
| battle, battle view | 1.525 | 1.635 (+7 %) | 2.654 | 2.523 (-5 %) | 3.298 | 2.928 | 6.34 | 5.44 | 2/2 |
| battle, strategic view | 2.117 | 1.950 (-8 %) | 2.517 | 2.218 (-12 %) | 3.070 | 2.758 | 5.00 | 4.38 | 2/2 |

### 3.2 Shipped defaults against the baseline's defaults

Direct3D 12, final build (the baseline's numbers are those of the first run):

| scene / view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | frame wall ms base | ours | p99 ms base | ours | runs |
|---|---|---|---|---|---|---|---|---|---|
| lake, lake view | 1.600 | 1.675 (+5 %) | 1.223 | 1.335 (+9 %) | 1.680 | 1.765 | 2.02 | 2.46 | 3/4 |
| lake, close view | 1.210 | 1.280 (+6 %) | 0.792 | 0.869 (+10 %) | 1.290 | 1.370 | 1.58 | 1.69 | 3/4 |
| battle, battle view | 4.990 | 5.495 (+10 %) | 2.832 | 3.151 (+11 %) | 5.040 | 5.580 | 6.04 | 6.79 | 3/4 |
| battle, strategic view | 2.290 | 2.300 (+0 %) | 2.115 | 1.986 (-6 %) | 2.730 | 2.610 | 3.82 | 3.50 | 3/4 |
| river, falls view | 1.355 | 1.590 (+17 %) | 1.085 | 1.514 (+40 %) | 1.438 | 1.735 | 1.79 | 2.37 | 2/4 |
| river, wide view | 1.118 | 1.500 (+34 %) | 1.096 | 1.519 (+39 %) | 1.328 | 1.743 | 1.71 | 2.58 | 2/4 |

Vulkan, final build (one run of the final build; the baseline of the first run):

| scene / view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | frame wall ms base | ours | p99 ms base | ours | runs |
|---|---|---|---|---|---|---|---|---|---|
| lake, lake view | 1.500 | 1.580 (+5 %) | 1.296 | 1.385 (+7 %) | 1.810 | 1.930 | 2.66 | 2.81 | 2/1 |
| lake, close view | 1.125 | 1.230 (+9 %) | 0.850 | 0.878 (+3 %) | 1.400 | 1.480 | 1.99 | 2.08 | 2/1 |
| battle, battle view | 5.055 | 5.405 (+7 %) | 2.986 | 3.008 (+1 %) | 5.435 | 5.770 | 7.05 | 6.84 | 2/1 |
| battle, strategic view | 2.465 | 2.205 (-11 %) | 2.708 | 1.966 (-27 %) | 3.327 | 2.905 | 5.86 | 4.32 | 2/1 |

Direct3D 12, first run (before the fixes of section 7):

| scene / view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | frame wall ms base | ours | p99 ms base | ours | runs |
|---|---|---|---|---|---|---|---|---|---|
| lake, lake view | 1.600 | 1.690 (+6 %) | 1.223 | 1.343 (+10 %) | 1.680 | 1.780 | 2.02 | 2.12 | 3/3 |
| lake, close view | 1.210 | 1.280 (+6 %) | 0.792 | 0.874 (+10 %) | 1.290 | 1.370 | 1.58 | 1.67 | 3/3 |
| battle, battle view | 4.990 | 5.530 (+11 %) | 2.832 | 3.374 (+19 %) | 5.040 | 5.640 | 6.04 | 6.68 | 3/3 |
| battle, strategic view | 2.290 | 2.310 (+1 %) | 2.115 | 2.053 (-3 %) | 2.730 | 2.740 | 3.82 | 3.71 | 3/3 |
| river, falls view | 1.355 | 1.600 (+18 %) | 1.085 | 1.513 (+40 %) | 1.438 | 1.740 | 1.79 | 2.23 | 2/2 |
| river, wide view | 1.118 | 1.505 (+35 %) | 1.096 | 1.590 (+45 %) | 1.328 | 1.855 | 1.71 | 2.52 | 2/2 |

Vulkan, first run:

| scene / view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | frame wall ms base | ours | p99 ms base | ours | runs |
|---|---|---|---|---|---|---|---|---|---|
| lake, lake view | 1.500 | 1.585 (+6 %) | 1.296 | 1.397 (+8 %) | 1.810 | 1.948 | 2.66 | 2.97 | 2/2 |
| lake, close view | 1.125 | 1.235 (+10 %) | 0.850 | 0.911 (+7 %) | 1.400 | 1.500 | 1.99 | 2.16 | 2/2 |
| battle, battle view | 5.055 | 5.375 (+6 %) | 2.986 | 3.939 (+32 %) | 5.435 | 5.840 | 7.05 | 8.00 | 2/2 |
| battle, strategic view | 2.465 | 2.230 (-10 %) | 2.708 | 2.287 (-16 %) | 3.327 | 3.130 | 5.86 | 4.59 | 2/2 |
| river, falls view | 1.380 | 1.605 (+16 %) | 1.305 | 1.672 (+28 %) | 1.817 | 2.220 | 2.67 | 3.46 | 2/2 |
| river, wide view | 1.140 | 1.505 (+32 %) | 1.276 | 1.647 (+29 %) | 1.790 | 2.185 | 2.64 | 3.50 | 2/2 |

Direct3D 11, first run:

| scene / view | GPU ms base | GPU ms ours | CPU ms base | CPU ms ours | frame wall ms base | ours | p99 ms base | ours | runs |
|---|---|---|---|---|---|---|---|---|---|
| lake, lake view | 1.007 | 1.495 (+48 %) | 1.284 | 1.497 (+17 %) | 1.650 | 1.958 | 2.16 | 2.49 | 2/2 |
| lake, close view | 0.745 | 0.800 (+7 %) | 0.752 | 0.833 (+11 %) | 1.150 | 1.312 | 1.56 | 1.73 | 2/2 |
| battle, battle view | 1.292 | 1.882 (+46 %) | 2.432 | 3.116 (+28 %) | 2.875 | 3.660 | 5.21 | 6.05 | 2/2 |
| battle, strategic view | 2.020 | 2.383 (+18 %) | 2.432 | 2.502 (+3 %) | 2.970 | 3.055 | 4.69 | 4.61 | 2/2 |

What the defaults add (each is on by default in the stack, off in upstream): ambient occlusion Standard, FXAA, sharpening Medium,
colour grading, soft particles Low, Large Particle Quality Half (never taken below 5 megapixels), texture filtering 8x, and the water
additions (simulation, rivers, waterfalls, SSR, thickness, caustics, sheen, unit shadows, banks, terrain water levels, shore
tessellation). Dynamic lights, shadow filtering, temporal AA, render scale, sun shafts, wide glow and ray tracing are off at the
defaults. Each default is a few hundredths of a
millisecond on its own (section 5); together they are +0.06 to +0.33 ms of GPU time in the per-feature runs
(`Configurations: shipped defaults on` rows), which the parity runs confirm for the lake (+0.07 ms on Direct3D 12).
Two scenes are larger: the battle (+0.5 ms, of which 0.4 is the particle patch of section 8.1) and the river map, where the
default-on water (simulation, rivers, waterfalls, SSR) is everywhere in view: +0.24 to +0.38 ms GPU and +0.4 ms CPU on a
1.1 ms frame (+17 to +34 % GPU, +40 % CPU). In a game the sim, not the render thread, is the frame; these numbers are what the render thread adds.

Direct3D 11 shows +0.5 ms (+48 %) on the lake at default in the parity runs against +0.33 ms in the per-feature
`shipped defaults on` row; the 0.16 ms in between was not traced (it is not one of the switches: every Direct3D 11 row in the
per-feature table is below 0.4 ms).

### 3.3 Startup, uploads and draws

Uploads per frame and draws are the same at defaults on the lake and the battle (66 / 66 KB, 331 / 332 KB per frame; the draw
count of the battle differs because the soak scene is not frame-exact). The river map at defaults draws 414 against 350 calls
and uploads 148 against 130 KB per frame (the water bodies, waterfalls and rivers). Startup (renderer ready, shaders compiled,
simulation started, first frame) is the same to within 0.1 s on Direct3D 12 and Vulkan with warm caches (section 6.1); Direct3D 11
is different (section 6.1).

| config | API | scene | process private MB base / ours | GPU local budget MB base / ours | renderer ready s | shaders compiled s | sim started s | first profile frame s |
|---|---|---|---|---|---|---|---|---|
| off | d3d12 | lake | 1078 / 1088 (+10) | 535 / 545 (+10) | 0.85 / 0.86 | 0.98 / 0.98 | 1.91 / 1.92 | 1.29 / 1.29 |
| off | d3d12 | battle | 1153 / 1187 (+34) | 472 / 482 (+10) | 0.80 / 0.83 | 0.93 / 0.96 | 1.86 / 1.89 | 1.17 / 1.20 |
| off | d3d12 | river | 840 / 860 (+20) | 405 / 421 (+16) | 0.89 / 0.84 | 1.02 / 0.96 | 2.02 / 1.96 | 1.28 / 1.21 |
| off | vulkan | lake | 1476 / 1497 (+21) | 532 / 532 (+0) | 1.19 / 1.02 | 1.31 / 1.11 | 2.25 / 2.02 | 1.78 / 1.57 |
| off | vulkan | battle | 1354 / 1380 (+26) | 469 / 469 (+0) | 0.95 / 0.94 | 1.08 / 1.06 | 1.98 / 1.91 | 1.35 / 1.31 |
| off | vulkan | river | 1012 / 1016 (+4) | 401 / 401 (+0) | 0.95 / 0.93 | 1.05 / 1.06 | 2.05 / 1.94 | 1.40 / 1.34 |
| off | d3d11 | lake | 1184 / 1190 (+5) | 407 / 424 (+16) | 0.84 / 0.83 | 12.97 / 14.11 | 13.91 / 15.05 | 13.41 / 14.55 |
| off | d3d11 | battle | 1142 / 1162 (+20) | 360 / 364 (+4) | 0.81 / 0.81 | 12.69 / 14.04 | 13.94 / 14.95 | 13.34 / 14.32 |
| default | d3d12 | lake | 1083 / 1156 (+73) | 540 / 609 (+69) | 0.86 / 0.92 | 0.99 / 1.10 | 2.12 / 2.04 | 1.30 / 1.41 |
| default | d3d12 | battle | 1155 / 1248 (+93) | 476 / 545 (+69) | 0.85 / 0.86 | 0.98 / 0.98 | 1.87 / 1.92 | 1.18 / 1.23 |
| default | d3d12 | river | 842 / 994 (+152) | 409 / 484 (+74) | 0.83 / 0.89 | 0.96 / 1.02 | 1.92 / 2.06 | 1.21 / 1.27 |
| default | vulkan | lake | 1270 / 1376 (+106) | 533 / 597 (+64) | 1.08 / 0.94 | 1.24 / 1.07 | 2.23 / 1.94 | 1.64 / 1.47 |
| default | vulkan | battle | 1258 / 1345 (+88) | 469 / 533 (+64) | 1.25 / 1.02 | 1.40 / 1.14 | 2.62 / 2.11 | 1.75 / 1.42 |
| default | vulkan | river | 952 / 1064 (+112) | 401 / 401 (+0) | 1.61 / 0.96 | 1.71 / 1.02 | 2.93 / 1.93 | 2.12 / 1.40 |
| default | d3d11 | lake | 1165 / 1264 (+98) | 408 / 486 (+78) | 0.85 / 0.85 | 12.64 / 19.57 | 13.61 / 20.52 | 13.08 / 19.98 |
| default | d3d11 | battle | 1128 / 1240 (+111) | 361 / 427 (+66) | 0.81 / 0.90 | 12.62 / 22.96 | 13.50 / 23.90 | 12.94 / 23.27 |

## 4. The user's profile

`Game_perf_user.prefs` is a copy of `Game_tsuser.prefs`, the profile in daily use, with vsync off and no frame limit: Ultra dynamic
lights, shadow filtering Ultra, ambient occlusion High, FXAA, sharpening High, soft particles High, water quality High, 16x texture
filtering and Large Particle Quality Half; temporal AA, render scale, sun shafts, wide glow and ray tracing are off in it (its
ray-tracing keys are opt-in flags at 0; the log shows no ray pass). Same scenes, Direct3D 12, medians of the repeats, base is
upstream with its own default prefs:

| scene / view | GPU ms base | GPU ms ours (before the fixes) | GPU ms ours (after) | CPU ms base | CPU ms ours (before) | CPU ms ours (after) | frame p99 ms base / before / after |
|---|---|---|---|---|---|---|---|
| lake, lake view | 1.61 | 4.53 (2.8x) | 3.06 (1.9x) | 1.21 | 2.12 | 1.61 | 1.97 / 4.97 / 3.37 |
| lake, close view | 1.22 | 3.77 (3.1x) | 2.47 (2.0x) | 0.81 | 1.29 | 1.04 | 1.59 / 4.09 / 2.81 |
| battle, battle view | 5.00 | 9.43 (1.9x) | 7.83 (1.6x) | 2.83 | 6.89 | 3.80 | 6.19 / 11.92 / 8.94 |
| battle, strategic view | 2.31 | 6.05 (2.6x) | 4.63 (2.0x) | 2.09 | 3.96 | 2.82 | 3.66 / 7.37 / 6.05 |
| river, falls view | 1.37 | 3.57 (2.6x) | not run | 1.27 | 1.78 | not run | 3.10 / 3.95 / not run |
| river, wide view | 1.12 | 2.44 (2.2x) | not run | 1.12 | 1.79 | not run | 1.89 / 2.93 / not run |

The "before" column is the stack as it came; the "after" column is the stack with the fixes of section 7 (lights, particles),
measured in a second run. The profile costs 1.6 to 2.0 times the baseline's GPU time on these scenes (a 1.1 to 5 ms baseline) and
+0.44 to +0.47 GB of process memory and +0.34 GB of video memory (section 4.1). Most of the GPU difference is dynamic lights at
Ultra (+1 to +2.3 ms depending on the scene, section 7.1); AO High (+0.4 ms), shadow filtering Ultra (+0.1 to +0.5 ms), soft
particles High and sharpening High (each below +0.05 ms) are the rest (section 5).

### 4.1 Memory

| config | API | scene | process private MB base / ours | GPU local budget MB base / ours | renderer ready s | shaders compiled s | sim started s | first profile frame s |
|---|---|---|---|---|---|---|---|---|
| user | d3d12 | lake | 1084 / 1522 (+438) | 540 / 875 (+335) | 0.91 / 0.85 | 1.04 / 1.04 | 1.98 / 1.95 | 1.35 / 1.33 |
| user | d3d12 | battle | 1158 / 1629 (+471) | 476 / 812 (+336) | 0.83 / 0.89 | 0.92 / 1.04 | 1.86 / 2.04 | 1.17 / 1.33 |
| user | d3d12 | river | 841 / 1308 (+466) | 409 / 751 (+342) | 1.12 / 0.90 | 1.23 / 1.03 | 2.25 / 1.96 | 1.50 / 1.27 |

Where the video memory of the profile goes (Direct3D 12, lake, settled; the profile with one group of its options put back to the
default, run again from the prefs file each time):

| run (Direct3D 12, lake scene, settled) | process private MB | GPU dedicated MB | GPU MB against the whole profile |
|---|---|---|---|
| the user profile as it is | 1446 | 876 | +0 |
| dynamic lights at the default (off) | 1255 | 699 | -177 |
| shadow filtering at the default (off) | 1465 | 800 | -76 |
| ambient occlusion at the default (Standard) | 1495 | 862 | -14 |
| soft particles at the default (Low) | 1446 | 876 | +0 |
| sharpening quality at the default (Medium) | 1506 | 876 | +0 |
| lights, shadow filtering and AO at the default | 1140 | 609 | -267 |

Dynamic lights are the largest part (177 MB of video memory, about 190 MB of process memory at startup), then shadow filtering
(76 MB); together with AO High they are the 267 MB between the profile and the default (876 -> 609 MB; 1446 -> 1140 MB of process
memory). Soft particles High and sharpening High allocate nothing (a run each at the default differs by less than 1 MB of video
memory). The video memory is the same to the MB between repeats; the process figures of single runs vary by about 50 MB.

Where the memory of the default configuration goes (Direct3D 12, lake, settled, MB):

| run (Direct3D 12, lake scene, settled) | process private MB | GPU dedicated MB | buffer copies MB | placed buffers MB |
|---|---|---|---|---|
| baseline, defaults | 1080 | 544 | 14.8 | 17.6 |
| ours, defaults | 1158 | 614 | 18.2 | 20.4 |
| ours, FAF_NO_RENDER_ADDITIONS=1 | 1135 | 601 | 18.2 | 20.4 |
| ours, /noparticlelowres (particle.fx unpatched) | 1134 | 601 | 18.2 | 20.4 |
| ours, ren_WaterSim=0 at startup | 1152 | 570 | 16.2 | 19.1 |
| ours, water features off + /noparticlelowres | 1085 | 557 | 16.2 | 19.1 |
| ours, particle low-resolution and soft particles off | 1145 | 614 | 18.2 | 20.4 |
| ours, FXAA, sharpening, grading and occlusion off | 1147 | 614 | 18.2 | 20.4 |

The +70 MB of video memory at defaults is the water simulation (about 44 MB of targets and history) and the low-resolution
particle targets (about 13 MB, made even below the 5 megapixels where they are never used; the fix of section 7.2 removes that
for the smaller views); the rest is the post chain. Memory per feature, switched on one after the other in one session
(`ren_*` commands, process private bytes and the GPU process counter, 7 s each, cumulative):

**Direct3D 12**

| step (cumulative) | process private MB | delta | GPU dedicated MB | delta |
|---|---|---|---|---|
| start_default | 1144 | +0 | 614 | +0 |
| all_off | 1146 | +2 | 610 | -4 |
| hold_off | 1152 | +6 | 610 | +0 |
| aa_fxaa | 1156 | +4 | 610 | +0 |
| aa_smaa | 1157 | +1 | 610 | +0 |
| sharpen_grade | 1171 | +14 | 623 | +14 |
| softparticles_high | 1171 | +0 | 623 | +0 |
| lowres_half_forced | 1171 | +0 | 623 | +0 |
| watersim | 1171 | +0 | 623 | +0 |
| waterq3 | 1171 | +0 | 623 | +0 |
| ssr_absorb_caustics | 1171 | +0 | 623 | +0 |
| ao_standard | 1202 | +31 | 654 | +31 |
| ao_high | 1202 | +0 | 654 | +0 |
| shadowfilter_ultra | 1202 | +0 | 654 | +0 |
| lights_ultra | 1216 | +14 | 667 | +14 |
| taa | 1216 | +0 | 667 | +0 |
| renderscale_75 | 1314 | +98 | 760 | +93 |
| atmosphere | 1555 | +241 | 941 | +181 |
| bloomwide | 1556 | +0 | 941 | +0 |
| rays_shadows | 1599 | +43 | 985 | +44 |
| rays_ao_bounce_water | 1599 | +0 | 985 | +0 |
| final_hold | 1603 | +4 | 983 | -2 |

**Vulkan**

| step (cumulative) | process private MB | delta | GPU dedicated MB | delta |
|---|---|---|---|---|
| start_default | 1303 | +0 | 622 | +0 |
| all_off | 1305 | +2 | 622 | +0 |
| hold_off | 1317 | +13 | 622 | +0 |
| aa_fxaa | 1319 | +2 | 622 | +0 |
| aa_smaa | 1319 | +0 | 622 | +0 |
| sharpen_grade | 1320 | +1 | 622 | +0 |
| softparticles_high | 1320 | -0 | 622 | +0 |
| lowres_half_forced | 1320 | +0 | 622 | +0 |
| watersim | 1320 | +0 | 622 | +0 |
| waterq3 | 1321 | +1 | 622 | +0 |
| ssr_absorb_caustics | 1322 | +1 | 622 | +0 |
| ao_standard | 1322 | +0 | 622 | +0 |
| ao_high | 1322 | +0 | 622 | +0 |
| shadowfilter_ultra | 1354 | +32 | 654 | +32 |
| lights_ultra | 1386 | +32 | 686 | +32 |
| taa | 1541 | +155 | 833 | +147 |
| renderscale_75 | 1641 | +100 | 899 | +66 |
| atmosphere | 1736 | +95 | 965 | +66 |
| bloomwide | 1736 | +0 | 965 | +0 |
| rays_shadows | 1758 | +22 | 965 | +0 |
| rays_ao_bounce_water | 1758 | +0 | 965 | +0 |
| final_hold | 1758 | +0 | 965 | +0 |

The same three big post features switched on alone, one after the other, from everything off:

| step (each alone, in this order, after all off) | Direct3D 12: process MB delta | GPU MB delta (total) | Vulkan: process MB delta | GPU MB delta (total) |
|---|---|---|---|---|
| all_off | +3 | -4 (605) | +3 | +0 (622) |
| hold_off | +7 | +0 (605) | +12 | +0 (622) |
| atmosphere | +10 | +6 (611) | +35 | +32 (654) |
| taa | +7 | +6 (618) | +31 | +32 (686) |
| renderscale_75 | +43 | +44 (662) | -1 | +0 (686) |
| final_hold | +0 | +0 (662) | +0 | +0 (686) |

Alone, sun shafts and temporal AA take 6 MB (Direct3D 12) or 32 MB (Vulkan) each, and render scale 75 % 44 MB (Direct3D 12) or
nothing (Vulkan). Switched on after all the others in the table before it, the same three took 340 to 350 MB on both APIs: the
cost is in the combination (and in what each API allocates when), not in a feature; it was not isolated further.

## 5. Cost per feature

How to read the tables: each row is a feature at one level compared with the off step before it in the same session, three
times (the median of the three differences, and in brackets the range of the three, GPU ms). Everything else is off. GPU ms is
the engine's own `Frame` GPU region (first to last timestamp of the frame), CPU ms the render thread's `Frame` scope. "What
changes most" lists the two profile passes with the largest change (GPU / CPU ms). Rows with `-` or negative values below the
range are noise. The ray tracing rows are cumulative (each level is added to the ones above: `shadows` is shadows alone, `water`
is shadows + AO + bounce + water, `soft` is all of them with the sun angle of 3 degrees). `Dynamic Lights, mode at Ultra` rows are
diagnostic modes (`grid` is the old cell-grid path every shader walks, the default is `field`) and are not part of any ranking.
**These tables were measured before the fixes of section 7**, so the lights and large-particle rows are the cost as it came;
section 7 gives them again after.

### 5.1 Ranking per API

Most expensive switches, GPU (the largest of the scenes, the default is the lowest level that is on; ray rows are cumulative):

**Direct3D 12**

| # | feature | level | GPU ms | CPU ms | scene |
|---|---|---|---|---|---|
| 1 | Ray tracing (cumulative: each row adds to the one above) | soft | +26.68 | +0.19 | battle |
| 2 | Ray tracing (cumulative: each row adds to the one above) | water | +7.46 | -0.03 | battle |
| 3 | Ray tracing (cumulative: each row adds to the one above) | bounce | +7.25 | -0.05 | battle |
| 4 | Ray tracing (cumulative: each row adds to the one above) | ao | +6.99 | -0.03 | battle |
| 5 | Ray tracing (cumulative: each row adds to the one above) | shadows | +6.85 | -0.18 | battle |
| 6 | Dynamic Lights | Ultra | +3.22 | +4.45 | battle |
| 7 | Dynamic Lights | High | +3.04 | +4.28 | battle |
| 8 | Dynamic Lights | Medium | +2.08 | +0.79 | battle |
| 9 | Dynamic Lights | Low | +0.85 | -0.08 | strategic |
| 10 | Shadow filtering | Ultra | +0.47 | -0.31 | battle |
| 11 | Ambient occlusion | High | +0.41 | +0.03 | battle |
| 12 | Ambient occlusion | Medium | +0.21 | +0.14 | battle |
| 13 | Shadow filtering | High | +0.19 | -0.28 | battle |
| 14 | Shadow filtering | Medium | +0.19 | +0.01 | nuke |

**Vulkan**

| # | feature | level | GPU ms | CPU ms | scene |
|---|---|---|---|---|---|
| 1 | Ray tracing (cumulative: each row adds to the one above) | soft | +22.10 | +0.56 | battle |
| 2 | Ray tracing (cumulative: each row adds to the one above) | water | +7.05 | +0.11 | battle |
| 3 | Ray tracing (cumulative: each row adds to the one above) | bounce | +6.84 | -0.04 | battle |
| 4 | Ray tracing (cumulative: each row adds to the one above) | shadows | +6.56 | -0.07 | battle |
| 5 | Ray tracing (cumulative: each row adds to the one above) | ao | +6.45 | -0.08 | battle |
| 6 | Dynamic Lights | Ultra | +2.93 | +4.25 | battle |
| 7 | Dynamic Lights | High | +2.84 | +3.96 | battle |
| 8 | Dynamic Lights | Medium | +1.98 | +0.91 | battle |
| 9 | Ambient occlusion | High | +0.44 | +0.06 | battle |
| 10 | Shadow filtering | Ultra | +0.39 | -0.01 | battle |
| 11 | Dynamic Lights | Low | +0.28 | +0.13 | battle |
| 12 | Shadow filtering | High | +0.18 | +0.03 | battle |
| 13 | Ambient occlusion | Medium | +0.16 | +0.03 | lake |
| 14 | Ambient occlusion | Low | +0.14 | -0.01 | lake |

**Direct3D 11** (no lights, no ray tracing, no temporal AA, no atmosphere there)

| # | feature | level | GPU ms | CPU ms | scene |
|---|---|---|---|---|---|
| 1 | Ambient occlusion | High | +0.40 | +0.03 | lake |
| 2 | Ambient occlusion | Medium | +0.16 | +0.01 | lake |
| 3 | Ambient occlusion | Low | +0.16 | +0.03 | lake |
| 4 | Ambient occlusion | Standard | +0.12 | +0.03 | lake |
| 5 | Render resolution (the share of the view) | 85 | +0.09 | +0.00 | lake |
| 6 | Sharpening | Medium | +0.08 | +0.00 | lake |
| 7 | Anti-aliasing | SMAA | +0.08 | +0.02 | lake |
| 8 | Render resolution (the share of the view) | 75 | +0.08 | +0.01 | lake |
| 9 | Sharpening | Low | +0.08 | +0.02 | lake |
| 10 | Shadow filtering | Ultra | +0.07 | +0.05 | lake |
| 11 | Texture filtering (8x is the default) | x16 | +0.06 | +0.01 | lake |
| 12 | Sharpening | High | +0.05 | -0.01 | lake |
| 13 | Terrain water levels | On | +0.05 | -0.00 | lake |
| 14 | Colour grading | On | +0.04 | -0.00 | lake |

Most expensive on the CPU (render thread):

**Direct3D 12**

| # | feature | level | CPU ms | GPU ms | scene |
|---|---|---|---|---|---|
| 1 | Dynamic Lights | Ultra | +4.45 | +3.22 | battle |
| 2 | Dynamic Lights | High | +4.28 | +3.04 | battle |
| 3 | Dynamic Lights | Medium | +0.79 | +2.08 | battle |
| 4 | Large particle quality | Quarter | +0.62 | +0.02 | battle |
| 5 | Large particle quality | Half | +0.54 | -0.09 | battle |
| 6 | Water simulation | On | +0.29 | +0.09 | battle |
| 7 | Ray tracing (cumulative: each row adds to the one above) | soft | +0.19 | +26.68 | battle |
| 8 | Wide glow | Strong | +0.15 | +0.04 | lake |

**Direct3D 11**

| # | feature | level | CPU ms | GPU ms | scene |
|---|---|---|---|---|---|
| 1 | Water simulation | On | +0.07 | +0.00 | lake |
| 2 | Texture filtering (8x is the default) | tri | +0.06 | +0.03 | lake |
| 3 | Shadow filtering | Ultra | +0.05 | +0.07 | lake |
| 4 | Ambient occlusion | High | +0.03 | +0.40 | lake |
| 5 | Ambient occlusion | Standard | +0.03 | +0.12 | lake |
| 6 | Ambient occlusion | Low | +0.03 | +0.16 | lake |
| 7 | Soft particles | High | +0.02 | +0.02 | lake |
| 8 | Anti-aliasing | SMAA | +0.02 | +0.08 | lake |

### 5.2 Direct3D 12

#### 5.2.1 Lake: the structures of four factions and eight experimentals beside a lake, nothing moves (`static`)

Everything off: GPU 1.56 ms, CPU 1.31 ms per frame, frame wall p99 2.38 ms. Differences are to the off step before; GPU ms with the range of the three repeats where it is wider than 0.02 ms.

| feature | level | GPU ms | CPU ms | what changes most (pass: GPU / CPU ms) |
|---|---|---|---|---|
| Dynamic Lights | Low | +0.22 [-0.13, +0.22] | +0.07 | Frame +0.21 / +0.07, LightField +0.20 / +0.01 |
| Dynamic Lights | Medium | +0.21 [-0.13, +0.23] | +0.02 | Frame +0.21 / +0.02, LightField +0.20 / +0.01 |
| Dynamic Lights | High | +2.27 [+1.79, +2.29] | +0.69 | Frame +2.27 / +0.69, LightField +0.29 / +0.01 |
| Dynamic Lights | Ultra | +2.29 [+2.12, +2.29] | +0.82 | Frame +2.29 / +0.82, LightField +0.29 / +0.01 |
| Dynamic Lights, mode at Ultra | grid | +9.79 [+1.17, +9.86] | +0.88 | Frame +9.79 / +0.88, Terrain +5.46 / +0.04 |
| Dynamic Lights, mode at Ultra | field_noshadow | +2.15 [+2.14, +2.26] | +0.64 | Frame +2.15 / +0.64, Reflections +0.17 / +0.05 |
| Dynamic Lights, mode at Ultra | field | +2.31 | +0.74 | Frame +2.30 / +0.74, LightField +0.30 / +0.01 |
| Shadow filtering | Low | -0.05 [-0.23, -0.03] | -0.03 | Terrain +0.09 / +0.00, Reflections -0.08 / +0.00 |
| Shadow filtering | Medium | +0.06 [-0.30, +0.10] | -0.05 | Terrain +0.18 / -0.00, Reflections -0.07 / -0.00 |
| Shadow filtering | High | +0.03 [-0.31, +0.05] | +0.01 | Terrain +0.12 / +0.00, Reflections -0.07 / +0.00 |
| Shadow filtering | Ultra | +0.14 [-0.00, +0.16] | -0.04 | Terrain +0.19 / +0.00, Frame +0.13 / -0.04 |
| Shadow cascades (1, 2; the default is 3) | c1 | -0.06 | -0.07 | Frame -0.06 / -0.07, Shadows -0.04 / -0.04 |
| Shadow cascades (1, 2; the default is 3) | c2 | -0.02 | -0.00 | Frame -0.02 / -0.00, Reflections -0.01 / +0.00 |
| Ambient occlusion | Standard | +0.08 | +0.03 | AmbientOcclusion +0.10 / +0.01, Frame +0.09 / +0.03 |
| Ambient occlusion | Low | +0.13 | +0.05 | AmbientOcclusion +0.14 / +0.02, Frame +0.13 / +0.06 |
| Ambient occlusion | Medium | +0.15 | +0.03 | AmbientOcclusion +0.17 / +0.02, Frame +0.15 / +0.03 |
| Ambient occlusion | High | +0.39 | +0.04 | AmbientOcclusion +0.39 / +0.02, Frame +0.39 / +0.04 |
| Anti-aliasing | FXAA | +0.03 | -0.05 | Fxaa +0.04 / +0.01, Frame +0.03 / -0.05 |
| Anti-aliasing | SMAA | +0.05 | -0.01 | Smaa +0.06 / +0.01, Frame +0.05 / -0.01 |
| Sharpening | Low | +0.02 | +0.06 | Post +0.03 / +0.01, Frame +0.03 / +0.07 |
| Sharpening | Medium | +0.02 | +0.00 | Post +0.03 / +0.01, Frame +0.02 / +0.00 |
| Sharpening | High | +0.02 | +0.01 | Post +0.03 / +0.01, Frame +0.02 / +0.01 |
| Colour grading | On | +0.02 | +0.04 | Frame +0.02 / +0.04, Post +0.02 / +0.01 |
| FXAA/SMAA + sharpen + grade | fxaa+sharp+grade | +0.07 | +0.03 | Frame +0.07 / +0.03, Fxaa +0.04 / +0.01 |
| FXAA/SMAA + sharpen + grade | smaa+sharp+grade | +0.09 | +0.07 | Frame +0.09 / +0.07, Smaa +0.06 / +0.01 |
| Temporal AA | On | +0.08 | +0.08 | Frame +0.08 / +0.08, Taa +0.07 / +0.01 |
| Render resolution (the share of the view) | 85 | -0.03 | +0.03 | RenderScale +0.06 / +0.01, Terrain -0.06 / +0.00 |
| Render resolution (the share of the view) | 75 | -0.13 | +0.00 | Frame -0.12 / +0.00, Terrain -0.09 / -0.01 |
| Render resolution (the share of the view) | 50 | -0.27 | +0.04 | Frame -0.26 / +0.04, Terrain -0.15 / -0.01 |
| Soft particles | Low | +0.02 | +0.03 | EffParticles +0.03 / +0.01, Effects +0.02 / +0.01 |
| Soft particles | High | +0.01 | +0.00 | EffParticles +0.03 / +0.01, Effects +0.02 / +0.01 |
| Wide glow | Normal | +0.04 [+0.03, +0.05] | +0.06 | Frame +0.04 / +0.06, BloomWide +0.04 / +0.02 |
| Wide glow | Strong | +0.04 | +0.15 | Frame +0.04 / +0.15, BloomWide +0.04 / +0.02 |
| Sun shafts and height fog | On | +0.04 | -0.03 | Atmosphere +0.07 / +0.01, Frame +0.04 / -0.03 |
| Texture filtering (8x is the default) | tri | -0.05 | -0.04 | Frame -0.05 / -0.04, TerrainNormals -0.03 / -0.01 |
| Texture filtering (8x is the default) | x16 | +0.00 | -0.03 | Effects -0.01 / -0.01, EffParticles -0.01 / -0.01 |
| Water quality | 1 | -0.03 | +0.03 | Reflections -0.03 / +0.00, Frame -0.02 / +0.03 |
| Water quality | 2 | +0.00 | +0.05 | Frame +0.00 / +0.05 |
| Water quality | 3 | +0.05 | -0.01 | Reflections +0.07 / -0.00, Frame +0.05 / -0.01 |
| Water simulation | On | +0.03 | +0.04 | Frame +0.03 / +0.04, WaterSim +0.02 / +0.00 |
| Water: screen-space reflections | On | +0.01 [-0.01, +0.01] | -0.02 | Water +0.01 / +0.01, WaterDepth +0.01 / +0.01 |
| Water: caustics | 50 | +0.01 | -0.04 | Water +0.01 / +0.01, WaterDepth +0.01 / +0.01 |
| Water: caustics | 100 | +0.01 | +0.00 | Frame +0.01 / +0.00, Water +0.01 / +0.01 |
| Water: thickness | On | +0.01 [+0.00, +0.02] | -0.03 | Water +0.01 / +0.01, Meshes -0.01 / -0.01 |
| Water: sheen | On | -0.01 | -0.00 |  |
| Water: unit shadows | On | +0.01 | +0.07 | Frame +0.01 / +0.07, WaterDepth +0.01 / +0.01 |
| Water: banks | 1 | +0.00 | -0.05 | Effects -0.01 / -0.01, EffParticles -0.01 / -0.00 |
| Water: banks | 2 | +0.00 | -0.05 | Effects -0.01 / -0.01, EffParticles -0.01 / -0.00 |
| Terrain water levels | On | +0.00 [-0.01, +0.01] | +0.02 | Effects +0.01 / +0.01, EffParticles +0.01 / +0.01 |
| Shore tessellation | On | +0.00 | +0.02 |  |
| All the water features | defaults | -0.02 | -0.03 | Reflections -0.03 / -0.00, Frame -0.02 / -0.03 |
| All the water features | maxed | +0.06 | -0.01 | Reflections +0.07 / -0.01, Frame +0.06 / -0.01 |
| Ray tracing (cumulative: each row adds to the one above) | shadows | +2.51 [+2.50, +2.52] | +0.00 | Frame +2.50 / +0.00, Terrain +1.25 / +0.01 |
| Ray tracing (cumulative: each row adds to the one above) | ao | +2.50 [+2.49, +2.52] | -0.03 | Frame +2.50 / -0.03, Terrain +1.24 / +0.01 |
| Ray tracing (cumulative: each row adds to the one above) | bounce | +2.86 [+2.84, +2.87] | +0.02 | Frame +2.86 / +0.02, Terrain +1.25 / +0.01 |
| Ray tracing (cumulative: each row adds to the one above) | water | +2.89 [+2.85, +2.90] | +0.03 | Frame +2.88 / +0.03, Terrain +1.25 / +0.01 |
| Ray tracing (cumulative: each row adds to the one above) | soft | +10.31 [+10.00, +10.34] | +0.06 | Frame +10.31 / +0.06, Terrain +3.99 / +0.02 |
| Configurations | shipped defaults on | +0.16 [+0.07, +0.17] | +0.01 |  |
| Configurations | everything at Ultra | +3.18 [+3.15, +3.19] | +0.92 |  |
| Configurations | Ultra + ray tracing | +17.03 [+16.24, +17.81] | +1.00 |  |

#### 5.2.2 Battle: 80 against 80 firing units, standing (`battlestill`)

Everything off: GPU 8.14 ms, CPU 3.76 ms per frame, frame wall p99 9.00 ms. Differences are to the off step before; GPU ms with the range of the three repeats where it is wider than 0.02 ms.

| feature | level | GPU ms | CPU ms | what changes most (pass: GPU / CPU ms) |
|---|---|---|---|---|
| Dynamic Lights | Low | +0.30 [+0.17, +0.42] | -0.01 | Frame +0.30 / -0.01, LightField +0.20 / +0.01 |
| Dynamic Lights | Medium | +2.08 [+2.08, +2.23] | +0.79 | Frame +2.08 / +0.79, LightField +0.31 / +0.01 |
| Dynamic Lights | High | +3.04 [+3.01, +3.39] | +4.28 | Frame +3.04 / +4.28, LightField +0.95 / +0.01 |
| Dynamic Lights | Ultra | +3.22 [+3.19, +3.53] | +4.45 | Frame +3.22 / +4.45, LightField +1.11 / +0.01 |
| Dynamic Lights, mode at Ultra | grid | +225.19 [+223.46, +251.83] | +9.02 | Frame +225.19 / +9.02, Terrain +181.70 / +0.03 |
| Dynamic Lights, mode at Ultra | field_noshadow | +28.37 [+7.90, +40.09] | +5.04 | Frame +28.37 / +5.04, Terrain +20.73 / +0.01 |
| Dynamic Lights, mode at Ultra | field | +3.22 [+3.17, +3.31] | +4.35 | Frame +3.22 / +4.35, LightField +1.11 / +0.01 |
| Shadow filtering | Low | +0.03 [-0.00, +0.07] | -0.09 | Terrain +0.18 / +0.00, Reflections -0.07 / -0.00 |
| Shadow filtering | Medium | +0.13 [+0.08, +0.22] | +0.00 | Terrain +0.29 / +0.00, Frame +0.13 / +0.01 |
| Shadow filtering | High | +0.19 [+0.15, +0.27] | -0.28 | Terrain +0.34 / +0.00, Frame +0.19 / -0.28 |
| Shadow filtering | Ultra | +0.47 [+0.44, +0.52] | -0.31 | Terrain +0.50 / -0.00, Frame +0.47 / -0.31 |
| Shadow cascades (1, 2; the default is 3) | c1 | -0.09 [-0.24, +0.08] | -0.17 | Frame -0.09 / -0.17, Shadows -0.04 / -0.07 |
| Shadow cascades (1, 2; the default is 3) | c2 | -0.10 [-0.27, +0.19] | +0.00 | Frame -0.10 / +0.00, Effects -0.07 / -0.01 |
| Ambient occlusion | Standard | +0.10 [+0.08, +0.11] | +0.08 | AmbientOcclusion +0.10 / +0.01, Frame +0.10 / +0.08 |
| Ambient occlusion | Low | +0.11 [+0.11, +0.29] | +0.14 | AmbientOcclusion +0.15 / +0.02, Frame +0.12 / +0.14 |
| Ambient occlusion | Medium | +0.21 [+0.17, +0.27] | +0.14 | Frame +0.21 / +0.14, AmbientOcclusion +0.18 / +0.02 |
| Ambient occlusion | High | +0.41 [+0.35, +0.54] | +0.03 | AmbientOcclusion +0.42 / +0.02, Frame +0.41 / +0.03 |
| Anti-aliasing | FXAA | +0.17 [-0.00, +0.18] | +0.01 | Frame +0.17 / +0.01, Effects +0.12 / +0.04 |
| Anti-aliasing | SMAA | +0.00 [-0.06, +0.21] | +0.05 | EffParticles -0.06 / +0.02, Effects -0.06 / +0.03 |
| Sharpening | Low | +0.06 [+0.04, +0.13] | -0.04 | Frame +0.06 / -0.04, EffParticles +0.05 / -0.01 |
| Sharpening | Medium | +0.09 [+0.02, +0.13] | +0.10 | Frame +0.09 / +0.10, EffParticles +0.08 / +0.03 |
| Sharpening | High | +0.04 [-0.01, +0.12] | -0.15 | Frame +0.03 / -0.15, Post +0.03 / +0.01 |
| Colour grading | On | -0.02 [-0.07, +0.09] | +0.04 | Effects -0.04 / +0.01, EffParticles -0.03 / +0.02 |
| FXAA/SMAA + sharpen + grade | fxaa+sharp+grade | +0.06 [+0.05, +0.10] | +0.09 | Frame +0.06 / +0.09, Fxaa +0.04 / +0.01 |
| FXAA/SMAA + sharpen + grade | smaa+sharp+grade | +0.10 [+0.04, +0.15] | +0.07 | Frame +0.11 / +0.07, Smaa +0.06 / +0.01 |
| Temporal AA | On | +0.05 [+0.02, +0.08] | +0.05 | Taa +0.07 / +0.01, Frame +0.05 / +0.05 |
| Render resolution (the share of the view) | 85 | -0.32 [-0.45, -0.15] | +0.06 | Frame -0.32 / +0.06, EffParticles -0.21 / +0.02 |
| Render resolution (the share of the view) | 75 | -0.55 [-0.60, -0.45] | +0.04 | Frame -0.55 / +0.04, EffParticles -0.43 / +0.03 |
| Render resolution (the share of the view) | 50 | -1.07 [-1.15, -1.06] | -0.00 | Frame -1.07 / -0.01, Effects -0.69 / +0.03 |
| Soft particles | Low | -0.03 [-0.18, +0.03] | +0.05 | Frame -0.02 / +0.05, Effects -0.01 / +0.05 |
| Soft particles | High | +0.04 [-0.05, +0.05] | +0.11 | EffParticles +0.07 / +0.03, Effects +0.07 / +0.03 |
| Large particle quality | Half | -0.09 [-0.17, -0.09] | +0.54 | EffParticles -0.12 / +0.40, Effects -0.11 / +0.40 |
| Large particle quality | Quarter | +0.02 [-0.07, +0.07] | +0.62 | Effects +0.04 / +0.44, EffParticles +0.03 / +0.43 |
| Sun shafts and height fog | On | -0.02 [-0.03, +0.09] | -0.16 | Effects -0.08 / -0.04, EffParticles -0.07 / -0.03 |
| Texture filtering (8x is the default) | tri | -0.01 [-0.07, +0.09] | +0.01 | EffParticles +0.05 / +0.01, Effects +0.05 / +0.01 |
| Texture filtering (8x is the default) | x16 | -0.02 [-0.11, +0.17] | +0.06 | Effects -0.05 / +0.01, EffParticles -0.03 / +0.00 |
| Water simulation | On | +0.09 [-0.03, +0.19] | +0.29 | Frame +0.08 / +0.29, WaterSim +0.04 / +0.01 |
| Ray tracing (cumulative: each row adds to the one above) | shadows | +6.85 [+6.78, +7.03] | -0.18 | Frame +6.85 / -0.18, Terrain +4.77 / +0.00 |
| Ray tracing (cumulative: each row adds to the one above) | ao | +6.99 [+6.84, +7.18] | -0.03 | Frame +7.00 / -0.03, Terrain +4.84 / +0.00 |
| Ray tracing (cumulative: each row adds to the one above) | bounce | +7.25 [+7.06, +7.50] | -0.05 | Frame +7.24 / -0.05, Terrain +4.81 / +0.00 |
| Ray tracing (cumulative: each row adds to the one above) | water | +7.46 [+7.22, +7.57] | -0.03 | Frame +7.46 / -0.03, Terrain +4.75 / +0.00 |
| Ray tracing (cumulative: each row adds to the one above) | soft | +26.68 [+15.43, +27.56] | +0.19 | Frame +26.68 / +0.19, Terrain +16.24 / +0.00 |
| Configurations | shipped defaults on | +0.11 [-0.01, +0.21] | +0.46 |  |
| Configurations | everything at Ultra | +4.45 [+4.40, +4.62] | +5.26 |  |
| Configurations | Ultra + ray tracing | +38.62 [+33.38, +42.30] | +5.61 |  |

#### 5.2.3 Nuke: a strategic missile, game paused at the explosion

Everything off: GPU 0.96 ms, CPU 0.46 ms per frame, frame wall p99 1.32 ms. Differences are to the off step before; GPU ms with the range of the three repeats where it is wider than 0.02 ms.

| feature | level | GPU ms | CPU ms | what changes most (pass: GPU / CPU ms) |
|---|---|---|---|---|
| Dynamic Lights | Low | +0.27 [+0.27, +0.32] | +0.06 | Frame +0.27 / +0.06, LightField +0.22 / +0.01 |
| Dynamic Lights | Medium | +0.27 [+0.27, +0.32] | +0.06 | Frame +0.27 / +0.06, LightField +0.21 / +0.01 |
| Dynamic Lights | High | +0.27 [+0.27, +0.33] | +0.06 | Frame +0.27 / +0.06, LightField +0.22 / +0.01 |
| Dynamic Lights | Ultra | +0.27 [+0.27, +0.33] | +0.05 | Frame +0.27 / +0.05, LightField +0.22 / +0.01 |
| Dynamic Lights, mode at Ultra | grid | -0.04 | +0.03 | Frame -0.04 / +0.03, Terrain -0.03 / +0.00 |
| Dynamic Lights, mode at Ultra | field_noshadow | -0.04 | +0.03 | Frame -0.04 / +0.03, Terrain -0.03 / +0.00 |
| Dynamic Lights, mode at Ultra | field | +0.27 | +0.10 | Frame +0.27 / +0.10, LightField +0.22 / +0.01 |
| Shadow filtering | Low | +0.07 [+0.02, +0.07] | -0.01 | Terrain +0.12 / +0.00, Frame +0.07 / -0.01 |
| Shadow filtering | Medium | +0.19 [+0.14, +0.19] | +0.01 | Terrain +0.21 / +0.00, Frame +0.19 / +0.01 |
| Shadow filtering | High | +0.07 [+0.02, +0.07] | -0.03 | Terrain +0.08 / -0.00, Frame +0.06 / -0.03 |
| Shadow filtering | Ultra | +0.09 [+0.03, +0.09] | -0.04 | Terrain +0.11 / -0.00, Frame +0.09 / -0.04 |
| Shadow cascades (1, 2; the default is 3) | c1 | -0.04 | -0.00 | Frame -0.04 / -0.00, Shadows -0.02 / -0.01 |
| Shadow cascades (1, 2; the default is 3) | c2 | -0.01 | +0.01 | Frame -0.01 / +0.01, Terrain -0.01 / +0.00 |
| Ambient occlusion | Standard | +0.09 | +0.01 | Frame +0.09 / +0.01, AmbientOcclusion +0.09 / +0.01 |
| Ambient occlusion | Low | +0.14 [+0.12, +0.14] | +0.15 | Frame +0.13 / +0.15, AmbientOcclusion +0.13 / +0.03 |
| Ambient occlusion | Medium | +0.17 | +0.01 | Frame +0.17 / +0.01, AmbientOcclusion +0.16 / +0.02 |
| Ambient occlusion | High | +0.41 | +0.06 | Frame +0.40 / +0.06, AmbientOcclusion +0.39 / +0.02 |
| Anti-aliasing | FXAA | +0.04 | +0.01 | Frame +0.04 / +0.01, Fxaa +0.03 / +0.01 |
| Anti-aliasing | SMAA | +0.05 | -0.00 | Frame +0.04 / -0.00, Smaa +0.04 / +0.01 |
| Soft particles | Low | +0.02 | +0.02 | Effects +0.06 / +0.01, EffParticles +0.06 / +0.01 |
| Soft particles | High | +0.02 | +0.03 | Effects +0.06 / +0.01, EffParticles +0.06 / +0.01 |
| Large particle quality | Half | +0.00 | -0.01 |  |
| Large particle quality | Quarter | +0.00 | -0.01 |  |
| Wide glow | Normal | +0.04 | +0.00 | Frame +0.04 / +0.00, BloomWide +0.04 / +0.02 |
| Wide glow | Strong | +0.04 | -0.00 | Frame +0.04 / -0.00, BloomWide +0.04 / +0.02 |
| Configurations | shipped defaults on | +0.31 [+0.23, +0.31] | +0.07 |  |
| Configurations | everything at Ultra | +1.17 | +0.20 |  |
| Configurations | Ultra + ray tracing | +2.14 | +0.22 |  |

#### 5.2.4 River map (`faf_re_waterrivers`), camera at the falls

Everything off: GPU 1.25 ms, CPU 1.17 ms per frame, frame wall p99 1.83 ms. Differences are to the off step before; GPU ms with the range of the three repeats where it is wider than 0.02 ms.

| feature | level | GPU ms | CPU ms | what changes most (pass: GPU / CPU ms) |
|---|---|---|---|---|
| Sun shafts and height fog | On | +0.06 [+0.04, +0.07] | +0.02 | Atmosphere +0.07 / +0.01, Frame +0.06 / +0.02 |
| Water quality | 1 | -0.01 [-0.01, +0.01] | +0.01 | Frame -0.01 / +0.01 |
| Water quality | 2 | -0.01 [-0.01, +0.01] | -0.01 | Frame -0.01 / -0.01 |
| Water quality | 3 | +0.00 | +0.00 |  |
| Water simulation | On | +0.02 [+0.00, +0.02] | +0.23 | Frame +0.02 / +0.23, WaterSim +0.02 / +0.01 |
| Water: screen-space reflections | On | +0.04 | +0.01 | Water +0.04 / +0.01, Frame +0.04 / +0.01 |
| Water: caustics | 50 | +0.00 [-0.02, +0.01] | +0.01 | WaterDepth +0.01 / +0.01 |
| Water: caustics | 100 | +0.01 | +0.00 | WaterDepth +0.01 / +0.01, Frame +0.01 / +0.00 |
| Water: thickness | On | +0.01 [+0.00, +0.02] | +0.00 | Frame +0.01 / +0.00, WaterDepth +0.01 / +0.01 |
| Water: sheen | On | -0.01 [-0.02, +0.00] | -0.01 | Effects -0.01 / -0.01, EffParticles -0.01 / -0.00 |
| Water: unit shadows | On | +0.01 | -0.02 | Water +0.01 / +0.01, WaterDepth +0.01 / +0.01 |
| Water: banks | 1 | +0.01 [+0.00, +0.02] | -0.02 | Frame +0.01 / -0.02, Meshes +0.01 / -0.00 |
| Water: banks | 2 | +0.00 | +0.00 |  |
| Rivers | On | +0.01 [-0.01, +0.01] | +0.00 | Effects +0.01 / +0.00, EffParticles +0.01 / +0.00 |
| Terrain water levels | On | +0.04 [+0.03, +0.05] | +0.00 | Terrain +0.04 / +0.00, Frame +0.04 / +0.00 |
| Shore tessellation | On | +0.01 | +0.01 | Meshes +0.01 / +0.00 |
| Waterfalls | 1 | +0.00 [+0.00, +0.03] | +0.02 |  |
| Waterfalls | 2 | +0.02 [+0.02, +0.04] | +0.03 | Frame +0.02 / +0.03, Effects +0.01 / +0.02 |
| Waterfalls | 3 | +0.04 [+0.03, +0.05] | +0.03 | Frame +0.04 / +0.03, Effects +0.02 / +0.03 |
| All the water features | defaults | +0.08 [+0.08, +0.10] | +0.01 | Frame +0.08 / +0.01, Terrain +0.04 / +0.00 |
| All the water features | maxed | +0.11 | +0.03 | Frame +0.11 / +0.03, Terrain +0.04 / +0.00 |
| Configurations | shipped defaults on | +0.29 | +0.11 |  |
| Configurations | everything at Ultra | +2.50 | +0.32 |  |
| Configurations | Ultra + ray tracing | +5.79 [+5.77, +5.79] | +0.19 |  |

#### 5.2.5 Strategic view of the battle (zoom 420)

Everything off: GPU 3.41 ms, CPU 2.20 ms per frame, frame wall p99 4.08 ms. Differences are to the off step before; GPU ms with the range of the three repeats where it is wider than 0.02 ms.

| feature | level | GPU ms | CPU ms | what changes most (pass: GPU / CPU ms) |
|---|---|---|---|---|
| Dynamic Lights | Low | +0.85 [+0.81, +0.96] | -0.08 | LightField +0.99 / +0.01, Frame +0.84 / -0.08 |
| Dynamic Lights | Medium | +1.40 [+1.33, +1.70] | +0.11 | Frame +1.39 / +0.11, LightField +1.00 / +0.01 |
| Dynamic Lights | High | +2.68 [+2.64, +2.75] | +1.08 | Frame +2.68 / +1.08, LightField +1.03 / +0.01 |
| Dynamic Lights | Ultra | +2.70 [+2.68, +2.88] | +1.34 | Frame +2.70 / +1.34, LightField +1.08 / +0.01 |
| Shadow filtering | Low | -0.03 [-0.05, -0.02] | +0.01 | Frame -0.03 / +0.01, Reflections -0.01 / +0.00 |
| Shadow filtering | Medium | -0.04 [-0.08, -0.02] | +0.04 | Frame -0.05 / +0.04, Effects -0.03 / -0.02 |
| Shadow filtering | High | -0.02 [-0.02, +0.07] | +0.03 | Frame -0.02 / +0.03, Reflections -0.01 / -0.00 |
| Shadow filtering | Ultra | +0.02 [+0.00, +0.04] | +0.02 | EffParticles +0.03 / +0.00, Effects +0.02 / +0.00 |
| Ambient occlusion | Standard | +0.05 [+0.00, +0.05] | +0.01 | Frame +0.05 / +0.01, AmbientOcclusion +0.04 / +0.01 |
| Ambient occlusion | Low | +0.09 [+0.08, +0.14] | +0.01 | AmbientOcclusion +0.11 / +0.02, Frame +0.09 / +0.01 |
| Ambient occlusion | Medium | +0.10 | -0.02 | AmbientOcclusion +0.14 / +0.02, Frame +0.10 / -0.01 |
| Ambient occlusion | High | +0.28 [+0.21, +0.29] | -0.06 | AmbientOcclusion +0.38 / +0.02, Frame +0.28 / -0.06 |
| Anti-aliasing | FXAA | +0.09 [+0.06, +0.12] | +0.02 | Frame +0.09 / +0.02, EffParticles +0.07 / +0.01 |
| Anti-aliasing | SMAA | +0.10 [+0.08, +0.13] | +0.08 | Frame +0.10 / +0.08, Smaa +0.05 / +0.01 |
| FXAA/SMAA + sharpen + grade | fxaa+sharp+grade | +0.04 [+0.03, +0.09] | +0.03 | Frame +0.04 / +0.03, Post +0.03 / +0.01 |
| FXAA/SMAA + sharpen + grade | smaa+sharp+grade | +0.09 [+0.04, +0.13] | -0.01 | Frame +0.09 / -0.01, Smaa +0.05 / +0.01 |
| Configurations | shipped defaults on | +0.06 [+0.04, +0.16] | +0.10 |  |
| Configurations | everything at Ultra | +3.40 [+3.38, +3.42] | +1.54 |  |
| Configurations | Ultra + ray tracing | +3.48 [+3.44, +3.51] | +1.77 |  |

### 5.3 Vulkan

#### 5.3.1 Lake

Everything off: GPU 1.43 ms, CPU 1.32 ms per frame, frame wall p99 2.91 ms. Differences are to the off step before; GPU ms with the range of the three repeats where it is wider than 0.02 ms.

| feature | level | GPU ms | CPU ms | what changes most (pass: GPU / CPU ms) |
|---|---|---|---|---|
| Dynamic Lights | Low | +0.22 [+0.01, +0.23] | +0.37 | Frame +0.22 / +0.37, LightField +0.20 / +0.01 |
| Dynamic Lights | Medium | +0.21 [+0.10, +0.21] | +0.11 | Frame +0.20 / +0.11, LightField +0.20 / +0.01 |
| Dynamic Lights | High | +2.18 [+2.17, +2.31] | +0.96 | Frame +2.18 / +0.96, LightField +0.30 / +0.01 |
| Dynamic Lights | Ultra | +2.18 [+2.17, +2.19] | +0.85 | Frame +2.18 / +0.85, LightField +0.25 / +0.01 |
| Dynamic Lights, mode at Ultra | grid | +8.08 [+8.04, +8.41] | +0.90 | Frame +8.07 / +0.90, Terrain +4.21 / +0.03 |
| Dynamic Lights, mode at Ultra | field_noshadow | +3.39 [+2.13, +3.68] | +0.70 | Frame +3.39 / +0.70, Terrain +0.89 / +0.03 |
| Dynamic Lights, mode at Ultra | field | +2.17 [+2.15, +2.18] | +0.82 | Frame +2.17 / +0.82, LightField +0.25 / +0.01 |
| Shadow filtering | Low | -0.01 [-0.04, +13.34] | +0.03 | Terrain +0.09 / +0.01, Shadows -0.06 / -0.02 |
| Shadow filtering | Medium | +0.03 [-0.25, +0.04] | -0.02 | Terrain +0.12 / +0.01, Reflections -0.05 / +0.01 |
| Shadow filtering | High | +0.03 [-0.04, +0.04] | -0.02 | Terrain +0.11 / +0.00, Reflections -0.05 / +0.00 |
| Shadow filtering | Ultra | +0.11 [+0.04, +0.12] | -0.06 | Terrain +0.14 / -0.00, Frame +0.11 / -0.06 |
| Shadow cascades (1, 2; the default is 3) | c1 | -0.05 [-0.06, -0.04] | -0.06 | Frame -0.05 / -0.06, Shadows -0.03 / -0.04 |
| Shadow cascades (1, 2; the default is 3) | c2 | +0.00 | +0.03 |  |
| Ambient occlusion | Standard | +0.09 [+0.08, +0.11] | +0.04 | AmbientOcclusion +0.10 / +0.01, Frame +0.09 / +0.04 |
| Ambient occlusion | Low | +0.14 [+0.11, +0.14] | -0.01 | AmbientOcclusion +0.14 / +0.02, Frame +0.13 / -0.01 |
| Ambient occlusion | Medium | +0.16 | +0.03 | AmbientOcclusion +0.18 / +0.02, Frame +0.16 / +0.03 |
| Ambient occlusion | High | +0.35 | +0.03 | AmbientOcclusion +0.39 / +0.02, Frame +0.34 / +0.03 |
| Anti-aliasing | FXAA | +0.03 | -0.00 | Fxaa +0.04 / +0.01, Frame +0.03 / -0.00 |
| Anti-aliasing | SMAA | +0.05 | +0.05 | Frame +0.05 / +0.05, Smaa +0.05 / +0.01 |
| Sharpening | Low | +0.03 | +0.03 | Frame +0.04 / +0.03, Post +0.03 / +0.01 |
| Sharpening | Medium | +0.03 | -0.00 | Frame +0.03 / -0.00, Post +0.03 / +0.01 |
| Sharpening | High | +0.03 | +0.01 | Post +0.03 / +0.01, Frame +0.03 / +0.01 |
| Colour grading | On | +0.01 | -0.02 | Post +0.02 / +0.01, Frame +0.01 / -0.02 |
| FXAA/SMAA + sharpen + grade | fxaa+sharp+grade | +0.07 | +0.01 | Frame +0.06 / +0.01, Fxaa +0.04 / +0.01 |
| FXAA/SMAA + sharpen + grade | smaa+sharp+grade | +0.07 | -0.00 | Frame +0.07 / -0.00, Smaa +0.05 / +0.01 |
| Temporal AA | On | +0.08 [+0.06, +0.09] | +0.05 | Frame +0.09 / +0.05, Taa +0.07 / +0.01 |
| Render resolution (the share of the view) | 85 | -0.02 [-0.03, -0.01] | +0.03 | RenderScale +0.06 / +0.01, Terrain -0.04 / +0.00 |
| Render resolution (the share of the view) | 75 | -0.07 | +0.03 | Frame -0.07 / +0.03, RenderScale +0.06 / +0.01 |
| Render resolution (the share of the view) | 50 | -0.19 | +0.01 | Frame -0.19 / +0.01, Terrain -0.10 / +0.01 |
| Soft particles | Low | +0.03 | +0.01 | Frame +0.03 / +0.01, EffParticles +0.03 / +0.02 |
| Soft particles | High | +0.04 | +0.07 | Frame +0.04 / +0.07, EffParticles +0.03 / +0.02 |
| Wide glow | Normal | +0.03 | +0.02 | BloomWide +0.04 / +0.02, Frame +0.03 / +0.02 |
| Wide glow | Strong | +0.04 | -0.01 | BloomWide +0.04 / +0.02, Frame +0.04 / -0.01 |
| Sun shafts and height fog | On | +0.06 | +0.03 | Atmosphere +0.08 / +0.01, Frame +0.06 / +0.03 |
| Texture filtering (8x is the default) | tri | -0.05 | +0.01 | Frame -0.05 / +0.01, TerrainNormals -0.03 / +0.00 |
| Texture filtering (8x is the default) | x16 | +0.00 | -0.03 |  |
| Water quality | 1 | +0.00 | -0.02 | Reflections -0.01 / -0.00 |
| Water quality | 2 | +0.01 [-0.02, +0.01] | +0.01 | Frame +0.01 / +0.01 |
| Water quality | 3 | +0.04 [+0.03, +0.07] | +0.01 | Reflections +0.04 / +0.00, Frame +0.04 / +0.01 |
| Water simulation | On | +0.05 | +0.09 | Frame +0.05 / +0.09, WaterSim +0.03 / +0.01 |
| Water: screen-space reflections | On | +0.01 | +0.00 | Frame +0.01 / +0.00, WaterDepth +0.01 / +0.01 |
| Water: caustics | 50 | +0.01 [+0.00, +0.03] | -0.01 | Frame +0.01 / -0.01, Water +0.01 / +0.01 |
| Water: caustics | 100 | +0.01 [+0.01, +0.03] | -0.01 | Frame +0.01 / -0.01, Water +0.01 / +0.01 |
| Water: thickness | On | +0.02 | +0.05 | Frame +0.02 / +0.05, Water +0.01 / +0.01 |
| Water: sheen | On | +0.00 [-0.01, +0.02] | -0.01 |  |
| Water: unit shadows | On | +0.00 | -0.00 | Water +0.01 / +0.01, WaterDepth +0.01 / +0.01 |
| Water: banks | 1 | -0.01 | -0.05 | Frame -0.01 / -0.05 |
| Water: banks | 2 | -0.01 | -0.04 | Frame -0.01 / -0.04 |
| Terrain water levels | On | +0.00 | -0.01 |  |
| Shore tessellation | On | -0.01 [-0.01, +0.01] | -0.01 |  |
| All the water features | defaults | +0.02 | +0.06 | Frame +0.02 / +0.06, Water +0.01 / +0.01 |
| All the water features | maxed | +0.05 | +0.05 | Frame +0.05 / +0.05, Reflections +0.04 / +0.00 |
| Ray tracing (cumulative: each row adds to the one above) | shadows | +2.54 [+2.52, +2.54] | -0.07 | Frame +2.54 / -0.07, Terrain +1.16 / +0.01 |
| Ray tracing (cumulative: each row adds to the one above) | ao | +2.52 [+2.51, +2.53] | -0.01 | Frame +2.53 / -0.01, Terrain +1.16 / +0.01 |
| Ray tracing (cumulative: each row adds to the one above) | bounce | +2.91 [+2.89, +2.92] | -0.00 | Frame +2.91 / -0.00, Terrain +1.18 / +0.01 |
| Ray tracing (cumulative: each row adds to the one above) | water | +2.93 [+2.90, +2.94] | -0.02 | Frame +2.94 / -0.02, Terrain +1.19 / +0.01 |
| Ray tracing (cumulative: each row adds to the one above) | soft | +11.49 [+9.38, +12.37] | +0.08 | Frame +11.49 / +0.08, Terrain +4.06 / +0.02 |
| Configurations | shipped defaults on | +0.19 [+0.11, +0.20] | +0.11 |  |
| Configurations | everything at Ultra | +3.15 [+1.56, +3.15] | +0.91 |  |
| Configurations | Ultra + ray tracing | +8.98 [+3.19, +20.27] | +0.96 |  |

#### 5.3.2 Battle

Everything off: GPU 7.82 ms, CPU 3.73 ms per frame, frame wall p99 9.20 ms. Differences are to the off step before; GPU ms with the range of the three repeats where it is wider than 0.02 ms.

| feature | level | GPU ms | CPU ms | what changes most (pass: GPU / CPU ms) |
|---|---|---|---|---|
| Dynamic Lights | Low | +0.28 [+0.21, +0.42] | +0.13 | Frame +0.28 / +0.13, LightField +0.20 / +0.01 |
| Dynamic Lights | Medium | +1.98 [+1.97, +2.12] | +0.91 | Frame +1.99 / +0.91, LightField +0.31 / +0.01 |
| Dynamic Lights | High | +2.84 [+2.80, +2.87] | +3.96 | Frame +2.85 / +3.96, LightField +0.73 / +0.01 |
| Dynamic Lights | Ultra | +2.93 [+2.79, +3.00] | +4.25 | Frame +2.94 / +4.25, LightField +0.78 / +0.01 |
| Dynamic Lights, mode at Ultra | grid | +191.56 [+187.04, +208.38] | +7.97 | Frame +191.55 / +7.97, Terrain +149.53 / +0.03 |
| Dynamic Lights, mode at Ultra | field_noshadow | +2.68 [+2.65, +28.83] | +3.79 | Frame +2.69 / +3.79, LightField +0.55 / +0.01 |
| Dynamic Lights, mode at Ultra | field | +2.88 [+2.80, +2.90] | +4.38 | Frame +2.88 / +4.38, LightField +0.77 / +0.01 |
| Shadow filtering | Low | +0.02 [-0.04, +0.05] | +0.10 | Terrain +0.16 / +0.00, Reflections -0.08 / +0.01 |
| Shadow filtering | Medium | +0.12 [+0.03, +0.24] | +0.09 | Terrain +0.23 / +0.00, Frame +0.12 / +0.09 |
| Shadow filtering | High | +0.18 [+0.12, +0.19] | +0.03 | Terrain +0.28 / +0.00, Frame +0.18 / +0.03 |
| Shadow filtering | Ultra | +0.39 [+0.38, +0.44] | -0.01 | Terrain +0.40 / +0.00, Frame +0.39 / -0.01 |
| Shadow cascades (1, 2; the default is 3) | c1 | -0.04 [-0.06, -0.01] | -0.12 | EffParticles +0.06 / -0.00, Effects +0.06 / -0.00 |
| Shadow cascades (1, 2; the default is 3) | c2 | +0.04 | +0.12 | EffParticles +0.07 / +0.03, Effects +0.06 / +0.03 |
| Ambient occlusion | Standard | +0.09 [-0.09, +0.16] | +0.02 | AmbientOcclusion +0.10 / +0.01, Frame +0.08 / +0.02 |
| Ambient occlusion | Low | +0.06 [+0.03, +0.12] | -0.07 | AmbientOcclusion +0.15 / +0.02, Effects -0.08 / -0.02 |
| Ambient occlusion | Medium | +0.04 [-0.01, +0.15] | -0.04 | AmbientOcclusion +0.18 / +0.02, EffParticles -0.14 / -0.03 |
| Ambient occlusion | High | +0.44 [+0.31, +0.48] | +0.06 | Frame +0.43 / +0.06, AmbientOcclusion +0.43 / +0.02 |
| Anti-aliasing | FXAA | +0.01 [-0.04, +0.02] | -0.06 | Effects -0.06 / -0.03, Fxaa +0.04 / +0.01 |
| Anti-aliasing | SMAA | +0.01 [-0.01, +0.02] | -0.08 | Effects -0.06 / -0.03, Smaa +0.05 / +0.01 |
| Sharpening | Low | +0.09 [+0.07, +0.16] | +0.11 | Frame +0.09 / +0.11, Effects +0.07 / +0.02 |
| Sharpening | Medium | +0.02 [-0.07, +0.07] | +0.14 | Effects -0.03 / +0.04, Post +0.03 / +0.01 |
| Sharpening | High | +0.01 [-0.07, +0.10] | +0.16 | Effects -0.04 / +0.02, EffParticles -0.03 / +0.02 |
| Colour grading | On | -0.03 [-0.04, +0.03] | +0.13 | EffParticles -0.04 / +0.00, Frame -0.03 / +0.13 |
| FXAA/SMAA + sharpen + grade | fxaa+sharp+grade | +0.17 [+0.01, +0.17] | +0.15 | Frame +0.17 / +0.15, Effects +0.08 / +0.05 |
| FXAA/SMAA + sharpen + grade | smaa+sharp+grade | +0.05 [+0.05, +0.14] | +0.11 | Frame +0.06 / +0.11, Smaa +0.05 / +0.01 |
| Temporal AA | On | +0.06 [+0.05, +0.12] | +0.03 | Taa +0.07 / +0.01, Frame +0.06 / +0.03 |
| Render resolution (the share of the view) | 85 | -0.30 [-0.37, -0.27] | -0.01 | Frame -0.30 / -0.01, EffParticles -0.26 / -0.00 |
| Render resolution (the share of the view) | 75 | -0.62 [-0.65, -0.53] | -0.14 | Frame -0.62 / -0.14, EffParticles -0.48 / -0.02 |
| Render resolution (the share of the view) | 50 | -1.05 [-1.10, -1.03] | +0.09 | Frame -1.05 / +0.09, EffParticles -0.77 / +0.01 |
| Soft particles | Low | +0.03 [-0.04, +0.08] | -0.04 | EffParticles +0.05 / -0.01, Effects +0.05 / -0.01 |
| Soft particles | High | +0.01 [-0.04, +0.08] | +0.02 | Effects +0.03 / -0.01, EffParticles +0.02 / -0.00 |
| Large particle quality | Half | +0.00 [+0.00, +0.09] | +0.35 | Effects +0.03 / +0.38, EffParticles +0.02 / +0.38 |
| Large particle quality | Quarter | +0.05 [+0.04, +0.16] | +0.41 | Effects +0.08 / +0.40, EffParticles +0.05 / +0.40 |
| Sun shafts and height fog | On | +0.10 [+0.04, +0.23] | -0.04 | Frame +0.10 / -0.04, Atmosphere +0.08 / +0.01 |
| Texture filtering (8x is the default) | tri | -0.08 [-0.11, +0.03] | +0.01 | Frame -0.07 / +0.01, TerrainNormals -0.03 / -0.01 |
| Texture filtering (8x is the default) | x16 | +0.00 [-0.05, +0.05] | -0.03 | Effects -0.04 / +0.01, EffParticles -0.01 / +0.01 |
| Water simulation | On | +0.01 [-0.02, +0.15] | +0.00 | EffParticles -0.06 / -0.03, Effects -0.05 / -0.04 |
| Ray tracing (cumulative: each row adds to the one above) | shadows | +6.56 [+6.46, +6.59] | -0.07 | Frame +6.56 / -0.07, Terrain +3.88 / +0.00 |
| Ray tracing (cumulative: each row adds to the one above) | ao | +6.45 [+6.45, +6.77] | -0.08 | Frame +6.46 / -0.08, Terrain +3.85 / +0.00 |
| Ray tracing (cumulative: each row adds to the one above) | bounce | +6.84 [+6.64, +7.12] | -0.04 | Frame +6.84 / -0.04, Terrain +3.88 / +0.00 |
| Ray tracing (cumulative: each row adds to the one above) | water | +7.05 [+6.82, +7.14] | +0.11 | Frame +7.05 / +0.11, Terrain +3.94 / +0.00 |
| Ray tracing (cumulative: each row adds to the one above) | soft | +22.10 [+17.96, +28.32] | +0.56 | Frame +22.10 / +0.56, Terrain +11.80 / +0.01 |
| Configurations | shipped defaults on | +0.25 [+0.00, +0.27] | +0.40 |  |
| Configurations | everything at Ultra | +4.07 [+4.04, +4.14] | +5.67 |  |
| Configurations | Ultra + ray tracing | +44.41 [+44.32, +45.35] | +6.07 |  |

#### 5.3.3 River map

Everything off: GPU 1.26 ms, CPU 1.31 ms per frame, frame wall p99 2.88 ms. Differences are to the off step before; GPU ms with the range of the three repeats where it is wider than 0.02 ms.

| feature | level | GPU ms | CPU ms | what changes most (pass: GPU / CPU ms) |
|---|---|---|---|---|
| Sun shafts and height fog | On | +0.04 | -0.00 | Atmosphere +0.08 / +0.01, Frame +0.05 / -0.00 |
| Water quality | 1 | +0.00 | +0.01 | Frame +0.01 / +0.01, Terrain +0.01 / +0.00 |
| Water quality | 2 | +0.01 [-0.01, +0.02] | +0.03 | Frame +0.00 / +0.03 |
| Water quality | 3 | +0.00 [-0.01, +0.01] | +0.01 | Frame +0.01 / +0.01 |
| Water simulation | On | +0.03 [+0.03, +0.05] | +0.25 | Frame +0.03 / +0.25, WaterSim +0.02 / +0.01 |
| Water: screen-space reflections | On | +0.04 | -0.00 | Water +0.05 / +0.01, Frame +0.04 / -0.00 |
| Water: caustics | 50 | +0.02 | +0.05 | Frame +0.02 / +0.05, Water +0.01 / +0.01 |
| Water: caustics | 100 | +0.02 [-0.01, +0.02] | +0.04 | Frame +0.02 / +0.04, Water +0.01 / +0.01 |
| Water: thickness | On | +0.02 [+0.00, +0.03] | +0.02 | Water +0.01 / +0.01, WaterDepth +0.01 / +0.01 |
| Water: sheen | On | +0.00 | +0.02 | Meshes -0.01 / +0.00, Frame +0.00 / +0.02 |
| Water: unit shadows | On | +0.00 | -0.02 | Water +0.02 / +0.01, WaterDepth +0.01 / +0.01 |
| Water: banks | 1 | +0.01 | +0.00 |  |
| Water: banks | 2 | -0.01 | -0.19 | Frame -0.01 / -0.19, Terrain -0.01 / -0.07 |
| Rivers | On | -0.01 | -0.05 | Frame -0.01 / -0.05, Terrain -0.01 / -0.02 |
| Terrain water levels | On | +0.05 | -0.01 | Frame +0.05 / -0.01, Terrain +0.05 / -0.01 |
| Shore tessellation | On | +0.01 [-0.01, +0.01] | -0.05 | Frame +0.01 / -0.05, Meshes -0.01 / -0.00 |
| Waterfalls | 1 | +0.01 | +0.05 | Frame +0.01 / +0.05 |
| Waterfalls | 2 | +0.02 [+0.01, +0.04] | +0.02 | Frame +0.03 / +0.02, Effects +0.01 / +0.02 |
| Waterfalls | 3 | +0.03 | +0.02 | Frame +0.03 / +0.02, Effects +0.02 / +0.03 |
| All the water features | defaults | +0.09 [+0.08, +0.10] | +0.06 | Frame +0.10 / +0.06, Terrain +0.04 / +0.00 |
| All the water features | maxed | +0.10 | +0.06 | Frame +0.10 / +0.06, Water +0.04 / +0.01 |
| Configurations | shipped defaults on | +0.28 | +0.03 |  |
| Configurations | everything at Ultra | +1.77 [+1.00, +1.77] | +0.37 |  |
| Configurations | Ultra + ray tracing | +5.29 | +0.35 |  |

### 5.4 Direct3D 11

#### 5.4.1 Lake (Direct3D 11 has no dynamic lights table beyond the lake: the lights and shadow filtering run on the effects patched at load)

Everything off: GPU 1.07 ms, CPU 1.31 ms per frame, frame wall p99 2.17 ms. Differences are to the off step before; GPU ms with the range of the three repeats where it is wider than 0.02 ms.

| feature | level | GPU ms | CPU ms | what changes most (pass: GPU / CPU ms) |
|---|---|---|---|---|
| Shadow filtering | Low | -0.00 [-0.03, +0.11] | +0.00 | Terrain +0.10 / -0.00, Reflections -0.10 / +0.01 |
| Shadow filtering | Medium | +0.00 [-0.03, +0.14] | -0.00 | Reflections -0.17 / +0.01, Terrain +0.15 / -0.00 |
| Shadow filtering | High | +0.00 [-0.03, +0.18] | -0.01 | Reflections -0.19 / +0.01, Terrain +0.15 / -0.00 |
| Shadow filtering | Ultra | +0.07 [+0.05, +0.12] | +0.05 | Terrain +0.20 / +0.00, Reflections -0.16 / +0.02 |
| Ambient occlusion | Standard | +0.12 [+0.10, +0.15] | +0.03 | Frame +0.12 / +0.03, AmbientOcclusion +0.08 / +0.01 |
| Ambient occlusion | Low | +0.16 [+0.13, +0.20] | +0.03 | Frame +0.15 / +0.03, AmbientOcclusion +0.08 / +0.01 |
| Ambient occlusion | Medium | +0.16 [+0.14, +0.17] | +0.01 | Frame +0.16 / +0.01, AmbientOcclusion +0.11 / +0.01 |
| Ambient occlusion | High | +0.40 [+0.37, +0.48] | +0.03 | Frame +0.39 / +0.03, AmbientOcclusion +0.33 / +0.01 |
| Anti-aliasing | FXAA | +0.03 [-0.06, +0.03] | -0.00 | Fxaa +0.04 / +0.00, Frame +0.03 / -0.00 |
| Anti-aliasing | SMAA | +0.08 [-0.05, +0.10] | +0.02 | Frame +0.08 / +0.02, Smaa +0.05 / +0.01 |
| Sharpening | Low | +0.08 [+0.05, +0.13] | +0.02 | Frame +0.08 / +0.02, Reflections +0.05 / +0.00 |
| Sharpening | Medium | +0.08 [+0.07, +0.14] | +0.00 | Frame +0.09 / +0.00, Reflections +0.06 / -0.00 |
| Sharpening | High | +0.05 [+0.04, +0.09] | -0.01 | Frame +0.05 / -0.01, Post +0.03 / +0.00 |
| Colour grading | On | +0.04 [-0.02, +0.11] | -0.00 | Frame +0.05 / -0.00, Reflections +0.03 / -0.00 |
| FXAA/SMAA + sharpen + grade | fxaa+sharp+grade | +0.08 [+0.08, +0.15] | +0.01 | Frame +0.09 / +0.01, Fxaa +0.04 / +0.01 |
| FXAA/SMAA + sharpen + grade | smaa+sharp+grade | +0.14 [+0.14, +0.19] | +0.02 | Frame +0.15 / +0.02, Reflections +0.05 / +0.00 |
| Render resolution (the share of the view) | 85 | +0.09 [+0.01, +0.13] | +0.00 | Reflections +0.11 / -0.00, Frame +0.09 / +0.00 |
| Render resolution (the share of the view) | 75 | +0.08 [+0.00, +0.11] | +0.01 | Reflections +0.14 / -0.00, Frame +0.08 / +0.01 |
| Render resolution (the share of the view) | 50 | -0.00 [-0.10, +0.02] | -0.00 | Reflections +0.18 / -0.00, TerrainNormals -0.08 / -0.00 |
| Soft particles | Low | +0.01 [-0.00, +0.09] | +0.01 | EffParticles +0.01 / +0.01, Effects +0.01 / +0.01 |
| Soft particles | High | +0.02 [-0.04, +0.05] | +0.02 | Frame +0.01 / +0.02, Effects +0.01 / +0.01 |
| Texture filtering (8x is the default) | tri | +0.03 [-0.01, +0.07] | +0.06 | Reflections +0.09 / +0.01, Frame +0.04 / +0.06 |
| Texture filtering (8x is the default) | x16 | +0.06 [-0.09, +0.11] | +0.01 | Frame +0.06 / +0.01, Reflections +0.06 / +0.00 |
| Water quality | 1 | -0.02 [-0.05, -0.01] | -0.01 | Reflections -0.02 / -0.00, Frame -0.02 / -0.01 |
| Water quality | 2 | +0.02 [-0.04, +0.05] | +0.00 | Reflections +0.03 / +0.00, Frame +0.02 / +0.00 |
| Water quality | 3 | +0.04 [+0.00, +0.10] | -0.00 | Frame +0.04 / -0.00, Reflections +0.04 / -0.00 |
| Water simulation | On | +0.00 [-0.07, +0.09] | +0.07 | Reflections -0.03 / +0.00, WaterSim +0.02 / +0.01 |
| Water: screen-space reflections | On | -0.03 [-0.07, +0.14] | -0.01 | Reflections -0.04 / -0.00, Frame -0.03 / -0.01 |
| Water: caustics | 50 | +0.03 [+0.02, +0.05] | +0.00 | Frame +0.03 / +0.00, Reflections +0.02 / +0.00 |
| Water: caustics | 100 | +0.04 [+0.01, +0.08] | +0.01 | Frame +0.04 / +0.01, Reflections +0.04 / +0.00 |
| Water: thickness | On | -0.01 [-0.03, +0.10] | -0.00 | Reflections -0.02 / -0.00, Frame -0.02 / -0.00 |
| Water: sheen | On | +0.03 [-0.01, +0.05] | +0.02 | Frame +0.04 / +0.02, Reflections +0.04 / +0.00 |
| Water: unit shadows | On | +0.03 [-0.09, +0.08] | +0.00 | Frame +0.04 / +0.01, Reflections +0.02 / +0.00 |
| Water: banks | 1 | -0.01 [-0.01, +0.02] | -0.01 |  |
| Water: banks | 2 | +0.01 [-0.08, +0.06] | -0.00 | Frame +0.01 / -0.01, Reflections +0.01 / -0.00 |
| Terrain water levels | On | +0.05 [-0.02, +0.07] | -0.00 | Reflections +0.05 / +0.00, Frame +0.05 / -0.00 |
| All the water features | defaults | -0.03 [-0.05, -0.00] | +0.01 | Reflections -0.05 / +0.00, Frame -0.04 / +0.01 |
| All the water features | maxed | +0.05 [-0.01, +0.16] | +0.00 | Frame +0.06 / +0.00, Reflections +0.04 / -0.00 |
| Configurations | shipped defaults on | +0.33 [+0.31, +0.36] | +0.07 |  |
| Configurations | everything at Ultra | +0.56 [+0.52, +0.65] | +0.06 |  |

## 6. Loading, switching and hitches

### 6.1 Shader caches and the first frame

Start of the game (markers of the log, seconds after the process start; "cold" is an empty shader cache, "warm" the cache of the
cold run; effect compile ms is the sum of the `compiled effect` log lines, Direct3D 11 only):

| API | build | cache | renderer ready s | shaders compiled s | sim started s | first frame s | map loaded, scene ready s | effect compile ms (sum of the log lines) | shaders compiled in the background |
|---|---|---|---|---|---|---|---|---|---|
| d3d12 | baseline | cold | 0.85 | 0.98 | 2.04 | 1.29 | 16.4 | - | 342 |
| d3d12 | baseline | warm | 0.83 | 0.95 | 1.89 | 1.26 | 14.6 | - | - |
| d3d12 | ours | cold | 0.80 | 0.99 | 2.17 | 1.30 | 17.6 | - | 352 |
| d3d12 | ours | warm | 0.78 | 0.91 | 1.85 | 1.22 | 14.6 | - | - |
| vulkan | baseline | cold | 0.91 | 1.04 | 2.10 | 1.47 | 16.6 | - | 342 |
| vulkan | baseline | warm | 0.92 | 0.98 | 1.85 | 1.41 | 14.6 | - | - |
| vulkan | ours | cold | 0.91 | 1.04 | 2.12 | 1.48 | 20.1 | - | 352 |
| vulkan | ours | warm | 0.92 | 1.04 | 1.85 | 1.42 | 14.6 | - | - |
| d3d11 | baseline | cold | 0.92 | 12.48 | 13.36 | 12.86 | 26.4 | 11454 | - |
| d3d11 | baseline | warm | 0.79 | 0.92 | 1.92 | 1.29 | 14.8 | - | - |
| d3d11 | ours | cold | 0.74 | 18.73 | 19.67 | 19.11 | 33.4 | 17890 | - |
| d3d11 | ours | warm | 0.78 | 0.97 | 1.85 | 1.35 | 15.8 | - | - |

* **Warm caches**: Direct3D 12 and Vulkan start in the same time as upstream (renderer ready 0.8 to 0.9 s, first frame 1.2 to
  1.4 s). The stack queues 352 shaders to compile in the background, upstream 342.
* **Cold caches**: the background compile of the extra variants lengthens the first launch: the map is loaded and the scene ready at 17.6 s
  against 16.4 s (Direct3D 12) and 20.1 against 16.6 s (Vulkan); the longest frame of the first launch was 2.3 s against 1.3 s
  (Direct3D 12) and 5.1 s against 1.4 s (Vulkan), single runs, in the loading phase. Section 8.4.
* **Direct3D 11** compiles every effect with `fxc` when the cache is empty: 11.5 s upstream, 17.9 s here (`water2.fx` 0.06 -> 5.6 s,
  `particle.fx` 0.6 -> 1.5 s, `mesh.fx` 7.7 -> 7.8 s, `terrain.fx` 2.8 -> 2.7 s). With a warm cache both builds read their compiled effects (no compile, first frame at 1.3 s; the map is loaded 1 s later in the stack's single run, 15.8 against 14.8 s).

### 6.2 Switching a feature on in a running game

The largest frame of the 4 s after the switch (the effect rebuilds of the live switch, texture reads, first use of a pipeline;
on Direct3D 11 the patched effects first compile in the background, 23.5 s for the lights and 13 s for the shadow filter in these
runs, and the table shows the frame of the swap):

| feature switched on in a running game | D3D12 largest frame ms | Vulkan | Direct3D 11 |
|---|---|---|---|
| Dynamic Lights Ultra | 170 | 141 | 2537 |
| Shadow filtering Ultra | 118 | 102 | 96 |
| Water quality High | 4 | 4 | 4 |
| Temporal AA | 6 | 4 | n/a |
| Render resolution 75 % | 8 | 4 | 113 |
| Ambient occlusion High | 5 | 4 | 4 |
| Sun shafts and height fog | 5 | 7 | n/a |
| Soft particles High | 3 | 4 | 4 |
| Large particle quality Half | 4 | 4 | 4 |
| Ray-traced shadows | 28 | 46 | n/a |
| Water simulation | 4 | 4 | 4 |
| SMAA | 4 | 3 | 83 |

Dynamic lights are the one with a hitch (170 ms on Direct3D 12, 141 ms on Vulkan, 2.5 s on Direct3D 11): the mesh, terrain and
water effects are rebuilt (`Live switch ... 3 effects rebuilt in` 117 to 133 ms on the three APIs) and the light textures of the units in
view are read. Shadow filtering costs 100 to 120 ms for the same reason; ray-traced shadows 28 and 46 ms. Everything else is below 10 ms on Direct3D 12 and Vulkan.

### 6.3 Render-thread texture reads of the dynamic lights

The lights read the albedo and specular maps of each mesh LOD once to find its glow colour (`LightTextureCache`, on the render
thread, 2 ms budget per frame checked per analysis). In the four-minute battles the log shows 23 to 34 frames with reads
(about 180 textures, 100 to 120 ms in all); most are a few ms, the worst a single frame of 14 ms for two textures and, in a
live switch with many unit types in view, 25 to 40 ms. That is one-time per unit type; section 8.3.

### 6.4 Four-minute battle, soak and leaks

80 against 80 units walking into each other with structures, trees, and a nuke every 25 s, 16 steps of 15 s; memory sampled every
2 s, `ren_Info` every 15 s. "u1" and "u2" are the same Ultra run twice (the leak comparison), "user" the profile of section 4,
"base" upstream with its defaults (a lighter configuration, so the frame times are not comparable between rows).

| run | build / API / config | frames (windows) | median GPU ms | median CPU ms | frame p99 median ms | worst frame ms | windows with a frame over 20 ms | private MB start -> end (MB/min) | GPU dedicated MB start -> end (MB/min) |
|---|---|---|---|---|---|---|---|---|---|
| base | baseline / d3d12 | 267840 (4464) | 1.06 | 0.60 | 1.46 | 22.0 | 1 | 1117 -> 1030 (-16.0) | 417 -> 417 (+0.0) |
| u1 | ours / d3d12 | 43380 (723) | 7.58 | 0.98 | 8.45 | 202.3 | 22 | 1612 -> 1567 (-17.1) | 861 -> 861 (+0.0) |
| u1 | ours / vulkan | 120420 (2007) | 2.02 | 0.89 | 2.98 | 24.4 | 1 | 1825 -> 1795 (-14.6) | 846 -> 846 (+0.0) |
| u2 | ours / d3d12 | 47040 (784) | 7.72 | 0.93 | 8.38 | 86.8 | 22 | 1624 -> 1569 (-16.3) | 862 -> 862 (+0.0) |
| user | ours / d3d12 | 121380 (2023) | 2.56 | 0.84 | 3.59 | 27.8 | 2 | 1550 -> 1455 (-16.6) | 752 -> 752 (+0.0) |

* **No growth** in video memory (0.0 MB/min in every run, both repeats) and the process private bytes fall by 15 to 17 MB/min over the
  run (the load garbage being returned), the same slope as upstream. No leak in the stack's per-frame allocations or the
  backends' resources at these scenes.
* **Windows with a frame over 20 ms** (22 of 723 in the Ultra Direct3D 12 runs) are not hitches: they are the first 40 s of the
  run, with all 160 units firing, in which the Ultra configuration's GPU frame is 19 to 25 ms (the windows' GPU time is that),
  plus the switch-on frame (188 to 221 ms; 87 to 202 ms at the start of the soak steps). The Ultra run on Vulkan has one such window,
  the user's profile two. Upstream's single window is one frame of 22 ms.

## 7. Fixes made in this audit

Small, safe, each its own commit on `perf/audit` (Conventional Commits, with the numbers). Host tests: 68 of 68 pass (the
`math_dump` check that fails on this CPU is not counted). Frames of the touched features were compared paused, before and after,
on Direct3D 12 and Vulkan: the pixels that differ are the ones that differ between two frames of one build (0.12 %, the HUD clock).

### 7.1 Dynamic lights: no cell table or grid upload while the irradiance field is the path (`6818b2edc`, Stack PR: lights)

With `ren_DynLightsMode 1` (the default) the irradiance field reads the lights' data and the shadow casters only; the table and the
lists of the light grid's cells are for the shaders' old grid path. They were built and uploaded every frame anyway
(`BuildLightGrid`: every light's footprint over the cells, a sort, 3 MB of texture, locked with Discard and sent whole). The frame
now builds the data and the casters (`withCells = false`) and uploads the data texture; the cell table is made in `SetView`, from
the same lights, only when the field is not run that frame (no compute, no ground in view, no lights, a failed resource, or the
debug view) and in mode 0 as before. New profile scopes `LightsFrame / LightsFeed / LightsCollect / LightsGrid / LightsUpload /
LightsMeshes` show where the CPU time of the lights goes. Host test `LightGridTests` checks that the cell-less image has the same
data and casters.

80 against 80 firing units, Direct3D 12, medians of three, over everything off:

| Dynamic Lights | GPU ms before -> after | CPU ms before -> after | uploaded per frame |
|---|---|---|---|
| High | +3.04 -> +1.58 | +4.28 -> +0.74 | 3.0 MB -> 1.0 MB |
| Ultra | +3.22 -> +1.74 | +4.45 -> +1.06 | 3.0 MB -> 1.0 MB |

`LightsGrid` CPU 3.3 -> 0.08 ms and `LightsUpload` GPU 1.49 -> 0.16 ms at High. A second run with the final build gave Ultra
+1.77 GPU / +0.93 CPU ms and High +1.54 / +0.95, Medium +0.88 / +0.28 (it was +2.08 / +0.79), Low +0.38 / +0.12. For the user's
profile the lake went from 4.53 to 3.06 ms GPU and from 2.12 to 1.61 ms CPU, the battle from 9.43 to 7.83 ms GPU and from 6.89
to 3.80 ms CPU (section 4).

### 7.2 Particles: the large-quad estimate and the low-resolution targets only exist while the path can run (`a473417b1`, Stack PR: particles)

The low-resolution particle path needs a viewport of `ren_ParticleLowResMinViewport` million pixels (5 by default: 4K); a smaller
one never takes it. Large Particle Quality is Half by default, so at 1600x900 and 2560x1440 the game still copied 88 bytes of every
uploaded particle for the CPU estimate of its quad, computed that estimate (an `exp` per particle with drag) for every live
particle of every eligible bucket every frame, made the low-resolution targets (13 MB of video memory), and then drew every
bucket the normal way. `Begin` now asks for the viewport before it makes the targets, and the upload keeps the copies only while
the path ran within the last 600 calls of `Begin` (so a second, smaller view does not stop it). Output is unchanged: the path never
ran below the minimum.

80 against 80 firing units, Direct3D 12, frame CPU over Large Particle Quality Off: Half +0.54 -> -0.13 ms, Quarter +0.62 ->
-0.16 ms (EffParticles CPU +0.40 -> -0.05 ms). Vulkan before: +0.35 and +0.41 ms. Settled lake scene at defaults, Direct3D 12 (process private / GPU dedicated MB): 1158 / 614 before, 1140 / 609 after (upstream 1080 / 544).

### 7.3 Profile scopes (`f0fdd5969`, `067e0880b`, Stack PR: base and water)

The render profile holds 64 regions (48 before; the audit's scopes and the passes of the Ultra profile together came to 49 and the
surplus was added to the last region). New scopes `WaterFeed` (every mesh instance of the frame against the water bodies) and
`Waterfalls` (clock and particles of the falls) show the CPU cost of the default-on water on a river map, which was in no pass
the profile had.

### 7.5 Particles: `particle.fx` is patched only while it is used (Stack PR: particles)

The effect was patched at load whatever the options said, and the patched effect costs more per fragment than the original
(section 8.1 of the first version of this audit). `particlelowres::PatchWanted` now decides at load, and
`particlelowres::ApplyLive` (first thing in every frame, like the lights' and the terrain's live rebuilds) builds the effect again
when the answer changes: the patch is on while Soft Particles is on, or Large Particle Quality is on and a viewport of
`ren_ParticleLowResMinViewport` Mpix (5, 4K) can exist. Until a particle pass has measured the viewport it really draws into,
the size of the window's head stands in; after that the viewports of the last 600 passes decide (a smaller second view does not
drop the patch, a resize or fullscreen change to a big viewport takes it, a render scale under 100 % counts the scaled size). So
at 1600x900 and 2560x1440 with Soft Particles off the effect is upstream's text, upstream's shaders and upstream's cost; the
default (Soft Particles Low) keeps the patch, which is the feature.

80 against 80 firing units (`soak` scene, the `wide` step), every particle option off, Direct3D 12, three runs each, medians
(`p2_partest`: `perfbase` = upstream, before = the audit's build, after = this build, after with `/noparticlelowres` = the
unpatched effect by hand):

| | frame GPU ms | EffParticles GPU ms | frame CPU ms | strategic view (zoom 420) GPU ms |
|---|---|---|---|---|
| upstream | 7.065 | 5.013 | 3.253 | 3.390 |
| before | 7.795 | 5.744 | 3.159 | 3.285 |
| after | 7.070 | 5.037 | 3.285 | 3.270 |
| after, `/noparticlelowres` | 7.065 | 5.034 | 3.252 | 3.280 |

Vulkan and Direct3D 11 (one run each, same scene): frame GPU 6.805 / 1.560 ms after against 6.790 / 1.460 upstream, EffParticles
4.914 / 0.794 against 4.889 / 0.787 (the audit had +7 % on both before); the 0.1 ms of frame GPU that Direct3D 11 has over upstream is the same with `/noparticlelowres` (1.555 ms), so it is not the particle effect (section 8.8). The live switch in one session (`p2_live`: soft on,
soft off, Half on a 1600x900 view, `ren_ParticleLowResMinViewport 0`, back to 5, ...) rebuilds the effect only when the answer
changes: 6 to 8 ms on Direct3D 12 and Vulkan, 9 to 19 ms on Direct3D 11 once the compiled copy is in the effect cache, 1.25 s
the first time it is compiled there; Half on a 1600x900 view with Soft Particles off rebuilds nothing. The paused battle frames
(24 s, 1600x900) of the audit's build and this one are the same to the pixel except the HUD clock (0.12 % of the pixels, the
same in two frames of one build) with the defaults on Direct3D 12 and Vulkan and with every option off on Direct3D 12. The
paused nuke frames cannot be compared byte for byte: the pause lands on another tick in every run (42.03 s and 42.19 s).
The logs of the three APIs have no warning the baseline's does not have.

What changes for a player: with Soft Particles Off and no Large Particle Quality that can run, the muzzle-flash depth pull
(`FAF_FLASH_PULL`) that the patched vertex shader carried is gone with the patch (upstream has none).

### 7.6 Water: a body that has not moved is only kept (Stack PR: water)

`WaterFeed` was 0.21 ms of CPU a frame on the river map in every view, with only the commanders (out of sight) as units. The
cost was not the walk over the batch (0.003 ms when nothing stands in water) but the 37 mesh instances of 153 whose centre is
over a water body: the trees and rocks of the banks, which the feed treats as bodies in the water (columns of the mesh's
footprint, worked into bins, sorted and merged against last frame's bins) about 5 microseconds each, every frame, to find that the
change of every bin is zero. `water::BodyTracker::Hold` now remembers the pose the bins of a body were worked out from (position,
orientation, scale, the level of the water there, the mesh's foot); a body whose pose is the same bit for bit is kept as seen and
not worked out again. The bins and so every delta would have been identical (`BodyBins` is a function of the pose and the foot
alone), so the simulation gets exactly what it got: the sources per 240 frames are 3840 in every step with and without it
(the falls' own, no body emitted any). `ren_WaterBodyHold 0` works every body out every frame as before. A moving body (a unit,
a hull) goes through the old path unchanged. New profile scope `WaterStep` (the CPU side of `StepWaterSimulation`).

River map (`faf_re_waterrivers`), default configuration, Direct3D 12, same session, the switch flipped every 8 s (two repeats; ms,
per frame of the render thread):

| view | `WaterFeed` CPU, hold off -> on | frame CPU, hold off -> on |
|---|---|---|
| the falls (zoom 38) | 0.211 / 0.208 -> 0.013 / 0.013 | 1.48 / 1.42 -> 1.28 / 1.21 |
| wide (zoom 90) | 0.205 / 0.209 -> 0.012 / 0.012 | 1.43 / 1.48 -> 1.27 / 1.27 |

Direct3D 11 and Vulkan (the same switch, two repeats): `WaterFeed` 0.22 / 0.22 -> 0.014 / 0.014 ms and 0.21 / 0.23 -> 0.013 / 0.014 ms, frame CPU
(Direct3D 11) 1.80 / 1.77 -> 1.55 / 1.56 ms at the falls and 1.72 / 1.73 -> 1.49 / 1.50 wide (Vulkan 1.59 / 1.89 -> 1.40 / 1.68, a noisier run).
The frame GPU is unchanged (1.58 / 1.57 and 1.47 / 1.48 ms on Direct3D 12). The river map's frame CPU at the default configuration is now 1.2
to 1.3 ms against upstream's 1.06 (1.4 to 1.5 before in this session, 1.57 in the audit's parity run). The remaining difference to upstream on this map is the shoreline of the
rivers (49 of the 60 extra draw calls, 0.04 ms CPU: every cell of a sloped river is at its own level and the shoreline shader
takes one level a draw, `ren_Shoreline 0` takes 410 draws to 361), soft particles and the waterfalls' own work (0.006 ms).

### 7.7 Dynamic lights: the light field is sized by the quality level (Stack PR: lights)

The irradiance field made its buffers for 512 x 512 cells x 5 layers at every level: the cells 63 MB, the RGBA16F atlas
(2560 x 1536) 31.5 MB, the two visibility buffers 10.5 MB, 105 MB of video memory whether the player asked for Low
(big explosions only) or Ultra. They are now made at `CellsForLevel` of `ren_DynLights` when the field first runs (as before:
the first frame with a light, or with the sun's shadow on) and again when a change of level changes the count: Low 256 cells (26 MB),
Medium 384 (59 MB), High and Ultra 512 (105 MB, unchanged); the visibility history starts again with the new buffers. The ladder of cell sizes
is the same (0.5 to 16 units), so a smaller field reaches the next size sooner (the cell is twice as wide for a view whose
extent is between the two fields' limits) and the largest view it covers is smaller: (cells - 16) x 16 units, 3.8 km at Low, 6.0 km at Medium, 7.9 km at
High and Ultra (the field is the shadows and occlusion of the lights, which Low only has for big explosions).

Direct3D 12, lake scene, one run per level, lights switched on live at that level, settled (the process's GPU dedicated and
private memory, increase over the state before the switch):

| level | GPU MB before -> after | process MB before -> after |
|---|---|---|
| Low | +181 -> +106 | +239 -> +167 |
| Medium | +181 -> +137 | +241 -> +197 |
| High | +181 -> +181 | +241 -> +241 |
| Ultra | +181 -> +181 | +241 -> +244 |

The paused frames of the 80 against 80 battle with the lights at Ultra are the same to the pixel as the audit's build (except the HUD
clock, 0.12 % of the pixels) on Vulkan, and on Direct3D 12 when the pause lands on the same tick (the pause tick is quantised to a tenth
of a second and the missiles in flight move between two ticks; builds that paused on the same tick agree). Low and Medium were not compared with
the old pictures: they are coarser by design. The other two items of the proposal were looked at and left: the 76 MB of
shadow filtering Ultra are the shadow atlas itself (the level's 4096 map is a 2 x 2 atlas of tiles of `kAtlasTileLimit` = 2048, a
colour and a depth target of 4096 x 4096), and `Shadow::Init` already makes no blur targets while the filter is on, so nothing
of it is unused; the render-scale targets are already made at the scaled size (`RenderScalePass::Prepare`). The temporal AA
history and the atmosphere's targets (the 150 and 240 MB the audit saw when they were switched on after the others) were not looked at.

### 7.8 Dynamic lights: light textures are read on a worker thread (Stack PR: lights)

The lights read the DDS file of every effect and unit texture they see for the first time (the file lookup, the memory map, a DXT
decode and the colour summary) on the render thread: 13 to 14 frames in the 80 against 80 battle with 92 to 127 ms in all, the worst
36 to 59 ms, and part of the 170 to 180 ms frame of switching the lights on. `LightTextureCache` now has one worker thread:
`FindTexture` answers `Ready`, `Failed` or `Pending` (the first call for a path queues it), the render thread takes the finished ones into the
cache once a frame in `TrimTextureCache`, where no feed holds a pointer into it, and the worker owns nothing else. While a
texture is pending a mesh has no glow (`GlowOf` asks again next frame; its analysis is cached only when the textures are
there), and an effect source gives no light for that beat (a light made with a guessed colour would keep it for its whole life; the
next beat, 0.1 s later, has the texture). `FAF_LIGHT_TEXTURES_SYNC=1` reads on the render thread as before. Render only; nothing
the simulation sees.

Direct3D 12, 80 against 80 firing units, lights switched on to Ultra in the running game, three runs of each build alternated
(`lights_switch.py`):

| | frames with texture reads on the render thread (runs) | ms in all | worst frame of them | frame of the switch-on, max ms |
|---|---|---|---|---|
| before | 14 / 13 / 14 | 93 / 108 / 92 | 36 / 45 / 36 ms | 171 / 180 / 170 |
| after | 0 / 0 / 0 | 0 | none | 160 / 129 / 129 |

The worker needed 15 to 16 batches, none more than 23 ms of its own time. Over the held steps the longest frame is 19 to 21 ms
before and 20 to 23 ms after, no change (a 64 ms frame in one of the earlier runs of the audit's build, a switch back to Ultra, did
not occur again in the runs of the new one). The paused frames of the battle are the same
to the pixel at the same pause tick with and without the worker (`FAF_LIGHT_TEXTURES_SYNC=1`), on Direct3D 12 (59 frames, 0.12 % of the
pixels: the HUD clock) and Vulkan (the Vulkan run against the audit's build as well).

### 7.9 Dynamic lights: the pool is ranked through compact keys (Stack PR: lights)

`LightCollector::Update` (`LightsCollect`, the pool of the frame, strongest first) built a vector of every active light with its sort
key (a 64-byte record) every frame and sorted that vector: an allocation of the pool's size and a sort that moves 64 bytes at a time. It now
builds the lights once into a vector that lives from frame to frame and sorts 16-byte keys (power, birth, serial, index) that point
into it; the comparison is the same, and the serial makes the order total, so the lights that come out are the same ones in the same
order (`faf_light_tests`: 94,649 checks of the collector, grid and the rest pass). Direct3D 12, 80 against 80, Ultra, `LightsCollect` CPU
in the held step, three runs of each build alternated: 0.76 / 0.76 / 0.71 ms before, 0.72 / 0.66 / 0.68 after (-0.08 ms, 11 %); the same in the
paired runs of the first set (0.78 to 0.83 before, 0.70 to 0.76 after). The frame's GPU time is unchanged. The paused battle frames
with Ultra lights are the same as before to the pixel at the same tick (7.7). `TerrainContext` (+0.24 ms) is the terrain's own
`UpdateRenderContext`, upstream code; what the lights add to it was not investigated.

### 7.4 Tried and dropped

* An early-out in `FeedWaterFromMeshes` for instances far above every water level: `WaterFeed` 0.214 -> 0.210 ms on the river, 0.082
  -> 0.070 ms in the battle. Below what is worth a change in that code; not committed.
* A branch on `SoftFade` in the patched particle pixel shader (8.1): no change in the particle pass; reverted.
* Frustum culling of the water meshes of a body (a bounding box per chunk against the camera, `ren_WaterChunkCull`): on the river
  map the Water pass went from 57 to 53 draws and from 0.19 to 0.11 ms GPU at the falls; in the other three views (wide, side,
  away) it changed nothing beyond the noise (the pass 0.11 to 0.34 ms with and without, within 0.03) and the frame's GPU time
  did not change in any (1.56 to 1.61 ms with and without at the falls). The three waters of the map are 6764 quads; the 53
  draws are the shoreline's (7.6). Not kept: no gain worth a frustum test in the water passes.

## 8. Found and not fixed

Ordered by cost to a player at the shipped defaults, then by what the user's profile turns on. Cost is what the audit measured
(Direct3D 12, 1600x900, RX 7900 XTX, 80 against 80 battle unless said); "proposal" is what the change would be, not tried.

### 8.1 The patched particle effect is slower than upstream's even with every particle option off (fixed, section 7.5)

**Status: fixed in `perf/fix2`** (section 7.5): the effect is patched only while Soft Particles or Large Particle Quality can run,
and built again live when that changes. What follows is the finding.

* **Cost**: +0.4 ms GPU in the 80 against 80 battle (EffParticles 3.15 -> 3.52 ms, +12 % of the pass, +9 % of the frame; the
  second run at a heavier moment: +0.74 ms of 7.05); Vulkan +7 %, Direct3D 11 +7 %. Zero in scenes without a particle load. With
  `/noparticlelowres` (the effect is not patched) the pass equals upstream's. With Soft Particles on (the default) the patched
  effect is what the feature is, and costs its +0.7 to +0.8 ms in this battle (one scene-depth read per particle fragment).
* **Cause**: `particle.fx` is patched at load whether or not soft particles or the low-resolution path are on; the replaced soft-fade
  pixel shader and the large-quad path cost more per fragment than the original. A branch on the soft-fade flag in the shader did
  not help (section 7.4).
* **Proposal**: patch the effect only while Soft Particles or Large Particle Quality is on, and rebuild it on the live switch (the
  same mechanism the lights use: about 120 ms for three effects on Direct3D 12 and Vulkan; on Direct3D 11 a compile in the background, 13 to
  24 s). Touches the effect-patch and option plumbing of all three backends, so
  it is a feature-sized change, not a cleanup. (Done as proposed; `particlelowres::PatchWanted` / `ApplyLive`.)

### 8.2 Dynamic lights still cost +1.7 ms GPU and +0.9 to 1.1 ms CPU at Ultra in a battle (1.5 / 0.7 to 0.9 at High)

**Status: `LightsCollect` -0.08 ms (7.9); the rest is documented, not changed.** The finding:

* **Where** (Ultra, after the fixes; CPU / GPU ms over lights off): `LightsCollect` +0.71 / 0 (the lights of the effects, meshes
  and units collected every frame), `TerrainContext` +0.24 / 0 (terrain constants for the field), `LightsGrid` +0.08, `LightsMeshes`
  +0.04, `LightsUpload` +0.03 / +0.16, `LightField` +0.01 / +1.03 (the compute), the lit `Meshes` / `Terrain` / `Reflections` passes
  +0.22 / +0.20 / +0.23 GPU.
* **Proposal**: `LightsCollect` is a full walk every frame; keep the light list of unchanged emitters and collect only what moved
  (or collect on a worker thread, the field's inputs are one frame old anyway). The compute's cost scales with the field resolution:
  a lower resolution at High would cut it. Both change what the lights look like or add threading, so not done here. (What was
  safe was the allocation and the sort of the frame, 7.9: -0.08 ms of 0.76. The walk itself, about 0.6 ms for the pool of this battle,
  is per-light arithmetic; skipping unchanged lights would need the lights' envelope to be cached between frames, which
  moves with the clock every frame. `TerrainContext` is upstream's `UpdateRenderContext`; what the lights add to it was not investigated.)

### 8.3 The render thread reads light textures (fixed, section 7.8)

**Status: fixed in `perf/fix2` (7.8): the files are read and decoded on a worker thread.** The finding:

* **Cost**: 23 to 34 frames in a four-minute battle with texture reads, about 180 textures, 100 to 120 ms in all; single frames of
  14 ms (two textures) and 25 to 40 ms when many unit types appear at once (the live switch). A 20 to 40 ms frame is a visible stutter.
* **Cause**: `LoadTexture` memory-maps and decodes the DDS (downscaled to 256) on the render thread; the budget of 2 ms per frame is
  checked before each analysis, not inside it, and two maps took 14 ms in one case.
* **Proposal**: decode on a worker, analyse the mesh with the neutral glow until the result is there (the lights already analyse a
  mesh "the next frame" when the budget is out), and cap the decode to the smallest mip that holds 256 pixels. (Done; the decode
  already takes the largest mip that fits 256 x 256, `DecodeDds`.)

### 8.4 First launch with an empty shader cache

* **Cost**: Direct3D 12 scene ready at 17.6 s against 16.4 s upstream, the longest frame 2.3 s against 1.3 s; Vulkan 20.1 against 16.6
  s, the longest frame 5.1 against 1.4 s; Direct3D 11 +6.4 s of compile, scene ready at 33.4 against 26.4 s (section 6.1). Single cold runs; warm caches show no difference.
* **Cause** (not isolated): the stack has more shader variants (352 against 342 queued; `water2.fx` is a large effect on Direct3D 11:
  5.6 s of `fxc`); the longest frame is a frame that waits for a pipeline or effect that is not compiled yet.
* **Proposal**: compile the default-on variants first and the rest of the options' variants after the first frame, and let the first
  use of an uncompiled variant fall back to the unpatched pipeline for a frame instead of waiting.

### 8.5 Memory (the light field fixed, section 7.7)

**Status: the light field is sized by the level and made when the field first runs (7.7); the other proposals are open or looked at (7.7).**

* **Default configuration**: +70 MB of video memory and +75 to 150 MB of process memory against upstream (water simulation 44 MB of
  video memory, low-resolution particle targets 13 MB (fixed for small views, 7.2), the post chain). After 7.2 the settled lake scene is 1140 MB / 609 MB against upstream's 1080 / 544; what is left is mostly the water simulation (about 44 MB of video memory) and 3 MB of buffers.
* **The user's profile**: +0.44 to 0.47 GB of process memory and +0.34 GB of video memory. Put back to the default one group at a time
  (section 4.1): Ultra dynamic lights are **177 MB** of video memory (and 190 MB of process memory), shadow filtering Ultra 76 MB,
  AO High 14 MB. The light field's own buffers are 105 MB at every quality level (`LightField.cpp`: 512 x 512 cells x 5 layers,
  `LightFieldCells` 63 MB, the 2560x1536 RGBA16F atlas 31.5 MB, two visibility buffers 10.5 MB); the other 70 MB of the lights were
  not itemised. Switched on in a running game on the lake the lights added only 14 MB (their buffers are made when the first
  light exists), so the number a player sees is the one at the load of a map with lights.
* **Temporal AA, render scale 75 % and sun shafts** are not in the profile; together they took 340 to 350 MB when switched on after
  the others (56 MB alone, section 4.1), which is a cost of the combination.
* **Proposal**: size the light field by the quality level (Low and Medium do not need 512 cells and 5 layers) and make it when the
  first light of the map exists (done, 7.7); allocate the post targets at the size they are used (the render-scale targets already
  are the scaled size, 7.7) and share the history of temporal AA with the sharpen/grade chain's ping-pong targets (open); shadow
  filtering's 76 MB want the same check (done: it is the 4096 x 4096 atlas, none of it unused, 7.7).

### 8.6 The default-on water on a river map (mostly fixed, section 7.6)

**Status: `WaterFeed` fixed in `perf/fix2` (0.21 -> 0.013 ms, section 7.6); the shoreline's draws are left.** What follows is the
finding.

* **Cost**: +0.24 to +0.38 ms GPU and +0.4 ms CPU per frame on the river map (a 1.1 ms frame), +64 draw calls and 18 KB of
  upload per frame; `WaterFeed` 0.21 ms and the water simulation 0.23 to 0.29 ms CPU of that.
* **What it was**: not the instances far from the water (a walk over 153 instances with 0 over water is 0.003 ms) but the 37
  that stand over a river's level, the trees and rocks of its banks, each worked out as a body in the water every frame to find
  that nothing changed. A coarse grid of the water bodies would not have helped; keeping a body that has not moved did (7.6).
  The simulation's own CPU is 0.008 ms (`WaterStep`), the waterfalls 0.006 ms.
* **Left**: the +53 draw calls of the Water pass are the shoreline: `Shoreline::mShorelineRuns` has one run, so one draw, for each
  distinct level of the visible cells, and every cell of a sloped river has its own (`ren_Shoreline 0`: 410 -> 361 draws, Water
  CPU 0.074 -> 0.034 ms, GPU 0.108 -> 0.085 ms at the falls). Sharing the draw needs the level per vertex (the shoreline record is
  six floats, two for each of its three points) and a `water2.fx` patch for `TShoreline`; not done here. Skipping the water
  meshes that are off the screen saves nothing measurable (section 7.4).

### 8.7 Ray tracing (off by default)

* **Cost**: ray-traced shadows +6.9 ms in the battle (+2.5 on the lake), all four rays +7.5, the sun angle (soft shadows) +26.7 ms
  and in total Ultra + rays +38.6 ms on Direct3D 12; Vulkan +22.1 for the soft step. The terrain pass carries 4.8 of the 6.9 ms and
  16 of the 26.7. Switching it on in a running game is a 28 to 46 ms frame.
* **Proposal**: not a cleanup. The terrain pass casts one ray per pixel against the whole scene; a half-resolution shadow mask for
  the terrain, or the sun-angle samples spread over frames with the temporal AA's history, are the two options.

### 8.8 Smaller

* Shadow filtering Ultra +0.47 ms GPU in the battle, +0.14 on the lake (High +0.19 in the battle, Medium +0.19 on the nuke); AO High +0.4 ms
  everywhere (all three APIs); the default Medium / Standard levels are +0.1 to 0.2 ms.
* Direct3D 11, switched on in a running game: the patched effects compile in the background first (23.5 s for the lights, 13 s for
  the shadow filter, in the toggle runs), then the swap is a frame of 2.5 s (lights), 96 ms (shadow filter); render scale 113 ms,
  SMAA 83 ms.
* The Direct3D 11 default-config parity shows +0.16 ms GPU in the lake that is in no per-feature row (3.2).

## 9. Reproduce

`tools/perf_audit/README.md` lists the files. In short: put the two builds as `perf.exe` and `perfbase.exe` in a run folder with
their data folders, run `python tools/perf_audit/mk_prefs.py` for the prefs copies, then `jobs.py feat` (per-feature tables),
`parity.py` (parity matrix), `jobs.py load | toggle | soak | vram | membisect` and the `*_report.py` readers. Every run takes
0.5 to 7 minutes of a game window; run them alone on the machine and wait for other games to finish.
