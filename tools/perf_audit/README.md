# Performance audit harness

The scripts behind [docs/PERFORMANCE_AUDIT.md](../../docs/PERFORMANCE_AUDIT.md): they run the game with the render profile on
(`FAF_GPU_PROFILE`), switch features on and off from a test script, and turn the profile lines of the log into tables. Windows,
PowerShell 7 and Python 3. Nothing here is part of the engine or its tests.

## Set-up

* A run folder (`PERF_BIN`, default `C:/ProgramData/FAForever/bin_x64_perf`) with `dxcompiler.dll`, `dxil.dll`, the two builds as
  `perf.exe` (the tree under test) and `perfbase.exe` (the baseline, built from the commit the tree is based on, same compiler and
  preset), and for each of them a data folder `fafengine_perf` / `fafengine_perfbase` (a copy of `data/fafengine` of that tree, and in
  `lua/ui/game/gamemain.lua` and `lua/simInit.lua` the test hooks of `tests/featab`). `perf_run.ps1` copies the folder of the build it
  starts to `fafengine` first. Overwrite the two exe names, do not add new ones.
* Preferences copies next to `Game.prefs` (`python mk_prefs.py`: `Game_perf_off.prefs`, `Game_perf_off_base.prefs`,
  `Game_perf_default.prefs`, `Game_perf_user.prefs`, made from a copy of the profile `Game_tsuser.prefs`: vsync off, no frame limit; `python mk_prefs_umb.py` makes
  the `Game_perf_u_*.prefs` variants of the profile for the `umb` queue). The
  profile of the player is not touched.
* `PERF_AUDIT_OUT` (default `tools/perf_audit/out`): where the results go (`perf_out/*.json`, `perf_out/*.jsonl`). `FAF_LOGS`: the game's
  log folder (the logs are read from there: `pf_<tag>_<api>_<exe>.log`).

## Pieces

| File | What |
|---|---|
| `perf_run.ps1` | one game run: starts the exe with a scene and a steps file, waits for other games, logs the time of the start markers, samples process and GPU memory, stops the game by its PID |
| `perf_camera.lua`, `scene_main.lua`, `scene_falls.lua`, `scene_terraform.lua` | the test hooks: the camera and the steps (`{label, {console commands}, preset, hold, 'info'}`), the scenes (static, battle, soak, nuke, water, falls, terraform) |
| `gen_steps.py`, `gen_steps_cmds.py`, `gen_soak.py` | the steps files of the per-feature tables, the memory run and the soak |
| `parity.py`, `parity_report.py` | the parity matrix: baseline and tree, every combination of configuration, API, scene, repetition (alternating the order) |
| `jobs.py` | the queues: `feat` (per-feature tables), `soak`, `load` (cold and warm shader caches), `vram` and `vramiso` (memory per feature, in two orders), `toggle` (the hitch of switching), `mem`, `membisect`, `mbfinal`, `umb` (video memory of the user's profile, one group of switches off at startup), `d3dcache` (the effect cache of Direct3D 11), `partest`, `after`, `cmp` |
| `perf_parse.py`, `feat_report.py`, `ft_tables.py`, `passdiff.py`, `hitch_report.py`, `soak_report.py`, `mem_report.py`, `vram_report.py`, `vramiso_report.py`, `umb_report.py`, `compile_times.py`, `cmp_frames.py` | the readers of the logs |

## Reading the numbers

A step of a test lasts a few seconds; the first 1.2 s of it are dropped; its value is the median of the profile windows of the rest. A
feature is compared with the `off` step before it in the same session (`feat_report.py`), three times, so `ft_tables.py` shows the
median difference and the range. GPU ms is the `Frame` region (first to last GPU timestamp of the frame), CPU ms the render thread's
`Frame` scope. Both are what the engine measures itself (`docs/SWITCHES.md`, `FAF_GPU_PROFILE`).

## The second round (`second_round/`, `perf/fix2`)

The scripts that measured the fixes of sections 7.5 to 7.9 of the audit. They run the exe that is named `perf.exe` in the run folder
(copy the build to be measured over it between runs; the baseline stays `perfbase.exe`), through `jobs.run`, and write their steps files
next to `jobs.py`.

| File | What |
|---|---|
| `particles_off.py`, `particles_off_report.py` | every particle option off, the 80 against 80 battle: upstream, this build, this build with `/noparticlelowres`; the report prints frame GPU, `EffParticles` and frame CPU per view |
| `particles_live.py` | the particle patch switched on and off in one session (soft particles, Large Particle Quality, the minimum viewport); the log says when `particle.fx` was rebuilt and how long it took |
| `frames_paused.py`, `frames_diff.py` | paused frames of a build (`cfg` default, off, lights) dumped to a folder, and two builds compared (the noise floor is the 0.12 % of the HUD clock; the pause lands on a tick, so a scene with things in flight only compares builds that paused on the same tick) |
| `river_ab.py`, `river_report.py` | the river map at the falls and wide, a switch flipped every 8 s in one session (`ren_WaterBodyHold`, `ren_Shoreline`, `ren_WaterSim`), the passes of each step |
| `lights_switch.py`, `lights_report.py` | lights switched on to Ultra in a running 80 against 80 battle: the frames of the switch, the texture reads on the render thread and on the worker, `LightsCollect` |
| `lights_memory.py` | video and process memory of the lake scene settled after the lights are switched on live at a level, one run per level |
