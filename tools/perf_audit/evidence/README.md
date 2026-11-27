# Evidence harness: before / after frames and cost of the render stack

The scripts behind the "Evidence for a render change" sections of the render PRs (Draiget/faf-re#492 to #500): the same replay
paused at the same tick, played by builds of master and of a PR, on Direct3D 11, 12 and Vulkan, the frames dumped with
`FAF_GAL_DUMP_DIR` and compared, and the cost of a running replay segment from the render profile (`FAF_GPU_PROFILE`).
Windows, PowerShell 7, Python 3 with Pillow. Nothing here is part of the engine.

## Set-up

* A run folder per build, `C:/ProgramData/FAForever/bin_x64_ev/<name>/` (`ev.exe`, `dxcompiler.dll`, `dxil.dll`, `fafengine/`):
  `stage.ps1 -Name pr02 -Tree <worktree>` copies `build/clang-x64-release/src/main_x64.exe` and `data/fafengine` of a tree there and
  appends the two test hooks (`simhook.lua` to `simInit.lua`, a UI hook to `gamemain.lua`). A baseline build is staged the same way
  from a master build.
* The replays as `<id>.scfareplay` in `FAF_REPLAYS` (see `docs/PR_REPLAY_CHECK.md`); replay 28041625 needs M28AI v328: an init file
  that mounts it, `C:/ProgramData/FAForever/bin_x64_ev/init_m28.lua` (a copy of `init_faf.lua` with the two M28 mount lines).
* Maps of the water scenarios (`faf_re_waterlevels`, `faf_re_waterrivers`, `tools/scenarios/`) in the user's maps folder.

## Pieces

| File | What |
|---|---|
| `ev_run.ps1` | one session: starts a staged build with a replay (or a map), runs a scenes file through `ev_camera.lua` (seek to a tick with `ReplaySeek`, pause, hide the UI, snap the camera, run console commands, hold), dumps the back buffer every second, logs which scene was on when |
| `ev_camera.lua`, `ev_perf_camera.lua` | the UI test scripts (scenes; seek and then run for `EV_MEASURE` seconds with the profile on) |
| `scenes_*.lua` | the scenes of each group: `sr` (Serenity Reef replay 28041625, tick 9000: ships, coasts, Water Quality levels), `astro` (28013263, tick 12000, a map without water in view), `levels` and `rivers` (scenario maps); `__OFF__` stands for the switches a PR is turned off with |
| `matrix.ps1` | a build over groups and APIs |
| `mkcomp.py`, `evlib.py` | the composites (master, PR defaults, PR switches off; full frame and crop) and the share of pixels that differ (any channel by more than 8 of 255) |
| `cost.ps1`, `cost_report.py` | 75 s of the running replay with the profile on, defaults and switches off; medians and 95th percentiles of the profile windows |

The pause lands on the first frame after the seek finishes (game second 900.8 for tick 9000), so two builds are compared at the same
sim state; the water still moves while the game is paused (it runs on wall clock time), which is why two runs of master differ:
the report always carries that noise floor.
