---
name: project_runtime_verification_2026_09_02
description: First live run after the CAniPose/MeshBatch/MeshBatchKey fixes. Builds and runs 150s without crashing, sim ticks to 17min game time, terrain+water+UI render — but NO unit meshes, at a camera parked at zoom 883.9. Records what the run does and does not prove.
metadata:
  type: project
---

## What the run was

`.vscode/run-engine.bat 150 map SCMP_009 nomovie` — the operator's own
build+stage+launch script, unattended, with two DPI-aware screenshots taken 55s
and 85s after the window appeared. Engine log at
`C:\ProgramData\FAForever\bin\engine.log` (`/log` is passed by that script).

## Proven

- **The tree builds and the game runs.** Zero compile errors across the whole
  sdk, including all files touched by `3dff30e6`, `34ab0097`, `fd114bc5`,
  `6a5eafe4`, `2d7cb10a`, `9d496aed`. 150 seconds, no crash.
- **The sim runs.** Game time reached **00:17:35** in ~2 minutes of session
  time; all eight AI armies logged *"Initiating Archetype using SetonsCustom"*;
  ARMY_1 is created with the player's nickname.
- **Terrain, water and UI render.** HUD reads 850 mass / 3900 energy, panels
  and toolbars draw, the render loop spins.

## NOT proven — the camera confound

**No unit meshes were visible, but the camera was at zoom 883.9, height 772**
(`[WORLDDIAG] camPos=(512.0,772.2,971.5) zoom=883.9`). Unit LOD cutoffs are far
below that, so `Mesh::ComputeLOD` legitimately returns null there and FA would
normally show strategic icons instead. **This run therefore does not disprove
the commander fix** — it never put the camera anywhere a unit mesh could draw.

Any re-test must get the camera near a unit first. Until then, "no commander
visible" at this zoom is not evidence either way.

## Real observations worth chasing

- One **solid black hard-edged quadrilateral** on the terrain — geometry
  reaching the screen with a failed/black material. Zoomed capture saved. Worth
  identifying: it is the only non-terrain geometry that drew.
- Player economy **frozen at 850/3900 with +0 income** across 30s. Consistent
  with either an observer focus army or simply the HUD not being driven; NOT
  yet diagnosed. `score.lua:288` calls `SessionIsReplay()` unguarded in the
  **sim** state while the engine registers it only into `scr_UserInits` — the
  binary does the same (`FUN_00897D90` verified), so our recovery is faithful
  and this warning is probably not the cause. Do not "fix" it.
- `FocusArmy` comes from `launchInfo->mCommandSources.mOriginalSource`
  (`CWldSession.cpp:14403`). Both writers are correct: `-1` on the replay path,
  `0` in `WLD_SetupSessionInfo` for skirmish. Not the bug.

## The link-log trap this run exposed

The build emitted **37 LNK2019 + 2 LNK2001**, and `main.exe` was produced
anyway because the project links with **`/FORCE`**. Three of those were real
and are now fixed (`5ca9a518`, `4d7bb0fd`, `b18bb989`); the rest are mostly
anonymous-namespace wx bridges. **A green-looking run does not mean the link
was clean** — grep the build log for `error LNK` every time. See
[[feedback_msvc_param_const_breaks_cross_tu_linkage]].
