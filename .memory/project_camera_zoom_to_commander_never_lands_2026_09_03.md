---
name: camera-zoom-to-commander-never-lands-2026-09-03
description: Commander-spawn goal, camera lane, PARKED 2026-09-03 when the operator redirected to index tooling. World camera stays at map centre / max zoom (907 = (640+8)*1.4) instead of framing the ACU; UIZoomTo->TargetBox chain desk-checked faithful; probe build is staged, [CAMDIAG] log never read.
metadata:
  type: project
---

**State when parked (2026-09-03):** the operator stopped recovery and set a
new goal (source index). Nothing below is resolved.

**Symptom, re-baselined after the peer's view-matrix revert:** a fresh
100 s `/map SCMP_009` run (`.vscode/run-engine.bat nobuild 100 map SCMP_009`,
log at `C:\ProgramData\FAForever\bin\engine.log`) shows the world camera at
`camPos=(512,772,971)` with `zoom=883.9`, drifting run-to-run between 854 and
907. `GetMaxZoom` is asm-faithful and evaluates to exactly 907.2 for this map
(playable extent 640 + `ren_BorderSize` 8, times `mMaxZoomMult` 1.4), and
`ClampTargetPos` at max zoom forces the focus to the map centre. So the zoom
lane is slewing UP toward max zoom in `UpdateBasis`, which means `mNearZoom`
== max zoom and no timed move is active: the `UIZoomTo(avatars, 1)` transition
(gamemain.lua `StartupSequence`, 1 s after first update) either never targets
or is undone.

**Desk-checked faithful against the .c/.asm exports:** `cfunc_UIZoomToL`
(0x00867240), `TargetBox` (0x007A83E0), `TimedMoveInit` (0x007A74C0),
`UpdateTargets` (0x007A9110), `Frame` (0x007A9030), `InterpolateBasis`
(0x007A9BA0, incl. the swapped-looking offset tangent pairing, harmless because
ease-in/out zeroes the tangents), `UpdateBasis` (0x007A95F0), `TargetNothing`
(0x007A6BF0), `GetMaxZoom` (0x007A7310), `CalculateFOV`, `SaveSettings` /
`RestoreSettings`, the camera ctor (system clock is the default time source).
Landed: `CameraReset` lane fix (mCurrentPitch/mHeadingZoom), not the cause.

**Open candidates, in order:** (1) the avatar table entries do not resolve
through `GetUserUnitOptional` (UserUnit.cpp:3557), so the binder returns
before targeting; (2) something re-targets after the 1 s move (`SetZoom`,
`TargetManual`, `Reset`, `MoveToRegion` from Lua); (3) the world view is
rebuilt after the move and `RestoreSettings` re-applies a pre-move snapshot.

**Probe build is ready:** `[CAMDIAG]` probes (ctor, Reset, TargetLocation,
TargetBox, TargetManual, TargetEntities, InterpolateBasis, sampled UpdateBasis,
and the three UIZoomTo exits) are committed in the temporary-probes commit and
were compiled into the staged `main.exe`. Next step is literally: run the
bat above, `grep CAMDIAG engine.log`, and the sequence of TargetBox / Interp /
UpdateBasis lines answers which candidate it is.

**Peer warning that applies to this file:** the hand-expanded view quaternion
in `UpdateCoords` (CameraImpl.cpp ~3698..3706, `qx=-lz, qy=-lw, qz=lx, qw=ly`)
compensates for the tree-wide rotated quaternion convention; converting it to
scalar-first in isolation projects the world as one giant triangle (the peer
did exactly that and reverted in b795819e). See
[[feedback-quaternion-x-scalar-convention-bug-class]].

Pre-existing, not new: ~70 "Evaluating LazyVar failed ... circular dependency"
warnings per run from score_mini.lua / control.lua, identical counts in every
log since at least 09:15 today.
