---
name: project_initial_camera_never_focuses_acu
description: BLOCKER for visually verifying the commander fixes. On a /map launch the camera stays at map centre at max zoom (512, ~790, ~1015, zoom ~920) instead of focusing the player's ACU, so unit meshes are always beyond LOD cutoff and cannot be seen. Reproduced twice.
metadata:
  type: project
---

## The blocker

Two unattended `/map SCMP_009` runs (2026-09-02), one with AI and one with
`/noAi`, both parked the camera at **map centre, maximum zoom**:

```
[WORLDDIAG] camPos=(512.0,772.2,971.5)  viewFwd=(0.00,0.85,0.52) zoom=883.9
[WORLDDIAG] camPos=(512.0,790.5,1014.7) viewFwd=(0.00,0.84,0.55) zoom=922.4
```

`x = 512` is dead centre of a 1024 map — this is the default "nothing focused"
state, not a spawn-point view. Retail FA snaps the camera to the player's ACU
at session start.

**Why it matters:** unit LOD cutoffs are far below zoom ~900, so
`Mesh::ComputeLOD` correctly returns null and no unit mesh can draw at that
distance. Every "the commander isn't visible" observation from these runs is
therefore uninformative — the camera was never anywhere a unit could render.
This blocks runtime verification of
[[project_canipose_empty_bones_hid_every_unit]] and
[[project_meshbatch_initialize_zeroed_every_counter]].

## What is known

- The camera Lua API is recovered and bound: `Camera:Reset()`,
  `Camera:MoveTo(position, orientationHPR, zoom, seconds)`,
  `Camera:MoveToRegion(...)` (`CameraImpl.cpp`), and UI Lua reaches it via
  `GetCamera('WorldCamera')` (`gamedata/lua/ui/game/worldview.lua:160`).
- So the binding layer exists; what is missing is whoever *drives* the initial
  focus at session start.

## Next steps

1. Find the session-start focus call on the retail side — likely UI Lua
   (`gamedata/lua/ui/game/gamemain.lua` / `worldview.lua`) calling
   `Camera:Reset()` or `MoveTo` with the army start position. Check whether
   the engine binding it needs is registered and reachable.
2. Note the operator reports the camera *does* move to the spawn point in
   their own manual runs — so their launch path may differ from bare `/map`.
   Worth asking how they launch before assuming this is broken for everyone.
3. Until it is fixed, verify the mesh fixes some other way: a lower forced
   zoom, a scripted `Camera:MoveTo`, or a console command.

`GetFocusArmy`/`mOriginalSource` were investigated and are **not** the cause -
both writers are correct (`-1` replay, `0` skirmish); see
[[project_runtime_verification_2026_09_02]].

## Ruled out (verified 2026-09-02) - do NOT re-audit

- **`CameraImpl::CameraReset` (0x007A80A0) is faithful.** It *deliberately*
  resets to map centre at max zoom: target x/z = (width-1)/2, (height-1)/2,
  elevation from the heightfield (raised to water level), `mNearZoom =
  GetMaxZoom()`, `mTargetType = Location`. The measured (512, ~790, zoom ~920)
  is exactly this. Reset ran and did the right thing.
- **Every camera Lua binding is registered.** `func_CameraImplReset_LuaFuncDef`,
  `...MoveTo...`, `...MoveToRegion...`, `...SnapTo...`, `...SetZoom...`,
  `...SetTargetZoom...` are all invoked from the registrar block at
  `CameraImpl.cpp:5714-5718`. This is NOT a "defined but never called" gap like
  [[project_clutter_update_never_called]].
- The `/noAi` run's log contains **no worldview/camera/gamemain activity at
  all**, and its only Lua errors are a user mod ('Acu highlight') missing
  `mod_icons.lua` plus the usual `LazyVar` circular-dependency noise - both
  present in retail.

So: the engine side is intact. What is missing is whatever *drives* the focus
after `Reset` — i.e. the session-start UI flow that would call
`Camera:MoveTo`/`SnapTo` with the army start position. Look there next, and
first ask the operator how they launch, since they report the camera *does*
move to the spawn point for them.
