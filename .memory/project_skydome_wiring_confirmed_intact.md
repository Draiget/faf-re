---
name: skydome-wiring-confirmed-intact
description: "SkyDome (atmosphere/cloud sky rendering) is fully wired end-to-end and NOT an orphan — checked while investigating the remaining ~40% black area after the viewport.r[0] LOD fix (a15c5cc8). Rules out 'sky dome forgotten' as an explanation; does not rule out a bug inside SkyDome's own geometry/culling."
metadata:
  type: project
---

While the primary render-goal investigation (see [[project_2026_08_31_ui_fully_works_3d_viewport_still_black]] — read that file for full context) was chasing why a debug-launch camera framing still shows black past the terrain edge, I independently checked whether `Moho::SkyDome` (atmosphere/horizon/cirrus/cumulus sky rendering, `src/sdk/moho/render/SkyDome.h`/`.cpp`) is actually wired into the render path, since unrendered sky would show as black too.

**Confirmed fully wired, not an orphan:**
- `moho::ren_SkyDome = true` by default (`src/sdk/moho/misc/RuntimeTuningGlobals.cpp:7`) — already committed, not a disabled-by-default kill-switch.
- `WRenViewport::RenderSkyDome()` is called every frame, gated by that flag, right before the terrain composite pass (`src/sdk/moho/app/WxRuntimeTypes.cpp:70540-70541`).
- `SkyDome::SetupHorizonAndCirrus` (dome shape/origin/radius from the loaded map's bounds) is called from `CWldMap.cpp` at two real call sites (lines ~3183, ~4943) as part of map load — not an unreachable stub.
- `RenderSkyDome()` dispatches to `RenderAtmosphere`/`RenderCirrus`/`RenderCumulus`/`RenderDecals`, all real recovered bodies with address citations, not stubs.

**Not yet checked** (didn't go deeper — no specific bug lead found, so didn't want to duplicate the primary agent's active work): whether the dome's actual geometry (`CreateDomeVertexBuffer`'s sphere coverage, `mDomeShapeParams` height/radius/start-angle) genuinely covers the full upward hemisphere the camera could look into from an extreme high-angle "whole map overview" framing, or whether some frustum-culling/technique-selection step inside the render passes silently no-ops in that specific viewing direction. If the zoom-framing hypothesis in the primary memory file turns out NOT to fully explain the remaining black area, this is the next place to look — not "is it wired" (confirmed yes) but "does its geometry/culling actually cover this specific camera angle."

**One concrete data point gathered**: `domeRadius = sqrt(halfExtentX² + halfExtentZ²) / cos(72°)` (`CWldMap.cpp:3175-3177`, real ground-truth-cited formula, XZ half-diagonal of the map bounds divided by cos(72°)). For a 1024×1024 map (`halfExtentX=halfExtentZ=512`): `domeRadius ≈ 512*sqrt(2) / 0.309 ≈ 2343` world units, centered at the map's XZ midpoint with Y=0. If a future check finds the extreme-zoom camera position sits farther than ~2343 units from the map center, the camera would be OUTSIDE the sky dome sphere, which is a concrete, checkable candidate explanation for black past the terrain edge (dome backface-culled or behind the near/far clip in that configuration) — genuinely different from the plain "nothing rendered past the map edge, and that's fine" explanation. Cross-reference against whatever camera distance the zoom experiment measures before concluding either way.
