---
name: project_worldcamera_extreme_zoom_looks_like_minimap
description: "Investigated why WorldCamera's own full-screen viewport shows a blue-green mottled/blobby texture resembling the minimap. Camera/viewport-object mixup and a wrong-dimension fog-of-war quad are both REFUTED with concrete evidence. Leading (not 100% closed) explanation: WorldCamera is very likely sitting at CameraReset()'s raw, byte-verified, faithful default (map-centered, GetMaxZoom(), ~60deg pitch) because nothing in the currently-recovered gamedata/lua or src/sdk repositions it at match start - and that exact default was already screenshot-verified last session to render real, correctly-working terrain, which just looks flat/mottled from that height. No source change made; no bug found in an editable file."
metadata:
  type: project
---

## The question investigated

User report (real gameplay session, not a synthetic `/map` test): the small
bordered Minimap panel shows its own already-known flat-blue-fill bug
(separate, not this investigation's concern). But the ENTIRE REST of the
window — which is `WorldCamera`'s own full-screen `CUIWorldView`, per the
"CRITICAL CORRECTION" chapter of
[[project_2026_08_31_ui_fully_works_3d_viewport_still_black]] — shows a
"blue-green mottled/blobby texture" the user says resembles a top-down
fog-of-war/heightmap minimap, "not a normal 3D-perspective world view."

Three hypotheses were assigned: (a) a camera/viewport identity mixup between
`WorldCamera` and `Minimap`, (b) a fog-of-war overlay drawn full-screen with
the minimap's dimensions/UVs, (c) a genuinely different camera projection
(e.g. an observer/no-commander default) that's visually unusual but not
actually broken. This file records what was checked for each, with concrete
evidence, per this repo's citation rules.

## (a) Camera/viewport mixup — REFUTED

- `RCamManager::CreateCamera` (`src/sdk/moho/render/RCamManager.cpp:279-300`)
  always `operator new`s a brand-new `CameraImpl` and placement-constructs it
  — it never looks up or returns an existing camera by name. `WorldCamera`
  and `Minimap` are constructed from two separate `CUIWorldView` ctor calls
  (`UiRuntimeTypes.cpp:20463`, `camManager->CreateCamera(gpg::StrArg(name), ...)`,
  `name` = the Lua-supplied widget name), so they are provably distinct
  `CameraImpl*` objects at every step, not just at construction. This matches
  the independently-gathered live diagnostic already in
  [[project_2026_08_31_ui_fully_works_3d_viewport_still_black]]:
  `ptr=48303800 name=WorldCamera` vs `ptr=48303200 name=Minimap` — two
  different addresses.
- The one other camera-creation call site,
  `WxRuntimeTypes.cpp:70315-70316` (`"Strategic map render camera"`, a 256x256
  viewport), lives inside `WRenViewport::RenderPreviewImage`
  (`WxRuntimeTypes.h:8498`, `WxRuntimeTypes.cpp:70293`) — re-confirmed THIS
  SESSION still `[[maybe_unused]]` with no real caller anywhere in
  `src/sdk` (`grep -n "RenderPreviewImage("` finds only the declaration, the
  `WD3DViewport` override that trivially forwards to it, and the body itself
  — nothing calls the override). It cannot be contributing to what's on
  screen right now.
- Render TARGETS (the actual D3D surfaces) ARE shared per device head across
  every registered `IRenderWorldView`
  (`REN_RenderCartographic`, `WxRuntimeTypes.cpp:69888-69891`:
  `passView->mPrimaryTargetLocks[head]`/`mDepthStencilTargets[head]`, indexed
  only by monitor head, not by view) — but this is normal single-backbuffer
  UI compositing, not a mixup: each view's actual draw calls are scoped to
  its OWN screen rect via `device->SetViewport(&worldViewViewport)`, built
  from THAT view's own `cameraView.viewport.r[3]` (`Cartographic.cpp:2313-2318`,
  `Cartographic::Render`). Confirmed no cross-assignment of one view's camera
  or rect into the other's slot anywhere in this call chain.

## (b) Fog-of-war overlay drawn at the wrong size/UVs — REFUTED

`VisionRenderer.h`/`.cpp`'s `RenderFogOfWar` is not a 2D screen-space quad at
all: it "collects every visible vision circle inside the **camera's terrain
footprint** ... then instance-draws the vision cylinder geometry ... through
the `CastVision` technique" (doc comment, `VisionRenderer.h:115-121`) — real,
camera-relative 3D instanced geometry that projects correctly regardless of
the camera's own zoom/angle, not a fixed-size stretched texture.

There are exactly two call sites, and both pass the CALLER's own camera/view,
not a hardcoded one:
- `WxRuntimeTypes.cpp:70673-70675` — the ordinary per-frame main-view pass,
  gated only on `ren_FogOfWar` (`= true` by default,
  `RuntimeTuningGlobals.cpp:91`) `&& session != nullptr && FocusArmy != -1`,
  using `*runtime->mCam` (that view's own camera). This runs for
  `WorldCamera` every normal frame, same as it always has — it is not new
  and not mis-scoped.
- `Cartographic.cpp:2348`, inside `Cartographic::Render` — receives
  `cameraView` from `worldView->GetCameraView()` (the view passed in by its
  caller) and is drawn only after `device->SetViewport(&worldViewViewport)`
  has already confined the device to that view's own rect
  (`Cartographic.cpp:2338`, using the SAME `cameraView.viewport.r[3]` read at
  line 2313-2318). No path was found where one view's vision geometry gets
  drawn using another view's dimensions.

## (c) Camera projection/mode — LEADING explanation, well-evidenced, not 100% closed

### What's confirmed true right now

1. `CameraImpl::CameraReset()` (`CameraImpl.cpp:1934-1971`, address
   `0x007A80A0`) is byte-verified against ground truth and sets, on every
   camera construction and every explicit reset: `mTargetLocation` = the
   MAP CENTER (`heightField->width/2`, `height/2`) — never a player start
   position — and `mNearZoom = mTargetZoom = GetMaxZoom()`. The prior
   session's own live testing (see "Tried and RULED OUT" chapter,
   [[project_2026_08_31_ui_fully_works_3d_viewport_still_black]] lines
   ~1384-1406) already confirmed this produces a genuinely extreme
   "whole-map-overview" framing: `camPos ~= (512, 772, 971)` on a
   1024x1024 map, i.e. very high up, looking down at roughly 59-60 degrees
   below horizontal (matches `cam_FarPitch = 60.0f`,
   `RuntimeTuningGlobals.cpp:109`, unchanged this session).
2. Exhaustively grepped `gamedata/lua/**` (the real shipped FA/FAF Lua tree —
   not decompiler output, so it should already be authoritative) and
   `src/sdk/**` for every mechanism that ever moves `WorldCamera`:
   explicit hotkeys/UI actions (`usercamera.lua`, `zoomslider.lua`,
   `objectives2.lua` on-demand pings, `ToggleMainCartographicView`),
   split-view settings restore (`worldview.lua:213-219`, only fires on a
   VIEW RECREATE, not first creation), and sim-side
   `Sync.CameraRequests` (`SimCamera.lua`/`usercamera.lua`'s
   `ProcessCameraRequests`). **None of these fire automatically at the
   start of a normal skirmish/multiplayer match.** In particular,
   `CommandUnit.lua`'s `WarpInEffectThread` (the ACU "warp in" sequence —
   read in full, `gamedata/lua/sim/units/CommandUnit.lua:164-196`) contains
   **zero** camera calls of any kind. So even a fully-working commander
   spawn (independent of the already-diagnosed
   [[project_commander_spawn_script_class_resolution_gap]] bug) would not,
   on the evidence gathered, move the camera off this default by itself.
3. Checked the most plausible way this default view could ALSO be pulled
   into the Minimap's own distinctive top-down "cartographic" render style
   (which would have been a genuinely different, findable bug):
   `REN_RenderCartographic` (`WxRuntimeTypes.cpp:69829-69926`, **read-only,
   file is peer-locked**) calls `Cartographic::Render` — which forces
   `ui_AlwaysRenderStrategicIcons = true` and draws terrain + fog-of-war +
   boundary + meshes + decals through a dedicated strategic-view pass — for
   ANY `IRenderWorldView` whose `CanShake()` returns true. An existing,
   already-recovered doc comment (`CRenderWorldView.cpp:222-233`, NOT
   written this session) already explains this precisely: *"Returns the
   stored orthographic toggle - the binary reuses this one byte for both
   lanes, so an orthographic view reports 'can shake'"* — i.e.
   `CanShake() == mOrthographic`. Traced every place `mOrthographic` can be
   set: it zero-inits at construction
   (`UiRuntimeTypes.cpp:20426`, `view->mCanShake = 0` — confirmed to be the
   SAME storage as `CRenderWorldView::mOrthographic`, since
   `CRenderWorldView`'s secondary vtable sits at complete-object offset
   `0x11C` per the RTTI dump and `mOrthographic`'s own offset is `+0x18`
   relative to that subobject, `0x11C + 0x18 = 0x134`, exactly matching the
   ctor-time view's `mCanShake@+0x134`), and afterward changes only via the
   Lua-exposed `CUIWorldView:SetCartographic(bool)`
   (`UiRuntimeTypes.cpp:19988-19999`). Grepped all of `gamedata/lua` for
   every caller of `SetCartographic`/`IsCartographic`: `minimap.lua:119`
   (always sets the MINIMAP's own view true, unrelated), two explicit
   user-toggle paths (`worldview.lua:348-352`'s `ToggleMainCartographicView`
   hotkey function, `multifunction.lua:446-451`'s options-dialog checkbox —
   the checkbox handler is also what persists the choice via
   `Prefs.SetToCurrentProfile(camName.."_cartographic_mode", checked)`), a
   split-view NIS save/restore (`gamemain.lua:955-980`), and the
   profile-restore-on-`Register()` read
   (`gamedata/lua/ui/controls/worldview.lua:1341-1342`).
   **Checked the actual persisted preference this dev machine's dbgrun
   testing uses**
   (`C:\Users\Draiget\AppData\Local\Gas Powered Games\Supreme Commander Forged Alliance\Game.prefs`,
   modified today, single profile `FAF_Draiget`, confirmed via a recent
   real `lastGame` entry against an AI on `Four-Corners`): the ONLY
   "cartographic" key present anywhere in the whole file is
   `WorldCamera2_cartographic_mode = false` (the SPLIT-VIEW second camera,
   line 162) — there is **no** `WorldCamera_cartographic_mode` key at all,
   so `Register()`'s `!= nil` guard never fires for the primary
   `WorldCamera`, and its `mOrthographic` stays at its construction default,
   `false`. **So `WorldCamera` is not going through the Minimap's
   cartographic/strategic render path** — this was a real, concrete,
   checkable candidate bug, and it came back negative.

### What this leaves as the most likely explanation

`WorldCamera` is very likely rendering through the exact same ordinary
terrain pipeline already independently screenshot-verified as WORKING at
the end of the previous session, just at this same extreme, rarely-tested
default zoom/pitch. The previous session's own final verification shot
(`screenshot_dpitest3.png`, taken at this SAME default `CameraReset()` zoom,
same `"Ready for recall"` HUD state, DPI-shim applied) was described as
"real, properly-textured, camera-responsive terrain — coastlines, water
depth gradients — filling the entire WorldCamera viewport, ZERO unexplained
black." An earlier shot at the same zoom
(`screenshot_rectcache1.png`) used almost the user's own words without
knowing it: "shallow-water cyan/teal gradients, deep-water dark blue-black."
Combined with the tessellation being confirmed maximally coarse at this
zoom (`rectCacheCount=20` — the entire 1024x1024 map as one huge quad, see
the "SIXTH fix landed" chapter of
[[project_2026_08_31_ui_fully_works_3d_viewport_still_black]]), real ground
texture at that scale would be minified past recognition into large,
smoothed patches of blue/green — which is a completely ordinary rendering
consequence of extreme zoom-out, not a defect, and would visually read as
"mottled" and "not like normal 3D perspective" to anyone who has never seen
this engine's default start-of-match framing render correctly before (this
project has never had working terrain long enough for anyone to have looked
at what the *default* camera position actually shows, until last session).

### What is NOT closed out

Whether the ORIGINAL 2007 binary/game genuinely leaves the camera at this
raw "whole map" default for any meaningful duration at the start of a real
match, or whether some distinct, still-missing camera-initialization call
(separate from anything commander-spawn-related, since that thread was
traced clean) is supposed to pull the camera in toward the player's own
start position within the first second or two. `gamedata/lua` is the real
shipped Lua tree and should not need "recovery" the way `src/sdk` does, so
if such a call exists in the genuine original it should already be present
here — none was found after a systematic search, which argues for "this is
faithful, expected behavior" over "something is missing" — but this was not
proven by directly comparing against the real original binary's runtime
behavior (`C:\ProgramData\FAForever\bin\ForgedAlliance.exe`, present on this
machine per
[[project_2026_08_31_ui_fully_works_3d_viewport_still_black]]'s DPI-fix
chapter, but launching it into a live comparable skirmish match was not
attempted this session — it needs real lobby/match setup, not just running
the exe). Nor was a live re-test of the CURRENT recovered build attempted
(the existing `main.exe`, built `2026-09-01 02:00`, already reflects all
render-relevant fixes through commit `a15c5cc8`; two later commits,
`545a48bd`/`e79fdd52`, are unrelated quaternion-composition fixes to
`VTransform`/`CD3DPrimBatcher`, not camera/terrain code) — building the
`dbgrun` harness and driving a fresh screenshot was judged out of scope for
a source-archaeology investigation pass and was not started.

## If resuming this

1. **Fastest close-out**: rebuild (ask first, per this repo's build-gate
   rule) is not even required — `main.exe` already reflects everything
   analyzed here. Launch it under the existing DPI shim
   (`HKCU\...\AppCompatFlags\Layers`, already applied, see
   [[project_2026_08_31_ui_fully_works_3d_viewport_still_black]]) into the
   SAME kind of real skirmish the user played (not just `/map SCMP_009`),
   let it sit for 10-20 seconds past match start without touching the
   camera, and screenshot. If it looks like real, perspective-correct,
   if-unusual terrain (matches the coloring/description above), this
   theory is confirmed and the remaining work is purely UX (should
   something snap the camera in at match start — a feature request, not a
   recovery defect) rather than a rendering bug.
2. If that screenshot instead shows something flatter/more literally
   minimap-like than ordinary extreme-zoom terrain (e.g. visibly using
   strategic icons instead of unit meshes, or a visibly different color
   grading than `screenshot_dpitest3.png`), hypothesis (c)'s "just zoom"
   sub-theory is wrong and `mOrthographic` needs re-checking live (add a
   temporary `OutputDebugStringA` probe reading
   `worldViewView->mCamera` and the `CRenderWorldView::mOrthographic`/
   `IsMiniMap()` values for BOTH registered views every frame, per this
   repo's established dbgrun diagnostic recipe) rather than trusting the
   static analysis above.
3. To settle "is this faithful to the original 2007 game", the cleanest
   test is the real, unmodified `ForgedAlliance.exe` in a real skirmish
   (host a local skirmish against an AI, same as the `lastGame` entry
   already in this profile's `Game.prefs`) and watch whether ITS camera
   auto-focuses on anything at match start.

## Not committed

No source change was made. Both concrete, checkable "bug-shaped" leads this
session investigated (camera/render-target identity mixup; WorldCamera
being pulled into the Minimap's own cartographic render path) came back
negative with direct evidence, and no defect was found in an editable file
(`WxRuntimeTypes.cpp`, where the one real piece of relevant logic
— `REN_RenderCartographic` — lives, is peer-locked this session; it was
read only, never edited).
