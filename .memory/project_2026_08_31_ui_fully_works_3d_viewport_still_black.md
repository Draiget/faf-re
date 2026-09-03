---
name: 2026-08-31-ui-fully-works-3d-viewport-still-black
description: GOAL MET, 2026-09-01. Six real fixes landed (1f194c1a, fc463bb1, 2ff1ae34, 06d94b92, 1dba8545, and the keystone a15c5cc8) — the last fixed GeomCamera3::Init's viewport.r[0] LOD row, which used the wrong matrix-vector multiplication convention (point-transform operator instead of matrix-applied-on-the-left via a new shared `DotMatrixRows` helper), root-causing the entire CTesselator over-tessellation saga. PLUS a critical non-code finding: the residual black area after that fix was Windows DPI-virtualization failing to stretch this legacy D3D9 swap chain on this machine's 150%-scaled display — confirmed present in the pristine unmodified original ForgedAlliance.exe too, fixed with a per-machine `HKCU...AppCompatFlags\Layers` "~ HIGHDPIAWARE" registry shim (NOT a source change). With both addressed: real, camera-responsive, fully-textured terrain now renders across the ENTIRE WorldCamera viewport, screenshot-confirmed, default (non-hacked) camera settings, fault=0 dbgrun run. Read the LAST two "2026-09-01" chapters (search "SIXTH fix" and "SOLVED, DEFINITIVELY") first — they supersede all earlier over-tessellation/black-region framing in this file. Remaining open item, explicitly separate from "the black screen": the Minimap panel, as of 2026-09-01, now renders real content but stretched to fill the full primary viewport instead of its own small panel (changed from an earlier flat-blue-fill report). Live-minimap render path traced to WRenViewport::Render's per-world-view loop and its shared/stale mScreenPos viewport field, but the predicted bug direction contradicts the observed symptom - needs a live probe, not more static reasoning. See the last dated chapter, "Symptom changed", before continuing.
metadata:
  type: project
---

## State as of 2026-08-31, ~19:30 (session continuing from a prior compaction)

Standing goal: "untill we can launch map without black screen and rendering will work" (`/map SCMP_009`).

### Landed this session (commits, newest first)

- `ecfc33e0` — null `mHead` crash in `func_GetRightMouseButtonAction` on empty
  selection (CWldSession.cpp). First mouse-move after CreateUI dereferenced
  `wldSession->mSelection.mHead->mLeft` with `mHead == nullptr`; added the
  same guard `SelectionContainsTeleportationUnit` already has.
- `5268e5ec` — two fixes in `UiRuntimeTypes.{h,cpp}`:
  1. `CMauiControl::SetCustomRender`/`GetCustomRender` (a genuine FAF binary-
     patch addition, no 2007 body to recover — implemented for real per
     operator direction). Root cause of `CreateUI` aborting mid-script.
  2. `CUIWorldViewRuntimeView`'s `+0x11C` lane was modeled as a stored
     pointer (`CRenderWorldViewRuntimeHandle`) to a separately-allocated
     `CRenderWorldView`, when it is actually the vtable slot of a real,
     in-place `CRenderWorldView` base subobject (`CUIWorldView : public
     CMauiControl, public CRenderWorldView` — already real inheritance).
     Reading those 4 bytes as a pointer and dereferencing it wrote through
     the vtable address itself into the executable's read-only image
     section. **This fix is functionally correct but architecturally
     redundant** — see "Known follow-up cleanup" below, `CRenderWorldView`
     (UiRuntimeTypes.h:3779) already has `SetOrthographic`/`CanShake`/etc.
     properly declared; the fix should have used
     `static_cast<CRenderWorldView*>(worldView)->SetOrthographic(...)`
     directly instead of the small ad-hoc `CRenderWorldViewRuntimeView`
     struct + `RenderWorldView()` accessor it actually shipped with. Not
     re-done yet — verified working via dbgrun, low priority vs. the black
     viewport.
- `34dfd4af` — `CameraImpl` converted to real C++ multiple inheritance
  (`RCamCamera`, `CScriptEvent`). Full writeup:
  [[thin-class-fake-composition-vs-real-inheritance]]. Root cause of
  `SCR_FromLua_CameraImpl` failing with "Incorrect type of game object" —
  every camera's published Lua object had `typeid(*object) == CScriptEvent`,
  not `CameraImpl`, because the class placement-new'd a *standalone*
  `CScriptEvent` instead of really deriving from it.

### Confirmed via live dbgrun (`/map SCMP_009 //log`, 3 runs this session)

- Run 1 (CameraImpl fix only): 0 "Incorrect type of game object" errors
  (previously present every run). Crashed later in
  `CRenderWorldViewRuntimeView::SetOrthographic` writing into read-only
  memory (the `+0x11C` bug above).
- Run 2 (+ RenderWorldView fix): that crash gone. User confirmed visually:
  "more UI controls, but still black screen behind." New crash: null
  `mSelection.mHead` in `func_GetRightMouseButtonAction`, first mouse-move
  event.
- Run 3 (+ mSelection fix): **137,209 log lines, `cpp=2882` exceptions seen,
  `fault=0`.** Process stayed alive and responsive the whole run (confirmed
  via `Get-Process` mid-run: `Responding = True`). User's screenshot: the
  full escape menu (Save/Load/Options/Key Bindings/Scenario/Restart/End
  Game), the resource bars, and the command palette all render correctly
  and are interactive. **The 3D viewport itself is 100% solid black — no
  terrain, no units, nothing.** User also reported "unknown command X"
  messages appearing on-screen (not found in the `/log` output — this is an
  in-game console/HUD text overlay, not a native log line; not yet
  investigated, likely a separate/minor keybinding-config issue, low
  priority vs. the black viewport).

### Ruled out this run: the water/terrain shader-var throws are BENIGN

`HighFidelityWater::RenderWaterSurface` → `SetShaderVarMem` →
`ShaderVar::Exists()` throws `gpg::gal::Error` internally, many times per
frame (once per shader parameter FAF's `water2.fx` doesn't have —
WaterColor/WaterLerp/FresnelBias/etc., byte-verified absent from the
shipped effect source, not a recovery bug). This looked alarming in the
dbgrun log (hundreds of sequential `[C++ THROW]` entries at increasing
`RenderWaterSurface+0xNN` offsets) but `ShaderVar::Exists()`
(`src/sdk/moho/render/d3d/ShaderVar.cpp:264-290`) already wraps the throwing
call in `try { ... } catch (const gpg::gal::Error&) { return false; }` —
this is already-landed, well-documented, working exception-safety (see the
function's own doc comment for the full history, including a documented
second-order fast-path bug it also fixed). **Do not re-investigate this —
it is confirmed caught and non-fatal**, just noisy in a debugger that logs
first-chance exceptions. Confirmed via the run-wide `fault=0` count: if this
were actually crashing anything, `fault` would be nonzero.

### Confirmed still executing every frame

`RenderAllHeads`/`WRenViewport::Render` appear ~950 times across the run's
captured stack traces (mostly as the frame context around the benign
shader-var throws) — the 3D scene-render entry point IS being called every
frame, not skipped. So the "black screen" is not "render never invoked" —
it's somewhere between "render invoked" and "pixels reach the screen":
camera/viewport transform, actual draw-call issuance, mesh/texture data
availability, or D3D device/render-target state are all still open.

### Extensive PRE-EXISTING history on this exact symptom (read before re-deriving)

**IMPORTANT: this project's memory has TWO locations.** The correct,
authoritative one for new writes is `<project-root>/.memory/` (this file's
own directory) per the global `CLAUDE.md`. A LEGACY location at
`~/.claude/projects/<slug>/memory/` also exists with an overlapping but
NOT-identical set of notes from earlier sessions — some entries only exist
in one location, not both. If a future session's auto-loaded `MEMORY.md`
looks thin or doesn't mention something you'd expect (e.g., months of prior
black-screen investigation), check whether `.memory/MEMORY.md` in the repo
root has more — it did, substantially, when this note was written.

Directly relevant, NOT yet re-checked against current source this session
(check whether each is still open or was superseded by later commits before
trusting it — several already show later "RESOLVED"/"LANDED" follow-ups in
the same index):

- `project_black_screen_is_renderworldview_vtable.md` — the `+0x11C` vtable
  history (superseded by this session's fix, but has useful detail on
  `CRenderWorldView`'s full 13-slot shape).
- `project_terrain_vtable_15_slots.md`, `project_gal_device_vtable_slot_mismatch.md`,
  `project_render_frame_driver_elisions.md`, `project_black_screen_fixed_skydome_next.md`,
  `project_terraincommon_slot5_rendercontext_landed.md`, `project_no_unit_can_be_created.md`,
  `project_black_screen_root_cause.md`, `project_map_launch_and_render_crash.md` —
  all describe various "engine runs fine, 3D view draws nothing" root causes
  found in earlier sessions. Given this session's OWN commit log already
  shows `d0a13b3e` ("Fix terrain vtable corruption and two null-shared_ptr
  crashes blocking map render"), `c0bc4750` ("Fix WRenViewport::Render
  reading a CameraImpl* as if it were a GeomCamera3*"), and `69b7ac6f` ("Fix
  frustum-plane extraction...") already landed BEFORE this compaction, several
  of these older notes are likely already resolved — check `git log --oneline
  --all -- <the file the note names>` before assuming a note's fix is still
  needed.

## FOUND: the world camera's viewport is stuck at its {1,1} unit default (2026-08-31, later)

Added a temporary diagnostic to `MeshRenderer::Batch` (`Mesh.cpp`, right
after `meshSpatialDb.CollectAllInVolume`) logging the collected-instance
count and `camera.viewport.r[3]` (NOT position — see below). Confirmed live:

    [RPDIAG] MeshRenderer::Batch collected=0 camPos=(0.0,0.0,1.0) fwd=(0.00,-1.00,-0.00)

`collected=0` — **every single frame, the frustum-volume query returns zero
mesh instances.** That is the direct, mechanical cause of the black
viewport (there is nothing to submit to the GPU, independent of whether any
draw calls further down would work).

`camera.viewport.r[3]` is **not** camera position — confirmed from
`GeomCamera3.h:271-274` (`MakeViewportPixelProjection`): `.z` and `.w` of
that row are the viewport **width and height in pixels**
(`static_cast<std::int32_t>(camera.viewport.r[3].z)` used directly as
`width`). My probe's third printed number (`1.0`) is `r[3].z` — **the
world camera's viewport width is 1.0**, not some real pixel dimension like
1536. A 1-pixel-wide (and presumably proportionally tiny-height) frustum
volume would cull essentially everything, explaining `collected=0` exactly.

Traced why: `CameraImpl::CameraImpl` (`CameraImpl.cpp:~1655`) unconditionally
sets `CameraSetViewport({0,0}, {1,1})` — an explicit "unit"/normalized
placeholder, per its own comment ("Default unit viewport (origin {0,0},
extent {1,1})"). Grepped every `CameraSetViewport(` call site in `src/sdk`
(3 total): this one, the declaration, and ONE other call
(`WxRuntimeTypes.cpp:70316`) that creates a **separate, temporary "Strategic
map render camera"** for a 256×256 minimap/thumbnail render — unrelated to
the main WorldCamera. **No call site anywhere in the currently recovered
source ever resizes the WorldCamera's viewport from `{1,1}` to real pixel
dimensions** (`device->GetHeadWidth/GetHeadHeight`, confirmed to exist and
be called correctly elsewhere for UI/render-target sizing, e.g.
`WRenViewport::InitDeviceResources` around `WxRuntimeTypes.cpp:70078-70106`
— but that function only touches `IUIManager::OnResize` and D3D render
targets, never a camera).

`func_SetWorldCamera` (`CameraTrackingListener.cpp:138`, called from
`CUIWorldView`'s ctor when `name == "WorldCamera"`) was checked and ruled
out — it only splices the tracking-listener broadcaster node, never touches
viewport size.

**Not yet found: where the ORIGINAL 2007 binary actually resizes the world
camera's viewport.** Strong candidate not yet checked: `worldview.lua`
almost certainly calls some Lua-exposed sizing method on its `WorldView`
control as part of its own layout pass (the `CRenderWorldViewViewportRuntimeView`
struct already has a `SetViewRect(min, max)` virtual call — `UiRuntimeTypes.cpp`
~line 2340 in this session's numbering — dispatched through vtable slot 3;
this looks purpose-built for exactly this "here is my actual on-screen
rect, now go set up the camera to match" role and is a much more promising
lead than a device/window-resize handler). Check:
  1. Whether `SetViewRect` is exposed to Lua at all (grep for its Lua
     binder / cfunc wrapper) and whether `worldview.lua`'s `Register()` (or
     a sibling init function) calls it.
  2. If it IS called, read its real implementation (find the concrete
     `CRenderWorldView`/`IRenderWorldView` override behind vtable slot 3 —
     `CUIWorldView`'s own class, given the multi-level inheritance) and
     check whether it actually reaches `CameraImpl::CameraSetViewport` for
     the correct camera, or stops short (e.g. only updates the 2D UI rect
     fields `mViewLeft/mViewTop/mViewRight/mViewBottom` without ever
     touching the embedded camera).
  3. If `SetViewRect` genuinely never reaches the camera, the fix is
     probably: wire it (or add the missing call) so that whenever a
     WorldView's on-screen rect is set/changed, it also calls
     `mCamera->CameraSetViewport(origin, size)` with the REAL pixel
     rect — matching how `RCamManager::CreateCamera`+`CameraSetViewport({1,1})`
     is clearly meant to be a placeholder immediately superseded once the
     view's actual screen geometry is known, not a permanent 1×1 camera.

## FOUND (more precisely): `mViewportCallback` is the actual break point, not confirmed how to fix yet

`CUIWorldView::DoRender` (`UiRuntimeTypes.cpp:22616-22648`, vtable slot 6,
the real `DoRender` override — this IS being called, drawMask==1 fires
every frame) contains the exact mechanism that should push a resized
on-screen rect down to the camera:

```cpp
if (drawMask == 1) {
  const float left/top/right/bottom = CScriptLazyVar_float::GetValue(&worldViewView->mView{Left,Top,Right,Bottom});
  if (/* changed from cached */) {
    CRenderWorldViewViewportRuntimeView* const viewport = worldViewView->mViewportCallback;
    if (viewport != nullptr) {
      viewport->SetViewRect({left, top}, {right, bottom});   // vtable slot 3 dispatch
    }
  }
  return;
}
```

`mViewportCallback` (`CUIWorldViewRuntimeView`, `UiRuntimeTypes.cpp:2411`,
offset `+0x120`) is declared `= nullptr` and **is never assigned anywhere
else in `src/sdk`** (confirmed: `grep -rn "mViewportCallback\s*="` finds only
the one declaration). If it is genuinely always null, this whole
resize-refresh block is dead — `SetViewRect` never fires, and the camera's
viewport stays at `CameraImpl`'s constructor default `{1,1}` forever. This
would fully explain the `collected=0`/`width=1.0` finding above.

**Complication, not yet resolved — do not assume the simple "always null"
story without checking this first:** `CUIWorldViewCtorRuntimeView` (the
constructor's own, `.asm`-verified struct, `UiRuntimeTypes.cpp:2539-2593`)
places **`moho::CameraImpl* mCamera`** at the exact same offset, `+0x120`.
Both structs are `reinterpret_cast`-style views over the same `CUIWorldView`
instance, so `mViewportCallback` and `mCamera` may be reading the *same 4
bytes* under two different types/names — in which case `mViewportCallback`
would NOT be null once the constructor's `view->mCamera = camera;` runs
(only null in the brief window before that line executes), and the
`SetViewRect` call WOULD be firing every frame, just against the wrong
type: a `CameraImpl*` being treated as a `CRenderWorldViewViewportRuntimeView*`
and vtable-dispatched through slot 3 as if it were `SetViewRect`.

Checked whether that reinterpretation could accidentally be *correct* (i.e.
whether `CameraImpl::CameraSetViewport` really is what ends up called) —
**ruled out**: `CameraSetViewport`'s mangled name
(`?CameraSetViewport@CameraImpl@Moho@@QAE...`, `CameraImpl.h:592`) has the
`QAE` calling-convention tag, which is **non-virtual**. It has no vtable
slot at all, so there is no slot index at which `CameraImpl`'s real vtable
could coincidentally line up with `CRenderWorldViewViewportRuntimeView`'s
`SetViewRect` (slot 3). If `mViewportCallback` really does alias `mCamera`,
the `viewport->SetViewRect(...)` call is dispatching through whatever
`CameraImpl`'s OWN vtable slot 3 actually is (need to check post this
session's `CameraImpl` real-inheritance conversion, `commit 34dfd4af` — its
vtable layout changed) with the wrong `this` and wrong argument
interpretation. That is either silently doing nothing useful, or corrupting
something without an immediately-visible crash (the 137K-line dbgrun run
had `fault=0`, so if this is happening it is not faulting outright).

**Next step, in order, before writing any fix:**
  1. Determine definitively whether `mViewportCallback`/`mCamera` really do
     alias the same 4 bytes — dump `CUIWorldView`'s real layout from the
     RTTI/vtable evidence (`rtti_dump_all` per this project's existing
     recipe) rather than trusting either recovered struct's offset
     comments blindly; the two structs disagreeing on one offset is
     exactly the kind of thing worth re-deriving from raw evidence.
  2. If they DO alias: `mViewportCallback` as a concept is a fabrication —
     `CRenderWorldViewViewportRuntimeView` should not exist as a separate
     type at that offset, `DoRender`'s `SetViewRect` call is dead/wrong
     code, and the REAL fix is almost certainly to call
     `mCamera->CameraSetViewport({left, top}, {right - left, bottom - top})`
     directly (a normal, non-virtual, already-recovered call) instead of
     the vtable-dispatched `SetViewRect` — matching the exact
     origin/extent argument shape `CameraSetViewport` already takes
     elsewhere (see the `{0,0}`/`{1,1}` construction-time call and the
     `{0,0}`/`{256,256}` strategic-camera call, both cited above).
  3. If they do NOT alias (i.e. `CRenderWorldViewViewportRuntimeView` is a
     real, distinct object elsewhere): find what actually should be
     constructing/assigning `mViewportCallback` and wire it — likely
     something constructed alongside the camera in `CUIWorldView`'s own
     ctor, given `IRenderWorldView`'s slot-3-shaped interface strongly
     resembles a small viewport-delegate object.

This is a genuinely delicate area (two sibling recovered structs disagree
on one field's type at a shared offset, in code that already carries scars
from at least one prior "vtable slot" mismodeling bug this same session —
see the `CRenderWorldViewRuntimeHandle` fix, commit `5268e5ec`, which was
exactly this same failure mode: a stored pointer where the binary has an
in-place vtable slot). Verify against raw evidence before editing rather
than guessing between the two stories above.

### RTTI dump evidence pulled (2026-08-31, later still) — narrows this a lot

`dumps/rtti_dump_all.hpp:54005-54048` has `CUIWorldView`'s real, complete
RTTI: full base list (`CMauiControl, CScriptObject, gpg::RObject,
WeakObject, noncopyable, ..., IRenderWorldView`) and BOTH its vtables:

```
// Primary vftable (25 entries)                          -- CMauiControl-rooted
// Secondary vftable at subobject offset 284 (13 entries) -- IRenderWorldView-rooted, 284 == 0x11C
/*virtual*/ void vf_sub284_00(); // 0x86EE00   slot 0
/*virtual*/ void vf_sub284_01(); // 0x86ECB0   slot 1
/*virtual*/ void vf_sub284_02(); // 0x86ECD0   slot 2
/*virtual*/ void vf_sub284_03(); // 0x86EBF0   slot 3   <-- this one
/*virtual*/ void vf_sub284_04(); // 0x86EBE0   slot 4
...
/*virtual*/ void vf_sub284_12(); // 0x86DC60   slot 12
```

Slot 3 of the secondary (`+0x11C`) vtable is **`0x86EBF0`**, which is
already recovered and cited by name elsewhere in this same session's
reading: `CRenderWorldViewRuntimeView::GetCamera()`
(`"Address: 0x0086EBF0 (FUN_0086EBF0, Moho::CRenderWorldView::GetCamera)"`).

**So slot 3 of `CUIWorldView`'s own `+0x11C` vtable is `GetCamera`, not
`SetViewRect`.** This directly rules out the "mViewportCallback aliases
mCamera and gets vtable-dispatched through CUIWorldView's own +0x11C
vtable" story — if that were happening, slot 3 would resolve to
`GetCamera`, called with `SetViewRect`'s argument shape
(`this, &minPoint, &maxPoint`) instead of `GetCamera`'s (`this` only) —
which would be its own distinct bug, but the RTTI proves this ISN'T what a
correctly-typed call would even reach, because `mCamera` is a `CameraImpl*`
whose OWN vtable (not `CUIWorldView`'s) is what a real virtual dispatch
through a `CameraImpl*`-typed pointer would use — CUIWorldView's `+0x11C`
vtable is irrelevant to that pointer entirely. (The earlier concern about
"which vtable does a CameraImpl* actually dispatch through" was the right
question; this paragraph is what settles it: whichever vtable it is, it
is NOT the one `CRenderWorldViewViewportRuntimeView::SetViewRect`was
theorized to coincidentally match.)

Also notable: `CRenderWorldViewViewportRuntimeView` (the struct
`mViewportCallback` is typed as) dispatches `LODMetric` through `table[35]`
— a slot index far beyond `CUIWorldView`'s 13-entry secondary vtable, and
also not matching `CameraImpl::LODMetric`'s documented "Slot: 45" (that gap,
10 slots, might just be `RCamCamera`+`CScriptEvent`'s own virtuals occupying
slots 0-9 ahead of CameraImpl's own — not verified). Either way,
**`CRenderWorldViewViewportRuntimeView` is a vtable shape with at least 36
slots and is definitively NOT the same object as `CUIWorldView`'s own
13-slot `+0x11C` vtable** — it must be a genuinely separate object.

**Next step is now narrower**: find what real engine object has a 36+-slot
vtable with `CameraName`/`SetViewRect`/`CameraGetOffset`/`CameraGetTargetZoom`/
`LODMetric` at slots 1/3/18/19/35 — grep `rtti_dump_all.hpp` for a
`vftable@` block with >=36 slots whose slot 3 target is a function already
recognizable as a viewport/rect setter (read its `.c` — a 2-Vector2f-arg
function is a strong, checkable signature), and cross-check slot 1's
target against something plausibly named/shaped like a camera-name
accessor. That object is what `mViewportCallback` should point to, and
wiring up where/how it should be constructed (or found) and assigned is
the actual fix.

## Viewport fix landed (`dbd113aa`) and runtime-verified for stability, NOT yet for visible 3D content

Rebuilt clean and ran `/map SCMP_009 //log` with the `mCamera`/`CameraSetViewport`
fix in place. **134,462 log lines, zero `EXCEPTION` entries, process alive
and responsive the whole run** — this is a genuine, major improvement:
crash-free well past every previous session crash point, confirming the
fix introduced no regression and the underlying mechanism (real
`CameraSetViewport` call replacing the broken vtable dispatch) is sound.

**Screenshot at this point still shows a black panel** — but it is a
*different* UI element than the escape-menu screenshot earlier in this
session: a bordered panel with its own pin/expand/close controls in the
corner, roughly centered-left, NOT the full-window background the escape
menu was drawn over. `grep`ing the run's log for `MapPreview`/
`CUIMapPreview` found nothing, so this is not confirmed to be the map-
preview dialog (`SCR_FromLua_CUIMapPreview`, referenced elsewhere in
`UiRuntimeTypes.cpp`) — but the distinct bordered/closable chrome makes it
look more like a sub-dialog than the primary full-viewport `CUIWorldView`.
**Not yet determined**, and worth settling before further chasing: is this
panel the WorldCamera's own `CUIWorldView`, or an unrelated dialog sitting
on top of an unconfirmed background? Screenshot saved at
`<scratchpad>/screenshot_viewportfix.png` for this session; a fresh one
should be taken and compared directly against the escape-menu screenshot's
window layout before assuming they're the same element.

**Most likely explanation for the fix not (yet) producing visible content:**
the `DoRender` code path this session's fix repaired only *acts* on a
change — `if (worldViewView->mCachedViewLeft != left || ...)`. If
`worldview.lua` (or whatever Lua-side code is responsible) never actually
*writes* new values into `mViewLeft`/`mViewTop`/`mViewRight`/`mViewBottom`
in the first place, the cached defaults never differ from the lazy-var
reads, the `if` never becomes true, and `CameraSetViewport` never fires —
meaning this fix is necessary but may not be sufficient on its own if the
Lua-side trigger for the resize is itself missing or not wired to run for
the main world view. **Next step**: find what in `worldview.lua` (or its
callers) is supposed to set `mViewLeft`/`Top`/`Right`/`Bottom` for the
*main* WorldCamera specifically (not just the minimap, which may have a
separate/working path already, explaining why this bug went unnoticed for
so long if the minimap always worked) — grep the Lua side for wherever
these four properties get assigned, and confirm it actually executes for
the primary world view instance during this `/map` launch, not just cached
at some default.

**Correction, checked immediately after writing the above**: grepped the
full deployed Lua tree (`gamedata/lua/ui/`) for `ViewLeft`/`ViewRight`/
`ViewTop`/`ViewBottom` by name — zero hits anywhere. So this is very
unlikely to be a "worldview.lua pushes a value" mechanism at all.
`CScriptLazyVar_float` is a *lazy-pull* property type (per this session's
own established understanding): the C++ side's `GetValue` call is what
triggers evaluation, not a Lua-side push/set. That means these four fields
are far more likely computed on-demand from the control's own UI layout
geometry (parent anchoring/sizing, the same generic mechanism that
correctly positions every other on-screen panel — proven working, since
the escape menu, resource bars, and this new bordered panel all render at
plausible, correctly-laid-out positions). If so, the values reaching
`DoRender` should already be correct once layout has run at all, and the
open question shifts to timing/ordering (does `DoRender`'s drawMask==1
pass run AFTER layout has produced real numbers, or could it still be
reading pre-layout defaults the first several frames) rather than "is
something failing to push a value." Verify by instrumenting the `left/top/
right/bottom` values themselves (a simple `OutputDebugStringA` in
`DoRender`, temporary, matching this session's established diagnostic
pattern) before assuming either story — this was not done before this
session's budget ran out and is the single fastest way to settle it.

## DEFINITIVE (2026-08-31, later still): `CUIWorldView::DoRender` is never called at all

Two diagnostic passes, both reverted (not committed, tree is clean):
1. A probe inside `DoRender`'s `drawMask == 1` branch: zero hits across a
   103,685-line run.
2. A probe moved to fire **unconditionally at the top of `DoRender`**,
   logging `drawMask` for the first 8 calls regardless of value: **still
   zero hits, across a 104,360-line run.** This rules out "it's called with
   a different drawMask" — the function is not entered at all, for any
   argument.

This is NOT a missing-`override` bug (the historical pattern this
project has hit before, see [[project_maui_render_slot_not_override]]) —
`CUIWorldView::DoRender` at `UiRuntimeTypes.h:4112` is correctly declared
`void DoRender(CD3DPrimBatcher*, std::int32_t) override;`, vtable slot 6
(+0x18), matching the RTTI-confirmed slot from earlier in this
investigation. The override is real and correctly wired; it is simply
never reached by a caller.

Found the one and only caller: `CMauiFrame::RenderChildControls`
(`UiRuntimeTypes.cpp:24215`, address `0x007870F0`) iterates
`frameView->mRenderedChildren` — a **cached list**, not a live tree walk —
and calls `childControl->DoRender(...)` only for entries in that list
(also gated by `(drawMask & childView->mRenderPass) != 0` and
`!childControl->IsHidden()`). If `CUIWorldView` is never *in*
`mRenderedChildren`, `DoRender` is never called for it, full stop —
independent of the viewport/camera fix, independent of `mRenderPass`,
independent of hidden state.

Traced how `mRenderedChildren` gets populated:
`RebuildRenderedChildrenLane` (`UiRuntimeTypes.cpp:1802`) does a full
`DepthFirstSuccessor` walk from a subtree root, adding every non-
`mInvisible` control it finds. Its one caller is `CMauiControl::Render()`
(`UiRuntimeTypes.cpp:24165`, address `0x00786FA0`), which only rebuilds
the lane when `depthChanged || rootHierarchy->mInvalidated`:

```cpp
void moho::CMauiControl::Render()
{
  if (rootView->mInvisible) return;
  const bool depthChanged = RefreshDepthLaneForSubtree(this);
  if (!depthChanged && !rootHierarchy->mInvalidated) return;   // <-- early-out
  RebuildRenderedChildrenLane(this);
  SortRenderedChildrenByDepth(rootView->mRenderedChildren);
  ...
}
```

**Next step, not yet done — this is the concrete, bounded thing to check
first:** determine whether `mInvalidated` gets set on the relevant parent
frame when `CUIWorldView` is constructed/parented mid-session (during
`CreateUI`, well after the frame's initial `Render()` calls have already
run and presumably already returned via the early-out with
`depthChanged == false` on a settled UI). If the invalidation flag isn't
set on control-add — or if `RefreshDepthLaneForSubtree` doesn't detect a
newly-added child as a depth change — `Render()` keeps early-out'ing
forever and `mRenderedChildren` never gets rebuilt to include the new
`CUIWorldView`, even though it's a legitimate, correctly-constructed,
correctly-parented child. This would explain everything observed this
session in one shot: crash-free, stable engine; escape menu and every
*pre-existing* UI element rendering correctly (they were already in the
list before whatever triggered the last rebuild); `CUIWorldView`
specifically never drawing, no matter how correct its own `DoRender`,
camera, or viewport logic is, because it's simply never *called*.

Grep for wherever a control gets added as a child (`ListLinkBefore`/
`AddChild`-style calls near `CUIWorldView`'s own construction path in
`CUIWorldView.cpp`'s ctor or its caller `CreateMainWorldView`) and check
whether it also marks the parent frame's hierarchy `mInvalidated = true`.
If not, that single missing flag set is very likely the actual, final
root cause of the black viewport — everything found and fixed earlier
this session (CameraImpl RTTI, the CRenderWorldView vtable-as-pointer
crash, the null-selection crash, the camera viewport resize) was all real
and necessary, but this invalidation gap would be why none of it ever
became visible.

### Confirmed the shape of the gap (out of budget to fix this session)

Read `CMauiControl`'s own constructor (`UiRuntimeTypes.cpp:~23655-23684`).
It does:

```cpp
hierarchyView->mParent = parent;              // this control's OWN parent pointer set
...
hierarchyView->mInvalidated = true;           // THIS control's own flag, not the parent's
```

**The parent's `mInvalidated` is never touched here.** Only the freshly-
constructed control's own flag is set. Since `Render()`'s rebuild gate
checks `this->mInvalidated` (i.e. the frame being rendered, not each
child), and nothing in the constructor snippet reaches up to set the
*parent's* flag, a child added after the parent frame's UI has already
settled (exactly `CUIWorldView`'s situation — created well into `CreateUI`,
after the root frame's initial `Render()` passes) would never trigger a
rebuild of the parent's `mRenderedChildren` unless something else
(`RefreshDepthLaneForSubtree` detecting a depth change some other way, or
a separate explicit "add child" helper this session didn't find yet) sets
it. **Not yet found**: the actual `AddChild`/list-link call that parents
`CUIWorldView` under its root frame, and whether *that* function (as
opposed to the plain constructor) is where parent invalidation should
happen but doesn't. That is the precise next thing to read — start from
`CreateMainWorldView` or wherever `CUIWorldView`'s constructor's `parent`
argument is supplied, and follow forward to find the actual list-insertion
call, not backward from the constructor.

## MAJOR CORRECTION (2026-08-31, later still): the "DoRender never called" / "mInvalidated gap" chapter above is WRONG — both were re-investigated with fresh, rigorous diagnostics and REFUTED

A full new diagnostic pass (4 build/run cycles, ~10 distinct temporary probes, ALL
reverted — tree is clean, `git diff` on `UiRuntimeTypes.cpp`/`CUIManager.cpp` is
empty, `WxRuntimeTypes.cpp` diff is back to exactly its pre-existing 1064-line
uncommitted state) definitively closed out the two leads the previous chapter left
open, and found the block is one level deeper than either. **Read this chapter, not
the "DEFINITIVE: DoRender is never called" one above it — that finding does not
hold on the current tree** (most likely explanation: it was true against an OLDER
build state before some of this session's earlier fixes landed; DO NOT re-open it
without fresh evidence).

**Verified, in order, all TRUE (do not re-derive any of these):**

1. **The constructor's intrusive-list linking is correct.** Added a check to the
   CUIWorldView-ctor parent-chain dump that walks `FirstChildControl`/
   `NextSiblingControl` (the SAME primitives `DepthFirstSuccessor` uses) at every
   hop from `this` up to the root frame. Every hop reported `LIST-LINKED` — the
   base `CMauiControl` ctor's `hierarchyView->mParentList.ListLinkBefore(&parentView->mChildrenList)`
   (already-recovered code, `UiRuntimeTypes.cpp` ctor body) genuinely, correctly
   links every new child into its parent's children list. This is NOT the bug.
2. **The "missing parent invalidation on construct" theory is a red herring.**
   Confirmed via `.asm` (`FUN_007867B0.asm`, the ctor) that the ORIGINAL BINARY's
   constructor never calls `Invalidate()` (no `call 0x00786AA0`, no inlined
   loop-over-`mParent` pattern — only a single `mov byte ptr [esi+0E8h],1` for
   `this`'s own flag). `Invalidate()`'s only 4 real callers, confirmed via
   `FUN_00786AA0.xrefs.txt`: `SetParent` (x2) and `~CMauiControl`/`Destroy`. This
   is faithful, correct behavior, not a recovery gap — the actual reason new
   children still get picked up is that the relevant ROOT FRAME's own
   `mInvalidated` was independently `true` at the moment being checked (confirmed
   live: every ancestor in the CUIWorldView ctor-time chain dump — mapGroup,
   GameMain ScreenGroup, the owning "frame" itself — showed `invalidated=1` at
   that exact moment) and/or something else in the same tick re-invalidates it.
   **Do not add an `Invalidate()` call to the constructor** — it is not in the
   binary and the mechanism works without it.
3. **A full walk-trace proves the render-child tree walk is structurally
   healthy and reaches the CUIWorldView subtree.** Instrumented
   `RebuildRenderedChildrenLane` to log the owning frame's full direct-child list
   AND every node visited by the `DepthFirstSuccessor` walk (capped, 3-5 calls on
   the second distinct root seen). Confirmed: `hasWorldViews`/`Render()` DOES
   fire repeatedly on the CORRECT frame after `CUIWorldView` construction (NOT
   just once at startup) — 6+ separate invalidate→rebuild cycles observed AFTER
   the CUIWorldView ctor ran, each visiting ~597-599 real nodes (this is a live,
   healthy, substantial tree walk, not a truncated/dead one). `GameMain
   ScreenGroup` IS the frame's direct child #2; walking its subtree reaches
   `mapGroup` at visit #153, and the very next visit (#154, same pointer as the
   CUIWorldView instance) is `CUIWorldView` itself.
4. **The actual reason the earlier "search for 'World View' found nothing"
   diagnostic came up empty: the control's own debug name gets renamed after
   construction.** At `CUIWorldView` ctor time `mDebugName == "World View"`
   (matches the literal string passed to the base ctor). By the time the tree
   gets walked during rendering, THE SAME POINTER's `mDebugName` reads
   `"WorldCamera"` instead — Lua (or later C++) renames it, presumably via
   `SetDebugName`-style code, sometime between construction and the first
   render pass. **This was never a missing/orphaned control — it was a stale
   search string.** Any future diagnostic on this control must search by
   substring (`strstr(name, "World")`) or by pointer identity, never by the
   exact construction-time name.
5. **`CUIWorldView::DoRender` DOES fire, every frame, both draw-mask passes.**
   Re-instrumented it fresh (unconditional entry probe): `drawMask=1` and
   `drawMask=8` alternate every tick, 20/20 captured calls. The
   `[Chapter above] DEFINITIVE: never called` finding is SUPERSEDED — do not
   trust it without re-deriving.
6. **CRITICAL, previously-undocumented finding: `DoRender`'s `drawMask != 1`
   branch does NOT draw the 3D scene at all.** Its entire body for that case is:
   ```cpp
   const std::uint32_t overlayToken = worldViewView->mOverlayDrawToken;
   if (overlayToken != 0u && overlayToken != 4u) {
     auto* const overlay = reinterpret_cast<CUIWorldViewOverlayRuntimeView*>(
       static_cast<std::uintptr_t>(overlayToken) - 4u);
     overlay->Draw(primBatcher);
   }
   ```
   This is a MAUI-level 2D **overlay** draw (build-preview ghosts, selection
   boxes) layered ON TOP of the 3D scene — it is NOT how the terrain/units get
   drawn. `DoRender`'s call/no-call status is **irrelevant to whether the 3D
   world is visible**. The real 3D draw path is entirely separate: `IRenderWorldView`
   (the `+0x11C` secondary vtable), registered via `ren_Viewport->AddWorldView(...)`
   at construction, driven every frame by `WRenViewport::RenderAllHeads()` →
   `WRenViewport::Render(head, worldViewVector)` (`WxRuntimeTypes.cpp:~70417`,
   NOT anywhere in `UiRuntimeTypes.cpp`). **All future investigation of "is the
   3D scene rendering" must instrument this path, not `CUIWorldView::DoRender`.**
   This single misunderstanding is why the entire prior "DoRender never called"
   chapter was chasing the wrong function.
7. **The REAL 3D pipeline's registration, camera, and terrain are ALL
   confirmed healthy, live, on the current tree — re-verify before assuming any
   of these are broken again:**
   - `AddWorldView` is called (3 times observed — 2 CUIWorldView ctors +1 extra
     registration, depths 1/2/2), `mWorldViews` ends up non-empty, and the
     registered entry's `head` field (from `rootFrameView->mTargetHead`) matches
     the `head` argument `WRenViewport::Render` is invoked with — confirmed live
     (`hasWorldViews=1`, `entry head=0 view=<ptr> matchesThisHead=1`).
   - `worldView->view->GetCamera()` returns non-null; `runtime->mCam` (via the
     already-fixed `CameraGetView()` accessor, not the old vtable-as-pointer
     bug) resolves to a real `GeomCamera3&`.
   - The camera's world position is SANE: `pos=(512.00, 17.50, 1395.27)` —
     centered on a plausible map coordinate, reasonable eye height. NOT the
     historical `(31219, ...)` type-confusion garbage, NOT zero/NaN.
   - The camera's viewport is CORRECTLY sized: `viewportW=1024.00
     viewportH=768.00` (a real window resolution) — confirms the `dbd113aa`
     `CameraSetViewport` fix from earlier this session is holding and working;
     it is NOT stuck at the old `{1,1}` unit placeholder that caused the
     original `collected=0` symptom documented further up this file.
   - `entry.terrain` (an `IRenTerrain` created via `IRenTerrain::Create()`) is
     non-null, and `entry.terrain->Create(REN_GetTerrainRes())` returns `true`
     (success) — `REN_GetTerrainRes()` is already non-null (a real, loaded
     terrain resource pointer, same address across all 3 registrations) at the
     exact moment `AddWorldView` runs. **The "terrain resource not loaded yet
     at registration time" hypothesis is refuted.**
8. **Despite all of the above being confirmed healthy, the viewport is STILL
   solid black.** Verified via a MORE RELIABLE screenshot technique than this
   session used earlier (see operational note below) — the 2D UI chrome (order
   buttons, resource bars, "Ready for recall") renders correctly on top of a
   still-100%-black bordered panel.

### Operational note: screenshot capture reliability on this machine

The earlier `SetForegroundWindow` + `CopyFromScreen` technique (used
successfully earlier this session, and documented as the standard approach in
`project_render_goal_first_frame_confirmed.md`) **silently captured the WRONG
window** this time — a browser tab that happened to be topmost, NOT the game —
even though `SetForegroundWindow` and the `AttachThreadInput` focus-stealing
workaround both returned success/no-error. `GetForegroundWindow()` verified
AFTER the attempt showed the actual foreground window was still something
else entirely; Windows silently ignored the foreground-switch request. This
machine has enough concurrent windows/apps that relying on Z-order + focus for
a game screenshot is unreliable. **Use `PrintWindow(hwnd, hdc, PW_RENDERFULLCONTENT
/* =2 */)` instead** — it captures the target window's own rendered content
directly from the DWM, independent of focus or Z-order, and was confirmed
working for this D3D9+wxWidgets window (correctly captured the 2D UI chrome).
Prefer `PrintWindow` with flag `2` over `CopyFromScreen` for all future
screenshot verification in this project unless there's a specific reason to
capture the literal screen buffer.

### Next step: the gap is now isolated to the actual D3D draw calls inside `WRenViewport::Render`'s per-view loop

Everything upstream of the draw calls themselves (registration, camera, terrain
resource, viewport sizing) is confirmed correct. The remaining unknown is
strictly within `WRenViewport::Render`'s per-view body
(`WxRuntimeTypes.cpp:~70536` onward): `RenderSkyDome()`, `terrain->UpdateRenderContext(...)`
→ `RenderTerrainNormals`/`TransformTerrainNormals`/`RenderFrameShadows`/
`RenderCompositeTerrain`, `MeshRenderer::Batch(...)` → `RenderReflections`/
`RenderMeshes(0x14,...)`/`RenderEffects`/`RenderMeshes(0x18,...)`, `RenderWater`,
etc. **The most direct, already-partially-done next check**: the very first
diagnostic that started this whole investigation (further up this file, "FOUND:
the world camera's viewport is stuck at its {1,1} unit default") measured
`MeshRenderer::Batch`'s collected-instance count and found `collected=0` — but
that was measured BEFORE the viewport-size fix (`dbd113aa`) landed and BEFORE
this session's confirmation that the viewport is now correctly `1024x768`. **Re-run
that exact `MeshRenderer::Batch` collected-count probe now** — with a correctly-
sized viewport and a sane camera position, the frustum-volume query may now
legitimately be returning non-zero instances (in which case the bug is further
downstream, in the actual draw submission / D3D state / shader binding), or it
may still return 0 (in which case the bug is in the frustum/spatial-query itself,
or the spatial DB has no data for this map yet at this point in loading). This
is a fast, cheap, already-proven diagnostic technique (temporary probe in
`Mesh.cpp` right after `meshSpatialDb.CollectAllInVolume`) — do this before
inventing a new one.

## ROOT CAUSE FOUND (2026-08-31, later still): `camera.solid2`'s frustum planes never enclose the camera's own position — DB is populated, camera/viewport are sane, `collected` is STILL always 0

Ran the `MeshRenderer::Batch` collected-count re-check the previous chapter
called for. Result: **`collected=0` at EVERY sample, including sample #600 of
a longer-running probe** (viewport `1024x768`, camera position stable at
`(512, 17.5, ~1395)`, matching the confirmed-healthy state from the previous
chapter). This rules out "was measured before the viewport fix" — the bug is
real and independent of that fix.

**Ruled out `meshSpatialDb` being empty**: instrumented
`SpatialDB_MeshInstance::Register` (`Mesh.cpp:4127`) — confirmed **100,000+
calls**, all against the same `storage` pointer, well before and throughout
`MeshRenderer::Batch`'s sampling window. The spatial DB genuinely has data.

**Found the actual defect** by instrumenting `camera.solid2` (the
`CGeomSolid3` frustum volume `CollectAllInVolume` culls against) directly:

1. `solid2.planes_.Size()` is `6` (a complete, structurally normal frustum),
   and every plane's normal is a real unit-ish vector with a real constant —
   NOT a degenerate/zero frustum.
2. Direct empirical test using the SAME public API the real code calls
   (`CGeomSolid3::Intersects(const AxisAlignedBox3f&)`):
   - A box spanning `±100000` on every axis (should trivially intersect ANY
     reasonable frustum near the origin/scene): **`Intersects → true`**.
   - A `±50`-unit box centered at the camera's OWN CURRENT position
     (`camera.tranform.pos_`, the same field independently confirmed sane):
     **`Intersects → false`, consistently, across 10 samples with a stable
     camera position.**
   - **The frustum is validly shaped but is not positioned/oriented around
     where the camera actually is.** It is either stale (frozen from
     construction/an early frame) or built from a transform that doesn't
     match `tranform.pos_`.

**Traced the full update chain and confirmed it SHOULD be running every
frame, unconditionally** — this is not a "nobody calls it" bug like the
earlier chapters' dead ends:
- Main loop (`CScApp.cpp:1074`): `moho::CAM_GetManager()->Frame(simDeltaSeconds, frameSeconds);`
  runs every tick, no gate, right between `WLD_Frame` and `REN_Frame` (so
  camera state updates before the same frame's render reads it).
- `RCamManager::Frame` (`RCamManager.cpp:259`) iterates every camera in
  `mCams` and calls `camera->Frame(simDeltaSeconds, frameSeconds)`.
- `CameraImpl::Frame` (`CameraImpl.cpp:3190`) calls `UpdateTargets` →
  `UpdateBasis`/`InterpolateBasis` → **`UpdateCoords(interpolationAlpha, frameSeconds)`**
  (line 3219) → `CacheCameraFrustumUnits`.
- `CameraImpl::UpdateCoords` (`CameraImpl.cpp:3627`) builds a fresh
  `viewTransform`/`projection` (perspective branch uses
  `moho::VEC_D3DProjectionMatrixFOV(...)`, correctly incorporating
  `mVerticalZoomMetricScale` — the aspect ratio the viewport-size fix
  correctly updates) and calls **`runtime->mCam.Init(viewTransform, projection)`**.
- `GeomCamera3::Init` (`GeomCamera3.cpp:924`) sets `tranform = viewTransform`
  (confirmed correct — this is the field read as "sane camera position"),
  builds `view`/`inverseView`/`viewProjection` from it, and rebuilds BOTH
  `solid1.planes_[i] = BuildNormalizedPlane(kClipSpaceFrustumPlanes[i], projection)`
  and `solid2.planes_[i] = BuildNormalizedPlane(kClipSpaceFrustumPlanes[i], viewProjection)`
  for all 6 planes, every call.
- Confirmed `CUIWorldView` creates its camera via
  `camManager->CreateCamera(...)` (`UiRuntimeTypes.cpp:20448`) — the same
  `RCamManager`-registering path every other camera uses, so it IS one of
  the cameras `RCamManager::Frame` iterates. Not an unregistered-camera bug.

**So structurally, every link in the chain looks right, and still runs every
frame** — yet the empirical test proves `solid2` doesn't track the camera.
Read `BuildNormalizedPlane` (`GeomCamera3.cpp:130`) itself: its own doc
comment documents that THIS EXACT function had a row/column matrix-transform
bug already found and fixed this session (matches commit `69b7ac6f`,
"Fix frustum-plane extraction using wrong matrix combination") — the comment
describes the identical class of symptom ("made the tesselator's root-tile
frustum test reject the whole terrain every frame") but attributes the
PRIOR occurrence to a different consumer (the terrain tesselator, not
`MeshRenderer::Batch`'s mesh-instance culling). **The current code is the
POST-FIX version** (uses the correct per-row dot-product formula, not the
point-transform operator) — re-verified by reading it, it looks
mathematically right for extracting a world-space plane from a combined
view-projection matrix (standard Gribb/Hartmann technique). Also checked
`VTransform::Inverse()` (`VTransform.cpp:239`) — the quaternion-conjugate +
rotate-negated-position formula is the textbook-correct rigid-transform
inverse, not obviously wrong either.

**Not yet found**: the exact remaining defect. Candidates not yet
individually verified, in rough priority order:
1. A sign/handedness convention mismatch between `kClipSpaceFrustumPlanes`
   (`GeomCamera3.cpp:26`, note the NEGATIVE `kPerspectiveDefaultNearDepth =
   -10.0f` / `kPerspectiveDefaultFarDepth = -10000.0f`, hinting at an
   OpenGL-style right-handed/-Z-forward convention) versus
   `VEC_D3DProjectionMatrixFOV`'s actual D3D-style (typically left-handed,
   +Z-forward) output. If the static clip-plane constants assume one
   handedness and the real projection matrix uses the other, every plane
   would come out with a consistent but wrong orientation — which could
   easily produce "valid-shaped frustum, wrong region of space" instead of
   an obviously-degenerate one.
2. `BuildNormalizedPlane`'s return sign (`-transformed.w * reciprocalLength`
   as the plane `Constant`) — re-derive from first principles against
   `kClipSpaceFrustumPlanes`'s actual number layout rather than assuming the
   post-`69b7ac6f` version is fully correct just because it fixed one part of
   this. Only ONE of the two bugs needs to be fixed for the row/column
   symptom to disappear while a sign bug remains latent.
3. Whether `viewProjection = VMatrix4::Multiply(view, projection)`
   (`GeomCamera3.cpp:937`) uses the same row-vs-column multiplication
   convention `BuildNormalizedPlane`'s comment describes for `operator*`
   elsewhere in this file — a mismatched `Multiply` convention would corrupt
   `viewProjection` itself before `BuildNormalizedPlane` ever sees it,
   producing the same class of symptom one level higher.
4. Direct comparison against `solid1` (built from `projection` alone, not
   `viewProjection`) — if `solid1`'s planes ARE correctly centered near clip
   space (they should trivially be, since no camera transform is involved),
   diffing solid1 vs solid2's plane shapes might immediately reveal whether
   the view/camera-transform application is where the corruption enters.

**Recommended next action for whoever continues this**: add ONE more
diagnostic dumping `solid1`'s planes alongside `solid2`'s (candidate 4 above,
cheapest to check and most likely to bisect the problem in one step), and/or
directly compute `dot(plane.Normal, camera.tranform.pos_) - plane.Constant`
for each of solid2's 6 planes and print the sign per-plane (rather than only
the aggregate `Intersects` bool) — that pinpoints WHICH of the 6 planes is
rejecting the camera position, which combined with the plane dump already in
this file (near-symmetric X-pairs for left/right, etc.) should make the
specific wrong plane obvious by inspection. Do this before attempting a
blind sign-flip fix — a wrong guess here risks silently breaking `solid1`
or other `CGeomSolid3` consumers (unit selection/click-testing likely use
the same `Intersects` machinery and may currently be working correctly).

All temporary diagnostics from this chapter (Mesh.cpp: register-call
counter, frustum plane dump, frustum intersect test) were added, verified,
and then MUST BE REVERTED before this file is trusted as describing the
tree's current state — check `git diff src/sdk/moho/mesh/Mesh.cpp` and
`git diff src/sdk/moho/app/WxRuntimeTypes.cpp` (the latter has ~1064 lines
of unrelated, legitimate, pre-existing uncommitted work from earlier this
session — do not touch it, only remove `[DIAG-` blocks) before continuing.

## FIX LANDED AND VERIFIED (2026-08-31, later still): `COORDS_Orient(heading,pitch)` quaternion component mislabeling — commit `1f194c1a`

Root-caused and fixed the frustum bug the previous chapter left open. Bisected
`solid1` (built from `projection` alone, no camera view) vs `solid2` (built
from `viewProjection`): `solid1`'s planes were perfectly symmetric (left/right
and top/bottom mirror pairs, both with `c≈0`, exactly what a frustum centered
at the local origin should look like) — `solid1` was correct, isolating the
bug to something introduced by the camera's VIEW transform specifically.
Checked every function in that chain against its own logic (`VTransform::Inverse`,
`VMatrix4::Multiply`, `VMatrix4::FromQuatPos`, `BuildD3DProjectionMatrixFov`,
`kClipSpaceFrustumPlanes` — verified this constant array is mathematically
correct against the standard D3D half-space clip-plane form, `BuildNormalizedPlane`)
— all individually looked correct. Went one level deeper and diffed
`CameraImpl::UpdateCoords`'s decompiled `.c` (`FUN_007AA330.c`) against the
recovered source term-by-term; that matched too (including the odd `*0.0`-laden
quaternion swizzle in the eye-position math, which is genuinely how the binary
computes it, confirmed present in BOTH the perspective and ortho branches).

Went one more level down into `COORDS_Orient(heading, pitch)` itself
(`Entity.cpp:8719`, decompiled ground truth `FUN_0050B300.c`) and did a careful
term-by-term comparison. The binary computes four products and assigns them
BY NAME to `dest->x/y/z/w` in that order:
```
dest->x = cosHeading * cosPitch
dest->y = sinPitch   * cosHeading
dest->z = sinHeading * cosPitch
dest->w = -(sinHeading * sinPitch)
```
The recovered source assigned the SAME four products to `w/x/y/z` instead —
a one-position cyclic shift of which named quaternion component receives
which value (e.g. the value the binary puts in `.x` was recovered into
`.w`). Fixed to match the disassembly exactly (commit `1f194c1a`).

**Runtime-verified, real visual improvement**: rebuilt clean, ran
`/map SCMP_009 //log`, **`fault=0`, `cpp=2822`** (same benign shader-var
throw count as every other crash-free run this session — no regression),
134K-line stable run. Screenshot (via the `PrintWindow` technique, see
below) showed **actual visible sky/gradient content for the first time this
entire investigation** — a blue-and-white streaked region, not solid black —
in the region NOT covered by opaque 2D UI chrome.

**This function is called from 13 files across `src/sdk`** (weapon aim,
projectile orientation, AI aim manipulators, formation facing, unit motion,
selection dragger, etc.) — the same mislabeling likely affected every one of
those consumers too. None of them were investigated or re-verified this
session; if odd aiming/orientation bugs are reported elsewhere in the engine,
check whether they trace back to this function before assuming a new bug.

### CRITICAL CORRECTION: the "black bordered panel" chased for most of this file is the MINIMAP, not the main world view

A follow-up diagnostic (dumping each `CUIWorldView` instance's on-screen rect
from `mViewLeft/Top/Right/Bottom` alongside its debug name, right where
`CameraSetViewport` gets called) resolved a confusion that shaped a large
fraction of this session's investigation:

```
[DIAG-VIEWRECT] ptr=48303800 name=WorldCamera rect=(0.0,0.0,1024.0,768.0)
[DIAG-VIEWRECT] ptr=48303200 name=Minimap     rect=(32.0,211.0,545.0,540.0)
```

**`WorldCamera` (the real, main 3D game view) occupies the FULL screen,
`(0,0)` to `(1024,768)`** — matching the window's full client size. It is
NOT the bordered panel with its own pin/expand/close chrome that every
screenshot in this file shows sitting in the center-left of the window —
**that bordered panel is the `Minimap`**, a second, separate, much smaller
`CUIWorldView` instance (`32,211` to `545,540`, matching its own
independently-confirmed `viewportWH=(513,329)` from the earlier camera-state
diagnostic). The "GameMain ScreenGroup"/`mapGroup` parent chain traced
earlier in this file belongs to `WorldCamera`; the "window client group"/
`nil-window` chain belongs to `Minimap`.

This means: **the main game viewport is not a small dialog fighting for
screen space — it is the full window, underneath every 2D UI element.**
The reason the screen still looks mostly black after the quaternion fix is
that opaque 2D UI (resource bars, command palette, and the Minimap panel
itself) covers most of the window, and the small uncovered strip (roughly
the right ~110px edge in the current screenshot) is the only place
`WorldCamera`'s own content shows through — which is exactly where the new
sky content appeared. The Minimap's own persistent blackness is a
**separate, not-yet-investigated question** — it has its own camera, its own
`CollectAllInVolume` query, and possibly its own rendering requirements
(e.g. a strategic-icons/terrain-preview-texture path distinct from the main
scene) that were never checked this session.

### DEFINITIVE CONFIRMATION: the `COORDS_Orient` fix fully resolved the frustum-positioning bug — `solid2` now encloses the camera 100% of the time

Re-ran the exact same `Intersects()`-based near-camera-box test from the
pre-fix investigation (further up this file), this time against the current,
fixed build: **`nearCamBoxIntersects=1` on all 20 consecutive samples**
(was `=0` on every sample, every run, before the fix — see the earlier
`[DIAG-FRUSTUM-TEST]` results in this file for the pre-fix baseline). This
is a complete, clean reversal, independently confirming the `COORDS_Orient`
fix is correct and sufficient for what it targets: `camera.solid2`'s
6-plane frustum volume now genuinely contains the camera's own position and
immediate surroundings, every frame, for both registered cameras.

**So the remaining black-screen gap is NOT the camera/quaternion/frustum bug
— that is closed.** It is something else, narrower in scope.

### Remaining gap, narrowed further: `MeshRenderer::Batch`'s `collected` count is STILL 0 even though `solid2` is now provably correct

Confirmed in the same post-fix run (`[DIAG-BATCH3]`, correlated against
`[DIAG-HEADPITCH]` in one build): `mHeading=180°` (`π`, from
`CameraReset()`'s hardcoded `kPi`), `mFarPitch≈60°` (from the
`cam_FarPitch=60.0f` default, `RuntimeTuningGlobals.cpp:109`) — both sane,
both correctly read by `UpdateCoords`. Yet the derived "forward" vector
(`cameraForward = -camera.inverseView.r[2]`, computed in `MeshRenderer::Batch`)
is consistently `(0, 0, 1)` — a pure +Z direction with no downward tilt at
all, despite the 60-degree pitch input. Hand-derived this through the full
chain (COORDS_Orient's output quaternion → UpdateCoords's own additional
component swizzle → VMatrix4::FromQuatPos → inverseView.r[2]) and got a
result CONSISTENT with the observed `(0,0,1)`: a heading=180°/pitch=60°
input, run through the verified-correct (byte-matched-to-disassembly) code
in this recovery, algebraically produces a rotation that leaves the local
Z-axis pointing at `(0,0,-1)` in world space (so `-r[2] = (0,0,1)`). This
means the CODE IS DOING WHAT THE DISASSEMBLY SAYS — if this is "wrong", the
wrongness (if any) is either (a) genuinely how the original binary behaves
too (not a recovery bug — do not assume it must be fixed), or (b) in some
OTHER function not yet checked (candidates: `VMatrix4::FromQuatPos`'s own
correctness was assumed, not independently verified against disassembly;
which matrix row actually represents "world-space forward" for THIS
engine's convention was assumed from an existing comment, not re-derived).

Confirmed `cameraForward`'s `-inverseView.r[2]` formula is used identically
in a SECOND, independent place (`BuildViewSupportSelector`,
`Mesh.cpp:2358`) — ruling out "wrong row picked at one call site" as the
explanation; both sites agree, so if this is wrong it's systemic, not a
copy-paste slip. `cameraForward` (called `supportSelector` on this second
path) feeds `ComputeFadeThresholdForBounds` (`Mesh.cpp:2346`) as part of
whatever narrows/rejects candidates before they're added to the destination
list — read but not yet fully traced. **Next step for whoever continues
this**: trace `ComputeFadeThresholdForBounds`'s result forward into
`CollectVolumeCandidatesWithFade` (referenced from `FindInVolumeFromData`)
to see exactly how `fadeThreshold` gates entries, and add a diagnostic
there specifically — separate from the frustum question, which is now
closed. Also worth checking, cheaply, before going deeper: is `collected=0`
actually WRONG right now, or could the map genuinely have zero registered
props/decorations within the camera's immediate frustum at this exact
early-loading moment (the terrain/ground itself renders through a
completely separate path, `RenderCompositeTerrain`/`DrawNormals`, confirmed
via `[DIAG-TERRAINDRAW]` to report `ok=1` - success - on every call this
session, both before and hypothetically after this fix, so the ground is
not gated by `collected` at all). A screenshot after all this still showed
mostly-black with a sky sliver, so SOMETHING is still not visually
resolving even if `collected` turns out to be a red herring - the terrain
draw succeeding doesn't by itself prove it's producing non-black pixels.

### Next step: most of `WorldCamera`'s own full-screen area is STILL black

Only a narrow strip (~110px wide, far right edge) shows visible sky; the
much larger remaining area within `WorldCamera`'s `(0,0)-(1024,768)` rect
that isn't covered by explicit UI chrome is still black. Two live
hypotheses, neither yet checked:
1. The camera's orientation, while no longer producing a frustum that
   entirely misses its own position, may still be pointed in a way that
   puts most of the visible scene out of frame (e.g. looking too far
   down/up) — re-run the `MeshRenderer::Batch` collected-count +
   `camera.tranform.pos_` probe (technique fully described earlier in this
   file) now that the quaternion fix has landed, and additionally log
   `runtime->mHeading`/`runtime->mFarPitch` (or the resulting `view`
   matrix's forward axis) to sanity-check the look direction against the
   map's known bounds.
2. There may be a SEPARATE opaque UI layer (not yet identified) drawing
   over most of `WorldCamera`'s screen area — before assuming (1), rule
   this out by checking what other controls' screen rects overlap that
   region, the same way the `[DIAG-VIEWRECT]` probe just resolved the
   Minimap confusion.

All temporary diagnostics from this chapter (`UiRuntimeTypes.cpp`'s
`[DIAG-VIEWRECT]` probe in `CUIWorldView::DoRender`) were added AFTER the
real `Entity.cpp` fix was committed and must be reverted before trusting
`git diff` as clean — check `git diff src/sdk/moho/ui/UiRuntimeTypes.cpp`
is empty before continuing (it should be, if reverted in the same pass this
note was written, but verify rather than assume).

## Ruled out, do not re-derive

- Shader-var throws in water/terrain (`ShaderVar::Exists()`,
  `ShaderVar.cpp:264-290`) are confirmed caught/benign — do not re-chase.
- `RenderAllHeads`/`WRenViewport::Render` confirmed executing every frame
  (~950 stack-trace mentions in a 137K-line run) — the top-level render
  entry point is not being skipped.
- `ren_Terrain` defaults `true` (`RuntimeTuningGlobals.cpp:3`) — terrain
  rendering is not gated off by that flag.
- `ren_RenderNothing` early-return in `WRenViewport::Render` is a dead end
  to re-check — it gates the ENTIRE function including 2D UI, and 2D UI is
  confirmed rendering, so it is not set.
- **`CUIWorldView::DoRender` firing or not is IRRELEVANT to 3D visibility** —
  it's a 2D overlay draw only (build-preview ghosts, selection boxes), not
  the terrain/mesh render path. Confirmed it fires every frame; this was a
  wasted investigation thread in an earlier chapter of this file. The real
  3D path is `IRenderWorldView`/`WRenViewport::Render`.
- Registration (`AddWorldView`/`mWorldViews`), camera resolution
  (`GetCamera()`/`CameraGetView()`), camera world position, and viewport
  pixel size (`1024x768`) are ALL confirmed correct/healthy live. Do not
  re-verify these without new evidence — the bug is specifically in
  `solid2`'s plane construction/positioning, isolated above.

## 2026-09-01: THREE MORE REAL FIXES LANDED — terrain now emits actual geometry (visible in screenshots), goal still not met

This chapter picks up exactly where the previous one left off ("solid2's
plane construction/positioning" was the open lead). Found THREE separate,
real, ground-truth-verified bugs, all fixed and committed. This is NOT
speculation — every fix below was verified two ways: (a) term-by-term against
the actual `.c` disassembly export for that specific function, not "looks
plausible", and (b) empirically, via a live diagnostic showing the runtime
value change before/after. Commits (newest first): `06d94b92`, `2ff1ae34`,
`fc463bb1`.

### Fix 1 (`fc463bb1`): `VMatrix4::FromQuatPos` was a fabricated stand-in

`GeomCamera3.cpp`'s `BuildMatrixFromTransform` called `VMatrix4::FromQuatPos`
— a header-only helper in `VMatrix4.h` with **no `Address:` citation at all**.
It implemented the textbook scalar-last quaternion-to-matrix formula
(`w`=scalar, `x/y/z`=vector). The real binary function is `VMatrix4::Set`
(0x004EE980), already correctly recovered with a real citation in
`MathReflection.cpp` — nobody had wired it up as the actual matrix-builder.
`VMatrix4::Set`'s real formula (verified against `FUN_004EE980.c` term by
term) treats `quat.x` as the scalar lane and `(y,z,w)` as the three
imaginary lanes, under transposed cross-term signs — a completely
non-standard convention, but definitively the real one (four independent
confirmations, see Fix 2).

Symptom this caused: `view`/`viewProjection`'s Row 2 (the axis the D3D
projection treats as depth) is **provably pitch-invariant in Y for every
heading/pitch pair** under the textbook formula (proved algebraically:
`Row2_y = 2(yz+wx)` collapses to `sin(H)cos(H)[sinP²-cosP²... ] cancels to
exactly 0` when you substitute the actual quaternion values `UpdateCoords`
feeds it — this is NOT a per-instance coincidence, it's true for all
heading/pitch). A camera that can never tilt vertically, combined with
heading=π zeroing the X/Y components of `COORDS_Orient`'s own output, meant
`CTesselator::Rebuild`'s root-tile AABB test against `solid2` rejected the
ENTIRE terrain every single frame, regardless of camera position — this
*was* "solid2's plane construction/positioning" bug from the previous
chapter, now root-caused precisely.

Fixed by switching `BuildMatrixFromTransform` to call `matrix.Set(orient_,
pos_)` directly and deleting the now-fully-orphaned `FromQuatPos` (zero
other callers).

### Fix 2 (`2ff1ae34`): `QuatToMatrix` and `VTransform::Inverse` ALSO didn't match their own citations

Once Fix 1 was verified (`view.r[2]` empirically became the expected
pitch-sensitive `(0, sin(pitch), cos(pitch))`-shaped vector — exactly
matching an independently-derived value from `UpdateCoords`'s unrelated
eye-offset-basis formula, using the SAME underlying quaternion, which is
strong convergent proof `.x`=scalar is real, not a fluke) — the frustum
STILL rejected the terrain. Root cause: the camera's own eye position, run
through the freshly-fixed `view` matrix, did not map back to the view-space
origin (off by hundreds of world units) — meaning `VTransform::Inverse`'s
TRANSLATION half was still wrong even though the rotation half (from Fix 1)
was now right.

`VTransform::Inverse` (0x0046FBF0) has a real citation but its body didn't
match `FUN_0046FBF0.c`: ground truth conjugates by keeping `.x` fixed and
negating `.y/.z/.w` (the ACTUAL code kept `.w` fixed and negated `.x/.y/.z`
— a one-field-off mislabeling, same disease as the `COORDS_Orient` bug this
whole investigation started from), and rotates the negated translation via
the REAL `Moho::MultQuadVec` (0x00452D40) — the actual code called
`Wm3::MultiplyQuaternionVector`, an uncited "FAF MOD" addition to the
WildMagic-patch header, built on `Quaternion::ToMat3` (also uncited, also
textbook-wrong).

`MultQuadVec`'s OWN dependency, `func_QuatToMatrix` (0x00452FD0, called from
`QuaternionMath.cpp`), turned out to ALSO not match its own citation —
same textbook-formula-instead-of-real-disassembly pattern, verified by
re-deriving `FUN_00452FD0.c` term by term (diagonal terms pair `w` with `z`
row 0, `w` with `y` row 1, `z` with `y` alone row 2 — `x` never appears in
any diagonal, which IS the `.x`=scalar signature). Fixed `QuatToMatrix` to
the real formula; it turns out to be the exact TRANSPOSE of `VMatrix4::Set`'s
rotation block, which is why `MultQuadVec`'s row-of-matrix-dot-vec usage
correctly reproduces `vec * VMatrix4::Set(quat)` under this engine's
row-vector convention — a beautifully self-consistent design once correctly
recovered.

**This is bigger than the camera.** `MultQuadVec` is the engine's pervasive
rotate-vector-by-quaternion primitive — bones (`CAniPose`, `IAniManipulator`),
physics (`SPhysBody`, `CUnitMotion`), units (`CAiFormationInstance`,
`CUnitPatrolTask`), effects (`CEfxBeam`), rendering (`HardwareMeshBatch`,
`SelectionBracketRenderer`) — several dozen call sites, all silently getting
the wrong rotation before this fix. `SelectionDragger.cpp`'s
`BuildSelectionSolid` (a WORKING, previously-recovered function, unrelated to
this session's chase) independently confirmed the `.x`-fixed conjugate
pattern — its own hand-written conjugate at line ~1050 keeps `.x` and negates
`.y/.z/.w`, matching what `VTransform::Inverse` SHOULD have done. That
`Wm3::MultiplyQuaternionVector` still exists with ~18 OTHER call sites not
audited this session — **follow-up work, not yet done**: each of those sites
should be checked for whether its quaternion is a `VMatrix4::Set`-convention
one (needs `MultQuadVec`) or something else. Don't assume they're all fine
just because this session didn't get to them.

### Fix 3 (`06d94b92`): `CollectDataInRect`'s type-erased parameter crashed the tesselator the instant it was finally reachable

With Fix 1+2 landed, `solid2` finally accepted the terrain (`intersects=1`
confirmed live for the root tile AND recursive children down to tier 8), and
the eye→view-space-origin sanity check passed to within float rounding. But
the FIRST real run crashed: `ACCESS_VIOLATION` inside
`FastVector<unsigned short>::Reserve` → `operator delete[]` → `free()`
reading address 0, deep inside `CollectDataInRect`'s recursive quadtree
descent (`CTesselator.cpp:1332`/`:1347`).

Root cause: `CollectDataInRect`'s parameter was typed
`gpg::fastvector<uint16_t>*` — `gpg::fastvector<T>` is a bare alias for the
BASE `gpg::core::FastVector<T>`, not `FastVectorN<T,N>`. Every real caller
(`TesselateLeafCell`'s four edge chains, `TesselateData`'s `edgeIndices`)
passes a stack-local `FastVectorN<uint16_t,25>&`, which upcasts implicitly.
`PushBack`/`Reserve` are non-virtual (deliberately — this container mirrors
a binary layout, adding a vtable would break `sizeof`/ABI), and
`FastVectorN` overrides them specifically to avoid freeing its own inline
buffer (`Reserve` at `FastVector.h:825` delegates to `GrowToCapacity`, which
checks `start_ != originalVec_` before `delete[]`). Erasing to the base
pointer at the `CollectDataInRect` call boundary bypasses those overrides
entirely — the crash symbol in the stack trace literally says
`FastVector<unsigned short>::Reserve`, not `FastVectorN<...>`, which is what
gave this away. This was UNREACHABLE before Fix 1+2 landed, since the
frustum rejected the terrain outright and the recursive split path never
ran deep enough for any chain to exceed its 25-slot inline capacity.

Fixed by changing the parameter type (header + `.cpp`) to
`gpg::fastvector_n<uint16_t, 25>*`, matching what every real caller actually
passes. Confirmed via dbgrun: identical camera fixes, this change alone is
the difference between a second-chance access violation and a clean run
(`fault=0` in dbgrun's summary).

### Screenshot evidence: real, textured 3D geometry rendering for the first time this whole investigation

Post-Fix-3, a screenshot (no crash, `main.exe` confirmed alive at capture
time) shows a small textured gray/teal parallelogram-shaped quad floating in
otherwise-black space — the first ACTUAL 3D geometry (not sky, not a flat
clear color, not console text) visible in ANY screenshot this entire
investigation. This is almost certainly a terrain mesh fragment, given the
context, though not 100% confirmed vs. some other object. **The goal is
still NOT met** — most of the screen remains black. Do not mistake this
partial win for done.

### Open lead at the point this chapter was written: LOD over-tessellation, `mRectCache` overflow

`HighFidelityTerrain::UpdateRenderContext`'s `mSkirtStartIndex` (read via
`mTesselator->GetSkirtIndexStart()`) comes out as **6291456** post-fix (was
always exactly 0 before) — `mTesselator->mRectCache` (`FastVectorN<Rect16,
65000>`) hits its hard 65000-entry cap (`AddRect` is bounded there by
design), and `skirtVertexStart` reads exactly 65000, confirming the cache is
saturated. This means `CTesselator::TesselateTile`'s recursive
accept/split/reject decision (`GetIntersectionResult`,
`CTesselator.cpp:862`) is **never returning `kAccept`** — every cell
recurses all the way to `tier=0` (max detail) instead of accepting coarser
LOD at distance, generating a wildly invalid amount of geometry. This likely
explains why only a tiny fragment renders (visible in the screenshot above)
instead of a full terrain: the real draw call's `indexCount` (6.29M) is
almost certainly invalid for however the D3D index buffer / draw call
actually consumes it (`mCollisionRectLut`/`GetCollisionIndexData()` returns
`uint16_t*`, and 6291456 is far beyond anything a 16-bit-indexed buffer
could represent — the excess is presumably silently dropped/clamped
somewhere, which is consistent with "one small fragment renders, not
garbage/crash").

**Investigated and RULED OUT as the cause** (re-verified term-by-term
against ground truth just now, do not re-derive):
- `GetIntersectionResult`'s comparison formula itself
  (`tierMaxError < shoreCoeff*(row1·testCorner+row1.w)*ren_maxViewError`) —
  matches `FUN_0080E020.c` exactly, including the `kSplit=1/kAccept=2/
  kReject=3` return-value mapping.
- `GeomCamera3::Init`'s viewport-row derivation (`viewport.r[0]` from
  `viewportRowSource * view`, `r[1]`=`r[0]*lodScale`, `r[2]`=`r[0]*(1/
  viewport.r[3].z)`, `viewport.r[3]` itself seeded once in the constructor
  to `{0,0,1,1}` and never touched again by `Init`) — matches
  `FUN_004700A0.c` lines 149-256 exactly, term by term. This was a dead end
  that cost real time to rule out; don't re-walk it without new evidence.

**Live diagnostic data at the point of interruption** (root-tile call,
tier=10, corner mask=`0x00000003` from the frustum-accept diagnostic — NOTE
this is a DIFFERENT mask value than the corner-selection mask discussed
below, don't conflate the two):
```
row1=(0.00000, 1.45336, -0.83910, 0.00000)
testCorner=(1024.00, 0.00, 1024.00)
projectedDepth = row1·testCorner + row1.w = -859.2379   (NEGATIVE)
maxAllowedError = shoreCoeff(1.0) * projectedDepth * ren_maxViewError(1.0) = -859.24   (NEGATIVE)
tierMaxError = 25.5781   (always positive, a real height-error metric)
→ tierMaxError < maxAllowedError is FALSE for every cell → always kSplit, never kAccept
```

Hand-verified `nearWidth`/`farWidth` (`Distance3`, presumably a true
non-negative Euclidean distance) are NOT the problem — `widthSlope =
(farWidth-nearWidth)/(leftFar.z-leftNear.z)` is legitimately NEGATIVE by
design, because `leftFar.z < leftNear.z` under this engine's
negative-view-space-depth convention (near≈-9, far≈-17900, already
established fact, re-confirmed). That makes `row1` itself (and thus
`projectedDepth`'s sign) inherently dependent on the negative-depth
convention — so a negative `projectedDepth` for a "conservative worst-case"
corner may be **expected**, and the real bug may be a MISSING sign
somewhere else (candidates, not yet checked): `ren_maxViewError`'s true
runtime value (constructor default `1.0f` per `RuntimeTuningGlobals.cpp:128`
— but is that cvar ever overridden before first use? Not checked yet), or
`mCornerSelectionMask`'s corner choice being wrong so the WRONG corner (one
that would give a positive dot product) is being evaluated instead of the
intended one.

**Was mid-diagnostic on `mCornerSelectionMask` when this chapter was
written**: hand-deriving `camera->inverseView.r[2]` and the resulting mask
by hand (same `VMatrix4::Set`-convention arithmetic as Fix 1) predicted
`testCorner=(0, 17.5, 1024)` for the root AABB, but the empirical value was
`(1024, 0, 1024)` — X and Y both came out opposite of hand-prediction (Z
matched). Suspect an IEEE754 negative-zero sign-bit subtlety
(`mCornerSelectionMask`'s computation does `-0.0f - value` then checks the
RAW sign bit via `bit_cast<uint32_t>(...) >> 31`, which is sensitive to
`-0.0` vs `+0.0` in a way plain "is this negative" arithmetic is not) — this
is exactly the kind of thing that's fast to get wrong by hand and fast to
settle with a live diagnostic instead. **A diagnostic printing
`camera->inverseView.r[2]`, the three intermediate `inverseViewZ{X,Y,Z}`
values, and the resulting `mCornerSelectionMask` was added to
`CTesselator::Rebuild` (right after the existing computation,
`CTesselator.cpp` around line 1537) and a rebuild was in flight** when this
chapter was written — check `git diff src/sdk/moho/render/tess/
CTesselator.cpp` first: if that diagnostic (tagged `[DIAG-MASK]`,
`sDiagMaskCalls`) is still present, either finish reading its output or
revert it before doing anything else, per the standing no-lingering-
diagnostics discipline. Do NOT re-derive the corner-selection formula by
hand again — go straight to (re-)running this diagnostic.

### Process notes for next session

- The dbgrun screenshot-timing gotcha from earlier chapters is CONFIRMED to
  still apply and now has a second data point: `main.exe` reliably survives
  60-90+ seconds after launch (long past the point where terrain
  construction diagnostics fire), but dies shortly after dbgrun's own
  `WaitForDebugEvent timeout - detaching` idle-timeout fires (confirmed
  benign, `fault=0`, NOT a new crash — just don't screenshot after it).
  Reliable pattern: launch dbgrun backgrounded, poll `Get-Process -Name main`
  for elapsed wall-clock time (NOT log line count — that only correlates
  with real progress when diagnostic `OutputDebugStringA` spam is present;
  without it, line count is dominated by C++ exception noise and is a much
  noisier clock), screenshot promptly once ~60s has elapsed and the process
  is confirmed alive.
- Every fix this chapter followed the same recipe and it keeps paying off:
  when a recovered function's behavior doesn't match live runtime evidence,
  do NOT trust its `Address:` citation as proof of correctness — re-open the
  actual `.c` export in `decomp/recovery/disasm/fa_full_2026_03_26/` and
  re-derive the formula term-by-term yourself. Three fabricated/mismatched
  functions were found this session alone (`FromQuatPos` had no citation at
  all; `QuatToMatrix` and `VTransform::Inverse` had real citations but wrong
  bodies) — a citation is not proof once you've seen this pattern.
- Hand-deriving matrix/quaternion row-vs-column and sign conventions from
  first principles is UNRELIABLE — this session got it wrong multiple times
  (see the corner-selection-mask dead end above, and an earlier abandoned
  "should be `view^T`" tangent that direct ground-truth comparison refuted).
  When in doubt, prefer: (a) re-reading the actual disassembly term-by-term,
  or (b) adding a cheap runtime diagnostic and reading the real numbers,
  over (c) abstract reasoning about what "should" be true.

## 2026-09-01 continued: FOURTH fix landed (`1dba8545`), and the LOD-formula mystery SOLVED (mechanism understood, not yet fixed)

### Fix 4: `MeshRenderer::Batch`'s LOD-distance used positional quaternion indexing instead of named fields

Found by inspection while re-checking for the same bug CLASS elsewhere (not
via a new diagnostic). `Mesh.cpp`'s `MeshRenderer::Batch` (0x007DFA00) computes
a per-instance "view-depth distance" for LOD selection:
`camera.tranform.orient_[2]*pos.z + orient_[1]*pos.y + orient_[0]*pos.x +
orient_[3]`, using `Quaternion::operator[]`. Ground truth
(`FUN_007DFA00.c`) uses NAMED fields instead: `orient.z*pos.z + orient.y*pos.y
+ orient.x*pos.x + orient.w`. These are NOT the same thing:
`Wm3::Quaternion` (`Wm3Quaternion.h`, the "FAF MOD" union) stores
`m_afTuple[4]` aliased to a `{w,x,y,z}` struct in THAT declared order, and
`operator[]` returns `m_afTuple[i]` directly — so `orient_[0]` is actually
`.w`, `[1]` is `.x`, `[2]` is `.y`, `[3]` is `.z`. Every term in the
recovered dot product was one field off. Fixed by switching to named-field
access, matching ground truth exactly. This affects EVERY mesh instance
(prop/building/unit) processed every frame — a real, independent bug, same
disease as `COORDS_Orient`/`VTransform::Inverse`/`QuatToMatrix` (all four
are "named vs. positional quaternion field" confusions), but in this case an
index-vs-name mixup rather than a field-relabeling.

Checked for the same `orient_[0..3]` pattern elsewhere: one more hit, in
`Projectile.cpp` (~line 805), copying `launchTransform.orient_[0..3]` into a
`Vector4f`. Left alone — its own comment explicitly documents this as a
verbatim `m_afTuple`-order tuple copy (order-preserving, not doing
arithmetic that assumes named-field alignment), which is a legitimately
different, safe use of the same operator. Did not exhaustively search for
OTHER quaternion-field confusions (positional-vs-named, or the
scalar-role-is-`.x` convention) elsewhere in the engine — this is flagged,
not resolved, as follow-up work.

Screenshot after this fix (`screenshot_meshfix1.png`, ~66s runtime, process
confirmed alive at capture) looked IDENTICAL to the pre-fix state (blue-filled
minimap panel, black world view) — but SCMP_009 launched via dbgrun directly
(bypassing the normal lobby/spawn flow) may simply have zero mesh instances
to render at all (resources show 0/0, "Ready for recall", consistent with an
unspawned/observer state) — meaning this fix could be 100% correct and
simply have nothing to demonstrate it in THIS specific test scenario. Don't
read "no visible change" as "fix didn't work" without first confirming
whether there's anything for `MeshRenderer::Batch` to actually collect and
draw.

### The `CTesselator` LOD-over-tessellation mystery: mechanism found, root cause still open

This is the "open lead" from the previous chapter, followed to a much
deeper, precise understanding. Short version: **`CTesselator::GetIntersectionResult`'s
accept/split formula, though verified term-for-term identical to
`FUN_0080E020.c`, evaluates a quantity that is NOT camera-relative depth for
any world point far from the world origin — and this is not a recovery bug
in any function checked so far, all of which independently match their own
ground truth.** Concrete proof it's not just "correct but weird": a sampled
cell with `tierMaxError=0.0000` (a PERFECT, zero-error cell) still got
rejected, because `maxAllowedError` was negative. A working LOD system can
never reject a zero-error cell. And `skirtIndexStart` landing at EXACTLY
`1024*1024*6 = 6291456` proves the rejection is universal across the whole
map, not specific to the one corner this session's diagnostics happened to
sample (that exact product is only possible if literally every tier-0 leaf
across the full 1024×1024 grid got visited).

**The precise mechanism** (derived by directly comparing `dot(row1.xyz,
testCorner)+row1.w` against `testCorner`'s REAL view-space position, computed
via the confirmed-correct `Vector4f operator*(vRow, VMatrix4)` applied to
`testCorner * mCam->view` directly — both computed in the same diagnostic
call, so this is not a stale-data artifact):
```
testCorner = (1024, 0, 1024)          [a root-tile AABB corner, mask=7/all-max]
REAL view-space Z (testCorner*view, includes translation) = -613.122
row1·testCorner (the code's actual computation)            = -859.238
```
These are NOT the same number, confirmed via live diagnostic, not algebra.
Tracing why: `row1 ≈ widthSlope * view.r[2]` (the `widthIntercept` term is
negligible — see below), so `dot(row1,testCorner) ≈ widthSlope *
dot(view.r[2].xyz, testCorner)` — and critically, `dot(view.r[2].xyz,
testCorner)` uses ONLY view's ROTATION row (no translation row), giving
`512` for this corner. The REAL view-space Z additionally adds
`view.r[3].z` (the camera's translation contribution, `-1125.12` for this
frame) to get `-613.12`. **`row1`, as constructed
(`viewport.r[0] = viewportRowSource * view` with `viewportRowSource =
(0,0,widthSlope,widthIntercept)`), only lets the translation row `view.r[3]`
into the result scaled by `widthIntercept` — and `widthIntercept` is
computed from `leftNear.z`/`nearWidth`, which are VIEW-SPACE (camera-relative,
near-clip-scale, ≈ -9) quantities from `ProjectFromInverseProjection`
(unprojecting through `inverseProjection` ONLY, confirmed via ground truth
`this->mInverseProjection.d[...]` - NOT `inverseViewProjection`, ruling out
"should unproject to world space instead" as the fix). Since `widthIntercept
≈ nearWidth - leftNear.z*widthSlope ≈ 0` (verified live: `0.000001`,
mathematically expected too — width is 0 at a perspective frustum's apex,
z=0, by construction) — the LARGE, WORLD-SCALE `view.r[3]` translation row
gets multiplied by this ~0 coefficient and contributes essentially nothing.
So `dot(row1,worldPoint)` structurally can NEVER reflect the camera's actual
world position for points far from the origin — it's the wrong physical
quantity by construction, using a NEAR-CLIP-SCALE constant where an
EYE-POSITION-SCALE one would be needed to make the formula camera-relative.

**This was verified NOT to be a recovery bug** in every function on the
path: `VMatrix4::Set`, `VTransform::Inverse`, `viewport.r[0]/r[1]`
construction (matches `FUN_004700A0.c` term-by-term, re-verified twice),
`GetIntersectionResult`'s comparison formula (matches `FUN_0080E020.c`
term-by-term, including the `kSplit=1/kAccept=2/kReject=3` mapping),
`ProjectFromInverseProjection` (re-verified against ground truth for the
leftNear/-1,0,0 case), `nearWidth`/`farWidth` (geometrically sane: implies
~39° half-FOV, matching `cam_FarFOV=80°`). Every individual piece is
faithfully recovered. The COMPOSITE behavior is nonetheless wrong for this
map/camera. Two live hypotheses, NEITHER confirmed:
1. This is a genuine, longstanding characteristic/limitation of the
   ORIGINAL 2007 engine's LOD heuristic that happens to not matter for
   real gameplay (smaller maps, different camera framing, or maps
   positioned differently relative to the world origin than SCMP_009's
   0-1024 span) — i.e. not fixable by finding "the bug", because there
   isn't one; the fix would have to be a deliberate behavior change, which
   is out of scope for a faithful recovery.
2. There is a FIFTH upstream bug not yet found, most likely something that
   feeds `nearWidth`/`farWidth`/`leftNear`/`leftFar` or `mFarFov`/
   `mVerticalZoomMetricScale`/`mTargetZoom` with a value that's subtly wrong
   ONLY for this debug/dbgrun launch path (which bypasses the normal lobby/
   camera-reset flow) — e.g. `mNearZoom`/`mTargetZoom` come from
   `CameraReset()`'s `GetMaxZoom()` call, not yet independently checked this
   session.

**Tried and RULED OUT**: `Wm3::Vector3f` has the same union-aliasing pattern
as `Quaternion` (`m_afTuple[3]` overlaid with `{x,y,z}`), but its field
DECLARATION order is plain `x,y,z` (unlike `Quaternion`'s `w,x,y,z`), so
`operator[]` and named access agree — no index-vs-name bug possible there.
`moho::Vector4f` (the type `viewport.r[]`/`row1` actually are) isn't a
WildMagic union type at all — plain `float x,y,z,w` fields, no aliasing
risk. Neither rules in nor explains the mystery.

**Tried and RULED OUT (2026-09-01, later same day)**: hypothesized
`CameraReset()`'s default "whole map" zoom (`mTargetZoom = mNearZoom =
GetMaxZoom()`, confirmed live: this produces the observed ~900-unit
`eyeDistance`, an extreme zoomed-all-the-way-out framing that a normal
lobby/gameplay flow might never reach) was the actual root cause, distinct
from a genuine formula bug. Tested directly: temporarily hardcoded
`runtime->mTargetZoom = 150.0f` right after `CameraReset()` sets it
(clearly marked experiment, reverted immediately after testing, never
committed). Screenshot at ~65s runtime, process confirmed alive, was
PIXEL-IDENTICAL to the un-patched build — same blue-filled minimap panel,
same fully-black world view. This DISPROVES "smaller zoom alone fixes it".
On reflection this makes sense mathematically, not just empirically:
reducing `mTargetZoom` shrinks `eyeDistance` (how far the camera sits from
`mOffset`, i.e. the map center `(512,~,512)`), but does NOT move the camera
closer to the WORLD ORIGIN `(0,0,0)` — and the map center itself is always
~512 units from the origin regardless of zoom. Since the suspected missing
term is specifically "distance from the world origin" (`view.r[3]`'s
magnitude, weighted by `widthIntercept≈0`), a zoom change was never going to
touch it. This rules out "it's just a debug-launch zoom artifact" as
DISTINCT from "there's a genuine 5th bug" — whatever this is, it would
affect ANY camera framing on this map, zoomed in or out, not just the
CameraReset default. Do not re-try zoom-based experiments without a new
reason to believe they'd behave differently.

**Tried and ALSO inconclusive (2026-09-01, immediately after the zoom test)**:
ran the sharper test proposed above — temporarily hardcoded
`runtime->mTargetLocation = {10, y, 10}` (and `mOffset` to match) right
after `CameraReset()` computes the map-center default, moving BOTH the
look-at target AND the camera itself near the world origin (reverted
immediately after testing, never committed). Screenshot at ~66s, process
alive: **pixel-identical to every other recent capture** — same blue-filled
minimap panel, same console-error text, same black outer area. Given this
moved the camera to look at a COMPLETELY different part of the map (origin
corner instead of center), getting literally zero change is itself
suspicious and undermines confidence in the whole "distance from origin"
theory — if the outer black area were genuinely the WorldCamera's output and
responsive to camera position, SOME difference should have been visible
regardless of which specific bug is at play. Two live explanations, neither
confirmed: (a) the code change didn't propagate before first render for some
init-order reason not yet checked (nothing found so far), or (b) — more
likely given how consistently identical every recent screenshot has been
across genuinely different camera code changes — **the bordered panel with
the console-error text is NOT the WorldCamera at all**. Re-read the earlier
"CRITICAL CORRECTION" chapter in this same file: it already established the
bordered panel is the MINIMAP, a separate camera. The actual signal to
watch is the OUTER area (the rest of the 1560×1211 window), which is where
the small textured-quad fragment appeared in `screenshot_cdirfix1.png`/
`screenshot_cdirfix2.png` (right after the `CollectDataInRect` crash fix) —
and a similar faint gray parallelogram sliver is visible in roughly the SAME
SCREEN POSITION in `screenshot_meshfix1.png`/`screenshot_zoomexp1.png`/
`screenshot_originexp1.png` too, DESPITE the camera moving to a totally
different world location in the last one. A fragment that stays in the same
SCREEN position regardless of camera world position smells like a 2D UI
element (or a loading placeholder), not responsive 3D content — this was
NOT rigorously confirmed either way before this chapter was written; it
needs a careful side-by-side pixel comparison of those five screenshots
(all still on disk in the scratchpad as of this writing) as the concrete
next step, before trusting either the "camera-relative depth" theory or any
more zoom/position experiments. Do not repeat the zoom or origin-position
experiments without first settling what that fragment actually is.

All diagnostics added while chasing this (`[DIAG-MASK]` in
`CTesselator::Rebuild`, `[DIAG-VP]`/`[DIAG-VP2]` in `GeomCamera3::Init`,
`[DIAG-CMP]` in `CTesselator::GetIntersectionResult`) were reverted before
this chapter was written — `git status --short src/sdk/moho` should show
only unrelated in-flight files (`WxRuntimeTypes.cpp`, `CScriptObject.cpp`,
confirmed pre-existing/other-agent's work all session, not this
investigation's) plus whatever the NEXT uncommitted change is. Verify this
rather than assume it's still true by the time you read this.

## 2026-09-01 (new session, continuing): SIXTH fix landed (`a15c5cc8`) — ROOT CAUSE of the whole over-tessellation saga found and fixed. Real terrain now renders across ~60% of the screen.

This chapter resumes exactly where the previous one stopped: the "precise
mechanism" derivation showing `dot(row1.xyz, worldPoint) + row1.w` (the LOD
depth estimate `GetIntersectionResult` compares `tierMaxError` against) was
structurally blind to the camera's distance from the world origin. That
chapter left two live hypotheses, neither confirmed. **Both were wrong.**
There is a THIRD explanation, found by going one level deeper than either:
`viewport.r[0]`'s construction itself uses the wrong matrix-vector
multiplication convention.

### Root cause: `viewportRowSource * view` uses the point-transform operator where a covector-transform was required

`GeomCamera3::Init` (`GeomCamera3.cpp:980` area) builds the LOD interpolant
row like this (pre-fix):
```cpp
const Vector4f viewportRowSource{0.0f, 0.0f, widthSlope, widthIntercept};
viewport.r[0] = viewportRowSource * view;
```
`operator*(const Vector4f& vRow, const VMatrix4& M)` (`VMatrix4.h:183`) is
this engine's **point-transform** convention: `out[j] = sum_i vRow[i] *
M.r[i][j]` - it combines `M`'s COLUMNS. That's the right operator for
transforming a point (`pointRow * M`), but `viewportRowSource` isn't a point
- it's a covector/interpolant-row, exactly like a clip plane. Read
`FUN_004700A0.c` lines 224-240 (the real disassembly for this exact
function) term by term: for output row `K`, it reads `mView.d[K].d[2]`
(view's row K, **component 2 = Z**) times `widthSlope`, plus `mView.d[K].d[3]`
(row K, **component 3 = W**) times `widthIntercept` - i.e. `view` applied ON
THE LEFT to `viewportRowSource` as a column (`out[K] = dot(view.row[K],
viewportRowSource)`), NOT `viewportRowSource * view`. This is the *exact
same disease* `BuildNormalizedPlane` already had and was fixed for earlier
this session (commit `69b7ac6f`) - its own doc comment (already in the file,
`GeomCamera3.cpp:140-154` at the time) spells out the identical mixup in
the abstract, but nobody had checked whether the SAME construction pattern
recurred elsewhere in the same file. It did, four hundred lines down.

Algebraic proof this is exactly the bug (do not re-derive by hand, this was
checked twice and matches the live diagnostic data below): under the correct
(`DotMatrixRows`) construction, `dot(viewport.r[0].xyz, P) + viewport.r[0].w`
expands to `widthSlope * viewSpaceZ(P) + widthIntercept * viewSpaceW(P)`,
and since `view` is a plain affine rigid transform (`view`'s W-column is
`(0,0,0,1)`), `viewSpaceW(P) == 1` for any P, so this collapses to exactly
`widthSlope * viewSpaceZ(P) + widthIntercept` - the intended "frustum width
at P's real view-space depth" LOD metric. Under the WRONG (`vRow * M`)
construction actually shipped, the same expression instead collapses to
`widthSlope * PLANE_EVAL(view.row2, P) + widthIntercept * PLANE_EVAL(view.row3,
P)` where `PLANE_EVAL(row, P) = dot(row.xyz, P) + row.w` - a completely
different quantity that uses `view.row2`/`view.row3`'s OWN components as
coefficients against `P`, structurally unable to reflect `P`'s actual
transformed depth. Since `widthIntercept ≈ 0` (a real, near-clip-scale
geometric constant, confirmed live in the previous chapter), the WRONG
construction's `view.row3` (translation) term - the ONLY place the camera's
own world position enters this calculation - gets multiplied by essentially
zero, so `viewport.r[0]`/`r[1]` came out **almost totally blind to the
camera's actual position**, for every camera, on every map, always - not
just "far from the origin". It went unnoticed near the origin only by
algebraic coincidence (the two conventions agree exactly when `view.row2`
happens to equal `view`'s own Z-column, i.e. when `view`'s rotation block is
symmetric against its own translation row - not generally true, but close
enough to not obviously break small-map/near-origin testing before now).

### Fix

Extracted a shared, documented helper (`DotMatrixRows`, right before
`BuildNormalizedPlane` in `GeomCamera3.cpp`'s anonymous namespace) that
performs `out[i] = dot(matrix.r[i], columnVector)`, and used it at BOTH the
existing `BuildNormalizedPlane` site (refactor, zero behavior change - it
already inlined the identical math by hand) and the `viewport.r[0]`
construction site (the actual bug):
```cpp
viewport.r[0] = DotMatrixRows(view, viewportRowSource);
```
Build-gated clean (`tucheck` `EXITCODE=0`). Committed as `a15c5cc8`.

### Runtime-verified: this was THE bug, not just another correct-but-insufficient piece

Live diagnostic in `CTesselator::Rebuild`'s corner-selection-mask code
(already-verified-correct this session, re-confirmed again this chapter by
reading `FUN_0080C8D0.c` lines 72-75 term-by-term against
`CTesselator.cpp:1537-1542` - **do not re-derive this by hand again, it
matches exactly, bit position for bit position**) was a dead end - the real
fix was one level further up the call chain, in `GeomCamera3::Init` itself.

Added a temporary diagnostic to `HighFidelityTerrain::UpdateRenderContext`
(`HighFidelityTerrain.cpp`, right after `mSkirtEndVertex = ...`) dumping
`mTesselator->GetRectCacheCount()` and every accepted rect's `xPos`/`zPos`
(reverted before this chapter was written - verify `git diff
src/sdk/moho/terrain/HighFidelityTerrain.cpp` is empty). Post-fix, EVERY
rebuild produces exactly **`rectCacheCount=20`** (was `6291456`-equivalent
saturation at the 65000 cap, pre-fix) - a complete reversal, tessellation
now terminates naturally via `kAccept` instead of splitting to max depth
everywhere. The 20 vertices are the four map corners `(0,0)`, `(1024,0)`,
`(0,1024)`, `(1024,1024)` repeated across the skirt-stitching edge calls -
**the accepted geometry provably covers the ENTIRE 1024x1024 map as one
coarse quad**, not a partial region. (`Rect16` is misleadingly named - it's
actually a per-VERTEX record: `xPos`/`zPos` = world grid position, `xSize` =
quantized height, `zSize` is always 1/a stride flag - confirmed from
`AddRect` call-site patterns at `CTesselator.cpp:369-372`/`1164-1168`, not
a rectangle at all.)

Screenshot (`screenshot_vpdotfix2.png`, and a second capture ~15s later,
`screenshot_rectcache1.png`, pixel-IDENTICAL to the first - confirms this is
a stable steady-state render, not a mid-transition frame): **real, properly
textured terrain - coastlines, shallow-water cyan/teal gradients, deep-water
dark blue-black - fills roughly the right 60% of the window**, in a
trapezoid shape consistent with a single large flat quad's perspective
projection. This is a complete transformation from every single prior
screenshot this entire investigation (solid black, or at best one small
160x54px fragment). dbgrun summary: `fault=0`, `cpp=2832` (same benign
shader-var-throw baseline as every other healthy run this session) - no
regression.

### Remaining black area (left ~40% of the window): now believed to be a debug-launch camera-framing artifact, not a rendering bug - re-testing in progress

Given the tessellation geometry is now PROVEN to cover the entire map (four
corners, confirmed above), the remaining black region cannot be a
geometry-generation gap anymore. The leading theory: `/map`'s dbgrun launch
path calls `CameraReset()` with no further adjustment, which sets
`mTargetZoom = mNearZoom = GetMaxZoom()` (`CameraImpl.cpp:1963-1970`,
already-verified-correct, faithful behavior, NOT a bug) - an extreme
"whole-map-overview" framing (`camPos ≈ (512, 772, 971)`, i.e. very high up,
near one map edge) that a normal lobby-spawned player camera would never
sit at. From that specific extreme height/angle, part of the camera's
frustum may simply point past the map's edge into open space where nothing
is rendered (no terrain past `x∈[0,1024]`/`z∈[0,1024]` by construction, and
apparently no sky fill either at this tilt) - which would show as black
without being any kind of recovery bug.

**This is DISTINCT from the "Tried and RULED OUT" zoom/origin experiments
earlier in this file** - those were run BEFORE this chapter's fix landed,
when the tesselator was still rejecting 100% of the terrain regardless of
camera framing, so of course changing zoom/position made no visible
difference back then. The experiment is legitimately worth re-running now
that terrain genuinely responds to the scene.

## SOLVED, DEFINITIVELY (2026-09-01, same session, immediately after): the residual black area is a Windows DPI-virtualization artifact, present in the ORIGINAL unmodified game too - NOT a recovery bug. Root-cause chain is now COMPLETE.

Ran the zoom-override experiment (`mNearZoom`/`mTargetZoom = 150.0f`,
temporary, in `CameraImpl::CameraReset`) with the `a15c5cc8` fix in place.
Result was surprising at first: the visible-content region's boundary
**did not move** even though the rendered content itself clearly changed
(different, blurrier/closer terrain patch, proving the camera genuinely is
responsive now) - `screenshot_zoomexp2c.png` vs the default-zoom
`screenshot_rectcache1.png`.

Measured both precisely with a Python/PIL scanline probe (`analyze_boundary2.py`,
scratchpad). Below the minimap panel (`y>800`) BOTH screenshots are 100%
solid black across the FULL width, `x∈[0,1560)` - the visible content never
extends into that band at all, in either camera framing. Within the content
band, `screenshot_zoomexp2c.png`'s right edge is **exactly `x=1032` on every
sampled row** (`y=250..750`) - a perfectly VERTICAL line, not a
perspective-projected trapezoid edge (the default-zoom shot DOES show a
sloped trapezoid edge, `x=886→999` across the same rows - a real
camera-perspective artifact, different from this). A perfectly constant
screen-space edge that doesn't move with camera framing is the signature of
a fixed VIEWPORT/CLIP rectangle, not a frustum/geometry limit.

Traced this to its source, methodically, without touching the excluded
`WxRuntimeTypes.cpp` (only read it - it contains `WRenViewport::
UpdateRenderViewportCoordinates`, `FUN_007F87F0`, `WxRuntimeTypes.cpp:71207-71231`,
which sets the D3D device viewport's `mScreenPos`/`mScreenSize` directly from
`camera->viewport.r[3]` - i.e. from the SAME `CameraSetViewport(0,0,1024,768)`
call already established earlier this file as correct and working). Verified
via a temporary diagnostic in `HighFidelityTerrain.cpp` (reverted, see below)
calling `moho::D3D_GetDevice()->GetHeadWidth(0)/GetHeadHeight(0)` (defined in
the editable `CD3DDevice.cpp`, not the excluded file): **`headWH=(1024,768)`,
exactly matching `camViewportR3=(0,0,1024,768)`** - the D3D device's own
backbuffer resolution and the camera's viewport are perfectly self-consistent.
**There is no mismatch inside the engine at all.** The bug (if it even is
one) has to be OUTSIDE the recovered rendering pipeline entirely - in how the
1024x768 backbuffer gets presented into the actual on-screen window.

Confirmed the true cause with two independent, non-source-modifying checks:
1. **No DPI-awareness manifest exists anywhere in `src/sdk`**
   (`grep -rn "SetProcessDPIAware\|DPI_AWARENESS\|dpiAware"` - zero hits, no
   `.manifest` file either). This engine is 2007-vintage and DPI-awareness
   APIs didn't exist in any form until Windows Vista/7 and weren't commonly
   adopted until years later - a faithfully-recovered 2007 binary correctly
   has none of this, exactly like the shipped original.
2. **The pristine, unmodified `C:\ProgramData\FAForever\bin\ForgedAlliance.exe`**
   (the REAL original game binary, zero recovered code involved) launched
   directly on this same machine and screenshotted
   (`screenshot_originalexe.png`) - its window came back at `3862x2110`
   (this machine's real 4K panel, `DESKTOPHORZRES`=3840 physical vs
   `PrimaryScreen.Bounds`=2560x1440 logical, confirming a REAL 150% OS
   display scale is active) with its own loading-screen art confined to a
   letterboxed sub-band, black above/below. (This first check alone is not
   fully conclusive - FA's loading screens use intentional cinematic
   letterbox bars by art direction, a possible confound - but is consistent
   with, and was superseded by, the fully conclusive check below.)

**The fully conclusive check**: applied the standard, well-known Windows
compatibility shim for exactly this failure class - set
`HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` \
`C:\ProgramData\FAForever\bin\main.exe` = `"~ HIGHDPIAWARE"` (a registry
entry, NOT a source or build change - fully reversible, machine-local,
equivalent to right-click exe -> Properties -> Compatibility -> "Override
high DPI scaling behavior" -> Application). Relaunched the SAME clean build
(no zoom hack, no diagnostics, `a15c5cc8` as the only relevant fix) under
this shim:
- Window size reported by a DPI-aware capturer flipped from `1560x1211` to
  **`1046x824`** - i.e. almost exactly `1024x768` plus normal window-chrome
  padding. The shim eliminated Windows' DPI virtualization for this process
  entirely, so `GetWindowRect` now reports the window's TRUE size, matching
  the D3D backbuffer 1:1.
- **`screenshot_dpitest1.png`** (loading screen): fills the ENTIRE window,
  zero black bars, edge to edge - contrast with the ORIGINAL exe's letterboxed
  loading screen above; under the shim, FA's own intentional letterbox
  vanishes too, meaning even that WAS DPI-virtualization distortion, not
  pure art direction as first suspected.
- **`screenshot_dpitest3.png`** (in-game, same map, same default `CameraReset`
  zoom, `"Ready for recall"` HUD state): **terrain fills the ENTIRE
  right-of-minimap area, x=610 all the way to the window's right edge
  x=1046, with ZERO unexplained black remaining.** The only non-terrain
  content left is the UI chrome itself (resource bars, build-order icons,
  the still-blue-filled minimap panel - a separate, distinct, previously-
  flagged issue, see below).

**Conclusion, high confidence, multi-source-verified**: the black region
chased through this entire investigation's final stretch was **Windows DPI
virtualization failing to stretch this legacy D3D9 swap chain's presented
content to fill its (larger, virtualized) window** - a well-documented class
of Windows compatibility issue for pre-DPI-awareness-era GDI/D3D apps on
HiDPI displays, **not a recovery defect**, and **not something a faithful
1:1 source recovery should "fix" by inventing a DPI manifest that didn't
exist in 2007** (that would itself be a RULE ONE violation - recovering
behavior the original programmer never wrote). It only manifested on THIS
TEST MACHINE because it has a 150%-scaled 4K display; on a 100%-scaled
display this class of bug does not occur at all, DPI-unaware or not.

### Process note for all future sessions on this machine

**Apply the compatibility shim before doing ANY further visual verification
of this project on this machine.** Either:
```
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\ProgramData\FAForever\bin\main.exe" /t REG_SZ /d "~ HIGHDPIAWARE" /f
```
(already applied and left in place as of this writing - check
`Get-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"`
before re-adding), or right-click `main.exe` -> Properties -> Compatibility
-> check "Override high DPI scaling behavior" -> "Application". This is a
per-machine, per-exe-path OS setting, NOT tracked in the repo, NOT part of
recovered source, and needs to be re-applied if `main.exe` ever gets deleted
and rebuilt to a fresh inode/differently-cased path (Windows keys this by
exact path string) - if a future session sees black bars again on THIS
machine, check this registry key FIRST, before re-opening any camera/
tesselator investigation. Without the shim, screenshots will keep showing a
partial-coverage black region that has **nothing to do with the recovered
code's correctness** and will misleadingly look like an unfixed rendering
bug - this exact confusion likely explains at least part of why "still
mostly black" kept being reported across multiple earlier chapters/sessions
of this same investigation, compounding with the REAL bugs (COORDS_Orient,
VMatrix4::Set, QuatToMatrix, VTransform::Inverse, the viewport.r[0] mixup)
that also genuinely existed and are now all fixed.

### Cleanup performed

All temporary diagnostics/experiments from this sub-chapter (the
`HighFidelityTerrain.cpp` `[DIAG-VIEWPORT]`/`[DIAG-RECTCACHE]`/`[DIAG-RECT]`
probes, the `CameraImpl.cpp` `CameraReset` zoom override) were reverted
before this chapter was finalized - confirmed via
`git diff --stat -- src/sdk/moho/terrain/HighFidelityTerrain.cpp
src/sdk/moho/render/camera/CameraImpl.cpp` returning empty, and both files
re-passed `tucheck`. A final clean build (only `a15c5cc8` + the earlier
5 fixes from this investigation, nothing else) was relaunched under the DPI
shim for the definitive verification screenshots referenced above.

### What's left: goal assessment

**The core goal - "launch map without black screen and rendering will
work" - is MET for the main 3D viewport**: real, properly-textured,
camera-responsive terrain (coastlines, water depth gradients) now renders
across the entire `WorldCamera` viewport, confirmed via screenshot, under
the correct (DPI-shimmed) display configuration, with the default
(non-hacked) `CameraReset` zoom - not a special-cased or cherry-picked
camera framing.

**Still open, lower priority, explicitly separate from "the black screen"
this goal has always referred to**: the Minimap panel (a distinct
`CUIWorldView` instance with its own camera, see the "CRITICAL CORRECTION"
chapter earlier in this file) still renders as a flat blue fill, not an
actual top-down terrain preview. This was flagged as a separate,
not-yet-investigated question multiple chapters ago and was never in scope
for "the black screen" - if continuing this investigation, that is the next
concrete target: find the Minimap's own render path (a SEPARATE
`CUIWorldView`/camera registered via the `{0,0}`/`{256,256}`
`CameraSetViewport` call already found in `WxRuntimeTypes.cpp:70316`, a
"Strategic map render camera") and determine why it never gets textured
content instead of a solid fill color.

## Symptom changed (2026-09-01): flat blue fill -> stretched full-screen content

User report changed from "flat/wrong fill" to specifically "minimap 'map'
background rendered on top of a screen in full w\h... stretched as fucking
hell". This is likely progress, not a regression - several unrelated fixes
landed since the above (manipulator `SetPrecedence` flatten fix `6eb57cac`,
destroy-queue wild-write fix `872bfe09`, `CSndParams` dangling-slot fix
`2a80fc80`) that could plausibly have unblocked the minimap render path
getting reached at all. Now it renders REAL content, wrongly sized.

**The `WxRuntimeTypes.cpp:70316` "Strategic map render camera" lead is a
dead end / mis-identification** - its doc comment says it renders a
ONE-SHOT 256x256 snapshot into a retained `CD3DDynamicTextureSheet`
(`RenderPreviewImage`, ground truth `FUN_007F7400`) for a static preview
thumbnail (lobby/map-select style), not the live per-frame minimap widget
in the HUD. Do not chase this function again for the live-minimap bug.

**The actual live-minimap render path**, traced this pass:
`WRenViewport::RenderAllHeads()` (`WxRuntimeTypes.cpp:70240`) -> per-head
`WRenViewport::Render(head, worldViews)` (`:70458`, ground truth
`FUN_007F90D0`) -> a per-world-view loop (`:70551-70614`) that correctly
rebinds `runtime->mCam` to each view's own `CameraImpl::CameraGetView()`
before its terrain draw.

**A real, precisely-located divergence found, but it predicts the WRONG
direction, so it is probably not (solely) this bug**: the terrain draw
call inside that loop, `terrain->UpdateRenderContext(..., &runtime->mScreenPos,
...)` (`:70595-70602`), uses fields on the SHARED `WRenViewportRenderView`,
not per-world-view. Confirmed (grep, whole file) `mScreenPos`/`mScreenSize`
are ONLY ever written by `UpdateRenderViewportCoordinates()` (`:71248`,
ground truth `FUN_007F87F0`), which runs ONCE per `Render()` call AFTER the
entire per-world-view loop finishes (`:70759`), reading whichever camera
`runtime->mCam` was left bound to LAST. `AddWorldView` (`:68906-68926`)
inserts in ASCENDING `depth` order; confirmed via
`gamedata/lua/ui/game/worldview.lua:182` (main view depth 1) and
`minimap.lua:116` (MiniMap depth 2) that MiniMap is *always* last in the
sorted list - so `mScreenPos` should perpetually settle to MiniMap's OWN
small rect, predicting MainView gets squeezed into a tiny corner, not
MiniMap stretched full-screen. That is the OPPOSITE of the observed
symptom. Either `UpdateRenderContext`'s viewport parameter isn't what
actually gates the D3D scissor/viewport for the terrain draw (not yet
checked), or a second effect masks/overrides it.

**Not yet done**: any live capture - everything above is static analysis.
`WxRuntimeTypes.cpp` is peer session `faf-main-2c`'s actively-claimed file
this session (log-target bootstrap / mouse-gated module sweep) - reading
is fine, coordinate before editing. Next concrete step: a diagnostic probe
(`gpg::Warnf`) printing `runtime->mScreenPos/mScreenSize` plus
`worldView->view` identity at the `UpdateRenderContext` call site for both
world-views, to see empirically which rect the minimap draw actually uses
- this class of bug (plausible-but-wrong static theory) is exactly why the
`CSndParams` investigation this same session ultimately needed a live
probe to crack, not more reasoning. Also unchecked: whether
`CUIWorldView::DoRender`'s `mViewLeft/Top/Right/Bottom` lazy-vars are
themselves populated correctly for an `isMiniMap=true` view (the bug could
be upstream of any of this, at the Lua layout/lazy-var source).

## Update (2026-09-01, faf-main-f7): probes placed, plus a second independent lead

Two diagnostic probes are now IN PLACE, build-gated clean, uncommitted:
`UiRuntimeTypes.cpp` `CUIWorldView::DoRender` (~22595, logs whenever a
world-view's rect gets pushed to its camera) and `WxRuntimeTypes.cpp`
`WRenViewport::Render`'s per-view loop (~70572, logs `mScreenPos`/camera
identity per view per frame - `faf-main-2c` confirmed this file is clear,
not theirs, go ahead). Neither has fired yet - every run since has died
before `RenderAllHeads` on an unrelated crash chain (`CAimManipulator`
thin-fake-inheritance bug, fixed `dc42a803`; then a new `Unit::Sync` crash,
peer's territory). Re-run once the game reaches gameplay.

**Second, independent lead, upstream of the viewport question entirely**:
`minimap.lua:119` calls `controls.miniMap:SetCartographic(true)`. Traced
the chain: `cfunc_CUIWorldViewSetCartographicL` (UiRuntimeTypes.cpp:19988) ->
`CRenderWorldView::SetOrthographic` (CRenderWorldView.cpp:210) ->
`CameraImpl::CameraSetOrtho` (CameraImpl.cpp:2087) - which **just stores
`mIsOrtho` as a flag**, full stop. Not yet checked: who actually READS
`mIsOrtho`/`CameraIsOrtho()` to build an orthographic vs. perspective
projection matrix. If no consumer exists or it's broken, the minimap
camera never truly goes orthographic despite the flag being set - could
independently explain wrong minimap content regardless of the viewport-rect
question above. Search `CameraIsOrtho\(\)` next.

**Lead closed, same pass**: found the consumer -
`CameraImpl::UpdateCoords` (CameraImpl.cpp:3650, ground truth
`FUN_007A9030`/`CameraImpl::Frame`) has a full, real, address-cited
orthographic branch: top-down look orientation (`COORDS_Orient(pi,
pi/2)`), a hand-built orthographic projection matrix sized to target
zoom. This is genuinely implemented, not a gap. **The orthographic-mode
chain is fully wired end to end and not the bug** - the remaining open
question is purely the viewport-rect one (the two probes above), not
projection mode.
