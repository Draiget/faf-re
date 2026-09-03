---
name: project-black-screen-next-steps
description: Startup is exception-free and the whole paint chain is measured as reached, but the window is still black - the UI frame draws nothing. Records what is proven working, the capture recipe, and the two open leads.
metadata:
  type: project
---

State as of 2026-08-04. `cpp=0 fault=0`, resizes survive, but the client area
is **entirely black**. "Runs clean" turned out not to mean "renders", which is
worth checking explicitly every time.

## Proven reached (probe-measured, not inferred)

With the default (movie) path, `runwinlog.bat`:

- `CD3DDevice::Paint` runs: `init=1 ready=1 vp=1 clear=0`, so it dispatches to
  `WD3DViewport::D3DWindowOnDeviceRender` rather than `Clear`.
- `WRenViewport::Render` reaches its shared tail: `ren_Ui=1 mgr=1 head=0
  batcher=1`.
- `CUIManager::RenderFrames` is entered with `frames=1 valid=1 frameSet=1`.

So the message loop, paint dispatch, viewport render, UI draw and the frame
lookup all work. **The frame exists and is drawn - it just produces nothing
visible.** Next question is whether that frame has any children, i.e. whether
the Lua front end actually attached controls to it.

`da4bd46` fixed one real gap found on the way: the mask-4 `DrawUI` pass was
missing from the tail (`RenderFrames`=1 and `DrawHead`=8 were already wired).
That alone did not change the picture.

## Two open leads

1. **The frame may have no children.** Probe `CMauiFrame::RenderChildControls`
   for the child count per mask. If zero, the front end built no controls and
   the problem is in the UI Lua wiring, not the renderer.
2. **Five UI textures fail**: `scx_menu/profile/panel_bmp.dds` and the four
   `scx_menu/panel-brackets/bracket-*_bmp.dds`. Only 5 of 675 `.dds` paths
   fail, so texture loading broadly works - these are probably genuinely absent
   from FAF's data and a red herring, but confirm before dismissing.

## `/nomovie` is separately broken - do not use it to test rendering

With `/nomovie` the engine never reaches `CD3DDevice::Paint` at all (probe:
zero hits, vs three with the movie path). Its log stops during UI texture
loading inside `UI_Init`, i.e. still in `CScApp::AppInit`, before
`CreateDevice` and before the main loop. The older note recommending
`/nomovie` for window work is **superseded** - it takes a different and
currently broken path. Also note `runnomovie.bat` passes no `/log`;
`runnomovielog.bat` adds it.

## Capture recipe

`scratchpad/shot2.ps1` - finds the `main` window by pid, `PrintWindow` with
flag **2** (`PW_RENDERFULLCONTENT`, needed to pull the DWM-composited surface
so a windowed D3D back buffer is capturable), then counts non-black sampled
pixels so "did it draw" is a number rather than an eyeball. A fully black
client area reads as `nonblack 96/6596` (that 96 is the title bar).

**Do not use `CopyFromScreen`** - `SetForegroundWindow` fails silently when the
caller is not foreground, and the capture then silently grabs whatever window
is actually on top. That produced a screenshot of the editor that looked like a
real result.

Related: [[project-render-frame-blockers-2026-08]],
[[project-lua-gc-upvalue-corruption]]
