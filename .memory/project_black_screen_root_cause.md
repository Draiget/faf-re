---
name: project-black-screen-root-cause
description: The render path DOES run - OnPaint, Paint and the frame tick all fire every frame with ready=1. Earlier notes claiming it never runs were built on unverified probes and are retracted. The black screen is an output problem, not a dispatch problem.
metadata:
  type: project
---

**Read this before touching the paint/dispatch path. Two earlier versions
of this note claimed the render path was never entered. Both were wrong.**

## What is actually true (all probes byte-verified in the STAGED exe)

    CScApp::Main()                   FIRES every frame
    CD3DDevice::Refresh()            FIRES, viewport non-null (vp=04657800)
    wxWindowBase::Refresh()          -> InvalidateRect
    wxWindowMswRuntime::HandlePaint  FIRES, this = the viewport
    ProcessEvent                     paint reaches the tables, not swallowed
    event table row                  type=10008 id=-1  <- matches wxEVT_PAINT
    WD3DViewport::OnPaint  ENTRY     FIRES every frame, this=<viewport>
    ... after wxPaintDCRuntime ctor  FIRES, ready=1 from call #2 on

`OnPaint`'s body is

    if (IsReady() && device != nullptr) { ...; device->Paint(); return; }

with `ready=1`, so **`CD3DDevice::Paint()` is called every frame.** The
dispatch chain is healthy end to end.

## The mistake that produced two wrong root causes

`bld.bat` builds into `output\main\Win32\Debug\`. The **staging xcopy** is
what puts the exe where `run-engine.bat nobuild` runs it. Twice I built a
probe, saw zero hits, and concluded the function was never called - when
the probe simply was not in the running binary.

**Always byte-check the probe string in
`C:\ProgramData\FAForever\bin\main.exe` before believing a negative.**

    python -c "d=open('C:/ProgramData/FAForever/bin/main.exe','rb').read(); print(d.count(b'DIAGPROBE'))"

Second trap, same family: a probe placed **after** a constructor cannot
distinguish "not called" from "died in the constructor". Probe the FIRST
statement of a function when asking whether it runs at all. My
`OnPaint` probe sat after `wxPaintDCRuntime paintDc(this);` and read as
"fires once" when it actually fires every frame.

## Hypotheses killed by evidence - do not revisit

  1. Idle-spin: `ProcessIdle` returns 0, `app->Main()` is reached.
  2. Event-type mismatch: table stores a *pointer* to
     `gWxEvtPaintRuntimeType`; the factory calls the same
     `EnsureWxEvtPaintRuntimeType()`. Both read 10008.
  3. Pushed handler swallowing the paint (CUIManager MAUI mapper): probe
     shows the paint reaching the tables.
  4. Wrong `GetEventTable()` / inverted inheritance breaking the lookup:
     the returned table carries the 10008 row with `id=-1`.
  5. Missing `this`-adjustment in `InvokeWxEventTableHandler`: `OnPaint`
     receives the correct viewport `this`.
  6. `gal::Error` throws from `DeviceD3D9::Clear` on WM_SIZE: expected and
     caught in the shipped binary.

## The WHOLE chain runs. Probed inside Paint:

    DIAGPROBE Paint #1 coop=0 clear=0 vp=04657800
    DIAGPROBE Paint->OnDeviceRender #1
    ... repeating every frame

`coop=0` (device healthy, no lost/reset), `clear=0`, and `Paint` takes
the **`D3DWindowOnDeviceRender()`** branch - so `RenderAllHeads` and
`Render(head, worldViews)` run too. `Present()` is called every frame.

That was the third zero-hit probe from batch 98 to turn out unverified.
**All three** of the "never called" claims were tooling error.

So the complete path is live:

    Main -> Refresh -> InvalidateRect -> WM_PAINT -> HandlePaint
      -> ProcessEvent -> OnPaint -> Paint -> Present
        -> D3DWindowOnDeviceRender -> RenderAllHeads -> Render

## RESOLVED - there are zero world views. Nothing is registered to draw.

    DIAGPROBE RAH #1 heads=1 wvFirst=00000000 wvLast=00000000 count=0

Every frame. `RenderAllHeads` runs with `mNumHeads=1` and an **empty**
world-view vector, so `Render(head, worldViews)` correctly draws nothing.

**The black screen is not a defect at this stage.** The render path is
healthy end to end - it presents an empty scene because the engine has no
session and no map loaded. These runs pass only `/windowed 1024 768`.

The remaining question is not "why is rendering broken" but **"why is no
world view registered"**, i.e. why no session/map is being started - and
whether the menu UI should be drawing in the meantime.

## Superseded question: so why is the window empty?

The engine renders and presents every frame. Nothing in the dispatch or
device layer is broken. Two candidates remain, and they are ordinary:

  1. **There is nothing to draw.** These runs launch with no map and no
     session - `/windowed 1024 768` only. An empty 3D scene legitimately
     presents black. The operator asked to "start with a map"; that was
     never actually done, so a black 3D view may be *correct* here and the
     real question is why no **menu UI** appears.
  2. **The UI layer draws nothing** - worth checking
     `runtime->mWorldViews` is non-empty in `RenderAllHeads`, and whether
     the UI pass (`ren_Ui`, CUIManager) has anything registered.

Next: probe `RenderAllHeads` for `mNumHeads` and whether
`mWorldViews.mFirst != mLast`, and **launch with an actual map/session**
before calling a black 3D view a defect.

`HardwareMeshBatch::FillBatch` remains a genuine unresolved external
(vtable slot 9 pointing at garbage) and is worth fixing, but it is
downstream of whatever `Paint` decides.
