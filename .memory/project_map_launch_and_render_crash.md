---
name: project-map-launch-and-render-crash
description: The engine loads a real map and session end-to-end, then crashes in RenderAllHeads dereferencing a null world-view. How to launch with a map, and where the maps actually live.
metadata:
  type: project
---

## Launching with a map - it works

    main.exe /windowed 1024 768 /map SCMP_009 /log <path>

`CScApp::InitializeSessionFromCommandLine` (0x008CE3D0) accepts
**`/map <name>`** or **`/scenario <name>`** (also `/replay`, lobby
host/join, `/perf`, `/gpgnet`). Script:
`<scratchpad>/runmap.bat <MapName> <seconds>`.

**Maps are mounted from the Steam install, not from FAForever or
Documents:**

    g:\games\steamapps\common\supreme commander forged alliance\maps

61 maps there, `SCMP_001` .. `SCMP_0xx`. A name from
`Documents\My Games\...\Maps` fails with

    Error launching session: Map scenario file does not exist at location
    "/maps/<Name>/<Name>_scenario.lua"     (singleplayerlaunch.lua:151 FixupMapName)

## How far it gets

With `SCMP_009` the log goes from ~530 lines to **3545**. It loads the
scenario, creates armies (`CreateArmy group ARMY_2` .. `ARMY_8`,
`NEUTRAL_CIVILIAN`), hooks UI mods, builds build-templates. Session
bootstrap is genuinely working.

## Then it crashes - THE next thing to fix

    CRASH: EXCEPTION_ACCESS_VIOLATION (0xC0000005) at 0x00C49F1E
    CRASH: attempted to read memory at 0x00000004
      moho::WRenViewport::RenderAllHeads + 222
        (WxRuntimeTypes.cpp:64990)
      moho::WD3DViewport::D3DWindowOnDeviceRender + 15

Line 64990 is the world-view tick at the top of `RenderAllHeads`:

    for (WRenViewportWorldViewParamRuntime* worldView = runtime->mWorldViews.mFirst;
         worldView != runtime->mWorldViews.mLast;
         ++worldView) {
      worldView->view->Func1();          // <-- faults here
    }

Reading **0x00000004** means a null base plus a 4-byte field offset - so
either `worldView->view` is null and `Func1` is reached through it, or the
`mWorldViews` first/last pair is not a valid range. Note this only fires
once a session exists: with no map, `count=0` and the loop never runs,
which is exactly why every no-map run looked "healthy but black".

## ROOT CAUSE - CUIWorldView::mRenderVftable is never assigned

The loop and `AddWorldView` are both fine. What is registered is:

    UiRuntimeTypes.cpp:19226
    auto* const renderView =
        reinterpret_cast<moho::IRenderWorldView*>(&view->mRenderVftable);
    ren_Viewport->AddWorldView(renderView, ...);

This is the **CUIWorldView MI flip**: the binary has `CUIWorldView`
multiply-inherit `IRenderWorldView`, so the compiler installs a second
vtable pointer in the ctor. This tree models that subobject as a manual
`void* mRenderVftable` field at **+0x11C** and hands out its address as
the interface pointer.

For that to dispatch, `mRenderVftable` must *hold the vtable*. It has
**exactly four references in the whole tree** and none of them writes it:

    UiRuntimeTypes.cpp:2500   void* mRenderVftable;   // +0x11C   declaration
    UiRuntimeTypes.cpp:2543   offsetof assert
    UiRuntimeTypes.cpp:19226  read  (AddWorldView)
    UiRuntimeTypes.cpp:19324  read  (RemoveWorldView)

So it is zero, `renderView->__vftable` is null, and `worldView->view->Func1()`
reads slot 1 at address **0x00000004** - the exact fault.

**The fix, with the binary's own evidence.** `CUIWorldView::CUIWorldView`
(`FUN_0086E480`, 0x0086E480, 396 instrs) writes that field twice - base
first, then its own override:

    0x0086E4DF  mov [edi+11Ch], offset ??_7IRenderWorldView@Moho@@6B@
                                        ; the base interface vtable
    0x0086E4EF  mov [edi+11Ch], offset ??_7CUIWorldView@Moho@@6BIRenderWorldView@Moho@@@
                                        ; CUIWorldView's own, 0x00E490DC
    0x0086E825  lea eax, [edi+11Ch]     ; and hands that address out -
                                        ; this is the AddWorldView pointer

+0x11C is confirmed correct, and the field is a **real secondary vtable
pointer**, not a spare slot. Our ctor writes neither value, so it stays
zero.

Because this tree models the MI subobject as a plain `void*` rather than
a base class, the fix cannot just be "assign an address" - a C++ virtual
call through it needs a real dispatch table. Build a static table of
function pointers for `IRenderWorldView`'s slots, filled with
`CUIWorldView`'s implementations, and point `mRenderVftable` at it in the
constructor. Take the slot order from
`??_7CUIWorldView@Moho@@6BIRenderWorldView@Moho@@@` at **0x00E490DC**
(and the base at 0x00E4054C) - do not guess it. `Func1` is the slot
`RenderAllHeads` calls per world view.

This is the open todo already on file as "the CUIWorldView MI flip".

## Context

The render path itself is proven healthy - see
[[project-black-screen-root-cause]]. This crash is downstream of all of
it and only reachable with real content loaded.


## The vtable, dumped - and 10 of its 13 slots are already recovered

`??_7CUIWorldView@Moho@@6BIRenderWorldView@Moho@@@` @ **0x00E490DC**,
read out of `bin/external/ForgedAlliance.exe`. Slot order is
`IRenderWorldView`'s 13 virtuals as declared in
`moho/render/IRenderWorldView.h`:

    slot  addr        name                  recovered in
     0    0x0086EE00  Render                ** ABSENT **
     1    0x0086ECB0  Func1                 ** ABSENT **  <- the crash
     2    0x0086ECD0  RenderCommandGraph    ** ABSENT **
     3    0x0086EBF0  GetCamera             ui/UiRuntimeTypes.cpp
     4    0x0086EBE0  GetCameraView         ui/CRenderWorldView.cpp
     5    0x0086EC00  GetCameraOffset       ui/CRenderWorldView.cpp
     6    0x0086EC10  CameraGetTargetZoom   ui/UiRuntimeTypes.cpp
     7    0x0086EC20  GetMaxZoom            ui/CRenderWorldView.cpp
     8    0x0086EC30  CameraGetZoom         ui/CRenderWorldView.cpp
     9    0x007F6260  Func2                 render/IRenderWorldView.cpp
    10    0x0086DC90  IsMiniMap             ui/CRenderWorldView.cpp
    11    0x0086DC00  SetOrthographic       ui/UiRuntimeTypes.cpp
    12    0x0086DC60  CanShake              ui/CRenderWorldView.cpp

**`Func1` is slot 1, i.e. vtable+4** - which is precisely the 0x00000004
the crash reads through a null vtable pointer. The diagnosis is closed.

The base `??_7IRenderWorldView@Moho@@6B@` @ 0x00E4054C is mostly
`_purecall` (0x00A82547) with real bodies only for Func1 (0x007F6250),
Func2 (0x007F6260) and IsMiniMap (0x007F6270) - consistent with the
header, where those three are the only non-pure virtuals.

**So the remaining work is small and bounded:**

  1. recover the three absent bodies - `Render` (0x0086EE00),
     `Func1` (0x0086ECB0), `RenderCommandGraph` (0x0086ECD0);
  2. build the 13-entry dispatch table in `ui/CRenderWorldView.cpp`
     (which already exists and already hosts six of the slots);
  3. point `mRenderVftable` at it in the CUIWorldView ctor, matching
     0x0086E4EF.

## Probe-address typo - made three times now

`for a in 0086EE00; do rg "0x00$a" ...` yields `0x000086EE00` and reports
everything ABSENT. The addresses in these dumps **already carry their
leading zeros**. Write `0x0086EE00` directly. This has produced a false
"nothing is recovered" three separate times this session.


## The three missing bodies, decoded

**slot 1 `Func1` (0x0086ECB0)** - 8 lines, and the one that crashes:

    int CRenderWorldView::Func1() {
      if (!mIsMiniMap)
        return sub_852C10(&this->mSubobject);
      // binary falls through returning whatever is in eax
    }

`sub_852C10` is **recovered**: it is
`CUIWorldViewBuildDragRuntimeView::UpdateDragPreview()` in
`ui/UiRuntimeTypes.cpp`. So `Func1` means *"refresh the build-drag preview
each frame, unless this view is a minimap"* - which is exactly the kind of
per-world-view tick `RenderAllHeads` runs it for.

`mIsMiniMap` is at **+0x19** of `CRenderWorldViewRuntimeView`
(UiRuntimeTypes.cpp:2187, asserted at :2280). The remaining unknown is
which field `&this->mSubobject` names - identify the build-drag subobject's
offset inside `CRenderWorldView` before writing it.

**slot 2 `RenderCommandGraph` (0x0086ECD0)** - 38 lines. Early-outs when
`mIsMiniMap` or SHIFT is not held (`MAUI_KeyIsDown(MKEY_SHIFT)`), otherwise
re-seats `mComGraph` from `CWldSession::GetCommandGraph(mWldSession, &result, 1)`
through the `WeakPtr_UICommandGraph` ctor/dtor pair.

**slot 0 `Render` (0x0086EE00)** - not yet read.

`CRenderWorldView` is declared at `ui/UiRuntimeTypes.h:3222` as
`class CRenderWorldView : public IRenderWorldView`, and
`ui/CRenderWorldView.cpp` already implements six slots as ordinary methods
(GetCamera, GetCameraView, GetCameraOffset, CameraGetTargetZoom,
GetMaxZoom, CameraGetZoom, IsMiniMap, SetOrthographic, CanShake).

**Note the tension to resolve first:** the class already inherits
`IRenderWorldView` properly in the header, yet the registration site hands
out `&view->mRenderVftable` - a raw field - instead of the object. Decide
which model wins before adding a hand-rolled dispatch table; if the real
inheritance works, the fix may be to pass the object and delete the manual
vtable field entirely.


## DO NOT EDIT CRenderWorldView.cpp right now - another agent owns it

`git status` shows `?? src/sdk/moho/ui/CRenderWorldView.cpp` - **untracked**,
i.e. a new file another agent is writing in this shared checkout as of
2026-08-17. Six of the thirteen slots appearing there is that work in
flight, not finished work.

Adding the three missing bodies or a dispatch table to that file now would
collide with them. Either coordinate, or land the fix in a file this work
owns. Same rule as always here: stage only your own files, never touch
another agent's unstaged or untracked work.
