---
name: project-frame-side-table-and-close-chain
description: WSupComFrame overrides exactly 4 vtable slots - every other "override" in WSupComFrameRuntime was a fabricated side table, and that is what broke resize. Also the WM_CLOSE chain, the load-bearing catch in CD3DDevice::Clear, and the IDA wide-string truncation trap.
metadata:
  type: project
---

Established 2026-08-05. Commits 5124b32, 3077e34, 4453f6d.

## WSupComFrame overrides exactly four slots

Diff `??_7WSupComFrame@@6B@` (0x00E4F434) against `??_7wxFrame@@6B@`
(0x00D571AC) and only four differ:

| slot | offset | function |
|---|---|---|
| 1 | +0x004 | deleting dtor 0x008CE060 |
| 6 | +0x018 | GetEventTable 0x008CE090 |
| 124 | +0x1F0 | MSWWindowProc 0x008CDD40 |
| 125 | +0x1F4 | MSWDefWindowProc 0x008CDCD0 |

`WSupComFrameRuntime` had **seventeen** overrides against a
`SupComFrameState` map keyed on `this`. All but the four above were
invented. Script to re-run the check is in the session scratchpad
(`vtdiff.py A B N`, reads the PE + callgraph index).

**That side table is what broke resizing.** `DoGetClientSize` returned
`state.clientWidth`, whose only writer was `DoSetClientSize` being handed
the value `DoGetClientSize` had just produced - a closed loop that never
touched the HWND, pinned at the `wnd_MinDrag*` seed. So
`SyncSupComFrameClientSizeAndViewport` rebuilt the viewport and the D3D head
at 1024x768 for any window size: the fixed black rectangle in the corner.

Slots 102/105 are `wxFrame::DoGetClientSize` / `DoSetClientSize`, **not**
the wxWindow ones - wxFrame's subtract the client-area origin and a shown
status bar. SupCom has neither, so they reduce to wxWindow's.

## The catch in CD3DDevice::Clear is load-bearing

`CD3DDevice::Clear` (0x004300E0) wraps its body in
`catch (const gpg::gal::Error&) {}`. Evidence: `__ehfuncinfo` at 0x00EC2D50
= one try block, one handler, type `.?AVError@gal@gpg@@`, adjectives 0x9
(const + reference), dispCatchObj 0; funclet at 0x00430158 just returns the
epilogue address. Decode script: `ehinfo.py <funcinfo-va>` in the
scratchpad.

It has to be there. Clear runs from the frame's WM_SIZE handler, between
frames, and `GetHeadParameters` (0x008E82B0) creates the swapchain with
`EnableAutoDepthStencil = 0`, so the only depth-stencil is whatever the last
pass bound - a UI-only pass binds none. Probed at the throw site:
`GetDepthStencilSurface` -> D3DERR_NOTFOUND with a live render target, so
`Clear(target|z|stencil)` is D3DERR_INVALIDCALL. Without the catch, every
maximize/restore killed the process.

Related trap in the same function family: `GetHeadParameters` really does
`Windowed = !head.mWindowed` and `FullScreen_RefreshRateInHz = mWindowed ?
fps : 0`. The field is **misnamed** - `mWindowed != 0` means fullscreen. Do
not "fix" it.

## The close chain (3077e34)

`WSupComFrame::OnCloseWindow` (0x008CDAA0) and `OnMove` (0x008CDAD0) were
recovered but orphans. Three links were missing:

1. `wxWindowBase::Close` (0x00963220) did not exist.
2. `wxFrame::MSWWindowProc` (0x0099F4B0) was `{ return 0; }`. Its WM_CLOSE
   row is `processed = Close(this,0) == 0` - a close that goes ahead is
   deliberately NOT marked handled so DefWindowProc destroys the window;
   only a vetoed close is swallowed.
3. `WSupComFrame::GetEventTable` (0x008CE090) did not exist. Table at
   0x00DFE4EC = {base 0x00D56F70, rows 0x00F5BB4C}, two rows only.

wxCloseEvent layout (confirmed): loggingOff +0x20, veto +0x21, canVeto
+0x22. `Close` writes canVeto at +0x22; 0x00962A70 is SetCanVeto, not
SetLoggingOff. The ctor's `v8 = 1` is one 16-bit store covering +0x20/+0x21.

Note `OnCloseWindow` only calls `ExitMainLoop` when **iconized**; otherwise
it calls `ShowEscapeDialog(true)`. So X on a normal window is supposed to
raise the in-game quit prompt, not exit.

Also fixed: `wxTopLevelWindowRuntime::GetEventTable` built its table then
returned `nullptr`, dropping its own wxEVT_ACTIVATE row and every base table
behind it. ProcessEvent walks the chain via `wxEventTable::baseTable`, so
these must return `&sm_eventTable`.

**Shutdown AV - FIXED (00ceb7f).** `wxWindowBase::~wxWindowBase`
(0x00965730) opens with two statements this tree never had:

```
wxList::DeleteObject(&wxPendingDelete, this);
wxList::DeleteObject(&wxTopLevelWindows, this);
```

`gWxTopLevelWindows` is appended to in `wxWindow::Create` and was never
erased from, so a destroyed frame left a dangling pointer that
`WxSendIdleEventsRuntime` dereferenced on the way out of `WIN_AppExecute`.
Latent for the whole project; only reachable once WM_CLOSE could end the
main loop.

Put in `~wxWindowMswRuntime`, **non-virtual and deliberately not on
wxWindowBase**: wxWindowBase models the binary's vtable slot-for-slot (its
deleting-dtor slot is `DeleteObject`), so a real C++ destructor there would
insert a slot the binary does not have. Every teardown path already runs
`~wxWindowMswRuntime`.

Closing a minimised frame now exits with code 0 and `cpp=0 fault=0`.

## IDA truncates wide strings (4453f6d)

The frame icon name at 0x008CD9F2 prints as `"ID"`. The bytes at 0x00E4E5D8
are UTF-16 `L"IDI_WIN_FAICON"` - IDA decoded ANSI and stopped at the first
embedded NUL. It matches the GROUP_ICON at rva 0x00E8A2E0. **Any wide-string
constant taken from an IDA `aXxx` label may be truncated the same way.**

## Taskbar icon - DONE (0712519), and the code half was the smaller half

Two gaps, only one of them code:

1. **`main.vcxproj` compiled no `.rc` at all.** Added
   `src/sdk/moho/app/MohoResources.rc` + `res/faicon.ico`, the GROUP_ICON at
   rva 0x00E8A2E0 rebuilt from its nine ICON entries (16/32/48/256 px at
   4/8/32 bpp). It is a *named* resource, which is what an .rc line gives
   when the symbol is not `#defined`. `ExtractAssociatedIcon` now returns
   pixel-identical results for our main.exe and ForgedAlliance.exe.
   **This is what actually fixes the reported symptom.**
2. No `wxIcon`/`wxIconBundle` existed. Recovered wxIcon (0x009AA610 /
   0x009AA540 / 0x004FB7B0/D0/E0), the wxGDIImage handler registry
   (0x009AAE00 / 0x009ABA00 / 0x009ABA70), `wxICOResourceHandler::Load`
   (0x009ABE80), `wxGetHiconSize` (0x009AAF60), wxIconBundle (0x0098BEC0 /
   0x009F3220 / 0x009F2FE0) and SetIcon/SetIcons/GetIcon (0x0098C640 /
   0x0098C6B0 / 0x0098BFA0). `WX_CreateSupComFrame` runs the ctor tail from
   0x008CD9E9.

`InitStandardHandlers` registers 1 handler where the binary registers 4; the
other three are BMP resource / BMP file / ICO file, want wxBitmap, and
nothing in this engine loads those types. Registered next to
`wxInitializeStockObjects` - an empty handler list makes LoadFile a no-op.

**Trap, verified against the reference binary - do not "fix" this.**
`SetIcons` compares against a literal 16 and 32 before sending each half of
WM_SETICON, but `LoadIcon` returns the icon at the *physical* large-icon
size, so a DPI-unaware process on a scaled display gets 48x48 and neither
check passes. Ran the shipped ForgedAlliance.exe at 150%: `WM_GETICON`
answers ICON_BIG and ICON_SMALL with **nothing**, and its window class
carries no icon either - identical to ours. Its taskbar icon is the
executable resource Windows falls back to. At 100% the metric is 32,
everything lines up, and ICON_BIG does get set.

Recipes in the session scratchpad: `peres.py <exe>` dumps the resource
directory, `exticon.py <exe> <groupname> <out.ico>` rebuilds a .ico,
`icontest.ps1 -ProcName <name>` reports a live window's icons.

Related: [[project-resize-crash-depth-stencil-binding]],
[[project-frame-driver-refresh-stub]], [[project-gal-device-vtable-mismatch]]
