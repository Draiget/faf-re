---
name: project-wx-frame-windowproc-vein
description: wxTopLevelWindowRuntime::MSWWindowProc translated only WM_CLOSE; its own declaration lists the missing cases. A productive, well-scoped vein - three landed 2026-08-17, three left with exact closures.
metadata:
  type: project
---

`wxTopLevelWindowRuntime::MSWWindowProc` (0x0099F4B0, the `wxFrame` slot)
is genuinely recovered, and its declaration in `WxRuntimeTypes.h` names
every case still missing:

> Only WM_CLOSE is translated so far. The binary's switch also covers
> WM_MENUSELECT, WM_ENTERMENULOOP/WM_EXITMENULOOP, WM_COMMAND, WM_SIZE,
> WM_PAINT and WM_QUERYDRAGICON.

That makes each case a self-contained recovery with a real recovered
caller - the best-shaped vein found in this pass.

## Landed 2026-08-17

  - `1bcef86` **WM_ENTERMENULOOP / WM_EXITMENULOOP**. Recovered
    `DoSendMenuOpenCloseEvent` (0x0099F410). Everything it needed was
    already modelled: `WxMenuEventFactoryRuntime` (mMenuId +0x20, ctor
    0x00979D60) and the `EnsureWxEvt*RuntimeType()` family - only the two
    menu-loop event types were missing from it. Both the event id and the
    menu-id lane get `-(isPopup != 0)`, so a popup reports -1.
  - `ca97340` **WM_PAINT**. Recovered `HandlePaint` (0x0099F0A0) and
    `GetDefaultIcon` (0x0099F040). Non-minimised frames paint through
    wxWindow; minimised ones draw their icon centred. The `39` handed to
    MSWDefWindowProc is WM_ICONERASEBKGND. Stock icons
    `wxSTD_FRAME_ICON` (0x00F8F810) and `wxDEFAULT_FRAME_ICON`
    (0x00F8F81C) both read 0x00000000 in the shipped image, so
    null-initialised globals are exact - they are filled by the wx
    stock-object init lane, not recovered yet.
  - `bfdc824` **annotation only**: `WxClassInfoDerivesFromRuntime` *is*
    `wxClassInfo::IsKindOf` (0x009627D0), 30 instrs / 20 callers, and had
    no address. See [[reference-have-set-detection-gap]].

## Left, with exact closures

**WM_SIZE** - `HandleSize` (0x0099F1C0, 55). Closure 4 fns / 223 instrs:

    FUN_0099F1C0  55  HandleSize
    FUN_0099EF40  86  IconizeChildFrames   <- the blocker
    FUN_0098D090  52  SendIconizeEvent
    FUN_009627D0  30  IsKindOf             <- DONE (bfdc824)

`SendIconizeEvent` is the same event-dispatch shape as the menu one
(`WxIconizeEventFactoryRuntime` already exists) and is trivial once
written. `IconizeChildFrames` is the real work: it walks the child list,
filters on `IsKindOf(wxFrame)` and `!IsKindOf(wxMDIChildFrame)`, and
needs `wxMDIChildFrame::sm_classInfo` plus an `m_wasMinimized` byte at
child +0x174 and vtable slots 133 (`Iconize`) / 135 (`IsIconized`) /
34 (`GetWindowStyleFlag`). Model those three first.

`HandleSize` decoded: switch on the size flag - RESTORED(0) and
MAXIMIZED(2) clear `m_iconized` (+0x130), MINIMIZED(1) sets it, and
either of the first two also runs `IconizeChildFrames` +
`SendIconizeEvent`. When not iconized it calls `PositionStatusBar`
(vtable +628) and `PositionToolBar` (+632) then defers to
`wxWindow::HandleSize`; when iconized it returns 0.

**WM_MENUSELECT** - closure 5 fns / 192 instrs, all `wxString`
machinery:

    FUN_0099F2F0 102  the handler
    FUN_00960860  44  wxString::InitWith
    FUN_0095FD20  32  wxString::AllocBuffer
    FUN_00422AF0  10  wxString::~wxString
    FUN_0095FD10   4  delete

**WM_COMMAND** and **WM_QUERYDRAGICON** not yet scoped.

## Both remaining cases bottom out in wx subsystems this game never uses

Chased 2026-08-17; recording so the next pass does not re-derive it.

**WM_SIZE** needs `IconizeChildFrames`, whose guard is
`IsKindOf(wxFrame::sm_classInfo)` (0x00F355B8) and
`!IsKindOf(wxMDIChildFrame::sm_classInfo)` (0x00F3A820). Both are real
`.data` objects and vendored wx 2.4.2 does ship `wxMDIChildFrame`
(`dependencies/wxWindows-2.4.2/include/wx/msw/mdi.h:191`,
`DECLARE_DYNAMIC_CLASS`). The problem is which class-info the *children*
carry: this tree builds its own runtime classes with their own
`sm_classInfo` objects (`wxTopLevelWindowRootRuntime::sm_classInfo` and
friends), so the hierarchy test needs a deliberate decision about
whether recovered runtime classes register against vendored wx class
infos. That is a wx-hybrid design call, not a layout lookup - see
[[project-wx-is-a-hybrid-link]] and [[project-wx-odr-conversion-plan]].

**WM_MENUSELECT** needs `SetStatusText` for its popup/separator branch.
The chain is short but lands in an unmodelled subsystem:

    FUN_009A92C0   7  wxFrameBase::SetStatusText  -> status bar vtable +528
    FUN_004BAAF0   2  wxFrameBase::GetStatusBar   -> returns m_frameStatusBar
    FUN_0099E780  11  wxStatusBar::dtr
    FUN_0099EA80  39  wxFrame::PositionStatusBar
    FUN_0099F830  97  wxFrame::OnCreateStatusBar

`wxStatusBar` is not modelled at all. In this engine `GetStatusBar()`
always answers null, so the branch is a no-op in practice - but writing
it needs the class to exist.

Note IDA mislabels the status-bar pointer as `m_oldStatusText.m_pchData`
in both accessors; it is `m_frameStatusBar`.

The unpack helper `sub_968BC0` (WM_MENUSELECT's wParam/lParam split) is
**already recovered**, so only the status-bar half blocks.

**Verdict:** the cheap cases in this vein are done. The two left are
worth doing only alongside a decision on the wx class-info hybrid, or as
part of modelling `wxStatusBar` - neither of which this engine exercises.

## Why this vein works

Each case is small, the caller is genuinely recovered (not a
comment-only stub), and the surrounding wx runtime turns out to be far
more complete than the missing-address sweeps suggest - twice in this
pass the "blocker" was already modelled and simply never connected.
Check what exists before concluding a case is blocked.
