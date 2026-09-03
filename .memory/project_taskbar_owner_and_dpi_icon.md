---
name: project-taskbar-owner-and-dpi-icon
description: The frame had no taskbar button because MSWGetParent was the wrong function (hidden-parent accessor, not the virtual) - and the missing caption icon was a HIGHDPIAWARE compat shim, not a code bug. Also the exact current movie failure.
metadata:
  type: project
---

Established 2026-08-05. Commit bcaf2a9.

## MSWGetParent was the wrong function entirely

`wxTopLevelWindowMSW::MSWGetParent` is **FUN_0098CAB0**, not FUN_0098C9B0.

FUN_0098C9B0 takes no `this` and is `wxTLWHiddenParentModule::GetHWND` - the
lazy accessor for the single hidden window wx owns frames to when they must
stay off the taskbar. It had been attached to the vtable slot, so **every**
top-level window came back owned, and an owned top-level window gets no
taskbar button. That was the whole "window not in taskbar" report.

Proof, and the recipe for this class of mistake: search the image for the
address as a dword (`findslot.py` in the scratchpad). 0x0098CAB0 appears in
30 vtables at slot 115 (+0x1CC), including WSupComFrame's at 0x00E4F600
(head 0x00E4F434). **0x0098C9B0 appears in no vtable at all** - a function
with zero vtable occurrences is not a virtual, however much its shape fits.

The real body:

```
hwnd = (m_windowStyle & wxFRAME_FLOAT_ON_PARENT/0x08) ? m_parent->m_hWnd : NULL;
if ((m_windowStyle & wxFRAME_NO_TASKBAR/0x02) && !hwnd) hwnd = HiddenParent();
```

Verified by running the shipped binary side by side: both windows now report
`style=0x16CF0000 exstyle=0x00000100`, owner none. Use that as the regression
check - `tbprobe.ps1 -ProcName main|ForgedAlliance` in the scratchpad prints
style/exstyle/owner/icons and a taskbar-eligibility verdict.

MSWGetStyle's local constants were also misnamed for the same bits: 0x04 is
wxFRAME_TOOL_WINDOW, 0x20000000 is wxCAPTION, 0x02 is wxFRAME_NO_TASKBAR,
extra-style 0x08 is wxTOPLEVEL_EX_DIALOG, 0x40000 is WS_EX_APPWINDOW.

## The missing caption icon was NOT a code bug - it was a DPI compat shim

Symptom: taskbar button showed the flame (executable resource) but the window
itself had the generic default icon. `WM_GETICON` answered nothing.

Root cause: `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`
carried **`HIGHDPIAWARE`** for both `main.exe` and `ForgedAlliance.exe`. That
makes the process system-DPI-aware, so at 150% scale `SM_CXICON` is 48,
`LoadIcon` hands back the 48x48 image, and wx's SetIcons - which compares
against a **literal** 16 and 32 - rejects it and never sends WM_SETICON.

Removed the shim for `main.exe` only. To restore:
`reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\ProgramData\FAForever\bin\main.exe" /d HIGHDPIAWARE /f`

After removal: `ICON_BIG = 32x32 bpp=32`, `ICON_SMALL = <none>` - exactly what
the binary produces, since the bundle holds one 32x32 icon so the 16x16 request
never matches and Windows scales the caption icon down from BIG.

**Two measurement traps this cost time to:**
  - PowerShell is DPI-unaware, so `GetDeviceCaps(LOGPIXELSX)` reports 96 and
    `SM_CXICON` 32 **even at 150%**. Do not conclude the display is at 100%
    from a PowerShell probe. Measure in-process.
  - `SendMessageTimeout(WM_GETICON)` returns 0 both for "no icon" and for
    "window busy". Always check the call's own return value - `iconwait.ps1`
    retries until the call succeeds, `tbprobe.ps1` flags the failure.

## Movie: exactly where it fails today

Not a regression from the window work. `/movies/` **is** mounted and the engine
**does** reach the open; it is rejected during header classification:

```
ours       debug: OpenMovie /movies/thqlogo.sfd: 0
           warning: /movies/thqlogo.sfd is not a valid SFD file.
reference  debug: OpenMovie /movies/thqlogo.sfd: 1
           debug: Preparing movie /movies/thqlogo.sfd: 1   (x4)
```

That warning is the `(streamType != 3 && streamType != 1) || !headerValid`
branch in `CMovie::OpenMovie`, so `mwPlyGetHdrInf` returned streamType 0. The
chain `SFD_AnalyCreInf (0x00AD9FC0) -> sfcre_AnalyCreInf (0x00ADA020) ->
sfcre_AnalySfh (0x00ADA2B0) -> SFHDS_IsSfdHeader (0x00AE7280) -> SFH_Create /
SFH_IsSfdHeader` is all **recovered**, so this is a behaviour bug in one of
them, not a missing body. Next step is a probe at each link to find which one
stops identifying the pack. Note `mwPlyGetHdrInf` writes width/height into
reserved18/1C and then `MWSFFRM_AnalyzeSofdecHeader` overwrites both - check
that against the binary while you are in there.

Also seen intermittently: the run hangs in the Lua GC (`reallymarkobject`),
which is the separate documented wild write.

Related: [[project-frame-side-table-and-close-chain]],
[[project-sofdec-movie-crash]], [[project-resize-path-and-depth-stencil]]
