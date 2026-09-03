---
name: project_window_closes_process_survives
description: Operator symptom - window closes but the process keeps running with audio still playing in bursts. The whole C++ close chain was re-verified faithful to ground truth this pass, so the defect is NOT in OnCloseWindow/ShowEscapeDialog/ExitMainLoop. One concrete untested hypothesis remains - the last-top-level-window gate requiring the tracked-window map to hold exactly one entry.
metadata:
  type: project
---

## Verified faithful this pass — do NOT re-audit these

- `WSupComFrame::OnCloseWindow` (`WxRuntimeTypes.cpp:65696`, `FUN_008CDAA0`):
  when iconized calls `wxTheApp->ExitMainLoop()`, otherwise
  `moho::ShowEscapeDialog(true)`. Clicking X bringing up the in-game escape
  menu instead of quitting is the **original game's UX**, not a bug.
- `moho::ShowEscapeDialog` (`IUIManager.cpp:484`, `FUN_0083D340`): compared
  against the decompile — same `UI_Manager->mState`, `SCR_Import
  ("/lua/ui/uimain.lua")`, `operator[]("ShowEscapeDialog")`, `LuaFunction`,
  `Call_Bool`. Our extra `state == nullptr` early-return is a defensive
  addition (ground truth would fault there); harmless, not the bug.
- Virtual dispatch to the engine override is correctly wired:
  `wxApp::ExitMainLoop` is `virtual` (`WxRuntimeTypes.h:6647`),
  `MohoApp::ExitMainLoop` is `override` (`:7628`) and sets `m_keepGoing = 0`
  (`WxRuntimeTypes.cpp:68055`), which is exactly what `WxAppRuntime::
  KeepGoing()` (`WxAppRuntime.cpp:56`) tests and `WIN_AppExecute`'s loop
  breaks on. The base `wxApp::ExitMainLoop` only does `PostQuitMessage(0)`
  (`:67741`) and never clears the flag — but virtual dispatch means the base
  is not what runs.
- The auto-exit path exists and is wired: `WxRuntimeTypes.cpp:34086-34092`
  calls `wxTheApp->ExitMainLoop()` when
  `wxShouldExitMainLoopOnLastTopLevelWindowDelete(topLevelWindow)` is true.

## The one remaining concrete hypothesis (untested, needs a live run)

`wxShouldExitMainLoopOnLastTopLevelWindowDelete` (`WxRuntimeTypes.cpp:34485`,
`FUN_0098CEC0`) returns true **only** when
`gWxTopLevelWindowRuntimeStateByWindow.size() == 1u` and the window being
destroyed is that one entry (and `m_exitOnFrameDelete == kExitOnFrameDeleteYes`,
which `EnableLoopFlags` does set).

So if the engine ever registers **more than one** top-level window runtime
state — a hidden/never-shown frame, a debug/console frame, a dialog frame that
outlives its use, or a stale entry never erased on destroy — the size check
fails, `ExitMainLoop()` is never called, `m_keepGoing` stays 1, and
`WIN_AppExecute` pumps forever. That matches the symptom exactly: the visible
window is gone, but the process and its sim/audio threads keep ticking (the
"pauses" in the audio being an unattended message queue no longer feeding it
smoothly).

**Next step**: probe `gWxTopLevelWindowRuntimeStateByWindow.size()` at the
moment of the main frame's destroy, plus dump what each remaining entry is.
If size > 1, find who registers the extra entry and whether its destroy path
fails to erase. Do this with a temp `OutputDebugStringA` probe on a live run
rather than more static reading — the static chain above is already confirmed
faithful, so only runtime data can distinguish "gate correctly false" from
"stale entry never erased".
