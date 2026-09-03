---
name: project-splash-click-crash-solved
description: SOLVED (ab38d43) - clicking through the splash crashed because the Lua click handler freed the CMauiFrame under CMauiControl::PostEvent's walk. Records the real mechanism and corrects two wrong conclusions from the hunt.
metadata:
  type: project
---

# SOLVED: click during splash crashed in PostEvent's parent walk

Fixed in `ab38d43`. `EXCEPTION_ACCESS_VIOLATION` reading `0x00000044` inside
`moho::CMauiControl::PostEvent`, reached from `OnMouseMove`, on the click that
ends the splash movies.

## The mechanism

`0x44` is a **vtable slot offset**, not a field offset. `HandleEvent` is virtual
(`UiRuntimeTypes.h:1251`), so the faulting read is `[vptr + 0x40]` through a
**null vptr** — a virtual dispatch on a released control. Chain, from a
symbolised destructor backtrace:

    control's HandleEvent runs script
      -> EngineStartFrontEndUI -> UI_StartFrontEnd -> CUIManager::SetNewLuaState
      -> ReleaseFrameSharedPtrRange -> shared_ptr<CMauiFrame>::reset
      -> ~CMauiFrame -> ~CMauiControl

`PostEvent` reads a control's parent *before* handing the event to script and
dispatches to it *after*, so the script freed the frame it was about to call.
`~CMauiFrame` also deletes the wx event mapper whose method is on the stack.

Both `PostEvent` (FUN_00787370) and `SetNewLuaState` (FUN_0084CC50) **match the
binary** — verified against the decompiles. Neither is where the bug is. The
original survives on the freed block staying intact.

## The fix

The engine's answer to this hazard is deferral: `Destroy()` queues a control,
`PurgeDeleted` frees it on the tick. Controls were already covered by the
dispatch guard. **Frames were not**, because a frame's owner is a `shared_ptr`,
not the deleted-control list, so `reset()` ran `~CMauiFrame` inline.

`ReleaseFrameSharedPtrRange` (the single choke point for all three frame-release
paths) now parks the owning reference in a retired list when
`moho::MAUI_EventDispatchInProgress()`, and `CUIManager::UpdateFrameRate` drops
it on the next tick. Non-dispatch callers are unchanged.

## ⚠ Three wrong conclusions from the hunt — do NOT repeat

1. **"`mParent` reads back as `0x00000004`, so a live control points at a freed
   parent."** WRONG, and it cost a whole pass. The `4` was the *freed block's*
   contents, and the fault was never the `mParent` read at all — it was the
   virtual call on the next line. **Check which statement the line number names
   before theorising about which field is corrupt.**
2. **"It's a destructed object with a cleared vptr", tested by probing the walk
   cursor.** The probe fired zero times because it ran at the *top* of the loop,
   before the `HandleEvent` that does the freeing. The vptr genuinely is null —
   just not when that probe looked.
3. **"`this == nullptr` at PostEvent entry."** Never was; `this` is always a real
   pointer in the logs.

`4` is not corruption, it is the engine's **"null control" encoding**: control
pointers are stored as `control + 4` and resolved as `ptr[-1]`, so a null
control stores `0 + 4`. `func_OnMouseMove` (FUN_007A4970) checks `!= 4` before
every dereference of its stack sentinel. Expect to see `4` anywhere a control
sentinel is empty.

## Reproducing without a human

`scratchpad/clicktest.ps1` does the whole loop: launches with `/windowed 1024
768 /nobugreport /log`, waits, then `PostMessage`s WM_MOUSEMOVE +
WM_LBUTTONDOWN/UP to every window of the process (top-level +
`EnumChildWindows`) for N rounds. `SetForegroundWindow` is blocked here, so
synthetic input must be posted, and it must go to the **child** window.

Always run with `/nobugreport`; the default crash path blocks forever in the
BugSplat sender, so a crash presents as a hang.

Symbolising a runtime address: log `GetModuleHandleW(nullptr)` as the load base,
then `scratchpad/symat.exe <exe> <loadbase-hex> <addr-hex>...`.

Related: [[project-ui-input-never-dispatched]],
[[project-movie-resize-crash-null-vptr]].
