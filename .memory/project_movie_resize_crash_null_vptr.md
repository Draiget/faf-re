---
name: project-movie-resize-crash-null-vptr
description: Resize/maximize during movie playback crashed with an AV reading 0 — CMovie modelled its Listener base as a plain `void* mVtable` lane that nothing could ever assign. Fixed 941238b. Also why crashes looked like hangs (3e253fb).
metadata:
  type: project
---

# Resize during movie playback = AV reading address 0 — FIXED (941238b)

Operator report: "when I click maximize during nvidia or any other video it's
crashing." It reproduced without any resize at all — window creation alone
fires the device event.

## The defect: a hand-modelled vtable pointer

`CMovie` carried its listener base as a **data lane**:

```cpp
struct DeviceEventListenerLane {
  void* mVtable = nullptr;            // +0x00   <-- nothing can ever set this
  TDatListItem<CMovie, void> mLink{}; // +0x04
};
```

The ctor links `mLink` into the D3D device's listener ring. `CD3DDevice`
**is a `Broadcaster`**, and a device reset walks that ring calling slot 0 on
each node's owner (`DispatchDeviceEventToListeners`, CD3DDevice.cpp:178). So
the first device event with a live movie loaded a null vtable and dereferenced
it → `EXCEPTION_ACCESS_VIOLATION ... attempted to read memory at 0x00000000`.

Needed a movie alive to reproduce: with an empty ring the dispatcher returns
early (`ListIsSingleton`), and the only other registrant, `DeviceExitListener`,
declares a **real** `virtual void Receive(...)` so it has a real vtable.

**Fix**: `class CMovie : public IMovie, public Listener<const SD3DDeviceEvent&>`.
`IMovie` is the primary base contributing only its vptr at +0x00, so the
`Listener` subobject lands at +0x04 with its vtable there and `mListenerLink`
at +0x08 — exactly the offsets that were hand-modelled. The handler became the
`OnEvent` override it always was. The binary's own dtor layout said so all
along: the teardown comment named the `~Listener<SD3DDeviceEvent const&>` base
subobject.

Also replaced `reinterpret_cast<...>(device) + 0x04` with
`static_cast<Broadcaster*>(device)` — same address, honest types.

## ⚠ The generalisable lesson

**A `void* mVtable` field in a recovered class is always a bug.** It is the
CLAUDE.md "no vtable magic" rule showing up as a crash rather than a style
complaint. Grep for it: any recovered type that is dispatched through by
something else must derive from a real polymorphic base so the compiler emits
the pointer. The same shape appears in listener/lane structs across the tree —
if the object is ever linked into a broadcaster ring, it needs a real vtable.

Sibling to check when a listener crashes: does the type declare a virtual, or
does it just *describe* one?

## Why the crash looked like a hang (fixed 3e253fb)

`TopLevelExceptionFilter` takes the BugSplat path by default
(`ShouldUseBugSplatPath()` is true unless `/nobugreport`). It destroys the main
window, suspends sibling threads, then blocks **forever** in
`MiniDmpSender` → `WaitForSingleObject` — no reachable endpoint, and the dialog
resource does not load in this build either. Symptom: live process, no window,
log stops mid-sentence, zero CPU. It reads as a hang; it is a crash.

Two things that make this diagnosable now:
- The filter logs the exception + symbolised callstack **before** either path
  (3e253fb), so every crash leaves a record.
- **`/nobugreport` selects the local dialog path** — use it on every dev run.

## Getting a stack out of an apparently-hung engine

`dbgrun` only reports on exceptions, so it has nothing to say about a process
already stuck in its own filter. `scratchpad/stackdump.cpp` (built this
session) attaches to a live PID and walks every thread with
StackWalk64 + SymFromAddr against the staged `main.pdb`. That is what showed
the filter blocked in `WaitForSingleObject` with the real fault four frames
below it. Rebuild it with `buildsd.bat` if the scratchpad is cleared.

Detecting the moment to dump: poll `(Get-Process).CPU` and dump when it stops
advancing — a crashed-then-blocked engine is at 0% CPU, not spinning.

Related: [[project-resize-crash-depth-stencil-binding]],
[[project-frame-driver-refresh-stub]], [[project-ui-input-never-dispatched]].
