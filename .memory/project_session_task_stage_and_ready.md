---
name: project-session-task-stage-and-ready
description: CWldSession's constructor and WLD_DoInitializing were both partial lifts; completing them fixed ForkThread and the "waiting for other players" hang.
metadata:
  type: project
---

Two partial lifts around session startup, both fixed 2026-08-12. The pattern is
worth remembering: **a function with a "Partial lift of 0xXXXX ... tracked for a
subsequent pass" comment is a live bug, not a note.**

## `CWldSession::CWldSession` (0x00893160)

Missing pieces, each of which broke something visible:

- **Task stage** (`a460cfb`). The binary allocates a `CTaskStage`, swaps it into
  `mCurThread`, and publishes it on the session Lua state:
  `mState->m_luaTask = (CLuaTask*)mCurThread`. For a *root* state `m_luaTask`
  carries the owning `CTaskStage`, not a `CLuaTask` - `cfunc_ForkThreadL` reads
  it back with the same cast. Without it every session script calling
  `ForkThread` died with "Lua state has not been set up for multiple threads",
  4092 times in 75 seconds, starting at `SessionClients.lua`.
- **Scenario table** (`53d6304`). `SCR_FromString(launchInfo->mScenarioInfo,
  mState)` at 0x0089359B parses the lobby's serialized scenario into the
  session's own Lua universe. Left unbound, `mScenarioInfo` had a null owning
  state and every `SessionGetScenarioInfo` from the UI threw inside `PushStack`
  (7518 times). `Options.AllowObservers` comes off the same table.
- **`mCurFormation`** (`2d3d0b3`). `new CFormation` at 0x00893529.
  `SessionFrame` calls `UpdateOrientation` on it unconditionally.

Still missing from that constructor: `mSessionRes1` (the 0xCC0 CommandManager),
`userArmies` resize to the army count, `cmdSources` copy, `FocusArmy` from
`mCommandSources.mOriginalSource`, `IsCheatsEnabled` from the launch info, the
spatial-DB and VisionDB sizing, and the cursor seed from map bounds.

## `WLD_DoInitializing` (0x0088C3F0) - 228 instructions, six were lifted

This is the loading-to-playing handover. After `UI_StartGameUI` the binary runs
`DoBeat(syncData)`, `StopLoadingDialog`, `CreateGameInterface(isReplay)`,
deletes the session info, runs the loader teardown callbacks, and then calls
`clientManager->Cleanup()`.

**That last call is why a local skirmish sat on "waiting for other players".**
`CClientManagerImpl::Cleanup` (0x0053E4B0, vtable slot 11 - IDA's name; it means
"loading finished, tell every client") is the only writer of `mWeAreReady`, and
`DoBeat` will not set `mEveryoneIsReady` until `mWeAreReady` is already true. It
has no code xrefs at all, only the vtable data ref, which is why searching for a
caller failed - the caller is this function, dispatching virtually.

Landed in `2d3d0b3`; the session now reaches `Playing` and the sim runs beats.

## What is still elided there

`CWldSession::DoBeat` (0x00894530, 1475 instructions) is the per-frame sim-state
consumer and is not lifted. Both `WLD_DoInitializing` and `SessionFrame`
(0x00895B40) call it in the binary. Until it lands the first sync payload is
dequeued for its driver-side effects but not applied - and not destroyed either,
because `~SSyncData` faults on a live payload: its teardown view reads an
`mTerrainUpdate` lane the constructor never initialises (SimDriver.cpp:887).

See [[project-shared-rules-race]] for the defect that follows this one.
