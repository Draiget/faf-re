---
name: project-skirmish-doloading-loop
description: FIXED (6180829 + 0ac5e3b) - the world-frame machine looped Preload->Loading->CreateSession forever and the scenario worker was empty. Both recovered; a skirmish now runs the real load and stops on a stream defect inside RRuleGameRules::Create.
metadata:
  type: project
---

# Skirmish: how far `/map` gets, and what stops it now

`main.exe /windowed 1280 720 /nobugreport /map SCMP_009` is the headless
skirmish test - `InitializeSessionFromCommandLine` turns `/map` into
`/maps/<m>/<m>_scenario.lua` and reaches `LaunchSinglePlayerSession` without a
single click. Driver: `scratchpad/skirm.ps1`.

## What was wrong (all fixed)

`WLD_Frame` dispatches on `gWldFrameAction`. Two of its handlers were
stand-ins that fed each other:

    Preload       -> WLD_DoPreload         (real)   -> Loading
    Loading       -> WLD_DoLoading         STUB     -> CreateSession
    CreateSession -> WLD_CreateSessionInfo STUB     -> Preload

so a skirmish cycled forever, restarting the in-game UI and reopening the
loading movie every lap (measured: 85 UI restarts, 104 movie opens in 90s),
until the Lua module table degraded and `CUIManager::Init` died with no root
frame. Neither transition exists in the binary - `CreateSession` is the
**restart** path (`func_CreateSWldSessionInfo`, 0x0088C9D0) and only
`WLD_RequestRestartSession` reaches it.

Landed:

  - **`WLD_DoLoading` (FUN_0088C000, 342 instrs)** - beats the client manager
    each frame; once loaded takes the Lua state / rules / map, builds the
    session, gives the launch info its own `STIMap` copy and `__language`,
    hands single-player a shared clone of the launch info, creates the sim
    driver, and sets **Initialize**. Failure warns
    `"map %s failed.  aborting session."` and exits.
  - **`VCR_CreateReplay` (FUN_00875B60, 855 instrs)** - needed because
    `SetupCommandLineSkirmish` sets `createReplay = true`, so the recording
    branch is live. Writes the v1.9 replay header.
  - **`WorldSessionUserLoad` (FUN_00885DE0, 298 instrs)** - the scenario
    worker, previously an empty placeholder. Builds the rules from the mod
    list, makes a Lua state and runs the **Core then User** init-form sets on
    it, exports the rules into it, runs `/lua/SessionInit.lua`, loads the map.
  - the client-manager UI interface: the binary's `sCWldUiInterface` is a
    static object with a real ctor; ours was raw zeroed storage nothing ever
    constructed, so the first `ReportBottleneckCleared()` `DoBeat` dispatched
    read a vtable slot off address 0. Constructed on first use now.

## The blocker now

The worker throws on its **first** real step - probed with per-stage
`Debugf`, only "stage 1" prints:

    RRuleGameRules::Create(scenario->mGameMods, waitSet)
      -> std::runtime_error("Attempt to UnGetByte() beyond the start of the buffer.")

That message is `MemBufferStream::VirtUnGetByte` (0x008E5E70), which always
throws by design - the binary does the same. So the defect is a caller inside
the rules/blueprint load calling `Stream::UnGetByte` (or `CheckByte`) while
`mReadHead == mReadStart` on a memory-backed stream. `Stream::CheckByte`
(0x004D29F0) and `Stream::UnGetByte` (0x004CCC10) were both checked against
the binary and match, so look one level up: whatever reads blueprints through
a `MemBufferStream` in `RRuleGameRulesImpl`'s constructor.

`SWldScenarioLoadControl::RunWorkerThread` swallows the exception in
`catch (...)`; add a temporary `catch (const std::exception&)` above it to see
the message again.

Related: [[project-sofdec-handle-pools]], [[project-lua-registration-sweep]].
