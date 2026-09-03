---
name: project-simdriver-bootstrap-map
description: Complete field and call map for the CSimDriver sim-bootstrap chain that keeps the frame machine stuck in Initialize.
metadata:
  type: project
---

The skirmish frame machine parks in `EWldFrameAction::Initialize` because
`CSimDriver`'s constructor starts a **placeholder lambda** instead of the real
bootstrap (`src/sdk/moho/sim/SimDriver.cpp`, search `createSimBootstrapProc`).
The lambda only sets `mState = Ready`, so no `Sim` is built, no thread runs,
and `HasSyncData()` is never true. See [[project-skirmish-load-completes]].

**Good news: most of the chain is already recovered.**
`Sim::Create` / `Sim_Create_exxt` (StartupHelpers.cpp, currently orphaned),
`ExecuteDispatchStepLocked`, `FinalizeSyncDispatchLocked` (= the binary's
`CSimDriver::Sync`, 0x0073DAD0), `PreparePendingSaveRequestLocked`,
`SetStateAndNotify`, `PromoteToDispatchingWhenBeatAvailable` all exist.
`Sim::Sync` (0x007474B0) is a documented **partial lift** but does publish a
beat packet, which is enough for the queue to become non-empty.

**Only two functions are missing:**
- `FUN_0073BDF0` `CSimDriver::ThreadRun` — 315 instrs, the **"Issue" thread**
  (`SetThreadName(-1,"Issue")`, priority 2). Loops until the stop flag:
  `mClientManager->DoBeat()`, computes a wait from sim rate / `net_Lag` /
  queued beats, calls `mMarshaller->AdvanceBeat(n)`, promotes `mState` to
  Dispatching when a beat is available, then waits on `mConnectionEvent`.
- `FUN_0073D260` `CSimDrive::ThreadCreateSim` — 503 instrs. Optional `/NUMA`
  affinity pinning, `_controlfp(_PC_24,_MCW_PC)`, `SetThreadName(-1,"Sim")`,
  `Sim_Create_exxt(mLaunchInfo)`, release the launch info, build a `CDecoder`
  (sink = sim, stream = `mStream` moved out, rules = `*(sim+0x8C8)`,
  state = `*(sim+0x8D8)`), `CMessageDispatcher::PushReceiver(.., 0, 0x32, decoder)`,
  start the `ThreadRun` thread, call the sync publish, `mState = Ready`, then
  run the driver dispatch loop. With no sim it sets `mState = 5` and returns.

**Field map — verified against `.asm` displacements, not the decompiler.**
IDA name → our `CSimDriver` member (offset):
`mClientManager` +0x08 · `v2` → `mLastDequeuedBeat` +0x1C ·
`v3` → `mDispatchBeat` +0x20 · `v4` → **+0x24, see below** ·
`mMarshaller` +0x28 · `mLock` +0x30 · `mCounter1` → `mOutstandingRequests`
+0x3C · `mConnectionTimeStart` → `mTimer` +0x40 · `mEvent2_discon` →
`mConnectionEvent` +0x48 · `mTime1` → `mLastSyncCycleTime` +0x50 ·
`mRunThread` → `mStopSimThread` +0x58 · `mConnectionTime` →
`mFirstCommandCycleTime` +0x60 · `v9` → `mSimBusy` +0x68 · `mSemaphore2` →
`mStateChanged` +0x74 · `mState` +0x8C · `mSyncdat` → `mSyncDataQueue` +0x90
(size at +0xA0) · `mEvent1` → `mSyncDataAvailableEvent` +0xA4.

**+0x24 is misnamed in our header.** We call it `mCommandCookie`, but
`ThreadRun` uses it as the *next beat to issue*
(`mMarshaller->AdvanceBeat(target - v4 + 1); v4 = target + 1;`) and
`RequestPause` (0x0073C660) returns that same field as the "cookie". One
field, one meaning: the beat a command issued now will land on. Rename it
(`mNextIssueBeat`) when recovering `ThreadRun`; ~20 call sites in the
ISTIDriver command methods assign it to an out-parameter.
