---
name: project_sim_runs_11x_too_fast
description: "FIXED 2026-09-03 (504f746c). ExecuteDispatchStepLocked published its own speed MEASUREMENT through SetSimRate (a game-speed REQUEST), creating a feedback loop that pinned the rate at 50. Correct channel is BroadcastIntParam/CLIMSG_IntParam. Game time now tracks real time."
metadata:
  type: project
---

## The measurement

Same map, same launch (`/map SCMP_009`), both with `/log`:

| build | session time | game time |
|---|---|---|
| ours | 00:00:33 -> 00:00:43 | 00:00:00 -> **00:01:49** |
| original | 00:00:19 -> 00:00:29 | 00:00:00 -> **00:00:09** |

109 game-seconds per 10 real ones versus real time -- about **11x too fast**.
Nothing crashes; the game is simply unplayable at that speed. Running the
original with `/log` and diffing is what surfaced this; do it for any
"is this behaviour right?" question.

## Eliminated -- do not re-chase

- **`GetSimRate()` is 0.** Every `CLIENT_CreateClientManager` call site in
  `SessionStartup.cpp` passes `gameSpeed = 0`; the accessor takes the min across
  clients. So `simRateScale` is 1 and the arithmetic gives the correct
  **100 ms per beat**.
- **`net_Lag` is 0** (`CConCommand.cpp:109`), so it is not dragging `dueAt`
  backwards.
- **`mSimBusy` is only set for a pause or game-over sync**, so the *timed*
  branch in `CSimDriver::ThreadRun` is the one executing, not the untimed
  `mSimBusy` path above it.
- **The busy-transition stamp is faithful.** `mLastSyncCycleTime` being stamped
  inside `if (mSimBusy != hasBlockingSyncState)` rather than per sync looks
  wrong but matches 0x0073DAD0 exactly:
  `if (busy != new) { busy = new; if (!new) stamp; SetEvent; }`.
- **The stamp is not stale.** `CSimDriver::GetSyncData` also stamps
  `mLastSyncCycleTime`, and that runs on every dequeued sync.

## FIXED (504f746c)

`CSimDriver::ExecuteDispatchStepLocked` published its own dispatch-speed
**measurement** through `SetSimRate`. That is a *request*: it sends
`CLIMSG_AdjustSimSpeed` and overwrites `mGameSpeed`. Feeding a measurement into
it is a feedback loop -- fast dispatch raises the requested speed, the higher
speed makes dispatch faster, and the request runs away (observed 2, 53, 61, 81,
94). `GetSimRate()` then returns `min(runaway mGameSpeed, mSimRate default 50)`
= **50**, giving `simRateScale` 100000 and 0.0010 ms/beat.

The value is this client's *capability* -- the debug readout calls it
"max speed", `SessionStartup` reports the same lane as `maxSP`. Its channel is
`BroadcastIntParam` -> `CLIMSG_IntParam`, which peers store in
`CClientBase::mSimRate`; `GetSimRate` mins across clients so the session paces
to the slowest machine. One-line fix.

After: 10 session-seconds -> ~6 game-seconds, zero crashes. The gap to 1:1 is
this Debug build being CPU-bound with nine AI armies; the driver caps at real
time and takes what it can get.

**Correction:** an earlier pass blamed the input/key-binding path behind Lua
`IncreaseGameSpeed`. Wrong. A captured call stack at `SetSimRate` showed its
only caller is `ExecuteDispatchStepLocked` on the sim thread, and the 50 is
`mSimRate`'s default, not `WLD_IncreaseSimRate`'s clamp. **Capture a call stack
before attributing a caller** -- `PLAT_GetCallStack` + `PLAT_FormatCallstack`
work outside an exception if you feed them an `RtlCaptureContext` record.

## Superseded reasoning

`GetSimRate()` starts at 0 (`msPerBeat` 100.00, correct) and within seconds
reads **50**, making `simRateScale` 100000 and `msPerBeat` **0.0010**. The
throttle is faithfully pacing a sim asked to run fifty steps fast -- the pacing
math needs no change.

The 50 is a **ceiling being pinned**, not a chosen setting.
`WLD_IncreaseSimRate` (`CWldSession.cpp`) raises the requested rate one step and
stops at 50, and it is invoked **~17 times a second with no user input**: 1912
`CLIMSG_AdjustSimSpeed` broadcasts in a 110-second run, each incrementing
`mGameSpeedClock` by one, the rate climbing 2, 53, 61, 81, 94 and pinning.

**Next:** the defect is upstream of the driver, in whatever dispatches that
console command -- the input/key-binding path behind Lua's `IncreaseGameSpeed`
(`lua/ui/uimain.lua:288`). `WLD_IncreaseSimRate` is registered as a `CConFunc`,
so find what fires that console command unprompted.

## Superseded lead

```
leadMilliseconds = (mNextIssueBeat - mLastDequeuedBeat) * msPerBeat - net_Lag;
dueAt            = mLastSyncCycleTime + MillisecondsToCycles(leadMilliseconds);
```

Pacing only holds if `mNextIssueBeat - mLastDequeuedBeat` stays >= 1, giving a
>= 100 ms lead. If the consumer keeps up so that the difference collapses to 0 or
less, `dueAt <= now` every iteration, the catch-up path runs with
`waitMilliseconds = 0`, and beats are issued as fast as they can be consumed --
which is exactly the observed behaviour. Instrument those two counters before
changing anything; the note is at the branch in `SimDriver.cpp` (`01e807a0`).
