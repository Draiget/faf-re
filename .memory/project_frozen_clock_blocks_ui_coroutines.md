---
name: project_frozen_clock_blocks_ui_coroutines
description: NEXT BLOCKER - gpg::time::GetCycle takes its monotonic clamp on every call, so CurrentTime() advances per-call not per-second, WaitSeconds never completes and every UI coroutine stalls. Measured, not inferred.
metadata:
  type: project
---

# The clock is frozen: `GetCycle` clamps on every call

This is the **active next blocker** for intro playback. It is measured, not
theorised.

## Symptom chain (each link verified by probe)

1. `splash.lua` never calls `Play`. It sets `movie.OnLoaded = movie.Play` and
   only ever calls `movie:Set(...)`.
2. `/lua/maui/movie.lua`'s `Set` forks a coroutine that polls
   `IsLoaded() and SoundIsPrepared(...)` every `WaitSeconds(0.01)` and calls
   `OnLoaded()` when both hold.
3. Probes show that loop runs **exactly once**: `IsLoaded#1 -> 1`,
   `SoundIsPrepared#1 -> 0` (false on the first poll is normal - the cue is
   still preparing) and then never again.
4. `userInit.lua`'s `WaitSeconds` is
   `repeat WaitFrames(...) until CurrentTime() - start >= n`, so a frozen clock
   spins it forever. `CLuaTask::Execute` probes confirm the task *is* resumed
   repeatedly (`resume=0 type1=3 ticks=1`) - it is the wait that never ends.
5. `CurrentTime()` (`cfunc_CurrentTimeL`, faithful) returns
   `gpg::time::GetSystemTimer().ElapsedSeconds()`, and that value advances
   **per call, not per second**:

```
CurrentTime#1    = 0.000002 cycles=16   qpc=864157299972 qpf=10000000
CurrentTime#2    = 0.000002 cycles=26   qpc=864157450981
CurrentTime#500  = 0.000451 cycles=4513 qpc=864243542577
```

QPC advances normally (84M ticks ≈ 8.4 s) and QPF is right, but `ElapsedCycles`
grows by a fixed +10 per call. That is `GetCycle`'s monotonic clamp
(`next = current + 1`) firing **every** time, i.e. `PerformanceCount < cycle`
always holds.

## What is NOT the cause (ruled out)

- **Symbol collision on the `cycle` global.** Giving `cycle`,
  `sPerformanceFrequency`, `sTimerCycleToSeconds` and `systemTimer` internal
  linkage (anonymous namespace) changed nothing - identical numbers. Reverted.
- Scale: `sTimerCycleToSeconds = 1/QPF` with QPF = 10,000,000, correct.
- `cfunc_CurrentTimeL`, `Timer::ElapsedSeconds`, `Timer::ElapsedCycles`,
  `CyclesToSeconds` - all checked against the binary, all faithful.

## Start here next time

Probe **inside** `gpg::time::GetCycle` (`src/sdk/gpg/core/time/Timer.cpp:109`,
FUN_00955400): log `cycle` and `PerformanceCount.QuadPart` on entry for the
first few calls. `cycle` must be exceeding QPC (~8.6e11); find who put a larger
value there. Note the binary's decompile reads the global as
`__PAIR64__(cycle.LowPart, cycle.HighPart)` - **halves swapped** - which is
worth checking against our plain `LONGLONG` load, and against
`InterlockedCompareExchange64` behaviour on 32-bit.

Fixing this should unblock every UI coroutine at once, not just the movie.

## Landed this session (all runtime-verified)

| Commit | Fix |
|---|---|
| `e136f85` | `adxmng_DecideFramework` ternary inverted - see [[project_adxm_framework_inversion]] |
| `a7ba1df` | Sound: `AudioEngine::Create` never called `func_InitSound`; XACT params passed at +0x2C instead of +0x34; `finalMixFormat` view 0x18 instead of 0x28 (stack overrun caught by /RTC) |
| `5aafc52` | `lua_yield` was never defined here, so it resolved to the prebuilt LuaPlus lib and wrote stock CI_* bitmask flags where this fork wants enum 2/4 - every resume failed with "cannot resume non-suspended coroutine" |

## Current state vs the shipped binary

Sound now matches **exactly**: 270 `Wavebank` lines, 90 `Wavebank prepared`,
90 `Loaded WaveBank` - identical to `ForgedAlliance.exe` on the same startup.
Movie opens, prepares in 6 iterations (also identical) and decodes; a frame dump
shows the THQ prism and swoosh rendering correctly. The only remaining
difference is `Playing movie` 0 vs 2, caused entirely by the frozen clock above.
