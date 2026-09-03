---
name: project-game-time-zero-creategameinterface-throws
description: Why the sim never ticks (Game time 00:00:00) — CreateGameInterface throws, so the client never declares ready, so no beat is ever issued. Full causal chain with live probe data.
metadata:
  type: project
---

# `Game time: 00:00:00` — the sim never beats, and why

State at time of writing: the session reaches a live UI, all 5182 props, all 8
armies + NEUTRAL_CIVILIAN, AI brains, NavGenerator, and `Session time` advances
— but `Game time` stays at `00:00:00`, so nothing spawns or moves and the
commander never appears. See
[[project_commander_spawn_initializearmies_nil_binding]] for the fixes that got
it this far.

## The chain, established with live probes

1. **`CreateGameInterface` never returns.** A probe bracketing the call in
   `CWldSession.cpp`'s Initializing handler prints
   `[INITDIAG] before CreateGameInterface` and **never** the matching `after`.
   The process stays alive, so it throws rather than hangs.
2. Because it throws, the rest of that handler is skipped — including
   `clientManager->Cleanup()` a few lines below.
3. `CClientManagerImpl::Cleanup` (0x0053E4B0) is **the only writer of
   `mWeAreReady`** (and it broadcasts `CLIMSG_Ready`). The name is a
   misnomer — it is the "announce we are ready" call, not teardown.
4. `DoBeat` only sets `mEveryoneIsReady` inside `if (mWeAreReady && !mEveryoneIsReady)`,
   so it stays false.
5. `WLD_DoPostInitializing` / `WLD_DoWaiting` gate the Playing transition on
   `clientManager->IsEveryoneReady()`, so the session sits in **Waiting**
   forever (which is what the "loading screen" capture actually shows — it is
   the waiting dialog).
6. Those same two functions are what call
   `DecrementOutstandingRequestsAndSignal`, so `mOutstandingRequests` stays at
   its constructor value of **1**.
7. `CSimDriver::ThreadRun`'s issue loop requires
   `mLastSyncCycleTime != 0 && mOutstandingRequests == 0 && queue < cap`.
   Live probe:

       [BEATDIAG] lastSync=489969015 outstanding=1 queue=0 |
                  nextIssue=1 lastDequeued=0 dispatch=1 simBusy=0 state=1

   `lastSync` is primed and the queue has room — **`outstanding=1` is the term
   that blocks**. No beat is ever issued, so the sim never ticks.

## What is NOT the bug (checked, don't re-derive)

- **`mSimBusy` never changing** is faithful. `FinalizeSyncDispatchLocked`
  (FUN_0073DAD0) has the identical "only stamp on a change" gate, so it
  genuinely cannot fire on a normal never-paused start in the original binary
  either.
- **`GetSyncData` (0x0073C520)** is faithful — it stamps `mLastSyncCycleTime`
  unconditionally on a successful pop, which is what primed it here.
- **`mOutstandingRequests` starting at 1** is correct in both ours and the
  binary; it is an opening handshake meant to be cleared by the
  Initializing→Playing transition.

## CORRECTION (same session, later run): the sim DOES tick

The chain above is real as far as `CreateGameInterface` not returning goes, but
the conclusion "no beat is ever issued, so the sim never ticks" is **wrong**. A
later run's fault stack shows:

    newkey <- luaH_set <- luaV_settable <- luaV_execute <- luaD_call
    <- LuaCallProtected <- CScriptObject::CallbackStr
    <- Entity::OnDestroy <- Unit::OnDestroy
    <- RunQueuedDestroy        Sim.cpp:7474
    <- Sim::AdvanceBeat        Sim.cpp:13503
    <- CDecoder::DecodeAdvance <- CDecoder::DecodeMessage

`Sim::AdvanceBeat` and `RunQueuedDestroy` are running, i.e. beats are being
advanced and units created and destroyed. The `[BEATDIAG] outstanding=1`
samples were the **first 12 loop iterations only** (the probe has a report
budget) — they describe startup, not steady state.

Note the sim advances here via `CDecoder::DecodeAdvance` — the decoder
replaying the command stream — which is a different path from
`ThreadRun`'s issue loop. So "the issue loop is gated" and "the sim is
ticking" are not contradictory.

`Game time: 00:00:00` in the log is a single sample taken at the one-minute
mark; the run died before a second sample, so it is **not** established that
game time is stuck. Do not treat that line as evidence without at least two
samples.

## Actual current blocker

An access violation in `newkey` (LuaObject.cpp:4569) — Lua table insertion —
during a unit's `OnDestroy` callback. That is the same memory-corruption family
as [[project_locvars_use_after_free_localized]], now surfacing in table code
rather than in `traverseproto` or `PopLaneNode`.

## Next step

Name the exception. The prefetch half of `CreateGameInterface` is already known
good — a probe showed `GetPrefetchTextures` returns a real table
(`tt=5 isTable=1`) — so the throw is from the second half,
`RunScript("CreateGameInterface", ...)`, i.e. the UI's own Lua. The game log
shows `Evaluating LazyVar failed: ... score_mini.lua(57) ... control.lua(39)`
right before the stall, which is consistent.

A try/catch probe around the call printing `ex.what()` is in flight. Read the
game log with **`/log <name>` — one slash**, see
[[reference_game_log_flag_is_single_slash]].
