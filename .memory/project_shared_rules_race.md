---
name: project-shared-rules-race
description: The session and the Sim share one RRuleGameRulesImpl, so two threads run SynchronizeBlueprintTable over the same rules Lua universe every beat.
metadata:
  type: project
---

As of 2026-08-12 a skirmish reaches `EWldFrameAction::Playing`, the sim thread
runs beats, and the crash that follows is a **data race on the rules' Lua
universe**.

Two call sites drive `RRuleGameRulesImpl::UpdateLuaState` ->
`SynchronizeBlueprintTable`, and **both are faithful to the binary**:

- `CWldSession::SessionFrame` (0x00895B40) - main thread, session state.
- `Sim::AdvanceBeat` (0x00749F40) - sim thread, sim state.

In retail those are two *different* `RRuleGameRules` objects, so there is no
sharing. In this tree they are the same object. A temporary `Logf` in
`SynchronizeBlueprintTable` proved it outright:

    SYNCBP: count=5337 srcPtr=06244028 dstPtr=104035A0 srcState=08ECE8F8 rootState=160F8C40
    SYNCBP: count=5337 srcPtr=06244028 dstPtr=1A1B3528 srcState=08ECE8F8 rootState=19CD97E0
    SYNCBP: ord=0 ... / SYNCBP: ord=500 ... / SYNCBP: ord=1 ...   <- interleaved

Same `srcState` (the rules' own `lua_State`), same source table, two different
root states, and the per-ordinal lines interleave - two threads inside the same
5337-iteration loop, both reading and pushing on one `lua_State`.

The symptom is an AV in `luaV_index` reading `0x0000000C` (the `metatable`
displacement) from `lua_gettable` under `LuaObject::GetByIndex`. Adding the
diagnostic `Logf` made it disappear, which is the usual timing tell.

`Sim` takes its rules from `LaunchInfoNew::mGameRules` (`Sim::Sim`,
`mRules(info->mGameRules)`); `CWldSession` takes ownership of the `auto_ptr`
handed to its constructor. Giving the sim its own independently-loaded rules
instance is the fix, and it is also what makes the sim deterministic and
independent of the UI - the reason the split exists.

Note `SynchronizeBlueprintTable` deep-copies all 5337 blueprints **every beat**
through `SCR_Copy`. Confirm that against `FUN_0052A3D0` before optimising; if it
is faithful, the cost is the binary's.
