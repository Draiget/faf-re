---
name: project-intermittent-lua-state-crash
description: A ~1-in-3 intermittent startup crash (Ensure(state != nullptr, "state") after a lua coroutine error) — do NOT bisect engine changes against a single run, the runs are not deterministic.
metadata:
  type: project
---

Measured 2026-08-13 over repeated `skirm.ps1` runs on an unmodified tree.

## The crash

About one run in three, a skirmish dies ~40 s in with:

    CRASH: Unhandled exception:
    state
    gpg::Die + 61 bytes (gpg/core/utils/Global.cpp:1220)
    WinMain + 1083 bytes (moho/app/WinMain.cpp:575)

`state` is the tag of `Ensure(state != nullptr, "state")` in
`src/sdk/lua/LuaObject.cpp` (20 sites) — a `LuaPlus::LuaObject` operation
reaching a null `lua_State`.

It always happens at the *same* point in the log, immediately after:

    warning: Error running lua script: ...\lua\system\performance.lua(711):
             attempt to loop over field `Children' (a nil value)
             stack traceback:

Both the surviving and the crashing runs log that lua error, and both produce
an empty traceback body. The surviving run just goes on to the next
`Session time:` heartbeat.

Likely cause: `CLuaTask::Execute` (`moho/task/CLuaTask.cpp:558`) logs that
warning and returns -1; the task is then torn down and `~CLuaTask` deletes
`mLuaState`. A `LuaObject` still naming that state afterwards sees it
nulled/freed. Nondeterministic because it depends on what is left in that
memory. **Not diagnosed further yet.**

## The trap this note exists for

**Runs are not deterministic.** The skirmish picks a random faction each time
(`GRN: 1/2/3` vs `GRN: 4/4/4`, `aeon_load.sfd` vs `cybran_load.sfd` in the
log), and this crash is a coin flip on top of that.

An earlier version of this note claimed that adding
`#include "moho/command/CommandIssueHelper.h"` to `UserUnitManager.h` crashed
startup on its own, "verified by bisection". **That was wrong** — it was two
clean runs against two crashing runs, all four the same build behaviour. The
same "reproduction" then appeared for a completely unrelated change
(converting `UserUnit` to real inheritance), which is what exposed it.

So:

- **Never conclude anything from one run.** Three runs per side, minimum, and
  compare crash *rates*, not crash/no-crash.
- When diffing two logs, normalise first: strip addresses, heap sizes,
  `Session time:`/`Game time:`, and the `Wavebank`/`SND:`/`Preloading` blocks.
  Faction-dependent lines will still differ; that is noise.
- The dedup that note wrongly blocked is fine to do: `UserUnit.cpp`'s local
  `UserCommandQueueEntry {helper, link}` really is
  `moho::CommandIssueObserverLink {mOwnerLinkSlot, mNext}`.

See [[project-dobeat-keystone-chain]].
