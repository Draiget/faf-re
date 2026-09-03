---
name: project_sessionisreplay_is_a_faf_patch_not_a_gap
description: "The sim-side SessionIsReplay Lua global is installed at runtime by FAF's external faext.dll, not by this binary. score.lua's 'nonexistent global variable' error is expected; adding a CScrLuaBinder for it would be fabricated recovery."
metadata:
  type: project
---

Running a skirmish logs exactly one sim script error:

```
lua/sim/score.lua(288): access to nonexistent global variable "SessionIsReplay"
```

**It is not a recovery gap, and it is not why anything is broken.** Do not
"fix" it by adding a `CScrLuaBinder` to `SimLuaInitSet()`.

**Why:** the string `"SessionIsReplay"` has **exactly one** reference in the
whole image -- `func_SessionIsReplayUser_LuaFuncDef` (0x00897D90), the *user*
binder, already recovered and registered. The base engine publishes this global
to the UI Lua state and nowhere else. `cfunc_SessionIsReplaySim` (0x0128BB27)
sits inside `.exxt` (VA 0x0128B000), FAF's patch section: `start_exxt`
(0x0128BE0D) `LoadLibraryA`s **`faext.dll`** and hot-patches slots from a
`(procName, target)` table through `VirtualProtect`. The sim binding is
installed at runtime by that external DLL. There is no registration in this
binary to recover.

**How to apply:** treat every `.exxt` (>= 0x0128B000) symbol this way -- it is
FAF patch-layer code driven by an external DLL, so "it is referenced by nothing
in the binary" is the expected state, not a missing callsite. Confirm intent by
counting string references before writing any binder. Related:
[[project_exxt_fabricated_recoveries]].

Behaviourally the error is harmless: `score.lua:288` is inside `ScoreThread`,
which `init()` `ForkThread`s, so the error kills that one forked thread and
leaves the sim beat running. It is *not* the cause of the stall that
[[project_sim_stall_countedptr_root_cause_2026_09_03]] fixed -- that was checked
before being ruled out.
