---
name: project_entities_never_ticked_2026_09_03
description: "RESOLVED 2026-09-03 (118daf73 + f72e1bef). Entity::StandardInit never pushed entities onto a task thread, so no unit was ever simulated. Fixed; with the economy solver, income now matches the original exactly (650/650 +1, 4000/4000 +20)."
metadata:
  type: project
---

## RESOLVED

`Entity::StandardInit` never called `CTask::CreateTaskThread`, so no entity was
ever scheduled. The binary does it at **0x00678477**, between the entity-DB
registration and the collision revert: it pushes the CTask subobject
(`lea esi, [ebp+34h]`, RTTI mdisp=52) onto a fresh thread on
`[this+0x148] + 0x930` = `SimulationRef->mTaskStageA` (pinned by
`mCurCommandSource` ending at 0x092C), with `own = false`. One line, landed in
**118daf73**.

With `func_ArmyProcessEconomy` recovered on top (**f72e1bef**), the economy now
reads **650/650 mass at +1 and 4000/4000 energy at +20** -- byte-identical to
the original binary on the same map. Soaked to 00:49:20 game time, zero crashes.

**Order matters:** the solver alone drains storage to zero, because it
faithfully reports nothing produced. Land the scheduling fix first.

## The fact (as originally measured)

`Unit::MotionTick` **is never entered**. A counter placed at the top of
`Unit::HandleResourceManagement` -- which `MotionTick` reaches unconditionally,
with no early return in between -- logged **zero** times across two runs
covering more than twenty minutes of game time with nine armies. The
`Sim::Logf` line at the top of `MotionTick` never appears either.

So the sim advances its clock and runs Lua while **units do nothing**: no
motion, no economy, no per-unit state. The beat counter is independent of entity
ticking, which is why [[project_sim_stall_countedptr_root_cause_2026_09_03]]
(game time now reaching 01:40:48 cleanly) did not fix this and is a separate,
genuine win.

This is the top blocker for actual gameplay, and it subsumes the "+0 income"
symptom in [[project_economy_solver_gap_2026_09_03]] -- production is banked
only from `HandleResourceManagement`, so no tick means no income, with no second
cause needed.

## The chain, and where to start

Entirely virtual, which is why the callgraph shows no edges into it -- the only
xref to `MotionTick` is **vtable slot 20** of the `Entity` subobject at
`0x00E2A5EC`:

```
task scheduler
  -> Entity::Execute   (0x00679F70)   CTask entry point
  -> Entity::TaskTick  (0x00679C40)
  -> MotionTick        [virtual slot 20]
  -> HandleResourceManagement
```

`Entity::Execute` being the CTask entry point means **entities run as tasks**.
The missing link is whatever enqueues them into the task stage that
`CArmyImpl::OnTick` drives via `CTaskStage::DoFrame`. Start at the scheduler;
`Unit.cpp` is intact from `MotionTick` down (the warning is recorded there in
`b1ff8293`).

## Ruled out — do not re-chase (f64c43e7)

- **The dispatcher works.** `CTaskStage::DoFrame` -> `CTaskThread::DoTaskTick`
  (0x004091F0, recovered as `RunThreadUserFrameStep` in `CTaskThread.cpp`)
  really does call `task->Execute()`. Nothing wrong there.
- **`Entity`'s `CTask(nullptr, false)` is FAITHFUL.** `Entity` does derive from
  `CTask` (RTTI: base at mdisp=52, own vftable 0xE27590), and `CTask`'s ctor
  pushes onto a thread only when given one -- so the null looks like the bug.
  It is not: both Entity ctors in the binary inline that ctor and store the
  vftable straight into `[this+0x34]` (**0x006779E0** serializer path,
  **0x00677F40** normal path) without touching any task stack. Passing a thread
  there would diverge from the binary. Warning recorded at the ctor.
- So entities are genuinely unscheduled at construction, and the push happens
  **later**, from a site we have not found. Look for whoever creates/owns a
  `CTaskThread` per unit and pushes the entity onto it.
- The economy setters are fine too: `lua/sim/Unit.lua:307-309` calls them, the
  binders are registered, `Unit::SetProductionActive` sets the flag.

## How to re-check cheaply

Put a `gpg::Warnf` counter at the top of `HandleResourceManagement`, log on the
first few calls and every 500th, build, run `/map SCMP_009` for ~150 s, then
grep the `.sclog`. Zero lines means the chain is still broken. Do **not** budget
the probe to early frames -- an earlier session drew an entirely wrong
conclusion that way.

The differential reference is the original `ForgedAlliance.exe` run the same
way: camera on the ACU, `12000/12000 +10/s`, income +1/+20, populated minimap.
