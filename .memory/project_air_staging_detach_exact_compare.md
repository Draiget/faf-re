---
name: project_air_staging_detach_exact_compare
description: FAF issue 7184 (regen aura blocks air-staging detach) confirms CUnitRefuel::Execute is byte-faithful; detach predicate is float == on Health/MaxHealth
metadata:
  node_type: memory
  type: project
---

FAForever/fa#7184: aircraft never detach from air staging after passing
through a regen aura. K-ETFreeman's diagnosis is correct AND the defect is in
the engine, not the Lua layer.

`CUnitRefuel::Execute` (0x00621490) gates undocking on
`FuelRatio > 0.99f && Health == MaxHealth`. Verified in the disassembly at
BOTH sites -- pad path 0x006217F1 (TASKSTATE_Processing) and carrier path
0x006021DEA (TASKSTATE_Waiting):

    movss   xmm0, [unit+294h]     ; Unit::FuelRatio  (Unit +0x294)
    comiss  xmm0, flt_E4F8BC      ; 0.99f
    jbe     -> not done
    movss   xmm0, [unit+98h]      ; Entity::Health    (Entity @ Unit+8, +0x90)
    ucomiss xmm0, [unit+9Ch]      ; Entity::MaxHealth (+0x94)
    lahf / test ah,44h / jp -> not done

`lahf; test ah,44h; jp` is the MSVC float `==` pattern: falls through only on
ZF=1,PF=0. Health > MaxHealth gives ZF=0 -> result 0 -> parity even -> PF=1 ->
jp taken -> not done. So overheal makes the detach branch unreachable until
damage brings HP back to exactly max.

**This is a fidelity CONFIRMATION, not a bug to fix in our tree.** Our
recovered source already says `==`. Do not "fix" it to `>=` -- that would
diverge from the binary. Any gameplay fix belongs in the FAF game repo.

**ROOT CAUSE (lL1l1, same thread) -- also confirmed from the binary.** The
air-staging symptom is downstream of stale Health when MaxHealth drops:

  - `Entity:SetMaxHealth(x)` (cfunc_EntitySetMaxHealthL, 0x0068D790) is a BARE
    STORE: `entity->MaxHealth = x; return 0;`. No clamp of Health, no SetHealth
    call. Lowering MaxHealth below Health leaves Health stale indefinitely.
  - `Entity::AdjustHealth` (0x00679860) then adds BEFORE clamping:
    `next = Health + delta; if (next > MaxHealth) next = MaxHealth;`
    So at Health=1000 / MaxHealth=500, a -600 hit lands at 400 -- the unit
    absorbed 600 but sits at 400/500. Matches lL1l1's "600 damage does 100".

Both are recovered in our tree and both are faithful. `Unit::AdjustHealth`
(0x006A9350) is just a thunk to the Entity one.

The health/damage lane has NO remaining unrecovered functions with recovered
callers -- checked by name sweep. So the engine side of this issue is fully
recovered and reproduces the reported behaviour exactly.

Reusable lesson: live bug reports against the retail binary are free
verification evidence for recovered predicates. Worth checking issue threads
when a recovered state machine is in doubt.

Related: [[project_unit_motion_closure_scoped]]
