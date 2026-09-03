---
name: project_decreasecount_teardown_landed
description: 2026-08-12 d444ed1 CUnitCommand::DecreaseCount + sub_6EE4F0 upgrade-chain queue prune landed; sibling-symmetry fabrication is a detectable elision pattern
metadata:
  node_type: memory
  type: project
---

LANDED d444ed1 (also af5fa15 earlier in the same session).

**Detection heuristic that found this: compare the DB `instruction_count`
against the size of the recovered body.** `FUN_006F16A0` is 96 instructions
with SEH; the recovered `DecreaseCount` was a 6-line arithmetic body.

CAVEAT -- the raw ratio has a HIGH false-positive rate, verified by running it
over moho/unit + moho/ai (467 candidates at ratio>=3, instr>=60). Two big
false-positive classes:
  1. **Lifted helpers.** `CAiPersonality::ReadData` (0x005B7340) scores 33x
     (1917 instr / 58 lines) and is FULLY recovered -- the body is 30+
     `LoadRangeField(...)` calls whose inlined expansion is the instruction
     count. This is the fidelity contract working as intended.
  2. **Adjacent Address blocks.** Any body measured as ~1 line is an artifact
     of two Doxygen address blocks sitting next to each other.
Before trusting a hit, check whether the body delegates to named helpers in
the same TU. The signal is only strong when the body is *flat* arithmetic with
no helper calls, as DecreaseCount was.

**Sibling-symmetry fabrication (new named failure mode):** DecreaseCount had
been given IncreaseCount's `mCmdType != UNITCOMMAND_BuildFactory` early-return
and its `amount <= 0` guard. The binary has NEITHER. Only IncreaseCount gates
on type (only factory builds count *up*). DecreaseCount tests `amount >= 0`,
so a negative amount retires the command outright. When two functions look
like a pair, do not assume the guards are mirrored -- diff both disassemblies.

What was actually missing: at count==0 the binary unlinks the command from
every assigned unit's queue, and for `UNITCOMMAND_Upgrade` (0x1B) re-prunes
that queue via sub_6EE4F0 and sets `Entity::DirtySyncState` (Unit+0xA2 =
Entity+0x9A).

sub_6EE4F0 semantics: walks `CUnitCommandQueue::mCommandVec` carrying (a) the
blueprint the unit will be by the time each order runs and (b) the categories
it can build by then = `(army.BuildCategoryFilterSet & bp.Economy.CategoryCache)
- unit.GetAttributes().restrictionCategory`. Build orders (type 7/8) survive
while `EntityCategory::HasBlueprint(cmd.mConstDat.blueprint, &reachable)`;
upgrade orders survive while they continue the chain, and each survivor
advances the blueprint and Adds its unlocked set. Non-survivors get
`cmd->RemoveUnit(queue.mUnit, queue.mCommandVec)` + `mNeedsRefresh = 1`.

Chain match: if `queued.General.SeedUnit` non-empty, stricmp it against
`current.mBlueprintId`; else stricmp `queued.mBlueprintId` against
`current.General.UpgradesTo`.

KEY LAYOUT FACT: `msvc8::string` here is 0x1C with a 4-byte leading proxy --
body at +0x04, size at +0x14, res at +0x18. `RResId` is just that string, so
`General(+0x17C).UpgradesTo(+0x08)` reads at +0x188/+0x19C and
`General.SeedUnit(+0x5C)` at +0x1DC/+0x1EC. This 4-byte offset is what makes
blueprint string offsets look "off by 4" -- do not mis-assign the field.

Also: `CUnitCommand` mConstDat is at +0x44 and mVarDat at +0x80 (derives from
mCmdType@+0x98 and blueprint@+0x60); the header's declared prefix does not
assert this. `EntityCategory::Add(ecx=source, ebx=out)` -- IDA renders the
args in the misleading order, verify direction from the dtor that follows.

OPEN DEBT: `RUnitBlueprintEconomyCategoryCache` duplicates `EntityCategorySet`
(both 0x28). Unit.cpp already carries a `CategoryWordRangeView` for the same
reason. Deserves a unifying pass.

Related: [[project_mistyped_void_fields]] [[feedback_no_stub_functions]]
