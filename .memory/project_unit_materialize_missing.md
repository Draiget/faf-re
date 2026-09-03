---
name: project-unit-materialize-missing
description: Unit::Materialize (FUN_006A9F40) is missing, so construction silently does nothing - four live call sites hit Entity::Materialize, which returns 0.0f. Full decode ready to write.
metadata:
  type: project
---

**LANDED 2026-08-14 as `2f55421`.** tucheck EXITCODE=0, marked recovered.
Kept for the decode notes and for the two traps below, which cost two failed
attempts before it went in.

`Entity::Materialize(float)` (0x005BDC20) is a base no-op - `return 0.0f;`.
The real override **`Unit::Materialize` (FUN_006A9F40, 289 instrs) is not in
`src/sdk/**` at all**, and `Unit.h` does not declare it. Four live recovered
call sites dispatch on a `Unit*`:

  - `CBuildTaskHelper.cpp:239`, `:269`, `:366`
  - `CUnitSacrificeTask.cpp:458`

so **unit construction currently advances nothing**: no health added, no
fraction-complete progress, `mIsBeingBuilt` never cleared, no OnCreate or
OnAdjacentTo scripts, no army stats. Buildings and units should never finish.

## Callsite evidence (complete)

Vtable `??_7Unit@Moho@@6BEntity@Moho@@@` at **0x00E2A5EC**:
**slot 29 = Materialize (0x006A9F40)**, slot 12 = Sync (0x006ABCC0).
Base declarations are `Entity.h`: `virtual float Materialize(float)` and
`virtual void Sync(SSyncData*)`. Both are genuine overrides; neither is
declared in `Unit.h` yet.

## Decoded body

    Sim::Logf(mSim, "Unit[0x%08x]->Materialize(%.5f [0x%08x])\n",
              mConstDat.mId, delta, delta);
    if (delta >= 0.0f) mCreationTick = mSim->mCurTick;   // Unit+0x528
    if (delta == 0.0f) return;

    // fraction-complete update, asymmetric by sign
    f = mVarDat.mFractionComplete + delta;
    if (delta <= 0.0f) {            // demolition
        clamp f to [0,1]; mFractionComplete = f;
    } else {                        // construction
        f = (f < 1.0f) ? f : 1.0f;  if (f < 0) f = 0;
        // never report less complete than the health ratio already implies
        f = max(f, mVarDat.mHealth / mVarDat.mMaxHealth);
        mFractionComplete = f;
    }
    AdjustHealth(nullptr, mVarDat.mMaxHealth * delta);

    if (mVarDat.mIsBeingBuilt && mVarDat.mFractionComplete == 1.0f) {
        mUnitVarDat.mUnitStates &= ~(1ull << 39);   // asm clears 0x80 of the HIGH dword
        mVarDat.mIsBeingBuilt = 0;
        layerName = (layer > LAYER_Orbit) ? "" : COORDS_LayerToString(layer);
        CScriptObject::RunScript_WeakunitStr(entity, &mCreator, layerName);

        if (GetBlueprint()->General.CapCost > 0.0f) {
            IncrementArmyBlueprintFloatStat(stats, "Units_Active",  blueprint, +1.0f);
            stats->UpdateUnitStat("Units_Active", &one);
            IncrementArmyBlueprintFloatStat(stats, "Units_History", blueprint, +1.0f);
            stats->UpdateUnitStat("Units_History", &one);
            <0x00593290>(mArmy->GetStatDefaultStr("Units_MassValue_Built"),   ...);
            <0x00593290>(mArmy->GetStatDefaultStr("Units_EnergyValue_Built"), ...);
            IncrementArmyBlueprintFloatStat(stats, "Units_BeingBuilt", blueprint, -1.0f);
        }

        if (!IsMobile()) {          // adjacency only for structures
            for (Unit* other : CollectAllOverlapping()) {
                CScriptObject::RunScript_OnAdjacentTo(this,  other, this);
                CScriptObject::RunScript_OnAdjacentTo(other, this,  this);
            }
        }
    }

## Helper availability - all present except one

`Sim::Logf`, `mCreationTick` (Unit+0x528), `Entity::AdjustHealth`,
`RunScript_WeakunitStr`, `COORDS_LayerToString`, `Unit::CollectAllOverlapping`,
`RunScript_OnAdjacentTo`, `mVarDat.mFractionComplete` (+0x60),
`mVarDat.mIsBeingBuilt` (+0x20) all exist. The stats idiom is already in
`Unit.cpp` around line 13537: `IncrementArmyBlueprintFloatStat(armyStats,
name, blueprint, delta)` and `armyStats->UpdateUnitStat(name, &delta)`.

**Unresolved:** `CArmyImpl::GetStatDefaultStr` has no src match, and
`sub_593290`'s src name still needs pinning (0x00593290 does appear in
Unit.cpp). Resolve those two before writing the stats block.

## Open question: the return type

`Entity` declares `float Materialize(float)`, so the vtable slot's ABI returns
float, but IDA types the Unit override `void __thiscall` and no caller uses the
result (`CUnitSacrificeTask.cpp:458` casts it to void). Check the asm tail for
what lands in xmm0/eax before choosing; do not guess.

Related: [[project_lua_stdlib_openers]] (the family-audit query that found it).

## Attempted 2026-08-14, reverted - it is a CHAIN, not one function

Wrote the body, tucheck failed on names, reverted cleanly (tree verified back to
zero diff, `Unit.cpp` still compiles). Everything above is still correct; these
are the extra blockers the attempt surfaced. **Resolve these before writing.**

Resolved along the way:
  - **Return type is `float`.** 0x006AA2F2 is `fld [esp+0Ch+a18]` before the
    epilogue. But `a18` is *never written* anywhere in the function - the binary
    returns an indeterminate frame slot, and every caller discards it. Declare
    `float Materialize(float) override;` to match `Entity`, return 0.0f, and say
    so in the comment.
  - **The stats deltas are blueprint costs**: 0x006AA1DB `add esi, 4ECh` and
    0x006AA215 `add esi, 4E8h` against the blueprint, and `Economy` is at
    +0x4E8 - so `Economy.BuildCostMass` (+0x4EC) for `Units_MassValue_Built`
    and `Economy.BuildCostEnergy` (+0x4E8) for `Units_EnergyValue_Built`.
    `sub_593290` is `AddArmyStatFloatByName(stats, float* delta, name)`
    (Unit.cpp:1736). `GetArmyStats` is army vtable slot 18 (`[edx+48h]`).
    Trailing `flt_E4F6E8` is -1.0 for the `Units_BeingBuilt` decrement.
  - Field spellings: `Entity::Health` (0x90), `MaxHealth` (0x94),
    `BeingBuilt` (0x98), `FractionCompleted` (0xD8), `mCurrentLayer` (0x118),
    `id_` (0x68), `SimulationRef` (0x148), `ArmyRef` (0x14C);
    `Unit::mCreationTick` (0x528). Stats idiom at Unit.cpp:13537.

### CORRECTION - both RunScript variants DO exist; it is NOT a chain

I claimed they were missing. Wrong - I had only grepped `CScriptObject.h` for
the *IDA* spelling. Both are recovered, under intent-first names:

  - `RunScript_WeakunitStr` (0x006B0DD0) = **`CScriptObject::
    RunScriptOnStopBeingBuilt(const WeakPtr<Unit>& sourceUnitLink,
    const char* layerName)`** - fires `OnStopBeingBuilt(self, sourceUnit,
    layerName)`. Exactly Materialize's call.
  - `RunScript_OnAdjacentTo` (0x006B0660) = **`CScriptObject::
    RunScriptOnAdjacentTo(Unit* sourceUnit, Unit* adjacentUnit)`**.

Materialize's two adjacency calls are therefore
`this->RunScriptOnAdjacentTo(neighbour, this)` and
`neighbour->RunScriptOnAdjacentTo(this, this)`.

**This is the false-negative trap again - the fifth time this run.** Always
grep the whole tree for the behaviour, never one header for the IDA name.

### Names now all resolved

  - unit states: `VarDat().mUnitStates`, bit **`UNITSTATE_BeingBuilt = 39`**
    (`IUnit.h:65`) - matches the asm clearing 0x80 of the high dword.
  - `CollectAllOverlapping` is `static SEntitySetTemplateUnit*
    CollectAllOverlapping(SEntitySetTemplateUnit* outSet, Unit* unit)` -
    out-param, not a value return.
  - `COORDS_LayerToString` is declared in `Entity.h`; qualify it.
  - `Unit.cpp` needs `CScriptObject.h` included (that, not a missing function,
    is what the failed build was really telling me).

### ONE thing left to settle before writing

The creator link is **`Unit::CreatorRef`, an `SWeakRefSlot` at 0x04B8**, but
`RunScriptOnStopBeingBuilt` takes `const WeakPtr<Unit>&`. Find the typed bridge
between the two (or the accessor that already does it) - do NOT reinterpret_cast
between them, that is exactly the offset magic the fidelity contract bans.


## Landed - the two traps that cost two attempts

1. **`RunScript_WeakunitStr` / `RunScript_OnAdjacentTo` are NOT missing.** I
   grepped only `CScriptObject.h` for the IDA spelling, concluded they were
   absent, and reported Materialize as a bottom-up chain. Both were recovered
   all along under intent-first names:
   `CScriptObject::RunScriptOnStopBeingBuilt(const WeakPtr<Unit>&, const char*)`
   and `CScriptObject::RunScriptOnAdjacentTo(Unit*, Unit*)`. **Grep the whole
   tree for the behaviour, never one header for the IDA name.**
2. The real build failure was that I guessed method names, not that anything
   was missing - `Unit.cpp` already included both `CScriptObject.h` and
   `CArmyStats.h`.

Final name set, for anything else in this area:
`VarDat().mUnitStates` with `UNITSTATE_BeingBuilt = 39` (IUnit.h:65) ·
`Entity::LayerToString(ELayer)` (static, not a free `COORDS_*`) ·
`CreatorRef.AsWeakPtr<Unit>()` (the layout-asserted bridge on `SWeakRefSlot`;
do not reinterpret_cast) · `CollectAllOverlapping(&outSet, this)` filling a
`SEntitySetTemplateUnit`, iterated as `for (Entity* e : set.mVec)` through
`SEntitySetTemplateUnit::UnitFromEntry(e)` · `Entity::Health` / `MaxHealth` /
`BeingBuilt` / `FractionCompleted` / `id_` / `mCurrentLayer`.

**Still open in this family:** `Unit::Sync` (FUN_006ABCC0, 465i) is vtable slot
12 over `Entity::Sync(SSyncData*)` and is still missing, same situation
Materialize was in. `HandleResourceManagement` (227i), `MotionTick` (241i),
`UpdateGuardFormation` (117i) and `GetGuardFormation` (2i) also remain.
