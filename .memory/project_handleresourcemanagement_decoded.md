---
name: project-handleresourcemanagement-decoded
description: Unit::HandleResourceManagement (FUN_006AAAC0) and both its callees are fully decoded and ready to write; only field-name verification remains.
metadata:
  type: project
---

`Unit::HandleResourceManagement` (FUN_006AAAC0, 227 instrs) plus its whole
unrecovered closure (3 functions, 283 instrs) is decoded. Nothing is unknown -
what remains is verifying ~15 field/offset names against the headers, then
writing it. Do not write it without that verification pass.

## The three bodies

**FUN_006AD750 `func_SetExtraStorage(CEconStorage** slot, CEconStorage* next)`**
(15 instrs, `__usercall` slot@eax next@ecx):

    old = *slot; *slot = next;
    if (old) { if (old->mEconomy) old->Chng(-1); delete old; }

This is the same teardown the tail of `HandleResourceManagement` open-codes, so
lift it once and call it from both.

**FUN_007736A0 `CEconRequest::TakeFromPending(SEconValue* out, const SEconValue& wanted)`**
(41 instrs, `__userpurge` out@eax this@edx, wanted on stack) - take up to the
pending amount, then decrement pending, floored at zero:

    out = componentwise min(wanted, mAddWhenSetOff)         // 2-iteration loop
    mAddWhenSetOff = max(mAddWhenSetOff - out, 0)           // per component
    return out

**FUN_006AAAC0 `Unit::HandleResourceManagement()`**:

    mResourceConsumed = 0;
    rate = 1.0f;
    if (!GetBlueprint()->Economy.NaturalProducer && mConsumptionData)
      rate = mConsumptionData->LimitingRate();

    if (!IsDead() && mConsumptionIsActive && mConsumptionData) {
      r = mConsumptionData->LimitingRate();
      mResourceConsumed = r;
      want = mConsumptionData->mPerSecond;  want.ENERGY *= r; want.MASS *= r;
      SEconValue took; mConsumptionData->TakeFromPending(&took, want);
      VarDat().mResourcesSpent += took;              // componentwise
    }

    if (!mVarDat.mIsBeingBuilt && !IsDead() && mProductionActive) {
      bp = GetBlueprint();
      if (bp->Economy.StorageEnergy == 0 && bp->Economy.StorageMass == 0) {
        SetExtraStorage(&mExtraStorage, nullptr);
      } else {
        SEconValue cap{ bp->Economy.StorageEnergy, bp->Economy.StorageMass };
        if (mExtraStorage) mExtraStorage->ChangeAmt(cap);
        else SetExtraStorage(&mExtraStorage,
                             new CEconStorage(mArmy->GetEconomy(), cap));
      }
      SEconValue made{ VarDat().mAttributes.mProductionPerSecondEnergy * rate,
                       VarDat().mAttributes.mProductionPerSecondMass   * rate };
      made *= 0.1f;                                  // per-tick share, 10 ticks/s
      econ = mArmy->GetEconomy();
      econ->mResources += made;   econ->v4 += made;  // v4 needs a real name
      VarDat().mProduced += made;
      return;                                        // early return - no teardown
    }

    old = mExtraStorage; mExtraStorage = nullptr;     // same body as SetExtraStorage(.., nullptr)
    if (old) { if (old->mEconomy) old->Chng(-1); delete old; }

## Notes that matter

- The `0.1f` is the per-tick share of a per-second rate (10 ticks/s). Name it.
- `rate` is computed from `LimitingRate()` **twice** on two different
  conditions - the first is gated on `!NaturalProducer` and feeds *production*,
  the second is gated on `mConsumptionIsActive` and feeds *consumption*. They
  are not redundant; do not collapse them.
- The production branch **returns early**, so the storage teardown at the end
  runs only when the unit is being built, dead, or not producing.
- All the 2-iteration `do` loops over `&x.ENERGY` are componentwise SEconValue
  arithmetic. Lift them into named helpers/operators rather than reproducing
  decompiler-shaped pointer walks - see the fidelity contract.
- `CEconomy::v4` is an unnamed second accumulator that receives the same
  production delta as `mResources`. Name it from its other users before writing.

## VERIFIED (2026-08-15) - all offsets below are confirmed from FUN_006AAAC0.asm

`ebp` is the `Unit*` **unshifted**. Confirmed against `Unit.h`:
`[ebp+52Ch]` mExtraStorage, `[ebp+534h]` mConsumptionData, `[ebp+538h]`
ConsumptionActive, `[ebp+539h]` ProductionActive, `[ebp+53Ch]` ResourceConsumed,
`[ebp+154h]` army, `[ebp+0A0h]` = Entity::BeingBuilt (Entity subobject is at
Unit+8, so Entity+0x98). Vtable `[eax+1Ch]` GetBlueprint (slot 7), `[eax+28h]`
IsDead (slot 10), army `[edx+24h]` GetEconomy (slot 9).

Blueprint: `Economy` @ RUnitBlueprint+0x4E8, so `[eax+4F8h]` StorageEnergy,
`[eax+4FCh]` StorageMass, `[eax+500h]` NaturalProducer - all matching
`RUnitBlueprintEconomy` (+0x10/+0x14/+0x18).

**CEconRequest lanes settled** (`CEconomyEvent.h`: mNode +0x00, mRequested
+0x08, mGranted +0x10): the caller reads `[edx+8]` = **mRequested**, and
FUN_007736A0 does `edi = edx + 10h` = **mGranted**. So IDA's `mPerSecond` is
`mRequested` and its `mAddWhenSetOff` is `mGranted`. Semantics: want
`mRequested * rate`, draw it out of the granted pool, decrement granted.

Production attributes: `[ebp+478h]`/`[ebp+47Ch]` = VarDat(+0x288) + 0x1F0, and
`mAttributes` is at +0x1A0, so these are **UnitAttributes +0x50 / +0x54**
(per-second energy / mass). `[ebp+2E8h]` = VarDat+0x60 = `mProduced`. Confirmed.

## ⛔ THE REAL BLOCKER: no recovered caller (Unit::MotionTick)

The body is **written, correct and build-clean** - saved as a patch at
`<scratchpad>/handleresourcemanagement_ready.patch`. It was reverse-applied,
not committed, for one reason: `FUN_006AAAC0`'s **only** binary caller is
`FUN_006A9010 = Unit::MotionTick`, which is not recovered and not even declared
in `Unit.h`. Committing would create exactly the orphan helper the
source-level-invocation rule forbids.

`Unit::MotionTick` is 241 instrs; see [[project-unit-motion-closure-scoped]]
(6 fns / ~2600 instrs, no layout blockers). **Recover MotionTick first, then
re-apply the patch in the same pass** - that is a legal paired bottom-up
commit. The two file-private helpers (`SetExtraStorage`, `DrawFromGranted`) are
in the same patch and are invoked by the body, so they travel with it.

## ~~CSimArmyEconomyInfo +0x08 unmodelled~~ - RESOLVED, landed in 0e4fcb5

`CArmyImpl::GetEconomy()` returns `CSimArmyEconomyInfo*`, which we model as
`std::uint8_t _pad_00[0x18]; SEconTotals economy; // +0x18`
(`CSimArmyEconomyInfo.h:78-80`).

But the production accumulation writes **`lea ecx, [eax+8]`** - i.e. a 2-float
lane at **CSimArmyEconomyInfo+0x08**, inside that `_pad_00`. A second
accumulation follows at another offset (register-loaded; read the asm around
0x006AAD6B-0x006AAD89 to pin it), then the third writes `mProduced`.

There was never a layout unknown - I was reading the wrong class.
`CArmyImpl` allocates a **`CEconomy`** and hands it out through `GetEconomy()`
as a `CSimArmyEconomyInfo*` (`CArmyImpl.cpp:1445`), and `CEconomy`
(`moho/sim/CEconomy.h:92-96`) already had the region modelled: `mSim` +0x00,
`mIndex` +0x04, **`mResources` +0x08**, **`mPendingResources` +0x10**,
`mTotals` +0x18. The two lanes production writes are those. `_pad_00[0x18]`
was just the second, staler declaration of the same object; it now carries the
real names (commit 0e4fcb5).

**Lesson worth keeping:** when a field looks unmodelled, check whether the
object is declared twice under different names before concluding it is unknown.
`CSimArmyEconomyInfo` and `CEconomy` are the same binary object, and the
duplicate-layout contract says they should collapse into one.

## Still to verify before writing

Field names/offsets on: `Unit::{mResourceConsumed, mConsumptionData,
mConsumptionIsActive, mProductionActive, mExtraStorage, mArmy}`,
`CEconRequest::{mPerSecond, mAddWhenSetOff, LimitingRate}`,
`CEconStorage::{mEconomy, ChangeAmt, Chng, ctor(CEconomy*, SEconValue)}`,
`CEconomy::{mResources, v4}`, `RUnitBlueprint::Economy::{NaturalProducer,
StorageEnergy, StorageMass}`.

Related: [[project-unit-materialize-missing]].
