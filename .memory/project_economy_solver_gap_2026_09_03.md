---
name: project_economy_solver_gap_2026_09_03
description: "RESOLVED 2026-09-03 (118daf73 + f72e1bef). Income read +0; it needed BOTH entity scheduling and the func_ArmyProcessEconomy solver. Now matches the original exactly: 650/650 +1 mass, 4000/4000 +20 energy. Solver alone drains storage to zero -- scheduling must land first."
metadata:
  type: project
---

## RESOLVED -- both halves landed

`118daf73` scheduled entities as tasks (they were never ticked at all), then
`f72e1bef` recovered the solver. Income now reads **650/650 mass at +1 and
4000/4000 energy at +20**, identical to the original binary. Soaked to 00:49:20
game time, zero crashes. Still unwritten and purely additive: the ally
resource-sharing block (0x00771EE0) and the 24 `Economy_*` stat publishes
(0x00772050).

## The symptom (as first seen)

Our build shows `+0` mass and `+0` energy income. The **original binary**,
launched identically with `/map SCMP_009`, shows **`+1` mass / `+20` energy**,
the ACU selected, its panel reading `12000/12000 +10/s`, and a populated
minimap. That differential run is the fastest way to check any economy or UI
claim -- do it before theorising.

## Gap 1: the solver is unrecovered

`func_ArmyProcessEconomy` (**0x00771B50, 1418 instructions**) was claimed by
`ProcessArmyEconomyTick` in `CArmyImpl.cpp` -- a twenty-line copy of
already-computed totals into display fields. The false `Address:` line is
removed in `de1341ae`; the progress DB may still call the address `recovered`.

Everything needed to write it (verified from `.asm` + `.c`):

- Signature is `func_ArmyProcessEconomy(CEconomy*)`, **not** an army. Sole
  caller `CArmyImpl::OnTick` pushes `[army+0x1F4]` (`EconomyInfo`) at
  0x006FFDC4, so the existing call site is already correct.
- Walk: start at `[economy+0x5C]`, advance through the **+0x04 slot**
  (`mNext`), terminate at `&mConsumptionData`. `TDatListItem`'s names are the
  opposite of its slots -- both start and advance use +0x04, so `mNext` is
  right.
- Nodes are `CEconRequest` (already modelled; ctor 0x00773630 proves `mNode`
  +0x00, `mRequested` +0x08, `mGranted` +0x10, size 0x18). Its `mNode` is
  first, so a node pointer *is* the request pointer.
- Pass 1 sums `max(0, mRequested - mGranted)` per node, pooling requests that
  want **both** lanes separately from single-lane ones.
- `available = mTotals.mStored + mResources`, the latter scaled by
  `(Handicap + 1)` when `HasHandicap != 0` (`CArmyImpl::HasHandicap` @0x1DC,
  `Handicap` @0x1E0 -- they are on CArmyImpl, *not* `mVarDat`).
- Dual ratio = min `available/totalDemand` across lanes, remembering the
  limiting lane; single ratio comes from what remains, over the other lane.
- Pass 2 grants each node its outstanding share at whichever ratio applies
  (a node wanting nothing from the limiting lane uses the single ratio), adds
  it to `mGranted`, and subtracts from `available`.
- Then `mLastUseRequested = totalDemand`; `mLastUseActual` is **recomputed** as
  `dual*dualRatio + single*singleRatio`, not the running total;
  `mIncome = mResources`.
- Tails not yet written: the `mResourceSharing` block (~0x00771EE0) spreading
  overflow across allied economies, and 24 `Economy_*` stat publishes via
  `func_GetArmyStat2` with interlocked accumulate.
- `mStored = clamp(available, 0, |mMaxStorage|)`, then **`mResources` and
  `mPendingResources` are zeroed** (0x00772D5E). That reset is inside this
  same function -- without it income would accumulate without bound.

## Gap 2: NO UNIT IS TICKED AT ALL

**Corrected 2026-09-03.** I first recorded this as "production never reaches
`mResources`", implying a broken production setter. That was an inference and it
was wrong. The measured cause is broader and simpler -- see
[[project_entities_never_ticked_2026_09_03]].

`Unit::MotionTick` is **never called**. A counter at the top of
`HandleResourceManagement`, which `MotionTick` reaches unconditionally, logged
**zero** times over twenty-plus minutes of game time with nine armies.
Production is banked only from there, so income is +0 for that reason alone --
gap 1 is not required to explain it.

Everything that looked suspect is intact: `lua/sim/Unit.lua:307-309` calls
`SetProductionPerSecondEnergy` and `SetProductionActive(true)` at OnCreate, both
binders are registered, and `Unit::SetProductionActive` does set the flag.

## Why they must land together — measured, not predicted

I wrote the solver, built it clean, and ran it: stable (23m35s game time, zero
crashes), but storage fell from 650/3900 to **0/100**. That is a *correct*
solver faithfully reporting zero production -- it consumes and clamps properly
while nothing produces. Observably it is worse than the frozen values, so the
change was reverted rather than shipped half-done. Land gap 2 first, or both at
once.
