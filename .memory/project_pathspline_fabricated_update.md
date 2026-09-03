---
name: project-pathspline-fabricated-update
description: CAiPathSpline::Update is a fabricated "provisional typed lift" with invented stepping math, not a recovery. Its stated blockers are stale - all three cited helpers are recovered - and 16 helpers in the file are orphaned because nothing calls them.
metadata:
  type: project
---

`CAiPathSpline::Update` (0x005B26C0, `CAiPathSpline.cpp:1339`) carries:

    // TODO(binary-fidelity): current body is a provisional typed lift. Exact FA behavior
    // depends on sub_6990E0/sub_6992C0/sub_699760 math and additional physics helpers.

The body under it is **invented**, not recovered. It makes up its own
path: a `stepLen = max(0.1f, maxSpeed * 0.1f)`, a node count of `6` when
`updateMode` is 3 or 4 and `4` otherwise, and a cursor stepped along a
forward vector. None of that comes from the binary. The real function is
**534 instructions** (276 decompiled lines); the stand-in is about 40.

This is the same defect class as
[[project-fabricated-recovery-and-container-dup]] - plausible-looking
invented code in place of a recovery, which is worse than a stub because
nothing flags it.

## The stated blocker is stale

All three helpers the TODO names as blocking are **already recovered**:

    0x006990E0  BuildSteeringParamsFromTransform    CAiPathSpline.h:92
    0x006992C0  RotateDirectionTowardTargetLimited  CAiPathSpline.h:167
    0x00699760  ComputeSteeringSpeedCapFromParams   CAiPathSpline.cpp:262

The third is `[[maybe_unused]]` - an orphan - which is the tell: the real
`Update` is what would call it, and the fabricated body does not.

Unrecovered closure of `Update` is only **3 fns / 683 instrs**, and two of
those are terminal:

    FUN_005B26C0  534  Update itself
    FUN_005B4BB0  141  fastvector<CPathPoint>::insert   <- container emission
    FUN_00452FC0    8  sqrtf                            <- CRT

So there is **no real blocker left**. This is a single-session job: read
the 276-line decompile and write the body against the three helpers that
already exist.

## LANDED 07cb83e - and two claims above were wrong

`Update` is recovered for real as of `07cb83e`, tucheck EXITCODE=0. Two
things this note asserted beforehand did not survive contact:

  - **"landing Update should un-orphan the steering helpers."** It does
    not. The real `Update` calls the `SteeringParams` ctor, `VecSetLength`
    and `CHeightField::GetElevation` - it never calls
    `ComputeSteeringSpeedCapFromParams`. The orphan count is still 16.
    Those helpers belong to some other caller; do not treat them as a
    correctness check for this function.
  - **"Update has no source-level caller."** It does.
    `CAiSteeringImpl::UpdatePath` calls `mPath->Update(mOwnerUnit, pathMode)`
    by name. The grep that missed it filtered call lines on the word
    "spline", and the receiver here is `mPath`. Grep the *method* name,
    never the type name, when testing source-level invocation.

What the real body does: full reverse thrust against current velocity,
clamped by brake then speed limit, stepped in the (x, -z) plane with y
only ever sampled from the height field (water line for water /
amphibious-floating / hover). The facing comes from
`orient.Rotate({0,0,1})` unflattened - `UnitForwardXZ` flattens and
renormalises, so it is the wrong helper here.

`UpdatePath` independently confirms the mode analysis: it calls `Update`
only when `pathMode` is 3 or 4, which are exactly the two modes whose
terminal test can fire.

## The file has 16 orphans

`rg -c maybe_unused src/sdk/moho/ai/CAiPathSpline.cpp` returns **16**.
Several are steering helpers that only `Update` would call:

    ConstructSteeringParamsAdapter        :152
    NormalizeDirection2DUnchecked         :204
    BlendAndClampDirection3D              :224
    ComputeSteeringSpeedCapFromParams     :262

Landing the real `Update` should un-orphan most of them. Treat any that
remain orphaned afterwards as a signal the body is still incomplete.

## Second fabricated body: Generate, which blocks on itself

`CAiPathSpline::Generate` (0x005B2FF0, `CAiPathSpline.cpp:1376`) carries
the same TODO shape, and its stated blocker is **itself**:

    :1376  * Address: 0x005B2FF0 (FUN_005B2FF0, Moho::CAiPathSpline::Generate)
    :1386  // depends on full PPS state-machine reconstruction from 0x005B2FF0.

A function cannot be blocked on its own reconstruction. That is not a
stale blocker, it is a **placeholder blocker** - text written to make an
invented body look pending rather than wrong. Treat a TODO whose cited
address equals the enclosing function's own address as proof of
fabrication, and grep for the pattern across the tree.

The real `Generate` is **1236 instructions / 722 decompiled lines** -
almost 3x the 276 lines `Update` took, and it pulls in formation state
(`Unit::GetFormation`), the footprint (`Entity::GetFootprint`), a
`VAxes3` basis off the transform, water elevation, and repeated
`sub_6992C0` steering calls. Budget it as a session of its own, not as a
tail-end task; its unrecovered closure is
5 fns / 1399 instrs, and everything under it is terminal or trivial:

    FUN_005B2FF0  1236  Generate itself
    FUN_005B4BB0   141  fastvector insert emission
    FUN_0040DAB0     8  _fabs
    FUN_00452FC0     8  sqrtf
    FUN_005413C0     6  STIMap::GetWaterElevation   <- already recovered

So this file needs **1770 instructions** of real pathing written across
two bodies, against helpers that all already exist. No layout gate, no
unrecovered subsystem - just the work.

## Still open: Generate

`Generate` is still the fabricated one, and it is also called by name
from `UpdatePath`, so the invented body is live in the pathing path.

## Do not land the remaining one at the end of a long session

Both are dense steering/spline math. Replacing one plausible-but-wrong
body with another plausible-but-wrong body is worse than leaving the
TODO, because the second one will not carry a marker. Take these fresh,
with the `.c` open, and un-orphan the helpers as the correctness check:
if `ComputeSteeringSpeedCapFromParams` is still `[[maybe_unused]]` after
`Update` lands, the body is not the real one.

## Scope: contained to this one file

Audited tree-wide 2026-08-17. `TODO(binary-fidelity)` appears in exactly
**one file** - `CAiPathSpline.cpp`, twice - and the self-citing-blocker
pattern has exactly **one** instance, the `Generate` one above. So this
marker style is not a widespread habit; it is two bodies in one file.

That does NOT mean fabrication is confined here. It means *this marker*
is. Fabricated bodies that carry no TODO at all are invisible to this
audit - [[project-fabricated-recovery-and-container-dup]] found one that
cited a fake PR instead. The reusable signals are:

    TODO(binary-fidelity) / "provisional typed lift"   <- 1 file
    a cited blocker address == the enclosing function  <- 1 site
    helpers left [[maybe_unused]] in a file whose
      keystone is "recovered"                          <- 16 in this file

The third is the one worth generalising. A recovered keystone should
consume its file's helpers; a pile of orphans next to a "recovered"
caller means the caller is not really recovered.

## Why this matters for the goal

This is unit movement. A unit following a path built from invented
stepping math will not move the way the original does, and nothing about
it will look wrong in a build or a sweep.
