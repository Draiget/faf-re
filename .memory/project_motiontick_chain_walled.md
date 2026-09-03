---
name: project-motiontick-chain-walled
description: The Unit::MotionTick chain (~4000 instrs) has no landable entry point - every member is gated on the chain itself, so it must be recovered top-down as one atomic cluster.
metadata:
  type: project
---

`Unit::MotionTick` (FUN_006A9010, 241 instrs) is the single keystone gating two
already-written, build-clean patches:
[[project-handleresourcemanagement-decoded]] and the `UpdateGuardFormation`
patch (see [[project-newformation-arg1-type-conflict]]). Both are saved in the
session scratchpad and land together once MotionTick does.

Every one of `Unit::MotionTick`'s callees is already recovered **except**
`CUnitMotion::MotionTick` (FUN_006B9D10).

## The chain, in bottom-up order (measured 2026-08-17)

Closure of `CUnitMotion::MotionTick`: **25 functions / 4772 instrs**. Excluding
CRT (`std::string::*`, `sqrtf`, `sinf`, `cosf`) and vendored WildMagic
(`Wm3::Vector3::Normalize`), the engine work is ~4000 instrs:

    deps=0     6  FUN_005413C0  STIMap water-elevation-or-default (see below)
    deps=0     8  FUN_0050ACC0  WeakPtr_CHeightField::GetElevation
    deps=0   126  FUN_006978D0  sub_6978D0
    deps=0   161  FUN_00698350  sub_698350
    deps=1    62  FUN_00697B00  sub_697B00
    deps=1   246  FUN_006BC460  CUnitMotion::HandleGroundCollision
    deps=2   365  FUN_006BDEE0  CUnitMotion::CalcCirclingOrientation
    deps=2   376  FUN_006B9D10  CUnitMotion::MotionTick        <- root
    deps=2   455  FUN_006BE6B0  CUnitMotion::ComputeAirControl
    deps=3   604  FUN_006BCDB0  CUnitMotion::ComputeAirCombatTactics
    deps=4   592  FUN_006C0290  CUnitMotion::CalcMoveBallistic
    deps=10 1235  FUN_006BEE50  CUnitMotion::CalcMoveAir

## ⛔ Why it cannot be recovered incrementally

**No member of this chain has a usable caller outside the chain.** Checked every
leaf: `sub_6978D0`, `sub_698350`, `sub_697B00` and `HandleGroundCollision` have
zero recovered callers, and the two trivial accessors' only non-chain callers
are themselves problems (below). So recovering any leaf first produces an orphan
helper, which the source-level-invocation rule forbids.

**It must be recovered top-down as one atomic cluster** - like the AcquireTarget
11-function commit - holding everything uncommitted until the chain closes, then
landing MotionTick + both saved patches together. Budget a full context window;
do not start it on a partial one.

## Two traps found while probing for an entry point

**1. `CAiPathSpline::Generate` (0x005B2FF0) is NOT a valid recovered caller.**
Its body carries an explicit `TODO(binary-fidelity): current body is a
provisional typed lift. Exact FA behavior depends on full PPS state-machine
reconstruction`. It is marked `recovered` and appears in every have-set, so it
looks like a clean caller and is not one. Treat any candidate whose only
recovered caller is `Generate` as blocked. Same class as
[[project-elided-caller-false-positives]].

**2. `FUN_005413C0` is not `STIMap::GetWaterElevation`.** IDA labels it that,
but the body is:

    if (mWaterEnabled) return mWaterElevation;   // +0x1534 / +0x1538
    else               return -10000.0f;         // ds:dword_E4F6E4

i.e. `GetWaterElevationOrDefault`. The real `STIMap::GetWaterElevation`
(`STIMap.cpp:4219`) is a plain field read and is already recovered. Three sites
open-code the or-default form -- `IUnit.cpp:131`, `IUnit.cpp:135`,
`Entity.cpp:3270` (with a literal `-10000.0f`) -- but the binary genuinely
inlines it at those sites, so they stay as they are. Only `Generate` and
`CalcMoveAir` call the out-of-line copy.

## Callgraph caveat worth remembering

`call_edges.src_ea` for this edge pointed at 0x005B31B0, which is **inside** the
`movss` at 0x005B31AB - i.e. the recorded call address can be bogus even when
the edge itself is real. Do not conclude an edge is spurious from the address
alone; grep the `.asm` for the callee symbol name instead
(`rg -o 'call.*' FUN_x.asm | sort -u`).
