---
name: project-typeinfo-missing-members
description: 306 TypeInfo members are missing from src across 162 type infos; several are missing base REGISTRATIONS (a real reflection bug), not just orphaned helpers.
metadata:
  type: project
---

Found 2026-08-15 by extending the family audit to every `*TypeInfo::` member.

    306 TypeInfo members missing from src, across 162 type infos

Query: group binary functions whose demangled name contains `TypeInfo::`, drop
any whose address appears in `src/sdk`, bucket by class. Biggest offenders:

    CUnitPatrolTaskTypeInfo        6   CBoneEntityManipulatorTypeInfo  5
    RTrailBlueprintTypeInfo        5   CFootPlantManipulatorTypeInfo   5
    RBeamBlueprintTypeInfo         5   CThrustManipulatorTypeInfo      5
    EntityDBTypeInfo               5   CAiSteeringImplTypeInfo         4
    CUnitCarrierLaunchTypeInfo     4   CUnitMoveTaskTypeInfo           4
    CUnitUnloadUnitsTypeInfo       4   CTextureScrollerTypeInfo        4

Most are `Init` / `GetName` / `dtr` / `Delete` / `Destruct` / `NewRef` /
`CtrRef` that exist in src **unannotated** - those need an `Address:` line, not
a body (see the third family-audit outcome in
[[project_lua_stdlib_openers]]).

## The ones that matter: missing base REGISTRATIONS

**`CUnitPatrolTaskTypeInfo::Init` registers no bases at all.** Source is
`size_ = ...; RType::Init(); Finish();`. The binary emits three:

    AddBase_CCommandTask                0x0061CAA0  offset 0x00
    AddBase_Listener_ECommandEvent      0x0061CB00  offset 0x34
    AddBase_Listener_EFormationdStatus  0x0061CB60  offset 0x44

(the binary's own spelling is "Formationd" - keep it). Same bug class as
`IAiNavigator`: reflection cannot see these bases, so any reflected upcast
through them fails. `CAiSteeringImplTypeInfo` (AddBase_IAiSteering +
AddBase_CTask) looks like the same situation.

## Blocker before writing them

The clean pattern to copy is `CUnitScriptTaskTypeInfo.cpp:186`:
`AddBaseIfPresent(typeInfo, CachedXType(), offset)` with one member per base.
**But `AddBaseIfPresent` is already file-local-duplicated in two TUs**
(`CUnitScriptTaskTypeInfo.cpp:64` and `IAiCommandDispatchImplTypeInfo.cpp:92`).
Adding a third copy for the patrol task would recreate exactly the
duplicate-helper defect this whole line of work has been removing.

So: **hoist `AddBaseIfPresent` (and the `Cached*Type()` accessors it needs)
into a shared reflection header first**, then write the per-type-info members
on top of it. Do not start by copy-pasting a third local copy.

Related: [[project_lua_stdlib_openers]].


## The base-calls check has a FALSE-POSITIVE mode (found 2026-08-15)

The check that found the real bugs is: for each type info, compare the
`AddBase_*` members the binary emits against the base registrations the source
`Init` performs. Implemented as
`rg -A 14 "void <Class>::Init" <file> | rg -c 'AddBase|Base\(this\)'`.

**It reports 0 when `Init` is not a member.** Several type infos have their
`Init` recovered as a *free function* instead - e.g.
`CBoneEntityManipulatorTypeInfo::Init` (0x00634AC0) is
`InitBoneEntityManipulatorTypeInfo(gpg::RType*)` in `IAniManipulator.cpp:530`,
and it **does** call `AddIAniManipulatorBase`. Nothing is missing there.

Confirmed false positives (Init is a free function, base IS registered):
`CBoneEntityManipulatorTypeInfo`, `CFootPlantManipulatorTypeInfo`,
`CThrustManipulatorTypeInfo`. Do **not** "fix" these - they need the different
treatment of promoting both the Init and the AddBase to real members, and the
free-function Inits are `[[maybe_unused]]` orphans in their own right.

Before acting on a zero from this check, confirm the type info actually has a
member `Init` in src. `RTypeTypeInfo` (0x008E09C0 AddBase_RObject, offset 0)
and `CAiAttackerImplTypeInfo` (AddBase_IAiAttacker at 0, **AddBase_CScriptObject
at 0x0C**, source registers only one of the two) still need checking properly.

Genuine missing registrations confirmed and fixed so far: `CUnitPatrolTask`
(3 bases, d020b94), `CUnitCarrierLaunch` / `CUnitUnloadUnits` /
`CAiSiloBuildImpl` (1 each, a032ff6). Still open and genuine: `IAiNavigator`
(blocked on the missing base class).
