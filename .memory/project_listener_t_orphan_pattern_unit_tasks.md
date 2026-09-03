---
name: project-listener-t-orphan-pattern-unit-tasks
description: Repeated bug across CUnitXTask sibling classes - Listener<ECommandEvent>/<EFormationdStatus>/<EAiNavigatorEvent> modeled as inert data members (mVftable always null) instead of real C++ multiple inheritance, orphaning an already-recovered OnEvent body. Fixed for CUnitPatrolTask + CUnitGuardTask + CUnitMoveTask + CUnitFormAndMoveTask 2026-08-19; CUnitMeleeAttackTargetTask/CUnitAttackTargetTask still open (different shape).
metadata:
  type: project
---

## The bug

Several `CUnitXTask : public CCommandTask` sibling classes multiply-inherit
`Listener<ECommandEvent>` (and sometimes `Listener<EFormationdStatus>` /
`Listener<EAiNavigatorEvent>`) in the real binary, but got modeled in
`src/sdk/**` as plain data members shaped like the listener
(`mCommandEventListenerVftable` (always initialized to `0`) +
`mCommandEventListenerLink` as a `Broadcaster`) instead of real C++ base
classes. Since the vtable pointer is never populated, there is no
source-level dispatch path to the (often already-recovered!) `OnEvent`
body - it sat as a correctly-decoded but genuinely orphaned function,
violating the "no orphans" rule silently.

**Established-correct precedent**: `CUnitSacrificeTask`, `CUnitRepairTask`,
`CUnitReclaimTask`, `CUnitCaptureTask` already use real inheritance
(`: public CCommandTask, public <ClassName>ListenerPad, public
Listener<ECommandEvent>`), each with a 4-byte layout-only "Pad" base
absorbing the gap between `CCommandTask`'s end and the listener's real
offset.

## Fixed this session

- **`CUnitPatrolTask`** (783ecb5): two listeners
  (`Listener<ECommandEvent>` @+0x34, `Listener<EFormationdStatus>` @+0x44).
  Both `OnEvent` bodies recovered: `FUN_0061C3E0` (rebuild 1-cell `mGoal`
  from the bound command's position, push to navigator if moving,
  recompute search box) and `FUN_0061C470` (5 instructions: set
  `mNavStalled` when `event == FORMATIONSTATUS_FormationAtGoal`).
- **`CUnitGuardTask`** (6884648): one listener (`Listener<ECommandEvent>`
  @+0x34). Body was already recovered as a plain method
  (`OnLinkedCommandTargetChanged`) - just renamed to `OnEvent` and rewired.
- **`CUnitMoveTask`** (441b592): THREE listeners
  (`Listener<EAiNavigatorEvent>` @+0x34, `Listener<EFormationdStatus>` @+0x44
  - 1-instruction nullsub, `Listener<ECommandEvent>` @+0x54). All three
  `OnEvent` bodies landed: `HandleNavigatorEvent`/`FUN_00618BB0` and the
  nullsub/`FUN_00618C30` just needed renaming; the real new recovery was
  `FUN_00618C40` (0x00618C40, 143 instr, ECommandEvent) - rebuilds `mMoveGoal`
  from the bound command, either a dynamic footprint-derived path
  (`Unit::PrepareMove` + `SFootprint::ToCellPos` + `COORDS_ToWorldPos`,
  `useWholeMap` from `Entity::ArmyRef->UseWholeMap()` - confirmed via a
  raw PE vtable-slot read at `??_7CArmyImpl@Moho@@6B@+0xB8`, slot 46, which
  resolved to the ALREADY-recovered, correctly-named `CArmyImpl::UseWholeMap`)
  or a simpler static command-position path, preserving `mMoveGoal.mLayer`
  across the dynamic rebuild (save this+48 before the SNavGoal rebuild,
  restore after - exactly mirroring the idiom the class's own arg ctor
  already uses: `mMoveGoal = SNavGoal(cell); mMoveGoal.mLayer = ...;`).
  `Unit+340(0x154)` in the raw asm turned out to be `Entity::ArmyRef`
  (Entity subobject sits at Unit+8, `Entity::ArmyRef`@Entity+0x14C ==
  Unit+0x154) - always resolve a mystery `mUnit+N` field via the Entity
  offsetof asserts in `Entity.h` before treating it as unknown.
- **`CUnitFormAndMoveTask`** (5432da2): THREE listeners, same shape as
  `CUnitMoveTask` (Navigator@0x34/FormationStatus@0x44/CommandEvent@0x54).
  Purely a wiring fix, zero new decompilation - all three bodies
  (`HandleNavigatorEvent`, `HandleFormationStatusEvent`,
  `HandleCommandEvent`) were ALREADY fully recovered and correct; just
  renamed to `OnEvent` + converted to real MI. Fastest of the four passes
  (~15 min) precisely because no new asm tracing was needed - a good
  reminder to check whether the body already exists under a plausible name
  BEFORE assuming a blocked/orphaned token needs fresh decompilation work.

## Recipe (proven three times, fast to repeat)

1. Confirm the vtable secondary-base data xref exists:
   `grep -rl "<ClassName>@Moho@@6B?\$Listener" decomp/recovery/disasm/<ns>/*.xrefs.txt`
2. For each hit, read the `.xrefs.txt` to get the exact `Listener<T>`
   specialization and the target `FUN_` address (that address IS the real
   `OnEvent` body).
3. Check `recovered_progress.json` status for that token - it's often
   ALREADY `recovered` under a misleadingly-generic or overly-specific name;
   grep `src/sdk/**` for its address citation to find the existing body.
4. Add a 4-byte `<ClassName><Something>Slot` struct per gap (one per
   listener, absorbing whatever plain field currently sits between
   `CCommandTask`'s end/the previous listener's end and the next listener's
   real offset - usually named `mUnknownXX`/`mReservedXX`/a real field like
   `mFirstCommand` already).
5. Change the class declaration to
   `: public CCommandTask, public <Slot1>, public Listener<T1>, public <Slot2>, public Listener<T2>, ...`
   in EXACT offset order.
6. Remove the old plain-member field declarations (vftable + Broadcaster
   pairs) from the class body; remove their `offsetof` static_asserts;
   replace with ONE `sizeof(Base1)+sizeof(Slot1)+sizeof(Listener<T1>)+...  ==
   <nextRealFieldOffset>` assert (offsetof on a non-first-base member is not
   portable/reliable to assert directly).
7. Fix constructors: replace the removed fields' initializer-list entries
   with base-class initializers (`CUnitXTaskSlot()`, `Listener<T>()`) in the
   SAME position.
8. Rename the existing recovered method to `OnEvent(T event) override`
   (required exact name to satisfy the pure virtual). Body usually doesn't
   read the `event` parameter at all - both landed cases fire unconditionally
   regardless of which event value triggered them.
9. Fix in-body references: bare `mCommandEventListenerLink` -> qualify as
   `Listener<T>::mListenerLink` (unqualified works fine EXCEPT when
   multiple `Listener<T>` bases exist with the same member name - then it's
   ambiguous and MUST be qualified even for plain non-address use).
   `&mCommandEventListenerLink` (address-of) ALWAYS needs `&this->Listener<T>::mListenerLink`
   even with only one listener base - `&Base::member` outside the class
   parses as a pointer-to-member, not "address of this instance's member",
   unless qualified with `this->`.
10. `tucheck`, verify with `fa-find-callers` (`src_inv=yes`,
    `verdict=VTABLE_CONFIRMED`), commit.

## Still open (deliberately not rushed)

- **`CUnitMeleeAttackTargetTask` / `CUnitAttackTargetTask`**: NOT the same
  quick recipe - investigated 2026-08-19, this is a materially bigger job.
  Both derive from `CAttackTargetTask`, which is currently a fully
  layout-stubbed opaque blob (`unsigned char mPadding[0x90];`, zero real
  fields, not even a confirmed `: public CCommandTask` relationship). Both
  derived classes access their own state (target payload, listener links,
  etc.) through `RuntimeView` reinterpret_cast structs defined in their own
  `.cpp` anonymous namespaces, NOT as real class members - so this bug
  isn't "plain member instead of base class", it's "the whole object
  layout was never recovered, just poked at through casts". Fixing it
  properly means a real `CAttackTargetTask` layout recovery pass (RTTI +
  vtable + per-field asm evidence for BOTH derived classes, since they
  likely add different tail fields after the shared base) before any
  Listener<T> conversion is even possible. That's a dedicated-session task,
  not a same-recipe repeat.

  Also: as of 2026-08-19 another agent had `CUnitAttackTargetTask.cpp`
  mid-edit (uncommitted, unrelated small change - adding a
  `QuaternionMath.h` include and dropping a duplicate `MultQuadVec` forward
  decl). Low collision risk for THAT specific diff, but a full
  `CAttackTargetTask` layout rewrite touches the shared base header both
  classes depend on - re-check `git log`/current diff on both
  `CUnitAttackTargetTask.*` and `CUnitMeleeAttackTargetTask.*` before
  starting, in case it already landed or is mid-flight.

## How to apply

When picking up unit-task work again, re-run the vtable-xref grep across
`CUnitFormAndMoveTask`/`CUnitMeleeAttackTargetTask`/`CUnitAttackTargetTask`
first - if this note is stale (another session already landed one), skip it
and move to the next. Never trust Hexrays pseudocode's argument order for a
call into an already-established multi-parameter function without
cross-checking the raw `.asm` push sequence first - the `CUnitMoveTask` pass
raised a false alarm this way over `Unit::PrepareMove`'s argument order that
cost real time; the actual asm matched the established header fine, the
"mismatch" was Hexrays' own low-level register/stack-slot renaming, not a
real bug. A `mUnit+N` field with no obvious name should be resolved against
the `Entity.h` offsetof asserts (`Entity` subobject sits at `Unit+8`) before
assuming it needs new investigation - `Unit+340` looked mysterious but was
just `Entity::ArmyRef` eight bytes off.
