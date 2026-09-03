---
name: project-newformation-arg1-type-conflict
description: RESOLVED - NewFormation reads arg1's vector at +0x08, so SFormationUnitWeakRefSet is mis-modelled as a FastVectorN; it is really the same node+view+inline[N] family as SGuardedByRuntimeList.
metadata:
  type: project
---

`Unit::UpdateGuardFormation` (FUN_006AA7A0, 117 instrs, **unrecovered closure = 1**)
is fully decoded and ready to write except for one type conflict on
`NewFormation`'s first argument. Do not write it with a `reinterpret_cast` -
that is the offset magic the fidelity contract forbids. Resolve the conflict
first; it is one `.asm` read away.

## RESOLVED (2026-08-15) - the alias is wrong, the offset is right

`FUN_0059C120` settles it callee-side, which binds every caller:

    0x0059C15D: mov edi, [ebp+arg_0]   ; arg1
    0x0059C168: mov esi, [edi+8]       ; begin  <- +0x08
    0x0059C16B: mov eax, [edi+0Ch]     ; end    <- +0x0C

`FastVector<T>` puts `start_` at +0x00 (`FastVector.h:269`), so **no**
`FastVectorN` can match. `SGuardedByRuntimeList` does match exactly: 8-byte
`TDatListItem` node, then the vector at +0x08.

And the sizes give the whole game away - both are the same family, differing
only in inline capacity:

    SGuardedByRuntimeList    0x28 = 8 (node) + 0x10 (view) + 4 * 4
    SFormationUnitWeakRefSet 0x38 = 8 (node) + 0x10 (view) + 8 * 4

So `Unit::GuardedByList` is modelled **correctly**, and
`using SFormationUnitWeakRefSet = gpg::fastvector_n<SFormationUnitWeakRef,10>`
(`IAiFormationDB.h:46`) is **wrong** - both in shape and in inline count (8,
not 10).

### DONE - landed in 772c276 + 643a6c1

`SWeakUnitRefList` (node +0x00, lane +0x08) now exists in `IAiFormationDB.h`;
`SFormationUnitWeakRefSet` is it plus 8 inline slots (0x38), and
`SGuardedByRuntimeList` is it plus 4 (0x28). `NewFormation` takes the shared
head. `SGuardedByWeakOwnerSlot` is now an alias of `SFormationUnitWeakRef`,
which carries both the `void* ownerLinkSlot` and `uint32_t ownerLinkSlotWord`
spellings in a union so all 21 pre-existing call sites still compile.

The `ScopedLinkedIUnitRefs` bug is fixed as a side effect - it already called
`begin()`/`end()`, which now resolve through the corrected head.

**`UpdateGuardFormation` is written, build-clean, and NOT committed** - saved at
`<scratchpad>/updateguardformation_ready.patch`. Its only caller is
`Unit::MotionTick`, same as [[project-handleresourcemanagement-decoded]]. Both
patches land together once MotionTick does.

### Original target design (kept for the reasoning trail)

The original almost certainly had an N-independent base plus a sized
derivative, mirroring `fastvector_runtime_view` vs `FastVectorN`:

    struct SWeakUnitRefList {              // the shape NewFormation takes
      TDatListItem<void,void> mOwnerNode;                        // +0x00
      gpg::fastvector_runtime_view<SFormationUnitWeakRef> mSlots; // +0x08
    };
    template <int N> struct SWeakUnitRefListN : SWeakUnitRefList {
      SFormationUnitWeakRef mInlineSlots[N];                     // +0x18
    };

`Unit::GuardedByList` is the N=4 instantiation, the formation temp is N=8, and
`NewFormation`'s parameter becomes `const SWeakUnitRefList*`. That single change
makes `UpdateGuardFormation` pass `&GuardedByList` **by type**, with no cast.

### Live bug this exposes in already-recovered code

`ScopedLinkedIUnitRefs` (`CAiFormationDBImpl.cpp:229-241`) reads
`unitWeakSet->begin()/->end()` at +0x00/+0x04 - i.e. it reads the **list node**
as begin/end. Every current `NewFormation` caller that builds a
`SFormationUnitWeakRefSet` local is therefore feeding it garbage:
`CAiTransportImpl.cpp:1591` and `CUnitCommand.cpp:1854`. Only 8 references
across 5 files, so the fix is contained - but it touches recovered code, so do
it as its own commit with a build check, not as a rider on another recovery.

## The conflict (original write-up, kept for the evidence trail)

`CAiFormationDBImpl::NewFormation` (0x0059C120) is declared in
`src/sdk/moho/ai/CAiFormationDBImpl.h` as taking
`const SFormationUnitWeakRefSet*` = `gpg::fastvector_n<SFormationUnitWeakRef,10>`,
size **0x38**, vector header at **+0x00**. `ScopedLinkedIUnitRefs`
(`CAiFormationDBImpl.cpp:226`) reads it via `->begin()/->end()`, i.e. +0x00/+0x04.

But `UpdateGuardFormation` passes `lea ecx, [esi+4F8h]` - that is
`Unit::GuardedByList`, a `SGuardedByRuntimeList` (Unit.h:2057), size **0x28**,
whose layout is `TDatListItem mOwnerNode` @+0x00 (8 bytes), then
`fastvector_runtime_view mSlots` @**+0x08**, then `mInlineSlots[4]` @+0x18.

The same function reads the guard count from `[esi+500h] - [esi+504h]`, i.e.
`GuardedByList + 0x08 / + 0x0C` - confirming the vector really is at +0x08 in
the object being passed.

So `NewFormation` receives a pointer whose vector starts 8 bytes further in
than `ScopedLinkedIUnitRefs` looks. Either:
  - (a) `SGuardedByRuntimeList` is right and `NewFormation`'s parameter should
    be `SGuardedByRuntimeList*` - meaning `ScopedLinkedIUnitRefs` reads the
    wrong offset and `CAiTransportImpl.cpp:1591`'s local `weakSet` is also
    mis-typed; or
  - (b) `Unit::GuardedByList`'s offset/type is wrong.

**Decisive test:** read `FUN_0059C120` (and the `TryConstructFormationInstance`
body it calls) in `.asm` and see which displacement off arg1 it dereferences.
+0x00 means (b); +0x08 means (a).

## Everything else about UpdateGuardFormation is already resolved

`esi` is `this` **unshifted** - offsets match `Unit.h` directly
(`[esi+520h]` = `GuardFormation`, `[esi+4F8h]` = `GuardedByList`), and `[esi]`
is the **IUnit** primary vtable. Verified slots, all matching our headers:
GetPosition = 5 (+0x14), GetTransform = 6 (+0x18), GetBlueprint = 7 (+0x1C),
IsMobile = 12 (+0x30). Final call is `[edx+54h]` = slot 21 =
`CAiFormationInstance::Func22(float)` documented at `CAiFormationInstance.h:536`.
Blueprint string is `AI.GuardFormationName` at RUnitBlueprint+0x470, taken as
`.c_str()` (the `_Myres < 0x10` SSO test).

Shape (mirrors the recovered precedent at `CAiTransportImpl.cpp:1591-1622`
almost line for line, which is a good template):

    if (GuardFormation != nullptr || GuardedByList is empty) return;
    name = GetBlueprint()->AI.GuardFormationName.c_str();  if (!name) return;
    SCoordsVec2 center{ GetPosition().x, GetPosition().z };
    Quatf q = IsMobile() ? GetTransform().orient_ : Zeroed<Quatf>();
    old = GuardFormation;
    GuardFormation = db->NewFormation(&GuardedByList, name, &center, q.x,q.y,q.z,q.w, 15);
    if (old) old->operator_delete(1);
    GuardFormation->Func22(1.0f);

`15` is `commandType`. The `db` is `SimulationRef->mFormationDB` (`[esi+150h]`
then `[ecx+980h]`).

## ⚠ IDA trap here - there is NO mobile/immobile asymmetry

IDA renders the two branches as passing *different* stack slots for
`formationCenter` (`v16` vs `&x`), which looks like a genuine 2007 copy-paste
bug. **It is not.** IDA wrongly attributed the `push 0Fh` (which is really
`NewFormation`'s trailing `commandType`, pushed early) to `GetTransform`,
which actually takes **no** arguments. That mis-attribution shifted IDA's own
`esp` base by 4 in the mobile branch only - hence `[esp+24h+var_8]` vs
`[esp+28h+var_C]` for what is the same encoded `esp+1Ch`.

Track `esp` yourself: `GetTransform` pops nothing, so both branches resolve to
frame-0xC = `&center.x`, and both pass `15` as `commandType`. Both branches are
identical apart from the quaternion source.

This is the concrete failure mode behind the "normalise esp before trusting
two references to the same slot" rule - IDA's base is only trustworthy when
its call-argument attribution is right. See [[project-missing-list-is-mostly-annotated]].

Related: [[project-cformationinstance-split-blocked]].
