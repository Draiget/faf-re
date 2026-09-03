---
name: project-advancebeat-extradata-gap
description: LANDED d48eb47. Sim::AdvanceBeat is missing its entire sync-filter packing loop (~45 lines), not just the GetExtraData call - extra-unit-data records never reach the sync payload.
metadata:
  type: project
---

`Sim::AdvanceBeat` (0x00749F40, 551 instrs, `Sim.cpp:13324`) carries the note
"Partial high-fidelity lift ... one additional sync-filter packing pass still
tracked for follow-up evidence." **That pass is now pinpointed.**

## The gap - larger than first recorded

I first wrote this up as "one missing call". **It is the whole loop.** `Sim.cpp`
has zero references to `syncVec3`, `mSyncfilter.mSet1`, `ExtraData` *or*
`SExtraUnitData` - roughly 45 decompiled lines (emission ~196-242) are absent:

    for (id = BVIntSet::GetNext(-1, &mSyncFilter.mSet1); id != end;
         id = BVIntSet::GetNext(id, &mSyncFilter.mSet1)) {
      auto it = mEntityDB->mAllUnits.find(id);
      if (it == end) continue;
      Entity* ent = it->second;
      if (!ent || !ent->IsUnit()) continue;

      SExtraUnitData rec{};        // 32 bytes (the loop's >>5 stride)
      rec.<+0x00> = 0xF0000000;    // same "no entity" sentinel as kNoCreatorEntityId
      rec.<+0x14> = 0;
      unit->GetExtraData(&rec);
      syncVec3.push_back(rec);     // via sub_753AF0 / sub_74F3E0
    }

So no extra-unit-data reaches the sync payload at all.

The callee is not the problem - `Unit::GetExtraData` is fully recovered at
`Unit.cpp:17185` (0x006ACB20) and `Unit.h:230-247` documents the packed pair it
emits (8-byte records, owner id written at +0x18). Only the call site is
absent.

## What writing it needs

Good news on dependencies - the hard parts are already recovered:
`Unit::GetExtraData` (`Unit.cpp:17185`), and both fastvector insert lanes
`sub_753AF0` / `sub_74F3E0` (`gpg/core/containers/FastVectorInsertLanes.cpp`).

**Both unknowns are now RESOLVED from the emission's displacements.**

    lea esi, [ebp+0AA8h]   -> mSet1    = mSyncFilter.maskA
                              (mSyncFilter @0x0A88 + maskA @0x20 = 0x0AA8)
    lea edi, [ebp+0A28h]   -> syncVec3 = the Sim member at 0x0A28
    add ebx, 20h           -> element stride is 0x20 (32 bytes)

`SSyncFilterMaskBlock` (`SSyncFilter.h:18`) is exactly the BVIntSet shape the
decompile assumes: `rawWord` +0x00 is `mSet1.mStart`, `masks` +0x08 is
`mSet1.mUsed`, 0x20 total. `SSyncFilter` holds two (`maskA` +0x20, `maskB`
+0x50) - the displacement picks `maskA`.

## ⚠ And `syncVec3` is mis-typed in Sim.h

Sim+0x0A28 is **`mSyncSerializeGroup2`**, declared `msvc8::vector<void*>`
(`Sim.h:1363`; it follows `mLoadedMapRects` @0x0A08 and `mPrintField` @0x0A18,
each 0x10). But the emission strides **0x20 per element**, so it cannot be a
pointer vector - it holds 32-byte `SExtraUnitData` records.

That mis-typing is very likely *why* the packing loop was never written: the
declared type cannot express what the loop does. **Retype it first**, confirm
`SExtraUnitData` is 32 bytes (it is only forward-declared in `Sim.h:43`; note
`Unit.h:235` also defines a related `SExtraUnitDataPair` - check which the
vector holds), then write the loop.

## Two false alarms ruled out while finding this

Comparing the emission's call list against `Sim.cpp` by **symbol name** flags
two apparent gaps; only one is real.

- `CTaskStage::DoFrame` x3 - **not a gap.** Present as
  `TickTaskStage(&mTaskStageA / &mDiskWatcherTaskStage / &mTaskStageB)` at
  `Sim.cpp:13358-13360`. Grepping for `DoFrame` misses it entirely.
- `Unit::GetExtraData` - **real gap**, confirmed by grepping for the *behaviour*
  (`ExtraData`, `SExtraUnitData`) rather than the callee symbol.

Same lesson as [[project-entity-deserializer-missing]]: check for the behaviour
in the caller's file, never for the callee's name.

## Everything needed is now confirmed (2026-08-17) - it is transcription

- **Destination retyped**: `mSyncSerializeGroup2` is now
  `msvc8::vector<SExtraUnitData>` at Sim+0x0A28 (commit c764a0f). That retype was
  the real blocker - the old `vector<void*>` could not express the loop.
- **Filter set**: `mSyncFilter.maskA` (Sim+0x0AA8). `SSyncFilterMaskBlock` is the
  BVIntSet shape: `rawWord` +0x00 = `mStart`, `masks` +0x08 = `mUsed`.
- **Record**: `SExtraUnitData`, `sizeof == 0x20`, matching the emission's
  `add ebx, 20h`.
- **Callee**: `Unit::GetExtraData` recovered (`Unit.cpp:17185`).
- **Append helpers**: `sub_753AF0` / `sub_74F3E0` recovered
  (`FastVectorInsertLanes.cpp`).

### ⚠ The caller must seed the record's inline storage

`ExtraDataPairBuffer` (`Unit.cpp:2765`) **does not initialise** `pairsBegin` /
`pairsEnd` / `pairsCapacityEnd` / `pairsInlineBegin` - it assumes the caller
already did, and `push_back` expands "when the cursor reaches
`pairsCapacityEnd`". That is what the emission's three stores before the
`GetExtraData` call are doing. Seed it as an SBO fastvector over the single
inline pair:

    SExtraUnitData rec{};
    rec.pairsBegin       = &rec.inlinePair;
    rec.pairsEnd         = &rec.inlinePair;
    rec.pairsCapacityEnd = &rec.inlinePair + 1;   // exactly one inline slot
    rec.pairsInlineBegin = &rec.inlinePair;
    rec.unitEntityId     = 0xF0000000;            // same sentinel as kNoCreatorEntityId
    rec.syncAuxWord1C    = 0;                     // Unit.h already notes AdvanceBeat zeroes this

**Getting this seeding wrong corrupts the heap** via `push_back`, and it happens
every beat for every synced unit - so verify the four pointers against the
emission's stores before trusting the shape above.

## ⛔ CORRECTION: the loop shape recorded above is WRONG

The pseudo-code near the top (build a local record, seed it, call
`GetExtraData`, then `push_back`) does **not** match the emission. Reading the
stores around 0x0074A398:

    mov eax, [ebp+0A30h]   ; mSyncSerializeGroup2._Mylast   (0x0A28 + 8)
    lea edi, [eax-20h]     ; edi = &back()  - the element JUST appended
    mov eax, [ebx]         ; ebx = the Unit
    mov edx, [eax+10h]     ; vtable slot 4
    mov ecx, ebx
    call edx               ; unit->slot4()
    push eax               ; its result is the argument
    mov eax, edi
    call Unit::GetExtraData

So the real order is **append first, then fill in place**: the record is
push_back'ed into `mSyncSerializeGroup2`, and `GetExtraData` writes into
`vector.back()` - it does not populate a local that is then copied. That also
means the inline-storage seeding happens on the *vector's* element, not on a
stack temporary, and the earlier "seed a local `SExtraUnitData rec{}`" recipe
would produce a differently-shaped payload.

**Also unresolved**: the argument passed to `GetExtraData` is the result of a
virtual call through the unit's vtable slot 4, not the record pointer, while our
recovered signature is `GetExtraData(SExtraUnitData*) const` with `this` in
`ecx` (which holds the Unit here) and `eax` holding `&back()`. Reconcile the
calling convention against `FUN_006ACB20`'s own prologue before writing
anything - one of the two readings of which pointer is the destination must be
wrong.

**Do not write this loop from the pseudo-code above.** Re-derive it from the
emission.

## RESOLVED: the convention, and the final loop shape

`FUN_006ACB20`'s prologue settles which pointer is which:

    mov ebp, [esp+18h+a2]     ; the STACK argument ...
    mov ecx, [ebp+544h]       ; ... is the Unit  (Unit::AiAttacker is at 0x0544)
    mov edi, eax              ; and EAX is the SExtraUnitData* destination

IDA calls it `__usercall` because the compiler passed `out` in `eax` and the
unit on the stack, but semantically that is just `unit->GetExtraData(out)` -
**our recovered signature `void Unit::GetExtraData(SExtraUnitData*) const` is
correct**, no change needed.

At the call site, `[eax+10h]` (vtable slot 4) on the entity yields the `Unit*`
that becomes the stack argument - i.e. `Entity::IsUnit()`, which in this tree
returns a `Unit*` (same accessor `PickPathPreviewSubject` uses).

So the loop is:

    for (id = BVIntSet::GetNext(-1, &mSyncFilter.maskA); id != end;
         id = BVIntSet::GetNext(id, &mSyncFilter.maskA)) {
      auto it = mEntityDB->mAllUnits.find(id);
      if (it == mEntityDB->mAllUnits.end()) continue;
      Entity* ent = it->second;
      if (!ent) continue;
      Unit* unit = ent->IsUnit();
      if (!unit) continue;

      SExtraUnitData record{};
      record.pairsBegin       = &record.inlinePair;
      record.pairsEnd         = &record.inlinePair;
      record.pairsCapacityEnd = &record.inlinePair + 1;
      record.pairsInlineBegin = &record.inlinePair;
      record.unitEntityId     = 0xF0000000;
      record.syncAuxWord1C    = 0;

      mSyncSerializeGroup2.push_back(record);              // append FIRST
      unit->GetExtraData(&mSyncSerializeGroup2.back());     // then fill in place
    }

Append-then-fill is the part two earlier drafts of this note got backwards.
The remaining care point is that the seeded inline pointers must survive the
`push_back` copy - if `msvc8::vector`'s copy does not re-anchor them, seed the
element *after* appending instead (`back()` then fix its four pointers), which
is what the emission's ordering actually implies.

## Last unresolved piece: the entity lookup

Everything else is confirmed. The one thing still to find is the **`CEntityDb`
member the emission's `std::map_EntId_Entity::find` hits** - the decompile calls
it `mEntityDB->mAllUnits`, but `EntityDb.h` exposes only the node types
(`CEntityDbAllUnitsNode`, `UnitFronNode`) and no map member under that name.
Locate it by offset from `FUN_00749F40`'s `find` call site.

Two conveniences already exist for the rest:

- `BVSet::ForEachValue` (`BVSet.h:93`) is exactly the emission's
  `GetNext(0xFFFFFFFF)` / `GetNext(value)` walk - use it over
  `mSyncFilter.maskA` rather than open-coding the iteration.
- `Entity::IsUnit()` (`Entity.h:842`) returns `Unit*`, which is the vtable
  slot-4 call the emission makes.

Insertion point: `Sim.cpp:13394` carries the TODO comment, but note it sits
*before* the `AdvanceCoords` loop while the emission runs this pass *after* it
(asm: `call AdvanceCoords` at 0x0074A255, loop back to 0x0074A249, then
`lea esi, [ebp+0AA8h]` at 0x0074A261). Insert after the loop, and move or delete
the stale comment.

## CORRECTION 2 (RETRACTED) - and the real defect it uncovered

I briefly recorded that the lookup was `mCommandDB`, not `mEntityDB`, because
the asm reads

    mov edi, [ebp+984h]      ; Sim+0x0984
    mov ecx, edi             ; `this` for the map find
    call std__map_EntId_Entity__find
    mov edi, [edi+4]         ; _Myhead, for the end() compare

and `Sim.h` labelled 0x0984 as `mCommandDB`. **That retraction was itself
wrong. The decompile was right: it is the entity DB.** `Sim.h` was wrong.

Two independent proofs:

1. `CEntityDb` *is* the flattened map triplet - `mAllUnitsIteratorProxy` +0x00,
   `mAllUnits` (`_Myhead`) +0x04, `mAllUnitsSize` +0x08 (`EntityDb.h:301-303`).
   So passing a `CEntityDb*` straight in as the map `this` and reading `[+4]`
   for `_Myhead` is exactly right. `CCommandDb` cannot fit: its `sim` is at
   +0x00 and its map at +0x04, which would need `lea ecx,[edi+4]`.
2. `Sim`'s own ctor/dtor name the slots outright, at four sites:

       mov [ebx+984h], eax   right after  EntityDB::EntityDB()
       mov [ebx+988h], eax   right after  CommandDatabase::CommandDatabase()
       mov esi, [edi+984h]   before       ~EntityDB
       mov esi, [edi+988h]   before       ~CommandDatabase

## The real defect: Sim.h had mEntityDB and mCommandDB swapped

Binary order is `mFormationDB` 0x0980, **`mEntityDB` 0x0984, `mCommandDB`
0x0988**. `Sim.h` declared `mCommandDB` first, so C++ gave it 0x0984 and pushed
`mEntityDB` to 0x0988 - both pointers off by one slot from the binary.

Fixed by swapping the declarations and locking all three with `offsetof`
asserts. Name-based source stays correct either way (the two are only ever
touched by name), so this is a layout-fidelity fix rather than a behavioural
one - but it is exactly the kind of silent drift that makes an asm offset
argue against a correct decompile, which is what happened here.

**Lesson: when an asm displacement contradicts the decompiler's field name,
suspect our reconstructed header before suspecting the decompiler.** IDA
resolved that member from the real ctor; our header comment was hand-written.

## Meta: the loop shape has been corrected five times

Scope (one call -> ~45 lines), the mis-typed destination, loop shape
(fill-then-append -> append-then-fill), the calling convention, and the
insertion point. Confirmed against asm displacements: destination
`mSyncSerializeGroup2` @Sim+0x0A28 (retyped in c764a0f), filter set
`mSyncFilter.maskA` @Sim+0x0AA8, element size 0x20,
`GetExtraData(out@eax, unit@stack)`, and the lookup
`mEntityDB->mAllUnits` @Sim+0x0984.


## LANDED (2026-08-17) - d48eb47

The pass is in `Sim::AdvanceBeat`, after the `AdvanceCoords` loop. Four
underlying defects had to be fixed first, all of them real bugs rather than
tidying:

1. **`Sim::mEntityDB` / `mCommandDB` were swapped** (see the retraction above).
2. **`SExtraUnitData` was trivially copyable**, so `msvc8::vector` relocated it
   with `memcpy` (`Vector.h` `reallocate_to` picks that branch) and every
   already-packed record's self-pointers dangled into the freed buffer. It is
   really `{ FastVectorN<SExtraUnitDataPair,1> pairs; EntId; int32 }` - the four
   pointer stores at 0x0074A2F6-0x0074A302 are that container's default ctor.
3. **`FastVectorN` had no copy ctor.** The implicit one copied the pointer lanes
   so a copy aliased the source's inline buffer - a dangle, and a double free
   given the dtor frees heap storage. Now rebinds via `ResetFrom`.
4. **`SSyncFilterMaskBlock` was a duplicate declaration of `BVIntSet`** (same
   0x20 layout) with its own `Equals`/`CopyFrom`. Now an alias. Keep the one
   real difference: FUN_0073DD10 does **not** copy the metadata word, so
   `CopySyncFilterMaskPayload` exists instead of using `operator=`.

Retired along the way: `ExtraDataPairBuffer` in `Unit.cpp`, a hand-rolled
reimplementation of `FastVectorN::PushBack` + grow.

**Generalisable:** a struct that stores pointers into itself must never be
trivially copyable. Two more may exist - the audit is
`rg -n "InlineBegin|originalVec_|inlineVec_" src/sdk` and then check whether the
owning struct is stored in any vector.
