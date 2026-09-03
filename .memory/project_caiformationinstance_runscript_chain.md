---
name: project-caiformationinstance-runscript-chain
description: Full bottom-up map of CAiFormationInstance::Setup/PreRunScript/RunScript/FORMATION_RunScript/UpdateFormation chain (formation-script Lua execution pipeline). RunScript itself is FULLY TRACED (2026-08-19, background agent, 1010 instr/12 phases) but its own dependency closure (sub_56AAF0/sub_56C940/sub_572350+4/sub_56D9D0/sub_575690/FORMATION_RunScript+deps) is bigger than originally scoped - multi-session effort, deliberately not landed yet. SFormationScriptResult's real layout is now known (bool mSuccess +0x00, fastvector mObjs +0x08 of 0x38-byte elements).
metadata:
  type: project
---

## The chain (bottom-up, all currently `blocked` except where noted)

```
UpdateFormation (FUN_00568CA0, 416 instr, callee_health 94%, verdict OK_RECOVERED_CALLER
                 - already has REAL recovered callers: FUN_005694B0/FUN_00569CB0/
                 FUN_00569F70/FUN_0059AE80, all in CAiFormationInstance.cpp /
                 CAiFormationDBImpl.cpp)
  -> Setup (FUN_00568820, ~40 instr, tiny, Hexrays .c IS available and fully read -
            see below)
       -> PreRunScript (FUN_00566B10, 144 instr, callee_health 100%, Hexrays .c
                         available - see below, genuinely intricate WeakPtr<Unit>
                         intrusive-list surgery with ADJ() ptr-adjustment casts)
       -> RunScript (FUN_00567300, 1010 instr, 4372 bytes - Hexrays CANNOT decompile
                      it, verified via 8 failed retry attempts, exit_code=-1073741819/
                      ACCESS_VIOLATION every time. Raw asm only. Has an SEH prologue
                      and a 0xC64=3172-byte stack frame.)
            -> FORMATION_RunScript (FUN_00576690, 344 instr, callee_health 94%,
                                     Hexrays .c available - see below)
                 -> sub_576C20 (FUN_00576C20, 48 instr) - fastvector_n15_LuaObject
                    copy-construct helper. Container/template-emission lane
                    (gpg::FastVectorN<LuaPlus::LuaObject,15> per legacy/containers/
                    FastVector.h - this template already exists and is used
                    elsewhere), NOT a standalone recovery target.
                 -> sub_576C80 (FUN_00576C80, 59 instr) - grows a vector of
                    struct_FormationResult elements (copies offset.x/offset.z/v2/
                    catOrdinal/arg4, calls gpg::fastvector_uint::resize on a nested
                    v6 member). Also container-growth mechanics, but touches the
                    NOT-YET-MODELED SFormationScriptResult-adjacent per-entry type -
                    worth re-reading once SFormationScriptResult's layout is pinned
                    down, since its field names/offsets are direct evidence for it.
```

## What's already understood

**`Setup` (FUN_00568820)** - fully read via Hexrays, trivial:
```c
void __userpurge Moho::CAiFormationInstance::Setup(int idx@<edi>, CAiFormationInstance *a2, fastvector_n4_WeakPtr_IUnit *a3)
{
  // build local fastvector_n4_WeakPtr_IUnit a1 (SBO, inline capacity 4)
  PreRunScript(&a1, a2, a3, idx);
  if (a1.start != a1.finish)          // PreRunScript found >=1 matching unit
    RunScript(a2, &a1, idx);
  UnlinkWeakPtrUnitRange(a1.start, a1.finish);   // == sub_56D3C0, ALREADY recovered
  if (a1.start != a1.originalvec) operator delete[](a1.start);  // heap-spill cleanup
}
```
RunScript is called CONDITIONALLY - the "no stub" rule means Setup cannot be
committed without RunScript also being real (can't skip/stub a real conditional
call the binary makes).

**`PreRunScript` (FUN_00566B10)** - fully read via Hexrays. Filters `a3` (a
`fastvector_n4_WeakPtr_IUnit` of ALL formation-member units) down into `a1`
(destination), keeping only units where `unit->GetLayer() == idx` (a virtual
call), using intrusive `WeakPtr<Unit>`/`WeakObject_IUnit` link manipulation
(`mNextUse` chains) to MOVE (not copy) matching entries out of `a3` into `a1`
by splicing. Calls `sub_56B2F0` (grow, ALREADY recovered per progress DB),
`sub_5725A0` (ALREADY recovered), `sub_56D3C0`/`UnlinkWeakPtrUnitRange`
(ALREADY recovered). Heavy `ADJ()` decompiler pointer-adjustment casts
throughout (multiple-inheritance this-pointer adjustment artifacts) - needs
careful, unhurried translation to the real typed `WeakPtr<Unit>` API rather
than raw offset surgery. Genuinely all-recovered-callees now (confirmed via
fa-find-callers: callee_health 100%), so this ONE function is close to
landable in isolation - the blocker is purely that its caller (Setup) can't
be committed until RunScript is also ready.

**`FORMATION_RunScript` (FUN_00576690)** - fully read via Hexrays. Does the
actual Lua call: imports `/lua/formations.lua`, looks up `scriptName` as a
function, calls it with the pre-built units Lua table, iterates the returned
Lua table's entries (each expected to be a 5-element table: x, z,
EntityCategory, some float "arg4", a bool), builds one
`struct_FormationResult` per entry (`v26` local: `v2`=arg4 int param passed
through unchanged per-entry?, `offset.x`/`offset.z`=floats from slots 1/2,
`catOrdinal`=`EntityCategory->mSet.mStart`, a `fastvector_uint`-shaped `v6`
copied from `EntityCategory->mSet.mUsed` via `gpg::fastvector_uint::cpy`,
`arg4`=float from slot 4), appends it via `sub_576C80`, and does cleanup.
Result carries `mSuccess` (bool from slot-5 boolean) and `mObjs` (a
fastvector-shaped range - the accumulated per-slot `struct_FormationResult`
entries) as the two currently-known named fields of
`Moho::SFormationScriptResult`. SEH-guarded (the `v37`/`v36` state-machine
locals are unwind-cleanup-stage markers, standard MSVC EH pattern - each
`LOBYTE(v37) = N` marks "how far constructed" for the SEH funclet's teardown
path, not meaningful application state).

**`RunScript` (FUN_00567300)** - FULLY TRACED 2026-08-19 by a background
agent (1010 instructions, 12 phases A-L + EH funclets, 85-local offset table
computer-verified against the raw SIB-byte encodings, zero inconsistencies).
Full report is long; key actionable findings below. **The upshot: RunScript's
own dependency closure is bigger than originally scoped** - landing it needs
several MORE blocked functions recovered first, not just RunScript itself.

Real signature (confirmed from both the caller's clean Hexrays output AND
the callee's own prologue): `this=ebx` (arg_0, stack), `units=ebp` (arg_4,
stack, the `fastvector_n4_WeakPtr_IUnit*`), `idx=arg_8` (stack, int, never
register-cached - read directly at its one use, `0x00568190`). All three
are plain stack params (not fastcall/thiscall for this specific
`__usercall`-shaped function) - `retn 0Ch` pops all 3. Effectively `void`
(caller ignores the return register).

Phase summary (see full report for exact addresses/instructions - this is
condensed):
- **A** (`0x567300-336`): SEH prologue, `sub esp, 0xC64` (3172-byte frame).
- **B** (`336-3BB`): build a `LuaPlus::LuaObject` table from the unit range -
  per unit, `WeakPtr<IUnit>::GetObjectPtr()`-equivalent decode (raw `-4`),
  vtable slot 8 (`IUnit::GetLuaObject()`, confirmed via `IUnit.h:161-165`),
  `LuaObject::Insert`.
- **C** (`3BB-405`): resolve `mScriptName` (SSO string at `this+0x2F4`), call
  `FORMATION_RunScript(mLuaState, mGameRules, scriptName, unitsTable)` -
  returns `SFormationScriptResult` by value via RVO. **If `mObjs` comes back
  empty, skip straight to Phase L (teardown)** - this is the one big branch
  gating whether Phases D-K run at all.
- **D** (`41B-428`): default-init a local `SFormationLaneEntry`-shaped
  staging object `a1` (NOT part of `SFormationScriptResult` - confirmed via
  `sub_568360`'s own recovery note and a 7-float field-copy pattern later
  matching `SFormationLaneUnitNode`, not the result struct).
- **E** (`428-526`): average-position accumulation over the ORIGINAL unit
  range (vtable slot 5 = `IUnit::GetPosition()`, confirmed `IUnit.h:139-144`).
- **F** (`526-7D3`): per-`mObjs`-entry (stride 0x38) farthest-distance scan,
  optional orientation-rotation via `Moho::MultQuadVec` when
  `mOrientationBaseline` isn't identity, builds a 16-slot "candidate" vector,
  reads `GetBlueprint()` (vtable slot 7, `IUnit.h:154-158`) twice per unit
  for an unresolved blueprint-field comparison. **Correction to my own
  earlier framing**: the agent found this loop's continuation bound at
  `0x005677C6` is `cmp ebx,[ebp+4]` - the ORIGINAL unit-range bound, not an
  `mObjs` bound as I'd assumed setting up the task. Re-verify this
  specifically before trusting it further.
- **G** (`7E4-C1B`): builds a second, SORTABLE "result" array of 0x48-byte
  "AI formation entries" - two passes over `mObjs`, calling
  `ComputeRunScriptOffset` (`FUN_00566A30`, ALREADY recovered,
  `CAiFormationInstance.cpp:687-693`) per entry, `gpg::fastvector_uint::cpy`
  to copy each entry's category bitset, `sub_56C940` (**blocked**) to append
  into the result array.
- **H** (`C21-8030`): `sub_572350` (**blocked**, needs 4 more deps) sorts the
  0x48-byte result array; then the main per-slot assignment loop matches
  each sorted formation-slot entry against the 16-slot candidate vector by
  category-bitset match + nearest distance, using `IUnit::GetEntityId()`
  (vtable slot 4, `IUnit.h:133-137`) as a tree-map key via `sub_56AF80`
  (already recovered) / `sub_56AAF0` (**blocked**) into `a1`'s
  `SFormationLaneUnitMap`, with a genuine "HASH duplicated" warning path
  (not a bug to fix - faithful behavior) and an unresolved second
  tree-insert pattern.
- **I** (`8036-230`): flushes "Failed to assign unit a slot" warnings for
  unmatched candidates (calls `[this_vtable+0x3C]`/slot 15, inferred but not
  independently re-derived to be `RemoveUnit(Unit*)`), then
  `sub_56B590(&this->mLanes[idx], &a1)` (already recovered) - **this is the
  actual payload-delivery call**, committing the built lane entry into the
  persistent `this->mLanes[idx]` array.
- **J** (`238-292`): `sub_56EB40` (= `EraseLaneMapNodeRange`, already
  recovered) tears down `a1.unitMap`'s tree now that it's copied out, then
  `operator delete` frees the tree's node-pool allocation.
- **K/L** (`292-31C`): `sub_570390` (already recovered) destroys `mObjs`
  range - this is the JOIN POINT for both the empty-`mObjs` early-out and
  the full path - then normal SEH-disarmed teardown and return.

`Moho::SFormationScriptResult`'s real layout (cross-confirmed 3 ways: the
offset table, the EH funclet trampoline, and `sub_568320`'s own already-
decompiled body which literally reads/writes `a1+8/+12/+16/+20`):
```cpp
struct SFormationScriptResult {
  bool mSuccess;   // +0x00 (1 byte; +0x01..+0x07 unobserved, likely padding)
  struct { T* start, *finish, *capacity, *originalvec; } mObjs;  // +0x08, element = 0x38 bytes
};
```
**Important correction**: `FUN_00576690.c`'s (`FORMATION_RunScript`) local
`result` is Hexrays-mistyped as `gpg::fastvector_n15_LuaObject` - the real
element size is 0x38 bytes (matching the mObjs stride, confirmed
independently via the `0x92492493` reciprocal-divide magic constant AND
`sub_570390`'s own recovery note "0x38 script-slot records"), NOT
`sizeof(LuaObject)`. Do NOT model `SFormationScriptResult::mObjs`'s element
as a `LuaObject`-shaped thing - it's the `struct_FormationResult`/`v26`
shape from `FORMATION_RunScript.c` (partially reconstructed, see that
function's own section above - `v2`/`offset.x`/`offset.z`/`catOrdinal` at
the front, a `fastvector_uint` category-bitset around `+0x18`, a trailing
float `arg4`; bytes `+0x10..+0x17` still unaccounted for).

**RunScript's OWN unresolved dependency closure (this is the real remaining
scope, bigger than originally estimated)**:
- `sub_56AAF0` (blocked, depends on `FUN_005683F0`/`FUN_0056CCE0`/`FUN_0056D9D0`) - tree node construct/insert into `a1.unitMap`.
- `sub_56C940` (blocked, depends on `FUN_0056CB60`/`FUN_0056E620`) - appends one 0x48-byte result-array entry.
- `sub_572350` (blocked, depends on `FUN_005734F0`/`FUN_00574170`/`FUN_00574A30`/`FUN_00574B40`) - introsort over the 0x48-byte result array.
- `sub_56D9D0` (blocked) and `sub_575690` (blocked) - **could not even be located as literal call-site text** in RunScript's own `.asm` (zero grep hits); `meta.json` lists them as callees, meaning they're reached via one of RunScript's several indirect `call eax`/`call edx` vtable dispatches, most likely from inside `sub_572350`'s own call tree given a size-match ("72-byte heap lane" in `sub_575690`'s note matches the result array). Needs its own resolution pass.
- `FORMATION_RunScript` (blocked, depends on `FUN_00568320`/`FUN_00570390`/`FUN_005704C0`/`FUN_00576C20`/...) - already covered above, needs `struct_FormationResult` modeled plus `sub_576C80`'s container-growth mechanics understood.

This is genuinely a MULTI-SESSION-SCALE subsystem once you count the full
transitive closure - not "RunScript + 4 small friends" as originally scoped.
Budget accordingly; don't try to rush the whole thing in one sitting even
with this trace in hand.

Explicit uncertainty flags from the trace (verify before relying on them):
blueprint-field offsets (`+0x368`/`+8`/`+0x28` off `GetBlueprint()`) are
unread; the `var_B7C` family of float-pair writes plausibly but unverifiedly
feed `SFormationLaneEntry`'s six `overlapRadius*/dynamicOffset*/
overlapAnchor*` floats; `mObjs` element bytes `+0x10..+0x17` unaccounted
for; EH state-table chaining (states 3/4/6/7) is inferred from local
liveness windows, not read from the raw `stru_F12B50` FuncInfo bytes; the
self-vtable-call at slot 15 (`0x3C`) is inferred to be `RemoveUnit` from
declaration order, not independently re-derived the way slots 4/5/7/8 were.

## Investigated and RULED OUT while drafting PreRunScript (2026-08-19, same pass)

Initially hypothesized the `fastvector_n4_WeakPtr_IUnit` element type Hexrays
names for `PreRunScript`/`Setup`'s vectors was actually a mis-simplified
label for the ALREADY-modeled `Moho::SFormationLinkedUnitRef`
(`CAiFormationInstance.h:37`, used by `CAiFormationInstance::mUnits` +0x20),
based on the already-recovered `sub_56B2F0` (PreRunScript's "grow" callee)
being documented in `gpg/core/containers/FastVector.h:810` as
`gpg::fastvector_n<Moho::SFormationLinkedUnitRef, 4>::InsertAt`.

**This was checked against `UpdateFormation`'s (FUN_00568CA0) own body and
DISPROVEN.** Its local `units` (the exact vector later passed as Setup's
`a3`) is built via
`Moho::WeakPtr_IUnit::WeakPtr_IUnit((WeakPtr_IUnit*)&a2, v8); fastvector_n4_WeakPtr_IUnit::push_back(&units, &a2);`
- a REAL, freshly-constructed `WeakPtr<IUnit>` (or `WeakPtr<Unit>`, need to
pin down which - check whether `WeakPtr<IUnit>` is a distinct established
instantiation or an alias) gets pushed, not an `SFormationLinkedUnitRef`.
So Hexrays' original `fastvector_n4_WeakPtr_IUnit` naming was RIGHT for
THIS vector all along.

The `sub_56B2F0` "SFormationLinkedUnitRef::InsertAt" doc comment is not
wrong either - it's almost certainly an **ICF (identical COMDAT folding)
twin**: `FastVector<SFormationLinkedUnitRef,4>::InsertAt` and
`FastVector<WeakPtr<IUnit>,4>::InsertAt` (or `WeakPtr<Unit>`) are BOTH
8-byte-owner-link-node shapes, so the linker folded their byte-identical
compiled bodies to one address. Both logical call sites are real and
correct; they just share machine code. No fix needed on that doc comment,
but don't use it as type evidence for THIS call site again.

Net effect: PreRunScript/Setup's vectors genuinely are `WeakPtr<Unit-or-IUnit>`
as Hexrays originally said - `sub_56D3C0` = `UnlinkWeakPtrUnitRange` (already
established, `WeakPtr.h:1202`) is the right function after all, and the
earlier "use SFormationLinkedUnitRef's DecodeLinkedRefUnit/UnlinkLinkedRef/
RelinkLinkedRef helpers instead" idea does NOT apply here - those are for
`CAiFormationInstance::mUnits` itself (a genuinely different field/vector),
not for the transient `units`/PreRunScript-local vectors. Don't rediscover
this dead end again; go back to translating PreRunScript's `ADJ()` casts
directly against the established `WeakPtr<T>` API (GetObjectPtr,
UnlinkFromOwnerChain, LinkIntoOwnerChainHeadUnlinked, etc. - see
`moho/misc/WeakPtr.h`), the same way CUnitMoveTask/CUnitPatrolTask's
listener-link code already does elsewhere this session.

## PreRunScript's per-entry move is genuinely subtle - do not rush the translation

Traced the exact per-matching-entry logic (the `v8`/`v15`/`v16` dance in the
`.c`). It is NOT a simple "call `WeakPtr<T>::ResetFromObject`" translation.
For each `a3` entry whose unit matches the layer filter:

1. Compute `v8 = &unit's owner-chain-head field` (the slot every `WeakPtr<Unit>`
   pointing at that unit is linked through).
2. Temporarily splice a LOCAL STACK VARIABLE (`v15`, itself shaped like one
   link node) into `unit`'s owner chain in place of whatever was there
   (`v16 = *v8; *v8 = &v15;`) - this "reserves" the position representing the
   about-to-be-created new weak observation, before the new slot in `a1`
   even exists yet.
3. THEN decide how to actually create the new `a1`-tail entry: if `a1` needs
   to grow (`finish == capacity`), call `sub_56B2F0`
   (`FastVector<T,4>::InsertAt`, already recovered/generic) passing `&v15` as
   the source to copy from your local placeholder into the newly-allocated
   storage. If no growth needed, write `finish->mUnit`/`finish->mNext`
   directly and splice `finish` itself into `unit`'s REAL chain.
4. Finally unlink `v15` back out of `unit`'s chain (`restore *v8 = v16` via
   walking `v15`'s own `mNextUse`), since by this point the REAL entry
   (either the grown copy or `finish`) already occupies the position `v15`
   was temporarily holding.

This looks like manual "reserve a slot via a scratch node before the real
storage exists, to keep the intrusive chain valid across a potentially-
reallocating insert" - i.e. exception/reallocation safety for the intrusive
link structure. Translating this to "just call the WeakPtr<T> high-level
API" (`ResetFromObject`/`Set`) risks silently dropping this ordering
guarantee. If/when this gets written for real, either preserve the same
temporary-placeholder trick explicitly, or prove (don't assume) that
`FastVector<T,4>::InsertAt`'s existing implementation already handles
insert-with-possible-realloc safely enough that the placeholder dance is
unnecessary in the modern form - check `InsertAt`'s actual body
(`FastVector.h:833+`) for how it handles intrusive weak-ref elements
(there's already a `GrowInsertIntrusiveWeakRef` branch mentioned at line 857
- that's very likely the modern equivalent of this exact dance and may mean
you can just call `InsertAt` directly without hand-rolling the placeholder
node at all).

**Checked - `InsertAt`'s intrusive-relink branch does NOT yet cover
`WeakPtr<Unit>`.** `IsIntrusiveWeakRefSlot<T>` (`FastVector.h:75`, default
`std::false_type`) has exactly ONE true-specialization in the whole repo:
`IsIntrusiveWeakRefSlot<::moho::SWeakRefSlot>` (`Unit.h:174` - a DIFFERENT
already-modeled type, unrelated to `WeakPtr<T>`). So
`FastVector<WeakPtr<Unit>, N>::InsertAt` currently falls through to the
trivially-copyable memmove branch, NOT the relink-safe branch - calling it
as-is on a `WeakPtr<Unit>` vector would silently corrupt the intrusive
chain. The original binary's `sub_56B2F0` callee IS relink-safe for this
call site (proven by the fact it's the SAME address as the
`SFormationLinkedUnitRef::InsertAt` ICF twin, and per-byte-layout the two
types are relink-identical), meaning the ORIGINAL 2007 source had a generic
insert-with-relink primitive that both types shared - the MODERN recovered
`FastVector<T>::InsertAt` template just hasn't been extended with a
`WeakPtr<Unit>` (or a common base) specialization yet, only `SWeakRefSlot`.
Landing PreRunScript faithfully via the "just call InsertAt" shortcut would
therefore require EITHER (a) adding a new `IsIntrusiveWeakRefSlot<WeakPtr<Unit>>`
specialization to the shared container framework - a decision with
consequences for every OTHER consumer of `FastVector<WeakPtr<T>,N>`, not
something to rush - or (b) faithfully hand-rolling the binary's own
placeholder-node dance directly in PreRunScript's body instead of delegating
to the container. Either path is a genuine, non-trivial engineering
decision, not a copy-paste. This is the strongest single piece of evidence
that this chain needs a dedicated pass, not a same-session bolt-on.

**Found the right existing primitive - `AssignWeakPtrLaneWithRelink`.**
`moho/misc/WeakPtr.h:612` has exactly the single-element operation needed:
`AssignWeakPtrLaneWithRelink(WeakPtr<void>& destination, const WeakPtr<void>& source)`
- unlinks `destination` from whatever chain it's currently in (if any), then
links it into `source.ownerLinkSlot`'s chain head, preserving order. This is
a GENUINE, ALREADY-ESTABLISHED, heavily-reused idiom (its range form,
`AssignWeakPtrRangeForward` at line 648, has EIGHT ICF-folded address twins:
0x004FAF20/0x005725A0/0x00573140/0x006B2400/0x006EC520/0x006EB810/
0x007A5EB0/0x007A6030 - meaning this exact "relink-safe range copy" pattern
is used across at least 8 distinct call sites in the binary already). The
likely-correct modern PreRunScript per-entry move is: grow `a1` (manual
capacity check, or reuse whatever the vector's own grow path is once
resolved), `AssignWeakPtrLaneWithRelink(a1's new slot, a3[i])` to create the
new linked observation, then erase `a3[i]` from `a3` (shift tail; its own
destructor call unlinks the old slot). This is a real, concrete plan - just
still needs the exact grow-path mechanism nailed down (see the
`IsIntrusiveWeakRefSlot` gap above) and cross-verification against the raw
asm before writing anything final. Good starting point for whoever picks
this up next.

## UpdateFormation's offset-info loop - a second agent fully traced this too

The loop at `.c` lines 208-251 (the one calling `sub_56EB40` per-lane before
dispatching `Setup`) is **NOT** offset computation - `sub_56EB40` does zero
offset math. It's pure teardown: for each stale `SFormationLaneEntry` in
`mLanes[index]` (both lanes 0 and 1), unlink its weak-owner-word chain,
destroy its `unitMap`, reset the lane vector to inline storage, THEN
dispatch `Setup(index, this, &units)` to rebuild it. Confirmed **byte-for-
byte identical in shape** to the already-recovered, already-committed
sibling `CleanupFormation` (`FUN_00568AC0`, `CAiFormationInstance.cpp:4234-
4252`) - same fields, same call sequence, same helpers:

```cpp
for (std::int32_t index = 0; index < 2; ++index) {
  SFormationLaneEntry* lane = mLanes[index].begin();
  SFormationLaneEntry* const laneEnd = mLanes[index].end();
  while (lane != laneEnd) {
    UnlinkWeakWordNode(lane->linkedUnitBackLinkHeadWord, lane->linkedUnitBackLinkNextWord);
    DestroyLaneMapStorage(lane->unitMap);
    ++lane;
  }
  mLanes[index].ResetStorageToInline();
  Setup(index, this, &units);   // <-- the ONLY piece still blocked
}
```
`UnlinkWeakWordNode`, `DestroyLaneMapStorage`, `ResetStorageToInline` are
ALL already recovered and already used by `CleanupFormation` - this loop's
teardown half needs zero new recovery work. The `Setup()` call is the sole
remaining blocker, unchanged from the rest of this document.

**`sub_56EB40`/`EraseLaneMapNodeRange`** (`cpp:2404-2481`) and its caller
`sub_568360`/`ResetFormationLaneEntryUnitMapStorage` (`cpp:2483-2499`) are
BOTH still `[[maybe_unused]]` - but do NOT treat them like the
`EraseLinkedRefAndShiftTail` cluster removed this session. Unlike that one,
these have REAL, IDENTIFIED evidence: `sub_568360` is one of `RunScript`'s
own EH unwind funclets (destructs local `a1` on exception, trampoline at
`0xBADE31` per the RunScript trace above) - its caller genuinely exists,
just isn't committable until `RunScript` lands. Leave these alone.

**Naming/layout note for later**: `Moho::SOffsetInfo` (`h:139-190`) and
`Moho::SFormationLaneEntry` (`h:214-232`) are the SAME byte-identical
struct (both `0x4C`, every field matches 1:1) under two different names -
`SOffsetInfo` is genuinely RTTI-evidenced (confirmed via
`dumps/moho_engine_rtti.json`'s mangled `.?AUSOffsetInfoTypeInfo@Moho@@`
etc.), `SFormationLaneEntry` is a later, non-address-evidenced descriptive
rename applied by a different pass without recognizing the RTTI name
already existed. This is a live "Duplicate layout contract" violation
(CLAUDE.md: "pick a single owning reconstructed definition"), not urgent
but worth reconciling in a future pass - prefer `SFormationLaneEntry` for
the `mLanes`/`CleanupFormation` surface (source-consistency with what's
already committed) while treating `SOffsetInfo` as the correctly-named
reflection-surface alias for `MemberSerialize`/`SOffsetInfoSerializer`.

Also flagged (not fixed, out of scope for pure analysis): `FUN_00568AC0`
(`CleanupFormation`)'s progress-DB note is STALE - text claims
"mSlots/mMap1/mMap2/... untyped, Block: owner_layout" but the actual
committed source is fully typed with matching static_asserts, and its
status is already `recovered` regardless (confirmed - the stale text is
cosmetic only, doesn't gate anything, not worth a special fix pass).

## Why this wasn't landed 2026-08-19

1. RunScript has literally zero decompiler assistance (1010 raw instructions,
   SEH-guarded, 3172-byte stack frame) - a genuine evidence-quality blocker,
   not just "large."
2. `Moho::SFormationScriptResult` is a brand new, currently-unmodeled struct
   type that needs its OWN layout recovery pass (at least `mSuccess`, `mObjs`,
   and whatever RunScript's own untraced back-half touches) before anything
   downstream can be written faithfully.
3. The caller-wiring mandate means NONE of {Setup, PreRunScript, RunScript,
   FORMATION_RunScript} can be committed individually - Setup calls RunScript
   conditionally (no stubs allowed) and RunScript calls FORMATION_RunScript
   unconditionally, so the whole chain has to land in one atomic pass once
   RunScript's back half is understood.
4. `UpdateFormation` (the true root, already has real recovered callers) is
   ALSO worth landing in the same pass once Setup is ready, closing out the
   entire formation-instantiation-and-script-run pipeline in one go.

## How to apply

If picking this up again: re-run `fa-find-callers --callees` on FUN_00568CA0/
FUN_00568820/FUN_00566B10/FUN_00567300/FUN_00576690 first to confirm nothing's
changed (this is a shared, actively multi-agent-worked checkout - one of
FUN_0056B2F0/FUN_005725A0/FUN_0056D3C0/FUN_005692D0 being blocked used to gate
this chain and all four got resolved between an earlier pass and 2026-08-19,
so the dependency picture DOES shift under you). The full 7-function landing
order once RunScript is understood: sub_576C20/sub_576C80 (skip as covered by
FastVectorN<LuaObject,15>/container mechanics, don't hand-recover) ->
FORMATION_RunScript -> RunScript -> PreRunScript -> Setup -> UpdateFormation,
one commit.
