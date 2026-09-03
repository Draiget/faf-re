---
name: project-lua-stdlib-openers
description: The Lua math library was never opened from our Lua (22 orphaned math_* bodies); all standard openers are now ours. Includes the fork's exact RNG constant and the table-order trap.
metadata:
  type: project
---

**Landed 2026-08-14: `4b04336` (math) and `ab49034` (loadlib).**

## The gap that existed

Every `math_*` body was already recovered in `src/sdk/lua/LuaObject.cpp` and
every one carried `[[maybe_unused]]` - **22 functions nothing could reach**,
because the `mathlib` registration table and `luaopen_math` were missing, so
`luaopen_math(state)` at the init site resolved to the prebuilt **LuaPlusLibD**
instead. Same hybrid-ABI split that forced `LuaOpenIo` / `LuaOpenString` to be
renamed (see [[project_lua_hybrid_abi_blocker]]).

Genuinely absent and now recovered: `math_asin` (0x00919B10),
`math_random` (0x00919F90), the table at 0x00D46278, `luaopen_math`
(0x0091A110). Also `luaopen_loadlib` (0x0091A4B0), `loadlib` (0x0091A410) and
its GetLastError helper (0x0091A3B0).

**All standard openers are now ours**: LuaOpenTable, LuaOpenIo,
luaopen_serialize, LuaOpenString, LuaOpenMath, luaopen_debug, LuaOpenLoadLib,
luaopen_base.

## Two things that would have been wrong by assumption

1. **The table order is not stock Lua 5.0.** Read from `.rdata` at 0x00D46278,
   this fork lists `pow` **between `deg` and `rad`**, not after `randomseed`.
2. **`math_random`'s scale constant is `0x38000100`**
   (3.0518509447574615e-05), which is **NOT** 1/32768 (`0x38000000`). The
   fork's value is a hair larger. Keep it bit-exact - `math.random` feeds
   simulation code and drift desyncs. The sample is drawn *before* the argument
   count is read, so the RNG advances on every call regardless of form.

`luaopen_math` also installs `__pow` into the **globals** table (pseudo-index
-10001), not into `math` - that is what makes the `^` operator work. Only the
`pi` write lands on the math table.

## Recipe: reading a registration table out of the PE

Worth reusing - it is how both traps above were caught. Map RVA->file offset
through the section headers of `bin/2025.7.1/ForgedAlliance.exe` (imagebase
0x400000), then walk 8-byte `{const char* name; lua_CFunction fn}` pairs until
a null name, resolving each name pointer back through the same mapping.

## Audit result: no other orphaned Lua family

Checked all 171 `[[maybe_unused]]` in LuaObject.cpp. The 25 `luaB_*` and 8
`io_*` are all referenced from `base_funcs` / the io method tables, so their
attribute is stale noise, not orphanhood. **math was the only real gap.**

## Caveat on the reported lobby crash

The user's `attempt to call method 'pairs' (a nil value)` says *method*
(`obj:pairs()`), so it is a LuaPlus binding, not the base-library `pairs` -
`luaB_pairs` is registered correctly. Do not chase it here.

Related: [[project_lua_strlib_landed]], [[project_lua_registration_sweep]].

## Same pattern found again in reflection (`7eafdfb`)

`gpg::RRef` had six of the nine per-type integer upcasts the binary emits;
plain `char` (0x008E15B0), `short` (0x008E1680) and `int` (0x008E1720) were
missing. Cause was identical to the math case: `RIntegerTypes.cpp` carried a
file-private `TryUpcastIntegerValue<T>` that re-derived the same
lookup-and-throw, so the real functions were never needed - **and the six that
did exist had no caller either.** Replaced with an `UpcastIntegerLane` overload
set dispatching to `RRef::TryUpcast*`, so all nine are now reached by name from
`RIntType_*::CpyRef / CtrRef / MovRef`.

Note plain `char` is a distinct reflected type from both `signed char` and
`unsigned char` - it needs its own lane, not an alias.

**The generalisable lesson: a file-private template that re-implements a
recovered API silently orphans the whole family it duplicates.** Both gaps
found this way were invisible to the closure query (which counts *called*
functions) and to the progress DB. Grep for private helpers whose body matches
an existing `src/sdk` API before trusting either.

### Do not trust a naive `[[maybe_unused]]` orphan audit

Tried a tree-wide regex sweep for genuinely-unreferenced `[[maybe_unused]]`
functions; it reported 9537 "symbols" and 7329 "orphans", which is nonsense -
the pattern captures type names and parameters, and substring counting matches
unrelated identifiers. If this audit is worth doing, drive it from the
callgraph index or a real parser, not a regex.

## Third instance, and the family-audit query that finds them (`aa0b492`)

`RRef::TryUpcast_CAniPose` (0x0054E230) and `TryUpcast_PositionHistory`
(0x0067FBA0) were the last two missing from the 35-member family - same cause
again: `CAniPoseTypeInfo.cpp` and `EntityAttachPositionReflection.cpp` each had
a file-private copy. Rewired both; the family is now 35/35. The PositionHistory
copy had also **lost a diagnostic** - it threw `BadRefCast("type error")` where
the binary passes the real source/target type names.

### The query that surfaces these

Group every named binary function by family key (`Class::` prefix, or the name
up to the last `_`), count how many members are in `src/sdk` vs not, and keep
families that are **mostly done with a handful missing**. Those stragglers are
where a private duplicate is hiding.

    # 268 families with >=3 recovered and 1-6 missing, as of 2026-08-14
    key = lab.rsplit('::',1)[0] if '::' in lab else lab.rsplit('_',1)[0]

Top hits worth working: `Moho::Unit` (83 done / 6 missing, incl. MotionTick
0x006A9010 and Materialize 0x006A9F40), `Moho::Sim` (88/6),
`LuaPlus::LuaObject` (63/6), `Moho::CFormationInstance` (17/6),
`Moho::MediumFidelityTerrain` (10/5).

### Caveat: `gpg::RPointerType_*` is NOT one of these

Six of those families show 3 done / 6 missing, but the missing members
(`SubscriptIndex`, `GetCount`, ...) are **generic implementations on
`RPointerTypeBase`** that dispatch through `GetPointeeType()`. The per-type
copies in the binary are template emissions the base already covers - writing
36 of them would recreate exactly the duplicate-helper problem. Check the base
class before treating a partial family as a gap.


## Fourth instance: `Unit::GetArmorMult` (`ac5cb22`)

`Unit:GetArmorMult(damageType)`'s Lua worker called `LookupArmorMultiplier`, a
file-private helper in `Unit.cpp`, so **`Unit::GetArmorMult` (0x006A9E10) had
never been written**. Recovered and the worker rewired; duplicate deleted.

Careful: it is NOT the same as `Unit::ProcessArmorOnDamage` (0x006A9D60), which
applies the multiplier to an amount. `GetArmorMult` returns the multiplier, and
yields 1.0 for a damage type the blueprint never listed.

## Remaining `Moho::Unit` gaps (from the family audit)

| token | instrs | note |
|---|---|---|
| FUN_006AA790 | 2 | `GetGuardFormation` - **zero xrefs**, needs callsite evidence first |
| FUN_006AA7A0 | 117 | `UpdateGuardFormation` - only caller is MotionTick (unrecovered) |
| FUN_006AAAC0 | 227 | `HandleResourceManagement` - 2 open callees |
| FUN_006A9010 | 241 | `MotionTick` - 18 open callees; plan in decomp/recovery/reports/unit-motion-tick-closure.md |
| FUN_006A9F40 | 289 | `Materialize` - closure 0, but only a **data xref with owner=None**, so confirm the vtable slot before writing |
| FUN_006ABCC0 | 465 | `Sync` - closure 1, same data-xref-only situation |

None of these is declared in `Unit.h` yet. `Materialize` and `Sync` are the
best value (closure 0/1) but both need the virtual-slot check from CLAUDE.md
"Virtual methods and inheritance" before any body is written.

## Family audit: a third outcome besides "gap" and "template emission"

`LuaPlus::LuaObject` reports 63 done / 6 missing, but the "missing" ones are
**unannotated overloads of bodies already in src**:

  - `0x00907D80` is the `PushStack(LuaState*)` overload at LuaObject.cpp:20081;
    the sibling `PushStack(lua_State*)` at :20062 carries `0x00907D10`.
  - `0x00907E50` is almost certainly `GetN` at :21320, which has no annotation.
  - `0x00907A30` sits next to `GetNumber` at :21628, annotated `0x00907970`.

So a partial family has **three** possible causes, and they need different
actions:
  1. genuine gap -> recover it (math, TryUpcast, GetArmorMult, Materialize);
  2. template emission the base already implements -> leave alone
     (`gpg::RPointerType_*`);
  3. **unannotated overload of an existing body -> add the `Address:` line, do
     NOT write a body.** Writing one here produces a duplicate symbol for an
     overload set, which is worse than the orphan it was meant to fix.

Confirm which overload each address belongs to (compare the decompile's
parameter type) before annotating - do not assign addresses by proximity.

## Sixth instance, and a whole vein of them: `*TypeInfo::AddBase_*` (`8810f4a`)

`CLuaTaskTypeInfo::AddBase_CTask` (0x004CB680) was missing because
`CLuaTaskTypeInfo::Init` registered its base through `AddCTaskBaseToTypeInfo`,
a file-private helper in the same TU. Recovered as the real member, `Init`
rewired, duplicate deleted.

**There are at least a dozen more exactly like it.** The clean-candidate query
(named, closure 0, caller-backed, non-CRT, 25-160 instrs) returns 86 hits and
the `*TypeInfo::AddBase_*` family dominates the small end - all 26 instructions,
all the same shape:

    DColPrimSphereTypeInfo::AddBase_CColPrimitiveBase   0x00500390  DONE 8e9d0e7
    DColPrimBoxTypeInfo::AddBase_CColPrimitiveBase      0x005004D0  DONE 8e9d0e7
    RBlueprintTypeInfo::AddBase_RObject                 0x0050E190  DONE 743f49d
    REffectBlueprintTypeInfo::AddBase_RObject           0x00510CF0  DONE 87be208
    RTrailBlueprintTypeInfo::AddBase_REffectBlueprint   0x00510E50  DONE 87be208
    REmitterBlueprintTypeInfo::AddBase_REffectBlueprint 0x00510EB0  DONE 87be208
    RBeamBlueprintTypeInfo::AddBase_REffectBlueprint    0x00510F90  DONE 87be208
    RRuleGameRulesImplTypeInfo::AddBase_RRuleGameRules  0x00533250  DONE 44c2ac7 (anno fix)
    CAniResourceSkelTypeInfo::AddBase_CAniSkel          0x00539B20  OPEN
    CAniDefaultSkelTypeInfo::AddBase_CAniSkel           0x0054DDF0  DONE 44c2ac7
    CAiFormationDBImplTypeInfo::AddBase_IAiFormationDB  0x0059DB80  OPEN
    IAiNavigatorTypeInfo::AddBase_Broadcaster_...       0x005A7B00  OPEN - **offset 4**
    CAiPathFinderTypeInfo::AddBase_IPathTraveler        0x005AB9F0  OPEN

Template to copy is `UnitTypeInfo::AddBase_Entity` (UnitTypeInfo.cpp:108).
The only per-case detail is **`mOffset`** - 0 for single inheritance, the
sub-object offset otherwise (Unit's Entity base is at 8). Take the offset from
the decompile's `memset(&field.mOffset, 0, 12)` (offset 0) or its explicit
store; do not assume 0.

Each one needs its TU's local `Add*BaseToTypeInfo` helper deleted and `Init`
rewired, same as this one - that is where the duplicate lives.


### Working the AddBase vein - the actual shape of the duplicate

It is NOT always a differently-named helper. Three variants seen so far:
  - `CLuaTask.cpp`: local `AddCTaskBaseToTypeInfo` (different name).
  - `CColPrimitive{Sphere,Box}3f.cpp`: a file-private **free function with the
    same name** as the member, in each TU - so `Init` already read as
    `AddBase_CColPrimitiveBase(this)` and looked correct. Two distinct binary
    members (one per type info) were being served by two free functions.
  - `RBlueprint.cpp`: local `AddRObjectBase`.

Mechanical recipe: declare `static void AddBase_X(gpg::RType*)` on the type
info next to its `Init()` decl, move the body across as a member (de-indent one
level - it was inside an anonymous namespace), annotate with the address, point
`Init` at it. Offset comes from the decompile: `memset(&field.mOffset, 0, 12)`
means 0.


### The offset check paid off, and a fourth duplicate variant

**`IAiNavigatorTypeInfo::AddBase_Broadcaster_*` (0x005A7B00) is `mOffset = 4`,
not 0** - the only non-zero one in the family so far. Every other member
decompiles to `memset(&field.mOffset, 0, 12)`; this one has an explicit
`a2.mOffset = 4`. Multiple inheritance. Had I batch-applied "offset 0" across
the family this would have been silently wrong.

Fourth variant of the duplicate, seen in `CAiPathFinderTypeInfo.cpp`: a
**generic parameterised** helper,
`AddBaseByTypeInfo(gpg::RType*, const std::type_info&, std::int32_t offset)`.
That one serves several bases from one body, so promoting it needs care - the
member per binary function still has to exist, but the generic helper may
legitimately stay for other uses.

Also found and fixed a **mis-cited address**:
`RRuleGameRulesImplTypeInfo::AddBase_RRuleGameRules` was annotated "Alias of
FUN_0052B640 (non-canonical helper lane)". 0x0052B640 is that type info's
`Init`. The member is 0x00533250 and the body was already correct - only the
annotation was wrong. Worth grepping for other "Alias of FUN_" comments.

Still open: `CAniResourceSkelTypeInfo` (0x00539B20) and
`CAiFormationDBImplTypeInfo` (0x0059DB80) - neither showed an obvious local
helper, so find how their `Init` registers the base before assuming a gap.

## REAL BUG found in the AddBase vein: IAiNavigator's base is never registered

**Not yet fixed.** `IAiNavigatorTypeInfo::Init` in
`src/sdk/moho/ai/IAiNavigatorTypeInfo.cpp:71` is:

    size_ = sizeof(IAiNavigator);
    gpg::RType::Init();
    Finish();

The binary's Init (FUN_005A31F0) is:

    this->mSize = 0xC;
    gpg::RType::Init();
    IAiNavigatorTypeInfo::AddBase_Broadcaster_EAiNavigatorEvent(this);
    this->Finish();

So **the base registration is missing entirely** - not just the helper
function. `IAiNavigator`'s reflected `Broadcaster<EAiNavigatorEvent>` base at
**offset 4** is never registered, so any reflected upcast from an IAiNavigator
RRef to its broadcaster base fails. This is the only member of the AddBase
family whose absence changes behaviour rather than just leaving an orphan.

`AddBase_Broadcaster_EAiNavigatorEvent` is FUN_005A7B00 and is the sole
**offset-4** member of the family - it caches into
`Broadcaster_EAiNavigatorEvent::sType` and looks up
`typeid(Broadcaster<enum EAiNavigatorEvent>)`.

**FIXED 2026-08-15 as `18997bb`, and my "needs a layout change" call was
WRONG.** `IAiNavigator` has no base *class* in our model, true - but it does
not need one. Measured: vptr at 0, `TDatListItem<void,void> mListenerNode` at
**+0x04**, `sizeof == 0xC` - identical to the binary. Our model just expresses
the broadcaster sub-object as a member instead of a base, so the reflected base
registers on the right bytes either way. It was a one-line registration after
all. The RType to use is the one registered under
`typeid(BroadcasterEventTag<EAiNavigatorEvent>)`, not `Broadcaster<...>`.

Lesson: before calling something "blocked on a layout change", measure the
layout. I deferred this for two batches on an assumption.

To finish it: find how to reach that RType from source. `IAiNavigator.cpp` has
an `RBroadcasterRType_EAiNavigatorEvent` class and a
`register_RBroadcasterRType_EAiNavigatorEvent()` (0x00BCC9A0) registrar; the
member needs whichever accessor those publish, then Init must call it. Also
worth confirming `sizeof(IAiNavigator) == 0xC` while there, since the binary
hard-codes 0xC.

**VEIN COMPLETE** except `IAiNavigator` (blocked on the missing base class -
see above). `CAiFormationDBImplTypeInfo::AddBase_IAiFormationDB` DONE `d830ae0`;
`CAiPathFinderTypeInfo` DONE `dc4f89a` - that one had **two** members, not one:
`AddBase_IPathTraveler` (0x005AB9F0, offset 0) and
`Addbase_Broadcaster_NavPath` (0x005ABA50, **offset 0x0C**, and note the
binary's own lowercase `b` - kept rather than tidied).

Lesson: check the family audit for *all* members of a type info before
assuming one missing AddBase means one base. The path finder registers two.

**Five shapes of this duplicate seen so far**, all needing the same fix but
found differently: differently-named helper (`AddCTaskBaseToTypeInfo`);
same-named file-private free function (the collision pair - the call site reads
correctly, which is what makes it sneaky); generic parameterised helper
(`AddBaseByTypeInfo`); shared cross-TU lane (`resource_reflection::AddBase`);
and **fully inlined into `Init`** (`CAiFormationDBImplTypeInfo`).
