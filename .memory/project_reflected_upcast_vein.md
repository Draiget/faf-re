---
name: project-reflected-upcast-vein
description: 58 per-type gpg::RRef::Upcast_* emissions were missing because the recovered archive readers open-coded REF_UpcastPtr inline. Landed 2026-08-17 in four commits; the discovery query generalizes to other elided-helper families.
metadata:
  type: project
---

**Landed 2026-08-17**: `7ca0fbf` (9), `331d310` (40), `1989336` (7 helpers / 8
readers), `29f8b16` (2). 58 functions total, all `tucheck EXITCODE=0`.

## The defect class

Every `gpg::ReadArchive::ReadPointerOwned_X` / `gpg::ReadPointerShared_X`
reader in the binary calls a **distinct per-type function**
`gpg::RRef::Upcast_X` (17 instructions: lazily resolve `X::sType`, call
`REF_UpcastPtr`, return `mObj`). The recovered readers instead open-coded that
sequence, so ~60 real functions had no source equivalent at all - the classic
elided-helper orphan, invisible to any address-presence sweep because the
readers themselves were annotated and recovered.

Two reader families, two different elisions:

  - `ReadArchive.cpp` readers: `const gpg::RRef upcast = gpg::REF_UpcastPtr(source, Cached<X>Type());`
    followed by `*outValue = static_cast<moho::X*>(upcast.mObj);`
    -> replaced by `*outValue = UpcastToX(source);`
  - `ArchiveSerialization.cpp` shared readers: a **generic** predicate
    `IsPointerCompatibleWithExpectedType(tracked, expectedType)` + `ThrowTypeMismatch`.
    The binary calls the per-type upcast and treats a null result as the
    mismatch -> replaced by building the `RRef` and testing
    `UpcastToX(source) == nullptr`. The generic predicate **stays** for every
    reader whose type has no separate emission.

## The discovery query (reusable)

    select token, listing_name from functions where listing_name like 'gpg::RRef::Upcast_%'

then drop anything already in the have-set, and keep those with a `kind='code'`
incoming xref whose owner is recovered. **Anchor each rewire to the specific
caller** by matching the helper's sole code xref against that caller's
`Address: 0x...` annotation in the source - several types have two readers
(owned and unowned) and only one is the emission's caller. Rewiring both would
invent a call site.

The same shape almost certainly exists for other tiny per-type reflection
emissions (`RRef_X` builders, `Cached*Type` lookups, tracked-pointer writers).
Query `listing_name like 'gpg::%_%'` for 10-25 instruction functions with a
recovered caller and check whether the caller open-codes the body.

## Traps hit (both cost a rebuild)

1. **Do not compute an insertion point by scanning for the next `  }`** - that
   matches an inner brace and drops the helpers *inside* a function body
   (`error C2601: local function definitions are illegal`). Brace-depth
   counting is also unreliable here because string literals in this file
   contain braces. The robust move is to insert a fresh `namespace { ... }`
   block immediately before a known file-scope definition (e.g. the first
   `void gpg::ReadPointerShared_`); multiple unnamed-namespace blocks in one TU
   share the same namespace, so the `Cached*Type` helpers stay reachable.
2. **Symbol spelling != our type spelling.** `Upcast_CCommandDB` ->
   `moho::CCommandDb`, `Upcast_EntityDB` -> `moho::CEntityDb`. Also
   `Upcast_CIntelGrid` and `Upcast_CIntelGrid2` are two emissions of the *same*
   upcast - give them one helper carrying both addresses rather than duplicate
   functions.
3. Cached-type lookups are not uniformly named - `CachedOwnedSPhysConstantsType`,
   `CachedPathQueueImplType`, `CachedCompatRType<moho::RScaResource>()`. A
   `Cached{Type}Type` pattern match silently misses those.

## Left alone deliberately

`Upcast_RUnitBlueprint` (0x00527AD0). `CUnitFerryTask::HasNewUnit` already
documents that the checked upcast was reduced to a `static_cast` because
factory build commands always carry unit blueprints, and it has three further
callers. Restoring the checked form should consider all four together.

Nine others have no separate emission for their type and correctly keep the
generic predicate.

## Sweep false positives: implemented but unannotated (2026-08-17)

The "unrecovered" test used everywhere in this repo is **address presence in
`src/sdk`**. That produces a real false-positive class: a function that is fully
implemented and correct, but whose Doxygen block never got the address, looks
exactly like a gap. Two found while working this vein and fixed in `fbc1c0b`:

    0x00523D00  gpg::RVectorType_float::SerSave    -> VectorFloatReflectionType::SerSave
                                                      (RUnitBlueprintNestedTypeInfo.cpp)
    0x0086D7E0  gpg::RType::AddBase_CScriptObject  -> debug_reflection::AddBaseCScriptObject
                                                      (RDebugOverlayReflectionHelpers.cpp)

**Before writing any body from a sweep result, grep the caller's file for the
behaviour**, not the address - the same check that caught the
`ComputeSupportPointAgainstDirection` duplicate earlier. Writing first and
checking second produces a duplicate sitting next to a working implementation.

Also seen in the same pool: IDA `listing_name` can be outright misleading.
`FUN_0053B2C0` is listed as `gpg::RRef_RScaResource::FinishType` but is really
`func_AtomicCopyRRef` (copy an `RRef`, bump the type's refcount) - a compiler
emission of the `RRef` copy ctor, not a resource-factory method. Read the `.c`
before trusting the name.

