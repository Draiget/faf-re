---
name: project-moho-class-exports-10-missing
description: CLOSED 2026-09-01 — ROOT CAUSE of the commander-spawn failure. Engine exports 56 `moho.*` Lua class tables, we published 46. All 10 missing names now accounted for: 5 fixed (IEffect runtime-verified; AnimationManipulator/CollisionBeamEntity/userDecal_methods/PathDebugger_methods built-clean, not yet runtime-proven), 5 confirmed zero/annotation-only impact. Two of the "annotation-only" ones were actually real bugs on first pass — read past the ---@class line, don't stop at the first grep hit.
metadata:
  type: project
---

# 10 of the engine's 56 `moho.*` class exports are not published

This is the mechanism behind
[[project_commander_spawn_initializearmies_nil_binding]] and, through it, the
commander not spawning.

## How the export works

`globalinit.lua:45` — `for name, cclass in moho do
ConvertCClassToLuaSimplifiedClass(cclass, name) end` — calls `moho` "a list of
exported methods and base classes" built by the engine.

The engine builds it with `CScrLuaClassBinder` (`moho/lua/CScrLuaClassBinder.cpp`).
Its `Run` splits a dotted name, creates the namespace tables, and assigns the
class's method table:

    scope.SetObject(lastSegment, mClassFactory->Get(state));

so `moho.IEffect` *is* the `CScrLuaMetatableFactory<IEffect>` table — the very
table the method binders register into. Existing example
(`ManipulatorStartupRegistrations.cpp:585`):

    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.AimManipulator",
      &CScrLuaMetatableFactory<CAimManipulator>::Instance(),
      "CAimManipulator", "");

## The gap, enumerated

**Count carefully: a `"moho\.[A-Za-z]+"` regex is WRONG** — it silently drops
every `_methods` name and made this look like a 43-class hole on the first
pass. Use `[A-Za-z_][A-Za-z0-9_]*`.

`src/sdk` publishes **46**. The shipped binary
(`G:/tmp/ForgedAlliance.exe`) contains **56**, extracted with
`re.finditer(rb'moho\.[A-Za-z_][A-Za-z0-9_]{1,40}', data)`.

**10 are missing:**

    moho.AnimationManipulator      moho.CAiAttackerImpl_methods
    moho.CDamage                   moho.CDecalHandle
    moho.CollisionBeamEntity       moho.EconomyEvent
    moho.EntityCategory            moho.IEffect
    moho.PathDebugger_methods      moho.userDecal_methods

Every Lua site doing `moho.<Class>.<Method>` against a missing class reads nil,
and the ones that capture such a method into an upvalue at module load — the
common FAF performance idiom — fail later at call time with
"attempt to call upval '<X>' (a nil value)", exactly the observed error.

### The IEffect record, located

`moho.IEffect` is at file offset 0xA25EF4 = **VA 0x00E25EF4** (`.rdata`;
image base 0x400000, and for this image `.rdata`'s raw offset equals its RVA).
Exactly one pointer to it exists in the file, at **VA 0x00F59EE8** — the
class-binder record, in the same table region as the already-recovered binders
(annotated e.g. "record at 0x00F59A38"). Its neighbouring fields read:

    name  0x00E25EF4 -> "moho.IEffect"
    group 0x00E25EEC -> "IEffect"
    help  0x00E00779 -> ""

which is the `CScrLuaClassBinder(set, "moho.IEffect", &factory, "IEffect", "")`
shape. Use the same technique for the other nine: find the string, find the
single pointer to it, read the adjacent fields.

## Why the string search had to be done against the file

A `string_refs` query over the callgraph index finds no `moho.` class names,
because that table only indexes strings referenced from **code**. These names
are referenced from static class-binder **data records** (the existing binders
are annotated e.g. "record at 0x00F59A38"). Search the PE bytes directly.

## Fixing one

`dfa833f7` already corrected a prerequisite: the seven `IEffect` method binders
were passing `nullptr` as the owner factory, so they published as globals
instead of into `CScrLuaMetatableFactory<IEffect>`'s table. That fix alone does
not clear the symptom — without the class binder, that table is never named
`moho.IEffect`. Both halves are needed.

Note the naming split in the export list: some are class names
(`moho.IEffect`), most are `<lowercase>_methods` tables. Match the binary's
spelling exactly; `globalinit.lua` iterates whatever keys exist.

## Which of the remaining nine actually bite

Most gamedata references are LuaLS annotations (`---@field`, `---@alias`,
`---@class`) and are inert. Two are executable and will fail the same way
IEffect did:

- **`moho.AnimationManipulator`** — referenced in 14 files, and
  `sim/units/cybran/CAirFactoryUnit.lua:35-36` does the load-time upvalue
  capture that is the failure mode here:
  `local AnimatorPlayAnim = moho.AnimationManipulator.PlayAnim`. Highest
  priority of the nine.
- **`moho.CollisionBeamEntity`** — `sim/CollisionBeam.lua:34` does
  `CollisionBeam = Class(moho.CollisionBeamEntity) {`, a load-time base-class
  reference, so a nil there fails the whole module rather than one call.

`moho.CDamage` and `moho.CDecalHandle` have zero gamedata references at all.
`EntityCategory`, `EconomyEvent`, `userDecal_methods`, `PathDebugger_methods`
and `CAiAttackerImpl_methods` appear once each, annotation-only on inspection —
worth re-checking before spending a pass on them.

## All 10 accounted for — CLOSED 2026-09-01

**5 of 10 fixed** (same recipe throughout: pefile string search -> single
in-image pointer -> decode the 6-dword `CScrLuaClassBinder` record ->
confirm name/group/help -> add `register_moho_<Name>_ClassBinder()` next to
the class's existing method binders -> wire into the same bootstrap
constructor):

- **`moho.IEffect`** — commit `f36336a0`, `faf-main-2c`.
  **Runtime-verified**: army init now completes past `InitializeArmies`.
- **`moho.AnimationManipulator`** — commit `5e96bdcb`, `faf-main-f7`,
  `moho/sim/ManipulatorStartupRegistrations.cpp`. Record VA 0x00F59B50.
  `CAnimationManipulator` already had its base-class-flattening
  registration — only the export itself was missing.
- **`moho.CollisionBeamEntity`** — commit `b171ae1f`, `faf-main-f7`,
  `moho/entity/CollisionBeamEntityLuaFunctionThunks.cpp`. Record VA
  0x00F59F1C. Method binders already correctly targeted the factory (no
  `dfa833f7`-style nullptr bug here), only the export was missing.
- **`moho.userDecal_methods`** — commit `5d52f7fc`, `faf-main-f7`,
  `moho/script/ScriptedDecal.cpp`. Record VA 0x00F5B6B8, group=
  "ScriptedDecal" (the Lua export name doesn't have to match the C++ class
  name — same as `moho.manipulator_methods` naming `IAniManipulator`).
  **Was wrongly bucketed "annotation-only" in the first pass of this file** —
  it's a real `Class(moho.userDecal_methods) { ... }` statement at
  `UserDecal.lua:3`, one line below a `---@class` comment that made a quick
  `grep -B1` look annotation-only. Caught only by reading past the
  annotation line.
- **`moho.PathDebugger_methods`** — commit `e018cff3`, `faf-main-f7`,
  `moho/debug/CPathDebugger.cpp`. Record VA 0x00F5A72C, group=
  "CPathDebugger". Same "wrongly bucketed annotation-only" mistake as
  userDecal_methods — `PathDebugger.lua:237` is `PathDebugger =
  Class(moho.PathDebugger_methods) { ... }`, real code, one line below its
  own `---@class` comment. **Lesson for next time: `---@field X moho.Y` is
  always inert (LuaLS field-type annotation, never executes) but
  `---@class X : moho.Y` is frequently followed immediately by a REAL
  `Class(moho.Y) { ... }` statement on the very next line — always read past
  the annotation line, don't stop at the first grep hit.**

4 of these 5 (all but IEffect) are **not yet runtime-verified** — no live
dbgrun access at write time. `faf-main-2c` reported after `5e96bdcb`/
`b171ae1f` landed: "in the binary I just ran, no new Lua nil-faults
appeared... but I can't positively confirm AnimatorPlayAnim/CollisionBeam's
module load exercised their paths in this run" — built-and-ran-clean, not
path-proven. `userDecal_methods`/`PathDebugger_methods` landed after that
report, fully unverified.

**5 of 10 confirmed zero real-world impact, correctly left alone:**
- `moho.CAiAttackerImpl_methods`, `moho.EntityCategory`,
  `moho.EconomyEvent` — confirmed genuinely annotation-only
  (`---@field`/`---@class` comments with no accompanying `Class(moho.X){}`
  statement anywhere in `gamedata/lua/**`). Verified by reading past every
  hit, not just grepping.
- `moho.CDamage`, `moho.CDecalHandle` — confirmed **zero** references of
  any kind (annotation or executable) anywhere in `gamedata/lua/**`.

No further action needed on this file's own investigation — every one of
the original 56-vs-46 gap's 10 names has a settled, evidenced disposition.
