---
name: project-units-build-again
description: Sim::CreateUnit no longer returns nullptr - the Unit gameplay ctor is recovered and the ACU builds. Records the four latent defects it exposed and the next blocker, which is that engine Lua method tables have no base chain.
metadata:
  type: project
---

Supersedes the "no unit can be created" state in
[[project-no-unit-can-be-created]] - the ctor is landed. 2026-08-13.

## Landed

| commit | what |
|---|---|
| `3899d2c` | Fallback mesh/texture existence goes through the VFS, not `std::filesystem`. `Failed to load mesh` 5298 -> **0**. |
| `5c3d662` | `Unit::Unit(const SUnitConstructionParams&)` (0x006A53F0) + `CUnitMotion(Unit*)` (0x006B7B60) + `CAiAttackerImpl(Unit*)` (0x005D6AA0) + `AI_CreateAttacker` (0x005D62B0). |
| `49804e3` | `REntityBlueprint` is polymorphic, so a blueprint can say what kind it is. |

The ACU now builds: the log shows `uel0001` constructed with its six
weapons, and `SetArmyStart() failed` is gone.

## Four latent defects it exposed, all invisible until units existed

- **`Unit::GetBlueprint` returned null for every unit.** It goes through
  the blueprint's virtual `IsUnitBlueprint`, but `REntityBlueprint`
  modelled its vtable word as an opaque `void* mVTable` nothing ever
  filled in, so the call bound statically to the base's "no".
- **`ResolveBlueprintScriptFactory` was guessing** the blueprint kind from
  substrings of the script module/class names. `uel0001` matched none, so
  "Can't tell the type of blueprint id" and every `GetWeaponClass` on the
  ACU returned nil. 0x00677360 asks the reflection system to upcast
  (`REF_UpcastPtr` vs `RUnitBlueprint::sType2`); `dynamic_cast` is the
  same question, and needs the vptr above.
- **`CScriptObject::CreateLuaObject` called `GetActiveState()` before its
  null check.** That accessor walks `m_state->m_state->l_G->lstate` with
  no checks. 0x004C70D0 reads `m_state` directly and puts the body behind
  it. `UnitWeapon` passes an unbound LuaObject, as the binary does.
- **`msvc8::list` had a destructor but no copy operations**, so the
  implicit ones shallow-copied the sentinel node and two lists freed it.
  `ARMOR_GetArmorDefinations` returns one by value. Now has real copy and
  move operations.

## The `/FORCE` trap - read this before chasing any wild jump

The link uses `/FORCE`, so an **unresolved symbol still links** and its
call site jumps to whatever symbol happened to land there. That is what
"execute at address 00D80000 / `main!wxRED_PEN+0x0`" means: not a
corrupted pointer, a missing definition. It cost two debugging rounds
here - `AI_CreateAttacker` was defined at global scope in a file that
uses `using namespace moho;`, so `moho::AI_CreateAttacker` was never
defined.

**After adding any new cross-TU symbol, diff the build's LNK2019/LNK2001
list against the baseline (17 entries as of this note).** A new one is a
bug, not noise.

`dbgrun` now prints the call site for execute-type AVs (`[call site]
returns to ...` plus the 24 bytes before the return address), which is
what identified it - see [[reference-dbgrun-crash-harness]].

## Next blocker: engine Lua classes have no base chain

`InitializeArmies` still dies at the first army, now on
`unit.lua:3417: attempt to call method 'DisableIntel' (a nil value)`.

`DisableIntel` is registered **once**, on the `Entity` metatable
(0x0068E310) - the image has exactly one binder for that name. `Unit` is
declared `ClassUnit(moho.unit_methods, ...)`, so `moho.unit_methods` has
to expose it, and FA's `class.lua` `ConvertCClassToLuaSimplifiedClass`
flattens a C class by walking its metatable chain.

Ours has no chain to walk: `CScrLuaMetatableFactory<T>::Create` returns
`SCR_CreateSimpleMetatable`, a flat table with `__index = self`, and the
binary's `CScrLuaMetatableFactory<Unit>::Create` (FUN_005E9CA0) does the
same. Neither `CScrLuaBinder::Run` (0x004CD3A0) nor
`CScrLuaClassBinder::Run` (0x004CD460) links a base. So something else
walks the reflection base list and joins the metatables - find it. This
very likely also explains the UI-side `Show` failure recorded in
[[project-no-unit-can-be-created]], which is the same shape one layer up.

Also open, same run: `Invalid bone index of 0; must be between 0
(inclusive) and 0 (exclusive)` from `scenarioutilities.lua:400`, i.e. the
ACU's skeleton has no bones - the `.scm` now loads but
`RScmResource::GetSkeleton` yields nothing.
