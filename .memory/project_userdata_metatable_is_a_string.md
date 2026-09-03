---
name: project-userdata-metatable-is-a-string
description: Open blocker after 7f6bc1d. The sim now ticks, then dies in luaH_getstr because a Udata's metatable field points at a TString. Records the confirmed layout/tags from the binary and the probe that isolates it.
metadata:
  type: project
---

Open as of 2026-08-14, immediately after commit 7f6bc1d fixed the
`UnitAttributes` bogus-free (see
[[project-lua-gc-string-table-corruption]]). That fix removed the heap
corruption entirely, and the sim now gets **past `Sim::Setup` and ticks**
(`Sim::AdvanceBeat` -> `TickTaskStage` -> `CLuaTask::Execute` ->
`lua_resume`) before hitting this.

## The crash

Deterministic AV in `luaH_getstr` reading `0x6C6C6163` - which is the ASCII
`"call"`. Reached by:

    luaV_execute -> CallBinTmOrRaiseArithmeticTypeError -> call_binTM
                 -> luaT_gettmbyobj -> luaH_getstr

i.e. Lua doing arithmetic on a non-number and looking for the metamethod.

`luaT_gettmbyobj` takes the **userdata** branch. Dumping the metatable
pointer shows it is a `TString`, not a `Table`:

    next  = 00000000
    tt    = 04            <- LUA_TSTRING
    hash  = e6074c39
    len   = 0000002a      <- 42
    str   = "call expected..."

So a live `Udata`'s `metatable` field (+0x08) holds a pointer to an error
message string. Several distinct userdata objects shared the same bad
pointer, so it is one corrupting write reused, not random garbage.

## Confirmed against the binary - do not re-derive

`luaT_gettmbyobj` is FUN_00928450; the disassembly settles all of this:

    cmp eax, 5   -> mov edx,[esi+4]; mov eax,[edx+0Ch]  ; Table metatable @ +0x0C
    cmp eax, 8   -> mov eax,[esi+4]; mov ecx,[eax+8]    ; Udata  metatable @ +0x08
    default      -> lea eax,[ecx+eax*8+0D4h]            ; _defaultmetatypes @ G+0xD4, stride 8

- This fork's tags are shifted by one from stock 5.0:
  `LUA_TTABLE 5`, `LUA_TFUNCTION 7`, `LUA_TUSERDATA 8`, `LUA_TTHREAD 9`.
  `LuaPrimitives.h` already matches, and so does the `switch`.
- `Table::metatable` at +0x0C and `Udata::metatable` at +0x08 in
  `LuaRuntimeTypes.h` **both match the binary**. The layout is not the bug.
- `object->tt` is at offset 0 of the `TObject` and `value.p` at +4.

## Ruled out

- Anything freeing a Lua-owned block prematurely. A probe that set an "owned"
  bit in `luaM_realloc` (set on alloc, cleared *before* `reallocFunc`/`freeFunc`)
  and checked it at the single engine `free()` choke point reported **zero**
  hits. Clearing the bit *after* the call gives ~24 false positives from
  `realloc_0` freeing the old block internally - clear it before.
- The `UnitAttributes` alias-then-delete bug (fixed, 7f6bc1d).

## Round 2 findings (2026-08-14, same session)

More things now proven, so the next pass starts from here:

- **The crash is deterministic and reproduces on a clean tree at 7f6bc1d.**
  `luaH_getstr` reading `0x6C6C6163`, always the userdata branch
  (`LuaObject.cpp:3489`).
- **`luaS_newudata` is faithful.** FUN_00924A10 does
  `mov edx,[ecx+118h]` / `mov [esi+8],edx` (metatable) and uses G+0x14 for
  `rootudata`. All three creators in our source
  (`CreateDefaultConstructedUserdata`, `CreateRefUserdata`, the `newproxy`
  branch of `lua_newuserdata_ref`) set the metatable from that same slot.
- **G+0x118 is `_defaultmetatypes[LUA_TUSERDATA].value`**, because
  `LuaPlus::TObject` is `{int tt; Value value;}` (tt first - confirmed by
  `luaT_gettmbyobj` reading `[esi]` for tt and `[esi+4]` for the pointer).
  `_defaultmetatypes` is at G+0xD4, stride 8. Our `global_State` models all
  of this correctly.
- **Nothing writes that slot after init.** A DR0 write-watch on
  `&_defaultmetatypes[8].value` caught exactly two writes, both from
  `f_luaopen`'s own init loop (`nullptr`, then the fresh table). *Caveat:
  the watch only covered the thread/state armed last - there are several
  states, so the sim state's slot was not necessarily the one watched. Arm
  per state before trusting this.*
- **`lua_setmetatable` is faithful.** FUN_0090D340 also stores
  `metatable->value.p` with no table check (nil falls back to
  `_defaultmeta` at G+0x38). So a string on the stack would corrupt the
  field in the original too - meaning the original never gets there.
- **`markroot` does mark `_defaultmetatypes`,** and
  `reallymarkobject` case 3 (tt-LUA_TTABLE==3, i.e. userdata) does mark
  `u.metatable`. Neither is missing.
- **The `_defaultmetatypes` tables are not prematurely collected.** A probe
  recording them at `f_luaopen` and checking `freeobj` reported only frees
  where no live slot still referenced the table - all from `lua_close` of
  the temporary state in `DISK_SetupDataAndSearchPaths`. Filter on
  "still referenced by a slot" or this probe is pure noise.
- **The `Udata` looks genuine**, not a stale stack read: its header shows
  `tt`=8 and a plausible `marked`, and several *different* userdata share
  the same bad metatable pointer - so they got it at creation from a slot
  that held a `TString` at that moment.

That last point and the watch caveat are the contradiction to resolve: arm
the watch per `global_State` (the probe overwrites DR0 each call, so only
the last-armed slot is covered) and catch the write on the sim's state.

Also note: probes perturb which blocker surfaces. With the userdata branch
guarded, a run got as far as calling `wxCYAN_PEN` - one of the 17 unresolved
`/FORCE` symbols - which is a genuinely later blocker. Always re-baseline on
a clean tree before concluding a blocker moved.

## Round 3 - THE WRITER IS IDENTIFIED (2026-08-14)

Bisected with two probes in one run: validate the slot at *creation*
(`DefaultUserdataMetatable`) and at *use* (`luaT_gettmbyobj`).

- `CREATEBAD` fired **0 times** - the slot is valid when the userdata is
  built, and `USEBAD` shows `slotNow` still valid (`tt`=5) at crash time.
- `USEBAD` fired 16 times with `ud->tt`=8 (a genuine userdata) and a
  metatable that is **neither the creation-time value nor the current slot**.

So `ud->metatable` is overwritten after creation. Instrumenting both writers
named it immediately:

    AssignMetatableByTaggedValueType   (LuaObject.cpp:20643)
      <- LuaPlus::LuaObject::SetMetaTable
      <- moho::func_NewEntityCategory  (EntityCategoryReflection.cpp:379)
      <- moho::cfunc_EntityCategory__addL
      <- moho::cfunc_EntityCategory__add

`func_NewEntityCategory` (FUN_00533150) does:

    LuaObject metatable = EntityCategoryLuaMetatableFactory::Instance().Get(state);
    out->AssignNewUserData(state, categoryRef);
    out->SetMetaTable(metatable);          // <- stores a NON-TABLE

`AssignMetatableByTaggedValueType` stores the pointer with no tag check, and
so does the binary (FUN_0090D340 `lua_setmetatable` likewise) - so the
writers are faithful. **The defect is that the factory returns a non-table.**

Which closes the loop on the crash: `EntityCategory + EntityCategory` builds
a userdata with a junk metatable, and the *next* `__add` on it goes
`CallBinTmOrRaiseArithmeticTypeError -> call_binTM -> luaT_gettmbyobj ->
luaH_getstr(junk)` and dies.

### Where to look next (start here)

`CScrLuaObjectFactory::Get` (CScrLuaObjectFactory.cpp:1360, FUN_004CCE70)
memoises one object per `mFactoryObjectIndex` in the per-state
`__factory_objects` table. Prime suspect is the **index**, not `Get`:

- `mFactoryObjectIndex` comes from `AllocateFactoryObjectIndex()`
  (`++sNumIds`), assigned when the function-local `Instance()` static is
  first constructed - so it depends on runtime call order.
- `startup_EntityCategoryLuaMetatableFactory_Index()` (FUN_00537070) then
  calls `SetFactoryObjectIndexForRecovery(AllocateFactoryObjectIndex())`,
  **allocating a second index and overwriting the first**. If that runs
  after anything cached an object under the old index, this factory starts
  reading whatever *other* factory owns the new index - which is exactly
  "the metatable is some unrelated object".
- That startup function is `[[maybe_unused]]`, i.e. an orphan helper by
  CLAUDE.md's rule. Establish whether it is actually invoked, and from
  where, before changing anything.

Verify by logging `(factory, mFactoryObjectIndex)` for every factory and
checking for duplicate indices, and by dumping the `tt` of what `Get`
returns for the entity-category factory.

## Next step

Find who writes the `Udata` `metatable` slot. The cheap, decisive probe is
the same shape that cracked the last one: guard the userdata branch of
`luaT_gettmbyobj` with
`meta == nullptr || (uintptr & 3) || meta->tt != LUA_TTABLE`, return
`&luaO_nilobject` on failure (this makes the game run further, so it is also
a usable stopgap), and log the owning `Udata` address. Then put a hardware
write watchpoint (DR0 + `AddVectoredExceptionHandler`, recipe in
[[project-lua-gc-string-table-corruption]]) on `&ud->metatable` for one of
the reported objects and catch the writer.

Suspect worth checking first: whatever constructs these userdata. This fork's
userdata header carries an RRef - see [[project-userdata-ref-and-ui-typeinfos]] -
so a constructor writing the RRef at the wrong offset would land exactly on
+0x08.

Note: after guarding the userdata branch the run gets further still and then
faults with a null deref in
`std::_Tree<...Wm3::Vector2<int>, moho::SBuildReserveInfo...>::begin`, which
is a separate, later blocker.
