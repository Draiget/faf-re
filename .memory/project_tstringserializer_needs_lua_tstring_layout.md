---
name: project_tstringserializer_needs_lua_tstring_layout
description: TStringSerializer (register_TStringSerializer FUN_00BEA270) turned out to need a real Lua TString struct layout recovery, not a quick citation. Deferred deliberately given this project's documented Lua-fork-layout landmine history. Full research trail below so a future pass can execute directly.
metadata:
  type: project
---

## How this was found

Started from the DAG's "highest leverage" list looking for a second quick
citation win after landing `FUN_0087B5B0` (see commit `d5d2c0f9`). Traced
`register_TStringSerializer` (`FUN_00BEA270`, real address `0x00BEA270`) —
DB status `recovered` but that turned out to be about the two callback
bodies only (`TStringSerializerDeserializeNoOp`/`SerializeNoOp`, already in
`src/sdk/gpg/core/reflection/RStringType.cpp`); the CONSTRUCTOR/global-
instance that actually wires them up was never written, so those two
NoOp bodies are currently orphans (zero callers in `src/sdk`).

## What the ctor's real asm shows (`0x00BEA270`-`0x00BEA2A4`)

```
mov ecx, offset TStringSerializer            ; this = 0x00F8E934
call gpg::SerHelperBase::SerHelperBase()     ; base ctor
push offset TStringSerializer::~TStringSerializer   ; atexit target, 0x00C09A60
mov [this+0x0C], offset TStringSerializerDeserializeNoOp
mov [this+0x10], offset TStringSerializerSerializeNoOp
mov [this+0x00], offset TStringSerializer::vftable  ; 0x00D46A60
call _atexit
```

This is the standard `SerHelperBase`-derived global-singleton shape
already established for `RResIdSerializer`
(`src/sdk/moho/resource/RResIdSerializer.{h,cpp}` — use as the template).

## The RTTI ancestry (real, not a guess)

`dumps/rtti_dump_all.hpp:75892-75901`:

```
TStringSerializer : public _AU_SerSaveLoadHelper_UTString_gpg_,
                     public gpg::SerHelperBase,
                     public _AV_DListItem_USerHelperBase_gpg_X_gpg_,
                     public boost::noncopyable_::noncopyable
```

i.e. the REAL inheritance is `TStringSerializer : public
gpg::SerSaveLoadHelper<TString>` (the other listed bases are
`SerSaveLoadHelper<T>`'s own bases, restated by the RTTI dumper — normal
for this dump format, see the `Rect2iSerializer` precedent already
documented at `Reflection.h:4561-4580`). `vftable@0xD46A60 slots=1` (only
`Init()` is virtual, matching `SerHelperBase`).

## The gap: `Init()` does NOT match the currently-recovered generic template

Vtable slot 0 (read directly from the PE, `0x00D46A60` -> `0x0091FA30`)
is SHARED between `TStringSerializer::vftable` and `gpg::
SerSaveLoadHelper<TString>::vftable` — confirming `TStringSerializer`
does NOT override `Init()` itself; it uses the template's own `Init()`
as-is. `FUN_0091FA30` is ALSO marked `recovered` in the DB but has
**zero citation anywhere in `src/sdk`** — a second orphan/fake-recovered
token in this same small cluster.

Read `FUN_0091FA30`'s raw asm directly
(`decomp/recovery/disasm/fa_full_2026_03_26/FUN_0091FA30.asm`). It caches
the looked-up `RType*` into a symbol IDA names `lua__TString__sType`, and
asserts `!type->mSerLoadFunc`/`!type->mSerSaveFunc` before installing
`[this+0x0C]`/`[this+0x10]` (same offsets confirmed on `TStringSerializer`
above) — otherwise identical in shape to the ALREADY-recovered generic
`SerSaveLoadHelper<T>::Init()` at `Reflection.h:4704-4719`, which reads:

```cpp
void Init() override
{
  if (T::sType == nullptr) {
    T::sType = LookupRType(typeid(T));
  }
  ...
  T::sType->serLoadFunc_ = mLoadCallback;
  T::sType->serSaveFunc_ = mSaveCallback;
}
```

**The template assumes `T::sType` is a static member the target type `T`
itself already declares** (confirmed true for `BVIntSet`/`CAniPose`, per
the template's own Doxygen block). For `T=TString` this only compiles to
the SAME shape if Lua's `TString` struct genuinely has a `static gpg::
RType* sType;` member of its own — matching the "lua__TString__sType"
naming (very plausibly IDA's own flattened rendering of a real
`TString::sType` static member symbol it couldn't fully demangle, not
evidence of some separate free-standing global).

## Why this isn't a quick citation after all

**`TString` (Lua's own interned-string struct, `lobject.h` in real Lua)
has NO full definition anywhere in `src/sdk` yet** — checked exhaustively
(`grep -rn "struct TString"` across the whole tree; the only hit is the
bare forward declaration in `src/sdk/lua/LuaStateSaveConstruct.h:10`,
grouped with `LClosure`/`UpVal`/`Proto`/`Table`/`Udata`/`lua_State` —
genuine Lua VM internal types, confirming this IS Lua's TString, not some
unrelated engine type of the same name). So landing this properly means:

1. Recovering `TString`'s real struct layout from this project's OWN Lua
   fork (NOT assumed from stock Lua 5.0 — this project's Lua has
   confirmed, documented deltas from stock in at least one other struct,
   see [[project_lua_table_layout_bug]] — "wrong Table offsets; game Lua
   ≠ stock+2"). Cross-check against `Proto`'s already-recovered, asm-
   verified layout (`LuaObject.cpp`, offsets confirmed via `traverseproto`/
   `luaF_freeproto` this session, see
   [[project_commander_spawn_goal_synthesis_2026_09_02]]'s wild-free-sweep
   trail) as a sibling example of how Lua-internal structs get modeled
   faithfully in this codebase.
2. Adding the `static gpg::RType* sType;` member this project's fork adds
   on top of stock Lua's `TString` (find the write site — should be a
   simple, low-risk, additive static-member declaration once TString's
   base layout is confirmed).
3. Writing `TStringSerializer` itself (trivial once the above lands —
   directly mirrors `RResIdSerializer.{h,cpp}`'s shape almost verbatim,
   just deriving from `gpg::SerSaveLoadHelper<TString>` instead of
   `gpg::SerHelperBase` directly, with an EMPTY derived class per the
   `CEfxTrailEmitterSerializer`/`CUnitTeleportTaskSerializer` "two-
   distinct-adjacent-vtables" precedent already documented at
   `Reflection.h:4588-4650` — do NOT skip the "does this T need an empty
   derived class or a `using` alias" check that section describes).
4. Citing `FUN_0091FA30` on the generic template `Init()` (it's already a
   valid instantiation of the CURRENT template body, once `TString::sType`
   genuinely exists — likely just needs the citation added, no template
   changes).
5. Citing `FUN_0087A080`-equivalent... no wait, wrong token — citing
   `FUN_00C09A60` (currently `skip`) on an explicit `~TStringSerializer()
   { ResetLinks(); }`, matching `RResIdSerializer`'s exact destructor
   shape (safe to upgrade skip -> recovered once the class exists, per
   this project's own "clearing a block/reclassifying toward more
   evidence is always welcome" convention).

## Why not fixed this pass

Lua-internal struct layout work has a documented history of real bugs in
this project when rushed (`project_lua_table_layout_bug.md`, "Lua GC
crash" family in this same session's own commander-spawn investigation
trail) — `TString` is fundamental to every Lua string in the engine, so
an under-verified layout here has a large blast radius. This deserves a
dedicated, unhurried pass with the SAME register-trace rigor this session
applied to the RB-tree migrations and the heap-corruption sweep, not a
squeeze-in alongside other concurrent work. Landing `FUN_0087B5B0`'s
citation (commit `d5d2c0f9`, unrelated, unlocked file, zero layout risk)
was the right-sized win for this pass; this one is not.

## Next step if resuming

Start at step 1 above: find/confirm this project's own Lua fork's real
`TString` layout via raw `.asm` register-tracing of Lua-internal functions
that already touch `TString` fields (grep `LuaObject.cpp` for anywhere a
`TString*` gets dereferenced — `luaS_newlstr`, `newlstr`, string-hashing/
interning code, all already read and verified clean earlier this session
per [[project_commander_spawn_goal_synthesis_2026_09_02]]'s "Lua GC
upvalue corruption" investigation, so those functions are a good, already-
trusted starting point for the offsets). Do NOT assume stock Lua 5.0's
`TString`/`TObject` layout without independently confirming against this
fork's own `.asm`.
