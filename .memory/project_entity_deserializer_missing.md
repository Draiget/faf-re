---
name: project-entity-deserializer-missing
description: Entity - the base class of every entity - can be serialized but not deserialized. Entity::MemberDeserialize, EntitySerializer::Deserialize and register_EntitySerializer are all absent from src.
metadata:
  type: project
---

**`Entity` can be saved but not loaded.** The save side is present; the entire
load side is missing. Since `Entity` is the base of every entity in the game,
this is the most central instance of the one-sided-serializer class found so far
(cf. [[project-reflection-serializer-vein-verified]]).

| Piece | Address | Instrs | State |
|---|---|---|---|
| `Entity::MemberDeserialize` | 0x00681220 (`sub_681220`) | 384 | **ABSENT** |
| `EntitySerializer::Deserialize` | 0x0067B630 | 6 | **ABSENT** |
| `register_EntitySerializer` | 0x00BD5050 | 9 | **ABSENT** |
| `EntitySerializer::Serialize` | 0x0067B640 | 6 | present, `Entity.cpp` |
| `Entity::MemberSerialize` | - | - | present |

`Entity::MemberDeserialize` has **closure = 1** - no unrecovered callees at all,
so it is pure transcription once the lanes are read off.

## Why the earlier sweeps missed it

1. The `MemberSerialize`/`MemberDeserialize` pair sweep keys off IDA's
   `listing_name`, and this one is only ever called `sub_681220` - IDA never
   named it. **Match on the caller (`EntitySerializer::Deserialize`) rather than
   on the callee's name.**
2. `FUN_00680790` is a 1-instruction thunk into it that *is* annotated in
   `Projectile.cpp` as one of several addresses on
   `Projectile::MemberDeserialize`, so an address-presence check on the thunk
   looks satisfied while the real body is absent.

## How to land it

Model on the formation serializer landed this run (`de0fe86`, `3fd7b4a`) - same
shape, same idioms:
  - `EntitySerializer` helper struct follows `CAiBrainSerializer`
    (`moho/ai/CAiBrainSerializer.{h,cpp}`): node links +0x04/+0x08,
    `mLoadCallback` +0x0C, `mSaveCallback` +0x10, size 0x14.
  - `Entity::MemberDeserialize` mirrors the existing `Entity::MemberSerialize`
    lane for lane; read `sub_681220`'s `.c` and pair each `Read` against the
    matching `Write`.
  - `InstallEntitySerializerCallbacks` already exists at `Entity.cpp:170` and
    already caches into `Entity::sType` correctly - do not duplicate it.

## Wider lesson for target selection

A sweep filtered to demangled `Moho::`/`gpg::` names reported the frontier as
drained (5 candidates). Dropping that filter and allowing `sub_*` names returned
**151** candidates at closure <= 1 with a recovered caller, in the 60-700
instruction band. **Do not filter candidate sweeps on having a demangled name** -
the unnamed ones are where the real gaps are.

## Working the 151-candidate list (2026-08-17 experience)

The wide sweep is right that ~151 candidates exist, but they are dense with
three kinds of non-target. **Check in this order before writing a line:**

1. **Is it already implemented under an intent-first name?** Grep the *caller's
   file* for the behaviour, not the address. `sub_4752F0` was already
   `ComputeSupportPointAgainstDirection` in the same file (annotated in
   bc9840d); I had a full duplicate written and compiling before the
   caller-wiring step caught it. Writing first and checking the caller second is
   the wrong order.
2. **Is the caller a real body?** `sub_85E0A0`'s caller
   `CWldSession::RenderStrategicIcons` is a comment-only stub - the
   false-recovered-caller trap, and the address annotation makes it look clean.
3. **Is it a container/CRT lane?** `sub_7600A0` is `std::sort` internals that
   the recovered `SortDumpUnitsCountEntries` explicitly absorbs. `sub_7E3340` is
   a map-insert wrapper whose five callees are all RB-tree internals. Both are
   skips per the container-emission rule, not recoveries.

Cheap discriminator for (3): if the candidate's callee list is several
same-family `sub_*` in a tight address range, it is container machinery.
