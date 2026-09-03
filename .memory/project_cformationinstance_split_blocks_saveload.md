---
name: project-cformationinstance-split-blocks-saveload
description: The long-tracked CFormationInstance/CAiFormationInstance split also blocks the entire formation save/load subsystem, not just the Lua side.
metadata:
  type: project
---

Traced 2026-08-17 while decoding the formation serializer. This supplements the
older `project_cformationinstance_split_blocked` note (legacy memory path),
which framed the split as blocked on the formation Lua subsystem.

## The mismatch

`CFormationInstance` **does not exist as a type in `src/sdk`** - only a forward
declaration at `Unit.h:54`. Our `CAiFormationInstance` derives straight from
`IFormationInstance` (`CAiFormationInstance.h:335`) and holds the fields that
belong to the missing middle class: every offset the serializer touches, 0x18
`mCommandType` through 0x320 `mMaxUnitSlotCount`.

The binary disagrees. `CAiFormationInstanceTypeInfo::Init` (0x0059BDE0) calls
`AddCFormationInstanceBaseToCAiFormationInstanceType`, so
`CAiFormationInstance` derives *from* `CFormationInstance` and those fields live
on the base. Our base registration therefore points at a type with no members.

## Why it matters beyond Lua

`CFormationInstance::MemberSerialize` (FUN_005744E0) and `MemberDeserialize`
(FUN_005741D0) are methods **on the missing class**, as is the whole
seven-piece serializer cluster in
[[project-formation-serializer-decoded]] - which is otherwise fully decoded,
down to all 18 lanes in both directions and the install site.

**Formation instances have no save/load path in the recovered engine, and
cannot get one until this split lands.**

## Order of work

1. Split `CFormationInstance` out of `CAiFormationInstance`, moving the fields
   at 0x18-0x320 onto the base. The size asserts in `CAiFormationInstance.h`
   pin every offset, so the split is mechanical once the class exists.
2. Model the six reflection globals (addresses and convention in
   [[project-formation-serializer-decoded]]).
3. Land the seven-piece serializer cluster - pure transcription at that point;
   `CAiBrainSerializer` (`moho/ai/CAiBrainSerializer.{h,cpp}`) is an exact
   structural template, including its `register_*` and cleanup lanes.
