---
name: feedback_icf_twins_view_unsound_for_rel32_thunks
description: "The callgraph DB's function_icf_twins view is categorically WRONG for 5-byte E9 rel32 thunks: identical bytes at different addresses jump to different absolute targets. All 157 all-thunk twin groups (486 tokens) are bogus. Never trust that view for thunks; decode addr+5+rel32 instead."
metadata:
  type: feedback
---

## What happens

`function_icf_twins` groups functions by `function_sha256`. For a 5-byte
`E9 rel32` jump thunk the encoded displacement is **relative to the thunk's own
address**, so two thunks at different addresses with byte-identical encodings
jump to **different absolute targets**. They hash the same and land in one twin
group while being semantically unrelated.

**Why:** ICF folding would never have merged them. The view reports a
similarity the linker does not have, and acting on it produces two distinct
failures: marking a live function `skip` as a "twin of the canonical", and
attaching a foreign thunk's address to an unrelated recovered body.

**How to apply:** for any candidate whose `instruction_count == 1` and
`span_bytes == 5`, ignore the hash and decode the target yourself:

```python
target = addr + 5 + int.from_bytes(bytes[1:5], 'little', signed=True)
```

Two thunks are aliases only if their **targets** match. Extends
[[feedback_verify_duplicate_claims_bytewise]] from hand-written "duplicate of
0xADDR" notes to the DB view itself.

## Measured, 2026-09-03 (`fa_full_2026_03_26`)

- 1,957 twin groups total; **157** consist entirely of 5-byte E9 thunks.
- **157 of those 157 are bogus** — in every single one the members jump to
  different targets. Not one is a real twin. They cover **486 tokens**.
- DB damage was small: of the 486, only **2** were `skip` citing ICF/twin.
  `FUN_0087FD90`'s note shows the right method — that worker decoded the jump
  (`-> FUN_0087FCF0`, an external `InlineIsEqualGUID`) instead of trusting the
  hash, so its skip is sound.

## Where it had leaked into the tree

A recovered forwarder would cite several thunk addresses as aliases when only
one actually forwards to the documented function. Detection: for each doc block
citing **2+** addresses, decode every cited thunk; flag any whose target is
owned by a doc block in an unrelated class's file.

That found 54 conflicts, 18 of them genuine cross-class errors, removed in
`05c905d4`. Clearest: `Projectile::MemberDeserialize` cited `0x00680790`
next to its real thunk `0x0069F8E0`, but `0x00680790` jumps to `0x00681220` =
`Entity::MemberDeserialize`, already owned by `Entity.cpp`.

Two false-positive classes to exclude, or the sweep flags ~99% of everything:

- a block citing **only** the thunk's own address is a normal standalone thunk
  recovery, not a defect;
- an `XSerializer` citing a thunk into `X` is correct — it forwards to the
  class it serializes. Strip `Serializer`/`TypeInfo`/`NestedTypeInfo` before
  comparing owners.

Consistent families are fine too: nine `Reflection.cpp` thunks all sharing one
target in `Global.cpp` agree with each other, so they are a real alias family
and were left alone.
