---
name: feedback-verify-duplicate-claims-bytewise
description: "Never act on a DB note claiming 'ICF twin of X' or 'duplicate of 0xADDR' without comparing bytes and resolving call targets yourself; two of the three claims checked were wrong"
metadata:
  node_type: memory
  type: feedback
---

Found 2026-08-21 (batch 32) while looking for a landable target. Notes in
`recovered_progress.json` that assert one function is a duplicate of another
are **not reliable** and must be re-verified from the `.asm` exports before
any status flip or source edit. Two of the three claims audited were wrong.

**The three checks:**

1. `FUN_0043CBC0` -> "ICF twin of `FUN_00428340`", status `skip`.
   **Correct.** Both 10 instructions / 27 bytes, byte-identical.

2. `FUN_00826620` -> "ICF-eligible duplicate of the already-recovered
   `UICommandGraph::RelocateDrawNode` (0x0082D530)".
   **WRONG.** 86 instrs / 232 bytes vs 128 / 378, differing at the very first
   instruction. ICF folds *byte-identical* COMDATs, so different sizes rule it
   out on sight. What they actually are: the same source function emitted
   twice -- 0x0082D530 is the SEH-wrapped emission (SEH_82D530, unwind funclets
   at 0x00B843xx, `___CxxFrameHandler3_0`), 0x00826620 is the same field-by-field
   copy with no EH scaffolding. Resolution is a second `Address:` citation on
   the recovered body, **not** `skip` -- marking it skip would have lost the
   address.

3. `FUN_0082F7A0` -> "instruction-for-instruction identical to
   `GrowHashBucketVector`, just one more level of pointer indirection; recover
   as a thin wrapper".
   **WRONG twice over.** (a) `GrowHashBucketVector` no longer exists -- ba0d58a5
   collapsed it onto `msvc8::vector<void*>::insert` under RULE ONE. (b) The two
   are 236 instructions with a *0-difference mnemonic sequence*, but resolving
   the 13 direct `call rel32` targets shows they call different per-type
   helpers (throw 0x008307F0 vs 0x00830620, allocator 0x00831C20 vs 0x00831B40,
   copy/fill 0x00832BE0 vs 0x00832BC0). Same shape, **different template
   instantiation** -- not a wrapper. Also re-classified: its real blocker is
   `needs_recovered_caller`, not `owner_layout`.

**How to check, cheaply:**

- Sizes first. Different instruction/byte counts kill an ICF claim outright.
- Then the mnemonic sequence. Identical mnemonics + differing bytes means the
  deltas are relocations.
- Then **resolve the call targets**: `target = addr_of_call + 5 + rel32` for
  `E8` opcodes. Identical shape with *different* call targets means two
  instantiations of the same template, not one function reachable two ways.
  This is the step that distinguishes "cite a second address on the same
  recovered body" from "this is a separate element type".

Extends [[feedback-verify-before-declaring-missing]]. Same family as
[[project-fake-recovered-status-contamination]]: a confident note is not
evidence.
