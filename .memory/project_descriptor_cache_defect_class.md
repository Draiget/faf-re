---
name: project-descriptor-cache-defect-class
description: Six recovered reflection registrations dropped the descriptor store into the class's sType static, leaving other reflection paths resolving null. Detection recipe plus what is already fixed.
metadata:
  type: project
---

A recurring recovery defect: the binary's reflection registrations resolve a
type descriptor **and store it into that class's `sType` static**; several
recovered versions either look it up and discard it, or cache it in a
**function-local static**. Either way the class static stays null, and every
other reflection path that reads `X::sType` first re-resolves or resolves to
nothing.

The binary shape is always:

    v1 = Moho::X::sType;
    if (!Moho::X::sType) {
      v1 = gpg::LookupRType(&Moho::X `RTTI Type Descriptor');
      Moho::X::sType = v1;          // <- the store that gets dropped
    }

## Fixed so far (2026-08-17 run)

| Commit | Class | Was |
|---|---|---|
| 39bd696 | `CScriptEvent` | uncached `LookupRType(typeid(...))` |
| 322b105 | `Entity` | uncached |
| 0a10186 | `Broadcaster<EAiTransportEvent>` | function-local static; class had no `sType` at all - added to `BroadcasterEventTag<TEvent>` |
| b20cc03 | `IAniManipulator` (CAnimationManipulator) | uncached |
| b20cc03 | `IAniManipulator` (CCollisionManipulator) | function-local static |

Earlier in the same run, six genuinely **missing** base registrations were also
added (a032ff6, d020b94, 49edf56, 18997bb, 1e663b2, cb884e8) - same subsystem,
different failure.

## Detection recipe

The `AddBase_*` family is the tractable population: **156 emissions, 146
annotated and correct, 10 unannotated** as of this run. Query them with the
have-set:

    SELECT token, demangled_name, instruction_count FROM functions
    WHERE demangled_name LIKE '%AddBase_%'

then for each unannotated one, read the `.c` (they are all ~26 instrs) and
compare the cache target against source.

**Do not sweep `LookupRType(typeid(` broadly** - there are ~1572 sites and most
are legitimate. The defect only exists where a *binary* counterpart does the
cache-and-store, so the emission is the oracle. Likewise there are many
`static gpg::RType* cached = nullptr` function-local caches left in the tree;
they are only wrong where the corresponding emission writes a class static.
Changing the rest without checking is guesswork.

## Two traps in this vein

- **Free-function `Init`s.** Several manipulator TypeInfos register their base
  from a *free function*, not a member, so a "does the member exist" check
  scores zero and invites a duplicate registration. `CThrustManipulatorTypeInfo`
  hit this - the helper existed, just unannotated.
- **`StaticGetClass()` is fine.** `ScriptedDecalTypeInfo` looked defective but
  routes through `CScriptObject::StaticGetClass()`, which does the
  check-and-store internally.

Related: [[project-descriptor-registration-vein]], [[reference-crlf-byte-safe-edits]]
(these files need byte-wise edits).
