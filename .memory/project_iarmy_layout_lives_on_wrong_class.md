---
name: project-iarmy-layout-lives-on-wrong-class
description: "IArmy is modelled as a 55-virtual interface with zero data, but the binary has it non-polymorphic with SSTIArmyConstantData@0x00 + SSTIArmyVariableData@0x80; CArmyImpl re-declares those bytes flattened at 0x08/0x88"
metadata:
  node_type: memory
  type: project
---

Found 2026-08-21 while removing `SimArmyRuntimeView` from `moho/sim/ReconBlip.cpp`
(the operator flagged it: *"what the heck is SimArmyRuntimeView [...] I don't
think we even need this helper struct"*). The overlay is a **symptom**: the
data it reaches for is declared on the wrong class, so nothing typed could
reach it.

**Evidence (all asm/RTTI, not inference):**

- `ReconBlip::GetReconInfo(SimArmy*)` FUN_005BDED0 is 4 instructions:
  `mov eax,[eax+8]; imul eax,34h; add eax,[ecx+4C4h]; retn`
  -> the army index is at **SimArmy+0x08**.
- `SimArmy::SimArmy` FUN_006FDAB0: `lea eax,[esi+8]; call IArmy::IArmy` then
  `mov [esi], ??_7SimArmy@Moho@@6B@`
  -> **IArmy data block at SimArmy+0x08**, SimArmy's own vptr at +0x00.
- `IArmy::IArmy` FUN_006FD520: constructs `SSTIArmyConstantData` at IArmy+0x00
  (`this` passed straight through) and `SSTIArmyVariableData` at IArmy+0x80
  (`lea eax,[esi+80h]`). **It writes no vptr at all.**
- `dumps/moho_engine_rtti.json`: `IArmy@Moho` has **0 vtable slots**;
  `SimArmy@Moho` and `CArmyImpl@Moho` have **52 each**.
- `CArmyImpl::CArmyImpl` FUN_006FE690: `lea ebx,[ebp+8]` for the base,
  `mov [ebp+0], ??_7CArmyImpl@Moho@@6B@`. Nothing ever writes `army+0x04`.

**The contradiction in our model:**

- `moho/sim/IArmy.h` declares **55 virtuals and zero data members** -- the exact
  inverse of the binary, whose IArmy is a non-polymorphic data block. Its own
  doc comments already say "`SSTIArmyConstantData` (+0x00) and
  `SSTIArmyVariableData` (+0x80)"; the fields were simply never declared.
- `moho/sim/CArmyImpl.h` (`class CArmyImpl : public SimArmy`) **re-declares the
  same bytes flattened one level down**, with asserts:
  `offsetof(CArmyImpl, ArmyId) == 0x08` (that *is* `mConstDat.mArmyIndex`) and
  `offsetof(CArmyImpl, EnergyCurrent) == 0x88` (the `mVarDat` head).
- So `SimArmy` is 8 bytes with nothing declared at +0x08, and the fabricated
  `SimArmyRuntimeView { pad[8]; SSTIArmyConstantData mConstDat; }` existed
  purely to reach past that hole.

**Open before this can be fixed:** nothing in the ctor chain initialises
`SimArmy+0x04`. Until that 4-byte slot is identified, moving `mConstDat` onto
`IArmy`/`SimArmy` shifts everything by 4 and breaks CArmyImpl's ~15 offset
asserts. Resolve that slot first (candidates: a second base's vptr, or an
uninitialised member set outside the ctor).

**The real fix** is a 3-class layout unification: give the owning class its
`SSTIArmyConstantData mConstDat` / `SSTIArmyVariableData mVarDat`, delete
CArmyImpl's ~200 flattened duplicates, and rewire consumers. That is a
duplicate-layout defect under the CLAUDE.md "Duplicate layout contract",
not just a cosmetic overlay. Do NOT attempt it piecemeal.

Related: [[feedback-recover-input-not-compiler-output]] (RULE ONE) -- the
overlay is the same failure shape as the container lanes: fabricating a local
struct because the real modelled type was inadequate, instead of fixing the
real type.
