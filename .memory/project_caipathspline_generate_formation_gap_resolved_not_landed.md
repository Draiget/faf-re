---
name: project-caipathspline-generate-formation-gap-resolved-not-landed
description: Both blockers CAiPathSpline::Generate's TODO names (CommandIsForm, formation_path_value) are now fully resolved with hard evidence; the full 722-line rewrite itself is NOT done -- deliberately deferred, needs a dedicated asm-verified pass.
metadata:
  type: project
---

`Moho::CAiPathSpline::Generate` (FUN_005B2FF0, `src/sdk/moho/ai/CAiPathSpline.cpp`)
carries a TODO: its current body is a "provisional typed lift" (simple lerp
stepping), not the real 722-line PPS_0..PPS_8 brake/steer state machine the
binary implements. The TODO named exactly two blockers. Both are now resolved:

## 1. `CFormationInstance::CommandIsForm` (0x00569BF0) -- already fully recovered

Confirmed real, correct, and already wired (`CAiFormationInstance.cpp:6822`,
called internally from `Update()`/`CalcFormationSpeed()`). The wiring pattern
`Generate` needs already has a working precedent in the SAME kind of call
in `Unit.cpp`:

```cpp
CAiFormationInstance* const formation = reinterpret_cast<CAiFormationInstance*>(GetFormation());
if (formation != nullptr && formation->CommandIsForm()) { ... }
```

(`Unit.cpp:15645-15647` and `:15698-15701`, both already-recovered call sites
doing exactly this reinterpret-from-`IFormationInstance*` idiom.) No new work
needed on `CAiFormationInstance.h/.cpp` for this piece -- **do not** touch
those files for this; they are the CFormationInstance-split hot zone (see
`project_cformationinstance_base_missing.md` / `_ownership_defect.md` /
`_split_blocks_saveload.md` -- a much bigger, separately-scoped refactor that
this task correctly does not need).

## 2. `formation_path_value` (data symbol at 0x00F59978) -- resolved via raw PE read

`.asm`-confirmed read site: `0x005B3097: 8B 0D 78 99 F5 00  mov ecx, [0x00F59978]`.
Read the raw DWORD directly from `bin/2025.7.1/ForgedAlliance.exe` via `pefile`
(installed, `pefile.__version__ == '2023.2.7'`):

```python
import pefile, struct
pe = pefile.PE(r"G:\projects\faf-main\bin\2025.7.1\ForgedAlliance.exe", fast_load=True)
rva = 0x00F59978 - pe.OPTIONAL_HEADER.ImageBase   # -> 0x00B59978
data = pe.get_data(rva, 4)                         # section: .data
struct.unpack("<I", data)[0]                       # -> 5
```

Value is `5` (int32, `.data` section, no other code or data xref anywhere in
the indexed disassembly touches this address -- it's a plain compile-time
constant, not a runtime-tunable `rule_*` global). Semantics per the decompile
(`FUN_005B2FF0.c` lines 172-181): `v119 = 20; if (unit->GetFormation() &&
formation->CommandIsForm()) v119 = formation_path_value /* =5 */; if
(physics.mTurnRadius > physics.mTurnRate) v119 *= 3;` -- `v119` is later used
at decompile line 582 as the hard cap on accumulated path nodes
(`this->mNodes.end - this->mNodes.start >= v119`), forcing `PPS_8` (terminal)
once reached.

## Why this is NOT wired into the current body

The current "provisional" `Generate()` doesn't have an equivalent concept to
patch this onto: it uses `steps = std::clamp(distance/1.5+1, 2, 20)` as an
*interpolation resolution* parameter, not `v119`'s role as a *hard loop-
termination node cap* in the real brake/steer simulation loop. Swapping the
literal `20` for the resolved formation-aware expression inside the
provisional algorithm would be cosmetic -- it would not reproduce the
binary's actual behavior, and it risks reading as "this gap is now closed"
when the real algorithm still isn't there. Declined to do that.

## Why the full rewrite is deferred (not a refusal -- a scoping call)

Read the complete 722-line decompile (`decomp/recovery/disasm/fa_full_2026_03_26/FUN_005B2FF0.c`)
end to end and cross-verified the opening ~40 lines (forward-vector-with-
gimbal-lock-guard computation, decompile lines 185-198) against raw `.asm`
bytes (`FUN_005B2FF0.asm` 0x005B30D8-0x005B3193). The arithmetic transcribed
cleanly (`v110.x = 2*(x*z+w*y)`, `v110.y = 2*(w*z-x*y)`, `v110.z =
1-2*(z*z+y*y)`, clamped to `(0,0,1)` when `|v110.y| > 0.99`), **but it does
not match** `Wm3::Quaternion::Rotate({0,0,1})`'s generic column-2 extraction
(`Wm3Quaternion.inl:646-669`) term-for-term -- the cross terms and which
matrix row/column gets read differ, most likely a coordinate-convention
difference between Moho's own quaternion layout and WildMagic's, not a
transcription error (verified the raw multiply/add/sub instruction sequence
directly, not just the decompiler's pseudocode). `Update()` (the sibling
PPS state machine in the same class, already recovered) calls the generic
`.orient_.Rotate(...)` for its own forward vector -- given this mismatch,
that call in `Update()` may itself warrant a second look some day, but that
is out of scope here; not touched, not asserted as a bug, just flagged.

Getting this ONE opening sub-expression right took a full raw-.asm
verification pass. The remaining ~680 lines are denser (15+ `goto`-driven
branch labels, heavy x87/SSE register reuse, `doBackup`/reverse-driving
special cases) and this is **lockstep simulation code** -- a transcription
mistake here is a desync bug, not a cosmetic one, and there is no way to
runtime-verify a rewrite against the real binary's output in this pass.
Concluded the full transcription needs its own dedicated, asm-verified pass
(matching `Update()`'s already-accepted style/structure as the template),
not a rushed pass riding on top of an unrelated batch. Nothing written to
`CAiPathSpline.cpp` for this piece; the TODO comment there is unchanged and
still accurate about what's missing (the state machine itself), just no
longer accurate that `CommandIsForm`/`formation_path_value` are open -- a
future pass should update that comment when it lands the rewrite.

## Real caller (unchanged, already correct)

`CAiSteeringImpl::UpdatePath` (`CAiSteeringImpl.cpp:1385`) already calls
`mPath->Generate(mOwnerUnit, destination, pathMode, allowContinuation)` by
name. No caller-wiring work needed; only `Generate`'s own body is incomplete.

Related: `project_cformationinstance_base_missing.md`,
`project_cformationinstance_ownership_defect.md`,
`project_cformationinstance_split_blocks_saveload.md` (the separate, larger
CFormationInstance/CAiFormationInstance split -- not needed for this specific
gap, but adjacent).
