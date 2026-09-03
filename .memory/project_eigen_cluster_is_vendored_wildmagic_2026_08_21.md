---
name: project-eigen-cluster-is-vendored-wildmagic-2026-08-21
description: The 0xA6D000-0xA71500 "CrtRuntimeHelpers fake recovery" cluster is Wm3::Eigen<float>/<double> whose source is already vendored in-repo; plus the general rule that owner=<none> callers mean IDA under-tokenized a strided template block
metadata:
  type: project
---

## The finding

The cluster of fake-recovered / blocked tokens in **0x00A6D000-0x00A71500**
(part of [[project_crtruntimehelpers_fake_recovery_contamination_2026_08_21]])
is **not lost engine source at all**. It is the complete MSVC out-of-line
emission of WildMagic 3.8's `Wm3::Eigen<Real>` eigensolver, for both the
`float` and `double` explicit instantiations.

The source **already exists in this repo**, vendored at
`dependencies/WildMagic3p8/Foundation/Numerics/Wm3Eigen.cpp`, compiled by
`dependencies/WildMagic3p8/Foundation/Foundation.vcxproj`, and emitted by the
`template WM3_ITEM class Eigen<float>; template WM3_ITEM class Eigen<double>;`
pair at the bottom of that file.

18 addresses mapped and cited (9 members x 2 instantiations) — full table in
`decomp/recovery/reports/by-source/dependencies/WildMagic3p8/Foundation/Numerics/Wm3Eigen.cpp.reconstruction.md`.

### Layout fingerprint — recognise this instantly

`Eigen<Real>` is `m_iSize`@0x00, `GMatrix<Real> m_kMat`@0x04 (which is
`m_iRows`/`m_iCols`/`m_iQuantity`/`m_afData`@0x10/`m_aafEntry`@0x14),
`m_afDiag`@0x18, `m_afSubd`@0x1C, `m_bIsRotation`@0x20.

**Any body in this repo that touches only `[this]`, `[this+0x14]`,
`[this+0x18]`, `[this+0x1C]`, `[this+0x20]` with float or double lanes is an
`Eigen<Real>` member.** Do not recover it into `src/sdk` — cite the vendored
template instead.

## Two fabricated bodies deleted (commit 6975a5d4)

`src/sdk/moho/sim/SimRecoveryRuntime.cpp` had `SnapshotAndResetBasis2fRuntime`
/ `SnapshotAndResetBasis2dRuntime` citing 0x00A6D420 / 0x00A6EF10, described as
"2x2 basis snapshot+reset". They were `Eigen<Real>::Tridiagonal2()` in
disguise, over stand-in structs `BasisPointerResetRuntimeF/D` = `std::byte
pad00[20]` + `basisPair` + `outputPrimary` + `outputSecondary` + `wasReset`,
i.e. the Eigen offsets exactly. Both had **zero callers** in `src/sdk`.

They also transcribed the compiler's output: invented null guards the binary
never performs, and returned `m_kMat.m_aafEntry` as a `uint32` because IDA
typed the leftover `EAX` as a return value where the real member returns
`void`. **A `uint32` return that is just a pointer the function last loaded is
a strong tell for a fabricated recovery of a `void` function.**

## Generalizable: `owner=<none>` callers != missing parent function

`FUN_00A6E7C0`/`FUN_00A6FF60` (QLAlgorithm) each report **15 callers, 13 with
`owner=<none>`** and matching no IDA-classified function. This looked like a
truncated `end_ea` or an unclassified parent. It was neither.

`Eigen<Real>` declares exactly 15 public solve entry points —
`EigenStuff{2,3,4,N,generic}` x `{plain, DecrSort, IncrSort}` — each calling
`QLAlgorithm()` once. **IDA tokenized only 2 of the 15 per instantiation**
(`IncrSortEigenStuff2`/`3`); the other 13 are real, int3-padded functions at a
regular **0x40 stride** that IDA never classified, so the exporter produced no
`.asm`/`.meta.json`/`FUN_*` token for them.

Recipe when a callee has many `owner=<none>` callers:
1. Count them. If the count equals the number of declared entry points of a
   plausible class/template, that IS the explanation.
2. Check whether the unowned addresses sit on a **fixed stride** between two
   tokenized siblings — a hallmark of a dense template-instantiation block.
3. Decode the gap bytes straight from `bin/external/ForgedAlliance.exe`
   (ImageBase 0x400000); the call sequences identify each member.
4. A size-`switch` dispatch block is gold: it maps `case 2/3/4/default` onto
   four call targets at once, so confirming three confirms the fourth.

## Auditing gotcha

These 18 tokens are `recovered` with `source_paths` pointing at the **vendored**
`Wm3Eigen.cpp`, so the standard contamination-audit recipe (which greps only
`src/sdk`) will flag them as "recovered with no citation". That is a false
positive. **Check `source_paths` for a `dependencies/` prefix before treating a
token as contamination.**

Also: `dependencies/WildMagic3p8/` is **not tracked by git** (only
`dependencies/patches/*.patch` is), so annotations there live in the local
working copy only — same as `decomp/`. This matches the pre-existing precedent
set for `Tridiagonal4` by `codex-batch-20260507`.

## Still open in the window

`FUN_00A705E0` + its adjustor thunk `FUN_00A71130`, and the GMatrix
allocate/deallocate helpers `FUN_00A6D050`/`FUN_00A6D120`/`FUN_00A6D190`/
`FUN_00A6D230` — all still fake-marked `recovered` against
`CrtRuntimeHelpers.cpp` with no citation anywhere. `FUN_00A6D0B0`,
`FUN_00A70760`, `FUN_00A707C0` are `recovered` with **empty** `source_paths`.
Strong hypothesis: the rest of the window is `Wm3::GMatrix<Real>`, resolvable
the same way.
