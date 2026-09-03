---
name: project-geomcam-compare-discrepancy
description: AreGeomCameraVectorsEqual uses memcmp over all 712 bytes of GeomCamera3, but the binary compares 16 floats element-wise. Real discrepancy, but the 64-byte span does not land on a field boundary - trace the caller before changing it.
metadata:
  type: project
---

`CSimDriver::SetGeomCams` (0x0073B270) only replaces the pending sync-filter
cameras when the content differs. The recovered comparison and the binary's do
not agree, in two ways.

## What source does

`AreGeomCameraVectorsEqual` (`SimDriver.cpp:748`):

    if (lhs.size() != rhs.size()) return false;
    for each i: if (memcmp(&lhs[i], &rhs[i], sizeof(GeomCamera3)) != 0) return false;

## What the binary does

`sub_73AEF0` (FUN_0073AEF0) is `BOOL __fastcall(float* a1, float* a2)` and
compares **exactly 16 floats element-wise** with `==`:

    return a2[0]==a1[0] && a2[1]==a1[1] && ... && a2[15]==a1[15];

The caller's loop stride is **0x2C8** = `sizeof(GeomCamera3)`, so the elements
really are cameras - but only their first 0x40 bytes are compared.

## Two independent divergences

1. **Scope**: 64 bytes compared vs 712. Source is far stricter and will replace
   the vector on changes the original ignores.
2. **Semantics**: `memcmp` compares bit patterns; the binary uses float `==`.
   They disagree on `-0.0f` vs `+0.0f` (bitwise different, numerically equal)
   and on NaN (bitwise equal, numerically unequal). With NaN present the binary
   always reports "changed" and source reports "unchanged" - opposite
   behaviours.

## RESOLVED: sub_73AEF0 is matrix equality, and the compare is field-wise

Reading `FUN_0073B270`'s call site settles it. The binary does **not** compare
the camera as a blob - it compares field by field:

    lea  ecx, [ebx-4Ch] / [edi-4Ch]   -> Wm3::Vector3::Compare
                                      -> Wm3::Quaternion::Compare
    mov  ecx, ebx ; mov edx, edi      -> sub_73AEF0            (matrix)
    lea  ecx, [ebx-40h] / [edi-40h]   -> sub_73AEF0            (matrix)

So **`sub_73AEF0` is `gpg::gal::Matrix` equality**: 16 floats is exactly
`sizeof(gpg::gal::Matrix)` = 0x40, a clean field boundary. The earlier "spans
7 floats of VTransform plus 9 of projection" reading was wrong because it
assumed the argument was `&vec[i]`; the caller actually passes interior field
addresses (note the `esi+5Ch` / `ebx-4Ch` / `ebx-40h` adjustments).

`VTransform` is position (`Vector3`) + orientation (`Quaternion`) = 0x1C, which
is what the two `Wm3::*::Compare` calls cover.

### What still needs doing

Replace the `memcmp` in `AreGeomCameraVectorsEqual` with the field-wise compare:
transform position, transform orientation, then each matrix via a recovered
`AreMatricesEqual` (= `sub_73AEF0`). **Walk the whole of `FUN_0073B270` first to
enumerate every field it compares** - the snippet above shows two matrix
compares, but there may be more further along, and the point of the fix is that
the binary compares a *subset*, so guessing the subset defeats it.

Both divergences below remain real and are the reason this matters.
