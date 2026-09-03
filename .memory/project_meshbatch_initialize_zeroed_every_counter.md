---
name: project_meshbatch_initialize_zeroed_every_counter
description: RESOLVED (commit 2d7cb10a). MeshBatch::Initialize was a partial recovery that zeroed every counter and left the bone-remap table empty, so no mesh instance ever got a GPU skinning palette written. Also names SScmFile +0x0C/+0x20 and fixes a bone-count citation error in e522e1dc.
metadata:
  type: project
---

## RESOLVED — commit `2d7cb10a`

`MeshBatch::Initialize` (`0x007E6F60`, 166 lines of ground truth) had been
recovered as a counter-zeroing shell ending in *"Full scm-file and D3D effect
binding is recovered in follow-up meshbatch passes."* — which never happened.
Everything downstream therefore ran on zeros:

  - `FillInstanceBonePalettes` loops `boneIndex < mBoneCount`, so with
    `mBoneCount == 0` **no instance ever got a skinning palette written**;
  - `mBoneRemapIndices` stayed empty, so the palette's remap lookup had nothing
    to read;
  - `HardwareMeshBatch::Initialize` divides the device primitive cap by
    `mTriangleCount` on the non-remapped path.

This is a second, independent cause of skinned units not rendering, alongside
[[project_canipose_empty_bones_hid_every_unit]]. Both had to be fixed.

### What the shipped body actually does (0x007E6FB9..0x007E7181)

| Field | Source |
|---|---|
| `mVertexCount` | `SScmFile` +0x18 |
| `mIndexCount` | `SScmFile` +0x20 |
| `mTriangleCount` | index count / 3 (`imul 55555556h` signed magic divide) |
| `mBoneCount` | `SScmFile` +0x0C |
| `mAttachCount` | `SScmFile` +0x2C − bone count |
| `mUseSecondaryData` | `lod->scrolling` (lod +0xAC) |
| `mParameterAnnotation` | `"mesh"` effect's `"parameter"` integer annotation on `lod->mat.mShaderAnnotation` (lod +0x10) |

Remap table: identity when the reference resource is absent or *is* the current
resource; otherwise both SCM bone-name blocks are walked and each bone matched
by name, unmatched bones falling to slot 0. Instance budget: `80 / boneCount`
when remapped, else the tighter of `0xFFFF / vertexCount` and
`maxPrimitiveCount / triangleCount`.

### Verified, NOT a bug — the duplicated instance budget

`HardwareMeshBatch::Initialize` recomputes `mMaxInstancesPerDraw` as
`maxPrimitiveCount / mTriangleCount` when `!mUseBoneRemap`, clobbering the base
class's value and losing the `0xFFFF / vertexCount` clamp. Checked against
`0x007E75E6..0x007E75F4` — the shipped binary really does this. Leave it.

### SScmFile +0x0C vs +0x2C — a citation error in `e522e1dc`

IDA names both lanes similarly and the header had only `mBoneCount` at +0x2C,
so `e522e1dc` passed the **total** bone count to `InterpolatePose`. The binary
reads +0x0C there (`0x007DEDEF`). The two lanes are now named apart:

  - `mSkinBoneCount` (+0x0C) — skinned bones; pose blending, palette slots.
    Used by `MeshBatch::Initialize` and `UpdateInterpolatedFields`.
  - `mBoneTotalCount` (+0x2C) — skinned **plus** attachment bones; their
    difference is `mAttachCount`. Genuinely used by `GetDebugBoneCount`
    (`0x007DE758`), `ComputeDebugPose` (`0x007DE7E0`), the `CAniSkel` ctor, and
    the bone-name list.

Different call sites really do read different lanes — check the `.asm`
displacement before assuming which one a site wants.

`FillSScmBoneNamePointers` moved out of `CAniSkel.cpp`'s anonymous namespace to
`moho::scm_file::FillBoneNamePointers` in `SScmFile.h/.cpp`, since the remap
branch needs it cross-TU. Its old comment already said it was file-static only
"because that caller is not yet recovered into source".
