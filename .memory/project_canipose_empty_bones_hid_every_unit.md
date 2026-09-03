---
name: project_canipose_empty_bones_hid_every_unit
description: RESOLVED (commit fd114bc5). CAniPose's (skeleton, scale) ctor left mBones EMPTY instead of building one visible bone per skeleton bone, so FillInstanceBonePalettes parked every bone at -1000 and every skinned unit rendered invisible. Almost certainly the "commander not spawning" root cause.
metadata:
  type: project
---

## RESOLVED — commit `fd114bc5`

`CAniPose::CAniPose(shared_ptr<const CAniSkel>, float)` (`0x0054AF00`, 140
lines of ground truth) was recovered as a ~15-line shell: it stored the
skeleton and scale, seeded the inline bone storage, and **left `mBones`
empty**. The shipped body sizes the array to the skeleton's bone count
(`0x0054AFEC`) and initialises each bone from the skeleton's rest pose —
parent link from `mParentBoneIndex`, rest offset scaled by `scale`, rest
orientation verbatim, `mCompositeDirty = 1`, and **`mVisible = 1`** at
`0x0054B0A5`.

### Why an empty pose hides the unit

`FillInstanceBonePalettes` (`HardwareMeshBatch.cpp:145`) resolves each bone
against the pose's own bone count:

```cpp
const auto poseBoneCount = pose.mBones.end() - pose.mBones.begin();   // 0
const CAniPoseBone* poseBone = remapIndex < poseBoneCount ? ... : nullptr;
if (poseBone == nullptr || poseBone->mVisible == 0) { /* park at -1000 */ }
```

With the count zero, *every* remap index is out of range, so every bone took
the hidden branch and was parked at `kHiddenBoneDepth` with a zero scale — the
whole unit collapses to nothing. Unskinned geometry (terrain, boundary) never
reads a pose, which is exactly why only units disappeared.

Also restored: the null-skeleton fallback to `CAniSkel::GetDefaultSkeleton()`
(`0x0054AF4C..0x0054AFE9`).

### Quaternion convention — NOT the x-scalar bug, do not "fix" it

Ground truth reads `mLocalTransform.orient.x = 1.0` with the other three
zeroed. That is **not** the x-scalar convention: `VTransform` declares
`Wm3::Quatf orient_; // 0x00 (w,x,y,z)`, so IDA's `.x` is memory slot 0, which
is `.w` under Wm3 naming. `MakeIdentityPoseTransform`'s `.w = 1.0f` is
correct; the constant at `0x00DFEC20` is `0000803f` = 1.0f. Cross-check the
declared memory order in `VTransform.h` before touching any of these — see
[[feedback_quaternion_x_scalar_convention_bug_class]].

### The chain this sits in (traced and verified this pass)

`UserEntity::CreateMeshInstance(forUnitPose=true)` allocates `mPosePrimary`
and `mPoseSecondary` from the mesh skeleton (`UserEntity.cpp:794/797`), and
`MeshInstance`'s ctor allocates `curPose` the same way (`Mesh.cpp:4880`). Both
were therefore empty. This also **properly proves** the null-safety invariant
for [[project_meshinstance_curpose_orphan_visibility_bug]]: the same
`forUnitPose` flag drives both `isStaticPose` and the pose allocation, so the
poses are non-null exactly when `InterpolatePose` is gated to fire.

### The HideBone → renderer chain DOES work — traced end to end

An earlier read of this pass wrongly concluded it was broken because
`SSyncData::mPoseUpdates` (+0x220) is read at `CWldSession.cpp:16075` and
written nowhere in `src/sdk`. That lane is **not** how units sync their pose,
so it is a much smaller gap than it looks (some non-unit entity path). Units
go through the variable-data lane instead:

`HideBone` → `AniActor->mPose` → `Unit::Sync` publishes it as
`VarDat().mSharedPose = AniActor->GetPoseShared()` (`Unit.cpp:17285`, and
`Unit::SetPoses` `0x006ABB90` for the prior pose) → replicated in
`mUnitUpdates` → `UserUnit::UpdateUnitData` sets
`mPosePrimary = mUnitVarDat.mPriorSharedPose` and
`mPoseSecondary = mUnitVarDat.mSharedPose` (`UserUnit.cpp:4336-4337`) →
`SetStance(..., mPosePrimary, mPoseSecondary)` → `InterpolatePose` copies
`mVisible` from the **target** (secondary) pose → `curPose` → the GPU palette.

So the only thing that was broken is the one this commit fixes: the blend is
bounded by `min(destBoneCount, bones)`, and with `curPose` empty that is
always zero, so nothing was ever copied into it no matter how correct the
source poses were.

### Verified faithful this pass — do NOT re-audit

`CAniPose::InterpolatePose` (`0x0054B770` — the `_WORD` copy at its line 51 is
exactly the adjacent `mVisible`/`mSkipNextInterp` pair at +0x48/+0x49),
`CAniPoseBone::SetVisibleRecur` (`0x0054BE30`), `CAniSkel::GetBone`,
`cfunc_UnitShowBoneL` / `cfunc_UnitHideBoneL` (`0x006D14F0` / `0x006D1690`),
and `MeshRenderer::Render`'s batch dispatch (`FUN_007E0C30` lines 211-261 —
no non-instanced fallback exists, `if (batch) batch->Func4(...)` is the whole
tail).
