---
name: project_meshinstance_curpose_orphan_visibility_bug
description: RESOLVED (commit e522e1dc). MeshInstance::curPose was never re-blended, so the GPU skinning palette read a pose frozen at construction -- HideBone/ShowBone (which mutate AniActor->mPose) could never affect what rendered, leaving a warp-in commander permanently hidden. Fixed in UpdateInterpolatedFields, verified line-for-line against FUN_007DEC80.
metadata:
  type: project
---

## RESOLVED — commit `e522e1dc`

`MeshInstance::UpdateInterpolatedFields` (`0x007DEC80`) never refreshed
`curPose`, but that is the exact `CAniPose` the render path reads:
`HardwareMeshBatch::FillBatch` → `CaptureMeshInstanceCurrentPose`
(`Mesh.cpp:134`, a plain shared_ptr copy of `meshInstance->curPose`) →
`FillInstanceBonePalettes` (`HardwareMeshBatch.cpp:145`), which parks any
bone with `mVisible == 0` at `kHiddenBoneDepth = -1000.0f`.

`HideBone`/`ShowBone` mutate `unit.AniActor->mPose` — a **different**
`CAniPose` object. So `CommandUnit.lua`'s `WarpInEffectThread`, which does
`HideBone(0,true)` on spawn and `ShowBone(0,true)` ~5s later, could hide
nothing and reveal nothing: the renderer was reading a pose frozen at
construction. Before the fix `curPose`'s only writers were the constructor
(`Mesh.cpp:4934`) and the static-pose-only, debug-only `ComputeDebugPose`.

### Three divergences fixed, all verified against `FUN_007DEC80.c` directly

1. **Early-return guard.** Ground truth enters on
   `sCurrentInterpolant != mCurrInterpolant && (mFrameCounter != sFrameCounter || !v54b)`;
   the recovered code had a bare interpolant compare. `SetStance` resets
   `currInterpolant` to `-1.0f` but leaves the frame counter alone, so the
   second half is what lets a fresh stance be picked up.
2. **The missing pose blend** (decompile lines 58-64):
   `if (mIsStatic && !mIsLocked) InterpolatePose(mCurPose, interp, mStartPose, mEndPose, resource->mFile->mBoneCount)`.
3. **Bounds.** Ground truth rebuilds the world sphere/OBB/AABB from the mesh
   resource's own local bounds (`sub_7DAC10` → `sub_472CF0` → `sub_7DEF60`)
   plus `curPose->mMaxOffset`; the recovered code recentered whatever stale
   extents the instance already held. **This half also affects culling**, so it
   is a plausible cause of the separately-reported "meshes blink / disappear
   while scrolling" symptom.

### `isStaticPose` means the OPPOSITE of what its name suggests

`ResolveInitialPoseSkeleton` (`Mesh.cpp:2802`): when `isStaticPose` is TRUE the
instance gets the mesh resource's **own** skeleton; when FALSE it gets
`CAniSkel::GetDefaultSkeleton()`. So `isStaticPose != 0` = "a real skinned unit
with its own pose", not "a static prop". An earlier pass in this session read it
backwards and nearly discarded the fix on that basis — don't repeat that.

### Why the missing null check is correct, not a latent crash

`CAniPose::InterpolatePose` dereferences `sourcePose`/`targetPose` immediately
with no guard — and ground truth does the same. That is safe because the
invariant holds on both sides: `UserEntity.cpp:588` passes `mPosePrimary`/
`mPoseSecondary` into the pose-carrying `SetStance` overload **only** when
`isStaticPose != 0u`, and that overload itself bails to the 2-arg form when
`isStaticPose == 0`. So `startPose`/`endPose` are non-null exactly when the
`InterpolatePose` call is gated to fire. Verified before committing.

### Still open / not claimed by this fix

Runtime verification. The operator reported four symptoms (commander not
visible, meshes blinking grey while scrolling, no map-border meshes, window
closes but process and audio keep running). This fix plausibly addresses the
first two; it makes no claim on the other two. Do not report it as confirmed
until a live `/map SCMP_009` run shows the commander appearing after the ~5s
warp-in.
