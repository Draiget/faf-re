---
name: project_raw_vtable_dispatch_remaining_targets
description: "Survey of raw vtable-dispatch sites left in src/sdk after the CUIWorldMesh/CameraImpl cleanups. Most are legitimate (boost sp_counted_base, COM/D3D10, unrecovered wx). The one real remaining engine target is CAiFormationDBImpl.cpp:231, with the exact verification it needs."
metadata:
  type: project
---

## Cleared this pass (2026-09-02)

- `82885c22` -- `CameraTargetRuntimeView` hand-dispatched vtable **slot 10**
  through a raw `__thiscall` cast. That slot is
  `CameraImpl::TargetLocation` (0x007A82F0), a recovered virtual with exactly
  the asserted signature, and both call sites already held a typed
  `CameraImpl*`. Now a plain virtual call.
- `bceff8aa` -- `CUIWorldMeshRuntimeView` was a pad-to-0x34 alias of
  `CUIWorldMesh::mMeshInstance`, which is public and typed at the same offset.
  Twelve sites now use the member.
- `e81f6d71` -- `MeshInstanceOwnerRuntimeView` (+0x34 == the same member) and
  its sphere/bounds view structs became `CUIWorldMesh::GetWorldSphere` /
  `GetWorldBounds` over real `Wm3::Sphere3f` / `Wm3::AxisAlignedBox3f`.

## Legitimate -- do NOT "fix" these

Surveying `reinterpret_cast<...Fn>(vtable[N])` across `src/sdk` turns up mostly
genuine indirect dispatch, where there is no recovered C++ type to call:

- `gpg/core/utils/BoostWrappers.cpp` -- `sp_counted_base` dispose/destroy is
  how boost's control block actually works, and the comments already say so.
- `gpg/gal/backends/d3d10/D3D10Interfaces.cpp` -- COM (`IUnknown` AddRef /
  Release, `ID3D10Device` slots). Vtable dispatch is the ABI.
- `moho/app/WxRuntimeTypes.cpp` -- wx classes are not recovered, so slot
  dispatch is the honest model. (Also peer-locked all of 2026-09-02.)
- `moho/ai/CAiFormationInstance.cpp:3279` -- `FormationUpdateListenerNode` is an
  opaque `{void** vtable; TDatListItem link;}` node. Naming an interface for it
  would be invention, not recovery.

## The last engine target: LANDED (`9635d5a8`)

`moho/ai/CAiFormationDBImpl.cpp`'s `ResolveFormationBucketTypeFromUnitSet`
(0x0062EE40) called vtable slot 7 through a `void*(*)(void*)` cast, then read a
"class tag" at a magic `+0x290` and compared it to 2. All three resolved:

| raw | real |
|---|---|
| `vtable[7]` | `Unit::GetBlueprint` (0x006A8B20) -- `Unit.h` annotates `Slot: 7` outright |
| `+0x290` | `Physics.MotionType` -- `Physics` starts at `RUnitBlueprint + 0x278`, `MotionType` is `Physics + 0x18` |
| `== 2` | `RULEUMT_Air` |

Now `blueprint->Physics.MotionType == RULEUMT_Air`. The `- 8` unbias stays
(entity base is at `Unit + 0x08`) but yields a typed `const moho::Unit*`.

**Method worth reusing for any magic `+0xNNN`:** find the sub-struct whose base
offset brackets it (the top-level type lists its members with offsets), subtract
that base, then look up the remainder in the sub-struct. Here 0x290 - 0x278 =
0x18. And check the header for an explicit `Slot:` annotation before counting
virtuals by hand -- `Unit.h` had it.

## No engine targets left

