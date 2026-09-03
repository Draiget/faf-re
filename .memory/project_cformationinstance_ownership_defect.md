---
name: project_cformationinstance_ownership_defect
description: CFormation::Finalize/ProcessMouse are blocked by CFormationInstance being modelled abstract and having UpdateFormation/Setup declared on the wrong (derived) class.
metadata:
  type: project
---

`CFormation::Finalize` (0x008382A0) and `CFormation::ProcessMouse` (0x00838800)
cannot land until `CFormationInstance::CFormationInstance` (**0x005694B0**, 283
instrs, not recovered) does. `CFormationInstance::operator new` (0x0056A920) is
*not* a leaf: it is the compiler's new-expression helper — `::operator new(0x328)`
then the ctor.

Two modelling defects in `src/sdk/moho/ai/CAiFormationInstance.h` block the ctor
(diagnosed 2026-08-20; nothing landed, no edits made):

1. **`CFormationInstance` is abstract in the model, concrete in the binary.**
   `IFormationInstance::operator_delete` is pure (`IFormationInstance.h:73`) and
   `CFormationInstance` never overrides it, so `new CFormationInstance(...)`
   will not compile. The binary disagrees: 0x005694B1 publishes
   `??_7CFormationInstance@Moho@@6B@` at **0x00E18E0C**, whose slot 0 is
   **0x00569430** (13 instrs: `~CFormationInstance()` then `operator delete` on
   bit 0). Adding that override is small and fully evidenced.
2. **`UpdateFormation` and `Setup` are declared on the derived class.** The ctor
   tail-calls `UpdateFormation` directly on a plain `CFormationInstance`
   (`call` at 0x00569857), but the repo declares `UpdateFormation()` at
   `CAiFormationInstance.h:810` and `Setup(SFormationLayerUnitSet&, int)` at
   `:769` on `CAiFormationInstance`. PE slots 0x00E18E10/14/18 =
   0x00569A10 / 0x00569A30 / 0x0056A210 — the exact addresses the repo declares
   as `CAiFormationInstance::Func2/Func3/UnitCount`, confirming the
   misattribution.

**Why it matters:** fixing (2) is a class-ownership refactor of a 37 KB header
plus a 197 KB `.cpp`, and it also forces retyping the anonymous-namespace helpers
`MergeOverlappingLaneBands`, `CleanupFormationTransientState`,
`RefreshFormationPlanIfRequested` from `CAiFormationInstance&` to
`CFormationInstance&`. Do it as its own pass — leaving that file mid-surgery
breaks every other agent on the shared checkout.

**How to apply:** the ctor itself is *fully scoped, no layout unknowns* — every
offset verified against the existing model in `FUN_005694B0.asm`:
`[edi+4]` mUnitCount=0, `[edi+8]` mUnitLinkListHead self-link, `[edi+0x10]`
mLuaState, `[edi+0x14]` mGameRules (ecx), `[edi+0x18]` mCommandType (edx),
`sub_56B200` mUnits inline-reset + `ResetFrom(units)`,
eh-vector-ctor(`[edi+0x50]`, 0xA8, 2) mLanes[2], `[edi+0x1A0..0x2B0]`
mOccupiedSlots inline, `sub_570300`×2 `AllocateFormationCoordCacheHeadNode`,
`[edi+0x2C8]` mForwardVector=vec0, `[edi+0x2D4]` mOrientation (by value),
`[edi+0x2E4]` mOrientationBaseline=kZeroQuaternion, `[edi+0x2F4]`
mScriptName(name, strlen), `[edi+0x310/0x314]` mFormationCenter, `[edi+0x318]`
mFormationUpdateScale=1.0f, `[edi+0x31C]` mPlanUpdateRequested=0, `[edi+0x320]`
mMaxUnitSlotCount=0. Guarded tail: `IsValid_Vector3f({center.x,0,center.z})` ->
forward-axis rebuild `fwd = (2(wy+zx), 2(zy-wx), 1-2(xx+yy))` when
`mOrientation != kZeroQuaternion` (Wm3 `{w,x,y,z}` order, K=2.0f @0x00DFEB0C) ->
reset occupied slots + both coord caches -> `UpdateFormation()`.

`ChooseFormation` (0x008384C0) itself landed in commit `0ea3da21` and already
calls `FORMATION_PickTravelFormation` by name; its drag threshold is exactly
`200.0f` (`.rdata` 0x00E4F8E4, bytes `00 00 48 43`). It still has no
source-level caller — that closes only when `ProcessMouse` lands, i.e. behind
this same blocker. Related: [[project_cformationinstance_split_blocked]],
[[project_caiformationinstance_runscript_chain]].
