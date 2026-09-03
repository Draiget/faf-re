---
name: project-treeb-build-drag-preview
description: Tree B of the CUIWorldView render-vtable cluster - decoded offsets and semantics for sub_8534F0 (LANDED) and sub_852C10 (analysed, not written).
metadata:
  type: project
---

Started 2026-08-14. Tree B is the **crashing path** of
[[project_cuiworldview_render_vtable_cluster]]: `Func1` (slot 1) ->
`sub_852C10` -> `sub_8534F0`.

## LANDED: `0f335f4`

`FUN_008534F0` = `CUIWorldViewBuildDragRuntimeView::RefreshQueuedBuildGhosts()`.
Rebuilds the ghost mesh for every queued mobile-build order into a fresh
`msvc8::map<CmdId, shared_ptr<MeshInstance>>` and swaps it over
`mPreviewPositions`.

**Every unrecovered callee was a container/shared_ptr template emission** of the
map lane f53b890 established, so the body is written against the container, not
against six hand-rolled node helpers:

| token | what it really is |
|---|---|
| FUN_00856D60 | `map::_Buynode` (head sentinel: `_Isnil=1`, self-links) |
| FUN_00855320 | `map::find` (already in src as `FindExactMapNodeFlag25RuntimeA`) |
| FUN_00855260 | `map::_Insert` w/ lower-bound hint = `operator[]` |
| FUN_008564E0 | `map::erase(first,last)` |
| FUN_00857030 | `pair<CmdId, shared_ptr>` construct |
| FUN_00855DF0 | `vector<shared_ptr<MeshInstance>>::_Insert_n` |
| FUN_00852AF0 | `map::~map` (erase-all + delete head) |
| FUN_007D5D90 | `shared_count::release` |

Constants read out of the shipped PE, not trusted from the decompiler:
`0x00DFEC20 = 1.0f` (identity quaternion `w`), `0x00E4F6E0 = 0.0f`
(the `mWorkProgress > 0` threshold), `0x00F57BD0 = 2.0f`
(`ui_FootprintMinThickness`).

Two public bridges added to `UserUnit.h/.cpp` (the file-private-helper trap):
`ResolveWeakEntitySetNodeEntity` (the `slot - 8` weak-owner decode) and
`ResolveUserUnitFrontCommandIssueHelper` (rebuild queue + take first live
entry - the binary open-codes it twice, at 0x008535F8 and 0x00853634).

## Mis-typed fields found (2 fixed in `0f335f4`, 1 open)

- **FIXED** `CUIWorldViewBuildDragRuntimeView+0x04` was `RUnitBlueprint*
  mActiveBuildBlueprint`; it holds an **`RMeshBlueprint*`** - FUN_00852C10 fills
  it from `mRules->GetMeshBlueprint(...)` (0x00852C75) then divides
  `[+0x64,+0x68)` by 204 (0x00852CD4) = `mLods` of 0xCC-byte
  `RMeshBlueprintLOD`. Now `mActiveBuildMesh`.
- **FIXED** `+0x40` was `ERuleBPUnitCommandCaps mCommandCaps`; it holds
  **`ECommandMode`** - FUN_00852C10 copies `CommandModeData::mMode` in at
  0x00852C9C and gates the preview on 2/3 = `COMMOD_Build` /
  `COMMOD_BuildAnchored`. Now `mActiveCommandMode`.
- **OPEN** `CWldSession+0x4B0` is a **flattened `MouseInfo`** (0x24 bytes,
  exact fit 0x4B0..0x4D3): `mCursorWorldState[4]`=`mHitValid`+pad,
  `CursorWorldPos`=`mMouseWorldPos`, `pad_04C0[8]`=`{mUnitHover,mPrevious}`,
  `HighlightCommandId`=**`mIsDragger`** (misnamed), `CursorScreenPos`=
  `mMouseScreenPos`. FUN_00852C10 passes `session + 0x4B0` straight to
  `GetLeftMouseButtonAction(out, const MouseInfo*, int)`. 31 call sites across
  the tree, so the consolidation is its own commit.

## LANDED: `bc50d73`

`sub_852C10` (0x00852C10, 562) = `UpdateDragPreview()`. Shape:

    CommandModeData mode;
    mSession->GetLeftMouseButtonAction(&mode, &cursorInfo, 0);
    activeMesh = mode.mBlueprint ? rules->GetMeshBlueprint(bp->Display.MeshBlueprint) : null;
    if (mActiveBuildMesh != activeMesh || mode.mMode != mActiveCommandMode) ClearBuildPreviewCache();
    mActiveBuildMesh = activeMesh;  mActiveCommandMode = mode.mMode;
    RefreshQueuedBuildGhosts();                                   // <- the landed body
    if (mode.mMode not in {COMMOD_Build, COMMOD_BuildAnchored}) -> mPreviewInvalid = 1, return
    if (!mActiveBuildMesh || mActiveBuildMesh->mLods.empty())   -> mPreviewInvalid = 1, return
    start = mStart; end = mEnd;
    if (!IsValidVector3f(start)) start = end = mode.mMouseDragStart.mMouseWorldPos;
    if (!IsValidVector3f(start) || !IsValidVector3f(end))       -> mPreviewInvalid = 1, return
    mPreviewInvalid = 0;
    rect = GetSTIMap()->mPlayableRect;      // {x0@+8, z0@+0xC, x1@+0x10, z1@+0x14}
    startCell = bp->mFootprint.ToCellPos(start);   // bp+0xD8 == REntityBlueprint::mFootprint
    endCell   = bp->mFootprint.ToCellPos(end);
    meshCount = mMeshes.size();  placed = 0;
    tmpl = mSession->GetActiveBuildTemplate(&spanZ, &spanX, &buffer);
    if (!buffer.Empty())  <template branch>  else  <single branch>
    if (meshCount > placed) { mMeshes.resize(placed); mBlueprints.resize(placed); }
    buffer.DestroyStorage();

Both branches step with `InitBuildDragStepStateAndReturnState`
(FUN_00822F60, already in UiRuntimeTypes.cpp as a `[[maybe_unused]]` orphan)
over `BuildDragStepStateRuntimeView {mX,mZ,mXStep,mZStep,mStepCount}`:

- step length = `abs(dx) > abs(dz) ? spanX : spanZ` (0x00852E8F)
- args: `(state, stepLength, (float)startCell.x, (float)startCell.z,
  (float)endCell.x, (float)endCell.z)` (pushes at 0x00852EB2..0x00852ED9)
- per step: `cell = {(short)state.mX, (short)state.mZ}`;
  `origin = COORDS_ToWorldPos(map, cell, layer, sizeX, sizeZ)`;
  then `mX += mXStep; mZ += mZStep; --mStepCount`.

**Template branch** (0x00852F60..0x008531E0), one stamp per template entry
(`SBuildTemplateInfo`, stride 0x2C):
`COORDS_ToWorldPos(map, cell, LAYER_None, 1, 1)`; per entry
`pos = origin + t.mPos`; `STR_InitFilename` the entry's `mBlueprintId` then
`rules->GetUnitBlueprint(path)` (**vtable +0x34** - slot 13, confirmed against
`EntityCategoryLookupResolver`); rect-test; `ApplyBuildTemplatePlacementPreviewStatus`
(FUN_00854930); Append-or-Replace; write `mesh->color` then `SetStance`.
Out-of-rect **skips the entry**.

**Single branch** (0x008532A0..0x00853433): layer/size come from the blueprint
footprint - `COORDS_ToWorldPos(map, cell, (ELayer)bp->mFootprint.mOccupancyCaps
/*+0xDA*/, bp->mFootprint.mSizeX /*+0xD8*/, bp->mFootprint.mSizeZ /*+0xD9*/)`;
rect-test **breaks the whole loop**; `ApplyCommandModeBuildPlacementPreviewStatus`
(FUN_00854860); Append, or overwrite `mBlueprints[placed]` in place (no
Replace call).

Append-vs-replace in both: `if (placed >= meshCount) { AppendBuildPreviewMesh(bp);
++meshCount; } else { ReplaceBuildPreviewMesh(placed, bp); }` then `++placed`.

### Settled: the two `__usercall` register mappings

`sub_854930` and `sub_854860` are `__usercall` and their recovered signatures in
CWldSession.cpp map **`esi` to `CWldSession&`** - but FUN_00852C10 passes
`esi = ebx = the drag object` (0x00853114) and `push ebx` (0x00853352). The drag
object's `+0x00` *is* `mSession`, so either the recovered signature is wrong
about `esi` or those helpers deref `[esi]`. Settled by reading the callees: FUN_00854930 does `mov ecx, [esi]` and passes
the result as `USERUNIT_CanBeBuiltAt`'s `CWldSession&` (0x00854937), so `esi`
IS the drag object and the session is its +0x00 lane. FUN_00854860 takes the
world position in `esi` and the drag object as its first stack arg. Public
bridges `EvaluateBuildTemplatePlacementPreview` /
`EvaluateCommandModeBuildPlacementPreview` added to CWldSession.h; both take
`CWldSession&` directly. Single-lane step length is **max**(SkirtSizeX,
SkirtSizeZ) - the `comiss`/`jbe` at 0x00853239 keeps the larger.

Landing `UpdateDragPreview` un-orphaned six existing `[[maybe_unused]]` helpers:
`AppendBuildPreviewMesh`, `ReplaceBuildPreviewMesh`, `ClearBuildPreviewCache`,
`InitBuildDragStepStateAndReturnState`, and the two `Apply*` placement helpers.
Its own caller `Func1` only exists once the whole cluster lands - there is still
no seam.

**Tree B is complete bar `Func1` (13 instrs).** Next: tree A -
`CWldSession::DrawEconomyOverlay` (0x00858D80, 682, every callee already
recovered) then `CRenderWorldView::RenderProjectileArcs` (0x008600E0, 751) +
its 7 helpers; then tree C.
