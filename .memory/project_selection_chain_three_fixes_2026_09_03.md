---
name: project_selection_chain_three_fixes_2026_09_03
description: "2026-09-03: THE IN-GAME UI IS BACK. Three stacked defects kept the session from ever holding a selection - UserUnit::IsSelectable had an inverted guard (82ced525), the session-listener registry dispatched the wrong vtable slot AND was wiped by static-init order (748fb964), and CWldSession's mSelection was never given its sentinel head (58f9b958). Orders panel, unit info panel and construction panel all render now."
metadata:
  type: project
---

## Symptom chain, and why it looked like a render bug

Operator report: "no commander spawning", "we do not have bottom UI", meshes
and terrain look wrong. The commander *was* spawning and *was* being drawn -
the missing piece was that **nothing was ever selected**, and FA's whole
bottom control cluster is selection-driven.

Measured, in order:

1. `MeshRenderer::Batch` collected 13 of **5356** live `MeshInstance`s. The
   spatial DB is healthy (4096 leaves, 971 non-empty, 5378 nodes, 117 leaves
   with 599 nodes inside the frustum) - the culling is the camera being parked
   at map centre 1052 units up, where every mesh is past its LOD fade cutoff
   (`fadePlane.w` = 1003.5 vs a 640 cutoff). **Not** a spatial-DB bug.
2. `CMauiFrame`'s root bounds are correct (1024x768), `controlClusterGroup`
   sits at Top=580 Bottom=768, not hidden, alpha 1, and **108 correctly
   laid-out controls live inside it**. They were simply all `IsHidden()`.
3. `orders.lua` hides the whole grid when the selection is empty, and
   `GetSelectedUnits()` was returning nil forever.

## The three defects

| commit | defect |
|---|---|
| `82ced525` | `UserUnit::IsSelectable` demanded `busy && mobile` to be selectable; ground truth rejects on `busy && mobile && !POD` |
| `748fb964` | the session-listener registry called the wrong vtable slot, and lost its entries to static-init order |
| `58f9b958` | `CWldSession::mSelection.mHead` was left null, so `SetSelection` never copied the new selection back |

### 1. `UserUnit::IsSelectable` (0x008C0500) - inverted first guard

The whole first block is one short-circuit conjunction whose result flag is
"reject", written 1 just before the POD test and cleared on every path that
continues (0x008C0522..0x008C056D, read the flag stores, not the decompile's
`if`). Rejecting case is `mIsBusy && IsMobile() && !IsInCategory("POD")` -
i.e. "a mobile passenger riding something is not individually selectable",
with attached PODs deliberately exempt. `+0x1A2` is `mUnitVarDat.mIsBusy`,
which the sim assigns from `mAttachInfo.HasAttachTarget()` (Unit.cpp:13278).

### 2. `IWldTeardownCallback` was really `ISessionListener`

FUN_00869870 dispatches **slot 0** (`(**v4)(v4, sWldSession)`) at session
creation; FUN_008698B0 dispatches **slot 1** (`(*(*v4 + 4))(...)`) at
teardown. Our `IWldTeardownCallback` had a virtual destructor in slot 0, so
its one method resolved to slot 1 in *both* - the creation pass detached
listeners that had never been attached.

And the registry was empty anyway: `msvc8::vector`'s default ctor is not
`constexpr`, so a namespace-scope `WldTeardownCallbackVector` got a dynamic
initialiser and joined static-init order. `SelectionListener`,
`PauseListener` and `IdleUnitSelector` all register from their own TU's
static initialiser, and those ran first - the vector's constructor then
null'd all three lanes on top of them. It is now a function-local static,
which is what the binary's zero-initialised static + atexit-guard shape
actually means.

### 3. `mSelection` had no sentinel head

`CWldSession`'s ctor hand-zeroed the member instead of constructing it.
Ground truth 0x00893465..0x00893497 calls `AllocateWeakEntitySetHead`
(sub_7B08D0), stamps `mIsSentinel` at `[eax+19h]` and self-links
`[eax]`/`[eax+4]`/`[eax+8]` - exactly `InitializeSelectionSetHeadStorage`
(0x007B25C0), a helper this same file already uses for every locally built
selection set.

## Technique worth reusing

`CMauiFrame::DumpGraph()` (0x007966F0) prints the entire UI control tree with
per-control `Hidden`/`Alpha`/`RenderPass` and resolved Left/Right/Top/Bottom.
Calling it once from `CMauiFrame::Frame` after ~2400 ticks answered "is the
bottom UI missing, mis-laid-out, or hidden?" in a single run. Pair it with a
counter in `CMauiFrame::RenderChildControls` (total / hidden / mask-rejected /
drawn, split by screen band) to separate layout from visibility from drawing.

`gpg::Warnf` probes plus a 95-120 s scripted run is the whole loop; the
engine's own log is the instrument. See
[[project_commander_spawn_crash_fixed_mesh_invisible]] for the mesh-side
equivalent.

## Still open after this

- The world camera never moves off (512, 1052, 511) looking straight down, so
  everything is at max LOD distance and the ACU is a few pixels. `UIZoomTo`
  *is* called with the avatar table - check `CameraImpl::TargetBox`.
- Terrain renders as a blurry base albedo with `normalMapCount=0`; no props
  or trees draw at all.
- Minimap is empty (`REN_RenderCartographic drew=0`).
- Selection-box release still faults in the small-block allocator
  (`PopLaneNode`, Global.cpp) - a peer session's in-flight heap-corruption
  hunt, probes still in the working tree.
