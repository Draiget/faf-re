---
name: project-cuiworldview-render-vtable-cluster
description: The black-screen/crash blocker is CUIWorldView's null IRenderWorldView vtable; full scope, confirmed layout, and the three callee trees.
metadata:
  type: project
---

Started 2026-08-14. **This is the live blocker for "map renders / in-game UI works".**

## The defect

`WRenViewport::RenderAllHeads` (WxRuntimeTypes.cpp:64822) calls
`worldView->view->Func1()`. `view` is
`reinterpret_cast<IRenderWorldView*>(&view->mRenderVftable)` — a raw `void*`
field at CUIWorldView+0x11C that **nothing ever writes**. Null vptr →
`0xC0000005 read from 0x00000004` → 2nd-chance `0xC000041D` on the very first
WM_PAINT. That is why the window is black: the frame driver dies before
`WRenViewport::Render` ever draws terrain.

`WRenViewport::Render` itself only needs slot 3 (`GetCamera`) from the world
view — terrain, meshes, water and effects are all drawn by the viewport. So
**the moment the vtable is real, the map renders.** Every other slot is
overlay-only.

## Confirmed layout (hard `static_assert`s pass, so this is verified)

The binary's class is `CUIWorldView : CMauiControl (0..0x11B), CRenderWorldView
(0x11C..0x2A7)`. Every render-vtable method is compiled against the *sub-object*
pointer, so all of CUIWorldView's own fields belong to `CRenderWorldView`:

    +0x00 vptr   +0x04 mCamera   +0x08..0x17 cached view bounds
    +0x18 mOrthographic  +0x19 mIsMiniMap  +0x1A mEnableResourceRendering
    +0x1C mInputLocks  +0x20 mWorldViewDepth  +0x24 mState
    +0x2C mLeftMouseCommand (CommandModeData 0x60)   +0x8C mCommandData
    +0xEC mWldSession   +0xF0 mComGraph (boost::SharedPtrRaw<UICommandGraph>)
    +0xF8 mBuildDrag (CUIWorldViewBuildDragRuntimeView 0x60)
    +0x158 mConvertToPatrolCursor  +0x15A mHideResources
    +0x164 mCameraTrack (msvc8::string)  +0x180 mOverlayLink
    +0x188 mHighlightEnabled/mIconsVisible/mGlobalCameraCommands
    sizeof == 0x18C;  0x11C + 0x18C == 0x2A8 == sizeof(CUIWorldView)

Cross-checks that all landed: `Func1` tests `[this+0x19]` (mIsMiniMap) and hands
`this+0xF8` (mBuildDrag) to the update; `Render` reads `[this+0xEC]`
(mWldSession) and `[this+0x15A]` (mHideResources); `RenderCommandGraph` uses
`[this+0xF0]` (mComGraph). `mComGraph` is a **strong** `shared_ptr`, not a weak
one — 0x0086EDD0 is `assign_retain` and 0x00873780/0x00824060 are `release()`
(use_count at +4, dispose, weak_count at +8, destroy).

Vtable at PE 0x00E490DC (dumped, not inferred):
0 Render 0x0086EE00 · 1 Func1 0x0086ECB0 · 2 RenderCommandGraph 0x0086ECD0 ·
3 GetCamera 0x0086EBF0 · 4 GetCameraView 0x0086EBE0 · 5 GetCameraOffset
0x0086EC00 · 6 CameraGetTargetZoom 0x0086EC10 · 7 GetMaxZoom 0x0086EC20 ·
8 CameraGetZoom 0x0086EC30 · 9 Func2 0x007F6260 (base default, not overridden) ·
10 IsMiniMap 0x0086DC90 · 11 SetOrthographic 0x0086DC00 · 12 CanShake 0x0086DC60

## Why it is atomic

Slots 0, 2, 3, 4, 5, 6, 7, 8, 11, 12 are `_purecall` in `IRenderWorldView`'s own
vtable, so they are `= 0` in the base and a concrete `CUIWorldView` cannot exist
until all of them have bodies. No stub is permitted, so the whole tree lands in
one commit.

## Scope: three independent callee trees, ~4000 instructions

**Landed:** `f53b890` retypes `CUIWorldViewBuildDragRuntimeView::mPreviewPositions`
from a bespoke red-black tree (five hand-written helpers) to
`msvc8::map<CmdId, boost::shared_ptr<MeshInstance>>` — the container the binary
actually uses, and a prerequisite for tree B. Behaviour-neutral; re-ran the
skirmish and the only blocker is still `RenderAllHeads`.

**Work in progress, left UNCOMMITTED in the main tree** (compiles; the .cpp is
deliberately NOT in `src/sdk/main.vcxproj` yet, so it cannot break the build): `moho/ui/CRenderWorldView.cpp` with the
class + slots 3,4,5,6,7,8,10,11,12; `DrawUnitSkirt` (0x0085ABD0);
`DrawAllUnitSkirts` (0x0085AD80); `ui_FootprintMinThickness` (= 2.0f, read from
the PE at 0x00F57BD0); and a `ResolveCommandIssueHelperAnchorPosition` bridge in
CWldSession.h/.cpp that also un-orphans `ResolveCommandGraphAnchorHistoryWorldPosition`.

It stays uncommitted because **every piece of this cluster is an orphan until the
whole thing lands**: `DrawUnitSkirt` <- `DrawAllUnitSkirts` <- `DrawCommandGraph`
<- `RenderCommandGraph`, and `RenderCommandGraph` is a pure virtual that only
exists once the class is constructible. Confirmed from the xrefs: DrawCommandGraph
has exactly one caller (0x0086EDB3, inside RenderCommandGraph) and DrawAllUnitSkirts
exactly two, both inside the cluster. Do not "land it incrementally" - there is no
seam.

Honest size: ~24 functions / ~5000 instructions, i.e. 3-5 focused sessions. Order
that minimises risk: tree B (2 fns, no external deps, subsystem already typed) ->
`DrawEconomyOverlay` (682, every callee already recovered) -> tree C's
`DrawCommandGraph` half (needs only sub_854B70 + sub_7B4640) -> `sub_829190`'s half
(needs the `UICommandGraph` layout first) -> `RenderProjectileArcs` + its 7 helpers
-> the three slots + the MI change.

**A. `Render` (0x0086EE00, 126) — 5 of 7 callees already recovered.**
Missing: `CWldSession::DrawEconomyOverlay` 0x00858D80 (682),
`CRenderWorldView::RenderProjectileArcs` 0x008600E0 (751).

**B. `Func1` (0x0086ECB0, 13) — the crashing path.**
`sub_852C10` 0x00852C10 (562, = `CUIWorldViewBuildDragRuntimeView::UpdateDragPreview`)
→ `sub_8534F0` 0x008534F0 (691) → sub_855260, sub_855320, sub_8564E0, sub_856D60,
sub_857030, sub_7B29C0, UserUnitManager::Get, func_GetEntitiesUnderCursor.
`sub_8554D0`/`sub_855750` are `msvc8::vector::resize` template emissions — they
become plain `resize()` calls, not bodies.
Subsystem is already typed (`CUIWorldViewBuildDragRuntimeView` in UiRuntimeTypes.h),
so this tree is the most tractable of the three.

**C. `RenderCommandGraph` (0x0086ECD0, 80) — the expensive one.**
`sub_85AF40` (56) → `sub_829190` (478) → sub_8288D0, sub_8282B0, sub_828DD0,
`DisplayCommandNode`, `DrawPathPreview`; plus `DrawCommandGraph` 0x00853DC0 (260)
→ sub_854B70, sub_856860, sub_7B4640, sub_7B29C0, sub_7B33B0, DRAW_Circle,
GetSelectionUnits. ~~`UICommandGraph` has no layout model~~ **STALE - see the correction below.**

## Traps found while scoping

- `TerrainPlayableRectSource` (CWldMap.h) is a duplicate partial model of
  `STIMap`; use `CWldSession::GetSTIMap()` rather than adding another cast.
- `CopySharedToWeakCommandGraph` (CWldSession.cpp, 0x0086EDD0) models the
  command-graph assign with `weak_add_ref`/`weak_release`, but the binary uses
  the **strong** lane. Latent bug if it is ever called.
- `UserCommandIssueHelperRuntimeView` (UserUnit.cpp) and
  `CommandGraphAnchorHistoryRuntimeView` (CWldSession.cpp) are two private models
  of the same object; likewise `UserCommandTargetView` vs
  `CommandGraphAnchorSampleRuntimeView`. Public entry points that already exist
  and should be preferred: `ResolveCommandIssueHelperCommandType` (UserUnit.h)
  and the new `ResolveCommandIssueHelperAnchorPosition` (CWldSession.h).
- Editing UiRuntimeTypes.h with a python line-range move split the `CUIWorldView`
  class in half. The file is CRLF — always match `\r\n`, and re-read the seams
  after any scripted move.

See also [[project_ingame_ui_chain_2026_08_14]].

## Progress log

- `f53b890` build-preview lane -> `msvc8::map`.
- `0f335f4` `RefreshQueuedBuildGhosts` (FUN_008534F0) + 2 mis-typed fields.
- `bc50d73` `UpdateDragPreview` (FUN_00852C10) + 6 helpers un-orphaned.
  **Tree B is complete bar `Func1` (13 instrs, needs the class).**

### In progress: tree A, `CWldSession::DrawEconomyOverlay` (0x00858D80, 682)

Its only caller is `CRenderWorldView::Render` (slot 0). Every callee is an
already-recovered engine API (CD3DFont Create/Render2D/GetAdvance,
CD3DPrimBatcher SetViewMatrix/SetProjectionMatrix/SetTexture/DrawQuad/Flush,
`GeomCamera3::Project`, `UserEntity::GetInterpolatedPosition`, `STR_Printf`,
`D3D_GetDevice`, FUN_00426A50 which is already in CD3DFont.cpp) **except one**:

  - `func_ImportEconOverlayParams` at **0x00858850** (401 asm lines, not in
    `src/sdk/**`). It is a Lua import: `SCR_Import(state,
    "/lua/ui/game/econoverlayparams.lua")` then reads the `EconOverlayParams`
    table field-by-field into a set of file-scope globals
    (`EconOverlayParam_positiveColor`, ... , plus three
    `boost::shared_ptr<CD3DBatchTexture>` lanes decoded via `SCR_DecodeColor`
    and a texture loader). Recover it **first**, bottom-up, then
    `DrawEconomyOverlay`.

After tree A: `CRenderWorldView::RenderProjectileArcs` (0x008600E0, 751) + its
7 helpers (sub_515890, sub_562100, sub_860D20, sub_860E20, sub_860FB0,
sub_861320, sub_861D10), then tree C, then the three slots + the MI change.

#### `func_ImportEconOverlayParams` (0x00858850) - evidence gathered, ready to write

Nine optional fields off the `EconOverlayParams` table, each guarded by an
`IsNil` probe on a temporary before being re-read and consumed. All APIs
already exist in `src/sdk/**`: `SCR_Import(state, "/lua/ui/game/econoverlayparams.lua")`
(CScrLuaObjectFactory.h), `SCR_DecodeColor` (SCR_Color.h),
`CD3DBatchTexture::FromFile(name, border=1)` (CD3DBatchTexture.h), `UI_Manager`
(IUIManager.h). Globals and their PE addresses, taken from the store
instructions:

| global | address | type |
|---|---|---|
| `EconOverlayParam_positiveColor` | 0x00F57C00 | `std::uint32_t` (SCR_DecodeColor) |
| `EconOverlayParam_negativeColor` | 0x00F57BFC | `std::uint32_t` |
| `EconOverlayParam_leftTexture`   | 0x010C4230 | shared/weak `CD3DBatchTexture` |
| `EconOverlayParam_rightTexture`  | 0x010C4238 | ditto |
| `EconOverlayParam_midTexture`    | 0x010C4244 | ditto |
| `EconOverlayParam_fontName`      | 0x00F5B210 | `msvc8::string` |
| `EconOverlayParam_fontSize`      | 0x00F57C04 | `std::int32_t` (from GetNumber) |
| `EconOverlayParam_energyTopOffset` | 0x010A6458 | `float` |
| `EconOverlayParam_massTopOffset` | 0x00F57C08 | `float` |

**Settled:** all three texture lanes are plain 8-byte
`boost::shared_ptr<CD3DBatchTexture>`. At 0x00858A1A `esi` is loaded with the
*destination* global and 0x00858A24 calls `??0shared_ptr_CD3DBatchTexture@boost@@QAE@@Z`
against it; the `WeakPtr_CD3DBatchTexture::Release` right after is on the local
temporary FromFile returned, not on the global. The 4-byte gap at 0x010C4240 is
just linker ordering, not a wider lane.

## Progress log (cont.)

- `89dfe62` EntId reflected-type hijack fix (not cluster work, but it was
  killing every reflected `int` blueprint field - see the commit body).
- `2ceafd0` **tree A part 1 LANDED**: `ImportEconOverlayParams` (0x00858850)
  + `CWldSession::DrawEconomyOverlay` (0x00858D80, 682). `VMatrix4` gained
  `ProjectViewportDepthRow1` as a member (the dot product CEfxBeam.cpp /
  CEfxEmitter.cpp / CEfxTrailEmitter.cpp each carry a file-private copy of;
  added as a member so those three keep compiling untouched).

### Lesson: IDA frame deltas drift in this cluster

`FUN_00858D80`'s export has IDA frame deltas that are 4 and 8 bytes wrong
across the `__usercall` call sites, so the same logical slot is printed
under two names (`var_DC` written / `var_D8` read for the first
`GetAdvance` result). Resolved by tracing `esp` through every call's real
cleanup - script kept at `<scratchpad>/esptrace2.py`, it takes the `.asm`
and prints frame-relative offsets for every `[esp+disp]` operand. The
vertex mapping it produced was independently confirmed by
`CD3DPrimBatcher::DrawQuad`'s own parameter names (topLeft, topRight,
bottomRight, bottomLeft).

### LANDED `98fb020`: tree A part 2, `RenderProjectileArcs` (0x008600E0, 751)

**All eight "helpers" are container template emissions**, exactly like tree
B - so this is one struct plus one body, not nine functions:

| token | what it really is |
|---|---|
| FUN_00861320 (23) | `map::find` |
| FUN_00861C70 (14) | `map::lower_bound` (already in SimRecoveryRuntime.cpp) |
| FUN_00860E20 (113) | `map::operator[]` (find-or-insert, returns `&node->second`) |
| FUN_00861850 (18) | `map::_Insert` |
| FUN_00861510 (117) | RB-tree insert + rebalance |
| FUN_00860FB0 (235) | `map::erase(key)` |
| FUN_00861D10 (28) | `_Tree::iterator::_Inc` (already in SimRecoveryRuntime.cpp) |
| FUN_00860D20 (18) | `ProjectileArcTrack` copy-assign |
| FUN_00515890 (21) | `vector<Vector3f>::push_back` |
| FUN_00515E30 (107) | that vector's `_Insert_n` (already in FastVectorInsertLanes.cpp) |
| FUN_00562100 (100) | `vector<int>::push_back` grow half |
| FUN_0065F240 (76) | `fastvector` copy (already in FastVectorInsertLanes.cpp) |

**`ProjectileArcTrack` layout - derived, all offsets cross-checked:**

    alignas(8) struct ProjectileArcTrack {   // sizeof == 0xC30 == 3120
      bool mActive;                                  // +0x0000
      gpg::fastvector_n<Wm3::Vector3f, 256> mSamples;// +0x0008 (12+4+3072 = 0xC10)
      std::int32_t mTicksSinceSample;                // +0x0C18
      Wm3::Vector3f mLatestPosition;                 // +0x0C1C
      bool mVisible;                                 // +0x0C28
    };

Derivation: `FUN_00861D10` puts `_Isnil` at node+0xC49 and `_Left/_Parent/
_Right` at 0/4/8, so the node is the standard msvc8 `_Tree` node with
`_Color`@0xC48. `FUN_00861320` reads the key at node+0x10, and
`FUN_00860E20` returns `node+0x18`, so `_Myval` is `pair<const int, Track>`
placed at 0x10 (8-aligned) with the key at 0x10 and the track at 0x18.
That pins sizeof(Track) = 0xC48-0x18 = 0xC30 and forces Track's alignment
to 8 - which is also why `mSamples` sits at +0x08 rather than +0x04.
`FUN_00860E20`'s staging locals confirm the interior: inline buffer 3072
bytes (= 256 * 12) at +0x18 of the vector, then the int at +0xC18 and the
byte at +0xC28. `FUN_00860D20` copies exactly +0/+8/+3096/+3100/+3104/
+3108/+3112, matching.

The map itself is a file-scope `msvc8::map<std::int32_t,
ProjectileArcTrack>` whose head node pointer is the global at 0x010C4318
(so the map object starts at 0x010C4314: `{proxy, head, size}`).

Two CVars gate it: `Moho::UI_RenProjectileArcs` (0x010A645C, tested by
`Render` before the call), `UI_RenProjectileArcsSampleInterval`,
`UI_RenProjectileTrailColor` and `UI_RenProectileTrailWidth` (sic - the
binary's own spelling).

**TREE A IS COMPLETE.** `Render` (slot 0) now has both of its missing
callees. `ProjectileArcTrack` needed an explicit copy ctor - `msvc8::map`
builds its node with `value_type(k, mapped_type())` and
`gpg::fastvector_n` has no accessible copy, which is also exactly what
`FUN_00860D20` does by hand. `GeomCamera3::MakeViewportPixelProjection`
now holds the shared screen projection both overlays inline.

## What is left

1. **Tree C** - `RenderCommandGraph` (slot 2, 0x0086ECD0, 80):
   `sub_85AF40` (56) -> `sub_829190` (478) -> sub_8288D0 (303), sub_8282B0
   (202), sub_828DD0 (120), DisplayCommandNode, DrawPathPreview; plus
   `DrawCommandGraph` 0x00853DC0 (260) -> sub_854B70, sub_856860,
   sub_7B4640, sub_7B29C0, sub_7B33B0, DRAW_Circle, GetSelectionUnits.
   `UICommandGraph` **is** already modelled (see the correction below).
2. `Render` (126), `Func1` (13), `RenderCommandGraph` (80) - the three
   remaining slot bodies.
3. Flip `class CUIWorldView : public CMauiControl` to
   `: public CMauiControl, public CRenderWorldView`, replace the two
   `reinterpret_cast<IRenderWorldView*>(&view->mRenderVftable)` sites in
   UiRuntimeTypes.cpp (:18932 and :19030) with `static_cast`, fix the ctor
   (it placement-news `mCameraTrack` through the flat overlay), and add
   `moho/ui/CRenderWorldView.cpp` to `src/sdk/main.vcxproj`.
4. Re-run the skirmish: `RenderAllHeads` should stop faulting and the map
   should draw.

### CORRECTION (2026-08-14): `UICommandGraph` IS modelled

The earlier claim that it "has no layout model in `src/sdk/**` at all" is
**wrong** and cost scoping time. `CWldSession.cpp` carries the full thing
around line 1293-1480: `UICommandGraphNode` (0x54, with `mWaypointTexture`
@0x44 and `mArrowheadTexture` @0x4C), then `UICommandGraph` with
`mNeedsRebuild`, `mNodes`, `mSession`, `mSessionRes1`, `mDebugFont`, three
`HashTable<HashListNode{88,2C,10}>` lanes (`mMapAB0`, `mMapAB1`, `mMapC`,
`mMapD`), and a `CommandGraphTree`. The ctor (0x00824810) is fully
recovered and constructs all of them.

So tree C is **not** a subsystem-modelling job - it is seven bodies written
against an existing model:

| token | instrs | note |
|---|---|---|
| FUN_007B4640 | 16 | |
| FUN_0085AF40 | 56 | `RenderCommandGraph`'s direct callee |
| FUN_00828DD0 | 120 | |
| FUN_008282B0 | 202 | |
| FUN_00853DC0 | 260 | `DrawCommandGraph` |
| FUN_008288D0 | 303 | |
| FUN_00854B70 | 313 | |

`FUN_00829190` (478) is marked recovered but is an **elided stub** -
CWldSession.cpp:3267 literally says "Remaining command-graph mesh build
pass (0x00829190 chain) is pending deep lift". It needs a real body too.
`FUN_00856860`, `FUN_007B29C0`, `FUN_007B33B0` are genuinely in src.

### `16beafc`: skirt renderers landed + a real link bug

`DrawUnitSkirt` / `DrawAllUnitSkirts` moved out of the parked
`moho/ui/CRenderWorldView.cpp` into `UiRuntimeTypes.cpp` (their decls were
already in `UiRuntimeTypes.h`, and they are free functions - nothing about
them needs `CRenderWorldView`). They had to land before tree C because
`FUN_00828DD0` calls `DrawUnitSkirt`.

**Trap worth remembering:** `IRenderWorldView.h` forward-declared
`class GeomCamera3;` while `GeomCamera3.h` defines it as a `struct`. MSVC
mangles the class-key, so every TU that saw the `class` form first emitted
`CD3DPrimBatcher::SetViewProjMatrix` with a `V` where the definition had a
`U`, and the call went unresolved - invisibly, because `/FORCE` swallows
it. If the unresolved count moves off 16, diff the symbol list; a
class/struct mismatch looks exactly like a missing recovery.

### Tree C: next concrete step

`moho/ui/CRenderWorldView.cpp` (untracked, still not in the vcxproj) now
holds only the nine accessor slot bodies. Remaining tree C bodies, all
against the **already-modelled** `UICommandGraph`:

  1. `FUN_008282B0` (202) and `FUN_00828DD0` (120) - leaves;
     `FUN_00828DD0` calls `DrawUnitSkirt` (landed) and `CAM_GetCamera`.
  2. `FUN_008288D0` (303)
  3. `FUN_00829190` (478) - currently an **elided stub** at
     CWldSession.cpp:3267 ("pending deep lift"); replace it.
  4. `FUN_00854B70` (313), `FUN_00853DC0` (260) = `DrawCommandGraph`
  5. `FUN_0085AF40` (56) - trivial: `GetCommandGraph(&g, 0);
     if (g) sub_829190(...)` then release.
  6. `FUN_007B4640` (16) is `map<uint,WeakPtr<UserEntity>>::_Buynode`, a
     container emission - not a body.

Then the three slot bodies + the MI flip (step 3 of "What is left").

### Tree C decode notes gathered so far

`FUN_008282B0` (202) = **`UICommandGraph::DrawWaypoint`** - the assert
string inside it names the original file and line:
"c:\work\rts\main\code\src\user\UICommandGraph.cpp" line 881. Shape:

    helper = *(arg8 + 4);  if (!helper) return;
    index  = sub_8B4140(helper);                 // command-type -> node index
    node   = &this->mNodes[index];               // stride 0x54, mNodes at this+4
    tex    = node->mWaypointTexture;             // {px @0x44, pi @0x48}
    switch (sub_8281E0(this, arg8)) {            // 0/1/2, else HandleAssertFailure
      case 0: color = node[+40]; size = node[+52]; break;   // node+0x2C / +0x38
      case 1: color = node[+48]; size = node[+60]; break;
      case 2: color = node[+44]; size = node[+56]; break;
    }
    if (!tex) tex = CD3DBatchTexture::FromSolidColor(0xFF30F030);   // green fallback
    inv   = 1.0f / arg8[24];                     // the anchor's homogeneous w
    pos   = {arg8[12], arg8[16], arg8[20]} * inv;
    depth = dot(arg0[169..172], pos)             // arg0 is the camera: +0x2A4.. = viewport.r[2]
    scale = clamp(arg8[64] * size / depth, ui_MinWaypointSize, ui_MaxWaypointSize)
    // ground-plane quad in XZ around pos, y constant, uv (0,0)-(1,1)
    DrawQuad(eax0, arg0a, a4, v26)

`ui_MinWaypointSize` / `ui_MaxWaypointSize` are two more CVars to declare.

`FUN_00828DD0` (120) = draws one queued-build footprint: pulls the unit
blueprint through the node's command (`vtable +0x14`), builds an identity
`VTransform`, `MeshInstance::SetStance`s the node's mesh at the anchor,
then `DrawUnitSkirt(heightField, blueprint, CAM_GetCamera("WorldCamera")
->CameraGetView(), pos, session, batcher, colour)` where colour is
0xD800D800 or 0xD8D80000 depending on the node's `+30` flag. The height
field comes from `session(+3364)->...`, the anchor from the node's
`+12/+16/+20` divided by `+24`.

## Slot-2 tree is ATOMIC - proved by xrefs, 2026-08-14

Every function under `RenderCommandGraph` has exactly one code xref chain and
it roots at the slot itself. Checked with `<token>.xrefs.txt` owner lines:

| token | instrs | its only owner(s) | owner in src? |
|---|---|---|---|
| `sub_85AF40` | 56 | `CRenderWorldView::RenderCommandGraph` | no (slot 2) |
| `sub_829190` | 478 | `sub_85AF40` | no |
| `sub_8282B0` DrawWaypoint | 202 | `sub_829190` | no |
| `sub_828DD0` | 120 | `sub_829190` | no |
| `sub_8288D0` | 303 | `sub_829190` (x2) | no |
| `sub_8281E0` | ~40 | `sub_8282B0`, `sub_8288D0`, `DisplayCommandNode` 0x828610 | no |
| `sub_828280` | ~15 | `sub_8281E0` | no |
| `sub_831110` | ~80 | `sub_828280`, `sub_829800` | no |
| `sub_827A00` | ~250 | `sub_8288D0`, `DrawPathPreview` 0x82A380 | no |
| `Moho::DrawCommandGraph` 0x853DC0 | 260 | `CRenderWorldView::RenderCommandGraph` | no (slot 2) |
| `sub_854B70` | 313 | `Moho::DrawCommandGraph` | no |

The three alternate owners (`sub_829800`, `DrawPathPreview` 0x0082A380,
`DisplayCommandNode` 0x00828610) are all themselves unrecovered, so none of
them provides an escape hatch. **There is no legal partial commit**: the
source-level invocation rule means the whole ~2100-instruction set plus slot 2
plus the MI flip land together, or nothing does.

Slot 0 `Render` (0x0086EE00) is by contrast nearly free - its seven callees are
`RenderResources`, `RenderStrategicIcons`, `RenderProjectileIcons`,
`RenderMeshPreviews`, `DrawCommandSplats` (all five already present in
CWldSession.cpp as **comment-only stubs** - pre-existing elision debt, see
[[project_mesh_render_elision_debt]]), plus `RenderProjectileArcs` and
`DrawEconomyOverlay`, which are real as of 98fb020/2ceafd0.
Slot 1 `Func1` (0x0086ECB0) is 13 instructions over `sub_852C10`, already landed.

## The node layout `sub_829190` iterates (partially derived)

From `sub_8282B0` and `sub_828DD0`, the graph draw node is:

    +0x04  CommandIssueHelper* mCommand
    +0x0C  float x        (homogeneous)
    +0x10  float y
    +0x14  float z
    +0x18  float w
    +0x1C  bool  mIsBuildPreview
    +0x1E  bool  mPlacementValid   (0xD800D800 green vs 0xD8D80000 red)
    +0x20  MeshInstance* mMeshInstance
    +0x40  float mScale

`sub_8282B0` indexes `graph->mNodes[ResolveHelperCommandType(cmd)]` (stride
0x54) and picks colour/scale by `sub_8281E0`'s 0/1/2:
0 -> `mWaypointColor`/`mWaypointScale`, 1 -> **highlight** pair (+0x30/+0x3C),
2 -> **selected** pair (+0x2C/+0x38). Depth divisor is
`dot(camera.viewport.r[2].xyz, pos) + r[2].w` - note **row 2**, not the row 1
that `VMatrix4::ProjectViewportDepthRow1` serves.

`sub_8281E0(graph, node)` returns 0/1/2:
  1 if the command's entity set under the cursor is non-empty, or if
    `node->mCommand->field_4 == session->mCursorInfo.mIsDragger` (+0x4C8);
  2 if `sub_828280` says the command's entity set intersects
    `session + 0x4A0` (`mSelection`);
  0 otherwise.
It reaches the session as `graph->mSession` (+0xD24 = 3364) and reads the
flattened MouseInfo at +0x4B0. `IDA itself names it mCursorInfo` at
0x00853DC0's `GetLeftMouseButtonAction` call - more evidence for folding the
five flattened lanes into a real member.

**`sub_829190`'s decompile is unusable** - IDA overlays
`boost::detail::sp_counted_base_vtbl` on the hash-list nodes and turns the
node walk into vtable chasing. Do that one from the `.asm`.

## UICommandGraph ctor stubs - 2 of 3 landed (efeb819), CreateMeshes mapped

The ctor calls three loaders in a row and all three were comment-only:

| fn | addr | state |
|---|---|---|
| `LoadWaypointParams` | 0x00825150 | **landed** efeb819 |
| `LoadPathParams` | 0x00824D50 | **landed** efeb819 |
| `CreateMeshes` | 0x00828FB0 | open, cluster mapped below |

`LoadWaypointParams` declared seven globals that did not exist in the tree:
`ui_CurveSegments` 0x00F57CC0, `ui_CurveSmoothness` 0x00F57CC4,
`ui_PathSmoothness` 0x00F57CC8, `ui_CommandGraphMaxNodeUnits` 0x00F57CD0,
`ui_MinWaypointSize` 0x00F57CD4, `ui_MaxWaypointSize` 0x00F57CD8,
`ui_WaypointLineScale` 0x00F57CDC. Tree C needs the min/max waypoint sizes and
the line scale, so that dependency is now discharged.

**Original-source bug preserved:** 0x00825524 writes the Lua key
`ui_CommandClickScale` into `ui_WaypointLineScale`, the same global the
preceding block writes; there is no `ui_CommandClickScale` symbol in the image
at all. Last key defined in the Lua table wins the line scale.

`LoadPathParams` keys the per-command-type entries as
`REnumType::mPrefix + RRef::GetLexical()`, giving `UNITCOMMAND_Attack` etc.
`mPrefix` is at REnumType +0x64, which is exactly `sizeof(RType)` - the binary
reads straight past the base at 0x00824F3E rather than calling `IsEnumType()`.

### CreateMeshes closure - 12 functions, ~1280 .c lines, then it closes

Everything else it reaches is already recovered (`sub_81CFD0`, `sub_7B29C0`,
`sub_7B33B0`, `sub_831310`, `sub_824500`, `sub_8B72F0`, `sub_7DB020`,
`sub_8B4140`, `SpatialDB_MeshInstance::Collect`, `MeshMaterial::Create`,
`MeshRenderer::GetInstance`, `RBlueprint::GetLuaBlueprint`, `SCR_Import`).

| token | .c lines | notes |
|---|---|---|
| `FUN_00828FB0` CreateMeshes | 115 | root; **real callers already in src** (ctor + CWldSession.cpp:10201) |
| `FUN_00826740` | 101 | `SpatialDB_MeshInstance::Collect` + `IsInCategory` |
| `FUN_00826BA0` | 31 | walks the two lists at graph +3424 / +3384 |
| `FUN_008272A0` | 53 | recursive tick-propagation over node children (+68/+72/+76) |
| `FUN_00827360` | 126 | `MeshMaterial::Create` / `MeshRenderer::GetInstance` |
| `FUN_008275B0` | 228 | self-recursive only |
| `FUN_00826C50` | 110 | |
| `FUN_00826F10` | 173 | `RBlueprint::GetLuaBlueprint`, `SCR_Import` |
| `FUN_00824550` | 27 | |
| `FUN_00826000` | 82 | |
| `FUN_00826140` | 222 | |
| `FUN_007D5D90` | 14 | |

Because `CreateMeshes` already has real source callers, **this whole cluster is
committable in one pass** - unlike the slot-2 tree above, which has no legal
partial commit at all. Do this one first: it is what actually builds the
command-graph node list that the slot-2 draw code then renders.

## Runtime state after efeb819 (verified, dbg_tt1)

- Terrain types still load after the `SCR_LuaDoScript` swap - zero
  "No terrain types found" in the log.
- `WRenViewport::RenderAllHeads+0xDE` (WxRuntimeTypes.cpp:64822) still takes
  `ACCESS_VIOLATION` then `0xC000041D`. Unchanged and expected: that is the
  uninitialised `IRenderWorldView` vtable at +0x11C, which needs the MI flip,
  which needs slot 2, which needs the atomic tree above.

## 2026-08-14 (batch 3): the slot-2 seam, and the closure is 6 fns not 32

**The draw node slot-2 iterates IS `UICommandGraphDrawNode`** (landed 182c629,
mapped in [[project_uicommandgraph_drawnode]]). Every offset in the "node layout
sub_829190 iterates" section above matches the 0x78 payload at hash-node+0x10:
`+0x04` mCommand is `mHelperLink.mHead`, and the "homogeneous x/y/z/w" at
`+0x0C..+0x18` is really `mPositionSum` / `mWeight` — so `pos = xyz * (1/w)` is
a **centroid**, not a perspective divide. That cross-validation is what caught a
real bug: `+0x20/+0x24` is a **strong** `boost::shared_ptr<MeshInstance>`, and
the destructor must call `release()` (use_count at +4, then dispose) not
`weak_release()`. Fixed in **8f3b683**.

**Seam found (the note above was too pessimistic).** `CWldSession::
DrawCommandSplats` (0x008515B0, 748) is a comment-only stub already declared in
`CWldSession.h`, and it is a real caller of `DrawPathPreview`. Recovering it
*replaces a stub* rather than adding an orphan, and it un-orphans the whole
`DrawPathPreview` subtree — which slot 2 also needs via `sub_829190`. So the
remaining work splits into two commits instead of one 4700-instruction blob:

  - **Batch A** `DrawCommandSplats` + `DrawPathPreview` subtree.
  - **Batch B** the slot-2 remainder (~2175) + the three slot bodies + MI flip.

**Batch A is 5 real functions / ~2133 instrs, not the 32 the closure reports:**

| token | instrs | |
|---|---|---|
| FUN_008515B0 | 748 | `DrawCommandSplats` (replaces the stub) |
| FUN_0082A380 | 823 | `DrawPathPreview` |
| FUN_00827A00 | 386 | |
| FUN_0082A120 | 111 | **Ramer-Douglas-Peucker** polyline simplification: farthest point from the [a2,a3] segment, and if its distance beats the tolerance, splice it into the list and recurse on both halves |
| FUN_0082A2B0 | 65 | walks a WeakSet<UserEntity>, accumulates a float |

Everything else in that closure is **`std::list<Wm3::Vector3f>` /
`std::vector<Wm3::Vector3f>` machinery** and becomes plain container usage —
verified one by one, do not re-derive:
`8317B0` list `_Buynode` (20-byte node) · `82ECA0` list clear · `82ECE0`
`_Buynode(next,prev,Vector3f)` · `82BDA0` list dtor · `82BDF0` list push_back ·
`82D430` list head sentinel · `82ED20` list splice · `7E6460`
`uninitialized_fill_n<Vector3f>` · `7E4370` vector reserve · `7E4CE0` `_Xlen` ·
`7E3730` vector fill-construct · `8522A0` vector push_back · `852170` vector
reserve (initially mis-listed as behavioural).
`FUN_0044F7E0` (`Wm3::Vector3::Normalize`) and `FUN_0069DE70` are WildMagic —
terminal.

Leaves of batch B already decoded and ready to write:
`sub_828280` (14) = `cmd && SetsIntersect(GetEntitiesUnderCursor(cmd),
graph->mSession->mSelection)`; `sub_8281E0` (63) = the 0/1/2 highlight state
exactly as documented above; `sub_831110` (108) = sorted-set intersection test
over two `WeakSet<UserEntity>`, keyed on `entity ? (uintptr)entity - 8 : 0`.

### Batch A staging (uncommitted, `moho/ui/CRenderWorldView.cpp`, untracked)

`PickPathPreviewSubject` (**FUN_0082A2B0**, 65) is **written and tucheck-green**.
It picks the path-preview subject: the selection member with the largest
`blueprint->mSizeZ`, skipping `IsBeingBuilt()` units and any whose
`Physics.ResolvedFootprint` is null. Virtuals pinned, do not re-derive:

  - weak-set element -> `ResolveWeakEntitySetNodeEntity` (the `slot - 8` decode,
    already public in `UserUnit.h`), then `UserEntity::IsUserUnit()` = the
    binary's slot-3 call at 0x0082A2F8;
  - `IUnit` sits at `UserUnit+0x148` because `sizeof(UserEntity) == 0x148`;
    its **slot 7 is `GetBlueprint()`** (0x0082A306);
  - primary-vtable **slot 13 is `IsBeingBuilt()`** (0x0082A31E);
  - `RUnitBlueprint` reads: `+0x2FC` = `Physics.ResolvedFootprint`,
    `+0xB4` = `REntityBlueprint::mSizeZ`.

Weak-set iteration idiom to copy verbatim (from `IsQueuedBuildAlreadyUnderway`,
UiRuntimeTypes.cpp:9318): `PruneTombstonesAndFindLive(&node, head->mLeft)`, loop
`while (node != head)`, `Iterator_inc(&node)` then prune again.

Remaining batch A: `sub_827A00` (386), `DrawPathPreview` (823),
`DrawCommandSplats` (748, replaces the stub at CWldSession.cpp:11353) and
`sub_82A120` (111, Douglas-Peucker - fully understood, see above). Nothing in
batch A commits until `DrawCommandSplats` lands, because it is the only member
with a real caller.
