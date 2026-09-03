---
name: project-ingame-ui-chain-2026-08-14
description: The black screen was CreateUI aborting at its first statement. Five defects fixed in a row (GetByIndex, anims prefetch, camera alloc, SetWorldCamera, userArmies, Sim::Sync armies); now blocked on CUIWorldView's IRenderWorldView vtable at +0x11C being uninitialised.
metadata:
  type: project
---

Session of 2026-08-14. The sim had been running a full skirmish - ticking,
AI initialising, armies alive - and drawing nothing. Cause: `CreateUI`
(gamemain.lua:153) aborted at line 237, its **first** real statement, so
none of the interface was ever built. Everything below was found by
walking that one abort outward.

## Fixed this session (in order)

| Commit | Defect |
|---|---|
| 20d565c | `LuaObject::GetByIndex` read off the wrong thread's stack |
| 0242530 | `"anims"` prefetch kind never registered |
| cce39dd | camera allocated 4 bytes instead of 0x858; `func_SetWorldCamera` orphaned |
| 1f15452 | `CWldSession::userArmies` never sized |
| 74643a4 | `Sim::Sync` never published the army roster |

**`GetByIndex`** open-coded a push/`lua_gettable`/read-slot dance instead
of the binary's plain `luaV_gettable` on `m_object`. It pushed onto
`GetActiveCState()` (`l_G->lstate`, whichever coroutine runs) and read
back through `LuaStackObject(m_state, -1)` (`m_state->m_state`, the
root). Inside a sim coroutine those are different stacks, so every
lookup returned the root's top - in practice a stale
`"call expected but got nil\n stack traceback:"`. Class metatables are
fetched by index out of `__factory_objects`, so `CScrLuaObjectFactory::Get`
handed that string to every factory and `luaT_gettmbyobj` died on it.
**When a decompile shows `luaV_gettable`, do not route it through the
stack API - the two use different `lua_State`s.**

**`anims`**: `Prefetcher:Update` takes
`{d3d_textures, batch_textures, models, anims}`. Only the first three had
a `RES_RegisterPrefetchType`. FUN_00BC9280 registers `RScaResource` as
`"anims"`; without it `CPrefetchSet::Update` raises and unwinds CreateUI.

**Camera**: `RCamManager::CreateCamera` used `sizeof(CameraImpl)` - the
class is thin (one pointer) - so `operator new` returned 4 bytes and the
constructor wrote 0x858. `kCameraImplRuntimeSize` now sits next to the
class. `func_SetWorldCamera` was an offset-lane orphan in
`WinApiImportThunks.cpp` that the linker never resolved; the real body is
`ListLinkBefore` on the global `CameraTrackingListener`'s broadcaster.

## Open blocker

`WRenViewport::RenderAllHeads` (WxRuntimeTypes.cpp:64822) calls
`worldView->view->Func1()`. `view` is
`reinterpret_cast<IRenderWorldView*>(&view->mRenderVftable)` -
`CUIWorldViewCtorRuntimeView::mRenderVftable` at **+0x11C**, which
**nothing ever writes**. The binary's `CUIWorldView` multiply-inherits
`IRenderWorldView`, so the compiler emits the sub-object vtable there
(`??_7CUIWorldView@Moho@@6BIRenderWorldView@1@@`). Ours models it as a
raw slot and leaves it uninitialised, so slot 0 dispatches into garbage
and the paint callback dies with `0xC000041D`.

Fix is a layout job: give `CUIWorldView` the second base and real
overrides (`IRenderWorldView.h` lists the slots), or build the vtable
explicitly and store it at +0x11C in the constructor.

## Method notes

- The **Lua error probe** is the highest-value diagnostic here: log the
  message in `luaG_errormsg` before it throws, deduped **per
  `state->l_G`**. Errors swallowed by `pcall` never reach the log
  otherwise, and the sim state's errors will otherwise starve the budget
  before the UI's appear. Filtering by `l_G` separates sim from UI.
- A `func_LuaDoScript` probe logging every `/ui/` module load reconstructs
  the exact UI boot order and shows precisely where `CreateUI` stops -
  `borders.lua`/`economy.lua` absent while `tabs.lua` is present was the
  tell.
- `.nx2` is the **current** FAF patch, `.nx5` the older baseline - see
  [[project_gamedata_archive_precedence]]. Confirmed again here: the
  loaded `tabs.lua`/`gamemain.lua` line numbers match `lua.nx2`.

Related: [[project_userdata_metatable_is_a_string]] (closed by 20d565c),
[[project_black_screen_next_steps]].

## The CUIWorldView render-vtable cluster (next batch, fully scoped)

`sizeof(CMauiControl) == 0x11C`, and 0x0086E4EF stores
`??_7CUIWorldView@Moho@@6BIRenderWorldView@Moho@@@` (at 0x00E490DC) to
`[this+0x11C]`. So the binary's class is
`CUIWorldView : public CMauiControl, public IRenderWorldView` and plain
MI puts the sub-object vtable at exactly the right offset - no manual
vtable store needed once the base is declared.

Slots read straight out of the PE at 0x00E490DC:

| # | IRenderWorldView slot | address |
|---|---|---|
| 0 | `Render` | 0x0086EE00 |
| 1 | `Func1` | 0x0086ECB0 |
| 2 | `RenderCommandGraph` | 0x0086ECD0 |
| 3 | `GetCamera` | 0x0086EBF0 |
| 4 | `GetCameraView` | 0x0086EBE0 |
| 5 | `GetCameraOffset` | 0x0086EC00 |
| 6 | `CameraGetTargetZoom` | 0x0086EC10 |
| 7 | `GetMaxZoom` | 0x0086EC20 |
| 8 | `CameraGetZoom` | 0x0086EC30 |
| 9 | `Func2` | 0x007F6260 - **not overridden**, base default |
| 10 | `IsMiniMap` | 0x0086DC90 |
| 11 | `SetOrthographic` | 0x0086DC00 |
| 12 | `CanShake` | 0x0086DC60 |

Slots 3-8 are one-line forwarders to `mCamera` (+0x120, i.e. sub-object
+0x04 - which is why IDA types them on a `CRenderWorldView` whose first
field is `mCamera`). `Render` and `RenderCommandGraph` are the real work.

Also to unwind in the same pass: `CRenderWorldViewRuntimeHandle` in
UiRuntimeTypes.cpp models +0x11C as a *pointer to a render-world-view
object* and calls through it (4 call sites). That reading is wrong - the
slot is a vtable pointer - and those call sites become plain virtual
calls on `this` once the base is real.

## Callee tree under the render slots (batch 3 scope)

`c80495f` landed the interface retype. Declaring the base is blocked on
bodies for slots 0/1/2, which need six functions we do not have:

| callee | address | instrs |
|---|---|---|
| `sub_852C10` (Func1's body) | 0x00852C10 | 562 |
| `sub_85AF40` (RenderCommandGraph tail) | 0x0085AF40 | 56 |
| `Moho::DrawAllUnitSkirts` | 0x0085AD80 | 142 |
| `Moho::DrawCommandGraph` | 0x00853DC0 | 260 |
| `CWldSession::DrawEconomyOverlay` | 0x00858D80 | 682 |
| `CRenderWorldView::RenderProjectileArcs` | 0x008600E0 | 751 |

They are not leaves: `sub_85AF40` calls `sub_829190`, `DrawAllUnitSkirts`
calls `DrawUnitSkirt` / `sub_8B4140` / `sub_8B4080` / `sub_8BED50` plus
several `CD3DPrimBatcher` and `CD3DBatchTexture` methods. This is the
command-graph + prim-batcher render layer and is a multi-batch job.

Slots 3-8, 10, 11, 12 have no missing dependencies - they read
`CUIWorldViewCtorRuntimeView` fields (`mCamera` +0x120, `mCanShake`
+0x134, `mIsMiniMap` +0x135) and forward to `CameraImpl`. They can be
written the moment the base is declared, but the class cannot be
instantiated until all thirteen exist, so the base declaration and the
whole slot set have to land together.

**Build breakage on 2026-08-14 - self-inflicted, fixed in a4f5d52.**
`CConCommand.cpp` and `UiRuntimeTypes.cpp` stopped compiling mid-session:
`IN_BindKey` was not a member of `moho`, and `IN_ParseKeyModifiers` was
declared `const std::string&` while its definition and both call sites
use `msvc8::string`/`msvc8::scoped_string`.

Cause: while clearing debug probes I ran `git checkout --` on
`UiRuntimeTypes.h`. Its diff was NOT probe-only - it carried the
declarations belonging to the `IN_BindKey` batch, which is still
`in_progress` in the recovery DB (all 14 in-progress tokens are that
cluster). I had verified insertions-only for an earlier seven-file batch
and then reused the same reasoning on this header without re-checking it.

**Lesson: `git checkout --` is as destructive as `git stash` in this
shared checkout. Re-verify the diff of every single file immediately
before reverting it, not once for a batch.** Restoring the two
declarations took the build straight back to 0 errors / 16 unresolved.

## Clean-candidate pool audit (2026-08-14) - it is 80% traps

Query: blocked tokens, 25-250 instructions, at least one caller that is
`recovered` WITH `source_paths`, and zero callees outside
recovered/external/skip. That yields 79 tokens - 55 unnamed `sub_*`, 24
with real symbols. Of the 24 named:

- **20 are container/template emissions** - `std::map_*::find/insert/erase/
  Iterator::inc`, `std::vector_*::push_back/append`, `std::queue_*`,
  `boost::shared_ptr_*`, `WeakPtr_*` dtors, `_Xlen`. The skill says skip
  these, and [[feedback_no_duplicate_container_helpers]] agrees.
- **2 were already recovered, stale in the DB**: `FUN_00795540`
  (SCR_FromLua_CMauiEdit - body present, address annotation was wrong,
  fixed in 549c69b) and `FUN_0088C3F0` (WLD_DoInitializing - correctly
  annotated and wired at CWldSession.cpp:11683, DB just stale).
- **2 are genuinely open**: `FUN_00AAA815` func_GetCompatModeSub (25) and
  `FUN_00624130` func_LuaObjectFunction03 (29), both CRT/Lua-helper
  shaped, plus `FUN_007EEE50` func_RenderBuildRings (158).

`func_RenderBuildRings` is the only substantial one, and its decompile is
badly typed - IDA overlays a `CRenFrame` on the frame and compares
`shared_ptr` internals against 2 and 3. It needs `.asm` work plus a
layout for `sBlueprintExtractors` (a `std::map<string, RangeExtractor>`)
and three unnamed callees (`sub_7F01D0`, `sub_7F0380`, `sub_7F0310`).
Its caller lives in `RangeRenderer.h` - see
[[project_fabricated_recovery_and_container_dup]], which is exactly where
fabricated bodies landed before. Do this one with the disassembly open,
not from the decompile.

**Conclusion: the small-candidate frontier really is drained.** What is
left is the large atomic clusters - the render-vtable one above being the
highest value.

### func_RenderBuildRings (FUN_007EEE50) - not a single-function landing either

Read the `.asm` rather than the decompile (the decompile overlays a
`CRenFrame` on the frame and is unusable). The shape is clear:

    GetLeftMouseButtonAction(this, &mode, &mCursorInfo, 0)
    if (mode.mMode != 2 && != 3) return;  if (!mode.mBlueprint) return;
    for (node = a3->head; node != head; node = next) {
        rec = node + 0x30;                      // record: msvc8::string @+0x00,
                                                // BVIntSet @+0x28/+0x30/+0x34,
                                                // lanes @+0x48/+0x78/+0x80
        if (!GetRangeExtractor(rec->name)) continue;   // 0x007EDA40, recovered
        if (rec->name == "AllMilitary") continue;
        if (rec->name == "AllIntel") continue;
        if (!rec->categories.Contains(mode.mBlueprint->mBlueprintOrdinal)) continue;
        if (!extractor->Range(&payload, mode.mBlueprint, mouseWorldPos)) continue;
        sub_7F0380(out); sub_7F0310(&payload, out);
        func_RenderRings(a3, idx, rec+0x48, rec+0x78, out, ...);
    }

`RangeExtractor`, `SRangeExtractionPayload` and `GetRangeExtractor` are
all already recovered in `moho/misc/RangeExtractor.h`, and the bit test is
the same `EntityCategorySet` shape as `AddMappedBlueprintOrdinalBits`.
What is missing: the **ring-record layout** (unmodelled) and four more
functions - `func_RenderRings`, `sub_7F0380`, `sub_7F0310`, `sub_7F2050`.
So this is a small cluster with a layout task at its centre, not a
one-function commit. Its caller `RangeRenderer::Render` (0x007EEA00) is
recovered and would wire it.

## Render-vtable cluster: refined scope (batch 6/7 finding)

Checked every slot and callee by **DB status**, not by grepping for the
`sub_*` spelling - that grep is what made batch 4 overestimate the work
(callees are recovered under intent-first names, as the naming contract
requires).

**Nine of the thirteen slots already have real bodies**, as methods on
`CRenderWorldViewRuntimeView` in UiRuntimeTypes.cpp (~line 2197-2260):
slots 1, 3, 4, 5, 6, 7, 8, 10, 11, 12. They are correct code on the wrong
owner - a runtime view instead of the class's `IRenderWorldView` base -
so the MI conversion largely **moves** them onto `CUIWorldView` as
overrides.

Only two slots need new bodies:
  - slot 0 `Render` (FUN_0086EE00, 126 instrs)
  - slot 2 `RenderCommandGraph` (FUN_0086ECD0, 80 instrs)

and behind them the eight-function callee tree, all still blocked:
`DrawUnitSkirt` 97, `sub_85AF40` 56, `DrawAllUnitSkirts` 142,
`DrawCommandGraph` 260, `sub_829190` 478, `sub_852C10` 562,
`DrawEconomyOverlay` 682, `RenderProjectileArcs` 751 - about 3028
instructions.

**It is genuinely atomic.** A class with unimplemented pure virtuals
cannot be instantiated, so the base declaration, all thirteen slots and
the whole callee tree land in one commit. Nothing calls slots 0/2 until
the vtable is real (`RenderAllHeads` dispatches through it), so they
cannot be parked as free helpers first without orphaning them.

## The candidate filter is self-defeating - do not trust `status=recovered` on callers

Three false-recovered callers in two batches:
  - `FUN_007EEA00` RangeRenderer::Render - RangeRenderer.h:151 says in
    plain text "No body is recovered yet"; blocks `func_RenderBuildRings`.
  - `FUN_00AAA865` func_GetCompatMode - note claims a CPUID/SSE2 probe in
    CrtRuntimeHelpers.cpp; there is no `__cpuid`/`__readeflags` anywhere
    in src/sdk. Blocks `FUN_00AAA815` (its SEH SSE2 probe).
  - `FUN_00795540` SCR_FromLua_CMauiEdit - opposite direction: body was
    present, annotation wrong (fixed, 549c69b).

Any candidate query that filters on "caller has status=recovered"
*selects for* mis-marked entries, because that field is exactly what is
unreliable. Verify the caller's body in source before writing anything.
