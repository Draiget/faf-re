---
name: project-skirmish-load-completes
description: Skirmish load, sim construction, blueprint pipeline and army setup all work now; the remaining wall is the Unit constructor keystone.
metadata:
  type: project
---

As of 2026-08-12 a skirmish on `/maps/scmp_009` loads the map, builds the
sim, runs the whole blueprint pipeline, spawns 5182 props, creates the
armies and their brains, and reaches the point where each army spawns its
ACU. The run log went from 598 lines to ~121000 and no longer crashes.

**The one remaining wall is `Moho::Unit::Unit(const SUnitConstructionParams&)`,
`FUN_006A53F0`, 1948 instructions, 1088 lines of decompiled C.** `Sim::CreateUnit`
(`moho/sim/Sim.cpp`) currently logs "Unit constructor path (0x006A53F0) pending
lift" and returns nullptr, so `CreateInitialArmyUnit` reports
`SetArmyStart() failed`. **77 of its 79 callees are already terminal** - only
two are open, and both are small:

- `FUN_005D62B0` `AI_CreateAttacker(Unit*)` - 33 instrs, literally
  `new CAiAttackerImpl(0xA4)` + ctor. Its only caller is the Unit ctor, so it
  has to land in the same commit.
- `FUN_006B7B60` `CUnitMotion::CUnitMotion(Unit*)` - 493 instrs. The class
  layout is already recovered (`moho/unit/CUnitMotion.h`, 0x1D8) and the
  *default* ctor `FUN_006B78E0` is in `CUnitMotion.cpp`; only the
  `Unit*`-taking one is missing. The decompile is straightforward: a long
  field-init run, then physics body mass/inertia from the blueprint, pose from
  `Unit::GetTransform`, fuel ratio, terrain/water elevation, a sub-layer
  vertical-event callback, and for non-POD aircraft a random elevation offset
  drawn from `SimConVar_RandomElevationOffset` and the sim's Mersenne twister.

Recovering `CUnitMotion::CUnitMotion(Unit*)` additionally needs four symbols
that are not in the tree yet, all small: `CScriptObject::CallbackStr2`, the
`vertMotionEvent_names` string table it passes, `SimConVar_RandomElevationOffset`,
and `Unit::GetAttributes1`. `MultQuadVec`, `Entity::GetPhysBody`,
`Entity::IsInCategory`, `CHeightField::GetElevation` and
`CMersenneTwister::ShuffleState` are all present.

Field mapping for that ctor is already confirmed against the `.asm`
displacements - IDA's `v4` is `mStopRequested` (+0x10), `v2` is
`mFollowingWaypoint` (+0x08), `v17` is `mVector44`, `v26` is `mVector68`,
`v37`/`v38` are `mUnknownFloat94`/`mUnknownFloat98`, `v41`/`v42`/`v44` are
`mUnknownA4`/`mUnknownA8`/`mStateWordB0`, `v45` `mPreviousVelocity`, `v48`
`mBodyTiltOffset`, `v54`/`v57`/`v60` the three wobble vectors, `v66`
`mVector108`, `v69` `mRaisedPlatformUnit`, `v71` `mLayerTransitionTicks`, `v91`
`mEconomyRequest`. The existing default ctor at `CUnitMotion.cpp` initialises
the same field list and is the right template to copy.

That is the whole remaining chain to a spawned ACU.

## What had to fall to get here (commits on `master`, newest last)

1. `71b1614` - `CWldSessionLoaderImpl::Update` reported an aborted load and then
   `break`, where the binary falls through into `mLoaded = true`. One failed
   load reopened the assert dialog every frame (264 in a 100-second run).
2. `ff26bda` - `RRuleGameRulesImpl::ExportToLuaState` pushed rules-universe
   objects onto the session stack instead of calling `Moho::SCR_Copy`. See
   [[project-scr-copy-vs-pushstack]].
3. `a18c875` + `f13fcd8` - two terrain-load defects, see
   [[project-vtable-underdeclaration-trap]].
4. `b7b3b18` - the sim bootstrap thread was a placeholder lambda; recovered
   `CSimDriver::ThreadCreateSim` + `ThreadRun`. See
   [[project-simdriver-bootstrap-map]].
5. `a963835` - `CArmyImpl` +0x198 is one `EntityCategorySet` (0x28, running to
   `IsOutOfGame` at 0x1C0), not a 0x14 word vector plus padding plus an
   invented `OutOfGameContext`. Nothing constructed it, so seeding the army's
   build-restriction set from "ALLUNITS" memcpy'd through a null pointer.
   **This was the `BVIntSet::operator=` AV.**
6. `00d6d04` - `LuaObject::GetByName` did a metamethod-firing `lua_gettable`;
   the binary forwards to `operator[]`, a raw `luaH_get`. A miss walked the
   module environment chain into a handler that calls `error()`.
7. `0f4b099` - same fix for `SCR_GetLuaTableField`, which stands in for
   `GetByName` at every site that uses it.
8. `f67100f` - `Sim::Setup` read the map's prop list through a locally declared
   `SPropInfo` whose fields were in the opposite order to the `CWldPropEntry`
   the loader actually writes. See [[project-prop-record-layout]].
9. `73bf269` - **the big one for scripting**: every sim-side Lua binder
   registered into `CScrLuaMetatableFactory<CScriptObject*>` instead of the
   concrete class, and 15 of the 31 `moho.<x>_methods` class binders were inert
   "startup lane anchors" or missing. See [[project-lua-class-binders]].
10. `2c93df1` - `call_binTM`/`call_orderTM` used a hand-written helper that
    called `luaT_gettm` (returns null when absent) instead of
    `luaT_gettmbyobj` (returns the nil sentinel).
11. `69b75bf` - `PROP_Create(Sim*, VTransform const&, char const*)` was declared
    and used but never defined; `/FORCE` linked it into unmapped memory.
12. `7c2e17c` - three Lua faults, see [[project-lua-fork-vs-vendored-lib]].
13. `090a6d3` - the entity-category lookup table's +0x38 rules back-reference
    was left null, so the first economy restriction parsed during category
    setup dispatched `GetBlueprintFromOrdinal` through a null pointer.
14. `44dccc9` - `lua_getglobaluserdata` was declared but never defined, so it
    resolved to the vendored LuaPlus copy and read a stock `global_State`
    layout. Every sim binding that starts by asking for the `Sim` got null.

## How to reproduce / verify

`scratchpad/skirm.ps1 -Tag <n> -Map SCMP_009 -WaitSeconds 90`. Add `/spewbp` to
the command line (run `main.exe` directly, `skirm.ps1` takes no extra args) to
log every blueprint id as it registers - 678 unit blueprints is the current
correct count.

For a symbolised stack, `scratchpad/dbgrun.exe <exe> <workdir> [args...]` logs
OutputDebugString traffic and dumps a fully symbolised stack on any AV or
unhandled throw. It is far faster than eliminating candidate owners by
inspection - it found the `CArmyImpl` field owner in one run after two sessions
of guessing.
