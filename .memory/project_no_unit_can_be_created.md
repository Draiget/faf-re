---
name: project-no-unit-can-be-created
description: The black in-game screen and every downstream gameplay failure trace to one stub - Sim::CreateUnit returns nullptr because the Unit(SUnitConstructionParams) ctor at 0x006A53F0 was never recovered. Includes the reference-binary diff that proves it.
metadata:
  type: project
---

Found 2026-08-13 by diffing our `/map SCMP_009` log against the shipped
`ForgedAlliance.exe` on the same map (see
[[project-reference-binary-log-diff]] for the recipe - it remains the
highest-signal tool on this project).

## The one-line cause

`src/sdk/moho/sim/Sim.cpp` `Sim::CreateUnit` (0x007489E0) ends in

    // The constructor body at 0x006A53F0 is still pending reconstruction.
    return nullptr;

so **no unit can ever exist**. Everything below follows from that.

## The diff that proves it

| category | ours | ref |
|---|---|---|
| `Initialize Armies` | 1 | 9 |
| `Initialize Skirmish` | 0 | 7 |
| `CreateArmy` | 1 | 17 |
| `creating <fidelity> terrain` | **0** | 6 |
| `Failed to load mesh` | **5298** | 0 |
| `attempt to call method` | 15 | 0 |
| `Compiled shader` | 11 | 11 |
| `Preloading …` | identical | identical |

Shaders, mounts, preloads and search paths are all fine. The scenario
script dies at `scmp_009_script.lua:4` with `SetArmyStart() failed`,
which is `cfunc_SetArmyStartL` raising because `CreateUnitForScript`
returned null on the ACU. That aborts the army loop after ARMY_1, so
armies 2-8 never exist.

`creating … terrain` at 0 means `WRenViewport::AddWorldView` never runs
(it is the only caller of `IRenTerrain::Create`), so there is no terrain
renderer either - the client area measures `nonblack 0/18952` in-game
while the main menu measures `14091/18952`. The renderer itself is fine.

## The target

`Unit::Unit(const SUnitConstructionParams&)` = **FUN_006A53F0**, ~1400
instructions / 1088 decompiled lines, 79 callees at **ch=97%**,
`reach=yes`, `OK_RECOVERED_CALLER` (3 of 4 callers recovered). This is
the create-monster the older note called the wall.

Dependencies that were still missing when this was written:
- `AI_CreateAttacker` = FUN_005D62B0 (trivial: `new CAiAttackerImpl(unit)`, 0xA4)
- `CAiAttackerImpl::CAiAttackerImpl(Unit*)` = **FUN_005D6AA0** (44 lines).
  Careful: IDA labels the call site `??0CAiAttackerImpl@Moho@@QAE@@Z`, the
  *no-arg* mangling, but the site pushes two stack args and the target is
  0x005D6AA0, not the 0x005D69A0 default ctor we already have.

Everything else it needs already exists, including the 4-arg
`Entity::Entity(REntityBlueprint*, Sim*, EntId, int)` at 0x00677C90.

## Field-name trap

`SUnitConstructionParams::mUseLayerOverride` (+0x24) is **misnamed**.
Both params ctors show what it really is: 0x00585AB0 (full transform)
sets it to 1, 0x005F54D0 (position only, identity orientation) sets it to
0, and the Unit ctor only overwrites `mTransform.orient` when it is 0. It
means "an explicit orientation was supplied", not a layer override.

## Ordered body of FUN_006A53F0 (derived, ready to write)

Names on the right are the ones that already exist in our tree.

1. `id = sim->mEntityDB->DoReserveId(army->mConstDat.mIndex << 20)`,
   `sim = params.mArmy->GetSim()`.
2. `Entity(params.mBlueprint, sim, id, ENTITYTYPE_Unit)` - the 4-arg
   protected ctor at 0x00677C90, **not** the 2-arg one the
   deserialization ctor uses. Then `InstanceCounter<Unit>` +1.
3. `SSTIUnitConstantData` + `SSTIUnitVariableData` ctors, then the same
   zero-init block as `Unit::Unit(Sim*)` (Unit.cpp:13601) - that ctor is
   the template for steps 3-4; only the sources differ.
4. `CreatorRef` links to `params.mLinkSourceUnit`; `mCreationTick =
   sim->mCurTick`; armor-map sentinel; `PriorityBoost = 1`.
5. `VarDat().mMaxHealth = bp->Defense.MaxHealth`;
   `Health = params.mComplete ? bp->Defense.Health : 1.0f`;
   `FractionCompleted = (float)params.mComplete`; `BeingBuilt = 0`;
   `EntityAttributes::Initialize(bp)`.
6. `VarDat().mCreator` = creator's EntId or `0xF0000000`;
   `UnitAttributes(bp, sim->mRules)`; `VarDat().mCreationTick`;
   `SetAutoMode(bp->AI.InitialAutoMode)`; `RunScript("OnPreCreate")`.
7. `mIntelManager = new CIntel(&bp->Intel, sim, army->GetReconDB())`,
   deleting the previous one.
8. Orientation: only when `params.mUseLayerOverride == 0` (see trap
   above) - random roll `EulerRollToQuat(FRand(-0.52359879,
   0.52359879))` when `bp+628` and virtual slot 4 both say so, else the
   `quatX` identity global.
9. Placeholder mesh: `STR_ToLower(bp->Display.PlaceholderMeshName)`, and
   if non-empty `STR_Printf("/units/%s/%s_mesh", lower, lower)` ->
   `STR_CopyFilename` -> `rules->GetMeshBlueprint`. Then, only if the
   entity has no mesh yet, `SetMesh(bp->Display.MeshBlueprint, that, true)`.
10. `SetCurrentLayer(GetStartingLayer(pos, params.mLayer))`;
    `UpdateTerrainType(pos)`; unless `params.mFixElevation`,
    `pos.y = IUnit::CalcSpawnElevation(sim->mMapData, attrs, layer, xf)`.
11. Write `mLastTrans`, `AdvanceCoords()` **twice**, push the transform
    into both `AniActor` poses, then copy the two shared poses into
    `VarDat().mPriorSharedPose` / `mSharedPose`.
12. Motion: `switch (bp->Physics.MotionType)` - case 2 air, cases 1 and
    3..8 pathing, default **none**. With motion: `new CUnitMotion(this)`,
    `AI_CreatePathingNavigator`/`AI_CreateAirNavigator`,
    `AI_CreateSteering(this, motion, layer)`. Without motion: occupy the
    ground (`ExecuteOccupyGround`, `mIsOccupying = 1`) unless the unit is
    in category `FERRYBEACON` or `UPGRADE`.
13. Weapons: walk `bp->Weapon` (stride **0x184**); for each non-dummy
    entry create the attacker lazily (`AI_CreateAttacker`) and call
    `mAttacker->CreateWeapon(entry)`.
14. Builder: if the buildable list is non-empty **or** category
    `REBUILDER` -> `AI_CreateBuilder`. If also `FACTORY`, flag the
    builder and, when the unit has no motion, `ReserveOgridRect` over the
    floor/ceil of `RUnitBlueprint::GetSkirtRect`.
15. `SILO` -> `AI_CreateSiloBuilder`. Transport unless
    `!(attrs.mCommandCaps & 0x100) && !IsInCategory("PODSTAGINGPLATFORM")`.
16. `new CUnitCommandQueue(this)`, `AI_CreateCommandDispatch(this)`.
17. Add self to a local unit set and `army->Func9(set, "ArmyPool")`;
    builder rally point; `InitializeArmor()`; `RunScript("OnCreate")`.
18. Incomplete -> `UnitStateMask |= 1<<39`, `BeingBuilt = 1`,
    `Units_BeingBuilt` stat +1, `RunScript("OnStartBeingBuilt", creatorObj,
    layerName)`. Complete -> adjacency callbacks both ways for every
    overlapping unit (only when it has no motion),
    `RunScript("OnStopBeingBuilt", ...)`, and `Units_Active` +
    `Units_History` stats when `CapCost > 0`.
19. `army->Func14(this)`, then the six category flags: `mIsNotPod`
    (`POD` or `STATIONASSISTPOD`), `mIsEngineer`, `mIsNaval`, `mIsAir`,
    `mIsMelee`, `mUsesGridBasedMotion`.

## State as of 2026-08-13

Landed and committed: `8908b73` (engine-stats publisher, unrelated but real).

**In the tree, compiling, uncommitted:** `CAiAttackerImpl(Unit*)` +
`AI_CreateAttacker` in `src/sdk/moho/ai/CAiAttackerImpl.{h,cpp}`
(`tucheck EXITCODE=0`). They are orphans until the Unit ctor calls them,
so they must land in the *same* commit as it.

**Draft ctor body:** `<scratchpad>/unit_ctor_draft.cpp`. It was written
against guessed API names, so it did **not** compile and was reverted out
of `Unit.cpp` to keep the shared tree green - do not paste it back
without fixing the names below first.

Verified while drafting:

- `Sim::mEntityDB` is a `CEntityDb*` (Sim.h:1344), not `EntityDB*`.
- `RULEUMT_*` are 0..9. The navigator switch covers **1..8 only**;
  `RULEUMT_None` (0) *and* `RULEUMT_Special` (9) both fall through to the
  no-motion branch. A `default:`-creates-motion switch is wrong.
- `CAniActor` exposes only `GetPoseShared()` / `GetPriorPoseShared()`;
  there is no `GetPose()` / `GetPriorPose()`.
- `Entity::Attributes` is the `UnitAttributes` at +0x428, reachable as
  `VarDat().mAttributes`; `EntityAttributes::Initialize(const RUnitBlueprint*)`.
- `UnitAttributes(const RUnitBlueprint*, const RRuleGameRulesImpl*)`.
- `blueprint.Weapons.WeaponBlueprints` is the weapon vector; the "make a
  weapon" gate is `DummyWeapon == 0` at weapon+0x44.
- The builder gate reads `blueprint.Economy.BuildableCategories`
  (`msvc8::vector<msvc8::string>`, element size 0x1C - that is the `/28`
  in the decompile), or category `REBUILDER`.
- `CScriptObject::RunScript(const char*, Ts...)` is variadic, so
  `OnPreCreate` / `OnCreate` / `OnStartBeingBuilt` / `OnStopBeingBuilt` /
  `OnAdjacentTo` all go through it.

Still to resolve before the next apply:

- `SWeakRefSlot` (Entity.h:112) is layout-compatible with `WeakPtr<void>`
  but exposes no link helper of its own - find how another recovered
  site attaches one to its target before writing `CreatorRef`.
- `CArmyImpl::Func9(set, "ArmyPool")` and `Func14(unit)` from the
  decompile: `MakePlatoon` (0x00700410) is the likely `Func9`; confirm
  the vtable slot rather than guessing.
- The army-stat bump pair (`func_GetArmyStat2` + `sub_70E2B0` in the
  decompile, used for `Units_BeingBuilt` / `Units_Active` /
  `Units_History`), `SEntitySetTemplateUnit::Add`, the `gpg::STR_*`
  return conventions, and whether `Unit` has a const-data accessor
  matching `VarDat()`.

Related: [[project-lua-worker-wall-2026-07-15]], [[project-unit-ctor-pair-state]].
