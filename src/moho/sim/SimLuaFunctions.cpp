#include "moho/sim/SimLuaPrivate.h"

namespace
{
  constexpr const char* kEndGameHelpText = "Signal the end of the game.  Acts like a permanent pause.";
  constexpr const char* kEntityAttachToHelpText = "Entity:AttachTo(entity, bone)";
  constexpr const char* kEntitySetOrientationHelpText = "Entity:SetOrientation(orientation, immediately )";
  constexpr const char* kEntitySetPositionHelpText = "Entity:SetPosition(vector,[immediate])";
  constexpr const char* kEntityGetPositionHelpText = "Entity:GetPosition([bone_name])";
  constexpr const char* kEntityGetPositionXYZHelpText = "Entity:GetPositionXYZ([bone_name])";
  constexpr const char* kEntityAttachFailureError = "Failed to attach entity %s to %s on bone %d";
  constexpr const char* kEntityGetCollisionExtentsHelpText = "Entity:GetCollisionExtents()";
  constexpr const char* kEntityIsIntelEnabledHelpText = "IsIntelEnabled(type)";
  constexpr const char* kEntityIsIntelEnabledInitWarning = "EnableIntel called before InitIntel";
  constexpr const char* kEntityEnableIntelHelpText = "EnableIntel(type)";
  constexpr const char* kEntityEnableIntelInitWarning = "EnableIntel called before InitIntel";
  constexpr const char* kEntityDisableIntelHelpText = "Intel:DisableIntel(type)";
  constexpr const char* kEntityDisableIntelInitWarning = "DisableIntel called before InitIntel";
  constexpr const char* kEntitySetIntelRadiusHelpText = "SetRadius(type,radius)";
  constexpr const char* kEntitySetIntelRadiusInitWarning = "SetIntelRadius called before InitIntel";
  constexpr const char* kEntityGetIntelRadiusHelpText = "GetIntelRadius(type)";
  constexpr const char* kEntityGetIntelRadiusInitWarning = "GetIntelRadius called before InitIntel";
  constexpr const char* kEntityInitIntelHelpText = "InitIntel(army,type,<radius>)";
  constexpr const char* kEntityInitIntelRadiusWarning = "Intel type requires a radius > 0.";
  constexpr const char* kEntityInitIntelUnknownArmyWarning = "Unknown army";
  constexpr const char* kEntityAddShooterHelpText = "AddShooter(shooter)";
  constexpr const char* kEntityRemoveShooterHelpText = "RemoveShooter(shooter)";
  constexpr const char* kCreatePropHelpText = "CreateProp(location,prop_blueprint_id)";
  constexpr const char* kEntityCreatePropAtBoneHelpText = "Entity:CreatePropAtBone(boneindex,prop_blueprint_id)";
  constexpr const char* kCreateResourceDepositHelpText = "type, x, y, z, size";
  constexpr const char* kUnknownResourceDepositTypeMessage = "unknown resource deposit type: %s";
  constexpr const char* kSessionIsReplayUserHelpText = "Return true iff the active session is a replay session.";
  constexpr const char* kRandomSimHelpText = "Random([[min,] max])";
  constexpr const char* kSelectedUnitHelpText =
    "unit = SelectedUnit() -- Returns the currently selected unit. For use at the lua console, so you can call Lua methods on a unit.";
  constexpr const char* kSimConExecuteHelpText = "SimConExecute('command string') -- Perform a console command";
  constexpr const char* kTryCopyPoseHelpText = "TryCopyPose(unitFrom,entityTo,bCopyWorldTransform)";
  constexpr const char* kFlattenMapRectName = "FlattenMapRect";
  constexpr const char* kFlattenMapRectHelpText = "FlattenRect(x, z, sizex, sizez, elevation)";
  constexpr const char* kParseEntityCategorySimHelpText = "parse a string to generate a new entity category";
  constexpr const char* kFlushIntelInRectHelpText = "FlushIntelInRect( minX, minZ, maxX, maxZ )";
  constexpr const char* kEntityCategoryCountAroundPositionHelpText =
    "Count how many units fit the specified category around a position";
  constexpr const char* kDebugGetSelectionHelpText = "Get DEBUG info for UI selection";
  constexpr const char* kPrintSimHelpText = "Print a log message";
  constexpr const char* kCheatsEnabledHelpText =
    "Return true iff cheats are enabled.  Logs the cheat attempt no matter what.";
  constexpr const char* kAudioSetLanguageSimHelpText = "AudioSetLanguage(name)";
  constexpr const char* kSubmitXMLArmyStatsHelpText = "Request that we submit xml army stats to gpg.net.";
  constexpr const char* kShouldCreateInitialArmyUnitsHelpText = "";
  constexpr const char* kListArmiesHelpText = "";
  constexpr const char* kGenerateArmyStartHelpText = "army";
  constexpr const char* kArmyInitializePrebuiltUnitsHelpText = "army";
  constexpr const char* kArmyIsCivilianHelpText = "ArmyIsCivilian(army)";
  constexpr const char* kOkayToMessWithArmyHelpText =
    "Return true if the current command source is authorized to mess with the given army.  Or if cheats are enabled.";
  constexpr const char* kArmyIsOutOfGameHelpText =
    "ArmyIsOutOfGame(army) -- return true iff the indicated army has been defeated.";
  constexpr const char* kArmyGetHandicapHelpText = "army";
  constexpr const char* kInitializeArmyAIHelpText = "army";
  constexpr const char* kWarpHelpText = "Warp( unit, location, [orientation] )";
  constexpr const char* kChangeUnitArmyHelpText = "ChangeUnitArmy(unit,armyIndex) Change a unit's army";
  constexpr const char* kGenerateRandomOrientationHelpText = "rotation = GenerateRandomOrientation()";
  constexpr const char* kDrawLineHelpText = "Draw a 3d line from a to b with color c";
  constexpr const char* kDrawLinePopHelpText =
    "Draw a 3d line from a to b with color c with a circle at the end of the target line";
  constexpr const char* kDrawCircleHelpText = "Draw a 3d circle at a with size s and color c";
  constexpr const char* kPlayLoopHelpText = "handle = PlayLoop(self,sndParams)";
  constexpr const char* kStopLoopHelpText = "StopLoop(self,handle)";
  constexpr const char* kSpecFootprintsHelpText = "SpecFootprints { spec } -- define the footprint types for pathfinding";
  constexpr const char* kRegisterUnitBlueprintHelpText = "UnitBlueprint { spec } - define a type of unit";
  constexpr const char* kRegisterPropBlueprintHelpText = "PropBlueprint { spec } - define a type of prop";
  constexpr const char* kRegisterProjectileBlueprintHelpText =
    "ProjectileBlueprint { spec } - define a type of projectile";
  constexpr const char* kRegisterMeshBlueprintHelpText = "MeshBlueprint { spec } - define mesh properties";
  constexpr const char* kRegisterTrailEmitterBlueprintHelpText =
    "TrailEmitterBlueprint { spec } - define a polytrail emitter";
  constexpr const char* kRegisterEmitterBlueprintHelpText = "EmitterBlueprint { spec } - define a particle emitter";
  constexpr const char* kRegisterBeamBlueprintHelpText = "BeamBlueprint { spec } - define a beam effect";
  constexpr const char* kBlueprintLoaderUpdateProgressHelpText = "";
  constexpr const char* kNoActiveSessionText = "No active session";
  constexpr const char* kEntityCategoryCountHelpText = "Count how many units fit the specified category";
  constexpr const char* kEntityCategoryContainsUserHelpText = "See if a unit category contains this unit";
  constexpr const char* kEntityCategoryCountInvalidTableText =
    "Pass in invalid table of units to EntityCategoryFilterDown!!.";
  constexpr const char* kEntityCategoryFilterDownUserHelpText =
    "Filter a list of units to only those found in the category";

  /**
   * `EEntityAttribute` lane of one `EIntel` value: the binary computes it as
   * `intel - 1` and range-checks it against 12 (`lea edx,[eax-1]; cmp edx,0Ch;
   * ja` at 0x0068E76A / 0x0068E946 / 0x0068ECE7 / 0x0068E1FA).
   */
  [[nodiscard]] constexpr moho::EEntityAttribute IntelAttributeLane(const moho::EIntel intelType) noexcept
  {
    return static_cast<moho::EEntityAttribute>(static_cast<std::int32_t>(intelType) - 1);
  }

  [[nodiscard]] constexpr bool IsIntelAttributeLane(const moho::EIntel intelType) noexcept
  {
    return static_cast<std::uint32_t>(IntelAttributeLane(intelType)) <= static_cast<std::uint32_t>(moho::ENTATTR_SonarStealth);
  }

  [[nodiscard]] gpg::RRef MakeEIntelRef(moho::EIntel* const intelType)
  {
    gpg::RRef enumRef{};
    if (intelType == nullptr) {
      return enumRef;
    }

    static gpg::RType* sEIntelType = nullptr;
    if (sEIntelType == nullptr) {
      sEIntelType = gpg::LookupRType(typeid(moho::EIntel));
    }

    enumRef.mObj = intelType;
    enumRef.mType = sEIntelType;
    return enumRef;
  }

  [[nodiscard]] moho::CIntelPosHandle* ResolveIntelPosHandleForType(
    moho::CIntel& intelManager, const moho::EIntel intelType
  ) noexcept
  {
    // Original InitIntel and Lua bindings index the owning slots by EIntel;
    // slot 0 is unused and Vision through CloakField occupy slots 1 through 8.
    const int intelIndex = static_cast<int>(intelType);
    if (intelIndex < static_cast<int>(moho::INTEL_Vision)
        || intelIndex >= static_cast<int>(moho::INTEL_Jammer)) {
      return nullptr;
    }

    const std::size_t handleSlot = static_cast<std::size_t>(intelIndex);
    if (handleSlot >= moho::CIntel::kHandleCount) {
      return nullptr;
    }

    return intelManager.mIntelHandles[handleSlot].get();
  }

  [[nodiscard]] const moho::CIntelPosHandle* ResolveIntelPosHandleForType(
    const moho::CIntel& intelManager, const moho::EIntel intelType
  ) noexcept
  {
    // Original InitIntel and Lua bindings index the owning slots by EIntel;
    // slot 0 is unused and Vision through CloakField occupy slots 1 through 8.
    const int intelIndex = static_cast<int>(intelType);
    if (intelIndex < static_cast<int>(moho::INTEL_Vision)
        || intelIndex >= static_cast<int>(moho::INTEL_Jammer)) {
      return nullptr;
    }

    const std::size_t handleSlot = static_cast<std::size_t>(intelIndex);
    if (handleSlot >= moho::CIntel::kHandleCount) {
      return nullptr;
    }

    return intelManager.mIntelHandles[handleSlot].get();
  }

  [[nodiscard]] moho::CIntelToggleState* ResolveIntelToggleStateForType(
    moho::CIntel& intelManager, const moho::EIntel intelType
  ) noexcept
  {
    // 0x0068E1F1 reaches the lane with `mov [ecx+eax*2+13h], 1`, indexing the
    // toggle block by the raw `EIntel` value -- so the lane order is the enum
    // order from `INTEL_Jammer` on, which is exactly `CIntel::mToggleStates`.
    const int toggleIndex = static_cast<int>(intelType) - static_cast<int>(moho::INTEL_Jammer);
    if (toggleIndex < 0 || toggleIndex >= static_cast<int>(moho::CIntel::kToggleCount)) {
      return nullptr;
    }

    return &intelManager.mToggleStates[static_cast<std::size_t>(toggleIndex)];
  }

  [[nodiscard]] const moho::CIntelToggleState* ResolveIntelToggleStateForType(
    const moho::CIntel& intelManager, const moho::EIntel intelType
  ) noexcept
  {
    const int toggleIndex = static_cast<int>(intelType) - static_cast<int>(moho::INTEL_Jammer);
    if (toggleIndex < 0 || toggleIndex >= static_cast<int>(moho::CIntel::kToggleCount)) {
      return nullptr;
    }

    return &intelManager.mToggleStates[static_cast<std::size_t>(toggleIndex)];
  }

  void RequeueEntityCoordUpdate(moho::Entity& entity) noexcept
  {
    entity.ListLinkBefore(&entity.SimulationRef->mCoordEntities);
  }

  [[nodiscard]] bool IsIntelEnabledForType(const moho::CIntel& intelManager, const moho::EIntel intelType) noexcept
  {
    if (const auto* const handle = ResolveIntelPosHandleForType(intelManager, intelType); handle != nullptr) {
      return handle->mEnabled != 0u;
    }

    const moho::CIntelToggleState* const toggleState = ResolveIntelToggleStateForType(intelManager, intelType);
    if (toggleState == nullptr) {
      return false;
    }
    return toggleState->present != 0u && toggleState->enabled != 0u;
  }

  /**
   * Address: 0x0074B550 (FUN_0074B550)
   *
   * What it does:
   * Receives one concatenated print line from `SCR_ConcatArgsAndCall` and
   * forwards it into the active sim log lane.
   */
  void PrintSimConcatSink(LuaPlus::LuaState* const state, const char* const text)
  {
    if (!state || !state->m_state) {
      return;
    }

    if (Sim* const sim = ResolveGlobalSim(state->m_state); sim != nullptr) {
      sim->Printf("%s", text != nullptr ? text : "");
    }
  }

  [[nodiscard]] CScrLuaInitFormSet& CoreLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Core"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("Core");
    return fallbackSet;
  }


  [[nodiscard]] const REntityBlueprint* ResolveEntityCategoryCountBlueprint(
    const LuaPlus::LuaObject& valueObject,
    RRuleGameRulesImpl* const rules
  )
  {
    if (valueObject.IsString()) {
      const char* const blueprintText = valueObject.GetString();
      if (!blueprintText || !rules) {
        return nullptr;
      }

      RResId blueprintId{};
      gpg::STR_SetFilename(&blueprintId.name, blueprintText);
      return rules->GetEntityBlueprint(blueprintId);
    }

    Entity* const entity = SCR_FromLuaNoError_Entity(valueObject);
    return entity ? entity->BluePrint : nullptr;
  }

  /**
   * Address: 0x00758DB0 (FUN_00758DB0, sub_758DB0)
   *
   * What it does:
   * Copies the active sync-filter `maskB` bitset payload into one temporary
   * `BVIntSet` used by `cfunc_DebugGetSelectionL`.
   */
  void CopyDebugSelectionMaskB(const Sim& sim, BVIntSet& outSelectionIds)
  {
    outSelectionIds.mReservedMetaWord = 0u;
    outSelectionIds.mFirstWordIndex = sim.mSyncFilter.maskB.mFirstWordIndex;
    outSelectionIds.mWords.ResetFrom(sim.mSyncFilter.maskB.mWords);
  }
}



/**
 * Address: 0x00528550 (FUN_00528550, cfunc_SpecFootprintsL)
 *
 * What it does:
 * Loads one Lua table-array of footprint specs into the rules footprint list,
 * warning and skipping duplicate named entries.
 */
int moho::cfunc_SpecFootprintsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  // 0x00528550: `(*TLS)->rules->mFootprints` -- the rules object the blueprint
  // loader is currently filling, which is the same thread-local the
  // Register*Blueprint bindings read. `Sim::mRules` is not published yet while
  // `LoadBlueprints` runs, so resolving through the sim left the footprint table
  // empty and every ground unit's `ResolvedFootprint` null.
  RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
  if (!rules) {
    return 0;
  }

  gpg::ScopedLogContext footprintScope("Initializing footprint groups");

  fa::list<SNamedFootprint>& footprints = rules->mFootprints.mFootprints;
  lua_State* const rawState = state->m_state;
  const LuaPlus::LuaObject footprintSpecsObject(LuaPlus::LuaStackObject(state, 1));
  const int footprintSpecCount = footprintSpecsObject.GetCount();
  for (int luaIndex = 1; luaIndex <= footprintSpecCount; ++luaIndex) {
    SNamedFootprint footprint{};
    footprint.mIndex = static_cast<std::int32_t>(footprints.size());

    lua_rawgeti(rawState, 1, luaIndex);
    const LuaPlus::LuaObject footprintObject(LuaPlus::LuaStackObject(state, lua_gettop(rawState)));

    const LuaPlus::LuaObject nameObject = footprintObject.GetByName("Name");
    const char* const nameText = nameObject.GetString();
    footprint.mName = nameText ? nameText : "";

    const LuaPlus::LuaObject sizeXObject = footprintObject.GetByName("SizeX");
    footprint.mSizeX = static_cast<std::uint8_t>(sizeXObject.GetInteger());

    const LuaPlus::LuaObject sizeZObject = footprintObject.GetByName("SizeZ");
    footprint.mSizeZ = static_cast<std::uint8_t>(sizeZObject.GetInteger());

    const LuaPlus::LuaObject capsObject = footprintObject.GetByName("Caps");
    footprint.mOccupancyCaps = static_cast<EOccupancyCaps>(capsObject.GetInteger());

    const LuaPlus::LuaObject minWaterDepthObject = footprintObject.GetByName("MinWaterDepth");
    if (minWaterDepthObject) {
      footprint.mMinWaterDepth = static_cast<float>(minWaterDepthObject.GetNumber());
    }

    const LuaPlus::LuaObject maxWaterDepthObject = footprintObject.GetByName("MaxWaterDepth");
    if (maxWaterDepthObject) {
      footprint.mMaxWaterDepth = static_cast<float>(maxWaterDepthObject.GetNumber());
    }

    const LuaPlus::LuaObject maxSlopeObject = footprintObject.GetByName("MaxSlope");
    if (maxSlopeObject) {
      footprint.mMaxSlope = static_cast<float>(maxSlopeObject.GetNumber());
    }

    const LuaPlus::LuaObject flagsObject = footprintObject.GetByName("Flags");
    if (flagsObject) {
      footprint.mFlags = static_cast<EFootprintFlags>(flagsObject.GetInteger());
    }

    // 0x005288AC..0x00528942: the scan runs to the end, warning at every
    // entry of the same name, and the spec is appended only when none matched.
    bool isDuplicate = false;
    for (const SNamedFootprint& existing : footprints) {
      if (existing.mName == footprint.mName) {
        isDuplicate = true;
        gpg::Warnf("Ignoring duplicate footprint spec %s", footprint.mName.c_str());
      }
    }

    if (!isDuplicate) {
      footprints.push_back(footprint);
    }
  }

  return 0;
}

/**
 * Address: 0x005284D0 (FUN_005284D0, cfunc_SpecFootprints)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_SpecFootprintsL`.
 */
int moho::cfunc_SpecFootprints(lua_State* const luaContext)
{
  return cfunc_SpecFootprintsL(moho::SCR_ResolveBindingState(luaContext));
}
namespace
{

  [[nodiscard]] EntityCategoryLookupTable* ResolveEntityCategoryLookupTable(RRuleGameRulesImpl& rules) noexcept
  {
    // `mEntityCategoryLookup` is already `EntityCategoryLookupTable*`
    // (RRuleGameRules.h) -- no cast needed now that this file shares that
    // type instead of reinterpret_casting its own separate duplicate.
    return rules.mEntityCategoryLookup;
  }

  /**
   * Address: 0x005555C0 (FUN_005555C0)
   *
   * IDA signature:
   * int __thiscall sub_5555C0(std::vector *this, std::string *a2,
   *                           Moho::RUnitBlueprint *arg4);
   *
   * What it does:
   * Looks the category name up in the entity-category lookup map
   * (`categoryMap.find`, 0x005561C0 -- `Address:` on `rb_tree::find_node`,
   * RbTree.h), inserts a fresh node when the lookup misses
   * (`categoryMap.insert`, 0x005560B0 -- `Address:` on
   * `rb_tree::insert_unique`, RbTree.h), then sets this blueprint's bit in
   * that node's `BVIntSet`. The binary reaches the set as `node + 56`,
   * which is `it->second.Bits()` here (`CategoryLookupValue` inherits
   * `EntityCategorySet::Bits()`).
   *
   * FUN_00556320's role (previously unresolved): it is the compiler-emitted
   * 2-argument converting constructor of `CategoryLookupMap::value_type`
   * (`pair<const fa::string, CategoryLookupValue>`), materialising the
   * temporary this function passes to `insert()`. The binary builds that
   * temporary's second half inline as "an empty `BVIntSet` seeded with
   * `lookup->mRules`" (0x00555601-0x00555625 hand-assembles a
   * `FastVectorN<uint,2>`-shaped empty vector on the stack, pointing its
   * inline storage at itself) rather than calling a named `ResetToEmpty` --
   * that inlining is why the key-assign and value-reset land in one fused
   * emission instead of the two-step shape a literal transcription of
   * `node->key = name; node->value.ResetToEmpty(handle);` would produce.
   * `FUN_00557310`, `buy_node`'s (FUN_005569C0) own value construction, is
   * the *other* `pair` constructor MSVC8 emits for this instantiation -- the
   * copy constructor invoked when `insert_at` copies the already-built
   * temporary into the freshly linked node. Both are `std::pair`
   * constructor emissions with no hand-written body of their own (RULE ONE);
   * writing `CategoryLookupMap::value_type(categoryName, freshValue)` below
   * is what makes the compiler emit both, matching the binary's two-step
   * construct-then-copy exactly.
   *
   * KNOWN FIDELITY DIVERGENCE (pre-existing, deliberately left alone here):
   * the binary has neither the `categoryName.empty()` early-out nor the two
   * `it == end()` guards below. `sub_5555C0` calls the lookup unconditionally
   * and dereferences the insert result without a null check. The guards are
   * defensive additions; removing them would restore 1:1 behavior, but this
   * lane is load-bearing for the whole unit-category system and the identity
   * of the bit-index field (`mCategoryBitIndex` here vs IDA's
   * `mBlueprintOrdinal`) is not independently confirmed, so that correction
   * is left for a pass that can verify it at runtime.
   */
  void AddCategoryMemberBit(
    EntityCategoryLookupTable& lookup,
    const fa::string& categoryName,
    const unsigned int categoryBitIndex
  )
  {
    if (categoryName.empty()) {
      return;
    }

    CategoryLookupMap& categoryMap = lookup.mCategoryMap;
    CategoryLookupMap::iterator it = categoryMap.find(categoryName);
    if (it == categoryMap.end()) {
      CategoryLookupValue freshValue{};
      freshValue.ResetToEmpty(EntityCategoryHelper{lookup.mRules});
      it = categoryMap.insert(CategoryLookupMap::value_type(categoryName, freshValue)).first;
    }
    if (it == categoryMap.end()) {
      return;
    }

    (void)it->second.Bits().Add(categoryBitIndex);
  }

  /**
   * Address: 0x005289D0 (FUN_005289D0, func_RegisterBlueprint)
   *
   * IDA signature:
   * int __thiscall func_RegisterBlueprint(Moho::RUnitBlueprint *this,
   *                                        Moho::RRuleGameRulesImpl *a2,
   *                                        char *a3);
   *
   * Callers (all 6 confirmed via `FUN_005289D0.xrefs.txt`, `type=17`/direct
   * call): `cfunc_RegisterUnitBlueprint` (0x00528AF0), `sub_528B90`
   * (0x00528B90, recovered here as `RegisterUnitBlueprintFromState`),
   * `cfunc_RegisterPropBlueprint` (0x00528BC0), `sub_528C60` (0x00528C60,
   * `RegisterPropBlueprintFromState`), `cfunc_RegisterProjectileBlueprint`
   * (0x00528C90), and `sub_528D30` (0x00528D30,
   * `RegisterProjectileBlueprintFromState`). The three `sub_528xx0` bodies
   * are wired to this helper by name below; the three `cfunc_Register*`
   * entry points (Sim.cpp, further down) reach it transitively by
   * delegating to those same `sub_528xx0` bodies rather than repeating the
   * call inline, matching this file's existing cast-and-forward pattern for
   * that trio.
   *
   * What it does:
   * Three-step sequence matching the binary exactly:
   *   1. For every string in `this->mCategories` (a msvc8-string vector),
   *      calls `sub_5555C0` (`Address:` on `AddCategoryMemberBit`,
   *      FUN_005555C0 above) with `a2->mEntityCategoryLookup` (read at
   *      `a2+0xC4`, `mov ecx, [eax+0C4h]` at 0x00528A26/0x00528A82/
   *      0x00528ABE) and the category name.
   *   2. If `a3` (the caller's extra implicit category, e.g. "ALLUNITS")
   *      is non-null, builds a temporary `std::string` from it and makes
   *      the same call.
   *   3. Unconditionally makes the same call a third time using the string
   *      at `this+8` (`Moho::REntityBlueprint::mBlueprintId`).
   *
   * KNOWN FIDELITY NOTES (left open, not fixed by this pass):
   *   - The binary has no null checks on `this`/`a2` and no empty-string
   *     guard on `a3` (`if (a3)` tests non-null only). This C++ body adds
   *     `!blueprint`/`!rules`/`!lookup` guards and an
   *     `extraCategory != nullptr && *extraCategory != '\0'` check as
   *     defensive additions, matching the same kind of divergence already
   *     documented on `AddCategoryMemberBit` above.
   *   - This function's own asm reads `this->mCategories.begin()`/`end()`
   *     (`_Myfirst`/`_Mylast`) at `this+0x64`/`this+0x68`
   *     (`mov eax,[esi+64h]` / `mov ecx,[esi+68h]` at
   *     0x005289F2/0x005289FC), which looked at first glance like it
   *     disagreed with the header's `offsetof(REntityBlueprint,
   *     mCategories) == 0x60` and with `REntityBlueprintTypeInfo::AddFields`
   *     (FUN_00512870, `push 60h` for the reflected "Categories" field).
   *     It does not: the binary's vector is 16 bytes
   *     (leading `myProxy_` before `first_`/`last_`/`end_`, matching VC8's
   *     `_SECURE_SCL=1` `_Container_base12` proxy word), so `begin()`/
   *     `end()` sit at the vector object's `+0x4`/`+0x8` -- `this+0x64`/
   *     `this+0x68` -- when the vector itself starts at `this+0x60`, exactly
   *     as reflection says. `REntityBlueprint::~REntityBlueprint`
   *     (FUN_00511E80) confirms this directly: it computes `this+0x60` once
   *     (`lea edi,[esi+60h]`) and its address-taken subobject-destructor
   *     trampoline does `add ecx,60h` immediately before tail-calling
   *     `??1vector_string@std@@QAE@@Z` (`std::vector<std::string>::
   *     ~vector()`) -- the linker's own mangled-symbol proof that the
   *     vector lives at `+0x60`. All sources agree; `blueprint->mCategories`
   *     below already reads the correct field via `begin()`/`end()`.
   */
  void RegisterBlueprintCategoryMembership(
    REntityBlueprint* const blueprint,
    RRuleGameRulesImpl* const rules,
    const char* const extraCategory
  )
  {
    if (!blueprint || !rules) {
      return;
    }

    EntityCategoryLookupTable* const lookup = ResolveEntityCategoryLookupTable(*rules);
    if (!lookup) {
      return;
    }

    const unsigned int categoryBitIndex = blueprint->mCategoryBitIndex;
    for (const fa::string& category : blueprint->mCategories) {
      AddCategoryMemberBit(*lookup, category, categoryBitIndex);
    }

    if (extraCategory != nullptr && *extraCategory != '\0') {
      AddCategoryMemberBit(*lookup, fa::string(extraCategory), categoryBitIndex);
    }

    AddCategoryMemberBit(*lookup, blueprint->mBlueprintId, categoryBitIndex);
  }

  void InitUnitBlueprintFromLua(LuaPlus::LuaObject& luaBlueprint, RUnitBlueprint* const blueprint)
  {
    gpg::RRef destination{};
    destination = gpg::MakeRRef<moho::RUnitBlueprint>(blueprint);

    LuaPlus::LuaObject source(luaBlueprint);
    (void)SCR_LuaBuildObject(source, destination, true);

    blueprint->OnInitBlueprint();

    gpg::RRef resolved{};
    resolved = gpg::MakeRRef<moho::RUnitBlueprint>(blueprint);
    SCR_RObjectToLuaMerge(resolved, luaBlueprint);
  }

  void InitPropBlueprintFromLua(LuaPlus::LuaObject& luaBlueprint, RPropBlueprint* const blueprint)
  {
    gpg::RRef destination{};
    destination = gpg::MakeRRef<moho::RPropBlueprint>(blueprint);

    LuaPlus::LuaObject source(luaBlueprint);
    (void)SCR_LuaBuildObject(source, destination, true);

    blueprint->OnInitBlueprint();

    gpg::RRef resolved{};
    resolved = gpg::MakeRRef<moho::RPropBlueprint>(blueprint);
    SCR_RObjectToLuaMerge(resolved, luaBlueprint);
  }

  void InitProjectileBlueprintFromLua(LuaPlus::LuaObject& luaBlueprint, RProjectileBlueprint* const blueprint)
  {
    gpg::RRef destination{};
    destination = gpg::MakeRRef<moho::RProjectileBlueprint>(blueprint);

    LuaPlus::LuaObject source(luaBlueprint);
    (void)SCR_LuaBuildObject(source, destination, true);

    blueprint->OnInitBlueprint();

    gpg::RRef resolved{};
    resolved = gpg::MakeRRef<moho::RProjectileBlueprint>(blueprint);
    SCR_RObjectToLuaMerge(resolved, luaBlueprint);
  }

  // Recovered helper chain for FUN_00528B90/FUN_00528C60/FUN_00528D30:
  // create-or-lookup blueprint object, apply Lua data to reflected fields,
  // mirror into __blueprints, and publish category-bit membership.

  /**
   * Address: 0x00532080 (FUN_00532080, func_CreateRPropBlueprint)
   *
   * What it does:
   * Creates or resolves one prop blueprint from Lua stack lane 1, applies Lua
   * payload fields, and publishes the merged object into `__blueprints`.
   */
  [[nodiscard]] RPropBlueprint* CreateOrGetPropBlueprintFromState(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules
  )
  {
    return GetOrCreateRegisteredBlueprint<RPropBlueprint>(
      state,
      rules,
      rules->mPropBlueprints,
      "prop",
      [](LuaPlus::LuaObject& blueprintSpec, RPropBlueprint* const propBlueprint) {
        InitPropBlueprintFromLua(blueprintSpec, propBlueprint);
      }
    );
  }

  /**
   * Address: 0x00531D80 (FUN_00531D80, func_CreateRUnitBlueprint)
   *
   * What it does:
   * Creates or resolves one unit blueprint from Lua stack lane 1, applies Lua
   * payload fields, and publishes the merged object into `__blueprints`.
   */
  [[nodiscard]] RUnitBlueprint* CreateOrGetUnitBlueprintFromState(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules
  )
  {
    return GetOrCreateRegisteredBlueprint<RUnitBlueprint>(
      state,
      rules,
      rules->mUnitBlueprints,
      "unit",
      [](LuaPlus::LuaObject& blueprintSpec, RUnitBlueprint* const unitBlueprint) {
        InitUnitBlueprintFromLua(blueprintSpec, unitBlueprint);
      }
    );
  }

  /**
   * Address: 0x00528B90 (FUN_00528B90)
   *
   * What it does:
   * Registers one unit blueprint from Lua into the rules unit map, updates
   * the ordinal/__blueprints lanes, and inserts category bits (including
   * implicit ALLUNITS membership).
   */
  int RegisterUnitBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    RUnitBlueprint* const blueprint = CreateOrGetUnitBlueprintFromState(state, rules);
    RegisterBlueprintCategoryMembership(blueprint, rules, "ALLUNITS");
    return 0;
  }

  /**
   * Address: 0x00528C60 (FUN_00528C60)
   *
   * What it does:
   * Registers one prop blueprint from Lua into the rules prop map, updates
   * the ordinal/__blueprints lanes, and publishes category-bit membership
   * from Blueprint.Categories plus blueprint id.
   */
  int RegisterPropBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    RPropBlueprint* const blueprint = CreateOrGetPropBlueprintFromState(state, rules);
    RegisterBlueprintCategoryMembership(blueprint, rules, nullptr);
    return 0;
  }

  /**
   * Address: 0x00532380 (FUN_00532380, func_CreateRProjectileBlueprint)
   *
   * What it does:
   * Creates or resolves one projectile blueprint from Lua stack lane 1,
   * applies Lua payload fields, and publishes the merged object into
   * `__blueprints`.
   */
  [[nodiscard]] RProjectileBlueprint* CreateOrGetProjectileBlueprintFromState(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules
  )
  {
    return GetOrCreateRegisteredBlueprint<RProjectileBlueprint>(
      state,
      rules,
      rules->mProjectileBlueprints,
      "projectile",
      [](LuaPlus::LuaObject& blueprintSpec, RProjectileBlueprint* const projectileBlueprint) {
        InitProjectileBlueprintFromLua(blueprintSpec, projectileBlueprint);
      }
    );
  }

  /**
   * Address: 0x00528D30 (FUN_00528D30)
   *
   * What it does:
   * Registers one projectile blueprint from Lua into the rules projectile
   * map, updates the ordinal/__blueprints lanes, and inserts category bits
   * (including implicit ALLPROJECTILES membership).
   */
  int RegisterProjectileBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    RProjectileBlueprint* const blueprint = CreateOrGetProjectileBlueprintFromState(state, rules);
    RegisterBlueprintCategoryMembership(blueprint, rules, "ALLPROJECTILES");
    return 0;
  }
}



/**
 * Address: 0x00528AF0 (FUN_00528AF0, cfunc_RegisterUnitBlueprint)
 *
 * What it does:
 * Casts the raw callback state and forwards unit-blueprint registration into
 * the fast-path helper lane.
 */
int moho::cfunc_RegisterUnitBlueprint(lua_State* const luaContext)
{
  return RegisterUnitBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528BC0 (FUN_00528BC0, cfunc_RegisterPropBlueprint)
 *
 * What it does:
 * Casts the raw callback state and forwards prop-blueprint registration into
 * the fast-path helper lane.
 */
int moho::cfunc_RegisterPropBlueprint(lua_State* const luaContext)
{
  return RegisterPropBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528C90 (FUN_00528C90, cfunc_RegisterProjectileBlueprint)
 *
 * What it does:
 * Casts the raw callback state and forwards projectile-blueprint registration
 * into the fast-path helper lane.
 */
int moho::cfunc_RegisterProjectileBlueprint(lua_State* const luaContext)
{
  return RegisterProjectileBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528D60 (FUN_00528D60, cfunc_RegisterMeshBlueprint)
 *
 * What it does:
 * Casts the raw callback state and dispatches mesh-blueprint registration into
 * the rules mesh map lane.
 */
int moho::cfunc_RegisterMeshBlueprint(lua_State* const luaContext)
{
  return RegisterMeshBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528E20 (FUN_00528E20, cfunc_RegisterTrailEmitterBlueprint)
 *
 * What it does:
 * Casts the raw callback state and dispatches trail-emitter blueprint
 * registration into the rules trail map lane.
 */
int moho::cfunc_RegisterTrailEmitterBlueprint(lua_State* const luaContext)
{
  return RegisterTrailEmitterBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528ED0 (FUN_00528ED0, cfunc_RegisterEmitterBlueprint)
 *
 * What it does:
 * Casts the raw callback state and dispatches emitter blueprint registration
 * into the rules emitter map lane.
 */
int moho::cfunc_RegisterEmitterBlueprint(lua_State* const luaContext)
{
  return RegisterEmitterBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528F80 (FUN_00528F80, cfunc_RegisterBeamBlueprint)
 *
 * What it does:
 * Casts the raw callback state and dispatches beam blueprint registration into
 * the rules beam map lane.
 */
int moho::cfunc_RegisterBeamBlueprint(lua_State* const luaContext)
{
  return RegisterBeamBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x005284F0 (FUN_005284F0, func_SpecFootprints_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SpecFootprints`.
 */
moho::CScrLuaInitForm* moho::func_SpecFootprints_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "SpecFootprints",
    &moho::cfunc_SpecFootprints,
    nullptr,
    "<global>",
    kSpecFootprintsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528B30 (FUN_00528B30, func_RegisterUnitBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterUnitBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterUnitBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterUnitBlueprint",
    &moho::cfunc_RegisterUnitBlueprint,
    nullptr,
    "<global>",
    kRegisterUnitBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528C00 (FUN_00528C00, func_RegisterPropBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterPropBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterPropBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterPropBlueprint",
    &moho::cfunc_RegisterPropBlueprint,
    nullptr,
    "<global>",
    kRegisterPropBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528CD0 (FUN_00528CD0, func_RegisterProjectileBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterProjectileBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterProjectileBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterProjectileBlueprint",
    &moho::cfunc_RegisterProjectileBlueprint,
    nullptr,
    "<global>",
    kRegisterProjectileBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528D90 (FUN_00528D90, func_RegisterMeshBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterMeshBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterMeshBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterMeshBlueprint",
    &moho::cfunc_RegisterMeshBlueprint,
    nullptr,
    "<global>",
    kRegisterMeshBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528E50 (FUN_00528E50, func_RegisterTrailEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterTrailEmitterBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterTrailEmitterBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterTrailEmitterBlueprint",
    &moho::cfunc_RegisterTrailEmitterBlueprint,
    nullptr,
    "<global>",
    kRegisterTrailEmitterBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528F00 (FUN_00528F00, func_RegisterEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterEmitterBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterEmitterBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterEmitterBlueprint",
    &moho::cfunc_RegisterEmitterBlueprint,
    nullptr,
    "<global>",
    kRegisterEmitterBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528FB0 (FUN_00528FB0, func_RegisterBeamBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterBeamBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterBeamBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterBeamBlueprint",
    &moho::cfunc_RegisterBeamBlueprint,
    nullptr,
    "<global>",
    kRegisterBeamBlueprintHelpText
  );
  return &binder;
}

int moho::cfunc_BlueprintLoaderUpdateProgress(lua_State* const luaContext)
{
  (void)LuaPlus::LuaState::CastState(luaContext);
  TickBlueprintLoaderProgressFromLoaderContext();
  return 0;
}

/**
 * Address: 0x00529060 (FUN_00529060, func_BlueprintLoaderUpdateProgress_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `BlueprintLoaderUpdateProgress`.
 */
moho::CScrLuaInitForm* moho::func_BlueprintLoaderUpdateProgress_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "BlueprintLoaderUpdateProgress",
    &moho::cfunc_BlueprintLoaderUpdateProgress,
    nullptr,
    "<global>",
    kBlueprintLoaderUpdateProgressHelpText
  );
  return &binder;
}

/**
 * Address: 0x00758F90 (FUN_00758F90, cfunc_RandomSim)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_RandomSimL`.
 */
int moho::cfunc_RandomSim(lua_State* const luaContext)
{
  return cfunc_RandomSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00758FB0 (FUN_00758FB0, func_RandomSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane Lua binder definition for global `Random`.
 */
moho::CScrLuaInitForm* moho::func_RandomSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "Random",
    &moho::cfunc_RandomSim,
    nullptr,
    "<global>",
    kRandomSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759010 (FUN_00759010, cfunc_RandomSimL)
 *
 * What it does:
 * Produces one random float or integer range sample from the active sim
 * random stream for `Random([[min,] max])`.
 */
int moho::cfunc_RandomSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kRandomSimHelpText,
      0,
      2,
      argumentCount
    );
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  if (!sim) {
    LuaPlus::LuaState::Error(state, "Random(): can only be called as part of the sim.");
  }

  if (argumentCount == 0) {
    // 0x00759150..0x00759165: `fild` word (+2^32), `fmul` 2^-32 (0x00E4F7B0)
    // under 24-bit x87 precision, stored as a float lua_Number.
    constexpr float kInvTwoTo32 = 2.3283064365386963e-10f;
    const float value = fa::MulTwisterWord(kInvTwoTo32, sim->mRngState->twister.NextUInt32());
    lua_pushnumber(rawState, value);
    return 1;
  }

  if (argumentCount == 1) {
    const int maxValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
    const std::uint32_t randomValue = sim->mRngState->twister.NextUInt32();
    const std::uint32_t scaledValue = static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(static_cast<std::uint32_t>(maxValue)) * static_cast<std::uint64_t>(randomValue)) >>
      32u
    );
    const int result = static_cast<int>(scaledValue + 1u);
    lua_pushnumber(rawState, static_cast<float>(result));
    return 1;
  }

  const int minValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
  const int maxValue = LuaPlus::LuaStackObject(state, 2).GetInteger();
  const std::uint32_t randomValue = sim->mRngState->twister.NextUInt32();
  const std::uint32_t span = (static_cast<std::uint32_t>(maxValue) + 1u) - static_cast<std::uint32_t>(minValue);
  const std::uint32_t scaledOffset =
    static_cast<std::uint32_t>((static_cast<std::uint64_t>(span) * static_cast<std::uint64_t>(randomValue)) >> 32u);
  const int result = static_cast<int>(static_cast<std::uint32_t>(minValue) + scaledOffset);
  lua_pushnumber(rawState, static_cast<float>(result));
  return 1;
}

/**
 * Address: 0x007593D0 (FUN_007593D0, cfunc_SelectedUnit)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SelectedUnitL`.
 */
int moho::cfunc_SelectedUnit(lua_State* const luaContext)
{
  return cfunc_SelectedUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007593F0 (FUN_007593F0, func_SelectedUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane global Lua binder for `SelectedUnit()`.
 */
moho::CScrLuaInitForm* moho::func_SelectedUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SelectedUnit",
    &moho::cfunc_SelectedUnit,
    nullptr,
    "<global>",
    kSelectedUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759450 (FUN_00759450, cfunc_SelectedUnitL)
 *
 * What it does:
 * Pushes the current `__selected_unit` global value.
 */
int moho::cfunc_SelectedUnitL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  LuaPlus::LuaObject selectedUnit = state->GetGlobals()["__selected_unit"];
  selectedUnit.PushStack(state);
  return 1;
}

/**
 * Address: 0x007594C0 (FUN_007594C0, cfunc_SimConExecute)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SimConExecuteL`.
 */
int moho::cfunc_SimConExecute(lua_State* const luaContext)
{
  return cfunc_SimConExecuteL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007594E0 (FUN_007594E0, func_SimConExecute_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SimConExecute`.
 */
moho::CScrLuaInitForm* moho::func_SimConExecute_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SimConExecute",
    &moho::cfunc_SimConExecute,
    nullptr,
    "<global>",
    kSimConExecuteHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759540 (FUN_00759540, cfunc_SimConExecuteL)
 *
 * What it does:
 * Reads one console command string and executes it.
 */
int moho::cfunc_SimConExecuteL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kSimConExecuteHelpText);

  LuaPlus::LuaStackObject commandArg(state, 1);
  const char* commandText = lua_tostring(rawState, 1);
  if (!commandText) {
    commandArg.TypeError("string");
    commandText = "";
  }

  CON_Execute(commandText);
  return 0;
}

/**
 * Address: 0x0075D060 (FUN_0075D060, cfunc_TryCopyPose)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_TryCopyPoseL`.
 */
int moho::cfunc_TryCopyPose(lua_State* const luaContext)
{
  return cfunc_TryCopyPoseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075D080 (FUN_0075D080, func_TryCopyPose_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane global Lua binder for `TryCopyPose`. The binary's
 * only caller is the tail-call trampoline `register_TryCopyPose_LuaFuncDef`
 * (0x00BDC130, `jmp func_TryCopyPose_LuaFuncDef`); the recovered source
 * skips modeling that bridge and instead invokes this publisher directly
 * from `SimLuaFuncDefBootstrap`, matching every other sibling in this file
 * (`func_RandomSim_LuaFuncDef`, `func_SelectedUnit_LuaFuncDef`, ...).
 */
moho::CScrLuaInitForm* moho::func_TryCopyPose_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "TryCopyPose",
    &moho::cfunc_TryCopyPose,
    nullptr,
    "<global>",
    kTryCopyPoseHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075D0E0 (FUN_0075D0E0, cfunc_TryCopyPoseL)
 *
 * IDA signature:
 * int __cdecl cfunc_TryCopyPoseL(LuaPlus::LuaState *a1);
 *
 * What it does:
 * Resolves `unitFrom` (arg 1) and `entityTo` (arg 2) from the Lua stack.
 * When both share the same mesh and, if the meshes differ, the same
 * skeleton, retains `unitFrom`'s current animation pose. If
 * `bCopyWorldTransform` (arg 3) is false, clones that pose and re-anchors
 * the clone to `entityTo`'s current world transform instead of carrying
 * over the source's own transform (used when the destination was placed
 * somewhere other than the source's location, e.g. a wreck pulled back
 * onto the map). Queues the resulting `{entity id, pose}` pair onto the
 * Sim's pending pose-copy lane (`Sim::mPendingPoseCopies`, +0x9E8) and
 * returns whether the copy was attempted.
 */
int moho::cfunc_TryCopyPoseL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 3, kTryCopyPoseHelpText);

  LuaPlus::LuaObject unitFromObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unitFrom = SCR_FromLua_Unit(unitFromObject);

  LuaPlus::LuaObject entityToObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const entityTo = SCR_FromLua_Entity(entityToObject, state);

  const bool sameMeshAndSkeleton =
    unitFrom->GetMesh() == entityTo->GetMesh() &&
    entityTo->GetMesh()->GetSkeleton() == unitFrom->GetMesh()->GetSkeleton();

  if (!sameMeshAndSkeleton) {
    lua_pushboolean(state->m_state, 0);
    return 1;
  }

  Sim* const sim = ResolveGlobalSim(state->m_state);

  SPendingPoseCopy pendingCopy{entityTo->id_, unitFrom->AniActor->GetPoseShared()};

  const bool bCopyWorldTransform = LuaPlus::LuaStackObject(state, 3).GetBoolean();
  if (!bCopyWorldTransform) {
    CAniPose* const clonedPose = new CAniPose(*pendingCopy.mPose);
    pendingCopy.mPose.reset(clonedPose);
    pendingCopy.mPose->SetWorldTransform(entityTo->GetTransformWm3());
  }

  sim->mPendingPoseCopies.push_back(pendingCopy);
  lua_pushboolean(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00759190 (FUN_00759190, cfunc_FlattenMapRect)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_FlattenMapRectL`.
 */
int moho::cfunc_FlattenMapRect(lua_State* const luaContext)
{
  return cfunc_FlattenMapRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007591B0 (FUN_007591B0, func_FlattenMapRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane global Lua binder for `FlattenMapRect`.
 */
moho::CScrLuaInitForm* moho::func_FlattenMapRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kFlattenMapRectName,
    &moho::cfunc_FlattenMapRect,
    nullptr,
    "<global>",
    kFlattenMapRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759210 (FUN_00759210, cfunc_FlattenMapRectL)
 *
 * What it does:
 * Reads `(x, z, sizex, sizez, elevation)` as `(x0, z0, x0+sizex, z0+sizez)`
 * plus a float elevation, then flattens that world rect on the global sim.
 */
int moho::cfunc_FlattenMapRectL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 5, kFlattenMapRectHelpText);

  gpg::Rect2i rect{};

  LuaPlus::LuaStackObject arg1(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    arg1.TypeError("integer");
  }
  const int originX = static_cast<int>(lua_tonumber(rawState, 1));
  rect.x0 = originX;

  LuaPlus::LuaStackObject arg2(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    arg2.TypeError("integer");
  }
  const int originZ = static_cast<int>(lua_tonumber(rawState, 2));
  rect.z0 = originZ;

  LuaPlus::LuaStackObject arg3(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    arg3.TypeError("integer");
  }
  rect.x1 = originX + static_cast<int>(lua_tonumber(rawState, 3));

  LuaPlus::LuaStackObject arg4(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    arg4.TypeError("integer");
  }
  rect.z1 = originZ + static_cast<int>(lua_tonumber(rawState, 4));

  LuaPlus::LuaStackObject arg5(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    arg5.TypeError("number");
  }
  const float elevation = static_cast<float>(lua_tonumber(rawState, 5));

  Sim* const sim = lua_getglobaluserdata(rawState);
  sim->FlattenMapRect(rect, elevation);
  return 0;
}

/**
 * Address: 0x00759810 (FUN_00759810, cfunc_ParseEntityCategorySim)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_ParseEntityCategorySimL`.
 */
int moho::cfunc_ParseEntityCategorySim(lua_State* const luaContext)
{
  return cfunc_ParseEntityCategorySimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00759830 (FUN_00759830, func_ParseEntityCategorySim_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane global Lua binder for `ParseEntityCategory`.
 */
moho::CScrLuaInitForm* moho::func_ParseEntityCategorySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ParseEntityCategory",
    &moho::cfunc_ParseEntityCategorySim,
    nullptr,
    "<global>",
    kParseEntityCategorySimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759890 (FUN_00759890, cfunc_ParseEntityCategorySimL)
 *
 * What it does:
 * Parses one category expression string and returns a new entity-category
 * userdata object.
 */
int moho::cfunc_ParseEntityCategorySimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kParseEntityCategorySimHelpText);

  Sim* const sim = ResolveGlobalSim(rawState);
  RRuleGameRulesImpl* const rules = sim ? static_cast<RRuleGameRulesImpl*>(sim->mRules) : nullptr;
  if (!rules) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  LuaPlus::LuaStackObject categoryTextArg(state, 1);
  const char* categoryText = lua_tostring(rawState, 1);
  if (!categoryText) {
    categoryTextArg.TypeError("string");
    categoryText = "";
  }

  EntityCategorySet parsedCategory = rules->ParseEntityCategory(categoryText);

  LuaPlus::LuaObject out;
  (void)func_NewEntityCategory(state, &out, &parsedCategory);
  out.PushStack(state);
  return 1;
}


/**
 * Address: 0x00759A10 (FUN_00759A10, cfunc_EntityCategoryContainsSimL)
 *
 * What it does:
 * Tests whether arg#1 category set contains arg#2 entity/blueprint category.
 */
int moho::cfunc_EntityCategoryContainsSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kEntityCategoryContainsUserHelpText);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); // 0x005575E0: raises on a non-category

  Sim* const sim = ResolveGlobalSim(rawState);
  RRuleGameRulesImpl* const rules = sim ? static_cast<RRuleGameRulesImpl*>(sim->mRules) : nullptr;

  const LuaPlus::LuaObject valueObject(LuaPlus::LuaStackObject(state, 2));
  const REntityBlueprint* const blueprint = ResolveEntityCategoryCountBlueprint(valueObject, rules);

  const bool contains =
    categorySet != nullptr && blueprint != nullptr && categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  lua_pushboolean(rawState, contains ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00759990 (FUN_00759990, cfunc_EntityCategoryContainsSim)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryContainsSimL`.
 */
int moho::cfunc_EntityCategoryContainsSim(lua_State* const luaContext)
{
  return cfunc_EntityCategoryContainsSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007599B0 (FUN_007599B0, func_EntityCategoryContainsSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryContains`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryContainsSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EntityCategoryContains",
    &moho::cfunc_EntityCategoryContainsSim,
    nullptr,
    "<global>",
    kEntityCategoryContainsUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759BD0 (FUN_00759BD0, cfunc_EntityCategoryFilterDownSim)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterDownSimL`.
 */
int moho::cfunc_EntityCategoryFilterDownSim(lua_State* const luaContext)
{
  return cfunc_EntityCategoryFilterDownSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00759BF0 (FUN_00759BF0, func_EntityCategoryFilterDownSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryFilterDown`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryFilterDownSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EntityCategoryFilterDown",
    &moho::cfunc_EntityCategoryFilterDownSim,
    nullptr,
    "<global>",
    kEntityCategoryFilterDownUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759C50 (FUN_00759C50, cfunc_EntityCategoryFilterDownSimL)
 *
 * What it does:
 * Filters arg#2 values into a result table by keeping entries whose resolved
 * entity blueprint category bit is present in arg#1 category set.
 */
int moho::cfunc_EntityCategoryFilterDownSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 2, kEntityCategoryFilterDownUserHelpText);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  if (!sourceListObject.IsTable()) {
    LuaPlus::LuaState::Error(state, kEntityCategoryCountInvalidTableText);
  }

  RRuleGameRulesImpl* const rules = ResolveRulesImpl(state);
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0u);

  int resultIndex = 1;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    const LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];
    const REntityBlueprint* const blueprint = ResolveEntityCategoryCountBlueprint(valueObject, rules);
    if (categorySet != nullptr && blueprint != nullptr && categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      resultObject.SetObject(resultIndex, valueObject); // 0x00759E53: plain table set, not table.insert
      ++resultIndex;
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00759F70 (FUN_00759F70, cfunc_EntityCategoryCountL)
 *
 * What it does:
 * Counts arg#2 list entries whose resolved blueprint category bit is present
 * in arg#1 category set.
 */
int moho::cfunc_EntityCategoryCountL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kEntityCategoryCountHelpText);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); // 0x005575E0: raises on a non-category
  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  if (!sourceListObject.IsTable()) {
    LuaPlus::LuaState::Error(state, kEntityCategoryCountInvalidTableText);
  }

  RRuleGameRulesImpl* const rules = ResolveRulesImpl(state);

  int categoryCount = 0;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];
    const REntityBlueprint* const blueprint = ResolveEntityCategoryCountBlueprint(valueObject, rules);
    if (categorySet != nullptr && blueprint != nullptr && categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      ++categoryCount;
    }
  }

  lua_pushnumber(rawState, static_cast<float>(categoryCount));
  return 1;
}

/**
 * Address: 0x00759EF0 (FUN_00759EF0, cfunc_EntityCategoryCount)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryCountL`.
 */
int moho::cfunc_EntityCategoryCount(lua_State* const luaContext)
{
  return cfunc_EntityCategoryCountL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00759F10 (FUN_00759F10, func_EntityCategoryCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryCount`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EntityCategoryCount",
    &moho::cfunc_EntityCategoryCount,
    nullptr,
    "<global>",
    kEntityCategoryCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A1D0 (FUN_0075A1D0, cfunc_EntityCategoryCountAroundPosition)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to
 * `cfunc_EntityCategoryCountAroundPositionL`.
 */
int moho::cfunc_EntityCategoryCountAroundPosition(lua_State* const luaContext)
{
  return cfunc_EntityCategoryCountAroundPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A1F0 (FUN_0075A1F0, func_EntityCategoryCountAroundPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `EntityCategoryCountAroundPosition`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryCountAroundPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EntityCategoryCountAroundPosition",
    &moho::cfunc_EntityCategoryCountAroundPosition,
    nullptr,
    "<global>",
    kEntityCategoryCountAroundPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A250 (FUN_0075A250, cfunc_EntityCategoryCountAroundPositionL)
 *
 * What it does:
 * Counts table entries whose entity category matches arg#1 and whose
 * horizontal distance from arg#3 is within arg#4.
 */
int moho::cfunc_EntityCategoryCountAroundPositionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 4, kEntityCategoryCountAroundPositionHelpText);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  if (!sourceListObject.IsTable()) {
    LuaPlus::LuaState::Error(state, kEntityCategoryCountInvalidTableText);
  }

  const LuaPlus::LuaObject centerObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vec3f center = SCR_FromLuaCopy<Wm3::Vector3<float>>(centerObject);

  LuaPlus::LuaStackObject radiusArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    radiusArg.TypeError("number");
  }

  const float radius = static_cast<float>(lua_tonumber(rawState, 4));
  const float radiusSquared = radius * radius;

  int categoryCount = 0;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    const LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];
    Entity* const entity = SCR_FromLuaNoError_Entity(valueObject);
    if (entity == nullptr || entity->BluePrint == nullptr || categorySet == nullptr) {
      continue;
    }

    const Wm3::Vec3f& entityPosition = entity->GetPositionWm3();
    const float deltaX = center.x - entityPosition.x;
    const float deltaZ = center.z - entityPosition.z;
    const float distanceSquared = (deltaX * deltaX) + (deltaZ * deltaZ);
    if (radiusSquared > distanceSquared && categorySet->Bits().Contains(entity->BluePrint->mCategoryBitIndex)) {
      ++categoryCount;
    }
  }

  lua_pushnumber(rawState, static_cast<float>(categoryCount));
  return 1;
}

/**
 * Address: 0x0075B940 (FUN_0075B940, cfunc_Warp)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_WarpL`.
 */
int moho::cfunc_Warp(lua_State* const luaContext)
{
  return cfunc_WarpL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075B9C0 (FUN_0075B9C0, cfunc_WarpL)
 *
 * What it does:
 * Reads `(entity, location [, orientation])` and warps the entity to
 * `location`; when arg#3 is absent/nil, preserves current entity orientation.
 */
int moho::cfunc_WarpL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kWarpHelpText,
      2,
      3,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vec3f location = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);

  VTransform transform = entity->GetTransformWm3();
  transform.pos_ = location;

  lua_settop(rawState, 3);
  if (lua_type(rawState, 3) != LUA_TNIL) {
    // 0x0075BB1F: retail converts arg#3 through SCR_FromLuaCopy<Quaternionf>
    // (0x004CFBD0) rather than reading the four slots inline.
    const LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 3));
    transform.orient_ = SCR_FromLuaCopy<Wm3::Quaternion<float>>(orientationObject);
  }

  entity->Warp(transform);
  return 0;
}

/**
 * Address: 0x0075B960 (FUN_0075B960, func_Warp_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `Warp`.
 */
moho::CScrLuaInitForm* moho::func_Warp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "Warp",
    &moho::cfunc_Warp,
    nullptr,
    "<global>",
    kWarpHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075B650 (FUN_0075B650, cfunc_ChangeUnitArmyL)
 *
 * IDA signature:
 * void __thiscall cfunc_ChangeUnitArmyL(LuaPlus::LuaState *state);
 *
 * What it does:
 * Cheat command `ChangeUnitArmy(unit, armyIndex)`. Resolves the target unit and
 * army from the Lua stack, rejects transfers to the unit's own army, and — unless
 * one of the unit's attached entities is a COMMAND unit — transfers the unit and
 * its cargo to the new army through `Sim::TransferUnit`. Pushes the replacement
 * unit's Lua object on success, `nil` otherwise. Always returns 1.
 */
int moho::cfunc_ChangeUnitArmyL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kChangeUnitArmyHelpText);

  Sim* const sim = lua_getglobaluserdata(rawState);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (!army) {
    // Faithful to FUN_0075B650: the worker independently validates the army lane.
    // (The recovered ARMY_FromLuaState already raises the Lua error for an invalid
    //  army, so this branch is defensive and mirrors the shipped worker.)
    LuaPlus::LuaStackObject armyStackObject(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      armyStackObject.TypeError("integer");
    }
    LuaPlus::LuaState::Error(state, "Invalid army %d", static_cast<int>(lua_tonumber(rawState, 2)));
  }

  if (unit->ArmyRef == army) {
    LuaPlus::LuaState::Error(state, "Unit already belongs to army %d", army->mConstDat.mArmyIndex);
  }

  // Disabled-validation predicate: the shipped binary computes this guard but the
  // conditional branch that consumed it was hot-patched to six NOPs
  // (asm 0x0075B816..0x0075B81B), so the result never gates behavior. Preserved for
  // fidelity.
  [[maybe_unused]] const bool sourceUnitIneligible =
    unit->IsBeingBuilt() || unit->IsDead() || unit->DestroyQueued() || unit->IsInCategory("COMMAND");

  // Refuse the transfer if any attached entity is a COMMAND unit.
  const fa::vector<Entity*>& attached = unit->GetAttachedEntities();
  for (Entity* const attachedEntity : attached) {
    Unit* const attachedUnit = attachedEntity->IsUnit();
    if (attachedUnit && attachedUnit->IsInCategory("COMMAND")) {
      lua_pushnil(rawState);
      return 1;
    }
  }

  Unit* const transferred = sim->TransferUnit(unit, army);
  if (transferred) {
    transferred->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(rawState);
  }
  return 1;
}

/**
 * Address: 0x0075B5D0 (FUN_0075B5D0, cfunc_ChangeUnitArmy)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_ChangeUnitArmyL`.
 */
int moho::cfunc_ChangeUnitArmy(lua_State* const luaContext)
{
  return cfunc_ChangeUnitArmyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075B5F0 (FUN_0075B5F0, func_ChangeUnitArmy_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ChangeUnitArmy`.
 */
moho::CScrLuaInitForm* moho::func_ChangeUnitArmy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ChangeUnitArmy",
    &moho::cfunc_ChangeUnitArmy,
    nullptr,
    "<global>",
    kChangeUnitArmyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E2A0 (FUN_0075E2A0, cfunc_DebugGetSelection)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_DebugGetSelectionL`.
 */
int moho::cfunc_DebugGetSelection(lua_State* const luaContext)
{
  return cfunc_DebugGetSelectionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E2C0 (FUN_0075E2C0, func_DebugGetSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `DebugGetSelection`.
 */
moho::CScrLuaInitForm* moho::func_DebugGetSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DebugGetSelection",
    &moho::cfunc_DebugGetSelection,
    nullptr,
    "<global>",
    kDebugGetSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E320 (FUN_0075E320, cfunc_DebugGetSelectionL)
 *
 * What it does:
 * Returns a Lua table of script objects for ids in the active debug-selection
 * sync filter (`Sim::mSyncFilter.maskB`).
 */
int moho::cfunc_DebugGetSelectionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kDebugGetSelectionHelpText);

  Sim* const sim = lua_getglobaluserdata(rawState);
  BVIntSet selectedEntityIds{};
  CopyDebugSelectionMaskB(*sim, selectedEntityIds);

  LuaPlus::LuaObject selectionTable(state);
  selectionTable.AssignNewTable(state, 0, 0);

  std::int32_t tableIndex = 0;
  for (unsigned int nextEntityId = selectedEntityIds.GetNext(static_cast<unsigned int>(-1));
       nextEntityId != selectedEntityIds.Max();
       nextEntityId = selectedEntityIds.GetNext(nextEntityId))
  {
    Entity* const entity = FindEntityById(sim->mEntityDB, static_cast<EntId>(nextEntityId));
    if (entity == nullptr || entity->mLuaObj.IsNil()) {
      continue;
    }

    LuaPlus::LuaObject entityObject(entity->mLuaObj);
    ++tableIndex;
    selectionTable.SetObject(tableIndex, entityObject);
  }

  selectionTable.PushStack(state);
  return 1;
}


/**
 * Address: 0x0074B570 (FUN_0074B570, cfunc_printSim)
 *
 * What it does:
 * Concatenates Lua print arguments and emits one line into sim print/log
 * output.
 */
int moho::cfunc_printSim(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  if (!state || !state->m_state) {
    return 0;
  }

  SCR_ConcatArgsAndCall(state, '\t', &PrintSimConcatSink);
  return 0;
}

/**
 * Address: 0x0074B590 (FUN_0074B590, func_printSim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `print(...)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_printSim_LuaFuncDef()
{
  static CScrLuaBinder binder(SimLuaInitSet(), "print", &moho::cfunc_printSim, nullptr, "<global>", kPrintSimHelpText);
  return &binder;
}

/**
 * Address: 0x0074B620 (FUN_0074B620, cfunc_CheatsEnabled)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_CheatsEnabledL`.
 */
int moho::cfunc_CheatsEnabled(lua_State* const luaContext)
{
  return cfunc_CheatsEnabledL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0074B640 (FUN_0074B640, func_CheatsEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes global `CheatsEnabled()` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_CheatsEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "CheatsEnabled",
    &moho::cfunc_CheatsEnabled,
    nullptr,
    "<global>",
    kCheatsEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074B6A0 (FUN_0074B6A0, cfunc_CheatsEnabledL)
 *
 * What it does:
 * Validates no Lua args and returns `Sim::CheatsEnabled()` as a boolean.
 */
int moho::cfunc_CheatsEnabledL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kCheatsEnabledHelpText);

  Sim* const sim = ResolveGlobalSim(state->m_state);
  const bool cheatsEnabled = sim != nullptr && sim->CheatsEnabled();
  lua_pushboolean(state->m_state, cheatsEnabled ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0074B8B0 (cfunc_EndGameL)
 *
 * What it does:
 * Validates the Lua argument count, then forwards to `Sim::EndGame()`.
 *
 * Game version 3835's exe replaced this body with FAF's old desync fix
 * (0x0128F260 in `.exxt`), which first set an end-game flag and its input
 * block latch; FA-Binary-Patches #173 (Remove old desync-fix code, game
 * version 3840) restored the original, which is this.
 */
int moho::cfunc_EndGameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    luaL_error(rawState, "%s\n  expected %d args, but got %d", kEndGameHelpText, 0, argumentCount);
  }

  if (Sim* const sim = ResolveGlobalSim(rawState)) {
    sim->EndGame();
  }

  return 0;
}

/**
 * Address: 0x0074B830 (FUN_0074B830, cfunc_EndGame)
 * Address: 0x0128F085 (FUN_0128F085 thunk)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_EndGameL`.
 */
int moho::cfunc_EndGame(lua_State* const luaContext)
{
  return cfunc_EndGameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A5A0 (FUN_0075A5A0, func_GenerateRandomOrientation_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GenerateRandomOrientation()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GenerateRandomOrientation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GenerateRandomOrientation",
    &moho::cfunc_GenerateRandomOrientation,
    nullptr,
    "<global>",
    kGenerateRandomOrientationHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A580 (FUN_0075A580, cfunc_GenerateRandomOrientation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GenerateRandomOrientationL`.
 */
int moho::cfunc_GenerateRandomOrientation(lua_State* const luaContext)
{
  return cfunc_GenerateRandomOrientationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A600 (FUN_0075A600, cfunc_GenerateRandomOrientationL)
 *
 * What it does:
 * Samples four Gaussian random lanes, normalizes one quaternion, and returns
 * it as a Lua quaternion object.
 */
int moho::cfunc_GenerateRandomOrientationL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGenerateRandomOrientationHelpText);

  Sim* const sim = lua_getglobaluserdata(rawState);
  CRandomStream* const random = sim->mRngState;

  // 0x0075A657..0x0075A677: the four draws fill x, y, z and then w
  // (`[esp+10h]`, `[+14h]`, `[+18h]`, `[+0Ch]` of a {w,x,y,z} quaternion),
  // and 0x0075A67B..0x0075A696 sums the squares z, y, x, then w.
  Wm3::Quaternionf orientation{};
  orientation.x = random->FRandGaussian();
  orientation.y = random->FRandGaussian();
  orientation.z = random->FRandGaussian();
  orientation.w = random->FRandGaussian();

  const float magnitude = std::sqrt(
    (((orientation.z * orientation.z) + (orientation.y * orientation.y)) + (orientation.x * orientation.x)) +
    (orientation.w * orientation.w)
  );
  if (magnitude <= 1.0e-6f) {
    orientation = Wm3::Quaternionf{};
  } else {
    const float inverseMagnitude = 1.0f / magnitude;
    orientation.x *= inverseMagnitude;
    orientation.y *= inverseMagnitude;
    orientation.z *= inverseMagnitude;
    orientation.w *= inverseMagnitude;
  }

  LuaPlus::LuaObject rotationObject = SCR_ToLua<Wm3::Quaternionf>(state, orientation);
  rotationObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075C9D0 (FUN_0075C9D0, cfunc_FlushIntelInRect)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_FlushIntelInRectL`.
 */
int moho::cfunc_FlushIntelInRect(lua_State* const luaContext)
{
  return cfunc_FlushIntelInRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C9F0 (FUN_0075C9F0, func_FlushIntelInRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `FlushIntelInRect(minX,minZ,maxX,maxZ)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_FlushIntelInRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "FlushIntelInRect",
    &moho::cfunc_FlushIntelInRect,
    nullptr,
    "<global>",
    kFlushIntelInRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075CA50 (FUN_0075CA50, cfunc_FlushIntelInRectL)
 *
 * What it does:
 * Flushes recon blips inside one rectangle for every active army recon db.
 */
int moho::cfunc_FlushIntelInRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 4, kFlushIntelInRectHelpText);

  LuaPlus::LuaStackObject maxZArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    maxZArg.TypeError("integer");
  }
  const std::int32_t maxZ = static_cast<std::int32_t>(lua_tonumber(rawState, 4));

  LuaPlus::LuaStackObject maxXArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    maxXArg.TypeError("integer");
  }
  const std::int32_t maxX = static_cast<std::int32_t>(lua_tonumber(rawState, 3));

  LuaPlus::LuaStackObject minZArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    minZArg.TypeError("integer");
  }
  const std::int32_t minZ = static_cast<std::int32_t>(lua_tonumber(rawState, 2));

  LuaPlus::LuaStackObject minXArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    minXArg.TypeError("integer");
  }
  const std::int32_t minX = static_cast<std::int32_t>(lua_tonumber(rawState, 1));

  Sim* const sim = ResolveGlobalSim(rawState);
  if (!sim) {
    return 0;
  }

  gpg::Rect2i rect{};
  rect.x0 = minX;
  rect.z0 = minZ;
  rect.x1 = maxX;
  rect.z1 = maxZ;

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (!army) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    if (reconDb) {
      reconDb->ReconFlushBlipsInRect(rect);
    }
  }

  return 0;
}

/**
 * Address: 0x0075DBA0 (FUN_0075DBA0, func_DrawLine_LuaFuncDef)
 *
 * What it does:
 * Publishes global `DrawLine(a,b,c)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_DrawLine_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DrawLine",
    &moho::cfunc_DrawLine,
    nullptr,
    "<global>",
    kDrawLineHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075DB80 (FUN_0075DB80, cfunc_DrawLine)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_DrawLineL`.
 */
int moho::cfunc_DrawLine(lua_State* const luaContext)
{
  return cfunc_DrawLineL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075DC00 (FUN_0075DC00, cfunc_DrawLineL)
 *
 * What it does:
 * Reads `(startVec3, endVec3, color)` from Lua and emits one debug line
 * segment on the current sim debug canvas.
 */
int moho::cfunc_DrawLineL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kDrawLineHelpText);

  Sim* const sim = ResolveGlobalSim(rawState);
  CDebugCanvas* const debugCanvas = sim ? sim->GetDebugCanvas() : nullptr;
  if (!debugCanvas) {
    return 0;
  }

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 3));
  LuaPlus::LuaObject endObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject startObject(LuaPlus::LuaStackObject(state, 1));

  SDebugLine line{};
  line.p0 = SCR_FromLuaCopy<Wm3::Vector3f>(startObject);
  line.p1 = SCR_FromLuaCopy<Wm3::Vector3f>(endObject);
  line.depth0 = static_cast<std::int32_t>(SCR_DecodeColor(state, colorObject));
  line.depth1 = line.depth0;

  debugCanvas->DebugDrawLine(line);
  return 0;
}

/**
 * Address: 0x0075DDA0 (FUN_0075DDA0, cfunc_DrawLinePop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_DrawLinePopL`.
 */
int moho::cfunc_DrawLinePop(lua_State* const luaContext)
{
  return cfunc_DrawLinePopL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075DDC0 (FUN_0075DDC0, func_DrawLinePop_LuaFuncDef)
 *
 * What it does:
 * Publishes global `DrawLinePop(a,b,c)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_DrawLinePop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DrawLinePop",
    &moho::cfunc_DrawLinePop,
    nullptr,
    "<global>",
    kDrawLinePopHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075DE20 (FUN_0075DE20, cfunc_DrawLinePopL)
 *
 * What it does:
 * Reads `(startVec3, endVec3, color)`, draws the line, and emits one
 * wire-circle "pop" marker just past the line end.
 */
int moho::cfunc_DrawLinePopL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kDrawLinePopHelpText);

  Sim* const sim = ResolveGlobalSim(rawState);
  CDebugCanvas* const debugCanvas = sim ? sim->GetDebugCanvas() : nullptr;
  if (!debugCanvas) {
    return 0;
  }

  LuaPlus::LuaObject startObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject endObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 3));

  const Wm3::Vector3f start = SCR_FromLuaCopy<Wm3::Vector3f>(startObject);
  const Wm3::Vector3f end = SCR_FromLuaCopy<Wm3::Vector3f>(endObject);
  const std::uint32_t color = SCR_DecodeColor(state, colorObject);

  Wm3::Vector3f lineDirection{};
  lineDirection.x = start.x - end.x;
  lineDirection.y = start.y - end.y;
  lineDirection.z = start.z - end.z;

  const float directionLengthSquared =
    // 0x0075DF76: (z*z + y*y) + x*x.
    ((lineDirection.z * lineDirection.z) + (lineDirection.y * lineDirection.y)) + (lineDirection.x * lineDirection.x);
  if (directionLengthSquared > 0.0f) {
    const float scale = 2.0f / std::sqrt(directionLengthSquared);
    lineDirection.x *= scale;
    lineDirection.y *= scale;
    lineDirection.z *= scale;
  } else {
    lineDirection.x = 0.0f;
    lineDirection.y = 0.0f;
    lineDirection.z = 0.0f;
  }

  SDebugLine line{};
  line.p0 = start;
  line.p1 = end;
  line.depth0 = static_cast<std::int32_t>(color);
  line.depth1 = line.depth0;
  debugCanvas->DebugDrawLine(line);

  Wm3::Vector3f popCenter{};
  popCenter.x = end.x + lineDirection.x;
  popCenter.y = end.y + lineDirection.y;
  popCenter.z = end.z + lineDirection.z;

  const Wm3::Vector3f upAxis(0.0f, 1.0f, 0.0f);
  debugCanvas->AddWireCircle(upAxis, popCenter, 1.0f, color, 8u);
  return 0;
}

/**
 * Address: 0x0075E0D0 (FUN_0075E0D0, func_DrawCircle_LuaFuncDef)
 *
 * What it does:
 * Publishes global `DrawCircle(a,s,c)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_DrawCircle_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DrawCircle",
    &moho::cfunc_DrawCircle,
    nullptr,
    "<global>",
    kDrawCircleHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E0B0 (FUN_0075E0B0, cfunc_DrawCircle)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_DrawCircleL`.
 */
int moho::cfunc_DrawCircle(lua_State* const luaContext)
{
  return cfunc_DrawCircleL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E130 (FUN_0075E130, cfunc_DrawCircleL)
 *
 * What it does:
 * Reads `(centerVec3, sizeNumber, color)` from Lua and emits one wireframe
 * debug circle on the current sim debug canvas.
 */
int moho::cfunc_DrawCircleL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kDrawCircleHelpText);

  Sim* const sim = ResolveGlobalSim(rawState);
  CDebugCanvas* const debugCanvas = sim ? sim->GetDebugCanvas() : nullptr;
  if (!debugCanvas) {
    return 0;
  }

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 3));
  LuaPlus::LuaObject centerObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject sizeArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&sizeArg, "number");
  }

  const float size = static_cast<float>(lua_tonumber(rawState, 2));
  const std::uint32_t color = SCR_DecodeColor(state, colorObject);
  const Wm3::Vector3f center = SCR_FromLuaCopy<Wm3::Vector3f>(centerObject);
  const Wm3::Vector3f upAxis(0.0f, 1.0f, 0.0f);
  debugCanvas->AddWireCircle(upAxis, center, size, color, 8u);
  return 0;
}

/**
 * Address: 0x0068BD90 (FUN_0068BD90, cfunc_EntityAttachTo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityAttachToL`.
 */
int moho::cfunc_EntityAttachTo(lua_State* const luaContext)
{
  return cfunc_EntityAttachToL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068BE10 (FUN_0068BE10, cfunc_EntityAttachToL)
 *
 * What it does:
 * Reads `(selfEntity, parentEntity, parentBone)` and applies one attach-info
 * payload through `Entity::AttachTo`.
 */
int moho::cfunc_EntityAttachToL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 3, kEntityAttachToHelpText);

  const LuaPlus::LuaObject childObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const childEntity = SCR_FromLua_Entity(childObject, state);

  const LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const parentEntity = SCR_FromLua_Entity(parentObject, state);

  LuaPlus::LuaStackObject parentBoneArg(state, 3);
  const int parentBoneIndex = ENTSCR_ResolveBoneIndex(parentEntity, parentBoneArg, true);

  SEntAttachInfo attachInfo(parentEntity, 0, parentBoneIndex, VTransform());

  const bool didAttach = childEntity->AttachTo(attachInfo);
  attachInfo.TargetWeakLink().UnlinkFromOwnerChain();

  if (!didAttach) {
    const char* const parentName = ResolveBlueprintIdCString(parentEntity);
    const char* const childName = ResolveBlueprintIdCString(childEntity);
    LuaPlus::LuaState::Error(
      state,
      kEntityAttachFailureError,
      childName ? childName : "",
      parentName ? parentName : "",
      parentBoneIndex
    );
  }

  return 0;
}

/**
 * Address: 0x0068BDB0 (FUN_0068BDB0, func_EntityAttachTo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:AttachTo()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityAttachTo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "AttachTo",
    &moho::cfunc_EntityAttachTo,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityAttachToHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068F660 (FUN_0068F660, cfunc_EntitySetOrientation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntitySetOrientationL`.
 */
int moho::cfunc_EntitySetOrientation(lua_State* const luaContext)
{
  return cfunc_EntitySetOrientationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068F6E0 (FUN_0068F6E0, cfunc_EntitySetOrientationL)
 *
 * What it does:
 * Reads `(entity, orientation, immediate)`, writes pending orientation while
 * preserving current position, then optionally commits coords immediately.
 */
int moho::cfunc_EntitySetOrientationL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 3, kEntitySetOrientationHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 2));
  Wm3::Quatf orientation{};
  SCR_FromLuaCopy<Wm3::Quaternion<float>>(&orientationObject, &orientation);

  LuaPlus::LuaStackObject immediateArg(state, 3);
  const bool immediate = immediateArg.GetBoolean();

  VTransform transform = entity->GetTransformWm3();
  transform.orient_ = orientation;
  entity->SetPendingTransform(transform, 1.0f);
  if (immediate) {
    entity->AdvanceCoords();
    entity->AdvanceCoords();
  }
  return 0;
}

/**
 * Address: 0x0068F680 (FUN_0068F680, func_EntitySetOrientation_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:SetOrientation()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntitySetOrientation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetOrientation",
    &moho::cfunc_EntitySetOrientation,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntitySetOrientationHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068FA10 (FUN_0068FA10, cfunc_EntitySetPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntitySetPositionL`.
 */
int moho::cfunc_EntitySetPosition(lua_State* const luaContext)
{
  return cfunc_EntitySetPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068FA90 (FUN_0068FA90, cfunc_EntitySetPositionL)
 *
 * What it does:
 * Reads `(entity, position[, immediate])`, writes pending position while
 * preserving current orientation, then optionally commits coords immediately.
 */
int moho::cfunc_EntitySetPositionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kEntitySetPositionHelpText,
      2,
      3,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  VTransform transform = entity->GetTransformWm3();
  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  transform.pos_ = SCR_FromLuaCopy<Wm3::Vec3f>(positionObject);
  entity->SetPendingTransform(transform, 1.0f);

  LuaPlus::LuaStackObject immediateArg(state, 3);
  if (immediateArg.GetBoolean()) {
    entity->AdvanceCoords();
    entity->AdvanceCoords();
  }
  return 0;
}

/**
 * Address: 0x0068FA30 (FUN_0068FA30, func_EntitySetPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:SetPosition()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntitySetPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetPosition",
    &moho::cfunc_EntitySetPosition,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntitySetPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068FC10 (FUN_0068FC10, cfunc_EntityGetPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityGetPositionL`.
 */
int moho::cfunc_EntityGetPosition(lua_State* const luaContext)
{
  return cfunc_EntityGetPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068FC90 (FUN_0068FC90, cfunc_EntityGetPositionL)
 *
 * What it does:
 * Reads `(entity[, boneName])` and returns one Lua vector table for the entity
 * world position or one resolved bone world position.
 */
int moho::cfunc_EntityGetPositionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kEntityGetPositionHelpText,
      1,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLuaNoError_Entity(entityObject);
  if (!entity) {
    const Wm3::Vec3f zeroPosition(0.0f, 0.0f, 0.0f);
    const LuaPlus::LuaObject zeroObject = SCR_ToLua<Wm3::Vector3<float>>(state, zeroPosition);
    zeroObject.PushStack(state);
    return 1;
  }

  if (lua_gettop(rawState) > 1) {
    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);
    const Wm3::Vec3f position = entity->GetBoneWorldTransform(boneIndex).pos_;
    const LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3<float>>(state, position);
    positionObject.PushStack(state);
    return 1;
  }

  const Wm3::Vec3f position = entity->GetTransformWm3().pos_;
  LuaPlus::LuaObject& cachedPositionObject = entity->mLuaPositionCache;
  if (cachedPositionObject.IsTable()) {
    cachedPositionObject.SetNumber(1, position.x);
    cachedPositionObject.SetNumber(2, position.y);
    cachedPositionObject.SetNumber(3, position.z);
  } else {
    const LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3<float>>(state, position);
    cachedPositionObject = positionObject;
  }

  cachedPositionObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0068FC30 (FUN_0068FC30, func_EntityGetPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:GetPosition()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityGetPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetPosition",
    &moho::cfunc_EntityGetPosition,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityGetPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068FEE0 (FUN_0068FEE0, cfunc_EntityGetPositionXYZ)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntityGetPositionXYZL`.
 */
int moho::cfunc_EntityGetPositionXYZ(lua_State* const luaContext)
{
  return cfunc_EntityGetPositionXYZL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068FF60 (FUN_0068FF60, cfunc_EntityGetPositionXYZL)
 *
 * What it does:
 * Reads `(entity[, boneName])` and returns three Lua numbers `(x, y, z)` for
 * entity world position or resolved bone world position.
 */
int moho::cfunc_EntityGetPositionXYZL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kEntityGetPositionXYZHelpText,
      1,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  Wm3::Vec3f position{};
  if (lua_gettop(rawState) <= 1) {
    position = entity->GetTransformWm3().pos_;
  } else {
    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);
    position = entity->GetBoneWorldTransform(boneIndex).pos_;
  }

  lua_pushnumber(rawState, position.x);
  lua_pushnumber(rawState, position.y);
  lua_pushnumber(rawState, position.z);
  return 3;
}

/**
 * Address: 0x0068FF00 (FUN_0068FF00, func_EntityGetPositionXYZ_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:GetPositionXYZ()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityGetPositionXYZ_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetPositionXYZ",
    &moho::cfunc_EntityGetPositionXYZ,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityGetPositionXYZHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068CA80 (FUN_0068CA80, cfunc_EntityGetCollisionExtentsL)
 *
 * What it does:
 * Reads one entity Lua object and returns one table containing `Min` and `Max`
 * vector entries when collision extents are available.
 */
int moho::cfunc_EntityGetCollisionExtentsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kEntityGetCollisionExtentsHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);
  CColPrimitiveBase* const collisionShape = entity->CollisionExtents;

  LuaPlus::LuaObject resultObject(state);
  if (collisionShape) {
    const Wm3::AxisAlignedBox3f bounds = collisionShape->GetBoundingBox();

    resultObject.AssignNewTable(state, 0, 0u);

    const LuaPlus::LuaObject minObject = SCR_ToLua<Wm3::Vector3<float>>(state, bounds.Min);
    resultObject.SetObject("Min", minObject);

    const LuaPlus::LuaObject maxObject = SCR_ToLua<Wm3::Vector3<float>>(state, bounds.Max);
    resultObject.SetObject("Max", maxObject);
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0068DE80 (FUN_0068DE80, cfunc_EntityIsIntelEnabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntityIsIntelEnabledL`.
 */
int moho::cfunc_EntityIsIntelEnabled(lua_State* const luaContext)
{
  return cfunc_EntityIsIntelEnabledL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068DEA0 (FUN_0068DEA0, func_EntityIsIntelEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:IsIntelEnabled()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityIsIntelEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsIntelEnabled",
    &moho::cfunc_EntityIsIntelEnabled,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityIsIntelEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068DF00 (FUN_0068DF00, cfunc_EntityIsIntelEnabledL)
 *
 * What it does:
 * Reads `(entity, intelType)`, validates intel initialization, and returns one
 * Lua boolean indicating whether the selected intel lane is currently enabled.
 */
int moho::cfunc_EntityIsIntelEnabledL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kEntityIsIntelEnabledHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntityIsIntelEnabledInitWarning);
  }

  const bool enabled = entity->mIntelManager ? IsIntelEnabledForType(*entity->mIntelManager, intelType) : false;
  lua_pushboolean(rawState, enabled ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0068E050 (FUN_0068E050, cfunc_EntityEnableIntel)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityEnableIntelL`.
 */
int moho::cfunc_EntityEnableIntel(lua_State* const luaContext)
{
  return cfunc_EntityEnableIntelL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E070 (FUN_0068E070, func_EntityEnableIntel_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:EnableIntel()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityEnableIntel_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EnableIntel",
    &moho::cfunc_EntityEnableIntel,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityEnableIntelHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068E0D0 (FUN_0068E0D0, cfunc_EntityEnableIntelL)
 *
 * What it does:
 * Reads `(entity, intelType)`, enables that intel lane, and requeues the
 * entity into sim coord updates.
 */
int moho::cfunc_EntityEnableIntelL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kEntityEnableIntelHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntityEnableIntelInitWarning);
  }

  if (CIntel* const intelManager = entity->mIntelManager; intelManager != nullptr) {
    if (CIntelPosHandle* const handle = ResolveIntelPosHandleForType(*intelManager, intelType); handle != nullptr) {
      if (handle->mEnabled == 0u) {
        handle->mEnabled = 1u;
        handle->AddViz();
      }
    } else if (CIntelToggleState* const toggleState = ResolveIntelToggleStateForType(*intelManager, intelType);
               toggleState != nullptr && toggleState->present != 0u) {
      toggleState->enabled = 1u;
    }
  }

  entity->mVarDat.mIntelAttributes.SetEnabled(IntelAttributeLane(intelType), true);
  RequeueEntityCoordUpdate(*entity);
  return 0;
}

/**
 * Address: 0x0068E2F0 (FUN_0068E2F0, cfunc_EntityDisableIntel)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntityDisableIntelL`.
 */
int moho::cfunc_EntityDisableIntel(lua_State* const luaContext)
{
  return cfunc_EntityDisableIntelL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E310 (FUN_0068E310, func_EntityDisableIntel_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:DisableIntel()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityDisableIntel_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DisableIntel",
    &moho::cfunc_EntityDisableIntel,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityDisableIntelHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068E370 (FUN_0068E370, cfunc_EntityDisableIntelL)
 *
 * What it does:
 * Reads `(entity, intelType)`, disables that intel lane, and requeues the
 * entity into sim coord updates.
 */
int moho::cfunc_EntityDisableIntelL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kEntityDisableIntelHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntityDisableIntelInitWarning);
  }

  if (CIntel* const intelManager = entity->mIntelManager; intelManager != nullptr) {
    if (CIntelPosHandle* const handle = ResolveIntelPosHandleForType(*intelManager, intelType); handle != nullptr) {
      if (handle->mEnabled != 0u) {
        handle->SubViz();
        handle->mEnabled = 0u;
      }
    } else if (CIntelToggleState* const toggleState = ResolveIntelToggleStateForType(*intelManager, intelType);
               toggleState != nullptr && toggleState->present != 0u) {
      toggleState->enabled = 0u;
    }
  }

  entity->mVarDat.mIntelAttributes.SetEnabled(IntelAttributeLane(intelType), false);
  RequeueEntityCoordUpdate(*entity);
  return 0;
}

/**
 * Address: 0x0068E590 (FUN_0068E590, cfunc_EntitySetIntelRadius)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntitySetIntelRadiusL`.
 */
int moho::cfunc_EntitySetIntelRadius(lua_State* const luaContext)
{
  return cfunc_EntitySetIntelRadiusL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E5B0 (FUN_0068E5B0, func_EntitySetIntelRadius_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:SetIntelRadius()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntitySetIntelRadius_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetIntelRadius",
    &moho::cfunc_EntitySetIntelRadius,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntitySetIntelRadiusHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068E610 (FUN_0068E610, cfunc_EntitySetIntelRadiusL)
 *
 * What it does:
 * Reads `(entity, intelType, radius)`, updates intel handle radius and synced
 * intel-attribute radius, then requeues coord updates.
 */
int moho::cfunc_EntitySetIntelRadiusL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kEntitySetIntelRadiusHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  LuaPlus::LuaStackObject radiusArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&radiusArg, "integer");
  }

  const int inputRadius = static_cast<int>(lua_tonumber(rawState, 3));
  const int newRadius = inputRadius > 0 ? inputRadius : 0;

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntitySetIntelRadiusInitWarning);
  }

  if (CIntel* const intelManager = entity->mIntelManager; intelManager != nullptr) {
    if (CIntelPosHandle* const handle = ResolveIntelPosHandleForType(*intelManager, intelType); handle != nullptr) {
      handle->ChangeRadius(newRadius);
    }
  }

  if (IsIntelAttributeLane(intelType)) {
    entity->mVarDat.mIntelAttributes.SetIntelRadius(IntelAttributeLane(intelType), newRadius);
  }

  RequeueEntityCoordUpdate(*entity);
  return 0;
}

/**
 * Address: 0x0068E7D0 (FUN_0068E7D0, cfunc_EntityGetIntelRadius)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntityGetIntelRadiusL`.
 */
int moho::cfunc_EntityGetIntelRadius(lua_State* const luaContext)
{
  return cfunc_EntityGetIntelRadiusL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E7F0 (FUN_0068E7F0, func_EntityGetIntelRadius_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:GetIntelRadius()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityGetIntelRadius_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetIntelRadius",
    &moho::cfunc_EntityGetIntelRadius,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityGetIntelRadiusHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068E850 (FUN_0068E850, cfunc_EntityGetIntelRadiusL)
 *
 * What it does:
 * Reads `(entity, intelType)`, validates intel initialization, and returns
 * the selected intel radius as one Lua number.
 */
int moho::cfunc_EntityGetIntelRadiusL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kEntityGetIntelRadiusHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntityGetIntelRadiusInitWarning);
  }

  std::uint32_t radius = 0u;
  if (IsIntelAttributeLane(intelType)) {
    radius = entity->mVarDat.mIntelAttributes.GetRange(IntelAttributeLane(intelType));
  }

  lua_pushnumber(rawState, static_cast<float>(radius));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0068E9A0 (FUN_0068E9A0, cfunc_EntityInitIntel)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityInitIntelL`.
 */
int moho::cfunc_EntityInitIntel(lua_State* const luaContext)
{
  return cfunc_EntityInitIntelL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E9C0 (FUN_0068E9C0, func_EntityInitIntel_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:InitIntel()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityInitIntel_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "InitIntel",
    &moho::cfunc_EntityInitIntel,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityInitIntelHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068EA20 (FUN_0068EA20, cfunc_EntityInitIntelL)
 *
 * What it does:
 * Reads `(entity, army, intelType[, radius])`, initializes/updates one intel
 * lane, refreshes handle positions, and requeues coord updates.
 */
int moho::cfunc_EntityInitIntelL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 3 || argumentCount > 4) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kEntityInitIntelHelpText,
      3,
      4,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (!army) {
    LuaPlus::LuaState::Error(state, kEntityInitIntelUnknownArmyWarning);
    return 0;
  }
  CAiReconDBImpl* const reconDb = army->GetReconDB();

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 3);
  const char* const intelTypeName = lua_tostring(rawState, 3);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  int radius = 0;
  if (argumentCount == 4) {
    LuaPlus::LuaStackObject radiusArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&radiusArg, "integer");
    }

    radius = static_cast<int>(lua_tonumber(rawState, 4));
    if (static_cast<int>(intelType) > static_cast<int>(INTEL_None)
        && static_cast<int>(intelType) <= static_cast<int>(INTEL_CloakField) && radius == 0) {
      LuaPlus::LuaState::Error(state, kEntityInitIntelRadiusWarning);
    }
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  CIntel* intelManager = entity->mIntelManager;
  if (intelManager != nullptr) {
    intelManager->InitIntel(static_cast<std::int32_t>(intelType), static_cast<std::uint32_t>(radius), reconDb, sim);
  } else {
    auto* const createdIntelManager = new CIntel();
    createdIntelManager->InitIntel(static_cast<std::int32_t>(intelType), static_cast<std::uint32_t>(radius), reconDb, sim);
    entity->mIntelManager = createdIntelManager;
    intelManager = createdIntelManager;
  }

  const std::int32_t currentTick = sim->mCurTick;
  const Wm3::Vec3f position = entity->GetTransformWm3().pos_;
  for (std::size_t index = 0; index < CIntel::kHandleCount; ++index) {
    CIntelPosHandle* const handle = intelManager->mIntelHandles[index].get();
    if (handle != nullptr) {
      handle->UpdatePos(currentTick, position);
    }
  }

  if (IsIntelAttributeLane(intelType)) {
    entity->mVarDat.mIntelAttributes.SetIntelRadius(IntelAttributeLane(intelType), static_cast<int>(radius));
  }

  RequeueEntityCoordUpdate(*entity);
  return 0;
}

/**
 * Address: 0x0068ED50 (FUN_0068ED50, cfunc_EntityAddShooter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityAddShooterL`.
 */
int moho::cfunc_EntityAddShooter(lua_State* const luaContext)
{
  return cfunc_EntityAddShooterL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068ED70 (FUN_0068ED70, func_EntityAddShooter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:AddShooter()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityAddShooter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "AddShooter",
    &moho::cfunc_EntityAddShooter,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityAddShooterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068EDD0 (FUN_0068EDD0, cfunc_EntityAddShooterL)
 *
 * What it does:
 * Reads `(entity, shooter)` and inserts `shooter` into the entity shooter set.
 */
int moho::cfunc_EntityAddShooterL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 2, kEntityAddShooterHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  const LuaPlus::LuaObject shooterObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const shooter = SCR_FromLua_Entity(shooterObject, state);
  if (shooter != nullptr) {
    (void)entity->mShooters.Add(shooter);
  }

  return 0;
}

/**
 * Address: 0x0068EEC0 (FUN_0068EEC0, cfunc_EntityRemoveShooter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityRemoveShooterL`.
 */
int moho::cfunc_EntityRemoveShooter(lua_State* const luaContext)
{
  return cfunc_EntityRemoveShooterL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068EEE0 (FUN_0068EEE0, func_EntityRemoveShooter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:RemoveShooter()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityRemoveShooter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "RemoveShooter",
    &moho::cfunc_EntityRemoveShooter,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityRemoveShooterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068EF40 (FUN_0068EF40, cfunc_EntityRemoveShooterL)
 *
 * What it does:
 * Reads `(entity, shooter)` and removes `shooter` from the entity shooter set.
 */
int moho::cfunc_EntityRemoveShooterL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 2, kEntityRemoveShooterHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  const LuaPlus::LuaObject shooterObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const shooter = SCR_FromLua_Entity(shooterObject, state);
  if (shooter != nullptr) {
    (void)entity->mShooters.Remove(shooter);
  }

  return 0;
}

/**
 * Address: 0x006FC3B0 (FUN_006FC3B0, cfunc_CreateProp)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CreatePropL`.
 */
int moho::cfunc_CreateProp(lua_State* const luaContext)
{
  return cfunc_CreatePropL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006FC430 (FUN_006FC430, cfunc_CreatePropL)
 *
 * What it does:
 * Reads `(location, prop_blueprint_id)`, creates one prop in sim space, and
 * returns the created prop Lua object.
 */
int moho::cfunc_CreatePropL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kCreatePropHelpText);

  LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 1));
  const Wm3::Vec3f location = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);

  LuaPlus::LuaStackObject blueprintArg(state, 2);
  const char* const blueprintId = lua_tostring(rawState, 2);
  if (!blueprintId) {
    LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
  }

  VTransform transform{};
  transform.pos_ = location;

  Sim* const sim = ResolveGlobalSim(rawState);
  Prop* const prop = PROP_Create(sim, transform, blueprintId);
  if (!prop) {
    LuaPlus::LuaState::Error(state, "Unable to create prop '%s'", blueprintId ? blueprintId : "");
  }

  prop->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006FC3D0 (FUN_006FC3D0, func_CreateProp_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CreateProp`.
 */
moho::CScrLuaInitForm* moho::func_CreateProp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "CreateProp",
    &moho::cfunc_CreateProp,
    nullptr,
    "<global>",
    kCreatePropHelpText
  );
  return &binder;
}


/**
 * Address: 0x006FC590 (FUN_006FC590, cfunc_EntityCreatePropAtBone)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_EntityCreatePropAtBoneL`.
 */
int moho::cfunc_EntityCreatePropAtBone(lua_State* const luaContext)
{
  return cfunc_EntityCreatePropAtBoneL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006FC610 (FUN_006FC610, cfunc_EntityCreatePropAtBoneL)
 *
 * What it does:
 * Reads `(entity, boneIndexOrName, propBlueprintId)` from Lua, creates a prop at
 * the resolved entity bone transform, then re-warps it using bone-local
 * compensation so the prop bone origin aligns to that entity bone.
 */
int moho::cfunc_EntityCreatePropAtBoneL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 3, kEntityCreatePropAtBoneHelpText);

  LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  LuaPlus::LuaStackObject boneArg(state, 2);
  const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);

  LuaPlus::LuaStackObject blueprintArg(state, 3);
  const char* const blueprintId = lua_tostring(state->m_state, 3);
  if (!blueprintId) {
    LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
  }

  const VTransform entityBoneTransform = entity->GetBoneWorldTransform(boneIndex);

  Sim* const sim = entity->SimulationRef;
  Prop* const prop = PROP_Create(sim, entityBoneTransform, blueprintId);
  if (!prop) {
    LuaPlus::LuaState::Error(state, "Unable to create prop '%s'", blueprintId ? blueprintId : "");
  }

  const VTransform propBoneInverse = prop->GetBoneLocalTransform(0).Inverse();
  const VTransform alignedTransform = VTransform::Compose(propBoneInverse, entityBoneTransform);
  prop->Warp(alignedTransform);

  prop->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006FC5B0 (FUN_006FC5B0, func_EntityCreatePropAtBone_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:CreatePropAtBone()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityCreatePropAtBone_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "CreatePropAtBone",
    &moho::cfunc_EntityCreatePropAtBone,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityCreatePropAtBoneHelpText
  );
  return &binder;
}

/**
 * Address: 0x00547030 (FUN_00547030, cfunc_CreateResourceDeposit)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CreateResourceDepositL`.
 */
int moho::cfunc_CreateResourceDeposit(lua_State* const luaContext)
{
  return cfunc_CreateResourceDepositL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005470B0 (FUN_005470B0, cfunc_CreateResourceDepositL)
 *
 * What it does:
 * Reads `(type, x, y, z, size)` from Lua, translates the deposit type string,
 * and emits one resource deposit point into sim resources.
 */
int moho::cfunc_CreateResourceDepositL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 5, kCreateResourceDepositHelpText);

  CSimResources* const resources = ResolveGlobalSim(state->m_state)->mSimResources.px;

  LuaPlus::LuaStackObject depositTypeArg{};
  depositTypeArg.m_state = state;
  depositTypeArg.m_stackIndex = 1;
  const char* const depositTypeText = lua_tostring(state->m_state, 1);
  if (!depositTypeText) {
    LuaPlus::LuaStackObject::TypeError(&depositTypeArg, "string");
  }

  const fa::string depositTypeName{depositTypeText != nullptr ? depositTypeText : ""};

  LuaPlus::LuaStackObject zArg{};
  zArg.m_state = state;
  zArg.m_stackIndex = 4;
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "number");
  }
  const float posZ = static_cast<float>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject yArg{};
  yArg.m_state = state;
  yArg.m_stackIndex = 3;
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&yArg, "number");
  }
  const float posY = static_cast<float>(lua_tonumber(state->m_state, 3));

  LuaPlus::LuaStackObject xArg{};
  xArg.m_state = state;
  xArg.m_stackIndex = 2;
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }

  Wm3::Vec3f position{};
  position.x = static_cast<float>(lua_tonumber(state->m_state, 2));
  position.y = posY;
  position.z = posZ;

  LuaPlus::LuaStackObject sizeArg0{};
  sizeArg0.m_state = state;
  sizeArg0.m_stackIndex = 5;
  if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&sizeArg0, "integer");
  }
  const int sizeY = static_cast<int>(lua_tonumber(state->m_state, 5));

  LuaPlus::LuaStackObject sizeArg1{};
  sizeArg1.m_state = state;
  sizeArg1.m_stackIndex = 5;
  if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&sizeArg1, "integer");
  }

  Wm3::Vec2i size{};
  size.x = static_cast<int>(lua_tonumber(state->m_state, 5));
  size.y = sizeY;

  static fa::string resourceDepositTypeNames[3] = {
    fa::string(""),
    fa::string("Mass"),
    fa::string("Hydrocarbon"),
  };

  fa::string* const match =
    moho::SearchStringArrayFor(resourceDepositTypeNames, resourceDepositTypeNames + 3, &depositTypeName);
  const int depositTypeIndex =
    match != resourceDepositTypeNames + 3 ? static_cast<int>(match - resourceDepositTypeNames) : 0;

  if (depositTypeIndex == 0) {
    gpg::Logf(kUnknownResourceDepositTypeMessage, depositTypeName.c_str());
  }

  resources->AddDepositPoint(static_cast<EDepositType>(depositTypeIndex), &position, &size);
  return 1;
}

/**
 * Address: 0x00547050 (FUN_00547050, func_CreateResourceDeposit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CreateResourceDeposit`.
 */
moho::CScrLuaInitForm* moho::func_CreateResourceDeposit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "CreateResourceDeposit",
    &moho::cfunc_CreateResourceDeposit,
    nullptr,
    "<global>",
    kCreateResourceDepositHelpText
  );
  return &binder;
}

/**
 * Address: 0x0128CC35 (the sim-lane `SessionIsReplay` body; IDA's
 * `cfunc_SessionIsReplaySim` label sits on 0x0128BB27, which is other code)
 *
 * What it does:
 * Pushes whether the current world session is in replay mode.
 *
 * The `.exxt` section (VA 0x0128B000) is FAF's own patch region, and it does
 * register this into the sim set -- the earlier note here claimed the string
 * `"SessionIsReplay"` had "exactly one reference in the whole image" and told
 * the next reader not to add a binder. Scanning the shipped PE refutes that:
 * the string at 0x00E4AFBC has **two** referents.
 *
 *   0x00897DA5  `func_SessionIsReplayUser_LuaFuncDef`, the user binder above;
 *   0x012928BF  a register block at 0x012928A5 that fills a def at 0x012932A8
 *               with the method name 0x00E4AFBC, class `"<global>"`
 *               (0x00E00D90), the help string 0x00E4AF84 it shares with the
 *               user form, and a function slot holding **0x0128CC35**.
 *
 * 0x0128CC35 is this body: `mov eax, ds:sWldSession` / `movzx eax, byte ptr
 * [eax+484h]` (`CWldSession::IsReplay`) / `lua_pushboolean` / `mov eax, 1`.
 * IDA labels 0x0128BB27 with this name, but that address holds unrelated code
 * -- neither the string reference nor the def's function slot points there.
 *
 * The consequence of leaving it unregistered is not confined to one thread:
 * `lua/sim/score.lua(288)` calls `SessionIsReplay()`, the missing global aborts
 * the score pass, the score UI never receives data, and
 * `/lua/ui/game/layouts/score_mini.lua` then reports a circular lazy-evaluation
 * dependency on every frame -- 60 in the first seconds of a live session, each
 * throwing a C++ exception out of the Lua binding.
 */
int moho::cfunc_SessionIsReplaySim(lua_State* const luaContext)
{
  if (!luaContext) {
    return 0;
  }

  const CWldSession* const session = WLD_GetActiveSession();
  lua_pushboolean(luaContext, (session && session->IsReplay) ? 1 : 0);
  return 1;
}

/**
 * Address: 0x012928A5 (the `.exxt` register block that fills
 * `luadef_SessionIsReplaySim` at 0x012932A8 and binds 0x0128CC35)
 *
 * What it does:
 * Publishes the sim-lane Lua binder definition for global `SessionIsReplay`.
 * The sim and user Lua lanes have separate global tables and separate init
 * sets, so the user-lane form above is not visible to `/lua/sim/ *`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsReplaySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SessionIsReplay",
    &moho::cfunc_SessionIsReplaySim,
    nullptr,
    "<global>",
    kSessionIsReplayUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x007080B0 (FUN_007080B0, cfunc_ShouldCreateInitialArmyUnits)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ShouldCreateInitialArmyUnitsL`.
 */
int moho::cfunc_ShouldCreateInitialArmyUnits(lua_State* const luaContext)
{
  return cfunc_ShouldCreateInitialArmyUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007080D0 (FUN_007080D0, func_ShouldCreateInitialArmyUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ShouldCreateInitialArmyUnits`.
 */
moho::CScrLuaInitForm* moho::func_ShouldCreateInitialArmyUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ShouldCreateInitialArmyUnits",
    &moho::cfunc_ShouldCreateInitialArmyUnits,
    nullptr,
    "<global>",
    kShouldCreateInitialArmyUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708130 (FUN_00708130, cfunc_ShouldCreateInitialArmyUnitsL)
 *
 * What it does:
 * Returns one Lua boolean indicating whether startup should spawn initial army
 * units (disabled by `/noinitialunits`).
 */
int moho::cfunc_ShouldCreateInitialArmyUnitsL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kShouldCreateInitialArmyUnitsHelpText);

  const bool disableInitialUnits = CFG_GetArgOption("/noinitialunits", 0u, nullptr);
  lua_pushboolean(state->m_state, !disableInitialUnits);
  return 1;
}

/**
 * Address: 0x007081A0 (FUN_007081A0, cfunc_ListArmies)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ListArmiesL`.
 */
int moho::cfunc_ListArmies(lua_State* const luaContext)
{
  return cfunc_ListArmiesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007081C0 (FUN_007081C0, func_ListArmies_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ListArmies`.
 */
moho::CScrLuaInitForm* moho::func_ListArmies_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ListArmies",
    &moho::cfunc_ListArmies,
    nullptr,
    "<global>",
    kListArmiesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708220 (FUN_00708220, cfunc_ListArmiesL)
 *
 * What it does:
 * Returns one Lua array table containing army names in simulation order.
 */
int moho::cfunc_ListArmiesL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kListArmiesHelpText);

  Sim* const sim = SIM_FromLuaState(state);
  LuaPlus::LuaObject armiesTable(state);
  armiesTable.AssignNewTable(state, 0, 0u);

  if (sim != nullptr) {
    for (std::size_t armyIndex = 0; armyIndex < sim->mArmiesList.size(); ++armyIndex) {
      CArmyImpl* const army = sim->mArmiesList[armyIndex];
      const char* const armyName = (army && army->mConstDat.mArmyName.c_str()) ? army->mConstDat.mArmyName.c_str() : "";
      armiesTable.SetString(static_cast<std::int32_t>(armyIndex + 1u), armyName);
    }
  }

  armiesTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x007085E0 (FUN_007085E0, cfunc_GenerateArmyStart)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GenerateArmyStartL`.
 */
int moho::cfunc_GenerateArmyStart(lua_State* const luaContext)
{
  return cfunc_GenerateArmyStartL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708600 (FUN_00708600, func_GenerateArmyStart_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GenerateArmyStart`.
 */
moho::CScrLuaInitForm* moho::func_GenerateArmyStart_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GenerateArmyStart",
    &moho::cfunc_GenerateArmyStart,
    nullptr,
    "<global>",
    kGenerateArmyStartHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708660 (FUN_00708660, cfunc_GenerateArmyStartL)
 *
 * What it does:
 * Reads one army selector and forwards start generation to `CArmyImpl`.
 */
int moho::cfunc_GenerateArmyStartL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kGenerateArmyStartHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  army->GenerateArmyStart();
  return 0;
}

/**
 * Address: 0x00708970 (FUN_00708970, cfunc_ArmyInitializePrebuiltUnits)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_ArmyInitializePrebuiltUnitsL`.
 */
int moho::cfunc_ArmyInitializePrebuiltUnits(lua_State* const luaContext)
{
  return cfunc_ArmyInitializePrebuiltUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708990 (FUN_00708990, func_ArmyInitializePrebuiltUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ArmyInitializePrebuiltUnits`.
 */
moho::CScrLuaInitForm* moho::func_ArmyInitializePrebuiltUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ArmyInitializePrebuiltUnits",
    &moho::cfunc_ArmyInitializePrebuiltUnits,
    nullptr,
    "<global>",
    kArmyInitializePrebuiltUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x007089F0 (FUN_007089F0, cfunc_ArmyInitializePrebuiltUnitsL)
 *
 * What it does:
 * Reads one army selector and runs `OnSpawnPreBuiltUnits` on that army's
 * brain script object.
 */
int moho::cfunc_ArmyInitializePrebuiltUnitsL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kArmyInitializePrebuiltUnitsHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  army->GetArmyBrain()->OnSpawnPreBuiltUnits();
  return 0;
}

/**
 * Address: 0x00709D50 (FUN_00709D50, cfunc_ArmyIsCivilian)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ArmyIsCivilianL`.
 */
int moho::cfunc_ArmyIsCivilian(lua_State* const luaContext)
{
  return cfunc_ArmyIsCivilianL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709D70 (FUN_00709D70, func_ArmyIsCivilian_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ArmyIsCivilian`.
 */
moho::CScrLuaInitForm* moho::func_ArmyIsCivilian_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ArmyIsCivilian",
    &moho::cfunc_ArmyIsCivilian,
    nullptr,
    "<global>",
    kArmyIsCivilianHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709DD0 (FUN_00709DD0, cfunc_ArmyIsCivilianL)
 *
 * What it does:
 * Returns whether the selected army is civilian.
 */
int moho::cfunc_ArmyIsCivilianL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kArmyIsCivilianHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  lua_pushboolean(rawState, (army != nullptr && army->mConstDat.mIsCivilian != 0u) ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0070A920 (FUN_0070A920, cfunc_OkayToMessWithArmy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_OkayToMessWithArmyL`.
 */
int moho::cfunc_OkayToMessWithArmy(lua_State* const luaContext)
{
  return cfunc_OkayToMessWithArmyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070A940 (FUN_0070A940, func_OkayToMessWithArmy_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `OkayToMessWithArmy`.
 */
moho::CScrLuaInitForm* moho::func_OkayToMessWithArmy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "OkayToMessWithArmy",
    &moho::cfunc_OkayToMessWithArmy,
    nullptr,
    "<global>",
    kOkayToMessWithArmyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070A9A0 (FUN_0070A9A0, cfunc_OkayToMessWithArmyL)
 *
 * What it does:
 * Returns true when current command source is valid for that army or cheats
 * are enabled.
 */
int moho::cfunc_OkayToMessWithArmyL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kOkayToMessWithArmyHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  bool allowed = false;
  if (army != nullptr && army->mVarDat.mIsOutOfGame == 0u) {
    Sim* const sim = army->GetSim();
    if (sim != nullptr) {
      const int commandSource = sim->mCurCommandSource;
      allowed = commandSource != static_cast<int>(kInvalidCommandSource) &&
        army->mVarDat.mValidCommandSources.Contains(static_cast<std::uint32_t>(commandSource));
      if (!allowed) {
        allowed = sim->CheatsEnabled();
      }
    }
  }

  lua_pushboolean(rawState, allowed ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0070AA60 (FUN_0070AA60, cfunc_ArmyIsOutOfGame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ArmyIsOutOfGameL`.
 */
int moho::cfunc_ArmyIsOutOfGame(lua_State* const luaContext)
{
  return cfunc_ArmyIsOutOfGameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070AA80 (FUN_0070AA80, func_ArmyIsOutOfGame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ArmyIsOutOfGame`.
 */
moho::CScrLuaInitForm* moho::func_ArmyIsOutOfGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ArmyIsOutOfGame",
    &moho::cfunc_ArmyIsOutOfGame,
    nullptr,
    "<global>",
    kArmyIsOutOfGameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070AAE0 (FUN_0070AAE0, cfunc_ArmyIsOutOfGameL)
 *
 * What it does:
 * Returns whether the selected army has been marked out-of-game.
 */
int moho::cfunc_ArmyIsOutOfGameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kArmyIsOutOfGameHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  lua_pushboolean(rawState, (army != nullptr && army->mVarDat.mIsOutOfGame != 0u) ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00708A70 (FUN_00708A70, cfunc_ArmyGetHandicap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ArmyGetHandicapL`.
 */
int moho::cfunc_ArmyGetHandicap(lua_State* const luaContext)
{
  return cfunc_ArmyGetHandicapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708A90 (FUN_00708A90, func_ArmyGetHandicap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ArmyGetHandicap`.
 */
moho::CScrLuaInitForm* moho::func_ArmyGetHandicap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ArmyGetHandicap",
    &moho::cfunc_ArmyGetHandicap,
    nullptr,
    "<global>",
    kArmyGetHandicapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708AF0 (FUN_00708AF0, cfunc_ArmyGetHandicapL)
 *
 * What it does:
 * Resolves one army selector and returns configured handicap or zero.
 */
int moho::cfunc_ArmyGetHandicapL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kArmyGetHandicapHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  float handicap = 0.0f;
  if (army->mVarDat.mHandicapValue != 0.0f) {
    handicap = army->mVarDat.mHandicapExtra;
  }
  lua_pushnumber(state->m_state, handicap);
  return 1;
}

/**
 * Address: 0x00708870 (FUN_00708870, cfunc_InitializeArmyAI)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_InitializeArmyAIL`.
 */
int moho::cfunc_InitializeArmyAI(lua_State* const luaContext)
{
  return cfunc_InitializeArmyAIL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708890 (FUN_00708890, func_InitializeArmyAI_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `InitializeArmyAI`.
 */
moho::CScrLuaInitForm* moho::func_InitializeArmyAI_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "InitializeArmyAI",
    &moho::cfunc_InitializeArmyAI,
    nullptr,
    "<global>",
    kInitializeArmyAIHelpText
  );
  return &binder;
}

/**
 * Address: 0x007088F0 (FUN_007088F0, cfunc_InitializeArmyAIL)
 *
 * What it does:
 * Resolves one army selector and invokes `CAiBrain::Initialize` on that army
 * brain object.
 */
int moho::cfunc_InitializeArmyAIL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kInitializeArmyAIHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CAiBrain* const brain = army ? army->GetArmyBrain() : nullptr;
  if (brain != nullptr) {
    brain->Initialize();
  }
  return 0;
}

/**
 * Address: 0x0074B850 (FUN_0074B850, func_EndGame_LuaFuncDef)
 *
 * What it does:
 * Creates/returns the global Lua binder form for `EndGame`.
 */
moho::CScrLuaInitForm* moho::func_EndGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EndGame",
    &moho::cfunc_EndGame,
    nullptr,
    "<global>",
    "Signal the end of the game.  Acts like a permanent pause."
  );
  return &binder;
}

/**
 * Address: 0x0075CEC0 (FUN_0075CEC0, cfunc_AudioSetLanguageSim)
 *
 * What it does:
 * Validates `AudioSetLanguage(name)` argument count for sim Lua lane.
 */
int moho::cfunc_AudioSetLanguageSim(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  moho::SCR_ExpectExactArgs(state, 1, kAudioSetLanguageSimHelpText);
  return 0;
}

/**
 * Address: 0x0075CF00 (FUN_0075CF00, func_AudioSetLanguageSim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `AudioSetLanguage(name)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_AudioSetLanguageSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "AudioSetLanguage",
    &moho::cfunc_AudioSetLanguageSim,
    nullptr,
    "<global>",
    kAudioSetLanguageSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075DA80 (FUN_0075DA80, cfunc_SubmitXMLArmyStats)
 *
 * What it does:
 * Validates no args and raises the sim-side XML army-stats submit request
 * flag.
 */
int moho::cfunc_SubmitXMLArmyStats(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  moho::SCR_ExpectExactArgs(state, 0, kSubmitXMLArmyStatsHelpText);

  if (Sim* const sim = ResolveGlobalSim(state->m_state); sim != nullptr) {
    sim->mRequestXMLArmyStatsSubmit = true;
  }
  return 0;
}

/**
 * Address: 0x0075DAD0 (FUN_0075DAD0, func_SubmitXMLArmyStats_LuaFuncDef)
 *
 * What it does:
 * Publishes global `SubmitXMLArmyStats()` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_SubmitXMLArmyStats_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SubmitXMLArmyStats",
    &moho::cfunc_SubmitXMLArmyStats,
    nullptr,
    "<global>",
    kSubmitXMLArmyStatsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00761570 (FUN_00761570, cfunc_PlayLoop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_PlayLoopL`.
 */
int moho::cfunc_PlayLoop(lua_State* const luaContext)
{
  return cfunc_PlayLoopL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00761590 (FUN_00761590, func_PlayLoop_LuaFuncDef)
 *
 * What it does:
 * Publishes global `PlayLoop(sndParams)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_PlayLoop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "PlayLoop",
    &moho::cfunc_PlayLoop,
    nullptr,
    "<global>",
    kPlayLoopHelpText
  );
  return &binder;
}

/**
 * Address: 0x007615F0 (FUN_007615F0, cfunc_PlayLoopL)
 *
 * What it does:
 * Builds one `HSound` loop handle from `CSndParams`, queues it in sim sound
 * manager, binds Lua userdata, and returns the handle object.
 */
int moho::cfunc_PlayLoopL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kPlayLoopHelpText);

  LuaPlus::LuaObject sndParamsObject(LuaPlus::LuaStackObject(state, 1));
  CSndParams* const sndParams = *func_GetCObj_CSndParams(sndParamsObject);
  HSound* const sound = new HSound(sndParams);

  Sim* const sim = ResolveGlobalSim(rawState);
  if (sim != nullptr && sim->mSoundManager != nullptr) {
    (void)sim->mSoundManager->AddLoop(sound);
  }

  func_CreateLuaHSoundObject(state, sound);
  sound->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00761700 (FUN_00761700, cfunc_StopLoop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_StopLoopL`.
 */
int moho::cfunc_StopLoop(lua_State* const luaContext)
{
  return cfunc_StopLoopL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00761720 (FUN_00761720, func_StopLoop_LuaFuncDef)
 *
 * What it does:
 * Publishes global `StopLoop(handle)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_StopLoop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "StopLoop",
    &moho::cfunc_StopLoop,
    nullptr,
    "<global>",
    kStopLoopHelpText
  );
  return &binder;
}

/**
 * Address: 0x00761780 (FUN_00761780, cfunc_StopLoopL)
 *
 * What it does:
 * Resolves one `HSound` loop handle and either requests stop on sim sound
 * manager or destroys the unbound handle when no manager exists.
 */
int moho::cfunc_StopLoopL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kStopLoopHelpText);

  const LuaPlus::LuaObject soundObject(LuaPlus::LuaStackObject(state, 1));
  HSound* const sound = SCR_FromLua_HSound(soundObject, state);

  Sim* const sim = ResolveGlobalSim(rawState);
  if (sim != nullptr && sim->mSoundManager != nullptr) {
    (void)sim->mSoundManager->StopLoop(sound);
    return 0;
  }

  if (sound != nullptr) {
    (void)sound->Destroy(1);
  }

  return 0;
}
