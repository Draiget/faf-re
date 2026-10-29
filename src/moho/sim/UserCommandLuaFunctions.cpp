// Engine addition (dedicated-server plan WPL.4, WPR.11): the user Lua state's
// command functions that lived in CCommandLuaFunctionRegistrations.cpp
// (UserLuaInitSet: IssueCommand, IssueUnitCommand, IssueBlueprintCommand,
// IssueDockCommand, the build-queue counts, GetUnitCommandData,
// GetRolloverInfo, the selection and zoom functions, overlays, build
// templates, OpenURL, SetCursor) and the UI_ExpandCurrentSelection and
// UI_SelectByCategory console commands, moved unchanged. Listed right after
// that file; its bootstrap registers these forms in the order the original
// bootstraps did, so the user init set keeps its order.
#include "moho/sim/CCommandLuaFunctionRegistrations.h"
#include "moho/sim/IdleUnitSelector.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/algorithms/Sort.h"
#include "legacy/containers/Set.h"
#include "lua/LuaTableIterator.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/app/WxUrl.h"
#include "moho/client/Localization.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"
#include "moho/sim/SOCellPos.h"
#include "gpg/core/containers/String.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/UserEntity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/math/Vector3f.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/render/RCamManager.h"
#include "moho/render/RangeRenderer.h"
#include "moho/render/WRenViewport.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/entity/Entity.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/sim/UserArmy.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/WeakObject.h"
#include "moho/ui/IUIManager.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/mesh/Mesh.h"
#include "moho/sim/COGrid.h"
#include "moho/math/Wm3AxisAlignedBox3FafExtras.h"
#include "moho/collision/CColPrimitiveBox3f.h"
#include "Wm3Box3.h"

using namespace moho;

// Engine addition: helpers shared with the file these functions came from.
namespace
{
    // Per-tick economy value → per-second UI rate (ds:dword_DFF31C == 10.0f).
    constexpr float kRolloverEconomyPerSecondToUiRate = 10.0f;
    // The rollover builders read the UI unit's own members (x86 offsets as
    // FUN_008421F0 reads them): `mParams.mEntityId` (+0x44),
    // `mVariableData.mHealth/mMaxHealth` (+0x68/+0x6C), `mArmy` (+0x120), the
    // replicated `mUnitVarDat` block at +0x198 (fuel +0x1A4, shield +0x1A8, work
    // +0x1BC, silo counters +0x1C0..+0x1D4, custom name +0x1DC, produced /
    // spent / maintenance pairs +0x1F8..+0x20C, focus / guarded / target-blip
    // ids +0x210..+0x218), and `mIntelStateFlags` (+0x3E0; 0x10 = has unit
    // data, 0x08 = health valid).
    constexpr std::uint32_t kRolloverHasUnitDataFlag = 0x10u;
    constexpr std::uint32_t kRolloverHealthValidFlag = 0x08u;

    /**
     * Address: 0x00842770 (FUN_00842770, sub_842770)
     *
     * IDA signature:
     * void __usercall sub_842770(LuaPlus::LuaObject *out@<esi>,
     *                            Moho::UserEntity *prop@<edi>,
     *                            LuaPlus::LuaState *state);
     *
     * What it does:
     * Fills one rollover sub-table for a focused prop entity: blueprintId +
     * fractionComplete, or "unknown"/0.0 when the prop has no blueprint.
     */
    void BuildFocusPropRolloverInfo(LuaPlus::LuaObject& out, UserEntity* const prop, LuaPlus::LuaState* const state)
    {
      out.AssignNewTable(state, 0, 0);

      const REntityBlueprint* const blueprint = prop->mParams.mBlueprint;
      if (blueprint != nullptr) {
        out.SetString("blueprintId", blueprint->mBlueprintId.c_str());
        out.SetNumber("fractionComplete", prop->mVariableData.mFractionComplete);
      } else {
        out.SetString("blueprintId", "unknown");
        out.SetNumber("fractionComplete", 0.0f);
      }
    }
    /**
     * Address: 0x008427E0 (FUN_008427E0, sub_8427E0)
     *
     * IDA signature:
     * void __usercall sub_8427E0(LuaPlus::LuaState *state@<eax>,
     *                            Moho::UserUnit *unit@<edi>,
     *                            LuaPlus::LuaObject *out);
     *
     * What it does:
     * Fills one compact rollover sub-table for a focus / upgrade target unit:
     * blueprintId + health/max when the target blueprint is present and the unit
     * data flags gate (mobile → 0x08, otherwise 0x10) is satisfied; otherwise a
     * stubbed "unknown" blueprintId.
     */
    void BuildFocusUnitRolloverInfo(LuaPlus::LuaObject& out, UserUnit* const unit, LuaPlus::LuaState* const state)
    {
      out.AssignNewTable(state, 0, 0);

      IUnit* const bridge = GetIUnitBridge(unit);
      const RUnitBlueprint* const blueprint = bridge->GetBlueprint();

      bool hasBlueprintId = false;
      if (blueprint != nullptr) {
        const std::uint32_t requiredFlag =
          blueprint->IsMobile() ? kRolloverHealthValidFlag : kRolloverHasUnitDataFlag;
        hasBlueprintId = (unit->mIntelStateFlags & requiredFlag) != 0u;
      }

      if (!hasBlueprintId) {
        out.SetString("blueprintId", "unknown");
        return;
      }

      out.SetString("blueprintId", blueprint->mBlueprintId.c_str());
      out.SetNumber("health", unit->mVariableData.mHealth);
      out.SetNumber("maxHealth", unit->mVariableData.mMaxHealth);
    }
    /**
     * Address: 0x008421F0 (FUN_008421F0, sub_8421F0)
     *
     * IDA signature:
     * void __usercall sub_8421F0(LuaPlus::LuaObject *out@<edi>,
     *                            Moho::UserUnit *unit@<esi>,
     *                            LuaPlus::LuaState *state);
     *
     * What it does:
     * Fills one rollover-info Lua table with full stats for a live user unit:
     * blueprint id, health/max, KILLS stat, per-second economy, silo counters,
     * fuel/shield/work ratios, the unit's own Lua object, entity id, army index
     * and encoded team color. When the +0x3E0 flag word lacks the has-unit-data
     * bit only a stubbed blueprintId / armyIndex / teamColor is written; when the
     * entity id nibble marks a being-placed entity the stat block is sentinel-filled.
     */
    void BuildUserUnitRolloverInfo(LuaPlus::LuaObject& out, UserUnit* const unit, LuaPlus::LuaState* const state)
    {
      out.AssignNewTable(state, 0, 0);

      const SSTIUnitVariableData& unitData = unit->mUnitVarDat;
      if ((unit->mIntelStateFlags & kRolloverHasUnitDataFlag) != 0u) {
        IUnit* const bridge = GetIUnitBridge(unit);
        out.SetString("blueprintId", bridge->GetBlueprint()->mBlueprintId.c_str());

        if ((unit->mIntelStateFlags & kRolloverHealthValidFlag) != 0u) {
          out.SetNumber("health", unit->mVariableData.mHealth);
          out.SetNumber("maxHealth", unit->mVariableData.mMaxHealth);
        }

        if ((unit->mParams.mEntityId & 0xF0000000u) == 0x30000000u) {
          // Placeholder / being-placed entity: sentinel values.
          out.SetNumber("kills", 0.0f);
          out.SetInteger("energyConsumed", -1);
          out.SetInteger("massConsumed", -1);
          out.SetInteger("energyRequested", 0);
          out.SetInteger("massRequested", 0);
          out.SetInteger("energyProduced", -1);
          out.SetInteger("massProduced", -1);
          out.SetInteger("tacticalSiloBuildCount", 0);
          out.SetInteger("tacticalSiloStorageCount", 0);
          out.SetInteger("tacticalSiloMaxStorageCount", 0);
          out.SetInteger("nukeSiloBuildCount", 0);
          out.SetInteger("nukeSiloStorageCount", 0);
          out.SetInteger("nukeSiloMaxStorageCount", 0);
          out.SetInteger("fuelRatio", -1);
          out.SetInteger("shieldRatio", -1);
          out.SetInteger("workProgress", -1);
        } else {
          int killsDefault = 0;
          StatItem* const killsStat = bridge->GetStat("KILLS", killsDefault);
          out.SetNumber("kills", static_cast<float>(killsStat->GetInt(false)));

          // FAF hot-patch (FA-Binary-Patches GetRolloverInfoFix): 0x008422FD..0x0084240C keep
          // the six rates as floats (`movd eax, xmm0` + LuaObject::SetNumber at 0x00908320)
          // instead of truncating them to integers for SetInteger.
          out.SetNumber("energyConsumed", unitData.mResourcesSpent.ENERGY * kRolloverEconomyPerSecondToUiRate);
          out.SetNumber("massConsumed", unitData.mResourcesSpent.MASS * kRolloverEconomyPerSecondToUiRate);
          out.SetNumber("energyRequested", unitData.mMaintainenceCost.ENERGY * kRolloverEconomyPerSecondToUiRate);
          out.SetNumber("massRequested", unitData.mMaintainenceCost.MASS * kRolloverEconomyPerSecondToUiRate);
          out.SetNumber("energyProduced", unitData.mProduced.ENERGY * kRolloverEconomyPerSecondToUiRate);
          out.SetNumber("massProduced", unitData.mProduced.MASS * kRolloverEconomyPerSecondToUiRate);
          out.SetInteger("tacticalSiloBuildCount", unitData.mTacticalSiloBuildCount);
          out.SetInteger("tacticalSiloStorageCount", unitData.mTacticalSiloStorageCount);
          out.SetInteger("tacticalSiloMaxStorageCount", unitData.mTacticalSiloMaxStorageCount);
          out.SetInteger("nukeSiloBuildCount", unitData.mNukeSiloBuildCount);
          out.SetInteger("nukeSiloStorageCount", unitData.mNukeSiloStorageCount);
          out.SetInteger("nukeSiloMaxStorageCount", unitData.mNukeSiloMaxStorageCount);
          out.SetNumber("fuelRatio", unitData.mFuelRatio);
          out.SetNumber("shieldRatio", unitData.mShieldRatio);
          out.SetNumber("workProgress", unitData.mWorkProgress);

          const LuaPlus::LuaObject unitObject = bridge->GetLuaObject();
          out.SetObject("userUnit", unitObject);

          const msvc8::string entityIdText = gpg::STR_Printf("%d", unit->mParams.mEntityId);
          out.SetString("entityId", entityIdText.c_str());
        }

        out.SetInteger("armyIndex", static_cast<int>(unit->mArmy->mArmyIndex));
        const LuaPlus::LuaObject teamColor = SCR_EncodeColor(state, unit->mArmy->mVarDat.mPlayerColorBgra);
        out.SetObject("teamColor", teamColor);

        if (!unitData.mCustomName.empty()) {
          out.SetString("customName", unitData.mCustomName.c_str());
        }
      } else {
        out.SetString("blueprintId", "unknown");
        const LuaPlus::LuaObject teamColor = SCR_EncodeColor(state, unit->mArmy->mVarDat.mPlayerColorBgra);
        out.SetObject("teamColor", teamColor);
        out.SetInteger("armyIndex", static_cast<int>(unit->mArmy->mArmyIndex));
      }
    }
    // One candidate air-staging platform: the ordering keys the binary computes for
    // each viable platform. Layout matches the 12-byte record the binary pushes
    // (platform @ +0x00, distSq @ +0x04, freeCapacity @ +0x08).
    struct DockCandidate
    {
      UserUnit* platform;      // +0x00
      float distSq;            // +0x04 (squared XZ distance to selection centroid)
      std::int32_t freeCapacity; // +0x08 (available docking slots)
    };
    constexpr std::uint32_t kDockRejectLayerSeabed = 2u; // LAYER_Seabed
    // Current-layer values that disqualify a platform from being a dock target:
    // an underwater platform (Sub or Seabed layer) cannot stage docked units.
    // (the binary gates `layer != LAYER_Sub(4) && layer != LAYER_Seabed(2)`.)
    constexpr std::uint32_t kDockRejectLayerSub = 4u;    // LAYER_Sub
    // Radius padding (world units) added to the nearest-platform distance when the
    // whole selection cannot dock at a single platform (binary literal 100.0f).
    constexpr float kMultiDockRadiusPadding = 100.0f;
    // RULEUCC_Dock command capability bit tested against UnitAttributes::commandCapsMask.
    constexpr std::uint32_t kRuleUccDock = 0x400000u;

  /**
   * Address: 0x00866020 (FUN_00866020, sub_866020)
   *
   * Moho::CWldSession *, int
   *
   * What it does:
   * Core of `UI_ExpandCurrentSelection`. Collects every unit in the
   * session's spatial DB, and for each one that is alive, selectable, and
   * not in the "WALL" category, checks whether the *current* selection
   * already contains a unit sharing the same blueprint; if so (and the
   * candidate is not mid-upgrade - `IUnit::IsUnitState(UNITSTATE_
   * BeingUpgraded)`, vtable-confirmed via `UserUnit::UserUnit`'s ctor write
   * of `??_7UserUnit@Moho@@6BIUnit@Moho@@@` at 0x008BF53D), adds it to a
   * working copy of the selection that starts seeded with the current
   * selection's own members (both `originalSelection` and
   * `expandedSelection` below are independent copies of `session->mSelection`
   * - the binary constructs two, not one, matching `sub_822210`'s citation
   * as the `WeakEntitySetUserEntity` copy constructor's underlying clone
   * step). Commits the expanded selection via `CWldSession::SetSelection`.
   *
   * The `camera` parameter is only ever null-checked, never dereferenced -
   * preserved as a real parameter rather than reduced to a bool, since the
   * binary's caller (`UI_ExpandCurrentSelection` below) always resolves and
   * passes a real `CameraImpl*` for this exact null-check gate.
   */
  void ExpandCurrentSelection(moho::CWldSession* const session, const moho::CameraImpl* const camera)
  {
    if (camera == nullptr) {
      return;
    }

    gpg::fastvector<moho::UserEntity*> collected{};
    auto* const spatialDb = session->GetEntitySpatialDbStorage();
    (void)spatialDb->Collect(collected, moho::ENTITYTYPE_Unit);

    moho::WeakSet<moho::UserEntity> originalSelection(session->mSelection);
    moho::WeakSet<moho::UserEntity> expandedSelection(session->mSelection);

    const msvc8::string wallCategory("WALL");

    for (moho::UserEntity* const candidateEntity : collected) {
      moho::UserUnit* const candidate = candidateEntity->IsUserUnit();
      if (candidate == nullptr || candidate->IsDead() || !session->CanSelectUnit(candidate)) {
        continue;
      }
      if (candidate->IsInCategory(wallCategory)) {
        continue;
      }

      bool sharesBlueprintWithSelection = false;
      for (const moho::UserEntity* const selectedEntity : originalSelection) {
        if (selectedEntity->mParams.mBlueprint == candidate->mParams.mBlueprint) {
          sharesBlueprintWithSelection = true;
          break;
        }
      }

      if (sharesBlueprintWithSelection && !candidate->IsUnitState(moho::UNITSTATE_BeingUpgraded)) {
        (void)expandedSelection.Add(candidate);
      }
    }

    session->SetSelection(expandedSelection);
  }
  // ---- UISelectionByCategory support (FUN_008662B0) ----

  [[nodiscard]] const Wm3::Box3f* SelectionEntityMeshBox(moho::UserEntity* const entity)
  {
    moho::MeshInstance* const meshInstance = (entity != nullptr) ? entity->mMeshInstance : nullptr;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      return &meshInstance->box;
    }
    return &moho::Invalid<Wm3::Box3f>();
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardCommandLuaRegistrationThunk() noexcept
  {
    return Target();
  }
  constexpr const char* kConsoleStartupUIExpandCurrentSelectionDescription =
    "Expand selection to all units in view that is found in our current selection group";
  constexpr const char* kConsoleStartupUISelectByCategoryDescription = "Select a set of units by category";
  constexpr const char* kDecreaseBuildCountInQueueHelpText = "DecreaseBuildCountInQueue(queueIndex, count)";
  constexpr const char* kDecreaseBuildCountInQueueName = "DecreaseBuildCountInQueue";
  constexpr const char* kGetActiveBuildTemplateHelpText = "get active build template back to lua.";
  constexpr const char* kGetActiveBuildTemplateName = "GetActiveBuildTemplate";
  constexpr const char* kGetRolloverInfoHelpText = "rolloverInfo GetRolloverInfo()";
  constexpr const char* kGetRolloverInfoName = "GetRolloverInfo";
  constexpr const char* kGetUnitCommandDataHelpText =
    "orders, buildableCategories, GetUnitCommandData(unitSet) -- given a set of units, gets the union of orders and "
    "unit categories (for determining builds)";
  constexpr const char* kGetUnitCommandDataName = "GetUnitCommandData";
  // Binary quirk: the Increase binder reuses the Decrease help string verbatim
  // (asm 0x00836703 -> "DecreaseBuildCountInQueue(queueIndex, count)").
  constexpr const char* kIncreaseBuildCountInQueueHelpText = "DecreaseBuildCountInQueue(queueIndex, count)";
  constexpr const char* kIncreaseBuildCountInQueueName = "IncreaseBuildCountInQueue";
  constexpr const char* kIssueBlueprintCommandHelpText =
    "IssueBlueprintCommand(command, blueprintid, count, clear = false)";
  constexpr const char* kIssueBlueprintCommandName = "IssueBlueprintCommand";
  constexpr const char* kIssueCommandHelpText = "IssueCommand(command,[string],[clear])";
  constexpr const char* kIssueCommandName = "IssueCommand";
  constexpr const char* kIssueDockCommandHelpText = "IssueDockCommand(clear)";
  constexpr const char* kIssueDockCommandName = "IssueDockCommand";
  constexpr const char* kIssueUnitCommandHelpText = "IssueUnitCommand(unitList,command,[string],[clear])";
  constexpr const char* kIssueUnitCommandName = "IssueUnitCommand";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kOpenURLHelpText =
    "OpenURL(string) - open the default browser window to the specified URL";
  constexpr const char* kOpenURLName = "OpenURL";
  constexpr const char* kSetActiveBuildTemplateHelpText = "set this as an active build template.";
  constexpr const char* kSetActiveBuildTemplateName = "SetActiveBuildTemplate";
  constexpr const char* kSetCursorHelpText = "SetCursor(cursor)";
  constexpr const char* kSetCursorName = "SetCursor";
  constexpr const char* kSetOverlayFilterHelpText = "SetOverlayFilter()";
  constexpr const char* kSetOverlayFilterName = "SetOverlayFilter";
  constexpr const char* kUISelectAndZoomToHelpText = "UISelectAndZoomTo(userunit,[seconds])";
  constexpr const char* kUISelectAndZoomToName = "UISelectAndZoomTo";
  constexpr const char* kUISelectionByCategoryHelpText =
    "UISelectionByCategory(expression, addToCurSel, inViewFrustum, nearestToMouse, mustBeIdle) - selects units based "
    "on a category expression";
  constexpr const char* kUISelectionByCategoryName = "UISelectionByCategory";
  constexpr const char* kUIZoomToHelpText = "UIZoomTo(units,[seconds])";
  constexpr const char* kUIZoomToName = "UIZoomTo";
  /**
   * Address: 0x008662B0 (FUN_008662B0, sub_8662B0, SelectUnitsByCategory)
   *
   * What it does:
   * Core of UISelectionByCategory. Gathers candidate units (camera frustum or the
   * spatial DB), filters by selectability / focus-army ownership / optional idle /
   * category (+ optional engineer/command exclusion), then either replaces or
   * extends the world selection. Optionally frames the result with the camera.
   */
  void SelectUnitsByCategory(
    moho::CWldSession* const session,
    moho::CameraImpl* const camera,
    const char* const categoryExpr,
    const bool addToSelection,        // a4
    const bool inViewFrustum,         // a5
    const bool nearestToMouse,        // a6
    const bool mustBeIdle,            // a7
    const bool doCameraTarget,        // a8
    const bool excludeEngineerCommand // a9
  )
  {
    // ---- Gather candidate entities ----
    gpg::fastvector<moho::UserEntity*> gathered{};
    if (inViewFrustum && camera != nullptr) {
      for (const moho::WeakPtr<moho::UserEntity>& ref : *camera->GetArmyUnitsInFrustum()) {
        if (moho::UserEntity* const entity = ref.GetObjectPtr(); entity != nullptr) {
          gathered.push_back(entity);
        }
      }
    } else {
      auto* const spatialDb = session->GetEntitySpatialDbStorage();
      (void)spatialDb->Collect(gathered, moho::ENTITYTYPE_Unit);
    }

    // Parse the category expression once (RRuleGameRules slot 23).
    const moho::EntityCategorySet parsedCategory = session->mRules->ParseEntityCategory(categoryExpr);

    // Result set: start empty, optionally seed with the current selection
    // (`operator=`, its `_Copy` 0x00867B20).
    moho::WeakSet<moho::UserEntity> resultSet;
    if (addToSelection) {
      resultSet = session->mSelection;
    }

    // ---- Per-candidate filter ----
    const moho::UserArmy* const focusArmy = session->GetFocusArmy();

    moho::UserEntity* nearestEntity = nullptr;
    float nearestDistance = gpg::pInf;

    for (moho::UserEntity* const candidate : gathered) {
      moho::UserUnit* const unit = candidate->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      // Selectable AND (owned by focus army OR cheat-select).
      if (!unit->IsSelectable()) {
        continue;
      }
      const bool ownedByFocusArmy = (focusArmy == candidate->mArmy);
      if (!ownedByFocusArmy && !(moho::UI_SelectAnything && session->IsCheatsEnabled)) {
        continue;
      }

      // Optional idle filter: not busy AND no queued commands.
      if (mustBeIdle) {
        if (unit->mUnitVarDat.mIsBusy) {
          continue;
        }
        if (moho::GetUserUnitManagerQueueSize(unit->mManager) != 0) {
          continue;
        }
      }

      // Category test (open-coded bitset in the binary -> EntityCategory::HasBlueprint).
      const moho::IUnit* const iunit = moho::GetIUnitBridge(unit);
      if (!moho::EntityCategory::HasBlueprint(iunit->GetBlueprint(), &parsedCategory)) {
        continue;
      }

      // Optional engineer/command exclusion (a9).
      if (excludeEngineerCommand) {
        const msvc8::string engineerCategory("ENGINEER");
        const msvc8::string commandCategory("COMMAND");
        if (candidate->IsInCategory(engineerCategory) || candidate->IsInCategory(commandCategory)) {
          continue;
        }
      }

      if (nearestToMouse) {
        // Keep only the single unit nearest the cursor world position.
        const Wm3::Vec3f& unitPos = iunit->GetPosition();
        const float dx = unitPos.x - session->CursorWorldPos.x;
        const float dy = unitPos.y - session->CursorWorldPos.y;
        const float dz = unitPos.z - session->CursorWorldPos.z;
        const float distance = std::sqrt(dx * dx + dy * dy + dz * dz);
        if (nearestDistance > distance) {
          nearestEntity = candidate;
          nearestDistance = distance;
        }
      } else if (!iunit->IsUnitState(moho::UNITSTATE_BeingUpgraded)) {
        // Add every passing unit (skip units mid-upgrade).
        (void)resultSet.Add(candidate);
      }
    }

    if (nearestToMouse && nearestEntity != nullptr) {
      (void)resultSet.Add(nearestEntity);
    }

    // ---- Optional camera framing of the result ----
    if (!resultSet.Empty() && doCameraTarget && camera != nullptr) {
      if (mustBeIdle) {
        moho::IdleUnitSelector::CycleCameraFocus(resultSet, camera);
      } else if (resultSet.Size() == 1) {
        camera->TargetEntityBox(*resultSet.begin(), 0.0f);
      } else {
        // Combined AABB over all selected entities, then frame it.
        Wm3::AxisAlignedBox3f combined = moho::Empty<Wm3::AxisAlignedBox3f>();
        for (moho::UserEntity* const entity : resultSet) {
          const Wm3::Box3f orientedBox(*SelectionEntityMeshBox(entity));
          Wm3::AxisAlignedBox3f entityBox{};
          entityBox = moho::AxisAlignedBoundsFromBox(orientedBox);

          if (entityBox.Min.x <= combined.Min.x) { combined.Min.x = entityBox.Min.x; }
          if (entityBox.Min.y <= combined.Min.y) { combined.Min.y = entityBox.Min.y; }
          if (entityBox.Min.z <= combined.Min.z) { combined.Min.z = entityBox.Min.z; }
          if (entityBox.Max.x >  combined.Max.x) { combined.Max.x = entityBox.Max.x; }
          if (entityBox.Max.y >  combined.Max.y) { combined.Max.y = entityBox.Max.y; }
          if (entityBox.Max.z >  combined.Max.z) { combined.Max.z = entityBox.Max.z; }
        }

        camera->TargetBox(combined, 0.0f);
        camera->TargetNothing();
      }
    }

    session->SetSelection(resultSet);
  }
  // The binary runs this registrar from the CRT static-initializer array;
  // this file-scope bootstrap object reproduces that, matching the
  // `ResolutionConsoleRegistrations` pattern established in
  // moho/app/ResolutionCommands.cpp.
  [[nodiscard]] bool TryParseUnitCommandTypeLexical(
    const char* const lexicalCommandType,
    moho::EUnitCommandType& outCommandType
  )
  {
    if (lexicalCommandType == nullptr) {
      return false;
    }

    gpg::RRef commandTypeRef{};
    commandTypeRef = gpg::MakeRRef<moho::EUnitCommandType>(&outCommandType);
    return commandTypeRef.SetLexical(lexicalCommandType);
  }
  /**
   * Address: 0x00866970 (FUN_00866970, sub_866970)
   *
   * char*
   *
   * What it does:
   * `UI_ExpandCurrentSelection` console command. Resolves the world camera
   * and dispatches `ExpandCurrentSelection` above. Prints localized "no
   * session" feedback when no session is active.
   *
   * Registrar: FUN_00BE61C0 (`__xc_a` lane), data-xref
   * `dword_F5B524 = offset sub_866970` is the callsite evidence. Name is
   * read from the PE `.data` initializer of `stru_F5B518`
   * ("UI_ExpandCurrentSelection").
   */
  void UI_ExpandCurrentSelection(const msvc8::vector<msvc8::string>& args)
  {
    (void)args;

    moho::CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr) {
      const msvc8::string noSessionText = moho::Loc(moho::USER_GetLuaState(), "<LOC _No_session>");
      moho::CON_Printf(noSessionText.c_str());
      return;
    }

    moho::RCamManager* const cameraManager = moho::CAM_GetManager();
    moho::CameraImpl* const camera = cameraManager->GetCamera("WorldCamera");

    ExpandCurrentSelection(session, camera);
  }
  /**
   * Address: 0x00866A30 (FUN_00866A30, sub_866A30)
   *
   * std::vector_string*
   *
   * What it does:
   * `UI_SelectByCategory [+add] [+nearest] [+idle] [+goto]
   * [+excludeengineers] categoryExpression`. Splits arguments into `+`-prefixed
   * modifier flags and free-text category-expression words (rejoined with a
   * single space each), resolves the world camera, then dispatches
   * `SelectUnitsByCategory` above with the parsed flags. Prints the usage
   * block with fewer than two arguments, and a localized "no session" line
   * with none active.
   *
   * Registrar: FUN_00BE6200 (`__xc_a` lane), data-xref
   * `dword_F5B534 = offset sub_866A30` is the callsite evidence. Name is
   * read from the PE `.data` initializer of `stru_F5B528`
   * ("UI_SelectByCategory").
   */
  void UI_SelectByCategory(const msvc8::vector<msvc8::string>& args)
  {
    moho::CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr) {
      const msvc8::string noSessionText = moho::Loc(moho::USER_GetLuaState(), "<LOC _No_session>");
      moho::CON_Printf(noSessionText.c_str());
      return;
    }

    if (args.size() < 2u) {
      moho::CON_Printf(
        "UI_SelectByCategory [+add] [+nearest] [+idle] [+goto] categoryExpression\n"
        "Select a set of units with the following parameters....\n"
        "+add : add to current selection\n"
        "+nearest : select only nearest unit matching category\n"
        "+idle : select only idle units\n"
        "+inview: select only units in the current view\n"
        "+goto: goto the unit if it's already selected\n"
        "categoryExpression uses the format CAT1 CAT2, CAT3 CAT4 where a space means intersection and a comma means union\n"
      );
      return;
    }

    bool addToSelection = false;
    bool inViewFrustum = false;
    bool nearestToMouse = false;
    bool mustBeIdle = false;
    bool doCameraTarget = false;
    bool excludeEngineerCommand = false;
    std::string categoryExpr;

    for (std::size_t index = 1u; index < args.size(); ++index) {
      const msvc8::string* const token = moho::ConCommandArg(args, index);
      if (token == nullptr) {
        continue;
      }

      const char* const tokenText = token->c_str();
      if (tokenText[0] == '+') {
        if (_stricmp(tokenText, "+add") == 0) {
          addToSelection = true;
        } else if (_stricmp(tokenText, "+nearest") == 0) {
          nearestToMouse = true;
        } else if (_stricmp(tokenText, "+idle") == 0) {
          mustBeIdle = true;
        } else if (_stricmp(tokenText, "+inview") == 0) {
          inViewFrustum = true;
        } else if (_stricmp(tokenText, "+goto") == 0) {
          doCameraTarget = true;
        } else if (_stricmp(tokenText, "+excludeengineers") == 0) {
          excludeEngineerCommand = true;
        } else {
          // The binary's `CON_Printf("Unknown modifier %s")` call at this
          // point supplies no second argument (a genuine missing-vararg bug
          // in the shipped build - the preceding `qmemcpy` of the offending
          // token into scratch stack space is the closest thing to evidence
          // of intent). Reading past the format string's %s would be
          // undefined behavior here, so this recovery supplies the token
          // the format string obviously wants instead of reproducing the
          // stack-garbage read.
          moho::CON_Printf("Unknown modifier %s", tokenText);
        }
        continue;
      }

      if (!categoryExpr.empty()) {
        categoryExpr.push_back(' ');
      }
      categoryExpr.append(tokenText);
    }

    moho::RCamManager* const cameraManager = moho::CAM_GetManager();
    moho::CameraImpl* const camera = cameraManager->GetCamera("WorldCamera");

    SelectUnitsByCategory(
      session,
      camera,
      categoryExpr.c_str(),
      addToSelection,
      inViewFrustum,
      nearestToMouse,
      mustBeIdle,
      doCameraTarget,
      excludeEngineerCommand
    );
  }
  /**
   * Sixteen of this file's binders go into the user set, not the sim one -
   * the command-queue accessors the UI reads while a game is running.
   */
  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }
} // namespace


namespace moho
{
  // Recovered child wrappers call these deeper callback lanes.
  int cfunc_UISelectionByCategoryL(LuaPlus::LuaState* state);

  int cfunc_UISelectAndZoomToL(LuaPlus::LuaState* state);

  int cfunc_UIZoomToL(LuaPlus::LuaState* state);

} // namespace moho

namespace
{
  /**
   * Address: 0x00BE61C0 (FUN_00BE61C0, dynamic initializer for `gCConFunc_UI_ExpandCurrentSelection`)
   * Address: 0x00C07550 (FUN_00C07550, dynamic atexit destructor for `gCConFunc_UI_ExpandCurrentSelection`)
   */
  moho::CConFunc gCConFunc_UI_ExpandCurrentSelection("UI_ExpandCurrentSelection", kConsoleStartupUIExpandCurrentSelectionDescription, &UI_ExpandCurrentSelection);

  /**
   * Address: 0x00BE6200 (FUN_00BE6200, dynamic initializer for `gCConFunc_UI_SelectByCategory`)
   * Address: 0x00C07580 (FUN_00C07580, dynamic atexit destructor for `gCConFunc_UI_SelectByCategory`)
   */
  moho::CConFunc gCConFunc_UI_SelectByCategory("UI_SelectByCategory", kConsoleStartupUISelectByCategoryDescription, &UI_SelectByCategory);

} // namespace

namespace moho
{
  int cfunc_IssueUnitCommandL(LuaPlus::LuaState* state);

  int cfunc_IssueBlueprintCommandL(LuaPlus::LuaState* state);

  int cfunc_GetRolloverInfoL(LuaPlus::LuaState* state);

  int cfunc_SetOverlayFilterL(LuaPlus::LuaState* state);

  int cfunc_GetActiveBuildTemplateL(LuaPlus::LuaState* state);

  int cfunc_SetActiveBuildTemplateL(LuaPlus::LuaState* state);

  int cfunc_SetCursorL(LuaPlus::LuaState* state);

  int cfunc_DecreaseBuildCountInQueueL(LuaPlus::LuaState* state);

  int cfunc_IncreaseBuildCountInQueueL(LuaPlus::LuaState* state);

  int cfunc_GetUnitCommandDataL(LuaPlus::LuaState* state);

  int cfunc_IssueDockCommandL(LuaPlus::LuaState* state);

  int cfunc_IssueCommandL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00BE6240 (FUN_00BE6240, register_UISelectionByCategory_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_UISelectionByCategory_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UISelectionByCategory_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_UISelectionByCategory_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE6250 (FUN_00BE6250, register_UISelectAndZoomTo_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_UISelectAndZoomTo_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UISelectAndZoomTo_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_UISelectAndZoomTo_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE6260 (FUN_00BE6260, register_UIZoomTo_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_UIZoomTo_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UIZoomTo_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_UIZoomTo_LuaFuncDef>();
  }

  /**
   * Address: 0x00836920 (FUN_00836920, func_DecreaseBuildCountInQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `DecreaseBuildCountInQueue(queueIndex, count)`.
   */
  CScrLuaInitForm* func_DecreaseBuildCountInQueue_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kDecreaseBuildCountInQueueName,
      &moho::cfunc_DecreaseBuildCountInQueue,
      nullptr,
      "<global>",
      kDecreaseBuildCountInQueueHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008366E0 (FUN_008366E0, func_IncreaseBuildCountInQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IncreaseBuildCountInQueue`. The published help
   * string reuses the Decrease text verbatim, matching the binary.
   */
  CScrLuaInitForm* func_IncreaseBuildCountInQueue_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kIncreaseBuildCountInQueueName,
      &moho::cfunc_IncreaseBuildCountInQueue,
      nullptr,
      "<global>",
      kIncreaseBuildCountInQueueHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008400D0 (FUN_008400D0, func_GetUnitCommandData_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `GetUnitCommandData(unitSet)`.
   */
  CScrLuaInitForm* func_GetUnitCommandData_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kGetUnitCommandDataName,
      &moho::cfunc_GetUnitCommandData,
      nullptr,
      "<global>",
      kGetUnitCommandDataHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00840A10 (FUN_00840A10, func_IssueDockCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueDockCommand(clear)`.
   */
  CScrLuaInitForm* func_IssueDockCommand_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kIssueDockCommandName,
      &moho::cfunc_IssueDockCommand,
      nullptr,
      "<global>",
      kIssueDockCommandHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00841550 (FUN_00841550, func_IssueCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueCommand(command,[string],[clear])`.
   */
  CScrLuaInitForm* func_IssueCommand_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kIssueCommandName,
      &moho::cfunc_IssueCommand,
      nullptr,
      "<global>",
      kIssueCommandHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00841860 (FUN_00841860, func_IssueUnitCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueUnitCommand(unitList,command,[string],[clear])`.
   */
  CScrLuaInitForm* func_IssueUnitCommand_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kIssueUnitCommandName,
      &moho::cfunc_IssueUnitCommand,
      nullptr,
      "<global>",
      kIssueUnitCommandHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00841BB0 (FUN_00841BB0, func_IssueBlueprintCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder
   * `IssueBlueprintCommand(command, blueprintid, count, clear = false)`.
   */
  CScrLuaInitForm* func_IssueBlueprintCommand_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kIssueBlueprintCommandName,
      &moho::cfunc_IssueBlueprintCommand,
      nullptr,
      "<global>",
      kIssueBlueprintCommandHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008428C0 (FUN_008428C0, func_GetRolloverInfo_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `GetRolloverInfo()`.
   */
  CScrLuaInitForm* func_GetRolloverInfo_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kGetRolloverInfoName,
      &moho::cfunc_GetRolloverInfo,
      nullptr,
      "<global>",
      kGetRolloverInfoHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00866D50 (FUN_00866D50, func_UISelectionByCategory_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder
   * `UISelectionByCategory(expression, addToCurSel, inViewFrustum, nearestToMouse, mustBeIdle)`.
   */
  CScrLuaInitForm* func_UISelectionByCategory_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kUISelectionByCategoryName,
      &moho::cfunc_UISelectionByCategory,
      nullptr,
      "<global>",
      kUISelectionByCategoryHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00866F60 (FUN_00866F60, func_UISelectAndZoomTo_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `UISelectAndZoomTo(userunit,[seconds])`.
   */
  CScrLuaInitForm* func_UISelectAndZoomTo_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kUISelectAndZoomToName,
      &moho::cfunc_UISelectAndZoomTo,
      nullptr,
      "<global>",
      kUISelectAndZoomToHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008671E0 (FUN_008671E0, func_UIZoomTo_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `UIZoomTo(units,[seconds])`.
   */
  CScrLuaInitForm* func_UIZoomTo_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kUIZoomToName,
      &moho::cfunc_UIZoomTo,
      nullptr,
      "<global>",
      kUIZoomToHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00846B80 (FUN_00846B80, func_SetOverlayFilter_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `SetOverlayFilter()`.
   */
  CScrLuaInitForm* func_SetOverlayFilter_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kSetOverlayFilterName,
      &moho::cfunc_SetOverlayFilter,
      nullptr,
      "<global>",
      kSetOverlayFilterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00847290 (FUN_00847290, func_GetActiveBuildTemplate_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `GetActiveBuildTemplate()`.
   */
  CScrLuaInitForm* func_GetActiveBuildTemplate_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kGetActiveBuildTemplateName,
      &moho::cfunc_GetActiveBuildTemplate,
      nullptr,
      "<global>",
      kGetActiveBuildTemplateHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00847580 (FUN_00847580, func_SetActiveBuildTemplate_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `SetActiveBuildTemplate()`.
   */
  CScrLuaInitForm* func_SetActiveBuildTemplate_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kSetActiveBuildTemplateName,
      &moho::cfunc_SetActiveBuildTemplate,
      nullptr,
      "<global>",
      kSetActiveBuildTemplateHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00847FF0 (FUN_00847FF0, func_OpenURL_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `OpenURL(string)`.
   */
  CScrLuaInitForm* func_OpenURL_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kOpenURLName,
      &moho::cfunc_OpenURL,
      nullptr,
      "<global>",
      kOpenURLHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0084DCA0 (FUN_0084DCA0, func_SetCursor_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `SetCursor(cursor)`.
   */
  CScrLuaInitForm* func_SetCursor_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      kSetCursorName,
      &moho::cfunc_SetCursor,
      nullptr,
      "<global>",
      kSetCursorHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008415B0 (FUN_008415B0, cfunc_IssueCommandL)
   *
   * What it does:
   * Parses one command lexical plus optional payload/clear flag and issues the
   * command to the current world-session selection.
   */
  int cfunc_IssueCommandL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kIssueCommandHelpText, 1, 3, argumentCount);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      gpg::Warnf("Attempt to call IssueCommand before world sessions exists.");
      return 0;
    }

    const int focusArmy = session->FocusArmy;
    if (focusArmy < 0 || static_cast<std::size_t>(focusArmy) >= session->userArmies.size()
        || session->userArmies[focusArmy] == nullptr) {
      return 0;
    }

    const LuaPlus::LuaStackObject commandArg(state, 1);
    const char* const commandLexical = lua_tostring(rawState, 1);
    if (commandLexical == nullptr) {
      commandArg.TypeError("string");
      return 0;
    }

    EUnitCommandType commandType = EUnitCommandType::UNITCOMMAND_None;
    if (!TryParseUnitCommandTypeLexical(commandLexical, commandType) || commandType == EUnitCommandType::UNITCOMMAND_None) {
      return 0;
    }

    // Silo build commands (BuildSiloTactical=5 / BuildSiloNuke=6) do NOT go
    // through the command-issue pipeline. The binary iterates the live world
    // selection weak-set directly and forwards each selected entity id to the
    // sync-driver as an "add" info-pair (asm 0x84177C-0x8417F6).
    if (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical
        || commandType == EUnitCommandType::UNITCOMMAND_BuildSiloNuke) {
      const char* const commandKey = (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical)
        ? "SiloBuildTactical"
        : "SiloBuildNuke";

      for (UserEntity* const selectedEntity : session->mSelection) {
        // sSimDriver global read fresh each iteration (asm reloads it in-loop).
        if (ISTIDriver* const driver = WLD_GetDriver(); driver != nullptr) {
          driver->ProcessInfoPair(selectedEntity->mParams.mEntityId, commandKey, "add");
        }
      }
      return 0;
    }

    SSTICommandIssueData commandIssueData(commandType);
    if (argumentCount >= 2) {
      commandIssueData.mObject = LuaPlus::LuaStackObject(state, 2);
    }

    bool clearQueue = true;
    if (argumentCount == 3) {
      clearQueue = LuaPlus::LuaStackObject(state, 3).GetBoolean();
    }

    // Client-side issue path: forward the current world selection weak-set to
    // the CWldSession ISSUE_Command(WeakSet) overload (asm 0x841748), NOT the
    // sim-side Sim::IssueCommand(BVSet) shortcut.
    ISSUE_Command(session->mSelection, commandIssueData, clearQueue);
    return 0;
  }

  /**
   * Address: 0x00841C10 (FUN_00841C10, cfunc_IssueBlueprintCommandL)
   *
   * What it does:
   * Parses a command lexical + a blueprint id + a repeat count (+ an optional
   * clear-queue flag) and issues that many blueprint-build commands to the
   * current world selection. Silo builds bypass the issue pipeline (per-entity
   * "add" info-pair, like cfunc_IssueCommandL); BuildFactory issues one command
   * per selected live FACTORY-category unit; every other command type issues to
   * the whole selection.
   */
  int cfunc_IssueBlueprintCommandL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 3 || argumentCount > 4) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kIssueBlueprintCommandHelpText, 3, 4, argumentCount);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      gpg::Warnf("Attempt to call IssueBlueprintCommand before world sessions exists.");
      return 0;
    }

    // Arg 1: command lexical -> EUnitCommandType (validated by the None gate below).
    const LuaPlus::LuaStackObject commandArg(state, 1);
    const char* const commandLexical = lua_tostring(rawState, 1);
    if (commandLexical == nullptr) {
      commandArg.TypeError("string");
      return 0;
    }
    EUnitCommandType commandType = EUnitCommandType::UNITCOMMAND_None;
    TryParseUnitCommandTypeLexical(commandLexical, commandType);

    // Arg 2: blueprint id -> normalized filename -> resolved blueprint pointer.
    const LuaPlus::LuaStackObject blueprintArg(state, 2);
    const char* const blueprintLexical = lua_tostring(rawState, 2);
    if (blueprintLexical == nullptr) {
      blueprintArg.TypeError("string");
      return 0;
    }
    RResId blueprintResId{};
    gpg::STR_InitFilename(&blueprintResId.name, blueprintLexical);
    REntityBlueprint* const blueprint = session->mRules->GetEntityBlueprint(blueprintResId);

    // Arg 3: repeat count (integer).
    const LuaPlus::LuaStackObject countArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      countArg.TypeError("integer");
      return 0;
    }
    const int repeatCount = static_cast<int>(lua_tonumber(rawState, 3));

    // Arg 4 (optional): clear-queue flag; defaults to false when absent.
    bool clearQueue = false;
    if (argumentCount >= 4) {
      clearQueue = LuaPlus::LuaStackObject(state, 4).GetBoolean();
    }

    // The binary resolves the blueprint pointer, reinterprets it as a float, and
    // gates on == 0.0 (a null-pointer test); an unparsable command type is None.
    if (blueprint == nullptr || commandType == EUnitCommandType::UNITCOMMAND_None) {
      return 0;
    }

    // Silo builds bypass the command-issue pipeline (mirrors cfunc_IssueCommandL):
    // forward each selected entity id to the sync-driver as an "add" info-pair.
    if (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical
        || commandType == EUnitCommandType::UNITCOMMAND_BuildSiloNuke) {
      const char* const commandKey = (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical)
        ? "SiloBuildTactical"
        : "SiloBuildNuke";

      for (UserEntity* const selectedEntity : session->mSelection) {
        if (ISTIDriver* const driver = WLD_GetDriver(); driver != nullptr) {
          driver->ProcessInfoPair(selectedEntity->mParams.mEntityId, commandKey, "add");
        }
      }
      return 0;
    }

    // BuildFactory: issue `count` commands per selected live FACTORY-category
    // unit. The blueprint travels in `mBlueprint`, exactly as it does for every
    // other command type.
    //
    // IDA renders this branch's store as `v36.mOri.w = v9`, which is a label
    // artifact, not a different lane: it places the payload at `esp+0x70` while
    // the branch's own `lea ecx,[esp+190h+var_130]` puts it at `esp+0x60`. The
    // store `mov [esp+0B0h], ebx` (0x00841E3D) is therefore `base+0x50`, i.e.
    // `mBlueprint` -- the same offset the else branch writes at 0x00841F71
    // (`lea edx,[esp+0F0h]` then `mov [esp+140h], ebx`). Both branches agree.
    if (commandType == EUnitCommandType::UNITCOMMAND_BuildFactory) {
      SSTICommandIssueData factoryCommand(EUnitCommandType::UNITCOMMAND_BuildFactory);
      factoryCommand.mBlueprint = static_cast<RUnitBlueprint*>(blueprint);

      const msvc8::string factoryCategory("FACTORY");
      for (UserEntity* const selectedEntity : session->mSelection) {
        UserUnit* const selectedUnit = selectedEntity->IsUserUnit();
        const moho::IUnit* const factoryUnit = moho::GetIUnitBridge(selectedUnit);
        if (selectedUnit != nullptr && factoryUnit != nullptr && !factoryUnit->IsDead()
            && selectedEntity->IsInCategory(factoryCategory)) {
          WeakSet<UserEntity> oneUnit;
          (void)oneUnit.Add(selectedEntity);
          for (int remaining = repeatCount; remaining > 0; --remaining) {
            ISSUE_Command(oneUnit, factoryCommand, clearQueue);
          }
        }
      }
      return 0;
    }

    // Every other command type: issue `count` copies to the whole selection.
    SSTICommandIssueData blueprintCommand(commandType);
    blueprintCommand.mBlueprint = static_cast<RUnitBlueprint*>(blueprint);
    for (int remaining = repeatCount; remaining > 0; --remaining) {
      ISSUE_Command(session->mSelection, blueprintCommand, clearQueue);
    }
    return 0;
  }

  /**
   * Address: 0x008418C0 (FUN_008418C0, cfunc_IssueUnitCommandL)
   *
   * What it does:
   * Parses explicit user-unit list + command lexical with optional payload/clear
   * flag and issues the command to that explicit list.
   */
  int cfunc_IssueUnitCommandL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 4) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kIssueUnitCommandHelpText,
        1,
        4,
        argumentCount
      );
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      gpg::Warnf("Attempt to call IssueCommand before world sessions exists.");
      return 0;
    }

    const int focusArmy = session->FocusArmy;
    if (focusArmy < 0 || static_cast<std::size_t>(focusArmy) >= session->userArmies.size()
        || session->userArmies[focusArmy] == nullptr) {
      return 0;
    }

    if (lua_type(rawState, 1) != LUA_TTABLE) {
      LuaPlus::LuaState::Error(state, "Unit list expected as first argument");
    }

    // Binary walks the explicit unit table with a LuaTableIterator and pushes every
    // decoded value unconditionally (no null filter) into a gpg::fastvector<UserUnit*>.
    gpg::fastvector<UserUnit*> units{};
    {
      LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
      for (LuaPlus::LuaTableIterator iter(unitListObject, 1); !iter.m_isDone; iter.Next()) {
        units.push_back(SCR_FromLua_UserUnit(iter.m_valueObj, state));
      }
    }

    const LuaPlus::LuaStackObject commandArg(state, 2);
    const char* const commandLexical = lua_tostring(rawState, 2);
    if (commandLexical == nullptr) {
      commandArg.TypeError("string");
      return 0;
    }

    EUnitCommandType commandType = EUnitCommandType::UNITCOMMAND_None;
    if (!TryParseUnitCommandTypeLexical(commandLexical, commandType)
        || commandType == EUnitCommandType::UNITCOMMAND_None) {
      return 0;
    }

    SSTICommandIssueData commandIssueData(commandType);
    if (argumentCount >= 3) {
      commandIssueData.mObject = LuaPlus::LuaStackObject(state, 3);
    }

    bool clearQueue = true;
    if (argumentCount == 4) {
      clearQueue = LuaPlus::LuaStackObject(state, 4).GetBoolean();
    }

    // Binary passes the SSTICommandIssueData BY VALUE to the fastvector overload of
    // Moho::ISSUE_Command (asm 0x00841B3B) — NOT via the sim BVSet path.
    ISSUE_Command(units, commandIssueData, clearQueue);
    return 0;
  }

  /**
   * Address: 0x00836900 (FUN_00836900, cfunc_DecreaseBuildCountInQueue)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_DecreaseBuildCountInQueueL`.
   */
  int cfunc_DecreaseBuildCountInQueue(lua_State* const luaContext)
  {
    return cfunc_DecreaseBuildCountInQueueL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008366C0 (FUN_008366C0, cfunc_IncreaseBuildCountInQueue)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IncreaseBuildCountInQueueL`.
   */
  int cfunc_IncreaseBuildCountInQueue(lua_State* const luaContext)
  {
    return cfunc_IncreaseBuildCountInQueueL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00840130 (FUN_00840130, cfunc_GetUnitCommandDataL)
   *
   * IDA signature:
   * int __cdecl cfunc_GetUnitCommandDataL(LuaPlus::LuaState *state);
   *
   * What it does:
   * Given a Lua table of user units, computes the intersection (across the
   * selection) of the buildable-unit category set and the union of command /
   * toggle capability masks, and returns `(commandCaps, toggleCaps, category)`.
   * For each unit the buildable set is `(blueprintEconomyCategory & armyFilter)
   * - restrictionCategory`, plus the same for every pending Upgrade command's
   * target blueprint (with the target's own blueprint-id category removed).
   */
  int cfunc_GetUnitCommandDataL(LuaPlus::LuaState* const state)
  {
    const int argc = lua_gettop(state->m_state);
    if (argc != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUnitCommandDataHelpText, 1, argc);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      gpg::Warnf("Attempt to call GetUnitCommands before world sessions exists.");
      return 0;
    }

    const LuaPlus::LuaObject unitTable(LuaPlus::LuaStackObject(state, 1));
    if (!unitTable.IsTable()) {
      LuaPlus::LuaState::Error(state, "Expected table of UserUnits but got %s.", unitTable.TypeName());
    }
    const int unitCount = unitTable.GetCount();

    std::uint32_t accCommandCaps = 0u;
    std::uint32_t accToggleCaps = 0u;
    bool haveAcc = false;

    // The category universe word is the owning rules object, stored as the
    // binary stores it (see `RUnitBlueprint`'s CategoryCache).
    EntityCategorySet accCategory{};
    accCategory.ResetToEmpty(EntityCategoryHelper{session->mRules});

    for (int i = 1; i <= unitCount; ++i) {
      EntityCategorySet perUnit{};
      perUnit.ResetToEmpty(EntityCategoryHelper{session->mRules});

      const LuaPlus::LuaObject unitObject = unitTable[i];
      UserUnit* const unit = GetUserUnitOptional(unitObject, state);
      if (unit != nullptr) {
        IUnit* const iunit = GetIUnitBridge(unit);
        UnitAttributes& attrs = iunit->GetAttributes();
        if (attrs.blueprint != nullptr) {
          const RUnitBlueprint* const bp = iunit->GetBlueprint();

          const EntityCategorySet* const economyCat = &bp->Economy.CategoryCache;
          const UserArmy* const army = unit->mArmy;
          const EntityCategorySet* const armyCat = &army->mVarDat.mCategoryFilterSet;
          const EntityCategorySet* const restrictionCat = &attrs.restrictionCategory;

          accCommandCaps |= attrs.commandCapsMask;
          accToggleCaps |= attrs.toggleCapsMask;

          EntityCategorySet intersect{};
          (void)EntityCategory::Mul(&intersect, economyCat, armyCat);

          EntityCategorySet buildable{};
          (void)EntityCategory::Sub(&buildable, &intersect, restrictionCat);

          (void)EntityCategory::Add(&perUnit, &buildable);


          msvc8::list<const RUnitBlueprint*> upgradeTargets;
          CollectUpgradeCommandTargetBlueprints(unit, upgradeTargets);
          for (const RUnitBlueprint* const targetBp : upgradeTargets) {
            const EntityCategorySet* const targetEconomyCat = &targetBp->Economy.CategoryCache;

            EntityCategorySet targetIntersect{};
            (void)EntityCategory::Mul(&targetIntersect, targetEconomyCat, armyCat);

            EntityCategorySet targetBuildable{};
            (void)EntityCategory::Sub(&targetBuildable, &targetIntersect, restrictionCat);

            // The binary reuses the per-unit accumulator as its scratch: it
            // OVERWRITES `perUnit` with this target's buildable set (v53 = v25),
            // then removes the target's own blueprint-id category from the rules
            // cache. Because the loop overwrites `perUnit` every iteration, the
            // accumulated per-unit set becomes the LAST upgrade target's
            // buildable set; the `Add(&perUnit, &buildable)` result above is only
            // retained when the unit has no pending Upgrade commands.
            perUnit = targetBuildable;

            // 0x008404CC..0x008404D3: FUN_00401A90 is called with ESI = this
            // per-unit set (the destination it masks) and EDI = the target's
            // own blueprint-id category (the bits removed), so the upgrade
            // target itself drops out of the menu and the shared rules
            // category is only read.
            const char* const bpId = targetBp->mBlueprintId.c_str();
            if (bpId != nullptr) {
              const EntityCategorySet* const rulesCat = session->mRules->GetEntityCategory(bpId);
              perUnit.mBits.RemoveAllFrom(&rulesCat->mBits);
            }
          }
        }
      }

      if (haveAcc) {
        accCategory.mBits.IntersectWith(&perUnit.mBits);
      } else {
        accCategory = perUnit;
        haveAcc = true;
      }
    }

    LuaPlus::LuaObject commandCapsTable;
    commandCapsTable.AssignNewTable(state, 23, 0);
    int commandRow = 1;
    for (int b = 0; b < 23; ++b) {
      if (((1u << b) & accCommandCaps) != 0u) {
        moho::ERuleBPUnitCommandCaps cap = static_cast<moho::ERuleBPUnitCommandCaps>(1u << b);
        gpg::RRef capRef{};
        capRef = gpg::MakeRRef<moho::ERuleBPUnitCommandCaps>(&cap);
        const msvc8::string lexical = capRef.GetLexical();
        commandCapsTable.SetString(commandRow, lexical.c_str());
        ++commandRow;
      }
    }
    commandCapsTable.PushStack(state);

    LuaPlus::LuaObject toggleCapsTable;
    toggleCapsTable.AssignNewTable(state, 9, 0);
    int toggleRow = 1;
    for (int b = 0; b < 9; ++b) {
      if (((1u << b) & accToggleCaps) != 0u) {
        moho::ERuleBPUnitToggleCaps cap = static_cast<moho::ERuleBPUnitToggleCaps>(1u << b);
        gpg::RRef capRef{};
        capRef = gpg::MakeRRef<moho::ERuleBPUnitToggleCaps>(&cap);
        const msvc8::string lexical = capRef.GetLexical();
        toggleCapsTable.SetString(toggleRow, lexical.c_str());
        ++toggleRow;
      }
    }
    toggleCapsTable.PushStack(state);

    LuaPlus::LuaObject categoryObject;
    (void)func_NewEntityCategory(state, &categoryObject, &accCategory);
    categoryObject.PushStack(state);

    return 3;
  }

  /**
   * Address: 0x008400B0 (FUN_008400B0, cfunc_GetUnitCommandData)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_GetUnitCommandDataL`.
   */
  int cfunc_GetUnitCommandData(lua_State* const luaContext)
  {
    return cfunc_GetUnitCommandDataL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00840A70 (FUN_00840A70, cfunc_IssueDockCommandL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueDockCommandL(LuaPlus::LuaState *state);
   *
   * What it does:
   * Implements the global Lua `IssueDockCommand(clear)`. Snapshots the current
   * world selection, keeps only units with the `RULEUCC_Dock` capability, and
   * computes their XZ centroid (each unit contributes either its live position or,
   * when `clear` is false and it has a queued command, that command's anchor
   * position). It then scans every session entity for viable focus-army air-staging
   * platforms (alive, not being built, in category `AIRSTAGINGPLATFORM`, not on an
   * air/water layer, idle) with free docking capacity, recording distance-to-centroid
   * and free-slot count for each. If the nearest platform can hold the whole
   * dock-capable set, one `UNITCOMMAND_Dock` is issued toward it; otherwise units are
   * distributed proportionally across the nearby platforms (within
   * nearest-distance + 100 units) by free-capacity share. If no viable platform was
   * found, or all had no capacity, it plays the corresponding "no staging platforms"
   * / "busy staging platforms" voice-over on one representative selected entity.
   */
  int cfunc_IssueDockCommandL(LuaPlus::LuaState* const state)
  {
    const int argc = lua_gettop(state->m_state);
    if (argc != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueDockCommandHelpText, 1, argc);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      gpg::Warnf("Attempt to call IssueCommand before world sessions exists.");
      return 0;
    }

    // Focus army must be valid (mFocusArmy >= 0 && mUserArmies[mFocusArmy] != null).
    if (session->GetFocusArmy() == nullptr) {
      return 0;
    }

    const bool clear = LuaPlus::LuaStackObject(state, 1).GetBoolean();

    // Snapshot the current selection (the copy constructor, 0x00822210).
    WeakSet<UserEntity> selectionSnapshot(session->mSelection);

    // The dock-capable subset of the selection; docks are issued to this set.
    WeakSet<UserEntity> dockTargets;

    // XZ centroid accumulator over the dock-capable units, and their count.
    float centroidX = 0.0f;
    float centroidZ = 0.0f;
    float dockCapableCount = 0.0f;

    // --- Phase 1: collect dock-capable selected units + accumulate the centroid. ---
    {
      for (UserEntity* const entity : selectionSnapshot) {
        UserUnit* const unit = entity->IsUserUnit();
        if (unit != nullptr) {
          IUnit* const bridge = GetIUnitBridge(unit);
          if ((bridge->GetAttributes().commandCapsMask & kRuleUccDock) != 0u) {
            const QueuedUserCommandRecord* const anchor = GetLastQueuedUserCommandAnchor(unit);
            if (clear || anchor == nullptr) {
              const Wm3::Vec3f& position = bridge->GetPosition();
              centroidX += position.x;
              centroidZ += position.z;
            } else {
              const Wm3::Vector3f anchorPos = ResolveLastQueuedCommandAnchorPosition(anchor);
              centroidX += anchorPos.x;
              centroidZ += anchorPos.z;
            }

            (void)dockTargets.Add(entity);
            dockCapableCount += 1.0f;
          }
        }
      }
    }

    if (dockCapableCount <= 0.0f) {
      return 0;
    }

    centroidX = (1.0f / dockCapableCount) * centroidX;
    centroidZ = centroidZ * (1.0f / dockCapableCount);

    // Voice-over gating flags: whether any focus-army staging platform was seen at
    // all, and whether any had free docking capacity.
    bool foundStagingPlatform = false;
    bool foundFreeStagingPlatform = false;

    // Staging-platform category snapshot (copy of the rules-cached set).
    EntityCategorySet stagingCategory(*session->mRules->GetEntityCategory("AIRSTAGINGPLATFORM"));

    // --- Phase 2: scan every session entity for viable air-staging platforms. ---
    std::vector<DockCandidate> candidates;
    {
      UserArmy* const focusArmy = session->GetFocusArmy();
      msvc8::vector<UserUnit*> sessionUnits;
      GetSessionUserUnits(session, sessionUnits);
      for (UserUnit* const platform : sessionUnits) {
        if (platform == nullptr) {
          continue;
        }
        if (platform->mArmy != focusArmy) {
          continue;
        }
        if (platform->IsBeingBuilt()) {
          continue;
        }

        IUnit* const platformBridge = GetIUnitBridge(platform);
        if (platformBridge->IsDead()) {
          continue;
        }

        const RUnitBlueprint* const blueprint = platformBridge->GetBlueprint();
        if (!EntityCategory::HasBlueprint(blueprint, &stagingCategory)) {
          continue;
        }

        foundStagingPlatform = true;

        const std::uint32_t layerMask = platform->mVariableData.mLayerMask;
        if (layerMask == kDockRejectLayerSub || layerMask == kDockRejectLayerSeabed) {
          continue;
        }
        if (!USERUNIT_IsDockTargetIdle(platform)) {
          continue;
        }

        const std::int32_t storageSlots = blueprint->Transport.StorageSlots;
        std::int32_t freeCapacity = blueprint->Transport.DockingSlots;
        if (storageSlots != 0) {
          const std::int32_t dockedCount =
            static_cast<std::int32_t>(platform->mVariableData.mAuxValueVector.Size());
          freeCapacity = storageSlots - dockedCount;
        }
        if (freeCapacity <= 0) {
          continue;
        }

        foundFreeStagingPlatform = true;

        const Wm3::Vec3f& platformPos = platformBridge->GetPosition();
        const float dx = platformPos.x - centroidX;
        const float dz = platformPos.z - centroidZ;
        const float distSq = (dz * dz) + (dx * dx);
        candidates.push_back(DockCandidate{platform, distSq, freeCapacity});
      }
    }

    // --- Phase 3: distance-sort candidates and assign dock commands. ---
    // The call inlines the `std::sort` entry and runs the MSVC8 introsort
    // driver for the 12-byte DockCandidate directly, seeding the recursion
    // budget with the element count, with the by-`distSq` predicate inlined
    // into every body. The instantiation is catalogued on
    // legacy/algorithms/Sort.h; platforms at equal distance only come out in
    // the original's order through that algorithm, not the modern `std::sort`.
    msvc8::sort(candidates.data(), candidates.data() + candidates.size(), [](const DockCandidate& a, const DockCandidate& b) {
      return a.distSq < b.distSq;
    });

    if (!candidates.empty()) {
      const std::int32_t dockCapableSize = static_cast<std::int32_t>(dockTargets.Size());
      if (dockCapableSize <= candidates.front().freeCapacity) {
        // The nearest platform can hold the entire dock-capable set: one command.
        SSTICommandIssueData command(EUnitCommandType::UNITCOMMAND_Dock);
        command.mTarget.mEnt = candidates.front().platform->mParams.mEntityId;
        command.mTarget.mType = EAiTargetType::AITARGET_Entity;
        command.mTarget.mPos = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
        ISSUE_Command(dockTargets, command, clear);
      } else {
        // Distribute the selection across nearby platforms by free-capacity share.
        // Gather platforms within (nearestDistance + 100)^2 and total their capacity.
        const float nearestDistance = std::sqrt(candidates.front().distSq);
        const float radiusSq =
          (nearestDistance + kMultiDockRadiusPadding) * (nearestDistance + kMultiDockRadiusPadding);

        std::int32_t totalFreeCapacity = 0;
        std::vector<DockCandidate> nearbyPlatforms;
        for (const DockCandidate& candidate : candidates) {
          if (radiusSq > candidate.distSq) {
            nearbyPlatforms.push_back(candidate);
            totalFreeCapacity += candidate.freeCapacity;
          }
        }

        // Order the chosen platforms by descending free capacity, so the
        // roomiest platform is filled first, then by ascending distance. The
        // predicate is inlined into the instantiation's `_Med3` and partition
        // as a signed `setg` on `freeCapacity` with a `comiss` `distSq`
        // tie-break; the instantiation is catalogued on
        // legacy/algorithms/Sort.h.
        msvc8::sort(
          nearbyPlatforms.data(),
          nearbyPlatforms.data() + nearbyPlatforms.size(),
          [](const DockCandidate& a, const DockCandidate& b) {
            if (a.freeCapacity != b.freeCapacity) {
              return a.freeCapacity > b.freeCapacity;
            }
            return a.distSq < b.distSq;
          }
        );

        // Per-platform quota scale = max(1, ceil(selectionSize / totalCapacity)).
        const float capacityRatio =
          static_cast<float>(dockCapableSize) / static_cast<float>(totalFreeCapacity);
        const float quotaScale = (capacityRatio > 1.0f) ? capacityRatio : 1.0f;

        // Walk the dock-capable set, filling each platform up to its scaled quota.
        WeakSet<UserEntity>& dockSet = dockTargets;
        for (const DockCandidate& platformSlot : nearbyPlatforms) {
          // Quota = round-to-nearest(freeCapacity * scale), rounding up on any
          // positive remainder above the rounded value (matches x87 frndint + adjust).
          const float quotaValue = static_cast<float>(platformSlot.freeCapacity) * quotaScale;
          const float roundedQuota = std::rint(quotaValue);
          std::int32_t quota = static_cast<std::int32_t>(roundedQuota);
          if (quotaValue > roundedQuota) {
            quota += 1;
          }

          // Build a fresh weak-set of up to `quota` units drawn from the dock set.
          WeakSet<UserEntity> quotaUnits;
          for (UserEntity* const unitEntity : dockSet) {
            if (static_cast<std::int32_t>(quotaUnits.Size()) >= quota) {
              break;
            }
            (void)quotaUnits.Add(unitEntity);
          }

          // If nothing could be assigned to this platform, stop distributing.
          if (quotaUnits.Empty()) {
            break;
          }

          SSTICommandIssueData command(EUnitCommandType::UNITCOMMAND_Dock);
          command.mTarget.mEnt = platformSlot.platform->mParams.mEntityId;
          command.mTarget.mType = EAiTargetType::AITARGET_Entity;
          command.mTarget.mPos = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
          ISSUE_Command(quotaUnits, command, clear);
        }
      }
    }

    // --- Voice-over feedback on one representative selected entity. ---
    UserEntity* representative = nullptr;
    {
      const auto firstLive = selectionSnapshot.begin();
      representative = firstLive != selectionSnapshot.end() ? *firstLive : nullptr;
    }

    if (representative != nullptr) {
      UserUnit* const representativeUnit = representative->IsUserUnit();
      if (representativeUnit != nullptr) {
        const char* voiceOver = nullptr;
        if (!foundStagingPlatform) {
          voiceOver = "PlayNoStagingPlatformsVO";
        } else if (!foundFreeStagingPlatform) {
          voiceOver = "PlayBusyStagingPlatformsVO";
        }

        if (voiceOver != nullptr) {
          if (ISTIDriver* const driver = WLD_GetDriver(); driver != nullptr) {
            // The voice-over name is the key and "play" the value
            // (0x008413C0..0x008413EE push "play" first, as the last
            // argument). `Sim::ProcessInfoPair` matches on the key, so the
            // other way round the voice-over never plays.
            driver->ProcessInfoPair(representativeUnit->mParams.mEntityId, voiceOver, "play");
          }
        }
      }
    }

    return 0;
  }

  /**
   * Address: 0x008409F0 (FUN_008409F0, cfunc_IssueDockCommand)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_IssueDockCommandL`.
   */
  int cfunc_IssueDockCommand(lua_State* const luaContext)
  {
    return cfunc_IssueDockCommandL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00841530 (FUN_00841530, cfunc_IssueCommand)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_IssueCommandL`.
   */
  int cfunc_IssueCommand(lua_State* const luaContext)
  {
    return cfunc_IssueCommandL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00841840 (FUN_00841840, cfunc_IssueUnitCommand)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IssueUnitCommandL`.
   */
  int cfunc_IssueUnitCommand(lua_State* const luaContext)
  {
    return cfunc_IssueUnitCommandL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00841B90 (FUN_00841B90, cfunc_IssueBlueprintCommand)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IssueBlueprintCommandL`.
   */
  int cfunc_IssueBlueprintCommand(lua_State* const luaContext)
  {
    return cfunc_IssueBlueprintCommandL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00842920 (FUN_00842920, cfunc_GetRolloverInfoL)
   *
   * IDA signature:
   * int __userpurge cfunc_GetRolloverInfoL(LuaPlus::LuaState *state@<edi>);
   *
   * What it does:
   * Builds the `GetRolloverInfo()` Lua table for the currently hovered unit:
   * fills full unit stats, then resolves the hovered unit's target-blip / focus /
   * focus-prop / guarded targets into nested tables. Pushes nil when there is no
   * in-world hovered unit. Holds a transient weak-link guard on the hovered unit
   * for the duration of the build.
   */
  int cfunc_GetRolloverInfoL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 0) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetRolloverInfoHelpText, 0, argumentCount);
    }

    CWldSession* const session = WLD_GetActiveSession();

    // Snapshot the hovered-unit weak slot and pin it with a transient guard node
    // linked into the entity's weak-owner chain (mirrors FUN_00842920 var_48 dance).
    moho::WeakObject* hoverOwner = nullptr;
    UserEntity* hoveredEntity = nullptr;
    bool inWorld = false;
    if (session != nullptr) {
      const MouseInfo& cursor = session->GetCursorInfo();
      hoveredEntity = cursor.HoveredEntity();
      if (hoveredEntity != nullptr) {
        hoverOwner = static_cast<moho::WeakObject*>(hoveredEntity);
      }
      inWorld = cursor.mHitValid != 0;
    }

    const WeakPtr<UserEntity> hoverGuard(hoveredEntity);

    LuaPlus::LuaObject result;

    UserUnit* hoveredUnit = nullptr;
    if (hoveredEntity != nullptr && inWorld) {
      hoveredUnit = hoveredEntity->IsUserUnit();
    }

    if (hoveredUnit == nullptr) {
      result.AssignNil(state);
    } else {
      BuildUserUnitRolloverInfo(result, hoveredUnit, state);

      const SSTIUnitVariableData& hoveredData = hoveredUnit->mUnitVarDat;

      if (UserEntity* const targetEntity = session->LookupEntityId(hoveredData.mTargetBlip); targetEntity != nullptr) {
        if (UserUnit* const targetUnit = targetEntity->IsUserUnit(); targetUnit != nullptr) {
          LuaPlus::LuaObject focusTable;
          BuildFocusUnitRolloverInfo(focusTable, targetUnit, state);
          result.SetObject("focus", focusTable);
        }
      } else if (UserEntity* const focusEntity = session->LookupEntityId(hoveredData.mFocusUnit); focusEntity != nullptr) {
        if (UserUnit* const focusUnit = focusEntity->IsUserUnit(); focusUnit != nullptr) {
          LuaPlus::LuaObject focusTable;
          BuildUserUnitRolloverInfo(focusTable, focusUnit, state);
          // The upgrade/focus key is chosen from the HOVERED unit's state, not the focus unit's.
          IUnit* const hoveredBridge = GetIUnitBridge(hoveredUnit);
          if (hoveredBridge->IsUnitState(UNITSTATE_Upgrading)) {
            result.SetObject("focusUpgrade", focusTable);
          } else {
            result.SetObject("focus", focusTable);
          }
        } else if ((hoveredData.mFocusUnit & 0xF0000000u) == 0x20000000u) {
          LuaPlus::LuaObject propTable;
          BuildFocusPropRolloverInfo(propTable, focusEntity, state);
          result.SetObject("focusProp", propTable);
        }
      } else if (UserEntity* const guardedEntity = session->LookupEntityId(hoveredData.mGuardedUnit);
                 guardedEntity != nullptr) {
        if (UserUnit* const guardedUnit = guardedEntity->IsUserUnit(); guardedUnit != nullptr) {
          LuaPlus::LuaObject guardedTable;
          BuildUserUnitRolloverInfo(guardedTable, guardedUnit, state);
          result.SetObject("guarded", guardedTable);
        }
      }
    }

    result.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x008428A0 (FUN_008428A0, cfunc_GetRolloverInfo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetRolloverInfoL`.
   */
  int cfunc_GetRolloverInfo(lua_State* const luaContext)
  {
    return cfunc_GetRolloverInfoL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00866DB0 (FUN_00866DB0, cfunc_UISelectionByCategoryL)
   *
   * What it does:
   * Lua worker for UISelectionByCategory(expression, addToCurSel, inViewFrustum,
   * nearestToMouse, mustBeIdle). Validates 5 args, resolves the world camera, and
   * dispatches SelectUnitsByCategory (camera-target / engineer-exclusion are
   * always off from Lua). Emits a localized error when there is no active session.
   */
  int cfunc_UISelectionByCategoryL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 5) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUISelectionByCategoryHelpText, 5, argumentCount);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      const msvc8::string noSessionText = Loc(USER_GetLuaState(), "<LOC _No_session>");
      CON_Printf(noSessionText.c_str());
      return 0;
    }

    const char* const categoryExpr = lua_tostring(rawState, 1);
    if (categoryExpr == nullptr) {
      LuaPlus::LuaStackObject categoryArg(state, 1);
      LuaPlus::LuaStackObject::TypeError(&categoryArg, "string");
    }

    // Decompiler bind order: arg5=mustBeIdle, arg4=nearestToMouse, arg3=inViewFrustum, arg2=addToCurSel.
    LuaPlus::LuaStackObject mustBeIdleArg(state, 5);
    const bool mustBeIdle = mustBeIdleArg.GetBoolean();
    LuaPlus::LuaStackObject nearestToMouseArg(state, 4);
    const bool nearestToMouse = nearestToMouseArg.GetBoolean();
    LuaPlus::LuaStackObject inViewFrustumArg(state, 3);
    const bool inViewFrustum = inViewFrustumArg.GetBoolean();
    LuaPlus::LuaStackObject addToSelectionArg(state, 2);
    const bool addToSelection = addToSelectionArg.GetBoolean();

    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const camera = cameraManager->GetCamera("WorldCamera");

    SelectUnitsByCategory(
      session,
      camera,
      categoryExpr,
      addToSelection,  // a4
      inViewFrustum,   // a5
      nearestToMouse,  // a6
      mustBeIdle,      // a7
      false,           // a8 doCameraTarget (no Lua arg)
      false            // a9 excludeEngineerCommand (no Lua arg)
    );
    return 0;
  }

  /**
   * Address: 0x00866D30 (FUN_00866D30, cfunc_UISelectionByCategory)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UISelectionByCategoryL`.
   */
  int cfunc_UISelectionByCategory(lua_State* const luaContext)
  {
    return cfunc_UISelectionByCategoryL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00866F40 (FUN_00866F40, cfunc_UISelectAndZoomTo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UISelectAndZoomToL`.
   */
  int cfunc_UISelectAndZoomTo(lua_State* const luaContext)
  {
    return cfunc_UISelectAndZoomToL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00866FC0 (FUN_00866FC0, cfunc_UISelectAndZoomToL)
   *
   * What it does:
   * Validates `UISelectAndZoomTo(userunit,[seconds])` from Lua. When the world
   * session is live and a `WorldCamera` exists, resolves the argument to a
   * `UserUnit`, replaces the active selection with the single-entity set, and
   * dispatches `CameraImpl::TargetEntityBox(unit, seconds)` to frame the
   * entity. Reports localized "No session" or the literal "No world camera
   * found." line via `CON_Printf` for the missing-prerequisite paths.
   */
  int cfunc_UISelectAndZoomToL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kUISelectAndZoomToHelpText, 1, 2, argumentCount
      );
    }

    UserUnit* unit = nullptr;
    {
      const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
      unit = SCR_FromLua_UserUnit(userUnitObject, state);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      const msvc8::string noSessionText = Loc(USER_GetLuaState(), "<LOC _No_session>");
      CON_Printf("%s", noSessionText.c_str());
      return 0;
    }

    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const camera =
      (cameraManager != nullptr) ? cameraManager->GetCamera("WorldCamera") : nullptr;
    if (camera == nullptr) {
      CON_Printf("UISelectAndZoomTo: No world camera found.");
      return 0;
    }

    WeakSet<UserEntity> selection;
    (void)selection.Add(unit);

    session->SetSelection(selection);

    float seconds = 0.0f;
    if (lua_gettop(rawState) == 2) {
      const LuaPlus::LuaStackObject secondsArg(state, 2);
      seconds = static_cast<float>(secondsArg.GetNumber());
    }

    camera->TargetEntityBox(static_cast<UserEntity*>(unit), seconds);
    return 0;
  }

  /**
   * Address: 0x008671C0 (FUN_008671C0, cfunc_UIZoomTo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UIZoomToL`.
   */
  int cfunc_UIZoomTo(lua_State* const luaContext)
  {
    return cfunc_UIZoomToL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00867240 (FUN_00867240, cfunc_UIZoomToL)
   *
   * IDA signature:
   * int __usercall cfunc_UIZoomToL@<eax>(LuaPlus::LuaState *state@<ebx>);
   *
   * What it does:
   * Implements `UIZoomTo(units,[seconds])`. Validates arg count (1..2). When the
   * world session is live and a `WorldCamera` exists, walks the Lua unit table,
   * resolves each element via `GetUserUnitOptional`, and accumulates the
   * world-space XZ bounds plus the Y centroid over all resolved units. When at
   * least one unit contributed, builds a world-space AABB centered on the XZ
   * min/max and the average Y, expanded by a fixed 20-unit margin on every face
   * (half-extent = 0.5 * max(spanX, spanZ)), and frames it through
   * `CameraImpl::TargetBox(box, seconds)` followed by `TargetNothing()`.
   * `seconds` defaults to 0 and is read from arg 2 when present. Reports the
   * localized "<LOC _No_session>" line when no session is active and
   * "UISelectAndZoomTo: No world camera found." when the world camera is missing.
   */
  int cfunc_UIZoomToL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kUIZoomToHelpText, 1, 2, argumentCount
      );
    }

    if (WLD_GetActiveSession() == nullptr) {
      const msvc8::string noSessionText = Loc(USER_GetLuaState(), "<LOC _No_session>");
      CON_Printf("%s", noSessionText.c_str());
      return 0;
    }

    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const camera = cameraManager->GetCamera("WorldCamera");
    if (camera == nullptr) {
      CON_Printf("UISelectAndZoomTo: No world camera found.");
      return 0;
    }

    const LuaPlus::LuaObject unitTable(LuaPlus::LuaStackObject(state, 1));
    if (!unitTable.IsTable() || unitTable.GetCount() <= 0) {
      return 0;
    }

    const float kPositiveInfinity = gpg::pInf;
    const float kNegativeInfinity = gpg::nInf;
    constexpr float kBoxMargin = 20.0f;

    float minX = kPositiveInfinity;
    float maxX = kNegativeInfinity;
    float minZ = kPositiveInfinity;
    float maxZ = kNegativeInfinity;
    float sumY = 0.0f;
    float count = 0.0f;

    const int unitCount = unitTable.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = unitTable[unitIndex];
      UserUnit* const unit = GetUserUnitOptional(unitObject, state);
      if (unit == nullptr) {
        continue;
      }

      const Wm3::Vec3f& position = GetIUnitBridge(unit)->GetPosition();
      minZ = std::min(minZ, position.z);
      maxZ = std::max(maxZ, position.z);
      minX = std::min(minX, position.x);
      maxX = std::max(maxX, position.x);
      sumY += position.y;
      count += 1.0f;
    }

    if (count <= 0.0f) {
      return 0;
    }

    const float averageY = sumY / count;
    const float spanX = maxX - minX;
    const float spanZ = maxZ - minZ;
    const float halfExtent = std::max(spanX, spanZ) * 0.5f;

    Wm3::AxisAlignedBox3f targetBox{};
    targetBox.Min.x = minX - kBoxMargin;
    targetBox.Min.y = (averageY - halfExtent) - kBoxMargin;
    targetBox.Min.z = minZ - kBoxMargin;
    targetBox.Max.x = maxX + kBoxMargin;
    targetBox.Max.y = (averageY + halfExtent) + kBoxMargin;
    targetBox.Max.z = maxZ + kBoxMargin;

    float seconds = 0.0f;
    if (lua_gettop(rawState) == 2) {
      const LuaPlus::LuaStackObject secondsArg(state, 2);
      seconds = static_cast<float>(secondsArg.GetNumber());
    }

    camera->TargetBox(targetBox, seconds);
    camera->TargetNothing();
    return 0;
  }

  /**
   * Address: 0x00846BE0 (FUN_00846BE0, cfunc_SetOverlayFilterL)
   *
   * What it does:
   * Parses one overlay profile payload
   * `(name, category, buildColor, selectedColor, highlightedColor,
   * innerRadius, innerThickness, outerRadius, outerThickness)` and applies it
   * to the active viewport range-render profile map.
   */
  int cfunc_SetOverlayFilterL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 9) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetOverlayFilterHelpText, 9, argumentCount);
    }

    if (moho::WLD_GetActiveSession() == nullptr || moho::ren_Viewport == nullptr) {
      return 0;
    }

    const LuaPlus::LuaObject highlightedColorObject(LuaPlus::LuaStackObject(state, 5));
    const LuaPlus::LuaObject selectedColorObject(LuaPlus::LuaStackObject(state, 4));
    const LuaPlus::LuaObject buildColorObject(LuaPlus::LuaStackObject(state, 3));

    LuaPlus::LuaStackObject profileNameArg(state, 1);
    const char* const profileName = lua_tostring(state->m_state, 1);
    if (profileName == nullptr) {
      profileNameArg.TypeError("string");
    }

    const auto requireFloatArg = [state](const int stackIndex) -> float {
      LuaPlus::LuaStackObject argument(state, stackIndex);
      if (lua_type(state->m_state, stackIndex) != LUA_TNUMBER) {
        argument.TypeError("number");
      }
      return static_cast<float>(lua_tonumber(state->m_state, stackIndex));
    };

    const moho::RangeRingRadiusParams innerRingParams{
      requireFloatArg(6),
      requireFloatArg(7),
    };
    const moho::RangeRingRadiusParams outerRingParams{
      requireFloatArg(8),
      requireFloatArg(9),
    };

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    moho::EntityCategorySet* const categoryFilter = moho::func_GetCObj_EntityCategory(categoryObject);

    const std::uint32_t highlightedColorPacked = moho::SCR_DecodeColor(state, highlightedColorObject);
    const std::uint32_t selectedColorPacked = moho::SCR_DecodeColor(state, selectedColorObject);
    const std::uint32_t buildColorPacked = moho::SCR_DecodeColor(state, buildColorObject);

    // 0x00846EA9 / 0x00846EC6: the profile is applied to the active viewport's
    // own range renderer (`ren_Viewport + 0x37C`). Passing null here registered
    // every overlay profile into nothing, so `mRangeRenderer.mRangeProfiles`
    // stayed empty and no weapon-range ring was ever drawn.
    moho::ApplyRangeProfileFilterToRenderer(
      highlightedColorPacked,
      categoryFilter,
      &moho::ren_Viewport->mRangeRenderer,
      profileName,
      buildColorPacked,
      selectedColorPacked,
      innerRingParams,
      outerRingParams
    );

    return 0;
  }

  /**
   * Address: 0x00846B60 (FUN_00846B60, cfunc_SetOverlayFilter)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_SetOverlayFilterL`.
   */
  int cfunc_SetOverlayFilter(lua_State* const luaContext)
  {
    return cfunc_SetOverlayFilterL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008472F0 (FUN_008472F0, cfunc_GetActiveBuildTemplateL)
   *
   * What it does:
   * Publishes the active world-session build-template payload as one Lua array
   * `{xSpan, zSpan, {bpId, buildOrder, x, z}...}`.
   */
  int cfunc_GetActiveBuildTemplateL(LuaPlus::LuaState* const state)
  {
    CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr) {
      return 0;
    }

    LuaPlus::LuaObject resultTable;
    resultTable.AssignNewTable(state, 0, 0);

    float templateSpanZ = 0.0f;
    float templateSpanX = 0.0f;
    gpg::fastvector_n<SBuildTemplateInfo, 16> activeTemplate{};
    session->GetActiveBuildTemplate(&templateSpanZ, &templateSpanX, &activeTemplate);

    if (!activeTemplate.Empty()) {
      resultTable.SetNumber(1, templateSpanX);
      resultTable.SetNumber(2, templateSpanZ);

      std::int32_t nextResultIndex = 3;
      for (const SBuildTemplateInfo& entry : activeTemplate) {
        LuaPlus::LuaObject entryTable;
        entryTable.AssignNewTable(state, 0, 0);
        entryTable.SetString(1, entry.mBlueprintId.c_str());
        entryTable.SetInteger(2, entry.mBuildOrder);
        entryTable.SetNumber(3, entry.mPos.x);
        entryTable.SetNumber(4, entry.mPos.z);
        resultTable.SetObject(nextResultIndex, entryTable);
        ++nextResultIndex;
      }
    }

    resultTable.PushStack(state);

    // `activeTemplate` is a local `gpg::fastvector_n<SBuildTemplateInfo, 16>`;
    // its own destructor releases every entry's blueprint-id string and any
    // spilled heap storage at scope exit -- the compiler-emitted teardown the
    // binary also runs here, not a hand-rolled release loop.
    return 1;
  }

  /**
   * Address: 0x00847270 (FUN_00847270, cfunc_GetActiveBuildTemplate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_GetActiveBuildTemplateL`.
   */
  int cfunc_GetActiveBuildTemplate(lua_State* const luaContext)
  {
    return cfunc_GetActiveBuildTemplateL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008475E0 (FUN_008475E0, cfunc_SetActiveBuildTemplateL)
   *
   * What it does:
   * Parses one Lua build-template table `{xSpan, zSpan, {bpId, buildOrder, x, z}...}`,
   * assembles the entries into a build-template buffer, and installs it as the
   * active world-session build template together with its X/Z spans (only when at
   * least one valid entry was parsed). Malformed template/entry tables are reported
   * via gpg::Warnf and skipped.
   */
  int cfunc_SetActiveBuildTemplateL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSetActiveBuildTemplateHelpText, 1, argumentCount);
    }

    CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr) {
      return 0;
    }

    const LuaPlus::LuaObject buildTemplate(LuaPlus::LuaStackObject(state, 1));
    if (!buildTemplate.IsTable() || buildTemplate.GetCount() < 3) {
      gpg::Warnf("Build template error! Not a table or insufficient members");
      return 0;
    }

    gpg::fastvector_n<SBuildTemplateInfo, 16> templates;

    const float templateSpanX = static_cast<float>(buildTemplate[1].GetNumber());
    const float templateSpanZ = static_cast<float>(buildTemplate[2].GetNumber());

    const int entryCount = buildTemplate.GetCount();
    for (int entryIndex = 3; entryIndex <= entryCount; ++entryIndex) {
      const LuaPlus::LuaObject entryObject = buildTemplate[entryIndex];
      if (!entryObject.IsTable() || entryObject.GetCount() < 4) {
        gpg::Warnf("Template info error! Not a table or insufficient members");
        continue;
      }

      SBuildTemplateInfo info{};
      info.mBlueprintId = entryObject[1].GetString();
      info.mBuildOrder = entryObject[2].GetInteger();
      info.mPos.x = static_cast<float>(entryObject[3].GetNumber());
      info.mPos.z = static_cast<float>(entryObject[4].GetNumber());
      info.mPos.y = 0.0f;

      templates.PushBack(info);
    }

    if (!templates.Empty()) {
      session->SetActiveBuildTemplate(templates, templateSpanX, templateSpanZ);
    }

    // `templates` releases its entries and any spilled heap storage in its
    // own destructor at scope exit; no hand-rolled teardown needed here.
    return 0;
  }

  /**
   * Address: 0x00847560 (FUN_00847560, cfunc_SetActiveBuildTemplate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_SetActiveBuildTemplateL`.
   */
  int cfunc_SetActiveBuildTemplate(lua_State* const luaContext)
  {
    return cfunc_SetActiveBuildTemplateL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00848050 (FUN_00848050, cfunc_OpenURLL)
   *
   * What it does:
   * Validates a requested URL through wxURL, permits only configured protocol
   * names, and opens an allowed URL through the Windows shell.
   */
  int cfunc_OpenURLL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kOpenURLHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaStackObject urlArgument(state, 1);
    const char* const urlText = lua_tostring(rawState, 1);
    if (urlText == nullptr) {
      urlArgument.TypeError("string");
    }

    const std::wstring wideUrl = gpg::STR_Utf8ToWide(urlText);
    OpenAllowedUrlByWx(wideUrl);
    return 0;
  }

  /**
   * Address: 0x00847FD0 (FUN_00847FD0, cfunc_OpenURL)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_OpenURLL`.
   */
  int cfunc_OpenURL(lua_State* const luaContext)
  {
    return cfunc_OpenURLL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0084DC80 (FUN_0084DC80, cfunc_SetCursor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_SetCursorL`.
   */
  int cfunc_SetCursor(lua_State* const luaContext)
  {
    return cfunc_SetCursorL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0084DD00 (FUN_0084DD00, cfunc_SetCursorL)
   *
   * What it does:
   * Decodes one optional cursor userdata (or nil) and updates the global UI
   * manager cursor binding.
   */
  int cfunc_SetCursorL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetCursorHelpText, 1, argumentCount);
    }

    CMauiCursor* cursor = nullptr;
    if (lua_type(state->m_state, 1) != LUA_TNIL) {
      const LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
      cursor = SCR_FromLua_CMauiCursor(cursorObject, state);
    }

    if (IUIManager* const uiManager = UI_GetManager(); uiManager != nullptr) {
      uiManager->SetCursor(cursor);
    }

    return 0;
  }

} // namespace moho


namespace
{
  /**
   * Engine addition (dedicated-server plan WPL.4): drives this file's Lua binder
   * definitions, the calls CCommandLuaFunctionRegistrations.cpp's two bootstraps made for them,
   * in the same order (register_ thunks first, as there).
   */
  struct UserCommandLuaFuncDefBootstrap
  {
    UserCommandLuaFuncDefBootstrap()
    {
      (void)::moho::register_UISelectionByCategory_LuaFuncDef();
      (void)::moho::register_UISelectAndZoomTo_LuaFuncDef();
      (void)::moho::register_UIZoomTo_LuaFuncDef();
      (void)::moho::func_DecreaseBuildCountInQueue_LuaFuncDef();
      (void)::moho::func_IncreaseBuildCountInQueue_LuaFuncDef();
      (void)::moho::func_GetUnitCommandData_LuaFuncDef();
      (void)::moho::func_IssueDockCommand_LuaFuncDef();
      (void)::moho::func_IssueCommand_LuaFuncDef();
      (void)::moho::func_IssueUnitCommand_LuaFuncDef();
      (void)::moho::func_IssueBlueprintCommand_LuaFuncDef();
      (void)::moho::func_GetRolloverInfo_LuaFuncDef();
      (void)::moho::func_UISelectionByCategory_LuaFuncDef();
      (void)::moho::func_UISelectAndZoomTo_LuaFuncDef();
      (void)::moho::func_UIZoomTo_LuaFuncDef();
      (void)::moho::func_SetOverlayFilter_LuaFuncDef();
      (void)::moho::func_GetActiveBuildTemplate_LuaFuncDef();
      (void)::moho::func_SetActiveBuildTemplate_LuaFuncDef();
      (void)::moho::func_OpenURL_LuaFuncDef();
      (void)::moho::func_SetCursor_LuaFuncDef();
    }
  };

  const UserCommandLuaFuncDefBootstrap gUserCommandLuaFuncDefBootstrap{};
} // namespace
