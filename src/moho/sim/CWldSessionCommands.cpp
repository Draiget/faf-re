#include "moho/sim/CWldSessionPrivate.h"

namespace moho
{
namespace
{

    /// `SCommandModeData::mModifiers` bit lanes, unpacked in one block at
    /// 0x0081FD00-0x0081FD24 before the mode switch runs.
    enum ECommandModeModifier : std::int32_t
    {
      /// Append to the existing command queue instead of replacing it.
      COMMODMOD_Queue = 0x1,
      /// Force the formation ("form") variant of the issued command.
      COMMODMOD_Formation = 0x2,
      /// Turn a plain move order into an aggressive-move order.
      COMMODMOD_AttackMove = 0x4,
    };
}
}

namespace moho
{
  // Address lanes:
  // - 0x010A645D (`ui_DebugAltClick`)
  // - 0x010A645E (`UI_SelectAnything`)
  // Recovered as process-global convar-backed toggles used by selection paths.
  bool ui_DebugAltClick = false;
namespace
{

    /**
     * Address: 0x0081FD2B..0x0081FD4E (inlined into
     * `Moho::SCommandModeData::HandleEvent`, FUN_0081FCD0)
     *
     * What it does:
     * Resolves the entity a command-mode drag snapshot is hovering.
     * `MouseInfo::mUnitHover` is an intrusive weak-link slot rather than a
     * live pointer (the same lane `CWldSession::GetHoveredUserEntity` decodes
     * for the session's own cursor), and an entity the session has already
     * orphaned (`mMarkedForDeletion`) counts as "nothing hovered".
     */
    [[nodiscard]] UserEntity* DecodeHoveredDragEntity(const MouseInfo& cursor) noexcept
    {
      UserEntity* const entity = cursor.HoveredEntity();
      if (entity == nullptr || entity->mMarkedForDeletion != 0u) {
        return nullptr;
      }
      return entity;
    }

    void RemoveUnitIfPresent(fa::vector<UserUnit*>& units, const UserUnit* const unit)
    {
      fa::vector<UserUnit*> filteredUnits{};
      filteredUnits.reserve(units.size());
      for (UserUnit* const candidate : units) {
        if (candidate != unit) {
          filteredUnits.push_back(candidate);
        }
      }
      units = filteredUnits;
    }

    /**
     * Address: 0x0081D160 (FUN_0081D160)
     *
     * What it does:
     * Returns true when at least one live entity in the current selection is in
     * the `TELEPORTATION` category.
     */
    [[nodiscard]] bool SelectionContainsTeleportationUnit(WeakSet<UserEntity>& selection)
    {
      fa::string teleportationCategory("TELEPORTATION");
      for (UserEntity* const entity : selection) {
        if (entity != nullptr && entity->IsInCategory(teleportationCategory)) {
          return true;
        }
      }

      return false;
    }

    /**
     * Address: 0x0081DB40 (FUN_0081DB40, func_CoordinatedAttack)
     *
     * What it does:
     * Returns true when the dragged command is an attack/form-attack command
     * and no live selected user-unit already has that command helper queued.
     *
     * Invocation: sole caller in the binary is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, 2167 instructions, owned by this file), from the
     * `RULEUCC_Attack` hovered-target arm at 0x0081FEBD - recovered below and
     * calling this by name.
     */
    [[nodiscard]] bool CanStartCoordinatedAttack(CWldSession& session, const CmdId commandId)
    {
      UserCommandIssueHelper* const helper = FindCommandIssueHelperInSession(&session, commandId);
      if (helper == nullptr) {
        return false;
      }

      const EUnitCommandType commandType = ResolveCommandIssueHelperCommandType(*helper);
      if (commandType != EUnitCommandType::UNITCOMMAND_Attack &&
          commandType != EUnitCommandType::UNITCOMMAND_FormAttack) {
        return false;
      }

      WeakSet<UserEntity>& selection = session.mSelection;
      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);
        if (userUnit != nullptr && iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
          UserCommandQueue* const manager = userUnit->GetCommandQueue();
          if (UserUnitManagerContainsCommandIssueHelper(manager, helper)) {
            return false;
          }
        }
      }

      return true;
    }

    /**
     * Address: 0x0081DD00 (FUN_0081DD00)
     *
     * IDA signature:
     * char __cdecl sub_81DD00(Moho::WeakSet_UserEntity *a1, struct_CommandIssueHelper *a2);
     *
     * What it does:
     * Tests whether a just-issued Move/FormMove drag command (`helper`) may
     * be silently restarted in place as Patrol/FormPatrol instead of being
     * queued as a brand-new order. Returns false when `helper` is null, the
     * selection is empty, or `helper`'s resolved command type is neither
     * Move nor FormMove. Otherwise walks the live selection: any live,
     * non-dead, non-destroy-queued `UserUnit` with a command queue that is
     * in the "POD" category vetoes the restart outright. For every such
     * unit whose queue already contains `helper` at a position other than
     * the last entry (queue depth over 1 and `helper` is not the tail),
     * every queued command in that unit's whole resolved queue must
     * resolve to `helper`'s own command type, or the restart is rejected;
     * units whose queue doesn't meet that depth/position/membership gate
     * are simply skipped. Returns true once every live selected entity has
     * been scanned without a rejection.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, 2167 instructions, owned by this file), from the
     * drag-move patrol-restart arm (0x008207E6) - on success the caller
     * skips issuing a new command and instead calls
     * `RestartMoveCommandAsPatrol` below with the same selection and helper.
     * `HandleEvent` is recovered below and calls this by name.
     */
    [[nodiscard]] bool CanRestartMoveCommandAsPatrol(
      WeakSet<UserEntity>& selection,
      UserCommandIssueHelper* const helper
    )
    {
      if (helper == nullptr) {
        return false;
      }


      const EUnitCommandType commandType = ResolveCommandIssueHelperCommandType(*helper);
      if (selection.Empty() ||
          (commandType != EUnitCommandType::UNITCOMMAND_Move &&
           commandType != EUnitCommandType::UNITCOMMAND_FormMove)) {
        return false;
      }

      const fa::string podCategory("POD");

      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);

        if (userUnit != nullptr && iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
          UserCommandQueue* const manager = userUnit->GetCommandQueue();
          if (manager != nullptr) {
            if (userUnit->IsInCategory(podCategory)) {
              return false;
            }

            if (GetUserUnitManagerQueueSize(manager) <= 1
                || GetUserUnitManagerQueueTailHelperRaw(manager) == helper
                || !UserUnitManagerContainsCommandIssueHelper(manager, helper)) {
              return false;
            }

            if (!UserUnitManagerQueueHasUniformCommandType(manager, commandType)) {
              return false;
            }
          }
        }
      }

      return true;
    }

    /**
     * Address: 0x0081DEF0 (FUN_0081DEF0)
     *
     * IDA signature:
     * std::map *__usercall sub_81DEF0@<eax>(Moho::WeakSet_UserEntity *ebx0@<ebx>, struct_CommandIssueHelper *a2);
     *
     * What it does:
     * Companion to `CanRestartMoveCommandAsPatrol`, invoked only once that
     * gate has confirmed the restart is safe. Resolves `helper`'s own
     * command type (Move -> Patrol, FormMove -> FormPatrol) then walks
     * every live selected entity's command queue via
     * `RestartQueuedCommandsFromHelper`, which reissues every queue entry
     * from `helper` onward (inclusive) that still shares its original
     * command type.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x008207F7), called with the same weak
     * selection set still live in a register from the
     * `CanRestartMoveCommandAsPatrol` call immediately before it.
     */
    void RestartMoveCommandAsPatrol(WeakSet<UserEntity>& selection, UserCommandIssueHelper* const helper)
    {
      const EUnitCommandType originalCommandType = ResolveCommandIssueHelperCommandType(*helper);
      const EUnitCommandType restartCommandType =
        (originalCommandType == EUnitCommandType::UNITCOMMAND_Move)
          ? EUnitCommandType::UNITCOMMAND_Patrol
          : EUnitCommandType::UNITCOMMAND_FormPatrol;

      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);

        if (userUnit != nullptr && iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
          if (UserCommandQueue* const manager = userUnit->GetCommandQueue(); manager != nullptr) {
            RestartQueuedCommandsFromHelper(manager, helper, originalCommandType, restartCommandType);
          }
        }
      }
    }

    /**
     * Address: 0x0081E050 (FUN_0081E050)
     *
     * IDA signature:
     * char __cdecl sub_81E050(Moho::WeakSet_UserEntity *arg0, float *a2, char a3);
     *
     * What it does:
     * Scans the live selection for eligible `UserUnit`s (`IsUserUnit`, has a
     * command queue, not dead, not destroy-queued), accumulating their live
     * `IUnit::GetPosition()` into `outAnchor` for a running average. Unless
     * `skipPatrolCheck` is set, also inspects each eligible unit's
     * most-recently-queued command helper - taken from its factory command
     * queue when the unit is immobile (`IUnit::IsMobile()` false), otherwise
     * its regular command queue - and returns true immediately the moment
     * that command resolves to Patrol/FormPatrol (the caller then reissues
     * the drag command as-is, using the existing target, with no new
     * anchor). Otherwise, when that command's own command-graph anchor
     * position (`ResolveCommandGraphAnchorWorldPosition`, 0x0081CFD0)
     * resolves to a valid (non-NaN) position, `outAnchor` is overwritten
     * with it (last live match wins). After the scan: if `outAnchor` ended
     * up anything other than the zero vector (an anchor override was
     * found), it is kept as-is; otherwise `outAnchor` is replaced by the
     * running position average. Returns false on both of those paths - only
     * the early Patrol/FormPatrol detection returns true.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below), called twice from the `RULEUCC_Patrol`
     * arm (0x00820BD7 and 0x00820CED): once for the plain-selection drag and
     * once for the paired rally-point `ISSUE_FactoryCommand` drag, each time
     * immediately followed by `Moho::STIMap::GetSurface` snapping `outAnchor`
     * to the terrain when this returns false.
     */
    [[nodiscard]] bool ResolveGroupMoveAnchorOrDetectPatrol(
      WeakSet<UserEntity>& selection,
      Wm3::Vector3f& outAnchor,
      const bool skipPatrolCheck
    )
    {
      outAnchor = Wm3::Vector3f::Zero();


      std::int32_t eligibleCount = 0;
      Wm3::Vector3f anchorOverride = Wm3::Vector3f::Zero();

      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          if (UserCommandQueue* const manager = userUnit->GetCommandQueue(); manager != nullptr) {
            IUnit* const iunit = GetIUnitBridge(userUnit);
            if (iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
              ++eligibleCount;
              const Wm3::Vec3f& position = iunit->GetPosition();
              outAnchor.x += position.x;
              outAnchor.y += position.y;
              outAnchor.z += position.z;

              if (!skipPatrolCheck) {
                UserCommandIssueHelper* lastHelper = GetUserUnitManagerLastQueuedHelper(manager);
                if (!iunit->IsMobile()) {
                  if (UserCommandQueue* const factoryManager = userUnit->GetFactoryCommandQueue();
                      factoryManager != nullptr) {
                    lastHelper = GetUserUnitManagerLastQueuedHelper(factoryManager);
                  }
                }

                if (lastHelper != nullptr) {
                  const EUnitCommandType lastCommandType = ResolveCommandIssueHelperCommandType(*lastHelper);
                  if (lastCommandType == EUnitCommandType::UNITCOMMAND_Patrol ||
                      lastCommandType == EUnitCommandType::UNITCOMMAND_FormPatrol) {
                    return true;
                  }

                  if (const Wm3::Vector3f resolvedAnchor = ResolveCommandGraphAnchorWorldPosition(*lastHelper);
                      IsValidVector3f(resolvedAnchor)) {
                    anchorOverride = resolvedAnchor;
                  }
                }
              }
            }
          }
        }
      }

      if (const Wm3::Vector3f zero = Wm3::Vector3f::Zero(); anchorOverride != zero) {
        outAnchor = anchorOverride;
        return false;
      }

      if (eligibleCount > 0) {
        const float invCount = 1.0f / static_cast<float>(eligibleCount);
        outAnchor.x *= invCount;
        outAnchor.y *= invCount;
        outAnchor.z *= invCount;
      }

      return false;
    }

    /**
     * Address: 0x0081E2E0 (FUN_0081E2E0)
     *
     * IDA signature:
     * char __cdecl sub_81E2E0(Moho::WeakSet_UserEntity *a1, float *a2);
     *
     * What it does:
     * Ferry-command sibling of `ResolveGroupMoveAnchorOrDetectPatrol`.
     * Scans the live selection for eligible `UserUnit`s (`IsUserUnit`, has
     * a command queue, not dead, not destroy-queued). For each: resolves
     * its most-recently-queued command helper; when one exists, accumulates
     * that command's own command-graph anchor position
     * (`ResolveCommandGraphAnchorWorldPosition`) into `outAnchor` and clears
     * the "all still ferrying" flag unless that command is itself
     * `UNITCOMMAND_Ferry`; when none exists, accumulates the unit's live
     * `IUnit::GetPosition()` instead and always clears the flag. After the
     * scan, `outAnchor` is divided by the eligible-unit count (left
     * untouched when there were none). Returns true when every eligible
     * unit's queued command was already `UNITCOMMAND_Ferry` (including the
     * vacuous case of no eligible units at all - the caller then reissues
     * the ferry command as-is), false otherwise (`outAnchor` now holds the
     * averaged anchor/position for the caller to snap to the terrain
     * surface).
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x008216BD), from the `RULEUCC_Ferry`
     * command-capability arm.
     */
    [[nodiscard]] bool ResolveGroupFerryAnchorOrDetectFerry(
      WeakSet<UserEntity>& selection,
      Wm3::Vector3f& outAnchor
    )
    {

      std::int32_t eligibleCount = 0;
      bool allFerrying = true;

      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          if (UserCommandQueue* const manager = userUnit->GetCommandQueue(); manager != nullptr) {
            IUnit* const iunit = GetIUnitBridge(userUnit);
            if (iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
              ++eligibleCount;

              UserCommandIssueHelper* const lastHelper = GetUserUnitManagerLastQueuedHelper(manager);
              if (lastHelper != nullptr) {
                const Wm3::Vector3f anchor = ResolveCommandGraphAnchorWorldPosition(*lastHelper);
                outAnchor.x += anchor.x;
                outAnchor.y += anchor.y;
                outAnchor.z += anchor.z;

                if (ResolveCommandIssueHelperCommandType(*lastHelper) != EUnitCommandType::UNITCOMMAND_Ferry) {
                  allFerrying = false;
                }
              } else {
                const Wm3::Vec3f& position = iunit->GetPosition();
                outAnchor.x += position.x;
                outAnchor.y += position.y;
                outAnchor.z += position.z;
                allFerrying = false;
              }
            }
          }
        }
      }

      if (eligibleCount > 0) {
        const float invCount = 1.0f / static_cast<float>(eligibleCount);
        outAnchor.x *= invCount;
        outAnchor.y *= invCount;
        outAnchor.z *= invCount;
      }

      return allFerrying;
    }

    /**
     * Address: 0x0081E4E0 (FUN_0081E4E0)
     *
     * IDA signature:
     * int __usercall sub_81E4E0@<eax>(Moho::WeakSet_UserEntity *eax0@<eax>, Wm3::Vector3f a2, int a3);
     *
     * What it does:
     * Returns the already-queued command-issue helper (if any) whose
     * blueprint pointer exactly matches `candidateBlueprint` AND whose own
     * command-graph anchor world position snaps to the same footprint cell
     * as `dragPosition` - i.e. detects "about to queue a second build order
     * for the same structure at the same spot". Only runs when the
     * selection holds exactly one live, eligible `UserUnit` (`IsUserUnit`,
     * has a command queue, not dead, not destroy-queued); returns null for
     * every other case, including a selection with zero or more than one
     * entity.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x00821E8A), from the
     * `COMMOD_Build`/`COMMOD_BuildAnchored` arm: when the drag position is
     * not a legal build spot, the existing colocated order is decremented
     * (`ISSUE_DecreaseCommandCount`) instead of a duplicate being stacked.
     */
    [[nodiscard]] UserCommandIssueHelper* FindColocatedQueuedBuildOrder(
      WeakSet<UserEntity>& selection,
      const Wm3::Vector3f& dragPosition,
      const REntityBlueprint* const candidateBlueprint
    )
    {
      if (selection.Size() != 1) {
        return nullptr;
      }

      UserEntity* const entity = *selection.begin();
      UserUnit* const userUnit = entity->IsUserUnit();
      if (userUnit == nullptr) {
        return nullptr;
      }

      UserCommandQueue* const manager = userUnit->GetCommandQueue();
      if (manager == nullptr) {
        return nullptr;
      }

      IUnit* const iunit = GetIUnitBridge(userUnit);
      if (iunit == nullptr || iunit->IsDead() || iunit->DestroyQueued()) {
        return nullptr;
      }

      return FindColocatedQueuedBuildOrderInManager(manager, dragPosition, candidateBlueprint);
    }

    /**
     * Address: 0x0081E610 (FUN_0081E610)
     *
     * IDA signature:
     * std::map_uint_WeakPtr_UserEntity::_Node *__usercall sub_81E610@<eax>(
     *     int a1@<eax>, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3, Moho::WeakSet_UserEntity *a4);
     *
     * What it does:
     * Splits the live entities of `source` into `rallyPointSet` (entities
     * in the "RALLYPOINT" category) and `otherSet` (everything else). The
     * binary inlines the same category-bitset test
     * `Moho::UserEntity::IsInCategory` (0x008B97C0) already performs -
     * verified field-for-field against that recovered body - so this calls
     * it directly per entity rather than re-inlining the raw bitset index
     * math. `a1` (the binary's category-lookup-resolver source) is not a
     * separate parameter here: `IsInCategory` resolves it from the
     * entity's own `mSession`, which is always the same session this
     * selection belongs to. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below), called three times - from the
     * `RULEUCC_Move` (0x0082069A), `RULEUCC_Patrol` (0x0082095E) and
     * `RULEUCC_CallTransport` (0x00820F49) arms - to split the current
     * selection ahead of a rally-point-aware factory command.
     */
    void SplitSelectionByRallyPointCategory(
      WeakSet<UserEntity>& source,
      WeakSet<UserEntity>& rallyPointSet,
      WeakSet<UserEntity>& otherSet
    )
    {
      const fa::string rallyPointCategory("RALLYPOINT");


      for (UserEntity* const entity : source) {
        if (entity->IsInCategory(rallyPointCategory)) {
          (void)rallyPointSet.Add(entity);
        } else {
          (void)otherSet.Add(entity);
        }
      }
    }

    /**
     * Address: 0x0081E700 (FUN_0081E700)
     *
     * IDA signature:
     * std::map_uint_WeakPtr_UserEntity::_Node *__cdecl sub_81E700(
     *     Moho::WeakSet_UserEntity *a1, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3);
     *
     * What it does:
     * Splits the live, mobile (`IUnit::IsMobile()`), `UserUnit` entities of
     * `source` for a ferry-command drag: units in the "TRANSPORTATION"
     * category that are also "AIR" or "AIRSTAGINGPLATFORM" go into
     * `airTransportSet` (the candidate ferriers); every other mobile unit
     * that is in the "LAND" category goes into `landUnitSet` (the
     * candidate passengers). Non-mobile units, non-`UserUnit` entities, and
     * mobile units that are neither an eligible air transport nor LAND are
     * left out of both sets. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below), from the `RULEUCC_Ferry` arm
     * (0x0082162F) - `airTransportSet` becomes the selection fed into
     * `ResolveGroupFerryAnchorOrDetectFerry` immediately afterward - and from
     * the `RULEUCC_Transport` arm's no-extra-selection branch (0x008213D6).
     */
    void SplitSelectionForFerryCommand(
      WeakSet<UserEntity>& source,
      WeakSet<UserEntity>& airTransportSet,
      WeakSet<UserEntity>& landUnitSet
    )
    {
      const fa::string transportationCategory("TRANSPORTATION");
      const fa::string airCategory("AIR");
      const fa::string airStagingCategory("AIRSTAGINGPLATFORM");
      const fa::string landCategory("LAND");

      for (UserEntity* const entity : source) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);

        if (userUnit != nullptr && iunit != nullptr && iunit->IsMobile()) {
          const bool isAirTransport = entity->IsInCategory(transportationCategory) &&
            (entity->IsInCategory(airCategory) || entity->IsInCategory(airStagingCategory));

          if (isAirTransport) {
            (void)airTransportSet.Add(entity);
          } else if (entity->IsInCategory(landCategory)) {
            (void)landUnitSet.Add(entity);
          }
        }
      }
    }

    /**
     * Address: 0x0081E9E0 (FUN_0081E9E0)
     *
     * IDA signature:
     * std::map_uint_WeakPtr_UserEntity::_Node *__cdecl sub_81E9E0(
     *     Moho::WeakSet_UserEntity *a1, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3);
     *
     * What it does:
     * Splits the live `UserUnit` entities of `source` by the "REBUILDER"
     * category: units in that category go into `rebuilderSet`, every other
     * `UserUnit` goes into `nonRebuilderSet`. Non-`UserUnit` entities are
     * left out of both sets. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x00820222), splitting the selection
     * ahead of issuing a guard-style command at a hovered "STRUCTURE"
     * target - `nonRebuilderSet` is issued the command immediately after
     * with the hovered entity as its direct target, `rebuilderSet` gets the
     * same command aimed at the structure's world position instead.
     */
    void SplitSelectionByRebuilderCategory(
      WeakSet<UserEntity>& source,
      WeakSet<UserEntity>& nonRebuilderSet,
      WeakSet<UserEntity>& rebuilderSet
    )
    {
      const fa::string rebuilderCategory("REBUILDER");

      for (UserEntity* const entity : source) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          if (userUnit->IsInCategory(rebuilderCategory)) {
            (void)rebuilderSet.Add(entity);
          } else {
            (void)nonRebuilderSet.Add(entity);
          }
        }
      }
    }

    /**
     * Address: 0x0081EB20 (FUN_0081EB20)
     *
     * IDA signature:
     * _Iterator_base **__usercall sub_81EB20@<eax>(
     *     Moho::WeakSet_UserEntity *a1@<ebx>, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3);
     *
     * What it does:
     * Splits the live `UserUnit` entities of `source` for an attack-move-
     * to-ground drag: units that are both mobile (`IUnit::IsMobile()`) and
     * set to `FIRESTATE_ReturnFire` go into `aggressiveMoveSet` (eligible
     * for AggressiveMove); every other live `UserUnit` (immobile, or on a
     * different fire state) goes into `otherSet`. Non-`UserUnit` entities
     * are left out of both sets. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x0081FF48), from the `RULEUCC_Attack`
     * no-hover ground-target arm: `aggressiveMoveSet` is issued
     * `UNITCOMMAND_AggressiveMove` immediately afterward when non-empty.
     */
    void SplitSelectionForAggressiveMove(
      WeakSet<UserEntity>& source,
      WeakSet<UserEntity>& aggressiveMoveSet,
      WeakSet<UserEntity>& otherSet
    )
    {
      for (UserEntity* const entity : source) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          IUnit* const iunit = GetIUnitBridge(userUnit);
          const bool eligible = iunit != nullptr && iunit->IsMobile() &&
            userUnit->mUnitVarDat.mFireState == FIRESTATE_ReturnFire;

          if (eligible) {
            (void)aggressiveMoveSet.Add(entity);
          } else {
            (void)otherSet.Add(entity);
          }
        }
      }
    }

    /**
     * Address: 0x008B4300 (FUN_008B4300, sub_8B4300)
     *
     * What it does:
     * Whether `candidateUnit` belongs to the helper's command, reading the
     * unconfirmed local edits first: walking `mLocalQueue` from the back, the
     * newest `SelectUnit` edit that lists the unit answers `true` and the
     * newest `DeselectUnit` edit that lists it answers `false`
     * (0x008B4346..0x008B439D). With no such edit it answers whether the unit's
     * entity id is in the replicated `mVariableData.mEntIds` (0x008B43B7..).
     *
     * The per-event lookup is `WeakSet<UserUnit>::find(candidateUnit)` over the
     * event's `mUnits` (`WeakSet<UserUnit>::Find`, 0x0082CEA0, which takes the
     * unit in `eax` from the second stack argument at 0x008B4363/0x008B438D and
     * runs the set's `find` 0x0082E560 on it). It used to be keyed with the dword at
     * `helper+0xB8` instead -- the local queue's own first word, read through
     * a padded view -- so no local select/deselect edit ever matched and every
     * answer came from the replicated id list.
     *
     */
    [[nodiscard]] bool IsCandidateExcludedByCachedRelation(
      const UserCommandIssueHelper& helper, UserUnit* const candidateUnit
    ) noexcept
    {
      for (std::size_t index = helper.mLocalQueue.size(); index != 0u; --index) {
        const UserCommandIssueLocalEvent& event = helper.mLocalQueue[index - 1u];
        if (event.mType != ECommandIssueEvent::SelectUnit && event.mType != ECommandIssueEvent::DeselectUnit) {
          continue;
        }

        // 0x008B4370/0x008B439A: the binary runs this lookup twice for a
        // `SelectUnit` edit (an early "listed" exit, then the shared gate);
        // nothing observable happens in between, so it is computed once.
        const bool listed = event.mUnits.Find(candidateUnit) != event.mUnits.end();
        if (!listed) {
          continue;
        }
        return event.mType == ECommandIssueEvent::SelectUnit;
      }

      for (const EntId entityId : helper.mVariableData.mEntIds) {
        if (static_cast<std::uint32_t>(entityId) == candidateUnit->mParams.mEntityId) {
          return true;
        }
      }
      return false;
    }
}


  /**
   * Address: 0x00829B40 (FUN_00829B40, func_ProcessCommandDrag)
     *
     * What it does:
     * The click-and-drag command redirect keystone both `UICommandDragger::
     * DragMove` and `DragRelease` (UiRuntimeTypes.h/.cpp) funnel into. Looks
     * the dragged command's live helper up by id; if the mouse position is
     * invalid or the command isn't found, does nothing. Otherwise updates
     * (or creates) the command's `mMapAB0` draw-node with the current mouse
     * position (keyed by the helper's own pointer identity - see
     * `sub_82C2E0`'s asm), and, for a factory-build command
     * (`ResolveCommandIssueHelperCommandType == 8`) whose draw node was
     * already resolved, re-validates build placement via
     * `USERUNIT_CanBeBuiltAt` and updates the node's visibility flag
     * (honoring `CWldSession::mShowInvalidBuildPlacementPreview`'s
     * override). On release, unless the drag just ended over an invalid
     * build placement, dispatches the new target: when the command already
     * follows a live cached target entity
     * (`ResolveCommandTargetEntity`), searches nearby
     * collected entities for the closest live unit sharing the cached
     * target's army and not excluded by `IsCandidateExcludedByCachedRelation`,
     * and issues that entity as the new target; otherwise, for a live
     * factory-build command, snaps to the blueprint's resolved-footprint
     * world position; otherwise clamps the raw mouse position to the map's
     * playable rect and issues that as a `Position` target. All three paths
     * converge on `Moho::ISSUE_SetCommandTarget`.
     */
    void ProcessCommandDrag(
      const Wm3::Vector3f& mouse, UICommandGraph& graph, const CmdId cmdId, const bool released
    )
    {
      CommandManager* const commandManager = graph.mSession->mCommandManager;

      UserCommandIssueHelper* helper = nullptr;
      if (const auto found = commandManager->mCommands.find(cmdId); found != commandManager->mCommands.end()) {
        helper = found->second;
      }
      if (helper == nullptr) {
        return;
      }

      if (!IsValidVector3f(mouse)) {
        return;
      }

      // mMapAB0's draw-node hash is keyed by the helper's own pointer
      // identity, not its command id (0x0082C2E3: sub_82C2E0 dereferences
      // its "key" arg once via [esi]; this function's own call passes
      // &result where result held the helper pointer's raw value).

      bool suppressDispatch = false;
      if (graph.mMapAB0.count(helper) != 0) {
        UICommandGraph::UICommandGraphDrawNode* const drawNode =
          &graph.mMapAB0[helper];

        drawNode->mPositionSum = mouse;
        drawNode->mWeight = 1.0f;

        if (drawNode->mHasResolvedPosition != 0 &&
            ResolveCommandIssueHelperCommandType(*helper) == static_cast<EUnitCommandType>(8)) {
          if (const REntityBlueprint* const genericBlueprint = helper->mConstantData.blueprint;
              genericBlueprint != nullptr) {
            // 0x00829C48..0x00829C4D is a plain virtual dispatch through slot
            // 5 of the blueprint's own vtable - `REntityBlueprint::
            // IsUnitBlueprint` - not a reflection upcast.
            if (const RUnitBlueprint* const unitBlueprint = genericBlueprint->IsUnitBlueprint();
                unitBlueprint != nullptr) {
              const float inverseWeight = 1.0f / drawNode->mWeight;
              const SCoordsVec2 buildCenter{
                drawNode->mPositionSum.x * inverseWeight, drawNode->mPositionSum.z * inverseWeight
              };
              SOccupationResult buildInfo{};
              const bool canBuild = USERUNIT_CanBeBuiltAt(
                *graph.mSession, unitBlueprint, buildCenter, false, &buildInfo,
                reinterpret_cast<const UserCommand*>(helper)
              );
              drawNode->mIsVisible = (canBuild || !graph.mSession->mShowInvalidBuildPlacementPreview) ? 1u : 0u;
            }
          }
        }

        const bool wasInvalidPlacement = (drawNode->mIsVisible == 0);
        drawNode->mHasResolvedPosition = released ? 0u : 1u;
        if (wasInvalidPlacement && released) {
          suppressDispatch = true;
        }
      }

      if (!released || suppressDispatch) {
        return;
      }

      // The playable-rect clamp runs once, here, ahead of all three dispatch
      // arms - 0x00829CF4..0x00829D7D sits between the `released` gate and
      // the cached-target search, and every later read (the distance loop's
      // `var_200`/`result`, the factory arm's `ToCellPos` input, and the
      // default arm's position target) is of the clamped vector, never of the
      // raw mouse. Clamping only inside the default arm let the other two
      // arms act on an off-map cursor.
      const STIMap* const map = graph.mSession->mWldMap->mTerrainRes->mMap;
      Wm3::Vector3f clampedPos = mouse;
      clampedPos.x = std::clamp(
        clampedPos.x, static_cast<float>(map->mPlayableRect.x0 + 1), static_cast<float>(map->mPlayableRect.x1 - 1)
      );
      clampedPos.z = std::clamp(
        clampedPos.z, static_cast<float>(map->mPlayableRect.z0 + 1), static_cast<float>(map->mPlayableRect.z1 - 1)
      );

      if (UserEntity* const cachedTargetEntity = ResolveCommandTargetEntity(*helper);
          cachedTargetEntity != nullptr) {
        // Cached-target reacquire: search nearby collected entities for the
        // closest live unit sharing the cached target's army.
        gpg::fastvector<UserEntity*> candidates{};
        auto* const spatialDb = graph.mSession->GetEntitySpatialDbStorage();
        (void)spatialDb->Collect(candidates, ENTITYTYPE_Unit);

        UserEntity* closest = nullptr;
        float closestDistanceSq = gpg::pInf;
        for (UserEntity* const candidate : candidates) {
          if (candidate == nullptr || candidate->IsBeingBuilt()) {
            continue;
          }

          if (UserUnit* const candidateUnit = candidate->IsUserUnit(); candidateUnit != nullptr) {
            if (IsCandidateExcludedByCachedRelation(*helper, candidateUnit)) {
              continue;
            }
          }

          if (candidate->mArmy != cachedTargetEntity->mArmy) {
            continue;
          }

          const Wm3::Vec3f& candidatePos = candidate->mVariableData.mCurTransform.pos_;
          const float deltaX = clampedPos.x - candidatePos.x;
          const float deltaZ = clampedPos.z - candidatePos.z;
          const float distanceSq = (deltaX * deltaX) + (deltaZ * deltaZ);
          if (distanceSq < closestDistanceSq) {
            closestDistanceSq = distanceSq;
            closest = candidate;
          }
        }

        if (closest != nullptr) {
          const UserTarget entityTarget(closest);
          ISSUE_SetCommandTarget(helper, entityTarget);
        }
        return;
      }

      const REntityBlueprint* const genericBlueprint = helper->mConstantData.blueprint;
      if (ResolveCommandIssueHelperCommandType(*helper) == static_cast<EUnitCommandType>(8) &&
          genericBlueprint != nullptr) {
        // Factory-build command: re-snap the dropped cursor onto the
        // blueprint's own footprint grid.
        //
        // 0x00829F0D..0x00829F40 copies the sixteen bytes at
        // `REntityBlueprint+0xD8` - the blueprint's inline `mFootprint` - into
        // a stack `SFootprint`; there is no reflection upcast and no
        // `Physics.ResolvedFootprint` indirection anywhere in this arm. The
        // upcast-and-deref version this replaces dropped the whole drag
        // silently whenever either step yielded null, so a queued building
        // could not be moved at all.
        const SFootprint& footprint = genericBlueprint->mFootprint;
        const SOCellPos cell = footprint.ToCellPos(clampedPos);

        // 0x00829F5E calls the `(STIMap const*, SOCellPos const&, SFootprint
        // const&)` overload, which re-centres the origin cell over the *full*
        // footprint (`cell + size/2`). Passing `1, 1` instead re-centred every
        // structure as if it were one cell across, displacing the re-issued
        // build position by `((1 - sizeX) / 2, (1 - sizeZ) / 2)` - i.e. toward
        // -X/-Z, up and to the left on screen, by a whole cell for a 3-cell
        // footprint - so the dropped order and its green placement ghost
        // landed off the structure they belonged to.
        const Wm3::Vector3f worldPos = COORDS_ToWorldPos(map, cell, footprint);

        UserTarget positionTarget{};
        positionTarget.targetType = UserTargetType::Position;
        positionTarget.position = worldPos;
        ISSUE_SetCommandTarget(helper, positionTarget);
        return;
      }

      // Default: issue the clamped cursor position as a `Position` target.
      UserTarget positionTarget{};
      positionTarget.targetType = UserTargetType::Position;
      positionTarget.position = clampedPos;
      ISSUE_SetCommandTarget(helper, positionTarget);
    }
namespace
{

    [[nodiscard]] ECommandMode DefaultModeFromDrag(const std::int32_t dragWord) noexcept
    {
      const std::uint32_t dragMask = static_cast<std::uint32_t>(dragWord) & 0xFF000000u;
      return (dragMask != 0xFF000000u) ? COMMOD_Reclaim : COMMOD_Move;
    }

    // ===================================================================
    // Right-mouse-button command resolution helpers (FUN_0081EC00 family)
    // ===================================================================
    //
    // These file-static helpers back the global right-click dispatcher
    // `func_GetRightMouseButtonAction` (FUN_0081EC00). They are only ever
    // called from that dispatcher inside this translation unit, so they stay
    // in this anonymous namespace next to the selection-iteration helpers they
    // reuse (DecodeSelectedUserEntity / ResolveIUnitBridge / IsSentinelNode).

    // The pending command the cursor drags is looked up through the session
    // command manager's own `mCommands` map (`CommandManager::mCommands`,
    // +0xCB4) with `FindCommandIssueHelper` below, and its type is read
    // through `ResolveCommandIssueHelperCommandType` -- see the no-hover arm
    // of `func_GetRightMouseButtonAction`.

    /// Engine addition: one entity category named once for a whole selection walk. `Contains`
    /// answers exactly what `UserEntity::IsInCategory(name)` answers, but resolves the name only
    /// when the entity's resolver differs from the last one, instead of building a string and
    /// looking the name up for every selected unit.
    class CNamedCategory
    {
    public:
      explicit CNamedCategory(const char* const name) noexcept
        : mName(name)
      {}

      [[nodiscard]] bool Contains(const UserEntity& entity) const
      {
        if (entity.mSession == nullptr || entity.mParams.mBlueprint == nullptr) {
          return false;
        }
        const EntityCategoryLookupResolver* const resolver = entity.mSession->GetCategoryLookupResolver();
        if (resolver == nullptr) {
          return false;
        }
        if (resolver != mResolver) {
          mResolver = resolver;
          mCategory = resolver->GetEntityCategory(mName);
        }
        if (mCategory == nullptr) {
          return false;
        }
        const std::uint32_t categoryBitIndex = entity.mParams.mBlueprint->mCategoryBitIndex;
        const auto wordIt = mCategory->FindWord(categoryBitIndex >> 5u);
        return wordIt != mCategory->WordEnd() && ((*wordIt >> (categoryBitIndex & 0x1Fu)) & 1u) != 0u;
      }

    private:
      const char* mName;
      mutable const EntityCategoryLookupResolver* mResolver = nullptr;
      mutable const EntityCategorySet* mCategory = nullptr;
    };

    /**
     * Address: 0x0081D080 (FUN_0081D080, sub_81D080)
     *
     * IDA signature:
     * char __cdecl sub_81D080(Moho::UserEntity *a1, Moho::CWldSession *a2);
     *
     * What it does:
     * Returns true when the hovered target `hoverEntity` is a live, non-destroy-
     * queued entity that at least one currently selected unit can attack (range-
     * checked). Backs the enemy-hover Attack decision in the right-click
     * dispatcher.
     */
    [[nodiscard]] bool AnySelectedUnitCanAttackHover(UserEntity* const hoverEntity, CWldSession* const session)
    {
      if (hoverEntity == nullptr) {
        return false;
      }
      if (hoverEntity->mVariableData.mIsDead != 0u) {
        return false;
      }

      if (UserUnit* const hoverUnit = hoverEntity->IsUserUnit(); hoverUnit != nullptr) {
        IUnit* const hoverBridge = GetIUnitBridge(hoverUnit);
        if (hoverBridge != nullptr && hoverBridge->DestroyQueued()) { // IUnit subobject slot +0x2C
          return false;
        }
      }

      WeakSet<UserEntity>& selection = session->mSelection;
      for (UserEntity* const selectedEntity : selection) {
        if (UserUnit* const selectedUnit = selectedEntity->IsUserUnit(); selectedUnit != nullptr) {
          if (selectedUnit->CanAttackTarget(hoverEntity, true)) {
            return true;
          }
        }
      }

      return false;
    }

    /**
     * Address: 0x0081D280 (FUN_0081D280, func_RightClickWithTransport)
     *
     * IDA signature:
     * char __cdecl func_RightClickWithTransport(Moho::WeakSet_UserEntity *a1, Moho::UserUnit *arg4);
     *
     * What it does:
     * Scans the current selection for any live transporter that may pick up or
     * interact with the hovered entity `hoverEntity`, honoring the transport-
     * eligibility category rules (CANTRANSPORTCOMMANDER / FERRYBEACON / COMMAND
     * / TRANSPORTATION / TELEPORTATION / AIRSTAGINGPLATFORM / CANNOTUSEAIRSTAGING).
     * Returns true on the first eligible transporter. `arg4` is declared
     * `UserUnit*` by the decompiler but only ever used through UserEntity
     * members, so the recovered parameter is typed as the base `UserEntity*`.
     */
    [[nodiscard]] bool SelectionHasTransportForTarget(WeakSet<UserEntity>* const selection, UserEntity* const hoverEntity)
    {
      if (hoverEntity == nullptr) {
        return false;
      }
      if (hoverEntity->mVariableData.mIsDead != 0u) {
        return false;
      }
      if (hoverEntity->mVariableData.mLayerMask == static_cast<std::uint32_t>(LAYER_Seabed)) {
        return false;
      }
      if (hoverEntity->IsBeingBuilt()) { // arg4 vtable slot +0x34
        return false;
      }

      // The binary re-tests the hovered entity's categories for every selected unit; they
      // cannot change during the walk, so they are tested once here (engine change: with
      // thousands of units selected this ran every frame and dominated the frame).
      //
      // Group 1: CANTRANSPORTCOMMANDER(hover) or FERRYBEACON(hover) -> never a skip;
      // otherwise skip iff the selected unit IS the commander, because a transport not
      // flagged CANTRANSPORTCOMMANDER cannot carry it. The binary spells this as
      //   if (IsInCategory(hover,"CANTRANSPORTCOMMANDER")) goto accept;
      //   if (IsInCategory(hover,"FERRYBEACON")
      //       || (skip = 1, !IsInCategory(selected,"COMMAND"))) { accept: skip = 0; }
      // so `skip` survives as 1 only when the selected unit IS COMMAND.
      const bool hoverTakesCommander = hoverEntity->IsInCategory(fa::string("CANTRANSPORTCOMMANDER")) ||
                                       hoverEntity->IsInCategory(fa::string("FERRYBEACON"));
      // Group 2: does the hovered entity want air transport?
      const bool wantsAir = hoverEntity->IsInCategory(fa::string("TRANSPORTATION")) ||
                            hoverEntity->IsInCategory(fa::string("TELEPORTATION")) ||
                            hoverEntity->IsInCategory(fa::string("FERRYBEACON"));
      if (!wantsAir && !hoverEntity->IsInCategory(fa::string("AIRSTAGINGPLATFORM"))) {
        return false; // no selected unit can be accepted
      }
      const CNamedCategory command{"COMMAND"};
      const CNamedCategory cannotUseAirStaging{"CANNOTUSEAIRSTAGING"};

      for (UserEntity* const selectedEntity : *selection) {
        UserUnit* const transporter = selectedEntity ? selectedEntity->IsUserUnit() : nullptr;
        if (transporter != nullptr) {
          IUnit* const transporterBridge = GetIUnitBridge(transporter);
          if (transporterBridge != nullptr && !transporterBridge->IsDead() // slot +0x28
              && !transporter->IsBeingBuilt()                              // v6 vtable slot +0x34
              && !transporterBridge->DestroyQueued())                      // slot +0x2C
          {
            if (!hoverTakesCommander && command.Contains(*transporter)) {
              continue;
            }

            if (wantsAir) {
              // Non-flying transporter for an air-transport request -> accept.
              // GetBlueprint() on the transporter IUnit subobject (slot +0x1C),
              // then Air.CanFly (blueprint + 0x368).
              if (transporterBridge->GetBlueprint()->Air.CanFly == 0u) {
                return true;
              }
            } else {
              // The hovered entity is an AIRSTAGINGPLATFORM: it docks aircraft, so accept
              // only a selected unit that can fly and is not CANNOTUSEAIRSTAGING.
              //
              // Same short-circuit shape as group 1: the binary's
              //   if (!CanFly || (ok = 1, IsInCategory(sel,"CANNOTUSEAIRSTAGING"))) ok = 0;
              //   if (ok) return 1;
              // leaves `ok` set only on the can-fly / not-excluded path.
              if (transporterBridge->GetBlueprint()->Air.CanFly != 0u && !cannotUseAirStaging.Contains(*transporter)) {
                return true;
              }
            }
          }
        }
      }

      return false;
    }

    /**
     * Address: 0x0081D660 (FUN_0081D660, func_RightClickTransport)
     *
     * IDA signature:
     * char __usercall func_RightClickTransport@<al>(int a1, Moho::UserEntity *a2@<ecx>);
     *
     * What it does:
     * Scans the current selection for any selected unit that the hovered
     * transporter `hoverEntity` is allowed to carry, honoring the transport
     * category rules (TELEPORTATION / EXPERIMENTAL / TRANSPORTFOCUS /
     * CANTRANSPORTCOMMANDER / COMMAND / TRANSPORTATION / FERRYBEACON /
     * AIRSTAGINGPLATFORM) against the hovered unit's air capability. Returns
     * true on the first accepted selected unit.
     */
    [[nodiscard]] bool HoverTransportAcceptsSelection(WeakSet<UserEntity>* const selection, UserEntity* const hoverEntity)
    {
      if (hoverEntity == nullptr) {
        return false;
      }
      if (hoverEntity->mVariableData.mIsDead != 0u || hoverEntity->IsBeingBuilt()) {
        return false;
      }

      UserUnit* const hoverUnit = hoverEntity->IsUserUnit();
      if (hoverUnit == nullptr) {
        return false;
      }
      IUnit* const hoverBridge = GetIUnitBridge(hoverUnit);
      if (hoverBridge == nullptr) {
        return false;
      }

      // As in SelectionHasTransportForTarget, the hovered unit's categories are tested once
      // rather than once per selected unit (engine change, same answers).
      //
      // Group 1: TELEPORTATION(candidate) or EXPERIMENTAL(hover) skips the candidate, so an
      // experimental hover skips them all.
      if (reinterpret_cast<const UserEntity*>(hoverUnit)->IsInCategory(fa::string("EXPERIMENTAL"))) {
        return false;
      }
      const bool hoverIsCommander = reinterpret_cast<const UserEntity*>(hoverUnit)->IsInCategory(fa::string("COMMAND"));
      const CNamedCategory teleportation{"TELEPORTATION"};
      const CNamedCategory transportFocus{"TRANSPORTFOCUS"};
      const CNamedCategory canTransportCommander{"CANTRANSPORTCOMMANDER"};
      const CNamedCategory transportation{"TRANSPORTATION"};
      const CNamedCategory ferryBeacon{"FERRYBEACON"};
      const CNamedCategory airStagingPlatform{"AIRSTAGINGPLATFORM"};

      for (UserEntity* const candidate : *selection) {
        if (candidate == nullptr || teleportation.Contains(*candidate) ||
            candidate->mVariableData.mLayerMask == static_cast<std::uint32_t>(LAYER_Seabed)) {
          continue;
        }
        // Group 2: TRANSPORTFOCUS(candidate).
        if (!transportFocus.Contains(*candidate)) {
          continue;
        }
        // Group 3: CANTRANSPORTCOMMANDER(candidate) -> never a skip; otherwise skip iff the
        // hovered unit IS the commander, which a transport without that flag cannot pick up.
        if (hoverIsCommander && !canTransportCommander.Contains(*candidate)) {
          continue;
        }
        // Group 4: TRANSPORTATION(candidate) or FERRYBEACON(candidate).
        if (transportation.Contains(*candidate) || ferryBeacon.Contains(*candidate)) {
          // Non-flying hover unit for an air-transport request -> accept.
          if (hoverBridge->GetBlueprint()->Air.CanFly == 0u) {
            return true;
          }
        } else if (airStagingPlatform.Contains(*candidate) && hoverBridge->GetBlueprint()->Air.CanFly != 0u) {
          // Air-staging platform docking a flying hover unit -> accept.
          return true;
        }
      }

      return false;
    }

    /**
     * Address: 0x0081DA20 (FUN_0081DA20, sub_81DA20)
     *
     * IDA signature:
     * char __usercall sub_81DA20@<al>(int a1@<ebx>, Moho::CWldSession *a2);
     *
     * What it does:
     * Returns true only when every currently selected entity is in the FACTORY
     * category. Used by the ferry-beacon right-click path to allow a
     * CallTransport order when the whole selection is factories. The binary
     * snapshots the FACTORY category's bit-vector and tests each selected
     * entity's blueprint ordinal against it; `EntityCategory::HasBlueprint`
     * expresses that same membership test.
     */
    [[nodiscard]] bool AllSelectedAreFactories(WeakSet<UserEntity>* const selection, CWldSession* const session)
    {
      const EntityCategorySet* const factoryCategory =
        static_cast<RRuleGameRules*>(session->mRules)->GetEntityCategory("FACTORY");

      for (UserEntity* const selectedEntity : *selection) {
        if (selectedEntity == nullptr
            || !EntityCategory::HasBlueprint(selectedEntity->mParams.mBlueprint, factoryCategory)) {
          return false;
        }
      }

      return true;
    }
}

  /**
   * Address: 0x008B0C80 (FUN_008B0C80)
   * Mangled: ?ISSUE_IncreaseCommandCount@Moho@@YAXPAVUserCommand@1@H@Z
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_IncreaseCommandCount(Moho::UserCommand* helper, int count);
   *
   * What it does:
   * Re-issues one factory-build command `count` extra times. Early-outs unless the
   * helper's resolved command type is `UNITCOMMAND_BuildFactory`. Reconstructs a
   * `SSTICommandIssueData` carrying the helper's constant command index and target
   * blueprint, decodes the helper's cached cursor-entity weak-set into live
   * `UserUnit*` lanes with a tombstone-pruning tree walk, then calls `ISSUE_Command`
   * once per requested count (the command payload is passed by value each call).
   */
  void ISSUE_IncreaseCommandCount(UserCommandIssueHelper* const helper, const int count)
  {
    // Gate: only factory-build commands are re-issued this way (asm 0x008B0CA2).
    if (ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildFactory) {
      return;
    }

    // Rebuild the issue payload from the helper's constant command descriptor: seed
    // an empty payload, then stamp BuildFactory + the command index (+0x04) and the
    // target blueprint pointer (+0x20) straight from the constant data.
    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_None);
    commandIssueData.mCommandType = EUnitCommandType::UNITCOMMAND_BuildFactory;
    commandIssueData.mIndex = helper->mConstantData.cmd;
    commandIssueData.mBlueprint = reinterpret_cast<RUnitBlueprint*>(helper->mConstantData.blueprint);

    // The command's units: a copy of the helper's cursor set (rebuilt first if
    // dirty, 0x008B43F0; copied through the range constructor 0x00831310),
    // then every unit of the copy into a vector sized by its `Size()`
    // (0x00838AE0). The copy is destroyed on the way out (0x008B0E61).
    const WeakSet<UserUnit> cursorUnits(*ResolveCommandIssueCursorEntities(*helper));
    gpg::fastvector<UserUnit*> selectedUnits{};
    selectedUnits.reserve(cursorUnits.Size());
    for (UserUnit* const unit : cursorUnits) {
      selectedUnits.push_back(unit);
    }

    // Issue the reconstructed factory-build command once per requested count;
    // clearQueue is always false here (asm push ebx==0 at 0x008B0E12).
    for (int remaining = count; remaining > 0; --remaining) {
      ISSUE_Command(selectedUnits, commandIssueData, false);
    }
  }

  // ---------------------------------------------------------------------
  // The ISSUE_FactoryCommand / ISSUE_RemoveLastCommand /
  // ISSUE_RemoveCommandFromUnitQueue family. Both of the binary callers this
  // family exists for are now recovered and call into it by name:
  //   - Moho::SCommandModeData::HandleEvent (0x0081FCD0) is defined further
  //     down this file and calls the `WeakSet<UserEntity>` overload of
  //     ISSUE_RemoveLastCommand from its RULEUCC_Attack arm;
  //   - Moho::CUIWorldView::HandleEvent (0x008704B0, moho/ui/UiRuntimeTypes.cpp)
  //     calls ISSUE_RemoveCommandFromUnitQueue from its shift+ctrl
  //     right-button-release arm, through the declaration in CWldSession.h.
  // ---------------------------------------------------------------------

  /**
   * Address: 0x008B5B50 (FUN_008B5B50, struct_CommandManager::NextCmdId)
   *
   * Recovered in Sim.cpp as a file-scope helper (no header declaration, so
   * it cannot be called from this translation unit as written - same
   * cross-TU gap as `func_OnCommandDragEnd`/moho/ui/CommandDragger.cpp).
   * Declared here to document the real call `ISSUE_FactoryCommand` makes.
   * Allocates one next command low-id from the manager's id-pool (released
   * set first, then sequential cursor), packs the active source byte into
   * the high byte, and writes the result to `outCommandId` (also returned).
   */
  // The top-level `const` on both parameters is load-bearing, not style:
  // MSVC decorates a `T* const` parameter as `QA...` and a plain `T*` as
  // `PA...`, so a declaration that drops it does not name the definition in
  // Sim.cpp. That mismatch is what left this call unresolved -
  // `?...@moho@@YAPAIPAUCommandManager@1@PAI@Z` wanted here against
  // `?...@moho@@YAPAIQAUCommandManager@1@QAI@Z` defined there.
  [[nodiscard]] std::uint32_t* AllocatePackedCommandIdFromManager(
    CommandManager* const commandManager, std::uint32_t* const outCommandId
  ) noexcept;

  /**
   * Address: 0x008B00A0 (FUN_008B00A0, func_DecodeEntIdSet)
   *
   * Recovered in Sim.cpp as a file-scope helper - same cross-TU gap as
   * `AllocatePackedCommandIdFromManager` above. Declared here to document
   * the real call `ISSUE_FactoryCommand` makes: builds an entity-id set from
   * a list of selected user units.
   */
  void func_DecodeEntIdSet(BVSet<EntId, EntIdUniverse>& out, const gpg::fastvector<UserUnit*>& units);

  /**
   * Address: 0x008B0730 (FUN_008B0730,
   * ?ISSUE_FactoryCommand@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@USSTICommandIssueData@1@_N@Z)
   *
   * IDA note: the decompiler flags this function's own local-variable
   * allocation as failed ("the output may be wrong!"), so its pseudocode is
   * lower-confidence than usual. The structure below is cross-checked
   * against the already-recovered sibling `ISSUE_Command(const
   * gpg::fastvector<UserUnit*>&, SSTICommandIssueData, bool)` (Sim.cpp),
   * which shares the same no-rush gate, id-allocation, and per-unit queue
   * bookkeeping shape almost verbatim - factory commands go through
   * `GetFactoryCommandQueue()`/`IssueFactoryCommand` instead of the plain
   * command queue/`IssueCommand`. The `struct_UserUnitManager::add` call
   * passes the issue data's `mIndex` as its 4th argument, exactly as
   * `ISSUE_Command`'s does (0x008B0566 pushes `data+0x08`); -1 appends.
   *
   * What it does:
   * Client/UI-side factory-command issue keystone over an explicit
   * `UserUnit*` list (factories): allocates a command id, runs the no-rush
   * gate against the resolved target, dispatches to the sim driver's
   * `IssueFactoryCommand`, publishes/reuses the command-issue helper, and
   * enqueues it into each unit's *factory* command queue (capped at 500
   * queued entries unless `clearQueue` forces a reset).
   */
  void ISSUE_FactoryCommand(
    const gpg::fastvector<UserUnit*>& units, SSTICommandIssueData commandIssueData, const bool clearQueue
  )
  {
    CWldSession* const session = WLD_GetActiveSession();
    CommandManager* const commandManager = session->mCommandManager;
    STIMap* const playableMap = session->mWldMap->mTerrainRes->mMap;

    std::uint32_t packedCommandId = 0u;
    commandIssueData.nextCommandId =
      static_cast<std::int32_t>(*AllocatePackedCommandIdFromManager(commandManager, &packedCommandId));
    if ((static_cast<std::uint32_t>(commandIssueData.nextCommandId) & 0xFF000000u) == 0xFF000000u) {
      return; // id-pool exhausted for this command source; nothing to issue.
    }

    // No-rush / playability gate - identical shape to ISSUE_Command's own
    // gate (Sim.cpp) and Moho::ISSUE_SetCommandTarget's (Sim.cpp).
    if (commandIssueData.mTarget.mType != EAiTargetType::AITARGET_None) {
      constexpr float kInvalidLane = std::numeric_limits<float>::quiet_NaN();
      Wm3::Vec3f targetPoint{kInvalidLane, kInvalidLane, kInvalidLane};

      if (commandIssueData.mTarget.mType == EAiTargetType::AITARGET_Entity) {
        if (UserEntity* const targetEntity = session->LookupEntityId(static_cast<EntId>(commandIssueData.mTarget.mEnt))) {
          targetPoint = targetEntity->mVariableData.mCurTransform.pos_;
        }
      } else {
        targetPoint = commandIssueData.mTarget.mPos;
      }

      const std::int32_t focusArmyIndex = session->FocusArmy;
      if (IsValidVector3f(targetPoint) && focusArmyIndex >= 0 &&
          session->userArmies[static_cast<std::size_t>(focusArmyIndex)] != nullptr) {
        const UserArmy* const focusArmy = session->GetFocusArmy();
        const bool insidePlayableArea =
          focusArmy->mVarDat.mUseWholeMap != 0u || playableMap == nullptr || playableMap->IsPlayable(targetPoint);

        if (!insidePlayableArea) {
          return;
        }
        if (focusArmy->mVarDat.mNoRushTimer > 0) {
          const float deltaX = (focusArmy->mVarDat.mArmyStart.x + focusArmy->mVarDat.mNoRushOffset.x) - targetPoint.x;
          const float deltaZ = (focusArmy->mVarDat.mArmyStart.y + focusArmy->mVarDat.mNoRushOffset.y) - targetPoint.z;
          const float noRushDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
          if (noRushDistance > focusArmy->mVarDat.mNoRushRadius) {
            return;
          }
        }
      }
    }

    BVSet<EntId, EntIdUniverse> issuedEntitySet{};
    func_DecodeEntIdSet(issuedEntitySet, units);
    // The returned execution beat expires local edits and retires the helper;
    // the packed command id remains in the published descriptor.
    const CmdId issueBeat = sSimDriver->IssueFactoryCommand(issuedEntitySet, commandIssueData, clearQueue);

    SSTICommandConstantData commandConstantData{};
    InitializePublishedCommandDescriptorFromIssueData(&commandConstantData, &commandIssueData);

    UserCommandIssueHelper* const commandHelper =
      FindOrCreateCommandIssueHelper(*commandManager, commandConstantData, 1u, issueBeat);
    commandHelper->mVariableData = SSTICommandVariableData(commandIssueData);
    commandHelper->mVariableDataDirty = 1u;

    for (UserUnit* const unit : units) {
      UserCommandQueue* const factoryQueue = unit->GetFactoryCommandQueue();
      if (factoryQueue == nullptr) {
        continue;
      }

      if (GetUserUnitManagerQueueSize(factoryQueue) <= 500) {
        if (clearQueue) {
          ResetUserUnitManagerState(factoryQueue, issueBeat);
        }
        UserUnitManagerAdd(factoryQueue, commandHelper, issueBeat, commandIssueData.mIndex);
      } else if (clearQueue) {
        ResetUserUnitManagerState(factoryQueue, issueBeat);
        UserUnitManagerAdd(factoryQueue, commandHelper, issueBeat, commandIssueData.mIndex);
      }
    }

    UI_OnCommandIssued(units, commandIssueData, clearQueue);
    session->DirtyCommandGraph();
  }

  /**
   * Address: 0x008B0B30 (FUN_008B0B30,
   * ?ISSUE_FactoryCommand@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes (inline-buffered fastvector, capacity pre-reserved from the set
   * size) and forwards to the explicit-unit `ISSUE_FactoryCommand`
   * overload, which takes the command payload by value (copy-constructed on
   * the stack here). Identical shape to `ISSUE_Command`'s own weak-set
   * overload (CWldSession.cpp).
   */
  void ISSUE_FactoryCommand(
    const WeakSet<UserEntity>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = static_cast<std::int32_t>(entities.Size());
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    for (UserEntity* const selectedEntity : entities) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }
    }

    ISSUE_FactoryCommand(selectedUnits, commandIssueData, clearQueue);
  }

  /**
   * Address: 0x008B1270 (FUN_008B1270,
   * ?ISSUE_RemoveLastCommand@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@@Z)
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_RemoveLastCommand(gpg::fastvector<Moho::UserUnit *> const &);
   *
   * What it does:
   * For each unit in `units`: resolves its command queue's most-recently
   * queued command helper (backward null-skip scan via
   * `GetUserUnitManagerLastQueuedHelper`), skipping units with no queue or
   * no queued helper at all. For each match: tells the active sim driver
   * to remove that command from the unit's server-side queue (by CmdId +
   * EntId), then records the removal locally via
   * `RecordUnitManagerCommandHelperRemoval` (UserUnit.h) - see that
   * declaration's doc comment for the `unitCount` tag-value oddity both
   * call sites here share. Finally marks the session's UI command graph
   * dirty so the graph overlay redraws.
   *
   * Invocation: sole caller is the `WeakSet<UserEntity>` overload of
   * `Moho::ISSUE_RemoveLastCommand` (FUN_008B1390, below), which calls it by
   * name a few lines down; that overload is in turn called by
   * `Moho::SCommandModeData::HandleEvent` (FUN_0081FCD0, recovered in this
   * file) from its `RULEUCC_Attack` arm.
   */
  void ISSUE_RemoveLastCommand(const gpg::fastvector<UserUnit*>& units)
  {
    const std::int32_t unitCount = static_cast<std::int32_t>(units.Size());

    for (UserUnit* const unit : units) {
      if (unit == nullptr) {
        continue;
      }

      UserCommandQueue* const manager = unit->GetCommandQueue();
      UserCommandIssueHelper* const lastHelper = GetUserUnitManagerLastQueuedHelper(manager);
      if (lastHelper == nullptr) {
        continue;
      }

      const EntId entityId = unit->mParams.mEntityId;
      if (ISTIDriver* const simDriver = sSimDriver.get(); simDriver != nullptr) {
        (void)simDriver->RemoveCommandFromUnitQueue(lastHelper->mConstantData.cmd, entityId);
      }

      RecordUnitManagerCommandHelperRemoval(lastHelper, manager, unitCount);
    }

    if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
      session->DirtyCommandGraph();
    }
  }

  /**
   * Address: 0x008B1390 (FUN_008B1390,
   * ?ISSUE_RemoveLastCommand@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@@Z)
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_RemoveLastCommand(Moho::WeakSet_UserEntity *a1@<ebx>);
   *
   * What it does:
   * Collects every live `UserUnit` in `entities` into a
   * `gpg::fastvector<UserUnit*>` (reserving up front for the weak-set's
   * live size) and forwards to the `gpg::fastvector<UserUnit*>` overload
   * of `ISSUE_RemoveLastCommand` (FUN_008B1270, above).
   *
   * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
   * (FUN_0081FCD0, recovered in this file), from the `RULEUCC_Attack` arm
   * at 0x0081FDB9 when the event replaces a command the same drag issued.
   */
  void ISSUE_RemoveLastCommand(WeakSet<UserEntity>& entities)
  {
    gpg::fastvector<UserUnit*> units{};
    units.reserve(entities.Size());

    for (UserEntity* const entity : entities) {
      if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
        units.push_back(unit);
      }
    }

    ISSUE_RemoveLastCommand(units);
  }

  /**
   * Address: 0x008B1220 (FUN_008B1220)
   * Mangled: ?ISSUE_RemoveCommandFromUnitQueue@Moho@@YAXPAVUserCommand@1@PAVUserUnit@1@@Z
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_RemoveCommandFromUnitQueue(
   *     Moho::UserCommand *command@<ebx>, Moho::UserUnit *unit@<esi>);
   *
   * What it does:
   * Removes exactly one queued command from exactly one unit. Null-tolerant on
   * both arguments (0x008B1223 / 0x008B1228). Tells the active sim driver to
   * drop `command`'s constant command id from `unit`'s server-side queue
   * (`ISTIDriver` vtable +0x80, 0x008B123C-0x008B1247), then records the local
   * removal against the unit's own command queue.
   *
   * Two details differ from the `ISSUE_RemoveLastCommand` sibling above and are
   * preserved verbatim:
   *   - the driver pointer is dereferenced unguarded (0x008B1232 loads the
   *     global and immediately reads its vptr); the sibling's null check is a
   *     property of that function, not of this one;
   *   - the tag handed to `RecordUnitManagerCommandHelperRemoval` is the `CmdId`
   *     the driver call returned through its sret slot (read back at
   *     0x008B1249 and pushed at 0x008B124F), not a unit count. The push
   *     happens *before* `GetCommandQueue` is dispatched (0x008B1255), so the
   *     evaluation order below matches the binary's.
   *
   * Invocation: sole call site in the image is `Moho::CUIWorldView::HandleEvent`
   * (0x008704B0) at 0x00871082, inside the shift+ctrl right-button-release loop
   * that strips the hovered command from every unit under the cursor. That
   * caller is recovered in moho/ui/UiRuntimeTypes.cpp and calls this by name.
   */
  void ISSUE_RemoveCommandFromUnitQueue(UserCommandIssueHelper* const command, UserUnit* const unit)
  {
    if (command == nullptr || unit == nullptr) {
      return;
    }

    const CmdId removedCommandId =
      sSimDriver.get()->RemoveCommandFromUnitQueue(command->mConstantData.cmd, unit->mParams.mEntityId);

    UserCommandQueue* const manager = unit->GetCommandQueue();
    RecordUnitManagerCommandHelperRemoval(command, manager, removedCommandId);
  }

  /**
   * Address: 0x008B4300 (FUN_008B4300, sub_8B4300)
   *
   * What it does:
   * Header-visible bridge over `IsCandidateExcludedByCachedRelation` (the
   * anonymous-namespace body earlier in this file), so callers outside this
   * translation unit can run the command-graph participant gate.
   *
   * Invocation: `Moho::CUIWorldView::HandleEvent` (0x008704B0) calls it at
   * 0x008706C6 while scanning the selection for a participant of the hovered
   * command.
   */
  bool IsCommandCandidateExcludedByCachedRelation(
    UserCommandIssueHelper& command,
    UserUnit* const candidateUnit
  ) noexcept
  {
    return IsCandidateExcludedByCachedRelation(command, candidateUnit);
  }

  /**
   * Address: 0x0081DD00 (FUN_0081DD00, sub_81DD00)
   *
   * What it does:
   * Header-visible bridge over `CanRestartMoveCommandAsPatrol` (the
   * anonymous-namespace body earlier in this file). Both parameter types are
   * already public, so this only lifts the linkage.
   *
   * Invocation: `Moho::CUIWorldView::HandleEvent` (0x008704B0) calls it at
   * 0x008707FC to gate the "convert moves into patrol" cursor banner; the
   * in-file caller `SCommandModeData::HandleEvent` keeps calling the
   * anonymous-namespace body directly.
   */
  bool CanRestartSelectionMoveCommandAsPatrol(
    WeakSet<UserEntity>& selection,
    UserCommandIssueHelper* const helper
  )
  {
    return CanRestartMoveCommandAsPatrol(selection, helper);
  }
namespace
{
    /// The `EntId` sentinel every ground-targeted command payload carries
    /// (`mov [target+4], 0F0000000h` at every ground-target site in
    /// `SCommandModeData::HandleEvent`).
    constexpr std::uint32_t kGroundTargetEntityId = 0xF0000000u;

    /// Cursor-banner lifetime shared by both banners this dispatcher raises
    /// (`flt_E4F718`, pushed at 0x0081FEC6 and 0x008207FC).
    constexpr float kCursorBannerSeconds = 3.0f;
    /// ARGB red (0x0081FED2).
    constexpr std::uint32_t kCoordinatedAttackBannerColor = 0xFFFF0000u;
    /// ARGB green (0x0082080B).
    constexpr std::uint32_t kPatrolInitiatedBannerColor = 0xFF00FF00u;

    /**
     * A `CmdId` packs the issuing command source into its high byte, and the
     * `(MouseInfo, modifiers)` command-mode constructor (0x0081CEA0) seeds
     * `mIsDragged` with an all-ones id. `HandleEvent` therefore tests only the
     * source byte for the "this drag is not editing a live command" sentinel
     * (0x0081FEA6 and 0x0082078E), not the whole word.
     */
    [[nodiscard]] bool HasDraggedCommand(const CommandModeData& commandMode) noexcept
    {
      constexpr std::uint32_t kCommandSourceMask = 0xFF000000u;
      return (static_cast<std::uint32_t>(commandMode.mIsDragged) & kCommandSourceMask) != kCommandSourceMask;
    }

    /**
     * The drag snapshot stores the cursor in screen space as a plain
     * `Wm3::Vector2f`; the cursor-banner API names the same two floats
     * `SMauiMousePos` (the binary just hands `&mMouseScreenPos` over in `ecx`
     * at 0x0081FEDA / 0x00820813).
     */
    [[nodiscard]] SMauiMousePos ToMauiMousePos(const Wm3::Vector2f& screenPos) noexcept
    {
      return SMauiMousePos{screenPos.x, screenPos.y};
    }

    void SetEntityTarget(SSTICommandIssueData& data, const UserEntity& target) noexcept
    {
      data.mTarget.mType = EAiTargetType::AITARGET_Entity;
      data.mTarget.mEntityId = static_cast<std::uint32_t>(target.mParams.mEntityId);
      data.mTarget.mPos = Wm3::Vec3f(0.0f, 0.0f, 0.0f);
    }

    void SetGroundTarget(SSTICommandIssueData& data, const Wm3::Vector3f& worldPos) noexcept
    {
      data.mTarget.mType = EAiTargetType::AITARGET_Ground;
      data.mTarget.mEntityId = kGroundTargetEntityId;
      data.mTarget.mPos = worldPos;
    }

    /**
     * Copies the drag formation's chosen script index, heading quaternion and
     * spacing scale into the payload's formation lanes - the same
     * `unk38`/`mOri`/`unk4C` triple `CPlatoon`'s own Form* command builders
     * fill (CPlatoon.cpp).
     */
    void ApplyFormationLanes(SSTICommandIssueData& data, const CFormation& formation) noexcept
    {
      data.unk38 = formation.mBestFormation;
      data.mOri = formation.mDirection;
      data.unk4C = formation.mDirectionScale;
    }

    /// The drag formation has settled on a usable script and stopped ticking.
    [[nodiscard]] bool IsFormationSettled(const CFormation& formation) noexcept
    {
      return formation.mReady && formation.mTimeLeft == 0.0f;
    }

    /// Issues `commandType` at the hovered entity for the whole selection.
    void IssueOrderAtEntity(
      WeakSet<UserEntity>& selection,
      const EUnitCommandType commandType,
      const UserEntity& target,
      const bool clearQueue
    )
    {
      SSTICommandIssueData commandData(commandType);
      SetEntityTarget(commandData, target);
      ISSUE_Command(selection, commandData, clearQueue);
    }

    /// Issues `commandType` at a world position for the whole selection.
    void IssueOrderAtGround(
      WeakSet<UserEntity>& selection,
      const EUnitCommandType commandType,
      const Wm3::Vector3f& worldPos,
      const bool clearQueue
    )
    {
      SSTICommandIssueData commandData(commandType);
      SetGroundTarget(commandData, worldPos);
      ISSUE_Command(selection, commandData, clearQueue);
    }

    /**
     * The "snap the group anchor to the terrain, then re-issue at the drag
     * position" tail both the `RULEUCC_Patrol` and `RULEUCC_Ferry` arms run
     * when their anchor resolver reports the group is not already doing this
     * exact thing. The second issue always passes `clearQueue == false` so it
     * appends behind the first.
     */
    template <typename TIssueFn>
    void IssueAnchoredThenDragPosition(
      SSTICommandIssueData& commandData,
      const CWldSession& session,
      const Wm3::Vector3f& groupAnchor,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue,
      TIssueFn&& issue
    )
    {
      const float anchorSurface = session.GetSTIMap()->GetSurface(groupAnchor);
      SetGroundTarget(commandData, Wm3::Vector3f(groupAnchor.x, anchorSurface, groupAnchor.z));
      issue(commandData, clearQueue);

      SetGroundTarget(commandData, dragWorldPos);
      issue(commandData, false);
    }

    /**
     * Address: 0x0081FF17-0x0082012A (the `RULEUCC_Attack` no-hover arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Splits the selection into units eligible for an attack-move
     * (mobile + `FIRESTATE_ReturnFire`) and everything else, then issues an
     * AggressiveMove at the drag position to the first group and a plain
     * ground Attack to the second.
     */
    void IssueAttackMoveToGround(
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      const Wm3::Vector3f& dragWorldPos,
      const bool formationModifier,
      const bool clearQueue
    )
    {
      WeakSet<UserEntity> otherUnits;
      WeakSet<UserEntity> aggressiveMoveUnits;
      SplitSelectionForAggressiveMove(selection, aggressiveMoveUnits, otherUnits);

      if (!aggressiveMoveUnits.Empty()) {
        const CFormation& formation = *session.mCurFormation;
        SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_AggressiveMove);
        ApplyFormationLanes(commandData, formation);

        Wm3::Vector3f destination = dragWorldPos;
        if (aggressiveMoveUnits.Size() > 1 && formationModifier) {
          commandData.mCommandType = EUnitCommandType::UNITCOMMAND_FormAggressiveMove;
          destination = formation.mFinish;
        }

        SetGroundTarget(commandData, destination);
        ISSUE_Command(aggressiveMoveUnits, commandData, clearQueue);
      }

      if (!otherUnits.Empty()) {
        IssueOrderAtGround(otherUnits, EUnitCommandType::UNITCOMMAND_Attack, dragWorldPos, clearQueue);
      }
    }

    /**
     * Address: 0x00820661-0x00820B37 (the `RULEUCC_Move` arm of
     * `Moho::SCommandModeData::HandleEvent`, also entered from the
     * `RULEUCC_Guard` arm once the drag formation has settled)
     *
     * What it does:
     * Splits the selection into rally-point holders and everything else, then
     * issues Move/AggressiveMove (or their Form* variants once the drag
     * formation has settled and more than one unit is moving) to the plain
     * units and the same order as a *factory* command to the rally-point
     * holders. Before issuing the plain order it offers the "keep dragging an
     * already-queued move to convert it into a patrol" shortcut: when the drag
     * is editing a live command whose queue passes
     * `CanRestartMoveCommandAsPatrol`, the queued commands are restarted as
     * Patrol/FormPatrol in place, a cursor banner is shown and **nothing** is
     * issued - not even the rally-point half.
     */
    void IssueMoveOrderForDrag(
      CommandModeData& commandMode,
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      const bool attackMoveModifier,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;

      WeakSet<UserEntity> rallyPointUnits;
      WeakSet<UserEntity> otherUnits;
      SplitSelectionByRallyPointCategory(selection, rallyPointUnits, otherUnits);

      const EUnitCommandType moveCommand = attackMoveModifier
        ? EUnitCommandType::UNITCOMMAND_AggressiveMove
        : EUnitCommandType::UNITCOMMAND_Move;
      const EUnitCommandType formMoveCommand = attackMoveModifier
        ? EUnitCommandType::UNITCOMMAND_FormAggressiveMove
        : EUnitCommandType::UNITCOMMAND_FormMove;

      if (!otherUnits.Empty()) {
        const CFormation& formation = *session.mCurFormation;
        SSTICommandIssueData commandData(moveCommand);
        ApplyFormationLanes(commandData, formation);

        Wm3::Vector3f destination = dragWorldPos;
        // The stock build short-circuits this on the formation modifier the
        // way the RULEUCC_Attack arm above does; in the shipped FAF binary the
        // `jnz` that did so is NOP'd out at 0x0082074D-0x0082074E, leaving only
        // the settled-formation test. Recovered as shipped.
        if (otherUnits.Size() > 1 && IsFormationSettled(formation)) {
          commandData.mCommandType = formMoveCommand;
          destination = formation.mFinish;
        }
        SetGroundTarget(commandData, destination);

        if (HasDraggedCommand(commandMode)) {
          UserCommandIssueHelper* const draggedCommand =
            FindCommandIssueHelperInSession(&session, commandMode.mIsDragged);
          if (CanRestartMoveCommandAsPatrol(selection, draggedCommand)) {
            RestartMoveCommandAsPatrol(selection, draggedCommand);
            UI_StartCursorText(
              ToMauiMousePos(commandMode.mMouseDragStart.mMouseScreenPos),
              "<LOC Engine0012>Patrol Initiated to location!",
              kPatrolInitiatedBannerColor,
              kCursorBannerSeconds,
              true
            );
            return;
          }
        }

        ISSUE_Command(otherUnits, commandData, clearQueue);
      }

      if (!rallyPointUnits.Empty()) {
        SSTICommandIssueData rallyCommandData(moveCommand);
        SetGroundTarget(rallyCommandData, dragWorldPos);
        ISSUE_FactoryCommand(rallyPointUnits, rallyCommandData, clearQueue);
      }
    }

    /**
     * Address: 0x008203CE-0x0082065C (the `RULEUCC_Guard` arm of
     * `Moho::SCommandModeData::HandleEvent`, reached once the drag formation
     * is *not* settled)
     *
     * What it does:
     * Guarding a hovered unit targets it directly, except when it is a
     * STRUCTURE: then the selection is split by the REBUILDER category so the
     * rebuilders are aimed at the structure's own world position (they can
     * rebuild the wreck in place) while everybody else guards the entity, both
     * halves carrying the structure's blueprint. With nothing hovered the
     * order becomes a guard-this-spot for every mobile selected entity, in
     * formation when more than one of them takes it.
     */
    void IssueGuardOrderForDrag(
      CommandModeData& commandMode,
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      UserEntity* const hovered,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;
      const EUnitCommandType guardCommand = UnitCommandCapToCommandType(commandMode.mCommandCaps);

      if (UserUnit* const hoveredUnit = hovered != nullptr ? hovered->IsUserUnit() : nullptr;
          hoveredUnit != nullptr) {
        const RUnitBlueprint* const hoveredBlueprint = GetIUnitBridge(hoveredUnit)->GetBlueprint();

        bool hoveredIsStructure = false;
        if (hoveredBlueprint != nullptr) {
          const fa::string structureCategory("STRUCTURE");
          hoveredIsStructure = hovered->IsInCategory(structureCategory);
        }

        if (!hoveredIsStructure) {
          IssueOrderAtEntity(selection, guardCommand, *hovered, clearQueue);
          return;
        }

        WeakSet<UserEntity> nonRebuilders;
        WeakSet<UserEntity> rebuilders;
        SplitSelectionByRebuilderCategory(selection, nonRebuilders, rebuilders);
        if (hovered != nullptr)
        {
          nonRebuilders.Remove(hovered);
          rebuilders.Remove(hovered);
        }

        {
          SSTICommandIssueData commandData(guardCommand);
          SetEntityTarget(commandData, *hovered);
          commandData.mBlueprint = const_cast<RUnitBlueprint*>(hoveredBlueprint);
          ISSUE_Command(nonRebuilders, commandData, clearQueue);
        }
        {
          SSTICommandIssueData commandData(UnitCommandCapToCommandType(commandMode.mCommandCaps));
          SetGroundTarget(commandData, hovered->mVariableData.mCurTransform.pos_);
          commandData.mBlueprint = const_cast<RUnitBlueprint*>(hoveredBlueprint);
          ISSUE_Command(rebuilders, commandData, clearQueue);
        }
        return;
      }

      WeakSet<UserUnit> formationUnits;
      WeakSet<UserEntity> guardTargets;

      for (UserEntity* const entity : selection) {
        const REntityBlueprint* const blueprint = entity != nullptr ? entity->mParams.mBlueprint : nullptr;
        if (blueprint != nullptr && blueprint->IsMobile()) {
          (void)guardTargets.Add(entity);

          if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
            (void)formationUnits.Add(unit);
          }
        }
      }

      CFormation& formation = *session.mCurFormation;
      if (guardTargets.Size() > 1) {
        formation.ChooseFormation(dragWorldPos, formationUnits, queueModifier);
        if (formation.mBestFormation >= 0) {
          SSTICommandIssueData commandData(UnitCommandCapToCommandType(commandMode.mCommandCaps));
          SetGroundTarget(commandData, dragWorldPos);
          ApplyFormationLanes(commandData, formation);
          ISSUE_Command(guardTargets, commandData, clearQueue);
          formation.Reset();
        }
        return;
      }

      if (!guardTargets.Empty()) {
        IssueOrderAtGround(
          guardTargets, UnitCommandCapToCommandType(commandMode.mCommandCaps), dragWorldPos, clearQueue
        );
      }
    }

    /**
     * Address: 0x00820923-0x00820B37 (the `RULEUCC_Patrol` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Splits the selection into rally-point holders and everybody else, picks
     * Patrol or FormPatrol (the latter only once the drag formation has
     * settled; otherwise a fresh formation is chosen from the selected units
     * around the hovered unit, or around the drag position when nothing is
     * hovered, and the whole arm is abandoned if no formation script fits),
     * then issues that command to both halves. Each half first asks
     * `ResolveGroupMoveAnchorOrDetectPatrol` whether the group is already
     * patrolling: if it is, the drag position is used as-is; if not, the
     * resolved group anchor is snapped to the terrain and issued first so the
     * patrol runs anchor -> drag position.
     */
    void IssuePatrolOrderForDrag(
      CommandModeData& commandMode,
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      UserEntity* const hovered,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;

      WeakSet<UserEntity> rallyPointUnits;
      WeakSet<UserEntity> otherUnits;
      SplitSelectionByRallyPointCategory(selection, rallyPointUnits, otherUnits);

      CFormation& formation = *session.mCurFormation;
      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Patrol);
      SetGroundTarget(commandData, dragWorldPos);

      if (selection.Size() > 1) {
        if (IsFormationSettled(formation)) {
          commandData.mCommandType = EUnitCommandType::UNITCOMMAND_FormPatrol;
          ApplyFormationLanes(commandData, formation);
        } else {
          WeakSet<UserUnit> formationUnits;

          for (UserEntity* const entity : selection) {
            if (UserUnit* const unit = entity != nullptr ? entity->IsUserUnit() : nullptr; unit != nullptr) {
              (void)formationUnits.Add(unit);
            }
          }

          const Wm3::Vector3f& formationAnchor =
            hovered != nullptr ? hovered->mVariableData.mCurTransform.pos_ : dragWorldPos;
          formation.ChooseFormation(formationAnchor, formationUnits, queueModifier);
          if (formation.mBestFormation < 0) {
            return;
          }

          ApplyFormationLanes(commandData, formation);
          formation.Reset();
        }
      }

      if (!otherUnits.Empty()) {
        Wm3::Vector3f groupAnchor(0.0f, 0.0f, 0.0f);
        if (ResolveGroupMoveAnchorOrDetectPatrol(selection, groupAnchor, !queueModifier)) {
          ISSUE_Command(otherUnits, commandData, clearQueue);
        } else {
          IssueAnchoredThenDragPosition(
            commandData, session, groupAnchor, dragWorldPos, clearQueue,
            [&otherUnits](const SSTICommandIssueData& data, const bool clear) {
              ISSUE_Command(otherUnits, data, clear);
            }
          );
        }
      }

      if (!rallyPointUnits.Empty()) {
        Wm3::Vector3f groupAnchor(0.0f, 0.0f, 0.0f);
        if (ResolveGroupMoveAnchorOrDetectPatrol(selection, groupAnchor, !queueModifier)) {
          ISSUE_FactoryCommand(rallyPointUnits, commandData, clearQueue);
        } else {
          IssueAnchoredThenDragPosition(
            commandData, session, groupAnchor, dragWorldPos, clearQueue,
            [&rallyPointUnits](const SSTICommandIssueData& data, const bool clear) {
              ISSUE_FactoryCommand(rallyPointUnits, data, clear);
            }
          );
        }
      }
    }

    /**
     * Address: 0x008215FD-0x008217CA (the `RULEUCC_Ferry` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Keeps only the air transports out of the selection and gives them a
     * ferry route. When every one of them is already ferrying, the drag
     * position is appended as-is; otherwise their averaged current route
     * anchor is snapped to the terrain and issued first so the ferry runs
     * anchor -> drag position. The land-unit half of the split is built (the
     * binary builds it too) but this arm never consumes it.
     */
    void IssueFerryOrderForDrag(
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue
    )
    {
      WeakSet<UserEntity> airTransports;
      WeakSet<UserEntity> landUnits;
      SplitSelectionForFerryCommand(selection, airTransports, landUnits);

      if (airTransports.Empty()) {
        return;
      }

      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Ferry);
      SetGroundTarget(commandData, dragWorldPos);

      Wm3::Vector3f groupAnchor(0.0f, 0.0f, 0.0f);
      if (ResolveGroupFerryAnchorOrDetectFerry(airTransports, groupAnchor)) {
        ISSUE_Command(airTransports, commandData, clearQueue);
        return;
      }

      IssueAnchoredThenDragPosition(
        commandData, session, groupAnchor, dragWorldPos, clearQueue,
        [&airTransports](const SSTICommandIssueData& data, const bool clear) {
          ISSUE_Command(airTransports, data, clear);
        }
      );
    }

    /**
     * Address: 0x00821014-0x008215BC (the `RULEUCC_Transport` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Four separate transport gestures, in the order the binary tests them:
     *   1. drop on a TELEPORTBEACON while a teleport-capable unit is selected
     *      -> unload onto the beacon;
     *   2. drop on a unit that itself has the CallTransport capability
     *      -> reverse-load into it;
     *   3. otherwise, when the session's extra-select list names specific
     *      units, unload exactly those at the drag position (as a plain Move
     *      when every one of them is a POD, since pods are not cargo);
     *   4. otherwise split the selection into air transports and land units:
     *      if either half is empty the whole selection is told to unload at
     *      the drag position, else the transports are folded into the land
     *      group and the group is given an AssistMove there.
     * Every path ends by re-applying the current selection, which is what
     * refreshes the extra-select overlay.
     */
    void IssueTransportOrderForDrag(
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      UserEntity* const hovered,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue
    )
    {
      if (hovered != nullptr) {
        const fa::string teleportBeaconCategory("TELEPORTBEACON");
        if (hovered->IsInCategory(teleportBeaconCategory) && SelectionContainsTeleportationUnit(selection)) {
          IssueOrderAtEntity(
            selection, EUnitCommandType::UNITCOMMAND_TransportUnloadUnits, *hovered, clearQueue
          );
          return;
        }
      }

      if (UserUnit* const hoveredUnit = hovered != nullptr ? hovered->IsUserUnit() : nullptr;
          hoveredUnit != nullptr) {
        const std::uint32_t hoveredCaps = GetIUnitBridge(hoveredUnit)->GetAttributes().commandCapsMask;
        if ((hoveredCaps & static_cast<std::uint32_t>(RULEUCC_CallTransport)) != 0u) {
          IssueOrderAtEntity(
            selection, EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits, *hovered, clearQueue
          );
          return;
        }
      }

      WeakSet<UserEntity> extraSelection = session.GetExtraSelectList();

      if (!extraSelection.Empty()) {
        WeakSet<UserEntity> unloadTargets(selection);

        bool onlyPods = true;
        for (UserEntity* const entity : extraSelection) {
          if (entity->mVariableData.mIsDead == 0u && entity->IsUserUnit() != nullptr) {
            (void)unloadTargets.Add(entity);

            const fa::string podCategory("POD");
            if (!entity->IsInCategory(podCategory)) {
              onlyPods = false;
            }
          }
        }

        const EUnitCommandType unloadCommand = onlyPods
          ? EUnitCommandType::UNITCOMMAND_Move
          : EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits;
        IssueOrderAtGround(unloadTargets, unloadCommand, dragWorldPos, clearQueue);
      } else {
        WeakSet<UserEntity> airTransports;
        WeakSet<UserEntity> landUnits;
        SplitSelectionForFerryCommand(selection, airTransports, landUnits);

        if (airTransports.Empty() || landUnits.Empty()) {
          IssueOrderAtGround(
            selection, EUnitCommandType::UNITCOMMAND_TransportUnloadUnits, dragWorldPos, clearQueue
          );
        } else {
          for (UserEntity* const entity : airTransports) {
            if (entity->mVariableData.mIsDead == 0u && entity->IsUserUnit() != nullptr) {
              (void)landUnits.Add(entity);
            }
          }

          IssueOrderAtGround(landUnits, EUnitCommandType::UNITCOMMAND_AssistMove, dragWorldPos, clearQueue);
        }
      }

      session.SetSelection(selection);
    }

    /**
     * Address: 0x00820E01-0x0082100F (the `RULEUCC_CallTransport` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Tells the selection to load into the hovered transport, splitting the
     * rally-point holders off into a factory command as every other move-like
     * arm does. The hovered transport is added to whichever half is being
     * ordered unless it is a ferry beacon or an air staging platform - a
     * carrier overrides that and is always loaded along with its cargo.
     */
    void IssueCallTransportOrderForDrag(
      WeakSet<UserEntity>& selection,
      UserEntity& hovered,
      const bool clearQueue
    )
    {
      const bool hoveredIsAirStaging = hovered.IsInCategory(fa::string("AIRSTAGINGPLATFORM"));
      const bool hoveredIsCarrier = hovered.IsInCategory(fa::string("CARRIER"));
      const bool hoveredIsFerryBeacon = hovered.IsInCategory(fa::string("FERRYBEACON"));

      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
      SetEntityTarget(commandData, hovered);

      WeakSet<UserEntity> rallyPointUnits;
      WeakSet<UserEntity> otherUnits;
      SplitSelectionByRallyPointCategory(selection, rallyPointUnits, otherUnits);

      const bool loadHoveredTransportToo = (!hoveredIsFerryBeacon && !hoveredIsAirStaging) || hoveredIsCarrier;

      if (!otherUnits.Empty()) {
        if (loadHoveredTransportToo) {
          (void)otherUnits.Add(&hovered);
        }
        ISSUE_Command(otherUnits, commandData, clearQueue);
      }

      if (!rallyPointUnits.Empty()) {
        if (loadHoveredTransportToo) {
          (void)rallyPointUnits.Add(&hovered);
        }
        ISSUE_FactoryCommand(rallyPointUnits, commandData, clearQueue);
      }
    }

    /**
     * Address: 0x00821AC0-0x00821CFA (the `RULEUCC_Script` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Hands the pending script command to
     * `/lua/user/UserScriptCommand.lua:VerifyScriptCommand` and, when the
     * script sets `UserValidated`, re-issues it to exactly the units the
     * script listed in `AuthorizedUnits`. The verified descriptor rides along
     * on the payload's Lua-object lane (minus `AuthorizedUnits`, which is
     * nilled out first so the sim never sees it).
     */
    void IssueScriptCommandForDrag(
      WeakSet<UserEntity>& selection,
      UserEntity* const hovered,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue
    )
    {
      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Script);
      if (hovered != nullptr) {
        SetEntityTarget(commandData, *hovered);
      } else {
        SetGroundTarget(commandData, dragWorldPos);
      }

      LuaPlus::LuaObject verifyResult = UI_VerifyScriptCommand(selection, commandData, clearQueue);
      if (!verifyResult["UserValidated"].GetBoolean()) {
        return;
      }

      commandData.mObject = verifyResult;
      LuaPlus::LuaState* const state = verifyResult.m_state;

      gpg::fastvector_n<UserUnit*, 1> authorizedUnits{};
      {
        // The binary lets the `operator[]` temporary die right after the
        // iterator is constructed (0x00821C2D) and keeps iterating the freed
        // slot; the table object is held for the whole walk here instead,
        // which is the same traversal without the dangling read.
        LuaPlus::LuaObject authorizedTable = verifyResult["AuthorizedUnits"];
        for (LuaPlus::LuaTableIterator entry(authorizedTable, 1); !entry.m_isDone; entry.Next()) {
          authorizedUnits.push_back(SCR_FromLua_UserUnit(entry.GetValue(), state));
        }
      }

      verifyResult.SetNil("AuthorizedUnits");
      ISSUE_Command(authorizedUnits, commandData, clearQueue);
    }

    /**
     * Address: 0x00821DEE-0x00821EA2 (the `COMMOD_Build`/`COMMOD_BuildAnchored`
     * arm of `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * While the session is previewing invalid build placements, validates the
     * drag spot (an anchored build additionally has to be inside the builder's
     * build radius). A legal spot - or a session that is not previewing at all
     * - just notifies the UI script layer that a command was issued; an
     * illegal one instead takes one build off an order this selection already
     * has queued on that same footprint, which is what makes dragging a
     * queued structure back onto itself cancel it.
     */
    void DispatchBuildCommandMode(CommandModeData& commandMode, CWldSession& session, const bool clearQueue)
    {
      WeakSet<UserEntity>& selection = session.mSelection;
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;
      const auto* const buildBlueprint = static_cast<const RUnitBlueprint*>(commandMode.mBlueprint);

      if (session.mShowInvalidBuildPlacementPreview) {
        const SCoordsVec2 buildPosition{dragWorldPos.x, dragWorldPos.z};

        const bool withinBuildDistance = commandMode.mMode != COMMOD_BuildAnchored
          || USERUNIT_WithinBuildDistance(session, buildBlueprint, buildPosition);

        bool placeable = false;
        if (withinBuildDistance) {
          SOccupationResult occupation{};
          placeable = USERUNIT_CanBeBuiltAt(session, buildBlueprint, buildPosition, false, &occupation, nullptr);
        }

        if (!placeable) {
          if (UserCommandIssueHelper* const queuedOrder =
                FindColocatedQueuedBuildOrder(selection, dragWorldPos, buildBlueprint);
              queuedOrder != nullptr) {
            ISSUE_DecreaseCommandCount(queuedOrder, 1);
          }
          return;
        }
      }

      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_None);
      UI_OnCommandIssued(selection, commandData, clearQueue);
    }

    /**
     * Address: 0x0081FD6D-0x00821CFA plus the shared tails (the `COMMOD_Order`
     * arm of `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * The command-capability switch: one arm per `ERuleBPUnitCommandCaps`
     * value the world view can put the cursor into. Everything that is not
     * called out below reduces to "issue this capability's command at the drag
     * position", and `RULEUCC_Invalid` is swallowed outright.
     */
    void DispatchOrderCommandMode(
      CommandModeData& commandMode,
      CWldSession& session,
      UserEntity* const hovered,
      const bool isDragUpdate,
      const bool formationModifier,
      const bool attackMoveModifier,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      WeakSet<UserEntity>& selection = session.mSelection;
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;

      switch (commandMode.mCommandCaps) {
        case RULEUCC_Move:
          IssueMoveOrderForDrag(commandMode, session, selection, attackMoveModifier, queueModifier, clearQueue);
          return;

        case RULEUCC_Attack: {
          // A drag that re-targets the order it already issued withdraws that
          // order first, so the queue never grows while the cursor moves.
          if (isDragUpdate) {
            ISSUE_RemoveLastCommand(selection);
          }

          if (hovered == nullptr) {
            IssueAttackMoveToGround(session, selection, dragWorldPos, formationModifier, clearQueue);
            return;
          }

          const CFormation& formation = *session.mCurFormation;
          SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Attack);
          ApplyFormationLanes(commandData, formation);
          if (selection.Size() > 1 && (formationModifier || IsFormationSettled(formation))) {
            commandData.mCommandType = EUnitCommandType::UNITCOMMAND_FormAttack;
          }
          SetEntityTarget(commandData, *hovered);

          // Several players attacking the same target with one drag get the
          // "coordinated attack" banner and share the dragged order's id.
          if (isDragUpdate && HasDraggedCommand(commandMode)
              && CanStartCoordinatedAttack(session, commandMode.mIsDragged)) {
            UI_StartCursorText(
              ToMauiMousePos(commandMode.mMouseDragStart.mMouseScreenPos),
              "<LOC Engine0011>Coordinated Attack!",
              kCoordinatedAttackBannerColor,
              kCursorBannerSeconds,
              true
            );
            commandData.unk04 = commandMode.mIsDragged;
          }

          ISSUE_Command(selection, commandData, clearQueue);
          return;
        }

        case RULEUCC_Guard:
          // A settled drag formation turns a guard gesture into a formation
          // move (0x0082013F-0x0082014F).
          if (IsFormationSettled(*session.mCurFormation)) {
            IssueMoveOrderForDrag(commandMode, session, selection, attackMoveModifier, queueModifier, clearQueue);
            return;
          }
          IssueGuardOrderForDrag(commandMode, session, selection, hovered, queueModifier, clearQueue);
          return;

        case RULEUCC_Patrol:
          IssuePatrolOrderForDrag(commandMode, session, selection, hovered, queueModifier, clearQueue);
          return;

        case RULEUCC_Ferry:
          IssueFerryOrderForDrag(session, selection, dragWorldPos, clearQueue);
          return;

        case RULEUCC_Transport:
          IssueTransportOrderForDrag(session, selection, hovered, dragWorldPos, clearQueue);
          return;

        case RULEUCC_CallTransport:
          if (hovered == nullptr) {
            return;
          }
          IssueCallTransportOrderForDrag(selection, *hovered, clearQueue);
          return;

        case RULEUCC_Script:
          IssueScriptCommandForDrag(selection, hovered, dragWorldPos, clearQueue);
          return;

        case RULEUCC_Reclaim: {
          if (hovered == nullptr) {
            return;
          }

          bool reclaimable = false;
          {
            const fa::string reclaimableCategory("RECLAIMABLE");
            reclaimable = hovered->IsInCategory(reclaimableCategory) || hovered->IsBeingBuilt();
          }
          if (!reclaimable) {
            return;
          }

          IssueOrderAtEntity(
            selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), *hovered, clearQueue
          );
          return;
        }

        // Sacrifice is its own emitted block in the binary (0x008217CF) but the
        // same source shape as the repair/capture/overcharge group below.
        case RULEUCC_Sacrifice:
        case RULEUCC_Repair:
        case RULEUCC_Capture:
        case RULEUCC_Overcharge:
          if (hovered == nullptr) {
            return;
          }
          IssueOrderAtEntity(
            selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), *hovered, clearQueue
          );
          return;

        case RULEUCC_Nuke:
        case RULEUCC_Tactical:
        case RULEUCC_SpecialAction:
          if (hovered != nullptr) {
            IssueOrderAtEntity(
              selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), *hovered, clearQueue
            );
          } else {
            IssueOrderAtGround(
              selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), dragWorldPos, clearQueue
            );
          }
          return;

        case RULEUCC_Invalid:
          return;

        default:
          IssueOrderAtGround(
            selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), dragWorldPos, clearQueue
          );
          return;
      }
    }
}


  /**
   * Address: 0x0081FCD0 (FUN_0081FCD0, Moho::SCommandModeData::HandleEvent)
   *
   * IDA signature:
   * void __thiscall Moho::SCommandModeData::HandleEvent(
   *     Moho::SCommandModeData *this, Moho::CWldSession *a2, char a3);
   *
   * What it does:
   * Turns one committed world-view mouse gesture into command traffic for the
   * session's current selection. The drag snapshot this object carries
   * (`mMouseDragStart`) supplies both the world position and the hovered
   * entity; `mModifiers` supplies the three keyboard modifier lanes; `mMode`
   * and `mCommandCaps` select the arm:
   *
   *   - `COMMOD_Order` -> `DispatchOrderCommandMode`, one arm per command
   *     capability (move / attack / guard / patrol / ferry / transport /
   *     call-transport / reclaim / sacrifice+repair+capture+overcharge /
   *     nuke+tactical+special-action / script), each of them documented on its
   *     own helper above;
   *   - `COMMOD_Build`, `COMMOD_BuildAnchored` -> `DispatchBuildCommandMode`,
   *     the build-placement validator;
   *   - `COMMOD_Ping` (and the unnamed mode 7 the binary's jump table routes
   *     to the same entry) -> just leave command mode;
   *   - `COMMOD_Move` and `COMMOD_Reclaim` are *not* handled here (the jump
   *     table sends them to the default arm): those modes are cursor states
   *     the world view resolves into a `COMMOD_Order` before committing.
   *
   * Every arm shares one derived flag: `clearQueue` is the inverse of the
   * queue modifier, so holding shift appends the new order instead of
   * replacing the queue.
   */
  void CommandModeData::HandleEvent(CWldSession& session, const bool isDragUpdate)
  {
    const bool queueModifier = (mModifiers & COMMODMOD_Queue) != 0;
    const bool formationModifier = (mModifiers & COMMODMOD_Formation) != 0;
    const bool attackMoveModifier = (mModifiers & COMMODMOD_AttackMove) != 0;
    const bool clearQueue = !queueModifier;

    UserEntity* const hovered = DecodeHoveredDragEntity(mMouseDragStart);

    switch (mMode) {
      case COMMOD_Order:
        DispatchOrderCommandMode(
          *this, session, hovered, isDragUpdate, formationModifier, attackMoveModifier, queueModifier, clearQueue
        );
        return;

      case COMMOD_Build:
      case COMMOD_BuildAnchored:
        DispatchBuildCommandMode(*this, session, clearQueue);
        return;

      case COMMOD_Ping:
      // The jump table at 0x00821F04 routes mode 7 to the same entry as
      // `COMMOD_Ping`.
      case COMMOD_CancelCommandMode:
        UI_EndCommandMode();
        return;

      default:
        return;
    }
  }

  /**
   * Address: 0x0083E150 (FUN_0083E150, func_UserScriptCommandObj)
   *
   * What it does:
   * Builds one Lua command-issue descriptor table (`Units`, `Blueprint`,
   * `Target`, optional `LuaParams`, `CommandType`, `Clear`) used by UI script
   * command callbacks.
   */
  LuaPlus::LuaObject* BuildUserScriptCommandObject(
    LuaPlus::LuaObject* const outCommandObject,
    LuaPlus::LuaState* const state,
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    if (outCommandObject == nullptr || state == nullptr) {
      return outCommandObject;
    }

    outCommandObject->AssignNewTable(state, 0, 0);

    LuaPlus::LuaObject unitsTable;
    unitsTable.AssignNewTable(state, 0, 0);
    std::int32_t unitIndex = 1;
    for (UserUnit* const unit : units) {
      if (unit == nullptr) {
        ++unitIndex;
        continue;
      }

      IUnit* const iunitBridge = GetIUnitBridge(unit);
      if (iunitBridge == nullptr) {
        ++unitIndex;
        continue;
      }

      const LuaPlus::LuaObject unitLuaObject = iunitBridge->GetLuaObject();
      unitsTable.SetObject(unitIndex, unitLuaObject);
      ++unitIndex;
    }
    outCommandObject->SetObject("Units", unitsTable);

    const char* blueprintId = "";
    if (commandIssueData.mBlueprint != nullptr) {
      blueprintId = commandIssueData.mBlueprint->mBlueprintId.c_str();
    }
    outCommandObject->SetString("Blueprint", blueprintId);

    LuaPlus::LuaObject targetTable;
    targetTable.AssignNewTable(state, 0, 0);

    ESTITargetType targetType = static_cast<ESTITargetType>(static_cast<std::int32_t>(commandIssueData.mTarget.mType));
    gpg::RRef targetTypeRef{};
    targetTypeRef = gpg::MakeRRef<moho::ESTITargetType>(&targetType);
    const fa::string targetTypeLexical = targetTypeRef.GetLexical();
    targetTable.SetString("Type", targetTypeLexical.c_str());

    if (commandIssueData.mTarget.mType == EAiTargetType::AITARGET_Entity) {
      const EntId targetEntityId = static_cast<EntId>(commandIssueData.mTarget.mEntityId);
      if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
        if (UserEntity* const targetEntity = session->LookupEntityId(targetEntityId); targetEntity != nullptr) {
          const fa::string entityIdLexical = gpg::STR_Printf("%d", static_cast<std::int32_t>(targetEntityId));
          targetTable.SetString("EntityId", entityIdLexical.c_str());

          const LuaPlus::LuaObject targetPositionObject =
            SCR_ToLua<Wm3::Vector3<float>>(state, targetEntity->mVariableData.mCurTransform.pos_);
          targetTable.SetObject("Position", targetPositionObject);
        }
      }
    } else {
      const LuaPlus::LuaObject targetPositionObject =
        SCR_ToLua<Wm3::Vector3<float>>(state, commandIssueData.mTarget.mPos);
      targetTable.SetObject("Position", targetPositionObject);
    }

    outCommandObject->SetObject("Target", targetTable);

    if (commandIssueData.mObject.m_state != nullptr) {
      const LuaPlus::LuaObject luaParams = SCR_Copy(commandIssueData.mObject, state);
      outCommandObject->SetObject("LuaParams", luaParams);
    }

    EUnitCommandType commandType = commandIssueData.mCommandType;
    gpg::RRef commandTypeRef{};
    commandTypeRef = gpg::MakeRRef<moho::EUnitCommandType>(&commandType);
    const fa::string commandTypeLexical = commandTypeRef.GetLexical();
    outCommandObject->SetString("CommandType", commandTypeLexical.c_str());
    outCommandObject->SetBoolean("Clear", doClear);
    return outCommandObject;
  }

  /**
   * Address: 0x0083E640 (FUN_0083E640,
   * ?UI_VerifyScriptCommand@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$fastvector@PAVUserUnit@Moho@@@gpg@@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Builds one script command descriptor from explicit `UserUnit*` lanes,
   * calls `/lua/user/UserScriptCommand.lua:VerifyScriptCommand`, and returns
   * the Lua result object (or the command descriptor on callback failure).
   */
  LuaPlus::LuaObject UI_VerifyScriptCommand(
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
    LuaPlus::LuaState* const state = (uiManager != nullptr) ? uiManager->mLuaState : nullptr;
    LuaPlus::LuaObject commandObject{};
    (void)BuildUserScriptCommandObject(&commandObject, state, units, commandIssueData, doClear);

    if (state == nullptr) {
      return commandObject;
    }

    LuaPlus::LuaObject commandModule = SCR_Import(state, "/lua/user/UserScriptCommand.lua");
    LuaPlus::LuaObject verifyScriptCommand = commandModule["VerifyScriptCommand"];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> verifyScriptCommandFn(verifyScriptCommand);
    try {
      return verifyScriptCommandFn.Call_Object_Obj(commandObject);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/user/UserScriptCommand.lua:VerifyScriptCommand': %s",
        exception.what() != nullptr ? exception.what() : "<unknown>"
      );
    } catch (...) {
      gpg::Warnf("Error running '/lua/user/UserScriptCommand.lua:VerifyScriptCommand': %s", "<unknown>");
    }

    return commandObject;
  }

  /**
   * Address: 0x0083E500 (FUN_0083E500,
   * ?UI_VerifyScriptCommand@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes and forwards to the explicit-unit `UI_VerifyScriptCommand` overload.
   */
  LuaPlus::LuaObject UI_VerifyScriptCommand(
    const WeakSet<UserEntity>& entities,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = static_cast<std::int32_t>(entities.Size());
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    for (UserEntity* const selectedEntity : entities) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }
    }

    return UI_VerifyScriptCommand(selectedUnits, commandIssueData, doClear);
  }

  /**
   * Address: 0x0083E770 (FUN_0083E770,
   * ?UI_OnCommandIssued@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Builds one Lua command descriptor table from explicit `UserUnit*` lanes and
   * invokes `/lua/ui/game/commandmode.lua:OnCommandIssued`.
   */
  void UI_OnCommandIssued(
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
    LuaPlus::LuaState* const state = (uiManager != nullptr) ? uiManager->mLuaState : nullptr;
    if (state == nullptr) {
      return;
    }

    LuaPlus::LuaObject commandObject{};
    (void)BuildUserScriptCommandObject(&commandObject, state, units, commandIssueData, doClear);

    LuaPlus::LuaObject commandModeModule = SCR_Import(state, "/lua/ui/game/commandmode.lua");
    LuaPlus::LuaObject onCommandIssued = commandModeModule["OnCommandIssued"];
    LuaPlus::LuaFunction callback(onCommandIssued);

    try {
      callback.Call_Object(commandObject);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/ui/game/commandmode.lua:OnCommandIssued': %s",
        exception.what() != nullptr ? exception.what() : "<unknown>"
      );
    } catch (...) {
      gpg::Warnf("Error running '/lua/ui/game/commandmode.lua:OnCommandIssued': %s", "<unknown>");
    }
  }

  /**
   * Address: 0x0083E870 (FUN_0083E870,
   * ?UI_OnCommandIssued@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes and forwards to the explicit-unit `UI_OnCommandIssued` overload.
   */
  void UI_OnCommandIssued(
    const WeakSet<UserEntity>& entities,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = static_cast<std::int32_t>(entities.Size());
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    for (UserEntity* const selectedEntity : entities) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }
    }

    UI_OnCommandIssued(selectedUnits, commandIssueData, doClear);
  }

  /**
   * Address: 0x008B05E0 (FUN_008B05E0,
   * ?ISSUE_Command@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_Command(WeakSet_UserEntity *entities@<ebx>,
   *     SSTICommandIssueData *data, BOOL clearQueue);
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*` lanes
   * (inline-buffered fastvector, capacity pre-reserved from the set size) and
   * forwards to the explicit-unit `ISSUE_Command(fastvector)` overload, which
   * takes the command payload by value (copy-constructed on the stack here).
   */
  void ISSUE_Command(
    const WeakSet<UserEntity>& entities,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = static_cast<std::int32_t>(entities.Size());
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    for (UserEntity* const selectedEntity : entities) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }
    }

    ISSUE_Command(selectedUnits, commandIssueData, clearQueue);
  }

  /**
   * Address: 0x00865920 (FUN_00865920, ?ReleaseDrag@CWldSession@Moho@@QAEXW4EMauiEventModifier@2@@Z)
   */
  void CWldSession::ReleaseDrag(const EMauiEventModifier modifiers)
  {
    constexpr std::uint32_t kShiftMask = static_cast<std::uint32_t>(MEM_Shift);
    constexpr std::uint32_t kCtrlMask = static_cast<std::uint32_t>(MEM_Ctrl);
    constexpr std::uint32_t kAltMask = static_cast<std::uint32_t>(MEM_Alt);
    constexpr std::uint32_t kShiftCtrlMask = kShiftMask | kCtrlMask;

    const std::uint32_t modifierBits = static_cast<std::uint32_t>(modifiers);
    fa::vector<UserUnit*> nextSelection{};

    UserEntity* const hoveredEntity = this->GetHoveredUserEntity();
    UserUnit* const hoveredUnit = hoveredEntity != nullptr ? hoveredEntity->IsUserUnit() : nullptr;

    if (ui_DebugAltClick && (modifierBits & kAltMask) != 0u && hoveredEntity != nullptr) {
      UserArmy* const hoveredArmy = hoveredEntity->mArmy;
      if (hoveredArmy != nullptr && hoveredArmy != GetFocusUserArmy()) {
        SetSelectionUnits(nextSelection);
        RequestFocusArmy(static_cast<int>(hoveredArmy->mArmyIndex));
        return;
      }
    }

    if (!CanSelectUnit(hoveredUnit)) {
      if ((modifierBits & kShiftCtrlMask) == 0u) {
        SetSelectionUnits(nextSelection);
      }
      return;
    }

    if ((modifierBits & kCtrlMask) != 0u) {
      fa::vector<UserUnit*> currentSelection{};
      GetSelectionUnits(currentSelection);

      const IUnit* const hoveredBridge = GetIUnitBridge(hoveredUnit);
      const RUnitBlueprint* const targetBlueprint = hoveredBridge != nullptr ? hoveredBridge->GetBlueprint() : nullptr;

      if ((modifierBits & kShiftMask) != 0u) {
        if (ContainsUnitPtr(currentSelection, hoveredUnit)) {
          for (UserUnit* const selectedUnit : currentSelection) {
            const IUnit* const selectedBridge = GetIUnitBridge(selectedUnit);
            if (selectedBridge == nullptr || selectedBridge->GetBlueprint() != targetBlueprint) {
              AppendUnitUnique(nextSelection, selectedUnit);
            }
          }

          SetSelectionUnits(nextSelection);
          return;
        }

        nextSelection = currentSelection;
      }

      fa::vector<UserUnit*> allSessionUnits{};
      CollectSessionUserUnits(this, allSessionUnits);
      const UserArmy* const focusArmy = GetFocusUserArmy();
      for (UserUnit* const sessionUnit : allSessionUnits) {
        if (sessionUnit == nullptr || sessionUnit->IsBeingBuilt()) {
          continue;
        }

        const IUnit* const sessionBridge = GetIUnitBridge(sessionUnit);
        if (sessionBridge == nullptr || sessionBridge->IsDead()) {
          continue;
        }

        const UserEntity* const sessionEntity = reinterpret_cast<const UserEntity*>(sessionUnit);
        if (sessionEntity == nullptr || sessionEntity->mArmy != focusArmy) {
          continue;
        }

        if (sessionBridge->GetBlueprint() != targetBlueprint) {
          continue;
        }

        AppendUnitUnique(nextSelection, sessionUnit);
      }

      SetSelectionUnits(nextSelection);
      return;
    }

    if ((modifierBits & kShiftMask) != 0u) {
      GetSelectionUnits(nextSelection);
      if (ContainsUnitPtr(nextSelection, hoveredUnit)) {
        RemoveUnitIfPresent(nextSelection, hoveredUnit);
      } else {
        AppendUnitUnique(nextSelection, hoveredUnit);
      }
    } else {
      AppendUnitUnique(nextSelection, hoveredUnit);
    }

    SetSelectionUnits(nextSelection);
  }

  /**
   * Address: 0x00865E20 (FUN_00865E20, ?HandleDoubleClickSelection@CWldSession@Moho@@QAEXPAVCameraImpl@2@@Z)
   */
  void CWldSession::HandleDoubleClickSelection(CameraImpl* const camera)
  {
    UserEntity* const hoveredEntity = this->GetHoveredUserEntity();
    if (hoveredEntity == nullptr) {
      return;
    }

    UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit();
    if (hoveredUnit == nullptr) {
      return;
    }

    // FAF hot-patch (FA-Binary-Patches WallSelection): the stock early return for a WALL unit
    // (`jne 0x00866002` after IsInCategory("WALL")) is NOPed at 0x00865EC2, so double-clicking
    // a wall selects all walls of that type on screen. The category test itself has no effect.

    if (hoveredEntity->mArmy != GetFocusUserArmy()) {
      return;
    }

    const IUnit* const hoveredBridge = GetIUnitBridge(hoveredUnit);
    if (hoveredBridge == nullptr) {
      return;
    }

    const RUnitBlueprint* const targetBlueprint = hoveredBridge->GetBlueprint();
    fa::vector<UserUnit*> nextSelection{};
    GetSelectionUnits(nextSelection);

    auto* const frustumUnits = camera != nullptr ? camera->GetArmyUnitsInFrustum() : nullptr;
    if (frustumUnits != nullptr) {
      for (const WeakPtr<UserEntity>& weakRef : *frustumUnits) {
        UserEntity* const entity = weakRef.GetObjectPtr();
        if (entity == nullptr) {
          continue;
        }

        UserUnit* const unit = entity->IsUserUnit();
        if (unit == nullptr || unit == hoveredUnit) {
          continue;
        }

        IUnit* const unitBridge = GetIUnitBridge(unit);
        if (unitBridge == nullptr || unitBridge->IsDead() || unitBridge->DestroyQueued()) {
          continue;
        }

        if (!CanSelectUnit(unit)) {
          continue;
        }

        if (unitBridge->GetBlueprint() != targetBlueprint) {
          continue;
        }

        if (unitBridge->IsUnitState(UNITSTATE_BeingUpgraded)) {
          continue;
        }

        AppendUnitUnique(nextSelection, unit);
      }
    }

    SetSelectionUnits(nextSelection);
  }

  /**
   * Address: 0x0081F7B0 (FUN_0081F7B0,
   * ?GetLeftMouseButtonAction@CWldSession@Moho@@QAEAAUCommandModeData@2@PAU32@PBUstruct_MouseInfo@@H@Z)
   */
  CommandModeData* CWldSession::GetLeftMouseButtonAction(
    CommandModeData* const outMode, const MouseInfo* const mouseInfo, const int modifiers
  )
  {
    if (!outMode) {
      return nullptr;
    }

    CommandModeData mode{};
    mode.mMode = COMMOD_None;
    mode.mCommandCaps = RULEUCC_None;
    mode.mBlueprint = nullptr;
    mode.mModifiers = modifiers;
    mode.mIsDragged = -1;
    mode.mReserved5C = -1;
    mode.mMouseDragEnd = MouseInfo{};
    mode.mMouseDragEnd.mIsDragger = -1;

    if (mouseInfo) {
      mode.mMouseDragStart = *mouseInfo;
      mode.mIsDragged = mouseInfo->mIsDragger;

      if (mouseInfo->mHitValid != 0u) {
        bool resolvedByUi = false;
        if (mState && FocusArmy >= 0) {
          const std::size_t focusIndex = static_cast<std::size_t>(FocusArmy);
          if (focusIndex < userArmies.size() && userArmies[focusIndex] != nullptr) {
            UICommandModeData uiMode{};
            UI_GetCommandMode(uiMode);
            {
              if (uiMode.mMode.empty()) {
                resolvedByUi = false;
              } else if (uiMode.mMode == "order") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Order;

                // 0x0081F91C-0x0081F965: the command name is never compared
                // against a fixed list. It is decoded through reflection
                // straight into `mode.mCommandCaps`:
                //
                //   0x0081F947  call LuaObject::GetString      ; the "name" field
                //   0x0081F94E  lea  eax, [esp+mode.mCommandCaps]
                //   0x0081F956  call gpg::RRef_ERuleBPUnitCommandCaps
                //   0x0081F962  mov  eax, [edx+14h]            ; RType::SetLexical
                //   0x0081F965  call eax
                //
                // The enum registers its lexicals as "RULEUCC_Move",
                // "RULEUCC_Repair", ... (RUnitBlueprintEnumTypeInfo.cpp), which
                // is exactly what the UI sends. The previous two strcmps looked
                // for bare "Transport"/"CallTransport" and so matched nothing at
                // all: every command-panel order - repair, reclaim, guard,
                // patrol, move - resolved with mCommandCaps left at
                // RULEUCC_None and was silently dropped.
                LuaPlus::LuaObject commandName = moho::SCR_GetLuaTableField(mState, uiMode.mPayload, "name");
                if (const char* const commandCapsName = commandName ? commandName.GetString() : nullptr;
                    commandCapsName != nullptr) {
                  gpg::RRef capsRef{};
                  capsRef = gpg::MakeRRef<moho::ERuleBPUnitCommandCaps>(&mode.mCommandCaps);
                  if (capsRef.mType != nullptr) {
                    (void)capsRef.mType->SetLexical(capsRef, commandCapsName);
                  }
                }
              } else if (uiMode.mMode == "build" || uiMode.mMode == "buildanchored") {
                resolvedByUi = true;
                LuaPlus::LuaObject blueprintNameField = moho::SCR_GetLuaTableField(mState, uiMode.mPayload, "name");
                if (blueprintNameField && blueprintNameField.IsString()) {
                  const char* const blueprintName = blueprintNameField.GetString();
                  RResId blueprintId{};
                  blueprintId.name = blueprintName ? blueprintName : "";

                  void* const blueprint =
                    mRules ? static_cast<RRuleGameRules*>(mRules)->GetUnitBlueprint(blueprintId) : nullptr;
                  if (blueprint) {
                    mode.mMode = (uiMode.mMode == "build") ? COMMOD_Build : COMMOD_BuildAnchored;
                    mode.mBlueprint = blueprint;
                  }
                }
              } else if (uiMode.mMode == "ping") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Ping;
              } else if (!uiMode.mMode.empty()) {
                resolvedByUi = true;
                gpg::Warnf("CWldSession::GetLeftMouseButtonAction invalid command mode: %s", uiMode.mMode.c_str());
              }
            }
          }
        }

        if (!resolvedByUi) {
          mode.mMode = DefaultModeFromDrag(mouseInfo->mIsDragger);
        }
      }
    }

    *outMode = mode;
    return outMode;
  }
}



/**
 * Address: 0x0081EC00 (FUN_0081EC00, func_GetRightMouseButtonAction)
 * Mangled: ?func_GetRightMouseButtonAction@@... (referenced at global scope)
 *
 * IDA signature:
 * Moho::SCommandModeData *__cdecl func_GetRightMouseButtonAction(
 *     Moho::SCommandModeData *commandData, Moho::UICursorInfo *mouseInfo,
 *     int modifiers, Moho::CWldSession *wldSession);
 *
 * What it does:
 * Resolves the command a right-mouse click issues for the current selection
 * given the cursor state (hover target, drag id, modifiers). Walks the selected
 * set to accumulate the union of command-caps, then applies the attack /
 * capture / reclaim / transport / repair / guard / move precedence against the
 * hovered entity (or the pending command-manager helper when there is no hover)
 * and writes the resolved SCommandModeData into `out`. This symbol is
 * referenced by the linker at global scope (not inside namespace moho), so the
 * definition stays at global scope.
 */
moho::CommandModeData* func_GetRightMouseButtonAction(
  moho::CommandModeData* out, moho::MouseInfo* mouseInfo, int modifiers, moho::CWldSession* wldSession)
{
  using namespace moho;

  // Seed defaults from the cursor snapshot + modifiers (FUN_0081CEA0).
  CommandModeData commandModeData(*mouseInfo, modifiers);

  // No valid focus army (observer) -> return the default (empty) command mode.
  if (wldSession->FocusArmy < 0 || wldSession->userArmies[wldSession->FocusArmy] == nullptr) {
    *out = commandModeData;
    return out;
  }

  // An active UI command mode (a build placement, a ping, a targeting order the
  // UI started) does not resolve a right-click into an order - it resolves it
  // into "cancel the mode you are in".
  //
  //     0x0081ED4E  mov [esp+commandModeData.mMode], 7
  //     0x0081ED56  call SCommandModeData::SCommandModeData(out, &commandModeData)
  //
  // `CommandModeData::HandleEvent` routes mode 7 to `UI_EndCommandMode`, so the
  // matching right-button release tears the placement down. Returning `out`
  // untouched left it `COMMOD_None`, and the release arm skips `COMMOD_None`
  // entirely - which is why right-clicking never discarded a building you were
  // about to place.
  UICommandModeData commandMode{};
  UI_GetCommandMode(commandMode);
  if (!commandMode.mMode.empty()) {
    commandModeData.mMode = COMMOD_CancelCommandMode;
    *out = commandModeData;
    return out;
  }

  // Accumulate the union of command caps over every live selected user-unit.
  // `categoryOrdinals` collects each selected blueprint's category-bit index;
  // the binary keeps this side effect but never reads the set for a decision
  // (dead accumulation), so it is built and then destructed at scope end.
  BVIntSet categoryOrdinals;
  ERuleBPUnitCommandCaps selectionCommandCaps = RULEUCC_None;
  {
    for (UserEntity* const selectedEntity : wldSession->mSelection) {
      (void)categoryOrdinals.Add(static_cast<unsigned int>(selectedEntity->mParams.mBlueprint->mCategoryBitIndex));
      if (UserUnit* const selectedUnit = selectedEntity->IsUserUnit()) {
        selectionCommandCaps = static_cast<ERuleBPUnitCommandCaps>(
          selectionCommandCaps | GetIUnitBridge(selectedUnit)->GetAttributes().commandCapsMask
        );
      }
    }
  }

  UserEntity* const hoverEntity = mouseInfo->HoveredEntity();

  if (hoverEntity == nullptr) {
    // No hover: consult the command the cursor is dragging. An attack/form-
    // attack command with an attack-capable selection resolves to an
    // Order+Attack; otherwise fall through to the move tail.
    //
    // 0x0081F513..0x0081F565: `mCommandManager->mCommands.find(mIsDragger)`
    // (0x008B6160), then the command type through `sub_8B4140` -- called
    // twice, once per comparison -- so a pending local SetCommandType edit
    // counts, not just the replicated `mVariableData.mCmdType`.
    CommandManager* const commandManager = wldSession->mCommandManager;
    UserCommandIssueHelper* const helper =
      commandManager != nullptr ? FindCommandIssueHelper(*commandManager, mouseInfo->mIsDragger) : nullptr;
    if (helper != nullptr
        && (ResolveCommandIssueHelperCommandType(*helper) == EUnitCommandType::UNITCOMMAND_Attack
            || ResolveCommandIssueHelperCommandType(*helper) == EUnitCommandType::UNITCOMMAND_FormAttack)
        && (selectionCommandCaps & RULEUCC_Attack) != 0) {
      commandModeData.mMode = COMMOD_Order;
      commandModeData.mCommandCaps = RULEUCC_Attack;
    } else if ((selectionCommandCaps & RULEUCC_Move) != 0) {
      commandModeData.mMode = COMMOD_Order;
      commandModeData.mCommandCaps = RULEUCC_Move;
    }
    commandModeData.mIsDragged = mouseInfo->mIsDragger;
    *out = commandModeData;
    return out;
  }

  // --- Hover branch --------------------------------------------------------
  const bool isBeingBuilt = hoverEntity->IsBeingBuilt();
  const bool isFerryBeacon = hoverEntity->IsInCategory(fa::string("FERRYBEACON"));
  const bool isCampaignGate = hoverEntity->IsInCategory(fa::string("CAMPAIGNGATE"));

  // Reclaim eligibility: RECLAIMABLE (or under-construction) targets are
  // reclaim-valid; everything else is not.
  bool reclaimTargetValid = true;
  if (hoverEntity->mParams.mBlueprint != nullptr) {
    const bool reclaimable =
      hoverEntity->IsInCategory(fa::string("RECLAIMABLE")) || hoverEntity->IsBeingBuilt();
    if (!reclaimable) {
      reclaimTargetValid = false;
    }
  } else {
    reclaimTargetValid = false;
  }

  bool mCapturable = false;
  if (UserUnit* const hoverUnitForCaps = hoverEntity->IsUserUnit()) {
    mCapturable = GetIUnitBridge(hoverUnitForCaps)->GetAttributes().mCapturable;
    // When the unit is busy it is neither reclaimable nor capturable via
    // right-click.
    if (hoverEntity->IsUserUnit()->mUnitVarDat.mIsBusy) {
      reclaimTargetValid = false;
      mCapturable = false;
    }
  }

  bool isEnemy = false;
  bool isAlly = false;
  UserArmy* const focusArmy =
    (wldSession->FocusArmy < 0) ? nullptr : wldSession->userArmies[wldSession->FocusArmy];
  UserArmy* const hoverArmy = hoverEntity->mArmy;
  if (hoverArmy != nullptr && focusArmy != nullptr) {
    isEnemy = focusArmy->IsEnemy(hoverArmy->mArmyIndex);
    isAlly = focusArmy->IsAlly(hoverArmy->mArmyIndex);
  }

  UserUnit* const hoverUnit = hoverEntity->IsUserUnit();

  bool resolved = false;

  if (!(isEnemy && (selectionCommandCaps & RULEUCC_Attack) != 0
        && AnySelectedUnitCanAttackHover(hoverEntity, wldSession))) {
    // Capture: a non-allied, finished, capturable target with capture-capable
    // selection resolves to Order+Capture.
    if (!isAlly && !isBeingBuilt && mCapturable && (selectionCommandCaps & RULEUCC_Capture) != 0) {
      commandModeData.mMode = COMMOD_Order;
      commandModeData.mCommandCaps = RULEUCC_Capture;
      resolved = true;
    }

    // Reclaim: enemy / ownerless / reclaim-friendly targets that are reclaim
    // valid with reclaim-capable selection resolve to Order+Reclaim.
    if (!resolved) {
      const bool reclaimEligible =
        (isEnemy || hoverArmy == nullptr || hoverEntity->IsInCategory(fa::string("RECLAIMFRIENDLY")))
        && reclaimTargetValid && (selectionCommandCaps & RULEUCC_Reclaim) != 0;
      if (reclaimEligible) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_Reclaim;
        resolved = true;
      }
    }

    // Transport chains only apply when the hover target belongs to the focus army.
    if (!resolved && hoverArmy == focusArmy) {
      if ((selectionCommandCaps & RULEUCC_CallTransport) != 0
          && SelectionHasTransportForTarget(&wldSession->mSelection, hoverEntity)) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_CallTransport;
        resolved = true;
      } else if (hoverUnit != nullptr
                 && (GetIUnitBridge(hoverUnit)->GetAttributes().commandCapsMask & RULEUCC_CallTransport) != 0
                 && HoverTransportAcceptsSelection(&wldSession->mSelection, hoverEntity)) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_Transport;
        resolved = true;
      } else if (isFerryBeacon && AllSelectedAreFactories(&wldSession->mSelection, wldSession)) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_CallTransport;
        resolved = true;
      }
    }

    const ERuleBPUnitCommandCaps selectionCommandCapsTail = selectionCommandCaps;

    if (!resolved) {
      if (isEnemy) {
        // Attack-capable but nothing in the selection can actually attack the
        // hover -> mark the order invalid (immediate 0x01000000 = RULEUCC_Invalid).
        if ((selectionCommandCaps & RULEUCC_Attack) != 0
            && !AnySelectedUnitCanAttackHover(hoverEntity, wldSession)) {
          commandModeData.mMode = COMMOD_Order;
          commandModeData.mCommandCaps = RULEUCC_Invalid;
          resolved = true;
        }
        // else: fall through to the move tail.
      } else {
        const std::int32_t guardCap = selectionCommandCaps & RULEUCC_Guard;

        if (!OPTIONS_GetBool("switch_right_click_behavior")) {
          // Normal right-click behavior.
          const std::int32_t repairCap = selectionCommandCapsTail & RULEUCC_Repair;

          // Repair-if-under-construction: repair-capable selection over an
          // under-construction target that is mobile, or neither factory nor silo.
          bool repairUnderConstruction = false;
          if (repairCap != 0 && hoverEntity->IsBeingBuilt()) {
            if (UserUnit* const builtUnit = hoverEntity->IsUserUnit()) {
              if (GetIUnitBridge(builtUnit)->IsMobile()
                  || (!hoverEntity->IsInCategory(fa::string("FACTORY"))
                      && !hoverEntity->IsInCategory(fa::string("SILO")))) {
                repairUnderConstruction = true;
              }
            }
          }
          if (repairUnderConstruction) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Repair;
            resolved = true;
          }

          // Guard: guard-capable selection over a non-campaign-gate hovered unit
          // that is not the first selection member, while a formation is active.
          if (!resolved && guardCap != 0 && !isCampaignGate && hoverUnit != nullptr
              && !wldSession->UnitFirstInSelection(hoverUnit)
              && wldSession->mCurFormation->mTimeLeft > 0.0f) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Guard;
            resolved = true;
          }

          // Repair (finished target): allied damaged target, or a hovered unit
          // that reports the upgrading unit-state.
          if (!resolved && repairCap != 0
              && ((isAlly && hoverEntity->mVariableData.mMaxHealth > hoverEntity->mVariableData.mHealth)
                  || (hoverUnit != nullptr
                      && GetIUnitBridge(hoverUnit)->IsUnitState(UNITSTATE_Upgrading)))) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Repair;
            resolved = true;
          }
          // else: fall through to the move tail.
        } else {
          // Switched right-click behavior: repair is prioritised over guard.
          if ((selectionCommandCapsTail & RULEUCC_Repair) != 0
              && ((isAlly && hoverEntity->mVariableData.mMaxHealth > hoverEntity->mVariableData.mHealth)
                  || (hoverUnit != nullptr
                      && GetIUnitBridge(hoverUnit)->IsUnitState(UNITSTATE_Upgrading)))) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Repair;
            resolved = true;
          } else if (guardCap != 0) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Guard;
            resolved = true;
          }
          // else: fall through to the move tail.
        }
      }
    }

    // Move tail: a move-capable selection defaults to Order+Move.
    if (!resolved) {
      if ((selectionCommandCapsTail & RULEUCC_Move) != 0) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_Move;
      }
      resolved = true;
    }
  } else {
    // Enemy target, attack-capable selection that can attack it -> Order+Attack.
    commandModeData.mMode = COMMOD_Order;
    commandModeData.mCommandCaps = RULEUCC_Attack;
    resolved = true;
  }

  // Finalize: stamp the drag id and copy the resolved state out.
  commandModeData.mIsDragged = mouseInfo->mIsDragger;
  *out = commandModeData;
  return out;
}
