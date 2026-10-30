#include "remote/VisibilityOracle.h"

#include "moho/entity/EVisibilityModeTypeInfo.h"
#include "moho/entity/Entity.h"
#include "moho/math/GridPos.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

// Engine addition, server mode: see VisibilityOracle.h. Each step cites the function it
// reproduces; every write those functions make to the entity is a local value here.

namespace faf::remote
{
  namespace
  {
    [[nodiscard]] const moho::CArmyImpl* ArmyAt(const moho::Sim& sim, const std::int32_t armyIndex) noexcept
    {
      const msvc8::vector<moho::CArmyImpl*>& armies = sim.mArmiesList;
      if (armyIndex < 0 || static_cast<std::uint32_t>(armyIndex) >= armies.size()) {
        return nullptr;
      }
      return armies[static_cast<std::size_t>(armyIndex)];
    }

    /**
     * `Entity::UpdateVisibility` (0x00678A70) with `viewArmy` as the sync focus: the viz channel
     * for the view's relation to the entity's army, and whether that channel publishes.
     */
    [[nodiscard]] SViewVisibility ResolveEntityChannel(
      const moho::Sim& sim, const std::int32_t viewArmy, const moho::Entity& entity
    )
    {
      SViewVisibility result;

      // 0x00678A7D..0x00678A89: no owning army, the neutral channel, published whatever it is.
      if (entity.ArmyRef == nullptr) {
        result.mode = static_cast<moho::EUserEntityVisibilityMode>(entity.mVizToNeutrals);
        result.published = true;
        return result;
      }

      std::int32_t viz = 0;
      if (viewArmy == entity.GetArmyIndex() || viewArmy == -1) {
        // 0x00678AA4..0x00678AAF -> 0x00678B4A: the view's own entity, or no focus.
        viz = entity.mVizToFocusPlayer;
      } else {
        // 0x00678AB5..0x00678AF2: by the alliance of the entity's army with the view's army
        // (null when the index is outside the army list, as the binary passes it).
        switch (entity.ArmyRef->GetAllianceWith(ArmyAt(sim, viewArmy))) {
          case moho::ALLIANCE_Neutral:
            viz = entity.mVizToNeutrals;
            break;
          case moho::ALLIANCE_Ally:
            viz = entity.mVizToAllies;
            break;
          case moho::ALLIANCE_Enemy:
          default:
            viz = entity.mVizToEnemies;
            break;
        }
      }

      result.mode = static_cast<moho::EUserEntityVisibilityMode>(viz);
      result.published = viz != moho::VIZMODE_Never;
      return result;
    }

    /** Units and blips: a `UserUnit` on the client, which never tests the grid. */
    [[nodiscard]] bool IsClientUnit(moho::Entity& entity)
    {
      return entity.IsUnit() != nullptr || entity.IsReconBlip() != nullptr;
    }

    constexpr std::uint32_t kReconSeenNow = 0x08u;  // `UserUnit::mIntelStateFlags`, 0x008C09ED
    constexpr std::uint32_t kReconSeenEver = 0x10u; // 0x008C0A02
    constexpr std::uint32_t kUnitReconFlags = 28u;  // `Unit::SyncInterface`: every unit update

    /** The recon flags the client's `UserUnit` holds: the unit's fixed word, or the blip's record. */
    [[nodiscard]] std::uint32_t ClientReconFlags(const std::int32_t viewArmy, moho::Entity& entity)
    {
      const moho::ReconBlip* const blip = entity.IsReconBlip();
      if (blip == nullptr) {
        return kUnitReconFlags;
      }
      if (viewArmy < 0 || static_cast<std::uint32_t>(viewArmy) >= blip->mReconDat.size()) {
        return 0u;
      }
      return blip->mReconDat[static_cast<std::size_t>(viewArmy)].mReconFlags;
    }

    /**
     * `UserUnit::IsMobile` (0x008C04E0) on the blueprint the client unit was created with (the
     * entity's own, `ReconBlip::CreateInterface` / `Unit::CreateInterface`): motion types Land
     * through AmphibiousFloating.
     */
    [[nodiscard]] bool IsClientMobile(const moho::Entity& entity)
    {
      const auto* const blueprint = reinterpret_cast<const moho::RUnitBlueprint*>(entity.BluePrint);
      if (blueprint == nullptr) {
        return false;
      }
      const auto motionType = static_cast<std::uint32_t>(blueprint->Physics.MotionType);
      return (motionType - 1u) <= (static_cast<std::uint32_t>(moho::RULEUMT_AmphibiousFloating) - 1u);
    }
  } // namespace

  /**
   * `UserArmy::CanSeeCell` (0x008B17F0) on the sim's grids: the view's own vision (or water)
   * grid, then every other army that counts the view as an ally, where an ally without the
   * grid counts as seeing.
   */
  [[nodiscard]] bool ViewCanSeeCell(
    const moho::Sim& sim, const moho::CArmyImpl& view, const std::int32_t x, const std::int32_t z,
    const bool underwater
  )
  {
    const moho::SSTIArmyConstantData& own = view.mConstDat;
    const moho::CIntelGrid* const ownGrid =
      underwater ? own.mWaterReconGrid.get() : own.mVisionReconGrid.get();
    if (ownGrid != nullptr && ownGrid->IsVisible(x, z)) {
      return true;
    }

    // 0x008B186E..0x008B18B6: every army of the list but the view itself, kept when it lists
    // the view among its allies (`ally->IsAlly(view index)`, 0x008B18AB).
    const std::uint32_t viewIndex = static_cast<std::uint32_t>(own.mArmyIndex);
    for (const moho::CArmyImpl* const ally : sim.mArmiesList) {
      if (ally == nullptr || ally == &view || !ally->mVarDat.mAllies.Contains(viewIndex)) {
        continue;
      }
      const moho::CIntelGrid* const allyGrid =
        underwater ? ally->mConstDat.mWaterReconGrid.get() : ally->mConstDat.mVisionReconGrid.get();
      if (allyGrid == nullptr || allyGrid->IsVisible(x, z)) {
        return true;
      }
    }
    return false;
  }

  SViewVisibility ResolveViewVisibility(const moho::Sim& sim, const std::int32_t viewArmy, moho::Entity& entity)
  {
    SViewVisibility result = ResolveEntityChannel(sim, viewArmy, entity);

    if (entity.IsProp() != nullptr) {
      // `Prop::Sync` (0x006FA2A0) keeps a prop's interface until its destroy pass, whatever its
      // visibility flag says.
      result.published = entity.mOnDestroyDispatched == 0u;
      return result;
    }

    if (entity.IsUnit() != nullptr) {
      // `Unit::UpdateVisibility` (0x006ABC30): published to its own army, or with no focus.
      result.published = viewArmy == -1 || viewArmy == entity.ArmyRef->mConstDat.mArmyIndex;
    } else if (const moho::ReconBlip* const blip = entity.IsReconBlip(); blip != nullptr) {
      // `ReconBlip::UpdateVisibility` (0x005BEE40): published while the view's recon record
      // needs a flush, never with no focus.
      result.published = false;
      if (viewArmy != -1 && static_cast<std::uint32_t>(viewArmy) < blip->mReconDat.size()) {
        result.published = blip->mReconDat[static_cast<std::size_t>(viewArmy)].mNeedsFlush != 0u;
      }
    }

    // `Entity::Sync` (0x0067A0A0): an entity in its destroy pass loses its interface.
    if (entity.mOnDestroyDispatched != 0u) {
      result.published = false;
    }
    return result;
  }

  bool ViewCanSeePoint(const moho::Sim& sim, const std::int32_t viewArmy, const Wm3::Vec3f& pos, const bool underwater)
  {
    // `UserEntity::UpdateVisibility` (0x008B9580): no focus army, nothing is fogged.
    const moho::CArmyImpl* const view = ArmyAt(sim, viewArmy);
    if (view == nullptr) {
      return true;
    }

    // `UserArmy::CanSeePoint` (0x008B22B0): no vision grid sees everything; the cell comes from
    // the vision grid's size whichever grid is then tested.
    const moho::CIntelGrid* const visionGrid = view->mConstDat.mVisionReconGrid.get();
    if (visionGrid == nullptr) {
      return true;
    }
    Wm3::Vec3f cellPos = pos;
    const moho::GridPos cell(&cellPos, static_cast<int>(visionGrid->mGridSize));
    return ViewCanSeeCell(sim, *view, cell.x, cell.z, underwater);
  }

  bool CanViewSee(const moho::Sim& sim, const std::int32_t viewArmy, moho::Entity& entity)
  {
    const SViewVisibility visibility = ResolveViewVisibility(sim, viewArmy, entity);
    if (!visibility.published) {
      return false;
    }
    if (visibility.mode != moho::EUserEntityVisibilityMode::ReconGrid || IsClientUnit(entity)) {
      return true;
    }
    return ViewCanSeePoint(
      sim, viewArmy, entity.mVarDat.mCurTransform.pos_, entity.mVarDat.UsesUnderwaterReconGrid()
    );
  }

  bool ViewShowsMesh(const moho::Sim& sim, const std::int32_t viewArmy, moho::Entity& entity)
  {
    const SViewVisibility visibility = ResolveViewVisibility(sim, viewArmy, entity);
    if (!visibility.published) {
      return false;
    }

    const bool clientUnit = IsClientUnit(entity);
    switch (visibility.mode) {
      case moho::EUserEntityVisibilityMode::Hidden:
        return false;

      case moho::EUserEntityVisibilityMode::MapPlayableRect: {
        // `UserUnit::UpdateVisibility` 0x008C0A24: shown. `UserEntity::UpdateVisibility`: the
        // cell of the truncated position inside the playable rect, `[min, max)`.
        if (clientUnit) {
          return true;
        }
        const gpg::Rect2i& rect = sim.mMapData->mPlayableRect;
        const auto cellX = static_cast<std::int32_t>(entity.mVarDat.mCurTransform.pos_.x);
        const auto cellZ = static_cast<std::int32_t>(entity.mVarDat.mCurTransform.pos_.z);
        return cellX >= rect.x0 && cellX < rect.x1 && cellZ >= rect.z0 && cellZ < rect.z1;
      }

      case moho::EUserEntityVisibilityMode::ReconGrid: {
        if (!clientUnit) {
          return ViewCanSeePoint(
            sim, viewArmy, entity.mVarDat.mCurTransform.pos_, entity.mVarDat.UsesUnderwaterReconGrid()
          );
        }
        // 0x008C09CF..0x008C0A0A: a mobile unit shows on "seen now", a structure on "seen ever".
        const std::uint32_t flags = ClientReconFlags(viewArmy, entity);
        return IsClientMobile(entity) ? (flags & kReconSeenNow) != 0u : (flags & kReconSeenEver) != 0u;
      }

      default:
        // Both client functions leave the mesh as it was for any other mode.
        return true;
    }
  }
} // namespace faf::remote
