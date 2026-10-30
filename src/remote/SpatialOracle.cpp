#include "remote/SpatialOracle.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>

#include "moho/entity/EVisibilityModeTypeInfo.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/math/GridPos.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/Sim.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode: see SpatialOracle.h. Which entity goes in which list follows
// the branches of `ResolveViewVisibility` and `CanViewSee` (VisibilityOracle.cpp) for a view
// with its own army and vision grid; every candidate is then admitted by `CanViewSee` itself.

namespace faf::remote
{
  namespace
  {
    // Neighbour cells tested around an entity's cell. The cell is computed exactly as
    // `ViewCanSeePoint` computes it, so 0 would do while `Build` and the query run under the
    // same FPU mode; the margin keeps a one-cell difference in the float-to-cell step (x87
    // precision or rounding control, `GridPos` 0x00506E20) from dropping a candidate.
    constexpr std::int32_t kCellMargin = 1;

    [[nodiscard]] bool IsReconGrid(const std::int32_t viz) noexcept
    {
      return static_cast<moho::EUserEntityVisibilityMode>(viz) == moho::EUserEntityVisibilityMode::ReconGrid;
    }

    /** Which list a plain entity (neither unit nor blip) goes in. */
    enum class EGridUse
    {
      Never, // no view with an army can be sent it
      Cells, // sent only through a grid test: indexed by cell
      Free,  // some view is sent it without a grid test: tested for every view
    };

    /**
     * The viz channels `ResolveEntityChannel` can pick for a view with an army (0x00678A70):
     * the neutral one alone for an entity with no army, else the own-army one or the one for
     * the alliance. A channel publishes when it is not Never, or always for an entity with no
     * army and for a prop (`Prop::Sync` 0x006FA2A0); a published channel other than ReconGrid
     * is sent without a grid test (`CanViewSee`).
     */
    [[nodiscard]] EGridUse ClassifyGridUse(moho::Entity& entity)
    {
      const bool publishesAnyMode = entity.ArmyRef == nullptr || entity.IsProp() != nullptr;

      std::int32_t channels[4] = {entity.mVizToNeutrals, 0, 0, 0};
      std::size_t channelCount = 1;
      if (entity.ArmyRef != nullptr) {
        channels[1] = entity.mVizToFocusPlayer;
        channels[2] = entity.mVizToAllies;
        channels[3] = entity.mVizToEnemies;
        channelCount = 4;
      }

      bool gridTested = false;
      for (std::size_t index = 0; index < channelCount; ++index) {
        const std::int32_t viz = channels[index];
        if (IsReconGrid(viz)) {
          gridTested = true;
        } else if (publishesAnyMode || viz != moho::VIZMODE_Never) {
          return EGridUse::Free;
        }
      }
      return gridTested ? EGridUse::Cells : EGridUse::Never;
    }

    /** Orders cell entries by layer, then z, then x, so one cell's entries are adjacent. */
    template <class TEntry>
    [[nodiscard]] bool CellLess(const TEntry& lhs, const TEntry& rhs) noexcept
    {
      if (lhs.mUnderwater != rhs.mUnderwater) {
        return rhs.mUnderwater;
      }
      if (lhs.mZ != rhs.mZ) {
        return lhs.mZ < rhs.mZ;
      }
      return lhs.mX < rhs.mX;
    }

    template <class TEntry>
    [[nodiscard]] bool SameCell(const TEntry& lhs, const TEntry& rhs) noexcept
    {
      return lhs.mUnderwater == rhs.mUnderwater && lhs.mZ == rhs.mZ && lhs.mX == rhs.mX;
    }

    /**
     * Whether `view` sees the cell or one within `kCellMargin` of it, through its own grid of
     * that layer or an ally's (`ViewCanSeeCell`, `UserArmy::CanSeeCell` 0x008B17F0).
     */
    [[nodiscard]] bool CellNearVisible(
      const moho::Sim& sim, const moho::CArmyImpl& view, const std::int32_t x, const std::int32_t z,
      const bool underwater
    )
    {
      constexpr std::int64_t kMin = std::numeric_limits<std::int32_t>::min();
      constexpr std::int64_t kMax = std::numeric_limits<std::int32_t>::max();
      for (std::int64_t cellZ = std::int64_t{z} - kCellMargin; cellZ <= std::int64_t{z} + kCellMargin; ++cellZ) {
        if (cellZ < kMin || cellZ > kMax) {
          continue;
        }
        for (std::int64_t cellX = std::int64_t{x} - kCellMargin; cellX <= std::int64_t{x} + kCellMargin; ++cellX) {
          if (cellX < kMin || cellX > kMax) {
            continue;
          }
          if (ViewCanSeeCell(
                sim, view, static_cast<std::int32_t>(cellX), static_cast<std::int32_t>(cellZ), underwater
              )) {
            return true;
          }
        }
      }
      return false;
    }
  } // namespace

  void CollectViewEntitiesBruteForce(const moho::Sim& sim, const std::int32_t viewArmy, std::vector<std::uint32_t>& outIds)
  {
    outIds.clear();
    if (sim.mEntityDB == nullptr) {
      return;
    }
    for (const auto& idAndEntity : sim.mEntityDB->mAllUnits) {
      moho::Entity* const entity = idAndEntity.second;
      if (entity != nullptr && CanViewSee(sim, viewArmy, *entity)) {
        outIds.push_back(static_cast<std::uint32_t>(entity->id_));
      }
    }
    std::sort(outIds.begin(), outIds.end());
  }

  void SpatialOracle::Build(const moho::Sim& sim)
  {
    const std::size_t armyCount = sim.mArmiesList.size();
    mUnitsByArmy.assign(armyCount, {});
    mFlushedBlipsByArmy.assign(armyCount, {});
    mGridFree.clear();
    mCellIndices.clear();

    // One cell index per vision-grid size a view can use (`ViewCanSeePoint` maps the point at
    // the view's own vision-grid size).
    for (const moho::CArmyImpl* const army : sim.mArmiesList) {
      const moho::CIntelGrid* const visionGrid = army != nullptr ? army->mConstDat.mVisionReconGrid.get() : nullptr;
      if (visionGrid != nullptr && FindCellIndex(visionGrid->mGridSize) == nullptr) {
        SCellIndex index;
        index.mGridSize = visionGrid->mGridSize;
        mCellIndices.push_back(std::move(index));
      }
    }

    if (sim.mEntityDB == nullptr) {
      return;
    }

    for (const auto& idAndEntity : sim.mEntityDB->mAllUnits) {
      moho::Entity* const entity = idAndEntity.second;
      if (entity == nullptr) {
        continue; // an id reserved before its entity is constructed
      }
      // `Entity::Sync` (0x0067A0A0): an entity in its destroy pass is published to no view.
      if (entity->mOnDestroyDispatched != 0u) {
        continue;
      }

      // The order of `ResolveViewVisibility`: a prop is decided as a prop, then units, then blips.
      if (entity->IsProp() == nullptr) {
        if (entity->IsUnit() != nullptr) {
          // `Unit::UpdateVisibility` (0x006ABC30): published to its own army's view only. A unit
          // without an army goes to the exact test like anything else not proven here.
          if (entity->ArmyRef == nullptr) {
            mGridFree.push_back(entity);
            continue;
          }
          const std::int32_t armyIndex = entity->ArmyRef->mConstDat.mArmyIndex;
          if (armyIndex >= 0 && static_cast<std::size_t>(armyIndex) < armyCount) {
            mUnitsByArmy[static_cast<std::size_t>(armyIndex)].push_back(entity);
          }
          continue;
        }
        if (const moho::ReconBlip* const blip = entity->IsReconBlip(); blip != nullptr) {
          // `ReconBlip::UpdateVisibility` (0x005BEE40): published while that army's record needs
          // a flush.
          const std::size_t recordCount = std::min<std::size_t>(blip->mReconDat.size(), armyCount);
          for (std::size_t armyIndex = 0; armyIndex < recordCount; ++armyIndex) {
            if (blip->mReconDat[armyIndex].mNeedsFlush != 0u) {
              mFlushedBlipsByArmy[armyIndex].push_back(entity);
            }
          }
          continue;
        }
      }

      switch (ClassifyGridUse(*entity)) {
        case EGridUse::Free:
          mGridFree.push_back(entity);
          break;

        case EGridUse::Cells: {
          const bool underwater = entity->mVarDat.UsesUnderwaterReconGrid();
          for (SCellIndex& index : mCellIndices) {
            Wm3::Vec3f cellPos = entity->mVarDat.mCurTransform.pos_;
            const moho::GridPos cell(&cellPos, static_cast<int>(index.mGridSize));
            SCellEntity entry;
            entry.mX = cell.x;
            entry.mZ = cell.z;
            entry.mUnderwater = underwater;
            entry.mEntity = entity;
            index.mEntries.push_back(entry);
          }
          break;
        }

        case EGridUse::Never:
          break;
      }
    }

    for (SCellIndex& index : mCellIndices) {
      std::sort(index.mEntries.begin(), index.mEntries.end(), CellLess<SCellEntity>);
    }
  }

  const SpatialOracle::SCellIndex* SpatialOracle::FindCellIndex(const std::uint32_t gridSize) const noexcept
  {
    for (const SCellIndex& index : mCellIndices) {
      if (index.mGridSize == gridSize) {
        return &index;
      }
    }
    return nullptr;
  }

  void SpatialOracle::CollectViewEntities(
    const moho::Sim& sim, const std::int32_t viewArmy, std::vector<std::uint32_t>& outIds
  ) const
  {
    // `ViewCanSeePoint`: a view with no army or no vision grid sees every point, so the grid
    // cannot narrow anything: brute force.
    const msvc8::vector<moho::CArmyImpl*>& armies = sim.mArmiesList;
    const moho::CArmyImpl* view = nullptr;
    if (viewArmy >= 0 && static_cast<std::size_t>(viewArmy) < armies.size()) {
      view = armies[static_cast<std::size_t>(viewArmy)];
    }
    const moho::CIntelGrid* const visionGrid = view != nullptr ? view->mConstDat.mVisionReconGrid.get() : nullptr;
    const SCellIndex* const cells = visionGrid != nullptr ? FindCellIndex(visionGrid->mGridSize) : nullptr;
    if (cells == nullptr || static_cast<std::size_t>(viewArmy) >= mUnitsByArmy.size()) {
      CollectViewEntitiesBruteForce(sim, viewArmy, outIds);
      return;
    }

    outIds.clear();
    const auto admit = [&](moho::Entity* const entity) {
      if (CanViewSee(sim, viewArmy, *entity)) {
        outIds.push_back(static_cast<std::uint32_t>(entity->id_));
      }
    };

    const auto armySlot = static_cast<std::size_t>(viewArmy);
    for (moho::Entity* const entity : mUnitsByArmy[armySlot]) {
      admit(entity);
    }
    for (moho::Entity* const entity : mFlushedBlipsByArmy[armySlot]) {
      admit(entity);
    }
    for (moho::Entity* const entity : mGridFree) {
      admit(entity);
    }

    // One visibility test per occupied cell, then the exact test for each entity in it.
    const std::vector<SCellEntity>& entries = cells->mEntries;
    for (std::size_t first = 0; first < entries.size();) {
      std::size_t last = first + 1;
      while (last < entries.size() && SameCell(entries[last], entries[first])) {
        ++last;
      }
      const SCellEntity& cell = entries[first];
      if (CellNearVisible(sim, *view, cell.mX, cell.mZ, cell.mUnderwater)) {
        for (std::size_t index = first; index < last; ++index) {
          admit(entries[index].mEntity);
        }
      }
      first = last;
    }

    // Each entity sits in exactly one of the lists this view reads, so no duplicates.
    std::sort(outIds.begin(), outIds.end());
  }
} // namespace faf::remote
