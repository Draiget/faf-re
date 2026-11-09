#include "remote/client/GridSnapshots.h"

#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/SimDriver.h"

// Engine addition, server mode: see GridSnapshots.h.

namespace faf::remote::client
{
  namespace
  {
    // A link that falls behind the sim (the GUI at high game speed takes several beats a frame) still
    // finds its beat; a link that stops taking does not grow this without end.
    constexpr std::size_t kMaxQueuedBeats = 256;
  }

  CGridSnapshots::~CGridSnapshots()
  {
    Uninstall();
  }

  void CGridSnapshots::Install()
  {
    mNext = moho::Sim::SyncObserver();
    moho::Sim::SetSyncObserver(this);
    mInstalled = true;
  }

  void CGridSnapshots::Uninstall()
  {
    if (mInstalled) {
      moho::Sim::SetSyncObserver(mNext); // waits for a walk in progress; the one replaced comes back
      mInstalled = false;
    }
  }

  void CGridSnapshots::OnEntityWillSync(moho::Entity& entity)
  {
    if (mNext != nullptr) {
      mNext->OnEntityWillSync(entity);
    }
  }

  void CGridSnapshots::OnEntitySynced(moho::Entity& entity)
  {
    if (mNext != nullptr) {
      mNext->OnEntitySynced(entity);
    }
  }

  void CGridSnapshots::OnSyncWalkDone(moho::Sim& sim, const moho::SSyncData& packet)
  {
    if (mNext != nullptr) {
      mNext->OnSyncWalkDone(sim, packet);
    }
    std::vector<wire::SGridSlot> grids;
    const std::int32_t view = sim.mSyncFilter.focusArmy;
    if (view >= 0) {
      for (std::size_t index = 0; index < sim.mArmiesList.size(); ++index) {
        const moho::CArmyImpl* const army = sim.mArmiesList[index];
        if (army == nullptr
            || (static_cast<std::int32_t>(index) != view && !army->mVarDat.mAllies.Contains(static_cast<unsigned int>(view)))) {
          continue;
        }
        const moho::CIntelGrid* const kinds[2] = {army->mConstDat.mVisionReconGrid.get(), army->mConstDat.mWaterReconGrid.get()};
        for (std::uint8_t kind = 0; kind < 2u; ++kind) {
          const moho::CIntelGrid* const grid = kinds[kind];
          if (grid == nullptr || grids.size() >= wire::kMaxGridSlots) {
            continue;
          }
          wire::SGridSlot& slot = grids.emplace_back();
          slot.army = static_cast<std::uint8_t>(index);
          slot.kind = kind;
          slot.gridSize = grid->mGridSize;
          slot.bits.width = grid->mWidth;
          slot.bits.height = grid->mHeight;
          slot.bits.cells.resize(static_cast<std::size_t>(grid->mWidth) * grid->mHeight);
          for (std::size_t cell = 0; cell < slot.bits.cells.size(); ++cell) {
            slot.bits.cells[cell] = grid->mGrid[cell] != 0 ? 1u : 0u;
          }
        }
      }
    }
    const std::lock_guard<std::mutex> guard(mLock);
    mBeats.emplace_back(static_cast<std::uint32_t>(packet.mCurBeat), std::move(grids));
    while (mBeats.size() > kMaxQueuedBeats) {
      mBeats.pop_front();
    }
  }

  bool CGridSnapshots::Take(const std::uint32_t beat, std::vector<wire::SGridSlot>& out)
  {
    const std::lock_guard<std::mutex> guard(mLock);
    while (!mBeats.empty() && mBeats.front().first < beat) {
      mBeats.pop_front();
    }
    if (mBeats.empty() || mBeats.front().first != beat) {
      return false;
    }
    out = std::move(mBeats.front().second);
    mBeats.pop_front();
    return true;
  }
} // namespace faf::remote::client
