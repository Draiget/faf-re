#include "remote/ViewLanes.h"

#include <algorithm>

#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimWorkerPool.h"
#include "remote/ArmyRecords.h"

namespace faf::remote
{
  wire::SFrameCodec MakeViewCodec(const float mapSizeX, const float mapSizeZ)
  {
    wire::SFrameCodec codec{};
    codec.position = wire::SPositionQuantizer::ForMap(mapSizeX, mapSizeZ);
    codec.maxEntities = 1u << 20;
    return codec;
  }

  CViewLanes::CViewLanes(const wire::SContentTables& tables, const float mapSizeX, const float mapSizeZ)
    : CViewFrames(tables, MakeViewCodec(mapSizeX, mapSizeZ))
  {}

  void CViewLanes::UninstallRouting()
  {
    moho::Sim::SetSyncRouting(nullptr);
  }

  void CViewLanes::OnViewFrames(moho::Sim& sim)
  {
    const auto armyCount = static_cast<std::size_t>(ArmyCount());
    if (mClients.size() < ViewSlots()) {
      mClients.resize(ViewSlots());
    }
    if (mLuaRouting && mRouter == nullptr) {
      mRouter = std::make_unique<CSyncRouter>(armyCount);
      mRouter->SetIdTranslator([this](const std::size_t view, const std::uint32_t simId) {
        return ViewEntityId(view, simId);
      });
      mRouter->SetDumpPrefix(mLuaRoutingDump);
      OnLuaRouterMade(*mRouter);
      moho::Sim::SetSyncRouting(mRouter.get());
    }
    if (mRouter != nullptr) {
      OnLuaRouterBeat(sim, *mRouter);
    }

    // Every army's grids, encoded once for all the views that receive them, on the workers.
    std::size_t slots = 0;
    for (std::size_t index = 0; index < sim.mArmiesList.size(); ++index) {
      const moho::CArmyImpl* const army = sim.mArmiesList[index];
      if (army == nullptr) {
        continue;
      }
      const moho::CIntelGrid* const kinds[2] = {army->mConstDat.mVisionReconGrid.get(), army->mConstDat.mWaterReconGrid.get()};
      for (std::uint8_t kind = 0; kind < 2u; ++kind) {
        const moho::CIntelGrid* const grid = kinds[kind];
        if (grid == nullptr) {
          continue;
        }
        if (mBeatGrids.size() <= slots) {
          mBeatGrids.emplace_back();
        }
        SBeatGrid& beatGrid = mBeatGrids[slots++];
        wire::SGridSlot& slot = beatGrid.slot;
        slot.army = static_cast<std::uint8_t>(index);
        slot.kind = kind;
        slot.gridSize = grid->mGridSize;
        slot.bits.width = grid->mWidth;
        slot.bits.height = grid->mHeight;
        beatGrid.fresh = beatGrid.source != grid || beatGrid.cells.size() != static_cast<std::size_t>(grid->mWidth) * grid->mHeight;
        if (beatGrid.fresh) {
          beatGrid.cells.assign(static_cast<std::size_t>(grid->mWidth) * grid->mHeight, 0);
        }
        beatGrid.source = grid;
        beatGrid.key = static_cast<std::uint16_t>(index * 2u + kind);
        // The view army's grids and those of every army that counts it as an ally
        // (`UserArmy::CanSeeCell`, 0x008B17F0).
        beatGrid.receivers = 0u;
        for (std::size_t view = 0; view < armyCount && view < 32u; ++view) {
          if (view == index || army->mVarDat.mAllies.Contains(static_cast<unsigned int>(view))) {
            beatGrid.receivers |= std::uint32_t{1} << view;
          }
        }
      }
    }
    mBeatGrids.resize(slots);
    const auto copyGrids = [this](const std::size_t begin, const std::size_t end) {
      for (std::size_t i = begin; i < end; ++i) {
        SBeatGrid& beatGrid = mBeatGrids[i];
        const moho::CIntelGrid* const grid = beatGrid.source;
        beatGrid.delta.Clear();
        wire::WriteGridSlotHeader(beatGrid.slot, beatGrid.delta);
        wire::EncodeGridDeltaInPlace(grid->mWidth, grid->mHeight, grid->mGrid.get(), beatGrid.cells.data(), beatGrid.delta);
      }
    };
    if (Parallel() && slots > 1u) {
      moho::CSimWorkerPool::Get().ParallelFor(slots, 1u, copyGrids);
    } else {
      copyGrids(0u, slots);
    }

    // Lua lane. `Sim::Sync` writes the `Sync` table after its entity walk, so these are the last
    // beat's, and it writes them again once this returns: a real server sends them when the beat's
    // sync is over.
    if (mRouter != nullptr) {
      for (std::size_t army = 0; army < armyCount && army < mRouter->ViewCount(); ++army) {
        SClient& client = mClients[army];
        client.lua.Clear();
        if (HasView(static_cast<std::int32_t>(army)) && !wire::EncodeLuaSyncLane(mRouter->Payload(army), mRouter->Prints(army), client.lua)) {
          ++client.failures;
        }
      }
    }

    if (!PipelineOn()) {
      if (Parallel() && armyCount > 1u) {
        moho::CSimWorkerPool::Get().ParallelFor(armyCount, 1u, [this](const std::size_t begin, const std::size_t end) {
          for (std::size_t army = begin; army < end; ++army) {
            Send(army);
          }
        });
      } else {
        for (std::size_t army = 0; army < armyCount; ++army) {
          Send(army);
        }
      }
    }
  }

  void CViewLanes::Send(const std::size_t army)
  {
    SClient& client = mClients[army];
    client.bytes = static_cast<std::uint32_t>(client.lua.Bytes().size());
    const auto view = static_cast<std::int32_t>(army);
    if (!HasView(view)) {
      client.grids.clear();
      return; // no client
    }
    if (army >= static_cast<std::size_t>(ArmyCount())) {
      // A team's view: its frame, once, for its players' messages.
      client.teamFrame.Clear();
      if (!EncodeHeldFrame(view, client.teamFrame)) {
        ++client.failures;
      }
      return;
    }
    bool ok = true;

    // Entity lanes: the view's frame against the one its client holds.
    wire::BitWriter frameWriter;
    if (EncodeHeldFrame(view, frameWriter)) {
      client.bytes += static_cast<std::uint32_t>(frameWriter.Bytes().size());
    } else {
      ++client.failures;
      ok = false;
    }

    // Army lane: every army's record as the view gets it.
    const moho::SSyncData& packet = Packet(view);
    std::vector<wire::SArmyRecord> records;
    records.reserve(packet.mArmyUpdates.size());
    for (std::size_t index = 0; index < packet.mArmyUpdates.size(); ++index) {
      records.push_back(ArmyToWire(ArmyRecordForView(packet.mArmyUpdates[index], index, view, packet.mCurBeat == 0)));
    }
    wire::BitWriter armyWriter;
    if (wire::EncodeArmyLane(records, client.haveArmies ? &client.armies : nullptr, armyWriter)) {
      client.bytes += static_cast<std::uint32_t>(armyWriter.Bytes().size());
    } else {
      ++client.failures;
      ok = false;
    }
    client.armies = std::move(records);
    client.haveArmies = true;

    // Grid lane.
    client.gridsNext.clear();
    for (const SBeatGrid& beatGrid : mBeatGrids) {
      if ((beatGrid.receivers & (std::uint32_t{1} << army)) != 0u && client.gridsNext.size() < wire::kMaxGridSlots) {
        client.gridsNext.push_back(beatGrid.key);
      }
    }
    wire::BitWriter gridWriter;
    gridWriter.WriteVarUint(static_cast<std::uint32_t>(client.gridsNext.size()));
    bool gridsOk = true;
    for (const std::uint16_t key : client.gridsNext) {
      const SBeatGrid& beatGrid = *std::find_if(mBeatGrids.begin(), mBeatGrids.end(), [key](const SBeatGrid& other) {
        return other.key == key;
      });
      if (!beatGrid.fresh && std::find(client.grids.begin(), client.grids.end(), key) != client.grids.end()) {
        gridWriter.Append(beatGrid.delta);
      } else {
        // A client new to this grid gets it whole, which is rare enough to make its cells here.
        wire::SGridSlot whole = beatGrid.slot;
        whole.bits.cells.resize(beatGrid.cells.size());
        std::transform(beatGrid.cells.begin(), beatGrid.cells.end(), whole.bits.cells.begin(), [](const std::int8_t cell) {
          return static_cast<std::uint8_t>(cell != 0 ? 1u : 0u);
        });
        gridsOk = wire::EncodeGridSlot(whole, nullptr, gridWriter) && gridsOk;
      }
    }
    if (gridsOk) {
      client.bytes += static_cast<std::uint32_t>(gridWriter.Bytes().size());
    } else {
      ++client.failures;
      ok = false;
    }
    client.grids.swap(client.gridsNext);

    SLanes lanes{frameWriter, armyWriter, gridWriter, client.lua, ok};
    if (const std::size_t teamSlot = TeamSlotOf(army); teamSlot != army) {
      lanes.team = &mClients[teamSlot].teamFrame;
      lanes.teamEntities = HeldCount(static_cast<std::int32_t>(teamSlot));
      client.bytes += static_cast<std::uint32_t>(lanes.team->Bytes().size());
    }
    OnLanesEncoded(army, lanes);
  }
} // namespace faf::remote
