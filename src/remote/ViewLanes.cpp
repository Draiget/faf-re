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
    // The grids were encoded with the frames (`PrepareSideJobs`).
    MarkPhase(EViewPhase::Grids);

    // Lua lane. `Sim::Sync` writes the `Sync` table after its entity walk, so these are the last
    // beat's, and it writes them again once this returns: a real server sends them when the beat's
    // sync is over.
    if (mRouter != nullptr && !mLuaSeparately) {
      for (std::size_t army = 0; army < armyCount && army < mRouter->ViewCount(); ++army) {
        SClient& client = mClients[army];
        client.lua.Clear();
        if (HasView(static_cast<std::int32_t>(army)) && !wire::EncodeLuaSyncLane(mRouter->Payload(army), mRouter->Prints(army), client.lua)) {
          ++client.failures;
        }
      }
    }
    MarkPhase(EViewPhase::Lua);

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

  std::size_t CViewLanes::PrepareSideJobs(moho::Sim& sim)
  {
    // Every army's grids, encoded once for all the views that receive them, on the workers with the
    // frames: the grids mostly wait on memory (a vision cell is 2 map units), the frames mostly compute.
    const auto armyCount = static_cast<std::size_t>(ArmyCount());
    std::size_t slots = 0;
    for (std::size_t index = 0; index < sim.mArmiesList.size(); ++index) {
      const moho::CArmyImpl* const army = sim.mArmiesList[index];
      if (army == nullptr) {
        continue;
      }
      moho::CIntelGrid* const kinds[2] = {army->mConstDat.mVisionReconGrid.get(), army->mConstDat.mWaterReconGrid.get()};
      for (std::uint8_t kind = 0; kind < 2u; ++kind) {
        moho::CIntelGrid* const grid = kinds[kind];
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
        const std::size_t words = wire::GridSeenWords(static_cast<std::size_t>(grid->mWidth) * grid->mHeight);
        beatGrid.fresh = beatGrid.source != grid || beatGrid.seen.size() != words || beatGrid.skipped;
        if (beatGrid.fresh) {
          beatGrid.seen.assign(words, 0u);
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
    MarkPhase(EViewPhase::GridSetup);
    return slots;
  }

  void CViewLanes::RunSideJob(const std::size_t index)
  {
    SBeatGrid& beatGrid = mBeatGrids[index];
    moho::CIntelGrid* const grid = beatGrid.source;
    beatGrid.delta.Clear();
    // A grid no view receives (a civilian army's, mostly) isn't read; whoever gets it later gets it whole.
    beatGrid.skipped = beatGrid.receivers == 0u;
    if (beatGrid.skipped) {
      return;
    }
    wire::WriteGridSlotHeader(beatGrid.slot, beatGrid.delta);
    // Only the chunks the sim may have rastered since last beat (a vision cell is 2 map units, so a
    // grid is up to a megabyte); a grid the clients get whole is read whole.
    wire::EncodeGridDeltaInPlace(
      grid->mWidth, grid->mHeight, grid->mGrid.get(), beatGrid.seen.data(), beatGrid.delta, grid->ChangedChunks(),
      moho::CIntelGrid::kChangeChunkCells, beatGrid.fresh
    );
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
    const bool check = ViewBeat() % kCheckEveryBeats == 0u;
    if (army >= static_cast<std::size_t>(ArmyCount())) {
      // A team's view: its frame, once, for its players' messages.
      client.teamFrame.Clear();
      if (!EncodeHeldFrame(view, client.teamFrame)) {
        ++client.failures;
      }
      client.teamHash = check ? HeldFrameHash(view) : 0u;
      return;
    }
    bool ok = true;
    const bool fresh = std::exchange(client.fresh, false);
    if (fresh) {
      client.haveArmies = false;
      client.grids.clear();
    }

    // Entity lanes: the view's frame against the one its client holds.
    wire::BitWriter frameWriter;
    if (fresh ? EncodeWholeHeldFrame(view, frameWriter) : EncodeHeldFrame(view, frameWriter)) {
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
        whole.bits.cells.resize(static_cast<std::size_t>(whole.bits.width) * whole.bits.height);
        for (std::size_t cell = 0; cell < whole.bits.cells.size(); ++cell) {
          whole.bits.cells[cell] = static_cast<std::uint8_t>((beatGrid.seen[cell / 64u] >> (cell % 64u)) & 1u);
        }
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

    // Pose lane (plan WP8.1): the bones of the units its client holds, against what it was sent.
    wire::BitWriter poseWriter;
    if (PosesOn()) {
      HeldUnitIds(army, client.poseUnitsNext);
      if (Poses().EncodeView(client.poseUnitsNext, client.poseUnits, fresh, poseWriter)) {
        client.bytes += static_cast<std::uint32_t>(poseWriter.Bytes().size());
      } else {
        ++client.failures;
        ok = false;
      }
      client.poseUnits.swap(client.poseUnitsNext);
    }

    SLanes lanes{frameWriter, armyWriter, gridWriter, client.lua, ok};
    lanes.poses = PosesOn() ? &poseWriter : nullptr;
    lanes.fresh = fresh;
    // A whole view carries its check, so a client that asked for one knows at once that it holds the right frames.
    lanes.check = check || fresh;
    lanes.frameHash = lanes.check ? HeldFrameHash(view) : 0u;
    // The team's frame goes once for all its players, except to one who holds none of it.
    wire::BitWriter wholeTeamFrame;
    if (const std::size_t teamSlot = TeamSlotOf(army); teamSlot != army && !CutFromTeam(army)) {
      lanes.team = &mClients[teamSlot].teamFrame;
      if (fresh) {
        if (!EncodeWholeHeldFrame(static_cast<std::int32_t>(teamSlot), wholeTeamFrame)) {
          ++client.failures;
          lanes.ok = false;
        }
        lanes.team = &wholeTeamFrame;
      }
      lanes.teamEntities = HeldCount(static_cast<std::int32_t>(teamSlot));
      // The team's view hashed itself only on a check's beat; between them a whole view hashes it here.
      lanes.teamHash = check ? mClients[teamSlot].teamHash : (fresh ? HeldFrameHash(static_cast<std::int32_t>(teamSlot)) : 0u);
      client.bytes += static_cast<std::uint32_t>(lanes.team->Bytes().size());
    }
    OnLanesEncoded(army, lanes);
  }
} // namespace faf::remote
