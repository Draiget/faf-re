#include "headless/ReplayViewBench.h"

#include <algorithm>

#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimWorkerPool.h"
#include "remote/ArmyRecords.h"
#include "remote/wire/BitStream.h"

// Engine addition, server mode: see ReplayViewBench.h.

namespace faf::headless
{
  namespace
  {
    /** The codec `--view-frames` uses: positions over the map, no dead reckoning. */
    [[nodiscard]] remote::wire::SFrameCodec MakeCodec(const float mapSizeX, const float mapSizeZ)
    {
      remote::wire::SFrameCodec codec{};
      codec.position = remote::wire::SPositionQuantizer::ForMap(mapSizeX, mapSizeZ);
      codec.maxEntities = 1u << 20;
      return codec;
    }

    [[nodiscard]] double MillisecondsBetween(
      const std::chrono::steady_clock::time_point from, const std::chrono::steady_clock::time_point to
    )
    {
      return std::chrono::duration<double, std::milli>(to - from).count();
    }

    /** "mean m p50 a p95 b p99 c max d <unit>" of `values` (sorted in place). */
    [[nodiscard]] std::string Distribution(std::vector<double>& values, const char* const unit)
    {
      if (values.empty()) {
        return "no beats";
      }
      double sum = 0.0;
      for (const double value : values) {
        sum += value;
      }
      std::sort(values.begin(), values.end());
      const auto at = [&values](const double share) {
        return values[std::min(values.size() - 1u, static_cast<std::size_t>(share * static_cast<double>(values.size())))];
      };
      char text[160];
      std::snprintf(
        text, sizeof(text), "mean %.2f p50 %.2f p95 %.2f p99 %.2f max %.2f %s", sum / static_cast<double>(values.size()),
        at(0.50), at(0.95), at(0.99), values.back(), unit
      );
      return text;
    }
  } // namespace

  CReplayViewBench::CReplayViewBench(
    const std::string& path, const remote::wire::SContentTables& tables, const float mapSizeX, const float mapSizeZ,
    const bool check
  )
    : remote::CViewFrames(tables, MakeCodec(mapSizeX, mapSizeZ))
    , mCodec(MakeCodec(mapSizeX, mapSizeZ))
  {
    EnableIdMaps();       // the server's frames carry each view's own ids
    SkipCivilianViews(); // and no client receives a civilian army's view
    EnableHeldFrames(check);
    if (fopen_s(&mFile, path.c_str(), "w") != 0) {
      mFile = nullptr;
      return;
    }
    std::fprintf(mFile, "beat,build_ms,send_ms,interval_ms,entities,bytes\n");
  }

  CReplayViewBench::~CReplayViewBench()
  {
    Uninstall();
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
  }

  void CReplayViewBench::Install()
  {
    moho::Sim::SetSyncObserver(this);
  }

  void CReplayViewBench::Uninstall()
  {
    moho::Sim::SetSyncObserver(nullptr);
  }

  void CReplayViewBench::OnViewFrames(moho::Sim& sim)
  {
    const auto sendStart = std::chrono::steady_clock::now();
    const auto armyCount = static_cast<std::size_t>(ArmyCount());
    if (mClients.size() < armyCount) {
      mClients.resize(armyCount);
    }

    // Every army's grids, copied and encoded once for all the views that receive them. The slots
    // keep their storage from beat to beat, and the cells are copied on the workers.
    std::size_t slots = 0;
    mBeatGrids.swap(mLastGrids);
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
        remote::wire::SGridSlot& slot = beatGrid.slot;
        slot.army = static_cast<std::uint8_t>(index);
        slot.kind = kind;
        slot.gridSize = grid->mGridSize;
        slot.bits.width = grid->mWidth;
        slot.bits.height = grid->mHeight;
        beatGrid.source = grid;
        beatGrid.key = static_cast<std::uint16_t>(index * 2u + kind);
        const auto last = std::find_if(mLastGrids.begin(), mLastGrids.end(), [&beatGrid](const SBeatGrid& other) {
          return other.key == beatGrid.key;
        });
        beatGrid.last = last != mLastGrids.end() ? &last->slot.bits : nullptr;
      }
    }
    mBeatGrids.resize(slots);
    const auto copyGrids = [this](const std::size_t begin, const std::size_t end) {
      for (std::size_t i = begin; i < end; ++i) {
        SBeatGrid& beatGrid = mBeatGrids[i];
        remote::wire::SGridSlot& slot = beatGrid.slot;
        const moho::CIntelGrid* const grid = beatGrid.source;
        slot.bits.cells.resize(static_cast<std::size_t>(grid->mWidth) * grid->mHeight);
        for (std::size_t cell = 0; cell < slot.bits.cells.size(); ++cell) {
          slot.bits.cells[cell] = grid->mGrid[cell] != 0 ? 1u : 0u;
        }
        beatGrid.delta.Clear();
        beatGrid.deltaOk = remote::wire::EncodeGridSlot(slot, beatGrid.last, beatGrid.delta);
      }
    };
    if (Parallel() && slots > 1u) {
      moho::CSimWorkerPool::Get().ParallelFor(slots, 1u, copyGrids);
    } else {
      copyGrids(0u, slots);
    }

    if (Parallel() && armyCount > 1u) {
      moho::CSimWorkerPool::Get().ParallelFor(armyCount, 1u, [this, &sim](const std::size_t begin, const std::size_t end) {
        for (std::size_t army = begin; army < end; ++army) {
          Send(sim, army);
        }
      });
    } else {
      for (std::size_t army = 0; army < armyCount; ++army) {
        Send(sim, army);
      }
    }

    const auto sendEnd = std::chrono::steady_clock::now();
    SBeat beat{};
    beat.buildMs = (BuildSeconds() - mLastBuildSeconds) * 1000.0;
    beat.sendMs = MillisecondsBetween(sendStart, sendEnd);
    beat.intervalMs = mHaveLastFrames ? MillisecondsBetween(mLastFrames, sendEnd) : 0.0;
    mLastBuildSeconds = BuildSeconds();
    mLastFrames = sendEnd;

    std::uint64_t entities = 0;
    std::uint64_t bytes = 0;
    mViews = 0;
    for (std::size_t army = 0; army < armyCount; ++army) {
      if (!HasView(static_cast<std::int32_t>(army))) {
        continue;
      }
      ++mViews;
      SClient& client = mClients[army];
      entities += HeldCount(static_cast<std::int32_t>(army));
      bytes += client.bytes;
      mClientBeatBytes.push_back(client.bytes);
      mEncodeFailures += client.failures;
      client.failures = 0;
    }
    mEntities += entities;
    if (mHaveLastFrames) {
      mBeats.push_back(beat); // the first beat has no interval and builds every view from nothing
    }
    mHaveLastFrames = true;
    if (mFile != nullptr) {
      std::fprintf(
        mFile, "%u,%.3f,%.3f,%.3f,%llu,%llu\n", sim.mCurBeat, beat.buildMs, beat.sendMs, beat.intervalMs,
        static_cast<unsigned long long>(entities), static_cast<unsigned long long>(bytes)
      );
    }
  }

  void CReplayViewBench::Send(const moho::Sim& sim, const std::size_t army)
  {
    SClient& client = mClients[army];
    client.bytes = 0;
    const auto view = static_cast<std::int32_t>(army);
    if (!HasView(view)) {
      client.grids.clear();
      return; // a civilian army: no client
    }

    // Entity lanes: the view's frame against the one its client holds.
    remote::wire::BitWriter frameWriter;
    if (EncodeHeldFrame(view, frameWriter)) {
      client.bytes += static_cast<std::uint32_t>(frameWriter.Bytes().size());
    } else {
      ++client.failures;
    }

    // Army lane: every army's record as the view gets it.
    const moho::SSyncData& packet = Packet(view);
    std::vector<remote::wire::SArmyRecord> records;
    records.reserve(packet.mArmyUpdates.size());
    for (std::size_t index = 0; index < packet.mArmyUpdates.size(); ++index) {
      records.push_back(remote::ArmyToWire(remote::ArmyRecordForView(packet.mArmyUpdates[index], index, view, packet.mCurBeat == 0)));
    }
    remote::wire::BitWriter armyWriter;
    if (remote::wire::EncodeArmyLane(records, client.haveArmies ? &client.armies : nullptr, armyWriter)) {
      client.bytes += static_cast<std::uint32_t>(armyWriter.Bytes().size());
    } else {
      ++client.failures;
    }
    client.armies = std::move(records);
    client.haveArmies = true;

    // Grid lane: the view army's grids and those of every army that counts it as an ally
    // (`UserArmy::CanSeeCell`, 0x008B17F0).
    client.gridsNext.clear();
    for (const SBeatGrid& beatGrid : mBeatGrids) {
      const moho::CArmyImpl* const owner = sim.mArmiesList[beatGrid.slot.army];
      if ((beatGrid.slot.army == army || owner->mVarDat.mAllies.Contains(static_cast<unsigned int>(army)))
          && client.gridsNext.size() < remote::wire::kMaxGridSlots) {
        client.gridsNext.push_back(beatGrid.key);
      }
    }
    remote::wire::BitWriter gridWriter;
    gridWriter.WriteVarUint(static_cast<std::uint32_t>(client.gridsNext.size()));
    bool gridsOk = true;
    for (const std::uint16_t key : client.gridsNext) {
      const SBeatGrid& beatGrid = *std::find_if(mBeatGrids.begin(), mBeatGrids.end(), [key](const SBeatGrid& other) {
        return other.key == key;
      });
      if (std::find(client.grids.begin(), client.grids.end(), key) != client.grids.end()) {
        gridWriter.Append(beatGrid.delta);
        gridsOk = gridsOk && beatGrid.deltaOk;
      } else {
        gridsOk = remote::wire::EncodeGridSlot(beatGrid.slot, nullptr, gridWriter) && gridsOk;
      }
    }
    if (gridsOk) {
      client.bytes += static_cast<std::uint32_t>(gridWriter.Bytes().size());
    } else {
      ++client.failures;
    }
    client.grids.swap(client.gridsNext);
  }

  std::string CReplayViewBench::Summary() const
  {
    std::vector<double> build;
    std::vector<double> send;
    std::vector<double> total;
    std::vector<double> interval;
    for (const SBeat& beat : mBeats) {
      build.push_back(beat.buildMs);
      send.push_back(beat.sendMs);
      total.push_back(beat.buildMs + beat.sendMs);
      interval.push_back(beat.intervalMs);
    }
    std::vector<double> perSecond; // each client's bytes per beat, as bytes per second (10 beats a second)
    perSecond.reserve(mClientBeatBytes.size());
    for (const std::uint32_t bytes : mClientBeatBytes) {
      perSecond.push_back(static_cast<double>(bytes) * 10.0);
    }
    std::string summary;
    char text[200];
    std::snprintf(
      text, sizeof(text), "view bench: %zu beats, %zu views (%s), %llu encode failures, %llu check differences, %.0f entities per beat",
      mBeats.size(), mViews, Parallel() ? "parallel" : "serial", static_cast<unsigned long long>(mEncodeFailures),
      static_cast<unsigned long long>(HeldMismatches()),
      mBeats.empty() ? 0.0 : static_cast<double>(mEntities) / static_cast<double>(mBeats.size() + 1u)
    );
    summary = text;
    summary += "; build " + Distribution(build, "ms");
    summary += "; send " + Distribution(send, "ms");
    summary += "; build+send " + Distribution(total, "ms");
    summary += "; beat interval " + Distribution(interval, "ms");
    summary += "; per client " + Distribution(perSecond, "B/s");
    return summary;
  }
} // namespace faf::headless
