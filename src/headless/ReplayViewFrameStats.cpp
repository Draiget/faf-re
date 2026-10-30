#include "headless/ReplayViewFrameStats.h"

#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/Sim.h"
#include "remote/wire/BitStream.h"

// Engine addition, server mode: see ReplayViewFrameStats.h.

namespace faf::headless
{
  namespace
  {
    /** The codec `--wire-stats` uses: positions over the map, no dead reckoning. */
    [[nodiscard]] remote::wire::SFrameCodec MakeCodec(const float mapSizeX, const float mapSizeZ)
    {
      remote::wire::SFrameCodec codec{};
      codec.position = remote::wire::SPositionQuantizer::ForMap(mapSizeX, mapSizeZ);
      codec.maxEntities = 1u << 20;
      return codec;
    }
  } // namespace

  CReplayViewFrameStats::CReplayViewFrameStats(
    const std::string& path, const remote::wire::SContentTables& tables, const float mapSizeX, const float mapSizeZ
  )
    : remote::CViewFrames(tables, MakeCodec(mapSizeX, mapSizeZ))
    , mCodec(MakeCodec(mapSizeX, mapSizeZ))
  {
    if (fopen_s(&mFile, path.c_str(), "w") != 0) {
      mFile = nullptr;
      return;
    }
    std::fprintf(mFile, "beat,army,entities,withheld,delta_bytes,grid_bytes\n");
  }

  CReplayViewFrameStats::~CReplayViewFrameStats()
  {
    Uninstall();
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
  }

  void CReplayViewFrameStats::Install()
  {
    moho::Sim::SetSyncObserver(this);
  }

  void CReplayViewFrameStats::Uninstall()
  {
    moho::Sim::SetSyncObserver(nullptr);
  }

  void CReplayViewFrameStats::OnViewFrames(moho::Sim& sim)
  {
    const auto armyCount = static_cast<std::size_t>(ArmyCount());
    while (mPrevious.size() < armyCount) {
      mPrevious.emplace_back();
      mHavePrevious.push_back(false);
      mBytes.push_back(0);
      mEntities.push_back(0);
      mGridBytes.push_back(0);
    }
    ++mBeats;

    for (std::size_t army = 0; army < armyCount; ++army) {
      const remote::wire::SViewFrame& frame = Frame(static_cast<std::int32_t>(army));
      const remote::wire::SViewFrame* const baseline = mHavePrevious[army] ? &mPrevious[army] : nullptr;
      remote::wire::BitWriter writer;
      if (!remote::wire::EncodeFrame(frame, baseline, mCodec, writer)) {
        ++mEncodeFailures;
        continue;
      }
      remote::wire::BitReader reader(writer.Bytes());
      remote::wire::SViewFrame decoded{};
      if (!remote::wire::DecodeFrame(reader, baseline, mCodec, decoded) || !(decoded == frame)) {
        ++mRoundTripFailures;
      }
      const auto bytes = static_cast<std::uint32_t>(writer.Bytes().size());
      const std::uint32_t gridBytes = SendGrids(sim, army);
      mBytes[army] += bytes;
      mEntities[army] += frame.entities.size();
      mGridBytes[army] += gridBytes;
      if (mFile != nullptr) {
        std::fprintf(
          mFile, "%u,%zu,%zu,%u,%u,%u\n", sim.mCurBeat, army, frame.entities.size(),
          Withheld(static_cast<std::int32_t>(army)), bytes, gridBytes
        );
      }
      mPrevious[army] = frame;
      mHavePrevious[army] = true;
    }
  }

  std::uint32_t CReplayViewFrameStats::SendGrids(const moho::Sim& sim, const std::size_t view)
  {
    const auto viewIndex = static_cast<std::uint32_t>(view);
    std::uint32_t total = 0;
    for (std::size_t index = 0; index < sim.mArmiesList.size(); ++index) {
      const moho::CArmyImpl* const army = sim.mArmiesList[index];
      // `UserArmy::CanSeeCell` (0x008B17F0): the view's own grids and those of every army that
      // lists the view among its allies.
      if (army == nullptr || (index != view && !army->mVarDat.mAllies.Contains(viewIndex))) {
        continue;
      }
      const moho::CIntelGrid* const grids[2] = {army->mConstDat.mVisionReconGrid.get(), army->mConstDat.mWaterReconGrid.get()};
      for (int kind = 0; kind < 2; ++kind) {
        const moho::CIntelGrid* const grid = grids[kind];
        if (grid == nullptr) {
          continue;
        }
        remote::wire::SGridBits bits;
        bits.width = grid->mWidth;
        bits.height = grid->mHeight;
        bits.cells.resize(static_cast<std::size_t>(grid->mWidth) * grid->mHeight);
        for (std::size_t cell = 0; cell < bits.cells.size(); ++cell) {
          bits.cells[cell] = grid->mGrid[cell] != 0 ? 1u : 0u;
        }

        remote::wire::SGridBits& sent = mSentGrids[{view, index, kind}];
        remote::wire::BitWriter writer;
        if (!remote::wire::EncodeGridDelta(bits, sent.cells.empty() ? nullptr : &sent, writer)) {
          ++mGridFailures;
          continue;
        }
        remote::wire::BitReader reader(writer.Bytes());
        remote::wire::SGridBits decoded;
        if (!remote::wire::DecodeGridDelta(reader, sent.cells.empty() ? nullptr : &sent, 1u << 24, decoded)
            || !(decoded == bits)) {
          ++mGridFailures;
        }
        total += static_cast<std::uint32_t>(writer.Bytes().size());
        sent = std::move(bits);
      }
    }
    return total;
  }

  std::string CReplayViewFrameStats::Summary() const
  {
    std::string summary;
    char text[320];
    std::snprintf(
      text, sizeof(text), "view frames: %llu beats, %zu armies, %llu encode failures, %llu round-trip failures",
      static_cast<unsigned long long>(mBeats), mBytes.size(), static_cast<unsigned long long>(mEncodeFailures),
      static_cast<unsigned long long>(mRoundTripFailures)
    );
    summary = text;
    for (std::size_t army = 0; army < mBytes.size(); ++army) {
      // 10 beats a second: bytes per beat x 10 / 1000 = KB/s.
      const double beats = mBeats > 0 ? static_cast<double>(mBeats) : 1.0;
      std::snprintf(
        text, sizeof(text),
        "\n  army %zu: %.0f entities and %.0f bytes per frame on average (%.1f KB/s); grids %.0f bytes per beat (%.2f KB/s)",
        army, static_cast<double>(mEntities[army]) / beats, static_cast<double>(mBytes[army]) / beats,
        static_cast<double>(mBytes[army]) / beats * 10.0 / 1000.0, static_cast<double>(mGridBytes[army]) / beats,
        static_cast<double>(mGridBytes[army]) / beats * 10.0 / 1000.0
      );
      summary += text;
    }
    return summary;
  }
} // namespace faf::headless
