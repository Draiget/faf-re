#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "remote/ViewFrames.h"
#include "remote/wire/ArmyLane.h"

// Engine addition, server mode (plan WP16.5, WPR.35): headless's `--view-bench <file>`. Run
// unfocused, every beat it does the work a dedicated server does for its players and nothing a
// check adds: every army's view but a civilian army's (no client receives one) is built with its
// own ids (remote/ViewFrames.h, plan WP5.9), and
// for every view the entity frame, the army lane and the grid lane (the vision and water grids of
// the view's army and of every army that counts it as an ally) are encoded against what that
// view's client received the beat before, as the server does with no loss. Nothing is decoded
// again. With `--parallel-views` the views are built and encoded on the sim's workers.
//
// One CSV line per beat: the time the views took to build (from the beat's sync walk to the
// frames), the time the lanes took to encode, the time since the previous beat's frames (the
// sim's beat plus all of this, when headless runs flat out), the entities in all frames and the
// bytes of all lanes. The summary gives the mean, p50, p95, p99 and maximum of each time and the
// bytes per client per second.

namespace moho
{
  class CIntelGrid;
}

namespace faf::headless
{
  class CReplayViewBench final : public remote::CViewFrames
  {
  public:
    /** `check`: `--view-bench-check`, each held frame is compared with the whole one (slow). */
    CReplayViewBench(const std::string& path, const remote::wire::SContentTables& tables, float mapSizeX, float mapSizeZ, bool check);
    ~CReplayViewBench() override;

    [[nodiscard]] bool IsOpen() const noexcept { return mFile != nullptr; }
    void Install();
    void Uninstall();
    [[nodiscard]] std::string Summary() const;
    /** Lanes that did not encode, and what the check found (should stay 0). */
    [[nodiscard]] std::uint64_t Failures() const noexcept { return mEncodeFailures + HeldMismatches(); }

  protected:
    void OnViewFrames(moho::Sim& sim) override;

  private:
    /** What one view's client received last (its frame is held by CViewFrames). */
    struct SClient
    {
      std::vector<remote::wire::SArmyRecord> armies;
      bool haveArmies = false;
      std::vector<std::uint16_t> grids; // the slots it received last beat (`SBeatGrid::key`)
      std::vector<std::uint16_t> gridsNext;
      std::uint32_t bytes = 0;      // this beat
      std::uint64_t failures = 0;   // this beat
    };

    /** One grid this beat: every client that holds last beat's gets the same delta, encoded once. */
    struct SBeatGrid
    {
      remote::wire::SGridSlot slot;
      const moho::CIntelGrid* source = nullptr;    // the sim's grid
      const remote::wire::SGridBits* last = nullptr; // last beat's, in `mLastGrids`
      remote::wire::BitWriter delta;               // the slot against `last`
      bool deltaOk = false;
      std::uint16_t key = 0;                       // army and kind
    };

    /** One beat's measurements. */
    struct SBeat
    {
      double buildMs = 0.0;
      double sendMs = 0.0;
      double intervalMs = 0.0;
    };

    void Send(const moho::Sim& sim, std::size_t army);

    std::FILE* mFile = nullptr;
    remote::wire::SFrameCodec mCodec;
    std::vector<SClient> mClients;
    std::size_t mViews = 0; // views built on the last beat (civilian armies have none)
    std::vector<SBeatGrid> mBeatGrids; // every army's grids this beat, copied once
    std::vector<SBeatGrid> mLastGrids; // last beat's; their storage is the next beat's
    std::vector<SBeat> mBeats;
    std::vector<std::uint32_t> mClientBeatBytes; // one entry per client and beat
    std::uint64_t mEntities = 0;                 // in all frames, all beats
    double mLastBuildSeconds = 0.0;
    bool mHaveLastFrames = false;
    std::chrono::steady_clock::time_point mLastFrames{};
    std::uint64_t mEncodeFailures = 0;
  };
} // namespace faf::headless
