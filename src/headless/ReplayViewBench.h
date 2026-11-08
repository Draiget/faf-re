#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "remote/ViewLanes.h"

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

namespace faf::headless
{
  class CReplaySyncSpy;

  class CReplayViewBench final : public remote::CViewLanes
  {
  public:
    /** `check`: `--view-bench-check`, each held frame is compared with the whole one (slow). */
    CReplayViewBench(const std::string& path, const remote::wire::SContentTables& tables, float mapSizeX, float mapSizeZ, bool check);
    ~CReplayViewBench() override;

    [[nodiscard]] bool IsOpen() const noexcept { return mFile != nullptr; }
    void Install();
    void Uninstall();
    /** `--spy` with `--lua-routing`: every Lua key each view receives is checked (ReplaySyncSpy.h). */
    void EnableLuaSpy() noexcept { mLuaSpyOn = true; }
    /** `--view-tables`: the session tables as a server keeps them, each beat's record written (and counted). */
    void EnableBenchTables() noexcept { EnableSessionTables(mSessionTables); }
    /** `--lua-move-view` and `--lua-resync`: moves and resyncs at a beat, to test them on replays. */
    void AddLuaMove(const std::int32_t beat, const std::size_t view, const std::int32_t army) { mLuaMoves.push_back({beat, view, army}); }
    void AddLuaResync(const std::int32_t beat, const std::size_t view) { mLuaResyncs.push_back({beat, view, 0}); }
    [[nodiscard]] std::string Summary() const;
    /** Lanes that did not encode, and what the check found (should stay 0). */
    [[nodiscard]] std::uint64_t Failures() const noexcept;

  protected:
    void OnViewFrames(moho::Sim& sim) override;
    void OnViewsFinished() override;
    void OnLuaRouterMade(remote::CSyncRouter& router) override;
    void OnLuaRouterBeat(moho::Sim& sim, remote::CSyncRouter& router) override;

  private:
    /** One beat's measurements. */
    struct SBeat
    {
      double buildMs = 0.0;
      double sendMs = 0.0;
      double intervalMs = 0.0;
    };

    std::FILE* mFile = nullptr;
    remote::wire::CSessionTableWriters mSessionTables; // `EnableBenchTables`
    std::uint64_t mTableBytes = 0;
    std::uint64_t mTableRecords = 0;
    std::size_t mViews = 0; // views built on the last beat (civilian armies have none)
    std::vector<SBeat> mBeats;
    SBeat mBeat{}; // this beat's, until `OnViewsFinished` adds it to them
    std::vector<std::uint32_t> mClientBeatBytes; // one entry per client and beat
    std::uint64_t mEntities = 0;                 // in all frames, all beats
    double mLastBuildSeconds = 0.0;
    bool mHaveLastFrames = false;
    double mWaitSeconds = 0.0;    // the sim thread's wait for the last beat's views to finish
    std::uint64_t mPhaseBeats = 0; // beats the phase times cover
    std::chrono::steady_clock::time_point mLastFrames{};
    std::uint64_t mEncodeFailures = 0;
    struct SLuaTestStep
    {
      std::int32_t beat;
      std::size_t view;
      std::int32_t army;
    };
    std::vector<SLuaTestStep> mLuaMoves;
    std::vector<SLuaTestStep> mLuaResyncs;
    bool mLuaSpyOn = false;
    std::unique_ptr<CReplaySyncSpy> mSyncSpy;
  };
} // namespace faf::headless
