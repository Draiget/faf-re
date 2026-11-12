#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "remote/ViewLanes.h"
#include "remote/client/EffectLaneApplier.h"
#include "remote/wire/EffectLane.h"
#include "server/EffectOpEncoder.h"
#include "server/EffectOpRouter.h"

namespace faf::server
{
  class CEffectOpRecorder;
}

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
    CReplayViewBench(
      const std::string& path,
      const remote::wire::SContentTables& tables,
      float mapSizeX,
      float mapSizeZ,
      bool check
    );
    ~CReplayViewBench() override;

    [[nodiscard]] bool IsOpen() const noexcept
    {
      return mFile != nullptr;
    }
    void Install();
    void Uninstall();
    /** `--spy` with `--lua-routing`: every Lua key each view receives is checked (ReplaySyncSpy.h). */
    void EnableLuaSpy() noexcept
    {
      mLuaSpyOn = true;
    }
    /** `--view-tables`: the session tables as a server keeps them, each beat's record written (and counted). */
    void EnableBenchTables() noexcept
    {
      EnableSessionTables(mSessionTables);
    }
    /** `--lua-move-view` and `--lua-resync`: moves and resyncs at a beat, to test them on replays. */
    void AddLuaMove(
      const std::int32_t beat,
      const std::size_t view,
      const std::int32_t army
    )
    {
      mLuaMoves.push_back({beat, view, army});
    }
    void AddLuaResync(
      const std::int32_t beat,
      const std::size_t view
    )
    {
      mLuaResyncs.push_back({beat, view, 0});
    }
    /**
     * Plan WP9.2, `--view-effects`, before the first beat: the sim's effect ops are recorded (this sets
     * `gEffectOpHook`) and each view's effects lane is written both ways, routed (server/EffectOpRouter.h) and with
     * every op, and counted; each routed lane is read back as its client would, counting ops on effects it doesn't
     * hold.
     */
    void EnableEffects();
    [[nodiscard]] std::string Summary() const;
    /** Lanes that did not encode, and what the check found (should stay 0). */
    [[nodiscard]] std::uint64_t Failures() const noexcept;

  protected:
    void OnViewFrames(moho::Sim& sim) override;
    void OnViewsFinished() override;
    void OnLuaRouterMade(remote::CSyncRouter& router) override;
    void OnLuaRouterBeat(moho::Sim& sim, remote::CSyncRouter& router) override;
    void OnLanesEncoded(std::size_t army, const SLanes& lanes) override;

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
    SBeat mBeat{};                               // this beat's, until `OnViewsFinished` adds it to them
    std::vector<std::uint32_t> mClientBeatBytes; // one entry per client and beat
    std::uint64_t mEntities = 0;                 // in all frames, all beats
    double mLastBuildSeconds = 0.0;
    bool mHaveLastFrames = false;
    double mWaitSeconds = 0.0;     // the sim thread's wait for the last beat's views to finish
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
    // `EnableEffects`: the beat's ops (written on the sim thread before the views) and each view's two lanes.
    static constexpr std::size_t kEffectKinds = static_cast<std::size_t>(moho::EEffectOp::Count);
    /**
     * Plan WP9.3: a view's client as the bench models it: the entities its frames hold, by the ids it holds them
     * under (the view's id map turns one back into the sim's, whose record the view's held frame answers for).
     */
    class CEffectClient final : public remote::client::IEffectLaneTarget
    {
    public:
      CEffectClient(
        const CReplayViewBench& bench,
        const std::size_t army
      ) noexcept
        : mBench(bench)
        , mArmy(army)
      {}
      [[nodiscard]] bool HoldsEntity(std::int32_t entity, bool orRemoved) const override;
      [[nodiscard]] bool Create(
        std::uint32_t,
        const remote::wire::SEffectLaneOp&,
        const std::string*,
        const std::string*
      ) override
      {
        return true; // blueprints aren't checked here (faf_server_probe --rebuild checks them with its rules)
      }
      void Change(
        std::uint32_t,
        const remote::wire::SEffectLaneOp&
      ) override
      {}
      void Destroy(
        std::uint32_t
      ) override
      {}
      void Light(
        const remote::wire::SEffectLaneOp&,
        const std::string*,
        const std::string*
      ) override
      {}

    private:
      const CReplayViewBench& mBench;
      std::size_t mArmy;
    };

    struct SEffectView
    {
      server::CEffectViewRoute route;
      server::CEffectLaneNames all;
      remote::wire::CEffectLaneReader reader;
      std::vector<remote::wire::SEffectLaneOp> ops;
      std::vector<std::uint8_t> lane;
      // Plan WP9.3: the client's applier on the routed lane, and each beat its effects against those the routes
      // count as its client's (`CEffectRoutes::HeldBy`).
      std::unique_ptr<CEffectClient> client;
      std::unique_ptr<remote::client::CEffectLaneApplier> applier;
      std::uint64_t beatsDiffering = 0; // beats whose two counts differ
      std::uint64_t mostDifference = 0; // the largest difference
      std::int64_t lastDifference = 0;  // the client's count less the routes', at the last beat
      std::uint64_t clientOnly = 0;     // at the first beat that differed: effects only the client holds
      std::uint64_t routesOnly = 0;     // and only the routes count
      std::uint32_t firstDiffering = 0; // that beat
      std::uint64_t routesHeldSum = 0;  // the routes' count, summed over the beats (for a mean)
      // Summed over the beats that differ: effects only the client holds (0: ended or unknown to the routes; 1-4: not
      // sent there, by where its entity is: follows nothing, a record, a blip, neither but the client follows a blip
      // record it holds), only the routes count (5-8), and (9) neither and the client follows no blip.
      std::array<std::uint64_t, 10> why{};
      std::uint64_t routedBytes = 0;
      std::uint64_t allBytes = 0;
      std::uint64_t allOps = 0;
      std::uint32_t routedMax = 0;
      std::uint32_t allMax = 0;
      std::uint64_t failed = 0; // routed lanes that didn't read back
      std::uint64_t beats = 0;
      std::array<std::uint64_t, kEffectKinds> kinds{}; // routed ops it read back, by `EEffectOp`
      // Beams between two entities at their create: neither end held, the first only, the second only, both.
      std::array<std::uint64_t, 4> beamEnds{};
    };
    std::unique_ptr<server::CEffectOpRecorder> mEffectRecorder;
    std::unique_ptr<server::CEffectRoutes> mEffectRoutes;
    server::SEffectBeat mEffectBeat;
    std::vector<SEffectView> mEffectViews;                  // by army
    std::array<std::uint64_t, kEffectKinds> mEffectKinds{}; // every op, by `EEffectOp`, once
  };
} // namespace faf::headless
