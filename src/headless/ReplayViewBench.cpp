#include "headless/ReplayViewBench.h"

#include <algorithm>

#include "headless/ReplaySyncSpy.h"
#include "moho/sim/Sim.h"

// Engine addition, server mode: see ReplayViewBench.h.

namespace faf::headless
{
  namespace
  {
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
    : remote::CViewLanes(tables, mapSizeX, mapSizeZ)
  {
    EnableIdMaps();       // the server's frames carry each view's own ids
    SkipCivilianViews(); // and no client receives a civilian army's view
    EnableHeldFrames(check);
    EnablePhaseTimes();
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
    (void)FinishViews();
    UninstallRouting();
    moho::Sim::SetSyncObserver(nullptr);
  }

  void CReplayViewBench::OnViewFrames(moho::Sim& sim)
  {
    const auto sendStart = std::chrono::steady_clock::now();
    if (mSessionTables.HasPending()) {
      // As a server's `CServerViews::OnViewFrames`: the beat's record, before the views.
      remote::wire::BitWriter record;
      mSessionTables.WritePending(record);
      mTableBytes += record.Bytes().size();
      ++mTableRecords;
    }
    remote::CViewLanes::OnViewFrames(sim);

    const auto sendEnd = std::chrono::steady_clock::now();
    mBeat = SBeat{};
    mBeat.buildMs = (BuildSeconds() - mLastBuildSeconds) * 1000.0;
    mBeat.sendMs = MillisecondsBetween(sendStart, sendEnd);
    mBeat.intervalMs = mHaveLastFrames ? MillisecondsBetween(mLastFrames, sendEnd) : 0.0;
    mLastBuildSeconds = BuildSeconds();
    mLastFrames = sendEnd;
    if (!PipelineOn()) {
      OnViewsFinished();
    }
  }

  void CReplayViewBench::OnLuaRouterMade(remote::CSyncRouter& router)
  {
    if (mLuaSpyOn) {
      mSyncSpy = std::make_unique<CReplaySyncSpy>(router);
      router.SetPayloadObserver([this](moho::Sim& observed) { mSyncSpy->Check(observed); });
    }
  }

  void CReplayViewBench::OnLuaRouterBeat(moho::Sim& sim, remote::CSyncRouter& router)
  {
    const auto beat = static_cast<std::int32_t>(sim.mCurBeat);
    for (const SLuaTestStep& step : mLuaMoves) {
      if (step.beat == beat && step.view < router.ViewCount()) {
        router.MoveView(step.view, step.army);
      }
    }
    for (const SLuaTestStep& step : mLuaResyncs) {
      if (step.beat == beat && step.view < router.ViewCount()) {
        router.RequestResync(step.view);
      }
    }
  }

  void CReplayViewBench::OnViewsFinished()
  {
    mBeat.sendMs += ViewWaitSeconds() * 1000.0; // what the views still cost the sim thread
    mWaitSeconds += ViewWaitSeconds();
    ++mPhaseBeats;
    const auto armyCount = static_cast<std::size_t>(ArmyCount());
    std::uint64_t entities = 0;
    std::uint64_t bytes = 0;
    mViews = 0;
    for (std::size_t army = 0; army < armyCount; ++army) {
      if (!HasView(static_cast<std::int32_t>(army))) {
        continue;
      }
      ++mViews;
      entities += HeldCount(static_cast<std::int32_t>(army));
      bytes += ClientBytes(army);
      mClientBeatBytes.push_back(ClientBytes(army));
      mEncodeFailures += TakeClientFailures(army);
    }
    mEntities += entities;
    if (mHaveLastFrames) {
      mBeats.push_back(mBeat); // the first beat has no interval and builds every view from nothing
    }
    mHaveLastFrames = true;
    if (mFile != nullptr) {
      std::fprintf(
        mFile, "%u,%.3f,%.3f,%.3f,%llu,%llu\n", ViewBeat(), mBeat.buildMs, mBeat.sendMs, mBeat.intervalMs,
        static_cast<unsigned long long>(entities), static_cast<unsigned long long>(bytes)
      );
    }
  }

  std::uint64_t CReplayViewBench::Failures() const noexcept
  {
    return mEncodeFailures + HeldMismatches() + (mSyncSpy != nullptr ? mSyncSpy->Failures() : 0u);
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
    if (PosesOn()) {
      const std::uint64_t beats = Poses().Beats() != 0u ? Poses().Beats() : 1u;
      summary += "; poses: " + std::to_string(Poses().PosedUnits()) + " units with a pose at the end, "
               + std::to_string(Poses().TotalChangedBones() / beats) + " bones changed a beat (all units), "
               + std::to_string(Poses().TotalHookedUnits() / beats) + " units a beat read from the animation hook's marks";
    }
    if (SessionTables() != nullptr) {
      summary += "; session tables " + std::to_string(mTableRecords) + " records, " + std::to_string(mTableBytes / 1024u) + " KB";
    }
    if (PhaseTimesOn() && mPhaseBeats != 0u) {
      // Per beat, ms: each step's wall time on the sim thread; for a step done a view at a time, the
      // sum over views, the slowest view and the team views' part of the sum.
      static constexpr const char* kNames[] = {"read", "read blocks", "read blips", "build", "write", "shared", "index", "facts", "keep", "poses", "tables", "frames", "release", "grid setup", "grids", "lua"};
      static_assert(std::size(kNames) == static_cast<std::size_t>(EViewPhase::Count));
      const double perBeat = 1000.0 / static_cast<double>(mPhaseBeats);
      double wall = 0.0;
      summary += "\n  view steps, ms a beat:";
      for (std::size_t phase = 0; phase < std::size(kNames); ++phase) {
        const SPhaseTime& time = PhaseTime(static_cast<EViewPhase>(phase));
        wall += time.wall;
        std::snprintf(text, sizeof(text), " %s %.2f", kNames[phase], time.wall * perBeat);
        summary += text;
        if (time.viewSum > 0.0) {
          std::snprintf(text, sizeof(text), " (views %.2f, slowest %.2f, teams %.2f)", time.viewSum * perBeat, time.viewMax * perBeat, time.teamViews * perBeat);
          summary += text;
        }
        summary += ";";
      }
      std::snprintf(text, sizeof(text), " all %.2f; waiting for the last beat's views %.2f", wall * perBeat, mWaitSeconds * perBeat);
      summary += text;
    }
    if (mSyncSpy != nullptr) {
      summary += "\n  ";
      summary += mSyncSpy->Summary();
    }
    return summary;
  }
} // namespace faf::headless
