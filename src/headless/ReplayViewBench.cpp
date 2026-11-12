#include "headless/ReplayViewBench.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iterator>

#include "headless/ReplaySyncSpy.h"
#include "moho/sim/Sim.h"
#include "remote/VisibilityOracle.h"
#include "server/EffectOpRecorder.h"

// Engine addition, server mode: see ReplayViewBench.h.

namespace faf::headless
{
  namespace
  {
    [[nodiscard]] double MillisecondsBetween(
      const std::chrono::steady_clock::time_point from,
      const std::chrono::steady_clock::time_point to
    )
    {
      return std::chrono::duration<double, std::milli>(to - from).count();
    }

    /** "mean m p50 a p95 b p99 c max d <unit>" of `values` (sorted in place). */
    [[nodiscard]] std::string Distribution(
      std::vector<double>& values,
      const char* const unit
    )
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
        return values[std::min(
          values.size() - 1u, static_cast<std::size_t>(share * static_cast<double>(values.size()))
        )];
      };
      char text[160];
      std::snprintf(
        text,
        sizeof(text),
        "mean %.2f p50 %.2f p95 %.2f p99 %.2f max %.2f %s",
        sum / static_cast<double>(values.size()),
        at(0.50),
        at(0.95),
        at(0.99),
        values.back(),
        unit
      );
      return text;
    }
  } // namespace

  CReplayViewBench::CReplayViewBench(
    const std::string& path,
    const remote::wire::SContentTables& tables,
    const float mapSizeX,
    const float mapSizeZ,
    const bool check
  )
    : remote::CViewLanes(tables, mapSizeX, mapSizeZ)
  {
    EnableIdMaps();      // the server's frames carry each view's own ids
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
    if (mEffectRecorder) {
      moho::gEffectOpHook = nullptr;
      mEffectRecorder->Detach();
    }
  }

  void CReplayViewBench::EnableEffects()
  {
    mEffectRecorder = std::make_unique<server::CEffectOpRecorder>();
    mEffectRoutes = std::make_unique<server::CEffectRoutes>();
    mEffectRecorder->Attach();
    moho::gEffectOpHook = &server::CEffectOpRecorder::Hook;
  }

  void CReplayViewBench::OnLanesEncoded(
    const std::size_t army,
    const SLanes& lanes
  )
  {
    // On the view's own job (a worker or a pipeline thread): its two lanes, and its routed one read back.
    if (!mEffectRoutes || army >= mEffectViews.size() || army >= 32u) {
      return;
    }
    SEffectView& view = mEffectViews[army];
    ++view.beats;
    view.all.Write(mEffectBeat, view.lane);
    view.allBytes += view.lane.size();
    view.allOps += mEffectBeat.opCount;
    view.allMax = std::max(view.allMax, static_cast<std::uint32_t>(view.lane.size()));
    const auto holds = [this, army](const std::int32_t entity, const bool orLeft) {
      return ViewHoldsEntityNow(army, static_cast<std::uint32_t>(entity), orLeft);
    };
    // Beams between two entities made this beat: which ends this view's client holds, as a record or through a blip
    // (the far end of a build beam is a script-made entity with no army).
    const std::uint32_t bit = std::uint32_t{1} << army;
    for (const server::SEffectBeatOp& op : mEffectBeat.list) {
      if (op.op == moho::EEffectOp::AttachBeamEntityToEntity || op.op == moho::EEffectOp::CreateBeamEntityToEntity) {
        const server::CEffectRoutes::SLive* const live = mEffectRoutes->Find(op.id);
        const bool first =
          op.entity >= 0 && ((live != nullptr && (live->shown & bit) != 0u) || holds(op.entity, false));
        const bool second =
          op.entity2 >= 0 && ((live != nullptr && (live->shown2 & bit) != 0u) || holds(op.entity2, false));
        ++view.beamEnds[(first ? 1u : 0u) + (second ? 2u : 0u)];
      }
    }
    // Plan WP9.3: entities as this view's client holds them (its id map), as the server sends them.
    const remote::CViewIdMap& ids = IdMap(static_cast<std::int32_t>(army));
    view.route.Write(
      mEffectBeat,
      *mEffectRoutes,
      army,
      lanes.fresh,
      holds,
      view.lane,
      [&ids](const std::int32_t entity, std::int32_t& clientId) {
      std::uint32_t viewId = 0;
      if (!ids.EntityToHeldView(static_cast<std::uint32_t>(entity), viewId)) {
        return false;
      }
      clientId = static_cast<std::int32_t>(viewId);
      return true;
    }
    );
    view.routedBytes += view.lane.size();
    view.routedMax = std::max(view.routedMax, static_cast<std::uint32_t>(view.lane.size()));
    if (!view.reader.Read(view.lane, view.ops)) {
      ++view.failed;
    }
    for (const remote::wire::SEffectLaneOp& op : view.ops) {
      ++view.kinds[static_cast<std::size_t>(op.op) % view.kinds.size()];
    }
    // As its client: the game client's applier on the lane, against what the view's frames hold, by the client's ids.
    if (!view.applier) {
      view.client = std::make_unique<CEffectClient>(*this, army);
      view.applier = std::make_unique<remote::client::CEffectLaneApplier>(*view.client);
    }
    remote::client::CEffectLaneApplier& applier = *view.applier;
    (void)applier.Apply(view.lane, lanes.fresh);
    for (const std::uint32_t id : mEffectBeat.ended) {
      applier.Ended(id); // its client derives the end (the effect's lifetime, its entity's death)
    }
    // The effects it holds against those the routes take it to hold.
    const std::size_t routesHeld = mEffectRoutes->HeldBy(army);
    view.routesHeldSum += routesHeld;
    const auto difference = static_cast<std::int64_t>(applier.Live()) - static_cast<std::int64_t>(routesHeld);
    view.lastDifference = difference;
    if (difference != 0) {
      view.mostDifference =
        std::max<std::uint64_t>(view.mostDifference, static_cast<std::uint64_t>(std::abs(difference)));
      if (view.beatsDiffering++ == 0u) {
        view.firstDiffering = ViewBeat();
        applier.ForEachHeld([&](const std::uint32_t id) {
          const server::CEffectRoutes::SLive* const live = mEffectRoutes->Find(id);
          view.clientOnly += live == nullptr || live->ended || (live->sent.load() & bit) == 0u ? 1u : 0u;
        });
        view.routesOnly = routesHeld - (applier.Live() - view.clientOnly);
      }
      // Why, on each beat that differs: the effects only one side holds, by what holds their entity.
      const auto where = [&](const server::CEffectRoutes::SLive& live) -> std::size_t {
        if (live.positioned || live.placed) {
          return 0u; // follows nothing
        }
        if (live.entity >= 0 && holds(live.entity, false)) {
          return 1u; // a record of the view's frames
        }
        if ((live.shown & bit) != 0u) {
          return 2u; // drawn through a blip
        }
        return 3u;
      };
      applier.ForEachHeld([&](const std::uint32_t id) {
        const server::CEffectRoutes::SLive* const live = mEffectRoutes->Find(id);
        if (live == nullptr || live->ended) {
          ++view.why[0];
        } else if ((live->sent.load() & bit) == 0u) {
          // Elsewhere: is what the client follows a blip (entity family 3) it still holds as a record?
          const std::int32_t following = applier.Following(id);
          const bool blip = following >= 0 && (static_cast<std::uint32_t>(following) >> 28u) == 3u;
          const std::size_t at = where(*live);
          ++view.why[at == 3u && !blip ? 9u : 1u + at];
        }
      });
      mEffectRoutes->ForEachLiveId([&](const std::uint32_t id, const server::CEffectRoutes::SLive& live) {
        if (!live.ended && (live.sent.load() & bit) != 0u && !applier.Holds(id)) {
          ++view.why[5 + where(live)];
        }
      });
    }
  }

  bool CReplayViewBench::CEffectClient::HoldsEntity(
    const std::int32_t entity,
    const bool orRemoved
  ) const
  {
    std::uint32_t simId = 0;
    return entity >= 0 &&
      mBench.IdMap(static_cast<std::int32_t>(mArmy)).EntityToSim(static_cast<std::uint32_t>(entity), simId) &&
      mBench.ViewHoldsEntityNow(mArmy, simId, orRemoved);
  }

  void CReplayViewBench::OnViewFrames(
    moho::Sim& sim
  )
  {
    const auto sendStart = std::chrono::steady_clock::now();
    if (mEffectRoutes) {
      // As a server's `CServerViews::OnViewFrames`: the beat's ops, the live effects and each army's sight of a point.
      mEffectBeat = mEffectRecorder->EndBeat();
      for (const server::SEffectBeatOp& op : mEffectBeat.list) {
        ++mEffectKinds[static_cast<std::size_t>(op.op) % mEffectKinds.size()];
      }
      const auto armyCount = static_cast<std::size_t>(ArmyCount());
      if (mEffectViews.size() < armyCount) {
        mEffectViews = std::vector<SEffectView>(armyCount);
      }
      std::uint32_t views = 0u;
      for (std::size_t army = 0; army < armyCount && army < 32u; ++army) {
        views |= HasView(static_cast<std::int32_t>(army)) ? std::uint32_t{1} << army : 0u;
      }
      mEffectRoutes->TakeBeat(mEffectBeat, views, 0u, [&sim, views](const std::array<float, 3>& at) {
        std::uint32_t seeing = 0u;
        const Wm3::Vec3f point(at[0], at[1], at[2]);
        for (std::size_t army = 0; army < 32u; ++army) {
          if (
            ((views >> army) & 1u) != 0u && remote::ViewCanSeePoint(sim, static_cast<std::int32_t>(army), point, false)
          ) {
            seeing |= std::uint32_t{1} << army;
          }
        }
        return seeing;
      }, [&sim, views](const std::int32_t entity, server::CEffectRoutes::SBlips& blips) {
        return remote::ViewsShowingUnitBlips(sim, views, static_cast<std::uint32_t>(entity), &blips);
      });
    }
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

  void CReplayViewBench::OnLuaRouterMade(
    remote::CSyncRouter& router
  )
  {
    if (mLuaSpyOn) {
      mSyncSpy = std::make_unique<CReplaySyncSpy>(router);
      router.SetPayloadObserver([this](moho::Sim& observed) {
        mSyncSpy->Check(observed);
      });
    }
  }

  void CReplayViewBench::OnLuaRouterBeat(
    moho::Sim& sim,
    remote::CSyncRouter& router
  )
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
        mFile,
        "%u,%.3f,%.3f,%.3f,%llu,%llu\n",
        ViewBeat(),
        mBeat.buildMs,
        mBeat.sendMs,
        mBeat.intervalMs,
        static_cast<unsigned long long>(entities),
        static_cast<unsigned long long>(bytes)
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
    char text[768];
    std::snprintf(
      text,
      sizeof(text),
      "view bench: %zu beats, %zu views (%s), %llu encode failures, %llu check differences, %.0f entities per beat",
      mBeats.size(),
      mViews,
      Parallel() ? "parallel" : "serial",
      static_cast<unsigned long long>(mEncodeFailures),
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
      summary += "; poses: " + std::to_string(Poses().PosedUnits()) + " units with a pose at the end, " +
        std::to_string(Poses().TotalChangedBones() / beats) + " bones changed a beat (all units), " +
        std::to_string(Poses().TotalHookedUnits() / beats) + " units a beat read from the animation hook's marks";
    }
    if (SessionTables() != nullptr) {
      summary += "; session tables " + std::to_string(mTableRecords) + " records, " +
        std::to_string(mTableBytes / 1024u) + " KB";
    }
    if (PhaseTimesOn() && mPhaseBeats != 0u) {
      // Per beat, ms: each step's wall time on the sim thread; for a step done a view at a time, the
      // sum over views, the slowest view and the team views' part of the sum.
      static constexpr const char* kNames[] = {
        "read",
        "read blocks",
        "read blips",
        "build",
        "write",
        "shared",
        "index",
        "facts",
        "keep",
        "poses",
        "tables",
        "frames",
        "release",
        "grid setup",
        "grids",
        "lua"
      };
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
          std::snprintf(
            text,
            sizeof(text),
            " (views %.2f, slowest %.2f, teams %.2f)",
            time.viewSum * perBeat,
            time.viewMax * perBeat,
            time.teamViews * perBeat
          );
          summary += text;
        }
        summary += ";";
      }
      std::snprintf(
        text, sizeof(text), " all %.2f; waiting for the last beat's views %.2f", wall * perBeat, mWaitSeconds * perBeat
      );
      summary += text;
    }
    if (mSyncSpy != nullptr) {
      summary += "\n  ";
      summary += mSyncSpy->Summary();
    }
    if (mEffectRoutes) {
      // Plan WP9.2: each view's effects lane, KB/s at 10 beats a second, with every op against routed.
      std::uint64_t allBytes = 0;
      std::uint64_t routedBytes = 0;
      std::uint64_t viewBeats = 0;
      for (std::size_t army = 0; army < mEffectViews.size(); ++army) {
        const SEffectView& view = mEffectViews[army];
        if (view.beats == 0u) {
          continue;
        }
        allBytes += view.allBytes;
        routedBytes += view.routedBytes;
        viewBeats += view.beats;
        const double perSecond = 10.0 / 1024.0 / static_cast<double>(view.beats);
        std::snprintf(
          text,
          sizeof(text),
          "\n  effects view %zu: all %.2f KB/s (%llu ops, most %u B), routed %.2f KB/s (%llu ops, most %u B), %llu "
          "lights, ",
          army,
          static_cast<double>(view.allBytes) * perSecond,
          static_cast<unsigned long long>(view.allOps),
          view.allMax,
          static_cast<double>(view.routedBytes) * perSecond,
          static_cast<unsigned long long>(view.route.OpsSent()),
          view.routedMax,
          static_cast<unsigned long long>(view.route.Lights())
        );
        summary += text;
        using remote::client::EEffectSkip;
        const remote::client::SEffectApplyCounts noCounts{};
        const remote::client::SEffectApplyCounts& applied = view.applier ? view.applier->Total() : noCounts;
        const auto skipped = [&applied](const EEffectSkip why) {
          return static_cast<unsigned long long>(applied.skipped[static_cast<std::size_t>(why)]);
        };
        std::snprintf(
          text,
          sizeof(text),
          "%llu held, %llu sent whole later, %llu dropped with their entity, %llu ops on unknown effects, %llu lanes "
          "didn't read",
          static_cast<unsigned long long>(view.route.Held()),
          static_cast<unsigned long long>(view.route.Released()),
          static_cast<unsigned long long>(view.route.Withdrawn()),
          skipped(EEffectSkip::UnknownEffect),
          static_cast<unsigned long long>(view.failed)
        );
        summary += text;
        // Plan WP9.3: the client's applier on the routed lane, and its effects against the routes' count.
        std::snprintf(
          text,
          sizeof(text),
          "\n  effects client %zu: entities as the client's ids %llu, held under none %llu; applied %llu (created "
          "%llu, "
          "replacing %llu, setters %llu, lights %llu, destroyed by script %llu), ended %llu, dropped with their entity "
          "%llu, at a whole view %llu; skipped: entity not held %llu, unknown effect %llu, name not sent %llu",
          army,
          static_cast<unsigned long long>(view.route.Translated()),
          static_cast<unsigned long long>(view.route.Untranslated()),
          static_cast<unsigned long long>(applied.applied),
          static_cast<unsigned long long>(applied.created),
          static_cast<unsigned long long>(applied.replaced),
          static_cast<unsigned long long>(applied.setters),
          static_cast<unsigned long long>(applied.lights),
          static_cast<unsigned long long>(applied.destroyedByScript),
          static_cast<unsigned long long>(applied.ended),
          static_cast<unsigned long long>(applied.droppedWithEntity),
          static_cast<unsigned long long>(applied.droppedWhole),
          skipped(EEffectSkip::EntityNotHeld),
          skipped(EEffectSkip::UnknownEffect),
          skipped(EEffectSkip::UnknownName)
        );
        summary += text;
        std::snprintf(
          text,
          sizeof(text),
          "\n  effects held %zu: client %zu, routes %zu at the end (mean %.1f a beat); %llu of %llu beats differ (the "
          "most by %llu; first at beat %u: %llu only the client holds, %llu only the routes count), last difference "
          "%lld",
          army,
          view.applier ? view.applier->Live() : std::size_t{0},
          mEffectRoutes->HeldBy(army),
          static_cast<double>(view.routesHeldSum) / static_cast<double>(view.beats),
          static_cast<unsigned long long>(view.beatsDiffering),
          static_cast<unsigned long long>(view.beats),
          static_cast<unsigned long long>(view.mostDifference),
          view.firstDiffering,
          static_cast<unsigned long long>(view.clientOnly),
          static_cast<unsigned long long>(view.routesOnly),
          static_cast<long long>(view.lastDifference)
        );
        summary += text;
        const auto why = [&view](const std::size_t i) {
          return static_cast<unsigned long long>(view.why[i]);
        };
        std::snprintf(
          text,
          sizeof(text),
          "\n  effects differ %zu, summed over those beats: only the client: ended %llu, not sent there and on nothing "
          "%llu, on a record %llu, on a blip %llu, on a blip record it holds but doesn't draw %llu; only the routes: "
          "on "
          "nothing %llu, on a record %llu, on a blip %llu, elsewhere %llu; only the client, on no blip %llu",
          army,
          why(0),
          why(1),
          why(2),
          why(3),
          why(4),
          why(5),
          why(6),
          why(7),
          why(8),
          why(9)
        );
        summary += text;
      }
      std::snprintf(
        text,
        sizeof(text),
        "\n  effects: a view's lane %.2f KB/s with every op, %.2f routed (%.1f %%); %llu effects ended without "
        "reaching "
        "a view (summed over views), %zu live at the end, %.1f KB kept",
        viewBeats != 0u ? static_cast<double>(allBytes) * 10.0 / 1024.0 / static_cast<double>(viewBeats) : 0.0,
        viewBeats != 0u ? static_cast<double>(routedBytes) * 10.0 / 1024.0 / static_cast<double>(viewBeats) : 0.0,
        allBytes != 0u ? 100.0 * static_cast<double>(routedBytes) / static_cast<double>(allBytes) : 0.0,
        static_cast<unsigned long long>(mEffectRoutes->Dropped()),
        mEffectRoutes->Live(),
        static_cast<double>(mEffectRoutes->KeptBytes()) / 1024.0
      );
      summary += text;
      // Per op kind: the ops the views got routed (summed over them) against every op times the views.
      std::size_t views = 0;
      std::array<std::uint64_t, kEffectKinds> routedKinds{};
      for (const SEffectView& view : mEffectViews) {
        views += view.beats != 0u ? 1u : 0u;
        for (std::size_t kind = 0; kind < kEffectKinds; ++kind) {
          routedKinds[kind] += view.kinds[kind];
        }
      }
      std::array<std::uint64_t, 4> beamEnds{};
      for (const SEffectView& view : mEffectViews) {
        for (std::size_t i = 0; i < beamEnds.size(); ++i) {
          beamEnds[i] += view.beamEnds[i];
        }
      }
      std::snprintf(
        text,
        sizeof(text),
        "\n  effects: beams between two entities at their create, summed over the views: both ends held %llu, only the "
        "first %llu, only the second %llu, neither %llu",
        static_cast<unsigned long long>(beamEnds[3]),
        static_cast<unsigned long long>(beamEnds[1]),
        static_cast<unsigned long long>(beamEnds[2]),
        static_cast<unsigned long long>(beamEnds[0])
      );
      summary += text;
      summary += "\n  effects by kind, routed / every op (summed over the views):";
      for (std::size_t kind = 0; kind < kEffectKinds; ++kind) {
        if (mEffectKinds[kind] == 0u) {
          continue;
        }
        const std::uint64_t all = mEffectKinds[kind] * views;
        std::snprintf(
          text,
          sizeof(text),
          " %s %llu / %llu (%.1f %%);",
          moho::EffectOpName(static_cast<moho::EEffectOp>(kind)),
          static_cast<unsigned long long>(routedKinds[kind]),
          static_cast<unsigned long long>(all),
          all != 0u ? 100.0 * static_cast<double>(routedKinds[kind]) / static_cast<double>(all) : 0.0
        );
        summary += text;
      }
    }
    return summary;
  }
} // namespace faf::headless
