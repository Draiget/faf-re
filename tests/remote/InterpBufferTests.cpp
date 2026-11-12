// Engine addition, server mode (plan WP10.9, WPR.14): the server-mode client's interpolation buffer
// (src/remote/client/InterpBuffer.h), its beat synthesis (BeatSynthesis.h) and the display model both run under
// (DisplayModel.h), on scripted view arrivals: steady, jittery, bursts behind a lost datagram, a lone late view, a cut.
// No engine and no game: the model plays the session's clock as `CWldSession::SessionFrame` runs it.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <vector>

#include <gtest/gtest.h>

#include "remote/client/BeatSynthesis.h"
#include "remote/client/DisplayModel.h"
#include "remote/client/InterpBuffer.h"

namespace
{
  using faf::remote::client::CBeatSynthesizer;
  using faf::remote::client::CInterpBuffer;
  using faf::remote::client::DescribeDisplayRun;
  using faf::remote::client::EBeatKind;
  using faf::remote::client::EDisplayPolicy;
  using faf::remote::client::ExtrapolateTransform;
  using faf::remote::client::RunDisplayModel;
  using faf::remote::client::SDisplayRun;
  using faf::remote::client::SInterpConfig;
  using faf::remote::client::SSynthTransform;
  using faf::remote::client::SSynthUpdate;
  using faf::remote::client::SViewArrival;

  constexpr double kBeat = 0.1;
  constexpr double kTransit = 0.04; // the quickest a view crosses the link

  /** A small deterministic generator, the same numbers on every platform. */
  class CNoise
  {
  public:
    explicit CNoise(
      std::uint32_t seed
    )
      : mState(seed != 0u ? seed : 1u)
    {}
    /** In [0, 1). */
    double Next()
    {
      mState ^= mState << 13u;
      mState ^= mState >> 17u;
      mState ^= mState << 5u;
      return static_cast<double>(mState) / 4294967296.0;
    }

  private:
    std::uint32_t mState;
  };

  /**
   * `beats` views, beat b built at b * 0.1 s on the server's clock and arriving `kTransit` plus `lateness(b)` later,
   * in beat order as the reliable stream delivers them: a view never arrives before the one ahead of it (a lost
   * datagram holds up every view behind it).
   */
  std::vector<SViewArrival> Schedule(
    const int beats,
    const std::function<double(int)>& lateness
  )
  {
    std::vector<SViewArrival> out;
    double previous = 0.0;
    for (int beat = 0; beat < beats; ++beat) {
      SViewArrival arrival;
      arrival.beat = beat;
      arrival.serverSeconds = beat * kBeat;
      arrival.localSeconds = std::max(previous, 100.0 + arrival.serverSeconds + kTransit + lateness(beat));
      previous = arrival.localSeconds;
      out.push_back(arrival);
    }
    return out;
  }

  SInterpConfig Adaptive()
  {
    return SInterpConfig{};
  }

  SInterpConfig NoSynthesis()
  {
    SInterpConfig config;
    config.synthBeats = 0;
    return config;
  }

  SInterpConfig Off()
  {
    SInterpConfig config;
    config.enabled = false;
    return config;
  }

  SDisplayRun Play(
    const std::vector<SViewArrival>& arrivals,
    const EDisplayPolicy policy,
    const SInterpConfig& config,
    const char* label
  )
  {
    const SDisplayRun run = RunDisplayModel(arrivals, policy, config);
    std::printf("MODEL %s\n", DescribeDisplayRun(label, run).c_str());
    return run;
  }

  // ---- the buffer's stamps --------------------------------------------------------------------------------------

  TEST(
    InterpBuffer,
    MadeUpBeatsThenCatchUpThenReal
  )
  {
    CInterpBuffer buffer;
    buffer.Configure(Adaptive());
    double now = 0.0;
    for (int beat = 0; beat < 3; ++beat) {
      const auto stamp = buffer.OnView(beat, beat * kBeat, now);
      EXPECT_EQ(stamp.kind, EBeatKind::Real);
      EXPECT_EQ(stamp.tick, beat);
      EXPECT_TRUE(stamp.advanced);
      buffer.OnTaken(stamp, now);
      now += kBeat;
    }
    // Two beats may be made up past the last real one (beat 2), then the picture stands still.
    const auto first = buffer.OnUnderrun(now);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->kind, EBeatKind::Synthesized);
    EXPECT_EQ(first->tick, 3);
    EXPECT_EQ(first->beat, 2);
    EXPECT_EQ(first->ahead, 1);
    buffer.OnTaken(*first, now);
    now += kBeat;
    const auto second = buffer.OnUnderrun(now);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->tick, 4);
    EXPECT_EQ(second->ahead, 2);
    buffer.OnTaken(*second, now);
    now += kBeat;
    EXPECT_FALSE(buffer.OnUnderrun(now).has_value());
    EXPECT_FALSE(buffer.OnUnderrun(now + 0.016).has_value()); // the next frame: the same display tick, counted once
    EXPECT_EQ(buffer.Stats().underruns, 3u);
    EXPECT_EQ(buffer.Stats().synthesized, 2u);
    EXPECT_EQ(buffer.Stats().stalls, 1u);

    // The real beats 3 and 4 come for ticks already shown: no display time, at the tick shown; 5 is real again.
    now += 0.05;
    const auto three = buffer.OnView(3, 0.3, now);
    EXPECT_EQ(three.kind, EBeatKind::CatchUp);
    EXPECT_FALSE(three.advanced);
    EXPECT_EQ(three.tick, 4);
    EXPECT_EQ(three.beat, 3);
    const auto four = buffer.OnView(4, 0.4, now);
    EXPECT_EQ(four.kind, EBeatKind::CatchUp);
    EXPECT_EQ(four.tick, 4);
    const auto five = buffer.OnView(5, 0.5, now);
    EXPECT_EQ(five.kind, EBeatKind::Real);
    EXPECT_TRUE(five.advanced);
    EXPECT_EQ(five.tick, 5);
    buffer.OnTaken(three, now);
    buffer.OnTaken(four, now);
    buffer.OnTaken(five, now);
    EXPECT_EQ(buffer.Stats().catchUps, 2u);
    EXPECT_EQ(buffer.Stats().lateViews, 3u);              // 3, 4 and 5 all came after the display asked for their tick
    EXPECT_NEAR(buffer.Stats().longestStall, 0.05, 1e-9); // from the refused tick to the real beat 5
  }

  TEST(
    InterpBuffer,
    SwitchesOffAndFixed
  )
  {
    CNoise noise(7u);
    const auto arrivals = Schedule(600, [&noise](int) {
      return noise.Next() * 0.5; // up to 500 ms late
    });
    CInterpBuffer off;
    off.Configure(Off());
    CInterpBuffer fixed;
    SInterpConfig fixedConfig;
    fixedConfig.adaptive = false;
    fixedConfig.floorBeats = 2;
    fixed.Configure(fixedConfig);
    CInterpBuffer capped;
    SInterpConfig cappedConfig;
    cappedConfig.maxBeats = 3;
    capped.Configure(cappedConfig);
    for (const SViewArrival& arrival : arrivals) {
      (void)off.OnView(arrival.beat, arrival.serverSeconds, arrival.localSeconds);
      (void)fixed.OnView(arrival.beat, arrival.serverSeconds, arrival.localSeconds);
      (void)capped.OnView(arrival.beat, arrival.serverSeconds, arrival.localSeconds);
      EXPECT_EQ(off.TargetDepth(), 0);
      EXPECT_EQ(fixed.TargetDepth(), 2);
      EXPECT_LE(capped.TargetDepth(), 3);
    }
    EXPECT_EQ(capped.TargetDepth(), 3);
    EXPECT_GT(off.Stats().lateness95Ms, 300.0); // measured either way, for the log
    EXPECT_FALSE(off.OnUnderrun(1000.0).has_value());
  }

  // ---- sizing from the views' lateness ----------------------------------------------------------------------------

  TEST(
    InterpBuffer,
    SteadyViewsKeepOneBeat
  )
  {
    const auto arrivals = Schedule(1200, [](int) {
      return 0.0;
    });
    const SDisplayRun run = Play(arrivals, EDisplayPolicy::Buffered, Adaptive(), "steady adaptive");
    EXPECT_EQ(run.mostTarget, 1);
    EXPECT_EQ(run.stallFrames, 0u);
    EXPECT_EQ(run.synthesized, 0u);
    EXPECT_EQ(run.jumpFrames, 0u);
    EXPECT_GE(run.ticksShown, 1195u);
    EXPECT_GT(run.meanDelayMs, 60.0); // one beat behind the views, less what the frames round off
    EXPECT_LT(run.meanDelayMs, 140.0);
  }

  TEST(
    InterpBuffer,
    JitterSizesTheDepth
  )
  {
    CNoise noise(11u);
    const auto arrivals = Schedule(1200, [&noise](int) {
      return noise.Next() * 0.25;
    });
    const SDisplayRun off = Play(arrivals, EDisplayPolicy::Buffered, Off(), "jitter 0-250 ms off");
    const SDisplayRun master = Play(arrivals, EDisplayPolicy::Master, Adaptive(), "jitter 0-250 ms master");
    const SDisplayRun adaptive = Play(arrivals, EDisplayPolicy::Buffered, Adaptive(), "jitter 0-250 ms adaptive");
    EXPECT_GE(adaptive.mostTarget, 2);
    EXPECT_LE(adaptive.mostTarget, 3);
    EXPECT_LT(adaptive.stallFrames, master.stallFrames);
    EXPECT_LT(adaptive.stallFrames, off.stallFrames);
    EXPECT_EQ(adaptive.jumpFrames, 0u);
    // What the depth costs: the display runs further behind the views than with none held.
    EXPECT_GT(adaptive.meanDelayMs, off.meanDelayMs);
  }

  TEST(
    InterpBuffer,
    BurstsBehindLostDatagrams
  )
  {
    // Every 5 s a datagram is lost and its resend comes 300 ms later: the views behind it come all at once.
    const auto arrivals = Schedule(1800, [](const int beat) {
      const int phase = beat % 50;
      return phase >= 20 && phase < 23 ? 0.3 - 0.1 * (phase - 20) : 0.0;
    });
    const SDisplayRun master = Play(arrivals, EDisplayPolicy::Master, Adaptive(), "bursts master");
    const SDisplayRun noSynth =
      Play(arrivals, EDisplayPolicy::Buffered, NoSynthesis(), "bursts adaptive, none made up");
    const SDisplayRun adaptive = Play(arrivals, EDisplayPolicy::Buffered, Adaptive(), "bursts adaptive");
    EXPECT_GT(master.stallEvents, 20u);
    // The bursts are 6 % of the views: the depth covers most of their lateness (2 beats, 3 at first), the rest is made
    // up instead of standing still.
    EXPECT_GE(adaptive.mostTarget, 2);
    EXPECT_LE(adaptive.stallEvents, 1u);
    EXPECT_LT(adaptive.stallFrames, master.stallFrames / 10u);
    EXPECT_LT(noSynth.stallFrames, master.stallFrames);
    EXPECT_EQ(adaptive.jumpFrames, 0u);
  }

  TEST(
    InterpBuffer,
    ShrinksSlowlyOnceTheLinkCalms
  )
  {
    CNoise noise(3u);
    // 60 s of 0-300 ms jitter, then 120 s of none.
    const auto arrivals = Schedule(1800, [&noise](const int beat) {
      return beat < 600 ? noise.Next() * 0.3 : 0.0;
    });
    CInterpBuffer buffer;
    buffer.Configure(Adaptive());
    std::int32_t most = 0;
    std::vector<double> lowered; // when each step down happened
    std::int32_t previous = 1;
    for (const SViewArrival& arrival : arrivals) {
      (void)buffer.OnView(arrival.beat, arrival.serverSeconds, arrival.localSeconds);
      most = std::max(most, buffer.TargetDepth());
      if (buffer.TargetDepth() < previous) {
        lowered.push_back(arrival.localSeconds);
      }
      previous = buffer.TargetDepth();
    }
    EXPECT_GE(most, 3);
    EXPECT_EQ(buffer.TargetDepth(), 1);
    ASSERT_GE(lowered.size(), 2u);
    for (std::size_t i = 1; i < lowered.size(); ++i) {
      EXPECT_GE(lowered[i] - lowered[i - 1], CInterpBuffer::kShrinkSeconds - 0.2); // a beat at a time
    }
  }

  // ---- loss: made-up beats, and the recovery after them -----------------------------------------------------------

  TEST(
    InterpBuffer,
    ALoneLateViewIsMadeUpNotStalled
  )
  {
    // One view in 20 s comes 250 ms late (the views behind it with it): too rare to deepen the buffer.
    const auto arrivals = Schedule(1800, [](const int beat) {
      return beat % 200 == 100 ? 0.25 : 0.0;
    });
    const SDisplayRun noSynth = Play(arrivals, EDisplayPolicy::Buffered, NoSynthesis(), "lone late view, none made up");
    const SDisplayRun adaptive = Play(arrivals, EDisplayPolicy::Buffered, Adaptive(), "lone late view adaptive");
    EXPECT_EQ(adaptive.mostTarget, 1);
    EXPECT_GE(noSynth.stallEvents, 8u);
    EXPECT_GT(adaptive.synthesized, 8u);
    EXPECT_LT(adaptive.stallFrames, noSynth.stallFrames / 4u);
    EXPECT_GE(adaptive.catchUps, adaptive.synthesized - 2u); // each made-up tick's real beat came and was caught up
    EXPECT_EQ(adaptive.jumpFrames, 0u);
  }

  TEST(
    InterpBuffer,
    ACutIsBoundedThenCaughtUp
  )
  {
    // A 2 s cut at 30 s: nothing for 2 s, then every view at once.
    const auto arrivals = Schedule(1200, [](const int beat) {
      return beat >= 300 && beat < 320 ? 2.0 - 0.1 * (beat - 300) : 0.0;
    });
    const SDisplayRun master = Play(arrivals, EDisplayPolicy::Master, Adaptive(), "2 s cut master");
    const SDisplayRun adaptive = Play(arrivals, EDisplayPolicy::Buffered, Adaptive(), "2 s cut adaptive");
    // At most two beats are made up, then the picture waits: no invented motion past 200 ms.
    EXPECT_LE(adaptive.synthesized, 2u);
    EXPECT_GE(adaptive.stallSeconds, 1.5);
    EXPECT_LE(adaptive.longestStall, 2.0);
    EXPECT_EQ(adaptive.jumpFrames, 0u);
    // The display then catches up with the views faster than before (15 % against 6 %).
    EXPECT_LT(adaptive.meanDelayMs, master.meanDelayMs);
    EXPECT_EQ(adaptive.mostTarget, 1); // a cut is no jitter: the depth stays
  }

  TEST(
    InterpBuffer,
    ACutsHeldViewsTricklingInDontDeepenIt
  )
  {
    // As a real link delivers a cut's held-back views (a game client found it): not at once but 20 ms apart, the
    // views behind them with them, until they have caught up.
    const auto arrivals = Schedule(1200, [](const int beat) {
      return beat >= 300 && beat < 325 ? 2.0 - 0.08 * (beat - 300) : 0.0;
    });
    const SDisplayRun adaptive = Play(arrivals, EDisplayPolicy::Buffered, Adaptive(), "2 s cut, trickling, adaptive");
    EXPECT_EQ(adaptive.mostTarget, 1);
    EXPECT_EQ(adaptive.buffer.outages, 1u);
    EXPECT_EQ(adaptive.stallEvents, 1u); // the cut itself
    EXPECT_LE(adaptive.synthesized, 4u); // two before it, and one or two while its views trickle in
  }

  // ---- what a made-up beat shows -------------------------------------------------------------------------------

  SSynthTransform At(
    const float x,
    const float z,
    const float yawDegrees = 0.0f
  )
  {
    SSynthTransform t;
    t.px = x;
    t.pz = z;
    const double half = yawDegrees * 3.14159265358979323846 / 360.0;
    t.qw = static_cast<float>(std::cos(half));
    t.qy = static_cast<float>(std::sin(half));
    return t;
  }

  TEST(
    BeatSynthesis,
    CarriesPositionAndTurnOn
  )
  {
    const SSynthTransform out = ExtrapolateTransform(At(0.0f, 0.0f, 0.0f), At(1.0f, 2.0f, 10.0f), 2);
    EXPECT_NEAR(out.px, 3.0f, 1e-5f);
    EXPECT_NEAR(out.pz, 6.0f, 1e-5f);
    const SSynthTransform yaw30 = At(0.0f, 0.0f, 30.0f);
    EXPECT_NEAR(out.qw, yaw30.qw, 1e-5f);
    EXPECT_NEAR(out.qy, yaw30.qy, 1e-5f);
    // A turn across the quaternion's sign flip goes the short way.
    SSynthTransform flipped = At(0.0f, 0.0f, 350.0f);
    flipped.qw = -flipped.qw;
    flipped.qy = -flipped.qy;
    const SSynthTransform across = ExtrapolateTransform(flipped, At(0.0f, 0.0f, 0.0f), 1);
    const SSynthTransform yaw10 = At(0.0f, 0.0f, 10.0f);
    EXPECT_NEAR(std::fabs(across.qw * yaw10.qw + across.qy * yaw10.qy), 1.0f, 1e-5f);
    // A warp is held where it landed.
    const SSynthTransform warped = ExtrapolateTransform(At(0.0f, 0.0f), At(300.0f, 0.0f), 1);
    EXPECT_EQ(warped, At(300.0f, 0.0f));
  }

  TEST(
    BeatSynthesis,
    MadeUpBeatsThenTheRealPathEasesBack
  )
  {
    // The client's real data: id -> (last, current).
    std::map<std::uint32_t, std::pair<SSynthTransform, SSynthTransform>> held;
    held[1] = {At(9.0f, 0.0f), At(10.0f, 0.0f)}; // moving +1 x a beat
    held[2] = {At(5.0f, 5.0f), At(5.0f, 5.0f)};  // still
    held[3] = {At(0.0f, 0.0f), At(0.0f, 0.0f)};  // still, will move in a catch-up beat
    const CBeatSynthesizer::ForEach forEach = [&held](const auto& visit) {
      for (const auto& [id, pair] : held) {
        visit(id, pair.first, pair.second);
      }
    };
    const CBeatSynthesizer::Lookup lookup = [&held](std::uint32_t id, SSynthTransform& last, SSynthTransform& cur) {
      const auto found = held.find(id);
      if (found == held.end()) {
        return false;
      }
      last = found->second.first;
      cur = found->second.second;
      return true;
    };
    CBeatSynthesizer synth;
    std::vector<SSynthUpdate> out;
    // Ticks 11 and 12 made up from beat 10.
    synth.Synthesize(11, 1, forEach, lookup, out);
    ASSERT_EQ(out.size(), 1u); // only the mover
    EXPECT_EQ(out[0].id, 1u);
    EXPECT_EQ(out[0].last, At(10.0f, 0.0f));
    EXPECT_EQ(out[0].cur, At(11.0f, 0.0f));
    synth.Synthesize(12, 2, forEach, lookup, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].last, At(11.0f, 0.0f)); // from where the screen showed it
    EXPECT_EQ(out[0].cur, At(12.0f, 0.0f));
    EXPECT_EQ(synth.Shown(), 1u);

    // Real beat 11 comes (a catch-up): the mover slowed to +0.5, and entity 3 started moving.
    held[1] = {At(10.0f, 0.0f), At(10.5f, 0.0f)};
    held[3] = {At(0.0f, 0.0f), At(0.0f, 1.0f)};
    synth.CompareWithReal(11, lookup);
    synth.OnCatchUp({{1, At(10.0f, 0.0f), At(10.5f, 0.0f)}, {3, At(0.0f, 0.0f), At(0.0f, 1.0f)}});
    EXPECT_EQ(synth.Stats().compared, 1u);
    EXPECT_NEAR(synth.Stats().errorMost, 0.5, 1e-6); // made up 11 against 10.5
    EXPECT_EQ(synth.Shown(), 2u);                    // entity 3 is shown at 0, not 1, until a beat with display time

    // Real beat 12 (a catch-up too), then 13 with display time; 13 updates only the mover.
    held[1] = {At(10.5f, 0.0f), At(11.0f, 0.0f)};
    held[3] = {At(0.0f, 1.0f), At(0.0f, 1.0f)};
    synth.CompareWithReal(12, lookup);
    synth.OnCatchUp({{1, At(10.5f, 0.0f), At(11.0f, 0.0f)}, {3, At(0.0f, 1.0f), At(0.0f, 1.0f)}});
    held[1] = {At(11.0f, 0.0f), At(11.5f, 0.0f)};
    std::vector<SSynthUpdate> beat13 = {{1, At(11.0f, 0.0f), At(11.5f, 0.0f)}};
    std::vector<SSynthUpdate> added;
    synth.OnAdvance(beat13, lookup, added);
    // The mover starts from the made-up 12 the screen showed, and entity 3 from 0, where the screen left it.
    EXPECT_EQ(beat13[0].last, At(12.0f, 0.0f));
    EXPECT_EQ(beat13[0].cur, At(11.5f, 0.0f));
    ASSERT_EQ(added.size(), 1u);
    EXPECT_EQ(added[0].id, 3u);
    EXPECT_EQ(added[0].last, At(0.0f, 0.0f));
    EXPECT_EQ(added[0].cur, At(0.0f, 1.0f));
    EXPECT_EQ(synth.Shown(), 0u);
    EXPECT_EQ(synth.Stats().eased, 2u);
    EXPECT_EQ(synth.Stats().easedAdded, 1u);
    EXPECT_EQ(synth.Stats().compared, 2u);
  }

  TEST(
    BeatSynthesis,
    AnEntityThatStopsGoesBackToItsRealPlace
  )
  {
    std::map<std::uint32_t, std::pair<SSynthTransform, SSynthTransform>> held;
    held[1] = {At(0.0f, 0.0f), At(1.0f, 0.0f)};
    const CBeatSynthesizer::ForEach forEach = [&held](const auto& visit) {
      for (const auto& [id, pair] : held) {
        visit(id, pair.first, pair.second);
      }
    };
    const CBeatSynthesizer::Lookup lookup = [&held](std::uint32_t id, SSynthTransform& last, SSynthTransform& cur) {
      const auto found = held.find(id);
      if (found == held.end()) {
        return false;
      }
      last = found->second.first;
      cur = found->second.second;
      return true;
    };
    CBeatSynthesizer synth;
    std::vector<SSynthUpdate> out;
    synth.Synthesize(2, 1, forEach, lookup, out); // shown at 2
    // The real beat 2 (a catch-up): it stopped at 1. The next made-up beat brings it back from 2 to 1.
    held[1] = {At(1.0f, 0.0f), At(1.0f, 0.0f)};
    synth.OnCatchUp({{1, At(1.0f, 0.0f), At(1.0f, 0.0f)}});
    synth.Synthesize(3, 1, forEach, lookup, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].last, At(2.0f, 0.0f));
    EXPECT_EQ(out[0].cur, At(1.0f, 0.0f));
    EXPECT_EQ(synth.Shown(), 0u);
    // A deleted entity is dropped, not updated.
    held[1] = {At(1.0f, 0.0f), At(2.0f, 0.0f)};
    synth.Synthesize(4, 1, forEach, lookup, out);
    EXPECT_EQ(synth.Shown(), 1u);
    held.clear();
    synth.Synthesize(5, 2, forEach, lookup, out);
    EXPECT_TRUE(out.empty());
    EXPECT_EQ(synth.Shown(), 0u);
  }
} // namespace
