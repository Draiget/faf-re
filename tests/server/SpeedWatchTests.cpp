// Engine addition, dedicated server: which sim speed news reaches the server's console.
//
// Build: cmake --build --preset linux-clang-x64-release-plain --target faf_server_tests
// Run:   build/linux-clang-x64-release-plain/faf_server_tests   (exit code = failures)

#include <cmath>
#include <cstdio>

#include <gtest/gtest.h>

#include "server/SpeedWatch.h"

namespace
{
  void Check(const bool ok, const char* const what)
  {
    EXPECT_TRUE(ok) << what;
  }

  using faf::server::CSpeedWatch;
  using faf::server::SSpeedNews;
  using faf::server::SSpeedSample;

  /** Samples once a second over `[from, to)` and adds up what they reported. */
  struct SRun
  {
    int requestChanges = 0;
    int speedChanges = 0;
    int speedBefore = 0;
    int slowStarts = 0;
    int slowEnds = 0;

    void Play(CSpeedWatch& watch, const int from, const int to, const int requested, const int speed, const float beatMs)
    {
      for (int second = from; second < to; ++second) {
        const SSpeedNews news = watch.Update(SSpeedSample{static_cast<double>(second), requested, speed, beatMs});
        requestChanges += news.requestChanged ? 1 : 0;
        if (news.speedChanged) {
          ++speedChanges;
          speedBefore = news.speedBefore;
        }
        slowStarts += news.slowStarted ? 1 : 0;
        slowEnds += news.slowEnded ? 1 : 0;
      }
    }
  };

  void QuietWhileSteady()
  {
    CSpeedWatch watch(90.0f);
    SRun run;
    run.Play(watch, 0, 3600, 1, 1, 60.0f);
    Check(run.requestChanges == 0 && run.speedChanges == 0 && run.slowStarts == 0 && run.slowEnds == 0, "an hour of steady speed says nothing");
  }

  void SpeedChangeMustHold()
  {
    CSpeedWatch watch(90.0f);
    SRun run;
    run.Play(watch, 0, 10, 1, 1, 60.0f);
    for (int second = 10; second < 300; second += 20) {
      run.Play(watch, second, second + 10, 1, 0, 80.0f);
      run.Play(watch, second + 10, second + 20, 1, 1, 70.0f);
    }
    Check(run.speedChanges == 0, "a speed flickering every 10 s says nothing");
    run.Play(watch, 300, 330, 1, 0, 85.0f);
    Check(run.speedChanges == 1, "a new speed that holds is reported once");
    Check(run.speedBefore == 1, "the report names the speed before");
  }

  void RequestReportedAtOnce()
  {
    CSpeedWatch watch(90.0f);
    SRun run;
    run.Play(watch, 0, 10, 0, 0, 30.0f);
    run.Play(watch, 10, 11, 4, 0, 30.0f);
    Check(run.requestChanges == 1, "a new request is reported on its first sample");
  }

  void SlowWarnsOnce()
  {
    CSpeedWatch watch(90.0f);
    SRun run;
    run.Play(watch, 0, 10, 0, 0, 60.0f);
    run.Play(watch, 10, 13, 0, 0, 95.0f);
    Check(run.slowStarts == 0, "a short spike doesn't warn");
    run.Play(watch, 13, 20, 0, 0, 60.0f);
    run.Play(watch, 20, 200, 0, 0, 95.0f);
    Check(run.slowStarts == 1, "a slow stretch warns once");
    run.Play(watch, 200, 400, 0, 0, 88.0f);
    Check(run.slowEnds == 0, "just under the warning level isn't over");
    run.Play(watch, 400, 420, 0, 0, 60.0f);
    Check(run.slowEnds == 0, "20 calm seconds aren't over");
    run.Play(watch, 420, 440, 0, 0, 60.0f);
    Check(run.slowEnds == 1, "calm for long enough is over");
    run.Play(watch, 440, 460, 0, 0, 95.0f);
    Check(run.slowStarts == 2, "a new slow stretch warns again");
  }

  void SpeedScale()
  {
    using faf::server::SecondsPerBeat;
    using faf::server::SpeedOfBeatRate;
    Check(std::fabs(SecondsPerBeat(0) - 0.1) < 1e-9, "+0 is 100 ms a beat");
    Check(std::fabs(SecondsPerBeat(1) - 0.07943) < 1e-4, "+1 is 79.4 ms a beat");
    Check(std::fabs(SecondsPerBeat(-1) - 0.12589) < 1e-4, "-1 is 125.9 ms a beat");
    Check(SpeedOfBeatRate(10.0) == 0, "ten beats a second is +0");
    Check(SpeedOfBeatRate(9.9) == 0, "a beat lost in ten seconds is still +0");
    Check(SpeedOfBeatRate(12.6) == 1, "12.6 beats a second is +1");
    Check(SpeedOfBeatRate(7.94) == -1, "7.94 beats a second is -1");
    Check(SpeedOfBeatRate(0.0) == -10, "no beats is the slowest speed");
    Check(SpeedOfBeatRate(1.0e9) == 50, "a burst stays in range");
  }

  void NoMeasureNoWarning()
  {
    CSpeedWatch watch(90.0f);
    SRun run;
    run.Play(watch, 0, 60, 0, 0, 0.0f);
    Check(run.slowStarts == 0, "no measure yet says nothing");
  }
} // namespace

TEST(Existing_SpeedWatch, QuietWhileSteady) { QuietWhileSteady(); }
TEST(Existing_SpeedWatch, SpeedChangeMustHold) { SpeedChangeMustHold(); }
TEST(Existing_SpeedWatch, RequestReportedAtOnce) { RequestReportedAtOnce(); }
TEST(Existing_SpeedWatch, SlowWarnsOnce) { SlowWarnsOnce(); }
TEST(Existing_SpeedWatch, NoMeasureNoWarning) { NoMeasureNoWarning(); }
TEST(Existing_SpeedWatch, SpeedScale) { SpeedScale(); }
