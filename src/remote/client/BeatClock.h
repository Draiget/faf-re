#pragma once

#include <cstdint>

// Engine addition, server mode (plan WP11.5): the remote client's clock of the server's beats.
// Each frame brings the server's beat, sim rate and clock; the client measures how fast beats
// arrive against how fast the rate says they should, and how many it holds that the session
// has not shown yet. `WLD_GetSimRate` takes the sim rate from the server (through the client
// manager) and the skew the driver reports (`GetSimSpeed`), which this clock computes, so the
// display neither runs ahead of the frames nor falls behind them.

namespace faf::remote::client
{
  class CBeatClock
  {
  public:
    /**
     * `targetBacklog`: the frames the client holds back against arrival jitter. In loopback the
     * frames come as the sim makes them and are shown at once, so it is 0 and the skew stays 0,
     * as the lockstep driver's GetSimSpeed is.
     */
    explicit CBeatClock(std::int64_t targetBacklog = 0) noexcept
      : mTargetBacklog(targetBacklog)
    {}

    /** Beats per second at sim rate 0 (the game's ten ticks a second). */
    static constexpr double kBeatsPerSecondAtRate0 = 10.0;

    /** A frame arrived: its beat, the server's rate and clock, and the local clock (seconds). */
    void OnFrame(std::uint32_t beat, std::int32_t simRate, std::uint32_t serverMs, double localSeconds) noexcept;
    /** The session showed a beat (took a sync packet). */
    void OnShown(std::uint32_t beat) noexcept { mShownBeat = beat; }

    [[nodiscard]] bool HasFrames() const noexcept { return mFrames != 0u; }
    [[nodiscard]] std::int32_t ServerSimRate() const noexcept { return mSimRate; }
    /** Beats a second the rate asks for: 10 * 10^(rate / 10). */
    [[nodiscard]] double ExpectedBeatsPerSecond() const noexcept;
    /** Measured on the server's clock, smoothed. */
    [[nodiscard]] double ServerBeatsPerSecond() const noexcept { return mServerRate; }
    /** Measured on the local clock (arrival), smoothed. */
    [[nodiscard]] double ArrivalBeatsPerSecond() const noexcept { return mArrivalRate; }
    /** Frames received that the session has not shown yet. */
    [[nodiscard]] std::int64_t Backlog() const noexcept;
    /**
     * The driver's `GetSimSpeed` for `WLD_GetSimRate`'s skew (`base^-speed`): positive slows the
     * display, negative hurries it. Zero while the backlog is the target; each beat short of it
     * or past it is half a step.
     */
    [[nodiscard]] double Skew() const noexcept;

  private:
    std::uint64_t mFrames = 0;
    std::uint32_t mLastBeat = 0;
    std::uint32_t mLastServerMs = 0;
    double mLastLocal = 0.0;
    std::int32_t mSimRate = 0;
    double mServerRate = 0.0;
    double mArrivalRate = 0.0;
    std::uint32_t mShownBeat = 0;
    std::int64_t mTargetBacklog;
  };
} // namespace faf::remote::client
