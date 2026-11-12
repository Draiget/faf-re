#pragma once

#include <cstdint>
#include <span>
#include <string>

#include "remote/client/InterpBuffer.h"

// Engine addition, server mode (plan WP10.9, WPR.14): the server-mode client's display, played over a schedule of view
// arrivals with no game. It runs the network driver's buffer (InterpBuffer.h) against a model of the session's clock as
// `CWldSession::SessionFrame` and `WLD_GetSimRate` run it: a frame every `frameSeconds`, the tick fraction advanced by
// the skewed rate (`wld_SkewRateAdjustBase` 1.03 per step of `GetSimSpeed`, at most `wld_SkewRateAdjustMax` 1.15 either
// way), beats taken while the session's tick is behind its clock, the fraction held at a whole tick when none is there.
//
// It counts what a player would see: frames the picture stood still waiting for a beat (stalls), frames that took more
// than one beat with display time at once (jumps: the motion of a tick never shown), beats made up, and how far behind
// the views the display ran. The unit tests feed it scripted schedules; the probe feeds it the arrivals it measured on
// a real link (`--display-model`).

namespace faf::remote::client
{
  /** One view as it came: its beat, the server's stamp of it and this side's clock, in seconds. */
  struct SViewArrival
  {
    std::int32_t beat = 0;
    double serverSeconds = 0.0;
    double localSeconds = 0.0;
  };

  enum class EDisplayPolicy : std::uint8_t
  {
    Master,   // the driver before the buffer: one beat held, the half-step skew of `CBeatClock`, nothing made up
    Buffered, // `CInterpBuffer` with the given config
  };

  struct SDisplayRun
  {
    std::uint64_t frames = 0;
    std::uint64_t ticksShown = 0;  // beats taken with display time (real and made up)
    std::uint64_t synthesized = 0; // made up
    std::uint64_t catchUps = 0;    // real beats taken without display time
    std::uint64_t stallFrames = 0; // frames the session wanted a beat and had none: the picture stood still
    std::uint64_t stallEvents = 0; // runs of such frames
    double stallSeconds = 0.0;
    double longestStall = 0.0;
    std::uint64_t jumpFrames = 0;   // frames that took two or more beats with display time
    std::uint64_t jumpBeats = 0;    // beats in them past the first: ticks whose motion never reached the screen
    std::uint64_t mergedFrames = 0; // frames that applied two or more real beats (a catch-up with the next one)
    double meanDelayMs = 0.0;       // a real beat's display start behind its quickest possible arrival, on average
    double p95DelayMs = 0.0;
    double meanTarget = 0.0; // the buffer's target depth over the frames
    std::int32_t mostTarget = 0;
    SInterpStats buffer; // the buffer's own counts at the end
  };

  /** Plays `arrivals` (in beat order) through the driver and the session's clock; frames from the first to the last. */
  [[nodiscard]] SDisplayRun RunDisplayModel(
    std::span<const SViewArrival> arrivals,
    EDisplayPolicy policy,
    const SInterpConfig& config,
    double frameSeconds = 1.0 / 60.0
  );

  /** One line of a run's counts, for logs: `label: stalls ..., jumps ..., ...`. */
  [[nodiscard]] std::string DescribeDisplayRun(const char* label, const SDisplayRun& run);
} // namespace faf::remote::client
