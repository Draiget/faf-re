#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>

// Engine addition, server mode (plan WP10.9, WPR.14; plan §7.1 "Client timeline"): the server-mode client's
// interpolation buffer. The session shows a beat when its own clock reaches it (`CWldSession::SessionFrame` takes one
// packet per tick of `WLD_GetSimRate`'s clock), so a view that comes late either stalls the picture (the session finds
// no packet and holds its last tick) or, once it and the next ones come, makes the clock run ahead to catch up. The
// buffer keeps the display a few beats behind the newest view: how many is its target depth, sized from how late the
// views have been coming. The driver's `GetSimSpeed` steers the session's clock towards that depth (`Skew`), slowly,
// so the picture never jumps for it.
//
// When the display wants a beat and none has come, the buffer lets the driver make one up from what the client holds,
// for at most `synthBeats` beats past the last real view (BeatSynthesis.h: entity transforms carried on by the last
// beat's motion, everything else held). The real beats that then come for those display ticks are catch-up beats: the
// session applies them without display time of their own (not `mAdvanced`), at the tick already shown, and the next
// beat that gets display time starts from what was on screen. Nothing the server didn't send is ever applied: a
// synthesized beat carries only transforms (and poses held still); creations, deaths, the Lua `Sync`, armies and
// effects wait for the real beat.
//
// Pure logic with no engine types, so the unit tests and the probe's display model (DisplayModel.h) run the same code
// the game client does.

namespace faf::remote::client
{
  struct SInterpConfig
  {
    bool enabled = true;         // `net_ClientInterp`: false shows each view as it comes (no depth held, none made up)
    bool adaptive = true;        // `net_ClientInterpAdaptive`: false fixes the depth at `floorBeats`
    std::int32_t floorBeats = 1; // `net_ClientInterpTicks`: the least depth
    std::int32_t maxBeats = 10;  // `net_ClientInterpMaxTicks`: the most depth adaptation may reach
    std::int32_t synthBeats = 2; // `net_ClientExtrapolateBeats`: beats past the last real view that may be made up

    [[nodiscard]] bool operator==(const SInterpConfig& other) const noexcept = default;
  };

  enum class EBeatKind : std::uint8_t
  {
    Real,        // a view's beat, with display time of its own
    CatchUp,     // a view's beat for a display tick a made-up beat already took
    Synthesized, // made up by the client
  };

  /** What the driver stamps on a packet: which beat's data it holds and where on the display it stands. */
  struct SBeatStamp
  {
    EBeatKind kind = EBeatKind::Real;
    std::int32_t beat = 0;  // the server beat of its data (`SSyncData::mCurBeat`); made up: the last real one's
    std::int32_t tick = 0;  // the display tick it stands at (`SSyncData::mCurTick`), never lower than the last one's
    bool advanced = true;   // the session gives it display time (`SSyncData::mAdvanced`)
    std::int32_t ahead = 0; // made up: beats past the last real view (1 .. synthBeats)
  };

  struct SInterpStats
  {
    std::uint64_t views = 0;
    std::uint64_t lateViews = 0;   // came after the display had asked for their beat
    std::uint64_t underruns = 0;   // display ticks that found no view held
    std::uint64_t synthesized = 0; // of them, made up
    std::uint64_t stalls = 0;      // and those that stalled the picture (nothing could be made up)
    double stallSeconds = 0.0;     // how long the picture stood still waiting, all told
    double longestStall = 0.0;     // the longest one
    std::uint64_t catchUps = 0;    // views whose display tick a made-up beat had taken
    std::uint64_t outages = 0;     // gaps with no view longer than `kOutageSeconds`
    std::uint64_t raised = 0;      // times the target depth grew
    std::uint64_t lowered = 0;     // times it shrank
    std::int32_t mostTarget = 0;   // the deepest target so far
    double lateness95Ms = 0.0;     // the views' lateness, last measured: 95th percentile
    double latenessMedianMs = 0.0; // and median, both against the quickest view of the window
  };

  class CInterpBuffer
  {
  public:
    /** Views whose lateness sizes the depth: 20 s of game at speed 0. */
    static constexpr std::size_t kWindow = 200;
    /** Views needed before the depth adapts. */
    static constexpr std::size_t kWarmup = 20;
    /** A shorter target waits this long before the depth goes down a beat. */
    static constexpr double kShrinkSeconds = 10.0;
    /**
     * Beats of slack the depth keeps over the views' lateness: the display takes a beat on the frame after its tick
     * comes, and the clock's steering is never exact.
     */
    static constexpr double kSlackBeats = 0.3;
    /**
     * No view for longer than this is an outage (a cut), not jitter: the views it held back don't size the depth. A
     * resend after a lost datagram comes within a round trip or two, well inside it.
     */
    static constexpr double kOutageSeconds = 0.6;
    /** After an outage, views that come less than this many beats after the one before are its burst. */
    static constexpr double kBurstGapBeats = 0.5;
    /** `Skew` per beat of depth off the target (`wld_SkewRateAdjustBase` 1.03: 3 % faster or slower per beat). */
    static constexpr double kSkewPerBeat = 1.0;
    /** The most `Skew` either way: past `wld_SkewRateAdjustMax`'s 15 % the session clamps it anyway. */
    static constexpr double kMaxSkew = 5.0;

    void Configure(const SInterpConfig& config) noexcept;
    [[nodiscard]] const SInterpConfig& Config() const noexcept
    {
      return mConfig;
    }
    /** The beat's length in seconds at the server's sim rate (0.1 at speed 0). */
    void SetBeatSeconds(double seconds) noexcept;

    /**
     * A view's packet, made in beat order: its stamp. `serverSeconds`: the server's clock when it built the beat (the
     * frame's stamp); `now`: this client's clock when the view came. Both in seconds, from any start.
     */
    [[nodiscard]] SBeatStamp OnView(std::int32_t beat, double serverSeconds, double now);
    /**
     * The session wants a beat and the driver holds none: the stamp of one to make up, or none, and the picture stands
     * still. Asked again each frame the session waits; counted once a display tick.
     */
    [[nodiscard]] std::optional<SBeatStamp> OnUnderrun(double now);
    /** The session took a packet with this stamp. */
    void OnTaken(const SBeatStamp& stamp, double now) noexcept;

    /** `ISTIDriver::GetSimSpeed` for `WLD_GetSimRate`'s skew: positive slows the display, negative hurries it. */
    [[nodiscard]] double Skew(double now) const noexcept;
    /** The depth the buffer steers to, in beats (0 when off). */
    [[nodiscard]] std::int32_t TargetDepth() const noexcept;
    /** Beats between the newest view and what the display shows now (fractional; negative while it shows made-up
     * beats). */
    [[nodiscard]] double Depth(double now) const noexcept;
    [[nodiscard]] const SInterpStats& Stats() const noexcept
    {
      return mStats;
    }
    [[nodiscard]] bool HasViews() const noexcept
    {
      return mLastRealBeat >= 0;
    }
    /**
     * The game's start: the session has taken nothing yet and the views haven't reached the target depth past the first
     * one, so the first beat waits (a fraction of a second on the loading screen) and the display starts that far back.
     */
    [[nodiscard]] bool HoldStart() const noexcept
    {
      return mShownTick < 0 && (mLastRealBeat < 0 || mLastRealBeat < mFirstBeat + mTarget);
    }
    /** The newest real beat (-1 before the first view). */
    [[nodiscard]] std::int32_t LastRealBeat() const noexcept
    {
      return mLastRealBeat;
    }

  private:
    void Resize(double now);

    SInterpConfig mConfig;
    SInterpStats mStats;
    double mBeatSeconds = 0.1;
    std::int32_t mTarget = 1;
    std::int32_t mLastRealBeat = -1;
    std::int32_t mFirstBeat = -1;
    double mLastViewAt = 0.0;
    std::int32_t mLastTick = -1;   // the display tick of the newest stamp handed out
    std::int32_t mSynthUntil = -1; // the highest display tick made up
    std::int32_t mShownTick = -1;  // the display tick the session showed last
    double mShownAt = 0.0;         // when it took it
    std::int32_t mWantedTick = -1; // the highest display tick the session asked for and found nothing
    bool mStalled = false;         // the picture stands still since `mStallStart`
    double mStallStart = 0.0;
    double mShorterSince = -1.0;  // since when a shorter target would do (-1: not)
    bool mInOutageBurst = false;  // the views coming now are an outage's burst
    std::deque<double> mTransits; // the window's views: arrival minus the server's stamp, seconds
  };
} // namespace faf::remote::client
