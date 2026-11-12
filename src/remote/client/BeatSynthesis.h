#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <unordered_map>
#include <vector>

// Engine addition, server mode (plan WP10.9): what a made-up beat shows (InterpBuffer.h), and how the real beats after
// it take the picture back.
//
// The session draws each entity between two transforms, the beat's last and current (`UserEntity::
// GetInterpolatedTransform`), so a made-up beat gives every entity that moved in the last real beat an update whose
// last transform is what the screen shows and whose current one is carried on by that beat's motion: position by the
// same step, orientation by the same turn, `ahead` times (the first made-up beat 1, the next 2 ...). An entity that
// didn't move gets nothing, nor does anything else (health, a creation, a death): those wait for the real beat.
//
// The entities a made-up beat moved are then shown off their real place. A real beat applied at a display tick a
// made-up one took (a catch-up beat) puts the real transforms into the session without display time; the next beat with
// display time (real or made up) starts each such entity from where the screen showed it, so the picture eases back
// onto the real path over one tick instead of jumping there.
//
// Pure logic on plain transforms, for the unit tests; the driver turns them into `SEntityVariableUpdateEntry`s.

namespace faf::remote::client
{
  /** An entity's transform as plain numbers: position, then orientation as a unit quaternion (w, x, y, z). */
  struct SSynthTransform
  {
    float px = 0.0f;
    float py = 0.0f;
    float pz = 0.0f;
    float qw = 1.0f;
    float qx = 0.0f;
    float qy = 0.0f;
    float qz = 0.0f;

    [[nodiscard]] bool operator==(const SSynthTransform& other) const noexcept = default;
  };

  /** A step longer than this (world units a beat) is a teleport, not motion: such an entity is held where it is. */
  inline constexpr float kMaxSynthStep = 50.0f;

  /** `cur` carried on `ahead` more beats by the step from `last` to it (position and turn); held when it teleported. */
  [[nodiscard]] SSynthTransform
  ExtrapolateTransform(const SSynthTransform& last, const SSynthTransform& cur, int ahead);

  /** Whether the session interpolates anything between the two (a moving entity). */
  [[nodiscard]] inline bool Moves(
    const SSynthTransform& last,
    const SSynthTransform& cur
  ) noexcept
  {
    return !(last == cur);
  }

  /** The largest distance between two transforms' positions. */
  [[nodiscard]] float PositionError(const SSynthTransform& a, const SSynthTransform& b) noexcept;

  /** One entity's update to the session: its id, then the transforms the session draws it between. */
  struct SSynthUpdate
  {
    std::uint32_t id = 0;
    SSynthTransform last;
    SSynthTransform cur;
  };

  struct SSynthStats
  {
    std::uint64_t beats = 0;      // made-up beats
    std::uint64_t moved = 0;      // entity updates in them
    std::uint64_t eased = 0;      // entities a beat with display time started from where the screen showed them
    std::uint64_t easedAdded = 0; // of them, entities the real beat had no update for
    std::uint64_t compared = 0;   // made-up positions compared with the real beat's when it came
    double errorSum = 0.0;        // their distances, all told
    double errorMost = 0.0;       // the largest
  };

  class CBeatSynthesizer
  {
  public:
    /** The client's real data of a live entity: its last and current transforms. False: none (gone, not held). */
    using Lookup = std::function<bool(std::uint32_t id, SSynthTransform& last, SSynthTransform& cur)>;
    /** Every live entity the client holds, with its real last and current transforms. */
    using ForEach =
      std::function<void(const std::function<void(std::uint32_t, const SSynthTransform&, const SSynthTransform&)>&)>;

    /**
     * A made-up beat `ahead` beats past the last real one, at display tick `tick`: an update for every entity that
     * moves (`forEach`) or is shown off its real place, into `out` (ascending ids).
     */
    void Synthesize(
      std::int32_t tick,
      std::int32_t ahead,
      const ForEach& forEach,
      const Lookup& lookup,
      std::vector<SSynthUpdate>& out
    );

    /**
     * A real beat for display tick `beat` was applied to the client's data: the made-up positions of that tick, if
     * any, against the real ones (counts only).
     */
    void CompareWithReal(std::int32_t beat, const Lookup& lookup);

    /**
     * A catch-up beat's entity updates (applied with no display time): an entity it moves that the screen showed at
     * its real place is now shown off it, at the transform the session had (the update's last one).
     */
    void OnCatchUp(const std::vector<SSynthUpdate>& updates);

    /**
     * A real beat with display time: the updates it has for entities shown off their place start from where the screen
     * showed them (`updates` changed in place); `added` gets one for each such entity it has no update for (from
     * `lookup`'s real data). Nothing is shown off its place after it.
     */
    void OnAdvance(std::vector<SSynthUpdate>& updates, const Lookup& lookup, std::vector<SSynthUpdate>& added);

    /** Entities shown off their real place now. */
    [[nodiscard]] std::size_t Shown() const noexcept
    {
      return mShown.size();
    }
    [[nodiscard]] const SSynthStats& Stats() const noexcept
    {
      return mStats;
    }
    /** A whole new picture (a reconnect): nothing made up is on screen any more. */
    void Clear() noexcept
    {
      mShown.clear();
      mMadeUp.clear();
    }

  private:
    std::unordered_map<std::uint32_t, SSynthTransform> mShown; // where the screen shows entities off their place
    // Per made-up display tick, each entity's made-up position (for `CompareWithReal`); the last few ticks only.
    std::map<std::int32_t, std::vector<std::pair<std::uint32_t, SSynthTransform>>> mMadeUp;
    SSynthStats mStats;
  };
} // namespace faf::remote::client
