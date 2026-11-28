#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include "moho/render/lights/LightModel.h"

// The light pool: feeds offer Emissions (a thing that glows, with its birth time, life and motion), Update(now) turns
// the live ones into the Lights of this frame (position, radius, colour x intensity), ranked by power and capped.
//
// Pure data and arithmetic, no engine headers and no GPU: compiled on its own by the host test (tests/lights). Render
// only; nothing here reads or writes sim state. Single-threaded: the feeds and Update run on the thread that renders.
//
// Times are sim ticks as floats (tick + sub-tick fraction); the caller supplies the same clock the particle shaders use
// (REN_GetGameTick() + frame alpha).
namespace moho::lights
{
  enum class Kind : std::uint8_t
  {
    Flash = 0, // CreateLightParticle ("TLight" particle)
    Glow,      // additive glow sprite
    Beam,      // a beam: a capsule from pos to end
    Trail,     // a poly trail: a capsule from pos to end
    Mesh,      // projectile or unit mesh
    Spot, // a spotlight (headlight): at pos, towards `end` read as a unit direction, with the cone's cosine in `cone`
    Count
  };

  // One glowing thing, as a feed measured it. Moves as pos + dir*t + 0.5*accel*t^2 with t in ticks since birth (the
  // particle shader's rule).
  struct Emission
  {
    Kind kind = Kind::Flash;
    float pos[3] = {0.0f, 0.0f, 0.0f};
    float dir[3] = {0.0f, 0.0f, 0.0f};
    float accel[3] = {0.0f, 0.0f, 0.0f};
    float end[3] =
      {0.0f, 0.0f, 0.0f}; // Beam / Trail: the other end point (moves with pos); Spot: the direction the light points
    float cone = 0.0f;    // Spot: cosine of the outer half angle
    float birth = 0.0f;   // tick (with fraction)
    float life = 0.0f;    // ticks
    float size0 = 0.0f;   // sprite size at birth and at the end of life, world units (the size the model turns into
                          // radius and intensity)
    float size1 = 0.0f;
    float rgb[3] = {1.0f, 1.0f, 1.0f}; // 0..1
    // Colour over the life, when the effect has a ramp texture: four points at 0, 1/3, 2/3 and 1 of the life, each
    // already multiplied by the ramp alpha (so it carries the brightness too). Used instead of `rgb` when `hasCurve`.
    float curve[4][3] = {{1.0f, 1.0f, 1.0f}, {1.0f, 1.0f, 1.0f}, {1.0f, 1.0f, 1.0f}, {1.0f, 1.0f, 1.0f}};
    bool hasCurve = false;
    // Explicit strength, for lights whose author states it (a Lua light, a measured beam): when radius > 0 the model is
    // not asked.
    float radius = 0.0f;
    float intensity = 0.0f;
    // Multiplies the intensity the model gives (energy of several merged sprites, brightness of the texture). 1 = as
    // modelled.
    float gain = 1.0f;
    // Velocity in world units per tick, for a tracked light whose owner knows it (a beam: current minus last
    // transform). When `hasVel` is false Track() derives it from the last two refreshes. `endVel` is the same for the
    // other end of a capsule.
    float vel[3] = {0.0f, 0.0f, 0.0f};
    float endVel[3] = {0.0f, 0.0f, 0.0f};
    bool hasVel = false;
  };

  // One light for this frame.
  struct Light
  {
    float pos[3];
    float radius;
    float rgb[3]; // colour x intensity, linear
    Kind kind;
    float power;  // intensity x radius^2 at this moment (the ranking key)
    float end[3]; // capsule end (Beam / Trail), spot direction (Spot), else = pos
    float cone;   // Spot: cosine of the outer half angle
  };

  struct Stats
  {
    std::uint32_t offered = 0;     // Add() calls
    std::uint32_t invalid = 0;     // non-finite or absurd values
    std::uint32_t gated = 0;       // below the quality level's importance class
    std::uint32_t poolFull = 0;    // no room even after pruning
    std::uint32_t stored = 0;      // accepted
    std::uint32_t expired = 0;     // pruned after their fade-out
    std::uint32_t active = 0;      // lights evaluated by the last Update (before the cap)
    std::uint32_t culledByCap = 0; // lights of the last Update that did not fit the cap
    std::uint32_t tracked = 0;     // tracked lights alive
  };

  class LightCollector
  {
  public:
    // Lights the pool holds at once. The first patch had 16 on units and 28 on the ground; the pool no longer is the
    // limit.
    static constexpr std::size_t kPoolCapacity = 16384;

    // How far past its last refresh a tracked light is carried along its velocity, in ticks.
    static constexpr float kMaxCarryTicks = 1.0f; // one tick: the gap to the next refresh; a projectile that hit
                                                  // something must not carry its light on past the impact

    // Quality: model::kOff..model::kUltra. Lowering it also drops stored lights the new level no longer admits.
    void SetQuality(int quality);
    [[nodiscard]] int Quality() const
    {
      return quality_;
    }

    // Seconds per tick at the current game speed (0.1 at speed 1); sets the envelope length in ticks.
    void SetSecondsPerTick(float secondsPerTick);

    // Offers one emission. Returns true when it was stored.
    bool Add(const Emission& emission);

    // A tracked light: one that lives as long as its owner keeps refreshing it (a Lua light on a bone, a headlight, a
    // beam that is re-sent every tick). `key` is the owner's identity; a second Track with the same key moves and
    // recolours the light instead of adding one. The light fades in once, stays at full strength while it is refreshed,
    // and fades out `holdTicks` after the last refresh. Untrack ends it at once (it still fades out). Returns false
    // when the emission is refused (invalid, gated, pool full).
    bool Track(std::uint64_t key, const Emission& emission, float nowTick, float holdTicks);
    void Untrack(std::uint64_t key, float nowTick);

    // Evaluates the stored lights at `nowTick`, prunes the expired ones, and fills `out` with at most `maxLights`,
    // strongest first (ties broken by birth time then by order of arrival, so the result does not depend on the sort
    // implementation).
    void Update(float nowTick, std::size_t maxLights, std::vector<Light>& out);

    void Clear();

    [[nodiscard]] std::size_t Stored() const
    {
      return pool_.size();
    }
    [[nodiscard]] const Stats& GetStats() const
    {
      return stats_;
    }

  private:
    struct Entry
    {
      // A tracked light is sent once per sim tick but drawn every frame: between two refreshes it is carried on by the
      // velocity of the last two samples (dead reckoning, at most kMaxCarryTicks), so it moves smoothly instead of
      // stepping with the tick.
      float sampleTick = 0.0f; // tick of the last refresh
      float vel[3] = {0.0f, 0.0f, 0.0f};
      float endVel[3] = {0.0f, 0.0f, 0.0f};
      Emission e;
      float peakPower; // importance, from the peak strength: fixed for the entry's life
      std::uint32_t serial;
      std::uint64_t key; // 0 = not tracked
    };

    [[nodiscard]] float FadeInTicks() const;
    [[nodiscard]] float FadeOutTicks() const;
    void PruneExpired(float nowTick);
    bool Validate(const Emission& emission);
    void RebuildIndex();

    std::vector<Entry> pool_;
    std::unordered_map<std::uint64_t, std::size_t>
      trackedIndex_; // key -> index in pool_, rebuilt when the pool is compacted
    Stats stats_;
    int quality_ = model::kOff;
    float secondsPerTick_ = 0.1f;
    std::uint32_t nextSerial_ = 1;
    float lastNow_ = 0.0f;
  };
} // namespace moho::lights
