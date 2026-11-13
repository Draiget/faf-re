#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "moho/sim/WaterRivers.h"

// The pure part of the waterfalls and rapids of a river (docs/projects/RIVERS.md, "Waterfall rendering" and "Particles
// and foam emitters"): where water is thrown, how much, which of it is near enough to be drawn, and what one particle
// or one strip of the curtain looks like. Plain values in, plain values out, no engine objects: Waterfall.cpp feeds the
// result to the particle renderer, the beam renderer and the wave simulation, and the host tests (tests/water) run it
// without a device.
//
// Render only: nothing here reads or writes the simulation. The random numbers are the renderer's own (`Rng`), the time
// is the game clock of the water (`GameClock`: it stands while the game is paused).
namespace moho::water::falls
{
  // The tick of the simulation, in seconds (ten a second). Particle times, velocities and accelerations of the particle
  // renderer are per tick and per tick squared; the plan works in seconds and metres and Waterfall.cpp converts.
  inline constexpr float kTickSeconds = 0.1f;

  // What a place of the river throws.
  enum class Kind : std::uint8_t
  {
    Fall,  // a waterfall: a curtain, splash and mist at its foot, foam in the pool
    Rapid, // a steep reach: spray and foam
  };

  struct Emitter
  {
    Kind kind{Kind::Fall};
    // A fall: where the centreline breaks (the middle of the lip). A rapid: a point of the centreline.
    float x{0.0f};
    float z{0.0f};
    // Unit direction of the flow there.
    float tx{1.0f};
    float tz{0.0f};
    float halfWidth{1.0f};
    // A fall: the surface above the lip and below the foot. A rapid: the surface there (both the same).
    float top{0.0f};
    float bottom{0.0f};
    // A rapid: how steeply the surface drops per unit of length. A fall: 0.
    float slope{0.0f};
    // A fall: how far the water is thrown beyond the lip, as a multiple of the ballistic throw (`FootOffset`): 1 is
    // the throw of water that leaves the lip at the speed of the river and falls under gravity, 0 a sheet that drops
    // straight down. Set by the renderer from `ren_WaterfallArc`; the foot (splash, mist, foam) follows it.
    float arc{1.0f};
  };

  // Where a fall's water lands, downstream of the lip, in units: a small standing offset plus the ballistic throw
  // (speed at the lip times the time of the fall, which the drop sets) of `emitter.arc`, capped at about half the drop.
  [[nodiscard]] float FootOffset(const Emitter& emitter) noexcept;

  // A steep reach of the centreline is a rapid from this drop per unit of length on (a 5 percent grade is white water),
  // one emitter every `kRapidSpacing` units of it, at most `kMaxRapidsPerRiver` of them.
  inline constexpr float kRapidMinSlope = 0.05f;
  inline constexpr float kRapidSpacing = 6.0f;
  inline constexpr std::size_t kMaxRapidsPerRiver = 256u;

  // The falls of a river, then its rapids along the polyline. `falls` and `segments` are what `RiverSegments` returns.
  [[nodiscard]] std::vector<Emitter>
  BuildEmitters(const std::vector<SRiverFall>& falls, const std::vector<SRiverSegment>& segments);

  // What the level of the player's choice (ren_Waterfalls) allows.
  struct Quality
  {
    int level{0};
    // Emitters further than this from the camera (world units, on the ground plane) throw nothing.
    float range{0.0f};
    // Distance between the strips of the curtain, and how many strips may be alive at once over all falls.
    float stripSpacing{1.5f};
    int maxStrips{0};
    // Particles alive at once, over all emitters.
    int maxParticles{0};
    // Particles a single frame may add.
    int maxPerFrame{0};
    // Multiplies every emission rate.
    float rateScale{1.0f};
    bool splash{true};
    bool spray{true};
    // Straight beams a strip of the curtain is chained from (its polyline along the arc); at most
    // `kMaxCurtainSegments`.
    int curtainSegments{8};
  };

  // Level 0 is off (range 0), 1 low, 2 normal, 3 high; others are clamped.
  [[nodiscard]] Quality QualityOf(int level) noexcept;

  // The curtain of a fall is a set of strips side by side along the lip. Each strip is a ribbon that follows the arc
  // the water takes: it leaves the lip horizontally, overshoots it by the throw of the river's speed, and falls under
  // gravity, so the ribbon bends from the lip to the foot (a parabola). The beam renderer only draws straight beams, so
  // the strip is a polyline of `points` points and the renderer chains one beam per piece.
  inline constexpr int kMaxCurtainSegments = 12;
  inline constexpr int kMaxCurtainPoints = kMaxCurtainSegments + 1;

  // The base alpha of the water at the lip and at the foot of the arc (it gets denser as it falls); a point's alpha is
  // this, times what the cross-section of the channel makes of it.
  inline constexpr float kCurtainTopAlpha = 0.22f;
  inline constexpr float kCurtainFootAlpha = 0.5f;

  struct Strip
  {
    int points{0};
    // The polyline, from the lip (point 0, at the surface above the lip) to the foot.
    float x[kMaxCurtainPoints]{};
    float y[kMaxCurtainPoints]{};
    float z[kMaxCurtainPoints]{};
    // Half the width of the ribbon at each point (the beam renderer offsets both edges by this). Wider in the middle of
    // the channel, where the flow is thickest, narrower toward the banks and the foot's edge strips taper; the ribbon
    // spreads where it meets the pool.
    float width[kMaxCurtainPoints]{};
    // The alpha of the water at each point (0 to 1).
    float alpha[kMaxCurtainPoints]{};
    // How fast the water runs down the strip, in metres a second.
    float speed{8.0f};
  };

  // The shape of the curtain; every amplitude is a multiple of the default (0 switches it off).
  struct Shape
  {
    // The cross-section of the channel: the lip bows downstream in the middle, the water is thicker (wider ribbons,
    // denser) in the middle of the channel than at the banks, the edge strips taper off, and the sheet narrows a
    // little while it falls and spreads again over the pool (`ren_WaterfallBulge`).
    float bulge{1.0f};
    // Strips differ in throw, end and speed, and the sheet undulates sideways (`ren_WaterfallFray`).
    float fray{1.0f};
    // Game time of the water in seconds, the phase of the undulation: it stands while the game is paused.
    float time{0.0f};
    // Pieces a strip is chained from (clamped to 1..`kMaxCurtainSegments`).
    int segments{8};
  };

  // How many strips a fall needs: they stand `spacing` apart over the width of the lip.
  [[nodiscard]] int CurtainStripCount(float halfWidth, float spacing) noexcept;

  // The strips of a fall's curtain, side by side along the lip (across the flow), each along its arc from the surface
  // above the lip to the surface below it (the last point is at `bottom` unless fray shortens the strip). Adds to
  // `out`. Nothing for a rapid. Pure: the same inputs give the same strips (the variation between strips comes from a
  // hash of the fall's place and the strip's number, not from a random stream).
  void CurtainStrips(const Emitter& emitter, float spacing, const Shape& shape, std::vector<Strip>& out);

  // Emission rates of one emitter in particles a second, for each layer of particles, at `rateScale` 1.
  struct Rates
  {
    float splash{0.0f}; // white water thrown up at the foot of a fall
    float mist{0.0f};   // the cloud over the foot of a fall
    float spray{0.0f};  // the white water of a rapid
  };

  [[nodiscard]] Rates RatesOf(const Emitter& emitter) noexcept;

  // 1 within the near part of the range, down to `kFarRate` at its end: far water is a thin cloud.
  inline constexpr float kFarRate = 0.35f;
  [[nodiscard]] float DistanceRate(float distance, float range) noexcept;

  // The whole particles due after `dt` seconds at `rate` a second; `carry` keeps the rest for the next call. A long
  // pause between two calls (a stall) is not made up for: at most `kMaxBurst` come at once.
  inline constexpr int kMaxBurst = 24;
  [[nodiscard]] int TakeEmission(float rate, float dt, float& carry) noexcept;

  // The renderer's own random numbers (xorshift; never the simulation's).
  struct Rng
  {
    std::uint32_t state{0x9E3779B9u};
    [[nodiscard]] std::uint32_t NextU32() noexcept
    {
      std::uint32_t x = state;
      x ^= x << 13;
      x ^= x >> 17;
      x ^= x << 5;
      state = x != 0u ? x : 0x9E3779B9u;
      return state;
    }
    // In [0, 1).
    [[nodiscard]] float Next() noexcept
    {
      return static_cast<float>(NextU32() >> 8) * (1.0f / 16777216.0f);
    }
    [[nodiscard]] float Range(
      float lo,
      float hi
    ) noexcept
    {
      return lo + (hi - lo) * Next();
    }
  };

  enum class Layer : std::uint8_t
  {
    Splash,
    Mist,
    Spray,
  };

  // One particle in metres and seconds.
  struct ParticleSpec
  {
    float x{0.0f};
    float y{0.0f};
    float z{0.0f};
    float vx{0.0f};
    float vy{0.0f};
    float vz{0.0f};
    // The pull of gravity or the rise of the cloud (metres a second squared).
    float ay{0.0f};
    float lifetime{1.0f};
    float beginSize{1.0f};
    float endSize{1.0f};
    // Turn (radians) and turn rate (radians a second).
    float angle{0.0f};
    float spin{0.0f};
  };

  // One new particle of `layer` at `emitter`: the splash springs from the foot of a fall and falls back, the mist
  // stands over it and drifts downstream, the spray of a rapid rises from the surface and goes with the flow.
  [[nodiscard]] ParticleSpec SpawnParticle(Layer layer, const Emitter& emitter, Rng& rng);

  // A disc of foam for the wave simulation (SimAddSource with strength 0): where, how wide, how much a step of the
  // simulation (the caller weighs it with the game time of the frame).
  struct FoamSource
  {
    float x{0.0f};
    float z{0.0f};
    float radius{2.0f};
    float foam{0.0f};
  };

  // Foam sources of one emitter: a fall's are spread over the width of its foot, one every ~3 units; a rapid's is one
  // disc at its point.
  void FoamSources(const Emitter& emitter, std::vector<FoamSource>& out);

  // Which of the emitters to serve this frame: the nearest ones that are in range and in view, as many as the budget
  // allows. `cost` is what an emitter takes of the budget (the strips of its curtain; 1 for a rapid).
  struct Candidate
  {
    std::size_t index{0};
    float distance{0.0f};
    int cost{1};
  };

  // Keeps the candidates within `range`, nearest first, as long as their costs add up to at most `budget`. A candidate
  // that does not fit is skipped and a cheaper one after it may still be taken. Candidates need not be sorted.
  [[nodiscard]] std::vector<Candidate> SelectWithinBudget(std::vector<Candidate> candidates, float range, int budget);

  // The planes of a view frustum (left, right, bottom, top, near) from a row-vector view-projection matrix, row-major
  // `m[row * 4 + column]` (the engine's: clip = (x, y, z, 1) * M, Direct3D depth 0..1), normalised so that
  // `a * x + b * y + c * z + d` is the distance inside.
  struct Plane
  {
    float a{0.0f};
    float b{0.0f};
    float c{0.0f};
    float d{0.0f};
  };

  struct Frustum
  {
    Plane planes[5];
  };

  [[nodiscard]] Frustum FrustumOf(const float (&m)[16]) noexcept;

  // False when the sphere is entirely outside one plane.
  [[nodiscard]] bool SphereInFrustum(const Frustum& frustum, float x, float y, float z, float radius) noexcept;

  // The game time of the water between two frames, in seconds: the wall time of the frame times the speed of the game
  // (the ticks that came over the real time), and 0 when no tick has come for a third of a second (the game is paused).
  // The same rule as the wave simulation's clock, so a paused game stops both.
  struct GameClock
  {
    // `tick` is the game tick of this frame, `wall` a monotonic clock in seconds. The first call returns 0.
    [[nodiscard]] float Advance(int tick, double wall) noexcept;

    [[nodiscard]] bool Paused() const noexcept
    {
      return paused;
    }
    [[nodiscard]] float Speed() const noexcept
    {
      return speed;
    }
    // Seconds of game time since the first call.
    [[nodiscard]] double Total() const noexcept
    {
      return total;
    }

  private:
    bool haveTick{false};
    bool haveWall{false};
    bool paused{false};
    int lastTick{0};
    double lastTickWall{0.0};
    double lastWall{0.0};
    float speed{1.0f};
    double total{0.0};
  };

  // Particles alive now, to hold the cap: each one is entered with the game time it dies at.
  class LiveCounter
  {
  public:
    // False (and nothing entered) when `cap` particles are alive at `now`.
    [[nodiscard]] bool TryAdd(double now, float lifetime, int cap);
    [[nodiscard]] int Live(double now);
    void Clear();

  private:
    void Purge(double now);
    // A min-heap of the times the particles die at.
    std::vector<double> deaths;
  };
} // namespace moho::water::falls
