#include "moho/terrain/water/WaterfallPlan.h"

#include <algorithm>
#include <cmath>
#include <functional>

namespace moho::water::falls
{
  namespace
  {
    constexpr float kTwoPi = 6.2831853f;
    // The pull the particle renderer's own gravity flag gives (0.02 a tick squared) in metres a second squared.
    constexpr float kGravity = 2.0f;
    // A fall of this drop (units) is the size the tuned particle sizes and speeds are for.
    constexpr float kReferenceDrop = 7.5f;
    // The foam a step of the simulation gets from one source at the foot of a fall, and from one rapid.
    constexpr float kFallFoam = 0.003f;
    constexpr float kRapidFoam = 0.0008f;
    // One foam source for every this much of a fall's width.
    constexpr float kFoamSpacing = 3.0f;
    constexpr int kMaxStripsPerFall = 64;

    [[nodiscard]] float Clamp(
      const float v,
      const float lo,
      const float hi
    ) noexcept
    {
      return v < lo ? lo : (v > hi ? hi : v);
    }

    // How fast the water of the middle of the channel leaves the lip (units a second): a deeper fall means a bigger
    // river above it, and a bigger river runs faster.
    [[nodiscard]] float LipSpeed(
      const float drop
    ) noexcept
    {
      return Clamp(0.55f + 0.03f * drop, 0.55f, 1.1f);
    }

    // How long the water takes to fall `drop` units under `kGravity` from rest (it leaves the lip horizontally).
    [[nodiscard]] float FallSeconds(
      const float drop
    ) noexcept
    {
      return std::sqrt(2.0f * std::max(drop, 0.0f) / kGravity);
    }

    // The standing offset of the foot from the lip: the face of the fall below the lip is not quite vertical.
    constexpr float kFootBase = 0.25f;

    // How far the water of the middle of the channel is thrown past the lip by the time it has fallen `drop`.
    [[nodiscard]] float Throw(
      const float drop,
      const float arc
    ) noexcept
    {
      if (!(arc > 0.0f)) {
        return 0.0f;
      }
      return std::min(LipSpeed(drop) * FallSeconds(drop) * arc, 0.5f * drop + 0.5f);
    }

    // The share of the time of the fall at which the arc (x = reach * t, y = drop * t * t, in the share t of the time)
    // has run a share `f` of its whole length, by bisection on the closed form of the length.
    [[nodiscard]] float ArcParam(
      const float f,
      const float reach,
      const float drop
    ) noexcept
    {
      const float a = std::max(reach, 0.05f);
      const float b = 2.0f * std::max(drop, 0.01f);
      auto length = [a, b](const float t) {
        return 0.5f * t * std::sqrt(a * a + b * b * t * t) + a * a / (2.0f * b) * std::asinh(b * t / a);
      };
      const float target = Clamp(f, 0.0f, 1.0f) * length(1.0f);
      float lo = 0.0f;
      float hi = 1.0f;
      for (int i = 0; i < 24; ++i) {
        const float mid = 0.5f * (lo + hi);
        (length(mid) < target ? lo : hi) = mid;
      }
      return 0.5f * (lo + hi);
    }

    // A number in [0, 1) from the place of a fall, the number of a strip and a purpose: the variation between strips
    // without a random stream, so a curtain looks the same every time it is built.
    [[nodiscard]] float Hash01(
      const Emitter& e,
      const int strip,
      const int purpose
    ) noexcept
    {
      auto mix = [](std::uint32_t h) {
        h ^= h >> 16;
        h *= 0x7FEB352Du;
        h ^= h >> 15;
        h *= 0x846CA68Bu;
        h ^= h >> 16;
        return h;
      };
      const auto a = static_cast<std::uint32_t>(static_cast<std::int32_t>(std::floor(e.x * 4.0f)));
      const auto b = static_cast<std::uint32_t>(static_cast<std::int32_t>(std::floor(e.z * 4.0f)));
      const std::uint32_t h = mix(
        a * 0x9E3779B1u ^ mix(b + 0x85EBCA6Bu) ^
        mix(
          static_cast<std::uint32_t>(strip) * 0x27D4EB2Fu + static_cast<std::uint32_t>(purpose) * 0x165667B1u +
          0x2545F491u
        )
      );
      return static_cast<float>(h >> 8) * (1.0f / 16777216.0f);
    }

    // How fast water runs down a fall: it leaves the lip at a few metres a second and gains speed with the drop.
    [[nodiscard]] float FallSpeed(
      const float drop
    ) noexcept
    {
      return 5.0f + 0.7f * drop;
    }

    // Size and speed of the splash scale with the square root of the drop (the fall speed), around the reference drop.
    [[nodiscard]] float DropScale(
      const float drop
    ) noexcept
    {
      return Clamp(std::sqrt(std::max(drop, 0.5f) / kReferenceDrop), 0.6f, 1.5f);
    }
  } // namespace

  float FootOffset(
    const Emitter& emitter
  ) noexcept
  {
    return kFootBase + Throw(std::max(emitter.top - emitter.bottom, 0.0f), emitter.arc);
  }

  std::vector<Emitter> BuildEmitters(
    const std::vector<SRiverFall>& falls,
    const std::vector<SRiverSegment>& segments
  )
  {
    std::vector<Emitter> out;
    out.reserve(falls.size());
    for (const SRiverFall& fall : falls) {
      Emitter e;
      e.kind = Kind::Fall;
      e.x = fall.x;
      e.z = fall.z;
      e.tx = fall.tx;
      e.tz = fall.tz;
      e.halfWidth = fall.halfWidth;
      e.top = fall.top;
      e.bottom = fall.bottom;
      out.push_back(e);
    }
    std::size_t rapids = 0u;
    for (const SRiverSegment& segment : segments) {
      if (!(segment.length > 0.5f)) {
        continue;
      }
      const float slope = (segment.level0 - segment.level1) / segment.length;
      if (!(slope >= kRapidMinSlope)) {
        continue;
      }
      // Points every `kRapidSpacing` along the segment, the first half a spacing in; a short one gets its middle.
      const int count = std::max(1, static_cast<int>(std::floor(segment.length / kRapidSpacing + 0.5f)));
      for (int i = 0; i < count && rapids < kMaxRapidsPerRiver; ++i, ++rapids) {
        const float t = (static_cast<float>(i) + 0.5f) / static_cast<float>(count);
        Emitter e;
        e.kind = Kind::Rapid;
        e.x = segment.x0 + (segment.x1 - segment.x0) * t;
        e.z = segment.z0 + (segment.z1 - segment.z0) * t;
        e.tx = segment.tx;
        e.tz = segment.tz;
        e.halfWidth = segment.half0 + (segment.half1 - segment.half0) * t;
        e.top = segment.level0 + (segment.level1 - segment.level0) * t;
        e.bottom = e.top;
        e.slope = slope;
        out.push_back(e);
      }
    }
    return out;
  }

  Quality QualityOf(
    const int level
  ) noexcept
  {
    Quality q;
    q.level = std::min(std::max(level, 0), 3);
    switch (q.level) {
    case 1:
      q.range = 150.0f;
      q.stripSpacing = 2.0f;
      q.maxStrips = 96;
      q.maxParticles = 400;
      q.maxPerFrame = 12;
      q.rateScale = 0.5f;
      q.splash = true;
      q.spray = false;
      q.curtainSegments = 5;
      break;
    case 2:
      q.range = 250.0f;
      q.stripSpacing = 1.5f;
      q.maxStrips = 192;
      q.maxParticles = 1000;
      q.maxPerFrame = 24;
      q.rateScale = 1.0f;
      q.splash = true;
      q.spray = true;
      q.curtainSegments = 8;
      break;
    case 3:
      q.range = 400.0f;
      q.stripSpacing = 1.2f;
      q.maxStrips = 384;
      q.maxParticles = 1500;
      q.maxPerFrame = 48;
      q.rateScale = 1.6f;
      q.splash = true;
      q.spray = true;
      q.curtainSegments = 10;
      break;
    default:
      q.range = 0.0f;
      q.maxStrips = 0;
      q.maxParticles = 0;
      q.maxPerFrame = 0;
      q.rateScale = 0.0f;
      q.splash = false;
      q.spray = false;
      break;
    }
    return q;
  }

  int CurtainStripCount(
    const float halfWidth,
    const float spacing
  ) noexcept
  {
    if (!(halfWidth > 0.0f) || !(spacing > 0.05f)) {
      return 0;
    }
    return std::min(std::max(static_cast<int>(std::ceil(2.0f * halfWidth / spacing)), 1), kMaxStripsPerFall);
  }

  void CurtainStrips(
    const Emitter& emitter,
    const float spacing,
    const Shape& shape,
    std::vector<Strip>& out
  )
  {
    if (emitter.kind != Kind::Fall) {
      return;
    }
    const int count = CurtainStripCount(emitter.halfWidth, spacing);
    if (count == 0) {
      return;
    }
    const int segments = std::min(std::max(shape.segments, 1), kMaxCurtainSegments);
    const float bulge = std::max(shape.bulge, 0.0f);
    const float fray = std::max(shape.fray, 0.0f);
    const float drop = std::max(emitter.top - emitter.bottom, 0.0f);
    const float lipThrow = Throw(drop, emitter.arc);
    // The lip bows downstream in the middle of the channel: the water there is quicker and thicker.
    const float lipBow = std::min(0.1f * emitter.halfWidth, 0.6f) * bulge;
    const float nx = -emitter.tz;
    const float nz = emitter.tx;
    const float fallSpeed = FallSpeed(drop);
    for (int i = 0; i < count; ++i) {
      const float u = (static_cast<float>(i) + 0.5f) / static_cast<float>(count) * 2.0f - 1.0f;
      const float edge = std::fabs(u);
      const float centre = 1.0f - u * u; // 1 in the middle of the channel, 0 at the banks
      const float across0 = u * emitter.halfWidth;
      const float vary = 2.0f * Hash01(emitter, i, 0) - 1.0f; // -1..1: how far this strip is thrown
      const float cut = Hash01(emitter, i, 1);                // how much of the foot this strip lacks
      const float phase = 0.21f * static_cast<float>(i) + 0.35f * Hash01(emitter, i, 2);
      // The quicker middle of the channel throws further; fray makes every strip a little different.
      const float reach = lipThrow * (0.72f + 0.28f * centre) * (1.0f + 0.18f * fray * vary);
      const float last = 1.0f - 0.05f * fray * cut;

      Strip s;
      s.points = segments + 1;
      s.speed = fallSpeed * (1.0f + 0.15f * fray * vary);
      for (int k = 0; k <= segments; ++k) {
        // The time of the fall as a share of the whole, for a point `f` of the way along the arc: the pieces are as
        // long as each other, which keeps the bend of the chain even.
        const float f = static_cast<float>(k) / static_cast<float>(segments);
        const float tau = last * ArcParam(f, reach, drop);
        const float down = lipBow * centre + reach * tau;
        // The sheet narrows a little while it falls and spreads over the pool.
        const float narrow = 1.0f - 0.07f * bulge * std::sin(3.1415927f * tau) + 0.07f * bulge * tau * tau * tau;
        const float wave =
          0.25f * fray * std::sin(kTwoPi * (1.1f * tau + phase + 0.3f * shape.time)) * std::sin(3.1415927f * tau);
        const float across = across0 * narrow + wave;
        s.x[k] = emitter.x + nx * across + emitter.tx * down;
        s.z[k] = emitter.z + nz * across + emitter.tz * down;
        s.y[k] = emitter.top - drop * tau * tau;
        // Half the width of the ribbon: neighbours overlap a little, so no gap shows between two. Thicker in the
        // middle of the channel, thinner toward the banks, and the edge strips taper as they fall; the ribbon spreads
        // over the foot.
        const float thick = 1.0f + bulge * (0.15f * centre - 0.05f);
        const float taper = 1.0f - 0.45f * bulge * edge * edge * tau;
        const float spread = 1.0f + 0.35f * bulge * tau * tau * tau * tau;
        s.width[k] = spacing * 0.58f * std::max(thick * taper * spread, 0.2f);
        // Denser as it falls; thin water at the banks, and the last strips of each bank fade out instead of ending.
        const float cross = 1.0f - 0.75f * bulge * edge * edge * edge;
        s.alpha[k] = Clamp(
          (kCurtainTopAlpha + (kCurtainFootAlpha - kCurtainTopAlpha) * tau) * Clamp(cross, 0.2f, 1.0f) * 0.8f,
          0.0f,
          1.0f
        );
      }
      out.push_back(s);
    }
  }

  Rates RatesOf(
    const Emitter& emitter
  ) noexcept
  {
    Rates r;
    const float width = 2.0f * std::max(emitter.halfWidth, 0.0f);
    if (emitter.kind == Kind::Fall) {
      const float root = std::sqrt(std::max(emitter.top - emitter.bottom, 0.0f));
      r.splash = 0.8f * width * root;
      r.mist = 0.22f * width * root;
    } else {
      // Every emitter of a reach stands `kRapidSpacing` apart, so it speaks for that much of the river.
      r.spray = 0.9f * width * emitter.slope * kRapidSpacing;
    }
    return r;
  }

  float DistanceRate(
    const float distance,
    const float range
  ) noexcept
  {
    if (!(range > 0.0f) || distance > range) {
      return 0.0f;
    }
    const float nearEnd = 0.4f * range;
    if (distance <= nearEnd) {
      return 1.0f;
    }
    const float t = (distance - nearEnd) / (range - nearEnd);
    return 1.0f + (kFarRate - 1.0f) * Clamp(t, 0.0f, 1.0f);
  }

  int TakeEmission(
    const float rate,
    const float dt,
    float& carry
  ) noexcept
  {
    if (!(rate > 0.0f) || !(dt > 0.0f)) {
      return 0;
    }
    carry += rate * dt;
    const int whole = static_cast<int>(std::floor(carry));
    carry -= static_cast<float>(whole);
    return std::min(whole, kMaxBurst);
  }

  ParticleSpec SpawnParticle(
    const Layer layer,
    const Emitter& e,
    Rng& rng
  )
  {
    const float nx = -e.tz;
    const float nz = e.tx;
    const float drop = std::max(e.top - e.bottom, 0.0f);
    const float k = DropScale(drop);
    ParticleSpec p;
    p.angle = rng.Range(0.0f, kTwoPi);
    switch (layer) {
    case Layer::Splash: {
      const float across = rng.Range(-0.95f, 0.95f) * e.halfWidth;
      const float down = FootOffset(e) + rng.Range(0.0f, 1.6f);
      p.x = e.x + nx * across + e.tx * down;
      p.z = e.z + nz * across + e.tz * down;
      p.y = e.bottom + 0.15f;
      const float flow = rng.Range(0.2f, 1.2f);
      const float side = rng.Range(-0.6f, 0.6f);
      p.vx = e.tx * flow + nx * side;
      p.vz = e.tz * flow + nz * side;
      p.vy = rng.Range(1.5f, 4.0f) * k;
      p.ay = -kGravity;
      p.lifetime = rng.Range(1.2f, 2.4f);
      p.beginSize = rng.Range(0.45f, 0.8f) * k;
      p.endSize = rng.Range(1.1f, 1.8f) * k;
      p.spin = rng.Range(-0.8f, 0.8f);
      break;
    }
    case Layer::Mist: {
      const float across = rng.Range(-1.0f, 1.0f) * e.halfWidth;
      const float down = rng.Range(0.5f, 3.5f);
      p.x = e.x + nx * across + e.tx * down;
      p.z = e.z + nz * across + e.tz * down;
      p.y = e.bottom + rng.Range(0.3f, 2.0f);
      const float flow = rng.Range(0.5f, 1.3f);
      const float side = rng.Range(-0.3f, 0.3f);
      p.vx = e.tx * flow + nx * side;
      p.vz = e.tz * flow + nz * side;
      p.vy = rng.Range(0.3f, 0.9f);
      p.ay = 0.0f;
      p.lifetime = rng.Range(3.0f, 5.0f);
      p.beginSize = rng.Range(3.0f, 5.0f) * k;
      p.endSize = rng.Range(8.0f, 13.0f) * k;
      p.spin = rng.Range(-0.3f, 0.3f);
      break;
    }
    case Layer::Spray: {
      const float across = rng.Range(-0.8f, 0.8f) * e.halfWidth;
      const float along = rng.Range(-2.0f, 2.0f);
      p.x = e.x + nx * across + e.tx * along;
      p.z = e.z + nz * across + e.tz * along;
      p.y = e.top + 0.1f;
      const float flow = rng.Range(0.8f, 1.8f);
      const float side = rng.Range(-0.5f, 0.5f);
      p.vx = e.tx * flow + nx * side;
      p.vz = e.tz * flow + nz * side;
      p.vy = rng.Range(0.8f, 2.0f);
      p.ay = -kGravity;
      p.lifetime = rng.Range(0.8f, 1.5f);
      p.beginSize = rng.Range(0.5f, 0.9f);
      p.endSize = rng.Range(1.2f, 2.0f);
      p.spin = rng.Range(-1.0f, 1.0f);
      break;
    }
    }
    return p;
  }

  void FoamSources(
    const Emitter& e,
    std::vector<FoamSource>& out
  )
  {
    if (e.kind == Kind::Fall) {
      const float drop = std::max(e.top - e.bottom, 0.0f);
      const int count = std::min(std::max(static_cast<int>(std::ceil(2.0f * e.halfWidth / kFoamSpacing)), 1), 24);
      const float nx = -e.tz;
      const float nz = e.tx;
      const float down = FootOffset(e) + 1.0f;
      const float radius = Clamp(1.6f + 0.12f * drop, 1.8f, 4.0f);
      for (int i = 0; i < count; ++i) {
        const float across =
          ((static_cast<float>(i) + 0.5f) / static_cast<float>(count) * 2.0f - 1.0f) * e.halfWidth * 0.9f;
        FoamSource s;
        s.x = e.x + nx * across + e.tx * down;
        s.z = e.z + nz * across + e.tz * down;
        s.radius = radius;
        s.foam = kFallFoam;
        out.push_back(s);
      }
    } else {
      FoamSource s;
      s.x = e.x;
      s.z = e.z;
      s.radius = Clamp(0.5f * e.halfWidth, 1.8f, 3.0f);
      s.foam = kRapidFoam * Clamp(e.slope / kRapidMinSlope, 1.0f, 3.0f);
      out.push_back(s);
    }
  }

  std::vector<Candidate> SelectWithinBudget(
    std::vector<Candidate> candidates,
    const float range,
    const int budget
  )
  {
    candidates.erase(
      std::remove_if(
        candidates.begin(),
        candidates.end(),
        [range](const Candidate& c) {
      return !(c.distance <= range) || c.cost <= 0;
    }
      ),
      candidates.end()
    );
    std::stable_sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
      return a.distance < b.distance;
    });
    std::vector<Candidate> chosen;
    int used = 0;
    for (const Candidate& c : candidates) {
      if (used + c.cost > budget) {
        continue;
      }
      used += c.cost;
      chosen.push_back(c);
    }
    return chosen;
  }

  Frustum FrustumOf(
    const float (&m)[16]
  ) noexcept
  {
    const auto column = [&m](const int c, float (&out)[4]) {
      for (int r = 0; r < 4; ++r) {
        out[r] = m[r * 4 + c];
      }
    };
    float c0[4];
    float c1[4];
    float c2[4];
    float c3[4];
    column(0, c0);
    column(1, c1);
    column(2, c2);
    column(3, c3);
    const float raw[5][4] = {
      {c3[0] + c0[0], c3[1] + c0[1], c3[2] + c0[2], c3[3] + c0[3]},
      {c3[0] - c0[0], c3[1] - c0[1], c3[2] - c0[2], c3[3] - c0[3]},
      {c3[0] + c1[0], c3[1] + c1[1], c3[2] + c1[2], c3[3] + c1[3]},
      {c3[0] - c1[0], c3[1] - c1[1], c3[2] - c1[2], c3[3] - c1[3]},
      {c2[0], c2[1], c2[2], c2[3]},
    };
    Frustum f;
    for (int i = 0; i < 5; ++i) {
      const float length = std::sqrt(raw[i][0] * raw[i][0] + raw[i][1] * raw[i][1] + raw[i][2] * raw[i][2]);
      const float inverse = length > 1.0e-12f ? 1.0f / length : 0.0f;
      f.planes[i] = Plane{raw[i][0] * inverse, raw[i][1] * inverse, raw[i][2] * inverse, raw[i][3] * inverse};
    }
    return f;
  }

  bool SphereInFrustum(
    const Frustum& frustum,
    const float x,
    const float y,
    const float z,
    const float radius
  ) noexcept
  {
    for (const Plane& p : frustum.planes) {
      if (p.a * x + p.b * y + p.c * z + p.d < -radius) {
        return false;
      }
    }
    return true;
  }

  float GameClock::Advance(
    const int tick,
    const double wall
  ) noexcept
  {
    double wallDelta = 0.0;
    if (haveWall) {
      wallDelta = std::min(std::max(wall - lastWall, 0.0), 0.1);
    }
    lastWall = wall;
    if (!haveTick || tick != lastTick) {
      if (haveTick && tick > lastTick) {
        const double elapsed = wall - lastTickWall;
        if (elapsed > 0.0005) {
          const float rate = std::min(static_cast<float>(static_cast<double>(tick - lastTick) / elapsed * 0.1), 8.0f);
          speed += (rate - speed) * 0.3f;
        }
      }
      lastTick = tick;
      lastTickWall = wall;
      haveTick = true;
    }
    paused = (wall - lastTickWall) > 0.35;
    if (!haveWall) {
      haveWall = true;
      return 0.0f;
    }
    float dt = paused ? 0.0f : static_cast<float>(wallDelta) * Clamp(speed, 0.1f, 6.0f);
    dt = std::min(dt, 0.1f);
    total += static_cast<double>(dt);
    return dt;
  }

  bool LiveCounter::TryAdd(
    const double now,
    const float lifetime,
    const int cap
  )
  {
    Purge(now);
    if (static_cast<int>(deaths.size()) >= cap) {
      return false;
    }
    deaths.push_back(now + static_cast<double>(lifetime));
    std::push_heap(deaths.begin(), deaths.end(), std::greater<double>());
    return true;
  }

  int LiveCounter::Live(
    const double now
  )
  {
    Purge(now);
    return static_cast<int>(deaths.size());
  }

  void LiveCounter::Clear()
  {
    deaths.clear();
  }

  void LiveCounter::Purge(
    const double now
  )
  {
    while (!deaths.empty() && deaths.front() <= now) {
      std::pop_heap(deaths.begin(), deaths.end(), std::greater<double>());
      deaths.pop_back();
    }
  }
} // namespace moho::water::falls
