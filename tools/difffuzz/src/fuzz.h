#pragma once

#include <cmath>
#include <cstdint>
#include <cstring>

namespace difffuzz
{
  constexpr int kMaxWords = 48;
  constexpr std::uint32_t kCanary = 0xCDCDCDCDu; // pre-fill of every output word

  struct Rng
  {
    std::uint64_t s;

    explicit Rng(const std::uint64_t seed) noexcept : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}

    std::uint64_t Next() noexcept // splitmix64
    {
      std::uint64_t z = (s += 0x9E3779B97F4A7C15ull);
      z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
      z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
      return z ^ (z >> 31);
    }
    std::uint32_t U32() noexcept { return static_cast<std::uint32_t>(Next() >> 32); }
    std::uint32_t Below(const std::uint32_t n) noexcept { return static_cast<std::uint32_t>((Next() >> 32) % n); }
    bool Chance(const std::uint32_t percent) noexcept { return Below(100) < percent; }
    double Unit() noexcept { return static_cast<double>(Next() >> 11) * (1.0 / 9007199254740992.0); } // [0,1)
    double Range(const double lo, const double hi) noexcept { return lo + (hi - lo) * Unit(); }
  };

  /// Global switch: allow signaling NaNs in generated inputs (off by default -
  /// engine arithmetic never produces one, and x87 `fld` quiets them, which
  /// is a known, intentional-free divergence class for pure copies).
  extern bool gAllowSnan;

  [[nodiscard]] inline std::uint32_t Bits(const float f) noexcept
  {
    std::uint32_t u;
    std::memcpy(&u, &f, 4);
    return u;
  }
  [[nodiscard]] inline float FromBits(const std::uint32_t u) noexcept
  {
    float f;
    std::memcpy(&f, &u, 4);
    return f;
  }

  /// One float drawn from a mix of classes: small, moderate, unit-range,
  /// log-uniform across every exponent, raw bit patterns (NaN payloads, inf,
  /// denormals), and a table of edge values plus their +-k ulp neighbours.
  float GenFloat(Rng& rng);
  /// A "well-behaved" float: uniform in [-lim, lim].
  float GenPlain(Rng& rng, float lim);
  /// An edge value (zeros, +-inf, NaN, FLT_MIN, denormals, FLT_MAX, +-1, ...).
  float GenEdge(Rng& rng);

  void GenVec3(Rng& rng, float* v);
  void GenUnitVec3(Rng& rng, float* v);
  /// v2 = +-v1 (+ a tiny perturbation): near-parallel / antiparallel pairs.
  void GenVecPair(Rng& rng, float* v1, float* v2);
  /// Scalar-first quaternion lanes (w, x, y, z): unit, near-identity, scaled,
  /// raw, or edge.
  void GenQuat(Rng& rng, float* q);
  /// q2 = +-q1 (+ perturbation) or independent.
  void GenQuatPair(Rng& rng, float* q1, float* q2);
  float GenAngle(Rng& rng);
  float GenT(Rng& rng);

  struct Target
  {
    const char* name;
    std::uint32_t va;     // retail entry point (for the report)
    const char* source;   // our definition, file:line
    int inWords;
    int outWords;
    const char* inLayout;  // e.g. "v[3] q[4]"
    const char* outLayout; // e.g. "dest[3] ret"
    void (*gen)(Rng&, std::uint32_t* in);
    void (*retail)(const std::uint32_t* in, std::uint32_t* out);
    void (*ours)(const std::uint32_t* in, std::uint32_t* out);
  };

  const Target* MathTargets(int& count);
} // namespace difffuzz
