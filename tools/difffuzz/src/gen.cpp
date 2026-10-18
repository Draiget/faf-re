#include "fuzz.h"

#include <cfloat>
#include <cmath>

namespace difffuzz
{
  bool gAllowSnan = false;

  namespace
  {
    constexpr std::uint32_t kEdgeBits[] = {
      0x00000000u, 0x80000000u,             // +-0
      0x7F800000u, 0xFF800000u,             // +-inf
      0x7FC00000u, 0xFFC00000u, 0x7FC12345u, // qNaN, x86 "indefinite", payload
      0x00800000u, 0x80800000u,             // +-FLT_MIN
      0x00000001u, 0x80000001u,             // +-smallest denormal
      0x007FFFFFu, 0x807FFFFFu,             // +-largest denormal
      0x7F7FFFFFu, 0xFF7FFFFFu,             // +-FLT_MAX
      0x3F800000u, 0xBF800000u,             // +-1
      0x3F000000u, 0xBF000000u,             // +-0.5
      0x40000000u, 0xC0000000u,             // +-2
      0x358637BDu, 0xB58637BDu,             // +-1e-6
      0x3A83126Fu, 0xBA83126Fu,             // +-1e-3
      0x3FC90FDBu, 0xBFC90FDBu,             // +-pi/2
      0x40490FDBu, 0xC0490FDBu,             // +-pi
      0x40C90FDBu, 0xC0C90FDBu,             // +-2pi
      0x1E3CE508u, 0x60AD78ECu,             // 1e-20, 1e20
      0x3F800001u, 0x3F7FFFFFu,             // 1 +- 1ulp
      0x5F800000u, 0x1F800000u,             // 2^64, 2^-64 (x87 range probes)
    };
    constexpr std::uint32_t kEdgeCount = sizeof(kEdgeBits) / sizeof(kEdgeBits[0]);

    [[nodiscard]] float Sanitize(std::uint32_t u) noexcept
    {
      const bool nan = (u & 0x7F800000u) == 0x7F800000u && (u & 0x007FFFFFu) != 0;
      if (nan && !gAllowSnan) {
        u |= 0x00400000u;
      }
      return FromBits(u);
    }

    [[nodiscard]] float Sign(Rng& rng, const double v) noexcept
    {
      return static_cast<float>(rng.Chance(50) ? -v : v);
    }

    void NormalizeD(double* v, const int n) noexcept
    {
      double s = 0.0;
      for (int i = 0; i < n; ++i) {
        s += v[i] * v[i];
      }
      s = std::sqrt(s);
      for (int i = 0; i < n; ++i) {
        v[i] /= s;
      }
    }

    [[nodiscard]] double Perturbation(Rng& rng) noexcept
    {
      static constexpr double kEps[] = {0.0, 1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2};
      return kEps[rng.Below(8)] * rng.Range(-1.0, 1.0);
    }
  } // namespace

  float GenEdge(Rng& rng)
  {
    return Sanitize(kEdgeBits[rng.Below(kEdgeCount)]);
  }

  float GenPlain(Rng& rng, const float lim)
  {
    return static_cast<float>(rng.Range(-lim, lim));
  }

  float GenFloat(Rng& rng)
  {
    switch (rng.Below(12)) {
    case 0:
    case 1:
      return GenPlain(rng, 1.0f);
    case 2:
      return GenPlain(rng, 1000.0f);
    case 3:
      return GenPlain(rng, 1.0e6f);
    case 4: // log-uniform over every exponent, may overflow to inf
      return Sign(rng, std::ldexp(rng.Range(1.0, 2.0), static_cast<int>(rng.Below(280)) - 150));
    case 5:
      return Sanitize(rng.U32());
    case 6:
    case 7:
      return GenEdge(rng);
    case 8: // +-k ulp around an edge value
      return Sanitize(kEdgeBits[rng.Below(kEdgeCount)] + rng.Below(7) - 3);
    case 9: // tiny
      return Sign(rng, std::ldexp(rng.Range(1.0, 2.0), -40 - static_cast<int>(rng.Below(110))));
    case 10: // huge
      return Sign(rng, std::ldexp(rng.Range(1.0, 2.0), 40 + static_cast<int>(rng.Below(88))));
    default:
      return static_cast<float>(rng.Below(9)) - 4.0f; // small integers incl. 0
    }
  }

  void GenUnitVec3(Rng& rng, float* v)
  {
    double d[3];
    do {
      d[0] = rng.Range(-1, 1);
      d[1] = rng.Range(-1, 1);
      d[2] = rng.Range(-1, 1);
    } while (d[0] * d[0] + d[1] * d[1] + d[2] * d[2] < 1e-6);
    NormalizeD(d, 3);
    for (int i = 0; i < 3; ++i) {
      v[i] = static_cast<float>(d[i]);
    }
  }

  void GenVec3(Rng& rng, float* v)
  {
    const std::uint32_t mode = rng.Below(100);
    if (mode < 35) {
      GenUnitVec3(rng, v);
    } else if (mode < 60) {
      for (int i = 0; i < 3; ++i) {
        v[i] = GenFloat(rng);
      }
    } else if (mode < 75) {
      for (int i = 0; i < 3; ++i) {
        v[i] = GenPlain(rng, 100.0f);
      }
    } else if (mode < 88) { // axis-aligned / signed zeros
      static constexpr float kLane[] = {0.0f, -0.0f, 1.0f, -1.0f, 0.0f, 0.0f};
      for (int i = 0; i < 3; ++i) {
        v[i] = rng.Chance(20) ? GenPlain(rng, 10.0f) : kLane[rng.Below(6)];
      }
    } else { // unit direction at a random magnitude
      GenUnitVec3(rng, v);
      const double mag = std::ldexp(rng.Range(1.0, 2.0), static_cast<int>(rng.Below(200)) - 100);
      for (int i = 0; i < 3; ++i) {
        v[i] = static_cast<float>(v[i] * mag);
      }
    }
  }

  void GenVecPair(Rng& rng, float* v1, float* v2)
  {
    GenVec3(rng, v1);
    const std::uint32_t mode = rng.Below(100);
    if (mode < 30) {
      GenVec3(rng, v2);
      return;
    }
    const double sign = mode < 65 ? 1.0 : -1.0;
    const double scale = rng.Chance(50) ? 1.0 : std::ldexp(rng.Range(1.0, 2.0), static_cast<int>(rng.Below(20)) - 10);
    for (int i = 0; i < 3; ++i) {
      v2[i] = static_cast<float>(sign * scale * v1[i] + Perturbation(rng));
    }
  }

  void GenQuat(Rng& rng, float* q)
  {
    const std::uint32_t mode = rng.Below(100);
    if (mode < 45 || mode >= 85) {
      double d[4];
      do {
        for (double& x : d) {
          x = rng.Range(-1, 1);
        }
      } while (d[0] * d[0] + d[1] * d[1] + d[2] * d[2] + d[3] * d[3] < 1e-6);
      NormalizeD(d, 4);
      const double scale = mode < 45 ? 1.0 : rng.Range(0.25, 4.0);
      for (int i = 0; i < 4; ++i) {
        q[i] = static_cast<float>(d[i] * scale);
      }
    } else if (mode < 60) { // near identity (scalar-first)
      q[0] = static_cast<float>(1.0 + Perturbation(rng));
      for (int i = 1; i < 4; ++i) {
        q[i] = static_cast<float>(Perturbation(rng));
      }
    } else if (mode < 75) {
      for (int i = 0; i < 4; ++i) {
        q[i] = GenFloat(rng);
      }
    } else {
      for (int i = 0; i < 4; ++i) {
        q[i] = rng.Chance(50) ? GenEdge(rng) : GenPlain(rng, 1.0f);
      }
    }
  }

  void GenQuatPair(Rng& rng, float* q1, float* q2)
  {
    GenQuat(rng, q1);
    const std::uint32_t mode = rng.Below(100);
    if (mode < 30) {
      GenQuat(rng, q2);
      return;
    }
    const double sign = mode < 70 ? 1.0 : -1.0;
    for (int i = 0; i < 4; ++i) {
      q2[i] = static_cast<float>(sign * q1[i] + Perturbation(rng));
    }
  }

  float GenAngle(Rng& rng)
  {
    const std::uint32_t mode = rng.Below(100);
    if (mode < 40) {
      return GenPlain(rng, 6.2831855f);
    }
    if (mode < 55) {
      return GenPlain(rng, 0.1f);
    }
    if (mode < 70) {
      return GenPlain(rng, 3.1415927f);
    }
    if (mode < 85) { // +-k ulp around +-pi (the |rads/2| >= pi/2 gate)
      const std::uint32_t pi = 0x40490FDBu + rng.Below(9) - 4;
      return FromBits(rng.Chance(50) ? pi : (pi | 0x80000000u));
    }
    return GenFloat(rng);
  }

  float GenT(Rng& rng)
  {
    const std::uint32_t mode = rng.Below(100);
    if (mode < 50) {
      return static_cast<float>(rng.Unit());
    }
    if (mode < 65) {
      static constexpr std::uint32_t kT[] = {0x00000000u, 0x80000000u, 0x3F800000u, 0x3F000000u, 0x3F7FFFFFu, 0x00000001u};
      return FromBits(kT[rng.Below(6)]);
    }
    if (mode < 80) {
      return static_cast<float>(rng.Range(-0.5, 1.5));
    }
    return GenFloat(rng);
  }
} // namespace difffuzz
