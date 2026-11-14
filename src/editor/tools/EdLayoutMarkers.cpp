#include "editor/tools/EdLayoutMarkers.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265f;

    float Rad(
      const float degrees
    )
    {
      return degrees * kPi / 180.0f;
    }

    /** Studio's small generator (its numbers stay below 2^24). */
    struct Rng
    {
      long s;
      explicit Rng(
        const int seed
      )
        : s((static_cast<long>(seed) * 7919L + 13L) % 65537L)
      {
        if (s < 0) {
          s += 65537L;
        }
      }
      float operator()()
      {
        s = (s * 75L + 74L) % 65537L;
        return static_cast<float>(s) / 65537.0f;
      }
    };

    struct Occupied
    {
      float x;
      float z;
      float r;
    };

    float SlopeDegrees(
      const LayoutGround& g,
      const float x,
      const float z
    )
    {
      const auto at = [&](const float px, const float pz) {
        return g.height(std::floor(px + 0.5f), std::floor(pz + 0.5f));
      };
      const float hx = (at(x + 1.0f, z) - at(x - 1.0f, z)) / 2.0f;
      const float hz = (at(x, z + 1.0f) - at(x, z - 1.0f)) / 2.0f;
      return std::atan(std::sqrt(hx * hx + hz * hz)) * 180.0f / kPi;
    }

    /** A resource sits in the middle of a build cell (the game's saves: x.5). */
    float Snap(
      const float v
    )
    {
      return std::floor(v) + 0.5f;
    }

    bool Fit(
      const LayoutPoint& ideal,
      const float sx,
      const float sz,
      const std::vector<Occupied>& occupied,
      Rng& rng,
      const LayoutMarkerSettings& s,
      const LayoutGround& g,
      float& outX,
      float& outZ
    )
    {
      const auto ok = [&](const float x, const float z) {
        if (x < g.x0 + 4.0f || z < g.z0 + 4.0f || x > g.x1 - 4.0f || z > g.z1 - 4.0f) {
          return false;
        }
        if (g.height && g.height(std::floor(x + 0.5f), std::floor(z + 0.5f)) < g.water + 1.0f) {
          return false;
        }
        if (g.height && SlopeDegrees(g, x, z) > s.maxSlope) {
          return false;
        }
        for (const Occupied& o : occupied) {
          const float dx = o.x - x;
          const float dz = o.z - z;
          if (dx * dx + dz * dz < o.r * o.r) {
            return false;
          }
        }
        return true;
      };
      const float dx0 = ideal.x - sx;
      const float dz0 = ideal.z - sz;
      const float d0 = std::sqrt(dx0 * dx0 + dz0 * dz0);
      const float a0 = std::atan2(dz0, dx0);
      for (int attempt = 0; attempt <= 30; ++attempt) {
        float x = ideal.x;
        float z = ideal.z;
        if (attempt > 0) {
          const float sign = attempt % 2 == 0 ? 1.0f : -1.0f;
          const float da = sign * Rad(static_cast<float>(attempt) * 4.0f) * (0.6f + 0.8f * rng());
          const float dd = (rng() - 0.5f) * static_cast<float>(attempt) * 1.2f;
          x = sx + (d0 + dd) * std::cos(a0 + da);
          z = sz + (d0 + dd) * std::sin(a0 + da);
        }
        x = Snap(x);
        z = Snap(z);
        if (ok(x, z)) {
          outX = x;
          outZ = z;
          return true;
        }
      }
      return false;
    }
  } // namespace

  const char* LayoutShapeName(
    const LayoutShape shape
  )
  {
    switch (shape) {
    case LayoutShape::Arc:
      return "Arc";
    case LayoutShape::Cluster:
      return "Cluster";
    case LayoutShape::Line:
      return "Line";
    case LayoutShape::Pairs:
      return "Pairs";
    default:
      return "Ring";
    }
  }

  const char* LayoutPatternName(
    const LayoutPattern pattern
  )
  {
    switch (pattern) {
    case LayoutPattern::Corners:
      return "Corners";
    case LayoutPattern::Sides:
      return "Two sides";
    case LayoutPattern::Line:
      return "Line";
    default:
      return "Ring";
    }
  }

  std::vector<LayoutPoint> LayoutStarts(
    const LayoutMarkerSettings& s,
    const LayoutGround& g,
    const std::vector<LayoutPoint>& existing,
    const std::vector<LayoutPoint>& bases
  )
  {
    if (s.starts == LayoutStartMode::Existing) {
      return existing;
    }
    if (s.starts == LayoutStartMode::Bases) {
      return bases;
    }
    std::vector<LayoutPoint> list;
    const float mx = (g.x0 + g.x1) / 2.0f;
    const float mz = (g.z0 + g.z1) / 2.0f;
    const float rx = s.radius * (g.x1 - g.x0) / 2.0f;
    const float rz = s.radius * (g.z1 - g.z0) / 2.0f;
    const int n = std::max(1, s.count);
    const float rot = Rad(s.rotation);
    const auto put = [&](const float u, const float v) {
      list.push_back({mx + rx * u, mz + rz * v, {}});
    };
    switch (s.pattern) {
    case LayoutPattern::Corners: {
      static const float corners[4][2] = {{-1, -1}, {1, 1}, {1, -1}, {-1, 1}};
      for (int k = 0; k < std::min(n, 4); ++k) {
        const float u = corners[k][0] * 0.82f;
        const float v = corners[k][1] * 0.82f;
        put(u * std::cos(rot) - v * std::sin(rot), u * std::sin(rot) + v * std::cos(rot));
      }
      break;
    }
    case LayoutPattern::Sides:
      for (int k = 0; k < std::min(n, 2); ++k) {
        const float a = rot + static_cast<float>(k) * kPi;
        put(std::cos(a), std::sin(a));
      }
      break;
    case LayoutPattern::Line:
      for (int k = 0; k < n; ++k) {
        const float off = n == 1 ? 0.0f
                                 : (static_cast<float>(k) - static_cast<float>(n - 1) / 2.0f) *
            (2.0f / static_cast<float>(std::max(1, n - 1)));
        put(off * std::cos(rot), off * std::sin(rot));
      }
      break;
    default:
      for (int k = 0; k < n; ++k) {
        const float a = rot + static_cast<float>(k) * 2.0f * kPi / static_cast<float>(n) - kPi / 2.0f;
        put(std::cos(a), std::sin(a));
      }
      break;
    }
    return list;
  }

  std::vector<LayoutPoint> LayoutShapePoints(
    const LayoutShape shape,
    const float sx,
    const float sz,
    const float facing,
    const int count,
    const float dmin,
    const float dmax,
    const float arc,
    const float spacing
  )
  {
    std::vector<LayoutPoint> out;
    if (count < 1) {
      return out;
    }
    const auto at = [&](const float a, const float d) {
      out.push_back({sx + d * std::cos(a), sz + d * std::sin(a), {}});
    };
    const auto distanceOf = [&](const int j) {
      return dmin + (dmax - dmin) * (j % 2 == 0 ? 0.75f : 0.25f);
    };
    switch (shape) {
    case LayoutShape::Arc:
      for (int j = 1; j <= count; ++j) {
        const float t = count == 1 ? 0.0f : static_cast<float>(j - 1) / static_cast<float>(count - 1) - 0.5f;
        at(facing + t * arc, distanceOf(j));
      }
      break;
    case LayoutShape::Cluster: {
      const float cd = (dmin + dmax) / 2.0f;
      const float rho = std::max(spacing, (dmax - dmin) / 2.0f + spacing * 0.5f);
      const float cx = sx + cd * std::cos(facing);
      const float cz = sz + cd * std::sin(facing);
      for (int j = 1; j <= count; ++j) {
        const float r = rho * std::sqrt((static_cast<float>(j) - 0.5f) / static_cast<float>(count));
        const float a = static_cast<float>(j - 1) * 2.39996f;
        out.push_back({cx + r * std::cos(a), cz + r * std::sin(a), {}});
      }
      break;
    }
    case LayoutShape::Line: {
      const float cd = (dmin + dmax) / 2.0f;
      const float px = -std::sin(facing);
      const float pz = std::cos(facing);
      const float cx = sx + cd * std::cos(facing);
      const float cz = sz + cd * std::sin(facing);
      for (int j = 1; j <= count; ++j) {
        const float off = (static_cast<float>(j - 1) - static_cast<float>(count - 1) / 2.0f) * spacing * 1.35f;
        out.push_back({cx + off * px, cz + off * pz, {}});
      }
      break;
    }
    case LayoutShape::Pairs: {
      const int groups = (count + 1) / 2;
      int placed = 0;
      for (int gi = 1; gi <= groups; ++gi) {
        const float a = facing + (static_cast<float>(gi) - 0.5f) * 2.0f * kPi / static_cast<float>(groups);
        const float d = distanceOf(gi);
        const float cx = sx + d * std::cos(a);
        const float cz = sz + d * std::sin(a);
        const float tx = -std::sin(a);
        const float tz = std::cos(a);
        for (int k = 0; k < 2 && placed < count; ++k, ++placed) {
          const float off = (k == 0 ? -0.5f : 0.5f) * spacing * 1.1f;
          out.push_back({cx + off * tx, cz + off * tz, {}});
        }
      }
      break;
    }
    default:
      for (int j = 1; j <= count; ++j) {
        at(facing + (static_cast<float>(j) - 0.5f) * 2.0f * kPi / static_cast<float>(count), distanceOf(j));
      }
      break;
    }
    return out;
  }

  LayoutMarkerPlan PlanLayoutMarkers(
    const LayoutMarkerSettings& s,
    const LayoutGround& g,
    const std::vector<LayoutPoint>& starts,
    const std::vector<LayoutPoint>& occupiedIn
  )
  {
    LayoutMarkerPlan plan;
    plan.starts = starts;
    Rng rng(s.seed);
    const float mx = (g.x0 + g.x1) / 2.0f;
    const float mz = (g.z0 + g.z1) / 2.0f;
    std::vector<Occupied> occupied;
    for (const LayoutPoint& p : occupiedIn) {
      occupied.push_back({p.x, p.z, s.spacing});
    }
    for (const LayoutPoint& st : starts) {
      occupied.push_back({st.x, st.z, std::max(s.spacing * 1.5f, 8.0f)});
    }
    const float arc = Rad(s.arc);
    const auto facingOf = [&](const LayoutPoint& st) {
      return std::atan2(mz - st.z, mx - st.x) + (s.facingAway ? kPi : 0.0f);
    };
    const auto group = [&](
                         const bool hydro,
                         const int count,
                         const float dmin,
                         const float dmax,
                         const LayoutShape shape,
                         const char* label
                       ) {
      if (count < 1) {
        return;
      }
      for (std::size_t si = 0; si < starts.size(); ++si) {
        const LayoutPoint& st = starts[si];
        for (const LayoutPoint& ideal : LayoutShapePoints(
               shape, st.x, st.z, facingOf(st), count, dmin, std::max(dmax, dmin + 1.0f), arc, s.spacing
             )) {
          float x = 0.0f;
          float z = 0.0f;
          if (Fit(ideal, st.x, st.z, occupied, rng, s, g, x, z)) {
            plan.items.push_back({hydro, x, z, static_cast<int>(si) + 1, label});
            occupied.push_back({x, z, hydro ? std::max(s.spacing, 12.0f) : s.spacing});
          } else {
            ++plan.failed;
          }
        }
      }
    };
    group(true, s.hydro, s.hydroMin, s.hydroMax, LayoutShape::Ring, "hydro");
    group(false, s.mass, s.massMin, s.massMax, s.massShape, "mass");
    group(false, s.extra, s.extraMin, s.extraMax, s.extraShape, "extra");
    if (s.middle >= 1) {
      for (const LayoutPoint& ideal : LayoutShapePoints(
             LayoutShape::Cluster, mx, mz, 0.0f, s.middle, 0.0f, std::max(2.0f, s.middleRadius * 0.5f), arc, s.spacing
           )) {
        float x = 0.0f;
        float z = 0.0f;
        if (Fit(ideal, mx, mz, occupied, rng, s, g, x, z)) {
          plan.items.push_back({false, x, z, 0, "middle"});
          occupied.push_back({x, z, s.spacing});
        } else {
          ++plan.failed;
        }
      }
    }
    for (const LayoutMarkerItem& item : plan.items) {
      ++(item.hydro ? plan.hydros : plan.masses);
    }
    plan.text = std::to_string(plan.starts.size()) + " starts, " + std::to_string(plan.masses) + " mass, " +
      std::to_string(plan.hydros) + " hydrocarbon" +
      (plan.failed > 0 ? ", " + std::to_string(plan.failed) + " did not fit" : std::string());
    return plan;
  }
} // namespace faf::editor
