#include "editor/tools/EdTerrainPath.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace faf::editor
{
  const char* PathModeName(
    const PathMode mode
  )
  {
    switch (mode) {
    case PathMode::Carve:
      return "Carve";
    case PathMode::Raise:
      return "Raise";
    case PathMode::Level:
      return "Level";
    case PathMode::Ramp:
      return "Ramp";
    case PathMode::River:
      return "River";
    }
    return "?";
  }

  namespace
  {
    float CatmullRom(
      const float p0,
      const float p1,
      const float p2,
      const float p3,
      const float t
    )
    {
      const float t2 = t * t;
      const float t3 = t2 * t;
      return 0.5f *
        (2.0f * p1 + (-p0 + p2) * t + (2.0f * p0 - 5.0f * p1 + 4.0f * p2 - p3) * t2 +
         (-p0 + 3.0f * p1 - 3.0f * p2 + p3) * t3);
    }
  } // namespace

  std::vector<TerrainPathPoint> SamplePath(
    const std::vector<TerrainPathPoint>& points,
    const bool closed,
    const float step
  )
  {
    std::vector<TerrainPathPoint> out;
    const int n = static_cast<int>(points.size());
    if (n == 0) {
      return out;
    }
    if (n == 1) {
      out.push_back(points[0]);
      return out;
    }
    const auto at = [&](int i) -> const TerrainPathPoint& {
      if (closed) {
        return points[static_cast<std::size_t>((i % n + n) % n)];
      }
      return points[static_cast<std::size_t>(std::clamp(i, 0, n - 1))];
    };
    const int segments = closed ? n : n - 1;
    for (int s = 0; s < segments; ++s) {
      const TerrainPathPoint& p0 = at(s - 1);
      const TerrainPathPoint& p1 = at(s);
      const TerrainPathPoint& p2 = at(s + 1);
      const TerrainPathPoint& p3 = at(s + 2);
      const float length = std::hypot(p2.x - p1.x, p2.z - p1.z);
      const int pieces = std::max(1, static_cast<int>(std::ceil(length / std::max(step, 0.1f))));
      for (int k = 0; k < pieces; ++k) {
        const float t = static_cast<float>(k) / static_cast<float>(pieces);
        // The heights run straight from point to point (a curve could overshoot a climb).
        out.push_back(
          {CatmullRom(p0.x, p1.x, p2.x, p3.x, t),
           CatmullRom(p0.z, p1.z, p2.z, p3.z, t),
           p1.height + (p2.height - p1.height) * t}
        );
      }
    }
    out.push_back(closed ? points.front() : points.back());
    return out;
  }

  SampleRect PathRect(
    const int width,
    const int height,
    const std::vector<TerrainPathPoint>& points,
    const PathOptions& o
  )
  {
    SampleRect rect{0, 0, -1, -1};
    if (points.empty() || width <= 0 || height <= 0) {
      return rect;
    }
    // The curve can swing out past its points a little: a quarter of the longest leg.
    float swing = 0.0f;
    for (std::size_t i = 1; i < points.size(); ++i) {
      swing = std::max(swing, std::hypot(points[i].x - points[i - 1].x, points[i].z - points[i - 1].z) * 0.25f);
    }
    const float reach = o.width * 0.5f + swing + 1.0f;
    float x0 = points[0].x;
    float x1 = x0;
    float z0 = points[0].z;
    float z1 = z0;
    for (const TerrainPathPoint& p : points) {
      x0 = std::min(x0, p.x);
      x1 = std::max(x1, p.x);
      z0 = std::min(z0, p.z);
      z1 = std::max(z1, p.z);
    }
    rect.x0 = std::clamp(static_cast<int>(std::floor(x0 - reach)), 0, width - 1);
    rect.z0 = std::clamp(static_cast<int>(std::floor(z0 - reach)), 0, height - 1);
    rect.x1 = std::clamp(static_cast<int>(std::ceil(x1 + reach)), 0, width - 1);
    rect.z1 = std::clamp(static_cast<int>(std::ceil(z1 + reach)), 0, height - 1);
    return rect;
  }

  SampleRect ApplyTerrainPath(
    std::uint16_t* const heights,
    const int width,
    const int height,
    const std::vector<TerrainPathPoint>& points,
    const PathOptions& o
  )
  {
    SampleRect none{0, 0, -1, -1};
    if (heights == nullptr || points.size() < 2 || o.width <= 0.0f) {
      return none;
    }
    const SampleRect rect = PathRect(width, height, points, o);
    if (rect.x1 < rect.x0 || rect.z1 < rect.z0) {
      return none;
    }
    const std::vector<TerrainPathPoint> curve = SamplePath(points, o.closed, 1.0f);
    const int bw = rect.x1 - rect.x0 + 1;
    const int bh = rect.z1 - rect.z0 + 1;
    // Each sample's nearest distance to the curve and the path's level there, segment by segment over its capsule.
    std::vector<float> best(static_cast<std::size_t>(bw) * bh, std::numeric_limits<float>::max());
    std::vector<float> level(best.size(), 0.0f);
    const float half = o.width * 0.5f;
    for (std::size_t s = 0; s + 1 < curve.size(); ++s) {
      const TerrainPathPoint& a = curve[s];
      const TerrainPathPoint& b = curve[s + 1];
      const float ex = b.x - a.x;
      const float ez = b.z - a.z;
      const float len2 = ex * ex + ez * ez;
      const int sx0 = std::max(rect.x0, static_cast<int>(std::floor(std::min(a.x, b.x) - half)));
      const int sx1 = std::min(rect.x1, static_cast<int>(std::ceil(std::max(a.x, b.x) + half)));
      const int sz0 = std::max(rect.z0, static_cast<int>(std::floor(std::min(a.z, b.z) - half)));
      const int sz1 = std::min(rect.z1, static_cast<int>(std::ceil(std::max(a.z, b.z) + half)));
      for (int z = sz0; z <= sz1; ++z) {
        for (int x = sx0; x <= sx1; ++x) {
          const float px = static_cast<float>(x) - a.x;
          const float pz = static_cast<float>(z) - a.z;
          const float t = len2 > 0.0f ? std::clamp((px * ex + pz * ez) / len2, 0.0f, 1.0f) : 0.0f;
          const float dx = px - ex * t;
          const float dz = pz - ez * t;
          const float d = std::sqrt(dx * dx + dz * dz);
          const std::size_t i = static_cast<std::size_t>(z - rect.z0) * bw + static_cast<std::size_t>(x - rect.x0);
          if (d < best[i]) {
            best[i] = d;
            level[i] = a.height + (b.height - a.height) * t;
          }
        }
      }
    }
    const float inner = half * (1.0f - std::clamp(o.falloff, 0.0f, 1.0f));
    const float firstLevel = points.front().height;
    SampleRect written{width, height, -1, -1};
    for (int z = rect.z0; z <= rect.z1; ++z) {
      for (int x = rect.x0; x <= rect.x1; ++x) {
        const std::size_t i = static_cast<std::size_t>(z - rect.z0) * bw + static_cast<std::size_t>(x - rect.x0);
        const float d = best[i];
        if (d > half) {
          continue;
        }
        const float w =
          d <= inner ? 1.0f : 0.5f * (1.0f + std::cos(3.14159265f * (d - inner) / std::max(half - inner, 1e-3f)));
        std::uint16_t& word = heights[static_cast<std::size_t>(z) * width + x];
        const float h = static_cast<float>(word) / 128.0f;
        float target = h;
        switch (o.mode) {
        case PathMode::Carve:
          target = std::min(h, level[i] - o.depth);
          break;
        case PathMode::Raise:
          target = std::max(h, level[i] + o.depth);
          break;
        case PathMode::Level:
          target = firstLevel;
          break;
        case PathMode::Ramp:
          target = level[i];
          break;
        case PathMode::River: {
          const float across = d / std::max(half, 1e-3f);
          target = std::min(h, level[i] - o.depth * (1.0f - across * across));
          break;
        }
        }
        const float now = h + (target - h) * w;
        const auto next = static_cast<std::uint16_t>(std::clamp(std::lround(now * 128.0f), 0L, 65535L));
        if (next != word) {
          word = next;
          written.x0 = std::min(written.x0, x);
          written.z0 = std::min(written.z0, z);
          written.x1 = std::max(written.x1, x);
          written.z1 = std::max(written.z1, z);
        }
      }
    }
    return written.x1 < written.x0 ? none : written;
  }

  void AddHeightChange(
    HeightChange& change,
    const std::uint16_t before,
    const std::uint16_t after
  )
  {
    if (before == after) {
      return;
    }
    ++change.samples;
    const float delta = (static_cast<float>(after) - static_cast<float>(before)) / 128.0f;
    if (delta < 0.0f) {
      change.removed -= delta;
      change.deepest = std::min(change.deepest, delta);
    } else {
      change.added += delta;
      change.highest = std::max(change.highest, delta);
    }
  }
} // namespace faf::editor
