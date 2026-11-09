#include "editor/tools/EdDecalShape.h"

#include <algorithm>
#include <cctype>
#include <cmath>

namespace faf::editor
{
  DecalFootprint DecalAround(const float cx, const float cz, const float sizeX, const float sizeZ, const float yaw)
  {
    const float c = std::cos(yaw);
    const float s = std::sin(yaw);
    // The middle is corner (0.5, 0.5): half of each side back from it.
    DecalFootprint decal;
    decal.x = cx - 0.5f * (sizeX * c - sizeZ * s);
    decal.z = cz - 0.5f * (sizeX * s + sizeZ * c);
    decal.sizeX = sizeX;
    decal.sizeZ = sizeZ;
    decal.yaw = yaw;
    return decal;
  }

  void DecalCentre(const DecalFootprint& decal, float& cx, float& cz)
  {
    const float c = std::cos(decal.yaw);
    const float s = std::sin(decal.yaw);
    cx = decal.x + 0.5f * (decal.sizeX * c - decal.sizeZ * s);
    cz = decal.z + 0.5f * (decal.sizeX * s + decal.sizeZ * c);
  }

  void DecalCorners(const DecalFootprint& decal, float (&x)[4], float (&z)[4])
  {
    const float c = std::cos(decal.yaw);
    const float s = std::sin(decal.yaw);
    static constexpr float kU[4] = {0.0f, 1.0f, 1.0f, 0.0f};
    static constexpr float kV[4] = {0.0f, 0.0f, 1.0f, 1.0f};
    for (int i = 0; i < 4; ++i) {
      // ComputeCorner: x + v * (-sizeZ sin) + u * (sizeX cos), z + v * (sizeZ cos) + u * (sizeX sin).
      x[i] = decal.x + kV[i] * (-decal.sizeZ * s) + kU[i] * (decal.sizeX * c);
      z[i] = decal.z + kV[i] * (decal.sizeZ * c) + kU[i] * (decal.sizeX * s);
    }
  }

  bool DecalContains(const DecalFootprint& decal, const float x, const float z)
  {
    if (decal.sizeX <= 0.0f || decal.sizeZ <= 0.0f) {
      return false;
    }
    const float c = std::cos(decal.yaw);
    const float s = std::sin(decal.yaw);
    const float dx = x - decal.x;
    const float dz = z - decal.z;
    const float u = (dx * c + dz * s) / decal.sizeX;
    const float v = (-dx * s + dz * c) / decal.sizeZ;
    return u >= 0.0f && u < 1.0f && v >= 0.0f && v < 1.0f;
  }

  int DecalTypeForTexture(const std::string& path)
  {
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    const std::size_t slash = lower.find_last_of('/');
    const std::string file = slash == std::string::npos ? lower : lower.substr(slash + 1);
    if (file.find("normal") != std::string::npos) {
      return 2;
    }
    if (file.find("glow") != std::string::npos) {
      return 6;
    }
    return 1;
  }

  std::pair<float, float> PathPoint(const std::vector<std::pair<float, float>>& points, const float t)
  {
    if (points.empty()) {
      return {0.0f, 0.0f};
    }
    const int last = static_cast<int>(points.size()) - 1;
    if (last == 0) {
      return points.front();
    }
    const float clamped = std::clamp(t, 0.0f, static_cast<float>(last));
    const int i = std::min(static_cast<int>(clamped), last - 1);
    const float u = clamped - static_cast<float>(i);
    const auto at = [&](const int k) { return points[static_cast<std::size_t>(std::clamp(k, 0, last))]; };
    const auto p0 = at(i - 1), p1 = at(i), p2 = at(i + 1), p3 = at(i + 2);
    const float u2 = u * u;
    const float u3 = u2 * u;
    const auto blend = [&](const float a, const float b, const float c, const float d) {
      return 0.5f * ((2.0f * b) + (-a + c) * u + (2.0f * a - 5.0f * b + 4.0f * c - d) * u2 + (-a + 3.0f * b - 3.0f * c + d) * u3);
    };
    return {blend(p0.first, p1.first, p2.first, p3.first), blend(p0.second, p1.second, p2.second, p3.second)};
  }

  std::vector<DecalFootprint> DecalsAlongPath(const std::vector<std::pair<float, float>>& points, const float length, const float width,
                                              const float overlap)
  {
    std::vector<DecalFootprint> decals;
    if (points.size() < 2 || length <= 0.0f || width <= 0.0f) {
      return decals;
    }
    // The curve as a fine polyline, with the distance along it at each sample.
    const int samples = static_cast<int>(points.size() - 1) * 32;
    std::vector<std::pair<float, float>> line;
    std::vector<float> along;
    line.reserve(static_cast<std::size_t>(samples) + 1);
    along.reserve(static_cast<std::size_t>(samples) + 1);
    for (int s = 0; s <= samples; ++s) {
      line.push_back(PathPoint(points, static_cast<float>(s) / 32.0f));
      along.push_back(s == 0 ? 0.0f
                             : along.back() + std::hypot(line.back().first - line[line.size() - 2].first,
                                                         line.back().second - line[line.size() - 2].second));
    }
    const float total = along.back();
    // The point at a distance along it (past the end: on along the last direction).
    const auto pointAt = [&](const float d) {
      const auto upper = std::lower_bound(along.begin(), along.end(), d);
      std::size_t k = static_cast<std::size_t>(upper - along.begin());
      if (k == 0) {
        return line.front();
      }
      if (k >= along.size()) {
        k = along.size() - 1;
      }
      const float span = along[k] - along[k - 1];
      const float f = span > 0.0f ? (d - along[k - 1]) / span : 0.0f;
      return std::pair<float, float>{line[k - 1].first + (line[k].first - line[k - 1].first) * f,
                                     line[k - 1].second + (line[k].second - line[k - 1].second) * f};
    };
    const float step = length * (1.0f - std::clamp(overlap, 0.0f, 0.9f));
    for (float start = 0.0f; start < total - 1e-3f && decals.size() < 4096; start += step) {
      // From where it starts to where it ends on the curve (clamped at the curve's end, then carried on straight).
      const auto from = pointAt(start);
      const auto to = pointAt(std::min(start + length, total));
      float dx = to.first - from.first;
      float dz = to.second - from.second;
      const float chord = std::hypot(dx, dz);
      if (chord < 1e-4f) {
        break;
      }
      dx /= chord;
      dz /= chord;
      const float yaw = std::atan2(dz, dx);
      // Centred across the curve, its length laid from the start point along the chord's direction.
      const float cx = from.first + dx * length * 0.5f;
      const float cz = from.second + dz * length * 0.5f;
      decals.push_back(DecalAround(cx, cz, length, width, yaw));
    }
    return decals;
  }

  const char* DecalTypeName(const int type)
  {
    switch (type) {
    case 1:
      return "albedo";
    case 2:
      return "normals";
    case 3:
      return "water mask";
    case 4:
      return "water albedo";
    case 5:
      return "water normals";
    case 6:
      return "glow";
    case 7:
      return "normals alpha";
    case 8:
      return "glow mask";
    case 9:
      return "albedo XP";
    default:
      return "undefined";
    }
  }
} // namespace faf::editor
