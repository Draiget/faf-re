#include "editor/tools/EdTexScale.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    constexpr float kStep = 0.5f;
    constexpr float kMin = 4.0f;
    constexpr float kMax = 64.0f;
    constexpr float kRepeatMin = 20.0f;
    constexpr int kFallbackPixels = 1024;
    constexpr double kPhi = 1.6180339887;

    float Round(
      const double v
    )
    {
      return static_cast<float>(std::floor(v / kStep + 0.5) * kStep);
    }
  } // namespace

  float TileForPixels(
    const int pixels
  )
  {
    const int px = pixels >= 1 ? pixels : kFallbackPixels;
    float t = Round(static_cast<double>(px) / kTexelDensity);
    t = std::max(t, kRepeatMin);
    return std::clamp(t, kMin, kMax);
  }

  float DecorrelatedTile(
    const float size,
    const int steps
  )
  {
    return std::max(kMin, Round(static_cast<double>(size) * std::pow(kPhi, steps)));
  }

  float MacroTile(
    const float baseTile
  )
  {
    constexpr double kTarget = 128.0;
    const double base = baseTile >= 1.0f ? baseTile : kMin;
    double best = 0.0;
    double bestErr = -1.0;
    double loose = 0.0;
    double looseErr = -1.0;
    for (int k = 2; k <= 5; ++k) {
      const double v = base * std::pow(kPhi, k);
      if (v < 32.0 || v > 256.0) {
        continue;
      }
      const double err = std::fabs(std::log(v / kTarget));
      const double ratio = static_cast<double>(Round(v)) / base;
      if (std::fabs(ratio - std::floor(ratio + 0.5)) >= 0.08) {
        if (bestErr < 0.0 || err < bestErr) {
          best = v;
          bestErr = err;
        }
      } else if (looseErr < 0.0 || err < looseErr) {
        loose = v;
        looseErr = err;
      }
    }
    return Round(bestErr >= 0.0 ? best : looseErr >= 0.0 ? loose : kTarget);
  }

  bool IsDefaultTile(
    const float size,
    const float optimal
  )
  {
    return size <= 0.0f || std::fabs(size - 4.0f) < 0.01f || std::fabs(size - 1.0f) < 0.01f ||
      std::fabs(size - optimal) < 0.01f;
  }

  int DdsWidth(
    const void* const bytes,
    const unsigned long long count
  )
  {
    if (bytes == nullptr || count < 20 || std::memcmp(bytes, "DDS ", 4) != 0) {
      return 0;
    }
    std::uint32_t width = 0;
    std::memcpy(&width, static_cast<const char*>(bytes) + 16, sizeof(width));
    return width > 0 && width < 65536 ? static_cast<int>(width) : 0;
  }
} // namespace faf::editor
