#include "editor/tools/EdWaterMasks.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  std::uint8_t WaterMaskDefault(
    const WaterMask mask
  ) noexcept
  {
    switch (mask) {
    case WaterMask::Foam:
      return 0;
    case WaterMask::Flatness:
      return 0xFF;
    default:
      return 0x7F;
    }
  }

  const char* WaterMaskName(
    const WaterMask mask
  ) noexcept
  {
    switch (mask) {
    case WaterMask::Foam:
      return "foam";
    case WaterMask::Flatness:
      return "flatness";
    default:
      return "depth bias";
    }
  }

  WaterMaskRect PaintWaterMask(
    std::uint8_t* const cells,
    const int width,
    const int height,
    const float x,
    const float z,
    const WaterMaskBrush& brush
  )
  {
    WaterMaskRect rect;
    if (cells == nullptr || width <= 0 || height <= 0 || !(brush.radius > 0.0f) || !(brush.strength > 0.0f)) {
      return rect;
    }
    // Cell i covers map units [2i, 2i + 2); its middle is 2i + 1.
    const int i0 = std::max(0, static_cast<int>(std::floor((x - brush.radius - 1.0f) * 0.5f)));
    const int i1 = std::min(width, static_cast<int>(std::ceil((x + brush.radius - 1.0f) * 0.5f)) + 1);
    const int j0 = std::max(0, static_cast<int>(std::floor((z - brush.radius - 1.0f) * 0.5f)));
    const int j1 = std::min(height, static_cast<int>(std::ceil((z + brush.radius - 1.0f) * 0.5f)) + 1);
    const float hard = brush.radius * (1.0f - std::clamp(brush.falloff, 0.0f, 1.0f));
    const float strength = std::clamp(brush.strength, 0.0f, 1.0f);
    rect.x0 = width;
    rect.z0 = height;
    for (int j = j0; j < j1; ++j) {
      for (int i = i0; i < i1; ++i) {
        const float d = std::hypot(2.0f * static_cast<float>(i) + 1.0f - x, 2.0f * static_cast<float>(j) + 1.0f - z);
        if (d >= brush.radius) {
          continue;
        }
        const float weight =
          d <= hard ? strength : strength * (brush.radius - d) / std::max(brush.radius - hard, 1e-4f);
        std::uint8_t& cell =
          cells[static_cast<std::size_t>(j) * static_cast<std::size_t>(width) + static_cast<std::size_t>(i)];
        const int now = cell;
        const int target = brush.value;
        if (now == target || !(weight > 0.0f)) {
          continue;
        }
        int step = static_cast<int>(std::lround(static_cast<float>(target - now) * weight));
        if (step == 0) {
          step = target > now ? 1 : -1;
        }
        cell = static_cast<std::uint8_t>(std::clamp(now + step, 0, 255));
        rect.x0 = std::min(rect.x0, i);
        rect.z0 = std::min(rect.z0, j);
        rect.x1 = std::max(rect.x1, i + 1);
        rect.z1 = std::max(rect.z1, j + 1);
      }
    }
    if (rect.x1 == 0) {
      rect = WaterMaskRect{};
    }
    return rect;
  }

  std::vector<std::uint8_t> WaterMaskBands(
    const std::uint8_t* const cells,
    const int width,
    const int height,
    const WaterMask mask
  )
  {
    std::vector<std::uint8_t> bands;
    if (cells == nullptr || width <= 0 || height <= 0) {
      return bands;
    }
    const std::size_t count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    bands.resize(count);
    const std::uint8_t neutral = WaterMaskDefault(mask);
    for (std::size_t k = 0; k < count; ++k) {
      bands[k] = cells[k] == neutral ? 0 : static_cast<std::uint8_t>(1 + cells[k] / 32);
    }
    return bands;
  }
} // namespace faf::editor
