#pragma once

#include <cmath>

namespace moho
{
  /**
   * Engine addition (`ren_ShadowStable`): the light-space box of one frame's shadow map, fitted so
   * that shadow texels stay on the same world positions while the camera pans. Without it the box
   * follows the view exactly, each frame rasterises casters on a different grid, and shadow edges
   * crawl.
   *
   * Depth is left to the caller on purpose: `ren_ShadowBias` is a fraction of the depth range, so
   * widening the range lifts shadows off their casters.
   *
   * Pure maths, so `tests/render/ShadowStableFitTests.cpp` can run it without a device.
   */
  struct ShadowStableBox
  {
    float minX;
    float maxX;
    float minY;
    float maxY;
  };

  /**
   * Picks the box length for one axis. `held` is the length used last frame; it stays while it
   * fits and isn't more than 12% too big, so panning over hills doesn't change the texel size.
   * Otherwise the length rounds up to a step of 1/16 of its octave. Every bit of length is shadow
   * resolution lost, so both limits stay small.
   */
  [[nodiscard]] inline float FitShadowStableExtent(const float needed, const float held) noexcept
  {
    if (held >= needed && held <= needed * 1.12f) {
      return held;
    }
    const float step = std::ldexp(1.0f, std::ilogb(needed) - 4);
    return std::ceil(needed / step) * step;
  }

  /**
   * Fits one axis: returns the box's low edge on a whole number of texels and updates `held`.
   * The draw viewport is inset one pixel on each side, so a texel is length / (size - 2). A corner
   * snapped down moves by under one texel, so the length carries one texel of margin.
   */
  [[nodiscard]] inline float FitShadowStableAxis(
    const float rawMin, const float rawMax, const int shadowSize, float& held
  ) noexcept
  {
    const float usable = static_cast<float>(shadowSize - 2);
    const float needed = (rawMax - rawMin) * usable / (usable - 1.0f);
    held = FitShadowStableExtent(needed, held);
    // In double: far from the origin a float quotient can step past a whole texel.
    const double texel = static_cast<double>(held) / static_cast<double>(usable);
    return static_cast<float>(std::floor(static_cast<double>(rawMin) / texel) * texel);
  }

  /** Fits the box. The raw values are the exact fit of this frame's volume in a world-anchored light space. */
  [[nodiscard]] inline ShadowStableBox FitShadowStableBox(
    const float rawMinX,
    const float rawMaxX,
    const float rawMinY,
    const float rawMaxY,
    const int shadowSize,
    float& heldWidth,
    float& heldHeight
  ) noexcept
  {
    ShadowStableBox box{};
    box.minX = FitShadowStableAxis(rawMinX, rawMaxX, shadowSize, heldWidth);
    box.maxX = box.minX + heldWidth;
    box.minY = FitShadowStableAxis(rawMinY, rawMaxY, shadowSize, heldHeight);
    box.maxY = box.minY + heldHeight;
    return box;
  }
} // namespace moho
