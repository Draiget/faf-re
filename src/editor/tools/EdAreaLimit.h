#pragma once

// Areas kept inside a rectangle (FAF Studio's "Limit to map bounds" and "Limit to playable area", tools.lua 54-100):
// while an area is drawn, resized or typed it is cut to the bounds; while it is moved it keeps its size and is pushed
// back inside (cut only when it is larger than the bounds). No engine types: tested on its own
// (tests/editor/RoundNineTests.cpp).

#include <algorithm>

namespace faf::editor
{
  struct AreaBounds
  {
    float x0 = -1e9f;
    float z0 = -1e9f;
    float x1 = 1e9f;
    float z1 = 1e9f;
  };

  /** `rect` is left, top, right, bottom (game units), left < right and top < bottom on the way in and out. */
  inline void LimitArea(
    float (&rect)[4],
    const AreaBounds& bounds,
    const bool keepSize
  )
  {
    if (keepSize) {
      const float w = rect[2] - rect[0];
      const float h = rect[3] - rect[1];
      if (w <= bounds.x1 - bounds.x0) {
        const float x0 = std::clamp(rect[0], bounds.x0, bounds.x1 - w);
        rect[0] = x0;
        rect[2] = x0 + w;
      }
      if (h <= bounds.z1 - bounds.z0) {
        const float z0 = std::clamp(rect[1], bounds.z0, bounds.z1 - h);
        rect[1] = z0;
        rect[3] = z0 + h;
      }
    }
    rect[0] = std::clamp(rect[0], bounds.x0, bounds.x1);
    rect[2] = std::clamp(rect[2], bounds.x0, bounds.x1);
    rect[1] = std::clamp(rect[1], bounds.z0, bounds.z1);
    rect[3] = std::clamp(rect[3], bounds.z0, bounds.z1);
    if (rect[2] < rect[0] + 1.0f) {
      rect[2] = std::min(rect[0] + 1.0f, bounds.x1);
      rect[0] = std::min(rect[0], rect[2] - 1.0f);
    }
    if (rect[3] < rect[1] + 1.0f) {
      rect[3] = std::min(rect[1] + 1.0f, bounds.z1);
      rect[1] = std::min(rect[1], rect[3] - 1.0f);
    }
  }
} // namespace faf::editor
