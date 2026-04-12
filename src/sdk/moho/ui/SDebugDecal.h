#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Vector3.h"

namespace moho
{
  /**
   * Address: 0x004516C0 (FUN_004516C0 payload in Moho::CDebugCanvas::Render)
   *
   * What it does:
   * Carries one four-corner colored debug decal quad.
   */
  struct SDebugDecal
  {
    Wm3::Vec3f corner0;     // +0x00
    Wm3::Vec3f corner1;     // +0x0C
    Wm3::Vec3f corner2;     // +0x18
    Wm3::Vec3f corner3;     // +0x24
    std::uint32_t color;    // +0x30
  };

  static_assert(offsetof(SDebugDecal, corner0) == 0x00, "SDebugDecal::corner0 offset must be 0x00");
  static_assert(offsetof(SDebugDecal, corner1) == 0x0C, "SDebugDecal::corner1 offset must be 0x0C");
  static_assert(offsetof(SDebugDecal, corner2) == 0x18, "SDebugDecal::corner2 offset must be 0x18");
  static_assert(offsetof(SDebugDecal, corner3) == 0x24, "SDebugDecal::corner3 offset must be 0x24");
  static_assert(offsetof(SDebugDecal, color) == 0x30, "SDebugDecal::color offset must be 0x30");
  static_assert(sizeof(SDebugDecal) == 0x34, "SDebugDecal size must be 0x34");
} // namespace moho
