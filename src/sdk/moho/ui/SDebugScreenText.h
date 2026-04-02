#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "wm3/Vector3.h"

namespace moho
{
  /**
   * Address: 0x004516C0 (FUN_004516C0 payload in Moho::CDebugCanvas::Render)
   *
   * What it does:
   * Carries one oriented world-space text draw command for debug rendering.
   */
  struct SDebugScreenText
  {
    Wm3::Vec3f origin;        // +0x00
    Wm3::Vec3f xAxis;         // +0x0C
    Wm3::Vec3f yAxis;         // +0x18
    msvc8::string text;       // +0x24
    std::int32_t pointSize;   // +0x40
    std::uint32_t color;      // +0x44
  };

  static_assert(offsetof(SDebugScreenText, origin) == 0x00, "SDebugScreenText::origin offset must be 0x00");
  static_assert(offsetof(SDebugScreenText, xAxis) == 0x0C, "SDebugScreenText::xAxis offset must be 0x0C");
  static_assert(offsetof(SDebugScreenText, yAxis) == 0x18, "SDebugScreenText::yAxis offset must be 0x18");
  static_assert(offsetof(SDebugScreenText, text) == 0x24, "SDebugScreenText::text offset must be 0x24");
  static_assert(
    offsetof(SDebugScreenText, pointSize) == 0x40,
    "SDebugScreenText::pointSize offset must be 0x40"
  );
  static_assert(offsetof(SDebugScreenText, color) == 0x44, "SDebugScreenText::color offset must be 0x44");
  static_assert(sizeof(SDebugScreenText) == 0x48, "SDebugScreenText size must be 0x48");
} // namespace moho
