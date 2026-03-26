#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "wm3/Vector3.h"

namespace moho
{
  /**
   * Address: 0x006531D0 (FUN_006531D0 callsite payload in Moho::RDebugWeapons::OnTick)
   *
   * What it does:
   * Carries one world-space text label entry submitted to `CDebugCanvas`.
   */
  struct SDebugWorldText
  {
    Wm3::Vec3f position;   // +0x00
    msvc8::string text;    // +0x0C
    std::int32_t style;    // +0x28
    std::uint32_t depth;   // +0x2C
  };

  static_assert(offsetof(SDebugWorldText, position) == 0x00, "SDebugWorldText::position offset must be 0x00");
  static_assert(offsetof(SDebugWorldText, text) == 0x0C, "SDebugWorldText::text offset must be 0x0C");
  static_assert(offsetof(SDebugWorldText, style) == 0x28, "SDebugWorldText::style offset must be 0x28");
  static_assert(offsetof(SDebugWorldText, depth) == 0x2C, "SDebugWorldText::depth offset must be 0x2C");
  static_assert(sizeof(SDebugWorldText) == 0x30, "SDebugWorldText size must be 0x30");
} // namespace moho
