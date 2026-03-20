#pragma once

#include <cstddef>

#include "legacy/containers/String.h"

namespace moho
{
  /**
   * Address: 0x004A94F0 (FUN_004A94F0)
   *
   * What it does:
   * Reflection type init sets `sizeof(RResId) = 0x1C`.
   */
  struct RResId
  {
    msvc8::string name;
  };

  static_assert(offsetof(RResId, name) == 0x00, "RResId::name offset must be 0x00");
  static_assert(sizeof(RResId) == 0x1C, "RResId size must be 0x1C");
} // namespace moho
