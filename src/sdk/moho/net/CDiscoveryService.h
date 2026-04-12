#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal stub for typeid() / TypeInfo registration.
   * Full layout recovery pending.
   */
  class CDiscoveryService
  {
    unsigned char mPadding[0x90];
  };

  static_assert(sizeof(CDiscoveryService) == 0x90, "CDiscoveryService size must be 0x90");
} // namespace moho
