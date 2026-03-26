#pragma once

#include <cstddef>
#include <cstdint>

#include "AdapterModeD3D9.hpp"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
  /**
   * VFTABLE: 0x00D42808
   * COL:     0x00E5089C
   */
  class AdapterD3D9
  {
  public:
    /**
     * Address: 0x008F0040 (FUN_008F0040)
     *
     * What it does:
     * Owns the scalar-deleting destructor thunk for AdapterD3D9 instances.
     */
    virtual ~AdapterD3D9();

  public:
    std::uint32_t vendorId = 0;                  // +0x04
    std::uint32_t deviceId = 0;                  // +0x08
    std::uint8_t reserved0x0C_5F_[0x54]{};       // +0x0C
    msvc8::vector<AdapterModeD3D9> modes{};      // +0x60
  };

  static_assert(offsetof(AdapterD3D9, vendorId) == 0x04, "AdapterD3D9::vendorId offset must be 0x04");
  static_assert(offsetof(AdapterD3D9, deviceId) == 0x08, "AdapterD3D9::deviceId offset must be 0x08");
  static_assert(offsetof(AdapterD3D9, modes) == 0x60, "AdapterD3D9::modes offset must be 0x60");
  static_assert(sizeof(AdapterD3D9) == 0x70, "AdapterD3D9 size must be 0x70");
} // namespace gpg::gal
