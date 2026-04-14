#pragma once

#include <cstddef>
#include <cstdint>

#include "AdapterModeD3D9.hpp"
#include "gpg/core/containers/String.h"
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
    AdapterD3D9() = default;

    /**
     * Address: 0x009410A0 (FUN_009410A0, gpg::gal::AdapterD3D9::AdapterD3D9)
     * Mangled: ??0AdapterD3D9@gal@gpg@@QAE@@Z
     *
     * What it does:
     * Initializes adapter vendor/device identifiers, copies adapter identity
     * strings, and clears the mode vector lanes.
     */
    AdapterD3D9(
      std::uint32_t vendorId,
      std::uint32_t deviceId,
      const msvc8::string& driver,
      const msvc8::string& device,
      const msvc8::string& desc
    );

    /**
     * Address: 0x00940C90 (FUN_00940C90)
     * Scalar-deleting wrapper: 0x008F0040 (FUN_008F0040)
     *
     * What it does:
     * Destroys adapter mode list and all descriptive string lanes.
     */
    virtual ~AdapterD3D9();

  public:
    std::uint32_t vendorId = 0;             // +0x04
    std::uint32_t deviceId = 0;             // +0x08
    msvc8::string driver{};                 // +0x0C
    msvc8::string deviceName{};             // +0x28
    msvc8::string description{};            // +0x44
    msvc8::vector<AdapterModeD3D9> modes{}; // +0x60
  };

  static_assert(offsetof(AdapterD3D9, vendorId) == 0x04, "AdapterD3D9::vendorId offset must be 0x04");
  static_assert(offsetof(AdapterD3D9, deviceId) == 0x08, "AdapterD3D9::deviceId offset must be 0x08");
  static_assert(offsetof(AdapterD3D9, driver) == 0x0C, "AdapterD3D9::driver offset must be 0x0C");
  static_assert(offsetof(AdapterD3D9, deviceName) == 0x28, "AdapterD3D9::deviceName offset must be 0x28");
  static_assert(offsetof(AdapterD3D9, description) == 0x44, "AdapterD3D9::description offset must be 0x44");
  static_assert(offsetof(AdapterD3D9, modes) == 0x60, "AdapterD3D9::modes offset must be 0x60");
  static_assert(sizeof(AdapterD3D9) == 0x70, "AdapterD3D9 size must be 0x70");
} // namespace gpg::gal
