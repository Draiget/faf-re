#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  /**
   * Recovered `UnitAttributes` layout.
   *
   * Evidence:
   * - UnitAttributesTypeInfo::Init (0x0055C270 / FUN_0055C270) sets type size to 0x70.
   * - IUnit::CalcSpawnElevation (0x00541540 / 0x1012EEF0) reads float +0x30.
   * - Unit::SetPaused (0x006A73F0) reads dword +0x60 and bit 0x40 from dword +0x64.
   * - Unit::ToggleScriptBit (0x006A7490) reads dword +0x64 as script-bit permission mask.
   */
  struct UnitAttributes
  {
    std::uint8_t unknown_0000[0x30];
    float spawnElevationOffset; // +0x30 (mElevation in decompiler output)
    float moveSpeedMult;        // +0x34 (GetAttributes vslot users scale movement tolerances/speeds)
    std::uint8_t unknown_0038[0x28];
    std::uint32_t commandCapsMask; // +0x60 (RULEUCC_* bits, e.g. Pause=0x20000)
    std::uint32_t toggleCapsMask;  // +0x64 (RULEUTC_* bits, e.g. GenericToggle=0x40)
    std::uint32_t unknown_0068;    // +0x68
    std::uint32_t unknown_006C;    // +0x6C

    [[nodiscard]] std::uint8_t GetReconBlipBlueprintState0() const noexcept
    {
      return static_cast<std::uint8_t>(unknown_0068 & 0xFFu);
    }

    [[nodiscard]] std::uint8_t GetReconBlipBlueprintState1() const noexcept
    {
      return static_cast<std::uint8_t>((unknown_0068 >> 8u) & 0xFFu);
    }
  };

  static_assert(
    offsetof(UnitAttributes, spawnElevationOffset) == 0x30, "UnitAttributes::spawnElevationOffset offset must be 0x30"
  );
  static_assert(offsetof(UnitAttributes, moveSpeedMult) == 0x34, "UnitAttributes::moveSpeedMult offset must be 0x34");
  static_assert(
    offsetof(UnitAttributes, commandCapsMask) == 0x60, "UnitAttributes::commandCapsMask offset must be 0x60"
  );
  static_assert(offsetof(UnitAttributes, toggleCapsMask) == 0x64, "UnitAttributes::toggleCapsMask offset must be 0x64");
  static_assert(offsetof(UnitAttributes, unknown_0068) == 0x68, "UnitAttributes::unknown_0068 offset must be 0x68");
  static_assert(offsetof(UnitAttributes, unknown_006C) == 0x6C, "UnitAttributes::unknown_006C offset must be 0x6C");
  static_assert(sizeof(UnitAttributes) == 0x70, "UnitAttributes size must be 0x70");
} // namespace moho
