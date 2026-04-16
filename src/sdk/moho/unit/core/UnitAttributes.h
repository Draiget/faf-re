#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/entity/EntityCategoryReflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class RType;
}

namespace moho
{
  struct RUnitBlueprint;
  class RRuleGameRulesImpl;

  /**
   * Recovered `UnitAttributes` layout.
   *
   * Evidence:
   * - UnitAttributesTypeInfo::Init (0x0055C270 / FUN_0055C270) sets type size to 0x70.
   * - IUnit::CalcSpawnElevation (0x00541540 / 0x1012EEF0) reads float +0x30.
   * - Unit::SetPaused (0x006A73F0) reads dword +0x60 and bit 0x40 from dword +0x64.
   * - Unit::ToggleScriptBit (0x006A7490) reads dword +0x64 as script-bit permission mask.
   * - Unit Lua setters in 0x006C9220..0x006CB360 write the movement/economy
   *   scalar lanes at +0x34..+0x5C.
   * - Unit Lua reverts in 0x006C93B0 / 0x006CAC70 read blueprint lanes through
   *   pointer at +0x00.
   */
  struct UnitAttributes
  {
    const RUnitBlueprint* blueprint;    // +0x00
    std::uint32_t unknown_0004;         // +0x04
    EntityCategorySet restrictionCategory; // +0x08
    float spawnElevationOffset;         // +0x30 (also written by Unit:SetElevation)
    float moveSpeedMult;                // +0x34 (also written by Unit:SetSpeedMult)
    float accelerationMult;             // +0x38
    float turnMult;                     // +0x3C
    float breakOffTriggerMult;          // +0x40
    float breakOffDistanceMult;         // +0x44
    float consumptionPerSecondEnergy; // +0x48
    float consumptionPerSecondMass;   // +0x4C
    float productionPerSecondEnergy;  // +0x50
    float productionPerSecondMass;    // +0x54
    float buildRate;                  // +0x58
    float regenRate;                  // +0x5C
    std::uint32_t commandCapsMask; // +0x60 (RULEUCC_* bits, e.g. Pause=0x20000)
    std::uint32_t toggleCapsMask;  // +0x64 (RULEUTC_* bits, e.g. GenericToggle=0x40)
    bool mReclaimable;             // +0x68
    bool mCapturable;              // +0x69
    std::uint8_t unknown_006A;     // +0x6A
    std::uint8_t unknown_006B;     // +0x6B
    std::uint32_t unknown_006C;    // +0x6C

    static gpg::RType* sType;
    UnitAttributes() = default;

    /**
     * Address: 0x006A4760 (FUN_006A4760, Moho::UnitAttributes::UnitAttributes)
     *
     * What it does:
     * Seeds runtime attribute lanes from blueprint defaults, initializes the
     * category universe from rules empty-category lookup, and restores command/
     * toggle capability masks.
     */
    UnitAttributes(const RUnitBlueprint* blueprint, const RRuleGameRulesImpl* rules);

    /**
     * Address: 0x0055C2D0 (FUN_0055C2D0, Moho::UnitAttributes::StaticGetClass)
     *
     * What it does:
     * Returns the cached reflection descriptor for `UnitAttributes`.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x0055DC00 (FUN_0055DC00, Moho::UnitAttributes::MemberDeserialize)
     *
     * What it does:
     * Deserializes pointer/category/float/caps/bool lanes into one
     * `UnitAttributes` object.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, UnitAttributes* attributes);

    /**
     * Address: 0x0055DD80 (FUN_0055DD80, Moho::UnitAttributes::MemberSerialize)
     *
     * What it does:
     * Serializes pointer/category/float/caps/bool lanes from one
     * `UnitAttributes` object.
     */
    static void MemberSerialize(const UnitAttributes* attributes, gpg::WriteArchive* archive);

    [[nodiscard]] std::uint8_t GetReconBlipBlueprintState0() const noexcept
    {
      return static_cast<std::uint8_t>(mReclaimable ? 1u : 0u);
    }

    [[nodiscard]] std::uint8_t GetReconBlipBlueprintState1() const noexcept
    {
      return static_cast<std::uint8_t>(mCapturable ? 1u : 0u);
    }
  };

  static_assert(offsetof(UnitAttributes, blueprint) == 0x00, "UnitAttributes::blueprint offset must be 0x00");
  static_assert(offsetof(UnitAttributes, unknown_0004) == 0x04, "UnitAttributes::unknown_0004 offset must be 0x04");
  static_assert(
    offsetof(UnitAttributes, restrictionCategory) == 0x08,
    "UnitAttributes::restrictionCategory offset must be 0x08"
  );
  static_assert(
    offsetof(UnitAttributes, spawnElevationOffset) == 0x30, "UnitAttributes::spawnElevationOffset offset must be 0x30"
  );
  static_assert(offsetof(UnitAttributes, moveSpeedMult) == 0x34, "UnitAttributes::moveSpeedMult offset must be 0x34");
  static_assert(offsetof(UnitAttributes, accelerationMult) == 0x38, "UnitAttributes::accelerationMult offset must be 0x38");
  static_assert(offsetof(UnitAttributes, turnMult) == 0x3C, "UnitAttributes::turnMult offset must be 0x3C");
  static_assert(
    offsetof(UnitAttributes, breakOffTriggerMult) == 0x40, "UnitAttributes::breakOffTriggerMult offset must be 0x40"
  );
  static_assert(
    offsetof(UnitAttributes, breakOffDistanceMult) == 0x44,
    "UnitAttributes::breakOffDistanceMult offset must be 0x44"
  );
  static_assert(
    offsetof(UnitAttributes, consumptionPerSecondEnergy) == 0x48,
    "UnitAttributes::consumptionPerSecondEnergy offset must be 0x48"
  );
  static_assert(
    offsetof(UnitAttributes, consumptionPerSecondMass) == 0x4C,
    "UnitAttributes::consumptionPerSecondMass offset must be 0x4C"
  );
  static_assert(
    offsetof(UnitAttributes, productionPerSecondEnergy) == 0x50,
    "UnitAttributes::productionPerSecondEnergy offset must be 0x50"
  );
  static_assert(
    offsetof(UnitAttributes, productionPerSecondMass) == 0x54,
    "UnitAttributes::productionPerSecondMass offset must be 0x54"
  );
  static_assert(offsetof(UnitAttributes, buildRate) == 0x58, "UnitAttributes::buildRate offset must be 0x58");
  static_assert(offsetof(UnitAttributes, regenRate) == 0x5C, "UnitAttributes::regenRate offset must be 0x5C");
  static_assert(
    offsetof(UnitAttributes, commandCapsMask) == 0x60, "UnitAttributes::commandCapsMask offset must be 0x60"
  );
  static_assert(offsetof(UnitAttributes, toggleCapsMask) == 0x64, "UnitAttributes::toggleCapsMask offset must be 0x64");
  static_assert(offsetof(UnitAttributes, mReclaimable) == 0x68, "UnitAttributes::mReclaimable offset must be 0x68");
  static_assert(offsetof(UnitAttributes, mCapturable) == 0x69, "UnitAttributes::mCapturable offset must be 0x69");
  static_assert(offsetof(UnitAttributes, unknown_006A) == 0x6A, "UnitAttributes::unknown_006A offset must be 0x6A");
  static_assert(offsetof(UnitAttributes, unknown_006B) == 0x6B, "UnitAttributes::unknown_006B offset must be 0x6B");
  static_assert(offsetof(UnitAttributes, unknown_006C) == 0x6C, "UnitAttributes::unknown_006C offset must be 0x6C");
  static_assert(sizeof(UnitAttributes) == 0x70, "UnitAttributes size must be 0x70");

  /**
   * Address: 0x0055C210 (FUN_0055C210, preregister_UnitAttributesTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `UnitAttributes`.
   */
  [[nodiscard]] gpg::RType* preregister_UnitAttributesTypeInfo();
} // namespace moho
