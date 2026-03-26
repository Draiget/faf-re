#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/RangeExtractor.h"

namespace moho
{
  struct RUnitBlueprint;

  /**
   * VFTABLE: 0x00E3F940
   * COL: 0x00E9835C
   */
  class WeaponExtractor : public RangeExtractor
  {
  public:
    std::int32_t mRangeCategory = 0; // +0x04

    /**
     * Address: 0x007EC840 (FUN_007EC840)
     * Slot: 0
     */
    ~WeaponExtractor() override;

    /**
     * Address: 0x007EC650 (FUN_007EC650, Moho::WeaponExtractor::Range)
     * Slot: 1
     *
     * What it does:
     * Scans weapon-blueprint lanes matching `mRangeCategory` and emits
     * `{center.x, center.z, minRange, maxRange}`.
     */
    [[nodiscard]] bool
    Range(SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center) const override;

    /**
     * Address: 0x007EC5B0 (FUN_007EC5B0, Moho::WeaponExtractor::Extract)
     * Slot: 2
     *
     * What it does:
     * Queries runtime weapon min/max range for `mRangeCategory` and emits
     * `{interp.x, interp.z, minRange, maxRange}`.
     */
    [[nodiscard]] bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const override;

    [[nodiscard]] static bool ResolveWeaponCategoryRange(
      float* outInnerRadius,
      float* outOuterRadius,
      const RUnitBlueprint& unitBlueprint,
      std::int32_t rangeCategoryFilter
    ) noexcept;
  };

#if defined(_M_IX86)
  static_assert(offsetof(WeaponExtractor, mRangeCategory) == 0x04, "WeaponExtractor::mRangeCategory offset must be 0x04");
  static_assert(sizeof(WeaponExtractor) == 0x08, "WeaponExtractor size must be 0x08");
#endif
} // namespace moho
