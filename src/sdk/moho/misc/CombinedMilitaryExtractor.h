#pragma once

#include "moho/misc/RangeExtractor.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3F930
   * COL: 0x00E983A8
   */
  class CombinedMilitaryExtractor : public RangeExtractor
  {
  public:
    /**
     * Address: 0x007EC560 (FUN_007EC560)
     * Slot: 0
     */
    ~CombinedMilitaryExtractor() override;

    /**
     * Address: 0x007EC550 (FUN_007EC550, Moho::CombinedMilitaryExtractor::Range)
     * Slot: 1
     *
     * What it does:
     * Blueprint path is intentionally disabled for this overlay extractor.
     */
    [[nodiscard]] bool
    Range(SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center) const override;

    /**
     * Address: 0x007EC3A0 (FUN_007EC3A0, Moho::CombinedMilitaryExtractor::Extract)
     * Slot: 2
     *
     * What it does:
     * Uses factory overlay range for `OVERLAYMISC` units when available;
     * otherwise falls back to all-weapon range extraction.
     */
    [[nodiscard]] bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const override;
  };

#if defined(_M_IX86)
  static_assert(sizeof(CombinedMilitaryExtractor) == 0x04, "CombinedMilitaryExtractor size must be 0x04");
#endif
} // namespace moho
