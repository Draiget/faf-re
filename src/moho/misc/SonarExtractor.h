#pragma once

#include "moho/misc/RangeExtractor.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3F990
   * COL: 0x00E981E0
   */
  class SonarExtractor : public RangeExtractor
  {
  public:
    /**
     * Address: 0x007EDB70 (FUN_007EDB70)
     * Slot: 0
     */
    ~SonarExtractor() override;

    /**
     * Address: 0x007ED150 (FUN_007ED150, Moho::SonarExtractor::Range)
     * Slot: 1
     */
    [[nodiscard]] bool
    Range(SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center) const override;

    /**
     * Address: 0x007ED090 (FUN_007ED090, Moho::SonarExtractor::Extract)
     * Slot: 2
     */
    [[nodiscard]] bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const override;
  };

#if defined(_M_IX86)
  static_assert(sizeof(SonarExtractor) == 0x04, "SonarExtractor size must be 0x04");
#endif
} // namespace moho
