#pragma once

#include "moho/misc/RangeExtractor.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3F980
   * COL: 0x00E9822C
   */
  class RadarExtractor : public RangeExtractor
  {
  public:
    /**
     * Address: 0x007EDB50 (FUN_007EDB50)
     * Slot: 0
     */
    ~RadarExtractor() override;

    /**
     * Address: 0x007ED000 (FUN_007ED000, Moho::RadarExtractor::Range)
     * Slot: 1
     */
    [[nodiscard]] bool
    Range(SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center) const override;

    /**
     * Address: 0x007ECF40 (FUN_007ECF40, Moho::RadarExtractor::Extract)
     * Slot: 2
     */
    [[nodiscard]] bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const override;
  };

#if defined(_M_IX86)
  static_assert(sizeof(RadarExtractor) == 0x04, "RadarExtractor size must be 0x04");
#endif
} // namespace moho
