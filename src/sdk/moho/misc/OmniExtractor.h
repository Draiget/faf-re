#pragma once

#include "moho/misc/RangeExtractor.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3F970
   * COL: 0x00E98278
   */
  class OmniExtractor : public RangeExtractor
  {
  public:
    /**
     * Address: 0x007EDB90 (FUN_007EDB90)
     * Slot: 0
     */
    ~OmniExtractor() override;

    /**
     * Address: 0x007ECEB0 (FUN_007ECEB0, Moho::OmniExtractor::Range)
     * Slot: 1
     */
    [[nodiscard]] bool
    Range(SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center) const override;

    /**
     * Address: 0x007ECDF0 (FUN_007ECDF0, Moho::OmniExtractor::Extract)
     * Slot: 2
     */
    [[nodiscard]] bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const override;
  };

#if defined(_M_IX86)
  static_assert(sizeof(OmniExtractor) == 0x04, "OmniExtractor size must be 0x04");
#endif
} // namespace moho
