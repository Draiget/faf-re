#pragma once

#include "moho/misc/RangeExtractor.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3F9A0
   * COL:  0x00E98194
   */
  class CounterIntelExtractor : public RangeExtractor
  {
  public:
    /**
     * Address: 0x007EDBB0 (FUN_007EDBB0)
     * Slot: 0
     */
    ~CounterIntelExtractor() override;

    /**
     * Address: 0x007ED270 (FUN_007ED270)
     * Slot: 1
     */
    [[nodiscard]] bool Range(
      SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center
    ) const override;

    /**
     * Address: 0x007ED1E0 (FUN_007ED1E0)
     * Slot: 2
     */
    [[nodiscard]] bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const override;
  };

#if defined(_M_IX86)
  static_assert(sizeof(CounterIntelExtractor) == 0x04, "CounterIntelExtractor size must be 0x04");
#endif
} // namespace moho
