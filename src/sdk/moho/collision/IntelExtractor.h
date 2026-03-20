#pragma once

#include "moho/misc/RangeExtractor.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3F960
   * COL:  0x00E982C4
   */
  class IntelExtractor : public RangeExtractor
  {
  public:
    /**
     * Address: 0x007EDB30 (FUN_007EDB30)
     * Slot: 0
     */
    ~IntelExtractor() override;

    /**
     * Address: 0x007ECCE0 (FUN_007ECCE0)
     * Slot: 1
     */
    [[nodiscard]] bool Range(
      SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center
    ) const override;

    /**
     * Address: 0x007ECC00 (FUN_007ECC00)
     * Slot: 2
     */
    [[nodiscard]] bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const override;
  };

#if defined(_M_IX86)
  static_assert(sizeof(IntelExtractor) == 0x04, "IntelExtractor size must be 0x04");
#endif
} // namespace moho
