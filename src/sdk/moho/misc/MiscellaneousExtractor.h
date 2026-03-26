#pragma once

#include "moho/misc/RangeExtractor.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3F9B0
   * COL: 0x00E98148
   */
  class MiscellaneousExtractor : public RangeExtractor
  {
  public:
    /**
     * Address: 0x007EDB10 (FUN_007EDB10)
     * Slot: 0
     */
    ~MiscellaneousExtractor() override;

    /**
     * Address: 0x007ED430 (FUN_007ED430, Moho::MiscellaneousExtractor::Range)
     * Slot: 1
     *
     * What it does:
     * Emits the positive staging-platform or guard overlay range from blueprint AI data.
     */
    [[nodiscard]] bool
    Range(SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center) const override;

    /**
     * Address: 0x007ED370 (FUN_007ED370, Moho::MiscellaneousExtractor::Extract)
     * Slot: 2
     *
     * What it does:
     * Emits runtime staging-platform/guard overlay radius from the factory queue.
     */
    [[nodiscard]] bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const override;
  };

#if defined(_M_IX86)
  static_assert(sizeof(MiscellaneousExtractor) == 0x04, "MiscellaneousExtractor size must be 0x04");
#endif
} // namespace moho
