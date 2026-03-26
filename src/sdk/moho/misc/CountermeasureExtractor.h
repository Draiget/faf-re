#pragma once

#include "moho/misc/RangeExtractor.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3F950
   * COL: 0x00E98310
   */
  class CountermeasureExtractor : public RangeExtractor
  {
  public:
    /**
     * Address: 0x007ECBD0 (FUN_007ECBD0)
     * Slot: 0
     */
    ~CountermeasureExtractor() override;

    /**
     * Address: 0x007EC980 (FUN_007EC980, Moho::CountermeasureExtractor::Range)
     * Slot: 1
     *
     * What it does:
     * Uses shield radius when present, else scans countermeasure weapon lanes
     * and emits `{center.x, center.z, minRange, maxRange}`.
     */
    [[nodiscard]] bool
    Range(SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center) const override;

    /**
     * Address: 0x007EC880 (FUN_007EC880, Moho::CountermeasureExtractor::Extract)
     * Slot: 2
     *
     * What it does:
     * Uses factory overlay radius when available, otherwise falls back to
     * runtime countermeasure weapon min/max ranges.
     */
    [[nodiscard]] bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const override;
  };

#if defined(_M_IX86)
  static_assert(sizeof(CountermeasureExtractor) == 0x04, "CountermeasureExtractor size must be 0x04");
#endif
} // namespace moho
