#pragma once

#include <cstddef>

#include "wm3/Vector3.h"

namespace moho
{
  class UserEntity;
  struct RUnitBlueprint;

  struct SRangeExtractionPayload
  {
    float centerX;
    float centerZ;
    float centerY;
    float radius;
  };

  static_assert(
    offsetof(SRangeExtractionPayload, centerX) == 0x00, "SRangeExtractionPayload::centerX offset must be 0x00"
  );
  static_assert(
    offsetof(SRangeExtractionPayload, centerZ) == 0x04, "SRangeExtractionPayload::centerZ offset must be 0x04"
  );
  static_assert(
    offsetof(SRangeExtractionPayload, centerY) == 0x08, "SRangeExtractionPayload::centerY offset must be 0x08"
  );
  static_assert(
    offsetof(SRangeExtractionPayload, radius) == 0x0C, "SRangeExtractionPayload::radius offset must be 0x0C"
  );
  static_assert(sizeof(SRangeExtractionPayload) == 0x10, "SRangeExtractionPayload size must be 0x10");

  /**
   * VFTABLE: 0x00E3F920
   * COL:  0x00E983F4
   */
  class RangeExtractor
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall in abstract base slot)
     * Slot: 0
     */
    virtual ~RangeExtractor() = 0;

    /**
     * Address: 0x00A82547 (_purecall in abstract base slot)
     * Slot: 1
     */
    [[nodiscard]] virtual bool
    Range(SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center) const = 0;

    /**
     * Address: 0x00A82547 (_purecall in abstract base slot)
     * Slot: 2
     */
    [[nodiscard]] virtual bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const = 0;
  };

#if defined(_M_IX86)
  static_assert(sizeof(RangeExtractor) == 0x04, "RangeExtractor size must be 0x04");
#endif
} // namespace moho
