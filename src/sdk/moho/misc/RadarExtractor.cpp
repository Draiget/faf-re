#include "moho/misc/RadarExtractor.h"

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace moho
{
  /**
   * Address: 0x007EDB50 (FUN_007EDB50)
   */
  RadarExtractor::~RadarExtractor() = default;

  /**
   * Address: 0x007ED000 (FUN_007ED000, Moho::RadarExtractor::Range)
   */
  bool RadarExtractor::Range(
    SRangeExtractionPayload* const outRange, const RUnitBlueprint* const unitBlueprint, const Wm3::Vec3f& center
  ) const
  {
    if (!outRange || !unitBlueprint) {
      return false;
    }

    const float radius = static_cast<float>(unitBlueprint->Intel.RadarRadius);
    return StoreRangeAtCenter(outRange, center, radius);
  }

  /**
   * Address: 0x007ECF40 (FUN_007ECF40, Moho::RadarExtractor::Extract)
   */
  bool RadarExtractor::Extract(
    SRangeExtractionPayload* const outRange, const UserEntity* const userEntity, const float interpolationAlpha
  ) const
  {
    if (!outRange || !userEntity) {
      return false;
    }

    float omniRange = 0.0f;
    float radarRange = 0.0f;
    float sonarRange = 0.0f;
    if (!TryGetIntelRanges(userEntity, &omniRange, &radarRange, &sonarRange)) {
      return false;
    }

    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, radarRange);
  }
} // namespace moho
