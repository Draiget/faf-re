#include "moho/misc/SonarExtractor.h"

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace moho
{
  /**
   * Address: 0x007EDB70 (FUN_007EDB70)
   */
  SonarExtractor::~SonarExtractor() = default;

  /**
   * Address: 0x007ED150 (FUN_007ED150, Moho::SonarExtractor::Range)
   */
  bool SonarExtractor::Range(
    SRangeExtractionPayload* const outRange, const RUnitBlueprint* const unitBlueprint, const Wm3::Vec3f& center
  ) const
  {
    if (!outRange || !unitBlueprint) {
      return false;
    }

    const float radius = static_cast<float>(unitBlueprint->Intel.SonarRadius);
    return StoreRangeAtCenter(outRange, center, radius);
  }

  /**
   * Address: 0x007ED090 (FUN_007ED090, Moho::SonarExtractor::Extract)
   */
  bool SonarExtractor::Extract(
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

    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, sonarRange);
  }
} // namespace moho
