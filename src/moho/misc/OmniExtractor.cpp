#include "moho/misc/OmniExtractor.h"

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace moho
{
  /**
   * Address: 0x007EDB90 (FUN_007EDB90)
   */
  OmniExtractor::~OmniExtractor() = default;

  /**
   * Address: 0x007ECEB0 (FUN_007ECEB0, Moho::OmniExtractor::Range)
   */
  bool OmniExtractor::Range(
    SRangeExtractionPayload* const outRange, const RUnitBlueprint* const unitBlueprint, const Wm3::Vec3f& center
  ) const
  {
    if (!outRange || !unitBlueprint) {
      return false;
    }

    const float radius = static_cast<float>(unitBlueprint->Intel.OmniRadius);
    return StoreRangeAtCenter(outRange, center, radius);
  }

  /**
   * Address: 0x007ECDF0 (FUN_007ECDF0, Moho::OmniExtractor::Extract)
   */
  bool OmniExtractor::Extract(
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

    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, omniRange);
  }
} // namespace moho
