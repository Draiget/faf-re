#include "moho/misc/MiscellaneousExtractor.h"

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace moho
{
  /**
   * Address: 0x007EDB10 (FUN_007EDB10)
   */
  MiscellaneousExtractor::~MiscellaneousExtractor() = default;

  /**
   * Address: 0x007ED430 (FUN_007ED430, Moho::MiscellaneousExtractor::Range)
   */
  bool MiscellaneousExtractor::Range(
    SRangeExtractionPayload* const outRange, const RUnitBlueprint* const unitBlueprint, const Wm3::Vec3f& center
  ) const
  {
    if (!outRange || !unitBlueprint) {
      return false;
    }

    const float radius = ResolvePositiveRadius(
      unitBlueprint->AI.StagingPlatformScanRadius, unitBlueprint->AI.GuardScanRadius
    );
    return StoreRangeAtCenter(outRange, center, radius);
  }

  /**
   * Address: 0x007ED370 (FUN_007ED370, Moho::MiscellaneousExtractor::Extract)
   */
  bool MiscellaneousExtractor::Extract(
    SRangeExtractionPayload* const outRange, const UserEntity* const userEntity, const float interpolationAlpha
  ) const
  {
    if (!outRange || !userEntity) {
      return false;
    }

    const UserUnit* const userUnit = userEntity->IsUserUnit();
    float radius = 0.0f;
    if (!TryGetFactoryOverlayRadius(userUnit, &radius)) {
      return false;
    }

    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, radius);
  }
} // namespace moho
