#include "moho/ai/AirPlatformExtractor.h"

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace moho
{
  /**
   * Address: 0x103B6340 (FUN_103B6340, Moho::AirPlatformExtractor::Extract)
   *
   * What it does:
   * Reads one user-entity interpolated transform and emits `{x, y, z, range}`
   * where range is the unit blueprint's staging-platform scan radius.
   */
  bool AirPlatformExtractor::Extract(float* const outPosRange, void* const userEntity, const float alpha)
  {
    if (outPosRange == nullptr || userEntity == nullptr) {
      return false;
    }

    const auto* const entity = static_cast<const UserEntity*>(userEntity);
    const REntityBlueprint* const entityBlueprint = entity->mParams.mBlueprint;
    const RUnitBlueprint* const unitBlueprint = entityBlueprint ? entityBlueprint->IsUnitBlueprint() : nullptr;
    if (unitBlueprint == nullptr) {
      return false;
    }

    const float range = unitBlueprint->AI.StagingPlatformScanRadius;
    if (range <= 0.0f) {
      return false;
    }

    const VTransform transform = entity->GetInterpolatedTransform(alpha);
    outPosRange[0] = transform.pos_.x;
    outPosRange[1] = transform.pos_.y;
    outPosRange[2] = transform.pos_.z;
    outPosRange[3] = range;
    return true;
  }
} // namespace moho
