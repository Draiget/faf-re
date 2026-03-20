#include "moho/collision/IntelExtractor.h"

#include <algorithm>

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/UserUnit.h"

namespace
{
  [[nodiscard]] bool StoreRangeAtCenter(
    moho::SRangeExtractionPayload* const outRange, const Wm3::Vec3f& center, const float radius
  ) noexcept
  {
    if (radius <= 0.0f) {
      return false;
    }

    outRange->centerX = center.x;
    outRange->centerZ = center.z;
    outRange->centerY = 0.0f;
    outRange->radius = radius;
    return true;
  }

  [[nodiscard]] bool StoreRangeAtEntity(
    moho::SRangeExtractionPayload* const outRange,
    const moho::UserEntity& userEntity,
    const float interpolationAlpha,
    const float radius
  )
  {
    if (radius <= 0.0f) {
      return false;
    }

    const moho::VTransform transform = userEntity.GetInterpolatedTransform(interpolationAlpha);
    outRange->centerX = transform.pos_.x;
    outRange->centerZ = transform.pos_.z;
    outRange->centerY = 0.0f;
    outRange->radius = radius;
    return true;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007EDB30 (FUN_007EDB30)
   *
   * What it does:
   * Scalar deleting destructor body that resets base vptr to `RangeExtractor`
   * and conditionally deletes storage.
   */
  IntelExtractor::~IntelExtractor() = default;

  /**
   * Address: 0x007ECCE0 (FUN_007ECCE0)
   *
   * What it does:
   * Computes max active intel radius from blueprint lanes
   * (`RadarRadius`, `SonarRadius`, `OmniRadius`, `RadarStealthFieldRadius`)
   * then emits `{center.x, center.z, 0, radius}`.
   */
  bool IntelExtractor::Range(
    SRangeExtractionPayload* const outRange, const RUnitBlueprint* const unitBlueprint, const Wm3::Vec3f& center
  ) const
  {
    const float radarRange = static_cast<float>(unitBlueprint->Intel.RadarRadius);
    const float sonarRange = static_cast<float>(unitBlueprint->Intel.SonarRadius);
    const float omniRange = static_cast<float>(unitBlueprint->Intel.OmniRadius);
    const float radarStealthFieldRange = static_cast<float>(unitBlueprint->Intel.RadarStealthFieldRadius);

    const float range = std::max(std::max(radarRange, sonarRange), std::max(omniRange, radarStealthFieldRange));
    return StoreRangeAtCenter(outRange, center, range);
  }

  /**
   * Address: 0x007ECC00 (FUN_007ECC00)
   *
   * What it does:
   * Reads intel tuple from user-unit (`omni`, `radar`, `sonar`),
   * selects max active range, then emits `{interp.x, interp.z, 0, range}`.
   */
  bool IntelExtractor::Extract(
    SRangeExtractionPayload* const outRange, const UserEntity* const userEntity, const float interpolationAlpha
  ) const
  {
    const UserUnit* const userUnit = userEntity->IsUserUnit();
    if (!userUnit) {
      return false;
    }

    float omniRange = 0.0f;
    float radarRange = 0.0f;
    float sonarRange = 0.0f;
    userUnit->GetIntelRanges(&omniRange, &radarRange, &sonarRange);

    const float range = std::max(std::max(omniRange, radarRange), sonarRange);
    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, range);
  }
} // namespace moho
