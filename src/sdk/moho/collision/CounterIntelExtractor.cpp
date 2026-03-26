#include "moho/collision/CounterIntelExtractor.h"

#include <algorithm>

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/UserUnit.h"

namespace moho
{
  /**
   * Address: 0x007EDBB0 (FUN_007EDBB0)
   *
   * What it does:
   * Scalar deleting destructor body that resets base vptr to `RangeExtractor`
   * and conditionally deletes storage.
   */
  CounterIntelExtractor::~CounterIntelExtractor() = default;

  /**
   * Address: 0x007ED270 (FUN_007ED270)
   *
   * What it does:
   * Computes max active counter-intel radius from blueprint lanes
   * (`JamRadius.max`, `SpoofRadius.max`, `RadarStealthFieldRadius`,
   * `SonarStealth`, `Cloak`) then emits `{center.x, center.z, 0, radius}`.
   */
  bool CounterIntelExtractor::Range(
    SRangeExtractionPayload* const outRange, const RUnitBlueprint* const unitBlueprint, const Wm3::Vec3f& center
  ) const
  {
    const float jammerRange = static_cast<float>(unitBlueprint->Intel.JamRadius.max);
    const float spoofRange = static_cast<float>(unitBlueprint->Intel.SpoofRadius.max);
    const float radarStealthFieldRange = static_cast<float>(unitBlueprint->Intel.RadarStealthFieldRadius);
    const float sonarStealthRange = static_cast<float>(unitBlueprint->Intel.SonarStealth);
    const float cloakRange = static_cast<float>(unitBlueprint->Intel.Cloak);

    const float range = std::max(
      std::max(jammerRange, spoofRange), std::max(std::max(radarStealthFieldRange, sonarStealthRange), cloakRange)
    );
    return StoreRangeAtCenter(outRange, center, range);
  }

  /**
   * Address: 0x007ED1E0 (FUN_007ED1E0)
   *
   * What it does:
   * Queries unit maximum counter-intel radius and, when active, emits
   * `{interp.x, interp.z, 0, radius}`.
   */
  bool CounterIntelExtractor::Extract(
    SRangeExtractionPayload* const outRange, const UserEntity* const userEntity, const float interpolationAlpha
  ) const
  {
    float maxCounterIntelRange = 0.0f;
    const UserUnit* const userUnit = userEntity ? userEntity->IsUserUnit() : nullptr;
    if (!userUnit || !userUnit->GetMaxCounterIntel(&maxCounterIntelRange)) {
      return false;
    }

    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, maxCounterIntelRange);
  }
} // namespace moho
