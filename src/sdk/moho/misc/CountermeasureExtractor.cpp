#include "moho/misc/CountermeasureExtractor.h"

#include <cstdint>

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/WeaponExtractor.h"

namespace
{
  constexpr std::int32_t kCountermeasureRangeCategory = static_cast<std::int32_t>(moho::UWRC_Countermeasure);
}

namespace moho
{
  /**
   * Address: 0x007ECBD0 (FUN_007ECBD0)
   */
  CountermeasureExtractor::~CountermeasureExtractor() = default;

  /**
   * Address: 0x007EC980 (FUN_007EC980, Moho::CountermeasureExtractor::Range)
   */
  bool CountermeasureExtractor::Range(
    SRangeExtractionPayload* const outRange, const RUnitBlueprint* const unitBlueprint, const Wm3::Vec3f& center
  ) const
  {
    if (!outRange || !unitBlueprint) {
      return false;
    }

    const float shieldRadius = static_cast<float>(unitBlueprint->Defense.Shield.ShieldSize) * 0.5f;
    if (shieldRadius > 0.0f) {
      return StoreRangeAtCenter(outRange, center, shieldRadius);
    }

    float innerRadius = 0.0f;
    float outerRadius = 0.0f;
    if (!WeaponExtractor::ResolveWeaponCategoryRange(
          &innerRadius, &outerRadius, *unitBlueprint, kCountermeasureRangeCategory
        )) {
      return false;
    }

    return StoreRangeAtCenter(outRange, center, outerRadius, innerRadius);
  }

  /**
   * Address: 0x007EC880 (FUN_007EC880, Moho::CountermeasureExtractor::Extract)
   */
  bool CountermeasureExtractor::Extract(
    SRangeExtractionPayload* const outRange, const UserEntity* const userEntity, const float interpolationAlpha
  ) const
  {
    if (!outRange || !userEntity) {
      return false;
    }

    const UserUnit* const userUnit = userEntity->IsUserUnit();
    if (userUnit) {
      float factoryOverlayRadius = 0.0f;
      if (TryGetFactoryOverlayRadius(userUnit, &factoryOverlayRadius)) {
        return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, factoryOverlayRadius);
      }
    }

    float innerRadius = 0.0f;
    float outerRadius = 0.0f;
    if (!TryGetWeaponRangeByCategory(userEntity, kCountermeasureRangeCategory, &innerRadius, &outerRadius)) {
      return false;
    }

    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, outerRadius, innerRadius);
  }
} // namespace moho
