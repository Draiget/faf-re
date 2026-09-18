#include "moho/misc/CountermeasureExtractor.h"

#include <cstdint>

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/unit/core/WeaponExtractor.h"

namespace
{
  constexpr std::int32_t kCountermeasureRangeCategory = static_cast<std::int32_t>(moho::UWRC_Countermeasure);

  /// 0x00E4F724, the multiplier applied to `Defense.Shield.ShieldSize`.
  constexpr float kShieldDiameterToRadius = 0.5f;
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

    // The countermeasure overlay's first ring is the shield bubble, not an
    // assist radius: 0x007EC89F reads `[blueprint+0x458]` - `Defense.Shield`
    // (+0x38 inside Defense at +0x420) `.ShieldSize` - and halves it with the
    // 0.5f at 0x00E4F724, a diameter turned into a radius. Only a
    // non-positive result falls through to the weapon ranges (0x007EC8BC).
    // An earlier pass had this branch reading a factory command queue through
    // a layout stand-in instead.
    if (const UserUnit* const userUnit = userEntity->IsUserUnit(); userUnit != nullptr) {
      if (const RUnitBlueprint* const unitBlueprint = static_cast<const IUnit*>(userUnit)->GetBlueprint();
          unitBlueprint != nullptr) {
        const float shieldRadius = unitBlueprint->Defense.Shield.ShieldSize * kShieldDiameterToRadius;
        if (shieldRadius > 0.0f) {
          return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, shieldRadius);
        }
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
