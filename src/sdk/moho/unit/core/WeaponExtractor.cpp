#include "moho/unit/core/WeaponExtractor.h"

#include <cstdint>
#include <limits>

#include "moho/entity/UserEntity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace
{
  constexpr std::int32_t kRangeCategoryAll = 6;
}

namespace moho
{
  /**
   * Address: 0x007EC840 (FUN_007EC840)
   */
  WeaponExtractor::~WeaponExtractor() = default;

  bool WeaponExtractor::ResolveWeaponCategoryRange(
    float* const outInnerRadius,
    float* const outOuterRadius,
    const RUnitBlueprint& unitBlueprint,
    const std::int32_t rangeCategoryFilter
  ) noexcept
  {
    if (!outInnerRadius || !outOuterRadius) {
      return false;
    }

    constexpr float kInitialInnerRadius = std::numeric_limits<float>::max();

    float innerRadius = kInitialInnerRadius;
    float outerRadius = 0.0f;
    const auto& weaponBlueprints = unitBlueprint.Weapons.WeaponBlueprints;
    for (const auto& weaponBlueprint : weaponBlueprints) {
      const std::int32_t weaponCategory = static_cast<std::int32_t>(weaponBlueprint.RangeCategory);
      if (rangeCategoryFilter != kRangeCategoryAll && rangeCategoryFilter != weaponCategory) {
        continue;
      }

      const float resolvedOuterRadius = ResolvePositiveRadius(weaponBlueprint.EffectiveRadius, weaponBlueprint.MaxRadius);
      if (resolvedOuterRadius > outerRadius) {
        outerRadius = resolvedOuterRadius;
      }

      if (weaponBlueprint.MinRadius <= innerRadius) {
        innerRadius = weaponBlueprint.MinRadius;
      }
    }

    if (outerRadius <= 0.0f) {
      return false;
    }

    if (innerRadius >= kInitialInnerRadius) {
      innerRadius = 0.0f;
    }

    *outInnerRadius = innerRadius;
    *outOuterRadius = outerRadius;
    return true;
  }

  /**
   * Address: 0x007EC650 (FUN_007EC650, Moho::WeaponExtractor::Range)
   */
  bool WeaponExtractor::Range(
    SRangeExtractionPayload* const outRange, const RUnitBlueprint* const unitBlueprint, const Wm3::Vec3f& center
  ) const
  {
    if (!outRange || !unitBlueprint) {
      return false;
    }

    float innerRadius = 0.0f;
    float outerRadius = 0.0f;
    if (!ResolveWeaponCategoryRange(&innerRadius, &outerRadius, *unitBlueprint, mRangeCategory)) {
      return false;
    }

    return StoreRangeAtCenter(outRange, center, outerRadius, innerRadius);
  }

  /**
   * Address: 0x007EC5B0 (FUN_007EC5B0, Moho::WeaponExtractor::Extract)
   */
  bool WeaponExtractor::Extract(
    SRangeExtractionPayload* const outRange, const UserEntity* const userEntity, const float interpolationAlpha
  ) const
  {
    if (!outRange || !userEntity) {
      return false;
    }

    float innerRadius = 0.0f;
    float outerRadius = 0.0f;
    if (!TryGetWeaponRangeByCategory(userEntity, mRangeCategory, &innerRadius, &outerRadius)) {
      return false;
    }

    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, outerRadius, innerRadius);
  }
} // namespace moho
