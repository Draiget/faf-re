#include "moho/misc/CombinedMilitaryExtractor.h"

#include <cstdint>

#include "moho/entity/UserEntity.h"

namespace
{
  constexpr std::int32_t kWeaponRangeCategoryAll = 6;
  constexpr char kOverlayMiscCategory[] = "OVERLAYMISC";
}

namespace moho
{
  /**
   * Address: 0x007EC560 (FUN_007EC560)
   */
  CombinedMilitaryExtractor::~CombinedMilitaryExtractor() = default;

  /**
   * Address: 0x007EC550 (FUN_007EC550, Moho::CombinedMilitaryExtractor::Range)
   */
  bool CombinedMilitaryExtractor::Range(
    SRangeExtractionPayload* const /*outRange*/,
    const RUnitBlueprint* const /*unitBlueprint*/,
    const Wm3::Vec3f& /*center*/
  ) const
  {
    return false;
  }

  /**
   * Address: 0x007EC3A0 (FUN_007EC3A0, Moho::CombinedMilitaryExtractor::Extract)
   */
  bool CombinedMilitaryExtractor::Extract(
    SRangeExtractionPayload* const outRange, const UserEntity* const userEntity, const float interpolationAlpha
  ) const
  {
    if (!outRange || !userEntity) {
      return false;
    }

    const UserUnit* const userUnit = userEntity->IsUserUnit();
    if (userUnit) {
      const msvc8::string overlayMiscCategory(kOverlayMiscCategory, sizeof(kOverlayMiscCategory) - 1u);
      if (userEntity->IsInCategory(overlayMiscCategory)) {
        float factoryOverlayRadius = 0.0f;
        if (TryGetFactoryOverlayRadius(userUnit, &factoryOverlayRadius)) {
          return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, factoryOverlayRadius);
        }
      }
    }

    float innerRadius = 0.0f;
    float outerRadius = 0.0f;
    if (!TryGetWeaponRangeByCategory(userEntity, kWeaponRangeCategoryAll, &innerRadius, &outerRadius)) {
      return false;
    }

    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, outerRadius, innerRadius);
  }
} // namespace moho
