#include "moho/misc/CombinedMilitaryExtractor.h"
#include "moho/entity/UserEntity.h"
#include <cstdint>

namespace
{
  constexpr std::int32_t kWeaponRangeCategoryAll = 6;
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
    SRangeExtractionPayload* const outRange,
    const UserEntity* const userEntity,
    const float interpolationAlpha
  ) const
  {
    if (!outRange || !userEntity) {
      return false;
    }

    // An `OVERLAYMISC` unit reports its assist radius and nothing else; only
    // when it has none does the binary fall through to the weapon ranges
    // (0x007EC44C / 0x007EC46F both jump to the weapon path at 0x007EC4A3).
    float assistRadius = 0.0f;
    if (TryGetAssistOverlayRadius(userEntity, &assistRadius)) {
      return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, assistRadius);
    }

    float innerRadius = 0.0f;
    float outerRadius = 0.0f;
    if (!TryGetWeaponRangeByCategory(userEntity, kWeaponRangeCategoryAll, &innerRadius, &outerRadius)) {
      return false;
    }

    return StoreRangeAtEntity(outRange, *userEntity, interpolationAlpha, outerRadius, innerRadius);
  }
} // namespace moho
