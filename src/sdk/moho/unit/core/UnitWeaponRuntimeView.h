#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace moho
{
  class RProjectileBlueprint;
  class UnitWeapon;

  /**
   * Runtime view over `UnitWeapon` storage used by attacker/silo/debug overlays.
   *
   * Evidence:
   * - `CAiSiloBuildImpl::SiloUpdateProjectileBlueprint` (0x005CEE40)
   * - `RDebugWeapons::OnTick` (0x00652E00)
   */
  struct UnitWeaponRuntimeView
  {
    std::uint8_t pad_000[0x48];
    RUnitBlueprintWeapon* mWeaponInfo;            // +0x48
    RProjectileBlueprint* mProjectileBlueprint;   // +0x4C
    std::uint8_t pad_050[0x04];
    RUnitBlueprintWeapon* mRangeFallbackInfo;     // +0x54
    std::uint8_t pad_058[0x0C];
    float mCurrentMaxRadius;                      // +0x64
    std::uint8_t pad_068[0x44];
    std::uint8_t mEnabled;                        // +0xAC
  };

  static_assert(
    offsetof(UnitWeaponRuntimeView, mWeaponInfo) == 0x48, "UnitWeaponRuntimeView::mWeaponInfo offset must be 0x48"
  );
  static_assert(
    offsetof(UnitWeaponRuntimeView, mProjectileBlueprint) == 0x4C,
    "UnitWeaponRuntimeView::mProjectileBlueprint offset must be 0x4C"
  );
  static_assert(
    offsetof(UnitWeaponRuntimeView, mRangeFallbackInfo) == 0x54,
    "UnitWeaponRuntimeView::mRangeFallbackInfo offset must be 0x54"
  );
  static_assert(
    offsetof(UnitWeaponRuntimeView, mCurrentMaxRadius) == 0x64,
    "UnitWeaponRuntimeView::mCurrentMaxRadius offset must be 0x64"
  );
  static_assert(offsetof(UnitWeaponRuntimeView, mEnabled) == 0xAC, "UnitWeaponRuntimeView::mEnabled offset must be 0xAC");

  [[nodiscard]] inline UnitWeaponRuntimeView* AsUnitWeaponRuntimeView(UnitWeapon* const weapon) noexcept
  {
    return reinterpret_cast<UnitWeaponRuntimeView*>(weapon);
  }

  [[nodiscard]] inline const UnitWeaponRuntimeView* AsUnitWeaponRuntimeView(const UnitWeapon* const weapon) noexcept
  {
    return reinterpret_cast<const UnitWeaponRuntimeView*>(weapon);
  }

  [[nodiscard]] inline bool WeaponSupportsSiloBuild(const UnitWeaponRuntimeView* const weapon) noexcept
  {
    return weapon != nullptr && weapon->mWeaponInfo != nullptr && weapon->mWeaponInfo->CountedProjectile != 0u;
  }

  [[nodiscard]] inline bool WeaponIsNukeClass(const UnitWeaponRuntimeView* const weapon) noexcept
  {
    return weapon != nullptr && weapon->mWeaponInfo != nullptr && weapon->mWeaponInfo->NukeWeapon != 0u;
  }

  [[nodiscard]] inline std::int32_t WeaponSiloMaxStorageCount(const UnitWeaponRuntimeView* const weapon) noexcept
  {
    return (weapon != nullptr && weapon->mWeaponInfo != nullptr) ? weapon->mWeaponInfo->MaxProjectileStorage : 0;
  }

  [[nodiscard]] inline float ResolveDebugWeaponRadius(const UnitWeaponRuntimeView* const weapon) noexcept
  {
    constexpr float kDefaultWeaponRadius = 1.0f;

    if (weapon == nullptr) {
      return kDefaultWeaponRadius;
    }

    float radius = weapon->mCurrentMaxRadius;
    if (radius < 0.0f && weapon->mRangeFallbackInfo != nullptr) {
      radius = weapon->mRangeFallbackInfo->MaxRadius;
    }
    return radius;
  }
} // namespace moho
