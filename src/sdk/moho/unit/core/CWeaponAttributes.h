#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  struct RUnitBlueprintWeapon;

  /**
   * Recovered `CWeaponAttributes` layout.
   *
   * Evidence:
   * - 0x006D3230 ctor initializes the full lane set.
   * - 0x006DF0C0 / 0x006DF180 serialize the pointer + float/string lanes.
   */
  struct CWeaponAttributes
  {
    RUnitBlueprintWeapon* mBlueprint; // +0x00
    float mFiringTolerance;           // +0x04
    float mRateOfFire;                // +0x08
    float mMinRadius;                 // +0x0C
    float mMaxRadius;                 // +0x10
    float mMinRadiusSq;               // +0x14
    float mMaxRadiusSq;               // +0x18
    float mMaxHeightDiff;             // +0x1C
    msvc8::string mType;              // +0x20
    float mDamageRadius;              // +0x3C
    float mDamage;                    // +0x40
    float mUnknown_0044;              // +0x44
    float mUnknown_0048;              // +0x48

    /**
     * Address: 0x006D3230 (FUN_006D3230, ??0CWeaponAttributes@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the weapon attribute lanes and derives radius squares when
     * a blueprint pointer is supplied.
     */
    explicit CWeaponAttributes(RUnitBlueprintWeapon* blueprint);

    /**
     * Address: 0x006D3340 (FUN_006D3340, Moho::CWeaponAttributes::SetType)
     *
     * What it does:
     * Replaces the stored type string with the provided value.
     */
    void SetType(msvc8::string type);
  };

  static_assert(
    offsetof(CWeaponAttributes, mBlueprint) == 0x00, "CWeaponAttributes::mBlueprint offset must be 0x00"
  );
  static_assert(
    offsetof(CWeaponAttributes, mFiringTolerance) == 0x04, "CWeaponAttributes::mFiringTolerance offset must be 0x04"
  );
  static_assert(offsetof(CWeaponAttributes, mRateOfFire) == 0x08, "CWeaponAttributes::mRateOfFire offset must be 0x08");
  static_assert(offsetof(CWeaponAttributes, mMinRadius) == 0x0C, "CWeaponAttributes::mMinRadius offset must be 0x0C");
  static_assert(offsetof(CWeaponAttributes, mMaxRadius) == 0x10, "CWeaponAttributes::mMaxRadius offset must be 0x10");
  static_assert(
    offsetof(CWeaponAttributes, mMinRadiusSq) == 0x14, "CWeaponAttributes::mMinRadiusSq offset must be 0x14"
  );
  static_assert(
    offsetof(CWeaponAttributes, mMaxRadiusSq) == 0x18, "CWeaponAttributes::mMaxRadiusSq offset must be 0x18"
  );
  static_assert(
    offsetof(CWeaponAttributes, mMaxHeightDiff) == 0x1C, "CWeaponAttributes::mMaxHeightDiff offset must be 0x1C"
  );
  static_assert(offsetof(CWeaponAttributes, mType) == 0x20, "CWeaponAttributes::mType offset must be 0x20");
  static_assert(
    offsetof(CWeaponAttributes, mDamageRadius) == 0x3C, "CWeaponAttributes::mDamageRadius offset must be 0x3C"
  );
  static_assert(offsetof(CWeaponAttributes, mDamage) == 0x40, "CWeaponAttributes::mDamage offset must be 0x40");
  static_assert(offsetof(CWeaponAttributes, mUnknown_0044) == 0x44, "CWeaponAttributes::mUnknown_0044 offset must be 0x44");
  static_assert(offsetof(CWeaponAttributes, mUnknown_0048) == 0x48, "CWeaponAttributes::mUnknown_0048 offset must be 0x48");
  static_assert(sizeof(CWeaponAttributes) == 0x4C, "CWeaponAttributes size must be 0x4C");
} // namespace moho
