#include "moho/unit/core/CWeaponAttributes.h"

#include <limits>

#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace moho
{
  /**
   * Address: 0x006D3230 (FUN_006D3230, ??0CWeaponAttributes@Moho@@QAE@@Z)
   */
  CWeaponAttributes::CWeaponAttributes(RUnitBlueprintWeapon* const blueprint)
    : mBlueprint(blueprint)
    , mFiringTolerance(-1.0f)
    , mRateOfFire(-1.0f)
    , mMinRadius(-1.0f)
    , mMaxRadius(-1.0f)
    , mMinRadiusSq(-1.0f)
    , mMaxRadiusSq(-1.0f)
    , mMaxHeightDiff(std::numeric_limits<float>::infinity())
    , mType()
    , mDamageRadius(-1.0f)
    , mDamage(-1.0f)
    , mUnknown_0044(-1.0f)
    , mUnknown_0048(-1.0f)
  {
    if (mBlueprint) {
      mMinRadiusSq = mBlueprint->MinRadius * mBlueprint->MinRadius;
      mMaxRadiusSq = mBlueprint->MaxRadius * mBlueprint->MaxRadius;
    }
  }

  /**
   * Address: 0x006D32D0 (FUN_006D32D0)
   *
   * What it does:
   * Stores one firing-tolerance float lane.
   */
  void CWeaponAttributes::SetFiringTolerance(const float firingTolerance)
  {
    mFiringTolerance = firingTolerance;
  }

  /**
   * Address: 0x006D3340 (FUN_006D3340, Moho::CWeaponAttributes::SetType)
   */
  void CWeaponAttributes::SetType(msvc8::string type)
  {
    mType.assign(type, 0u, msvc8::string::npos);
  }

  /**
   * Address: 0x006D32E0 (FUN_006D32E0)
   */
  CWeaponAttributes* CWeaponAttributes::SetRateOfFire(const float value)
  {
    mRateOfFire = value;
    return this;
  }

  /**
   * Address: 0x006D32F0 (FUN_006D32F0)
   */
  CWeaponAttributes* CWeaponAttributes::SetMinRadius(const float value)
  {
    mMinRadius = value;
    mMinRadiusSq = value * value;
    return this;
  }

  /**
   * Address: 0x006D3310 (FUN_006D3310)
   */
  CWeaponAttributes* CWeaponAttributes::SetMaxRadius(const float value)
  {
    mMaxRadius = value;
    mMaxRadiusSq = value * value;
    return this;
  }

  /**
   * Address: 0x006D3330 (FUN_006D3330)
   */
  CWeaponAttributes* CWeaponAttributes::SetMaxHeightDiff(const float value)
  {
    mMaxHeightDiff = value;
    return this;
  }

  /**
   * Address: 0x006D33A0 (FUN_006D33A0)
   */
  CWeaponAttributes* CWeaponAttributes::SetDamageRadius(const float value)
  {
    mDamageRadius = value;
    return this;
  }

  /**
   * Address: 0x006D33B0 (FUN_006D33B0)
   */
  CWeaponAttributes* CWeaponAttributes::SetDamage(const float value)
  {
    mDamage = value;
    return this;
  }

  /**
   * Address: 0x006D33C0 (FUN_006D33C0)
   */
  float CWeaponAttributes::GetRateOfFire() const
  {
    if (mRateOfFire < 0.0f && mBlueprint != nullptr) {
      return mBlueprint->RateOfFire;
    }
    return mRateOfFire;
  }

  /**
   * Address: 0x006D33E0 (FUN_006D33E0)
   */
  float CWeaponAttributes::GetMinRadiusSq()
  {
    if (mBlueprint != nullptr && mMinRadiusSq < 0.0f) {
      const float minRadius = mBlueprint->MinRadius;
      mMinRadiusSq = minRadius * minRadius;
    }
    return mMinRadiusSq;
  }

  /**
   * Address: 0x006D3410 (FUN_006D3410)
   */
  float CWeaponAttributes::GetMaxHeightDiff() const
  {
    if (mMaxHeightDiff < 0.0f && mBlueprint != nullptr) {
      return mBlueprint->MaxHeightDiff;
    }
    return mMaxHeightDiff;
  }

  /**
   * Address: 0x006D3470 (FUN_006D3470)
   */
  float CWeaponAttributes::GetDamageRadius() const
  {
    if (mDamageRadius < 0.0f && mBlueprint != nullptr) {
      return mBlueprint->DamageRadius;
    }
    return mDamageRadius;
  }

  /**
   * Address: 0x006D3490 (FUN_006D3490)
   */
  float CWeaponAttributes::GetDamage() const
  {
    if (mDamage < 0.0f && mBlueprint != nullptr) {
      return mBlueprint->Damage;
    }
    return mDamage;
  }

  /**
   * Address: 0x006D3430 (FUN_006D3430, Moho::CWeaponAttributes::GetName)
   *
   * What it does:
   * Returns `mType` when non-empty; otherwise returns `mBlueprint->mDamageType`.
   */
  msvc8::string CWeaponAttributes::GetName() const
  {
    const msvc8::string* sourceName = &mType;
    if (mType.empty()) {
      sourceName = &mBlueprint->DamageType;
    }

    msvc8::string result;
    result.assign(*sourceName, 0u, msvc8::string::npos);
    return result;
  }
} // namespace moho
