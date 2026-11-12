#include "moho/unit/core/CWeaponAttributes.h"

#include <limits>

#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace moho
{
  /**
   * Address: 0x006D3230 (FUN_006D3230, ??0CWeaponAttributes@Moho@@QAE@@Z)
   */
  CWeaponAttributes::CWeaponAttributes(
    RUnitBlueprintWeapon* const blueprint
  )
    : mBlueprint(blueprint)
    , mFiringTolerance(-1.0f)
    , mRateOfFire(-1.0f)
    , mMinRadius(-1.0f)
    , mMaxRadius(-1.0f)
    , mMinRadiusSq(-1.0f)
    , mMaxRadiusSq(-1.0f)
    , mMaxHeightDiff(gpg::pInf)
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
   * Address: 0x006D3340 (FUN_006D3340, Moho::CWeaponAttributes::SetType)
   */
  void CWeaponAttributes::SetType(
    fa::string type
  )
  {
    mType.assign(type, 0u, fa::string::npos);
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
  fa::string CWeaponAttributes::GetName() const
  {
    const fa::string* sourceName = &mType;
    if (mType.empty()) {
      sourceName = &mBlueprint->DamageType;
    }

    fa::string result;
    result.assign(*sourceName, 0u, fa::string::npos);
    return result;
  }
} // namespace moho
