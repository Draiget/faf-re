#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/CAiTarget.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptEvent.h"
#include "moho/serialization/SBlackListInfo.h"
#include "moho/unit/core/CWeaponAttributes.h"
#include "wm3/Vector3.h"

namespace moho
{
  class CFireWeaponTask;
  class IAiAttacker;
  struct RProjectileBlueprint;
  struct RUnitBlueprintWeapon;
  class Sim;
  class Unit;
  class UnitWeapon;

#ifndef MOHO_WEAKPTR_OWNER_LINK_OFFSET_UNITWEAPON_DEFINED
#define MOHO_WEAKPTR_OWNER_LINK_OFFSET_UNITWEAPON_DEFINED
  template <>
  struct WeakPtrOwnerLinkOffset<UnitWeapon>
  {
    static constexpr std::uintptr_t value = 0x14;
  };
#endif

  class UnitWeapon : public CScriptEvent
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x006D4100 (FUN_006D4100, sub_6D4100)
     *
     * What it does:
     * Initializes UnitWeapon runtime lanes, category filters, and default target
     * state for weapon task dispatch.
     */
    UnitWeapon();

    /**
     * Address family: 0x006DB9E0 / 0x006DB960 callsites
     *
     * What it does:
     * Lazily resolves and caches reflected RTTI for `UnitWeapon`.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x006DF3A0 (FUN_006DF3A0, Moho::UnitWeapon::MemberDeserialize)
     *
     * What it does:
     * Loads the serialized `UnitWeapon` payload from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive& archive);

    /**
     * Address: 0x006DF6E0 (FUN_006DF6E0, Moho::UnitWeapon::MemberSerialize)
     *
     * What it does:
     * Saves the serialized `UnitWeapon` payload into archive storage.
     */
    void MemberSerialize(gpg::WriteArchive& archive) const;

  public:
    Sim* mSim;                                  // +0x44
    RUnitBlueprintWeapon* mWeaponBlueprint;     // +0x48
    RProjectileBlueprint* mProjectileBlueprint; // +0x4C
    IAiAttacker* mAttacker;                     // +0x50
    CWeaponAttributes mAttributes;              // +0x54
    Unit* mUnit;                                // +0xA0
    std::int32_t mWeaponIndex;                  // +0xA4
    std::int32_t mBone;                         // +0xA8
    std::uint8_t mEnabled;                      // +0xAC
    std::uint8_t mPadAD[3];                     // +0xAD
    msvc8::string mLabel;                       // +0xB0
    CAiTarget mTarget;                          // +0xCC
    CFireWeaponTask* mFireWeaponTask;           // +0xEC
    std::uint8_t mCanFire;                      // +0xF0
    std::uint8_t mPadF1ToF7[7];                 // +0xF1
    EntityCategorySet mCat1;                    // +0xF8
    EntityCategorySet mCat2;                    // +0x120
    ELayer mFireTargetLayerCaps;                // +0x148
    float mFiringRandomness;                    // +0x14C
    msvc8::vector<EntityCategorySet> mTargetPriorities; // +0x150
    msvc8::vector<SBlackListInfo> mBlacklist;           // +0x160
    std::int32_t mUnknown170;                   // +0x170
    std::uint8_t mUnknown174;                   // +0x174
    std::uint8_t mPad175To177[3];               // +0x175
    Wm3::Vector3f mAimingAt;                    // +0x178
    std::int32_t mShotsAtTarget;                // +0x184
  };

  static_assert(offsetof(UnitWeapon, mWeaponBlueprint) == 0x48, "UnitWeapon::mWeaponBlueprint offset must be 0x48");
  static_assert(
    offsetof(UnitWeapon, mProjectileBlueprint) == 0x4C, "UnitWeapon::mProjectileBlueprint offset must be 0x4C"
  );
  static_assert(offsetof(UnitWeapon, mAttributes) == 0x54, "UnitWeapon::mAttributes offset must be 0x54");
  static_assert(offsetof(UnitWeapon, mEnabled) == 0xAC, "UnitWeapon::mEnabled offset must be 0xAC");
  static_assert(offsetof(UnitWeapon, mCat1) == 0xF8, "UnitWeapon::mCat1 offset must be 0xF8");
  static_assert(offsetof(UnitWeapon, mCat2) == 0x120, "UnitWeapon::mCat2 offset must be 0x120");
  static_assert(
    offsetof(UnitWeapon, mFireTargetLayerCaps) == 0x148,
    "UnitWeapon::mFireTargetLayerCaps offset must be 0x148"
  );
  static_assert(
    offsetof(UnitWeapon, mFiringRandomness) == 0x14C, "UnitWeapon::mFiringRandomness offset must be 0x14C"
  );
  static_assert(
    offsetof(UnitWeapon, mTargetPriorities) == 0x150, "UnitWeapon::mTargetPriorities offset must be 0x150"
  );
  static_assert(offsetof(UnitWeapon, mBlacklist) == 0x160, "UnitWeapon::mBlacklist offset must be 0x160");
  static_assert(offsetof(UnitWeapon, mAimingAt) == 0x178, "UnitWeapon::mAimingAt offset must be 0x178");
  static_assert(offsetof(UnitWeapon, mShotsAtTarget) == 0x184, "UnitWeapon::mShotsAtTarget offset must be 0x184");
  static_assert(sizeof(UnitWeapon) == 0x188, "UnitWeapon size must be 0x188");
  static_assert(WeakPtr<UnitWeapon>::kOwnerLinkOffset == 0x14, "UnitWeapon weak-owner slot offset must be 0x14");
} // namespace moho
