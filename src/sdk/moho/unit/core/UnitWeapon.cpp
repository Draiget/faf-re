#include "moho/unit/core/UnitWeapon.h"

#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/entity/EntityCategorySetVectorReflection.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/serialization/SBlackListInfoVectorReflection.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CFireWeaponTask.h"

namespace
{
  template <class T>
  [[nodiscard]] gpg::RType* CachedRType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(T));
    }

    return cached;
  }

  template <class T>
  [[nodiscard]] T* ReadTrackedPointer(gpg::ReadArchive& archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(&archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    const gpg::RRef source{tracked.object, tracked.type};
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRType<T>());
    if (upcast.mObj) {
      return static_cast<T*>(upcast.mObj);
    }

    const char* const expectedTypeName = CachedRType<T>() ? CachedRType<T>()->GetName() : "null";
    const char* const actualTypeName = source.GetTypeName();
    const msvc8::string errorMessage = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedTypeName ? expectedTypeName : "null",
      actualTypeName ? actualTypeName : "null"
    );
    throw gpg::SerializationError(errorMessage.c_str());
  }

  template <class T>
  [[nodiscard]] gpg::RRef MakeTrackedRef(T* object)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedRType<T>();
    if (!object) {
      return out;
    }

    gpg::RType* runtimeType = out.mType;
    try {
      runtimeType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      runtimeType = out.mType;
    }

    if (!runtimeType || !out.mType) {
      out.mObj = object;
      out.mType = runtimeType ? runtimeType : out.mType;
      return out;
    }

    std::int32_t baseOffset = 0;
    const bool derived = runtimeType->IsDerivedFrom(out.mType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = runtimeType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = runtimeType;
    return out;
  }

  template <class T>
  void WriteTrackedPointer(
    gpg::WriteArchive& archive,
    T* pointer,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef pointerRef = MakeTrackedRef(pointer);
    gpg::WriteRawPointer(&archive, pointerRef, state, ownerRef);
  }

  [[nodiscard]] const Wm3::Vector3f& GetRecoveredInvalidAimingVector() noexcept
  {
    static bool initialized = false;
    static Wm3::Vector3f invalid{};
    if (!initialized) {
      const float qnan = std::numeric_limits<float>::quiet_NaN();
      invalid = Wm3::Vector3f{qnan, qnan, qnan};
      initialized = true;
    }

    return invalid;
  }
} // namespace

namespace moho
{
  gpg::RType* UnitWeapon::sType = nullptr;

  /**
   * Address: 0x006D4100 (FUN_006D4100, sub_6D4100)
   */
  UnitWeapon::UnitWeapon()
    : CScriptEvent()
    , mSim(nullptr)
    , mWeaponBlueprint(nullptr)
    , mProjectileBlueprint(nullptr)
    , mAttacker(nullptr)
    , mAttributes(nullptr)
    , mUnit(nullptr)
    , mWeaponIndex(0)
    , mBone(-1)
    , mEnabled(0u)
    , mPadAD{0u, 0u, 0u}
    , mLabel()
    , mTarget()
    , mFireWeaponTask(nullptr)
    , mCanFire(0u)
    , mPadF1ToF7{0u, 0u, 0u, 0u, 0u, 0u, 0u}
    , mCat1{}
    , mCat2{}
    , mFireTargetLayerCaps(LAYER_None)
    , mFiringRandomness(0.0f)
    , mTargetPriorities()
    , mBlacklist()
    , mUnknown170(0)
    , mUnknown174(1u)
    , mPad175To177{0u, 0u, 0u}
    , mAimingAt(GetRecoveredInvalidAimingVector())
    , mShotsAtTarget(0)
  {
    mTarget.targetType = EAiTargetType::AITARGET_None;
    mTarget.targetEntity.ownerLinkSlot = nullptr;
    mTarget.targetEntity.nextInOwner = nullptr;
    mTarget.targetPoint = -1;
    mTarget.targetIsMobile = false;

    // Default member initialization already seeds both sets.
  }

  gpg::RType* UnitWeapon::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(UnitWeapon));
    }

    return sType;
  }

  /**
   * Address: 0x006DF3A0 (FUN_006DF3A0, Moho::UnitWeapon::MemberDeserialize)
   */
  void UnitWeapon::MemberDeserialize(gpg::ReadArchive& archive)
  {
    const gpg::RRef ownerRef{};

    archive.Read(CScriptEvent::StaticGetClass(), this, ownerRef);
    mSim = ReadTrackedPointer<Sim>(archive, ownerRef);
    mWeaponBlueprint = ReadTrackedPointer<RUnitBlueprintWeapon>(archive, ownerRef);
    mProjectileBlueprint = ReadTrackedPointer<RProjectileBlueprint>(archive, ownerRef);
    mAttacker = ReadTrackedPointer<IAiAttacker>(archive, ownerRef);
    archive.Read(CachedRType<CWeaponAttributes>(), &mAttributes, ownerRef);
    mUnit = ReadTrackedPointer<Unit>(archive, ownerRef);
    archive.ReadInt(&mWeaponIndex);
    archive.ReadInt(&mBone);

    bool enabled = (mEnabled != 0u);
    archive.ReadBool(&enabled);
    mEnabled = enabled ? 1u : 0u;

    archive.ReadString(&mLabel);
    archive.Read(CachedRType<CAiTarget>(), &mTarget, ownerRef);

    CFireWeaponTask* const oldTask = mFireWeaponTask;
    mFireWeaponTask = ReadTrackedPointer<CFireWeaponTask>(archive, ownerRef);
    if (oldTask) {
      delete oldTask;
    }

    bool canFire = (mCanFire != 0u);
    archive.ReadBool(&canFire);
    mCanFire = canFire ? 1u : 0u;

    archive.Read(CachedRType<EntityCategorySet>(), &mCat1, ownerRef);
    archive.Read(CachedRType<EntityCategorySet>(), &mCat2, ownerRef);
    archive.Read(CachedRType<ELayer>(), &mFireTargetLayerCaps, ownerRef);
    archive.ReadFloat(&mFiringRandomness);
    archive.Read(CachedRType<msvc8::vector<EntityCategorySet>>(), &mTargetPriorities, ownerRef);
    archive.Read(CachedRType<msvc8::vector<SBlackListInfo>>(), &mBlacklist, ownerRef);
    archive.ReadInt(&mUnknown170);

    bool unknown174 = (mUnknown174 != 0u);
    archive.ReadBool(&unknown174);
    mUnknown174 = unknown174 ? 1u : 0u;

    archive.Read(CachedRType<Wm3::Vector3f>(), &mAimingAt, ownerRef);
    archive.ReadInt(&mShotsAtTarget);
  }

  /**
   * Address: 0x006DF6E0 (FUN_006DF6E0, Moho::UnitWeapon::MemberSerialize)
   */
  void UnitWeapon::MemberSerialize(gpg::WriteArchive& archive) const
  {
    const gpg::RRef ownerRef{};

    archive.Write(CScriptEvent::StaticGetClass(), this, ownerRef);
    WriteTrackedPointer(archive, mSim, gpg::TrackedPointerState::Unowned, ownerRef);
    WriteTrackedPointer(archive, mWeaponBlueprint, gpg::TrackedPointerState::Unowned, ownerRef);
    WriteTrackedPointer(archive, mProjectileBlueprint, gpg::TrackedPointerState::Unowned, ownerRef);
    WriteTrackedPointer(archive, mAttacker, gpg::TrackedPointerState::Unowned, ownerRef);
    archive.Write(CachedRType<CWeaponAttributes>(), &mAttributes, ownerRef);
    WriteTrackedPointer(archive, mUnit, gpg::TrackedPointerState::Unowned, ownerRef);
    archive.WriteInt(mWeaponIndex);
    archive.WriteInt(mBone);
    archive.WriteBool(mEnabled != 0u);
    archive.WriteString(const_cast<msvc8::string*>(&mLabel));
    archive.Write(CachedRType<CAiTarget>(), &mTarget, ownerRef);
    WriteTrackedPointer(archive, mFireWeaponTask, gpg::TrackedPointerState::Owned, ownerRef);
    archive.WriteBool(mCanFire != 0u);
    archive.Write(CachedRType<EntityCategorySet>(), &mCat1, ownerRef);
    archive.Write(CachedRType<EntityCategorySet>(), &mCat2, ownerRef);
    archive.Write(CachedRType<ELayer>(), &mFireTargetLayerCaps, ownerRef);
    archive.WriteFloat(mFiringRandomness);
    archive.Write(CachedRType<msvc8::vector<EntityCategorySet>>(), &mTargetPriorities, ownerRef);
    archive.Write(CachedRType<msvc8::vector<SBlackListInfo>>(), &mBlacklist, ownerRef);
    archive.WriteInt(mUnknown170);
    archive.WriteBool(mUnknown174 != 0u);
    archive.Write(CachedRType<Wm3::Vector3f>(), &mAimingAt, ownerRef);
    archive.WriteInt(mShotsAtTarget);
  }
} // namespace moho
