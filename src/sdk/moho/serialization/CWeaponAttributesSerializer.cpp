#include "moho/serialization/CWeaponAttributesSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/CWeaponAttributes.h"

#pragma init_seg(lib)

namespace
{
  using Serializer = moho::CWeaponAttributesSerializer;

  [[nodiscard]] Serializer& GetCWeaponAttributesSerializer() noexcept
  {
    static Serializer serializer{};
    return serializer;
  }

  [[nodiscard]] gpg::RType* CachedCWeaponAttributesType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CWeaponAttributes));
    }

    return cached;
  }

  [[nodiscard]] gpg::RType* CachedRUnitBlueprintWeaponType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintWeapon));
    }

    return cached;
  }

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(Serializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] moho::RUnitBlueprintWeapon* ReadRUnitBlueprintWeaponPointer(
    gpg::ReadArchive* archive, const gpg::RRef& ownerRef
  )
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRUnitBlueprintWeaponType());
    if (upcast.mObj) {
      return static_cast<moho::RUnitBlueprintWeapon*>(upcast.mObj);
    }

    const char* const expected = CachedRUnitBlueprintWeaponType() ? CachedRUnitBlueprintWeaponType()->GetName() : "RUnitBlueprintWeapon";
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "RUnitBlueprintWeapon",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  [[nodiscard]] gpg::RRef MakeRUnitBlueprintWeaponRef(moho::RUnitBlueprintWeapon* value)
  {
    gpg::RRef ref{};
    ref.mObj = value;
    ref.mType = CachedRUnitBlueprintWeaponType();
    return ref;
  }

  /**
   * Address: 0x00BFE5F0 (FUN_00BFE5F0, serializer helper unlink cleanup)
   *
   * What it does:
   * Unlinks the `CWeaponAttributesSerializer` helper node and rewires it as a self-linked singleton.
   */
  gpg::SerHelperBase* cleanup_CWeaponAttributesSerializer_00BFE5F0_Impl()
  {
    Serializer& serializer = GetCWeaponAttributesSerializer();
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  void cleanup_CWeaponAttributesSerializer_atexit()
  {
    (void)cleanup_CWeaponAttributesSerializer_00BFE5F0_Impl();
  }

  /**
   * Address: 0x006D3780 (FUN_006D3780, load body)
   *
   * What it does:
   * Loads the reflected pointer/string/float lanes for `CWeaponAttributes`.
   */
  void LoadCWeaponAttributes(
    gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef
  )
  {
    auto* const attributes = reinterpret_cast<moho::CWeaponAttributes*>(objectPtr);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    attributes->mBlueprint = ReadRUnitBlueprintWeaponPointer(archive, owner);
    archive->ReadFloat(&attributes->mFiringTolerance);
    archive->ReadFloat(&attributes->mRateOfFire);
    archive->ReadFloat(&attributes->mMinRadius);
    archive->ReadFloat(&attributes->mMaxRadius);
    archive->ReadFloat(&attributes->mMinRadiusSq);
    archive->ReadFloat(&attributes->mMaxRadiusSq);
    archive->ReadString(&attributes->mType);
    archive->ReadFloat(&attributes->mDamageRadius);
    archive->ReadFloat(&attributes->mDamage);
    archive->ReadFloat(&attributes->mUnknown_0044);
    archive->ReadFloat(&attributes->mUnknown_0048);
  }

  /**
   * Address: 0x006D3790 (FUN_006D3790, save body)
   *
   * What it does:
   * Saves the reflected pointer/string/float lanes for `CWeaponAttributes`.
   */
  void SaveCWeaponAttributes(
    gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef
  )
  {
    const auto* const attributes = reinterpret_cast<const moho::CWeaponAttributes*>(objectPtr);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    gpg::RRef blueprintRef = MakeRUnitBlueprintWeaponRef(attributes->mBlueprint);
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, owner);
    archive->WriteFloat(attributes->mFiringTolerance);
    archive->WriteFloat(attributes->mRateOfFire);
    archive->WriteFloat(attributes->mMinRadius);
    archive->WriteFloat(attributes->mMaxRadius);
    archive->WriteFloat(attributes->mMinRadiusSq);
    archive->WriteFloat(attributes->mMaxRadiusSq);
    archive->WriteString(const_cast<msvc8::string*>(&attributes->mType));
    archive->WriteFloat(attributes->mDamageRadius);
    archive->WriteFloat(attributes->mDamage);
    archive->WriteFloat(attributes->mUnknown_0044);
    archive->WriteFloat(attributes->mUnknown_0048);
  }

  /**
   * Address: 0x00BD87D0 (FUN_00BD87D0, startup registration + atexit cleanup)
   *
   * What it does:
   * Initializes `CWeaponAttributesSerializer` callback slots and schedules exit cleanup.
   */
  int register_CWeaponAttributesSerializer_00BD87D0_Impl()
  {
    InitializeSerializerNode(GetCWeaponAttributesSerializer());
    GetCWeaponAttributesSerializer().mDeserialize = &LoadCWeaponAttributes;
    GetCWeaponAttributesSerializer().mSerialize = &SaveCWeaponAttributes;
    GetCWeaponAttributesSerializer().RegisterSerializeFunctions();
    return std::atexit(&cleanup_CWeaponAttributesSerializer_atexit);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006D3780 (FUN_006D3780, Moho::CWeaponAttributesSerializer::Deserialize)
   */
  void CWeaponAttributesSerializer::Deserialize(
    gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef
  )
  {
    LoadCWeaponAttributes(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006D3790 (FUN_006D3790, Moho::CWeaponAttributesSerializer::Serialize)
   */
  void CWeaponAttributesSerializer::Serialize(
    gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef
  )
  {
    SaveCWeaponAttributes(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006DB4C0 (FUN_006DB4C0, Moho::CWeaponAttributesSerializer::RegisterSerializeFunctions)
   */
  void CWeaponAttributesSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCWeaponAttributesType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFE5F0 (FUN_00BFE5F0, sub_BFE5F0)
   */
  gpg::SerHelperBase* cleanup_CWeaponAttributesSerializer()
  {
    return cleanup_CWeaponAttributesSerializer_00BFE5F0_Impl();
  }

  /**
   * Address: 0x00BD87D0 (FUN_00BD87D0, register_CWeaponAttributesSerializer)
   */
  int register_CWeaponAttributesSerializer()
  {
    return register_CWeaponAttributesSerializer_00BD87D0_Impl();
  }
} // namespace moho
