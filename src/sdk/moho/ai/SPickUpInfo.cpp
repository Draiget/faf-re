#include "moho/ai/SPickUpInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/core/Unit.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSPickUpInfoType()
  {
    gpg::RType* type = moho::SPickUpInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SPickUpInfo));
      moho::SPickUpInfo::sType = type;
    }
    return type;
  }

  // Address: 0x010B1F50 -- process-global `SPickUpInfoSerializer` singleton.
  // Constructing it runs SPickUpInfoSerializer::SPickUpInfoSerializer()
  // (0x00BD1C50), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~SPickUpInfoSerializer,
  // 0x00BFA520) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::SPickUpInfoSerializer gSPickUpInfoSerializer;
} // namespace

namespace moho
{
  gpg::RType* SPickUpInfo::sType = nullptr;

  /**
   * Address: 0x006246A0 (FUN_006246A0)
   *
   * What it does:
   * Links `mUnit` at the head of `unit`'s weak chain and stores the squared
   * distance.
   */
  SPickUpInfo::SPickUpInfo(Unit* const unit, const float distanceSquared) noexcept
    : mUnit(unit)
    , mDistanceSq(distanceSquared)
  {}

  Unit* SPickUpInfo::GetUnit() const noexcept
  {
    return mUnit.GetObjectPtr();
  }

  /**
   * Address: 0x00627EB0 (FUN_00627EB0)
   *
   * What it does:
   * Deserializes one pickup entry by reading weak-unit lane then distance.
   */
  void SPickUpInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RType* const weakUnitType = ResolveWeakPtrUnitType();
    GPG_ASSERT(weakUnitType != nullptr);

    const gpg::RRef ownerRef{};
    if (weakUnitType) {
      archive->Read(weakUnitType, &mUnit, ownerRef);
    }
    archive->ReadFloat(&mDistanceSq);
  }

  /**
   * Address: 0x00627F00 (FUN_00627F00)
   *
   * What it does:
   * Serializes one pickup entry by writing weak-unit lane then distance.
   */
  void SPickUpInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RType* const weakUnitType = ResolveWeakPtrUnitType();
    GPG_ASSERT(weakUnitType != nullptr);

    const gpg::RRef ownerRef{};
    if (weakUnitType) {
      archive->Write(weakUnitType, &mUnit, ownerRef);
    }
    archive->WriteFloat(mDistanceSq);
  }

  /**
   * Address: 0x00624810 (FUN_00624810, Moho::SPickUpInfoSerializer::Deserialize)
   */
  void SPickUpInfoSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    reinterpret_cast<SPickUpInfo*>(static_cast<std::uintptr_t>(objectPtr))->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00624820 (FUN_00624820, Moho::SPickUpInfoSerializer::Serialize)
   */
  void SPickUpInfoSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    reinterpret_cast<const SPickUpInfo*>(static_cast<std::uintptr_t>(objectPtr))->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BD1C50 (FUN_00BD1C50, dynamic initializer for the global
   * `SPickUpInfoSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`) and binds the load/save callback fields.
   */
  SPickUpInfoSerializer::SPickUpInfoSerializer()
    : mLoad(&SPickUpInfoSerializer::Deserialize)
    , mSave(&SPickUpInfoSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFA520 (FUN_00BFA520, ??1SPickUpInfoSerializer@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  SPickUpInfoSerializer::~SPickUpInfoSerializer() = default;

  /**
   * What it does:
   * Binds the `SPickUpInfo` serializer callbacks into reflected RTTI.
   */
  void SPickUpInfoSerializer::Init()
  {
    gpg::RType* const type = CachedSPickUpInfoType();
    if (type == nullptr) {
      return;
    }

    type->serLoadFunc_ = mLoad;
    type->serSaveFunc_ = mSave;
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00628090 (FUN_00628090)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_SPickUpInfo` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignSPickUpInfoRef(gpg::RRef* const outRef, moho::SPickUpInfo* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)gpg::RRef_SPickUpInfo(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg
