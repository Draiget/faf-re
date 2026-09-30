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

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SPickUpInfo>`, vtable 0x00E20DDC.
   *
   * Address: 0x00BD1C50 (FUN_00BD1C50 -- constructs the global and registers its destructor.)
   * Address: 0x00BFA520 (FUN_00BFA520 -- the global's destructor.)
   * Address: 0x00626B30 (FUN_00626B30 -- `Init`.)
   * Address: 0x00624810 (FUN_00624810 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00624820 (FUN_00624820 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SPickUpInfoSerializer : gpg::SerSaveLoadHelper<SPickUpInfo>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B1F50 -- process-global `SPickUpInfoSerializer` singleton.
  moho::SPickUpInfoSerializer gSPickUpInfoSerializer;
} // namespace
