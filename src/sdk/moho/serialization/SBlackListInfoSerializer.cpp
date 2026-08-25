#include "moho/serialization/SBlackListInfoSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/serialization/SBlackListInfo.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveSBlackListInfoType()
  {
    gpg::RType* type = moho::SBlackListInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SBlackListInfo));
      moho::SBlackListInfo::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Entity>));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  /**
   * Address: 0x006DD2B0 (FUN_006DD2B0, weakptr+int load body)
   *
   * What it does:
   * Loads the reflected `WeakPtr<Entity>` lane and the trailing integer payload.
   */
  void LoadSBlackListInfoBody(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const info = reinterpret_cast<moho::SBlackListInfo*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(ResolveWeakPtrEntityType(), &info->mEntity, nullOwner);
    archive->ReadInt(&info->mValue);
  }

  /**
   * Address: 0x006DD300 (FUN_006DD300, weakptr+int save body)
   *
   * What it does:
   * Saves the reflected `WeakPtr<Entity>` lane and the trailing integer payload.
   */
  void SaveSBlackListInfoBody(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    const auto* const info = reinterpret_cast<const moho::SBlackListInfo*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(ResolveWeakPtrEntityType(), &info->mEntity, nullOwner);
    archive->WriteInt(info->mValue);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD8830 (FUN_00BD8830, register_SBlackListInfoSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SBlackListInfoSerializer::SBlackListInfoSerializer()
    : mDeserialize(&SBlackListInfoSerializer::Deserialize)
    , mSerialize(&SBlackListInfoSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFE680 (FUN_00BFE680, implicit static-destructor registration target)
   */
  SBlackListInfoSerializer::~SBlackListInfoSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006D3980 (FUN_006D3980, Moho::SBlackListInfoSerializer::Deserialize)
   *
   * What it does:
   * Dispatches archive loading into the weakptr+int body for `SBlackListInfo`.
   */
  void SBlackListInfoSerializer::Deserialize(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef
  )
  {
    LoadSBlackListInfoBody(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006D3990 (FUN_006D3990, Moho::SBlackListInfoSerializer::Serialize)
   *
   * What it does:
   * Dispatches archive saving into the weakptr+int body for `SBlackListInfo`.
   */
  void SBlackListInfoSerializer::Serialize(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef
  )
  {
    SaveSBlackListInfoBody(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006DB560 (FUN_006DB560, gpg::SerSaveLoadHelper<Moho::SBlackListInfo>::Init)
   */
  void SBlackListInfoSerializer::Init()
  {
    gpg::RType* const type = ResolveSBlackListInfoType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

namespace
{
  // Address: 0x010B7DB8 -- process-global `SBlackListInfoSerializer` singleton.
  moho::SBlackListInfoSerializer gSBlackListInfoSerializer;
} // namespace
