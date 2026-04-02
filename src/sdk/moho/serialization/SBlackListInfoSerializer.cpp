#include "moho/serialization/SBlackListInfoSerializer.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/serialization/SBlackListInfo.h"

#pragma init_seg(lib)

namespace
{
  using Serializer = moho::SBlackListInfoSerializer;

  Serializer gSBlackListInfoSerializer{};

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

  /**
   * Address: 0x00BFE680 (FUN_00BFE680, serializer helper unlink cleanup)
   *
   * What it does:
   * Unlinks the `SBlackListInfoSerializer` helper node and rewires it as a self-linked singleton.
   */
  gpg::SerHelperBase* cleanup_SBlackListInfoSerializer_00BFE680_Impl()
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(gSBlackListInfoSerializer);
    if (gSBlackListInfoSerializer.mHelperNext == nullptr || gSBlackListInfoSerializer.mHelperPrev == nullptr) {
      gSBlackListInfoSerializer.mHelperPrev = self;
      gSBlackListInfoSerializer.mHelperNext = self;
      return self;
    }

    gSBlackListInfoSerializer.mHelperNext->mPrev = gSBlackListInfoSerializer.mHelperPrev;
    gSBlackListInfoSerializer.mHelperPrev->mNext = gSBlackListInfoSerializer.mHelperNext;
    gSBlackListInfoSerializer.mHelperPrev = self;
    gSBlackListInfoSerializer.mHelperNext = self;
    return self;
  }

  void cleanup_SBlackListInfoSerializer_00BFE680_AtExit()
  {
    (void)cleanup_SBlackListInfoSerializer_00BFE680_Impl();
  }

  /**
   * Address: 0x00BD8830 (FUN_00BD8830, register serializer + atexit cleanup)
   *
   * What it does:
   * Installs `SBlackListInfo` serializer callbacks and schedules helper cleanup.
   */
  int register_SBlackListInfoSerializer_00BD8830_Impl()
  {
    InitializeSerializerNode(gSBlackListInfoSerializer);
    gSBlackListInfoSerializer.mDeserialize = &moho::SBlackListInfoSerializer::Deserialize;
    gSBlackListInfoSerializer.mSerialize = &moho::SBlackListInfoSerializer::Serialize;
    gSBlackListInfoSerializer.RegisterSerializeFunctions();
    return std::atexit(&cleanup_SBlackListInfoSerializer_00BFE680_AtExit);
  }

  struct SBlackListInfoSerializerBootstrap
  {
    SBlackListInfoSerializerBootstrap()
    {
      (void)moho::register_SBlackListInfoSerializer();
    }
  };

  SBlackListInfoSerializerBootstrap gSBlackListInfoSerializerBootstrap;
} // namespace

namespace moho
{
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
  void SBlackListInfoSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSBlackListInfoType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFE680 (FUN_00BFE680, sub_BFE680)
   */
  gpg::SerHelperBase* cleanup_SBlackListInfoSerializer()
  {
    return cleanup_SBlackListInfoSerializer_00BFE680_Impl();
  }

  /**
   * Address: 0x00BD8830 (FUN_00BD8830, register_SBlackListInfoSerializer)
   */
  int register_SBlackListInfoSerializer()
  {
    return register_SBlackListInfoSerializer_00BD8830_Impl();
  }

  /**
   * Address: 0x006D39E0 (FUN_006D39E0, sub_6D39E0)
   */
  gpg::SerHelperBase* cleanup_SBlackListInfoSerializer_00()
  {
    return cleanup_SBlackListInfoSerializer_00BFE680_Impl();
  }

  /**
   * Address: 0x006D3970 (FUN_006D3970, nullsub_1857)
   */
  void nullsub_1857_00() {}
} // namespace moho
