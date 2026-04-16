#include "moho/resource/RResIdSerializer.h"

#include <cstdlib>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"

#pragma init_seg(lib)

namespace
{
  moho::RResIdSerializer gRResIdSerializer{};

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(moho::RResIdSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(moho::RResIdSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  gpg::SerHelperBase* ResetSerializerLinks(moho::RResIdSerializer& serializer)
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  void CleanupRResIdSerializerAtExit()
  {
    (void)moho::ResetRResIdSerializerLinksVariant2();
  }

  struct RResIdSerializerBootstrap
  {
    RResIdSerializerBootstrap()
    {
      (void)moho::register_RResIdSerializer();
    }
  };

  RResIdSerializerBootstrap gRResIdSerializerBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x004A9680 (FUN_004A9680, nullsub_693)
   */
  void nullsub_693() {}

  /**
   * Address: 0x004A9690 (FUN_004A9690, Moho::RResIdSerializer::Deserialize)
   */
  void RResIdSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const resourceId = reinterpret_cast<RResId*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(resourceId != nullptr);
    if (!archive || !resourceId) {
      return;
    }

    archive->ReadString(&resourceId->name);
  }

  /**
   * Address: 0x004A96B0 (FUN_004A96B0, Moho::RResIdSerializer::Serialize)
   */
  void RResIdSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const resourceId = reinterpret_cast<RResId*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(resourceId != nullptr);
    if (!archive || !resourceId) {
      return;
    }

    archive->WriteString(&resourceId->name);
  }

  /**
   * Address: 0x004A9790 (FUN_004A9790, gpg::SerSaveLoadHelper<Moho::RResId>::Init)
   */
  void RResIdSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = RResId::StaticGetClass();
    GPG_ASSERT(type != nullptr);
    if (!type) {
      return;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x004A9700 (FUN_004A9700)
   */
  gpg::SerHelperBase* ResetRResIdSerializerLinksVariant1()
  {
    return ResetSerializerLinks(gRResIdSerializer);
  }

  /**
   * Address: 0x004A9730 (FUN_004A9730)
   */
  gpg::SerHelperBase* ResetRResIdSerializerLinksVariant2()
  {
    return ResetSerializerLinks(gRResIdSerializer);
  }

  /**
   * Address: 0x00BC5A80 (register_RResIdSerializer)
   */
  int register_RResIdSerializer()
  {
    InitializeSerializerNode(gRResIdSerializer);
    gRResIdSerializer.mDeserialize = &RResIdSerializer::Deserialize;
    gRResIdSerializer.mSerialize = &RResIdSerializer::Serialize;
    return std::atexit(&CleanupRResIdSerializerAtExit);
  }
} // namespace moho

