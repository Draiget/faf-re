#include "moho/serialization/CPrefetchSetSerializer.h"

#include <cstdlib>

#include "gpg/core/utils/Global.h"
#include "moho/serialization/CPrefetchSet.h"
#include "moho/serialization/PrefetchHandleBaseVectorReflection.h"

namespace
{
  moho::CPrefetchSetSerializer gCPrefetchSetSerializer{};

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(moho::CPrefetchSetSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(moho::CPrefetchSetSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  gpg::SerHelperBase* ResetSerializerLinks(moho::CPrefetchSetSerializer& serializer)
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

  void CleanupPrefetchSetSerializerAtExit()
  {
    (void)moho::ResetCPrefetchSetSerializerLinksVariant2();
  }

  struct CPrefetchSetSerializerBootstrap
  {
    CPrefetchSetSerializerBootstrap()
    {
      moho::register_CPrefetchSetSerializer();
    }
  };

  CPrefetchSetSerializerBootstrap gCPrefetchSetSerializerBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x004A55F0 (FUN_004A55F0, Moho::CPrefetchSetSerializer::Deserialize)
   */
  void CPrefetchSetSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const setObject = reinterpret_cast<CPrefetchSet*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(setObject != nullptr);
    if (!archive || !setObject) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Read(gpg::ResolvePrefetchHandleBaseVectorType(), setObject, owner);
  }

  /**
   * Address: 0x004A5630 (FUN_004A5630, Moho::CPrefetchSetSerializer::Serialize)
   */
  void CPrefetchSetSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const setObject = reinterpret_cast<CPrefetchSet*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(setObject != nullptr);
    if (!archive || !setObject) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Write(gpg::ResolvePrefetchHandleBaseVectorType(), setObject, owner);
  }

  /**
   * Address: 0x004A5F50 (FUN_004A5F50)
   */
  void CPrefetchSetSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CPrefetchSet::StaticGetClass();
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
   * Address: 0x004A56A0 (FUN_004A56A0)
   */
  gpg::SerHelperBase* ResetCPrefetchSetSerializerLinksVariant1()
  {
    return ResetSerializerLinks(gCPrefetchSetSerializer);
  }

  /**
   * Address: 0x004A56D0 (FUN_004A56D0)
   */
  gpg::SerHelperBase* ResetCPrefetchSetSerializerLinksVariant2()
  {
    return ResetSerializerLinks(gCPrefetchSetSerializer);
  }

  /**
   * Address: 0x00BC5990 (FUN_00BC5990, register_CPrefetchSetSerializer)
   *
   * What it does:
   * Initializes the global serializer node for `CPrefetchSet`, binds archive
   * callback lanes, and schedules serializer-link cleanup at process exit.
   */
  void register_CPrefetchSetSerializer()
  {
    InitializeSerializerNode(gCPrefetchSetSerializer);
    gCPrefetchSetSerializer.mDeserialize = &CPrefetchSetSerializer::Deserialize;
    gCPrefetchSetSerializer.mSerialize = &CPrefetchSetSerializer::Serialize;

    (void)std::atexit(&CleanupPrefetchSetSerializerAtExit);
  }
} // namespace moho
