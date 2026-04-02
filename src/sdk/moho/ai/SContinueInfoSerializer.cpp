#include "moho/ai/SContinueInfoSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"

using namespace moho;

namespace
{
  alignas(SContinueInfoSerializer) unsigned char gSContinueInfoSerializerStorage[sizeof(SContinueInfoSerializer)] = {};
  bool gSContinueInfoSerializerConstructed = false;

  [[nodiscard]] SContinueInfoSerializer* AcquireSContinueInfoSerializer()
  {
    if (!gSContinueInfoSerializerConstructed) {
      new (gSContinueInfoSerializerStorage) SContinueInfoSerializer();
      gSContinueInfoSerializerConstructed = true;
    }

    return reinterpret_cast<SContinueInfoSerializer*>(gSContinueInfoSerializerStorage);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedSContinueInfoType()
  {
    gpg::RType* type = SContinueInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SContinueInfo));
      SContinueInfo::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF7460 (FUN_00BF7460, cleanup_SContinueInfoSerializer)
   *
   * What it does:
   * Unlinks the startup serializer helper node from the intrusive helper list.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_SContinueInfoSerializer()
  {
    if (!gSContinueInfoSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireSContinueInfoSerializer());
  }

  void cleanup_SContinueInfoSerializer_atexit()
  {
    (void)cleanup_SContinueInfoSerializer();
  }
} // namespace

/**
 * Address: 0x005B2290 (FUN_005B2290, Moho::SContinueInfoSerializer::Deserialize)
 */
void SContinueInfoSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const continuationInfo = reinterpret_cast<SContinueInfo*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !continuationInfo) {
    return;
  }

  continuationInfo->MemberDeserialize(archive);
}

/**
 * Address: 0x005B22A0 (FUN_005B22A0, Moho::SContinueInfoSerializer::Serialize)
 */
void SContinueInfoSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const continuationInfo = reinterpret_cast<SContinueInfo*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !continuationInfo) {
    return;
  }

  continuationInfo->MemberSerialize(archive);
}

/**
 * Address: 0x005B4820 (FUN_005B4820)
 */
void SContinueInfoSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSContinueInfoType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCD2F0 (FUN_00BCD2F0, register_SContinueInfoSerializer)
 *
 * What it does:
 * Initializes startup serializer callbacks for `SContinueInfo` and installs
 * process-exit helper unlink cleanup.
 */
int moho::register_SContinueInfoSerializer()
{
  SContinueInfoSerializer* const serializer = AcquireSContinueInfoSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &SContinueInfoSerializer::Deserialize;
  serializer->mSaveCallback = &SContinueInfoSerializer::Serialize;
  return std::atexit(&cleanup_SContinueInfoSerializer_atexit);
}

namespace
{
  struct SContinueInfoSerializerBootstrap
  {
    SContinueInfoSerializerBootstrap()
    {
      (void)moho::register_SContinueInfoSerializer();
    }
  };

  [[maybe_unused]] SContinueInfoSerializerBootstrap gSContinueInfoSerializerBootstrap;
} // namespace
