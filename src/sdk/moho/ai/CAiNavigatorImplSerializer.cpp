#include "moho/ai/CAiNavigatorImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorImpl.h"

using namespace moho;

namespace
{
  alignas(CAiNavigatorImplSerializer) unsigned char gCAiNavigatorImplSerializerStorage[sizeof(CAiNavigatorImplSerializer)] = {};
  bool gCAiNavigatorImplSerializerConstructed = false;

  [[nodiscard]] CAiNavigatorImplSerializer* AcquireCAiNavigatorImplSerializer()
  {
    if (!gCAiNavigatorImplSerializerConstructed) {
      new (gCAiNavigatorImplSerializerStorage) CAiNavigatorImplSerializer();
      gCAiNavigatorImplSerializerConstructed = true;
    }

    return reinterpret_cast<CAiNavigatorImplSerializer*>(gCAiNavigatorImplSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCAiNavigatorImplType()
  {
    gpg::RType* type = CAiNavigatorImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorImpl));
      CAiNavigatorImpl::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF6DA0 (FUN_00BF6DA0, cleanup_CAiNavigatorImplSerializer)
   *
   * What it does:
   * Unlinks recovered CAiNavigatorImpl serializer helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiNavigatorImplSerializer()
  {
    if (!gCAiNavigatorImplSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiNavigatorImplSerializer());
  }

  void cleanup_CAiNavigatorImplSerializer_atexit()
  {
    (void)cleanup_CAiNavigatorImplSerializer();
  }
} // namespace

/**
 * Address: 0x005A39F0 (FUN_005A39F0, Moho::CAiNavigatorImplSerializer::Deserialize)
 */
void CAiNavigatorImplSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  CAiNavigatorImpl::MemberDeserialize(
    reinterpret_cast<CAiNavigatorImpl*>(static_cast<std::uintptr_t>(objectPtr)),
    archive,
    version
  );
}

/**
 * Address: 0x005A3A10 (FUN_005A3A10, Moho::CAiNavigatorImplSerializer::Serialize)
 */
void CAiNavigatorImplSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  CAiNavigatorImpl::MemberSerialize(
    reinterpret_cast<const CAiNavigatorImpl*>(static_cast<std::uintptr_t>(objectPtr)),
    archive,
    version
  );
}

/**
 * Address: 0x005A72A0 (FUN_005A72A0)
 *
 * What it does:
 * Lazily resolves CAiNavigatorImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiNavigatorImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiNavigatorImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCC720 (FUN_00BCC720, register_CAiNavigatorImplSerializer)
 *
 * What it does:
 * Initializes the global CAiNavigatorImpl serializer helper callbacks and
 * installs process-exit cleanup.
 */
void moho::register_CAiNavigatorImplSerializer()
{
  CAiNavigatorImplSerializer* const serializer = AcquireCAiNavigatorImplSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiNavigatorImplSerializer::Deserialize;
  serializer->mSaveCallback = &CAiNavigatorImplSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_CAiNavigatorImplSerializer_atexit);
}

namespace
{
  struct CAiNavigatorImplSerializerBootstrap
  {
    CAiNavigatorImplSerializerBootstrap()
    {
      moho::register_CAiNavigatorImplSerializer();
    }
  };

  [[maybe_unused]] CAiNavigatorImplSerializerBootstrap gCAiNavigatorImplSerializerBootstrap;
} // namespace

