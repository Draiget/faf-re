#include "moho/ai/CAiBuilderImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBuilderImpl.h"

using namespace moho;

namespace
{
  alignas(CAiBuilderImplSerializer)
  unsigned char gCAiBuilderImplSerializerStorage[sizeof(CAiBuilderImplSerializer)] = {};
  bool gCAiBuilderImplSerializerConstructed = false;

  [[nodiscard]] CAiBuilderImplSerializer* AcquireCAiBuilderImplSerializer()
  {
    if (!gCAiBuilderImplSerializerConstructed) {
      new (gCAiBuilderImplSerializerStorage) CAiBuilderImplSerializer();
      gCAiBuilderImplSerializerConstructed = true;
    }

    return reinterpret_cast<CAiBuilderImplSerializer*>(gCAiBuilderImplSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCAiBuilderImplType()
  {
    gpg::RType* type = CAiBuilderImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBuilderImpl));
      CAiBuilderImpl::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF6AF0 (FUN_00BF6AF0, cleanup_CAiBuilderImplSerializer)
   *
   * What it does:
   * Unlinks recovered CAiBuilderImpl serializer helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiBuilderImplSerializer()
  {
    if (!gCAiBuilderImplSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiBuilderImplSerializer());
  }

  void cleanup_CAiBuilderImplSerializer_atexit()
  {
    (void)cleanup_CAiBuilderImplSerializer();
  }
} // namespace

/**
 * Address: 0x0059FE20 (FUN_0059FE20, Moho::CAiBuilderImplSerializer::Deserialize)
 */
void CAiBuilderImplSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const builder = reinterpret_cast<CAiBuilderImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!builder) {
    return;
  }

  builder->MemberDeserialize(archive);
}

/**
 * Address: 0x0059FE30 (FUN_0059FE30, Moho::CAiBuilderImplSerializer::Serialize)
 */
void CAiBuilderImplSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const builder = reinterpret_cast<const CAiBuilderImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!builder) {
    return;
  }

  builder->MemberSerialize(archive);
}

/**
 * Address: 0x005A06D0 (FUN_005A06D0)
 *
 * What it does:
 * Lazily resolves CAiBuilderImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiBuilderImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiBuilderImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCC320 (FUN_00BCC320, register_CAiBuilderImplSerializer)
 *
 * What it does:
 * Initializes the global builder serializer helper callbacks and installs
 * process-exit cleanup.
 */
void moho::register_CAiBuilderImplSerializer()
{
  CAiBuilderImplSerializer* const serializer = AcquireCAiBuilderImplSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiBuilderImplSerializer::Deserialize;
  serializer->mSaveCallback = &CAiBuilderImplSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_CAiBuilderImplSerializer_atexit);
}

namespace
{
  struct CAiBuilderImplSerializerBootstrap
  {
    CAiBuilderImplSerializerBootstrap()
    {
      moho::register_CAiBuilderImplSerializer();
    }
  };

  [[maybe_unused]] CAiBuilderImplSerializerBootstrap gCAiBuilderImplSerializerBootstrap;
} // namespace
