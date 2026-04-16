#include "moho/ai/IAiNavigatorSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"

using namespace moho;

namespace
{
  alignas(IAiNavigatorSerializer) unsigned char gIAiNavigatorSerializerStorage[sizeof(IAiNavigatorSerializer)] = {};
  bool gIAiNavigatorSerializerConstructed = false;

  [[nodiscard]] IAiNavigatorSerializer* AcquireIAiNavigatorSerializer()
  {
    if (!gIAiNavigatorSerializerConstructed) {
      new (gIAiNavigatorSerializerStorage) IAiNavigatorSerializer();
      gIAiNavigatorSerializerConstructed = true;
    }

    return reinterpret_cast<IAiNavigatorSerializer*>(gIAiNavigatorSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedIAiNavigatorType()
  {
    gpg::RType* type = IAiNavigator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiNavigator));
      IAiNavigator::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF6D20 (FUN_00BF6D20, cleanup_IAiNavigatorSerializer)
   *
   * What it does:
   * Unlinks recovered IAiNavigator serializer helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_IAiNavigatorSerializer()
  {
    if (!gIAiNavigatorSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireIAiNavigatorSerializer());
  }

  /**
   * Address: 0x005A3320 (FUN_005A3320)
   *
   * What it does:
   * Legacy startup-cleanup thunk lane that forwards to the canonical
   * IAiNavigator serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_IAiNavigatorSerializerStartupThunkA()
  {
    return cleanup_IAiNavigatorSerializer();
  }

  /**
   * Address: 0x005A3350 (FUN_005A3350)
   *
   * What it does:
   * Secondary startup-cleanup thunk lane that forwards to the canonical
   * IAiNavigator serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_IAiNavigatorSerializerStartupThunkB()
  {
    return cleanup_IAiNavigatorSerializer();
  }

  void cleanup_IAiNavigatorSerializer_atexit()
  {
    (void)cleanup_IAiNavigatorSerializer();
  }
} // namespace

/**
 * Address: 0x005A32D0 (FUN_005A32D0, Moho::IAiNavigatorSerializer::Deserialize)
 */
void IAiNavigatorSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  IAiNavigator::MemberDeserialize(reinterpret_cast<IAiNavigator*>(static_cast<std::uintptr_t>(objectPtr)), archive);
}

/**
 * Address: 0x005A32E0 (FUN_005A32E0, Moho::IAiNavigatorSerializer::Serialize)
 */
void IAiNavigatorSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  IAiNavigator::MemberSerialize(
    reinterpret_cast<const IAiNavigator*>(static_cast<std::uintptr_t>(objectPtr)),
    archive
  );
}

/**
 * Address: 0x005A71A0 (FUN_005A71A0)
 *
 * What it does:
 * Lazily resolves IAiNavigator RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void IAiNavigatorSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedIAiNavigatorType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCC6C0 (FUN_00BCC6C0, register_IAiNavigatorSerializer)
 *
 * What it does:
 * Initializes the global IAiNavigator serializer helper callbacks and
 * installs process-exit cleanup.
 */
void moho::register_IAiNavigatorSerializer()
{
  IAiNavigatorSerializer* const serializer = AcquireIAiNavigatorSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &IAiNavigatorSerializer::Deserialize;
  serializer->mSaveCallback = &IAiNavigatorSerializer::Serialize;
  (void)std::atexit(&cleanup_IAiNavigatorSerializer_atexit);
}

namespace
{
  struct IAiNavigatorSerializerBootstrap
  {
    IAiNavigatorSerializerBootstrap()
    {
      moho::register_IAiNavigatorSerializer();
    }
  };

  [[maybe_unused]] IAiNavigatorSerializerBootstrap gIAiNavigatorSerializerBootstrap;
} // namespace

