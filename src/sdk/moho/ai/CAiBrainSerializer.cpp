#include "moho/ai/CAiBrainSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBrain.h"

using namespace moho;

namespace
{
  alignas(CAiBrainSerializer) unsigned char gCAiBrainSerializerStorage[sizeof(CAiBrainSerializer)] = {};
  bool gCAiBrainSerializerConstructed = false;

  [[nodiscard]] CAiBrainSerializer* AcquireCAiBrainSerializer()
  {
    if (!gCAiBrainSerializerConstructed) {
      new (gCAiBrainSerializerStorage) CAiBrainSerializer();
      gCAiBrainSerializerConstructed = true;
    }

    return reinterpret_cast<CAiBrainSerializer*>(gCAiBrainSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCAiBrainType()
  {
    gpg::RType* type = CAiBrain::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBrain));
      CAiBrain::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF62F0 (FUN_00BF62F0, cleanup_CAiBrainSerializer)
   *
   * What it does:
   * Unlinks recovered CAiBrain serializer helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiBrainSerializer()
  {
    if (!gCAiBrainSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiBrainSerializer());
  }

  /**
   * Address: 0x00579DE0 (FUN_00579DE0)
   *
   * What it does:
   * Legacy startup-cleanup thunk lane that forwards to the canonical
   * CAiBrain serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CAiBrainSerializerStartupThunkA()
  {
    return cleanup_CAiBrainSerializer();
  }

  /**
   * Address: 0x00579E10 (FUN_00579E10)
   *
   * What it does:
   * Secondary startup-cleanup thunk lane that forwards to the canonical
   * CAiBrain serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CAiBrainSerializerStartupThunkB()
  {
    return cleanup_CAiBrainSerializer();
  }

  void cleanup_CAiBrainSerializer_atexit()
  {
    (void)cleanup_CAiBrainSerializer();
  }

  struct CAiBrainSerializerStartupBootstrap
  {
    CAiBrainSerializerStartupBootstrap()
    {
      moho::register_CAiBrainSerializer();
    }
  };

  [[maybe_unused]] CAiBrainSerializerStartupBootstrap gCAiBrainSerializerStartupBootstrap;
} // namespace

/**
 * Address: 0x00579D90 (FUN_00579D90, Moho::CAiBrainSerializer::Deserialize)
 */
void CAiBrainSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const brain = reinterpret_cast<CAiBrain*>(static_cast<std::uintptr_t>(objectPtr));
  brain->MemberDeserialize(archive);
}

/**
 * Address: 0x00579DA0 (FUN_00579DA0, Moho::CAiBrainSerializer::Serialize)
 */
void CAiBrainSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const brain = reinterpret_cast<const CAiBrain*>(static_cast<std::uintptr_t>(objectPtr));
  brain->MemberSerialize(archive);
}

/**
 * Address: 0x0057E460 (FUN_0057E460)
 *
 * What it does:
 * Lazily resolves CAiBrain RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void CAiBrainSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiBrainType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCB430 (FUN_00BCB430, register_CAiBrainSerializer)
 *
 * What it does:
 * Initializes the global CAiBrain serializer helper callbacks and
 * installs process-exit cleanup.
 */
void moho::register_CAiBrainSerializer()
{
  CAiBrainSerializer* const serializer = AcquireCAiBrainSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiBrainSerializer::Deserialize;
  serializer->mSaveCallback = &CAiBrainSerializer::Serialize;
  (void)std::atexit(&cleanup_CAiBrainSerializer_atexit);
}
