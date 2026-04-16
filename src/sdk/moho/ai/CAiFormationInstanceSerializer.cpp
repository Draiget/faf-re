#include "moho/ai/CAiFormationInstanceSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiFormationInstance.h"

using namespace moho;

namespace
{
  alignas(CAiFormationInstanceSerializer)
  unsigned char gCAiFormationInstanceSerializerStorage[sizeof(CAiFormationInstanceSerializer)] = {};
  bool gCAiFormationInstanceSerializerConstructed = false;

  [[nodiscard]] CAiFormationInstanceSerializer* AcquireCAiFormationInstanceSerializer()
  {
    if (!gCAiFormationInstanceSerializerConstructed) {
      new (gCAiFormationInstanceSerializerStorage) CAiFormationInstanceSerializer();
      gCAiFormationInstanceSerializerConstructed = true;
    }

    return reinterpret_cast<CAiFormationInstanceSerializer*>(gCAiFormationInstanceSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCAiFormationInstanceType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(CAiFormationInstance));
    }
    return sCachedType;
  }

  /**
   * Address: 0x00BF67A0 (FUN_00BF67A0, cleanup_CAiFormationInstanceSerializer)
   *
   * What it does:
   * Unlinks recovered CAiFormationInstance serializer helper node from
   * intrusive serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiFormationInstanceSerializer()
  {
    if (!gCAiFormationInstanceSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiFormationInstanceSerializer());
  }

  /**
   * Address: 0x0059BF40 (FUN_0059BF40)
   *
   * What it does:
   * Legacy startup-cleanup thunk lane that forwards to the canonical
   * CAiFormationInstance serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CAiFormationInstanceSerializerStartupThunkA()
  {
    return cleanup_CAiFormationInstanceSerializer();
  }

  /**
   * Address: 0x0059BF70 (FUN_0059BF70)
   *
   * What it does:
   * Secondary startup-cleanup thunk lane that forwards to the canonical
   * CAiFormationInstance serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CAiFormationInstanceSerializerStartupThunkB()
  {
    return cleanup_CAiFormationInstanceSerializer();
  }

  void cleanup_CAiFormationInstanceSerializer_atexit()
  {
    (void)cleanup_CAiFormationInstanceSerializer();
  }
} // namespace

/**
 * Address: 0x0059BEE0 (FUN_0059BEE0, Moho::CAiFormationInstanceSerializer::Deserialize)
 */
void CAiFormationInstanceSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const formation = reinterpret_cast<CAiFormationInstance*>(static_cast<std::uintptr_t>(objectPtr));
  if (!formation) {
    return;
  }

  formation->MemberDeserialize(archive);
}

/**
 * Address: 0x0059BEF0 (FUN_0059BEF0, Moho::CAiFormationInstanceSerializer::Serialize)
 */
void CAiFormationInstanceSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const formation = reinterpret_cast<const CAiFormationInstance*>(static_cast<std::uintptr_t>(objectPtr));
  if (!formation) {
    return;
  }

  formation->MemberSerialize(archive);
}

/**
 * Address: 0x0059C820 (FUN_0059C820)
 *
 * What it does:
 * Lazily resolves CAiFormationInstance RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void CAiFormationInstanceSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiFormationInstanceType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCC150 (FUN_00BCC150, register_CAiFormationInstanceSerializer)
 *
 * What it does:
 * Initializes the global formation-instance serializer helper callbacks and
 * installs process-exit cleanup.
 */
void moho::register_CAiFormationInstanceSerializer()
{
  CAiFormationInstanceSerializer* const serializer = AcquireCAiFormationInstanceSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiFormationInstanceSerializer::Deserialize;
  serializer->mSaveCallback = &CAiFormationInstanceSerializer::Serialize;
  (void)std::atexit(&cleanup_CAiFormationInstanceSerializer_atexit);
}

namespace
{
  struct CAiFormationInstanceSerializerBootstrap
  {
    CAiFormationInstanceSerializerBootstrap()
    {
      moho::register_CAiFormationInstanceSerializer();
    }
  };

  [[maybe_unused]] CAiFormationInstanceSerializerBootstrap gCAiFormationInstanceSerializerBootstrap;
} // namespace
