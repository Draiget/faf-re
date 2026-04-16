#include "moho/ai/IAiCommandDispatchImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/misc/Stats.h"

using namespace moho;

namespace
{
  template <std::uintptr_t SlotAddress>
  struct StartupEngineStatsSlot
  {
    static EngineStats* value;
  };

  template <>
  EngineStats* StartupEngineStatsSlot<0x10AE4DCu>::value = nullptr;

  alignas(IAiCommandDispatchImplSerializer)
  unsigned char gIAiCommandDispatchImplSerializerStorage[sizeof(IAiCommandDispatchImplSerializer)] = {};
  bool gIAiCommandDispatchImplSerializerConstructed = false;

  /**
   * Address: 0x00599A40 (FUN_00599A40, j_Moho::IAiCommandDispatchImpl::MemberSerialize)
   * Address: 0x0063A1B0 (FUN_0063A1B0)
   *
   * What it does:
   * Thin forwarding thunk to `IAiCommandDispatchImpl::MemberSerialize`.
   */
  [[maybe_unused]] void IAiCommandDispatchImplMemberSerializeThunk(
    const moho::IAiCommandDispatchImpl* const object, gpg::WriteArchive* const archive
  )
  {
    if (!archive) {
      return;
    }

    moho::IAiCommandDispatchImpl::MemberSerialize(object, archive);
  }

  /**
   * Address: 0x00599C70 (FUN_00599C70, j_Moho::IAiCommandDispatchImpl::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `IAiCommandDispatchImpl::MemberSerialize`.
   */
  [[maybe_unused]] void IAiCommandDispatchImplMemberSerializeThunkSecondary(
    const moho::IAiCommandDispatchImpl* const object, gpg::WriteArchive* const archive
  )
  {
    if (!archive) {
      return;
    }

    moho::IAiCommandDispatchImpl::MemberSerialize(object, archive);
  }

  [[nodiscard]] IAiCommandDispatchImplSerializer* AcquireIAiCommandDispatchImplSerializer()
  {
    if (!gIAiCommandDispatchImplSerializerConstructed) {
      new (gIAiCommandDispatchImplSerializerStorage) IAiCommandDispatchImplSerializer();
      gIAiCommandDispatchImplSerializerConstructed = true;
    }

    return reinterpret_cast<IAiCommandDispatchImplSerializer*>(gIAiCommandDispatchImplSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchImplType()
  {
    gpg::RType* type = IAiCommandDispatchImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiCommandDispatchImpl));
      IAiCommandDispatchImpl::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF66F0 (FUN_00BF66F0, cleanup_IAiCommandDispatchImplSerializer)
   *
   * What it does:
   * Unlinks recovered serializer helper node from intrusive serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_IAiCommandDispatchImplSerializer()
  {
    if (!gIAiCommandDispatchImplSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireIAiCommandDispatchImplSerializer());
  }

  /**
   * Address: 0x00599410 (FUN_00599410)
   *
   * What it does:
   * Legacy startup-cleanup thunk lane that forwards to the canonical
   * IAiCommandDispatchImpl serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_IAiCommandDispatchImplSerializerStartupThunkA()
  {
    return cleanup_IAiCommandDispatchImplSerializer();
  }

  /**
   * Address: 0x00599440 (FUN_00599440)
   *
   * What it does:
   * Secondary startup-cleanup thunk lane that forwards to the canonical
   * IAiCommandDispatchImpl serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_IAiCommandDispatchImplSerializerStartupThunkB()
  {
    return cleanup_IAiCommandDispatchImplSerializer();
  }

  void cleanup_IAiCommandDispatchImplSerializer_atexit()
  {
    (void)cleanup_IAiCommandDispatchImplSerializer();
  }

  /**
   * Address: 0x00BF6720 (FUN_00BF6720, cleanup_IAiCommandDispatchImplStartupStatsSlot)
   *
   * What it does:
   * Tears down one startup-owned engine-stats slot.
   */
  void cleanup_IAiCommandDispatchImplStartupStatsSlot()
  {
    EngineStats*& slot = StartupEngineStatsSlot<0x10AE4DCu>::value;
    if (!slot) {
      return;
    }

    delete slot;
    slot = nullptr;
  }
} // namespace

/**
 * Address: 0x005993C0 (FUN_005993C0, Moho::IAiCommandDispatchImplSerializer::Deserialize)
 */
void IAiCommandDispatchImplSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  IAiCommandDispatchImpl::MemberDeserialize(
    archive,
    reinterpret_cast<IAiCommandDispatchImpl*>(static_cast<std::uintptr_t>(objectPtr))
  );
}

/**
 * Address: 0x005993D0 (FUN_005993D0, Moho::IAiCommandDispatchImplSerializer::Serialize)
 */
void IAiCommandDispatchImplSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const object = reinterpret_cast<const IAiCommandDispatchImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (ownerRef != nullptr) {
    IAiCommandDispatchImpl::MemberSerialize(object, archive);
    return;
  }

  IAiCommandDispatchImplMemberSerializeThunk(object, archive);
}

/**
 * Address: 0x005996D0 (FUN_005996D0)
 *
 * What it does:
 * Lazily resolves IAiCommandDispatchImpl RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void IAiCommandDispatchImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedIAiCommandDispatchImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCBF00 (FUN_00BCBF00, register_IAiCommandDispatchImplSerializer)
 *
 * What it does:
 * Initializes recovered serializer helper storage/callback lanes and installs
 * process-exit unlink cleanup.
 */
void moho::register_IAiCommandDispatchImplSerializer()
{
  IAiCommandDispatchImplSerializer* const serializer = AcquireIAiCommandDispatchImplSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &IAiCommandDispatchImplSerializer::Deserialize;
  serializer->mSaveCallback = &IAiCommandDispatchImplSerializer::Serialize;
  (void)std::atexit(&cleanup_IAiCommandDispatchImplSerializer_atexit);
}

/**
 * Address: 0x00BCBF40 (FUN_00BCBF40, register_IAiCommandDispatchImplStartupStatsCleanup)
 *
 * What it does:
 * Registers an atexit cleanup thunk for one startup-owned engine-stats slot.
 */
int moho::register_IAiCommandDispatchImplStartupStatsCleanup()
{
  return std::atexit(&cleanup_IAiCommandDispatchImplStartupStatsSlot);
}

namespace
{
  struct IAiCommandDispatchImplSerializerBootstrap
  {
    IAiCommandDispatchImplSerializerBootstrap()
    {
      moho::register_IAiCommandDispatchImplSerializer();
      (void)moho::register_IAiCommandDispatchImplStartupStatsCleanup();
    }
  };

  [[maybe_unused]] IAiCommandDispatchImplSerializerBootstrap gIAiCommandDispatchImplSerializerBootstrap;
} // namespace
