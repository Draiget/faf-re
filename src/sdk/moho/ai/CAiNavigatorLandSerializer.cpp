#include "moho/ai/CAiNavigatorLandSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorLand.h"

using namespace moho;

namespace
{
  alignas(CAiNavigatorLandSerializer) unsigned char gCAiNavigatorLandSerializerStorage[sizeof(CAiNavigatorLandSerializer)] = {};
  bool gCAiNavigatorLandSerializerConstructed = false;

  /**
   * Address: 0x005A7E60 (FUN_005A7E60, j_Moho::CAiNavigatorLand::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiNavigatorLand::MemberSerialize`.
   */
  [[maybe_unused]] void CAiNavigatorLandMemberSerializeThunk(
    const moho::CAiNavigatorLand* const navigator, gpg::WriteArchive* const archive
  )
  {
    if (!navigator) {
      return;
    }

    moho::CAiNavigatorLand::MemberSerialize(navigator, archive);
  }

  /**
   * Address: 0x005A8790 (FUN_005A8790, j_Moho::CAiNavigatorLand::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiNavigatorLand::MemberSerialize`.
   */
  [[maybe_unused]] void CAiNavigatorLandMemberSerializeThunkSecondary(
    const moho::CAiNavigatorLand* const navigator, gpg::WriteArchive* const archive
  )
  {
    if (!navigator) {
      return;
    }

    moho::CAiNavigatorLand::MemberSerialize(navigator, archive);
  }

  [[nodiscard]] CAiNavigatorLandSerializer* AcquireCAiNavigatorLandSerializer()
  {
    if (!gCAiNavigatorLandSerializerConstructed) {
      new (gCAiNavigatorLandSerializerStorage) CAiNavigatorLandSerializer();
      gCAiNavigatorLandSerializerConstructed = true;
    }

    return reinterpret_cast<CAiNavigatorLandSerializer*>(gCAiNavigatorLandSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCAiNavigatorLandType()
  {
    gpg::RType* type = CAiNavigatorLand::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorLand));
      CAiNavigatorLand::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF6EA0 (FUN_00BF6EA0, cleanup_CAiNavigatorLandSerializer)
   *
   * What it does:
   * Unlinks recovered CAiNavigatorLand serializer helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiNavigatorLandSerializer()
  {
    if (!gCAiNavigatorLandSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiNavigatorLandSerializer());
  }

  void cleanup_CAiNavigatorLandSerializer_atexit()
  {
    (void)cleanup_CAiNavigatorLandSerializer();
  }
} // namespace

/**
 * Address: 0x005A47D0 (FUN_005A47D0, Moho::CAiNavigatorLandSerializer::Deserialize)
 */
void CAiNavigatorLandSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  CAiNavigatorLand::MemberDeserialize(
    reinterpret_cast<CAiNavigatorLand*>(static_cast<std::uintptr_t>(objectPtr)),
    archive
  );
}

/**
 * Address: 0x005A47E0 (FUN_005A47E0, Moho::CAiNavigatorLandSerializer::Serialize)
 */
void CAiNavigatorLandSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const navigator = reinterpret_cast<const CAiNavigatorLand*>(static_cast<std::uintptr_t>(objectPtr));
  if (ownerRef != nullptr) {
    CAiNavigatorLand::MemberSerialize(navigator, archive);
    return;
  }

  CAiNavigatorLandMemberSerializeThunk(navigator, archive);
}

/**
 * Address: 0x005A7430 (FUN_005A7430)
 *
 * What it does:
 * Lazily resolves CAiNavigatorLand RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiNavigatorLandSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiNavigatorLandType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCC7E0 (FUN_00BCC7E0, register_CAiNavigatorLandSerializer)
 *
 * What it does:
 * Initializes the global CAiNavigatorLand serializer helper callbacks and
 * installs process-exit cleanup.
 */
void moho::register_CAiNavigatorLandSerializer()
{
  CAiNavigatorLandSerializer* const serializer = AcquireCAiNavigatorLandSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiNavigatorLandSerializer::Deserialize;
  serializer->mSaveCallback = &CAiNavigatorLandSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_CAiNavigatorLandSerializer_atexit);
}

namespace
{
  struct CAiNavigatorLandSerializerBootstrap
  {
    CAiNavigatorLandSerializerBootstrap()
    {
      moho::register_CAiNavigatorLandSerializer();
    }
  };

  [[maybe_unused]] CAiNavigatorLandSerializerBootstrap gCAiNavigatorLandSerializerBootstrap;
} // namespace
