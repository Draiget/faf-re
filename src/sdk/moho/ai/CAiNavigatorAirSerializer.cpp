#include "moho/ai/CAiNavigatorAirSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorAir.h"

using namespace moho;

namespace
{
  alignas(CAiNavigatorAirSerializer) unsigned char gCAiNavigatorAirSerializerStorage[sizeof(CAiNavigatorAirSerializer)] = {};
  bool gCAiNavigatorAirSerializerConstructed = false;

  [[nodiscard]] CAiNavigatorAirSerializer* AcquireCAiNavigatorAirSerializer()
  {
    if (!gCAiNavigatorAirSerializerConstructed) {
      new (gCAiNavigatorAirSerializerStorage) CAiNavigatorAirSerializer();
      gCAiNavigatorAirSerializerConstructed = true;
    }

    return reinterpret_cast<CAiNavigatorAirSerializer*>(gCAiNavigatorAirSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCAiNavigatorAirType()
  {
    gpg::RType* type = CAiNavigatorAir::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorAir));
      CAiNavigatorAir::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF6F40 (FUN_00BF6F40, cleanup_CAiNavigatorAirSerializer)
   *
   * What it does:
   * Unlinks recovered CAiNavigatorAir serializer helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiNavigatorAirSerializer()
  {
    if (!gCAiNavigatorAirSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiNavigatorAirSerializer());
  }

  void cleanup_CAiNavigatorAirSerializer_atexit()
  {
    (void)cleanup_CAiNavigatorAirSerializer();
  }
} // namespace

/**
 * Address: 0x005A56D0 (FUN_005A56D0, Moho::CAiNavigatorAirSerializer::Deserialize)
 */
void CAiNavigatorAirSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  CAiNavigatorAir::MemberDeserialize(
    reinterpret_cast<CAiNavigatorAir*>(static_cast<std::uintptr_t>(objectPtr)),
    archive
  );
}

/**
 * Address: 0x005A56E0 (FUN_005A56E0, Moho::CAiNavigatorAirSerializer::Serialize)
 */
void CAiNavigatorAirSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  CAiNavigatorAir::MemberSerialize(
    reinterpret_cast<const CAiNavigatorAir*>(static_cast<std::uintptr_t>(objectPtr)),
    archive
  );
}

/**
 * Address: 0x005A7550 (FUN_005A7550)
 *
 * What it does:
 * Lazily resolves CAiNavigatorAir RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiNavigatorAirSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiNavigatorAirType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCC880 (FUN_00BCC880, register_CAiNavigatorAirSerializer)
 *
 * What it does:
 * Initializes the global CAiNavigatorAir serializer helper callbacks and
 * installs process-exit cleanup.
 */
void moho::register_CAiNavigatorAirSerializer()
{
  CAiNavigatorAirSerializer* const serializer = AcquireCAiNavigatorAirSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiNavigatorAirSerializer::Deserialize;
  serializer->mSaveCallback = &CAiNavigatorAirSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_CAiNavigatorAirSerializer_atexit);
}

namespace
{
  struct CAiNavigatorAirSerializerBootstrap
  {
    CAiNavigatorAirSerializerBootstrap()
    {
      moho::register_CAiNavigatorAirSerializer();
    }
  };

  [[maybe_unused]] CAiNavigatorAirSerializerBootstrap gCAiNavigatorAirSerializerBootstrap;
} // namespace

