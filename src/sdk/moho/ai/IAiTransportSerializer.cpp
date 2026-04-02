#include "moho/ai/IAiTransportSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiTransport.h"

using namespace moho;

namespace
{
  alignas(IAiTransportSerializer) unsigned char gIAiTransportSerializerStorage[sizeof(IAiTransportSerializer)];
  bool gIAiTransportSerializerConstructed = false;

  [[nodiscard]] IAiTransportSerializer* AcquireIAiTransportSerializer()
  {
    if (!gIAiTransportSerializerConstructed) {
      new (gIAiTransportSerializerStorage) IAiTransportSerializer();
      gIAiTransportSerializerConstructed = true;
    }

    return reinterpret_cast<IAiTransportSerializer*>(gIAiTransportSerializerStorage);
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
  void UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeSerializerNode(serializer);
  }

  [[nodiscard]] gpg::RType* CachedIAiTransportType()
  {
    gpg::RType* type = IAiTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiTransport));
      IAiTransport::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedTransportBroadcasterType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::BroadcasterEventTag<moho::EAiTransportEvent>));
    }
    return cached;
  }

  void cleanup_IAiTransportSerializer()
  {
    if (!gIAiTransportSerializerConstructed) {
      return;
    }

    IAiTransportSerializer* const serializer = AcquireIAiTransportSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~IAiTransportSerializer();
    gIAiTransportSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E4880 (FUN_005E4880, IAiTransportSerializer::Deserialize)
 */
void IAiTransportSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const transport = reinterpret_cast<IAiTransport*>(static_cast<std::uintptr_t>(objectPtr));
  auto* const broadcasterLane = static_cast<void*>(static_cast<Broadcaster*>(transport));
  gpg::RType* const broadcasterType = CachedTransportBroadcasterType();
  GPG_ASSERT(broadcasterType != nullptr);
  const gpg::RRef ownerRef{};
  archive->Read(broadcasterType, broadcasterLane, ownerRef);
}

/**
 * Address: 0x005E4890 (FUN_005E4890, IAiTransportSerializer::Serialize)
 */
void IAiTransportSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const transport = reinterpret_cast<const IAiTransport*>(static_cast<std::uintptr_t>(objectPtr));
  auto* const broadcasterLane = static_cast<const void*>(static_cast<const Broadcaster*>(transport));
  gpg::RType* const broadcasterType = CachedTransportBroadcasterType();
  GPG_ASSERT(broadcasterType != nullptr);
  const gpg::RRef ownerRef{};
  archive->Write(broadcasterType, broadcasterLane, ownerRef);
}

/**
 * Address: 0x005E9530 (FUN_005E9530)
 *
 * What it does:
 * Lazily resolves IAiTransport RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void IAiTransportSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedIAiTransportType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCEEB0 (FUN_00BCEEB0, register_IAiTransportSerializer)
 *
 * What it does:
 * Registers serializer callbacks for `IAiTransport` and installs process-exit
 * cleanup.
 */
int moho::register_IAiTransportSerializer()
{
  IAiTransportSerializer* const serializer = AcquireIAiTransportSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &IAiTransportSerializer::Deserialize;
  serializer->mSaveCallback = &IAiTransportSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_IAiTransportSerializer);
}
