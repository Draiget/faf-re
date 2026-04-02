#include "moho/ai/IAiAttackerSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiAttacker.h"

using namespace moho;

namespace
{
  alignas(IAiAttackerSerializer) unsigned char gIAiAttackerSerializerStorage[sizeof(IAiAttackerSerializer)];
  bool gIAiAttackerSerializerConstructed = false;

  [[nodiscard]] IAiAttackerSerializer* AcquireIAiAttackerSerializer()
  {
    if (!gIAiAttackerSerializerConstructed) {
      new (gIAiAttackerSerializerStorage) IAiAttackerSerializer();
      gIAiAttackerSerializerConstructed = true;
    }

    return reinterpret_cast<IAiAttackerSerializer*>(gIAiAttackerSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedIAiAttackerType()
  {
    gpg::RType* type = IAiAttacker::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiAttacker));
      IAiAttacker::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedAttackerBroadcasterType()
  {
    gpg::RType* type = Broadcaster_EAiAttackerEvent::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(Broadcaster_EAiAttackerEvent));
      Broadcaster_EAiAttackerEvent::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF82E0 (FUN_00BF82E0, sub_BF82E0)
   *
   * What it does:
   * Unlinks recovered `IAiAttackerSerializer` helper node from intrusive
   * serializer list and restores self-links.
   */
  void cleanup_IAiAttackerSerializer()
  {
    if (!gIAiAttackerSerializerConstructed) {
      return;
    }

    IAiAttackerSerializer* const serializer = AcquireIAiAttackerSerializer();
    UnlinkSerializerNode(*serializer);
    gIAiAttackerSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005DE8D0 (FUN_005DE8D0, sub_5DE8D0)
 */
void IAiAttackerSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive) {
    return;
  }

  IAiAttacker* const attacker = reinterpret_cast<IAiAttacker*>(static_cast<std::uintptr_t>(objectPtr));
  void* const broadcasterLane = (attacker != nullptr) ? static_cast<void*>(&attacker->mListeners) : nullptr;
  gpg::RType* const broadcasterType = CachedAttackerBroadcasterType();
  GPG_ASSERT(broadcasterType != nullptr);
  const gpg::RRef ownerRef{};
  archive->Read(broadcasterType, broadcasterLane, ownerRef);
}

/**
 * Address: 0x005DE920 (FUN_005DE920, sub_5DE920)
 */
void IAiAttackerSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive) {
    return;
  }

  const IAiAttacker* const attacker = reinterpret_cast<const IAiAttacker*>(static_cast<std::uintptr_t>(objectPtr));
  const void* const broadcasterLane = (attacker != nullptr) ? static_cast<const void*>(&attacker->mListeners) : nullptr;
  gpg::RType* const broadcasterType = CachedAttackerBroadcasterType();
  GPG_ASSERT(broadcasterType != nullptr);
  const gpg::RRef ownerRef{};
  archive->Write(broadcasterType, broadcasterLane, ownerRef);
}

/**
 * Address: 0x005DBC90 (FUN_005DBC90)
 *
 * What it does:
 * Lazily resolves IAiAttacker RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void IAiAttackerSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedIAiAttackerType();

  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCE7D0 (FUN_00BCE7D0, sub_BCE7D0)
 *
 * What it does:
 * Registers serializer callbacks for `IAiAttacker` and installs process-exit
 * cleanup.
 */
int moho::register_IAiAttackerSerializer()
{
  IAiAttackerSerializer* const serializer = AcquireIAiAttackerSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &IAiAttackerSerializer::Deserialize;
  serializer->mSaveCallback = &IAiAttackerSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_IAiAttackerSerializer);
}
