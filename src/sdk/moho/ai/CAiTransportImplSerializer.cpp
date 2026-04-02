#include "moho/ai/CAiTransportImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  alignas(CAiTransportImplSerializer) unsigned char gCAiTransportImplSerializerStorage[sizeof(CAiTransportImplSerializer)];
  bool gCAiTransportImplSerializerConstructed = false;

  [[nodiscard]] CAiTransportImplSerializer* AcquireCAiTransportImplSerializer()
  {
    if (!gCAiTransportImplSerializerConstructed) {
      new (gCAiTransportImplSerializerStorage) CAiTransportImplSerializer();
      gCAiTransportImplSerializerConstructed = true;
    }

    return reinterpret_cast<CAiTransportImplSerializer*>(gCAiTransportImplSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedCAiTransportImplType()
  {
    gpg::RType* type = CAiTransportImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiTransportImpl));
      CAiTransportImpl::sType = type;
    }
    return type;
  }

  void cleanup_CAiTransportImplSerializer()
  {
    if (!gCAiTransportImplSerializerConstructed) {
      return;
    }

    CAiTransportImplSerializer* const serializer = AcquireCAiTransportImplSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~CAiTransportImplSerializer();
    gCAiTransportImplSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E8590 (FUN_005E8590, Moho::CAiTransportImplSerializer::Deserialize)
 */
void CAiTransportImplSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
{
  auto* const object = reinterpret_cast<CAiTransportImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !object) {
    return;
  }

  object->MemberDeserialize(archive);
}

/**
 * Address: 0x005E85A0 (FUN_005E85A0, Moho::CAiTransportImplSerializer::Serialize)
 */
void CAiTransportImplSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
{
  auto* const object = reinterpret_cast<CAiTransportImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !object) {
    return;
  }

  object->MemberSerialize(archive);
}

/**
 * Address: 0x00BCEF50 (FUN_00BCEF50, register_CAiTransportImplSerializer)
 *
 * What it does:
 * Registers serializer callbacks for `CAiTransportImpl` and installs
 * process-exit cleanup.
 */
void moho::register_CAiTransportImplSerializer()
{
  CAiTransportImplSerializer* const serializer = AcquireCAiTransportImplSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiTransportImplSerializer::Deserialize;
  serializer->mSaveCallback = &CAiTransportImplSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_CAiTransportImplSerializer);
}

/**
 * Address: 0x005E9C30 (FUN_005E9C30)
 *
 * What it does:
 * Lazily resolves CAiTransportImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiTransportImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiTransportImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
