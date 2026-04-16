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

  /**
   * Address: 0x005EC3F0 (FUN_005EC3F0, j_Moho::CAiTransportImpl::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiTransportImpl::MemberSerialize`.
   */
  [[maybe_unused]] void CAiTransportImplMemberSerializeThunk(
    moho::CAiTransportImpl* const object, gpg::WriteArchive* const archive
  )
  {
    if (!object || !archive) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x005EDCC0 (FUN_005EDCC0, j_Moho::CAiTransportImpl::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiTransportImpl::MemberSerialize`.
   */
  [[maybe_unused]] void CAiTransportImplMemberSerializeThunkSecondary(
    moho::CAiTransportImpl* const object, gpg::WriteArchive* const archive
  )
  {
    if (!object || !archive) {
      return;
    }

    object->MemberSerialize(archive);
  }

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

  /**
   * Address: 0x005E85E0 (FUN_005E85E0)
   *
   * What it does:
   * Splices this serializer helper node out of its intrusive lane when linked,
   * then resets helper links to self and returns the self node pointer.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCAiTransportImplSerializerHelperNodeVariantA(
    CAiTransportImplSerializer& serializer
  ) noexcept
  {
    UnlinkSerializerNode(serializer);
    return SerializerSelfNode(serializer);
  }

  /**
   * Address: 0x005E8610 (FUN_005E8610)
   *
   * What it does:
   * Secondary helper-node unlink/reset variant that preserves the same
   * intrusive unlink semantics and returns the helper self node.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCAiTransportImplSerializerHelperNodeVariantB(
    CAiTransportImplSerializer& serializer
  ) noexcept
  {
    return UnlinkCAiTransportImplSerializerHelperNodeVariantA(serializer);
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

  /**
   * Address: 0x005E85B0 (FUN_005E85B0)
   *
   * What it does:
   * Initializes callback lanes for global `CAiTransportImplSerializer` helper
   * storage and returns that helper object.
   */
  [[maybe_unused]] [[nodiscard]] CAiTransportImplSerializer* InitializeCAiTransportImplSerializerStartupThunk()
  {
    CAiTransportImplSerializer* const serializer = AcquireCAiTransportImplSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mLoadCallback = &CAiTransportImplSerializer::Deserialize;
    serializer->mSaveCallback = &CAiTransportImplSerializer::Serialize;
    return serializer;
  }

  void cleanup_CAiTransportImplSerializer()
  {
    if (!gCAiTransportImplSerializerConstructed) {
      return;
    }

    CAiTransportImplSerializer* const serializer = AcquireCAiTransportImplSerializer();
    (void)UnlinkCAiTransportImplSerializerHelperNodeVariantA(*serializer);
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
void CAiTransportImplSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
)
{
  auto* const object = reinterpret_cast<CAiTransportImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !object) {
    return;
  }

  if (ownerRef != nullptr) {
    object->MemberSerialize(archive);
    return;
  }

  CAiTransportImplMemberSerializeThunk(object, archive);
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
