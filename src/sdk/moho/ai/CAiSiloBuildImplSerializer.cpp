#include "moho/ai/CAiSiloBuildImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiSiloBuildImpl.h"

using namespace moho;

namespace
{
  alignas(SSiloBuildInfoSerializer) unsigned char gSSiloBuildInfoSerializerStorage[sizeof(SSiloBuildInfoSerializer)];
  bool gSSiloBuildInfoSerializerConstructed = false;

  alignas(CAiSiloBuildImplSerializer) unsigned char gCAiSiloBuildImplSerializerStorage[sizeof(CAiSiloBuildImplSerializer)];
  bool gCAiSiloBuildImplSerializerConstructed = false;

  [[nodiscard]] SSiloBuildInfoSerializer* AcquireSSiloBuildInfoSerializer()
  {
    if (!gSSiloBuildInfoSerializerConstructed) {
      new (gSSiloBuildInfoSerializerStorage) SSiloBuildInfoSerializer();
      gSSiloBuildInfoSerializerConstructed = true;
    }

    return reinterpret_cast<SSiloBuildInfoSerializer*>(gSSiloBuildInfoSerializerStorage);
  }

  [[nodiscard]] CAiSiloBuildImplSerializer* AcquireCAiSiloBuildImplSerializer()
  {
    if (!gCAiSiloBuildImplSerializerConstructed) {
      new (gCAiSiloBuildImplSerializerStorage) CAiSiloBuildImplSerializer();
      gCAiSiloBuildImplSerializerConstructed = true;
    }

    return reinterpret_cast<CAiSiloBuildImplSerializer*>(gCAiSiloBuildImplSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedSSiloBuildInfoType()
  {
    gpg::RType* type = SSiloBuildInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SSiloBuildInfo));
      SSiloBuildInfo::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCAiSiloBuildImplType()
  {
    gpg::RType* type = CAiSiloBuildImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiSiloBuildImpl));
      CAiSiloBuildImpl::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF7EA0 (FUN_00BF7EA0, cleanup_SSiloBuildInfoSerializer)
   *
   * What it does:
   * Unlinks the static serializer helper node and tears down local storage.
   */
  void cleanup_SSiloBuildInfoSerializer()
  {
    if (!gSSiloBuildInfoSerializerConstructed) {
      return;
    }

    SSiloBuildInfoSerializer* const serializer = AcquireSSiloBuildInfoSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~SSiloBuildInfoSerializer();
    gSSiloBuildInfoSerializerConstructed = false;
  }

  /**
   * Address: 0x00BF7F60 (FUN_00BF7F60, cleanup_CAiSiloBuildImplSerializer)
   *
   * What it does:
   * Unlinks the static serializer helper node and tears down local storage.
   */
  void cleanup_CAiSiloBuildImplSerializer()
  {
    if (!gCAiSiloBuildImplSerializerConstructed) {
      return;
    }

    CAiSiloBuildImplSerializer* const serializer = AcquireCAiSiloBuildImplSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~CAiSiloBuildImplSerializer();
    gCAiSiloBuildImplSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005CEC70 (FUN_005CEC70, Moho::SSiloBuildInfoSerializer::Deserialize)
 */
void SSiloBuildInfoSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const info = reinterpret_cast<SSiloBuildInfo*>(static_cast<std::uintptr_t>(objectPtr));
  SSiloBuildInfo::MemberDeserialize(archive, info);
}

/**
 * Address: 0x005CEC80 (FUN_005CEC80, Moho::SSiloBuildInfoSerializer::Serialize)
 */
void SSiloBuildInfoSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const info = reinterpret_cast<const SSiloBuildInfo*>(static_cast<std::uintptr_t>(objectPtr));
  SSiloBuildInfo::MemberSerialize(info, archive);
}

/**
 * Address: 0x005CFB60 (FUN_005CFB60)
 *
 * What it does:
 * Lazily resolves `SSiloBuildInfo` RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void SSiloBuildInfoSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSSiloBuildInfoType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCE0B0 (FUN_00BCE0B0, register_SSiloBuildInfoSerializer)
 *
 * What it does:
 * Registers serializer callbacks for `SSiloBuildInfo` and installs
 * process-exit cleanup.
 */
int moho::register_SSiloBuildInfoSerializer()
{
  SSiloBuildInfoSerializer* const serializer = AcquireSSiloBuildInfoSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &SSiloBuildInfoSerializer::Deserialize;
  serializer->mSaveCallback = &SSiloBuildInfoSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_SSiloBuildInfoSerializer);
}

/**
 * Address: 0x005CF8D0 (FUN_005CF8D0, Moho::CAiSiloBuildImplSerializer::Deserialize)
 */
void CAiSiloBuildImplSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const object = reinterpret_cast<CAiSiloBuildImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !object) {
    return;
  }

  object->MemberDeserialize(archive);
}

/**
 * Address: 0x005CF8E0 (FUN_005CF8E0, Moho::CAiSiloBuildImplSerializer::Serialize)
 */
void CAiSiloBuildImplSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const object = reinterpret_cast<const CAiSiloBuildImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !object) {
    return;
  }

  object->MemberSerialize(archive);
}

/**
 * Address: 0x00BCE150 (FUN_00BCE150, register_CAiSiloBuildImplSerializer)
 *
 * What it does:
 * Registers serializer callbacks for `CAiSiloBuildImpl` and installs
 * process-exit cleanup.
 */
int moho::register_CAiSiloBuildImplSerializer()
{
  CAiSiloBuildImplSerializer* const serializer = AcquireCAiSiloBuildImplSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiSiloBuildImplSerializer::Deserialize;
  serializer->mSaveCallback = &CAiSiloBuildImplSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_CAiSiloBuildImplSerializer);
}

/**
 * Address: 0x005CFF30 (FUN_005CFF30)
 *
 * void ()
 *
 * IDA signature:
 * void (__cdecl *__thiscall sub_5CFF30(_DWORD *this))(gpg::ReadArchive *, int, int, gpg::RRef *);
 *
 * What it does:
 * Lazily resolves CAiSiloBuildImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiSiloBuildImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiSiloBuildImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
