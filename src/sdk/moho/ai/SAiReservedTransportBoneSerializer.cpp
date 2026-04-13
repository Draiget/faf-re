#include "moho/ai/SAiReservedTransportBoneSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/SAiReservedTransportBone.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  alignas(SAiReservedTransportBoneSerializer)
    unsigned char gSAiReservedTransportBoneSerializerStorage[sizeof(SAiReservedTransportBoneSerializer)];
  bool gSAiReservedTransportBoneSerializerConstructed = false;

  [[nodiscard]] SAiReservedTransportBoneSerializer* AcquireSAiReservedTransportBoneSerializer()
  {
    if (!gSAiReservedTransportBoneSerializerConstructed) {
      new (gSAiReservedTransportBoneSerializerStorage) SAiReservedTransportBoneSerializer();
      gSAiReservedTransportBoneSerializerConstructed = true;
    }

    return reinterpret_cast<SAiReservedTransportBoneSerializer*>(gSAiReservedTransportBoneSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedWeakUnitType()
  {
    gpg::RType* type = WeakPtr<Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(WeakPtr<Unit>));
      WeakPtr<Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIntVectorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::vector<int>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSAiReservedTransportBoneType()
  {
    gpg::RType* type = SAiReservedTransportBone::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SAiReservedTransportBone));
      SAiReservedTransportBone::sType = type;
    }
    return type;
  }

  void cleanup_SAiReservedTransportBoneSerializer()
  {
    if (!gSAiReservedTransportBoneSerializerConstructed) {
      return;
    }

    SAiReservedTransportBoneSerializer* const serializer = AcquireSAiReservedTransportBoneSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~SAiReservedTransportBoneSerializer();
    gSAiReservedTransportBoneSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005EB860 (FUN_005EB860, Moho::SAiReservedTransportBone::MemberDeserialize)
 *
 * What it does:
 * Loads transport/attach indices, reserved-unit weak link, and reserved
 * attach-bone list from one archive payload.
 */
void SAiReservedTransportBone::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  archive->ReadUInt(&transportBoneIndex);
  archive->ReadUInt(&attachBoneIndex);

  const gpg::RRef ownerRef{};

  gpg::RType* const weakUnitType = CachedWeakUnitType();
  GPG_ASSERT(weakUnitType != nullptr);
  archive->Read(weakUnitType, &reservedUnit, ownerRef);

  gpg::RType* const intVectorType = CachedIntVectorType();
  GPG_ASSERT(intVectorType != nullptr);
  archive->Read(intVectorType, &reservedBones, ownerRef);
}

/**
 * Address: 0x005EB8F0 (FUN_005EB8F0, Moho::SAiReservedTransportBone::MemberSerialize)
 *
 * What it does:
 * Stores transport/attach indices, reserved-unit weak link, and reserved
 * attach-bone list into one archive payload.
 */
void SAiReservedTransportBone::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  archive->WriteUInt(transportBoneIndex);
  archive->WriteUInt(attachBoneIndex);

  const gpg::RRef ownerRef{};

  gpg::RType* const weakUnitType = CachedWeakUnitType();
  GPG_ASSERT(weakUnitType != nullptr);
  archive->Write(weakUnitType, &reservedUnit, ownerRef);

  gpg::RType* const intVectorType = CachedIntVectorType();
  GPG_ASSERT(intVectorType != nullptr);
  archive->Write(intVectorType, &reservedBones, ownerRef);
}

/**
 * Address: 0x005E40A0 (FUN_005E40A0, SAiReservedTransportBoneSerializer::Deserialize)
 */
void SAiReservedTransportBoneSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const bone = reinterpret_cast<SAiReservedTransportBone*>(static_cast<std::uintptr_t>(objectPtr));
  bone->MemberDeserialize(archive);
}

/**
 * Address: 0x005E40B0 (FUN_005E40B0, SAiReservedTransportBoneSerializer::Serialize)
 */
void SAiReservedTransportBoneSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const bone = reinterpret_cast<const SAiReservedTransportBone*>(static_cast<std::uintptr_t>(objectPtr));
  bone->MemberSerialize(archive);
}

/**
 * Address: 0x005E8F70 (FUN_005E8F70)
 *
 * What it does:
 * Lazily resolves SAiReservedTransportBone RTTI and installs load/save
 * callbacks from this helper object into the type descriptor.
 */
void SAiReservedTransportBoneSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSAiReservedTransportBoneType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCED90 (FUN_00BCED90, register_SAiReservedTransportBoneSerializer)
 *
 * What it does:
 * Registers serializer callbacks for `SAiReservedTransportBone` and installs
 * process-exit cleanup.
 */
int moho::register_SAiReservedTransportBoneSerializer()
{
  SAiReservedTransportBoneSerializer* const serializer = AcquireSAiReservedTransportBoneSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &SAiReservedTransportBoneSerializer::Deserialize;
  serializer->mSaveCallback = &SAiReservedTransportBoneSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_SAiReservedTransportBoneSerializer);
}
