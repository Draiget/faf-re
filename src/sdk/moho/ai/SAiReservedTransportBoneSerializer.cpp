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
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeSerializerNode(serializer);
    return SerializerSelfNode(serializer);
  }

  /**
   * Address: 0x005E40F0 (FUN_005E40F0)
   *
   * What it does:
   * Unlinks the global `SAiReservedTransportBoneSerializer` helper node from
   * the intrusive serializer chain and restores it to a self-linked node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_SAiReservedTransportBoneSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(*AcquireSAiReservedTransportBoneSerializer());
  }

  /**
   * Address: 0x005E4120 (FUN_005E4120)
   *
   * What it does:
   * Secondary unlink/reset thunk for the global
   * `SAiReservedTransportBoneSerializer` helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_SAiReservedTransportBoneSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(*AcquireSAiReservedTransportBoneSerializer());
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
    (void)cleanup_SAiReservedTransportBoneSerializerStartupThunkA();
    serializer->~SAiReservedTransportBoneSerializer();
    gSAiReservedTransportBoneSerializerConstructed = false;
  }

} // namespace

/**
 * Address: 0x005E8230 (FUN_005E8230, sub_5E8230)
 *
 * What it does:
 * Releases one reserved-bones vector heap payload, clears the vector lanes,
 * and unlinks the reserved-unit weak node from its owner chain.
 */
void* moho::ResetReservedTransportBoneEntry(SAiReservedTransportBone& bone)
{
  auto& reservedBonesView = msvc8::AsVectorRuntimeView(bone.reservedBones);
  if (reservedBonesView.begin != nullptr) {
    ::operator delete(reservedBonesView.begin);
  }

  reservedBonesView.begin = nullptr;
  reservedBonesView.end = nullptr;
  reservedBonesView.capacityEnd = nullptr;

  void* result = bone.reservedUnit.ownerLinkSlot;
  if (result != nullptr) {
    auto** linkSlot = reinterpret_cast<WeakPtr<Unit>**>(result);
    WeakPtr<Unit>* const thisNode = &bone.reservedUnit;
    if (*linkSlot != thisNode) {
      do {
        linkSlot = &(*linkSlot)->nextInOwner;
      } while (*linkSlot != thisNode);
    }
    *linkSlot = thisNode->nextInOwner;
    result = linkSlot;
  }

  return result;
}

/**
 * Address: 0x005EE820 (FUN_005EE820, sub_5EE820)
 *
 * What it does:
 * Jump-only alias lane that forwards to `ResetReservedTransportBoneEntry`.
 */
void* moho::ResetReservedTransportBoneEntryThunkA(SAiReservedTransportBone& bone)
{
  return ResetReservedTransportBoneEntry(bone);
}

/**
 * Address: 0x005EF8B0 (FUN_005EF8B0, sub_5EF8B0)
 *
 * What it does:
 * Jump-only alias lane that forwards to `ResetReservedTransportBoneEntry`.
 */
void* moho::ResetReservedTransportBoneEntryThunkB(SAiReservedTransportBone& bone)
{
  return ResetReservedTransportBoneEntry(bone);
}

/**
 * Address: 0x005EA550 (FUN_005EA550, std::vector_SAiReservedTransportBone::reset_storage)
 *
 * What it does:
 * Destroys one `vector<SAiReservedTransportBone>` payload, releases the
 * backing heap block, and clears the vector storage lanes to empty.
 */
void moho::ResetReservedTransportBoneVectorStorage(msvc8::vector<SAiReservedTransportBone>& storage)
{
  auto& view = msvc8::AsVectorRuntimeView(storage);
  if (view.begin != nullptr) {
    (void)DestroyReservedTransportBoneRange(view.begin, view.end);
    ::operator delete(view.begin);
  }

  view.begin = nullptr;
  view.end = nullptr;
  view.capacityEnd = nullptr;
}

/**
 * Address: 0x005EE360 (FUN_005EE360, destroy_SAiReservedTransportBone_range)
 *
 * What it does:
 * Walks one half-open bone range, frees each reserved-bones heap lane, zeros
 * vector pointers, and unlinks each reserved-unit weak node from owner chain.
 */
void* moho::DestroyReservedTransportBoneRange(SAiReservedTransportBone* begin, SAiReservedTransportBone* end)
{
  void* result = begin;
  for (SAiReservedTransportBone* bone = begin; bone != end; ++bone) {
    result = ResetReservedTransportBoneEntry(*bone);
  }

  return result;
}

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
  return std::atexit(&cleanup_SAiReservedTransportBoneSerializer);
}
