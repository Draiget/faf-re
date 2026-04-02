#include "moho/ai/SAttachPointSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  alignas(SAttachPointSerializer) unsigned char gSAttachPointSerializerStorage[sizeof(SAttachPointSerializer)];
  bool gSAttachPointSerializerConstructed = false;

  [[nodiscard]] SAttachPointSerializer* AcquireSAttachPointSerializer()
  {
    if (!gSAttachPointSerializerConstructed) {
      new (gSAttachPointSerializerStorage) SAttachPointSerializer();
      gSAttachPointSerializerConstructed = true;
    }

    return reinterpret_cast<SAttachPointSerializer*>(gSAttachPointSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedSAttachPointType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SAttachPoint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return cached;
  }

  void cleanup_SAttachPointSerializer()
  {
    if (!gSAttachPointSerializerConstructed) {
      return;
    }

    SAttachPointSerializer* const serializer = AcquireSAttachPointSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~SAttachPointSerializer();
    gSAttachPointSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E42E0 (FUN_005E42E0, SAttachPointSerializer::Deserialize)
 */
void SAttachPointSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const point = reinterpret_cast<SAttachPoint*>(static_cast<std::uintptr_t>(objectPtr));
  archive->ReadUInt(&point->index);

  const gpg::RRef ownerRef{};
  gpg::RType* const vectorType = CachedVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Read(vectorType, &point->localPos, ownerRef);

  archive->ReadFloat(&point->distSq);
}

/**
 * Address: 0x005E42F0 (FUN_005E42F0, SAttachPointSerializer::Serialize)
 */
void SAttachPointSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const point = reinterpret_cast<const SAttachPoint*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteUInt(point->index);

  const gpg::RRef ownerRef{};
  gpg::RType* const vectorType = CachedVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Write(vectorType, &point->localPos, ownerRef);

  archive->WriteFloat(point->distSq);
}

void SAttachPointSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSAttachPointType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCEDF0 (FUN_00BCEDF0, register_SAttachPointSerializer)
 *
 * What it does:
 * Registers serializer callbacks for `SAttachPoint` and installs process-exit
 * cleanup.
 */
int moho::register_SAttachPointSerializer()
{
  SAttachPointSerializer* const serializer = AcquireSAttachPointSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &SAttachPointSerializer::Deserialize;
  serializer->mSaveCallback = &SAttachPointSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_SAttachPointSerializer);
}

