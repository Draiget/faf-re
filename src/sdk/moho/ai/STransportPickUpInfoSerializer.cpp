#include "moho/ai/STransportPickUpInfoSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  alignas(STransportPickUpInfoSerializer)
    unsigned char gSTransportPickUpInfoSerializerStorage[sizeof(STransportPickUpInfoSerializer)];
  bool gSTransportPickUpInfoSerializerConstructed = false;

  [[nodiscard]] STransportPickUpInfoSerializer* AcquireSTransportPickUpInfoSerializer()
  {
    if (!gSTransportPickUpInfoSerializerConstructed) {
      new (gSTransportPickUpInfoSerializerStorage) STransportPickUpInfoSerializer();
      gSTransportPickUpInfoSerializerConstructed = true;
    }

    return reinterpret_cast<STransportPickUpInfoSerializer*>(gSTransportPickUpInfoSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedSTransportPickUpInfoType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(STransportPickUpInfo));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSCoordsVec2Type()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SCoordsVec2));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Quaternion<float>));
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

  [[nodiscard]] gpg::RType* CachedEntitySetTemplateUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SEntitySetTemplateUnit));
    }
    return cached;
  }

  void cleanup_STransportPickUpInfoSerializer()
  {
    if (!gSTransportPickUpInfoSerializerConstructed) {
      return;
    }

    STransportPickUpInfoSerializer* const serializer = AcquireSTransportPickUpInfoSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~STransportPickUpInfoSerializer();
    gSTransportPickUpInfoSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E4660 (FUN_005E4660, STransportPickUpInfoSerializer::Deserialize)
 */
void STransportPickUpInfoSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const info = reinterpret_cast<STransportPickUpInfo*>(static_cast<std::uintptr_t>(objectPtr));
  const gpg::RRef ownerRef{};

  gpg::RType* const coordsType = CachedSCoordsVec2Type();
  GPG_ASSERT(coordsType != nullptr);
  archive->Read(coordsType, &info->mFallbackPos, ownerRef);

  gpg::RType* const orientationType = CachedQuaternionfType();
  GPG_ASSERT(orientationType != nullptr);
  archive->Read(orientationType, &info->mOri, ownerRef);

  gpg::RType* const vectorType = CachedVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Read(vectorType, &info->mPos, ownerRef);

  gpg::RType* const unitSetType = CachedEntitySetTemplateUnitType();
  GPG_ASSERT(unitSetType != nullptr);
  archive->Read(unitSetType, &info->mUnits, ownerRef);

  bool hasSpace = false;
  archive->ReadBool(&hasSpace);
  info->mHasSpace = static_cast<std::uint8_t>(hasSpace ? 1 : 0);
}

/**
 * Address: 0x005E4670 (FUN_005E4670, STransportPickUpInfoSerializer::Serialize)
 */
void STransportPickUpInfoSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const info = reinterpret_cast<const STransportPickUpInfo*>(static_cast<std::uintptr_t>(objectPtr));
  const gpg::RRef ownerRef{};

  gpg::RType* const coordsType = CachedSCoordsVec2Type();
  GPG_ASSERT(coordsType != nullptr);
  archive->Write(coordsType, &info->mFallbackPos, ownerRef);

  gpg::RType* const orientationType = CachedQuaternionfType();
  GPG_ASSERT(orientationType != nullptr);
  archive->Write(orientationType, &info->mOri, ownerRef);

  gpg::RType* const vectorType = CachedVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Write(vectorType, &info->mPos, ownerRef);

  gpg::RType* const unitSetType = CachedEntitySetTemplateUnitType();
  GPG_ASSERT(unitSetType != nullptr);
  archive->Write(unitSetType, &info->mUnits, ownerRef);

  archive->WriteBool(info->mHasSpace != 0);
}

void STransportPickUpInfoSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSTransportPickUpInfoType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCEE50 (FUN_00BCEE50, register_STransportPickUpInfoSerializer)
 *
 * What it does:
 * Registers serializer callbacks for `STransportPickUpInfo` and installs
 * process-exit cleanup.
 */
int moho::register_STransportPickUpInfoSerializer()
{
  STransportPickUpInfoSerializer* const serializer = AcquireSTransportPickUpInfoSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &STransportPickUpInfoSerializer::Deserialize;
  serializer->mSaveCallback = &STransportPickUpInfoSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_STransportPickUpInfoSerializer);
}

