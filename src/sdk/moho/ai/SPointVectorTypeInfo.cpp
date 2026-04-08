#include "moho/ai/SPointVector.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"

using namespace moho;

namespace
{
  alignas(SPointVectorTypeInfo) unsigned char gSPointVectorTypeInfoStorage[sizeof(SPointVectorTypeInfo)] = {};
  bool gSPointVectorTypeInfoConstructed = false;

  alignas(SPointVectorSerializer) unsigned char gSPointVectorSerializerStorage[sizeof(SPointVectorSerializer)] = {};
  bool gSPointVectorSerializerConstructed = false;

  [[nodiscard]] SPointVectorTypeInfo& AcquireSPointVectorTypeInfo()
  {
    if (!gSPointVectorTypeInfoConstructed) {
      new (gSPointVectorTypeInfoStorage) SPointVectorTypeInfo();
      gSPointVectorTypeInfoConstructed = true;
    }

    return *reinterpret_cast<SPointVectorTypeInfo*>(gSPointVectorTypeInfoStorage);
  }

  [[nodiscard]] SPointVectorSerializer& AcquireSPointVectorSerializer()
  {
    if (!gSPointVectorSerializerConstructed) {
      new (gSPointVectorSerializerStorage) SPointVectorSerializer();
      gSPointVectorSerializerConstructed = true;
    }

    return *reinterpret_cast<SPointVectorSerializer*>(gSPointVectorSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }

    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSPointVectorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SPointVector));
    }

    return cached;
  }

  void cleanup_SPointVectorTypeInfo()
  {
    if (!gSPointVectorTypeInfoConstructed) {
      return;
    }

    AcquireSPointVectorTypeInfo().~SPointVectorTypeInfo();
    gSPointVectorTypeInfoConstructed = false;
  }

  void cleanup_SPointVectorSerializer()
  {
    if (!gSPointVectorSerializerConstructed) {
      return;
    }

    SPointVectorSerializer& serializer = AcquireSPointVectorSerializer();
    UnlinkSerializerNode(serializer);
    serializer.~SPointVectorSerializer();
    gSPointVectorSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x0050C220 (FUN_0050C220, Moho::SPointVectorTypeInfo::SPointVectorTypeInfo)
 *
 * What it does:
 * Preregisters the `SPointVector` RTTI descriptor during startup.
 */
SPointVectorTypeInfo::SPointVectorTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(SPointVector), this);
}

/**
 * Address: 0x0050C2B0 (FUN_0050C2B0, Moho::SPointVectorTypeInfo::dtr)
 *
 * What it does:
 * Releases the `SPointVector` reflection descriptor lanes.
 */
SPointVectorTypeInfo::~SPointVectorTypeInfo() = default;

/**
 * Address: 0x0050C2A0 (FUN_0050C2A0, Moho::SPointVectorTypeInfo::GetName)
 *
 * What it does:
 * Returns the reflected type label for `SPointVector`.
 */
const char* SPointVectorTypeInfo::GetName() const
{
  return "SPointVector";
}

/**
 * Address: 0x0050C280 (FUN_0050C280, Moho::SPointVectorTypeInfo::Init)
 *
 * What it does:
 * Sets reflected width and finalizes the `SPointVector` type metadata.
 */
void SPointVectorTypeInfo::Init()
{
  size_ = sizeof(SPointVector);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x0050CF10 (FUN_0050CF10, Moho::SPointVector::MemberDeserialize)
 *
 * What it does:
 * Reads both `Vector3<float>` lanes for `SPointVector` from the archive.
 */
void SPointVector::MemberDeserialize(gpg::ReadArchive* const archive)
{
  const gpg::RRef ownerRef{};

  gpg::RType* const vectorType = CachedVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Read(vectorType, &point, ownerRef);

  archive->Read(vectorType, &vector, ownerRef);
}

/**
 * Address: 0x0050CF90 (FUN_0050CF90, Moho::SPointVector::MemberSerialize)
 *
 * What it does:
 * Writes both `Vector3<float>` lanes for `SPointVector` into the archive.
 */
void SPointVector::MemberSerialize(gpg::WriteArchive* const archive) const
{
  const gpg::RRef ownerRef{};

  gpg::RType* const vectorType = CachedVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Write(vectorType, &point, ownerRef);

  archive->Write(vectorType, &vector, ownerRef);
}

/**
 * What it does:
 * Binds the `SPointVector` serializer callbacks into reflected RTTI.
 */
void SPointVectorSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSPointVectorType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x0050C360 (FUN_0050C360, Moho::SPointVectorSerializer::Deserialize)
 *
 * What it does:
 * Forwards archive load requests into `SPointVector::MemberDeserialize`.
 */
void SPointVectorSerializer::Deserialize(gpg::ReadArchive* const archive, SPointVector* const value)
{
  value->MemberDeserialize(archive);
}

/**
 * Address: 0x0050C370 (FUN_0050C370, Moho::SPointVectorSerializer::Serialize)
 *
 * What it does:
 * Forwards archive save requests into `SPointVector::MemberSerialize`.
 */
void SPointVectorSerializer::Serialize(gpg::WriteArchive* const archive, SPointVector* const value)
{
  value->MemberSerialize(archive);
}

/**
 * Address: 0x00BC7E00 (FUN_00BC7E00, register_SPointVectorSerializer)
 *
 * What it does:
 * Registers serializer callbacks for `SPointVector` and installs process-exit
 * cleanup.
 */
void moho::register_SPointVectorSerializer()
{
  SPointVectorSerializer& serializer = AcquireSPointVectorSerializer();
  InitializeSerializerNode(serializer);
  serializer.mLoadCallback = reinterpret_cast<gpg::RType::load_func_t>(&SPointVectorSerializer::Deserialize);
  serializer.mSaveCallback = reinterpret_cast<gpg::RType::save_func_t>(&SPointVectorSerializer::Serialize);
  (void)std::atexit(&cleanup_SPointVectorSerializer);
}

/**
 * Address: 0x00BC7DE0 (FUN_00BC7DE0, register_SPointVectorTypeInfo)
 *
 * What it does:
 * Constructs the startup-owned `SPointVectorTypeInfo` descriptor and installs
 * process-exit cleanup.
 */
int moho::register_SPointVectorTypeInfo()
{
  (void)AcquireSPointVectorTypeInfo();
  return std::atexit(&cleanup_SPointVectorTypeInfo);
}

namespace
{
  struct SPointVectorSerializerBootstrap
  {
    SPointVectorSerializerBootstrap()
    {
      (void)moho::register_SPointVectorSerializer();
    }
  };

  struct SPointVectorTypeInfoBootstrap
  {
    SPointVectorTypeInfoBootstrap()
    {
      (void)moho::register_SPointVectorTypeInfo();
    }
  };

  [[maybe_unused]] SPointVectorSerializerBootstrap gSPointVectorSerializerBootstrap;
  [[maybe_unused]] SPointVectorTypeInfoBootstrap gSPointVectorTypeInfoBootstrap;
} // namespace
