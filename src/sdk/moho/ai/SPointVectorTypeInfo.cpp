#include "moho/ai/SPointVector.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"

using namespace moho;

namespace
{
  using SPointVectorVector = msvc8::vector<moho::SPointVector>;
  using SPointVectorVectorType = gpg::RVectorType<moho::SPointVector>;

  alignas(SPointVectorTypeInfo) unsigned char gSPointVectorTypeInfoStorage[sizeof(SPointVectorTypeInfo)] = {};
  bool gSPointVectorTypeInfoConstructed = false;

  alignas(SPointVectorSerializer) unsigned char gSPointVectorSerializerStorage[sizeof(SPointVectorSerializer)] = {};
  bool gSPointVectorSerializerConstructed = false;

  alignas(SPointVectorVectorType) unsigned char gSPointVectorVectorTypeStorage[sizeof(SPointVectorVectorType)] = {};
  bool gSPointVectorVectorTypeConstructed = false;

  msvc8::string gSPointVectorVectorTypeName;
  bool gSPointVectorVectorTypeNameCleanupRegistered = false;

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

  [[nodiscard]] SPointVectorVectorType& AcquireSPointVectorVectorType()
  {
    if (!gSPointVectorVectorTypeConstructed) {
      new (gSPointVectorVectorTypeStorage) SPointVectorVectorType();
      gSPointVectorVectorTypeConstructed = true;
    }

    return *reinterpret_cast<SPointVectorVectorType*>(gSPointVectorVectorTypeStorage);
  }

  [[nodiscard]] SPointVectorVectorType* PeekSPointVectorVectorType() noexcept
  {
    if (!gSPointVectorVectorTypeConstructed) {
      return nullptr;
    }

    return reinterpret_cast<SPointVectorVectorType*>(gSPointVectorVectorTypeStorage);
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

  [[nodiscard]] moho::SPointVector ZeroSPointVector() noexcept
  {
    const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
    return moho::SPointVector{zero, zero};
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

  /**
   * Address: 0x00BF6350 (FUN_00BF6350, cleanup_SPointVectorVectorTypeName)
   *
   * What it does:
   * Releases cached lexical name storage for `vector<SPointVector>`.
   */
  void cleanup_SPointVectorVectorTypeName()
  {
    gSPointVectorVectorTypeName = msvc8::string{};
    gSPointVectorVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00BF63E0 (FUN_00BF63E0, cleanup_SPointVectorVectorType)
   *
   * What it does:
   * Destroys startup-owned `vector<SPointVector>` reflection storage lanes.
   */
  void cleanup_SPointVectorVectorType()
  {
    SPointVectorVectorType* const type = PeekSPointVectorVectorType();
    if (!type) {
      return;
    }

    type->~SPointVectorVectorType();
    gSPointVectorVectorTypeConstructed = false;
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
 * Address: 0x0057DF60 (FUN_0057DF60, gpg::RVectorType_SPointVector::GetName)
 *
 * What it does:
 * Lazily builds and caches the reflected type label `vector<SPointVector>`.
 */
const char* gpg::RVectorType<moho::SPointVector>::GetName() const
{
  if (gSPointVectorVectorTypeName.empty()) {
    const gpg::RType* const elementType = CachedSPointVectorType();
    const char* const elementName = elementType ? elementType->GetName() : "SPointVector";
    gSPointVectorVectorTypeName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "SPointVector");

    if (!gSPointVectorVectorTypeNameCleanupRegistered) {
      gSPointVectorVectorTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_SPointVectorVectorTypeName);
    }
  }

  return gSPointVectorVectorTypeName.c_str();
}

/**
 * Address: 0x0057E020 (FUN_0057E020, gpg::RVectorType_SPointVector::GetLexical)
 *
 * What it does:
 * Returns one base lexical string plus `size=<count>` for reflected
 * `vector<SPointVector>` payloads.
 */
msvc8::string gpg::RVectorType<moho::SPointVector>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x0057E0B0 (FUN_0057E0B0, gpg::RVectorType_SPointVector::IsIndexed)
 *
 * What it does:
 * Exposes the `RIndexed` subobject for `vector<SPointVector>`.
 */
const gpg::RIndexed* gpg::RVectorType<moho::SPointVector>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x0057E000 (FUN_0057E000, gpg::RVectorType_SPointVector::Init)
 *
 * What it does:
 * Initializes reflected size/version lanes and vector serializer callbacks.
 */
void gpg::RVectorType<moho::SPointVector>::Init()
{
  size_ = sizeof(SPointVectorVector);
  version_ = 1;
  serLoadFunc_ = &gpg::RVectorType<moho::SPointVector>::SerLoad;
  serSaveFunc_ = &gpg::RVectorType<moho::SPointVector>::SerSave;
}

/**
 * Address: 0x0057F2D0 (FUN_0057F2D0, gpg::RVectorType_SPointVector::SerLoad)
 *
 * What it does:
 * Loads one `vector<SPointVector>` payload from archive and replaces
 * destination storage in one assignment.
 */
void gpg::RVectorType<moho::SPointVector>::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const storage = reinterpret_cast<SPointVectorVector*>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  unsigned int count = 0;
  archive->ReadUInt(&count);

  SPointVectorVector loaded{};
  loaded.reserve(static_cast<std::size_t>(count));

  gpg::RType* const elementType = CachedSPointVectorType();
  const gpg::RRef ownerRef{};
  for (unsigned int i = 0; i < count; ++i) {
    moho::SPointVector value = ZeroSPointVector();
    if (elementType) {
      archive->Read(elementType, &value, ownerRef);
    } else {
      value.MemberDeserialize(archive);
    }
    loaded.push_back(value);
  }

  *storage = loaded;
}

/**
 * Address: 0x0057F400 (FUN_0057F400, gpg::RVectorType_SPointVector::SerSave)
 *
 * What it does:
 * Saves one `vector<SPointVector>` payload to archive element-by-element.
 */
void gpg::RVectorType<moho::SPointVector>::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const storage = reinterpret_cast<const SPointVectorVector*>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  const unsigned int count = static_cast<unsigned int>(storage->size());
  archive->WriteUInt(count);
  if (count == 0u) {
    return;
  }

  gpg::RType* const elementType = CachedSPointVectorType();
  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  for (unsigned int i = 0; i < count; ++i) {
    const moho::SPointVector& value = (*storage)[static_cast<std::size_t>(i)];
    if (elementType) {
      archive->Write(elementType, &value, owner);
    } else {
      value.MemberSerialize(archive);
    }
  }
}

/**
 * Address: 0x0057E160 (FUN_0057E160, gpg::RVectorType_SPointVector::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference at index `ind`.
 */
gpg::RRef gpg::RVectorType<moho::SPointVector>::SubscriptIndex(void* const obj, const int ind) const
{
  gpg::RRef out{};
  gpg::RRef_SPointVector(&out, nullptr);

  auto* const storage = static_cast<SPointVectorVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(storage != nullptr && static_cast<std::size_t>(ind) < storage->size());
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_SPointVector(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x0057E0C0 (FUN_0057E0C0, gpg::RVectorType_SPointVector::GetCount)
 *
 * What it does:
 * Returns element count for one reflected `vector<SPointVector>` payload.
 */
size_t gpg::RVectorType<moho::SPointVector>::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const SPointVectorVector*>(obj);
  return storage ? storage->size() : 0u;
}

/**
 * Address: 0x0057E0F0 (FUN_0057E0F0, gpg::RVectorType_SPointVector::SetCount)
 *
 * What it does:
 * Resizes one reflected `vector<SPointVector>` payload using zero
 * `SPointVector` fill on growth lanes.
 */
void gpg::RVectorType<moho::SPointVector>::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<SPointVectorVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  const moho::SPointVector fill = ZeroSPointVector();
  storage->resize(static_cast<std::size_t>(count), fill);
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

/**
 * Address: 0x005825A0 (FUN_005825A0, register_SPointVectorVectorType)
 *
 * What it does:
 * Constructs/preregisters RTTI for `msvc8::vector<moho::SPointVector>`.
 */
gpg::RType* moho::register_SPointVectorVectorType()
{
  auto* const type = &AcquireSPointVectorVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::SPointVector>), type);
  return type;
}

/**
 * Address: 0x00BCB470 (FUN_00BCB470, register_SPointVectorVectorType_AtExit)
 *
 * What it does:
 * Registers `vector<SPointVector>` reflection and installs `atexit` cleanup.
 */
int moho::register_SPointVectorVectorType_AtExit()
{
  (void)register_SPointVectorVectorType();
  return std::atexit(&cleanup_SPointVectorVectorType);
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

  struct SPointVectorVectorTypeBootstrap
  {
    SPointVectorVectorTypeBootstrap()
    {
      (void)moho::register_SPointVectorVectorType_AtExit();
    }
  };

  [[maybe_unused]] SPointVectorSerializerBootstrap gSPointVectorSerializerBootstrap;
  [[maybe_unused]] SPointVectorTypeInfoBootstrap gSPointVectorTypeInfoBootstrap;
  [[maybe_unused]] SPointVectorVectorTypeBootstrap gSPointVectorVectorTypeBootstrap;
} // namespace
