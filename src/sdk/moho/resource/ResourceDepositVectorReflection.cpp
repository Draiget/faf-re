#include "moho/resource/ResourceDepositVectorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/ResourceDeposit.h"

namespace
{
  using ResourceDepositVector = msvc8::vector<moho::ResourceDeposit>;

  alignas(gpg::RVectorType_ResourceDeposit) unsigned char
    gResourceDepositVectorTypeStorage[sizeof(gpg::RVectorType_ResourceDeposit)];
  bool gResourceDepositVectorTypeConstructed = false;

  [[nodiscard]] gpg::RType* CachedResourceDepositType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::ResourceDeposit));
    }
    return cached;
  }

  [[nodiscard]] gpg::RVectorType_ResourceDeposit& AcquireResourceDepositVectorType()
  {
    if (!gResourceDepositVectorTypeConstructed) {
      new (gResourceDepositVectorTypeStorage) gpg::RVectorType_ResourceDeposit();
      gResourceDepositVectorTypeConstructed = true;
    }

    return *reinterpret_cast<gpg::RVectorType_ResourceDeposit*>(gResourceDepositVectorTypeStorage);
  }

  void cleanup_VectorResourceDepositTypeStorage()
  {
    if (!gResourceDepositVectorTypeConstructed) {
      return;
    }

    AcquireResourceDepositVectorType().~RVectorType_ResourceDeposit();
    gResourceDepositVectorTypeConstructed = false;
  }

  struct ResourceDepositVectorReflectionBootstrap
  {
    ResourceDepositVectorReflectionBootstrap()
    {
      (void)moho::register_VectorResourceDepositTypeAtexit();
    }
  };

  ResourceDepositVectorReflectionBootstrap gResourceDepositVectorReflectionBootstrap;
} // namespace

/**
 * Address: 0x005474C0 (FUN_005474C0, gpg::RVectorType_ResourceDeposit::GetName)
 *
 * What it does:
 * Builds and caches lexical reflection name `vector<element>` for
 * `msvc8::vector<moho::ResourceDeposit>`.
 */
const char* gpg::RVectorType_ResourceDeposit::GetName() const
{
  static msvc8::string sName{};
  if (sName.empty()) {
    const gpg::RType* const elementType = CachedResourceDepositType();
    const char* const elementName = elementType ? elementType->GetName() : "ResourceDeposit";
    sName = gpg::STR_Printf("vector<%s>", elementName);
  }
  return sName.c_str();
}

/**
 * Address: 0x00547580 (FUN_00547580, gpg::RVectorType_ResourceDeposit::GetLexical)
 *
 * What it does:
 * Returns base lexical text plus reflected vector size for one
 * `msvc8::vector<moho::ResourceDeposit>` instance.
 */
msvc8::string gpg::RVectorType_ResourceDeposit::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00547610 (FUN_00547610, gpg::RVectorType_ResourceDeposit::IsIndexed)
 */
const gpg::RIndexed* gpg::RVectorType_ResourceDeposit::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00547560 (FUN_00547560, gpg::RVectorType_ResourceDeposit::Init)
 *
 * What it does:
 * Sets vector metadata and installs reflected archive callbacks.
 */
void gpg::RVectorType_ResourceDeposit::Init()
{
  size_ = sizeof(ResourceDepositVector);
  version_ = 1;
  serLoadFunc_ = &RVectorType_ResourceDeposit::SerLoad;
  serSaveFunc_ = &RVectorType_ResourceDeposit::SerSave;
}

/**
 * Address: 0x00547950 (FUN_00547950, gpg::RVectorType_ResourceDeposit::SerLoad)
 *
 * What it does:
 * Reads element count, deserializes each `ResourceDeposit`, and replaces
 * destination storage in one assignment.
 */
void gpg::RVectorType_ResourceDeposit::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const storage = reinterpret_cast<ResourceDepositVector*>(objectPtr);
  unsigned int count = 0u;
  archive->ReadUInt(&count);

  ResourceDepositVector loaded{};
  loaded.reserve(static_cast<std::size_t>(count));

  gpg::RType* const elementType = CachedResourceDepositType();
  if (!elementType) {
    *storage = loaded;
    return;
  }

  for (unsigned int i = 0u; i < count; ++i) {
    moho::ResourceDeposit element{};
    gpg::RRef owner{};
    archive->Read(elementType, &element, owner);
    loaded.push_back(element);
  }

  *storage = loaded;
}

/**
 * Address: 0x00547A50 (FUN_00547A50, gpg::RVectorType_ResourceDeposit::SerSave)
 *
 * What it does:
 * Writes vector element count and serializes each `ResourceDeposit` payload
 * lane with reflected `WriteArchive::Write`.
 */
void gpg::RVectorType_ResourceDeposit::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  if (!archive) {
    return;
  }

  const auto* const storage = reinterpret_cast<const ResourceDepositVector*>(objectPtr);
  const unsigned int count = storage ? static_cast<unsigned int>(storage->size()) : 0u;
  archive->WriteUInt(count);

  if (!storage || count == 0u) {
    return;
  }

  gpg::RType* const elementType = CachedResourceDepositType();
  if (!elementType) {
    return;
  }

  const gpg::RRef emptyOwner{};
  const gpg::RRef& effectiveOwner = ownerRef ? *ownerRef : emptyOwner;
  for (const moho::ResourceDeposit& element : *storage) {
    archive->Write(elementType, &element, effectiveOwner);
  }
}

/**
 * Address: 0x00547690 (FUN_00547690, gpg::RVectorType_ResourceDeposit::SubscriptIndex)
 */
gpg::RRef gpg::RVectorType_ResourceDeposit::SubscriptIndex(void* const obj, const int ind) const
{
  gpg::RRef out{};
  out.mType = CachedResourceDepositType();
  out.mObj = nullptr;

  auto* const storage = static_cast<ResourceDepositVector*>(obj);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_ResourceDeposit(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x00547620 (FUN_00547620, gpg::RVectorType_ResourceDeposit::GetCount)
 */
size_t gpg::RVectorType_ResourceDeposit::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const ResourceDepositVector*>(obj);
  return storage ? storage->size() : 0u;
}

/**
 * Address: 0x00547650 (FUN_00547650, gpg::RVectorType_ResourceDeposit::SetCount)
 */
void gpg::RVectorType_ResourceDeposit::SetCount(void* const obj, const int count) const
{
  if (!obj || count < 0) {
    return;
  }

  auto* const storage = static_cast<ResourceDepositVector*>(obj);
  storage->resize(static_cast<std::size_t>(count));
}

gpg::RType* moho::preregister_VectorResourceDepositType()
{
  auto* const typeInfo = &AcquireResourceDepositVectorType();
  gpg::PreRegisterRType(typeid(ResourceDepositVector), typeInfo);
  return typeInfo;
}

int moho::register_VectorResourceDepositTypeAtexit()
{
  (void)preregister_VectorResourceDepositType();
  return std::atexit(&cleanup_VectorResourceDepositTypeStorage);
}

