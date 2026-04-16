#include "moho/resource/ResourceDepositVectorReflection.h"

#include <cstddef>
#include <cstdlib>
#include <cstdint>
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

  struct ResourceDepositVectorFieldView
  {
    std::uint8_t reserved00[0x0C];
    ResourceDepositVector mDeposits;
  };

  static_assert(
    offsetof(ResourceDepositVectorFieldView, mDeposits) == 0x0C,
    "ResourceDepositVectorFieldView::mDeposits offset must be 0x0C"
  );

  [[nodiscard]] gpg::RType* CachedResourceDepositVectorFieldType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(ResourceDepositVector));
    }
    return cached;
  }

  /**
   * Address: 0x00549850 (FUN_00549850)
   *
   * What it does:
   * Lazily resolves `vector<ResourceDeposit>` reflection type and dispatches
   * one archive read for the vector field stored at offset `+0x0C`.
   */
  void ReadResourceDepositVectorFieldArchiveAdapter(void* const object, gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    auto* const view = static_cast<ResourceDepositVectorFieldView*>(object);
    gpg::RRef owner{};
    archive->Read(CachedResourceDepositVectorFieldType(), &view->mDeposits, owner);
  }

  /**
   * Address: 0x005498A0 (FUN_005498A0)
   *
   * What it does:
   * Lazily resolves `vector<ResourceDeposit>` reflection type and dispatches
   * one archive write for the vector field stored at offset `+0x0C`.
   */
  void WriteResourceDepositVectorFieldArchiveAdapter(void* const object, gpg::WriteArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    auto* const view = static_cast<ResourceDepositVectorFieldView*>(object);
    gpg::RRef owner{};
    archive->Write(CachedResourceDepositVectorFieldType(), &view->mDeposits, owner);
  }

  /**
   * Address: 0x00547E00 (FUN_00547E00)
   *
   * What it does:
   * Ensures one `msvc8::vector<moho::ResourceDeposit>` can hold at least the
   * requested number of elements before reflected load fills it.
   */
  void EnsureResourceDepositLoadCapacity(ResourceDepositVector& storage, const std::size_t requiredCount)
  {
    if (requiredCount > 0x0CCCCCCCu) {
      throw std::bad_alloc{};
    }

    if (requiredCount <= storage.capacity()) {
      return;
    }

    storage.reserve(requiredCount);
  }

  /**
   * Address: 0x00549BC0 (FUN_00549BC0)
   *
   * What it does:
   * Copies one contiguous `ResourceDeposit` range `[sourceBegin, sourceEnd)`
   * into destination storage and returns one-past the last destination lane.
   */
  [[nodiscard]] std::uint32_t* CopyResourceDepositWordQuintRange(
    std::uint32_t* destination,
    const std::uint32_t* const sourceEnd,
    const std::uint32_t* sourceBegin
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        destination[0] = sourceBegin[0];
        destination[1] = sourceBegin[1];
        destination[2] = sourceBegin[2];
        destination[3] = sourceBegin[3];
        destination[4] = sourceBegin[4];
      }

      destination += 5;
      sourceBegin += 5;
    }

    return destination;
  }

  /**
   * Address: 0x00549A90 (FUN_00549A90)
   *
   * What it does:
   * Source-first adapter lane for copying one 5-dword `ResourceDeposit` range
   * `[sourceBegin, sourceEnd)` and returning one-past-end destination storage.
   */
  [[maybe_unused]] std::uint32_t* CopyResourceDepositWordQuintRangeSourceFirst(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    return CopyResourceDepositWordQuintRange(destination, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00548AB0 (FUN_00548AB0)
   *
   * What it does:
   * Register-shape adapter that forwards one 5-dword `ResourceDeposit` range
   * into the canonical range-copy helper.
   */
  [[maybe_unused]] std::uint32_t* CopyResourceDepositWordQuintRangeRegisterAdapterLaneA(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationBegin
  ) noexcept
  {
    return CopyResourceDepositWordQuintRange(destinationBegin, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00549480 (FUN_00549480)
   *
   * What it does:
   * Secondary register-shape adapter for 5-dword `ResourceDeposit` range copy.
   */
  [[maybe_unused]] std::uint32_t* CopyResourceDepositWordQuintRangeRegisterAdapterLaneB(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationBegin
  ) noexcept
  {
    return CopyResourceDepositWordQuintRange(destinationBegin, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x005498F0 (FUN_005498F0)
   *
   * What it does:
   * Third register-shape adapter for 5-dword `ResourceDeposit` range copy.
   */
  [[maybe_unused]] std::uint32_t* CopyResourceDepositWordQuintRangeRegisterAdapterLaneC(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationBegin
  ) noexcept
  {
    return CopyResourceDepositWordQuintRange(destinationBegin, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00549A50 (FUN_00549A50)
   * Address: 0x006E3D30 (FUN_006E3D30)
   *
   * What it does:
   * Fourth register-shape adapter for 5-dword `ResourceDeposit` range copy.
   */
  [[maybe_unused]] std::uint32_t* CopyResourceDepositWordQuintRangeRegisterAdapterLaneD(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationBegin
  ) noexcept
  {
    return CopyResourceDepositWordQuintRange(destinationBegin, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00549750 (FUN_00549750)
   *
   * What it does:
   * Register-shape adapter that forwards one source-first 5-dword
   * `ResourceDeposit` range copy lane.
   */
  [[maybe_unused]] std::uint32_t* CopyResourceDepositWordQuintRangeSourceFirstAdapterLaneA(
    std::uint32_t* const destinationBegin,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    return CopyResourceDepositWordQuintRangeSourceFirst(destinationBegin, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00549940 (FUN_00549940)
   *
   * What it does:
   * Secondary register-shape adapter for source-first 5-dword
   * `ResourceDeposit` range copy.
   */
  [[maybe_unused]] std::uint32_t* CopyResourceDepositWordQuintRangeSourceFirstAdapterLaneB(
    std::uint32_t* const destinationBegin,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    return CopyResourceDepositWordQuintRangeSourceFirst(destinationBegin, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00548C00 (FUN_00548C00)
   *
   * What it does:
   * Copies one contiguous 5-dword `ResourceDeposit` lane range and returns
   * one-past the last destination lane.
   */
  [[maybe_unused]] moho::ResourceDeposit* CopyResourceDepositRangeNullable(
    moho::ResourceDeposit* destination,
    const moho::ResourceDeposit* const sourceBegin,
    const moho::ResourceDeposit* const sourceEnd
  ) noexcept
  {
    auto* const copiedEnd = CopyResourceDepositWordQuintRange(
      reinterpret_cast<std::uint32_t*>(destination),
      reinterpret_cast<const std::uint32_t*>(sourceEnd),
      reinterpret_cast<const std::uint32_t*>(sourceBegin)
    );
    return reinterpret_cast<moho::ResourceDeposit*>(copiedEnd);
  }

  /**
   * Address: 0x00548ED0 (FUN_00548ED0)
   *
   * What it does:
   * Copy-assigns one `msvc8::vector<moho::ResourceDeposit>` lane and preserves
   * self-assignment fast-path semantics.
   */
  [[maybe_unused]] ResourceDepositVector* AssignResourceDepositVector(
    ResourceDepositVector* const destination,
    const ResourceDepositVector& source
  )
  {
    if (destination == &source) {
      return destination;
    }

    *destination = source;
    return destination;
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
  EnsureResourceDepositLoadCapacity(loaded, static_cast<std::size_t>(count));

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

/**
 * Address: 0x00548C70 (FUN_00548C70, preregister_VectorResourceDepositType)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for
 * `msvc8::vector<moho::ResourceDeposit>`.
 */
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

