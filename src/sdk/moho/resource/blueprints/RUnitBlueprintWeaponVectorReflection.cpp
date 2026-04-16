#include "moho/resource/blueprints/RUnitBlueprintWeaponVectorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace
{
  using WeaponVector = msvc8::vector<moho::RUnitBlueprintWeapon>;

  alignas(gpg::RVectorType_RUnitBlueprintWeapon) unsigned char
    gRUnitBlueprintWeaponVectorTypeStorage[sizeof(gpg::RVectorType_RUnitBlueprintWeapon)];
  bool gRUnitBlueprintWeaponVectorTypeConstructed = false;

  [[nodiscard]] gpg::RType* CachedRUnitBlueprintWeaponType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintWeapon));
    }
    return cached;
  }

  [[nodiscard]] gpg::RVectorType_RUnitBlueprintWeapon& AcquireRUnitBlueprintWeaponVectorType()
  {
    if (!gRUnitBlueprintWeaponVectorTypeConstructed) {
      new (gRUnitBlueprintWeaponVectorTypeStorage) gpg::RVectorType_RUnitBlueprintWeapon();
      gRUnitBlueprintWeaponVectorTypeConstructed = true;
    }

    return *reinterpret_cast<gpg::RVectorType_RUnitBlueprintWeapon*>(gRUnitBlueprintWeaponVectorTypeStorage);
  }

  void cleanup_VectorRUnitBlueprintWeaponTypeStorage()
  {
    if (!gRUnitBlueprintWeaponVectorTypeConstructed) {
      return;
    }

    AcquireRUnitBlueprintWeaponVectorType().~RVectorType_RUnitBlueprintWeapon();
    gRUnitBlueprintWeaponVectorTypeConstructed = false;
  }

  struct RUnitBlueprintWeaponVectorReflectionBootstrap
  {
    RUnitBlueprintWeaponVectorReflectionBootstrap()
    {
      (void)moho::register_VectorRUnitBlueprintWeaponTypeAtexit();
    }
  };

  RUnitBlueprintWeaponVectorReflectionBootstrap gRUnitBlueprintWeaponVectorReflectionBootstrap;

  /**
   * Address: 0x00524380 (FUN_00524380)
   *
   * What it does:
   * Ensures one `vector<RUnitBlueprintWeapon>` has capacity for `count`
   * elements before deserialization fills it.
   */
  void EnsureWeaponVectorCapacity(WeaponVector& storage, const std::size_t count)
  {
    if (count <= storage.capacity()) {
      return;
    }

    storage.reserve(count);
  }

  /**
   * Address: 0x00526170 (FUN_00526170)
   *
   * What it does:
   * Copy-assigns one contiguous `RUnitBlueprintWeapon` destination range from
   * source lanes and returns the advanced source cursor.
   */
  [[maybe_unused]] const moho::RUnitBlueprintWeapon* CopyAssignUnitBlueprintWeaponRange(
    moho::RUnitBlueprintWeapon* destinationBegin,
    moho::RUnitBlueprintWeapon* destinationEnd,
    const moho::RUnitBlueprintWeapon* sourceBegin
  )
  {
    moho::RUnitBlueprintWeapon* destinationCursor = destinationBegin;
    const moho::RUnitBlueprintWeapon* sourceCursor = sourceBegin;

    while (destinationCursor != destinationEnd) {
      *destinationCursor = *sourceCursor;
      ++destinationCursor;
      ++sourceCursor;
    }

    return sourceCursor;
  }

  /**
   * Address: 0x00524620 (FUN_00524620)
   *
   * What it does:
   * Destroys one contiguous half-open range `[first,last)` of
   * `RUnitBlueprintWeapon` elements.
   */
  void DestroyUnitBlueprintWeaponRange(
    moho::RUnitBlueprintWeapon* const first,
    moho::RUnitBlueprintWeapon* const last
  )
  {
    for (moho::RUnitBlueprintWeapon* cursor = first; cursor != last; ++cursor) {
      cursor->~RUnitBlueprintWeapon();
    }
  }

  /**
   * Address: 0x00524A80 (FUN_00524A80)
   *
   * What it does:
   * Destroys one half-open tail range in `vector<RUnitBlueprintWeapon>`,
   * updates the runtime `end` lane, and returns the erased begin iterator.
   */
  [[nodiscard]] moho::RUnitBlueprintWeapon** DestroyUnitBlueprintWeaponTailAndReturnIterator(
    WeaponVector& storage,
    moho::RUnitBlueprintWeapon** const outIterator,
    moho::RUnitBlueprintWeapon* const eraseBegin,
    moho::RUnitBlueprintWeapon* const eraseEnd
  )
  {
    if (eraseBegin != eraseEnd) {
      DestroyUnitBlueprintWeaponRange(eraseBegin, eraseEnd);

      auto& view = msvc8::AsVectorRuntimeView(storage);
      view.end = eraseBegin;
    }

    if (outIterator) {
      *outIterator = eraseBegin;
    }
    return outIterator;
  }

  /**
   * Address: 0x005244A0 (FUN_005244A0)
   *
   * What it does:
   * Adjusts one `vector<RUnitBlueprintWeapon>` length to `requestedCount` and
   * uses one caller-provided fill lane for growth.
   */
  [[nodiscard]] std::size_t ResizeUnitBlueprintWeaponVectorWithFill(
    WeaponVector& storage,
    const std::size_t requestedCount,
    const moho::RUnitBlueprintWeapon& fillValue
  )
  {
    const std::size_t currentCount = storage.size();
    if (currentCount < requestedCount) {
      storage.resize(requestedCount, fillValue);
      return requestedCount;
    }

    if (requestedCount < currentCount) {
      auto& view = msvc8::AsVectorRuntimeView(storage);
      if (view.begin && view.end) {
        moho::RUnitBlueprintWeapon* const eraseBegin = view.begin + requestedCount;
        moho::RUnitBlueprintWeapon* outIterator = nullptr;
        (void)DestroyUnitBlueprintWeaponTailAndReturnIterator(storage, &outIterator, eraseBegin, view.end);
      }
    }

    return requestedCount;
  }
} // namespace

/**
 * Address: 0x00523490 (FUN_00523490, gpg::RVectorType_RUnitBlueprintWeapon::GetName)
 *
 * What it does:
 * Builds and caches lexical reflection name `vector<element>` for
 * `msvc8::vector<moho::RUnitBlueprintWeapon>`.
 */
const char* gpg::RVectorType_RUnitBlueprintWeapon::GetName() const
{
  static msvc8::string sName{};
  if (sName.empty()) {
    const gpg::RType* const elementType = CachedRUnitBlueprintWeaponType();
    const char* const elementName = elementType ? elementType->GetName() : "RUnitBlueprintWeapon";
    sName = gpg::STR_Printf("vector<%s>", elementName);
  }
  return sName.c_str();
}

/**
 * Address: 0x00523550 (FUN_00523550, gpg::RVectorType_RUnitBlueprintWeapon::GetLexical)
 *
 * What it does:
 * Returns base lexical text plus reflected vector size for one
 * `msvc8::vector<moho::RUnitBlueprintWeapon>` instance.
 */
msvc8::string gpg::RVectorType_RUnitBlueprintWeapon::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x005235E0 (FUN_005235E0, gpg::RVectorType_RUnitBlueprintWeapon::IsIndexed)
 */
const gpg::RIndexed* gpg::RVectorType_RUnitBlueprintWeapon::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00523530 (FUN_00523530, gpg::RVectorType_RUnitBlueprintWeapon::Init)
 *
 * What it does:
 * Sets vector metadata and installs reflected archive callbacks.
 */
void gpg::RVectorType_RUnitBlueprintWeapon::Init()
{
  size_ = sizeof(WeaponVector);
  version_ = 1;
  serLoadFunc_ = &RVectorType_RUnitBlueprintWeapon::SerLoad;
  serSaveFunc_ = &RVectorType_RUnitBlueprintWeapon::SerSave;
}

/**
 * Address: 0x00523D50 (FUN_00523D50, gpg::RVectorType_RUnitBlueprintWeapon::SerLoad)
 *
 * What it does:
 * Reads element count, deserializes each `RUnitBlueprintWeapon`, and replaces
 * destination storage with the loaded sequence.
 */
void gpg::RVectorType_RUnitBlueprintWeapon::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const storage = reinterpret_cast<WeaponVector*>(objectPtr);
  unsigned int count = 0u;
  archive->ReadUInt(&count);

  WeaponVector loaded{};
  EnsureWeaponVectorCapacity(loaded, static_cast<std::size_t>(count));

  gpg::RType* const elementType = CachedRUnitBlueprintWeaponType();
  if (!elementType) {
    *storage = loaded;
    return;
  }

  for (unsigned int i = 0u; i < count; ++i) {
    moho::RUnitBlueprintWeapon element{};
    gpg::RRef owner{};
    archive->Read(elementType, &element, owner);
    loaded.push_back(element);
  }

  *storage = loaded;
}

/**
 * Address: 0x00523E80 (FUN_00523E80, gpg::RVectorType_RUnitBlueprintWeapon::SerSave)
 *
 * What it does:
 * Writes vector element count and serializes each
 * `RUnitBlueprintWeapon` payload lane with reflected write callbacks.
 */
void gpg::RVectorType_RUnitBlueprintWeapon::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  if (!archive) {
    return;
  }

  const auto* const storage = reinterpret_cast<const WeaponVector*>(objectPtr);
  const unsigned int count = storage ? static_cast<unsigned int>(storage->size()) : 0u;
  archive->WriteUInt(count);

  if (!storage || count == 0u) {
    return;
  }

  gpg::RType* const elementType = CachedRUnitBlueprintWeaponType();
  if (!elementType) {
    return;
  }

  const gpg::RRef emptyOwner{};
  const gpg::RRef& effectiveOwner = ownerRef ? *ownerRef : emptyOwner;
  for (const moho::RUnitBlueprintWeapon& element : *storage) {
    archive->Write(elementType, &element, effectiveOwner);
  }
}

/**
 * Address: 0x00523650 (FUN_00523650, gpg::RVectorType_RUnitBlueprintWeapon::SubscriptIndex)
 */
gpg::RRef gpg::RVectorType_RUnitBlueprintWeapon::SubscriptIndex(void* const obj, const int ind) const
{
  gpg::RRef out{};
  out.mType = CachedRUnitBlueprintWeaponType();
  out.mObj = nullptr;

  auto* const storage = static_cast<WeaponVector*>(obj);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_RUnitBlueprintWeapon(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x005235F0 (FUN_005235F0, gpg::RVectorType_RUnitBlueprintWeapon::GetCount)
 */
size_t gpg::RVectorType_RUnitBlueprintWeapon::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const WeaponVector*>(obj);
  return storage ? storage->size() : 0u;
}

/**
 * Address: 0x00523620 (FUN_00523620, gpg::RVectorType_RUnitBlueprintWeapon::SetCount)
 */
void gpg::RVectorType_RUnitBlueprintWeapon::SetCount(void* const obj, const int count) const
{
  if (!obj || count < 0) {
    return;
  }

  auto* const storage = static_cast<WeaponVector*>(obj);
  const moho::RUnitBlueprintWeapon fillValue{};
  (void)ResizeUnitBlueprintWeaponVectorWithFill(*storage, static_cast<std::size_t>(count), fillValue);
}

gpg::RType* moho::preregister_VectorRUnitBlueprintWeaponType()
{
  auto* const typeInfo = &AcquireRUnitBlueprintWeaponVectorType();
  gpg::PreRegisterRType(typeid(WeaponVector), typeInfo);
  return typeInfo;
}

/**
 * Address: 0x00BC8D30 (FUN_00BC8D30, register_VectorRUnitBlueprintWeaponTypeAtexit)
 *
 * What it does:
 * Startup lane that preregisters `vector<RUnitBlueprintWeapon>` reflection
 * metadata and installs teardown callback.
 */
int moho::register_VectorRUnitBlueprintWeaponTypeAtexit()
{
  (void)preregister_VectorRUnitBlueprintWeaponType();
  return std::atexit(&cleanup_VectorRUnitBlueprintWeaponTypeStorage);
}

