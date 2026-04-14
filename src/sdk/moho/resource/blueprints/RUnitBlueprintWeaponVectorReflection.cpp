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
  loaded.reserve(static_cast<std::size_t>(count));

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
  storage->resize(static_cast<std::size_t>(count));
}

gpg::RType* moho::preregister_VectorRUnitBlueprintWeaponType()
{
  auto* const typeInfo = &AcquireRUnitBlueprintWeaponVectorType();
  gpg::PreRegisterRType(typeid(WeaponVector), typeInfo);
  return typeInfo;
}

int moho::register_VectorRUnitBlueprintWeaponTypeAtexit()
{
  (void)preregister_VectorRUnitBlueprintWeaponType();
  return std::atexit(&cleanup_VectorRUnitBlueprintWeaponTypeStorage);
}

