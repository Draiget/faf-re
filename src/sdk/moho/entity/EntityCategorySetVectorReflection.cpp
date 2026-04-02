#include "moho/entity/EntityCategorySetVectorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>
#include <utility>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

namespace
{
  using EntityCategorySetVector = msvc8::vector<moho::EntityCategorySet>;
  using EntityCategorySetVectorType = gpg::RVectorType<moho::EntityCategorySet>;

  alignas(EntityCategorySetVectorType) unsigned char gEntityCategorySetVectorTypeStorage[sizeof(EntityCategorySetVectorType)];
  bool gEntityCategorySetVectorTypeConstructed = false;

  [[nodiscard]] EntityCategorySetVectorType* AcquireEntityCategorySetVectorType()
  {
    if (!gEntityCategorySetVectorTypeConstructed) {
      new (gEntityCategorySetVectorTypeStorage) EntityCategorySetVectorType();
      gEntityCategorySetVectorTypeConstructed = true;
    }
    return reinterpret_cast<EntityCategorySetVectorType*>(gEntityCategorySetVectorTypeStorage);
  }

  [[nodiscard]] EntityCategorySetVectorType* PeekEntityCategorySetVectorType() noexcept
  {
    if (!gEntityCategorySetVectorTypeConstructed) {
      return nullptr;
    }
    return reinterpret_cast<EntityCategorySetVectorType*>(gEntityCategorySetVectorTypeStorage);
  }

  [[nodiscard]] gpg::RType* ResolveEntityCategorySetType()
  {
    gpg::RType* type = moho::EntityCategorySet::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntityCategorySet));
      moho::EntityCategorySet::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeEntityCategorySetRef(moho::EntityCategorySet* value)
  {
    gpg::RRef out{};
    out.mObj = value;
    out.mType = ResolveEntityCategorySetType();
    return out;
  }

  /**
   * Address: 0x006DBEB0 (FUN_006DBEB0)
   *
   * What it does:
   * Loads a `vector<EntityCategorySet>` payload and replaces destination storage.
   */
  void LoadEntityCategorySetVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<EntityCategorySetVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    EntityCategorySetVector loaded{};
    loaded.resize(static_cast<std::size_t>(count));

    gpg::RType* const elementType = ResolveEntityCategorySetType();
    if (!elementType) {
      *storage = std::move(loaded);
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &loaded[static_cast<std::size_t>(i)], owner);
    }

    *storage = std::move(loaded);
  }

  /**
   * Address: 0x006DBFF0 (FUN_006DBFF0)
   *
   * What it does:
   * Writes a `vector<EntityCategorySet>` payload element-by-element.
   */
  void SaveEntityCategorySetVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<const EntityCategorySetVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    gpg::RType* const elementType = ResolveEntityCategorySetType();
    if (!elementType) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(storage->size());
    archive->WriteUInt(count);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &(*storage)[static_cast<std::size_t>(i)], owner);
    }
  }

  /**
   * Address: 0x00BFE8C0 (FUN_00BFE8C0, sub_BFE8C0)
   *
   * What it does:
   * Tears down `vector<EntityCategorySet>` reflection storage at process exit.
   */
  void cleanup_EntityCategorySetVectorType()
  {
    EntityCategorySetVectorType* const type = PeekEntityCategorySetVectorType();
    if (type == nullptr) {
      return;
    }

    type->~EntityCategorySetVectorType();
    gEntityCategorySetVectorTypeConstructed = false;
  }

  struct EntityCategorySetVectorReflectionBootstrap
  {
    EntityCategorySetVectorReflectionBootstrap()
    {
      (void)moho::register_EntityCategorySetVectorType_AtExit();
    }
  };

  EntityCategorySetVectorReflectionBootstrap gEntityCategorySetVectorReflectionBootstrap;
} // namespace

/**
 * Address: 0x006DB280 (FUN_006DB280, gpg::RVectorType_BVSet_PRBlueprint::GetName)
 */
const char* gpg::RVectorType<moho::EntityCategorySet>::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const gpg::RType* const elementType = ResolveEntityCategorySetType();
    const char* const elementName = elementType ? elementType->GetName() : "EntityCategorySet";
    sName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "EntityCategorySet");
  }

  return sName.c_str();
}

/**
 * Address: 0x006DB340 (FUN_006DB340, gpg::RVectorType_BVSet_PRBlueprint::GetLexical)
 */
msvc8::string gpg::RVectorType<moho::EntityCategorySet>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x006DB3D0 (FUN_006DB3D0, gpg::RVectorType_BVSet_PRBlueprint::IsIndexed)
 */
const gpg::RIndexed* gpg::RVectorType<moho::EntityCategorySet>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x006DB320 (FUN_006DB320, gpg::RVectorType_BVSet_PRBlueprint::Init)
 */
void gpg::RVectorType<moho::EntityCategorySet>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadEntityCategorySetVector;
  serSaveFunc_ = &SaveEntityCategorySetVector;
}

/**
 * Address: 0x006DB450 (FUN_006DB450, gpg::RVectorType_BVSet_PRBlueprint::SubscriptIndex)
 */
gpg::RRef gpg::RVectorType<moho::EntityCategorySet>::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<EntityCategorySetVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(storage != nullptr && static_cast<std::size_t>(ind) < GetCount(obj));

  gpg::RRef out{};
  out.mType = ResolveEntityCategorySetType();
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    return out;
  }

  out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
  return out;
}

/**
 * Address: 0x006DB3E0 (FUN_006DB3E0, gpg::RVectorType_BVSet_PRBlueprint::GetCount)
 */
size_t gpg::RVectorType<moho::EntityCategorySet>::GetCount(void* const obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = msvc8::AsVectorRuntimeView(*static_cast<const EntityCategorySetVector*>(obj));
  if (!view.begin) {
    return 0u;
  }

  return static_cast<std::size_t>(view.end - view.begin);
}

/**
 * Address: 0x006DB410 (FUN_006DB410, gpg::RVectorType_BVSet_PRBlueprint::SetCount)
 */
void gpg::RVectorType<moho::EntityCategorySet>::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<EntityCategorySetVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  const moho::EntityCategorySet zeroFill{};
  storage->resize(static_cast<std::size_t>(count), zeroFill);
}

/**
 * Address: 0x006DDF00 (FUN_006DDF00, sub_6DDF00)
 *
 * What it does:
 * Constructs and preregisters RTTI for `vector<EntityCategorySet>`.
 */
gpg::RType* moho::register_EntityCategorySetVectorType()
{
  EntityCategorySetVectorType* const type = AcquireEntityCategorySetVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::EntityCategorySet>), type);
  return type;
}

/**
 * Address: 0x00BD8B90 (FUN_00BD8B90, sub_BD8B90)
 *
 * What it does:
 * Registers `vector<EntityCategorySet>` reflection and installs
 * process-exit teardown via `atexit`.
 */
int moho::register_EntityCategorySetVectorType_AtExit()
{
  (void)register_EntityCategorySetVectorType();
  return std::atexit(&cleanup_EntityCategorySetVectorType);
}
