#include "moho/entity/EntityCategoryTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/BadRefCast.h"
#include "moho/entity/EntityCategoryReflection.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00556450 (FUN_00556450)
   *
   * What it does:
   * Completes startup preregistration for `EntityCategoryTypeInfo` by
   * publishing RTTI for `EntityCategory`.
   */
  void preregister_EntityCategoryTypeInfoCtorLane(gpg::RType* const typeInfo)
  {
    gpg::PreRegisterRType(typeid(moho::EntityCategory), typeInfo);
  }

  [[nodiscard]] gpg::RType* CachedEntityCategorySetType()
  {
    gpg::RType* type = moho::EntityCategorySet::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntityCategorySet));
      moho::EntityCategorySet::sType = type;
    }
    return type;
  }

  [[nodiscard]] moho::EntityCategorySet* TryUpcastEntityCategoryOrThrow(const gpg::RRef& sourceRef)
  {
    gpg::RType* const entityCategoryType = CachedEntityCategorySetType();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, entityCategoryType);
    auto* const categorySet = static_cast<moho::EntityCategorySet*>(upcast.mObj);
    if (!categorySet) {
      const char* const sourceName = sourceRef.mType ? sourceRef.mType->GetName() : "null";
      const char* const targetName = entityCategoryType->GetName();
      throw gpg::BadRefCast(nullptr, sourceName, targetName);
    }

    return categorySet;
  }

  [[nodiscard]] gpg::RRef MakeEntityCategoryRef(moho::EntityCategorySet* const categorySet)
  {
    gpg::RRef out{};
    (void)gpg::RRef_EntityCategory(&out, categorySet);
    return out;
  }

  /**
   * Address: 0x005564D0 (FUN_005564D0)
   *
   * What it does:
   * Installs the primary reference-lifecycle callbacks for
   * `EntityCategoryTypeInfo` (`NewRef`, `CtrRef`, `Delete`, `Destruct`).
   */
  [[maybe_unused]] [[nodiscard]] EntityCategoryTypeInfo* ConfigureEntityCategoryTypeRefCallbacksPrimary(
    EntityCategoryTypeInfo* const typeInfo
  ) noexcept
  {
    typeInfo->newRefFunc_ = &EntityCategoryTypeInfo::NewRef;
    typeInfo->ctorRefFunc_ = &EntityCategoryTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &EntityCategoryTypeInfo::Delete;
    typeInfo->dtrFunc_ = &EntityCategoryTypeInfo::Destruct;
    return typeInfo;
  }

  /**
   * Address: 0x005564F0 (FUN_005564F0)
   *
   * What it does:
   * Installs the copy/move reference-lifecycle callbacks for
   * `EntityCategoryTypeInfo` (`CpyRef`, `MovRef`, `Delete`, `Destruct`).
   */
  [[maybe_unused]] [[nodiscard]] EntityCategoryTypeInfo* ConfigureEntityCategoryTypeRefCallbacksSecondary(
    EntityCategoryTypeInfo* const typeInfo
  ) noexcept
  {
    typeInfo->cpyRefFunc_ = &EntityCategoryTypeInfo::CpyRef;
    typeInfo->movRefFunc_ = &EntityCategoryTypeInfo::MovRef;
    typeInfo->deleteFunc_ = &EntityCategoryTypeInfo::Delete;
    typeInfo->dtrFunc_ = &EntityCategoryTypeInfo::Destruct;
    return typeInfo;
  }

  /**
   * Address: 0x00556030 (FUN_00556030)
   *
   * What it does:
   * Configures `EntityCategoryTypeInfo` callback lanes, element size/version,
   * and serializer entrypoints for `EntityCategorySet`.
   */
  [[maybe_unused]] [[nodiscard]] EntityCategoryTypeInfo* ConfigureEntityCategoryTypeInitLanes(
    EntityCategoryTypeInfo* const typeInfo
  ) noexcept
  {
    (void)ConfigureEntityCategoryTypeRefCallbacksPrimary(typeInfo);
    (void)ConfigureEntityCategoryTypeRefCallbacksSecondary(typeInfo);
    typeInfo->size_ = sizeof(EntityCategorySet);
    typeInfo->Version(1);
    typeInfo->serLoadFunc_ = &EntityCategory::SerLoad;
    typeInfo->serSaveFunc_ = &EntityCategory::SerSave;
    return typeInfo;
  }

  alignas(EntityCategoryTypeInfo) unsigned char gStorage[sizeof(EntityCategoryTypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] EntityCategoryTypeInfo& Acquire()
  {
    if (!gConstructed) {
      new (gStorage) EntityCategoryTypeInfo();
      gConstructed = true;
    }
    return *reinterpret_cast<EntityCategoryTypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) return;
    auto& ti = *reinterpret_cast<EntityCategoryTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct Bootstrap { Bootstrap() { moho::register_EntityCategoryTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/**
 * Address: 0x00555E90 (FUN_00555E90, ??0EntityCategoryTypeInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Preregisters `EntityCategory` (BVSet<RBlueprint const*, EntityCategoryHelper>)
 * RTTI into the reflection lookup table.
 */
EntityCategoryTypeInfo::EntityCategoryTypeInfo()
  : gpg::RType()
{
  preregister_EntityCategoryTypeInfoCtorLane(this);
}

EntityCategoryTypeInfo::~EntityCategoryTypeInfo() = default;

/** Address: 0x00555F40 (FUN_00555F40) */
const char* EntityCategoryTypeInfo::GetName() const { return "EntityCategory"; }

/**
 * Address: 0x00555EF0 (FUN_00555EF0, Moho::EntityCategoryTypeInfo::Init)
 *
 * What it does:
 * Sets size = 0x28, version = 1, installs ref-management and serialization
 * function pointers, then finalizes.
 */
void EntityCategoryTypeInfo::Init()
{
  (void)ConfigureEntityCategoryTypeInitLanes(this);
  Finish();
}

/**
 * Address: 0x00556A90 (FUN_00556A90, Moho::EntityCategoryTypeInfo::NewRef)
 *
 * What it does:
 * Allocates and default-initializes one `EntityCategorySet`, then returns the
 * typed reflection reference.
 */
gpg::RRef EntityCategoryTypeInfo::NewRef()
{
  auto* const categorySet = new (std::nothrow) EntityCategorySet();
  return MakeEntityCategoryRef(categorySet);
}

/**
 * Address: 0x00556AF0 (FUN_00556AF0, Moho::EntityCategoryTypeInfo::CpyRef)
 *
 * What it does:
 * Allocates one destination `EntityCategorySet`, copies source universe/start
 * lanes and packed word storage, then returns a typed reflection reference.
 */
gpg::RRef EntityCategoryTypeInfo::CpyRef(gpg::RRef* const sourceRef)
{
  auto* const categorySet = new (std::nothrow) EntityCategorySet();
  if (categorySet != nullptr) {
    const EntityCategorySet* const source = TryUpcastEntityCategoryOrThrow(*sourceRef);
    categorySet->mUniverse = source->mUniverse;
    categorySet->mBits.mFirstWordIndex = source->mBits.mFirstWordIndex;
    (void)gpg::FastVectorN2RebindAndCopy<unsigned int>(&categorySet->mBits.mWords, &source->mBits.mWords);
  }

  return MakeEntityCategoryRef(categorySet);
}

/**
 * Address: 0x00556B90 (FUN_00556B90, Moho::EntityCategoryTypeInfo::Delete)
 *
 * What it does:
 * Deletes one heap-owned `EntityCategorySet` through the normal delete path.
 */
void EntityCategoryTypeInfo::Delete(void* const objectStorage)
{
  delete static_cast<EntityCategorySet*>(objectStorage);
}

/**
 * Address: 0x00556BD0 (FUN_00556BD0, Moho::EntityCategoryTypeInfo::CtrRef)
 *
 * What it does:
 * Placement-constructs one `EntityCategorySet` in caller-provided storage and
 * returns its typed reflection reference.
 */
gpg::RRef EntityCategoryTypeInfo::CtrRef(void* const objectStorage)
{
  auto* const categorySet = static_cast<EntityCategorySet*>(objectStorage);
  if (categorySet) {
    new (categorySet) EntityCategorySet();
  }
  return MakeEntityCategoryRef(categorySet);
}

/**
 * Address: 0x00556C20 (FUN_00556C20, Moho::EntityCategoryTypeInfo::MovRef)
 *
 * What it does:
 * Copies one source `EntityCategorySet` payload into caller-provided storage
 * and returns the typed reflection reference to destination storage.
 */
gpg::RRef EntityCategoryTypeInfo::MovRef(void* const objectStorage, gpg::RRef* const sourceRef)
{
  auto* const categorySet = static_cast<EntityCategorySet*>(objectStorage);
  if (categorySet != nullptr) {
    const EntityCategorySet* const source = TryUpcastEntityCategoryOrThrow(*sourceRef);
    categorySet->mUniverse = source->mUniverse;
    categorySet->mBits.mFirstWordIndex = source->mBits.mFirstWordIndex;
    (void)gpg::FastVectorN2RebindAndCopy<unsigned int>(&categorySet->mBits.mWords, &source->mBits.mWords);
  }

  return MakeEntityCategoryRef(categorySet);
}

/**
 * Address: 0x00556CB0 (FUN_00556CB0, Moho::EntityCategoryTypeInfo::Destruct)
 *
 * What it does:
 * Runs one in-place `EntityCategorySet` destructor without freeing backing
 * object storage.
 */
void EntityCategoryTypeInfo::Destruct(void* const objectStorage)
{
  if (!objectStorage) {
    return;
  }

  static_cast<EntityCategorySet*>(objectStorage)->~EntityCategorySet();
}

/** Address: 0x00BC9ED0 (FUN_00BC9ED0) */
void moho::register_EntityCategoryTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
