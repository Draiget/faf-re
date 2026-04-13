#include "moho/entity/EntityCategoryTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/BadRefCast.h"
#include "moho/entity/EntityCategoryReflection.h"

using namespace moho;

namespace
{
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
  gpg::PreRegisterRType(typeid(EntityCategory), this);
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
  newRefFunc_ = &EntityCategoryTypeInfo::NewRef;
  ctorRefFunc_ = &EntityCategoryTypeInfo::CtrRef;
  cpyRefFunc_ = &EntityCategoryTypeInfo::CpyRef;
  movRefFunc_ = &EntityCategoryTypeInfo::MovRef;
  deleteFunc_ = &EntityCategoryTypeInfo::Delete;
  dtrFunc_ = &EntityCategoryTypeInfo::Destruct;
  size_ = sizeof(EntityCategorySet);
  Version(1);
  serLoadFunc_ = &EntityCategory::SerLoad;
  serSaveFunc_ = &EntityCategory::SerSave;
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
