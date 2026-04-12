#include "moho/entity/EntityCategoryTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/EntityCategoryReflection.h"

using namespace moho;

namespace
{
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
  size_ = sizeof(EntityCategory);
  gpg::RType::Init();
  Finish();
}

/** Address: 0x00BC9ED0 (FUN_00BC9ED0) */
void moho::register_EntityCategoryTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
