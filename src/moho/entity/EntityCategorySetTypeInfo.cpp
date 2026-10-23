#include "moho/entity/EntityCategorySetTypeInfo.h"

#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "moho/resource/blueprints/RBlueprint.h"

namespace
{
  // No standalone instance of this base is registered. Registering one for
  // typeid(EntityCategorySet) shadowed EntityCategoryTypeInfo - the only type
  // that installs the reference-lifecycle callbacks - so every category set
  // handed to Lua came back "not copy constructible".

  [[nodiscard]] gpg::RType* CachedRBlueprintPointerType()
  {
    if (!moho::RBlueprint::sPointerType) {
      try {
        moho::RBlueprint::sPointerType = gpg::LookupRType(typeid(moho::RBlueprint*));
      } catch (...) {
        // RPointerType<RBlueprint> preregistration (FUN_00556CE0/FUN_00556FF0)
        // is still being reconstructed; preserve runtime continuity for naming.
        return nullptr;
      }
    }
    return moho::RBlueprint::sPointerType;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00556510 (FUN_00556510, deleting dtor thunk)
   */
  BVSetRType<const RBlueprint*, EntityCategoryHelper>::~BVSetRType() = default;

  /**
   * Address: 0x005563A0 (FUN_005563A0, Moho::BVSetRType_RBlueprintP_EntityCategoryHelper::GetName)
   * Address: 0x00BF4C70 (FUN_00BF4C70, atexit destructor of GetName's cached name)
   */
  const char* BVSetRType<const RBlueprint*, EntityCategoryHelper>::GetName() const
  {
    static const msvc8::string sName = gpg::STR_Printf(
      "BVSet<%s,%s>", CachedRBlueprintPointerType()->GetName(), EntityCategoryHelper::StaticGetClass()->GetName()
    );
    return sName.c_str();
  }

  /**
   * Address: 0x005564B0 (FUN_005564B0, Moho::BVSetRType_RBlueprintP_EntityCategoryHelper::Init)
   */
  void BVSetRType<const RBlueprint*, EntityCategoryHelper>::Init()
  {
    size_ = sizeof(EntityCategorySet);
    version_ = 1;
    serLoadFunc_ = &EntityCategory::SerLoad;
    serSaveFunc_ = &EntityCategory::SerSave;
  }
} // namespace moho

