#include "moho/entity/EntityCategorySetTypeInfo.h"

#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "moho/resource/blueprints/RBlueprint.h"

namespace
{
  moho::BVSetRType<const moho::RBlueprint*, moho::EntityCategoryHelper> gBlueprintCategorySetRType;

  struct BlueprintCategorySetTypeRegistration
  {
    BlueprintCategorySetTypeRegistration()
    {
      gpg::PreRegisterRType(typeid(moho::EntityCategorySet), &gBlueprintCategorySetRType);
      moho::EntityCategorySet::sType = &gBlueprintCategorySetRType;
    }
  };

  BlueprintCategorySetTypeRegistration gBlueprintCategorySetTypeRegistration;

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
  msvc8::string BVSetRType<const RBlueprint*, EntityCategoryHelper>::sName{};
  std::uint32_t BVSetRType<const RBlueprint*, EntityCategoryHelper>::sNameInitGuard = 0u;

  /**
   * Address: 0x00556510 (FUN_00556510, deleting dtor thunk)
   */
  BVSetRType<const RBlueprint*, EntityCategoryHelper>::~BVSetRType() = default;

  /**
   * Address: 0x005563A0 (FUN_005563A0, Moho::BVSetRType_RBlueprintP_EntityCategoryHelper::GetName)
   */
  const char* BVSetRType<const RBlueprint*, EntityCategoryHelper>::GetName() const
  {
    if ((sNameInitGuard & 1u) == 0u) {
      sNameInitGuard |= 1u;

      const char* const helperTypeName = EntityCategoryHelper::StaticGetClass()->GetName();
      gpg::RType* const pointerType = CachedRBlueprintPointerType();
      const char* const pointerTypeName = pointerType ? pointerType->GetName() : "RBlueprint *";

      sName = gpg::STR_Printf(
        "BVSet<%s,%s>",
        pointerTypeName ? pointerTypeName : "RBlueprint*",
        helperTypeName ? helperTypeName : "EntityCategoryHelper"
      );
    }

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

