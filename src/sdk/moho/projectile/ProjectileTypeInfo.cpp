#include "moho/projectile/ProjectileTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/entity/Entity.h"
#include "moho/projectile/Projectile.h"

namespace
{
  moho::ProjectileTypeInfo gProjectileTypeInfo;

  template <typename TTypeInfo>
  void ResetTypeInfoVectors(TTypeInfo& typeInfo) noexcept
  {
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0069E190 (FUN_0069E190, Moho::ProjectileTypeInfo::ProjectileTypeInfo)
   */
  ProjectileTypeInfo::ProjectileTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Projectile), this);
  }

  /**
   * Address: 0x0069E260 (FUN_0069E260, Moho::ProjectileTypeInfo::dtr)
   */
  ProjectileTypeInfo::~ProjectileTypeInfo() = default;

  /**
   * Address: 0x0069E250 (FUN_0069E250, Moho::ProjectileTypeInfo::GetName)
   */
  const char* ProjectileTypeInfo::GetName() const
  {
    return "Projectile";
  }

  /**
   * Address: 0x0069E1F0 (FUN_0069E1F0, Moho::ProjectileTypeInfo::Init)
   */
  void ProjectileTypeInfo::Init()
  {
    size_ = sizeof(Projectile);
    AddBase_Entity(this);
    gpg::RType::Init();

    gpg::RField* const damageField = AddFieldFloat("Damage", 0x2C8);
    damageField->v4 = 1;
    damageField->mDesc = "Damage per hit (configured by weapon)";

    gpg::RField* const damageRadiusField = AddFieldFloat("DamageRadius", 0x2CC);
    damageRadiusField->v4 = 1;
    damageRadiusField->mDesc = "Radius to inflict damage within (configured by weapon)";

    Finish();
  }

  /**
   * Address: 0x0069F820 (FUN_0069F820, Moho::ProjectileTypeInfo::AddBaseEntity)
   */
  void ProjectileTypeInfo::AddBase_Entity(gpg::RType* const typeInfo)
  {
    static gpg::RType* sEntityType = nullptr;
    if (!sEntityType) {
      sEntityType = gpg::LookupRType(typeid(::moho::Entity));
    }
    gpg::RType* const baseType = sEntityType;

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BFD610 (FUN_00BFD610, cleanup_ProjectileTypeInfo)
   */
  void cleanup_ProjectileTypeInfo()
  {
    ResetTypeInfoVectors(gProjectileTypeInfo);
  }

  /**
   * Address: 0x00BD63F0 (FUN_00BD63F0, register_ProjectileTypeInfo)
   */
  void register_ProjectileTypeInfo()
  {
    (void)gProjectileTypeInfo;
    (void)std::atexit(&cleanup_ProjectileTypeInfo);
  }
} // namespace moho

namespace
{
  struct ProjectileTypeInfoBootstrap
  {
    ProjectileTypeInfoBootstrap()
    {
      moho::register_ProjectileTypeInfo();
    }
  };

  ProjectileTypeInfoBootstrap gProjectileTypeInfoBootstrap;
} // namespace
