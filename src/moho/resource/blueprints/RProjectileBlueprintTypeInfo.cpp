#include "RProjectileBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "legacy/containers/String.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RProjectileBlueprintTypeInfo;

  [[nodiscard]] TypeInfo& AcquireRProjectileBlueprintTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  gpg::RType* CachedEntityBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REntityBlueprint));
    }
    return cached;
  }

  struct RProjectileBlueprintTypeInfoBootstrap
  {
    RProjectileBlueprintTypeInfoBootstrap()
    {
      (void)moho::register_RProjectileBlueprintTypeInfo();
    }
  };

  RProjectileBlueprintTypeInfoBootstrap gRProjectileBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0051C260 (FUN_0051C260, Moho::RProjectileBlueprintTypeInfo::RProjectileBlueprintTypeInfo)
   */
  RProjectileBlueprintTypeInfo::RProjectileBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RProjectileBlueprint), this);
  }

  /**
   * Address: 0x00BF2EF0 (FUN_00BF2EF0, scalar deleting destructor thunk)
   */
  RProjectileBlueprintTypeInfo::~RProjectileBlueprintTypeInfo() = default;

  /**
   * Address: 0x0051C2F0 (FUN_0051C2F0)
   */
  const char* RProjectileBlueprintTypeInfo::GetName() const
  {
    return "RProjectileBlueprint";
  }

  /**
   * Address: 0x0051CD60 (FUN_0051CD60)
   *
   * What it does:
   * Adds `REntityBlueprint` as the reflected base class lane.
   */
  void RProjectileBlueprintTypeInfo::AddBaseREntityBlueprint(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedEntityBlueprintType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x0051C3A0 (FUN_0051C3A0)
   *
   * What it does:
   * Registers projectile-blueprint field descriptors and descriptions.
   */
  void RProjectileBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    typeInfo->AddField<msvc8::string>("DevStatus", offsetof(RProjectileBlueprint, DevStatus), 3, "Development Status");
    gpg::RField* const displayField = typeInfo->AddField<moho::RProjectileBlueprintDisplay>("Display", offsetof(RProjectileBlueprint, Display));
    displayField->mFlags = 3;
    displayField->mDesc = "Display information for the Projectile";

    gpg::RField* const economyField = typeInfo->AddField<moho::RProjectileBlueprintEconomy>("Economy", offsetof(RProjectileBlueprint, Economy));
    economyField->mFlags = 3;
    economyField->mDesc = "Economy information for the unit";

    gpg::RField* const physicsField = typeInfo->AddField<moho::RProjectileBlueprintPhysics>("Physics", offsetof(RProjectileBlueprint, Physics));
    physicsField->mFlags = 3;
    physicsField->mDesc = "Physics information for the Projectile";
  }

  /**
   * Address: 0x0051C2C0 (FUN_0051C2C0)
   *
   * What it does:
   * Sets `RProjectileBlueprint` size, registers `REntityBlueprint` base
   * metadata, and publishes projectile-blueprint fields.
   */
  void RProjectileBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RProjectileBlueprint);
    AddBaseREntityBlueprint(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC86B0 (FUN_00BC86B0, register_RProjectileBlueprintTypeInfo)
   */
  void register_RProjectileBlueprintTypeInfo()
  {
    (void)AcquireRProjectileBlueprintTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RProjectileBlueprintTypeInfo_ed1a04, moho::register_RProjectileBlueprintTypeInfo)
