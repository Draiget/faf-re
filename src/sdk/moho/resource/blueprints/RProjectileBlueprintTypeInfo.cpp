#include "RProjectileBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "legacy/containers/String.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"

namespace
{
  using TypeInfo = moho::RProjectileBlueprintTypeInfo;

  alignas(TypeInfo) unsigned char gRProjectileBlueprintTypeInfoStorage[sizeof(TypeInfo)];
  bool gRProjectileBlueprintTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRProjectileBlueprintTypeInfo()
  {
    if (!gRProjectileBlueprintTypeInfoConstructed) {
      new (gRProjectileBlueprintTypeInfoStorage) TypeInfo();
      gRProjectileBlueprintTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRProjectileBlueprintTypeInfoStorage);
  }

  void cleanup_RProjectileBlueprintTypeInfo()
  {
    if (!gRProjectileBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireRProjectileBlueprintTypeInfo().~TypeInfo();
    gRProjectileBlueprintTypeInfoConstructed = false;
  }

  gpg::RType* CachedEntityBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REntityBlueprint));
    }
    return cached;
  }

  gpg::RType* CachedStringType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::string));
    }
    return cached;
  }

  gpg::RType* CachedProjectileDisplayType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RProjectileBlueprintDisplay));
    }
    return cached;
  }

  gpg::RType* CachedProjectileEconomyType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RProjectileBlueprintEconomy));
    }
    return cached;
  }

  gpg::RType* CachedProjectilePhysicsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RProjectileBlueprintPhysics));
    }
    return cached;
  }

  void AddFieldWithDescription(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int offset,
    const char* const description
  )
  {
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset, 3, description));
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
    baseField.v4 = 0;
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
    AddFieldWithDescription(typeInfo, "DevStatus", CachedStringType(), 0x17C, "Development Status");
    AddFieldWithDescription(
      typeInfo,
      "Display",
      CachedProjectileDisplayType(),
      0x198,
      "Display information for the Projectile"
    );
    AddFieldWithDescription(
      typeInfo,
      "Economy",
      CachedProjectileEconomyType(),
      0x1D0,
      "Economy information for the unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "Physics",
      CachedProjectilePhysicsType(),
      0x1DC,
      "Physics information for the Projectile"
    );
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
  int register_RProjectileBlueprintTypeInfo()
  {
    (void)AcquireRProjectileBlueprintTypeInfo();
    return std::atexit(&cleanup_RProjectileBlueprintTypeInfo);
  }
} // namespace moho
