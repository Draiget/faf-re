#include "RUnitBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "legacy/containers/Vector.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace
{
  using TypeInfo = moho::RUnitBlueprintTypeInfo;

  alignas(TypeInfo) unsigned char gRUnitBlueprintTypeInfoStorage[sizeof(TypeInfo)];
  bool gRUnitBlueprintTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRUnitBlueprintTypeInfo()
  {
    if (!gRUnitBlueprintTypeInfoConstructed) {
      new (gRUnitBlueprintTypeInfoStorage) TypeInfo();
      gRUnitBlueprintTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRUnitBlueprintTypeInfoStorage);
  }

  void cleanup_RUnitBlueprintTypeInfo()
  {
    if (!gRUnitBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireRUnitBlueprintTypeInfo().~TypeInfo();
    gRUnitBlueprintTypeInfoConstructed = false;
  }

  gpg::RType* CachedEntityBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REntityBlueprint));
    }
    return cached;
  }

  gpg::RType* CachedGeneralType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintGeneral));
    }
    return cached;
  }

  gpg::RType* CachedDisplayType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintDisplay));
    }
    return cached;
  }

  gpg::RType* CachedPhysicsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintPhysics));
    }
    return cached;
  }

  gpg::RType* CachedAirType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintAir));
    }
    return cached;
  }

  gpg::RType* CachedTransportType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintTransport));
    }
    return cached;
  }

  gpg::RType* CachedDefenseType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintDefense));
    }
    return cached;
  }

  gpg::RType* CachedAiType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintAI));
    }
    return cached;
  }

  gpg::RType* CachedIntelType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintIntel));
    }
    return cached;
  }

  gpg::RType* CachedWeaponVectorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::vector<moho::RUnitBlueprintWeapon>));
    }
    return cached;
  }

  gpg::RType* CachedEconomyType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintEconomy));
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

  struct RUnitBlueprintTypeInfoBootstrap
  {
    RUnitBlueprintTypeInfoBootstrap()
    {
      moho::register_RUnitBlueprintTypeInfo();
    }
  };

  RUnitBlueprintTypeInfoBootstrap gRUnitBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00522940 (FUN_00522940, Moho::RUnitBlueprintTypeInfo::RUnitBlueprintTypeInfo)
   */
  RUnitBlueprintTypeInfo::RUnitBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprint), this);
  }

  /**
   * Address: 0x00BF36F0 (FUN_00BF36F0, scalar deleting destructor thunk)
   */
  RUnitBlueprintTypeInfo::~RUnitBlueprintTypeInfo() = default;

  /**
   * Address: 0x005229D0 (FUN_005229D0)
   */
  const char* RUnitBlueprintTypeInfo::GetName() const
  {
    return "RUnitBlueprint";
  }

  /**
   * Address: 0x00525820 (FUN_00525820)
   *
   * What it does:
   * Adds `REntityBlueprint` as the reflected base class lane.
   */
  void RUnitBlueprintTypeInfo::AddBaseREntityBlueprint(gpg::RType* const typeInfo)
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
   * Address: 0x00522A80 (FUN_00522A80)
   *
   * What it does:
   * Registers unit-blueprint section field descriptors and descriptions.
   */
  void RUnitBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "General", CachedGeneralType(), 0x17C, "General information for the unit");
    AddFieldWithDescription(typeInfo, "Display", CachedDisplayType(), 0x200, "Display information for the unit");
    AddFieldWithDescription(typeInfo, "Physics", CachedPhysicsType(), 0x278, "Physics information for the unit");
    AddFieldWithDescription(typeInfo, "Air", CachedAirType(), 0x368, "Air control information for the unit");
    AddFieldWithDescription(
      typeInfo,
      "Transport",
      CachedTransportType(),
      0x3F8,
      "Transport related information for the unit"
    );
    AddFieldWithDescription(typeInfo, "Defense", CachedDefenseType(), 0x420, "Defense information for the unit");
    AddFieldWithDescription(typeInfo, "AI", CachedAiType(), 0x460, "AI information for the unit");
    AddFieldWithDescription(typeInfo, "Intel", CachedIntelType(), 0x330, "Intel information for the unit");
    AddFieldWithDescription(typeInfo, "Weapon", CachedWeaponVectorType(), 0x4D4, "Weapon information for the unit");
    AddFieldWithDescription(typeInfo, "Economy", CachedEconomyType(), 0x4E8, "Economy information for the unit");
  }

  /**
   * Address: 0x005229A0 (FUN_005229A0)
   *
   * What it does:
   * Sets `RUnitBlueprint` size, registers `REntityBlueprint` base metadata,
   * and publishes unit-blueprint section fields.
   */
  void RUnitBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprint);
    AddBaseREntityBlueprint(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC8C10 (FUN_00BC8C10, register_RUnitBlueprintTypeInfo)
   */
  void register_RUnitBlueprintTypeInfo()
  {
    (void)AcquireRUnitBlueprintTypeInfo();
    (void)std::atexit(&cleanup_RUnitBlueprintTypeInfo);
  }
} // namespace moho

