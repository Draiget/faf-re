#include "RUnitBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "legacy/containers/Vector.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprintWeaponVectorReflection.h"

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

  /**
   * Address: 0x005263B0 (FUN_005263B0, preregister_VectorRUnitBlueprintWeaponTypeStartup)
   *
   * What it does:
   * Constructs and preregisters startup reflection RTTI for
   * `msvc8::vector<moho::RUnitBlueprintWeapon>`.
   */
  [[nodiscard]] gpg::RType* preregister_VectorRUnitBlueprintWeaponTypeStartup()
  {
    return moho::preregister_VectorRUnitBlueprintWeaponType();
  }

  gpg::RType* CachedWeaponVectorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = preregister_VectorRUnitBlueprintWeaponTypeStartup();
      if (!cached) {
        cached = gpg::LookupRType(typeid(msvc8::vector<moho::RUnitBlueprintWeapon>));
      }
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

  struct RUnitBlueprintTypeInfoBootstrap
  {
    RUnitBlueprintTypeInfoBootstrap()
    {
      (void)preregister_VectorRUnitBlueprintWeaponTypeStartup();
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
   * Address: 0x00525880 (FUN_00525880, gpg::RType::AddField_RUnitBlueprintGeneral_0x17CGeneral)
   *
   * What it does:
   * Appends the reflected `General` section field descriptor at offset `0x17C`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldGeneral(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("General", CachedGeneralType(), 0x17C, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525900 (FUN_00525900, gpg::RType::AddField_RUnitBlueprintDisplay_0x200Display)
   *
   * What it does:
   * Appends the reflected `Display` section field descriptor at offset `0x200`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldDisplaySection(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("Display", CachedDisplayType(), 0x200, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525980 (FUN_00525980, gpg::RType::AddField_RUnitBlueprintPhysics_0x278Physics)
   *
   * What it does:
   * Appends the reflected `Physics` section field descriptor at offset `0x278`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldPhysicsSection(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("Physics", CachedPhysicsType(), 0x278, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525A00 (FUN_00525A00, gpg::RType::AddField_RUnitBlueprintAir_0x368Air)
   *
   * What it does:
   * Appends the reflected `Air` section field descriptor at offset `0x368`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldAirSection(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("Air", CachedAirType(), 0x368, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525A80 (FUN_00525A80, gpg::RType::AddField_RUnitBlueprintTransport_0x3F8Transport)
   *
   * What it does:
   * Appends the reflected `Transport` section field descriptor at offset `0x3F8`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldTransportSection(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("Transport", CachedTransportType(), 0x3F8, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525B00 (FUN_00525B00, gpg::RType::AddField_RUnitBlueprintDefense_0x420Defense)
   *
   * What it does:
   * Appends the reflected `Defense` section field descriptor at offset `0x420`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldDefenseSection(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("Defense", CachedDefenseType(), 0x420, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525B80 (FUN_00525B80, gpg::RType::AddField_RUnitBlueprintAI_0x460AI)
   *
   * What it does:
   * Appends the reflected `AI` section field descriptor at offset `0x460`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldAiSection(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("AI", CachedAiType(), 0x460, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525C00 (FUN_00525C00, gpg::RType::AddField_RUnitBlueprintIntel_0x330Intel)
   *
   * What it does:
   * Appends the reflected `Intel` section field descriptor at offset `0x330`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldIntelSection(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("Intel", CachedIntelType(), 0x330, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525C80 (FUN_00525C80, gpg::RType::AddField_vector_RUnitBlueprintWeapon_0x4D4Weapons)
   *
   * What it does:
   * Appends the reflected `Weapons` section field descriptor at offset `0x4D4`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldWeaponSection(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("Weapons", CachedWeaponVectorType(), 0x4D4, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525D00 (FUN_00525D00, gpg::RType::AddField_RUnitBlueprintEconomy_0x4E8Economy)
   *
   * What it does:
   * Appends the reflected `Economy` section field descriptor at offset `0x4E8`.
   */
  gpg::RField* RUnitBlueprintTypeInfo::AddFieldEconomySection(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("Economy", CachedEconomyType(), 0x4E8, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00522A80 (FUN_00522A80)
   *
   * What it does:
   * Registers unit-blueprint section field descriptors and descriptions.
   */
  void RUnitBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    gpg::RField* const generalField = AddFieldGeneral(typeInfo);
    generalField->v4 = 3;
    generalField->mDesc = "General information for the unit";

    gpg::RField* const displayField = AddFieldDisplaySection(typeInfo);
    displayField->v4 = 3;
    displayField->mDesc = "Display information for the unit";

    gpg::RField* const physicsField = AddFieldPhysicsSection(typeInfo);
    physicsField->v4 = 3;
    physicsField->mDesc = "Physics information for the unit";

    gpg::RField* const airField = AddFieldAirSection(typeInfo);
    airField->v4 = 3;
    airField->mDesc = "Air control information for the unit";

    gpg::RField* const transportField = AddFieldTransportSection(typeInfo);
    transportField->v4 = 3;
    transportField->mDesc = "Transport related information for the unit";

    gpg::RField* const defenseField = AddFieldDefenseSection(typeInfo);
    defenseField->v4 = 3;
    defenseField->mDesc = "Defense information for the unit";

    gpg::RField* const aiField = AddFieldAiSection(typeInfo);
    aiField->v4 = 3;
    aiField->mDesc = "AI information for the unit";

    gpg::RField* const intelField = AddFieldIntelSection(typeInfo);
    intelField->v4 = 3;
    intelField->mDesc = "Intel information for the unit";

    gpg::RField* const weaponField = AddFieldWeaponSection(typeInfo);
    weaponField->mName = "Weapon";
    weaponField->v4 = 3;
    weaponField->mDesc = "Weapon information for the unit";

    gpg::RField* const economyField = AddFieldEconomySection(typeInfo);
    economyField->v4 = 3;
    economyField->mDesc = "Economy information for the unit";
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
