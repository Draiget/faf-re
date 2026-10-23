#include "RUnitBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "legacy/containers/Vector.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprintWeaponVectorReflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RUnitBlueprintTypeInfo;

  [[nodiscard]] TypeInfo& AcquireRUnitBlueprintTypeInfo()
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
    baseField.mFlags = 0;
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
    gpg::RField* const generalField = typeInfo->AddField<moho::RUnitBlueprintGeneral>("General", offsetof(RUnitBlueprint, General));
    generalField->mFlags = 3;
    generalField->mDesc = "General information for the unit";

    gpg::RField* const displayField = typeInfo->AddField<moho::RUnitBlueprintDisplay>("Display", offsetof(RUnitBlueprint, Display));
    displayField->mFlags = 3;
    displayField->mDesc = "Display information for the unit";

    gpg::RField* const physicsField = typeInfo->AddField<moho::RUnitBlueprintPhysics>("Physics", offsetof(RUnitBlueprint, Physics));
    physicsField->mFlags = 3;
    physicsField->mDesc = "Physics information for the unit";

    gpg::RField* const airField = typeInfo->AddField<moho::RUnitBlueprintAir>("Air", offsetof(RUnitBlueprint, Air));
    airField->mFlags = 3;
    airField->mDesc = "Air control information for the unit";

    gpg::RField* const transportField = typeInfo->AddField<moho::RUnitBlueprintTransport>("Transport", offsetof(RUnitBlueprint, Transport));
    transportField->mFlags = 3;
    transportField->mDesc = "Transport related information for the unit";

    gpg::RField* const defenseField = typeInfo->AddField<moho::RUnitBlueprintDefense>("Defense", offsetof(RUnitBlueprint, Defense));
    defenseField->mFlags = 3;
    defenseField->mDesc = "Defense information for the unit";

    gpg::RField* const aiField = typeInfo->AddField<moho::RUnitBlueprintAI>("AI", offsetof(RUnitBlueprint, AI));
    aiField->mFlags = 3;
    aiField->mDesc = "AI information for the unit";

    gpg::RField* const intelField = typeInfo->AddField<moho::RUnitBlueprintIntel>("Intel", offsetof(RUnitBlueprint, Intel));
    intelField->mFlags = 3;
    intelField->mDesc = "Intel information for the unit";

    gpg::RField* const weaponField = typeInfo->AddField<msvc8::vector<moho::RUnitBlueprintWeapon>>("Weapons", offsetof(RUnitBlueprint, Weapons));
    weaponField->mName = "Weapon";
    weaponField->mFlags = 3;
    weaponField->mDesc = "Weapon information for the unit";

    gpg::RField* const economyField = typeInfo->AddField<moho::RUnitBlueprintEconomy>("Economy", offsetof(RUnitBlueprint, Economy));
    economyField->mFlags = 3;
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
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RUnitBlueprintTypeInfo_79d1ea, moho::register_RUnitBlueprintTypeInfo)
