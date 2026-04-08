#include "RPropBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"

namespace
{
  using TypeInfo = moho::RPropBlueprintTypeInfo;

  alignas(TypeInfo) unsigned char gRPropBlueprintTypeInfoStorage[sizeof(TypeInfo)];
  bool gRPropBlueprintTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRPropBlueprintTypeInfo()
  {
    if (!gRPropBlueprintTypeInfoConstructed) {
      new (gRPropBlueprintTypeInfoStorage) TypeInfo();
      gRPropBlueprintTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRPropBlueprintTypeInfoStorage);
  }

  /**
   * Address: 0x00BF30F0 (FUN_00BF30F0, Moho::RPropBlueprintTypeInfo::~RPropBlueprintTypeInfo)
   *
   * What it does:
   * Tears down process-global `RPropBlueprintTypeInfo` storage.
   */
  void cleanup_RPropBlueprintTypeInfo()
  {
    if (!gRPropBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireRPropBlueprintTypeInfo().~TypeInfo();
    gRPropBlueprintTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedEntityBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::REntityBlueprint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedPropDisplayType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RPropBlueprintDisplay));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedPropDefenseType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RPropBlueprintDefense));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedPropEconomyType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RPropBlueprintEconomy));
    }
    return cached;
  }

  [[nodiscard]] gpg::RField* AppendField(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int fieldOffset
  )
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);

    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, fieldOffset, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  struct RPropBlueprintTypeInfoBootstrap
  {
    RPropBlueprintTypeInfoBootstrap()
    {
      moho::register_RPropBlueprintTypeInfo();
    }
  };

  [[maybe_unused]] RPropBlueprintTypeInfoBootstrap gRPropBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0051D950 (FUN_0051D950, Moho::RPropBlueprintTypeInfo::RPropBlueprintTypeInfo)
   */
  RPropBlueprintTypeInfo::RPropBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RPropBlueprint), this);
  }

  /**
   * Address: 0x0051DA20 (FUN_0051DA20, Moho::RPropBlueprintTypeInfo::dtr)
   */
  RPropBlueprintTypeInfo::~RPropBlueprintTypeInfo() = default;

  /**
   * Address: 0x0051DA10 (FUN_0051DA10, Moho::RPropBlueprintTypeInfo::GetName)
   */
  const char* RPropBlueprintTypeInfo::GetName() const
  {
    return "RPropBlueprint";
  }

  /**
   * Address: 0x0051DEA0 (FUN_0051DEA0, Moho::RPropBlueprintTypeInfo::AddBase_REntityBlueprint)
   */
  void RPropBlueprintTypeInfo::AddBaseREntityBlueprint(gpg::RType* const typeInfo)
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
   * Address: 0x0051DF00 (FUN_0051DF00, gpg::RType::AddField_RPropBlueprintDisplay_0x17CDisplay)
   */
  gpg::RField* RPropBlueprintTypeInfo::AddFieldDisplay(gpg::RType* const typeInfo)
  {
    return AppendField(typeInfo, "Display", CachedPropDisplayType(), 0x17C);
  }

  /**
   * Address: 0x0051DF80 (FUN_0051DF80, gpg::RType::AddField_RPropBlueprintDefense_0x19CDefense)
   */
  gpg::RField* RPropBlueprintTypeInfo::AddFieldDefense(gpg::RType* const typeInfo)
  {
    return AppendField(typeInfo, "Defense", CachedPropDefenseType(), 0x19C);
  }

  /**
   * Address: 0x0051E000 (FUN_0051E000, gpg::RType::AddField_RPropBlueprintEconomy_0x1A4Economy)
   */
  gpg::RField* RPropBlueprintTypeInfo::AddFieldEconomy(gpg::RType* const typeInfo)
  {
    return AppendField(typeInfo, "Economy", CachedPropEconomyType(), 0x1A4);
  }

  /**
   * Address: 0x0051D9B0 (FUN_0051D9B0, Moho::RPropBlueprintTypeInfo::Init)
   */
  void RPropBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RPropBlueprint);
    AddBaseREntityBlueprint(this);
    gpg::RType::Init();

    gpg::RField* const displayField = AddFieldDisplay(this);
    displayField->v4 = 3;
    displayField->mDesc = "Display information for the unit";

    gpg::RField* const defenseField = AddFieldDefense(this);
    defenseField->v4 = 3;
    defenseField->mDesc = "Defense information for the unit";

    gpg::RField* const economyField = AddFieldEconomy(this);
    economyField->v4 = 3;
    economyField->mDesc = "Economy information for the unit";

    Finish();
  }

  /**
   * Address: 0x00BC8810 (FUN_00BC8810, register_RPropBlueprintTypeInfo)
   */
  void register_RPropBlueprintTypeInfo()
  {
    (void)AcquireRPropBlueprintTypeInfo();
    (void)std::atexit(&cleanup_RPropBlueprintTypeInfo);
  }
} // namespace moho
