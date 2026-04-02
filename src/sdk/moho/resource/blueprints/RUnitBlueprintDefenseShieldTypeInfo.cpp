#include "RUnitBlueprintDefenseShieldTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace
{
  using TypeInfo = moho::RUnitBlueprintDefenseShieldTypeInfo;

  alignas(TypeInfo) unsigned char gRUnitBlueprintDefenseShieldTypeInfoStorage[sizeof(TypeInfo)];
  bool gRUnitBlueprintDefenseShieldTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRUnitBlueprintDefenseShieldTypeInfo()
  {
    if (!gRUnitBlueprintDefenseShieldTypeInfoConstructed) {
      new (gRUnitBlueprintDefenseShieldTypeInfoStorage) TypeInfo();
      gRUnitBlueprintDefenseShieldTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRUnitBlueprintDefenseShieldTypeInfoStorage);
  }

  void cleanup_RUnitBlueprintDefenseShieldTypeInfo()
  {
    if (!gRUnitBlueprintDefenseShieldTypeInfoConstructed) {
      return;
    }

    AcquireRUnitBlueprintDefenseShieldTypeInfo().~TypeInfo();
    gRUnitBlueprintDefenseShieldTypeInfoConstructed = false;
  }

  gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
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

  struct RUnitBlueprintDefenseShieldTypeInfoBootstrap
  {
    RUnitBlueprintDefenseShieldTypeInfoBootstrap()
    {
      moho::register_RUnitBlueprintDefenseShieldTypeInfo();
    }
  };

  RUnitBlueprintDefenseShieldTypeInfoBootstrap gRUnitBlueprintDefenseShieldTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x005217D0 (FUN_005217D0, Moho::RUnitBlueprintDefenseShieldTypeInfo::RUnitBlueprintDefenseShieldTypeInfo)
   */
  RUnitBlueprintDefenseShieldTypeInfo::RUnitBlueprintDefenseShieldTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintDefenseShield), this);
  }

  /**
   * Address: 0x00BF3500 (FUN_00BF3500, scalar deleting destructor thunk)
   */
  RUnitBlueprintDefenseShieldTypeInfo::~RUnitBlueprintDefenseShieldTypeInfo() = default;

  /**
   * Address: 0x00521890 (FUN_00521890)
   */
  const char* RUnitBlueprintDefenseShieldTypeInfo::GetName() const
  {
    return "RUnitBlueprintDefenseShield";
  }

  /**
   * Address: 0x00521830 (FUN_00521830)
   *
   * What it does:
   * Sets `RUnitBlueprintDefenseShield` size and publishes shield field
   * metadata.
   */
  void RUnitBlueprintDefenseShieldTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintDefenseShield);
    gpg::RType::Init();
    AddFieldWithDescription(this, "ShieldSize", CachedFloatType(), 0x00, "Shield diameter");
    AddFieldWithDescription(this, "RegenAssistMult", CachedFloatType(), 0x04, "Regen assist multiplier");
    Finish();
  }

  /**
   * Address: 0x00BC8B50 (FUN_00BC8B50, register_RUnitBlueprintDefenseShieldTypeInfo)
   */
  void register_RUnitBlueprintDefenseShieldTypeInfo()
  {
    (void)AcquireRUnitBlueprintDefenseShieldTypeInfo();
    (void)std::atexit(&cleanup_RUnitBlueprintDefenseShieldTypeInfo);
  }
} // namespace moho

