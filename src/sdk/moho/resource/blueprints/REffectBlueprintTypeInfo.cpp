#include "REffectBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/blueprints/REffectBlueprint.h"
#include "moho/resource/RResId.h"

namespace
{
  using TypeInfo = moho::REffectBlueprintTypeInfo;

  alignas(TypeInfo) unsigned char gREffectBlueprintTypeInfoStorage[sizeof(TypeInfo)];
  bool gREffectBlueprintTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireREffectBlueprintTypeInfo()
  {
    if (!gREffectBlueprintTypeInfoConstructed) {
      new (gREffectBlueprintTypeInfoStorage) TypeInfo();
      gREffectBlueprintTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gREffectBlueprintTypeInfoStorage);
  }

  void cleanup_REffectBlueprintTypeInfo()
  {
    if (!gREffectBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireREffectBlueprintTypeInfo().~TypeInfo();
    gREffectBlueprintTypeInfoConstructed = false;
  }

  gpg::RType* CachedRObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::RObject));
    }
    return cached;
  }

  gpg::RType* CachedRResIdType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RResId));
    }
    return cached;
  }

  gpg::RType* CachedBoolType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(bool));
    }
    return cached;
  }

  void AddFieldWithDescription(
    gpg::RType* typeInfo, const char* fieldName, gpg::RType* fieldType, const int offset, const char* description
  )
  {
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset, 3, description));
  }

  void AddRObjectBase(gpg::RType* typeInfo)
  {
    gpg::RType* const rObjectType = CachedRObjectType();
    gpg::RField baseField(rObjectType->GetName(), rObjectType, 0);
    typeInfo->AddBase(baseField);
  }

  struct REffectBlueprintTypeInfoBootstrap
  {
    REffectBlueprintTypeInfoBootstrap()
    {
      moho::register_REffectBlueprintTypeInfo();
    }
  };

  REffectBlueprintTypeInfoBootstrap gREffectBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050F020 (FUN_0050F020, Moho::REffectBlueprintTypeInfo::REffectBlueprintTypeInfo)
   */
  REffectBlueprintTypeInfo::REffectBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(REffectBlueprint), this);
  }

  /**
   * Address: 0x0050F0C0 (FUN_0050F0C0, scalar deleting destructor thunk)
   */
  REffectBlueprintTypeInfo::~REffectBlueprintTypeInfo() = default;

  /**
   * Address: 0x0050F0B0 (FUN_0050F0B0)
   */
  const char* REffectBlueprintTypeInfo::GetName() const
  {
    return "REffectBlueprint";
  }

  /**
   * Address: 0x0050F080 (FUN_0050F080)
   *
   * What it does:
   * Sets `REffectBlueprint` size, registers `RObject` base metadata, and
   * publishes base effect-blueprint fields.
   */
  void REffectBlueprintTypeInfo::Init()
  {
    size_ = sizeof(REffectBlueprint);
    AddRObjectBase(this);
    gpg::RType::Init();
    AddFields();
    Finish();
  }

  /**
   * Address: 0x0050F160 (FUN_0050F160, Moho::REffectBlueprintTypeInfo::AddFields)
   *
   * What it does:
   * Registers reflected `REffectBlueprint` field lanes and field metadata text.
   */
  void REffectBlueprintTypeInfo::AddFields()
  {
    AddFieldWithDescription(this, "BlueprintId", CachedRResIdType(), 0x08, "Blueprint ID");
    AddFieldWithDescription(this, "HighFidelity", CachedBoolType(), 0x24, "Allowed in high fidelity");
    AddFieldWithDescription(this, "MedFidelity", CachedBoolType(), 0x25, "Allowed in medium fidelity");
    AddFieldWithDescription(this, "LowFidelity", CachedBoolType(), 0x26, "Allowed in low fidelity");
  }

  /**
   * Address: 0x00BC8050 (FUN_00BC8050, register_REffectBlueprintTypeInfo)
   */
  void register_REffectBlueprintTypeInfo()
  {
    (void)AcquireREffectBlueprintTypeInfo();
    (void)std::atexit(&cleanup_REffectBlueprintTypeInfo);
  }
} // namespace moho
