#include "REffectBlueprintTypeInfo.h"

#include <typeinfo>

#include "moho/resource/blueprints/REffectBlueprint.h"
#include "moho/resource/RResId.h"

namespace
{
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

  void RegisterEffectFields(gpg::RType* typeInfo)
  {
    AddFieldWithDescription(typeInfo, "BlueprintId", CachedRResIdType(), 0x08, "Blueprint ID");
    AddFieldWithDescription(typeInfo, "HighFidelity", CachedBoolType(), 0x24, "Allowed in high fidelity");
    AddFieldWithDescription(typeInfo, "MedFidelity", CachedBoolType(), 0x25, "Allowed in medium fidelity");
    AddFieldWithDescription(typeInfo, "LowFidelity", CachedBoolType(), 0x26, "Allowed in low fidelity");
  }
} // namespace

namespace moho
{
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
    RegisterEffectFields(this);
    Finish();
  }
} // namespace moho
