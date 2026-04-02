#include "RPropBlueprintDisplayTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RPropBlueprint.h"

namespace
{
  using TypeInfo = moho::RPropBlueprintDisplayTypeInfo;

  alignas(TypeInfo) unsigned char gRPropBlueprintDisplayTypeInfoStorage[sizeof(TypeInfo)];
  bool gRPropBlueprintDisplayTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRPropBlueprintDisplayTypeInfo()
  {
    if (!gRPropBlueprintDisplayTypeInfoConstructed) {
      new (gRPropBlueprintDisplayTypeInfoStorage) TypeInfo();
      gRPropBlueprintDisplayTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRPropBlueprintDisplayTypeInfoStorage);
  }

  void cleanup_RPropBlueprintDisplayTypeInfo()
  {
    if (!gRPropBlueprintDisplayTypeInfoConstructed) {
      return;
    }

    AcquireRPropBlueprintDisplayTypeInfo().~TypeInfo();
    gRPropBlueprintDisplayTypeInfoConstructed = false;
  }

  gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
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

  struct RPropBlueprintDisplayTypeInfoBootstrap
  {
    RPropBlueprintDisplayTypeInfoBootstrap()
    {
      (void)moho::register_RPropBlueprintDisplayTypeInfo();
    }
  };

  RPropBlueprintDisplayTypeInfoBootstrap gRPropBlueprintDisplayTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0051D450 (FUN_0051D450, Moho::RPropBlueprintDisplayTypeInfo::RPropBlueprintDisplayTypeInfo)
   */
  RPropBlueprintDisplayTypeInfo::RPropBlueprintDisplayTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RPropBlueprintDisplay), this);
  }

  /**
   * Address: 0x0051D510 (FUN_0051D510, scalar deleting destructor thunk)
   */
  RPropBlueprintDisplayTypeInfo::~RPropBlueprintDisplayTypeInfo() = default;

  /**
   * Address: 0x0051D500 (FUN_0051D500)
   */
  const char* RPropBlueprintDisplayTypeInfo::GetName() const
  {
    return "RPropBlueprintDisplay";
  }

  /**
   * Address: 0x0051D4B0 (FUN_0051D4B0)
   *
   * What it does:
   * Sets `RPropBlueprintDisplay` size and publishes display field metadata.
   */
  void RPropBlueprintDisplayTypeInfo::Init()
  {
    size_ = sizeof(RPropBlueprintDisplay);
    gpg::RType::Init();
    AddFieldWithDescription(
      this,
      "MeshBlueprint",
      CachedRResIdType(),
      0x00,
      "Name of mesh blueprint to use. Leave blank to use default mesh."
    );
    AddFieldWithDescription(this, "UniformScale", CachedFloatType(), 0x1C, "Uniform scale to apply to mesh");
    Finish();
  }

  /**
   * Address: 0x00BC87B0 (FUN_00BC87B0, register_RPropBlueprintDisplayTypeInfo)
   */
  int register_RPropBlueprintDisplayTypeInfo()
  {
    (void)AcquireRPropBlueprintDisplayTypeInfo();
    return std::atexit(&cleanup_RPropBlueprintDisplayTypeInfo);
  }
} // namespace moho
