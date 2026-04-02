#include "RMeshBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "legacy/containers/Vector.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"

namespace
{
  using TypeInfo = moho::RMeshBlueprintTypeInfo;

  alignas(TypeInfo) unsigned char gRMeshBlueprintTypeInfoStorage[sizeof(TypeInfo)];
  bool gRMeshBlueprintTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRMeshBlueprintTypeInfo()
  {
    if (!gRMeshBlueprintTypeInfoConstructed) {
      new (gRMeshBlueprintTypeInfoStorage) TypeInfo();
      gRMeshBlueprintTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRMeshBlueprintTypeInfoStorage);
  }

  void cleanup_RMeshBlueprintTypeInfo()
  {
    if (!gRMeshBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireRMeshBlueprintTypeInfo().~TypeInfo();
    gRMeshBlueprintTypeInfoConstructed = false;
  }

  gpg::RType* CachedRBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RBlueprint));
    }
    return cached;
  }

  gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
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

  gpg::RType* CachedMeshLodVectorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::vector<moho::RMeshBlueprintLOD>));
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

  struct RMeshBlueprintTypeInfoBootstrap
  {
    RMeshBlueprintTypeInfoBootstrap()
    {
      (void)moho::register_RMeshBlueprintTypeInfo();
    }
  };

  RMeshBlueprintTypeInfoBootstrap gRMeshBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x005186B0 (FUN_005186B0, Moho::RMeshBlueprintTypeInfo::RMeshBlueprintTypeInfo)
   */
  RMeshBlueprintTypeInfo::RMeshBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RMeshBlueprint), this);
  }

  /**
   * Address: 0x00BF2C60 (FUN_00BF2C60, scalar deleting destructor thunk)
   */
  RMeshBlueprintTypeInfo::~RMeshBlueprintTypeInfo() = default;

  /**
   * Address: 0x00518740 (FUN_00518740)
   */
  const char* RMeshBlueprintTypeInfo::GetName() const
  {
    return "RMeshBlueprint";
  }

  /**
   * Address: 0x0051A2D0 (FUN_0051A2D0)
   *
   * What it does:
   * Adds `RBlueprint` as the reflected base class lane.
   */
  void RMeshBlueprintTypeInfo::AddBaseRBlueprint(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedRBlueprintType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x005187F0 (FUN_005187F0)
   *
   * What it does:
   * Registers mesh-blueprint field descriptors and descriptions.
   */
  void RMeshBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "LODs", CachedMeshLodVectorType(), 0x60, "List of LOD info");
    AddFieldWithDescription(
      typeInfo,
      "IconFadeInZoom",
      CachedFloatType(),
      0x70,
      "Zoom level at which to start fading in the strategic icon"
    );
    AddFieldWithDescription(typeInfo, "SortOrder", CachedFloatType(), 0x74, "Sort order of mesh we render smallest to largest");
    AddFieldWithDescription(typeInfo, "UniformScale", CachedFloatType(), 0x78, "Uniform scale factor");
    AddFieldWithDescription(typeInfo, "StraddleWater", CachedBoolType(), 0x7C, "Render both above and below the water.");
  }

  /**
   * Address: 0x00518710 (FUN_00518710)
   *
   * What it does:
   * Sets `RMeshBlueprint` size, registers `RBlueprint` base metadata, and
   * publishes mesh-blueprint fields.
   */
  void RMeshBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RMeshBlueprint);
    AddBaseRBlueprint(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC8530 (FUN_00BC8530, register_RMeshBlueprintTypeInfo)
   */
  int register_RMeshBlueprintTypeInfo()
  {
    (void)AcquireRMeshBlueprintTypeInfo();
    return std::atexit(&cleanup_RMeshBlueprintTypeInfo);
  }
} // namespace moho
