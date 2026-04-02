#include "moho/entity/REntityBlueprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/collision/ECollisionShape.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/sim/SFootprint.h"

namespace
{
  using TypeInfo = moho::REntityBlueprintTypeInfo;

  alignas(TypeInfo) unsigned char gREntityBlueprintTypeInfoStorage[sizeof(TypeInfo)];
  bool gREntityBlueprintTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireREntityBlueprintTypeInfo()
  {
    if (!gREntityBlueprintTypeInfoConstructed) {
      new (gREntityBlueprintTypeInfoStorage) TypeInfo();
      gREntityBlueprintTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gREntityBlueprintTypeInfoStorage);
  }

  void cleanup_REntityBlueprintTypeInfo()
  {
    if (!gREntityBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireREntityBlueprintTypeInfo().~TypeInfo();
    gREntityBlueprintTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedRBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RBlueprint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVectorStringType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::vector<msvc8::string>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedStringType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::string));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCollisionShapeType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::ECollisionShape));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIntType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(int));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedBoolType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(bool));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedUCharType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(unsigned char));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedFootprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SFootprint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedRResIdType()
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

  struct REntityBlueprintTypeInfoBootstrap
  {
    REntityBlueprintTypeInfoBootstrap()
    {
      moho::register_REntityBlueprintTypeInfo();
    }
  };

  REntityBlueprintTypeInfoBootstrap gREntityBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00512730 (FUN_00512730, Moho::REntityBlueprintTypeInfo::REntityBlueprintTypeInfo)
   */
  REntityBlueprintTypeInfo::REntityBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(REntityBlueprint), this);
  }

  /**
   * Address: 0x005127D0 (FUN_005127D0, Moho::REntityBlueprintTypeInfo::dtr)
   */
  REntityBlueprintTypeInfo::~REntityBlueprintTypeInfo() = default;

  /**
   * Address: 0x005127C0 (FUN_005127C0, Moho::REntityBlueprintTypeInfo::GetName)
   */
  const char* REntityBlueprintTypeInfo::GetName() const
  {
    return "REntityBlueprint";
  }

  /**
   * Address: 0x005131D0 (FUN_005131D0, Moho::REntityBlueprintTypeInfo::AddBase_RBlueprint)
   *
   * What it does:
   * Adds `RBlueprint` as the reflected base lane at offset 0.
   */
  void REntityBlueprintTypeInfo::AddBaseRBlueprint(gpg::RType* const typeInfo)
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
   * Address: 0x00512870 (FUN_00512870, Moho::REntityBlueprintTypeInfo::AddFields)
   *
   * What it does:
   * Registers entity-blueprint reflection fields, version tags, and editor
   * help text in the same order as the binary.
   */
  void REntityBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(
      typeInfo,
      "Categories",
      CachedVectorStringType(),
      0x60,
      "Named categories that this entity belongs to"
    );
    AddFieldWithDescription(typeInfo, "ScriptModule", CachedStringType(), 0x70, "Module defining entity's class.");
    AddFieldWithDescription(typeInfo, "ScriptClass", CachedStringType(), 0x8C, "Name of entity's class.");
    AddFieldWithDescription(
      typeInfo,
      "CollisionShape",
      CachedCollisionShapeType(),
      0xA8,
      "Shape to use for collision db, 'None' for no collision."
    );
    AddFieldWithDescription(typeInfo, "SizeX", CachedFloatType(), 0xAC, "Unit size X");
    AddFieldWithDescription(typeInfo, "SizeY", CachedFloatType(), 0xB0, "Unit size Y");
    AddFieldWithDescription(typeInfo, "SizeZ", CachedFloatType(), 0xB4, "Unit size Z");
    AddFieldWithDescription(
      typeInfo,
      "AverageDensity",
      CachedFloatType(),
      0xB8,
      "Unit average density in tons / m^3. (Default is 0.49)"
    );
    AddFieldWithDescription(typeInfo, "InertiaTensorX", CachedFloatType(), 0xBC, "Component X,X of inertia tensor");
    AddFieldWithDescription(typeInfo, "InertiaTensorY", CachedFloatType(), 0xC0, "Component Y,Y of inertia tensor");
    AddFieldWithDescription(typeInfo, "InertiaTensorZ", CachedFloatType(), 0xC4, "Component Z,Z of inertia tensor");
    AddFieldWithDescription(
      typeInfo,
      "CollisionOffsetX",
      CachedFloatType(),
      0xC8,
      "Offset collision by this much on the X Axis"
    );
    AddFieldWithDescription(
      typeInfo,
      "CollisionOffsetY",
      CachedFloatType(),
      0xCC,
      "Offset collision by this much on the Y Axis"
    );
    AddFieldWithDescription(
      typeInfo,
      "CollisionOffsetZ",
      CachedFloatType(),
      0xD0,
      "Offset collision by this much on the Z Axis"
    );
    AddFieldWithDescription(typeInfo, "Footprint", CachedFootprintType(), 0xD8, "Unit footprint");
    AddFieldWithDescription(typeInfo, "AltFootprint", CachedFootprintType(), 0xE8, "Alternate Unit footprint");
    AddFieldWithDescription(
      typeInfo,
      "DesiredShooterCap",
      CachedIntType(),
      0xD4,
      "Set the desired maximum number of shooters taking shots at me"
    );
    AddFieldWithDescription(
      typeInfo,
      "StrategicIconName",
      CachedRResIdType(),
      0x13C,
      "Name of strategic icon to use for this unit"
    );
    AddFieldWithDescription(typeInfo, "LifeBarRender", CachedBoolType(), 0xF8, "Should render life bar or not.");
    AddFieldWithDescription(typeInfo, "LifeBarOffset", CachedFloatType(), 0xFC, "Vertical offset from unit for lifebar.");
    AddFieldWithDescription(typeInfo, "LifeBarSize", CachedFloatType(), 0x100, "size of lifebar in OGrids.");
    AddFieldWithDescription(typeInfo, "LifeBarHeight", CachedFloatType(), 0x104, "height of lifebar in OGrids.");
    AddFieldWithDescription(typeInfo, "SelectionSizeX", CachedFloatType(), 0x108, "X Size of selection box");
    AddFieldWithDescription(typeInfo, "SelectionSizeY", CachedFloatType(), 0x10C, "Y Size of selection box");
    AddFieldWithDescription(typeInfo, "SelectionSizeZ", CachedFloatType(), 0x110, "Z Size of selection box");
    AddFieldWithDescription(
      typeInfo,
      "SelectionCenterOffsetX",
      CachedFloatType(),
      0x114,
      "X center offset of selection box"
    );
    AddFieldWithDescription(
      typeInfo,
      "SelectionCenterOffsetY",
      CachedFloatType(),
      0x118,
      "Y center offset of selection box"
    );
    AddFieldWithDescription(
      typeInfo,
      "SelectionCenterOffsetZ",
      CachedFloatType(),
      0x11C,
      "Z center offset of selection box"
    );
    AddFieldWithDescription(
      typeInfo,
      "SelectionYOffset",
      CachedFloatType(),
      0x120,
      "How far to reduce top of collision box for selection (default 0.5 (half))"
    );
    AddFieldWithDescription(
      typeInfo,
      "SelectionMeshScaleX",
      CachedFloatType(),
      0x124,
      "Scale the mesh on the X axis by this much when we perform our mouse over entity test"
    );
    AddFieldWithDescription(
      typeInfo,
      "SelectionMeshScaleY",
      CachedFloatType(),
      0x128,
      "Scale the mesh on the Y axis by this much when we perform our mouse over entity test"
    );
    AddFieldWithDescription(
      typeInfo,
      "SelectionMeshScaleZ",
      CachedFloatType(),
      0x12C,
      "Scale the mesh on the Z axis by this much when we perform our mouse over entity test"
    );
    AddFieldWithDescription(
      typeInfo,
      "SelectionMeshUseTopAmount",
      CachedFloatType(),
      0x130,
      "Use this much of the top portion of our mesh for intersection test. Useful for naval stuctures that go deep into water"
    );
    AddFieldWithDescription(
      typeInfo,
      "SelectionThickness",
      CachedFloatType(),
      0x134,
      "Use this to modify the thickness of the rendered selection indicator for the unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "UseOOBTestZoom",
      CachedFloatType(),
      0x138,
      "Use OOB hit test for this unit when camera is below this zoom level"
    );
    AddFieldWithDescription(
      typeInfo,
      "StrategicIconSortPriority",
      CachedUCharType(),
      0x158,
      "0 renders on top, 255 on bottom"
    );
  }

  /**
   * Address: 0x00512790 (FUN_00512790, Moho::REntityBlueprintTypeInfo::Init)
   *
   * What it does:
   * Sets `REntityBlueprint` size, registers `RBlueprint` as base metadata,
   * and publishes derived field descriptors.
   */
  void REntityBlueprintTypeInfo::Init()
  {
    size_ = sizeof(REntityBlueprint);
    AddBaseRBlueprint(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC8290 (FUN_00BC8290, register_REntityBlueprintTypeInfo)
   */
  void register_REntityBlueprintTypeInfo()
  {
    (void)AcquireREntityBlueprintTypeInfo();
    (void)std::atexit(&cleanup_REntityBlueprintTypeInfo);
  }
} // namespace moho

