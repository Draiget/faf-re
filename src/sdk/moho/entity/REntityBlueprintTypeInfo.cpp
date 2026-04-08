#include "moho/entity/REntityBlueprintTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>
#include <type_traits>

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

  void AddEnumEntry(gpg::REnumType* const typeInfo, const char* const token, const int value)
  {
    typeInfo->AddEnum(typeInfo->StripPrefix(token), value);
  }

  class EFootprintFlagsTypeInfo final : public gpg::REnumType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "EFootprintFlags";
    }

    /**
     * Address: 0x00513C20 (FUN_00513C20, Moho::EFootprintFlagsTypeInfo::Init)
     *
     * What it does:
     * Sets enum size metadata, initializes enum RTTI base lanes, then registers
     * footprint-flag entries and finalizes the type.
     */
    void Init() override
    {
      size_ = sizeof(moho::EFootprintFlags);
      gpg::RType::Init();
      AddEnums();
      Finish();
    }

  private:
    /**
     * Address: 0x00513CB0 (FUN_00513CB0, Moho::EFootprintFlagsTypeInfo::AddEnums)
     *
     * What it does:
     * Registers reflected footprint-flag enum names under the `FPFLAGS_`
     * prefix.
     */
    void AddEnums()
    {
      mPrefix = "FPFLAGS_";
      AddEnumEntry(this, "FPFLAG_None", 0);
      AddEnumEntry(this, "FPFLAG_IgnoreStructures", 1);
    }
  };

  static_assert(sizeof(EFootprintFlagsTypeInfo) == 0x78, "EFootprintFlagsTypeInfo size must be 0x78");

  class RStringVectorTypeInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "vector<string>";
    }

    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
    }

    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override
    {
      return this;
    }

    void Init() override
    {
      size_ = sizeof(msvc8::vector<msvc8::string>);
      version_ = 1;
    }

    [[nodiscard]] gpg::RRef SubscriptIndex(void* const obj, const int ind) const override
    {
      gpg::RRef out{};
      out.mType = CachedStringType();

      auto* const storage = static_cast<msvc8::vector<msvc8::string>*>(obj);
      if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
        return out;
      }

      out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
      return out;
    }

    [[nodiscard]] size_t GetCount(void* const obj) const override
    {
      const auto* const storage = static_cast<const msvc8::vector<msvc8::string>*>(obj);
      return storage ? storage->size() : 0U;
    }

    void SetCount(void* const obj, const int count) const override
    {
      auto* const storage = static_cast<msvc8::vector<msvc8::string>*>(obj);
      if (!storage || count < 0) {
        return;
      }

      storage->resize(static_cast<std::size_t>(count));
    }
  };

  static_assert(sizeof(RStringVectorTypeInfo) == 0x68, "RStringVectorTypeInfo size must be 0x68");

  alignas(EFootprintFlagsTypeInfo) unsigned char gEFootprintFlagsTypeInfoStorage[sizeof(EFootprintFlagsTypeInfo)];
  bool gEFootprintFlagsTypeInfoConstructed = false;

  alignas(RStringVectorTypeInfo) unsigned char gRStringVectorTypeInfoStorage[sizeof(RStringVectorTypeInfo)];
  bool gRStringVectorTypeInfoConstructed = false;

  /**
   * Address: 0x00513BC0 (FUN_00513BC0, sub_513BC0)
   *
   * What it does:
   * Materializes the `EFootprintFlags` enum type descriptor and preregisters
   * it against `typeid(moho::EFootprintFlags)`.
   */
  [[nodiscard]] EFootprintFlagsTypeInfo* AcquireEFootprintFlagsTypeInfo()
  {
    if (!gEFootprintFlagsTypeInfoConstructed) {
      new (gEFootprintFlagsTypeInfoStorage) EFootprintFlagsTypeInfo();
      gpg::PreRegisterRType(typeid(moho::EFootprintFlags), reinterpret_cast<EFootprintFlagsTypeInfo*>(gEFootprintFlagsTypeInfoStorage));
      gEFootprintFlagsTypeInfoConstructed = true;
    }

    return reinterpret_cast<EFootprintFlagsTypeInfo*>(gEFootprintFlagsTypeInfoStorage);
  }

  /**
   * Address: 0x00BF2810 (FUN_00BF2810, sub_BF2810)
   *
   * What it does:
   * Releases startup-owned `EFootprintFlags` enum type-descriptor state.
   */
  void cleanup_EFootprintFlagsTypeInfo()
  {
    if (!gEFootprintFlagsTypeInfoConstructed) {
      return;
    }

    reinterpret_cast<EFootprintFlagsTypeInfo*>(gEFootprintFlagsTypeInfoStorage)->~EFootprintFlagsTypeInfo();
    gEFootprintFlagsTypeInfoConstructed = false;
  }

  /**
   * Address: 0x005134B0 (FUN_005134B0, sub_5134B0)
   *
   * What it does:
   * Materializes the reflected `vector<string>` descriptor and preregisters
   * it against `typeid(msvc8::vector<msvc8::string>)`.
   */
  [[nodiscard]] RStringVectorTypeInfo* AcquireRStringVectorTypeInfo()
  {
    if (!gRStringVectorTypeInfoConstructed) {
      new (gRStringVectorTypeInfoStorage) RStringVectorTypeInfo();
      gpg::PreRegisterRType(typeid(msvc8::vector<msvc8::string>), reinterpret_cast<RStringVectorTypeInfo*>(gRStringVectorTypeInfoStorage));
      gRStringVectorTypeInfoConstructed = true;
    }

    return reinterpret_cast<RStringVectorTypeInfo*>(gRStringVectorTypeInfoStorage);
  }

  /**
   * Address: 0x00BF2790 (FUN_00BF2790, sub_BF2790)
   *
   * What it does:
   * Releases startup-owned `vector<string>` descriptor resources.
   */
  void cleanup_RStringVectorTypeInfo()
  {
    if (!gRStringVectorTypeInfoConstructed) {
      return;
    }

    reinterpret_cast<RStringVectorTypeInfo*>(gRStringVectorTypeInfoStorage)->~RStringVectorTypeInfo();
    gRStringVectorTypeInfoConstructed = false;
  }

  struct TypeInfoRTypePair
  {
    const std::type_info* typeInfo;
    gpg::RType* rType;
  };

  struct TypeInfoCache3
  {
    bool initialized;
    TypeInfoRTypePair entries[3];
  };

  thread_local TypeInfoCache3 gREntityBlueprintRRefCache{false, {}};

  template <typename TObject>
  [[nodiscard]] gpg::RRef* BuildTypedRefWithCache(
    gpg::RRef* const outRef,
    TObject* const value,
    const std::type_info& declaredType,
    gpg::RType*& declaredTypeCache,
    TypeInfoCache3& cache
  )
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RType* declaredRuntimeType = declaredTypeCache;
    if (declaredRuntimeType == nullptr) {
      declaredRuntimeType = gpg::LookupRType(declaredType);
      declaredTypeCache = declaredRuntimeType;
    }

    const std::type_info* runtimeTypeInfo = &declaredType;
    if constexpr (std::is_polymorphic_v<TObject>) {
      if (value != nullptr) {
        runtimeTypeInfo = &typeid(*value);
      }
    }

    if (value == nullptr || (*runtimeTypeInfo == declaredType)) {
      outRef->mObj = value;
      outRef->mType = declaredRuntimeType;
      return outRef;
    }

    if (!cache.initialized) {
      cache.initialized = true;
      for (TypeInfoRTypePair& entry : cache.entries) {
        entry.typeInfo = nullptr;
        entry.rType = nullptr;
      }
    }

    int cacheSlot = 0;
    while (cacheSlot < 3) {
      const TypeInfoRTypePair& entry = cache.entries[cacheSlot];
      if (entry.typeInfo == runtimeTypeInfo || (entry.typeInfo && (*entry.typeInfo == *runtimeTypeInfo))) {
        break;
      }
      ++cacheSlot;
    }

    gpg::RType* runtimeType = nullptr;
    if (cacheSlot >= 3) {
      runtimeType = gpg::LookupRType(*runtimeTypeInfo);
      cacheSlot = 2;
    } else {
      runtimeType = cache.entries[cacheSlot].rType;
    }

    for (int slot = cacheSlot; slot > 0; --slot) {
      cache.entries[slot] = cache.entries[slot - 1];
    }

    cache.entries[0].typeInfo = runtimeTypeInfo;
    cache.entries[0].rType = runtimeType;

    std::int32_t baseOffset = 0;
    const bool isDerived = runtimeType->IsDerivedFrom(declaredRuntimeType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      outRef->mObj = value;
      outRef->mType = runtimeType;
      return outRef;
    }

    outRef->mObj = reinterpret_cast<char*>(value) - static_cast<std::ptrdiff_t>(baseOffset);
    outRef->mType = runtimeType;
    return outRef;
  }

  struct REntityBlueprintTypeInfoBootstrap
  {
    REntityBlueprintTypeInfoBootstrap()
    {
      (void)moho::register_EFootprintFlagsTypeInfo();
      (void)moho::register_RStringVectorTypeInfo();
      moho::register_REntityBlueprintTypeInfo();
    }
  };

  REntityBlueprintTypeInfoBootstrap gREntityBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC8340 (FUN_00BC8340, register_EFootprintFlagsTypeInfo)
   *
   * What it does:
   * Materializes the reflected `EFootprintFlags` enum descriptor and installs
   * process-exit cleanup.
   */
  int register_EFootprintFlagsTypeInfo()
  {
    (void)AcquireEFootprintFlagsTypeInfo();
    return std::atexit(&cleanup_EFootprintFlagsTypeInfo);
  }

  /**
   * Address: 0x00BC82B0 (FUN_00BC82B0, register_RStringVectorTypeInfo)
   *
   * What it does:
   * Materializes the reflected `vector<string>` descriptor and installs
   * process-exit cleanup.
   */
  int register_RStringVectorTypeInfo()
  {
    (void)AcquireRStringVectorTypeInfo();
    return std::atexit(&cleanup_RStringVectorTypeInfo);
  }

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
   * Address: 0x005132B0 (FUN_005132B0, gpg::RType::AddField_ECollisionShape_0xA8CollisionShape)
   *
   * What it does:
   * Appends the reflected `CollisionShape` field descriptor at offset `0xA8`.
   */
  gpg::RField* REntityBlueprintTypeInfo::AddFieldCollisionShape(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("CollisionShape", CachedCollisionShapeType(), 0xA8, 0, nullptr));
    return &typeInfo->fields_.back();
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
    gpg::RField* const categoriesField = typeInfo->AddFieldVectorString("Categories", 0x60);
    categoriesField->v4 = 3;
    categoriesField->mDesc = "Named categories that this entity belongs to";
    AddFieldWithDescription(typeInfo, "ScriptModule", CachedStringType(), 0x70, "Module defining entity's class.");
    AddFieldWithDescription(typeInfo, "ScriptClass", CachedStringType(), 0x8C, "Name of entity's class.");
    gpg::RField* const collisionShapeField = AddFieldCollisionShape(typeInfo);
    collisionShapeField->v4 = 3;
    collisionShapeField->mDesc = "Shape to use for collision db, 'None' for no collision.";
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
    gpg::RField* const footprintField = typeInfo->AddFieldSFootprint("Footprint", 0xD8);
    footprintField->v4 = 3;
    footprintField->mDesc = "Unit footprint";
    gpg::RField* const altFootprintField = typeInfo->AddFieldSFootprint("AltFootprint", 0xE8);
    altFootprintField->v4 = 3;
    altFootprintField->mDesc = "Alternate Unit footprint";
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
    gpg::RField* const strategicIconSortPriorityField = typeInfo->AddFieldUChar("StrategicIconSortPriority", 0x158);
    strategicIconSortPriorityField->v4 = 3;
    strategicIconSortPriorityField->mDesc = "0 renders on top, 255 on bottom";
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

/**
 * Address: 0x00555040 (FUN_00555040, gpg::RRef_REntityBlueprint)
 *
 * What it does:
 * Builds a typed reflection reference for `REntityBlueprint*`, resolving
 * derived runtime type + base adjustment when required.
 */
gpg::RRef* gpg::RRef_REntityBlueprint(gpg::RRef* const outRef, moho::REntityBlueprint* const value)
{
  return BuildTypedRefWithCache(
    outRef,
    value,
    typeid(moho::REntityBlueprint),
    moho::REntityBlueprint::sType,
    gREntityBlueprintRRefCache
  );
}
