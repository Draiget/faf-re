#include "moho/entity/REntityBlueprintTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <typeinfo>
#include <type_traits>
#include <utility>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/collision/ECollisionShape.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/sim/SFootprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::REntityBlueprintTypeInfo;

  [[nodiscard]] TypeInfo& AcquireREntityBlueprintTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
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
     * Address: 0x00513C80 (FUN_00513C80, Moho::EFootprintFlagsTypeInfo::dtr)
     *
     * What it does:
     * `EFootprintFlagsTypeInfo` adds no data members of its own, so the
     * vtable-slot-2 scalar deleting destructor just tail-calls
     * `gpg::REnumType::~REnumType` then conditionally frees the object --
     * exactly what a defaulted destructor produces.
     */
    ~EFootprintFlagsTypeInfo() override = default;

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
    /**
     * Address: 0x00513560 (FUN_00513560, gpg::RVectorType_string::dtr)
     */
    ~RStringVectorTypeInfo() override;

    /**
     * Address: 0x00512C30 (FUN_00512C30, gpg::RVectorType_string::GetName)
     *
     * What it does:
     * Lazily builds/caches the reflected lexical type label for one
     * `vector<string>` lane using the current reflected string element type
     * name.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00512CF0 (FUN_00512CF0, gpg::RVectorType_string::GetLexical)
     *
     * What it does:
     * Appends `size=` metadata to inherited lexical text for one reflected
     * `vector<string>` value.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00512CD0 (FUN_00512CD0, gpg::RVectorType_string::Init)
     *
     * What it does:
     * Sets reflected vector size/version and installs archive serializer lanes
     * for one `vector<string>` descriptor.
     */
    void Init() override;

    /**
     * Address: 0x00512E60 (FUN_00512E60, gpg::RVectorType_string::SerLoad)
     *
     * What it does:
     * Reads one serialized string-vector lane (count + string elements) and
     * replaces destination storage.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00512F60 (FUN_00512F60, gpg::RVectorType_string::SerSave)
     *
     * What it does:
     * Writes one reflected string-vector lane as count + element payloads.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    [[nodiscard]] gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    [[nodiscard]] size_t GetCount(void* obj) const override;
    /**
     * Address: 0x00512DC0 (FUN_00512DC0, gpg::RVectorType_string::SetCount)
     *
     * What it does:
     * Resizes one reflected string-vector lane to a requested count using a
     * default-constructed fill string.
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RStringVectorTypeInfo) == 0x68, "RStringVectorTypeInfo size must be 0x68");

  using StringVector = msvc8::vector<msvc8::string>;
  constexpr std::size_t kStringVectorMaxElements = 0x9249249u;

  /**
   * Address: 0x00513560 (FUN_00513560, gpg::RVectorType_string::dtr)
   */
  RStringVectorTypeInfo::~RStringVectorTypeInfo() = default;

  /**
   * Address: 0x00512C30 (FUN_00512C30, gpg::RVectorType_string::GetName)
   * Address: 0x00BF2760 (FUN_00BF2760, atexit destructor of GetName's cached name)
   *
   * What it does:
   * Builds `vector<std::string>` once from the reflected string element type
   * name and returns it.
   */
  const char* RStringVectorTypeInfo::GetName() const
  {
    static const msvc8::string sName = gpg::STR_Printf("vector<%s>", CachedStringType()->GetName());
    return sName.c_str();
  }

  msvc8::string RStringVectorTypeInfo::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  const gpg::RIndexed* RStringVectorTypeInfo::IsIndexed() const
  {
    return this;
  }

  void RStringVectorTypeInfo::Init()
  {
    size_ = sizeof(msvc8::vector<msvc8::string>);
    version_ = 1;
    serLoadFunc_ = &RStringVectorTypeInfo::SerLoad;
    serSaveFunc_ = &RStringVectorTypeInfo::SerSave;
  }


  /**
   * Address: 0x00512FC0 (FUN_00512FC0, gpg::RVectorType_string::Reserve)
   *
   * What it does:
   * Ensures a reflected string vector has enough capacity for a pending load
   * or append sequence and preserves any pre-existing elements. The binary
   * body's move-relocate loop is `msvc8::vector<msvc8::string>::reserve`'s
   * own growth step (FUN_00513980, cited on `reserve` in
   * legacy/containers/Vector.h), so the canonical template call covers it.
   */
  [[nodiscard]] std::size_t EnsureStringVectorCapacity(StringVector& value, const std::size_t requestedCount)
  {
    if (requestedCount > kStringVectorMaxElements) {
      throw std::length_error("vector<T> too long");
    }

    const std::size_t currentCount = value.size();
    if (currentCount < requestedCount) {
      value.reserve(requestedCount);
    }

    return currentCount;
  }

  /**
   * Address: 0x00512E60 (FUN_00512E60, gpg::RVectorType_string::SerLoad)
   *
   * What it does:
   * Reads one serialized string-vector lane (count + string elements) and
   * replaces destination storage.
   */
  void RStringVectorTypeInfo::SerLoad(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const storage = reinterpret_cast<StringVector*>(objectPtr);
    unsigned int count = 0u;
    archive->ReadUInt(&count);

    StringVector loaded{};
    (void)EnsureStringVectorCapacity(loaded, static_cast<std::size_t>(count));

    for (unsigned int index = 0; index < count; ++index) {
      msvc8::string value{};
      archive->ReadString(&value);
      loaded.push_back(value);
    }

    *storage = loaded;
  }

  void RStringVectorTypeInfo::SerSave(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    if (archive == nullptr) {
      return;
    }

    auto* const storage = reinterpret_cast<StringVector*>(objectPtr);
    const unsigned int count = storage != nullptr ? static_cast<unsigned int>(storage->size()) : 0u;
    archive->WriteUInt(count);

    if (storage == nullptr) {
      return;
    }

    for (msvc8::string& value : *storage) {
      archive->WriteString(&value);
    }
  }

  gpg::RRef RStringVectorTypeInfo::SubscriptIndex(void* const obj, const int ind) const
  {
    gpg::RRef out{};
    out.mType = CachedStringType();

    auto* const storage = static_cast<StringVector*>(obj);
    if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
      return out;
    }

    out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
    return out;
  }

  size_t RStringVectorTypeInfo::GetCount(void* const obj) const
  {
    const auto* const storage = static_cast<const StringVector*>(obj);
    return storage ? storage->size() : 0u;
  }

  /**
   * Address: 0x00512DC0 (FUN_00512DC0, gpg::RVectorType_string::SetCount)
   * Address: 0x005130E0 (FUN_005130E0, the `resize(n, value)` emission this
   * call produces for `msvc8::vector<msvc8::string>`)
   *
   * What it does:
   * Resizes one reflected string-vector lane to a requested count using a
   * default-constructed fill string.
   */
  void RStringVectorTypeInfo::SetCount(void* const obj, const int count) const
  {
    auto* const storage = static_cast<StringVector*>(obj);
    if (!storage || count < 0) {
      return;
    }

    msvc8::string fill{};
    storage->resize(static_cast<std::size_t>(count), fill);
  }

  /**
   * Address: 0x00513BC0 (FUN_00513BC0, sub_513BC0)
   * Address: 0x00BF2810 (FUN_00BF2810, atexit destructor of the EFootprintFlagsTypeInfo object)
   *
   * What it does:
   * Materializes the `EFootprintFlags` enum type descriptor and preregisters
   * it against `typeid(moho::EFootprintFlags)`.
   */
  [[nodiscard]] EFootprintFlagsTypeInfo* AcquireEFootprintFlagsTypeInfo()
  {
    static EFootprintFlagsTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(moho::EFootprintFlags), &sInstance);
    return &sInstance;
  }

  /**
   * Address: 0x005134B0 (FUN_005134B0, sub_5134B0)
   * Address: 0x00BF2790 (FUN_00BF2790, atexit destructor of the RStringVectorTypeInfo object)
   *
   * What it does:
   * Materializes the reflected `vector<string>` descriptor and preregisters
   * it against `typeid(msvc8::vector<msvc8::string>)`.
   */
  [[nodiscard]] RStringVectorTypeInfo* AcquireRStringVectorTypeInfo()
  {
    static RStringVectorTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(msvc8::vector<msvc8::string>), &sInstance);
    return &sInstance;
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
   * Materializes the reflected `EFootprintFlags` enum descriptor.
   */
  void register_EFootprintFlagsTypeInfo()
  {
    (void)AcquireEFootprintFlagsTypeInfo();
  }

  /**
   * Address: 0x00BC82B0 (FUN_00BC82B0, register_RStringVectorTypeInfo)
   *
   * What it does:
   * Materializes the reflected `vector<string>` descriptor.
   */
  void register_RStringVectorTypeInfo()
  {
    (void)AcquireRStringVectorTypeInfo();
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
    baseField.mFlags = 0;
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
    gpg::RField* const categoriesField = typeInfo->AddField<msvc8::vector<msvc8::string>>("Categories", offsetof(REntityBlueprint, mCategories));
    categoriesField->mFlags = 3;
    categoriesField->mDesc = "Named categories that this entity belongs to";
    typeInfo->AddField<msvc8::string>("ScriptModule", offsetof(REntityBlueprint, mScriptModule), 3, "Module defining entity's class.");
    typeInfo->AddField<msvc8::string>("ScriptClass", offsetof(REntityBlueprint, mScriptClass), 3, "Name of entity's class.");
    gpg::RField* const collisionShapeField = typeInfo->AddField<moho::ECollisionShape>("CollisionShape", offsetof(REntityBlueprint, mCollisionShape));
    collisionShapeField->mFlags = 3;
    collisionShapeField->mDesc = "Shape to use for collision db, 'None' for no collision.";
    typeInfo->AddField<float>("SizeX", offsetof(REntityBlueprint, mSizeX), 3, "Unit size X");
    typeInfo->AddField<float>("SizeY", offsetof(REntityBlueprint, mSizeY), 3, "Unit size Y");
    typeInfo->AddField<float>("SizeZ", offsetof(REntityBlueprint, mSizeZ), 3, "Unit size Z");
    typeInfo->AddField<float>("AverageDensity", offsetof(REntityBlueprint, mAverageDensity), 3, "Unit average density in tons / m^3. (Default is 0.49)");
    typeInfo->AddField<float>("InertiaTensorX", offsetof(REntityBlueprint, mInertiaTensorX), 3, "Component X,X of inertia tensor");
    typeInfo->AddField<float>("InertiaTensorY", offsetof(REntityBlueprint, mInertiaTensorY), 3, "Component Y,Y of inertia tensor");
    typeInfo->AddField<float>("InertiaTensorZ", offsetof(REntityBlueprint, mInertiaTensorZ), 3, "Component Z,Z of inertia tensor");
    typeInfo->AddField<float>("CollisionOffsetX", offsetof(REntityBlueprint, mCollisionOffsetX), 3, "Offset collision by this much on the X Axis");
    typeInfo->AddField<float>("CollisionOffsetY", offsetof(REntityBlueprint, mCollisionOffsetY), 3, "Offset collision by this much on the Y Axis");
    typeInfo->AddField<float>("CollisionOffsetZ", offsetof(REntityBlueprint, mCollisionOffsetZ), 3, "Offset collision by this much on the Z Axis");
    gpg::RField* const footprintField = typeInfo->AddField<moho::SFootprint>("Footprint", offsetof(REntityBlueprint, mFootprint));
    footprintField->mFlags = 3;
    footprintField->mDesc = "Unit footprint";
    gpg::RField* const altFootprintField = typeInfo->AddField<moho::SFootprint>("AltFootprint", offsetof(REntityBlueprint, mAltFootprint));
    altFootprintField->mFlags = 3;
    altFootprintField->mDesc = "Alternate Unit footprint";
    typeInfo->AddField<int>("DesiredShooterCap", offsetof(REntityBlueprint, mDesiredShooterCap), 3, "Set the desired maximum number of shooters taking shots at me");
    typeInfo->AddField<moho::RResId>("StrategicIconName", offsetof(REntityBlueprint, mStrategicIconName), 3, "Name of strategic icon to use for this unit");
    typeInfo->AddField<bool>("LifeBarRender", offsetof(REntityBlueprint, mLifeBarRender), 3, "Should render life bar or not.");
    typeInfo->AddField<float>("LifeBarOffset", offsetof(REntityBlueprint, mLifeBarOffset), 3, "Vertical offset from unit for lifebar.");
    typeInfo->AddField<float>("LifeBarSize", offsetof(REntityBlueprint, mLifeBarSize), 3, "size of lifebar in OGrids.");
    typeInfo->AddField<float>("LifeBarHeight", offsetof(REntityBlueprint, mLifeBarHeight), 3, "height of lifebar in OGrids.");
    typeInfo->AddField<float>("SelectionSizeX", offsetof(REntityBlueprint, mSelectionSizeX), 3, "X Size of selection box");
    typeInfo->AddField<float>("SelectionSizeY", offsetof(REntityBlueprint, mSelectionSizeY), 3, "Y Size of selection box");
    typeInfo->AddField<float>("SelectionSizeZ", offsetof(REntityBlueprint, mSelectionSizeZ), 3, "Z Size of selection box");
    typeInfo->AddField<float>("SelectionCenterOffsetX", offsetof(REntityBlueprint, mSelectionCenterOffsetX), 3, "X center offset of selection box");
    typeInfo->AddField<float>("SelectionCenterOffsetY", offsetof(REntityBlueprint, mSelectionCenterOffsetY), 3, "Y center offset of selection box");
    typeInfo->AddField<float>("SelectionCenterOffsetZ", offsetof(REntityBlueprint, mSelectionCenterOffsetZ), 3, "Z center offset of selection box");
    typeInfo->AddField<float>("SelectionYOffset", offsetof(REntityBlueprint, mSelectionYOffset), 3, "How far to reduce top of collision box for selection (default 0.5 (half))");
    typeInfo->AddField<float>("SelectionMeshScaleX", offsetof(REntityBlueprint, mSelectionMeshScaleX), 3, "Scale the mesh on the X axis by this much when we perform our mouse over entity test");
    typeInfo->AddField<float>("SelectionMeshScaleY", offsetof(REntityBlueprint, mSelectionMeshScaleY), 3, "Scale the mesh on the Y axis by this much when we perform our mouse over entity test");
    typeInfo->AddField<float>("SelectionMeshScaleZ", offsetof(REntityBlueprint, mSelectionMeshScaleZ), 3, "Scale the mesh on the Z axis by this much when we perform our mouse over entity test");
    typeInfo->AddField<float>("SelectionMeshUseTopAmount", offsetof(REntityBlueprint, mSelectionMeshUseTopAmount), 3, "Use this much of the top portion of our mesh for intersection test. Useful for naval stuctures that go deep into water");
    typeInfo->AddField<float>("SelectionThickness", offsetof(REntityBlueprint, mSelectionThickness), 3, "Use this to modify the thickness of the rendered selection indicator for the unit");
    typeInfo->AddField<float>("UseOOBTestZoom", offsetof(REntityBlueprint, mUseOOBTestZoom), 3, "Use OOB hit test for this unit when camera is below this zoom level");
    gpg::RField* const strategicIconSortPriorityField = typeInfo->AddField<unsigned char>("StrategicIconSortPriority", offsetof(REntityBlueprint, mStrategicIconSortPriority));
    strategicIconSortPriorityField->mFlags = 3;
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
  }
} // namespace moho

/**
 * Address: 0x0060C290 (FUN_0060C290, func_RRRefREntityBlueprint)
 *
 * What it does:
 * Builds one temporary `RRef_REntityBlueprint` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* gpg::PackRRef_REntityBlueprint(gpg::RRef* const outRef, moho::REntityBlueprint* const value)
{
  gpg::RRef temp{};
  temp = gpg::MakeRRef<moho::REntityBlueprint>(value);
  outRef->mObj = temp.mObj;
  outRef->mType = temp.mType;
  return outRef;
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EFootprintFlagsTypeInfo_4663ab, moho::register_EFootprintFlagsTypeInfo)
GPG_PREREGISTER_INIT(register_RStringVectorTypeInfo_4663ab, moho::register_RStringVectorTypeInfo)
GPG_PREREGISTER_INIT(register_REntityBlueprintTypeInfo_4663ab, moho::register_REntityBlueprintTypeInfo)

GPG_PREREGISTER_INIT(AcquireEFootprintFlagsTypeInfo_4663ab, AcquireEFootprintFlagsTypeInfo)
GPG_PREREGISTER_INIT(AcquireRStringVectorTypeInfo_4663ab, AcquireRStringVectorTypeInfo)
