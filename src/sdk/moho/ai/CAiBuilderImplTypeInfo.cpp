#include "moho/ai/CAiBuilderImplTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/CAiBuilderImpl.h"
#include "moho/misc/Stats.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  using BuilderRebuildMapStorage = std::map<unsigned int, const RUnitBlueprint*>;

  class CAiBuilderRebuildMapTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005A1FD0 (FUN_005A1FD0, gpg::RMapType_uint_RUnitBlueprintP::dtr)
     */
    ~CAiBuilderRebuildMapTypeInfo() override = default;

    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    void Init() override;
  };

  static_assert(sizeof(CAiBuilderRebuildMapTypeInfo) == 0x64, "CAiBuilderRebuildMapTypeInfo size must be 0x64");

  alignas(CAiBuilderImplTypeInfo) unsigned char gCAiBuilderImplTypeInfoStorage[sizeof(CAiBuilderImplTypeInfo)] = {};
  bool gCAiBuilderImplTypeInfoConstructed = false;

  alignas(CAiBuilderRebuildMapTypeInfo)
  unsigned char gCAiBuilderRebuildMapTypeInfoStorage[sizeof(CAiBuilderRebuildMapTypeInfo)] = {};
  bool gCAiBuilderRebuildMapTypeInfoConstructed = false;



  msvc8::string gCAiBuilderRebuildMapTypeName;
  bool gCAiBuilderRebuildMapTypeNameInitialized = false;

  template <std::uintptr_t SlotAddress>
  struct StartupEngineStatsSlot
  {
    static EngineStats* value;
  };

  template <>
  EngineStats* StartupEngineStatsSlot<0x10AE6CCu>::value = nullptr;

  template <>
  EngineStats* StartupEngineStatsSlot<0x10AEABCu>::value = nullptr;

  [[nodiscard]] CAiBuilderImplTypeInfo* AcquireCAiBuilderImplTypeInfo()
  {
    if (!gCAiBuilderImplTypeInfoConstructed) {
      new (gCAiBuilderImplTypeInfoStorage) CAiBuilderImplTypeInfo();
      gCAiBuilderImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiBuilderImplTypeInfo*>(gCAiBuilderImplTypeInfoStorage);
  }

  [[nodiscard]] CAiBuilderRebuildMapTypeInfo* AcquireCAiBuilderRebuildMapTypeInfo()
  {
    if (!gCAiBuilderRebuildMapTypeInfoConstructed) {
      new (gCAiBuilderRebuildMapTypeInfoStorage) CAiBuilderRebuildMapTypeInfo();
      gCAiBuilderRebuildMapTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiBuilderRebuildMapTypeInfo*>(gCAiBuilderRebuildMapTypeInfoStorage);
  }

  /**
   * Address: 0x00BF6A60 (FUN_00BF6A60)
   *
   * What it does:
   * Tears down startup-owned `CAiBuilderImplTypeInfo` storage.
   */
  void cleanup_CAiBuilderImplTypeInfo()
  {
    if (!gCAiBuilderImplTypeInfoConstructed) {
      return;
    }

    AcquireCAiBuilderImplTypeInfo()->~CAiBuilderImplTypeInfo();
    gCAiBuilderImplTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedIAiBuilderType()
  {
    if (!IAiBuilder::sType) {
      IAiBuilder::sType = gpg::LookupRType(typeid(IAiBuilder));
    }
    return IAiBuilder::sType;
  }

  /**
   * Address: 0x005A1C20 (FUN_005A1C20)
   *
   * What it does:
   * Registers `IAiBuilder` as one reflected base lane for `CAiBuilderImpl` at
   * offset `+0x00`.
   */
  void AddIAiBuilderBaseToCAiBuilderImplType(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedIAiBuilderType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  [[nodiscard]] gpg::RType* CachedUnsignedIntType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(unsigned int));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRUnitBlueprintType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(RUnitBlueprint));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRUnitBlueprintPointerType()
  {
    // The descriptor is pre-registered under `typeid(RUnitBlueprint*)` by
    // PreregisterRUnitBlueprintPointerType. `typeid(const RUnitBlueprint*)` is
    // a distinct type and is never registered, and LookupRType *throws* on a
    // miss rather than returning null - so asking for the const form first
    // threw out of REF_RegisterAllTypes, and the fallback below it was
    // unreachable.
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(RUnitBlueprint*));
    }
    return type;
  }

  /**
   * Address: 0x00BF6B20 (FUN_00BF6B20)
   *
   * What it does:
   * Releases cached lexical name storage for builder rebuild-map RTTI.
   */
  void cleanup_CAiBuilderRebuildMapTypeName()
  {
    gCAiBuilderRebuildMapTypeName.clear();
    gCAiBuilderRebuildMapTypeNameInitialized = false;
  }

  [[nodiscard]] gpg::RRef MakeBlueprintObjectRef(const RUnitBlueprint* const blueprint)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedRUnitBlueprintType();
    if (!blueprint) {
      return out;
    }

    auto* const mutableBlueprint = const_cast<RUnitBlueprint*>(blueprint);
    gpg::RType* dynamicType = out.mType;
    try {
      dynamicType = gpg::LookupRType(typeid(*mutableBlueprint));
    } catch (...) {
      dynamicType = out.mType;
    }

    std::int32_t baseOffset = 0;
    const bool derived =
      dynamicType != nullptr && out.mType != nullptr && dynamicType->IsDerivedFrom(out.mType, &baseOffset);
    out.mObj = derived
      ? reinterpret_cast<void*>(
          reinterpret_cast<std::uintptr_t>(mutableBlueprint) - static_cast<std::uintptr_t>(baseOffset)
        )
      : static_cast<void*>(mutableBlueprint);
    out.mType = dynamicType ? dynamicType : out.mType;
    return out;
  }

  [[nodiscard]] const RUnitBlueprint* DecodeTrackedBlueprintPointer(const gpg::TrackedPointerInfo& tracked)
  {
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expectedType = CachedRUnitBlueprintType();
    if (!expectedType || !tracked.type) {
      return static_cast<const RUnitBlueprint*>(tracked.object);
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<const RUnitBlueprint*>(upcast.mObj);
    }

    const char* const expected = expectedType->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "RUnitBlueprint",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  /**
   * Address: 0x005A0C60 (FUN_005A0C60)
   *
   * What it does:
   * Deserializes one rebuild-map lane by clearing existing entries, then
   * reading `(key, blueprint pointer)` pairs into tree storage.
   */
  void DeserializeBuilderRebuildMap(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto* const map = reinterpret_cast<SBuilderRebuildMap*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );

    unsigned int count = 0u;
    archive->ReadUInt(&count);
    map->clear();

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      unsigned int key = 0u;
      archive->ReadUInt(&key);
      const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
      (void)map->insert({key, DecodeTrackedBlueprintPointer(tracked)});
    }
  }

  /**
   * Address: 0x005A0D10 (FUN_005A0D10)
   *
   * What it does:
   * Serializes one rebuild-map lane as map size followed by
   * `(key, blueprint pointer)` pairs in key order.
   */
  void SerializeBuilderRebuildMap(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto* const map = reinterpret_cast<const SBuilderRebuildMap*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    const unsigned int count = map ? static_cast<unsigned int>(map->size()) : 0u;
    archive->WriteUInt(count);

    if (!map || map->empty()) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (const auto& [key, blueprint] : *map) {
      archive->WriteUInt(key);
      gpg::WriteRawPointer(archive, MakeBlueprintObjectRef(blueprint), gpg::TrackedPointerState::Unowned, owner);
    }
  }

  /**
   * Address: 0x00BF6BE0 (FUN_00BF6BE0)
   *
   * What it does:
   * Tears down startup-owned builder rebuild-map reflection storage.
   */
  void cleanup_CAiBuilderRebuildMapTypeInfo()
  {
    if (!gCAiBuilderRebuildMapTypeInfoConstructed) {
      return;
    }

    AcquireCAiBuilderRebuildMapTypeInfo()->~CAiBuilderRebuildMapTypeInfo();
    gCAiBuilderRebuildMapTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF6C40 (FUN_00BF6C40)
   *
   * What it does:
   * Destroys one startup-owned AI-builder engine-stats slot.
   */
  void cleanup_CAiBuilderStartupStatsPrimary()
  {
    if (EngineStats* const slot = StartupEngineStatsSlot<0x10AE6CCu>::value; slot) {
      delete slot;
    }
  }

  /**
   * Address: 0x00BF6C60 (FUN_00BF6C60)
   *
   * What it does:
   * Destroys one secondary startup-owned AI-builder engine-stats slot.
   */
  void cleanup_CAiBuilderStartupStatsSecondary()
  {
    if (EngineStats* const slot = StartupEngineStatsSlot<0x10AEABCu>::value; slot) {
      delete slot;
    }
  }
} // namespace

/**
 * Address: 0x0059FBB0 (FUN_0059FBB0, ctor)
 *
 * What it does:
 * Preregisters `CAiBuilderImpl` RTTI so lookup resolves to this type helper.
 */
CAiBuilderImplTypeInfo::CAiBuilderImplTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiBuilderImpl), this);
}

/**
 * Address: 0x0059FC40 (FUN_0059FC40, scalar deleting thunk)
 */
CAiBuilderImplTypeInfo::~CAiBuilderImplTypeInfo() = default;

/**
 * Address: 0x0059FC30 (FUN_0059FC30, ?GetName@CAiBuilderImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiBuilderImplTypeInfo::GetName() const
{
  return "CAiBuilderImpl";
}

/**
 * Address: 0x0059FC10 (FUN_0059FC10, ?Init@CAiBuilderImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiBuilderImplTypeInfo::Init()
{
  size_ = sizeof(CAiBuilderImpl);
  gpg::RType::Init();
  AddIAiBuilderBaseToCAiBuilderImplType(this);
  Finish();
}

/**
 * Address: 0x005A04C0 (FUN_005A04C0, gpg::RMapType_uint_RUnitBlueprintP::GetName)
 */
const char* CAiBuilderRebuildMapTypeInfo::GetName() const
{
  if (!gCAiBuilderRebuildMapTypeNameInitialized) {
    gpg::RType* const keyType = CachedUnsignedIntType();
    gpg::RType* const valueType = CachedRUnitBlueprintPointerType();
    const char* const keyName = keyType ? keyType->GetName() : "unsigned int";
    const char* const valueName = valueType ? valueType->GetName() : "Moho::RUnitBlueprint const *";
    gCAiBuilderRebuildMapTypeName = gpg::STR_Printf("map<%s,%s>", keyName, valueName);
    gCAiBuilderRebuildMapTypeNameInitialized = true;
    (void)std::atexit(&cleanup_CAiBuilderRebuildMapTypeName);
  }

  return gCAiBuilderRebuildMapTypeName.c_str();
}

/**
 * Address: 0x005A0590 (FUN_005A0590, gpg::RMapType_uint_RUnitBlueprintP::GetLexical)
 */
msvc8::string CAiBuilderRebuildMapTypeInfo::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string lexical = gpg::RType::GetLexical(ref);
  const auto* const map = static_cast<const SBuilderRebuildMap*>(ref.mObj);
  const unsigned int count = map ? static_cast<unsigned int>(map->size()) : 0u;
  return gpg::STR_Printf("%s, size=%d", lexical.c_str(), static_cast<int>(count));
}

/**
 * Address: 0x005A0570 (FUN_005A0570, gpg::RMapType_uint_RUnitBlueprintP::Init)
 */
void CAiBuilderRebuildMapTypeInfo::Init()
{
  size_ = sizeof(SBuilderRebuildMap);
  version_ = 1;
  serLoadFunc_ = &DeserializeBuilderRebuildMap;
  serSaveFunc_ = &SerializeBuilderRebuildMap;
}

/**
 * Address: 0x00BCC2C0 (FUN_00BCC2C0, register_CAiBuilderImplTypeInfo)
 *
 * What it does:
 * Constructs startup-owned `CAiBuilderImplTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_CAiBuilderImplTypeInfo()
{
  (void)AcquireCAiBuilderImplTypeInfo();
  (void)std::atexit(&cleanup_CAiBuilderImplTypeInfo);
}

/**
 * Address: 0x005A1F50 (FUN_005A1F50)
 *
 * What it does:
 * Constructs/preregisters reflection metadata for
 * `std::map<unsigned int,Moho::RUnitBlueprint const *>`.
 */
gpg::RType* moho::preregister_CAiBuilderRebuildMapTypeInfo()
{
  gpg::RType* const type = AcquireCAiBuilderRebuildMapTypeInfo();
  gpg::PreRegisterRType(typeid(BuilderRebuildMapStorage), type);
  return type;
}

/**
 * Address: 0x00BCC360 (FUN_00BCC360)
 *
 * What it does:
 * Preregisters builder rebuild-map RTTI and installs process-exit cleanup.
 */
int moho::register_CAiBuilderRebuildMapTypeInfo()
{
  (void)preregister_CAiBuilderRebuildMapTypeInfo();
  return std::atexit(&cleanup_CAiBuilderRebuildMapTypeInfo);
}

/**
 * Address: 0x00BCC380 (FUN_00BCC380)
 *
 * What it does:
 * Installs process-exit cleanup for one startup-owned AI-builder stats slot.
 */
int moho::register_CAiBuilderStartupStatsCleanupPrimary()
{
  return std::atexit(&cleanup_CAiBuilderStartupStatsPrimary);
}

/**
 * Address: 0x00BCC3F0 (FUN_00BCC3F0)
 *
 * What it does:
 * Installs process-exit cleanup for a second startup-owned AI-builder stats
 * slot.
 */
int moho::register_CAiBuilderStartupStatsCleanupSecondary()
{
  return std::atexit(&cleanup_CAiBuilderStartupStatsSecondary);
}

namespace
{
  struct CAiBuilderImplTypeInfoBootstrap
  {
    CAiBuilderImplTypeInfoBootstrap()
    {
      moho::register_CAiBuilderImplTypeInfo();
      (void)moho::register_CAiBuilderRebuildMapTypeInfo();
      (void)moho::register_CAiBuilderStartupStatsCleanupPrimary();
      (void)moho::register_CAiBuilderStartupStatsCleanupSecondary();
    }
  };

  [[maybe_unused]] CAiBuilderImplTypeInfoBootstrap gCAiBuilderImplTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiBuilderImplTypeInfo_a07870, moho::register_CAiBuilderImplTypeInfo)
GPG_PREREGISTER_INIT(register_CAiBuilderRebuildMapTypeInfo_a07870, moho::register_CAiBuilderRebuildMapTypeInfo)

GPG_PREREGISTER_INIT(preregister_CAiBuilderRebuildMapTypeInfo_a07870, moho::preregister_CAiBuilderRebuildMapTypeInfo)
