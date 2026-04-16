#include "CInfluenceMap.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/console/CConAlias.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityDb.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class RMapType_uint_int final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00718C70 (FUN_00718C70, gpg::RMapType_uint_int::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00718D50 (FUN_00718D50, gpg::RMapType_uint_int::GetLexical)
     *
     * What it does:
     * Formats inherited map lexical text with current element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00718D30 (FUN_00718D30, gpg::RMapType_uint_int::Init)
     *
     * What it does:
     * Initializes map reflection metadata and binds typed archive callbacks.
     */
    void Init() override;
  };

  class RMapType_uint_InfluenceMapEntry final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00718FE0 (FUN_00718FE0, gpg::RMapType_uint_InfluenceMapEntry::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007190C0 (FUN_007190C0, gpg::RMapType_uint_InfluenceMapEntry::GetLexical)
     *
     * What it does:
     * Formats inherited map lexical text with current element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x007190A0 (FUN_007190A0, gpg::RMapType_uint_InfluenceMapEntry::Init)
     *
     * What it does:
     * Initializes map reflection metadata and binds typed archive callbacks.
     */
    void Init() override;
  };

  class RVectorType_InfluenceGrid final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00718DE0 (FUN_00718DE0, gpg::RVectorType_InfluenceGrid::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00718EA0 (FUN_00718EA0, gpg::RVectorType_InfluenceGrid::GetLexical)
     *
     * What it does:
     * Formats inherited vector lexical text with current `InfluenceGrid` count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    void Init() override;
  };

  class RVectorType_SThreat final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00719150 (FUN_00719150, gpg::RVectorType_SThreat::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00719210 (FUN_00719210, gpg::RVectorType_SThreat::GetLexical)
     *
     * What it does:
     * Formats inherited vector lexical text with current `SThreat` count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    void Init() override;
  };
} // namespace gpg

namespace
{
  using UIntIntMap = std::map<std::uint32_t, int>;
  using UIntInfluenceMapEntryMap = std::map<std::uint32_t, moho::InfluenceMapEntry>;
  using InfluenceGridVector = msvc8::vector<moho::InfluenceGrid>;
  using SThreatVector = msvc8::vector<moho::SThreat>;
  using InfluenceEntrySet = msvc8::set<moho::InfluenceMapEntry, moho::InfluenceMapEntryLess>;
  using InfluenceMapCellSet = msvc8::set<moho::InfluenceMapCellIndex, moho::InfluenceMapCellIndexLess>;
  using InfluenceEntryIterator = InfluenceEntrySet::iterator;
  using InfluenceMapCellIterator = InfluenceMapCellSet::iterator;

  template <typename TSet>
  struct LegacySetStorageRuntimeView
  {
    void* proxy;
    void* head;
    std::uint32_t size;
  };

  static_assert(
    sizeof(LegacySetStorageRuntimeView<InfluenceEntrySet>) == sizeof(InfluenceEntrySet),
    "InfluenceEntrySet runtime view size must match legacy set storage"
  );
  static_assert(
    sizeof(LegacySetStorageRuntimeView<InfluenceMapCellSet>) == sizeof(InfluenceMapCellSet),
    "InfluenceMapCellSet runtime view size must match legacy set storage"
  );

  void DestroyInfluenceEntryRange(
    InfluenceEntrySet& entries,
    InfluenceEntryIterator first,
    InfluenceEntryIterator last
  ) noexcept;

  /**
   * Address: 0x0071B860 (FUN_0071B860)
   *
   * What it does:
   * Adjusts one `vector<InfluenceGrid>` length to `requestedCount` and uses
   * one caller-provided fill lane for growth.
   */
  [[maybe_unused]] std::size_t ResizeInfluenceGridVectorWithFill(
    InfluenceGridVector& storage,
    const std::size_t requestedCount,
    const moho::InfluenceGrid& fillValue
  )
  {
    (void)fillValue;

    const std::size_t currentCount = storage.size();
    if (currentCount < requestedCount) {
      storage.resize(requestedCount);
      return requestedCount;
    }

    if (requestedCount < currentCount) {
      storage.resize(requestedCount);
    }

    return requestedCount;
  }

  /**
   * Address: 0x00719DE0 (FUN_00719DE0)
   *
   * What it does:
   * Resizes one `vector<InfluenceGrid>` to `requestedCount` using one default-
   * constructed `InfluenceGrid` fill value for growth lanes.
   */
  [[maybe_unused]] void ResizeInfluenceGridVectorWithDefaultFill(
    InfluenceGridVector& storage,
    const unsigned int requestedCount
  )
  {
    moho::InfluenceGrid fillValue{};
    (void)ResizeInfluenceGridVectorWithFill(storage, static_cast<std::size_t>(requestedCount), fillValue);
  }

  /**
   * Address: 0x00719790 (FUN_00719790)
   *
   * What it does:
   * Destroys one `InfluenceGrid::entries` tree payload before the set object's
   * own storage release runs at scope teardown.
   */
  void ClearInfluenceGridEntryTree(InfluenceEntrySet& entries) noexcept
  {
    DestroyInfluenceEntryRange(entries, entries.begin(), entries.end());
  }

  /**
   * Address: 0x00719F20 (FUN_00719F20)
   *
   * What it does:
   * Clears one `vector<InfluenceGrid>` payload before the vector member
   * releases its backing storage during destruction.
   */
  void ClearInfluenceGridVectorStorage(InfluenceGridVector& storage) noexcept
  {
    storage.clear();
  }

  struct LegacyMapRuntimeView
  {
    void* allocProxy;
    void* head;
    std::uint32_t size;
  };

  template <class TValue>
  [[nodiscard]] std::size_t CountLegacyVectorElements(const void* const object) noexcept
  {
    if (object == nullptr) {
      return 0u;
    }

    const auto* const vector = static_cast<const msvc8::vector<TValue>*>(object);
    return vector->size();
  }

  [[nodiscard]] std::size_t CountLegacyMapElements(const void* const object) noexcept
  {
    if (object == nullptr) {
      return 0u;
    }

    const auto* const mapView = static_cast<const LegacyMapRuntimeView*>(object);
    return mapView->size;
  }

  template <class TObject>
  [[nodiscard]] TObject* PointerFromArchiveInt(const int objectPtr)
  {
    return reinterpret_cast<TObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
  }

  template <class TObject>
  [[nodiscard]] const TObject* ConstPointerFromArchiveInt(const int objectPtr)
  {
    return reinterpret_cast<const TObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
  }

  using SerializerWord = std::uint32_t;

  struct SerializerSlot36ByPointerVTable
  {
    void* reserved[9];
    int(__thiscall* invoke)(void* self, SerializerWord* value);
  };

  struct SerializerSlot36ByValueVTable
  {
    void* reserved[9];
    int(__thiscall* invoke)(void* self, SerializerWord value);
  };

  struct SerializerSlot36RuntimeByPointer
  {
    SerializerSlot36ByPointerVTable* vtable;
  };

  struct SerializerSlot36RuntimeByValue
  {
    SerializerSlot36ByValueVTable* vtable;
  };

  /**
   * Address: 0x00719FB0 (FUN_00719FB0)
   *
   * What it does:
   * Invokes serializer virtual slot `+0x24` with a by-reference temporary and
   * writes the updated 32-bit value back to `valueSlot`.
   */
  [[maybe_unused]] int InvokePrimitiveSerializerWordByPointerLane(
    void* const helperObject,
    SerializerWord* const valueSlot
  )
  {
    auto* const helper = static_cast<SerializerSlot36RuntimeByPointer*>(helperObject);
    SerializerWord value = static_cast<SerializerWord>(reinterpret_cast<std::uintptr_t>(helperObject));
    const int result = helper->vtable->invoke(helperObject, &value);
    *valueSlot = value;
    return result;
  }

  /**
   * Address: 0x00719FD0 (FUN_00719FD0)
   *
   * What it does:
   * Forwards one 32-bit primitive value lane through serializer virtual slot
   * `+0x24`.
   */
  [[maybe_unused]] int InvokePrimitiveSerializerWordByValueLane(
    void* const helperObject,
    SerializerWord* const valueSlot
  )
  {
    auto* const helper = static_cast<SerializerSlot36RuntimeByValue*>(helperObject);
    return helper->vtable->invoke(helperObject, *valueSlot);
  }

  [[nodiscard]] float DecayThreatLane(const float value, const float decay) noexcept
  {
    if (value <= 0.0f) {
      return value;
    }

    float candidate = value + decay;
    if (candidate > 0.0f) {
      candidate = 0.0f;
    }

    const float reduced = value - decay;
    if (reduced > candidate) {
      candidate = reduced;
    }

    return candidate;
  }

  [[nodiscard]] moho::Entity* FindEntityById(moho::CEntityDb* const entityDb, const std::int32_t id) noexcept
  {
    if (!entityDb) {
      return nullptr;
    }

    for (auto it = entityDb->Entities().begin(); it != entityDb->Entities().end(); ++it) {
      moho::Entity* const entity = *it;
      if (entity && entity->id_ == id) {
        return entity;
      }
    }

    return nullptr;
  }

  [[nodiscard]] bool IsAlliedOrSameArmy(const moho::CArmyImpl* const owner, const moho::CArmyImpl* const source) noexcept
  {
    if (!owner || !source) {
      return false;
    }

    if (owner == source) {
      return true;
    }

    if (source->ArmyId < 0) {
      return false;
    }

    return owner->Allies.Contains(static_cast<std::uint32_t>(source->ArmyId));
  }

  struct InfluenceMapMd5UpdateOwnerRuntime
  {
    std::uint8_t pad_00_4F[0x50];
    gpg::MD5Context context;
  };

  /**
   * Address: 0x0071CA70 (FUN_0071CA70)
   *
   * What it does:
   * Updates the embedded MD5 context at owner offset `+0x50` with one 32-bit
   * word lane from caller-provided storage.
   */
  [[maybe_unused]] void UpdateMd5ContextWordAtOffset50(
    const void* const wordLane,
    InfluenceMapMd5UpdateOwnerRuntime* const owner
  )
  {
    owner->context.Update(wordLane, 4u);
  }

  [[nodiscard]] moho::CConAlias& ConAlias_imap_debug()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_imap_debug_grid()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_imap_debug_path_graph()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_imap_debug_grid_type()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::CConAlias& ConAlias_imap_debug_grid_army()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  [[nodiscard]] moho::TSimConVar<bool>& SimConVar_imap_debug()
  {
    static moho::TSimConVar<bool> sVar(false, "imap_debug", false);
    return sVar;
  }

  [[nodiscard]] moho::TSimConVar<bool>& SimConVar_imap_debug_grid()
  {
    static moho::TSimConVar<bool> sVar(false, "imap_debug_grid", false);
    return sVar;
  }

  [[nodiscard]] moho::TSimConVar<bool>& SimConVar_imap_debug_path_graph()
  {
    static moho::TSimConVar<bool> sVar(false, "imap_debug_path_graph", false);
    return sVar;
  }

  [[nodiscard]] moho::TSimConVar<int>& SimConVar_imap_debug_grid_type()
  {
    static moho::TSimConVar<int> sVar(false, "imap_debug_grid_type", 0);
    return sVar;
  }

  [[nodiscard]] moho::TSimConVar<int>& SimConVar_imap_debug_grid_army()
  {
    static moho::TSimConVar<int> sVar(false, "imap_debug_grid_army", -1);
    return sVar;
  }

  msvc8::string gInfluenceGridVectorTypeName{};
  std::uint32_t gInfluenceGridVectorTypeNameInitGuard = 0u;
  msvc8::string gMapUintIntTypeName{};
  std::uint32_t gMapUintIntTypeNameInitGuard = 0u;
  msvc8::string gMapUintInfluenceMapEntryTypeName{};
  std::uint32_t gMapUintInfluenceMapEntryTypeNameInitGuard = 0u;
  msvc8::string gSThreatVectorTypeName{};
  std::uint32_t gSThreatVectorTypeNameInitGuard = 0u;

  /**
   * Address: 0x0071A8E0 (FUN_0071A8E0)
   *
   * What it does:
   * Resolves and caches RTTI for one `InfluenceGrid` lane.
   */
  [[nodiscard]] gpg::RType* CachedInfluenceGridType()
  {
    gpg::RType* type = moho::InfluenceGrid::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::InfluenceGrid));
      moho::InfluenceGrid::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0071A900 (FUN_0071A900)
   *
   * What it does:
   * Resolves and caches RTTI for one `SThreat` lane.
   */
  [[nodiscard]] gpg::RType* CachedSThreatType()
  {
    gpg::RType* type = moho::SThreat::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SThreat));
      moho::SThreat::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedUIntType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(unsigned int));
      if (!type) {
        type = gpg::REF_FindTypeNamed("unsigned int");
      }
      if (!type) {
        type = gpg::REF_FindTypeNamed("uint");
      }
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIntType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(int));
      if (!type) {
        type = gpg::REF_FindTypeNamed("int");
      }
    }
    return type;
  }

  /**
   * Address: 0x0071A8C0 (FUN_0071A8C0)
   *
   * What it does:
   * Resolves and caches RTTI for one `InfluenceMapEntry` lane.
   */
  [[nodiscard]] gpg::RType* CachedInfluenceMapEntryType()
  {
    gpg::RType* type = moho::InfluenceMapEntry::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::InfluenceMapEntry));
      moho::InfluenceMapEntry::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0071D220 (FUN_0071D220)
   *
   * What it does:
   * Loads one reflected `InfluenceGrid` payload through cached RTTI lookup and
   * returns the archive pointer for chaining.
   */
  gpg::ReadArchive* ReadInfluenceGridArchiveAndReturnArchive(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = CachedInfluenceGridType()) {
        archive->Read(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x0071D290 (FUN_0071D290)
   *
   * What it does:
   * Saves one reflected `InfluenceGrid` payload through cached RTTI lookup and
   * returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteInfluenceGridArchiveAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = CachedInfluenceGridType()) {
        archive->Write(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x0071D2D0 (FUN_0071D2D0)
   *
   * What it does:
   * Loads one reflected `InfluenceMapEntry` payload through cached RTTI lookup
   * and returns the archive pointer for chaining.
   */
  gpg::ReadArchive* ReadInfluenceMapEntryArchiveAndReturnArchive(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = CachedInfluenceMapEntryType()) {
        archive->Read(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x0071D310 (FUN_0071D310)
   *
   * What it does:
   * Saves one reflected `InfluenceMapEntry` payload through cached RTTI lookup
   * and returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteInfluenceMapEntryArchiveAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = CachedInfluenceMapEntryType()) {
        archive->Write(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x0071D350 (FUN_0071D350)
   *
   * What it does:
   * Loads one reflected `SThreat` payload through cached RTTI lookup and
   * returns the archive pointer for chaining.
   */
  gpg::ReadArchive* ReadSThreatArchiveAndReturnArchive(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = CachedSThreatType()) {
        archive->Read(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x0071D3C0 (FUN_0071D3C0)
   *
   * What it does:
   * Saves one reflected `SThreat` payload through cached RTTI lookup and
   * returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteSThreatArchiveAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = CachedSThreatType()) {
        archive->Write(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x0071DB20 (FUN_0071DB20)
   *
   * What it does:
   * Read-callback bridge that loads one reflected `InfluenceGrid` payload
   * through cached RTTI lookup.
   */
  void ReadInfluenceGridArchiveCallback(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    (void)ReadInfluenceGridArchiveAndReturnArchive(archive, objectPtr, ownerRef);
  }

  /**
   * Address: 0x0071DB50 (FUN_0071DB50)
   *
   * What it does:
   * Write-callback bridge that saves one reflected `InfluenceGrid` payload
   * through cached RTTI lookup.
   */
  void WriteInfluenceGridArchiveCallback(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    (void)WriteInfluenceGridArchiveAndReturnArchive(archive, objectPtr, ownerRef);
  }

  /**
   * Address: 0x0071EF60 (FUN_0071EF60)
   *
   * What it does:
   * Resolves and caches RTTI for one `map<unsigned int, InfluenceMapEntry>`
   * lane.
   */
  [[nodiscard]] gpg::RType* CachedInfluenceMapEntryMapType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(UIntInfluenceMapEntryMap));
    }
    return type;
  }

  /**
   * Address: 0x0071EF80 (FUN_0071EF80)
   *
   * What it does:
   * Resolves and caches RTTI for one `vector<SThreat>` lane.
   */
  [[nodiscard]] gpg::RType* CachedSThreatVectorType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(msvc8::vector<moho::SThreat>));
    }
    return type;
  }

  /**
   * Address: 0x0071FEA0 (FUN_0071FEA0)
   *
   * What it does:
   * Resolves and caches RTTI for one `map<unsigned int, int>` lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedUIntIntMapTypeLegacyLane()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(UIntIntMap));
    }
    return type;
  }

  /**
   * Address: 0x0071FEC0 (FUN_0071FEC0)
   *
   * What it does:
   * Resolves and caches RTTI for one `vector<InfluenceGrid>` lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedInfluenceGridVectorTypeLegacyLane()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(InfluenceGridVector));
    }
    return type;
  }

  void cleanup_InfluenceGridVectorTypeName()
  {
    gInfluenceGridVectorTypeName.clear();
    gInfluenceGridVectorTypeNameInitGuard = 0u;
  }

  void cleanup_SThreatVectorTypeName()
  {
    gSThreatVectorTypeName.clear();
    gSThreatVectorTypeNameInitGuard = 0u;
  }

  void cleanup_MapUintIntTypeName()
  {
    gMapUintIntTypeName.clear();
    gMapUintIntTypeNameInitGuard = 0u;
  }

  void cleanup_MapUintInfluenceMapEntryTypeName()
  {
    gMapUintInfluenceMapEntryTypeName.clear();
    gMapUintInfluenceMapEntryTypeNameInitGuard = 0u;
  }

  /**
   * Address: 0x0071A220 (FUN_0071A220)
   *
   * What it does:
   * Loads one `map<unsigned int,int>` payload from archive lanes.
   */
  void LoadUIntIntMap(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const mapObject = PointerFromArchiveInt<UIntIntMap>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(mapObject != nullptr);
    if (!archive || !mapObject) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    mapObject->clear();
    for (unsigned int i = 0; i < count; ++i) {
      unsigned int key = 0;
      int value = 0;
      archive->ReadUInt(&key);
      archive->ReadInt(&value);
      (*mapObject)[key] = value;
    }
  }

  /**
   * Address: 0x0071A2D0 (FUN_0071A2D0)
   *
   * What it does:
   * Saves one `map<unsigned int,int>` payload into archive lanes.
   */
  void SaveUIntIntMap(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const mapObject = ConstPointerFromArchiveInt<UIntIntMap>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(mapObject != nullptr);
    if (!archive || !mapObject) {
      return;
    }

    archive->WriteUInt(static_cast<unsigned int>(mapObject->size()));
    for (auto it = mapObject->begin(); it != mapObject->end(); ++it) {
      archive->WriteUInt(it->first);
      archive->WriteInt(it->second);
    }
  }

  /**
   * Address: 0x0071A530 (FUN_0071A530)
   *
   * What it does:
   * Loads one `map<unsigned int,InfluenceMapEntry>` payload from archive lanes.
   */
  void LoadUIntInfluenceMapEntryMap(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    auto* const mapObject = PointerFromArchiveInt<UIntInfluenceMapEntryMap>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(mapObject != nullptr);
    if (!archive || !mapObject) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    mapObject->clear();
    gpg::RType* const valueType = CachedInfluenceMapEntryType();
    GPG_ASSERT(valueType != nullptr);
    if (!valueType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      unsigned int key = 0;
      moho::InfluenceMapEntry value{};
      archive->ReadUInt(&key);
      archive->Read(valueType, &value, owner);
      (*mapObject)[key] = value;
    }
  }

  /**
   * Address: 0x0071A670 (FUN_0071A670)
   *
   * What it does:
   * Saves one `map<unsigned int,InfluenceMapEntry>` payload into archive lanes.
   */
  void SaveUIntInfluenceMapEntryMap(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const mapObject = ConstPointerFromArchiveInt<UIntInfluenceMapEntryMap>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(mapObject != nullptr);
    if (!archive || !mapObject) {
      return;
    }

    archive->WriteUInt(static_cast<unsigned int>(mapObject->size()));

    gpg::RType* const valueType = CachedInfluenceMapEntryType();
    GPG_ASSERT(valueType != nullptr);
    if (!valueType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (auto it = mapObject->begin(); it != mapObject->end(); ++it) {
      archive->WriteUInt(it->first);
      archive->Write(valueType, &(it->second), owner);
    }
  }

  /**
   * Address: 0x0071CF30 (FUN_0071CF30, deserialize_InfluenceGrid_record)
   *
   * What it does:
   * Deserializes one `InfluenceGrid` payload in archive field order:
   * `entries`, `threats`, aggregate threat, and decay lanes.
   */
  [[maybe_unused]] void DeserializeInfluenceGridRecord(
    gpg::ReadArchive* const archive,
    moho::InfluenceGrid* const grid,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || grid == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    gpg::RType* const entryMapType = CachedInfluenceMapEntryMapType();
    GPG_ASSERT(entryMapType != nullptr);
    if (!entryMapType) {
      return;
    }
    archive->Read(entryMapType, &grid->entries, owner);

    gpg::RType* const threatVectorType = CachedSThreatVectorType();
    GPG_ASSERT(threatVectorType != nullptr);
    if (!threatVectorType) {
      return;
    }
    archive->Read(threatVectorType, &grid->threats, owner);

    gpg::RType* const threatType = CachedSThreatType();
    GPG_ASSERT(threatType != nullptr);
    if (!threatType) {
      return;
    }
    archive->Read(threatType, &grid->threat, owner);
    archive->Read(threatType, &grid->decay, owner);
  }

  /**
   * Address: 0x0071D010 (FUN_0071D010, serialize_InfluenceGrid_record)
   *
   * What it does:
   * Serializes one `InfluenceGrid` payload in archive field order:
   * `entries`, `threats`, aggregate threat, and decay lanes.
   */
  [[maybe_unused]] void SerializeInfluenceGridRecord(
    gpg::WriteArchive* const archive,
    const moho::InfluenceGrid* const grid,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || grid == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    gpg::RType* const entryMapType = CachedInfluenceMapEntryMapType();
    GPG_ASSERT(entryMapType != nullptr);
    if (!entryMapType) {
      return;
    }
    archive->Write(entryMapType, grid, owner);

    gpg::RType* const threatVectorType = CachedSThreatVectorType();
    GPG_ASSERT(threatVectorType != nullptr);
    if (!threatVectorType) {
      return;
    }
    archive->Write(threatVectorType, &grid->threats, owner);

    gpg::RType* const threatType = CachedSThreatType();
    GPG_ASSERT(threatType != nullptr);
    if (!threatType) {
      return;
    }
    archive->Write(threatType, &grid->threat, owner);
    archive->Write(threatType, &grid->decay, owner);
  }

  /**
   * Address: 0x00717CF0 (FUN_00717CF0)
   *
   * What it does:
   * Read-callback thunk for `InfluenceGrid` archive lanes that forwards to
   * `DeserializeInfluenceGridRecord` (`FUN_0071CF30`).
   */
  [[maybe_unused]] void DeserializeInfluenceGridRecordCallbackThunk(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    DeserializeInfluenceGridRecord(
      archive,
      PointerFromArchiveInt<moho::InfluenceGrid>(objectPtr),
      ownerRef
    );
  }

  /**
   * Address: 0x00717D00 (FUN_00717D00)
   *
   * What it does:
   * Write-callback thunk for `InfluenceGrid` archive lanes that forwards to
   * `SerializeInfluenceGridRecord` (`FUN_0071D010`).
   */
  [[maybe_unused]] void SerializeInfluenceGridRecordCallbackThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    SerializeInfluenceGridRecord(
      archive,
      ConstPointerFromArchiveInt<moho::InfluenceGrid>(objectPtr),
      ownerRef
    );
  }

  /**
   * Address: 0x0071CB20 (FUN_0071CB20, deserialize_InfluenceMapEntry_record)
   *
   * What it does:
   * Deserializes one `InfluenceMapEntry` payload in archive field order:
   * `EntId`, `SimArmy*`, `Vector3f` position, `RUnitBlueprint*`, `ELayer`,
   * detail flag, threat magnitude/decay, and decay tick count.
   */
  void DeserializeInfluenceMapEntryRecord(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const entry = PointerFromArchiveInt<moho::InfluenceMapEntry>(objectPtr);
    if (archive == nullptr || entry == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    static gpg::RType* entIdType = nullptr;
    if (entIdType == nullptr) {
      entIdType = gpg::LookupRType(typeid(moho::EntId));
    }
    archive->Read(entIdType, &entry->entityId, owner);

    moho::SimArmy* sourceArmy = nullptr;
    archive->ReadPointer_SimArmy(&sourceArmy, &owner);
    entry->sourceArmy = reinterpret_cast<moho::CArmyImpl*>(sourceArmy);

    static gpg::RType* vector3fType = nullptr;
    if (vector3fType == nullptr) {
      vector3fType = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    archive->Read(vector3fType, &entry->lastPosition, owner);

    moho::RUnitBlueprint* sourceBlueprint = nullptr;
    archive->ReadPointer_RUnitBlueprint(&sourceBlueprint, &owner);
    entry->sourceBlueprint = sourceBlueprint;

    static gpg::RType* layerType = nullptr;
    if (layerType == nullptr) {
      layerType = gpg::LookupRType(typeid(moho::ELayer));
    }
    archive->Read(layerType, &entry->sourceLayer, owner);

    bool isDetailed = false;
    archive->ReadBool(&isDetailed);
    entry->isDetailed = isDetailed ? 1u : 0u;

    archive->ReadFloat(&entry->threatStrength);
    archive->ReadFloat(&entry->threatDecay);
    archive->ReadInt(&entry->decayTicks);
  }

  /**
   * Address: 0x0071CC30 (FUN_0071CC30, serialize_InfluenceMapEntry_record)
   *
   * What it does:
   * Serializes one `InfluenceMapEntry` payload in archive field order using
   * unowned pointer lanes for `SimArmy*` and `RUnitBlueprint*`.
   */
  void SerializeInfluenceMapEntryRecord(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const entry = ConstPointerFromArchiveInt<moho::InfluenceMapEntry>(objectPtr);
    if (archive == nullptr || entry == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    static gpg::RType* entIdType = nullptr;
    if (entIdType == nullptr) {
      entIdType = gpg::LookupRType(typeid(moho::EntId));
    }
    archive->Write(entIdType, &entry->entityId, owner);

    gpg::RRef armyRef{};
    (void)gpg::RRef_SimArmy(&armyRef, reinterpret_cast<moho::SimArmy*>(entry->sourceArmy));
    gpg::WriteRawPointer(archive, armyRef, gpg::TrackedPointerState::Unowned, owner);

    static gpg::RType* vector3fType = nullptr;
    if (vector3fType == nullptr) {
      vector3fType = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    archive->Write(vector3fType, &entry->lastPosition, owner);

    gpg::RRef blueprintRef{};
    (void)gpg::RRef_RUnitBlueprint(&blueprintRef, const_cast<moho::RUnitBlueprint*>(entry->sourceBlueprint));
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, owner);

    static gpg::RType* layerType = nullptr;
    if (layerType == nullptr) {
      layerType = gpg::LookupRType(typeid(moho::ELayer));
    }
    archive->Write(layerType, &entry->sourceLayer, owner);

    archive->WriteBool(entry->isDetailed != 0u);
    archive->WriteFloat(entry->threatStrength);
    archive->WriteFloat(entry->threatDecay);
    archive->WriteInt(entry->decayTicks);
  }

  struct RRefPairRuntime
  {
    void* object;      // +0x00
    gpg::RType* type;  // +0x04
  };
  static_assert(sizeof(RRefPairRuntime) == 0x08, "RRefPairRuntime size must be 0x08");

  /**
   * Address: 0x0071CAD0 (FUN_0071CAD0)
   *
   * What it does:
   * Builds one reflected `RRef` pair for `CInfluenceMap` and writes
   * `{mObj,mType}` lanes into caller-owned output storage.
   */
  [[maybe_unused]] RRefPairRuntime* BuildCInfluenceMapRRefPair(
    moho::CInfluenceMap* const object,
    RRefPairRuntime* const outRefPair
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_CInfluenceMap(&ref, object);
    outRefPair->object = ref.mObj;
    outRefPair->type = ref.mType;
    return outRefPair;
  }

  /**
   * Address: 0x0071D100 (FUN_0071D100)
   *
   * What it does:
   * Builds one reflected `RRef` pair for `InfluenceGrid` and writes
   * `{mObj,mType}` lanes into caller-owned output storage.
   */
  [[maybe_unused]] RRefPairRuntime* BuildInfluenceGridRRefPair(
    moho::InfluenceGrid* const object,
    RRefPairRuntime* const outRefPair
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_InfluenceGrid(&ref, object);
    outRefPair->object = ref.mObj;
    outRefPair->type = ref.mType;
    return outRefPair;
  }

  /**
   * Address: 0x0071D140 (FUN_0071D140)
   *
   * What it does:
   * Builds one reflected `RRef` pair for `SThreat` and writes
   * `{mObj,mType}` lanes into caller-owned output storage.
   */
  [[maybe_unused]] RRefPairRuntime* BuildSThreatRRefPair(
    moho::SThreat* const object,
    RRefPairRuntime* const outRefPair
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_SThreat(&ref, object);
    outRefPair->object = ref.mObj;
    outRefPair->type = ref.mType;
    return outRefPair;
  }

  /**
   * Address: 0x007178F0 (FUN_007178F0)
   *
   * What it does:
   * Read-callback thunk for `InfluenceMapEntry` archive lanes that forwards to
   * `DeserializeInfluenceMapEntryRecord` (`FUN_0071CB20`).
   */
  [[maybe_unused]] void DeserializeInfluenceMapEntryRecordCallbackThunk(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    DeserializeInfluenceMapEntryRecord(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00717900 (FUN_00717900)
   *
   * What it does:
   * Write-callback thunk for `InfluenceMapEntry` archive lanes that forwards
   * to `SerializeInfluenceMapEntryRecord` (`FUN_0071CC30`).
   */
  [[maybe_unused]] void SerializeInfluenceMapEntryRecordCallbackThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SerializeInfluenceMapEntryRecord(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x0071BE10 (FUN_0071BE10, sub_71BE10)
   *
   * What it does:
   * Advances one `InfluenceGrid::entries` iterator to its in-order successor.
   */
  void AdvanceInfluenceEntryIterator(InfluenceEntryIterator& it, const InfluenceEntryIterator end) noexcept
  {
    if (it != end) {
      ++it;
    }
  }

  /**
   * Address: 0x007189D0 (FUN_007189D0)
   *
   * What it does:
   * Thunk lane that advances one `InfluenceGrid::entries` iterator and returns
   * the same iterator-slot pointer.
   */
  [[maybe_unused]] InfluenceEntryIterator* AdvanceInfluenceEntryIteratorThunkA(
    const InfluenceEntryIterator end,
    InfluenceEntryIterator* const iteratorSlot
  ) noexcept
  {
    if (iteratorSlot != nullptr) {
      AdvanceInfluenceEntryIterator(*iteratorSlot, end);
    }
    return iteratorSlot;
  }

  /**
   * Address: 0x0071A0C0 (FUN_0071A0C0)
   *
   * What it does:
   * Secondary thunk lane that advances one `InfluenceGrid::entries` iterator
   * and returns the same iterator-slot pointer.
   */
  [[maybe_unused]] InfluenceEntryIterator* AdvanceInfluenceEntryIteratorThunkB(
    const InfluenceEntryIterator end,
    InfluenceEntryIterator* const iteratorSlot
  ) noexcept
  {
    if (iteratorSlot != nullptr) {
      AdvanceInfluenceEntryIterator(*iteratorSlot, end);
    }
    return iteratorSlot;
  }

  /**
   * Address: 0x00717EF0 (FUN_00717EF0, sub_717EF0)
   *
   * What it does:
   * Erases one `InfluenceGrid::entries` node and returns the successor iterator.
   */
  [[nodiscard]] InfluenceEntryIterator EraseInfluenceEntryAndAdvance(
    moho::InfluenceGrid& grid,
    const InfluenceEntryIterator current
  )
  {
    if (current == grid.entries.end()) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    InfluenceEntryIterator next = current;
    AdvanceInfluenceEntryIterator(next, grid.entries.end());
    grid.entries.erase(current);
    return next;
  }

  /**
   * Address: 0x0071C280 (FUN_0071C280, sub_71C280)
   *
   * What it does:
   * Destroys one ordered range of `InfluenceGrid::entries` nodes.
   */
  void DestroyInfluenceEntryRange(
    InfluenceEntrySet& entries,
    InfluenceEntryIterator first,
    const InfluenceEntryIterator last
  ) noexcept
  {
    while (first != last) {
      const InfluenceEntryIterator eraseIt = first;
      AdvanceInfluenceEntryIterator(first, last);
      entries.erase(eraseIt);
    }
  }

  /**
   * Address: 0x0071C590 (FUN_0071C590, sub_71C590)
   *
   * What it does:
   * Advances one `CInfluenceMap::mBlipCells` iterator to its in-order successor.
   */
  void AdvanceBlipCellIterator(InfluenceMapCellIterator& it, const InfluenceMapCellIterator end) noexcept
  {
    if (it != end) {
      ++it;
    }
  }

  /**
   * Address: 0x0071A060 (FUN_0071A060)
   *
   * What it does:
   * Thunk lane that advances one `mBlipCells` iterator and returns the same
   * iterator-slot pointer.
   */
  [[maybe_unused]] InfluenceMapCellIterator* AdvanceBlipCellIteratorThunkA(
    const InfluenceMapCellIterator end,
    InfluenceMapCellIterator* const iteratorSlot
  ) noexcept
  {
    if (iteratorSlot != nullptr) {
      AdvanceBlipCellIterator(*iteratorSlot, end);
    }
    return iteratorSlot;
  }

  /**
   * Address: 0x0071B420 (FUN_0071B420, sub_71B420)
   *
   * What it does:
   * Erases one `mBlipCells` iterator range and returns the first non-erased
   * successor.
   */
  [[nodiscard]] InfluenceMapCellIterator EraseBlipCellRange(
    InfluenceMapCellSet& blipCells,
    InfluenceMapCellIterator first,
    const InfluenceMapCellIterator last
  ) noexcept
  {
    if (first == blipCells.begin() && last == blipCells.end()) {
      blipCells.clear();
      return blipCells.begin();
    }

    while (first != last) {
      const InfluenceMapCellIterator eraseIt = first;
      AdvanceBlipCellIterator(first, last);
      blipCells.erase(eraseIt);
    }

    return first;
  }

  /**
   * Address: 0x0071D7B0 (FUN_0071D7B0, sub_71D7B0)
   *
   * What it does:
   * Allocates legacy red-black-tree node storage for blip-cell set lanes with
   * VC8-style overflow guard semantics (`0x18` bytes per node).
   */
  [[maybe_unused]] void* AllocateBlipCellNodeBlock(const unsigned int count)
  {
    constexpr unsigned int kNodeBytes = 0x18u;
    if (count != 0u && (std::numeric_limits<unsigned int>::max() / count) < kNodeBytes) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(count) * static_cast<std::size_t>(kNodeBytes));
  }

  /**
   * Address: 0x0071C790 (FUN_0071C790)
   *
   * What it does:
   * Allocates one legacy `mBlipCells` tree-node lane (`0x18` bytes).
   */
  [[maybe_unused]] void* AllocateSingleBlipCellNode() { return AllocateBlipCellNodeBlock(1u); }

  /**
   * Address: 0x0071C750 (FUN_0071C750)
   *
   * What it does:
   * Allocates one fixed `0x40`-byte runtime node lane.
   */
  [[maybe_unused]] void* AllocateSingle64ByteNode() { return ::operator new(0x40u); }

  struct BlipCellTreeNodeRuntime
  {
    BlipCellTreeNodeRuntime* left;   // +0x00
    BlipCellTreeNodeRuntime* parent; // +0x04
    BlipCellTreeNodeRuntime* right;  // +0x08
    std::uint32_t entityId;          // +0x0C
    std::int32_t cellIndex;          // +0x10
    std::uint8_t color;              // +0x14
    std::uint8_t isNil;              // +0x15
    std::uint8_t pad16;              // +0x16
    std::uint8_t pad17;              // +0x17
  };
  static_assert(sizeof(BlipCellTreeNodeRuntime) == 0x18, "BlipCellTreeNodeRuntime size must be 0x18");

#pragma pack(push, 1)
  struct InfluenceNodeFlag61Runtime
  {
    InfluenceNodeFlag61Runtime* left;   // +0x00
    InfluenceNodeFlag61Runtime* parent; // +0x04
    InfluenceNodeFlag61Runtime* right;  // +0x08
    std::uint32_t key;                  // +0x0C
    std::uint8_t pad_10_3C[0x2D];       // +0x10
    std::uint8_t isNil61;               // +0x3D
  };

  struct InfluenceNodeFlag21Runtime
  {
    InfluenceNodeFlag21Runtime* left;   // +0x00
    InfluenceNodeFlag21Runtime* parent; // +0x04
    InfluenceNodeFlag21Runtime* right;  // +0x08
    std::uint32_t key;                  // +0x0C
    std::uint8_t pad_10_14[0x05];       // +0x10
    std::uint8_t isNil21;               // +0x15
  };
#pragma pack(pop)

  static_assert(offsetof(InfluenceNodeFlag61Runtime, isNil61) == 0x3D, "InfluenceNodeFlag61Runtime::isNil61 offset");
  static_assert(offsetof(InfluenceNodeFlag21Runtime, isNil21) == 0x15, "InfluenceNodeFlag21Runtime::isNil21 offset");

  template <typename TNode, typename TIsNil>
  [[nodiscard]] TNode* AdvanceRuntimeRbIteratorSlot(TNode** const iteratorSlot, TIsNil&& isNil) noexcept
  {
    TNode* result = *iteratorSlot;
    if (!isNil(*iteratorSlot)) {
      TNode* right = result->right;
      if (isNil(right)) {
        for (result = result->parent; !isNil(result); result = result->parent) {
          if (*iteratorSlot != result->right) {
            break;
          }
          *iteratorSlot = result;
        }
        *iteratorSlot = result;
      } else {
        result = right->left;
        if (!isNil(right->left)) {
          do {
            right = result;
            result = result->left;
          } while (!isNil(result));
        }
        *iteratorSlot = right;
      }
    }
    return result;
  }

  template <typename TNode, typename TIsNil>
  [[nodiscard]] TNode* RetreatRuntimeRbIteratorSlot(TNode** const iteratorSlot, TIsNil&& isNil) noexcept
  {
    TNode* const node = *iteratorSlot;
    TNode* result = node;
    if (isNil(node)) {
      result = node->right;
      *iteratorSlot = result;
      return result;
    }

    TNode* left = node->left;
    if (isNil(left)) {
      for (result = node->parent; !isNil(result); result = result->parent) {
        if (*iteratorSlot != result->left) {
          break;
        }
        *iteratorSlot = result;
      }
      if (!isNil(*iteratorSlot)) {
        *iteratorSlot = result;
      }
      return result;
    }

    for (result = left->right; !isNil(result); result = result->right) {
      left = result;
    }
    *iteratorSlot = left;
    return result;
  }

  /**
   * Address: 0x0071B4E0 (FUN_0071B4E0)
   *
   * What it does:
   * Seeds one legacy set runtime header with a self-linked sentinel node and
   * zero element count.
   */
  [[maybe_unused]] void* ConstructBlipCellSetHeaderFromSentinel(
    LegacySetStorageRuntimeView<InfluenceMapCellSet>& setStorage
  )
  {
    auto* const sentinel = static_cast<BlipCellTreeNodeRuntime*>(AllocateBlipCellNodeBlock(1u));
    setStorage.head = sentinel;

    sentinel->left = sentinel;
    sentinel->parent = sentinel;
    sentinel->right = sentinel;
    sentinel->entityId = 0u;
    sentinel->cellIndex = 0;
    sentinel->color = 1u;
    sentinel->isNil = 1u;
    sentinel->pad16 = 0u;
    sentinel->pad17 = 0u;
    setStorage.size = 0u;
    return sentinel;
  }

  /**
   * Address: 0x0071BDB0 (FUN_0071BDB0)
   *
   * What it does:
   * Advances one nil-21 red-black iterator slot in place and returns the
   * same slot pointer.
   */
  [[maybe_unused]] InfluenceNodeFlag21Runtime** AdvanceRbIteratorNil21InPlaceLaneA(
    InfluenceNodeFlag21Runtime** const iteratorSlot
  ) noexcept
  {
    (void)AdvanceRuntimeRbIteratorSlot(
      iteratorSlot, [](const InfluenceNodeFlag21Runtime* const node) { return node->isNil21 != 0u; }
    );
    return iteratorSlot;
  }

  /**
   * Address: 0x0071C560 (FUN_0071C560)
   * Address: 0x0077C710 (FUN_0077C710)
   *
   * What it does:
   * Copies one nil-21 iterator slot into destination, then advances source.
   */
  [[maybe_unused]] InfluenceNodeFlag21Runtime** PostAdvanceRbIteratorNil21CopyLaneA(
    InfluenceNodeFlag21Runtime** const sourceSlot,
    InfluenceNodeFlag21Runtime** const destinationSlot
  ) noexcept
  {
    *destinationSlot = *sourceSlot;
    (void)AdvanceRbIteratorNil21InPlaceLaneA(sourceSlot);
    return destinationSlot;
  }

  /**
   * Address: 0x0071C5E0 (FUN_0071C5E0)
   *
   * What it does:
   * Copies one nil-61 iterator slot into destination, then advances source.
   */
  [[maybe_unused]] InfluenceNodeFlag61Runtime** PostAdvanceRbIteratorNil61CopyLaneA(
    InfluenceNodeFlag61Runtime** const sourceSlot,
    InfluenceNodeFlag61Runtime** const destinationSlot
  ) noexcept
  {
    *destinationSlot = *sourceSlot;
    (void)AdvanceRuntimeRbIteratorSlot(
      sourceSlot, [](const InfluenceNodeFlag61Runtime* const node) { return node->isNil61 != 0u; }
    );
    return destinationSlot;
  }

  /**
   * Address: 0x0071BD70 (FUN_0071BD70)
   *
   * What it does:
   * Steps one nil-21 red-black iterator slot backward and returns the input
   * slot pointer.
   */
  [[maybe_unused]] InfluenceNodeFlag21Runtime** StepRbIteratorNil21BackwardLaneA(
    void* const,
    InfluenceNodeFlag21Runtime** const iteratorSlot
  ) noexcept
  {
    (void)RetreatRuntimeRbIteratorSlot(
      iteratorSlot, [](const InfluenceNodeFlag21Runtime* const node) { return node->isNil21 != 0u; }
    );
    return iteratorSlot;
  }

  /**
   * Address: 0x0071C580 (FUN_0071C580)
   *
   * What it does:
   * Secondary adapter lane that steps one nil-21 red-black iterator slot
   * backward.
   */
  [[maybe_unused]] InfluenceNodeFlag21Runtime** StepRbIteratorNil21BackwardLaneB(
    void* const context,
    InfluenceNodeFlag21Runtime** const iteratorSlot
  ) noexcept
  {
    return StepRbIteratorNil21BackwardLaneA(context, iteratorSlot);
  }

  /**
   * Address: 0x0071BDD0 (FUN_0071BDD0)
   *
   * What it does:
   * Steps one nil-61 red-black iterator slot backward and returns the input
   * slot pointer.
   */
  [[maybe_unused]] InfluenceNodeFlag61Runtime** StepRbIteratorNil61BackwardLaneA(
    void* const,
    InfluenceNodeFlag61Runtime** const iteratorSlot
  ) noexcept
  {
    (void)RetreatRuntimeRbIteratorSlot(
      iteratorSlot, [](const InfluenceNodeFlag61Runtime* const node) { return node->isNil61 != 0u; }
    );
    return iteratorSlot;
  }

  /**
   * Address: 0x0071C600 (FUN_0071C600)
   *
   * What it does:
   * Secondary adapter lane that steps one nil-61 red-black iterator slot
   * backward.
   */
  [[maybe_unused]] InfluenceNodeFlag61Runtime** StepRbIteratorNil61BackwardLaneB(
    void* const context,
    InfluenceNodeFlag61Runtime** const iteratorSlot
  ) noexcept
  {
    return StepRbIteratorNil61BackwardLaneA(context, iteratorSlot);
  }

  /**
   * Address: 0x007196E0 (FUN_007196E0)
   *
   * What it does:
   * Returns the rightmost node reachable from a flag-61 RB-tree head.
   */
  [[maybe_unused]] InfluenceNodeFlag61Runtime* FindInfluenceTreeRightmostNodeFlag61(
    InfluenceNodeFlag61Runtime* head
  ) noexcept
  {
    InfluenceNodeFlag61Runtime* cursor = head->right;
    while (cursor->isNil61 == 0u) {
      head = cursor;
      cursor = head->right;
    }
    return head;
  }

  /**
   * Address: 0x00719700 (FUN_00719700)
   *
   * What it does:
   * Returns the leftmost node reachable from a flag-61 RB-tree head.
   */
  [[maybe_unused]] InfluenceNodeFlag61Runtime* FindInfluenceTreeLeftmostNodeFlag61(
    InfluenceNodeFlag61Runtime* head
  ) noexcept
  {
    InfluenceNodeFlag61Runtime* cursor = head->left;
    if (cursor->isNil61 != 0u) {
      return head;
    }

    do {
      head = cursor;
      cursor = head->left;
    } while (cursor->isNil61 == 0u);
    return head;
  }

  /**
   * Address: 0x00719CA0 (FUN_00719CA0)
   *
   * What it does:
   * Returns the rightmost node reachable from a flag-21 RB-tree head.
   */
  [[maybe_unused]] InfluenceNodeFlag21Runtime* FindInfluenceTreeRightmostNodeFlag21(
    InfluenceNodeFlag21Runtime* head
  ) noexcept
  {
    InfluenceNodeFlag21Runtime* cursor = head->right;
    while (cursor->isNil21 == 0u) {
      head = cursor;
      cursor = head->right;
    }
    return head;
  }

  /**
   * Address: 0x00719CC0 (FUN_00719CC0)
   *
   * What it does:
   * Returns the leftmost node reachable from a flag-21 RB-tree head.
   */
  [[maybe_unused]] InfluenceNodeFlag21Runtime* FindInfluenceTreeLeftmostNodeFlag21(
    InfluenceNodeFlag21Runtime* head
  ) noexcept
  {
    InfluenceNodeFlag21Runtime* cursor = head->left;
    if (cursor->isNil21 != 0u) {
      return head;
    }

    do {
      head = cursor;
      cursor = head->left;
    } while (cursor->isNil21 == 0u);
    return head;
  }

  /**
   * Address: 0x0071C4E0 (FUN_0071C4E0)
   *
   * What it does:
   * Allocates one blip-cell tree node and seeds links, key lanes, and
   * red-black marker bytes.
   */
  [[maybe_unused]] BlipCellTreeNodeRuntime* AllocateBlipCellTreeNode(
    const moho::InfluenceMapCellIndex& key,
    BlipCellTreeNodeRuntime* const left,
    BlipCellTreeNodeRuntime* const parent,
    BlipCellTreeNodeRuntime* const right
  )
  {
    auto* const node = static_cast<BlipCellTreeNodeRuntime*>(AllocateBlipCellNodeBlock(1u));
    if (node == nullptr) {
      return nullptr;
    }

    node->left = left;
    node->parent = parent;
    node->right = right;
    node->entityId = key.entityId;
    node->cellIndex = key.cellIndex;
    node->color = 0u;
    node->isNil = 0u;
    node->pad16 = 0u;
    node->pad17 = 0u;
    return node;
  }

  /**
   * Address: 0x0071A330 (FUN_0071A330, sub_71A330)
   *
   * What it does:
   * Loads one reflected `vector<InfluenceGrid>` payload from archive lanes.
   */
  [[maybe_unused]] void LoadInfluenceGridVectorArchive(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const vectorObject = PointerFromArchiveInt<InfluenceGridVector>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vectorObject != nullptr);
    if (!archive || !vectorObject) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    vectorObject->clear();
    if (count == 0u) {
      return;
    }

    vectorObject->resize(count);

    gpg::RType* const valueType = CachedInfluenceGridType();
    GPG_ASSERT(valueType != nullptr);
    if (!valueType) {
      vectorObject->clear();
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(valueType, &(*vectorObject)[static_cast<std::size_t>(i)], owner);
    }
  }

  /**
   * Address: 0x0071A4A0 (FUN_0071A4A0)
   *
   * What it does:
   * Serializes one reflected `vector<InfluenceGrid>` payload by writing count
   * and then each `InfluenceGrid` element lane.
   */
  [[maybe_unused]] void SaveInfluenceGridVectorArchive(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const vectorObject = ConstPointerFromArchiveInt<InfluenceGridVector>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const unsigned int count = vectorObject != nullptr ? static_cast<unsigned int>(vectorObject->size()) : 0u;
    archive->WriteUInt(count);
    if (count == 0u || vectorObject == nullptr) {
      return;
    }

    gpg::RType* const valueType = CachedInfluenceGridType();
    GPG_ASSERT(valueType != nullptr);
    if (!valueType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(valueType, const_cast<moho::InfluenceGrid*>(&(*vectorObject)[static_cast<std::size_t>(i)]), owner);
    }
  }

  /**
   * Address: 0x0071A830 (FUN_0071A830)
   *
   * What it does:
   * Serializes one reflected `vector<SThreat>` payload by writing count and
   * then each threat-element lane.
   */
  [[maybe_unused]] void SaveSThreatVectorArchive(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const vectorObject = ConstPointerFromArchiveInt<SThreatVector>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const unsigned int count = vectorObject != nullptr ? static_cast<unsigned int>(vectorObject->size()) : 0u;
    archive->WriteUInt(count);
    if (count == 0u || vectorObject == nullptr) {
      return;
    }

    gpg::RType* const valueType = CachedSThreatType();
    GPG_ASSERT(valueType != nullptr);
    if (!valueType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(valueType, const_cast<moho::SThreat*>(&(*vectorObject)[static_cast<std::size_t>(i)]), owner);
    }
  }

  /**
   * Address: 0x0071AEC0 (FUN_0071AEC0)
   *
   * What it does:
   * Resizes one `vector<SThreat>` with fill semantics, trimming or appending
   * zeroed threat lanes as needed.
   */
  void ResizeSThreatVectorWithFill(
    SThreatVector& storage,
    const std::size_t requestedCount,
    const moho::SThreat& fillValue
  )
  {
    const std::size_t currentCount = storage.size();
    if (currentCount < requestedCount) {
      storage.resize(requestedCount, fillValue);
      return;
    }

    if (requestedCount < currentCount) {
      storage.resize(requestedCount);
    }
  }

  /**
   * Address: 0x00719820 (FUN_00719820)
   *
   * What it does:
   * Resizes one `vector<SThreat>` lane to `requestedCount` using a zeroed
   * default fill value.
   */
  [[maybe_unused]] std::size_t ResizeSThreatVectorWithZeroFill(
    SThreatVector& storage,
    const std::size_t requestedCount
  )
  {
    const moho::SThreat zeroFill{};
    ResizeSThreatVectorWithFill(storage, requestedCount, zeroFill);
    return storage.size();
  }

  /**
   * Address: 0x0071C6C0 (FUN_0071C6C0, sub_71C6C0)
   *
   * What it does:
   * Clones one `InfluenceGrid::entries` ordered-set tree into destination
   * storage, preserving ordered contents and node count.
   */
  void CopyInfluenceEntryTreeStorage(InfluenceEntrySet& destination, const InfluenceEntrySet& source)
  {
    if (&destination == &source) {
      return;
    }

    destination.clear();
    for (InfluenceEntrySet::const_iterator it = source.begin(); it != source.end(); ++it) {
      destination.insert(*it);
    }
  }

  /**
   * Address: 0x0071AA60 (FUN_0071AA60, sub_71AA60)
   *
   * What it does:
   * Rebuilds one `InfluenceGrid::entries` tree from a source grid by copying
   * each stored `InfluenceMapEntry` into the destination set.
   */
  void CopyInfluenceGridEntries(const moho::InfluenceGrid& source, moho::InfluenceGrid& destination)
  {
    if (&source == &destination) {
      return;
    }

    new (&destination.entries) decltype(destination.entries)();
    CopyInfluenceEntryTreeStorage(destination.entries, source.entries);
  }

  /**
   * Address: 0x007181A0 (FUN_007181A0, sub_7181A0)
   *
   * What it does:
   * Returns one lower-bound iterator in `grid.entries` for `entityId`.
   */
  [[maybe_unused]] [[nodiscard]] InfluenceEntryIterator FindInfluenceEntryLowerBoundByEntityId(
    moho::InfluenceGrid& grid,
    const std::uint32_t entityId
  )
  {
    moho::InfluenceMapEntry key{};
    key.entityId = entityId;
    return grid.entries.lower_bound(key);
  }

  /**
   * Address: 0x007186F0 (FUN_007186F0, sub_7186F0)
   *
   * What it does:
   * Finds the exact `InfluenceMapEntry` for one entity id using the ordered
   * set lookup lane.
   */
  template <class TEntries>
  [[nodiscard]] auto FindInfluenceMapEntry(TEntries& entries, const std::uint32_t entityId)
  {
    moho::InfluenceMapEntry key{};
    key.entityId = entityId;

    auto it = entries.lower_bound(key);
    if (it == entries.end() || it->entityId != entityId) {
      return entries.end();
    }

    return it;
  }

  /**
   * Address: 0x00719C00 (FUN_00719C00, sub_719C00)
   *
   * What it does:
   * Releases the entries tree for one `InfluenceGrid`.
   */
  void DestroyInfluenceGridEntries(moho::InfluenceGrid& grid) noexcept
  {
    ClearInfluenceGridEntryTree(grid.entries);
  }

  /**
   * Address: 0x00717EA0 (FUN_00717EA0)
   *
   * What it does:
   * Destroys one `InfluenceGrid::entries` tree payload, releases its legacy
   * set-header sentinel storage, and zeros `{head,size}` lanes.
   */
  [[maybe_unused]] int ReleaseInfluenceEntrySetStorage(moho::InfluenceGrid& grid) noexcept
  {
    ClearInfluenceGridEntryTree(grid.entries);

    auto& runtime = reinterpret_cast<LegacySetStorageRuntimeView<InfluenceEntrySet>&>(grid.entries);
    if (runtime.head != nullptr) {
      ::operator delete(runtime.head);
    }
    runtime.head = nullptr;
    runtime.size = 0u;
    return 0;
  }

  /**
   * Address: 0x007183D0 (FUN_007183D0)
   *
   * What it does:
   * Releases one `mBlipCells` set payload, deletes the legacy set-header
   * sentinel storage, and zeros `{head,size}` lanes.
   */
  [[maybe_unused]] int ReleaseBlipCellSetStorageLaneA(InfluenceMapCellSet& blipCells) noexcept
  {
    blipCells.clear();

    auto& runtime = reinterpret_cast<LegacySetStorageRuntimeView<InfluenceMapCellSet>&>(blipCells);
    if (runtime.head != nullptr) {
      ::operator delete(runtime.head);
    }
    runtime.head = nullptr;
    runtime.size = 0u;
    return 0;
  }

  /**
   * Address: 0x00719D50 (FUN_00719D50)
   *
   * What it does:
   * Duplicate release lane for one `mBlipCells` set payload: clears tree
   * nodes, frees set-header sentinel storage, and zeros `{head,size}`.
   */
  [[maybe_unused]] int ReleaseBlipCellSetStorageLaneB(InfluenceMapCellSet& blipCells) noexcept
  {
    return ReleaseBlipCellSetStorageLaneA(blipCells);
  }

  /**
   * Address: 0x0071C4A0 (FUN_0071C4A0, sub_71C4A0)
   *
   * What it does:
   * Initializes the legacy blip-cell set into the empty-tree state used by
   * the constructor lane.
   */
  void InitializeBlipCellSet(InfluenceMapCellSet& blipCells) noexcept
  {
    (void)EraseBlipCellRange(blipCells, blipCells.begin(), blipCells.end());
  }

  /**
   * Address: 0x00715C30 (FUN_00715C30, sub_715C30)
   *
   * What it does:
   * Releases the legacy blip-cell set from the destructor lane.
   */
  void ReleaseBlipCellSet(InfluenceMapCellSet& blipCells) noexcept
  {
    (void)EraseBlipCellRange(blipCells, blipCells.begin(), blipCells.end());
  }

  /**
   * Address: 0x00716110 (FUN_00716110)
   *
   * What it does:
   * Adapts one linear cell index into `(x, z)` and forwards to
   * `CInfluenceMap::GetThreatRect`.
   */
  [[maybe_unused]] float GetThreatRectByLinearCellIndex(
    const moho::CInfluenceMap* const influenceMap,
    const int linearIndex,
    const int radius,
    const bool onMap,
    const moho::EThreatType threatType,
    const int armyIndex
  )
  {
    const int x = linearIndex % influenceMap->mWidth;
    const int z = linearIndex / influenceMap->mWidth;
    return influenceMap->GetThreatRect(x, z, radius, onMap, threatType, armyIndex);
  }

  /**
   * Address: 0x007197D0 (FUN_007197D0)
   *
   * What it does:
   * Releases one influence-map runtime storage lane through global
   * `operator delete`.
   */
  [[maybe_unused]] void DeleteInfluenceMapRuntimeStoragePrimary(void* const storage) noexcept
  {
    ::operator delete(storage);
  }

  /**
   * Address: 0x00719D90 (FUN_00719D90)
   *
   * What it does:
   * Secondary delete-thunk lane for influence-map runtime storage.
   */
  [[maybe_unused]] void DeleteInfluenceMapRuntimeStorageSecondary(void* const storage) noexcept
  {
    ::operator delete(storage);
  }
} // namespace

/**
 * Address: 0x00718C70 (FUN_00718C70, gpg::RMapType_uint_int::GetName)
 *
 * What it does:
 * Lazily builds and caches the reflected type label `map<unsigned int,int>`.
 */
const char* gpg::RMapType_uint_int::GetName() const
{
  if ((gMapUintIntTypeNameInitGuard & 1u) == 0u) {
    gMapUintIntTypeNameInitGuard |= 1u;

    const gpg::RType* const keyType = CachedUIntType();
    const gpg::RType* const valueType = CachedIntType();
    const char* const valueTypeName = valueType ? valueType->GetName() : "int";
    const char* const keyTypeName = keyType ? keyType->GetName() : "unsigned int";
    gMapUintIntTypeName = gpg::STR_Printf("map<%s,%s>", keyTypeName, valueTypeName);
    (void)std::atexit(&cleanup_MapUintIntTypeName);
  }

  return gMapUintIntTypeName.c_str();
}

/**
 * Address: 0x00718D50 (FUN_00718D50, gpg::RMapType_uint_int::GetLexical)
 *
 * What it does:
 * Formats inherited map lexical text with current element count.
 */
msvc8::string gpg::RMapType_uint_int::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(CountLegacyMapElements(ref.mObj)));
}

/**
 * Address: 0x00718D30 (FUN_00718D30, gpg::RMapType_uint_int::Init)
 *
 * What it does:
 * Initializes map reflection metadata and binds typed archive callbacks.
 */
void gpg::RMapType_uint_int::Init()
{
  size_ = 0x0C;
  version_ = 1;
  serLoadFunc_ = &LoadUIntIntMap;
  serSaveFunc_ = &SaveUIntIntMap;
}

/**
 * Address: 0x00718FE0 (FUN_00718FE0, gpg::RMapType_uint_InfluenceMapEntry::GetName)
 *
 * What it does:
 * Lazily builds and caches the reflected type label
 * `map<unsigned int,InfluenceMapEntry>`.
 */
const char* gpg::RMapType_uint_InfluenceMapEntry::GetName() const
{
  if ((gMapUintInfluenceMapEntryTypeNameInitGuard & 1u) == 0u) {
    gMapUintInfluenceMapEntryTypeNameInitGuard |= 1u;

    const gpg::RType* const keyType = CachedUIntType();
    const gpg::RType* const valueType = CachedInfluenceMapEntryType();
    const char* const valueTypeName = valueType ? valueType->GetName() : "InfluenceMapEntry";
    const char* const keyTypeName = keyType ? keyType->GetName() : "unsigned int";
    gMapUintInfluenceMapEntryTypeName = gpg::STR_Printf("map<%s,%s>", keyTypeName, valueTypeName);
    (void)std::atexit(&cleanup_MapUintInfluenceMapEntryTypeName);
  }

  return gMapUintInfluenceMapEntryTypeName.c_str();
}

/**
 * Address: 0x007190C0 (FUN_007190C0, gpg::RMapType_uint_InfluenceMapEntry::GetLexical)
 *
 * What it does:
 * Formats inherited map lexical text with current element count.
 */
msvc8::string gpg::RMapType_uint_InfluenceMapEntry::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(CountLegacyMapElements(ref.mObj)));
}

/**
 * Address: 0x007190A0 (FUN_007190A0, gpg::RMapType_uint_InfluenceMapEntry::Init)
 *
 * What it does:
 * Initializes map reflection metadata and binds typed archive callbacks.
 */
void gpg::RMapType_uint_InfluenceMapEntry::Init()
{
  size_ = 0x0C;
  version_ = 1;
  serLoadFunc_ = &LoadUIntInfluenceMapEntryMap;
  serSaveFunc_ = &SaveUIntInfluenceMapEntryMap;
}

/**
 * Address: 0x0071D980 (FUN_0071D980, preregister_RMapType_uint_int)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `std::map<std::uint32_t,int>`.
 */
[[nodiscard]] gpg::RType* preregister_RMapType_uint_int()
{
  static gpg::RMapType_uint_int typeInfo;
  gpg::PreRegisterRType(typeid(UIntIntMap), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x0071DA50 (FUN_0071DA50, preregister_RMapType_uint_InfluenceMapEntry)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for
 * `std::map<std::uint32_t,moho::InfluenceMapEntry>`.
 */
[[nodiscard]] gpg::RType* preregister_RMapType_uint_InfluenceMapEntry()
{
  static gpg::RMapType_uint_InfluenceMapEntry typeInfo;
  gpg::PreRegisterRType(typeid(UIntInfluenceMapEntryMap), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x00718DE0 (FUN_00718DE0, gpg::RVectorType_InfluenceGrid::GetName)
 *
 * What it does:
 * Lazily builds and caches the reflected lexical type label
 * `vector<InfluenceGrid>` from runtime RTTI metadata.
 */
const char* gpg::RVectorType_InfluenceGrid::GetName() const
{
  if ((gInfluenceGridVectorTypeNameInitGuard & 1u) == 0u) {
    gInfluenceGridVectorTypeNameInitGuard |= 1u;

    gpg::RType* const valueType = CachedInfluenceGridType();
    const char* const valueTypeName = valueType ? valueType->GetName() : "InfluenceGrid";
    gInfluenceGridVectorTypeName = gpg::STR_Printf("vector<%s>", valueTypeName ? valueTypeName : "InfluenceGrid");
    (void)std::atexit(&cleanup_InfluenceGridVectorTypeName);
  }

  return gInfluenceGridVectorTypeName.c_str();
}

/**
 * Address: 0x00718EA0 (FUN_00718EA0, gpg::RVectorType_InfluenceGrid::GetLexical)
 *
 * What it does:
 * Formats inherited vector lexical text with current `InfluenceGrid` count.
 */
msvc8::string gpg::RVectorType_InfluenceGrid::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf(
    "%s, size=%d",
    base.c_str(),
    static_cast<int>(CountLegacyVectorElements<moho::InfluenceGrid>(ref.mObj))
  );
}

void gpg::RVectorType_InfluenceGrid::Init()
{
  size_ = 0x0C;
  version_ = 1;
  serLoadFunc_ = &LoadInfluenceGridVectorArchive;
  serSaveFunc_ = &SaveInfluenceGridVectorArchive;
}

/**
 * Address: 0x00719150 (FUN_00719150, gpg::RVectorType_SThreat::GetName)
 *
 * What it does:
 * Lazily builds and caches the reflected lexical type label
 * `vector<SThreat>` from runtime RTTI metadata.
 */
const char* gpg::RVectorType_SThreat::GetName() const
{
  if ((gSThreatVectorTypeNameInitGuard & 1u) == 0u) {
    gSThreatVectorTypeNameInitGuard |= 1u;

    gpg::RType* const valueType = CachedSThreatType();
    const char* const valueTypeName = valueType ? valueType->GetName() : "SThreat";
    gSThreatVectorTypeName = gpg::STR_Printf("vector<%s>", valueTypeName ? valueTypeName : "SThreat");
    (void)std::atexit(&cleanup_SThreatVectorTypeName);
  }

  return gSThreatVectorTypeName.c_str();
}

/**
 * Address: 0x00719210 (FUN_00719210, gpg::RVectorType_SThreat::GetLexical)
 *
 * What it does:
 * Formats inherited vector lexical text with current `SThreat` count.
 */
msvc8::string gpg::RVectorType_SThreat::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(CountLegacyVectorElements<moho::SThreat>(ref.mObj)));
}

void gpg::RVectorType_SThreat::Init()
{
  size_ = 0x0C;
  version_ = 1;
  serSaveFunc_ = &SaveSThreatVectorArchive;
}

namespace moho
{
  gpg::RType* SThreat::sType = nullptr;
  gpg::RType* InfluenceMapEntry::sType = nullptr;
  gpg::RType* InfluenceGrid::sType = nullptr;
  gpg::RType* CInfluenceMap::sType = nullptr;

  gpg::RType* SThreat::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SThreat));
    }
    return sType;
  }

  gpg::RType* InfluenceMapEntry::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(InfluenceMapEntry));
    }
    return sType;
  }

  gpg::RType* InfluenceGrid::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(InfluenceGrid));
    }
    return sType;
  }

  gpg::RType* CInfluenceMap::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CInfluenceMap));
    }
    return sType;
  }

  /**
   * Address: 0x00BDA3E0 (FUN_00BDA3E0, register_imap_debug_ConAliasDef)
   */
  void register_imap_debug_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_imap_debug().InitializeRecovered(
      "Toggle influence map debug info.",
      "imap_debug",
      "DoSimCommand imap_debug"
    );
  }

  /**
   * Address: 0x00BDA410 (FUN_00BDA410, register_imap_debug_SimConVarDef)
   */
  void register_imap_debug_SimConVarDef()
  {
    (void)SimConVar_imap_debug();
  }

  /**
   * Address: 0x00BDA460 (FUN_00BDA460, register_imap_debug_grid_ConAliasDef)
   */
  void register_imap_debug_grid_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_imap_debug_grid().InitializeRecovered(
      "Toggle influence map debug grid info.",
      "imap_debug_grid",
      "DoSimCommand imap_debug_grid"
    );
  }

  /**
   * Address: 0x00BDA490 (FUN_00BDA490, func_imap_debug_grid_SimConVarDef)
   */
  void func_imap_debug_grid_SimConVarDef()
  {
    (void)SimConVar_imap_debug_grid();
  }

  /**
   * Address: 0x00BDA4E0 (FUN_00BDA4E0, register_imap_debug_path_graph_ConAliasDef)
   */
  void register_imap_debug_path_graph_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_imap_debug_path_graph().InitializeRecovered(
      "Toggle map hints path graph.",
      "imap_debug_path_graph",
      "DoSimCommand imap_debug_path_graph"
    );
  }

  /**
   * Address: 0x00BDA510 (FUN_00BDA510, func_imap_debug_path_graph_SimConVarDef)
   */
  void func_imap_debug_path_graph_SimConVarDef()
  {
    (void)SimConVar_imap_debug_path_graph();
  }

  /**
   * Address: 0x00BDA560 (FUN_00BDA560, register_imap_debug_grid_type_ConAliasDef)
   */
  void register_imap_debug_grid_type_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_imap_debug_grid_type().InitializeRecovered(
      "Set influence map debug grid threat type.",
      "imap_debug_grid_type",
      "DoSimCommand imap_debug_grid_type"
    );
  }

  /**
   * Address: 0x00BDA590 (FUN_00BDA590, func_imap_debug_grid_type_SimConVarDef)
   */
  void func_imap_debug_grid_type_SimConVarDef()
  {
    (void)SimConVar_imap_debug_grid_type();
  }

  /**
   * Address: 0x00BDA5E0 (FUN_00BDA5E0, register_imap_debug_grid_army_ConAliasDef)
   */
  void register_imap_debug_grid_army_ConAliasDef()
  {
    static bool sInitialized = false;
    if (sInitialized) {
      return;
    }

    sInitialized = true;
    ConAlias_imap_debug_grid_army().InitializeRecovered(
      "Set influence map debug grid for which army threat type.",
      "imap_debug_grid_army",
      "DoSimCommand imap_debug_grid_army"
    );
  }

  /**
   * Address: 0x00BDA610 (FUN_00BDA610, func_imap_debug_grid_army_SimConVarDef)
   */
  void func_imap_debug_grid_army_SimConVarDef()
  {
    (void)SimConVar_imap_debug_grid_army();
  }

  void SThreat::Clear() noexcept
  {
    overallInfluence = 0.0f;
    influenceStructuresNotMex = 0.0f;
    influenceStructures = 0.0f;
    navalInfluence = 0.0f;
    airInfluence = 0.0f;
    landInfluence = 0.0f;
    experimentalInfluence = 0.0f;
    commanderInfluence = 0.0f;
    artilleryInfluence = 0.0f;
    antiAirInfluence = 0.0f;
    antiSurfaceInfluence = 0.0f;
    antiSubInfluence = 0.0f;
    economyInfluence = 0.0f;
    unknownInfluence = 0.0f;
  }

  void SThreat::RecomputeOverall() noexcept
  {
    overallInfluence = antiSurfaceInfluence + experimentalInfluence + influenceStructures + antiSubInfluence
      + commanderInfluence + navalInfluence + economyInfluence + artilleryInfluence + airInfluence + unknownInfluence
      + antiAirInfluence + landInfluence + influenceStructuresNotMex;
  }

  void SThreat::DecayBy(const SThreat& decayRate) noexcept
  {
    influenceStructuresNotMex = DecayThreatLane(influenceStructuresNotMex, decayRate.influenceStructuresNotMex);
    influenceStructures = DecayThreatLane(influenceStructures, decayRate.influenceStructures);
    navalInfluence = DecayThreatLane(navalInfluence, decayRate.navalInfluence);
    airInfluence = DecayThreatLane(airInfluence, decayRate.airInfluence);
    landInfluence = DecayThreatLane(landInfluence, decayRate.landInfluence);
    experimentalInfluence = DecayThreatLane(experimentalInfluence, decayRate.experimentalInfluence);
    commanderInfluence = DecayThreatLane(commanderInfluence, decayRate.commanderInfluence);
    artilleryInfluence = DecayThreatLane(artilleryInfluence, decayRate.artilleryInfluence);
    antiAirInfluence = DecayThreatLane(antiAirInfluence, decayRate.antiAirInfluence);
    antiSurfaceInfluence = DecayThreatLane(antiSurfaceInfluence, decayRate.antiSurfaceInfluence);
    antiSubInfluence = DecayThreatLane(antiSubInfluence, decayRate.antiSubInfluence);
    economyInfluence = DecayThreatLane(economyInfluence, decayRate.economyInfluence);
    unknownInfluence = DecayThreatLane(unknownInfluence, decayRate.unknownInfluence);
    RecomputeOverall();
  }

  [[nodiscard]] float SThreat::ValueByType(const EThreatType threatType) const noexcept
  {
    switch (threatType) {
      case THREATTYPE_Overall:
      case THREATTYPE_OverallNotAssigned:
        return overallInfluence;
      case THREATTYPE_StructuresNotMex:
        return influenceStructuresNotMex;
      case THREATTYPE_Structures:
        return influenceStructures;
      case THREATTYPE_Naval:
        return navalInfluence;
      case THREATTYPE_Air:
        return airInfluence;
      case THREATTYPE_Land:
        return landInfluence;
      case THREATTYPE_Experimental:
        return experimentalInfluence;
      case THREATTYPE_Commander:
        return commanderInfluence;
      case THREATTYPE_Artillery:
        return artilleryInfluence;
      case THREATTYPE_AntiAir:
        return antiAirInfluence;
      case THREATTYPE_AntiSurface:
        return antiSurfaceInfluence;
      case THREATTYPE_AntiSub:
        return antiSubInfluence;
      case THREATTYPE_Economy:
        return economyInfluence;
      case THREATTYPE_Unknown:
      default:
        return unknownInfluence;
    }
  }

  /**
   * Address: 0x0071E760 (FUN_0071E760, func_VectorCpy_SThreat)
   *
   * What it does:
   * Copies one `SThreat` source value into `count` consecutive destination
   * slots while preserving the original helper's per-iteration null check on
   * the destination address.
   */
  void CopySThreatValueRange(SThreat* destination, std::uint32_t count, const SThreat* const source) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    while (count != 0u) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<SThreat*>(destinationAddress) = *source;
      }
      --count;
      destinationAddress += sizeof(SThreat);
    }
  }

  /**
   * Address: 0x0071F6A0 (FUN_0071F6A0, func_VectorMemCpy_SThreat)
   * Address: 0x0071EC00 (FUN_0071EC00)
   *
   * What it does:
   * Copies one contiguous `SThreat` source range `[sourceBegin, sourceEnd)`
   * into destination storage and returns one-past the last destination slot,
   * preserving the helper's original per-iteration null-destination guard.
   */
  SThreat* CopySThreatRangeNullable(
    SThreat* destination,
    const SThreat* const sourceBegin,
    const SThreat* const sourceEnd
  ) noexcept
  {
    const SThreat* source = sourceBegin;
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    while (source != sourceEnd) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<SThreat*>(destinationAddress) = *source;
      }

      ++source;
      destinationAddress += sizeof(SThreat);
    }

    return reinterpret_cast<SThreat*>(destinationAddress);
  }

  /**
   * Address: 0x007199C0 (FUN_007199C0)
   *
   * What it does:
   * Adapts one repeated-threat copy lane into `CopySThreatValueRange` and
   * returns one-past the last written destination slot.
   */
  [[maybe_unused]] SThreat* CopySThreatValueRangeAndReturnEnd(
    const SThreat* const source,
    SThreat* const destination,
    const std::uint32_t count
  ) noexcept
  {
    CopySThreatValueRange(destination, count, source);
    return destination + count;
  }

  /**
   * Address: 0x0071D180 (FUN_0071D180)
   *
   * What it does:
   * Adapts one register-lane caller shape into the canonical repeated-value
   * threat copy helper.
   */
  [[maybe_unused]] SThreat* CopySThreatValueRangeRegisterAdapter(
    const std::uint32_t count,
    const SThreat* const sourceValue,
    SThreat* const destination
  ) noexcept
  {
    return CopySThreatValueRangeAndReturnEnd(sourceValue, destination, count);
  }

  /**
   * Address: 0x00720140 (FUN_00720140)
   * Address: 0x0071E910 (FUN_0071E910)
   * Address: 0x0071F4E0 (FUN_0071F4E0)
   * Address: 0x0071FBE0 (FUN_0071FBE0)
   *
   * What it does:
   * Copies one contiguous `SThreat` source range `[sourceBegin, sourceEnd)`
   * into destination storage and returns one-past the last destination slot.
   */
  [[maybe_unused]] SThreat* CopySThreatRangeRawNullable(
    SThreat* destination,
    const SThreat* const sourceBegin,
    const SThreat* const sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    for (const SThreat* source = sourceBegin; source != sourceEnd; ++source) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<SThreat*>(destinationAddress) = *source;
      }
      destinationAddress += sizeof(SThreat);
    }

    return reinterpret_cast<SThreat*>(destinationAddress);
  }

  /**
   * Address: 0x0071D410 (FUN_0071D410)
   *
   * What it does:
   * Thin call-shape adapter into `CopySThreatRangeRawNullable`.
   */
  [[maybe_unused]] SThreat* CopySThreatRangeRawNullableAdapter(
    SThreat* const destination,
    const SThreat* const sourceBegin,
    const SThreat* const sourceEnd
  ) noexcept
  {
    return CopySThreatRangeRawNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0071D6D0 (FUN_0071D6D0)
   *
   * What it does:
   * Thin stdcall adapter into `CopySThreatRangeNullable`.
   */
  [[maybe_unused]] SThreat* CopySThreatRangeNullableStdcallAdapter(
    SThreat* const destination,
    const SThreat* const sourceBegin,
    const SThreat* const sourceEnd
  ) noexcept
  {
    return CopySThreatRangeNullable(destination, sourceBegin, sourceEnd);
  }

  struct SThreatMoveOwnerRuntime
  {
    SThreat* activeEnd;            // +0x00
    SThreat* moveDestinationBegin; // +0x04
    SThreat* moveSourceBegin;      // +0x08
  };
  static_assert(sizeof(SThreatMoveOwnerRuntime) == 0x0C, "SThreatMoveOwnerRuntime size must be 0x0C");

  /**
   * Address: 0x0071E1C0 (FUN_0071E1C0)
   *
   * What it does:
   * Moves one tail `[moveSourceBegin,activeEnd)` `SThreat` range down to
   * `moveDestinationBegin` and updates owner end to the compacted tail.
   */
  [[maybe_unused]] SThreat* MoveSThreatTailRangeAndUpdateOwnerEnd(SThreatMoveOwnerRuntime& owner) noexcept
  {
    SThreat* destination = owner.moveDestinationBegin;
    SThreat* source = owner.moveSourceBegin;
    if (destination != source) {
      while (source != owner.activeEnd) {
        *destination = *source;
        ++destination;
        ++source;
      }
      owner.activeEnd = destination;
    }

    return owner.moveDestinationBegin;
  }

  /**
   * Address: 0x0071CD70 (FUN_0071CD70)
   *
   * What it does:
   * Serializes the 14 contiguous `float` lanes of one `SThreat` record.
   */
  [[maybe_unused]] void SerializeSThreatFloatLanesRaw(gpg::WriteArchive* const archive, const SThreat* const threat)
  {
    if (archive == nullptr || threat == nullptr) {
      return;
    }

    const float* const lanes = reinterpret_cast<const float*>(threat);
    for (std::size_t i = 0u; i < 14u; ++i) {
      archive->WriteFloat(lanes[i]);
    }
  }

  /**
   * Address: 0x0071CE40 (FUN_0071CE40)
   *
   * What it does:
   * Serializes one `SThreat` record in named field order.
   */
  [[maybe_unused]] void SerializeSThreatFields(gpg::WriteArchive* const archive, const SThreat& threat)
  {
    if (archive == nullptr) {
      return;
    }

    archive->WriteFloat(threat.overallInfluence);
    archive->WriteFloat(threat.influenceStructuresNotMex);
    archive->WriteFloat(threat.influenceStructures);
    archive->WriteFloat(threat.navalInfluence);
    archive->WriteFloat(threat.airInfluence);
    archive->WriteFloat(threat.landInfluence);
    archive->WriteFloat(threat.experimentalInfluence);
    archive->WriteFloat(threat.commanderInfluence);
    archive->WriteFloat(threat.artilleryInfluence);
    archive->WriteFloat(threat.antiAirInfluence);
    archive->WriteFloat(threat.antiSurfaceInfluence);
    archive->WriteFloat(threat.antiSubInfluence);
    archive->WriteFloat(threat.economyInfluence);
    archive->WriteFloat(threat.unknownInfluence);
  }

  /**
   * Address: 0x0071D470 (FUN_0071D470)
   *
   * What it does:
   * Fills one `[destinationBegin, destinationEnd)` threat range from one
   * source record.
   */
  [[maybe_unused]] SThreat* FillSThreatRange(
    SThreat* destinationBegin,
    SThreat* const destinationEnd,
    const SThreat& source
  ) noexcept
  {
    while (destinationBegin != destinationEnd) {
      *destinationBegin = source;
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0071D490 (FUN_0071D490)
   *
   * What it does:
   * Copies one threat range backward into destination storage.
   */
  [[maybe_unused]] SThreat* CopySThreatRangeBackward(
    SThreat* destinationEnd,
    const SThreat* const sourceBegin,
    const SThreat* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

  struct Float4LaneRuntime
  {
    float x;
    float y;
    float z;
    float w;
  };
  static_assert(sizeof(Float4LaneRuntime) == 0x10, "Float4LaneRuntime size must be 0x10");

  /**
   * Address: 0x0071D660 (FUN_0071D660)
   *
   * What it does:
   * Fills one `[destinationBegin, destinationEnd)` 16-byte lane range from one
   * source lane.
   */
  [[maybe_unused]] Float4LaneRuntime* FillFloat4LaneRange(
    Float4LaneRuntime* destinationBegin,
    Float4LaneRuntime* const destinationEnd,
    const Float4LaneRuntime& source
  ) noexcept
  {
    while (destinationBegin != destinationEnd) {
      *destinationBegin = source;
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0071EBC0 (FUN_0071EBC0)
   *
   * What it does:
   * Copies one 16-byte lane range backward into destination storage.
   */
  [[maybe_unused]] Float4LaneRuntime* CopyFloat4LaneRangeBackward(
    Float4LaneRuntime* destinationEnd,
    const Float4LaneRuntime* const sourceBegin,
    const Float4LaneRuntime* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0071D200 (FUN_0071D200)
   *
   * What it does:
   * Copies `count` contiguous float4 lanes from one fixed source lane into
   * destination storage and returns one-past-end destination.
   */
  [[maybe_unused]] float* CopyFloatQuadCountLaneAdapter(
    float* destination,
    const float* const sourceQuad,
    const std::uint32_t count
  ) noexcept
  {
    const auto* const sourceLane = reinterpret_cast<const Float4LaneRuntime*>(sourceQuad);
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    for (std::uint32_t i = 0u; i < count; ++i) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<Float4LaneRuntime*>(destinationAddress) = *sourceLane;
      }
      destinationAddress += sizeof(Float4LaneRuntime);
    }

    return reinterpret_cast<float*>(destinationAddress);
  }

  [[maybe_unused]] void SwapFloat4LaneValues(Float4LaneRuntime& left, Float4LaneRuntime& right) noexcept
  {
    std::swap(left, right);
  }

  [[nodiscard]] std::int32_t RotateFloat4LaneRangeByMiddle(
    Float4LaneRuntime* const first,
    Float4LaneRuntime* const middle,
    Float4LaneRuntime* const last
  ) noexcept
  {
    if (first == nullptr || middle == nullptr || last == nullptr || first >= middle || middle >= last) {
      return 0;
    }

    std::rotate(first, middle, last);
    return 0;
  }

  [[maybe_unused]] Float4LaneRuntime* SortThreeFloat4ByLane3DescendingLocal(
    Float4LaneRuntime* const lane0,
    Float4LaneRuntime* const lane1,
    Float4LaneRuntime* const lane2
  ) noexcept
  {
    if (lane1->w > lane0->w) {
      SwapFloat4LaneValues(*lane0, *lane1);
    }
    if (lane2->w > lane1->w) {
      SwapFloat4LaneValues(*lane1, *lane2);
    }
    if (lane1->w > lane0->w) {
      SwapFloat4LaneValues(*lane0, *lane1);
    }
    return lane1;
  }

  /**
   * Address: 0x0071F870 (FUN_0071F870)
   *
   * What it does:
   * Selects pivot samples for one float4 range: for large spans it runs the
   * 4-step median-of-three sampling schedule, otherwise it sorts the direct
   * `(first, middle, last)` trio.
   */
  [[maybe_unused]] Float4LaneRuntime* SelectPivotSamplesForFloat4Sort(
    Float4LaneRuntime* const first,
    Float4LaneRuntime* const middle,
    Float4LaneRuntime* const last,
    const std::int32_t finalizeLane
  ) noexcept
  {
    (void)finalizeLane;

    const std::int32_t laneSpan = static_cast<std::int32_t>(last - first);
    if (laneSpan <= 40) {
      return SortThreeFloat4ByLane3DescendingLocal(first, middle, last);
    }

    const std::int32_t sampleStride = (laneSpan + 1) / 8;
    const std::int32_t sampleStride2 = sampleStride * 2;

    Float4LaneRuntime* const sampleFirst = first + sampleStride;
    Float4LaneRuntime* const sampleSecond = first + sampleStride2;
    (void)SortThreeFloat4ByLane3DescendingLocal(first, sampleFirst, sampleSecond);
    (void)SortThreeFloat4ByLane3DescendingLocal(middle - sampleStride, middle, middle + sampleStride);
    (void)SortThreeFloat4ByLane3DescendingLocal(last - sampleStride2, last - sampleStride, last);
    return SortThreeFloat4ByLane3DescendingLocal(sampleFirst, middle, last - sampleStride);
  }

  /**
   * Address: 0x0071F2C0 (FUN_0071F2C0)
   *
   * What it does:
   * Performs the short-range float4 insertion-sort lane used by the
   * threat-sample sorter, rotating contiguous lane blocks to insert each
   * element into descending `w` order.
   */
  [[maybe_unused]] void InsertionSortFloat4LaneRangeByDescendingW(
    Float4LaneRuntime* const begin,
    Float4LaneRuntime* const end
  ) noexcept
  {
    if (begin == end) {
      return;
    }

    for (Float4LaneRuntime* cursor = begin + 1; cursor != end; ++cursor) {
      const float pivotW = cursor->w;
      if (pivotW <= begin->w) {
        Float4LaneRuntime* insertPos = cursor;
        for (Float4LaneRuntime* scan = cursor;; insertPos = scan) {
          --scan;
          if (pivotW <= scan->w) {
            break;
          }
        }

        if (insertPos != cursor) {
          (void)RotateFloat4LaneRangeByMiddle(insertPos, cursor, cursor + 1);
        }
      } else if (begin != cursor) {
        (void)RotateFloat4LaneRangeByMiddle(begin, cursor, cursor + 1);
      }
    }
  }

  /**
   * Address: 0x0071EFA0 (FUN_0071EFA0)
   *
   * What it does:
   * Partitions one float4 lane range around a sampled pivot and writes the
   * resulting two partition cursors into `outBounds[0..1]`.
   */
  [[maybe_unused]] Float4LaneRuntime** PartitionFloat4LaneRangeAroundPivot(
    Float4LaneRuntime** const outBounds,
    Float4LaneRuntime* const begin,
    Float4LaneRuntime* const end,
    const std::int32_t finalizeLane
  ) noexcept
  {
    Float4LaneRuntime* rangeEnd = end;
    Float4LaneRuntime* pivot = begin + ((end - begin) / 2);
    (void)SelectPivotSamplesForFloat4Sort(begin, pivot, end - 1, finalizeLane);

    Float4LaneRuntime* equalRight = pivot + 1;
    while (begin < pivot) {
      const float leftW = (pivot - 1)->w;
      const float pivotW = pivot->w;
      if (leftW > pivotW) {
        break;
      }
      if (pivotW > leftW) {
        break;
      }
      --pivot;
    }

    if (equalRight < end) {
      const float pivotW = pivot->w;
      do {
        const float rightW = equalRight->w;
        if (rightW > pivotW) {
          break;
        }
        if (pivotW > rightW) {
          break;
        }
        ++equalRight;
      } while (equalRight < end);
    }

    Float4LaneRuntime* right = equalRight;
    Float4LaneRuntime* left = pivot;
    while (true) {
      while (true) {
        for (; right < rangeEnd; ++right) {
          const float pivotW = pivot->w;
          const float rightW = right->w;
          if (pivotW <= rightW) {
            if (rightW > pivotW) {
              break;
            }
            SwapFloat4LaneValues(*equalRight, *right);
            ++equalRight;
          }
        }

        bool atBegin = (left == begin);
        if (left > begin) {
          Float4LaneRuntime* probe = left - 1;
          do {
            const float probeW = probe->w;
            const float pivotW = pivot->w;
            if (probeW <= pivotW) {
              if (pivotW > probeW) {
                break;
              }
              SwapFloat4LaneValues(*(pivot - 1), *probe);
              --pivot;
            }
            --left;
            --probe;
          } while (begin < left);
          atBegin = (left == begin);
        }

        if (atBegin) {
          break;
        }

        --left;
        if (right == rangeEnd) {
          --pivot;
          if (left != pivot) {
            SwapFloat4LaneValues(*left, *pivot);
          }
          SwapFloat4LaneValues(*pivot, *(equalRight - 1));
          --equalRight;
        } else {
          SwapFloat4LaneValues(*right, *left);
          ++right;
        }
      }

      if (right == rangeEnd) {
        break;
      }

      if (equalRight != right) {
        SwapFloat4LaneValues(*pivot, *equalRight);
      }
      SwapFloat4LaneValues(*pivot, *right);
      ++equalRight;
      ++right;
      ++pivot;
      rangeEnd = end;
    }

    outBounds[1] = equalRight;
    outBounds[0] = pivot;
    return outBounds;
  }

  [[nodiscard]] std::int32_t BuildFloat4MinHeapRangeFromMiddle(
    Float4LaneRuntime* const rangeBegin,
    Float4LaneRuntime* const rangeEnd,
    const std::int32_t finalizeLane
  ) noexcept;

  [[nodiscard]] std::int32_t PopFloat4MinHeapToTailUntilSingle(
    Float4LaneRuntime* const rangeBegin,
    Float4LaneRuntime* const rangeEnd,
    const std::int32_t finalizeLane
  ) noexcept;

  /**
   * Address: 0x0071E200 (FUN_0071E200)
   *
   * What it does:
   * Drives one recursive/introspective float4 sort lane: pivot-partitions while
   * deep budget remains, otherwise falls back to heapify+tail-pop, and uses
   * insertion sort for short spans.
   */
  [[maybe_unused]] std::int32_t SortFloat4LaneRangeDispatcher(
    Float4LaneRuntime* begin,
    Float4LaneRuntime* end,
    std::int32_t depthBudget,
    const std::int32_t finalizeLane
  ) noexcept
  {
    std::int32_t laneCount = static_cast<std::int32_t>(end - begin);
    if (laneCount > 32) {
      while (depthBudget > 0) {
        Float4LaneRuntime* bounds[2]{};
        (void)PartitionFloat4LaneRangeAroundPivot(bounds, begin, end, finalizeLane);
        Float4LaneRuntime* const leftEnd = bounds[0];
        Float4LaneRuntime* const rightBegin = bounds[1];

        const std::int32_t half = depthBudget / 2;
        depthBudget = (half / 2) + half;

        const std::intptr_t leftBytes = (reinterpret_cast<const std::byte*>(leftEnd) - reinterpret_cast<const std::byte*>(begin))
          & ~static_cast<std::intptr_t>(0x0F);
        const std::intptr_t rightBytes = (reinterpret_cast<const std::byte*>(end) - reinterpret_cast<const std::byte*>(rightBegin))
          & ~static_cast<std::intptr_t>(0x0F);

        if (leftBytes >= rightBytes) {
          (void)SortFloat4LaneRangeDispatcher(rightBegin, end, depthBudget, finalizeLane);
          end = leftEnd;
        } else {
          (void)SortFloat4LaneRangeDispatcher(begin, leftEnd, depthBudget, finalizeLane);
          begin = rightBegin;
        }

        laneCount = static_cast<std::int32_t>(end - begin);
        if (laneCount <= 32) {
          break;
        }
      }

      if (laneCount > 32) {
        const std::intptr_t alignedBytes = (reinterpret_cast<const std::byte*>(end) - reinterpret_cast<const std::byte*>(begin))
          & ~static_cast<std::intptr_t>(0x0F);
        if (alignedBytes > 0x10) {
          (void)BuildFloat4MinHeapRangeFromMiddle(begin, end, finalizeLane);
        }
        return PopFloat4MinHeapToTailUntilSingle(begin, end, finalizeLane);
      }
    }

    if (laneCount > 1) {
      InsertionSortFloat4LaneRangeByDescendingW(begin, end);
    }
    return laneCount;
  }

  /**
   * Address: 0x0071CA80 (FUN_0071CA80)
   *
   * What it does:
   * Computes one float4 lane-count budget from `[begin, end)` span and forwards
   * to the canonical sort dispatcher.
   */
  [[maybe_unused]] std::int32_t SortFloat4LaneRangeDispatcherWithSpanBudget(
    Float4LaneRuntime* const begin,
    Float4LaneRuntime* const end,
    const std::int32_t finalizeLane
  ) noexcept
  {
    const std::int32_t depthBudget = static_cast<std::int32_t>(end - begin);
    return SortFloat4LaneRangeDispatcher(begin, end, depthBudget, finalizeLane);
  }

  [[nodiscard]] std::int32_t InsertFloat4HeapEntryByPromotingParents(
    Float4LaneRuntime* const heapBase,
    std::int32_t insertionIndex,
    const std::int32_t lowerBoundIndex,
    const Float4LaneRuntime& lane
  ) noexcept
  {
    std::int32_t parentIndex = (insertionIndex - 1) / 2;
    while (lowerBoundIndex < insertionIndex) {
      const Float4LaneRuntime& parent = heapBase[parentIndex];
      if (parent.w <= lane.w) {
        break;
      }

      heapBase[insertionIndex] = parent;
      insertionIndex = parentIndex;
      parentIndex = (parentIndex - 1) / 2;
    }

    heapBase[insertionIndex] = lane;
    return parentIndex;
  }

  [[nodiscard]] std::int32_t SiftDownFloat4HeapAndInsertEntry(
    std::int32_t heapIndex,
    const std::int32_t heapLast,
    Float4LaneRuntime* const heapBase,
    const Float4LaneRuntime& lane
  ) noexcept
  {
    const std::int32_t lowerBoundIndex = heapIndex;
    std::int32_t childIndex = (heapIndex * 2) + 2;
    while (childIndex < heapLast) {
      if (heapBase[childIndex].w > heapBase[childIndex - 1].w) {
        --childIndex;
      }

      heapBase[heapIndex] = heapBase[childIndex];
      heapIndex = childIndex;
      childIndex = (childIndex * 2) + 2;
    }

    if (childIndex == heapLast) {
      heapBase[heapIndex] = heapBase[heapLast - 1];
      heapIndex = heapLast - 1;
    }

    return InsertFloat4HeapEntryByPromotingParents(heapBase, heapIndex, lowerBoundIndex, lane);
  }

  using Float4HeapFinalizeFn = std::int32_t(__cdecl*)(Float4LaneRuntime*, float, float, float, float);

  [[nodiscard]] std::int32_t SiftDownFloat4HeapAndFinalize(
    std::int32_t heapIndex,
    const std::int32_t heapLast,
    Float4LaneRuntime* const heapBase,
    const Float4LaneRuntime& lane,
    const Float4HeapFinalizeFn finalizeFn
  ) noexcept
  {
    if (heapBase == nullptr) {
      return finalizeFn != nullptr ? finalizeFn(heapBase, lane.x, lane.y, lane.z, lane.w) : 0;
    }

    std::int32_t childIndex = (heapIndex * 2) + 2;
    while (childIndex < heapLast) {
      if (heapBase[childIndex].w > heapBase[childIndex - 1].w) {
        --childIndex;
      }

      heapBase[heapIndex] = heapBase[childIndex];
      heapIndex = childIndex;
      childIndex = (childIndex * 2) + 2;
    }

    if (childIndex == heapLast) {
      heapBase[heapIndex] = heapBase[heapLast - 1];
    }

    return finalizeFn != nullptr ? finalizeFn(heapBase, lane.x, lane.y, lane.z, lane.w) : 0;
  }

  /**
   * Address: 0x0071F990 (FUN_0071F990)
   *
   * What it does:
   * Heapifies one contiguous float4 lane range by iterating internal-parent
   * lanes from middle to front and invoking the caller finalize callback.
   */
  [[nodiscard]] std::int32_t BuildFloat4MinHeapRangeFromMiddle(
    Float4LaneRuntime* const rangeBegin,
    Float4LaneRuntime* const rangeEnd,
    const std::int32_t finalizeLane
  ) noexcept
  {
    const std::int32_t elementCount = static_cast<std::int32_t>(rangeEnd - rangeBegin);
    std::int32_t heapIndex = elementCount / 2;
    std::int32_t result = elementCount;
    const auto finalizeFn = reinterpret_cast<Float4HeapFinalizeFn>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(finalizeLane))
    );
    while (heapIndex > 0) {
      --heapIndex;
      const Float4LaneRuntime lane = rangeBegin[heapIndex];
      result = SiftDownFloat4HeapAndFinalize(heapIndex, elementCount, rangeBegin, lane, finalizeFn);
    }

    return result;
  }

  /**
   * Address: 0x0071FA00 (FUN_0071FA00)
   *
   * What it does:
   * Repeatedly swaps one heap root with tail lanes and re-sifts the root using
   * the caller finalize callback until one element remains.
   */
  [[nodiscard]] std::int32_t PopFloat4MinHeapToTailUntilSingle(
    Float4LaneRuntime* const rangeBegin,
    Float4LaneRuntime* const rangeEnd,
    const std::int32_t finalizeLane
  ) noexcept
  {
    std::int32_t result = static_cast<std::int32_t>(rangeEnd - rangeBegin);
    if (result <= 1) {
      return result;
    }

    const auto finalizeFn = reinterpret_cast<Float4HeapFinalizeFn>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(finalizeLane))
    );

    Float4LaneRuntime* tail = rangeEnd - 1;
    do {
      const Float4LaneRuntime replacementLane = *tail;
      *tail = *rangeBegin;

      const std::int32_t heapLast = static_cast<std::int32_t>(tail - rangeBegin);
      (void)SiftDownFloat4HeapAndFinalize(0, heapLast, rangeBegin, replacementLane, finalizeFn);

      --tail;
      result = static_cast<std::int32_t>((tail + 1) - rangeBegin);
    } while (result > 1);

    return result;
  }

  /**
   * Address: 0x007202E0 (FUN_007202E0)
   *
   * What it does:
   * Moves the trailing float4 lane into the root-pop slot and executes one
   * finalize-callback sift-down pass (`FUN_00720010` semantics).
   */
  [[nodiscard]] std::int32_t PopFloat4MinHeapRootSingleStepWithFinalize(
    Float4LaneRuntime* const rangeBegin,
    Float4LaneRuntime* const rangeEnd,
    const std::int32_t finalizeLane
  ) noexcept
  {
    Float4LaneRuntime* const tail = rangeEnd - 1;
    const Float4LaneRuntime replacementLane = *tail;
    *tail = *rangeBegin;

    const std::int32_t heapLast = static_cast<std::int32_t>(tail - rangeBegin);
    const auto finalizeFn = reinterpret_cast<Float4HeapFinalizeFn>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(finalizeLane))
    );
    return SiftDownFloat4HeapAndFinalize(0, heapLast, rangeBegin, replacementLane, finalizeFn);
  }

  /**
   * Address: 0x0071F280 (FUN_0071F280)
   *
   * What it does:
   * Heapifies one 16-byte lane range only when the aligned range span exceeds
   * one element.
   */
  [[maybe_unused]] std::intptr_t BuildFloat4HeapIfRangeHasMultipleElements(
    Float4LaneRuntime* const rangeBegin,
    Float4LaneRuntime* const rangeEnd,
    const std::int32_t finalizeLane
  ) noexcept
  {
    std::intptr_t result = reinterpret_cast<std::intptr_t>(rangeEnd);
    const auto byteSpan = reinterpret_cast<const std::byte*>(rangeEnd) - reinterpret_cast<const std::byte*>(rangeBegin);
    const std::intptr_t alignedByteSpan = static_cast<std::intptr_t>(byteSpan) & ~static_cast<std::intptr_t>(0x0F);
    if (alignedByteSpan > 0x10) {
      result = static_cast<std::intptr_t>(BuildFloat4MinHeapRangeFromMiddle(rangeBegin, rangeEnd, finalizeLane));
    }

    return result;
  }

  /**
   * Address: 0x0071F2B0 (FUN_0071F2B0)
   *
   * What it does:
   * Adapts one forwarder lane into the full tail-pop heap pass used by
   * contiguous 16-byte lane sorting helpers.
   */
  [[maybe_unused]] std::int32_t PopFloat4HeapToTailAdapter(
    Float4LaneRuntime* const rangeBegin,
    Float4LaneRuntime* const rangeEnd,
    const std::int32_t finalizeLane
  ) noexcept
  {
    return PopFloat4MinHeapToTailUntilSingle(rangeBegin, rangeEnd, finalizeLane);
  }

  /**
   * Address: 0x007200D0 (FUN_007200D0)
   *
   * What it does:
   * Performs one root-pop heap step when the aligned range span exceeds one
   * element; otherwise returns the end pointer lane unchanged.
   */
  [[maybe_unused]] std::intptr_t PopFloat4HeapRootIfRangeHasMultipleElements(
    Float4LaneRuntime* const rangeBegin,
    Float4LaneRuntime* const rangeEnd,
    const std::int32_t finalizeLane
  ) noexcept
  {
    std::intptr_t result = reinterpret_cast<std::intptr_t>(rangeEnd);
    const auto byteSpan = reinterpret_cast<const std::byte*>(rangeEnd) - reinterpret_cast<const std::byte*>(rangeBegin);
    const std::intptr_t alignedByteSpan = static_cast<std::intptr_t>(byteSpan) & ~static_cast<std::intptr_t>(0x0F);
    if (alignedByteSpan > 0x10) {
      result = static_cast<std::intptr_t>(PopFloat4MinHeapRootSingleStepWithFinalize(rangeBegin, rangeEnd, finalizeLane));
    }

    return result;
  }

  /**
   * Address: 0x00720470 (FUN_00720470)
   *
   * What it does:
   * Copies the current root lane into `outRoot` and then pushes one caller
   * provided replacement lane through the heap-root sift path.
   */
  [[maybe_unused]] std::int32_t CopyRootAndSiftFloat4HeapWithReplacement(
    Float4LaneRuntime* const rangeBegin,
    Float4LaneRuntime* const rangeEnd,
    Float4LaneRuntime* const outRoot,
    const float lane0,
    const float lane1,
    const float lane2,
    const float lane3
  ) noexcept
  {
    *outRoot = *rangeBegin;
    const Float4LaneRuntime replacementLane{lane0, lane1, lane2, lane3};
    const std::int32_t heapLast = static_cast<std::int32_t>(rangeEnd - rangeBegin);
    return SiftDownFloat4HeapAndInsertEntry(0, heapLast, rangeBegin, replacementLane);
  }

  /**
   * Address: 0x00715030 (FUN_00715030, ??0InfluenceGrid@Moho@@QAE@@Z)
   */
  InfluenceGrid::InfluenceGrid()
    : entries()
    , threats()
    , threat{}
    , decay{}
  {
    threat.Clear();
    decay.Clear();
  }

  /**
   * Address: 0x00716350 (FUN_00716350, ??1InfluenceGrid@Moho@@QAE@@Z)
   * Address: 0x0071EE70 (FUN_0071EE70)
   * Address: 0x0071F7C0 (FUN_0071F7C0)
   */
  InfluenceGrid::~InfluenceGrid()
  {
    threats.clear();
    DestroyInfluenceGridEntries(*this);
  }

  /**
   * Address: 0x0071F7F0 (FUN_0071F7F0)
   *
   * What it does:
   * Runs one `InfluenceGrid` destructor lane and returns the same object
   * pointer for caller chaining.
   */
  [[maybe_unused]] InfluenceGrid* DestroyInfluenceGridAndReturnSelf(InfluenceGrid* const grid)
  {
    grid->~InfluenceGrid();
    return grid;
  }

  /**
   * Address: 0x0071EA00 (FUN_0071EA00, std::vector_InfluenceGrid::~vector_InfluenceGrid)
   *
   * What it does:
   * Destroys one contiguous range of `InfluenceGrid` elements by releasing
   * per-grid threat vectors and entry maps.
   */
  [[maybe_unused]] static void DestroyInfluenceGridRange(InfluenceGrid* const start, InfluenceGrid* const end)
  {
    for (InfluenceGrid* cursor = start; cursor != end; ++cursor) {
      cursor->threats.clear();
      cursor->entries.clear();
    }
  }

  /**
   * Address: 0x0071B950 (FUN_0071B950)
   *
   * What it does:
   * Adapts one thiscall range-destroy lane into the canonical
   * `DestroyInfluenceGridRange(begin, end)` helper.
   */
  [[maybe_unused]] static void DestroyInfluenceGridRangeThiscallAdapter(
    InfluenceGrid* const rangeEnd,
    InfluenceGrid* const rangeBegin
  )
  {
    DestroyInfluenceGridRange(rangeBegin, rangeEnd);
  }

  /**
   * Address: 0x0071D550 (FUN_0071D550)
   *
   * What it does:
   * Adapts one scalar-delete caller lane into
   * `DestroyInfluenceGridRange(begin, end)`.
   */
  [[maybe_unused]] static void DestroyInfluenceGridRangeDeleteAdapter(
    InfluenceGrid* const rangeBegin,
    InfluenceGrid* const rangeEnd
  ) noexcept
  {
    DestroyInfluenceGridRange(rangeBegin, rangeEnd);
  }

  /**
   * Address: 0x0071ED10 (FUN_0071ED10)
   *
   * What it does:
   * Assigns one initialized `InfluenceGrid` from another by replacing entry-map
   * and per-army threat-vector contents, then copying aggregate threat and decay
   * lanes. Preserves self-assignment semantics.
   */
  [[maybe_unused]] InfluenceGrid& AssignInfluenceGridValue(InfluenceGrid& destination, const InfluenceGrid& source)
  {
    if (&destination != &source) {
      CopyInfluenceEntryTreeStorage(destination.entries, source.entries);

      destination.threats.clear();
      for (const SThreat* it = source.threats.begin(); it != source.threats.end(); ++it) {
        destination.threats.push_back(*it);
      }
    }

    destination.threat = source.threat;
    destination.decay = source.decay;
    return destination;
  }

  /**
   * Address: 0x0071ED90 (FUN_0071ED90)
   *
   * What it does:
   * Assigns one `InfluenceGrid` payload into `destination` and returns the
   * destination pointer (primary adapter lane).
   */
  [[maybe_unused]] moho::InfluenceGrid* AssignInfluenceGridAndReturnDestinationPrimary(
    const moho::InfluenceGrid* const source,
    moho::InfluenceGrid* const destination
  )
  {
    if (destination != nullptr && source != nullptr) {
      (void)AssignInfluenceGridValue(*destination, *source);
    }
    return destination;
  }

  /**
   * Address: 0x0071EDC0 (FUN_0071EDC0)
   *
   * What it does:
   * Assigns one `InfluenceGrid` payload into `destination` and returns the
   * destination pointer (secondary adapter lane).
   */
  [[maybe_unused]] moho::InfluenceGrid* AssignInfluenceGridAndReturnDestinationSecondary(
    const moho::InfluenceGrid* const source,
    moho::InfluenceGrid* const destination
  )
  {
    return AssignInfluenceGridAndReturnDestinationPrimary(source, destination);
  }

  /**
   * Address: 0x0071EAA0 (FUN_0071EAA0, fill_InfluenceGrid_range)
   *
   * What it does:
   * Assigns one shared `InfluenceGrid` value across `[destinationBegin,
   * destinationEnd)` by cloning entries, per-army threats, and aggregate/decay
   * threat lanes into each destination element.
   */
  [[maybe_unused]] static void FillInfluenceGridRange(
    InfluenceGrid* const destinationBegin,
    InfluenceGrid* const destinationEnd,
    const InfluenceGrid& fillValue
  )
  {
    for (InfluenceGrid* cursor = destinationBegin; cursor != destinationEnd; ++cursor) {
      AssignInfluenceGridValue(*cursor, fillValue);
    }
  }

  /**
   * Address: 0x0071D5A0 (FUN_0071D5A0)
   *
   * What it does:
   * Adapts one register-lane caller shape into
   * `FillInfluenceGridRange(destinationBegin, destinationEnd, fillValue)`.
   */
  [[maybe_unused]] static InfluenceGrid* FillInfluenceGridRangeRegisterAdapter(
    const InfluenceGrid& fillValue,
    InfluenceGrid* const destinationBegin,
    InfluenceGrid* const destinationEnd
  ) noexcept
  {
    FillInfluenceGridRange(destinationBegin, destinationEnd, fillValue);
    return destinationBegin;
  }

  /**
   * Address: 0x0071F5B0 (FUN_0071F5B0, copy_InfluenceGrid_range_backward)
   * Address: 0x0071EB20 (FUN_0071EB20)
   *
   * What it does:
   * Copies one `InfluenceGrid` range backward from `[sourceBegin, sourceEnd)`
   * into the destination range ending at `destinationEnd`, preserving overlap
   * semantics used by legacy vector insert/shift lanes.
   */
  [[maybe_unused]] static InfluenceGrid* CopyInfluenceGridRangeBackward(
    InfluenceGrid* const sourceEnd,
    InfluenceGrid* const sourceBegin,
    InfluenceGrid* const destinationEnd
  )
  {
    InfluenceGrid* sourceCursor = sourceEnd;
    InfluenceGrid* destinationCursor = destinationEnd;
    while (sourceCursor != sourceBegin) {
      --sourceCursor;
      --destinationCursor;

      AssignInfluenceGridValue(*destinationCursor, *sourceCursor);
    }

    return destinationCursor;
  }

  /**
   * Address: 0x0071D5B0 (FUN_0071D5B0)
   *
   * What it does:
   * Adapts one legacy call-convention lane into
   * `CopyInfluenceGridRangeBackward`.
   */
  [[maybe_unused]] static InfluenceGrid* CopyInfluenceGridRangeBackwardAdapter(
    InfluenceGrid* const sourceEnd,
    InfluenceGrid* const sourceBegin,
    InfluenceGrid* const destinationEnd
  ) noexcept
  {
    return CopyInfluenceGridRangeBackward(sourceEnd, sourceBegin, destinationEnd);
  }

  /**
   * Address: 0x0071E7B0 (FUN_0071E7B0, Moho::InfluenceGrid::ThreatDeconstruct)
   *
   * What it does:
   * Copies one contiguous `InfluenceGrid` range into destination storage for
   * vector relocation/copy lanes, preserving per-grid entry map, threat vector,
   * aggregate threat, and decay state.
   */
  [[maybe_unused]] static InfluenceGrid*
  CopyInfluenceGridRange(const InfluenceGrid* start, const InfluenceGrid* end, InfluenceGrid* dest)
  {
    for (const InfluenceGrid* source = start; source != end; ++source, ++dest) {
      if (dest != source) {
        CopyInfluenceGridEntries(*source, *dest);
        new (&dest->threats) decltype(dest->threats)();
        for (const SThreat* it = source->threats.begin(); it != source->threats.end(); ++it) {
          dest->threats.push_back(*it);
        }
      }
      dest->threat = source->threat;
      dest->decay = source->decay;
    }
    return dest;
  }

  /**
   * Address: 0x0071D1B0 (FUN_0071D1B0)
   *
   * What it does:
   * Adapts one register-lane caller shape into
   * `CopyInfluenceGridRange(sourceBegin, sourceEnd, destinationBegin)`.
   */
  [[maybe_unused]] static InfluenceGrid* CopyInfluenceGridRangeRegisterAdapter(
    const InfluenceGrid* const sourceBegin,
    const InfluenceGrid* const sourceEnd,
    InfluenceGrid* const destinationBegin
  )
  {
    return CopyInfluenceGridRange(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00720180 (FUN_00720180, copy_InfluenceGrid_range_with_rollback)
   * Address: 0x0071E9D0 (FUN_0071E9D0)
   * Address: 0x0071F550 (FUN_0071F550)
   * Address: 0x0071FC10 (FUN_0071FC10)
   *
   * What it does:
   * Copy-constructs one contiguous `InfluenceGrid` range into destination
   * storage and destroys already-constructed grids before rethrowing if a copy
   * step throws.
   */
  [[maybe_unused]] static InfluenceGrid*
  CopyInfluenceGridRangeWithRollback(const InfluenceGrid* start, const InfluenceGrid* end, InfluenceGrid* dest)
  {
    InfluenceGrid* cursor = dest;
    try {
      for (const InfluenceGrid* source = start; source != end; ++source, ++cursor) {
        if (cursor != source) {
          CopyInfluenceGridEntries(*source, *cursor);
          new (&cursor->threats) decltype(cursor->threats)();
          for (const SThreat* it = source->threats.begin(); it != source->threats.end(); ++it) {
            cursor->threats.push_back(*it);
          }
        }
        cursor->threat = source->threat;
        cursor->decay = source->decay;
      }
      return cursor;
    } catch (...) {
      for (InfluenceGrid* destroyCursor = dest; destroyCursor != cursor; ++destroyCursor) {
        destroyCursor->~InfluenceGrid();
      }
      throw;
    }
  }

  /**
   * Address: 0x0071D520 (FUN_0071D520)
   *
   * What it does:
   * Adapts one register-lane call shape into
   * `CopyInfluenceGridRangeWithRollback(sourceBegin, sourceEnd, destination)`.
   */
  [[maybe_unused]] static InfluenceGrid* CopyInfluenceGridRangeWithRollbackRegisterAdapter(
    const InfluenceGrid* const sourceBegin,
    const InfluenceGrid* const sourceEnd,
    InfluenceGrid* const destination
  )
  {
    return CopyInfluenceGridRangeWithRollback(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x0071E840 (FUN_0071E840, copy_InfluenceGrid_counted_range_with_rollback)
   *
   * What it does:
   * Copy-constructs `count` contiguous `InfluenceGrid` elements from `source`
   * into destination storage and destroys already-constructed lanes before
   * rethrowing if a copy step throws.
   */
  [[maybe_unused]] static InfluenceGrid* CopyInfluenceGridCountedRangeWithRollback(
    const std::uint32_t count,
    InfluenceGrid* const destination,
    const InfluenceGrid* const source
  )
  {
    if (count == 0u) {
      return destination;
    }

    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    return CopyInfluenceGridRangeWithRollback(source, source + count, destination);
  }

  /**
   * Address: 0x0071D1E0 (FUN_0071D1E0)
   *
   * What it does:
   * Adapts one register-lane call shape into
   * `CopyInfluenceGridCountedRangeWithRollback(count, destination, source)`.
   */
  [[maybe_unused]] static InfluenceGrid* CopyInfluenceGridCountedRangeWithRollbackRegisterAdapter(
    const std::uint32_t count,
    InfluenceGrid* const destination,
    const InfluenceGrid* const source
  )
  {
    return CopyInfluenceGridCountedRangeWithRollback(count, destination, source);
  }

  /**
   * Address: 0x00719F60 (FUN_00719F60)
   *
   * What it does:
   * Adapts one counted rollback-copy lane and returns one-past the last copied
   * `InfluenceGrid` destination slot.
   */
  [[maybe_unused]] static InfluenceGrid* CopyInfluenceGridCountedRangeWithRollbackAdapter(
    const InfluenceGrid* const sourceBegin,
    InfluenceGrid* const destinationBegin,
    const std::uint32_t count
  )
  {
    (void)CopyInfluenceGridCountedRangeWithRollback(count, destinationBegin, sourceBegin);
    return destinationBegin + count;
  }

  /**
   * Address: 0x0071FCA0 (FUN_0071FCA0, copy_InfluenceGrid_range_with_rollback_alt)
   * Address: 0x0071ECB0 (FUN_0071ECB0)
   * Address: 0x0071F6F0 (FUN_0071F6F0)
   *
   * What it does:
   * Alternate guarded contiguous `InfluenceGrid` range-copy lane that copies
   * `[sourceBegin, sourceEnd)` into destination storage and destroys already
   * constructed grids before rethrowing on copy failure.
   */
  [[maybe_unused]] static InfluenceGrid* CopyInfluenceGridRangeWithRollbackAlt(
    const InfluenceGrid* const sourceBegin,
    const InfluenceGrid* const sourceEnd,
    InfluenceGrid* const destinationBegin
  )
  {
    InfluenceGrid* destinationCursor = destinationBegin;
    try {
      for (const InfluenceGrid* sourceCursor = sourceBegin;
           sourceCursor != sourceEnd;
           ++sourceCursor, ++destinationCursor) {
        if (destinationCursor != nullptr) {
          (void)CopyInfluenceGridRange(sourceCursor, sourceCursor + 1, destinationCursor);
        }
      }
      return destinationCursor;
    } catch (...) {
      for (InfluenceGrid* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->~InfluenceGrid();
      }
      throw;
    }
  }

  /**
   * Address: 0x0071FD40 (FUN_0071FD40, copy_InfluenceGrid_counted_range)
   * Address: 0x0071EA70 (FUN_0071EA70)
   * Address: 0x0071F580 (FUN_0071F580)
   * Address: 0x0071F720 (FUN_0071F720)
   *
   * What it does:
   * Copies `count` contiguous `InfluenceGrid` elements from `source` into
   * `destination` using the recovered range-copy helper.
   */
  void CopyInfluenceGridCountedRange(
    InfluenceGrid* const destination,
    const InfluenceGrid* const source,
    const int count
  )
  {
    if (destination == nullptr || source == nullptr || count <= 0) {
      return;
    }

    (void)CopyInfluenceGridRange(source, source + count, destination);
  }

  /**
   * Address: 0x0071ECE0 (FUN_0071ECE0)
   *
   * What it does:
   * Adapts one fastcall register lane into `CopyInfluenceGridCountedRange`
   * using the register-provided element count and pointer arguments.
   */
  [[maybe_unused]] void CopyInfluenceGridCountedRangeFastcallAdapter(
    [[maybe_unused]] InfluenceGrid* const unusedThisLane,
    const int count,
    InfluenceGrid* const destination,
    const InfluenceGrid* const source
  ) noexcept
  {
    CopyInfluenceGridCountedRange(destination, source, count);
  }

  [[nodiscard]] bool AllocateInfluenceGridStorage(
    InfluenceGridVector& storage,
    const std::size_t elementCount
  ) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (elementCount == 0u) {
      view.begin = nullptr;
      view.end = nullptr;
      view.capacityEnd = nullptr;
      return true;
    }

    if (elementCount > (static_cast<std::size_t>(-1) / sizeof(InfluenceGrid))) {
      return false;
    }

    void* rawStorage = nullptr;
    try {
      rawStorage = ::operator new(sizeof(InfluenceGrid) * elementCount);
    } catch (...) {
      return false;
    }

    view.begin = static_cast<InfluenceGrid*>(rawStorage);
    view.end = view.begin;
    view.capacityEnd = view.begin + elementCount;
    return true;
  }

  [[nodiscard]] InfluenceGrid* CopyConstructInfluenceGridRangeWithRollback(
    InfluenceGrid* destination,
    const InfluenceGrid* sourceBegin,
    const InfluenceGrid* sourceEnd
  )
  {
    InfluenceGrid* write = destination;
    try {
      for (const InfluenceGrid* read = sourceBegin; read != sourceEnd; ++read, ++write) {
        ::new (write) InfluenceGrid();
        AssignInfluenceGridValue(*write, *read);
      }
      return write;
    } catch (...) {
      DestroyInfluenceGridRange(destination, write);
      throw;
    }
  }

  /**
   * Address: 0x0071E030 (FUN_0071E030)
   *
   * What it does:
   * Assigns one `vector<InfluenceGrid>` lane with the original VC8-style
   * capacity reuse and destruction order, including rollback-safe
   * copy-construction for growth and full-reallocation paths.
   */
  [[maybe_unused]] [[nodiscard]] InfluenceGridVector& AssignInfluenceGridVector(
    InfluenceGridVector& destination,
    const InfluenceGridVector& source
  )
  {
    if (&destination == &source) {
      return destination;
    }

    auto& destinationView = msvc8::AsVectorRuntimeView(destination);
    const auto& sourceView = msvc8::AsVectorRuntimeView(source);

    const std::size_t sourceCount =
      sourceView.begin ? static_cast<std::size_t>(sourceView.end - sourceView.begin) : 0u;
    if (sourceCount == 0u) {
      ClearInfluenceGridVectorStorage(destination);
      return destination;
    }

    const std::size_t currentCount =
      destinationView.begin ? static_cast<std::size_t>(destinationView.end - destinationView.begin) : 0u;
    const InfluenceGrid* const sourceBegin = sourceView.begin;
    const InfluenceGrid* const sourceEnd = sourceView.end;

    if (sourceCount > currentCount) {
      const std::size_t capacityCount =
        destinationView.begin ? static_cast<std::size_t>(destinationView.capacityEnd - destinationView.begin) : 0u;
      if (sourceCount <= capacityCount) {
        InfluenceGrid* destinationCursor = destinationView.begin;
        const InfluenceGrid* sourceCursor = sourceBegin;
        for (; destinationCursor != destinationView.end; ++destinationCursor, ++sourceCursor) {
          AssignInfluenceGridValue(*destinationCursor, *sourceCursor);
        }

        destinationView.end = CopyConstructInfluenceGridRangeWithRollback(destinationView.end, sourceCursor, sourceEnd);
        return destination;
      }

      if (destinationView.begin != nullptr) {
        DestroyInfluenceGridRange(destinationView.begin, destinationView.end);
        ::operator delete(destinationView.begin);
      }

      destinationView.begin = nullptr;
      destinationView.end = nullptr;
      destinationView.capacityEnd = nullptr;
      if (AllocateInfluenceGridStorage(destination, sourceCount)) {
        try {
          destinationView.end = CopyConstructInfluenceGridRangeWithRollback(destinationView.begin, sourceBegin, sourceEnd);
        } catch (...) {
          ::operator delete(destinationView.begin);
          destinationView.begin = nullptr;
          destinationView.end = nullptr;
          destinationView.capacityEnd = nullptr;
          throw;
        }
      }
      return destination;
    }

    InfluenceGrid* destinationCursor = destinationView.begin;
    const InfluenceGrid* sourceCursor = sourceBegin;
    for (; sourceCursor != sourceEnd; ++sourceCursor, ++destinationCursor) {
      AssignInfluenceGridValue(*destinationCursor, *sourceCursor);
    }
    DestroyInfluenceGridRange(destinationCursor, destinationView.end);
    destinationView.end = destinationView.begin + sourceCount;
    return destination;
  }

  [[nodiscard]] moho::InfluenceGrid* CopyConstructInfluenceGridIfPresent(
    moho::InfluenceGrid* const destination,
    const moho::InfluenceGrid* const source
  )
  {
    if (source == nullptr) {
      return nullptr;
    }

    ::new (destination) moho::InfluenceGrid();
    AssignInfluenceGridValue(*destination, *source);
    return destination;
  }

  /**
   * Address: 0x0071EE20 (FUN_0071EE20)
   *
   * What it does:
   * Primary adapter lane for nullable `InfluenceGrid` copy-construction into
   * caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::InfluenceGrid* CopyConstructInfluenceGridIfPresentPrimary(
    moho::InfluenceGrid* const destination,
    const moho::InfluenceGrid* const source
  )
  {
    return CopyConstructInfluenceGridIfPresent(destination, source);
  }

  /**
   * Address: 0x0071F770 (FUN_0071F770)
   *
   * What it does:
   * Secondary adapter lane for nullable `InfluenceGrid` copy-construction into
   * caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::InfluenceGrid* CopyConstructInfluenceGridIfPresentSecondary(
    moho::InfluenceGrid* const destination,
    const moho::InfluenceGrid* const source
  )
  {
    return CopyConstructInfluenceGridIfPresent(destination, source);
  }

  /**
   * Address: 0x0071D4B0 (FUN_0071D4B0, func_NewArray_SThreat)
   *
   * What it does:
   * Allocates contiguous storage for `count` `SThreat` elements with the same
   * overflow guard semantics as the original VC8 array-allocation helper.
   */
  [[maybe_unused]] static SThreat* func_NewArray_SThreat(const unsigned int count)
  {
    if (count != 0u && (0xFFFFFFFFu / count) < sizeof(SThreat)) {
      throw std::bad_alloc{};
    }

    return static_cast<SThreat*>(::operator new(sizeof(SThreat) * static_cast<std::size_t>(count)));
  }

  /**
   * Address: 0x0071D5E0 (FUN_0071D5E0, func_NewArray_InfluenceMap)
   *
   * What it does:
   * Allocates contiguous storage for `count` `InfluenceGrid` elements with the
   * same overflow guard semantics as the original VC8 array-allocation helper.
   */
  [[maybe_unused]] static InfluenceGrid* func_NewArray_InfluenceMap(const unsigned int count)
  {
    if (count != 0u && (0xFFFFFFFFu / count) < sizeof(InfluenceGrid)) {
      throw std::bad_alloc{};
    }

    return static_cast<InfluenceGrid*>(::operator new(sizeof(InfluenceGrid) * static_cast<std::size_t>(count)));
  }

  /**
   * Address: 0x0071B2F0 (FUN_0071B2F0)
   *
   * What it does:
   * Releases one raw allocation lane with `operator delete`.
   */
  [[maybe_unused]] void DeleteSThreatArrayOrZeroSizeBlockThunk(void* const allocation) noexcept
  {
    ::operator delete(allocation);
  }

  /**
   * Address: 0x0071BD30 (FUN_0071BD30)
   *
   * What it does:
   * Releases one raw allocation lane with `operator delete`.
   */
  [[maybe_unused]] void DeleteInfluenceGridArrayOrZeroSizeBlockThunk(void* const allocation) noexcept
  {
    ::operator delete(allocation);
  }

  /**
   * Address: 0x0071B300 (FUN_0071B300)
   *
   * What it does:
   * Allocates one checked `SThreat[count]` raw lane when `count != 0`; falls
   * back to `operator new(0)` for zero-count call sites.
   */
  [[maybe_unused]] SThreat* AllocateSThreatArrayOrZeroSizeBlock(const unsigned int count)
  {
    if (count != 0u) {
      return func_NewArray_SThreat(count);
    }

    return static_cast<SThreat*>(::operator new(0));
  }

  /**
   * Address: 0x0071BD40 (FUN_0071BD40)
   *
   * What it does:
   * Allocates one checked `InfluenceGrid[count]` raw lane when `count != 0`;
   * falls back to `operator new(0)` for zero-count call sites.
   */
  [[maybe_unused]] moho::InfluenceGrid* AllocateInfluenceGridArrayOrZeroSizeBlock(const unsigned int count)
  {
    if (count != 0u) {
      return func_NewArray_InfluenceMap(count);
    }

    return static_cast<moho::InfluenceGrid*>(::operator new(0));
  }

  /**
   * Address: 0x00715750 (FUN_00715750, ?GetThreat@InfluenceGrid@Moho@@QBEMW4EThreatType@2@H@Z)
   */
  float InfluenceGrid::GetThreat(const EThreatType threatType, const int army) const
  {
    float result = (threatType == THREATTYPE_OverallNotAssigned) ? 0.0f : threat.ValueByType(threatType);

    if (army >= 0) {
      const std::size_t armyIndex = static_cast<std::size_t>(army);
      if (armyIndex < threats.size()) {
        result += threats[armyIndex].ValueByType(threatType);
      }
      return result;
    }

    for (const SThreat* it = threats.begin(); it != threats.end(); ++it) {
      result += it->ValueByType(threatType);
    }
    return result;
  }

  /**
   * Address: 0x00715130 (FUN_00715130, ?DecayInfluence@InfluenceGrid@Moho@@QAEPAV12@XZ)
   */
  void InfluenceGrid::DecayInfluence()
  {
    threat.DecayBy(decay);
  }

  void InfluenceGrid::EnsureThreatSlots(const std::size_t armyCount)
  {
    const moho::SThreat fillValue{};
    ResizeSThreatVectorWithFill(threats, armyCount, fillValue);
  }

  void InfluenceGrid::ClearPerArmyThreats()
  {
    for (SThreat* it = threats.begin(); it != threats.end(); ++it) {
      it->Clear();
    }
  }

  InfluenceMapEntry* InfluenceGrid::FindEntry(const std::uint32_t entityId)
  {
    const auto it = FindInfluenceEntryLowerBoundByEntityId(*this, entityId);
    if (it == entries.end()) {
      return nullptr;
    }
    if (it->entityId != entityId) {
      return nullptr;
    }

    return const_cast<InfluenceMapEntry*>(&(*it));
  }

  const InfluenceMapEntry* InfluenceGrid::FindEntry(const std::uint32_t entityId) const
  {
    const auto it = FindInfluenceMapEntry(entries, entityId);
    if (it == entries.end()) {
      return nullptr;
    }

    return &(*it);
  }

  bool InfluenceGrid::RemoveEntry(const std::uint32_t entityId)
  {
    const auto it = FindInfluenceEntryLowerBoundByEntityId(*this, entityId);
    if (it == entries.end()) {
      return false;
    }
    if (it->entityId != entityId) {
      return false;
    }

    entries.erase(it);
    return true;
  }

  /**
   * Address: 0x00715BC0 (FUN_00715BC0, ??0CInfluenceMap@Moho@@QAE@XZ)
   */
  CInfluenceMap::CInfluenceMap()
    : mArmy(nullptr)
    , mTotal(0)
    , mWidth(0)
    , mHeight(0)
    , mGridSize(0)
    , mBlipCells()
    , mMapEntries()
  {
    InitializeBlipCellSet(mBlipCells);
    mMapEntries.clear();
  }

  /**
   * Address: 0x00716140 (FUN_00716140, ??0CInfluenceMap@Moho@@QAE@Z)
   */
  CInfluenceMap::CInfluenceMap(const std::int32_t gridSize, Sim* const sim, CArmyImpl* const army)
    : mArmy(army)
    , mTotal(0)
    , mWidth(0)
    , mHeight(0)
    , mGridSize(gridSize)
    , mBlipCells()
    , mMapEntries()
  {
    mMapEntries.clear();
    InitializeBlipCellSet(mBlipCells);

    const STIMap* const mapData = sim ? sim->mMapData : nullptr;
    const CHeightField* const heightField = mapData ? mapData->mHeightField.get() : nullptr;
    if (!heightField || mGridSize <= 0) {
      return;
    }

    mWidth = (heightField->width - 1) / mGridSize;
    mHeight = (heightField->height - 1) / mGridSize;
    mTotal = mWidth * mHeight;

    if (mTotal <= 0) {
      return;
    }

    mMapEntries.resize(static_cast<std::size_t>(mTotal));
    const std::size_t armyCount = sim ? static_cast<std::size_t>(sim->ArmyCount()) : 0u;
    for (InfluenceGrid* cell = mMapEntries.begin(); cell != mMapEntries.end(); ++cell) {
      cell->EnsureThreatSlots(armyCount);
    }
  }

  /**
   * Address: 0x007163A0 (FUN_007163A0, ??1CInfluenceMap@Moho@@QAE@Z)
   */
  CInfluenceMap::~CInfluenceMap()
  {
    ClearInfluenceGridVectorStorage(mMapEntries);
    ReleaseBlipCellSet(mBlipCells);
  }

  /**
   * Address: 0x00715C60 (FUN_00715C60, ?VectorToCoords@CInfluenceMap@Moho@@AAEHPAV?$Vector3@M@Wm3@@@Z)
   */
  std::int32_t CInfluenceMap::VectorToCoords(const Wm3::Vec3f& pos) const
  {
    if (mGridSize <= 0 || mWidth <= 0 || mHeight <= 0) {
      return 0;
    }

    std::int32_t x = static_cast<std::int32_t>(pos.x) / mGridSize;
    if (x >= (mWidth - 1)) {
      x = mWidth - 1;
    }
    if (x < 0) {
      x = 0;
    }

    std::int32_t z = static_cast<std::int32_t>(pos.z) / mGridSize;
    if (z >= (mHeight - 1)) {
      z = mHeight - 1;
    }
    if (z < 0) {
      z = 0;
    }

    return x + z * mWidth;
  }

  /**
   * Address: 0x00715F30 (FUN_00715F30, ?UpdateBlipPosition@CInfluenceMap@Moho@@QAEXHABV?$Vector3@M@Wm3@@PBVRUnitBlueprint@2@@Z)
   */
  void CInfluenceMap::UpdateBlipPosition(
    const std::uint32_t blipId, const Wm3::Vec3f& position, const RUnitBlueprint* const sourceBlueprint
  )
  {
    const InfluenceMapCellIndex* const knownCell = FindBlipCell(blipId);
    const std::int32_t newCellIndex = VectorToCoords(position);

    if (!knownCell) {
      InsertEntry(blipId, position, sourceBlueprint);
      return;
    }

    const std::int32_t oldCellIndex = knownCell->cellIndex;
    if (oldCellIndex == newCellIndex && oldCellIndex >= 0 && oldCellIndex < mTotal) {
      InfluenceGrid& cell = mMapEntries[static_cast<std::size_t>(oldCellIndex)];
      if (InfluenceMapEntry* const entry = cell.FindEntry(blipId)) {
        entry->threatStrength = 1.0f;
        entry->decayTicks = 10;
        entry->lastPosition = position;
      }
      return;
    }

    RemoveEntry(blipId);
    InsertEntry(blipId, position, sourceBlueprint);
  }

  /**
   * Address: 0x00715FF0 (FUN_00715FF0, ?GetThreatRect@CInfluenceMap@Moho@@QBEMHHH_W4EThreatType@2@H@Z)
   */
  float CInfluenceMap::GetThreatRect(
    const int x, const int z, const int radius, const bool onMap, const EThreatType threatType, const int army
  ) const
  {
    if (mWidth <= 0 || mHeight <= 0 || mMapEntries.empty()) {
      return 0.0f;
    }

    int mapX0 = 0;
    int mapX1 = mWidth - 1;
    int mapZ0 = 0;
    int mapZ1 = mHeight - 1;

    if (onMap && mArmy) {
      const Sim* const sim = mArmy->GetSim();
      const STIMap* const mapData = sim ? sim->mMapData : nullptr;
      if (mapData && mGridSize > 0) {
        mapX0 = mapData->mPlayableRect.x0 / mGridSize;
        mapX1 = mapData->mPlayableRect.x1 / mGridSize;
        mapZ0 = mapData->mPlayableRect.z0 / mGridSize;
        mapZ1 = mapData->mPlayableRect.z1 / mGridSize;
      }
    }

    float totalThreat = 0.0f;
    const int zStart = z - radius;
    const int zEnd = z + radius;

    for (int curZ = zStart; curZ <= zEnd; ++curZ) {
      if (curZ < 0 || curZ >= mHeight) {
        continue;
      }
      if (onMap && (curZ < mapZ0 || curZ > mapZ1)) {
        continue;
      }

      const int xStart = x - radius;
      const int xEnd = x + radius;
      for (int curX = xStart; curX <= xEnd; ++curX) {
        if (curX < 0 || curX >= mWidth) {
          continue;
        }
        if (onMap && (curX < mapX0 || curX > mapX1)) {
          continue;
        }

        const std::int32_t index = curX + curZ * mWidth;
        totalThreat += mMapEntries[static_cast<std::size_t>(index)].GetThreat(threatType, army);
      }
    }

    return totalThreat;
  }

  /**
   * Address: 0x00716E60 (FUN_00716E60, ?GetThreatBetweenPositions@CInfluenceMap@Moho@@QBEMABV?$Vector3@M@Wm3@@0_W4EThreatType@2@H@Z)
   */
  float CInfluenceMap::GetThreatBetweenPositions(
    const Wm3::Vec3f& pos1,
    const Wm3::Vec3f& pos2,
    const bool ring,
    const EThreatType threatType,
    const int armyIndex
  ) const
  {
    if (mWidth <= 0 || mHeight <= 0) {
      return 0.0f;
    }

    const std::int32_t index0 = VectorToCoords(pos1);
    const std::int32_t index1 = VectorToCoords(pos2);

    int x0 = index0 % mWidth;
    int z0 = index0 / mWidth;
    const int x1 = index1 % mWidth;
    const int z1 = index1 / mWidth;

    const int dx = std::abs(x1 - x0);
    const int dz = std::abs(z1 - z0);
    const int sx = (x0 < x1) ? 1 : -1;
    const int sz = (z0 < z1) ? 1 : -1;

    float totalThreat = 0.0f;
    int err = dx - dz;
    while (true) {
      totalThreat += GetThreatRect(x0, z0, 0, ring, threatType, armyIndex);
      if (x0 == x1 && z0 == z1) {
        break;
      }

      const int err2 = err * 2;
      if (err2 > -dz) {
        err -= dz;
        x0 += sx;
      }
      if (err2 < dx) {
        err += dx;
        z0 += sz;
      }
    }

    return totalThreat;
  }

  /**
   * Address: 0x00718A40 (FUN_00718A40)
   *
   * What it does:
   * Builds one Lua threat-sample row and appends it at the next array index in
   * the caller-owned result table.
   */
  void AppendThreatSampleRow(
    LuaPlus::LuaObject* const outObj,
    std::int32_t& luaIndex,
    LuaPlus::LuaState* const state,
    const float worldX,
    const float worldZ,
    const float threat
  )
  {
    LuaPlus::LuaObject point;
    point.AssignNewTable(state, 0, 4);
    point.SetNumber("x", worldX);
    point.SetNumber("y", 0.0f);
    point.SetNumber("z", worldZ);
    point.SetNumber("threat", threat);
    outObj->SetObject(luaIndex, point);
    ++luaIndex;
  }

  /**
   * Address: 0x007171D0 (FUN_007171D0, ?GetThreatsAroundPosition@CInfluenceMap@Moho@@QAE?AVLuaObject@LuaPlus@@AAV42@ABV?$Vector3@M@Wm3@@HHW4EThreatType@2@H@Z)
   */
  LuaPlus::LuaObject* CInfluenceMap::GetThreatsAroundPosition(
    LuaPlus::LuaObject* const outObj,
    const Wm3::Vec3f& pos,
    const int ring,
    const bool restrictToPlayable,
    const EThreatType threatType,
    const int armyIndex
  ) const
  {
    if (!outObj) {
      return nullptr;
    }

    LuaPlus::LuaState* const state = outObj->m_state;
    if (!state) {
      return outObj;
    }

    outObj->AssignNewTable(state, 0, 0);

    const std::int32_t centerIndex = VectorToCoords(pos);
    const int centerX = centerIndex % mWidth;
    const int centerZ = centerIndex / mWidth;

    int mapX0 = 0;
    int mapX1 = mWidth - 1;
    int mapZ0 = 0;
    int mapZ1 = mHeight - 1;

    Sim* const sim = mArmy ? mArmy->GetSim() : nullptr;
    if (restrictToPlayable && sim && sim->mMapData && mGridSize > 0) {
      mapX0 = sim->mMapData->mPlayableRect.x0 / mGridSize;
      mapX1 = sim->mMapData->mPlayableRect.x1 / mGridSize;
      mapZ0 = sim->mMapData->mPlayableRect.z0 / mGridSize;
      mapZ1 = sim->mMapData->mPlayableRect.z1 / mGridSize;
    }

    std::int32_t luaIndex = 1;
    for (int z = centerZ - ring; z <= centerZ + ring; ++z) {
      if (z < 0 || z >= mHeight) {
        continue;
      }
      if (restrictToPlayable && (z < mapZ0 || z > mapZ1)) {
        continue;
      }

      for (int x = centerX - ring; x <= centerX + ring; ++x) {
        if (x < 0 || x >= mWidth) {
          continue;
        }
        if (restrictToPlayable && (x < mapX0 || x > mapX1)) {
          continue;
        }

        const std::int32_t cellIndex = x + z * mWidth;
        const float threat = mMapEntries[static_cast<std::size_t>(cellIndex)].GetThreat(threatType, armyIndex);
        if (threat <= 0.0f) {
          continue;
        }

        const float worldX = static_cast<float>((mGridSize / 2) + (x * mGridSize));
        const float worldZ = static_cast<float>((mGridSize / 2) + (z * mGridSize));
        AppendThreatSampleRow(outObj, luaIndex, state, worldX, worldZ, threat);

        if (sim) {
          const float coords[3] = {worldX, 0.0f, worldZ};
          sim->mContext.Update(&threat, sizeof(threat));
          sim->mContext.Update(coords, sizeof(coords));
        }
      }
    }

    if (sim) {
      const gpg::MD5Digest digest = sim->mContext.Digest();
      const msvc8::string checksum = digest.ToString();
      sim->Logf("after GetThreatsAroundPosition checksum=%s\n", checksum.c_str());
    }

    return outObj;
  }

  /**
   * Address: 0x00716480 (FUN_00716480, ?Update@CInfluenceMap@Moho@@QAEXXZ)
   */
  void CInfluenceMap::Update()
  {
    Sim* const sim = mArmy ? mArmy->GetSim() : nullptr;
    const CategoryWordRangeView* commandCategory = nullptr;
    const CategoryWordRangeView* experimentalCategory = nullptr;
    const CategoryWordRangeView* artilleryCategory = nullptr;
    const CategoryWordRangeView* massExtractorCategory = nullptr;
    if (sim && sim->mRules) {
      commandCategory = sim->mRules->GetEntityCategory("COMMAND");
      experimentalCategory = sim->mRules->GetEntityCategory("EXPERIMENTAL");
      artilleryCategory = sim->mRules->GetEntityCategory("ARTILLERY, STRATEGIC");
      massExtractorCategory = sim->mRules->GetEntityCategory("MASSEXTRACTION");
    }

    for (InfluenceGrid* cell = mMapEntries.begin(); cell != mMapEntries.end(); ++cell) {
      cell->DecayInfluence();
      cell->ClearPerArmyThreats();

      for (auto it = cell->entries.begin(); it != cell->entries.end();) {
        InfluenceMapEntry& entry = const_cast<InfluenceMapEntry&>(*it);

        if (entry.decayTicks > 0) {
          --entry.decayTicks;
        }
        if (entry.decayTicks == 0) {
          entry.threatStrength = DecayThreatLane(entry.threatStrength, entry.threatDecay);
        }

        if (entry.threatStrength <= 0.0f) {
          const float threatStrengthChecksum = entry.threatStrength;
          RemoveBlipCell(entry.entityId);
          it = EraseInfluenceEntryAndAdvance(*cell, it);
          if (sim) {
            sim->mContext.Update(&threatStrengthChecksum, sizeof(threatStrengthChecksum));
          }
          continue;
        }

        if (!IsAlliedOrSameArmy(mArmy, entry.sourceArmy) && sim && sim->mEntityDB) {
          Entity* const entity = FindEntityById(sim->mEntityDB, static_cast<std::int32_t>(entry.entityId));
          if (entity) {
            if (ReconBlip* const blip = entity->IsReconBlip()) {
              entry.sourceLayer = static_cast<std::int32_t>(entity->mCurrentLayer);

              const std::int32_t sourceArmyIndex = entry.sourceArmy ? entry.sourceArmy->ArmyId : -1;
              if (sourceArmyIndex >= 0) {
                const SPerArmyReconInfo* const sourceArmyRecon = blip->GetPerArmyReconInfo(sourceArmyIndex);
                if (sourceArmyRecon) {
                  const std::uint32_t flags = sourceArmyRecon->mReconFlags;
                  if ((flags & RECON_KnownFake) != 0u) {
                    entry.threatStrength = 0.0f;
                  } else if ((flags & RECON_Omni) != 0u || (flags & RECON_LOSEver) != 0u) {
                    entry.isDetailed = 1u;
                  }
                }
              }
            }
          }
        }

        const std::int32_t sourceArmyIndex = entry.sourceArmy ? entry.sourceArmy->ArmyId : -1;
        if (
          sourceArmyIndex >= 0 && static_cast<std::size_t>(sourceArmyIndex) < cell->threats.size()
          && entry.sourceBlueprint != nullptr
        ) {
          SThreat& armyThreat = cell->threats[static_cast<std::size_t>(sourceArmyIndex)];
          const float strength = entry.threatStrength;

          const float antiAir = entry.sourceBlueprint->Defense.AirThreatLevel * strength;
          const float antiSurface = entry.sourceBlueprint->Defense.SurfaceThreatLevel * strength;
          const float antiSub = entry.sourceBlueprint->Defense.SubThreatLevel * strength;
          const float economy = entry.sourceBlueprint->Defense.EconomyThreatLevel * strength;
          const float total = antiAir + antiSurface + antiSub + economy;
          armyThreat.overallInfluence += total;

          if (!entry.sourceBlueprint->IsMobile()) {
            if (IsInCategory(massExtractorCategory, entry.sourceBlueprint->mCategoryBitIndex)) {
              armyThreat.influenceStructuresNotMex += total;
            } else {
              armyThreat.influenceStructures += total;
              armyThreat.influenceStructuresNotMex += total;
            }
          } else {
            if (entry.sourceBlueprint->Air.CanFly != 0u) {
              armyThreat.airInfluence += total;
            } else if (entry.sourceLayer == LAYER_Land) {
              armyThreat.landInfluence += total;
            } else if (entry.sourceLayer == LAYER_Water || entry.sourceLayer == LAYER_Seabed || entry.sourceLayer == LAYER_Sub) {
              armyThreat.navalInfluence += total;
            }
          }

          if (entry.isDetailed != 0u) {
            if (IsInCategory(experimentalCategory, entry.sourceBlueprint->mCategoryBitIndex)) {
              armyThreat.experimentalInfluence += total;
            }
            if (IsInCategory(commandCategory, entry.sourceBlueprint->mCategoryBitIndex)) {
              armyThreat.commanderInfluence += total;
            }
            if (IsInCategory(artilleryCategory, entry.sourceBlueprint->mCategoryBitIndex)) {
              armyThreat.artilleryInfluence += total;
            }

            armyThreat.antiAirInfluence += antiAir;
            armyThreat.antiSurfaceInfluence += antiSurface;
            armyThreat.antiSubInfluence += antiSub;
            armyThreat.economyInfluence += economy;
          } else {
            armyThreat.unknownInfluence += total;
          }
        }

        if (sim) {
          sim->mContext.Update(&entry.threatStrength, sizeof(entry.threatStrength));
        }
        ++it;
      }
    }

    if (sim) {
      const gpg::MD5Digest digest = sim->mContext.Digest();
      const msvc8::string checksum = digest.ToString();
      sim->Logf("after inf checksum=%s\n", checksum.c_str());
    }
  }

  CArmyImpl* CInfluenceMap::ResolveSourceArmy(const std::uint32_t blipId) const
  {
    if (!mArmy) {
      return nullptr;
    }

    Sim* const sim = mArmy->GetSim();
    if (!sim) {
      return nullptr;
    }

    const std::uint32_t armyIndex = (blipId >> 20u) & 0xFFu;
    if (armyIndex == 0xFFu || armyIndex >= sim->mArmiesList.size()) {
      return nullptr;
    }

    return sim->mArmiesList[armyIndex];
  }

  const InfluenceMapCellIndex* CInfluenceMap::FindBlipCell(const std::uint32_t blipId) const
  {
    InfluenceMapCellIndex key{};
    key.entityId = blipId;
    const auto it = mBlipCells.find(key);
    if (it == mBlipCells.end()) {
      return nullptr;
    }

    return &(*it);
  }

  void CInfluenceMap::UpsertBlipCell(const std::uint32_t blipId, const std::int32_t cellIndex)
  {
    RemoveBlipCell(blipId);
    mBlipCells.insert(InfluenceMapCellIndex{blipId, cellIndex});
  }

  void CInfluenceMap::RemoveBlipCell(const std::uint32_t blipId)
  {
    InfluenceMapCellIndex key{};
    key.entityId = blipId;
    const auto it = mBlipCells.find(key);
    if (it != mBlipCells.end()) {
      mBlipCells.erase(it);
    }
  }

  /**
   * Address: 0x00715D10 (FUN_00715D10, Moho::CInfluenceMap::InsertEntry)
   *
   * What it does:
   * Builds one per-blip influence entry at `position`, inserts/updates it in
   * the owning cell lane, and stores the blip-to-cell lookup mapping.
   */
  void CInfluenceMap::InsertEntry(
    const std::uint32_t blipId, const Wm3::Vec3f& position, const RUnitBlueprint* const sourceBlueprint
  )
  {
    const std::int32_t cellIndex = VectorToCoords(position);
    if (cellIndex < 0 || cellIndex >= mTotal) {
      return;
    }

    InfluenceMapEntry entry{};
    entry.entityId = blipId;
    entry.sourceArmy = ResolveSourceArmy(blipId);
    entry.lastPosition = position;
    entry.sourceBlueprint = sourceBlueprint;
    entry.sourceLayer = LAYER_None;
    entry.isDetailed = 0u;
    entry.pad_1D_1F[0] = 0u;
    entry.pad_1D_1F[1] = 0u;
    entry.pad_1D_1F[2] = 0u;
    entry.threatStrength = 1.0f;
    entry.threatDecay = (sourceBlueprint && sourceBlueprint->IsMobile()) ? 0.02f : 0.0f;
    entry.decayTicks = 10;

    InfluenceGrid& cell = mMapEntries[static_cast<std::size_t>(cellIndex)];
    const auto [it, inserted] = cell.entries.insert(entry);
    if (!inserted) {
      InfluenceMapEntry& mutableEntry = const_cast<InfluenceMapEntry&>(*it);
      mutableEntry = entry;
    }

    UpsertBlipCell(blipId, cellIndex);
  }

  /**
   * Address: 0x00715EB0 (FUN_00715EB0, Moho::CInfluenceMap::RemoveEntry)
   *
   * What it does:
   * Removes one blip entry from the owning influence cell and drops the
   * corresponding blip-to-cell index lane.
   */
  void CInfluenceMap::RemoveEntry(const std::uint32_t blipId)
  {
    const InfluenceMapCellIndex* const blipCell = FindBlipCell(blipId);
    if (!blipCell) {
      return;
    }

    const std::int32_t cellIndex = blipCell->cellIndex;
    if (cellIndex >= 0 && cellIndex < mTotal) {
      mMapEntries[static_cast<std::size_t>(cellIndex)].RemoveEntry(blipId);
    }

    RemoveBlipCell(blipId);
  }

  bool CInfluenceMap::IsInCategory(const CategoryWordRangeView* const category, const std::uint32_t categoryBitIndex)
  {
    return category && category->ContainsBit(categoryBitIndex);
  }

  /**
   * Address: 0x00716B00 (FUN_00716B00, Moho::CInfluenceMap::AssignThreatAtPosition)
   *
   * IDA signature:
   * void __userpurge Moho::CInfluenceMap::AssignThreatAtPosition(
   *   Wm3::Vector3f *pos@<eax>, Moho::CInfluenceMap *this@<ecx>,
   *   Moho::EThreatType threatType@<esi>, float assignedThreat, float assignedDecay);
   *
   * What it does:
   * Adds `assignedThreat` to the per-type threat lane of the cell
   * containing `position`, then re-derives the matching decay lane as
   * `(updated threat) * assignedDecay`. Negative `assignedDecay`
   * substitutes a default `0.01` rate. The Overall and Unknown enum
   * values both map to the cell's `unknownInfluence` lane to match
   * the binary's switch fallthrough.
   */
  void CInfluenceMap::AssignThreatAtPosition(
    const Wm3::Vec3f& position,
    const EThreatType threatType,
    const float assignedThreat,
    float assignedDecay
  )
  {
    const std::int32_t cellIndex = VectorToCoords(position);
    if (cellIndex < 0 || cellIndex >= static_cast<std::int32_t>(mMapEntries.size())) {
      return;
    }

    if (assignedDecay < 0.0f) {
      assignedDecay = 0.01f;
    }

    InfluenceGrid& cell = mMapEntries[static_cast<std::size_t>(cellIndex)];

    auto applyThreat = [&assignedThreat, &assignedDecay](float& threatLane, float& decayLane) {
      threatLane += assignedThreat;
      decayLane = threatLane * assignedDecay;
    };

    switch (threatType) {
      case THREATTYPE_Overall:
      case THREATTYPE_Unknown:
        applyThreat(cell.threat.unknownInfluence, cell.decay.unknownInfluence);
        break;
      case THREATTYPE_StructuresNotMex:
        applyThreat(cell.threat.influenceStructuresNotMex, cell.decay.influenceStructuresNotMex);
        break;
      case THREATTYPE_Structures:
        applyThreat(cell.threat.influenceStructures, cell.decay.influenceStructures);
        break;
      case THREATTYPE_Naval:
        applyThreat(cell.threat.navalInfluence, cell.decay.navalInfluence);
        break;
      case THREATTYPE_Air:
        applyThreat(cell.threat.airInfluence, cell.decay.airInfluence);
        break;
      case THREATTYPE_Land:
        applyThreat(cell.threat.landInfluence, cell.decay.landInfluence);
        break;
      case THREATTYPE_Experimental:
        applyThreat(cell.threat.experimentalInfluence, cell.decay.experimentalInfluence);
        break;
      case THREATTYPE_Commander:
        applyThreat(cell.threat.commanderInfluence, cell.decay.commanderInfluence);
        break;
      case THREATTYPE_Artillery:
        applyThreat(cell.threat.artilleryInfluence, cell.decay.artilleryInfluence);
        break;
      case THREATTYPE_AntiAir:
        applyThreat(cell.threat.antiAirInfluence, cell.decay.antiAirInfluence);
        break;
      case THREATTYPE_AntiSurface:
        applyThreat(cell.threat.antiSurfaceInfluence, cell.decay.antiSurfaceInfluence);
        break;
      case THREATTYPE_AntiSub:
        applyThreat(cell.threat.antiSubInfluence, cell.decay.antiSubInfluence);
        break;
      case THREATTYPE_Economy:
        applyThreat(cell.threat.economyInfluence, cell.decay.economyInfluence);
        break;
      default:
        break;
    }
  }

  /**
   * Address: 0x00716FC0 (FUN_00716FC0, Moho::CInfluenceMap::GetHighestThreatPosition)
   *
   * IDA signature:
   * Wm3::Vector3f *__userpurge Moho::CInfluenceMap::GetHighestThreatPosition@<eax>(
   *   Moho::CInfluenceMap *this@<eax>, Wm3::Vector3f *outPos, float *outThreat,
   *   int radius, char onMap, Moho::EThreatType threatType, int armyIndex);
   *
   * What it does:
   * Walks every cell of the influence grid, computes that cell's
   * threat value (rectangle aggregate when `radius > 0`, otherwise
   * the cell's own per-type sample), and tracks the cell with the
   * highest value. Ties are broken by squared XZ distance from this
   * army's start position (closer wins). The peak value is written
   * into `outThreat` and the chosen cell's world-space center
   * (with `y = 0`) is written into `outPosition`.
   *
   * Initial threat seed is `-200.0f` (binary's `nInf_200` constant)
   * so any positive sample wins.
   */
  Wm3::Vec3f* CInfluenceMap::GetHighestThreatPosition(
    Wm3::Vec3f* const outPosition,
    float* const outThreat,
    const int radius,
    const bool onMap,
    const EThreatType threatType,
    const int armyIndex
  )
  {
    constexpr float kInitialThreat = -200.0f;

    Wm3::Vector2f armyStart{};
    mArmy->GetArmyStartPos(armyStart);
    const float startX = armyStart.x;
    const float startZ = armyStart.y;

    float bestThreat = kInitialThreat;
    float bestDistanceSq = kInitialThreat;
    std::int32_t bestCellIndex = 0;

    const std::int32_t cellCount = static_cast<std::int32_t>(mMapEntries.size());
    for (std::int32_t cellIndex = 0; cellIndex < cellCount; ++cellIndex) {
      InfluenceGrid& cell = mMapEntries[static_cast<std::size_t>(cellIndex)];
      const std::int32_t cellX = cellIndex % mWidth;
      const std::int32_t cellZ = cellIndex / mWidth;

      const float currentThreat = (radius != 0)
        ? GetThreatRect(cellX, cellZ, radius, onMap, threatType, armyIndex)
        : cell.GetThreat(threatType, armyIndex);

      const std::int32_t halfStep = mGridSize / 2;
      const float cellCenterX = static_cast<float>(halfStep + cellX * mGridSize);
      const float cellCenterZ = static_cast<float>(halfStep + cellZ * mGridSize);
      const float deltaX = startX - cellCenterX;
      const float deltaZ = startZ - cellCenterZ;
      const float distanceSq = deltaX * deltaX + deltaZ * deltaZ;

      if (currentThreat > bestThreat) {
        bestThreat = currentThreat;
        bestCellIndex = cellIndex;
        bestDistanceSq = distanceSq;
      } else if (currentThreat == bestThreat && distanceSq < bestDistanceSq) {
        bestThreat = currentThreat;
        bestCellIndex = cellIndex;
        bestDistanceSq = distanceSq;
      }
    }

    *outThreat = bestThreat;

    const std::int32_t halfStep = mGridSize / 2;
    const std::int32_t bestX = bestCellIndex % mWidth;
    const std::int32_t bestZ = bestCellIndex / mWidth;
    outPosition->x = static_cast<float>(halfStep + bestX * mGridSize);
    outPosition->y = 0.0f;
    outPosition->z = static_cast<float>(halfStep + bestZ * mGridSize);
    return outPosition;
  }
} // namespace moho

namespace
{
  struct CInfluenceMapDebugBootstrap
  {
    CInfluenceMapDebugBootstrap()
    {
      moho::register_imap_debug_ConAliasDef();
      moho::register_imap_debug_SimConVarDef();
      moho::register_imap_debug_grid_ConAliasDef();
      moho::func_imap_debug_grid_SimConVarDef();
      moho::register_imap_debug_path_graph_ConAliasDef();
      moho::func_imap_debug_path_graph_SimConVarDef();
      moho::register_imap_debug_grid_type_ConAliasDef();
      moho::func_imap_debug_grid_type_SimConVarDef();
      moho::register_imap_debug_grid_army_ConAliasDef();
      moho::func_imap_debug_grid_army_SimConVarDef();
    }
  };

  CInfluenceMapDebugBootstrap gCInfluenceMapDebugBootstrap;
} // namespace
