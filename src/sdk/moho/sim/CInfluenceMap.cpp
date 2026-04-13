#include "CInfluenceMap.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <map>
#include <new>
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
  };
} // namespace gpg

namespace
{
  using UIntIntMap = std::map<std::uint32_t, int>;
  using UIntInfluenceMapEntryMap = std::map<std::uint32_t, moho::InfluenceMapEntry>;

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

  [[nodiscard]] gpg::RType* CachedInfluenceGridType()
  {
    gpg::RType* type = moho::InfluenceGrid::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::InfluenceGrid));
      moho::InfluenceGrid::sType = type;
    }
    return type;
  }

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

  [[nodiscard]] gpg::RType* CachedInfluenceMapEntryType()
  {
    gpg::RType* type = moho::InfluenceMapEntry::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::InfluenceMapEntry));
      moho::InfluenceMapEntry::sType = type;
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
   */
  InfluenceGrid::~InfluenceGrid()
  {
    threats.clear();
    entries.clear();
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
    while (threats.size() < armyCount) {
      SThreat slot{};
      slot.Clear();
      threats.push_back(slot);
    }
  }

  void InfluenceGrid::ClearPerArmyThreats()
  {
    for (SThreat* it = threats.begin(); it != threats.end(); ++it) {
      it->Clear();
    }
  }

  InfluenceMapEntry* InfluenceGrid::FindEntry(const std::uint32_t entityId)
  {
    InfluenceMapEntry key{};
    key.entityId = entityId;
    const auto it = entries.find(key);
    if (it == entries.end()) {
      return nullptr;
    }

    return const_cast<InfluenceMapEntry*>(&(*it));
  }

  const InfluenceMapEntry* InfluenceGrid::FindEntry(const std::uint32_t entityId) const
  {
    InfluenceMapEntry key{};
    key.entityId = entityId;
    const auto it = entries.find(key);
    if (it == entries.end()) {
      return nullptr;
    }

    return &(*it);
  }

  bool InfluenceGrid::RemoveEntry(const std::uint32_t entityId)
  {
    InfluenceMapEntry key{};
    key.entityId = entityId;
    const auto it = entries.find(key);
    if (it == entries.end()) {
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
    mBlipCells.clear();
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
    mBlipCells.clear();

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
    mMapEntries.clear();
    mBlipCells.clear();
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

        LuaPlus::LuaObject point;
        point.AssignNewTable(state, 0, 4);
        point.SetNumber("x", worldX);
        point.SetNumber("y", 0.0f);
        point.SetNumber("z", worldZ);
        point.SetNumber("threat", threat);
        outObj->SetObject(luaIndex, point);
        ++luaIndex;

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
          it = cell->entries.erase(it);
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
