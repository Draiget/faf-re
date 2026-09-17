#include "legacy/algorithms/Sort.h"
#include "CInfluenceMap.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/String.h"
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
#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{
  class RMapType_uint_int final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0071DC40 (FUN_0071DC40, gpg::RMapType_uint_int::dtr)
     */
    ~RMapType_uint_int() override = default;

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
     * Address: 0x0071DD00 (FUN_0071DD00, gpg::RMapType_uint_InfluenceMapEntry::dtr)
     */
    ~RMapType_uint_InfluenceMapEntry() override = default;

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

  /**
   * VFTABLE (gpg::RIndexed subobject @ +0x64): 0x00E3181C
   *   ??_7?$RVectorType@UInfluenceGrid@Moho@@@gpg@@6BRIndexed@gpg@@@
   *   +0x00 SubscriptIndex   0x00718FA0
   *   +0x04 GetCount         0x00718F40
   *   +0x08 SetCount         0x00718F70
   *   +0x0C AssignPointer    0x00401320 (inherited gpg::RIndexed base impl)
   */
  class RVectorType_InfluenceGrid final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0071DCA0 (FUN_0071DCA0, gpg::RVectorType_InfluenceGrid::dtr)
     */
    ~RVectorType_InfluenceGrid() override = default;

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

    /**
     * Address: 0x00718F30 (FUN_00718F30, gpg::RVectorType_InfluenceGrid::IsIndexed)
     *
     * What it does:
     * Returns the `gpg::RIndexed` subobject (`this ? this + 0x64 : nullptr`).
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    void Init() override;

    /**
     * Address: 0x00718FA0 (FUN_00718FA0, gpg::RVectorType_InfluenceGrid::SubscriptIndex)
     *
     * What it does:
     * Wraps `&vec[ind]` (stride 0x8C) as one `gpg::RRef_InfluenceGrid` reference.
     */
    [[nodiscard]] gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00718F40 (FUN_00718F40, gpg::RVectorType_InfluenceGrid::GetCount)
     *
     * What it does:
     * Returns `(last - first) / sizeof(InfluenceGrid)`, or 0 for an empty lane.
     */
    [[nodiscard]] std::size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00718F70 (FUN_00718F70, gpg::RVectorType_InfluenceGrid::SetCount)
     *
     * What it does:
     * Resizes the reflected `vector<InfluenceGrid>` to `count`, filling any
     * appended cells with a default-constructed `InfluenceGrid`.
     */
    void SetCount(void* obj, int count) const override;
  };
  static_assert(sizeof(RVectorType_InfluenceGrid) == 0x68, "RVectorType_InfluenceGrid size must be 0x68");

  /**
   * VFTABLE (gpg::RIndexed subobject @ +0x64): 0x00E31890
   *   ??_7?$RVectorType@USThreat@Moho@@@gpg@@6BRIndexed@gpg@@@
   *   +0x00 SubscriptIndex   0x00719300
   *   +0x04 GetCount         0x007192B0
   *   +0x08 SetCount         0x007192E0
   *   +0x0C AssignPointer    0x00401320 (inherited gpg::RIndexed base impl)
   */
  class RVectorType_SThreat final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0071DD60 (FUN_0071DD60, gpg::RVectorType_SThreat::dtr)
     */
    ~RVectorType_SThreat() override = default;

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

    /**
     * Address: 0x007192A0 (FUN_007192A0, gpg::RVectorType_SThreat::IsIndexed)
     *
     * What it does:
     * Returns the `gpg::RIndexed` subobject (`this ? this + 0x64 : nullptr`).
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    void Init() override;

    /**
     * Address: 0x00719300 (FUN_00719300, gpg::RVectorType_SThreat::SubscriptIndex)
     *
     * What it does:
     * Wraps `&vec[ind]` (stride 0x38) as one `gpg::RRef_SThreat` reference.
     */
    [[nodiscard]] gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x007192B0 (FUN_007192B0, gpg::RVectorType_SThreat::GetCount)
     *
     * What it does:
     * Returns `(last - first) / sizeof(SThreat)`, or 0 for an empty lane.
     */
    [[nodiscard]] std::size_t GetCount(void* obj) const override;

    /**
     * Address: 0x007192E0 (FUN_007192E0, gpg::RVectorType_SThreat::SetCount)
     *
     * What it does:
     * Resizes the reflected `vector<SThreat>` to `count`, filling any appended
     * cells with a zeroed `SThreat` (0x00719820 -> `ResizeSThreatVectorWithZeroFill`).
     */
    void SetCount(void* obj, int count) const override;
  };
  static_assert(sizeof(RVectorType_SThreat) == 0x68, "RVectorType_SThreat size must be 0x68");
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

    if (source->mConstDat.mArmyIndex < 0) {
      return false;
    }

    return owner->mVarDat.mAllies.Contains(static_cast<std::uint32_t>(source->mConstDat.mArmyIndex));
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
  void UpdateMd5ContextWordAtOffset50(
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
  [[nodiscard]] gpg::RType* CachedUIntIntMapTypeLegacyLane()
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
  [[nodiscard]] gpg::RType* CachedInfluenceGridVectorTypeLegacyLane()
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
  void DeserializeInfluenceGridRecord(
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
  void SerializeInfluenceGridRecord(
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
  void DeserializeInfluenceGridRecordCallbackThunk(
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
  void SerializeInfluenceGridRecordCallbackThunk(
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
  RRefPairRuntime* BuildCInfluenceMapRRefPair(
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
  RRefPairRuntime* BuildInfluenceGridRRefPair(
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
  RRefPairRuntime* BuildSThreatRRefPair(
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
  void DeserializeInfluenceMapEntryRecordCallbackThunk(
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
  void SerializeInfluenceMapEntryRecordCallbackThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SerializeInfluenceMapEntryRecord(archive, objectPtr, version, ownerRef);
  }

  // Addresses 0x007189D0/0x0071A0C0 (the "ThunkA"/"ThunkB" iterator-advance
  // duplicates formerly modeled here) are dead: zero data_refs/call_edges
  // for both, and no source-level caller anywhere in src/sdk/**.
  // AdvanceInfluenceEntryIterator above is the real body, used directly by
  // EraseInfluenceEntryAndAdvance and DestroyInfluenceEntryRange below
  // (both confirmed real via multiple binary callers).

  // Address 0x0071A060 (the "ThunkA" iterator-advance duplicate formerly
  // modeled here) is dead: zero data_refs/call_edges and no source-level
  // caller anywhere in src/sdk/**. AdvanceBlipCellIterator above is the
  // real body, used directly by EraseBlipCellRange below (confirmed real
  // via multiple binary callers).

  /**
   * Address: 0x0071C750 (FUN_0071C750)
   *
   * What it does:
   * Allocates one fixed `0x40`-byte runtime node lane.
   */
  void* AllocateSingle64ByteNode() { return ::operator new(0x40u); }

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

  /**
   * Address: 0x0071C830 (FUN_0071C830, TNode=InfluenceNodeFlag61Runtime
   * instantiation -- isNil@+0x3D matches this type's own
   * offsetof(InfluenceNodeFlag61Runtime, isNil61) static_assert above.
   * Branch-for-branch match: nil-node right-child fast path, then the
   * left-child-nil parent-walk predecessor search, then the
   * leftmost-of-right-subtree descent. Reached from
   * StepRbIteratorNil61BackwardLaneA/B's `RetreatRuntimeRbIteratorSlot`
   * call above.)
   * Address: 0x0071C7D0 (FUN_0071C7D0, TNode=InfluenceNodeFlag21Runtime
   * instantiation -- isNil@+0x15 matches this type's own
   * offsetof(InfluenceNodeFlag21Runtime, isNil21) static_assert above.
   * Same branch-for-branch shape as 0x0071C830. Reached from
   * StepRbIteratorNil21BackwardLaneA's `RetreatRuntimeRbIteratorSlot`
   * call at 0x0071BD70.)
   */
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
   * Address: 0x0071BDB0 (FUN_0071BDB0)
   *
   * What it does:
   * Advances one nil-21 red-black iterator slot in place and returns the
   * same slot pointer.
   */
  InfluenceNodeFlag21Runtime** AdvanceRbIteratorNil21InPlaceLaneA(
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
  InfluenceNodeFlag21Runtime** PostAdvanceRbIteratorNil21CopyLaneA(
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
  InfluenceNodeFlag61Runtime** PostAdvanceRbIteratorNil61CopyLaneA(
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
  InfluenceNodeFlag21Runtime** StepRbIteratorNil21BackwardLaneA(
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
  InfluenceNodeFlag21Runtime** StepRbIteratorNil21BackwardLaneB(
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
  InfluenceNodeFlag61Runtime** StepRbIteratorNil61BackwardLaneA(
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
  InfluenceNodeFlag61Runtime** StepRbIteratorNil61BackwardLaneB(
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
  InfluenceNodeFlag61Runtime* FindInfluenceTreeRightmostNodeFlag61(
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
  InfluenceNodeFlag61Runtime* FindInfluenceTreeLeftmostNodeFlag61(
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
  InfluenceNodeFlag21Runtime* FindInfluenceTreeRightmostNodeFlag21(
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
  InfluenceNodeFlag21Runtime* FindInfluenceTreeLeftmostNodeFlag21(
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
   * Address: 0x0071A330 (FUN_0071A330, sub_71A330)
   *
   * What it does:
   * Loads one reflected `vector<InfluenceGrid>` payload from archive lanes.
   * The binary never resizes the destination in place: it reads the element
   * count (`ReadUInt` through vtable slot +0x20 at 0x0071A378), reserves that
   * many slots on a stack-local scratch vector (0x0071A383 -> FUN_0071B730),
   * appends every element to the scratch through `push_back` (0x0071A3E9 ->
   * FUN_00718810), and only then swaps the scratch's `{first,last,end}` lanes
   * into the destination (0x0071A44E/0x0071A458/0x0071A45F). The destination's
   * previous buffer is destroyed and freed afterwards, by the scratch vector's
   * scope-exit teardown (0x0071A477/0x0071A47D).
   */
  void LoadInfluenceGridVectorArchive(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
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

    // Instantiates `msvc8::vector<InfluenceGrid>::reserve` (FUN_0071B730).
    InfluenceGridVector loaded;
    loaded.reserve(count);

    for (unsigned int i = 0; i < count; ++i) {
      moho::InfluenceGrid element;

      // The binary re-reads the lazily initialised `Moho::InfluenceGrid::sType`
      // global on every iteration (0x0071A3AB), so the lookup stays in-loop.
      gpg::RType* const valueType = CachedInfluenceGridType();
      GPG_ASSERT(valueType != nullptr);

      // 0x0071A3B2/0x0071A3B6 zero a fresh `RRef` per element — the owner
      // reference handed to this serLoad callback is deliberately not forwarded.
      const gpg::RRef elementOwner{};
      archive->Read(valueType, &element, elementOwner);

      loaded.push_back(element);
    }

    vectorObject->swap(loaded);
  }

  /**
   * Address: 0x0071A4A0 (FUN_0071A4A0)
   *
   * What it does:
   * Serializes one reflected `vector<InfluenceGrid>` payload by writing count
   * and then each `InfluenceGrid` element lane.
   */
  void SaveInfluenceGridVectorArchive(
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
  /**
   * Address: 0x0071A6F0 (FUN_0071A6F0, sub_71A6F0)
   *
   * IDA signature:
   * void __cdecl sub_71A6F0(gpg::ReadArchive* archive, _DWORD* storage);
   *
   * What it does:
   * Load mirror of `SaveSThreatVectorArchive`: reads the element count,
   * reserves, then reads that many reflected `SThreat` values and replaces the
   * destination vector's contents. Each element is read against a fresh empty
   * owner reference rather than the caller's.
   */
  void LoadSThreatVectorArchive(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const vectorObject = PointerFromArchiveInt<SThreatVector>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vectorObject != nullptr);
    if (!archive || !vectorObject) {
      return;
    }

    unsigned int count = 0u;
    archive->ReadUInt(&count);

    SThreatVector loaded{};
    loaded.reserve(static_cast<std::size_t>(count));

    gpg::RType* const valueType = CachedSThreatType();
    GPG_ASSERT(valueType != nullptr);
    if (!valueType) {
      return;
    }

    for (unsigned int i = 0u; i < count; ++i) {
      moho::SThreat value{};
      const gpg::RRef elementOwner{};
      archive->Read(valueType, &value, elementOwner);
      loaded.push_back(value);
    }

    *vectorObject = loaded;
  }

  void SaveSThreatVectorArchive(
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
   * Address: 0x0071C6C0 (FUN_0071C6C0, sub_71C6C0)
   * Address: 0x0071C9A0 (FUN_0071C9A0, msvc8::_Tree<InfluenceMapEntry>::_Copy)
   *
   * What it does:
   * Clones one `InfluenceGrid::entries` ordered-set tree into destination
   * storage, preserving ordered contents and node count.
   *
   * The binary used the MSVC8 `_Tree::_Copy` recursive clone helper
   * (FUN_0071C9A0) to walk the source tree depth-first and rebuild
   * matching links in the destination. The recovered version expresses
   * the same role via the legacy set's iterator + per-entry
   * `destination.insert(*it)` path, which the modern compiler emits
   * as its own per-entry insert chain. The recursive `_Tree::_Copy`
   * template emission is therefore absorbed by the iterator-based
   * clone — observable behavior is identical (destination ends up with
   * the same ordered contents and node count), and the per-T template
   * emission symbol shape is preserved through the named outer helper.
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
   * Address: 0x007181A0 (FUN_007181A0, sub_7181A0)
   *
   * What it does:
   * Returns one lower-bound iterator in `grid.entries` for `entityId`.
   */
  [[nodiscard]] InfluenceEntryIterator FindInfluenceEntryLowerBoundByEntityId(
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
   * Address: 0x00716110 (FUN_00716110)
   *
   * What it does:
   * Adapts one linear cell index into `(x, z)` and forwards to
   * `CInfluenceMap::GetThreatRect`.
   */
  float GetThreatRectByLinearCellIndex(
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
  void DeleteInfluenceMapRuntimeStoragePrimary(void* const storage) noexcept
  {
    ::operator delete(storage);
  }

  /**
   * Address: 0x00719D90 (FUN_00719D90)
   *
   * What it does:
   * Secondary delete-thunk lane for influence-map runtime storage.
   */
  void DeleteInfluenceMapRuntimeStorageSecondary(void* const storage) noexcept
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
 * Address: 0x0071D9E0 (FUN_0071D9E0, preregister_RVectorType_InfluenceGrid)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `std::vector<moho::InfluenceGrid>`.
 * The binary also installs the `gpg::RIndexed` subobject vtable
 * (`dword_1106A6C`) at this address; the `static gpg::RVectorType_InfluenceGrid
 * typeInfo` global's own (compiler-generated) constructor reproduces that
 * side effect, since the class inherits both `gpg::RType` and `gpg::RIndexed`.
 * Reached from `sub_BDA840` (`.CRT$XCL`/`__xc_a` static-init table), matching
 * the `preregister_RMapType_uint_InfluenceMapEntry` reachability shape above.
 */
[[nodiscard]] gpg::RType* preregister_RVectorType_InfluenceGrid()
{
  static gpg::RVectorType_InfluenceGrid typeInfo;
  gpg::PreRegisterRType(typeid(InfluenceGridVector), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x0071DAB0 (FUN_0071DAB0, preregister_RVectorType_SThreat)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `std::vector<moho::SThreat>`. The
 * binary also installs the `gpg::RIndexed` subobject vtable (`dword_1106A04`)
 * at this address; the `static gpg::RVectorType_SThreat typeInfo` global's own
 * (compiler-generated) constructor reproduces that side effect, the same
 * simplification as `preregister_RVectorType_InfluenceGrid` above. Reached
 * from `sub_BDA880` (`.CRT$XCL`/`__xc_a` static-init table).
 */
[[nodiscard]] gpg::RType* preregister_RVectorType_SThreat()
{
  static gpg::RVectorType_SThreat typeInfo;
  gpg::PreRegisterRType(typeid(SThreatVector), &typeInfo);
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
 * Address: 0x00718F30 (FUN_00718F30, gpg::RVectorType_InfluenceGrid::IsIndexed)
 *
 * IDA signature:
 * gpg::RIndexed *__thiscall gpg::RVectorType_InfluenceGrid::IsIndexed(
 *     gpg::RVectorType_InfluenceGrid *this);
 *
 * What it does:
 * Returns the `gpg::RIndexed` subobject at `this + 0x64`.
 */
const gpg::RIndexed* gpg::RVectorType_InfluenceGrid::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00718FA0 (FUN_00718FA0, gpg::RVectorType_InfluenceGrid::SubscriptIndex)
 * VFTable SLOT: gpg::RIndexed +0x00 (??_7?$RVectorType@UInfluenceGrid@Moho@@@gpg@@6BRIndexed@gpg@@@ @ 0x00E3181C)
 *
 * IDA signature:
 * gpg::RRef *__userpurge gpg::RVectorType_InfluenceGrid::SubscriptIndex(
 *     gpg::RRef *result, void *obj, int ind);
 *
 * What it does:
 * Forms `&vec[ind]` as `first + ind * 0x8C` (0x00718FA8/0x00718FAE) and wraps
 * it as one `gpg::RRef_InfluenceGrid` reference, returned by value.
 */
gpg::RRef gpg::RVectorType_InfluenceGrid::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<InfluenceGridVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(storage != nullptr && static_cast<std::size_t>(ind) < storage->size());

  gpg::RRef out{};
  if (!storage || ind < 0) {
    (void)gpg::RRef_InfluenceGrid(&out, nullptr);
    return out;
  }

  (void)gpg::RRef_InfluenceGrid(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x00718F40 (FUN_00718F40, gpg::RVectorType_InfluenceGrid::GetCount)
 * VFTable SLOT: gpg::RIndexed +0x04 (0x00E31820)
 *
 * IDA signature:
 * unsigned int __userpurge gpg::RVectorType_InfluenceGrid::GetCount(void *obj);
 *
 * What it does:
 * Returns `(last - first) / 0x8C`, short-circuiting to 0 when the lane has no
 * storage (0x00718F47).
 */
std::size_t gpg::RVectorType_InfluenceGrid::GetCount(void* const obj) const
{
  if (!obj) {
    return 0u;
  }

  return static_cast<const InfluenceGridVector*>(obj)->size();
}

/**
 * Address: 0x00718F70 (FUN_00718F70, gpg::RVectorType_InfluenceGrid::SetCount)
 * VFTable SLOT: gpg::RIndexed +0x08 (0x00E31824)
 *
 * IDA signature:
 * void __userpurge gpg::RVectorType_InfluenceGrid::SetCount(void *obj, int count);
 *
 * What it does:
 * Default-constructs one `Moho::InfluenceGrid` in the caller frame
 * (0x00718F81) and resizes the reflected `vector<InfluenceGrid>` to `count`
 * with that grid as the fill value, passing it by value to the resize lane
 * (0x00718F94 -> FUN_0071B860).
 */
void gpg::RVectorType_InfluenceGrid::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<InfluenceGridVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count), moho::InfluenceGrid{});
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
  size_ = sizeof(SThreatVector);
  version_ = 1;
  serLoadFunc_ = &LoadSThreatVectorArchive;
  serSaveFunc_ = &SaveSThreatVectorArchive;
}

/**
 * Address: 0x007192A0 (FUN_007192A0, gpg::RVectorType_SThreat::IsIndexed)
 *
 * IDA signature:
 * gpg::RIndexed *__thiscall gpg::RVectorType_SThreat::IsIndexed(
 *     gpg::RVectorType_SThreat *this);
 *
 * What it does:
 * Returns the `gpg::RIndexed` subobject at `this + 0x64`.
 */
const gpg::RIndexed* gpg::RVectorType_SThreat::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00719300 (FUN_00719300, gpg::RVectorType_SThreat::SubscriptIndex)
 * VFTable SLOT: gpg::RIndexed +0x00 (??_7?$RVectorType@USThreat@Moho@@@gpg@@6BRIndexed@gpg@@@ @ 0x00E31890)
 *
 * IDA signature:
 * gpg::RRef *__userpurge gpg::RVectorType_SThreat::SubscriptIndex(
 *     gpg::RRef *result, void *obj, int ind);
 *
 * What it does:
 * Forms `&vec[ind]` as `first + ind * 0x38` and wraps it as one
 * `gpg::RRef_SThreat` reference, returned by value.
 */
gpg::RRef gpg::RVectorType_SThreat::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<SThreatVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(storage != nullptr && static_cast<std::size_t>(ind) < storage->size());

  gpg::RRef out{};
  if (!storage || ind < 0) {
    (void)gpg::RRef_SThreat(&out, nullptr);
    return out;
  }

  (void)gpg::RRef_SThreat(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x007192B0 (FUN_007192B0, gpg::RVectorType_SThreat::GetCount)
 * VFTable SLOT: gpg::RIndexed +0x04 (0x00E31894)
 *
 * IDA signature:
 * unsigned int __userpurge gpg::RVectorType_SThreat::GetCount(void *obj);
 *
 * What it does:
 * Returns `(last - first) / 0x38`, short-circuiting to 0 when the lane has no
 * storage.
 */
std::size_t gpg::RVectorType_SThreat::GetCount(void* const obj) const
{
  if (!obj) {
    return 0u;
  }

  return static_cast<const SThreatVector*>(obj)->size();
}

/**
 * Address: 0x007192E0 (FUN_007192E0, gpg::RVectorType_SThreat::SetCount)
 * VFTable SLOT: gpg::RIndexed +0x08 (0x00E31898)
 *
 * IDA signature:
 * void __userpurge gpg::RVectorType_SThreat::SetCount(void *obj, int count);
 *
 * What it does:
 * Tail-calls 0x00719820 (`ResizeSThreatVectorWithZeroFill`), which resizes
 * the reflected `vector<SThreat>` to `count`, filling any appended cells with
 * a zero-initialized `SThreat`.
 */
void gpg::RVectorType_SThreat::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<SThreatVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count), moho::SThreat{});
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
  /**
   * Address: 0x00BFFCD0 (FUN_00BFFCD0, cleanup_imap_debug_ConAliasDef)
   *
   * What it does:
   * Tears down startup-owned alias payload for `imap_debug`.
   */
  void cleanup_imap_debug_ConAliasDef()
  {
    ConAlias_imap_debug().ShutdownRecovered();
  }

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
    (void)std::atexit(&cleanup_imap_debug_ConAliasDef);
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
  /**
   * Address: 0x00BFFD30 (FUN_00BFFD30, cleanup_imap_debug_grid_ConAliasDef)
   *
   * What it does:
   * Tears down startup-owned alias payload for `imap_debug_grid`.
   */
  void cleanup_imap_debug_grid_ConAliasDef()
  {
    ConAlias_imap_debug_grid().ShutdownRecovered();
  }

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
    (void)std::atexit(&cleanup_imap_debug_grid_ConAliasDef);
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
  /**
   * Address: 0x00BFFD90 (FUN_00BFFD90, cleanup_imap_debug_path_graph_ConAliasDef)
   *
   * What it does:
   * Tears down startup-owned alias payload for `imap_debug_path_graph`.
   */
  void cleanup_imap_debug_path_graph_ConAliasDef()
  {
    ConAlias_imap_debug_path_graph().ShutdownRecovered();
  }

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
    (void)std::atexit(&cleanup_imap_debug_path_graph_ConAliasDef);
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
  /**
   * Address: 0x00BFFDF0 (FUN_00BFFDF0, cleanup_imap_debug_grid_type_ConAliasDef)
   *
   * What it does:
   * Tears down startup-owned alias payload for `imap_debug_grid_type`.
   */
  void cleanup_imap_debug_grid_type_ConAliasDef()
  {
    ConAlias_imap_debug_grid_type().ShutdownRecovered();
  }

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
    (void)std::atexit(&cleanup_imap_debug_grid_type_ConAliasDef);
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
  /**
   * Address: 0x00BFFE50 (FUN_00BFFE50, cleanup_imap_debug_grid_army_ConAliasDef)
   *
   * What it does:
   * Tears down startup-owned alias payload for `imap_debug_grid_army`.
   */
  void cleanup_imap_debug_grid_army_ConAliasDef()
  {
    ConAlias_imap_debug_grid_army().ShutdownRecovered();
  }

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
    (void)std::atexit(&cleanup_imap_debug_grid_army_ConAliasDef);
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

  struct SThreatMoveOwnerRuntime
  {
    SThreat* activeEnd;            // +0x00
    SThreat* moveDestinationBegin; // +0x04
    SThreat* moveSourceBegin;      // +0x08
  };
  static_assert(sizeof(SThreatMoveOwnerRuntime) == 0x0C, "SThreatMoveOwnerRuntime size must be 0x0C");

  /**
   * Address: 0x0071CD70 (FUN_0071CD70)
   *
   * What it does:
   * Serializes the 14 contiguous `float` lanes of one `SThreat` record.
   */
  void SerializeSThreatFloatLanesRaw(gpg::WriteArchive* const archive, const SThreat* const threat)
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
  void SerializeSThreatFields(gpg::WriteArchive* const archive, const SThreat& threat)
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
   * Address: 0x00715030 (FUN_00715030, ??0InfluenceGrid@Moho@@QAE@@Z)
   *
   * The binary does not delegate `entries`' construction to a nested
   * `map<uint32_t,InfluenceMapEntry>` default ctor -- it inlines the
   * equivalent directly: `sub_71C2C0()` (FUN_0071C2C0, the checked
   * allocate-and-default-init emission for this tree's node, isNil=0/
   * color=1) is called, then this ctor overwrites `isNil` to 1 at +0x3D
   * and self-links `_Parent`/`_Left`/`_Right` to promote the fresh node
   * into the sentinel head -- the same buy_head()-equivalent inline
   * promotion pattern seen on `CAiFormationInstance.cpp`'s
   * `InitializeDefaultFormationLaneEntry`/`InitializeLaneEntryMapAndCloneSource`
   * for their own hand-rolled node type. `entries()`'s member-init syntax
   * here reaches the same final state (empty tree, self-linked isNil=1
   * head) that the binary's inline sequence produces.
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
   * Address: 0x0071C150 (FUN_0071C150, Moho::InfluenceGrid::Cpy)
   *
   * IDA signature:
   * Moho::InfluenceGrid *__stdcall Moho::InfluenceGrid::Cpy(
   *     Moho::InfluenceGrid *dst, Moho::InfluenceGrid *src);
   *
   * What it does:
   * Copy-constructs one grid from `other`:
   *   1) `entries()` below builds the sentinel-only ordered-set header that the
   *      binary creates at the head of `CopyConstructInfluenceGridEntries`
   *      (0x0071C1F0, called at 0x0071C173), and the clone loop in the body is
   *      that helper's second half;
   *   2) `threats(other.threats)` is the `vector_SThreat::Cpy` call at
   *      0x0071C187 (allocate matching storage, copy the live range);
   *   3) the aggregate `threat` / `decay` lanes are the two 56-byte
   *      `rep movsd` blocks at 0x0071C192 and 0x0071C19F.
   *
   * This is the element copy lane the `msvc8::vector<InfluenceGrid>` growth and
   * fill paths use (`_Insert_n` at FUN_0071B970 takes its `_Tmp` copy through
   * it at 0x0071B9A2).
   * Address: 0x0071EE20 (FUN_0071EE20 -- `InfluenceGrid::InfluenceGrid(const InfluenceGrid&)` -- member-wise copy of the entry set and the threat vector; zero callers, unreachable; formerly `CopyConstructInfluenceGridIfPresentPrimary` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071F770 (FUN_0071F770 -- `InfluenceGrid::InfluenceGrid(const InfluenceGrid&)` (second copy); zero callers, unreachable; formerly `CopyConstructInfluenceGridIfPresentSecondary` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071AA60 (FUN_0071AA60 -- the entry-set half of `InfluenceGrid`'s copy constructor; callers 0x00715440, 0x00716140, 0x00716350; formerly `CopyInfluenceGridEntries` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071C1F0 (FUN_0071C1F0 -- the entry-set half of `InfluenceGrid`'s copy constructor (the placement-new form); callers 0x0071C150, 0x0071C1E0; formerly `CopyConstructInfluenceGridEntries` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
   */
  InfluenceGrid::InfluenceGrid(const InfluenceGrid& other)
    : entries()
    , threats(other.threats)
    , threat(other.threat)
    , decay(other.decay)
  {
    CopyInfluenceEntryTreeStorage(entries, other.entries);
  }

  /**
   * Address: 0x00716350 (FUN_00716350, ??1InfluenceGrid@Moho@@QAE@@Z)
   * Address: 0x0071EE70 (FUN_0071EE70)
   * Address: 0x0071F7C0 (FUN_0071F7C0)
   * Address: 0x0071F7F0 (FUN_0071F7F0 -- `InfluenceGrid::~InfluenceGrid()` -- the entry set and the per-army threat vector released by their own destructors; zero callers, unreachable; formerly `DestroyInfluenceGridAndReturnSelf` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00719C00 (FUN_00719C00 -- the entry-set half of `InfluenceGrid`'s destructor; callers 0x00716140, 0x007163A0, 0x007186CC; formerly `DestroyInfluenceGridEntries` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
   */
  InfluenceGrid::~InfluenceGrid()
  {
    threats.clear();
    entries.clear();
  }

  /**
   * Address: 0x0071ED10 (FUN_0071ED10)
   *
   * What it does:
   * Assigns one initialized `InfluenceGrid` from another by replacing entry-map
   * and per-army threat-vector contents, then copying aggregate threat and decay
   * lanes. Preserves self-assignment semantics.
   */
  InfluenceGrid& AssignInfluenceGridValue(InfluenceGrid& destination, const InfluenceGrid& source)
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
  moho::InfluenceGrid* AssignInfluenceGridAndReturnDestinationPrimary(
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
  moho::InfluenceGrid* AssignInfluenceGridAndReturnDestinationSecondary(
    const moho::InfluenceGrid* const source,
    moho::InfluenceGrid* const destination
  )
  {
    return AssignInfluenceGridAndReturnDestinationPrimary(source, destination);
  }

  /**
   * Address: 0x0071D4B0 (FUN_0071D4B0, func_NewArray_SThreat)
   *
   * What it does:
   * Allocates contiguous storage for `count` `SThreat` elements with the same
   * overflow guard semantics as the original VC8 array-allocation helper.
   */
  static SThreat* func_NewArray_SThreat(const unsigned int count)
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
  static InfluenceGrid* func_NewArray_InfluenceMap(const unsigned int count)
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
  void DeleteSThreatArrayOrZeroSizeBlockThunk(void* const allocation) noexcept
  {
    ::operator delete(allocation);
  }

  /**
   * Address: 0x0071BD30 (FUN_0071BD30)
   *
   * What it does:
   * Releases one raw allocation lane with `operator delete`.
   */
  void DeleteInfluenceGridArrayOrZeroSizeBlockThunk(void* const allocation) noexcept
  {
    ::operator delete(allocation);
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
    threats.resize(armyCount, moho::SThreat{});
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
   * Address: 0x007171D0 (FUN_007171D0, ?GetThreatsAroundPosition@CInfluenceMap@Moho@@QBE?AV?$vector@USPositionThreat@Moho@@V?$allocator@USPositionThreat@Moho@@@std@@@std@@ABV?$Vector3@M@Wm3@@HH_NW4EThreatType@2@H@Z)
   *
   * IDA signature (corrected — the mis-recovered mangled form claimed a
   * `LuaObject*` return, but the binary fills a `vector<SPositionThreat>`):
   * vector<SPositionThreat>* __thiscall GetThreatsAroundPosition(
   *   CInfluenceMap *this, vector<SPositionThreat> *out, const Vector3f *pos,
   *   int ring, bool restrictToPlayable, EThreatType threatType, int army);
   *
   * What it does:
   * Iterates the grid cells within `ring` of the cell containing `pos`,
   * optionally clamped to the sim playable rect. For every cell with strictly
   * positive per-type threat it appends one `{worldX, 0.0f, worldZ, threat}`
   * record to `out` and folds `threat` (4 bytes) then `{worldX, 0, worldZ}`
   * (12 bytes) into the sim MD5 checksum context, matching the binary's two
   * `MD5Context::Update` calls at 0x71735F / 0x717377. Logs the final digest.
   */
  /**
   * Orders collected samples strongest-threat-first; the sort's emitted bodies
   * are cited on the `msvc8::sort` members in `legacy/algorithms/Sort.h`.
   */
  struct ThreatDescending
  {
    [[nodiscard]] bool operator()(const SPositionThreat& lhs, const SPositionThreat& rhs) const noexcept
    {
      return rhs.threat < lhs.threat;
    }
  };

  msvc8::vector<SPositionThreat>* CInfluenceMap::GetThreatsAroundPosition(
    msvc8::vector<SPositionThreat>& out,
    const Wm3::Vec3f& pos,
    const int ring,
    const bool restrictToPlayable,
    const EThreatType threatType,
    const int armyIndex
  ) const
  {
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

        const SPositionThreat sample{worldX, 0.0f, worldZ, threat};
        // push_back's capacity-full path is `msvc8::vector<SPositionThreat>::insert`
        // (FUN_0071BEE0), reached through the binary's push_back at FUN_00718A40.
        // `_Insert_n` (0071BEE0) itself calls FUN_0071A1F0 to relocate the
        // existing `[begin, insertPos)` run into the freshly-grown buffer: a
        // 16-byte-stride (`shl eax,4`) element-count loop that forwards to the
        // shared FPU-based 4-float block copy at FUN_0071E8E0, then returns
        // `dest + count*16` as the post-copy cursor -- the `uninit_copy_n`
        // sibling of `_Insert_n`'s own inline `_Tmp` fill for this 0x10-byte
        // `SPositionThreat` instantiation.
        out.push_back(sample);

        if (sim) {
          // Binary reuses the just-pushed stack record: Update(&threat, 4)
          // then Update(&{x,y,z}, 12) at 0x71735F / 0x717377.
          sim->mContext.Update(&sample.threat, sizeof(float));
          sim->mContext.Update(&sample.x, 3 * sizeof(float));
        }
      }
    }

    if (sim) {
      const gpg::MD5Digest digest = sim->mContext.Digest();
      const msvc8::string checksum = digest.ToString();
      sim->Logf("after GetThreatsAroundPosition checksum=%s\n", checksum.c_str());
    }

    // 0x0071E200 with `(begin, end, (end - begin) >> 4, <empty functor>)`: the
    // callers want the strongest threat first, so the samples leave sorted by
    // descending `threat`.
    msvc8::sort(out.begin(), out.end(), ThreatDescending{});

    return &out;
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

              const std::int32_t sourceArmyIndex = entry.sourceArmy ? entry.sourceArmy->mConstDat.mArmyIndex : -1;
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

        const std::int32_t sourceArmyIndex = entry.sourceArmy ? entry.sourceArmy->mConstDat.mArmyIndex : -1;
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

  /**
   * Absorbs binary helper:
   * Address: 0x00718360 (FUN_00718360, msvc8::map<uint32, cellIndex>::operator[])
   *
   * The binary's `CInfluenceMap::InsertEntry` used the
   * `msvc8::map<uint32, int32>::operator[]` template emission
   * (FUN_00718360) to find-or-default-insert a `blipId -> cellIndex`
   * lookup entry, then assigned the cell index to the returned slot.
   * The recovered `UpsertBlipCell` expresses the same role through
   * `mBlipCells` (a `set<InfluenceMapCellIndex>` keyed by entityId)
   * with a remove + insert pair, so the binary's `_Tree::operator[]`
   * template emission is absorbed by this named helper. The inner
   * insert helper FUN_00719AB0 (still blocked) corresponds to the
   * RB-tree allocate-and-link path inside the modern `insert(...)`
   * call.
   */
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
      // InfluenceGrid::RemoveEntry reports whether an entry was actually erased;
      // the binary ignores that result here and unconditionally drops the blip
      // cell below, so the discard is deliberate.
      (void)mMapEntries[static_cast<std::size_t>(cellIndex)].RemoveEntry(blipId);
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_RMapType_uint_int_9e247f, preregister_RMapType_uint_int)
GPG_PREREGISTER_INIT(preregister_RMapType_uint_InfluenceMapEntry_9e247f, preregister_RMapType_uint_InfluenceMapEntry)
GPG_PREREGISTER_INIT(preregister_RVectorType_InfluenceGrid_9e247f, preregister_RVectorType_InfluenceGrid)
GPG_PREREGISTER_INIT(preregister_RVectorType_SThreat_9e247f, preregister_RVectorType_SThreat)
