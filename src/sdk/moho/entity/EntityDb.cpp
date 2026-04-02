#include "EntityDb.h"

#include <cstdlib>
#include <initializer_list>
#include <list>
#include <limits>
#include <map>
#include <new>
#include <typeinfo>
#include <unordered_map>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/Reflection.h"
#include "Entity.h"
#include "legacy/containers/Tree.h"
#include "moho/containers/BVIntSet.h"
#include "moho/misc/StatItem.h"
#include "moho/sim/IdPool.h"
#include "moho/unit/core/Unit.h"

namespace
{
  // Packed EntId layout used by family/source allocation:
  // [31..28]=family, [27..20]=source index, [19..0]=serial.
  constexpr moho::EEntityIdBitMask kEntityIdFamilySourceMask =
    moho::EEntityIdBitMask::Family | moho::EEntityIdBitMask::Source;
  constexpr std::uint32_t kEntityIdFamilySourceMaskRaw = moho::ToMask(kEntityIdFamilySourceMask);
  constexpr std::uint32_t kEntityIdSerialMask = moho::ToMask(moho::EEntityIdBitMask::Serial);
  constexpr std::uint32_t kEntityIdSourceShift = moho::kEntityIdSourceShift;
  constexpr std::uint32_t kAllUnitsUnitTypeBoundaryKey = moho::ToRaw(moho::EEntityIdSentinel::FirstNonUnitFamily);

  struct IdPoolRuntime
  {
    // Corresponds to the sequential `(*v3)++` path in 0x00684480.
    std::uint32_t mNextSerial = 1u;
    // Corresponds to `(BVIntSet*)(v3 + 2)` in 0x00684480.
    moho::BVIntSet mReleasedSerials{};
    bool mSeededFromEntityDb = false;
  };

  using FamilyPoolMap = std::unordered_map<std::uint32_t, IdPoolRuntime>;
  std::unordered_map<const moho::CEntityDb*, FamilyPoolMap> gRuntimePools;
  std::unordered_map<const moho::CEntityDb*, msvc8::list<moho::Entity*>> gRuntimeEntityLists;
  moho::EntityDBSerializer gEntityDBSerializer;
  constexpr std::uint32_t kEntityIdInvalidSentinel = moho::ToRaw(moho::EEntityIdSentinel::Invalid);
  moho::StatItem* sEngineStat_EntityCount = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Prop = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Unit = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Blip = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Other = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Projectile = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Shield = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Unknown = nullptr;

  [[nodiscard]] moho::StatItem* EnsureEntityCountStatSlot(moho::StatItem*& slot, const char* const statPath)
  {
    if (slot) {
      return slot;
    }

    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (!engineStats) {
      return nullptr;
    }

    slot = engineStats->GetItem(statPath, true);
    if (slot) {
      (void)slot->Release(0);
    }
    return slot;
  }

  void AddEntityCountStat(moho::StatItem*& slot, const char* const statPath, const std::uint32_t delta) noexcept
  {
    moho::StatItem* const statItem = EnsureEntityCountStatSlot(slot, statPath);
    if (!statItem) {
      return;
    }

#if defined(_WIN32)
    ::InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), static_cast<long>(delta));
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  /**
   * Address: 0x00684030 (FUN_00684030, func_EngineStats_ChngEntityCount)
   *
   * What it does:
   * Updates engine entity-count stat lanes for one packed entity id family.
   */
  void UpdateEntityCountStats(const std::uint32_t entityId, const std::uint32_t delta)
  {
    AddEntityCountStat(sEngineStat_EntityCount, "EntityCount", delta);

    switch ((entityId >> moho::kEntityIdFamilyShift) & 0xFu) {
    case 0u:
      AddEntityCountStat(sEngineStat_EntityCount_Unit, "EntityCount_Unit", delta);
      break;
    case 1u:
      AddEntityCountStat(sEngineStat_EntityCount_Projectile, "EntityCount_Projectile", delta);
      break;
    case 2u:
      AddEntityCountStat(sEngineStat_EntityCount_Prop, "EntityCount_Prop", delta);
      break;
    case 3u:
      AddEntityCountStat(sEngineStat_EntityCount_Blip, "EntityCount_Blip", delta);
      break;
    case 4u:
      AddEntityCountStat(sEngineStat_EntityCount_Shield, "EntityCount_Shield", delta);
      break;
    case 5u:
      AddEntityCountStat(sEngineStat_EntityCount_Other, "EntityCount_Other", delta);
      break;
    default:
      AddEntityCountStat(sEngineStat_EntityCount_Unknown, "EntityCount_Unknown", delta);
      break;
    }
  }

  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdType()
  {
    static gpg::RType* sEntIdType = nullptr;
    if (!sEntIdType) {
      sEntIdType = ResolveTypeByAnyName({"EntId", "Moho::EntId", "int", "signed int"});
      if (!sEntIdType) {
        sEntIdType = gpg::LookupRType(typeid(int));
      }
    }
    return sEntIdType;
  }

  [[nodiscard]] gpg::RType* ResolveEntityType()
  {
    static gpg::RType* sEntityType = nullptr;
    if (!sEntityType) {
      sEntityType = ResolveTypeByAnyName({"Entity", "Moho::Entity"});
      if (!sEntityType) {
        sEntityType = gpg::LookupRType(typeid(moho::Entity));
      }
    }
    return sEntityType;
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetBaseType()
  {
    static gpg::RType* sEntitySetBaseType = nullptr;
    if (!sEntitySetBaseType) {
      sEntitySetBaseType = ResolveTypeByAnyName({"EntitySetBase", "Moho::EntitySetBase"});
    }
    return sEntitySetBaseType;
  }

  [[nodiscard]] gpg::RType* ResolveEntityDbType()
  {
    static gpg::RType* sEntityDbType = nullptr;
    if (!sEntityDbType) {
      sEntityDbType = ResolveTypeByAnyName({"EntityDB", "CEntityDB", "Moho::EntityDB"});
      if (!sEntityDbType) {
        sEntityDbType = gpg::LookupRType(typeid(moho::CEntityDb));
      }
    }
    return sEntityDbType;
  }

  [[nodiscard]] gpg::RRef NullOwnerRef() noexcept
  {
    return {};
  }

  [[nodiscard]] bool ContainsEntityPointer(const msvc8::list<moho::Entity*>& entities, const moho::Entity* const entity) noexcept
  {
    for (const moho::Entity* const current : entities) {
      if (current == entity) {
        return true;
      }
    }
    return false;
  }

  void TrackEntityPointer(msvc8::list<moho::Entity*>& entities, moho::Entity* const entity)
  {
    if (!entity || ContainsEntityPointer(entities, entity)) {
      return;
    }
    entities.push_back(entity);
  }

  [[nodiscard]] gpg::RRef MakeObjectRef(void* const object, gpg::RType* const type) noexcept
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = object ? type : nullptr;
    return ref;
  }

  [[nodiscard]] moho::Entity* ReadOwnedEntityPointer(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, NullOwnerRef());
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const entityType = ResolveEntityType();
    if (!entityType || !tracked.type) {
      return static_cast<moho::Entity*>(tracked.object);
    }

    const gpg::RRef source = MakeObjectRef(tracked.object, tracked.type);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, entityType);
    return static_cast<moho::Entity*>(upcast.mObj ? upcast.mObj : tracked.object);
  }

  [[nodiscard]] moho::CEntityDbListHead* ReadEntitySetPointer(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, NullOwnerRef());
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expectedType = ResolveEntitySetBaseType();
    if (!expectedType || !tracked.type) {
      return static_cast<moho::CEntityDbListHead*>(tracked.object);
    }

    const gpg::RRef source = MakeObjectRef(tracked.object, tracked.type);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<moho::CEntityDbListHead*>(upcast.mObj ? upcast.mObj : tracked.object);
  }

  void EnsureSetListHeadInitialized(moho::CEntityDbListHead& head) noexcept
  {
    if (!head.next || !head.prev) {
      head.next = &head;
      head.prev = &head;
    }
  }

  void LinkSetNodeToFront(moho::CEntityDbListHead& head, moho::CEntityDbListHead* const node) noexcept
  {
    if (!node) {
      return;
    }

    EnsureSetListHeadInitialized(head);

    if (node->next && node->prev) {
      static_cast<moho::CEntityDbListHead*>(node->next)->prev = node->prev;
      static_cast<moho::CEntityDbListHead*>(node->prev)->next = node->next;
    }

    node->next = node;
    node->prev = node;

    node->next = head.next;
    node->prev = &head;
    static_cast<moho::CEntityDbListHead*>(head.next)->prev = node;
    head.next = node;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext && helper.mHelperPrev) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
    return self;
  }

  void cleanup_EntityDBSerializer_atexit()
  {
    (void)moho::cleanup_EntityDBSerializer();
  }

  [[nodiscard]] moho::CEntityDbAllUnitsNode*
  TreeLowerBound(moho::CEntityDbAllUnitsNode* const head, const std::uint32_t lowerBoundKey) noexcept
  {
    return msvc8::lower_bound_node<moho::CEntityDbAllUnitsNode, &moho::CEntityDbAllUnitsNode::isNil>(
      head, lowerBoundKey, [](const auto& node, const std::uint32_t key) {
      return node.key < key;
    }
    );
  }

  [[nodiscard]] moho::CEntityDbAllUnitsNode*
  NextNodeInAllUnitsTree(moho::CEntityDbAllUnitsNode* node) noexcept
  {
    if (node == nullptr || node->isNil != 0u) {
      return node;
    }

    moho::CEntityDbAllUnitsNode* childOrParent = node->right;
    if (childOrParent == nullptr) {
      return nullptr;
    }

    if (childOrParent->isNil != 0u) {
      for (moho::CEntityDbAllUnitsNode* next = node->parent; next != nullptr && next->isNil == 0u; next = next->parent) {
        if (node != next->right) {
          return next;
        }
        node = next;
      }
      return (node != nullptr) ? node->parent : nullptr;
    }

    moho::CEntityDbAllUnitsNode* next = childOrParent->left;
    while (next != nullptr && next->isNil == 0u) {
      childOrParent = next;
      next = next->left;
    }
    return childOrParent;
  }

  [[nodiscard]] bool
  IdExistsInList(const msvc8::list<moho::Entity*>& entities, const std::uint32_t entityIdCandidate) noexcept
  {
    for (const moho::Entity* const entity : entities) {
      if (!entity) {
        continue;
      }

      if (static_cast<std::uint32_t>(entity->id_) == entityIdCandidate) {
        return true;
      }
    }

    return false;
  }

  void SeedFamilyPoolFromEntities(
    const msvc8::list<moho::Entity*>& entities, const std::uint32_t familySourceBits, IdPoolRuntime& pool
  )
  {
    if (pool.mSeededFromEntityDb) {
      return;
    }

    std::uint32_t maxSerial = 0u;
    for (const moho::Entity* const entity : entities) {
      if (!entity) {
        continue;
      }

      const std::uint32_t entityId = static_cast<std::uint32_t>(entity->id_);
      if ((entityId & kEntityIdFamilySourceMaskRaw) != familySourceBits) {
        continue;
      }

      const std::uint32_t serial = entityId & kEntityIdSerialMask;
      if (serial > maxSerial) {
        maxSerial = serial;
      }
    }

    pool.mNextSerial = maxSerial + 1u;
    if ((pool.mNextSerial & kEntityIdSerialMask) == 0u) {
      pool.mNextSerial = 1u;
    }

    pool.mSeededFromEntityDb = true;
  }

  [[nodiscard]] std::uint32_t AllocateSerialFromFamilyPool(IdPoolRuntime& pool)
  {
    if (pool.mReleasedSerials.Buckets() != 0) {
      const std::uint32_t serial = pool.mReleasedSerials.GetNext(std::numeric_limits<std::uint32_t>::max());
      if (serial < pool.mReleasedSerials.Max() && pool.mReleasedSerials.Remove(serial)) {
        return serial;
      }
    }

    for (;;) {
      const std::uint32_t serial = (pool.mNextSerial++) & kEntityIdSerialMask;
      if (serial != 0u) {
        return serial;
      }
    }
  }

  class EntityDbTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "EntityDB";
    }

    void Init() override
    {
      size_ = sizeof(moho::CEntityDb);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(EntityDbTypeInfo) == 0x64, "EntityDbTypeInfo size must be 0x64");

  class EntityDbIdPoolMapTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "std::map<unsigned int,Moho::IdPool>";
    }

    void Init() override
    {
      size_ = sizeof(std::map<unsigned int, moho::IdPool>);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(EntityDbIdPoolMapTypeInfo) == 0x64, "EntityDbIdPoolMapTypeInfo size must be 0x64");

  class EntityDbEntityListTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "std::list<Moho::Entity *>";
    }

    void Init() override
    {
      size_ = sizeof(std::list<moho::Entity*>);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(EntityDbEntityListTypeInfo) == 0x64, "EntityDbEntityListTypeInfo size must be 0x64");

  alignas(EntityDbTypeInfo) std::byte gEntityDbTypeInfoStorage[sizeof(EntityDbTypeInfo)]{};
  bool gEntityDbTypeInfoConstructed = false;
  alignas(EntityDbIdPoolMapTypeInfo) std::byte gEntityDbIdPoolMapTypeInfoStorage[sizeof(EntityDbIdPoolMapTypeInfo)]{};
  bool gEntityDbIdPoolMapTypeInfoConstructed = false;
  alignas(EntityDbEntityListTypeInfo)
    std::byte gEntityDbEntityListTypeInfoStorage[sizeof(EntityDbEntityListTypeInfo)]{};
  bool gEntityDbEntityListTypeInfoConstructed = false;

  [[nodiscard]] EntityDbTypeInfo& AcquireEntityDbTypeInfo()
  {
    if (!gEntityDbTypeInfoConstructed) {
      new (gEntityDbTypeInfoStorage) EntityDbTypeInfo();
      gEntityDbTypeInfoConstructed = true;
    }
    return *reinterpret_cast<EntityDbTypeInfo*>(gEntityDbTypeInfoStorage);
  }

  [[nodiscard]] EntityDbIdPoolMapTypeInfo& AcquireEntityDbIdPoolMapTypeInfo()
  {
    if (!gEntityDbIdPoolMapTypeInfoConstructed) {
      new (gEntityDbIdPoolMapTypeInfoStorage) EntityDbIdPoolMapTypeInfo();
      gEntityDbIdPoolMapTypeInfoConstructed = true;
    }
    return *reinterpret_cast<EntityDbIdPoolMapTypeInfo*>(gEntityDbIdPoolMapTypeInfoStorage);
  }

  [[nodiscard]] EntityDbEntityListTypeInfo& AcquireEntityDbEntityListTypeInfo()
  {
    if (!gEntityDbEntityListTypeInfoConstructed) {
      new (gEntityDbEntityListTypeInfoStorage) EntityDbEntityListTypeInfo();
      gEntityDbEntityListTypeInfoConstructed = true;
    }
    return *reinterpret_cast<EntityDbEntityListTypeInfo*>(gEntityDbEntityListTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00683C90 (FUN_00683C90,
   * ?AllUnitsEnd@EntityDB@Moho@@QAE?AV?$Iterator@VUnit@Moho@@@EntityDBIterators@2@XZ)
   *
   * What it does:
   * Returns the first all-units tree node with key >= (`sourceIndex << 20`).
   */
  CEntityDbAllUnitsNode* CEntityDb::AllUnitsEnd(const std::uint32_t sourceIndex) const
  {
    return TreeLowerBound(mAllUnits, sourceIndex << kEntityIdSourceShift);
  }

  /**
   * Address: 0x00683D10 (FUN_00683D10,
   * ?AllUnitsEnd@EntityDB@Moho@@QAE?AV?$Iterator@VUnit@Moho@@@EntityDBIterators@2@XZ_0)
   *
   * What it does:
   * Returns the first all-units tree node at/after the first non-unit family boundary
   * (`EEntityIdSentinel::FirstNonUnitFamily`, value `0x10000000`).
   */
  CEntityDbAllUnitsNode* CEntityDb::AllUnitsEnd() const
  {
    return TreeLowerBound(mAllUnits, kAllUnitsUnitTypeBoundaryKey);
  }

  /**
   * Address: 0x005C87A0 (FUN_005C87A0, Moho::CUnitIterAllArmies::Next)
   */
  CEntityDbAllUnitsNode* CEntityDb::NextAllUnitsNode(CEntityDbAllUnitsNode* node) noexcept
  {
    return NextNodeInAllUnitsTree(node);
  }

  /**
   * Address: 0x005C87A0 callsite shape (Moho::CUnitIterAllArmies payload)
   */
  Unit* CEntityDb::UnitFromAllUnitsNode(const CEntityDbAllUnitsNode* const node) noexcept
  {
    if (node == nullptr || node->unitListNode == nullptr) {
      return nullptr;
    }

    auto* const entitySubobject = reinterpret_cast<Entity*>(node->unitListNode);
    return static_cast<Unit*>(entitySubobject);
  }

  /**
   * Address: 0x00684480 (FUN_00684480, ?DoReserveId@EntityDB@Moho@@AAE?AVEntId@2@I@Z)
   *
   * What it does:
   * Reserves a new entity id in the requested packed-id family/source key.
   */
  std::uint32_t CEntityDb::DoReserveId(const std::uint32_t requestedFamilySourceBits)
  {
    const std::uint32_t familySourceBits = requestedFamilySourceBits & kEntityIdFamilySourceMaskRaw;
    IdPoolRuntime& pool = gRuntimePools[this][familySourceBits];
    SeedFamilyPoolFromEntities(Entities(), familySourceBits, pool);

    for (std::uint32_t attempt = 0; attempt < kEntityIdSerialMask; ++attempt) {
      const std::uint32_t serial = AllocateSerialFromFamilyPool(pool);
      const std::uint32_t entityId = familySourceBits | serial;
      if (!IdExistsInList(Entities(), entityId)) {
        UpdateEntityCountStats(entityId, 1u);
        return entityId;
      }
    }

    // Family/source pool exhausted: preserve old fail-safe behavior and hand back +1 serial.
    const std::uint32_t fallbackEntityId = familySourceBits | 1u;
    UpdateEntityCountStats(fallbackEntityId, 1u);
    return fallbackEntityId;
  }

  msvc8::list<Entity*>& CEntityDb::Entities() noexcept
  {
    return gRuntimeEntityLists[this];
  }

  const msvc8::list<Entity*>& CEntityDb::Entities() const noexcept
  {
    const auto it = gRuntimeEntityLists.find(this);
    if (it != gRuntimeEntityLists.end()) {
      return it->second;
    }

    static const msvc8::list<Entity*> kEmpty{};
    return kEmpty;
  }

  void CEntityDb::RegisterEntitySet(SEntitySetTemplateUnit& set) noexcept
  {
    LinkSetNodeToFront(mRegisteredEntitySets, reinterpret_cast<CEntityDbListHead*>(&set));
  }

  /**
   * Address: 0x00684AA0 (FUN_00684AA0, Moho::EntityDB::SerEntities read lane)
   */
  void CEntityDb::SerEntities(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RType* const entIdType = ResolveEntIdType();
    if (!entIdType) {
      return;
    }

    msvc8::list<Entity*>& entities = Entities();
    for (;;) {
      std::uint32_t entityId = kEntityIdInvalidSentinel;
      archive->Read(entIdType, &entityId, NullOwnerRef());
      if (entityId == kEntityIdInvalidSentinel) {
        break;
      }

      Entity* const entity = ReadOwnedEntityPointer(archive);
      if (!entity) {
        continue;
      }

      entity->id_ = static_cast<EntId>(entityId);
      TrackEntityPointer(entities, entity);
    }
  }

  /**
   * Address: 0x006849C0 (FUN_006849C0, Moho::EntityDB::SerEntities write lane)
   */
  void CEntityDb::SerEntities(gpg::WriteArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RType* const entIdType = ResolveEntIdType();
    gpg::RType* const entityType = ResolveEntityType();
    if (!entIdType) {
      return;
    }

    for (Entity* const entity : Entities()) {
      if (!entity) {
        continue;
      }

      const std::uint32_t entityId = static_cast<std::uint32_t>(entity->id_);
      archive->Write(entIdType, &entityId, NullOwnerRef());
      gpg::WriteRawPointer(
        archive,
        MakeObjectRef(entity, entityType),
        gpg::TrackedPointerState::Owned,
        NullOwnerRef()
      );
    }

    const std::uint32_t sentinel = kEntityIdInvalidSentinel;
    archive->Write(entIdType, &sentinel, NullOwnerRef());
  }

  /**
   * Address: 0x00684B40 (FUN_00684B40, Moho::EntityDB::SerSets read lane)
   */
  void CEntityDb::SerSets(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    EnsureSetListHeadInitialized(mRegisteredEntitySets);
    for (;;) {
      CEntityDbListHead* const setNode = ReadEntitySetPointer(archive);
      if (!setNode) {
        break;
      }

      LinkSetNodeToFront(mRegisteredEntitySets, setNode);
    }
  }

  /**
   * Address: 0x00684BC0 (FUN_00684BC0, Moho::EntityDB::SerSets write lane)
   */
  void CEntityDb::SerSets(gpg::WriteArchive* const archive)
  {
    if (!archive) {
      return;
    }

    EnsureSetListHeadInitialized(mRegisteredEntitySets);
    gpg::RType* const setType = ResolveEntitySetBaseType();

    for (CEntityDbListHead* node = static_cast<CEntityDbListHead*>(mRegisteredEntitySets.next); node && node != &mRegisteredEntitySets;
         node = static_cast<CEntityDbListHead*>(node->next)) {
      gpg::WriteRawPointer(
        archive,
        MakeObjectRef(node, setType),
        gpg::TrackedPointerState::Unowned,
        NullOwnerRef()
      );
    }

    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(nullptr, setType),
      gpg::TrackedPointerState::Unowned,
      NullOwnerRef()
    );
  }

  /**
   * Address: 0x00689760 (FUN_00689760, Moho::EntityDB::MemberSerialize)
   */
  void CEntityDb::MemberSerialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    SerEntities(archive);

    if (gpg::RType* const idPoolMapType = ResolveTypeByAnyName({"std::map<unsigned int,Moho::IdPool>"})) {
      std::map<unsigned int, moho::IdPool> serializedIdPools;
      archive->Read(idPoolMapType, &serializedIdPools, NullOwnerRef());

      FamilyPoolMap& runtimePools = gRuntimePools[this];
      runtimePools.clear();
      for (const auto& [familySourceBits, serializedPool] : serializedIdPools) {
        IdPoolRuntime runtimePool{};
        runtimePool.mNextSerial =
          serializedPool.mNextLowId > 0 ? static_cast<std::uint32_t>(serializedPool.mNextLowId) : 1u;
        runtimePool.mReleasedSerials = serializedPool.mReleasedLows;
        runtimePool.mSeededFromEntityDb = true;
        runtimePools[familySourceBits] = runtimePool;
      }
    }

    SerSets(archive);

    if (gpg::RType* const entityListType = ResolveTypeByAnyName({"std::list<Moho::Entity *>"})) {
      std::list<Entity*> serializedEntities;
      archive->Read(entityListType, &serializedEntities, NullOwnerRef());

      msvc8::list<Entity*>& runtimeEntities = Entities();
      runtimeEntities.clear();
      for (Entity* const entity : serializedEntities) {
        TrackEntityPointer(runtimeEntities, entity);
      }
    }
  }

  /**
   * Address: 0x006897F0 (FUN_006897F0, Moho::EntityDB::MemberDeserialize)
   */
  void CEntityDb::MemberDeserialize(gpg::WriteArchive* const archive)
  {
    if (!archive) {
      return;
    }

    SerEntities(archive);

    if (gpg::RType* const idPoolMapType = ResolveTypeByAnyName({"std::map<unsigned int,Moho::IdPool>"})) {
      std::map<unsigned int, moho::IdPool> serializedIdPools;
      const auto poolsIt = gRuntimePools.find(this);
      if (poolsIt != gRuntimePools.end()) {
        for (const auto& [familySourceBits, runtimePool] : poolsIt->second) {
          moho::IdPool serializedPool{};
          serializedPool.mNextLowId = static_cast<std::int32_t>(runtimePool.mNextSerial);
          serializedPool.mReleasedLows = runtimePool.mReleasedSerials;
          auto [insertIt, inserted] = serializedIdPools.try_emplace(familySourceBits);
          moho::IdPool& destinationPool = insertIt->second;
          destinationPool.mNextLowId = serializedPool.mNextLowId;
          destinationPool.mReleasedLows = serializedPool.mReleasedLows;
        }
      }

      archive->Write(idPoolMapType, &serializedIdPools, NullOwnerRef());
    }

    SerSets(archive);

    if (gpg::RType* const entityListType = ResolveTypeByAnyName({"std::list<Moho::Entity *>"})) {
      std::list<Entity*> serializedEntities;
      for (Entity* const entity : Entities()) {
        if (!entity) {
          continue;
        }
        serializedEntities.push_back(entity);
      }
      archive->Write(entityListType, &serializedEntities, NullOwnerRef());
    }
  }

  /**
   * Address: 0x00684910 (FUN_00684910, Moho::EntityDBSerializer::Deserialize)
   */
  void EntityDBSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const entityDb = reinterpret_cast<CEntityDb*>(objectPtr);
    if (!entityDb) {
      return;
    }

    entityDb->MemberSerialize(archive);
  }

  /**
   * Address: 0x00684920 (FUN_00684920, Moho::EntityDBSerializer::Serialize)
   */
  void EntityDBSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const entityDb = reinterpret_cast<CEntityDb*>(objectPtr);
    if (!entityDb) {
      return;
    }

    entityDb->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00688A90 (FUN_00688A90, Moho::EntityDBSerializer::RegisterSerializeFunctions)
   */
  void EntityDBSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const entityDbType = ResolveEntityDbType();
    if (!entityDbType) {
      return;
    }

    entityDbType->serLoadFunc_ = mDeserialize;
    entityDbType->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFCAD0 (FUN_00BFCAD0, Moho::EntityDBSerializer::~EntityDBSerializer)
   */
  gpg::SerHelperBase* cleanup_EntityDBSerializer()
  {
    return UnlinkHelperNode(gEntityDBSerializer);
  }

  /**
   * Address: 0x00BD51A0 (FUN_00BD51A0, register_EntityDBSerializer)
   */
  int register_EntityDBSerializer()
  {
    InitializeHelperNode(gEntityDBSerializer);
    gEntityDBSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&EntityDBSerializer::Deserialize);
    gEntityDBSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&EntityDBSerializer::Serialize);
    gEntityDBSerializer.RegisterSerializeFunctions();
    return std::atexit(&cleanup_EntityDBSerializer_atexit);
  }

  /**
   * Address: 0x006847B0 (FUN_006847B0, preregister_EntityDbTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `EntityDB`.
   */
  gpg::RType* preregister_EntityDbTypeInfo()
  {
    EntityDbTypeInfo& typeInfo = AcquireEntityDbTypeInfo();
    gpg::PreRegisterRType(typeid(CEntityDb), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFCA70 (FUN_00BFCA70, cleanup_EntityDbTypeInfo)
   *
   * What it does:
   * Tears down startup-owned RTTI metadata for `EntityDB`.
   */
  void cleanup_EntityDbTypeInfo()
  {
    if (!gEntityDbTypeInfoConstructed) {
      return;
    }

    AcquireEntityDbTypeInfo().~EntityDbTypeInfo();
    gEntityDbTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD5180 (FUN_00BD5180, register_EntityDbTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `EntityDB` RTTI and installs process-exit cleanup.
   */
  int register_EntityDbTypeInfoAtexit()
  {
    (void)preregister_EntityDbTypeInfo();
    return std::atexit(&cleanup_EntityDbTypeInfo);
  }

  /**
   * Address: 0x00689090 (FUN_00689090, preregister_EntityDbIdPoolMapTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `std::map<unsigned int,Moho::IdPool>`.
   */
  gpg::RType* preregister_EntityDbIdPoolMapTypeInfo()
  {
    EntityDbIdPoolMapTypeInfo& typeInfo = AcquireEntityDbIdPoolMapTypeInfo();
    gpg::PreRegisterRType(typeid(std::map<unsigned int, moho::IdPool>), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFCC20 (FUN_00BFCC20, cleanup_EntityDbIdPoolMapTypeInfo)
   *
   * What it does:
   * Tears down startup-owned RTTI metadata for
   * `std::map<unsigned int,Moho::IdPool>`.
   */
  void cleanup_EntityDbIdPoolMapTypeInfo()
  {
    if (!gEntityDbIdPoolMapTypeInfoConstructed) {
      return;
    }

    AcquireEntityDbIdPoolMapTypeInfo().~EntityDbIdPoolMapTypeInfo();
    gEntityDbIdPoolMapTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD5250 (FUN_00BD5250, register_EntityDbIdPoolMapTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `std::map<unsigned int,Moho::IdPool>` RTTI and installs
   * process-exit cleanup.
   */
  int register_EntityDbIdPoolMapTypeInfoAtexit()
  {
    (void)preregister_EntityDbIdPoolMapTypeInfo();
    return std::atexit(&cleanup_EntityDbIdPoolMapTypeInfo);
  }

  /**
   * Address: 0x006890F0 (FUN_006890F0, preregister_EntityDbEntityListTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `std::list<Moho::Entity *>`.
   */
  gpg::RType* preregister_EntityDbEntityListTypeInfo()
  {
    EntityDbEntityListTypeInfo& typeInfo = AcquireEntityDbEntityListTypeInfo();
    gpg::PreRegisterRType(typeid(std::list<moho::Entity*>), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFCBC0 (FUN_00BFCBC0, cleanup_EntityDbEntityListTypeInfo)
   *
   * What it does:
   * Tears down startup-owned RTTI metadata for `std::list<Moho::Entity *>`.
   */
  void cleanup_EntityDbEntityListTypeInfo()
  {
    if (!gEntityDbEntityListTypeInfoConstructed) {
      return;
    }

    AcquireEntityDbEntityListTypeInfo().~EntityDbEntityListTypeInfo();
    gEntityDbEntityListTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD5270 (FUN_00BD5270, register_EntityDbEntityListTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `std::list<Moho::Entity *>` RTTI and installs process-exit
   * cleanup.
   */
  int register_EntityDbEntityListTypeInfoAtexit()
  {
    (void)preregister_EntityDbEntityListTypeInfo();
    return std::atexit(&cleanup_EntityDbEntityListTypeInfo);
  }
} // namespace moho

namespace
{
  struct EntityDbReflectionBootstrap
  {
    EntityDbReflectionBootstrap()
    {
      (void)moho::register_EntityDbTypeInfoAtexit();
      (void)moho::register_EntityDbIdPoolMapTypeInfoAtexit();
      (void)moho::register_EntityDbEntityListTypeInfoAtexit();
      (void)moho::register_EntityDBSerializer();
    }
  };

  [[maybe_unused]] EntityDbReflectionBootstrap gEntityDbReflectionBootstrap;
} // namespace
