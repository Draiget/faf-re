#include "EntityDb.h"

#include <cstdlib>
#include <initializer_list>
#include <list>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <typeinfo>
#include <unordered_map>
#include <utility>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "Entity.h"
#include "legacy/containers/Tree.h"
#include "moho/containers/BVIntSet.h"
#include "moho/entity/Prop.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/WeakPtr.h"
#include "moho/sim/IdPool.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  struct CEntityDbIdPoolNode
  {
    CEntityDbIdPoolNode* left;              // +0x000
    CEntityDbIdPoolNode* parent;            // +0x004
    CEntityDbIdPoolNode* right;             // +0x008
    std::uint8_t payload_00C_0CC7[0xCBC]{}; // +0x00C
    std::uint8_t color;                     // +0xCC8
    std::uint8_t isNil;                     // +0xCC9
    std::uint8_t tail_0CCA_0CCF[0x06]{};    // +0xCCA
  };
  static_assert(offsetof(CEntityDbIdPoolNode, color) == 0xCC8, "CEntityDbIdPoolNode::color offset must be 0xCC8");
  static_assert(offsetof(CEntityDbIdPoolNode, isNil) == 0xCC9, "CEntityDbIdPoolNode::isNil offset must be 0xCC9");
  static_assert(sizeof(CEntityDbIdPoolNode) == 0xCD0, "CEntityDbIdPoolNode size must be 0xCD0");
} // namespace moho

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
  constexpr std::size_t kBoundedPropQueueMaxSize = 1000u;
  moho::StatItem* sEngineStat_EntityCount = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Prop = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Unit = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Blip = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Other = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Projectile = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Shield = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Unknown = nullptr;

  struct BoundedPropQueueEntry
  {
    std::int32_t priority = 0;
    std::int32_t boundedTick = 0;
    moho::WeakPtr<moho::Prop> weakProp{};
    std::int32_t handleIndex = -1;
  };

  struct BoundedPropQueueRuntime
  {
    std::vector<std::unique_ptr<BoundedPropQueueEntry>> heap{};
    std::vector<std::int32_t> handleToHeapIndex{};
    std::int32_t lastFreeHandle = -1;
  };

  std::unordered_map<const moho::CEntityDb*, BoundedPropQueueRuntime> gRuntimeBoundedProps;

  [[nodiscard]] bool IsHigherBoundedPropPriority(
    const BoundedPropQueueEntry& lhs, const BoundedPropQueueEntry& rhs
  ) noexcept
  {
    // Binary comparator is lexicographic min-heap on (priority, boundedTick).
    if (lhs.priority != rhs.priority) {
      return lhs.priority < rhs.priority;
    }

    return lhs.boundedTick < rhs.boundedTick;
  }

  [[nodiscard]] std::int32_t AcquireBoundedPropHandle(
    BoundedPropQueueRuntime& queue, const std::int32_t heapIndex
  )
  {
    if (queue.lastFreeHandle == -1) {
      const std::int32_t newHandle = static_cast<std::int32_t>(queue.handleToHeapIndex.size());
      queue.handleToHeapIndex.push_back(heapIndex);
      return newHandle;
    }

    const std::int32_t reusedHandle = queue.lastFreeHandle;
    queue.lastFreeHandle = queue.handleToHeapIndex[static_cast<std::size_t>(reusedHandle)];
    queue.handleToHeapIndex[static_cast<std::size_t>(reusedHandle)] = heapIndex;
    return reusedHandle;
  }

  void ReleaseBoundedPropHandle(BoundedPropQueueRuntime& queue, const std::int32_t handleIndex)
  {
    if (handleIndex < 0) {
      return;
    }

    const std::size_t handle = static_cast<std::size_t>(handleIndex);
    if (handle >= queue.handleToHeapIndex.size()) {
      queue.handleToHeapIndex.resize(handle + 1u, -1);
    }

    queue.handleToHeapIndex[handle] = queue.lastFreeHandle;
    queue.lastFreeHandle = handleIndex;
  }

  void UpdateBoundedPropHandleMapping(BoundedPropQueueRuntime& queue, const std::size_t heapIndex)
  {
    if (heapIndex >= queue.heap.size() || !queue.heap[heapIndex]) {
      return;
    }

    const std::int32_t handleIndex = queue.heap[heapIndex]->handleIndex;
    if (handleIndex < 0) {
      return;
    }

    const std::size_t handle = static_cast<std::size_t>(handleIndex);
    if (handle >= queue.handleToHeapIndex.size()) {
      queue.handleToHeapIndex.resize(handle + 1u, -1);
    }
    queue.handleToHeapIndex[handle] = static_cast<std::int32_t>(heapIndex);
  }

  void SwapBoundedPropHeapEntries(BoundedPropQueueRuntime& queue, const std::size_t lhs, const std::size_t rhs)
  {
    if (lhs == rhs) {
      return;
    }

    std::swap(queue.heap[lhs], queue.heap[rhs]);
    UpdateBoundedPropHandleMapping(queue, lhs);
    UpdateBoundedPropHandleMapping(queue, rhs);
  }

  void SiftBoundedPropUp(BoundedPropQueueRuntime& queue, std::size_t heapIndex)
  {
    while (heapIndex > 0u) {
      const std::size_t parent = (heapIndex - 1u) / 2u;
      if (!IsHigherBoundedPropPriority(*queue.heap[heapIndex], *queue.heap[parent])) {
        break;
      }

      SwapBoundedPropHeapEntries(queue, parent, heapIndex);
      heapIndex = parent;
    }
  }

  void SiftBoundedPropDown(BoundedPropQueueRuntime& queue, std::size_t heapIndex)
  {
    const std::size_t count = queue.heap.size();
    for (;;) {
      const std::size_t leftChild = heapIndex * 2u + 1u;
      if (leftChild >= count) {
        return;
      }

      std::size_t best = heapIndex;
      if (IsHigherBoundedPropPriority(*queue.heap[leftChild], *queue.heap[best])) {
        best = leftChild;
      }

      const std::size_t rightChild = leftChild + 1u;
      if (rightChild < count && IsHigherBoundedPropPriority(*queue.heap[rightChild], *queue.heap[best])) {
        best = rightChild;
      }

      if (best == heapIndex) {
        return;
      }

      SwapBoundedPropHeapEntries(queue, heapIndex, best);
      heapIndex = best;
    }
  }

  [[nodiscard]] std::int32_t PushBoundedPropEntry(
    BoundedPropQueueRuntime& queue, moho::Prop* const prop, const std::int32_t priority, const std::int32_t boundedTick
  )
  {
    const std::int32_t heapIndex = static_cast<std::int32_t>(queue.heap.size());
    const std::int32_t handleIndex = AcquireBoundedPropHandle(queue, heapIndex);

    auto entry = std::make_unique<BoundedPropQueueEntry>();
    entry->priority = priority;
    entry->boundedTick = boundedTick;
    entry->weakProp.ResetFromObject(prop);
    entry->handleIndex = handleIndex;

    queue.heap.push_back(std::move(entry));
    SiftBoundedPropUp(queue, queue.heap.size() - 1u);
    UpdateBoundedPropHandleMapping(queue, queue.heap.size() - 1u);
    return handleIndex;
  }

  [[nodiscard]] moho::Prop* PopBoundedPropHead(BoundedPropQueueRuntime& queue)
  {
    if (queue.heap.empty()) {
      return nullptr;
    }

    const std::size_t lastIndex = queue.heap.size() - 1u;
    SwapBoundedPropHeapEntries(queue, 0u, lastIndex);

    std::unique_ptr<BoundedPropQueueEntry> removed = std::move(queue.heap.back());
    queue.heap.pop_back();

    moho::Prop* removedProp = nullptr;
    if (removed) {
      removedProp = removed->weakProp.GetObject();
      removed->weakProp.ResetFromObject(nullptr);
      ReleaseBoundedPropHandle(queue, removed->handleIndex);
    }

    if (!queue.heap.empty()) {
      SiftBoundedPropDown(queue, 0u);
    }

    return removedProp;
  }

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
      node->next->prev = node->prev;
      node->prev->next = node->next;
    }

    node->next = node;
    node->prev = node;

    node->next = head.next;
    node->prev = &head;
    head.next->prev = node;
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

  template <typename TNode>
  [[nodiscard]] TNode* NextNodeInSentinelTree(TNode* node) noexcept
  {
    if (node == nullptr || node->isNil != 0u) {
      return node;
    }

    TNode* childOrParent = node->right;
    if (childOrParent == nullptr) {
      return nullptr;
    }

    if (childOrParent->isNil != 0u) {
      for (TNode* next = node->parent; next != nullptr && next->isNil == 0u; next = next->parent) {
        if (node != next->right) {
          return next;
        }
        node = next;
      }
      return node != nullptr ? node->parent : nullptr;
    }

    TNode* next = childOrParent->left;
    while (next != nullptr && next->isNil == 0u) {
      childOrParent = next;
      next = next->left;
    }
    return childOrParent;
  }

  template <typename TNode>
  void ClearSentinelTreeNodes(TNode* const head) noexcept
  {
    if (!head) {
      return;
    }

    for (TNode* node = head->left; node && node != head && node->isNil == 0u;) {
      TNode* const next = NextNodeInSentinelTree(node);
      ::operator delete(node);
      node = next;
    }

    head->parent = head;
    head->left = head;
    head->right = head;
  }

  [[nodiscard]] moho::CEntityDbAllUnitsNode* AllocateAllUnitsTreeNode()
  {
    auto* const node = static_cast<moho::CEntityDbAllUnitsNode*>(::operator new(sizeof(moho::CEntityDbAllUnitsNode)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->color = 1u;
    node->isNil = 0u;
    return node;
  }

  [[nodiscard]] moho::CEntityDbIdPoolNode* AllocateIdPoolTreeNode()
  {
    auto* const node = static_cast<moho::CEntityDbIdPoolNode*>(::operator new(sizeof(moho::CEntityDbIdPoolNode)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->color = 1u;
    node->isNil = 0u;
    return node;
  }

  [[nodiscard]] moho::CEntityDbListHead* AllocateEntityListHeadNode()
  {
    auto* const head = static_cast<moho::CEntityDbListHead*>(::operator new(sizeof(moho::CEntityDbListHead)));
    head->next = head;
    head->prev = head;
    return head;
  }

  void ResetBoundedPropQueueLane(moho::CEntityDbBoundedPropQueueRuntime& queue) noexcept
  {
    if (queue.storageBegin) {
      // The binary runs an element-dtor walk before deleting storage; this lane
      // remains unresolved because gameplay-side bounded props live in
      // `gRuntimeBoundedProps` in the current recovered implementation.
      ::operator delete(queue.storageBegin);
    }

    queue.storageBegin = nullptr;
    queue.storageCurrent = nullptr;
    queue.storageEnd = nullptr;
    queue.start = 0u;
    queue.end = 0u;
    queue.capacity = 0u;
  }

  void ClearEntityListNodes(moho::CEntityDbListHead* const head) noexcept
  {
    if (!head) {
      return;
    }

    for (moho::CEntityDbListHead* node = head->next; node && node != head;) {
      moho::CEntityDbListHead* const next = node->next;
      ::operator delete(node);
      node = next;
    }

    head->next = head;
    head->prev = head;
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
    /**
     * Address: 0x00687920 (FUN_00687920, Moho::EntityDBTypeInfo::NewRef)
     *
     * What it does:
     * Allocates and default-constructs one `CEntityDb`, then wraps it in an
     * `EntityDB` reflection reference.
     */
    [[nodiscard]] static gpg::RRef NewRef();

    [[nodiscard]] const char* GetName() const override
    {
      return "EntityDB";
    }

    void Init() override
    {
      newRefFunc_ = &EntityDbTypeInfo::NewRef;
      size_ = sizeof(moho::CEntityDb);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(EntityDbTypeInfo) == 0x64, "EntityDbTypeInfo size must be 0x64");

  /**
   * Address: 0x00687920 (FUN_00687920, Moho::EntityDBTypeInfo::NewRef)
   *
   * What it does:
   * Allocates and default-constructs one `CEntityDb`, then wraps it in an
   * `EntityDB` reflection reference.
   */
  gpg::RRef EntityDbTypeInfo::NewRef()
  {
    moho::CEntityDb* entityDb = nullptr;
    if (void* const storage = ::operator new(sizeof(moho::CEntityDb), std::nothrow); storage != nullptr) {
      entityDb = new (storage) moho::CEntityDb();
    }

    gpg::RRef out{};
    (void)gpg::RRef_EntityDB(&out, entityDb);
    return out;
  }

  extern msvc8::string gEntityDbIdPoolMapTypeName;
  extern std::uint32_t gEntityDbIdPoolMapTypeNameInitGuard;
  void cleanup_EntityDbIdPoolMapTypeName();

  extern msvc8::string gEntityDbEntityListTypeName;
  extern std::uint32_t gEntityDbEntityListTypeNameInitGuard;
  void cleanup_EntityDbEntityListTypeName();

  class EntityDbIdPoolMapTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00685C80 (FUN_00685C80, gpg::RMapType_uint_IdPool::GetName)
     *
     * What it does:
     * Builds/caches one lexical map type label from runtime key/value RTTI
     * names and returns `"map<key,value>"`.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if ((gEntityDbIdPoolMapTypeNameInitGuard & 1u) == 0u) {
        gEntityDbIdPoolMapTypeNameInitGuard |= 1u;

        gpg::RType* valueType = moho::IdPool::sType;
        if (valueType == nullptr) {
          valueType = gpg::LookupRType(typeid(moho::IdPool));
          moho::IdPool::sType = valueType;
        }

        gpg::RType* keyType = gpg::LookupRType(typeid(unsigned int));
        const char* const keyName = keyType != nullptr ? keyType->GetName() : "unsigned int";
        const char* const valueName = valueType != nullptr ? valueType->GetName() : "Moho::IdPool";

        gEntityDbIdPoolMapTypeName = gpg::STR_Printf("map<%s,%s>", keyName, valueName);
        (void)std::atexit(&cleanup_EntityDbIdPoolMapTypeName);
      }

      return gEntityDbIdPoolMapTypeName.c_str();
    }

    /**
     * Address: 0x00685D60 (FUN_00685D60, gpg::RMapType_uint_IdPool::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current map element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      const auto* const map = static_cast<const std::map<unsigned int, moho::IdPool>*>(ref.mObj);
      const int size = map ? static_cast<int>(map->size()) : 0;
      return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
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
    /**
     * Address: 0x00685DF0 (FUN_00685DF0, gpg::RListType_EntityP::GetName)
     *
     * What it does:
     * Builds/caches one lexical list type label from runtime `Entity*` RTTI
     * and returns `"list<value>"`.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if ((gEntityDbEntityListTypeNameInitGuard & 1u) == 0u) {
        gEntityDbEntityListTypeNameInitGuard |= 1u;

        gpg::RType* const valueType = gpg::LookupRType(typeid(moho::Entity*));
        const char* const valueName = valueType != nullptr ? valueType->GetName() : "Entity *";
        gEntityDbEntityListTypeName = gpg::STR_Printf("list<%s>", valueName ? valueName : "Entity *");
        (void)std::atexit(&cleanup_EntityDbEntityListTypeName);
      }

      return gEntityDbEntityListTypeName.c_str();
    }

    /**
     * Address: 0x00685E90 (FUN_00685E90, gpg::RListType_EntityP::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current list element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      const auto* const list = static_cast<const std::list<moho::Entity*>*>(ref.mObj);
      const int size = list ? static_cast<int>(list->size()) : 0;
      return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
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
  msvc8::string gEntityDbIdPoolMapTypeName{};
  std::uint32_t gEntityDbIdPoolMapTypeNameInitGuard = 0u;
  msvc8::string gEntityDbEntityListTypeName{};
  std::uint32_t gEntityDbEntityListTypeNameInitGuard = 0u;
  alignas(EntityDbEntityListTypeInfo)
    std::byte gEntityDbEntityListTypeInfoStorage[sizeof(EntityDbEntityListTypeInfo)]{};
  bool gEntityDbEntityListTypeInfoConstructed = false;

  /**
   * Address: 0x00BFCB90 (FUN_00BFCB90)
   *
   * What it does:
   * Releases cached lexical storage for `gpg::RMapType_uint_IdPool::GetName`.
   */
  void cleanup_EntityDbIdPoolMapTypeName()
  {
    gEntityDbIdPoolMapTypeName.clear();
    gEntityDbIdPoolMapTypeNameInitGuard = 0u;
  }

  /**
   * Address: 0x00B867B0 (FUN_00B867B0, cleanup_EntityDbEntityListTypeName)
   *
   * What it does:
   * Releases cached lexical storage for `gpg::RListType_EntityP::GetName`.
   */
  void cleanup_EntityDbEntityListTypeName()
  {
    gEntityDbEntityListTypeName.clear();
    gEntityDbEntityListTypeNameInitGuard = 0u;
  }

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
   * Address: 0x00684230 (FUN_00684230, Moho::EntityDB::EntityDB)
   */
  CEntityDb::CEntityDb()
  {
    mAllUnits = AllocateAllUnitsTreeNode();
    mAllUnits->isNil = 1u;
    mAllUnits->parent = mAllUnits;
    mAllUnits->left = mAllUnits;
    mAllUnits->right = mAllUnits;
    mAllUnitsSize = 0u;

    mIdPoolTree.head = AllocateIdPoolTreeNode();
    mIdPoolTree.head->isNil = 1u;
    mIdPoolTree.head->parent = mIdPoolTree.head;
    mIdPoolTree.head->left = mIdPoolTree.head;
    mIdPoolTree.head->right = mIdPoolTree.head;
    mIdPoolTree.size = 0u;

    mRegisteredEntitySets.next = &mRegisteredEntitySets;
    mRegisteredEntitySets.prev = &mRegisteredEntitySets;

    mEntityList.head = AllocateEntityListHeadNode();
    mEntityList.size = 0u;

    mBoundedProps.start = 0u;
    mBoundedProps.end = 0u;
    mBoundedProps.capacity = 0u;
    mBoundedProps.storageBegin = nullptr;
    mBoundedProps.storageCurrent = nullptr;
    mBoundedProps.storageEnd = nullptr;
    mBoundedProps.lastHandle = -1;
  }

  /**
   * Address: 0x006843B0 (FUN_006843B0, Moho::EntityDB::~EntityDB)
   */
  CEntityDb::~CEntityDb()
  {
    ResetBoundedPropQueueLane(mBoundedProps);

    ClearEntityListNodes(mEntityList.head);
    ::operator delete(mEntityList.head);
    mEntityList.head = nullptr;
    mEntityList.size = 0u;

    if (mRegisteredEntitySets.next && mRegisteredEntitySets.prev) {
      mRegisteredEntitySets.prev->next = mRegisteredEntitySets.next;
      mRegisteredEntitySets.next->prev = mRegisteredEntitySets.prev;
    }
    mRegisteredEntitySets.next = &mRegisteredEntitySets;
    mRegisteredEntitySets.prev = &mRegisteredEntitySets;

    ClearSentinelTreeNodes(mIdPoolTree.head);
    ::operator delete(mIdPoolTree.head);
    mIdPoolTree.head = nullptr;
    mIdPoolTree.size = 0u;

    ClearSentinelTreeNodes(mAllUnits);
    ::operator delete(mAllUnits);
    mAllUnits = nullptr;
    mAllUnitsSize = 0u;

    gRuntimeBoundedProps.erase(this);
    gRuntimeEntityLists.erase(this);
    gRuntimePools.erase(this);
  }

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

  /**
   * Address: 0x00684C30 (FUN_00684C30, Moho::EntityDB::AddBoundedProp)
   *
   * What it does:
   * Pushes one Prop into the bounded reclaim-priority queue and evicts queue
   * head entries while occupancy is at least 1000.
   */
  std::int32_t CEntityDb::AddBoundedProp(Prop* const prop)
  {
    BoundedPropQueueRuntime& queue = gRuntimeBoundedProps[this];
    while (queue.heap.size() >= kBoundedPropQueueMaxSize) {
      Prop* const evictedProp = PopBoundedPropHead(queue);
      if (!evictedProp) {
        continue;
      }

      evictedProp->mHandleIndex = -1;
      evictedProp->Destroy();
    }

    if (!prop) {
      return -1;
    }

    return PushBoundedPropEntry(queue, prop, prop->mPriorityInfo.mPriority, prop->mPriorityInfo.mBoundedTick);
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

  void CEntityDb::RegisterEntitySet(EntitySetBase& set) noexcept
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

    for (CEntityDbListHead* node = mRegisteredEntitySets.next; node && node != &mRegisteredEntitySets;
         node = node->next) {
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

    if (gpg::RType* const idPoolMapType = ResolveTypeByAnyName(
          {"std::map<unsigned int,Moho::IdPool>", "map<unsigned int,Moho::IdPool>"}
        )) {
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

    if (gpg::RType* const idPoolMapType = ResolveTypeByAnyName(
          {"std::map<unsigned int,Moho::IdPool>", "map<unsigned int,Moho::IdPool>"}
        )) {
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
   * Address: 0x00686010 (FUN_00686010, gpg::SerSaveLoadHelper_EntityDB::Init)
   */
  void EntityDBSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const entityDbType = ResolveEntityDbType();
    GPG_ASSERT(entityDbType != nullptr);
    if (!entityDbType) {
      return;
    }

    GPG_ASSERT(entityDbType->serLoadFunc_ == nullptr);
    GPG_ASSERT(entityDbType->serSaveFunc_ == nullptr);
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
