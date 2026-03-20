#include "CArmyImpl.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <new>

#include "CArmyStats.h"
#include "CSimArmyEconomyInfo.h"
#include "moho/containers/BVIntSet.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptObject.h"
#include "moho/unit/core/Unit.h"
#include "Sim.h"
#include "SSTIArmyConstantData.h"

namespace
{
  template <std::size_t SlotIndex>
  void CallDeletingDestructorSlot(void* object)
  {
    if (object == nullptr) {
      return;
    }

    auto** const vtable = *reinterpret_cast<void***>(object);
    if (vtable == nullptr) {
      return;
    }

    using DeletingDtor = void(__thiscall*)(void*, int);
    auto* const dtor = reinterpret_cast<DeletingDtor>(vtable[SlotIndex]);
    dtor(object, 1);
  }

  void DestroyPlatoonPool(moho::ArmyPool& pool)
  {
    // Address: 0x006FF9A0 (FUN_006FF9A0), platoon-pool destruction prefix.
    for (moho::CPlatoon** it = pool.platoons.begin(); it != pool.platoons.end(); ++it) {
      CallDeletingDestructorSlot<2>(*it);
    }

    pool.platoons.ResetStorageToInline();
  }

  void ReleaseSharedRaw(boost::SharedPtrRaw<void>& value)
  {
    if (value.pi != nullptr) {
      value.pi->release();
    }
    value.px = nullptr;
    value.pi = nullptr;
  }

  struct IntrusiveListNode
  {
    IntrusiveListNode* next;
    IntrusiveListNode* prev;
  };

  static_assert(sizeof(IntrusiveListNode) == 0x08, "IntrusiveListNode size must be 0x08");

  void UnlinkIntrusiveNode(IntrusiveListNode& node)
  {
    if (node.next != nullptr && node.prev != nullptr) {
      node.next->prev = node.prev;
      node.prev->next = node.next;
    }

    node.next = &node;
    node.prev = &node;
  }

  struct PointerTriplet
  {
    void* start;
    void* finish;
    void* capacity;
  };

  static_assert(sizeof(PointerTriplet) == 0x0C, "PointerTriplet size must be 0x0C");

  void ResetPointerTripletStorage(PointerTriplet& triplet)
  {
    if (triplet.start != nullptr) {
      operator delete(triplet.start);
    }
    triplet.start = nullptr;
    triplet.finish = nullptr;
    triplet.capacity = nullptr;
  }

  struct PathQueueNodeOwner
  {
    std::uint32_t unknown00;
    IntrusiveListNode* sentinel;
    std::uint32_t count;
  };

  static_assert(sizeof(PathQueueNodeOwner) == 0x0C, "PathQueueNodeOwner size must be 0x0C");

  struct PathQueueImplBaseView
  {
    PathQueueNodeOwner ownedNodes; // +0x00
    std::uint8_t pad_0C[0x08];
    PointerTriplet clusters; // +0x14
    std::uint8_t pad_20[0x0C];
    PointerTriplet bucketA; // +0x2C
    std::uint8_t pad_38[0x04];
    PointerTriplet bucketB; // +0x3C
    std::uint8_t pad_48[0x04];
    IntrusiveListNode traveler; // +0x4C
    std::uint8_t pad_54[0x14];
    PointerTriplet pending; // +0x68
  };

  static_assert(
    offsetof(PathQueueImplBaseView, ownedNodes) == 0x00, "PathQueueImplBaseView::ownedNodes offset must be 0x00"
  );
  static_assert(
    offsetof(PathQueueImplBaseView, clusters) == 0x14, "PathQueueImplBaseView::clusters offset must be 0x14"
  );
  static_assert(offsetof(PathQueueImplBaseView, bucketA) == 0x2C, "PathQueueImplBaseView::bucketA offset must be 0x2C");
  static_assert(offsetof(PathQueueImplBaseView, bucketB) == 0x3C, "PathQueueImplBaseView::bucketB offset must be 0x3C");
  static_assert(
    offsetof(PathQueueImplBaseView, traveler) == 0x4C, "PathQueueImplBaseView::traveler offset must be 0x4C"
  );
  static_assert(offsetof(PathQueueImplBaseView, pending) == 0x68, "PathQueueImplBaseView::pending offset must be 0x68");

  struct PathQueueRuntimeView
  {
    void* unknown00;
    IntrusiveListNode registrationNode;
    PathQueueImplBaseView implBase;
  };

  static_assert(
    offsetof(PathQueueRuntimeView, registrationNode) == 0x04,
    "PathQueueRuntimeView::registrationNode offset must be 0x04"
  );
  static_assert(offsetof(PathQueueRuntimeView, implBase) == 0x0C, "PathQueueRuntimeView::implBase offset must be 0x0C");

  struct PathFinderOwnerView
  {
    PathQueueRuntimeView* runtime;
  };

  static_assert(sizeof(PathFinderOwnerView) == 0x04, "PathFinderOwnerView size must be 0x04");

  void ClearOwnedPathQueueNodes(PathQueueNodeOwner& owner)
  {
    IntrusiveListNode* const sentinel = owner.sentinel;
    if (sentinel == nullptr) {
      owner.count = 0;
      return;
    }

    IntrusiveListNode* node = sentinel->next;
    sentinel->next = sentinel;
    sentinel->prev = sentinel;
    owner.count = 0;

    while (node != sentinel) {
      IntrusiveListNode* const next = node->next;
      operator delete(node);
      node = next;
    }
  }

  void DestroyPathQueueImplBase(PathQueueImplBaseView& implBase)
  {
    // Address: 0x00765C30 (FUN_00765C30, Moho::PathQueue::ImplBase::~ImplBase)
    ResetPointerTripletStorage(implBase.bucketB);
    ResetPointerTripletStorage(implBase.bucketA);
    ResetPointerTripletStorage(implBase.clusters);
    ClearOwnedPathQueueNodes(implBase.ownedNodes);
    operator delete(implBase.ownedNodes.sentinel);
    implBase.ownedNodes.sentinel = nullptr;
  }

  void DestroyPathQueueImpl(PathQueueImplBaseView& implBase)
  {
    // Address: 0x00765BE0 (FUN_00765BE0), PathQueue implementation teardown prefix.
    ResetPointerTripletStorage(implBase.pending);
    UnlinkIntrusiveNode(implBase.traveler);
    DestroyPathQueueImplBase(implBase);
  }

  void DestroyPathFinder(void*& pathFinder)
  {
    // Address: 0x00701A80 (FUN_00701A80), field helper used by CArmyImpl teardown.
    auto* const owner = static_cast<PathFinderOwnerView*>(pathFinder);
    if (owner == nullptr) {
      return;
    }

    PathQueueRuntimeView* const runtime = owner->runtime;
    if (runtime != nullptr) {
      DestroyPathQueueImpl(runtime->implBase);
      UnlinkIntrusiveNode(runtime->registrationNode);
      operator delete(runtime);
    }

    operator delete(owner);
    pathFinder = nullptr;
  }

  struct CEconStorageView
  {
    std::uint8_t* economyRuntime; // +0x00
    float amounts[4];             // +0x04
  };

  static_assert(
    offsetof(CEconStorageView, economyRuntime) == 0x00, "CEconStorageView::economyRuntime offset must be 0x00"
  );
  static_assert(offsetof(CEconStorageView, amounts) == 0x04, "CEconStorageView::amounts offset must be 0x04");

  void ApplyEconStorageDelta(const std::int32_t direction, CEconStorageView& storage)
  {
    // Address: 0x007732C0 (FUN_007732C0, Moho::CEconStorage::Chng)
    if (storage.economyRuntime == nullptr) {
      return;
    }

    const std::int64_t signedDirection = static_cast<std::int64_t>(direction);
    constexpr std::size_t kAccumOffset = 0x40;
    constexpr std::size_t kAccumCount = 4;
    for (std::size_t i = 0; i < kAccumCount; ++i) {
      auto* const accumulator =
        reinterpret_cast<std::int64_t*>(storage.economyRuntime + kAccumOffset + (i * sizeof(std::int64_t)));
      const std::int64_t delta = static_cast<std::int64_t>(storage.amounts[i]) * signedDirection;
      *accumulator += delta;
    }
  }

  void DestroyArmyEconomyInfo(moho::CSimArmyEconomyInfo*& economyInfo)
  {
    if (economyInfo == nullptr) {
      return;
    }

    // Address: 0x006FF9A0 (FUN_006FF9A0), +0x1F4 teardown branch.
    UnlinkIntrusiveNode(reinterpret_cast<IntrusiveListNode&>(economyInfo->registrationNode));

    auto* const storage = reinterpret_cast<CEconStorageView*>(economyInfo->storageDelta);
    if (storage != nullptr) {
      if (storage->economyRuntime != nullptr) {
        ApplyEconStorageDelta(-1, *storage);
      }
      operator delete(storage);
      economyInfo->storageDelta = nullptr;
    }

    operator delete(economyInfo);
    economyInfo = nullptr;
  }

  void ResetCategorySetStorage(moho::SEntitySetTemplateUnit& set)
  {
    // Address: 0x007056D0 (FUN_007056D0), per-set teardown mechanics.
    set.mVec.ResetStorageToInline();

    if (set.mNext != nullptr && set.mPrev != nullptr) {
      auto* const next = reinterpret_cast<IntrusiveListNode*>(set.mNext);
      auto* const prev = reinterpret_cast<IntrusiveListNode*>(set.mPrev);
      next->prev = prev;
      prev->next = next;
    }

    auto* const self = reinterpret_cast<IntrusiveListNode*>(&set);
    self->next = self;
    self->prev = self;
  }

  void DestroyArmyCategorySets(moho::CArmyImpl& army)
  {
    moho::SEntitySetTemplateUnit* const begin = army.UnitCategorySetsBegin;
    moho::SEntitySetTemplateUnit* const end = army.UnitCategorySetsEnd;
    if (begin == nullptr || end == nullptr || begin >= end) {
      army.UnitCategorySetsBegin = nullptr;
      army.UnitCategorySetsEnd = nullptr;
      army.UnitCategorySetsCapacityEnd = nullptr;
      return;
    }

    for (moho::SEntitySetTemplateUnit* it = begin; it != end; ++it) {
      ResetCategorySetStorage(*it);
    }

    operator delete(begin);
    army.UnitCategorySetsBegin = nullptr;
    army.UnitCategorySetsEnd = nullptr;
    army.UnitCategorySetsCapacityEnd = nullptr;
  }

  [[nodiscard]] moho::SSTIArmyConstantData* GetArmyConstantData(moho::CArmyImpl* army)
  {
    // Evidence: FUN_00700080 passes (this + 0x08) into the constant-data copier.
    return reinterpret_cast<moho::SSTIArmyConstantData*>(&army->ArmyId);
  }

  [[nodiscard]] const moho::SSTIArmyConstantData* GetArmyConstantData(const moho::CArmyImpl* army)
  {
    return reinterpret_cast<const moho::SSTIArmyConstantData*>(&army->ArmyId);
  }

  [[nodiscard]] moho::SSTIArmyVariableData* GetArmyVariableData(moho::CArmyImpl* army)
  {
    // Evidence: FUN_00700240 copies/exports variable data from (this + 0x88).
    return reinterpret_cast<moho::SSTIArmyVariableData*>(&army->EnergyCurrent);
  }

  [[nodiscard]] const moho::SSTIArmyVariableData* GetArmyVariableData(const moho::CArmyImpl* army)
  {
    return reinterpret_cast<const moho::SSTIArmyVariableData*>(&army->EnergyCurrent);
  }

  [[nodiscard]] moho::SArmyVectorWithMeta* GetRuntimeWordVectorWithMeta(moho::CArmyImpl* army)
  {
    // Evidence: FUN_006FDE70 targets (this + 0x17C), modeled as CArmyImpl::RuntimeWordVectorWithMeta.
    return &army->RuntimeWordVectorWithMeta;
  }

  [[nodiscard]] moho::BVIntSet& AsBVIntSet(moho::Set& set) noexcept
  {
    using WordVectorStorage = gpg::core::FastVectorN<std::uint32_t, 2>;
    static_assert(sizeof(moho::Set) == sizeof(moho::BVIntSet), "Set/BVIntSet size mismatch");
    static_assert(
      offsetof(moho::Set, baseWordIndex) == offsetof(moho::BVIntSet, mFirstWordIndex),
      "Set::baseWordIndex offset mismatch"
    );
    static_assert(
      offsetof(moho::Set, meta) == offsetof(moho::BVIntSet, mReservedMetaWord), "Set::meta offset mismatch"
    );
    static_assert(
      offsetof(moho::Set, items_begin) == offsetof(moho::BVIntSet, mWords) + offsetof(WordVectorStorage, start_),
      "Set::items_begin offset mismatch"
    );
    static_assert(
      offsetof(moho::Set, items_end) == offsetof(moho::BVIntSet, mWords) + offsetof(WordVectorStorage, end_),
      "Set::items_end offset mismatch"
    );
    static_assert(
      offsetof(moho::Set, items_capacity_end) ==
        offsetof(moho::BVIntSet, mWords) + offsetof(WordVectorStorage, capacity_),
      "Set::items_capacity_end offset mismatch"
    );
    return reinterpret_cast<moho::BVIntSet&>(set);
  }

  void ResetArmyPoolPlatoons(moho::ArmyPool& pool)
  {
    // Address: 0x00701B70 (FUN_00701B70), initialization prefix.
    pool.platoons.RebindInlineNoFree();
  }

  void ReserveArmyPoolPlatoons(moho::ArmyPool& pool, const std::size_t requiredCount)
  {
    auto& platoons = pool.platoons;
    const std::size_t currentCap = platoons.Capacity();
    if (requiredCount <= currentCap) {
      return;
    }

    moho::CPlatoon** const currentBegin = platoons.Data();
    const std::size_t currentSize = platoons.Size();
    auto* const newBegin = static_cast<moho::CPlatoon**>(operator new[](requiredCount * sizeof(moho::CPlatoon*)));
    if (currentSize > 0u) {
      memmove_s(newBegin, requiredCount * sizeof(moho::CPlatoon*), currentBegin, currentSize * sizeof(moho::CPlatoon*));
    }

    if (!platoons.UsingInlineStorage()) {
      operator delete[](currentBegin);
    } else {
      // Preserve fastvector_n inline header contract before switching to heap storage.
      platoons.SaveInlineCapacityHeader();
    }

    platoons.AdoptRawBufferNoFree(newBegin, currentSize, requiredCount);
  }

  void CopyArmyPoolPlatoons(moho::ArmyPool& dst, const moho::ArmyPool& src)
  {
    // Address: 0x00702CA0 (FUN_00702CA0), vector-copy helper semantics.
    if (&dst == &src) {
      return;
    }

    auto& dstPlatoons = dst.platoons;
    const auto& srcPlatoons = src.platoons;
    const std::size_t dstSize = dstPlatoons.Size();
    const std::size_t srcSize = srcPlatoons.Size();
    const moho::CPlatoon* const* srcBegin = srcPlatoons.Data();
    moho::CPlatoon** dstBegin = dstPlatoons.Data();

    if (dstSize >= srcSize) {
      if (srcSize > 0u) {
        memmove_s(dstBegin, srcSize * sizeof(moho::CPlatoon*), srcBegin, srcSize * sizeof(moho::CPlatoon*));
      }
      dstPlatoons.SetSizeUnchecked(srcSize);
      return;
    }

    const std::size_t dstCap = dstPlatoons.Capacity();
    if (srcSize > dstCap) {
      ReserveArmyPoolPlatoons(dst, srcSize);
      dstBegin = dstPlatoons.Data();
    }

    if (dstSize > 0u) {
      memmove_s(dstBegin, dstSize * sizeof(moho::CPlatoon*), srcBegin, dstSize * sizeof(moho::CPlatoon*));
    }

    const std::size_t tailCount = srcSize - dstSize;
    if (tailCount > 0u) {
      memmove_s(
        dstBegin + dstSize, tailCount * sizeof(moho::CPlatoon*), srcBegin + dstSize, tailCount * sizeof(moho::CPlatoon*)
      );
    }
    dstPlatoons.SetSizeUnchecked(srcSize);
  }

  struct RPlatoonDebugStringsView
  {
    std::uint8_t pad_0000[0x90];
    msvc8::string mAiPlan;
    msvc8::string mPlatoonName;
  };

  static_assert(
    offsetof(RPlatoonDebugStringsView, mAiPlan) == 0x90, "RPlatoonDebugStringsView::mAiPlan offset must be 0x90"
  );
  static_assert(
    offsetof(RPlatoonDebugStringsView, mPlatoonName) == 0xAC,
    "RPlatoonDebugStringsView::mPlatoonName offset must be 0xAC"
  );
  static_assert(sizeof(RPlatoonDebugStringsView) == 0xC8, "RPlatoonDebugStringsView size must be 0xC8");

  [[nodiscard]] msvc8::string CopyLegacyString(const msvc8::string& source)
  {
    return msvc8::string(source.data(), source.size());
  }

  [[nodiscard]] msvc8::string GetUnitUniqueName(const moho::Unit* unit)
  {
    if (unit == nullptr) {
      return msvc8::string();
    }

    // Evidence:
    // - FUN_00700A70 calls Entity::GetUniqueName with (unit + 0x08), i.e. Unit's Entity subobject.
    // - FUN_00689F20 reads the backing string from Entity + 0x1FC.
    const moho::Entity* const entity = static_cast<const moho::Entity*>(unit);
    return entity->GetUniqueName();
  }

  [[nodiscard]] msvc8::string GetPlatoonName(const moho::CPlatoon* platoon)
  {
    if (platoon == nullptr) {
      return msvc8::string();
    }

    const auto* const view = reinterpret_cast<const RPlatoonDebugStringsView*>(platoon);
    return CopyLegacyString(view->mPlatoonName);
  }

  [[nodiscard]] msvc8::string GetPlatoonAiPlan(const moho::CPlatoon* platoon)
  {
    if (platoon == nullptr) {
      return msvc8::string();
    }

    const auto* const view = reinterpret_cast<const RPlatoonDebugStringsView*>(platoon);
    return CopyLegacyString(view->mAiPlan);
  }

  [[nodiscard]] msvc8::string GetSquadClassLexical(const moho::ESquadClass squadClass)
  {
    switch (squadClass) {
    case moho::ESquadClass::Unassigned:
      return msvc8::string("Unassigned");
    case moho::ESquadClass::Attack:
      return msvc8::string("Attack");
    case moho::ESquadClass::Artillery:
      return msvc8::string("Artillery");
    case moho::ESquadClass::Guard:
      return msvc8::string("Guard");
    case moho::ESquadClass::Support:
      return msvc8::string("Support");
    case moho::ESquadClass::Scout:
      return msvc8::string("Scout");
    default:
      break;
    }

    char numeric[32] = {};
    std::snprintf(numeric, sizeof(numeric), "%d", static_cast<int>(squadClass));
    return msvc8::string(numeric);
  }

  [[nodiscard]] moho::StatItem* ResolveArmyDebugStatItem(moho::CArmyStats* armyStats, const msvc8::string& statName)
  {
    if (armyStats == nullptr || statName.empty()) {
      return nullptr;
    }

    return armyStats->TraverseTables(statName.data(), true);
  }

  void SetStatItemStringValue(moho::StatItem* statItem, const msvc8::string& value)
  {
    if (statItem == nullptr) {
      return;
    }

    boost::mutex::scoped_lock lock(statItem->mLock);
    statItem->mType = moho::EStatType::kString;
    statItem->mValue.assign(value, 0, msvc8::string::npos);
  }

  template <typename T>
  void AssignSharedRawWithRetain(boost::SharedPtrRaw<T>& target, const boost::SharedPtrRaw<T>& value)
  {
    // Matches the VC8-era shared_ptr raw assignment pattern used in recovered code:
    // copy px first, then transfer control-block refcount if the block pointer changed.
    target.px = value.px;
    if (value.pi != target.pi) {
      if (value.pi != nullptr) {
        value.pi->add_ref_copy();
      }
      if (target.pi != nullptr) {
        target.pi->release();
      }
      target.pi = value.pi;
    }
  }

  template <typename T>
  void CopySharedRawOutWithRetain(boost::SharedPtrRaw<T>& outValue, const boost::SharedPtrRaw<T>& value)
  {
    outValue.px = value.px;
    outValue.pi = value.pi;
    if (outValue.pi != nullptr) {
      outValue.pi->add_ref_copy();
    }
  }

  [[nodiscard]] std::uint32_t GetEntityIdForSort(const moho::Entity* entity)
  {
    if (entity == nullptr) {
      return 0;
    }

    return static_cast<std::uint32_t>(entity->id_);
  }

  [[nodiscard]] moho::Entity* AsEntitySubobject(moho::Unit* unit)
  {
    return (unit != nullptr) ? static_cast<moho::Entity*>(unit) : nullptr;
  }

  [[nodiscard]] const moho::Entity* AsEntitySubobject(const moho::Unit* unit)
  {
    return (unit != nullptr) ? static_cast<const moho::Entity*>(unit) : nullptr;
  }

  using EntitySetVector = gpg::fastvector_n<moho::Entity*, 4>;
  using EntitySetIterator = EntitySetVector::iterator;

  [[nodiscard]] EntitySetIterator
  LowerBoundByEntityId(EntitySetIterator begin, EntitySetIterator end, const moho::Unit* unit)
  {
    const std::uint32_t key = GetEntityIdForSort(AsEntitySubobject(unit));
    return std::lower_bound(begin, end, key, [](const moho::Entity* candidate, const std::uint32_t targetId) -> bool {
      return GetEntityIdForSort(candidate) < targetId;
    });
  }

  void AddUnitToEntitySet(moho::SEntitySetTemplateUnit& set, moho::Unit* unit)
  {
    const EntitySetIterator end = set.mVec.end();
    const EntitySetIterator spot = LowerBoundByEntityId(set.mVec.begin(), end, unit);
    moho::Entity* const entity = AsEntitySubobject(unit);
    if (spot != end && *spot == entity) {
      return;
    }

    set.mVec.InsertAt(spot, &entity, &entity + 1);
  }

  [[nodiscard]] bool ConsumeUnitFromEntitySet(moho::SEntitySetTemplateUnit& set, moho::Unit* unit)
  {
    const EntitySetIterator end = set.mVec.end();
    const EntitySetIterator spot = LowerBoundByEntityId(set.mVec.begin(), end, unit);
    const moho::Entity* const entity = AsEntitySubobject(unit);
    if (spot == end || *spot != entity) {
      return false;
    }

    if (spot != end) {
      const std::size_t tailCount = static_cast<std::size_t>(end - (spot + 1));
      if (tailCount > 0u) {
        memmove_s(spot, tailCount * sizeof(moho::Entity*), spot + 1, tailCount * sizeof(moho::Entity*));
      }
      set.mVec.end_ = spot + tailCount;
    }

    return true;
  }

  [[nodiscard]] moho::Unit* GetUnitFromSetEntry(moho::Entity* entity)
  {
    if (entity == nullptr) {
      return nullptr;
    }

    // Evidence:
    // - FUN_0057DDD0 inserts &unit->Moho::Unit_base_Entity into EntitySetTemplate_Unit.
    // - FUN_00700A00 consumes entries as Unit owner objects.
    //
    // Keep the same ownership assumption, but express it as a typed base->derived cast
    // instead of raw pointer subtraction.
    return static_cast<moho::Unit*>(entity);
  }

  [[nodiscard]] moho::SEntitySetTemplateUnit* ResolveCategorySetForUnit(moho::CArmyImpl* army, moho::Unit* unit)
  {
    if (army == nullptr || unit == nullptr) {
      return nullptr;
    }

    const moho::RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (blueprint == nullptr) {
      return nullptr;
    }

    const std::uint32_t categoryBitIndex = blueprint->mCategoryBitIndex;
    if (categoryBitIndex < army->UnitCategoryBaseIndex || categoryBitIndex > army->UnitCategoryMaxIndex) {
      return nullptr;
    }

    moho::SEntitySetTemplateUnit* const setsBegin = army->UnitCategorySetsBegin;
    if (setsBegin == nullptr) {
      return nullptr;
    }

    const std::size_t relativeIndex = static_cast<std::size_t>(categoryBitIndex - army->UnitCategoryBaseIndex);
    moho::SEntitySetTemplateUnit* const target = setsBegin + relativeIndex;
    if (army->UnitCategorySetsEnd != nullptr && target >= army->UnitCategorySetsEnd) {
      return nullptr;
    }

    return target;
  }

  [[nodiscard]] float GetUnitCapCost(const moho::Unit* unit)
  {
    if (unit == nullptr) {
      return 0.0f;
    }

    const moho::RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (blueprint == nullptr) {
      return 0.0f;
    }

    return blueprint->General.CapCost;
  }

  [[nodiscard]] moho::Unit* GetUnitFromAllUnitsTreeNode(const moho::CEntityDbAllUnitsNode* node)
  {
    if (node == nullptr || node->unitListNode == nullptr) {
      return nullptr;
    }

    auto* const entitySubobject = reinterpret_cast<moho::Entity*>(node->unitListNode);
    return static_cast<moho::Unit*>(entitySubobject);
  }

  /**
   * Address: 0x005C87A0 (FUN_005C87A0, Moho::CUnitIterAllArmies::Next)
   *
   * What it does:
   * Advances a red-black tree iterator node to its in-order successor.
   */
  void AdvanceAllUnitsNode(moho::CEntityDbAllUnitsNode*& node)
  {
    if (node == nullptr || node->isNil != 0u) {
      return;
    }

    moho::CEntityDbAllUnitsNode* childOrParent = node->right;
    if (childOrParent == nullptr) {
      node = nullptr;
      return;
    }
    if (childOrParent->isNil != 0u) {
      for (moho::CEntityDbAllUnitsNode* next = node->parent; next != nullptr && next->isNil == 0u;
           next = next->parent) {
        if (node != next->right) {
          node = next;
          return;
        }
        node = next;
      }
      node = (node != nullptr) ? node->parent : nullptr;
      return;
    }

    moho::CEntityDbAllUnitsNode* next = childOrParent->left;
    if (childOrParent->isNil == 0u) {
      do {
        childOrParent = next;
        if (childOrParent == nullptr) {
          node = nullptr;
          return;
        }
        next = next->left;
      } while (next != nullptr && next->isNil == 0u);
    }
    node = childOrParent;
  }

  class ArmyUnitsRange
  {
  public:
    class iterator
    {
    public:
      iterator(moho::CEntityDbAllUnitsNode* node, moho::CEntityDbAllUnitsNode* endNode) noexcept
        : node_(node)
        , endNode_(endNode)
      {}

      [[nodiscard]] moho::Unit* operator*() const noexcept
      {
        return GetUnitFromAllUnitsTreeNode(node_);
      }

      iterator& operator++() noexcept
      {
        if (node_ != endNode_) {
          AdvanceAllUnitsNode(node_);
        }
        return *this;
      }

      [[nodiscard]] bool operator!=(const iterator& other) const noexcept
      {
        return node_ != other.node_;
      }

    private:
      moho::CEntityDbAllUnitsNode* node_;
      moho::CEntityDbAllUnitsNode* endNode_;
    };

    ArmyUnitsRange(const moho::CEntityDb& entityDb, const std::uint32_t armyIndex) noexcept
      : beginNode_(entityDb.AllUnitsEnd(armyIndex))
      , endNode_(entityDb.AllUnitsEnd(armyIndex + 1u))
    {}

    [[nodiscard]] iterator begin() const noexcept
    {
      return iterator(beginNode_, endNode_);
    }

    [[nodiscard]] iterator end() const noexcept
    {
      return iterator(endNode_, endNode_);
    }

  private:
    moho::CEntityDbAllUnitsNode* beginNode_;
    moho::CEntityDbAllUnitsNode* endNode_;
  };
} // namespace

namespace moho
{
  /**
   * Address: 0x006FE670 (FUN_006FE670, Moho::CArmyImpl::~CArmyImpl)
   *
   * What it does:
   * Tears down owned CArmyImpl runtime allocations and pointer-owned subsystems.
   * Reconstructs pathfinder/economy destruction helpers from the binary teardown chain.
   */
  CArmyImpl::~CArmyImpl()
  {
    DestroyPlatoonPool(PlatoonPool);
    DestroyArmyCategorySets(*this);
    DestroyPlatoonPool(PlatoonPool);
    ReleaseSharedRaw(UnknownShared220);
    DestroyPathFinder(PathFinder);

    // Outstanding blocker:
    // - InfluenceMap (+0x218) still requires typed lift of CInfluenceMap helper chain.
    InfluenceMap = nullptr;

    if (Stats != nullptr) {
      delete Stats;
      Stats = nullptr;
    }

    DestroyArmyEconomyInfo(EconomyInfo);

    // Evidence: 0x006FF9A0 calls vtable slot 0 with delete-flag for mReconDB (+0x1F0).
    CallDeletingDestructorSlot<0>(AiReconDb);
    AiReconDb = nullptr;

    // Evidence: 0x006FF9A0 calls vtable slot 2 with delete-flag for mBrain (+0x1EC).
    CallDeletingDestructorSlot<2>(AiBrain);
    AiBrain = nullptr;
  }

  /**
   * Address: 0x006FDC10 (FUN_006FDC10, Moho::CArmyImpl::GetSim)
   */
  Sim* CArmyImpl::GetSim()
  {
    return Simulation;
  }

  /**
   * Address: 0x006FFC90 (FUN_006FFC90, Moho::CArmyImpl::IsHuman)
   */
  bool CArmyImpl::IsHuman()
  {
    return ArmyTypeText.equals_no_case("Human");
  }

  /**
   * Address: 0x006FDC20 (FUN_006FDC20, Moho::CArmyImpl::GetArmyType)
   */
  const char* CArmyImpl::GetArmyType()
  {
    return ArmyTypeText.raw_data_unsafe();
  }

  /**
   * Address: 0x006FDC40 (FUN_006FDC40, Moho::CArmyImpl::SetArmyPlans)
   */
  void CArmyImpl::SetArmyPlans(const msvc8::string& armyPlans)
  {
    ArmyPlans.assign(armyPlans, 0, msvc8::string::npos);
  }

  /**
   * Address: 0x006FDC60 (FUN_006FDC60, Moho::CArmyImpl::GetArmyPlans)
   */
  const char* CArmyImpl::GetArmyPlans()
  {
    return ArmyPlans.raw_data_unsafe();
  }

  /**
   * Address: 0x006FDC80 (FUN_006FDC80, Moho::CArmyImpl::GetIGrid)
   */
  CInfluenceMap* CArmyImpl::GetIGrid()
  {
    return InfluenceMap;
  }

  /**
   * Address: 0x006FDC90 (FUN_006FDC90, Moho::CArmyImpl::GetArmyBrain)
   */
  CAiBrain* CArmyImpl::GetArmyBrain()
  {
    return AiBrain;
  }

  /**
   * Address: 0x006FDCA0 (FUN_006FDCA0, Moho::CArmyImpl::GetReconDB)
   */
  CAiReconDBImpl* CArmyImpl::GetReconDB()
  {
    return AiReconDb;
  }

  /**
   * Address: 0x006FDCB0 (FUN_006FDCB0, Moho::CArmyImpl::GetEconomy)
   */
  CSimArmyEconomyInfo* CArmyImpl::GetEconomy()
  {
    return EconomyInfo;
  }

  /**
   * Address: 0x006FFCB0 (FUN_006FFCB0, Moho::CArmyImpl::GenerateArmyStart)
   */
  void CArmyImpl::GenerateArmyStart()
  {
    if (!Simulation || !Simulation->mRngState) {
      StartPosition.x = 0.0f;
      StartPosition.y = 0.0f;
      return;
    }

    const auto* const heightField =
      (Simulation->mMapData != nullptr) ? Simulation->mMapData->GetHeightField() : nullptr;
    const auto width = (heightField != nullptr) ? heightField->width : 0;
    const auto height = (heightField != nullptr) ? heightField->height : 0;

    CMersenneTwister& rng = Simulation->mRngState->twister;

    const float rx = CMersenneTwister::ToUnitFloat(rng.NextUInt32()) + 0.1f;
    const float ry = CMersenneTwister::ToUnitFloat(rng.NextUInt32()) + 0.1f;

    StartPosition.x = (width > 0) ? static_cast<float>(width - 1) * rx : 0.0f;
    StartPosition.y = (height > 0) ? static_cast<float>(height - 1) * ry : 0.0f;
  }

  /**
   * Address: 0x006FDCC0 (FUN_006FDCC0, Moho::CArmyImpl::SetArmyStart)
   */
  void CArmyImpl::SetArmyStart(const Wm3::Vector2f& startPosition)
  {
    StartPosition = startPosition;
  }

  /**
   * Address: 0x006FDCE0 (FUN_006FDCE0, Moho::CArmyImpl::GetArmyStartPos)
   */
  void CArmyImpl::GetArmyStartPos(Wm3::Vector2f& outStartPosition)
  {
    outStartPosition = StartPosition;
  }

  /**
   * Address: 0x006FDF30 (FUN_006FDF30, Moho::CArmyImpl::SetAlliance)
   */
  void CArmyImpl::SetAlliance(const std::uint32_t armyId, const int relationIndex)
  {
    Set* relationSets[3] = {&Neutrals, &Allies, &Enemies};

    for (int i = 0; i < 3; ++i) {
      Set& relation = *relationSets[i];
      if (i == relationIndex) {
        // Binary path uses FUN_00401980 (EnsureBounds) before setting the bit.
        AsBVIntSet(relation).Add(armyId);
      } else {
        // Binary path uses FUN_004018A0 (Finalize) after in-range clear.
        AsBVIntSet(relation).Remove(armyId);
      }
    }
  }

  /**
   * Address: 0x00700FC0 (FUN_00700FC0, Moho::CArmyImpl::OnCommandSourceTerminated)
   */
  void CArmyImpl::OnCommandSourceTerminated(const std::uint32_t sourceId)
  {
    MohoSetValidCommandSources.Remove(sourceId);
    if (MohoSetValidCommandSources.items_begin == MohoSetValidCommandSources.items_end && AiBrain != nullptr) {
      reinterpret_cast<CScriptObject*>(AiBrain)->CallbackStr("AbandonedByPlayer");
    }
  }

  /**
   * Address: 0x00700080 (FUN_00700080, Moho::CArmyImpl::CopyConstantDataToUserArmy)
   */
  UserArmy* CArmyImpl::CopyConstantDataToUserArmy(UserArmy* outUserArmy)
  {
    const SSTIArmyConstantData* const source = GetArmyConstantData(this);
    SSTIArmyConstantData* const dest = reinterpret_cast<SSTIArmyConstantData*>(outUserArmy);

    dest->mArmyIndex = source->mArmyIndex;
    dest->mArmyName.assign(source->mArmyName, 0, msvc8::string::npos);
    dest->mPlayerName.assign(source->mPlayerName, 0, msvc8::string::npos);
    dest->mIsCivilian = source->mIsCivilian;
    dest->mExploredReconGrid = source->mExploredReconGrid;
    dest->mFogReconGrid = source->mFogReconGrid;
    dest->mWaterReconGrid = source->mWaterReconGrid;
    dest->mRadarReconGrid = source->mRadarReconGrid;
    dest->mSonarReconGrid = source->mSonarReconGrid;
    dest->mOmniReconGrid = source->mOmniReconGrid;
    dest->mRciReconGrid = source->mRciReconGrid;
    dest->mSciReconGrid = source->mSciReconGrid;

    return outUserArmy;
  }

  /**
   * Address: 0x00700240 (FUN_00700240, Moho::CArmyImpl::CopyArmyVariableData)
   */
  SSTIArmyVariableData* CArmyImpl::CopyArmyVariableData(SSTIArmyVariableData* outBuffer)
  {
    if (EconomyInfo != nullptr) {
      const SEconTotals& econ = EconomyInfo->economy;
      EnergyCurrent = econ.mStored.ENERGY;
      MassCurrent = econ.mStored.MASS;
      IncomeEnergy10x = econ.mIncome.ENERGY;
      IncomeMass10x = econ.mIncome.MASS;
      ReclaimedEnergy10x = econ.mReclaimed.ENERGY;
      ReclaimedMass10x = econ.mReclaimed.MASS;
      RequestedEnergy10x = econ.mLastUseRequested.ENERGY;
      RequestedMass10x = econ.mLastUseRequested.MASS;
      ExpenseEnergy10x = econ.mLastUseActual.ENERGY;
      ExpenseMass10x = econ.mLastUseActual.MASS;
      EnergyCapacity = static_cast<std::uint32_t>(econ.mMaxStorage.ENERGY);
      MassCapacity = static_cast<std::uint32_t>(econ.mMaxStorage.MASS);
      IsResourceSharingEnabled = EconomyInfo->isResourceSharingEnabled;
    }

    if (outBuffer == nullptr) {
      return nullptr;
    }

    *outBuffer = *GetArmyVariableData(this);
    return outBuffer;
  }

  /**
   * Address: 0x006FDD50 (FUN_006FDD50, Moho::CArmyImpl::GetArmyStats)
   */
  CArmyStats* CArmyImpl::GetArmyStats()
  {
    return Stats;
  }

  /**
   * Address: 0x006FDD60 (FUN_006FDD60, Moho::CArmyImpl::GetArmyUnitCostTotal)
   */
  float CArmyImpl::GetArmyUnitCostTotal()
  {
    if (Simulation == nullptr || Simulation->mEntityDB == nullptr) {
      return 0.0f;
    }

    const std::uint32_t armyIndex = static_cast<std::uint32_t>(ArmyId);

    float currentCap = 0.0f;
    for (Unit* const unit : ArmyUnitsRange(*Simulation->mEntityDB, armyIndex)) {
      if (unit == nullptr) {
        break;
      }

      if (!unit->IsUnitState(UNITSTATE_NoCost)) {
        currentCap += GetUnitCapCost(unit);
      }
    }

    return currentCap;
  }

  /**
   * Address: 0x006FDDE0 (FUN_006FDDE0, Moho::CArmyImpl::GetPathFinder)
   */
  void* CArmyImpl::GetPathFinder()
  {
    return PathFinder;
  }

  /**
   * Address: 0x006FDDF0 (FUN_006FDDF0, Moho::CArmyImpl::SetUnknownSharedRef)
   */
  boost::SharedPtrRaw<void>* CArmyImpl::SetUnknownSharedRef(boost::SharedPtrRaw<void>* value)
  {
    if (value == nullptr) {
      return nullptr;
    }

    AssignSharedRawWithRetain(UnknownShared220, *value);

    return value;
  }

  /**
   * Address: 0x006FDE40 (FUN_006FDE40, Moho::CArmyImpl::GetUnknownSharedRef)
   */
  boost::SharedPtrRaw<void>* CArmyImpl::GetUnknownSharedRef(boost::SharedPtrRaw<void>* outValue)
  {
    if (outValue == nullptr) {
      return nullptr;
    }

    CopySharedRawOutWithRetain(*outValue, UnknownShared220);

    return outValue;
  }

  /**
   * Address: 0x006FDE70 (FUN_006FDE70, Moho::CArmyImpl::SetUnknownVectorWithMeta)
   */
  std::uint32_t CArmyImpl::SetUnknownVectorWithMeta(const SArmyVectorWithMeta* value)
  {
    if (value == nullptr) {
      return 0;
    }

    SArmyVectorWithMeta* const target = GetRuntimeWordVectorWithMeta(this);
    target->CopyWordPayloadFrom(*value);
    target->mMetaWord = value->mMetaWord;
    return target->mMetaWord;
  }

  /**
   * Address: 0x006FDE90 (FUN_006FDE90, Moho::CArmyImpl::GetPlatoonsList)
   */
  void CArmyImpl::GetPlatoonsList(ArmyPool& outPool)
  {
    // Address: 0x006FDE90 (FUN_006FDE90)
    // - Calls 0x00701B70 to init `outPool` platoon-vector header.
    // - Then copies platoon pointer payload via 0x00702CA0.
    ResetArmyPoolPlatoons(outPool);
    CopyArmyPoolPlatoons(outPool, PlatoonPool);
  }

  /**
   * Address: 0x00700A00 (FUN_00700A00, Moho::CArmyImpl::CountUnitsInBoundsXZ)
   */
  int CArmyImpl::CountUnitsInBoundsXZ(
    const Wm3::Vector3f& minBounds, const Wm3::Vector3f& maxBounds, const SEntitySetTemplateUnit& unitSet
  )
  {
    int count = 0;
    for (Entity* const* it = unitSet.mVec.start_; it != unitSet.mVec.end_; ++it) {
      Unit* const unit = GetUnitFromSetEntry(*it);
      if (unit == nullptr) {
        continue;
      }

      const Wm3::Vec3f& pos = unit->GetPosition();
      if (minBounds.x <= pos.x && pos.x <= maxBounds.x && minBounds.z <= pos.z && pos.z <= maxBounds.z) {
        ++count;
      }
    }

    return count;
  }

  /**
   * Address: 0x00700A70 (FUN_00700A70, Moho::CArmyImpl::UpdateAIDebugPlatoonStats)
   *
   * What it does:
   * Updates three AIDebug string stats for a unit's platoon:
   * - `<AIDebug_UnitName>_PlatoonName`
   * - `<AIDebug_UnitName>_SquadClass`
   * - `<AIDebug_UnitName>_AIPlan`
   */
  void CArmyImpl::UpdateAIDebugPlatoonStats(Unit* unit)
  {
    if (unit == nullptr || Stats == nullptr) {
      return;
    }

    const msvc8::string debugPrefix = msvc8::string("AIDebug_") + GetUnitUniqueName(unit);

    ESquadClass squadClass = ESquadClass::Unassigned;
    CPlatoon* const platoon = GetPlatoonFor(static_cast<int>(reinterpret_cast<std::uintptr_t>(unit)), &squadClass);
    if (platoon == nullptr) {
      return;
    }

    const msvc8::string platoonNameKey = debugPrefix + "_PlatoonName";
    const msvc8::string squadClassKey = debugPrefix + "_SquadClass";
    const msvc8::string aiPlanKey = debugPrefix + "_AIPlan";

    SetStatItemStringValue(ResolveArmyDebugStatItem(Stats, platoonNameKey), GetPlatoonName(platoon));
    SetStatItemStringValue(ResolveArmyDebugStatItem(Stats, squadClassKey), GetSquadClassLexical(squadClass));
    SetStatItemStringValue(ResolveArmyDebugStatItem(Stats, aiPlanKey), GetPlatoonAiPlan(platoon));
  }

  /**
   * Address: 0x00700E20 (FUN_00700E20, Moho::CArmyImpl::AddUnitToCategorySet)
   */
  void CArmyImpl::AddUnitToCategorySet(Unit* unit)
  {
    SEntitySetTemplateUnit* const set = ResolveCategorySetForUnit(this, unit);
    if (set == nullptr) {
      return;
    }

    AddUnitToEntitySet(*set, unit);
  }

  /**
   * Address: 0x00700E70 (FUN_00700E70, Moho::CArmyImpl::ConsumeUnitFromCategorySet)
   */
  bool CArmyImpl::ConsumeUnitFromCategorySet(Unit* unit)
  {
    SEntitySetTemplateUnit* const set = ResolveCategorySetForUnit(this, unit);
    if (set == nullptr) {
      return false;
    }

    return ConsumeUnitFromEntitySet(*set, unit);
  }

  /**
   * Address: 0x006FE090 (FUN_006FE090, Moho::CArmyImpl::GetAlliedArmies)
   */
  msvc8::vector<CArmyImpl*>* CArmyImpl::GetAlliedArmies(msvc8::vector<CArmyImpl*>* outArmyList)
  {
    if (outArmyList == nullptr) {
      return nullptr;
    }

    outArmyList->clear();

    if (Allies.items_begin == nullptr || Allies.items_end == nullptr) {
      return outArmyList;
    }

    const std::uint32_t wordCount = static_cast<std::uint32_t>(Allies.items_end - Allies.items_begin);
    for (std::uint32_t wordOffset = 0; wordOffset < wordCount; ++wordOffset) {
      // moho::Set is a packed bitset of army IDs in 32-bit words.
      const std::int32_t absoluteWord = Allies.baseWordIndex + static_cast<std::int32_t>(wordOffset);
      if (absoluteWord < 0) {
        continue;
      }

      std::uint32_t bits = Allies.items_begin[wordOffset];
      for (std::uint32_t bit = 0; bit < 32; ++bit) {
        const std::uint32_t mask = (1u << bit);
        if ((bits & mask) == 0u) {
          continue;
        }

        bits &= ~mask;

        // Army ID = (word index * 32) + bit position.
        const std::uint32_t armyIndex = (static_cast<std::uint32_t>(absoluteWord) << 5u) + bit;
        if (armyIndex == static_cast<std::uint32_t>(ArmyId)) {
          continue;
        }

        CArmyImpl* allyArmy = nullptr;
        if (Simulation != nullptr && armyIndex < Simulation->mArmiesList.size()) {
          allyArmy = Simulation->mArmiesList[armyIndex];
        }
        outArmyList->push_back(allyArmy);
      }
    }

    return outArmyList;
  }

  /**
   * Address: 0x006FDD00 (FUN_006FDD00, Moho::CArmyImpl::GetUnitCap)
   */
  float CArmyImpl::GetUnitCap()
  {
    return UnitCapacity;
  }

  /**
   * Address: 0x006FDD10 (FUN_006FDD10, Moho::CArmyImpl::SetUnitCap)
   */
  void CArmyImpl::SetUnitCap(const float unitCap)
  {
    UnitCapacity = unitCap;
  }

  /**
   * Address: 0x006FDD30 (FUN_006FDD30, Moho::CArmyImpl::IgnoreUnitCap)
   */
  bool CArmyImpl::IgnoreUnitCap()
  {
    return IgnoreUnitCapFlag != 0;
  }

  /**
   * Address: 0x006FDD40 (FUN_006FDD40, Moho::CArmyImpl::SetUseUnitCap)
   */
  void CArmyImpl::SetUseUnitCap(const bool useUnitCap)
  {
    IgnoreUnitCapFlag = static_cast<std::uint8_t>(useUnitCap);
  }

  /**
   * Address: 0x006FDEC0 (FUN_006FDEC0, Moho::CArmyImpl::SetIgnorePlayableRect)
   */
  void CArmyImpl::SetIgnorePlayableRect(const bool ignorePlayableRect)
  {
    UseWholeMapFlag = static_cast<std::uint8_t>(ignorePlayableRect);
  }

  /**
   * Address: 0x006FDED0 (FUN_006FDED0, Moho::CArmyImpl::UseWholeMap)
   */
  bool CArmyImpl::UseWholeMap()
  {
    return UseWholeMapFlag != 0;
  }

  /**
   * Address: 0x006FE290 (FUN_006FE290, Moho::CArmyImpl::SetNoRushTimer)
   */
  void CArmyImpl::SetNoRushTimer(const float seconds)
  {
    NoRushTicks = static_cast<std::int32_t>(seconds * 600.0f);
  }

  /**
   * Address: 0x006FE2B0 (FUN_006FE2B0, Moho::CArmyImpl::SetNoRushRadius)
   */
  void CArmyImpl::SetNoRushRadius(const float radius)
  {
    NoRushRadius = radius;
  }

  /**
   * Address: 0x006FE2D0 (FUN_006FE2D0, Moho::CArmyImpl::SetNoRushOffset)
   */
  void CArmyImpl::SetNoRushOffset(const float offsetX, const float offsetY)
  {
    NoRushOffsetX = offsetX;
    NoRushOffsetY = offsetY;
  }

  /**
   * Address: 0x006FE2F0 (FUN_006FE2F0, Moho::CArmyImpl::GetPathcapLand)
   */
  std::int32_t CArmyImpl::GetPathcapLand()
  {
    return PathCapacityLand;
  }

  /**
   * Address: 0x006FE300 (FUN_006FE300, Moho::CArmyImpl::GetPathcapSea)
   */
  std::int32_t CArmyImpl::GetPathcapSea()
  {
    return PathCapacitySea;
  }

  /**
   * Address: 0x006FE310 (FUN_006FE310, Moho::CArmyImpl::GetPathcapBoth)
   */
  std::int32_t CArmyImpl::GetPathcapBoth()
  {
    return PathCapacityBoth;
  }
} // namespace moho
