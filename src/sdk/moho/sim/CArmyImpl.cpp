#include "CArmyImpl.h"

#include <algorithm>
#include <bit>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>
#include <type_traits>
#include <typeinfo>

#include "CArmyStats.h"
#include "CPlatoon.h"
#include "CInfluenceMap.h"
#include "CSimArmyEconomyInfo.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/containers/BVIntSet.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/EntityDb.h"
#include "moho/path/PathTables.h"
#include "moho/sim/ArmyUnitSetVectorReflection.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/RRuleGameRules.h"
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

  using IntrusiveListNode = moho::IntrusiveNode;

  void UnlinkIntrusiveNode(IntrusiveListNode& node)
  {
    if (node.mNext != nullptr && node.mPrev != nullptr) {
      node.ListUnlink();
      return;
    }

    node.ListResetLinks();
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

    IntrusiveListNode* node = sentinel->mNext;
    sentinel->ListResetLinks();
    owner.count = 0;

    while (node != sentinel) {
      IntrusiveListNode* const next = node->mNext;
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
    auto* const econStorage = reinterpret_cast<moho::CEconStorage*>(&storage);
    (void)econStorage->Chng(direction);
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
      set.ListUnlink();
      return;
    }

    set.mNext = &set;
    set.mPrev = &set;
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

  struct UnitCategorySetVectorView
  {
    moho::SEntitySetTemplateUnit* begin;
    moho::SEntitySetTemplateUnit* end;
    moho::SEntitySetTemplateUnit* capacityEnd;
  };

  static_assert(sizeof(UnitCategorySetVectorView) == 0x0C, "UnitCategorySetVectorView size must be 0x0C");
  static_assert(
    offsetof(UnitCategorySetVectorView, begin) == 0x00, "UnitCategorySetVectorView::begin offset must be 0x00"
  );
  static_assert(offsetof(UnitCategorySetVectorView, end) == 0x04, "UnitCategorySetVectorView::end offset must be 0x04");
  static_assert(
    offsetof(UnitCategorySetVectorView, capacityEnd) == 0x08,
    "UnitCategorySetVectorView::capacityEnd offset must be 0x08"
  );

  constexpr const char* kCAiBrainTypeNames[] = {"Moho::CAiBrain", "CAiBrain"};
  constexpr const char* kCAiReconDBImplTypeNames[] = {"Moho::CAiReconDBImpl", "CAiReconDBImpl"};
  constexpr const char* kIAiReconDBTypeNames[] = {"Moho::IAiReconDB", "IAiReconDB"};
  constexpr const char* kCEconomyTypeNames[] = {"Moho::CEconomy", "CEconomy"};
  constexpr const char* kPathQueueTypeNames[] = {"Moho::PathQueue", "PathQueue"};
  constexpr const char* kCPlatoonTypeNames[] = {"Moho::CPlatoon", "CPlatoon"};
  constexpr const char* kEntitySetTemplateUnitVectorTypeNames[] = {
    "vector<Moho::EntitySetTemplate<Moho::Unit>>",
    "vector<Moho::EntitySetTemplate<Moho::Unit> >",
    "vector<EntitySetTemplate<Unit>>"
  };

  gpg::RType* gSimType = nullptr;
  gpg::RType* gCAiBrainType = nullptr;
  gpg::RType* gCAiReconDBImplType = nullptr;
  gpg::RType* gIAiReconDBType = nullptr;
  gpg::RType* gCEconomyType = nullptr;
  gpg::RType* gCArmyStatsType = nullptr;
  gpg::RType* gCInfluenceMapType = nullptr;
  gpg::RType* gPathQueueType = nullptr;
  gpg::RType* gCPlatoonType = nullptr;
  gpg::RType* gEntitySetTemplateUnitVectorType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  template <std::size_t NameCount>
  [[nodiscard]] gpg::RType* ResolveTypeByNames(gpg::RType*& slot, const char* const (&typeNames)[NameCount])
  {
    if (slot) {
      return slot;
    }

    for (const char* const typeName : typeNames) {
      if (!typeName || !*typeName) {
        continue;
      }

      slot = gpg::REF_FindTypeNamed(typeName);
      if (slot != nullptr) {
        return slot;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* ResolveSimType()
  {
    return CachedType<moho::Sim>(gSimType);
  }

  [[nodiscard]] gpg::RType* ResolveCAiBrainType()
  {
    return ResolveTypeByNames(gCAiBrainType, kCAiBrainTypeNames);
  }

  [[nodiscard]] gpg::RType* ResolveCAiReconDBImplType()
  {
    return ResolveTypeByNames(gCAiReconDBImplType, kCAiReconDBImplTypeNames);
  }

  [[nodiscard]] gpg::RType* ResolveIAiReconDBType()
  {
    return ResolveTypeByNames(gIAiReconDBType, kIAiReconDBTypeNames);
  }

  [[nodiscard]] gpg::RType* ResolveCEconomyType()
  {
    return ResolveTypeByNames(gCEconomyType, kCEconomyTypeNames);
  }

  [[nodiscard]] gpg::RType* ResolveCArmyStatsType()
  {
    return CachedType<moho::CArmyStats>(gCArmyStatsType);
  }

  [[nodiscard]] gpg::RType* ResolveCInfluenceMapType()
  {
    return CachedType<moho::CInfluenceMap>(gCInfluenceMapType);
  }

  [[nodiscard]] gpg::RType* ResolvePathQueueType()
  {
    return ResolveTypeByNames(gPathQueueType, kPathQueueTypeNames);
  }

  [[nodiscard]] gpg::RType* ResolveCPlatoonType()
  {
    return ResolveTypeByNames(gCPlatoonType, kCPlatoonTypeNames);
  }

  /**
   * Address: 0x005949D0 (FUN_005949D0, gpg::RRef::Upcast_CPlatoon)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CPlatoon` and returns the
   * resulting object pointer (or null on mismatch).
   */
  [[nodiscard]] moho::CPlatoon* UpcastCPlatoonRef(const gpg::RRef& source)
  {
    return static_cast<moho::CPlatoon*>(gpg::REF_UpcastPtr(source, ResolveCPlatoonType()).mObj);
  }

  /**
    * Alias of FUN_007040E0 (non-canonical helper lane).
   *
   * What it does:
   * Reads one tracked pointer lane, enforces owned-pointer transition
   * (`Unowned -> Owned`), and upcasts to `CPlatoon`.
   */
  [[nodiscard]] moho::CPlatoon* ReadOwnedCPlatoonPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    if (tracked.state != gpg::TrackedPointerState::Unowned) {
      throw gpg::SerializationError("Ownership conflict while loading archive");
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    moho::CPlatoon* const platoon = UpcastCPlatoonRef(source);
    if (!platoon) {
      gpg::RType* expectedType = moho::CPlatoon::sType;
      if (!expectedType) {
        expectedType = gpg::LookupRType(typeid(moho::CPlatoon));
        moho::CPlatoon::sType = expectedType;
      }

      const char* const expectedName = expectedType ? expectedType->GetName() : "CPlatoon";
      const char* const actualName = tracked.type ? tracked.type->GetName() : "null";
      const msvc8::string message = gpg::STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        expectedName ? expectedName : "CPlatoon",
        actualName ? actualName : "null"
      );
      throw gpg::SerializationError(message.c_str());
    }

    tracked.state = gpg::TrackedPointerState::Owned;
    return platoon;
  }

  /**
   * Address: 0x007041F0 (FUN_007041F0, sub_7041F0)
   *
   * What it does:
   * Writes one `CPlatoon` tracked-pointer lane as `Owned` through archive
   * pointer serialization.
   */
  void WriteOwnedCPlatoonPointer(gpg::WriteArchive* archive, moho::CPlatoon* platoon, const gpg::RRef& ownerRef)
  {
    gpg::RRef objectRef{};
    gpg::RRef_CPlatoon(&objectRef, platoon);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Owned, ownerRef);
  }

  /**
   * Address: 0x00705A50 (FUN_00705A50, sub_705A50)
   * Alias:   0x00704220 (FUN_00704220, sub_704220)
   * Alias:   0x00704C30 (FUN_00704C30, sub_704C30)
   *
   * What it does:
   * Writes one `CPlatoon` tracked-pointer lane as `Unowned` through archive
   * pointer serialization.
   */
  void WriteUnownedCPlatoonPointer(gpg::WriteArchive* archive, moho::CPlatoon* platoon, const gpg::RRef& ownerRef)
  {
    gpg::RRef objectRef{};
    gpg::RRef_CPlatoon(&objectRef, platoon);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetTemplateUnitVectorType()
  {
    if (!gEntitySetTemplateUnitVectorType) {
      gEntitySetTemplateUnitVectorType = gpg::ResolveEntitySetTemplateUnitVectorType();
      if (!gEntitySetTemplateUnitVectorType) {
        gEntitySetTemplateUnitVectorType =
          ResolveTypeByNames(gEntitySetTemplateUnitVectorType, kEntitySetTemplateUnitVectorTypeNames);
      }
    }
    return gEntitySetTemplateUnitVectorType;
  }

  template <class TObject>
  [[nodiscard]] gpg::RType* ResolveDynamicTypeOr(gpg::RType* const fallbackType, const TObject* const object)
  {
    if (object == nullptr) {
      return fallbackType;
    }

    if constexpr (std::is_polymorphic_v<TObject>) {
      if (gpg::RType* const dynamicType = gpg::LookupRType(typeid(*object)); dynamicType != nullptr) {
        return dynamicType;
      }
    }

    return fallbackType;
  }

  void PromoteTrackedPointerToOwned(gpg::TrackedPointerInfo& tracked)
  {
    if (tracked.object == nullptr) {
      return;
    }

    if (tracked.state == gpg::TrackedPointerState::Unowned) {
      tracked.state = gpg::TrackedPointerState::Owned;
      return;
    }

    GPG_ASSERT(tracked.state == gpg::TrackedPointerState::Owned);
  }

  template <class TObject>
  [[nodiscard]] TObject* DecodeTrackedPointer(const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType)
  {
    if (tracked.object == nullptr) {
      return nullptr;
    }

    if (expectedType != nullptr && tracked.type != nullptr) {
      gpg::RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;
      const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
      return static_cast<TObject*>(upcast.mObj);
    }

    return static_cast<TObject*>(tracked.object);
  }

  template <class TObject>
  [[nodiscard]] TObject*
  ReadPointerTyped(gpg::ReadArchive* const archive, const gpg::RRef& owner, gpg::RType* const expectedType, bool owned)
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, owner);
    if (owned) {
      PromoteTrackedPointerToOwned(tracked);
    }
    return DecodeTrackedPointer<TObject>(tracked, expectedType);
  }

  template <class TObject>
  void WritePointerTyped(
    gpg::WriteArchive* const archive,
    const TObject* const object,
    gpg::RType* const objectType,
    const gpg::TrackedPointerState trackedState,
    const gpg::RRef& owner
  )
  {
    gpg::RRef objectRef{};
    objectRef.mObj = const_cast<TObject*>(object);
    objectRef.mType = (object != nullptr) ? objectType : nullptr;
    gpg::WriteRawPointer(archive, objectRef, trackedState, owner);
  }

  template <std::size_t SlotIndex, class TObject>
  void ReplaceDeletingDtorOwnedPointer(TObject*& field, TObject* const value)
  {
    TObject* const prior = field;
    if (prior == value) {
      return;
    }

    field = value;
    CallDeletingDestructorSlot<SlotIndex>(prior);
  }

  template <class TObject>
  void ReplaceDeleteOwnedPointer(TObject*& field, TObject* const value)
  {
    TObject* const prior = field;
    if (prior == value) {
      return;
    }

    field = value;
    delete prior;
  }

  void ReplaceEconomyOwnedPointer(moho::CSimArmyEconomyInfo*& field, moho::CSimArmyEconomyInfo* const value)
  {
    moho::CSimArmyEconomyInfo* prior = field;
    if (prior == value) {
      return;
    }

    field = value;
    DestroyArmyEconomyInfo(prior);
  }

  void ReplacePathFinderOwnedPointer(void*& field, void* const value)
  {
    void* prior = field;
    if (prior == value) {
      return;
    }

    field = value;
    DestroyPathFinder(prior);
  }

  [[nodiscard]] UnitCategorySetVectorView& UnitCategorySetVector(moho::CArmyImpl& army)
  {
    return *reinterpret_cast<UnitCategorySetVectorView*>(&army.UnitCategorySetsBegin);
  }

  [[nodiscard]] const UnitCategorySetVectorView& UnitCategorySetVector(const moho::CArmyImpl& army)
  {
    return *reinterpret_cast<const UnitCategorySetVectorView*>(&army.UnitCategorySetsBegin);
  }

  struct CArmyBuildCategoryFilterRuntimeView
  {
    std::uint8_t unresolved0000_0198[0x198];
    moho::CategoryWordRangeView mBuildCategoryFilterSet; // +0x198
  };

  static_assert(
    offsetof(CArmyBuildCategoryFilterRuntimeView, mBuildCategoryFilterSet) == 0x198,
    "CArmyBuildCategoryFilterRuntimeView::mBuildCategoryFilterSet offset must be 0x198"
  );

  [[nodiscard]] moho::CategoryWordRangeView& ArmyBuildCategoryFilterWords(moho::CArmyImpl& army) noexcept
  {
    return reinterpret_cast<CArmyBuildCategoryFilterRuntimeView&>(army).mBuildCategoryFilterSet;
  }

  [[nodiscard]] moho::BVIntSet& CategoryWordRangeAsBitset(moho::CategoryWordRangeView& range) noexcept
  {
    return range.mBits;
  }

  void MarkAllArmyUnitsNeedSyncGameData(moho::CArmyImpl& army)
  {
    if (army.Simulation == nullptr || army.Simulation->mEntityDB == nullptr) {
      return;
    }

    const std::uint32_t armyIndex = static_cast<std::uint32_t>(army.ArmyId);
    moho::CEntityDbAllUnitsNode* node = army.Simulation->mEntityDB->AllUnitsEnd(armyIndex);
    const moho::CEntityDbAllUnitsNode* const endNode = army.Simulation->mEntityDB->AllUnitsEnd(armyIndex + 1u);
    while (node != endNode) {
      moho::Unit* const unit = moho::CEntityDb::UnitFromAllUnitsNode(node);
      if (unit == nullptr) {
        break;
      }

      unit->MarkNeedsSyncGameData();
      node = moho::CEntityDb::NextAllUnitsNode(node);
    }
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

  struct CategoryRuleCursor
  {
    moho::RRuleGameRules* rules;
    const moho::BVIntSet* categoryOrdinals;
    unsigned int currentOrdinal;
  };

  static_assert(sizeof(CategoryRuleCursor) == 0x0C, "CategoryRuleCursor size must be 0x0C");
  static_assert(offsetof(CategoryRuleCursor, rules) == 0x00, "CategoryRuleCursor::rules offset must be 0x00");
  static_assert(
    offsetof(CategoryRuleCursor, categoryOrdinals) == 0x04,
    "CategoryRuleCursor::categoryOrdinals offset must be 0x04"
  );
  static_assert(
    offsetof(CategoryRuleCursor, currentOrdinal) == 0x08, "CategoryRuleCursor::currentOrdinal offset must be 0x08"
  );

  /**
   * Address: 0x0052CBA0 (FUN_0052CBA0)
   *
   * What it does:
   * Initializes one category-rule traversal cursor with game-rules owner,
   * category ordinal bitset pointer, and first selected ordinal.
   */
  [[maybe_unused]] [[nodiscard]] CategoryRuleCursor* InitializeCategoryRuleCursor(
    CategoryRuleCursor* const outCursor,
    moho::RRuleGameRules* const rules,
    const moho::BVIntSet& categoryOrdinals
  ) noexcept
  {
    if (outCursor == nullptr) {
      return nullptr;
    }

    outCursor->rules = rules;
    outCursor->categoryOrdinals = &categoryOrdinals;
    outCursor->currentOrdinal = categoryOrdinals.GetNext(std::numeric_limits<unsigned int>::max());
    return outCursor;
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

  constexpr const char* kConVarPathArmyBudget = "path_ArmyBudget";
  constexpr const char* kConVarRenderDebugAttackVectors = "AI_RenderDebugAttackVectors";
  constexpr const char* kConVarDebugArmyIndex = "AI_DebugArmyIndex";
  constexpr const char* kConVarRenderDebugPlayableRect = "AI_RenderDebugPlayableRect";
  constexpr const char* kArmyPoolName = "ArmyPool";
  constexpr const char* kOnDestroyScriptName = "OnDestroy";

  [[nodiscard]] moho::CSimConVarBase* FindSimConVarByName(const char* const name)
  {
    if (name == nullptr || *name == '\0') {
      return nullptr;
    }

    moho::CSimConCommand* const command = moho::FindRegisteredSimConCommand(name);
    return dynamic_cast<moho::CSimConVarBase*>(command);
  }

  template <typename TValue>
  [[nodiscard]] bool ReadSimConVarValue(moho::Sim* const sim, const char* const name, TValue& outValue)
  {
    if (sim == nullptr) {
      return false;
    }

    moho::CSimConVarBase* const conVar = FindSimConVarByName(name);
    if (conVar == nullptr) {
      return false;
    }

    moho::CSimConVarInstanceBase* const instance = sim->GetSimVar(conVar);
    if (instance == nullptr) {
      return false;
    }

    const void* const valueStorage = instance->GetValueStorage();
    if (valueStorage == nullptr) {
      return false;
    }

    outValue = *static_cast<const TValue*>(valueStorage);
    return true;
  }

  void SetArmyFloatStatValue(moho::CArmyStats* const stats, const char* const statPath, const float value)
  {
    if (stats == nullptr || statPath == nullptr || *statPath == '\0') {
      return;
    }

    moho::CArmyStatItem* const statItem = stats->GetStringItemCached(statPath);
    if (statItem == nullptr) {
      return;
    }

    statItem->SynchronizeAsFloat();
    statItem->mPrimaryValueBits = std::bit_cast<std::int32_t>(value);
  }

  /**
   * Address: 0x00771B50 (FUN_00771B50, func_ArmyProcessEconomy)
   *
   * What it does:
   * Refreshes army-visible economy cache lanes from the current per-army
   * economy totals block.
   */
  void ProcessArmyEconomyTick(moho::CArmyImpl& army)
  {
    moho::CSimArmyEconomyInfo* const economyInfo = army.EconomyInfo;
    if (economyInfo == nullptr) {
      return;
    }

    const moho::SEconTotals& totals = economyInfo->economy;
    army.EnergyCurrent = totals.mStored.ENERGY;
    army.MassCurrent = totals.mStored.MASS;

    army.IncomeEnergy10x = totals.mIncome.ENERGY;
    army.IncomeMass10x = totals.mIncome.MASS;

    army.ReclaimedEnergy10x = totals.mReclaimed.ENERGY;
    army.ReclaimedMass10x = totals.mReclaimed.MASS;

    army.RequestedEnergy10x = totals.mLastUseRequested.ENERGY;
    army.RequestedMass10x = totals.mLastUseRequested.MASS;

    army.ExpenseEnergy10x = totals.mLastUseActual.ENERGY;
    army.ExpenseMass10x = totals.mLastUseActual.MASS;

    army.EnergyCapacity = static_cast<std::uint32_t>(totals.mMaxStorage.ENERGY);
    army.MassCapacity = static_cast<std::uint32_t>(totals.mMaxStorage.MASS);
    army.IsResourceSharingEnabled = economyInfo->isResourceSharingEnabled;
  }

  struct CSquadRuntimeUnitsView
  {
    std::uint8_t pad_0000_0010[0x10];
    moho::Entity** unitSlotsBegin; // +0x10
    moho::Entity** unitSlotsEnd;   // +0x14
  };

  static_assert(
    offsetof(CSquadRuntimeUnitsView, unitSlotsBegin) == 0x10, "CSquadRuntimeUnitsView::unitSlotsBegin offset must be 0x10"
  );
  static_assert(
    offsetof(CSquadRuntimeUnitsView, unitSlotsEnd) == 0x14, "CSquadRuntimeUnitsView::unitSlotsEnd offset must be 0x14"
  );

  struct CPlatoonCleanupView
  {
    std::uint8_t pad_0000_0040[0x40];
    CSquadRuntimeUnitsView** squadBegin; // +0x40
    CSquadRuntimeUnitsView** squadEnd;   // +0x44
    std::uint8_t pad_0048_00A8[0x60];
    msvc8::string uniqueName;            // +0xA8
    std::uint8_t pad_00C4_00E0[0x1C];
    std::uint8_t disbandOnIdle;          // +0xE0
  };

  static_assert(offsetof(CPlatoonCleanupView, squadBegin) == 0x40, "CPlatoonCleanupView::squadBegin offset must be 0x40");
  static_assert(offsetof(CPlatoonCleanupView, squadEnd) == 0x44, "CPlatoonCleanupView::squadEnd offset must be 0x44");
  static_assert(offsetof(CPlatoonCleanupView, uniqueName) == 0xA8, "CPlatoonCleanupView::uniqueName offset must be 0xA8");
  static_assert(
    offsetof(CPlatoonCleanupView, disbandOnIdle) == 0xE0, "CPlatoonCleanupView::disbandOnIdle offset must be 0xE0"
  );

  constexpr std::uintptr_t kEntitySetUnitOwnerBias = 0x8u;

  struct CSquadAssignmentRuntimeView
  {
    std::uint8_t pad_0000_0008[0x08];
    moho::SEntitySetTemplateUnit mUnits; // +0x08
    moho::ESquadClass mSquadClass; // +0x30
  };
  static_assert(
    offsetof(CSquadAssignmentRuntimeView, mUnits) == 0x08, "CSquadAssignmentRuntimeView::mUnits offset must be 0x08"
  );
  static_assert(
    offsetof(CSquadAssignmentRuntimeView, mSquadClass) == 0x30,
    "CSquadAssignmentRuntimeView::mSquadClass offset must be 0x30"
  );

  struct CPlatoonAssignmentRuntimeView
  {
    std::uint8_t pad_0000_0040[0x40];
    CSquadAssignmentRuntimeView** mSquadBegin; // +0x40
    CSquadAssignmentRuntimeView** mSquadEnd;   // +0x44
    std::uint8_t pad_0048_0108[0xC0];
    std::uint8_t mHasLuaList; // +0x108
  };
  static_assert(
    offsetof(CPlatoonAssignmentRuntimeView, mSquadBegin) == 0x40,
    "CPlatoonAssignmentRuntimeView::mSquadBegin offset must be 0x40"
  );
  static_assert(
    offsetof(CPlatoonAssignmentRuntimeView, mSquadEnd) == 0x44,
    "CPlatoonAssignmentRuntimeView::mSquadEnd offset must be 0x44"
  );
  static_assert(
    offsetof(CPlatoonAssignmentRuntimeView, mHasLuaList) == 0x108,
    "CPlatoonAssignmentRuntimeView::mHasLuaList offset must be 0x108"
  );

  struct CPlatoonTemplatePlanQueryView
  {
    std::uint8_t pad_0000_0070[0x70];
    msvc8::string mTemplateName; // +0x70
    msvc8::string mPlanName;     // +0x8C
  };
  static_assert(
    offsetof(CPlatoonTemplatePlanQueryView, mTemplateName) == 0x70,
    "CPlatoonTemplatePlanQueryView::mTemplateName offset must be 0x70"
  );
  static_assert(
    offsetof(CPlatoonTemplatePlanQueryView, mPlanName) == 0x8C,
    "CPlatoonTemplatePlanQueryView::mPlanName offset must be 0x8C"
  );

  [[nodiscard]] moho::Unit* DecodeUnitFromEntitySetEntry(const moho::Entity* const entry) noexcept
  {
    const auto rawEntry = reinterpret_cast<std::uintptr_t>(entry);
    if (rawEntry <= kEntitySetUnitOwnerBias) {
      return nullptr;
    }

    return reinterpret_cast<moho::Unit*>(rawEntry - kEntitySetUnitOwnerBias);
  }

  void AppendUnitsToUnassignedSquad(moho::CPlatoon* const platoon, const moho::SEntitySetTemplateUnit& units)
  {
    if (platoon == nullptr) {
      return;
    }

    auto& platoonView = *reinterpret_cast<CPlatoonAssignmentRuntimeView*>(platoon);
    constexpr moho::ESquadClass kUnassignedSquadClass = static_cast<moho::ESquadClass>(0);
    for (CSquadAssignmentRuntimeView** squadLane = platoonView.mSquadBegin; squadLane != platoonView.mSquadEnd;
         ++squadLane) {
      CSquadAssignmentRuntimeView* const squad = *squadLane;
      if (squad == nullptr || squad->mSquadClass != kUnassignedSquadClass) {
        continue;
      }

      squad->mUnits.AddRange(units.mVec.begin(), units.mVec.end());
      break;
    }

    platoonView.mHasLuaList = 0u;
  }

  [[nodiscard]] const CPlatoonCleanupView& AsCleanupView(const moho::CPlatoon* const platoon)
  {
    return *reinterpret_cast<const CPlatoonCleanupView*>(platoon);
  }

  [[nodiscard]] bool PlatoonDisbandsOnIdle(const moho::CPlatoon* const platoon)
  {
    return platoon != nullptr && AsCleanupView(platoon).disbandOnIdle != 0u;
  }

  [[nodiscard]] bool IsPlatoonUniqueNameEmpty(const moho::CPlatoon* const platoon)
  {
    if (platoon == nullptr) {
      return true;
    }

    return ::_stricmp(AsCleanupView(platoon).uniqueName.data(), "") == 0;
  }

  [[nodiscard]] std::size_t CountPlatoonUnits(const moho::CPlatoon* const platoon)
  {
    if (platoon == nullptr) {
      return 0u;
    }

    const CPlatoonCleanupView& view = AsCleanupView(platoon);
    std::size_t unitCount = 0u;
    for (CSquadRuntimeUnitsView* const* squadLane = view.squadBegin; squadLane != view.squadEnd; ++squadLane) {
      const CSquadRuntimeUnitsView* const squad = *squadLane;
      if (squad == nullptr || squad->unitSlotsBegin == nullptr || squad->unitSlotsEnd == nullptr) {
        continue;
      }

      if (squad->unitSlotsEnd > squad->unitSlotsBegin) {
        unitCount += static_cast<std::size_t>(squad->unitSlotsEnd - squad->unitSlotsBegin);
      }
    }

    return unitCount;
  }

  void RunPlatoonOnDestroyAndDelete(moho::CPlatoon* const platoon)
  {
    if (platoon == nullptr) {
      return;
    }

    reinterpret_cast<moho::CScriptObject*>(platoon)->RunScript(kOnDestroyScriptName);
    delete platoon;
  }

  void ProcessArmyPathQueueBudget(void* const pathQueueProxy, int budget)
  {
    if (pathQueueProxy == nullptr) {
      return;
    }

    // The full PathQueue::Work closure (FUN_00765ED0 family) is still pending
    // dedicated PathQueue owner recovery. The runtime proxy is layout-compatible
    // with PathTables and preserves the same queue pointer lane.
    auto* const pathTables = static_cast<moho::PathTables*>(pathQueueProxy);
    pathTables->UpdateBackground(&budget);
  }

} // namespace

namespace moho
{
  gpg::RType* CArmyImpl::sType = nullptr;

  gpg::RType* CArmyImpl::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CArmyImpl));
    }
    return sType;
  }

  /**
   * Address: 0x006FE5B0 (FUN_006FE5B0, ??0CArmyImpl@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Initializes CArmyImpl-owned runtime pointer lanes and binds platoon-pool
   * storage pointers to inline storage.
   */
  CArmyImpl::CArmyImpl()
    : Simulation(nullptr)
    , AiBrain(nullptr)
    , AiReconDb(nullptr)
    , EconomyInfo(nullptr)
    , ArmyPlans()
    , Stats(nullptr)
    , InfluenceMap(nullptr)
    , PathFinder(nullptr)
    , UnknownShared220{}
    , UnitCategorySetsBegin(nullptr)
    , UnitCategorySetsEnd(nullptr)
    , UnitCategorySetsCapacityEnd(nullptr)
  {
    PlatoonPool.platoons.start_ = PlatoonPool.platoons.inlineVec_;
    PlatoonPool.platoons.end_ = PlatoonPool.platoons.inlineVec_;
    PlatoonPool.platoons.capacity_ = PlatoonPool.platoons.inlineVec_ + 8;
    PlatoonPool.platoons.originalVec_ = PlatoonPool.platoons.inlineVec_;
  }

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
    UnknownShared220.release();
    DestroyPathFinder(PathFinder);

    delete InfluenceMap;
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
   * Address: 0x005A2C20 (FUN_005A2C20, Moho::AI_Tick)
   *
   * What it does:
   * Runs one AI brain task tick for the army's AI, attacker, and reserved
   * thread stages.
   */
  void AI_Tick(CArmyImpl* army)
  {
    (void)army->GetSim();

    CAiBrain* const brain = army->GetArmyBrain();
    brain->mAiThreadStage->UserFrame();
    brain->mAttackerThreadStage->UserFrame();
    brain->mReservedThreadStage->UserFrame();
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
   * Address: 0x007010B0 (FUN_007010B0, Moho::CArmyImpl::DeserializePlatoons)
   */
  void CArmyImpl::DeserializePlatoons(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    while (true) {
      CPlatoon* const platoon = ReadOwnedCPlatoonPointer(archive, owner);
      if (!platoon) {
        break;
      }

      PlatoonPool.platoons.PushBack(platoon);
    }
  }

  /**
   * Address: 0x00701130 (FUN_00701130, Moho::CArmyImpl::SerializePlatoons)
   */
  void CArmyImpl::SerializePlatoons(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    for (CPlatoon* const* it = PlatoonPool.platoons.begin(); it != PlatoonPool.platoons.end(); ++it) {
      WriteOwnedCPlatoonPointer(archive, *it, owner);
    }

    WriteUnownedCPlatoonPointer(archive, nullptr, owner);
  }

  /**
   * Address: 0x00705BE0 (FUN_00705BE0, Moho::CArmyImpl::MemberDeserialize)
   */
  void CArmyImpl::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(SimArmy::StaticGetClass(), static_cast<SimArmy*>(this), owner);

    Simulation = ReadPointerTyped<Sim>(archive, owner, ResolveSimType(), false);
    ReplaceDeletingDtorOwnedPointer<2>(AiBrain, ReadPointerTyped<CAiBrain>(archive, owner, ResolveCAiBrainType(), true));
    ReplaceDeletingDtorOwnedPointer<0>(
      AiReconDb, ReadPointerTyped<CAiReconDBImpl>(archive, owner, ResolveCAiReconDBImplType(), true)
    );
    ReplaceEconomyOwnedPointer(EconomyInfo, ReadPointerTyped<CSimArmyEconomyInfo>(archive, owner, ResolveCEconomyType(), true));

    archive->ReadString(&ArmyPlans);

    ReplaceDeleteOwnedPointer(Stats, ReadPointerTyped<CArmyStats>(archive, owner, ResolveCArmyStatsType(), true));
    ReplaceDeleteOwnedPointer(
      InfluenceMap, ReadPointerTyped<CInfluenceMap>(archive, owner, ResolveCInfluenceMapType(), true)
    );
    ReplacePathFinderOwnedPointer(PathFinder, ReadPointerTyped<void>(archive, owner, ResolvePathQueueType(), true));

    gpg::RType* const categoryVectorType = ResolveEntitySetTemplateUnitVectorType();
    GPG_ASSERT(categoryVectorType != nullptr);
    if (categoryVectorType != nullptr) {
      archive->Read(categoryVectorType, &UnitCategorySetVector(*this), owner);
    }

    archive->ReadUInt(&UnitCategoryBaseIndex);
    archive->ReadUInt(&UnitCategoryMaxIndex);
    archive->ReadFloat(&UnitCapacity);

    bool ignoreUnitCap = false;
    archive->ReadBool(&ignoreUnitCap);
    IgnoreUnitCapFlag = static_cast<std::uint8_t>(ignoreUnitCap);

    archive->ReadInt(&PathCapacityLand);
    archive->ReadInt(&PathCapacitySea);
    archive->ReadInt(&PathCapacityBoth);
    DeserializePlatoons(archive);
  }

  /**
   * Address: 0x00705E40 (FUN_00705E40, Moho::CArmyImpl::MemberSerialize)
   */
  void CArmyImpl::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(SimArmy::StaticGetClass(), static_cast<const SimArmy*>(this), owner);

    WritePointerTyped(
      archive,
      Simulation,
      ResolveDynamicTypeOr(ResolveSimType(), Simulation),
      gpg::TrackedPointerState::Unowned,
      owner
    );
    WritePointerTyped(
      archive,
      AiBrain,
      ResolveDynamicTypeOr(ResolveCAiBrainType(), AiBrain),
      gpg::TrackedPointerState::Owned,
      owner
    );

    gpg::RType* reconType = ResolveIAiReconDBType();
    if (!reconType) {
      reconType = ResolveCAiReconDBImplType();
    }
    WritePointerTyped(
      archive,
      AiReconDb,
      ResolveDynamicTypeOr(reconType, AiReconDb),
      gpg::TrackedPointerState::Owned,
      owner
    );

    WritePointerTyped(
      archive,
      EconomyInfo,
      ResolveCEconomyType(),
      gpg::TrackedPointerState::Owned,
      owner
    );
    archive->WriteString(const_cast<msvc8::string*>(&ArmyPlans));

    WritePointerTyped(
      archive,
      Stats,
      ResolveDynamicTypeOr(ResolveCArmyStatsType(), Stats),
      gpg::TrackedPointerState::Owned,
      owner
    );
    WritePointerTyped(
      archive,
      InfluenceMap,
      ResolveDynamicTypeOr(ResolveCInfluenceMapType(), InfluenceMap),
      gpg::TrackedPointerState::Owned,
      owner
    );
    WritePointerTyped(archive, PathFinder, ResolvePathQueueType(), gpg::TrackedPointerState::Owned, owner);

    gpg::RType* const categoryVectorType = ResolveEntitySetTemplateUnitVectorType();
    GPG_ASSERT(categoryVectorType != nullptr);
    if (categoryVectorType != nullptr) {
      archive->Write(categoryVectorType, &UnitCategorySetVector(*this), owner);
    }

    archive->WriteUInt(UnitCategoryBaseIndex);
    archive->WriteUInt(UnitCategoryMaxIndex);
    archive->WriteFloat(UnitCapacity);
    archive->WriteBool(IgnoreUnitCapFlag != 0);
    archive->WriteInt(PathCapacityLand);
    archive->WriteInt(PathCapacitySea);
    archive->WriteInt(PathCapacityBoth);
    SerializePlatoons(archive);
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
   * Address: 0x006FDEE0 (FUN_006FDEE0, Moho::CArmyImpl::SetCanSee)
   *
   * What it does:
   * Updates per-army ally visibility against the current focused army id.
   */
  void CArmyImpl::SetCanSee(const std::int32_t focusArmyIndex)
  {
    if (focusArmyIndex < 0) {
      IsAlly = 1u;
      return;
    }

    IsAlly = AsBVIntSet(Allies).Contains(static_cast<std::uint32_t>(focusArmyIndex)) ? 1u : 0u;
  }

  /**
   * Address: 0x006FFF70 (FUN_006FFF70, Moho::CArmyImpl::RenderDebugPlayableRect)
   *
   * What it does:
   * Draws this army's playable-rect bounds to the sim debug canvas when
   * corresponding debug convars are enabled.
   */
  void CArmyImpl::RenderDebugPlayableRect()
  {
    if (Simulation == nullptr || UseWholeMapFlag != 0u) {
      return;
    }

    bool renderPlayableRect = false;
    if (!ReadSimConVarValue<bool>(Simulation, kConVarRenderDebugPlayableRect, renderPlayableRect) || !renderPlayableRect) {
      return;
    }

    if (Simulation->mSyncFilter.focusArmy != ArmyId) {
      return;
    }

    CDebugCanvas* const debugCanvas = Simulation->GetDebugCanvas();
    STIMap* const mapData = Simulation->mMapData;
    CHeightField* const heightField = (mapData != nullptr) ? mapData->GetHeightField() : nullptr;
    if (debugCanvas == nullptr || mapData == nullptr || heightField == nullptr) {
      return;
    }

    const gpg::Rect2i& playableRect = mapData->mPlayableRect;

    const Wm3::Vector2f lowerLeft{static_cast<float>(playableRect.x0), static_cast<float>(playableRect.z0)};
    const Wm3::Vector2f upperLeft{static_cast<float>(playableRect.x0), static_cast<float>(playableRect.z1)};
    const Wm3::Vector2f upperRight{static_cast<float>(playableRect.x1), static_cast<float>(playableRect.z1)};
    const Wm3::Vector2f lowerRight{static_cast<float>(playableRect.x1), static_cast<float>(playableRect.z0)};

    constexpr std::uint32_t kPlayableRectColor = 0xFF7F7F7Fu;
    debugCanvas->AddContouredLine(upperLeft, lowerLeft, kPlayableRectColor, *heightField);
    debugCanvas->AddContouredLine(upperRight, upperLeft, kPlayableRectColor, *heightField);
    debugCanvas->AddContouredLine(lowerRight, upperRight, kPlayableRectColor, *heightField);
    debugCanvas->AddContouredLine(lowerLeft, lowerRight, kPlayableRectColor, *heightField);
  }

  /**
   * Address: 0x00700820 (FUN_00700820, Moho::CArmyImpl::CleanUpPlatoons)
   *
   * What it does:
   * Removes disbanded or empty uniquely-named platoons from this army and
   * dispatches script destruction callbacks.
   */
  void CArmyImpl::CleanUpPlatoons()
  {
    msvc8::vector<CPlatoon*> platoonsToDestroy;
    CPlatoon* const armyPool = GetPlatoonByName(kArmyPoolName);

    auto& platoons = PlatoonPool.platoons;
    for (CPlatoon** platoonIt = platoons.begin(); platoonIt != platoons.end();) {
      CPlatoon* const platoon = *platoonIt;
      bool shouldDisband = false;

      if (PlatoonDisbandsOnIdle(platoon) && platoon != nullptr && platoon->AssignedSquadsAreIdle()) {
        if (armyPool != nullptr && platoon != armyPool) {
          platoon->PullUnassignedUnitsFrom(armyPool);
        }
        shouldDisband = true;
      }

      if (!shouldDisband && IsPlatoonUniqueNameEmpty(platoon) && CountPlatoonUnits(platoon) == 0u) {
        shouldDisband = true;
      }

      if (!shouldDisband) {
        ++platoonIt;
        continue;
      }

      platoonsToDestroy.push_back(platoon);
      platoonIt = platoons.erase(platoonIt);
    }

    for (CPlatoon** destroyIt = platoonsToDestroy.begin(); destroyIt != platoonsToDestroy.end(); ++destroyIt) {
      RunPlatoonOnDestroyAndDelete(*destroyIt);
    }
  }

  /**
   * Address: 0x006FFD70 (FUN_006FFD70, Moho::CArmyImpl::OnTick)
   *
   * What it does:
   * Executes one per-army simulation tick: refreshes visibility and platoon
   * cleanup, updates selected stat lanes, advances AI task stages, processes
   * pathing budget work, and renders enabled AI debug overlays.
   */
  void CArmyImpl::OnTick()
  {
    if (Stats != nullptr && Stats->mItem != nullptr) {
      Stats->mItem->ClearChildren(1);
    }

    if (NoRushTicks > 0) {
      --NoRushTicks;
    }

    if (Simulation != nullptr) {
      SetCanSee(Simulation->mSyncFilter.focusArmy);
    }

    CleanUpPlatoons();

    ProcessArmyEconomyTick(*this);

    if (Simulation != nullptr && Simulation->mCurTick > 10u && Stats != nullptr) {
      Stats->Update();
    }

    if (
      Simulation != nullptr
      && static_cast<std::uint32_t>(ArmyId) == (Simulation->mCurTick % 30u)
      && InfluenceMap != nullptr
    ) {
      InfluenceMap->Update();
    }

    if (CArmyStats* const armyStats = GetArmyStats(); armyStats != nullptr) {
      SetArmyFloatStatValue(armyStats, "UnitCap_Current", GetArmyUnitCostTotal());
      SetArmyFloatStatValue(armyStats, "UnitCap_MaxCap", GetUnitCap());
    }

    if (AiBrain != nullptr) {
      if (AiBrain->mAiThreadStage != nullptr) {
        AiBrain->mAiThreadStage->UserFrame();
      }
      if (AiBrain->mAttackerThreadStage != nullptr) {
        AiBrain->mAttackerThreadStage->UserFrame();
      }
      if (AiBrain->mReservedThreadStage != nullptr) {
        AiBrain->mReservedThreadStage->UserFrame();
      }
    }

    int pathBudget = 2500;
    if (Simulation != nullptr) {
      (void)ReadSimConVarValue<int>(Simulation, kConVarPathArmyBudget, pathBudget);
    }
    ProcessArmyPathQueueBudget(PathFinder, pathBudget);

    RenderDebugPlayableRect();

    bool renderAttackVectors = false;
    if (Simulation != nullptr) {
      (void)ReadSimConVarValue<bool>(Simulation, kConVarRenderDebugAttackVectors, renderAttackVectors);
    }

    if (!renderAttackVectors || AiBrain == nullptr) {
      return;
    }

    int debugArmyIndex = -1;
    if (Simulation != nullptr) {
      (void)ReadSimConVarValue<int>(Simulation, kConVarDebugArmyIndex, debugArmyIndex);
    }

    if (debugArmyIndex >= 0 && Simulation != nullptr) {
      CArmyImpl* debugArmy = nullptr;
      const std::size_t armyIndex = static_cast<std::size_t>(debugArmyIndex);
      if (armyIndex < Simulation->mArmiesList.size()) {
        debugArmy = Simulation->mArmiesList[armyIndex];
      }

      AiBrain->mCurrentEnemy = debugArmy;
      AiBrain->ProcessAttackVectors();
    }

    (void)CAiBrain::DrawDebug(AiBrain);
  }

  /**
   * Address: 0x00700540 (FUN_00700540, Moho::CArmyImpl::DisbandPlatoon)
   *
   * What it does:
   * Removes one platoon from this army and dispatches its `OnDestroy` script.
   */
  void CArmyImpl::DisbandPlatoon(CPlatoon* platoon)
  {
    CPlatoon* const armyPool = GetPlatoonByName(kArmyPoolName);

    auto& platoons = PlatoonPool.platoons;
    for (CPlatoon** platoonIt = platoons.begin(); platoonIt != platoons.end(); ++platoonIt) {
      CPlatoon* const current = *platoonIt;
      if (current != platoon || current == armyPool) {
        continue;
      }

      if (armyPool != nullptr) {
        current->PullUnassignedUnitsFrom(armyPool);
      }
      platoons.erase(platoonIt);
      RunPlatoonOnDestroyAndDelete(current);
      return;
    }
  }

  /**
   * Address: 0x007005F0 (FUN_007005F0, Moho::CArmyImpl::DisbandPlatoonUniquelyNamed)
   *
   * What it does:
   * Locates one platoon by unique-name string, removes it from this army, and
   * dispatches its `OnDestroy` script.
   */
  void CArmyImpl::DisbandPlatoonUniquelyNamed(const char* platoonName)
  {
    if (platoonName == nullptr) {
      return;
    }

    CPlatoon* const armyPool = GetPlatoonByName(kArmyPoolName);
    auto& platoons = PlatoonPool.platoons;
    for (CPlatoon** platoonIt = platoons.begin(); platoonIt != platoons.end(); ++platoonIt) {
      CPlatoon* const platoon = *platoonIt;
      if (::_stricmp(AsCleanupView(platoon).uniqueName.data(), platoonName) != 0) {
        continue;
      }

      if (armyPool != nullptr && platoon != armyPool) {
        platoon->PullUnassignedUnitsFrom(armyPool);
      }

      platoons.erase(platoonIt);
      RunPlatoonOnDestroyAndDelete(platoon);
      return;
    }
  }

  /**
   * Address: 0x007006C0 (FUN_007006C0, Moho::CArmyImpl::AssignUnitsToPlatoon)
   *
   * What it does:
   * Removes all input units from their existing platoons, resolves one named
   * platoon, and appends those units into its unassigned squad lane.
   */
  void CArmyImpl::AssignUnitsToPlatoon(const SEntitySetTemplateUnit* const units, const char* const platoonName)
  {
    RemoveUnitsFromPlatoons(units);
    CPlatoon* const platoon = GetPlatoonByName(platoonName);
    if (platoon == nullptr) {
      return;
    }

    AppendUnitsToUnassignedSquad(platoon, *units);
  }

  /**
   * Address: 0x00700700 (FUN_00700700, Moho::CArmyImpl::RemoveFromPlatoon)
   *
   * What it does:
   * Resolves the platoon currently owning one unit and removes that unit from
   * the first matching squad lane.
   */
  void CArmyImpl::RemoveFromPlatoon(Unit* const unit)
  {
    ESquadClass squadClass = static_cast<ESquadClass>(0);
    CPlatoon* const platoon = GetPlatoonFor(static_cast<int>(reinterpret_cast<std::uintptr_t>(unit)), &squadClass);
    if (platoon != nullptr) {
      platoon->RemoveUnit(unit);
    }
  }

  /**
   * Address: 0x00700730 (FUN_00700730, Moho::CArmyImpl::RemoveUnitsFromPlatoons)
   *
   * What it does:
   * Iterates one unit-set entity storage and detaches each decoded unit from
   * its owning platoon.
   */
  void CArmyImpl::RemoveUnitsFromPlatoons(const SEntitySetTemplateUnit* const units)
  {
    for (Entity* const* unitEntry = units->mVec.begin(); unitEntry != units->mVec.end(); ++unitEntry) {
      RemoveFromPlatoon(DecodeUnitFromEntitySetEntry(*unitEntry));
    }
  }

  /**
   * Address: 0x00700770 (FUN_00700770, Moho::CArmyImpl::GetNumPlatoonsTemplateNamed)
   *
   * What it does:
   * Counts platoon lanes whose template-name string matches `templateName`
   * case-insensitively.
   */
  int CArmyImpl::GetNumPlatoonsTemplateNamed(const char* const templateName)
  {
    int count = 0;
    for (CPlatoon* const* platoonIt = PlatoonPool.platoons.begin(); platoonIt != PlatoonPool.platoons.end();
         ++platoonIt) {
      const auto& platoonView = *reinterpret_cast<const CPlatoonTemplatePlanQueryView*>(*platoonIt);
      if (::_stricmp(platoonView.mTemplateName.data(), templateName) == 0) {
        ++count;
      }
    }

    return count;
  }

  /**
   * Address: 0x007007C0 (FUN_007007C0, Moho::CArmyImpl::GetNumPlatoonWithPlan)
   *
   * What it does:
   * Counts platoon lanes whose active plan string matches `planName`
   * case-insensitively.
   */
  int CArmyImpl::GetNumPlatoonWithPlan(const char* const planName)
  {
    int count = 0;
    for (CPlatoon* const* platoonIt = PlatoonPool.platoons.begin(); platoonIt != PlatoonPool.platoons.end();
         ++platoonIt) {
      const auto& platoonView = *reinterpret_cast<const CPlatoonTemplatePlanQueryView*>(*platoonIt);
      if (::_stricmp(platoonView.mPlanName.data(), planName) == 0) {
        ++count;
      }
    }

    return count;
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
    CEntityDbAllUnitsNode* node = Simulation->mEntityDB->AllUnitsEnd(armyIndex);
    CEntityDbAllUnitsNode* const endNode = Simulation->mEntityDB->AllUnitsEnd(armyIndex + 1u);
    while (node != endNode) {
      Unit* const unit = CEntityDb::UnitFromAllUnitsNode(node);
      if (unit == nullptr) {
        break;
      }

      if (!unit->IsUnitState(UNITSTATE_NoCost)) {
        currentCap += GetUnitCapCost(unit);
      }

      node = CEntityDb::NextAllUnitsNode(node);
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

    UnknownShared220.assign_retain(*value);

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

    *outValue = UnknownShared220.clone_retained();

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
   * Address: 0x00700410 (FUN_00700410, Moho::CArmyImpl::MakePlatoon)
   *
   * What it does:
   * Creates one platoon object owned by this army/sim and appends it to the
   * platoon pool vector.
   */
  CPlatoon* CArmyImpl::MakePlatoon(const char* const platoonName, const char* const aiPlan)
  {
    CPlatoon* const platoon = CPlatoon::Create(Simulation, this, platoonName, aiPlan);
    PlatoonPool.platoons.PushBack(platoon);
    return platoon;
  }

  /**
   * Address: 0x00700470 (FUN_00700470, Moho::CArmyImpl::GetPlatoonByName)
   */
  CPlatoon* CArmyImpl::GetPlatoonByName(const char* const platoonName)
  {
    if (platoonName == nullptr) {
      return nullptr;
    }

    for (CPlatoon* const platoon : PlatoonPool.platoons) {
      if (platoon == nullptr) {
        continue;
      }

      if (::_stricmp(AsCleanupView(platoon).uniqueName.data(), platoonName) == 0) {
        return platoon;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x007004E0 (FUN_007004E0, Moho::CArmyImpl::GetPlatoonFor)
   */
  CPlatoon* CArmyImpl::GetPlatoonFor(const int queryArg, ESquadClass* const outSquadClass)
  {
    Unit* const queryUnit = reinterpret_cast<Unit*>(static_cast<std::uintptr_t>(queryArg));

    for (CPlatoon* const platoon : PlatoonPool.platoons) {
      if (platoon == nullptr || !platoon->IsInPlatoon(queryUnit)) {
        continue;
      }

      if (outSquadClass != nullptr) {
        *outSquadClass = platoon->GetSquadClass(queryUnit);
      }

      return platoon;
    }

    return nullptr;
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
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
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

    Stats->SetStringValueByPath(platoonNameKey.data(), GetPlatoonName(platoon));
    Stats->SetStringValueByPath(squadClassKey.data(), GetSquadClassLexical(squadClass));
    Stats->SetStringValueByPath(aiPlanKey.data(), GetPlatoonAiPlan(platoon));
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

    (void)set->AddUnit(unit);
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

    return set->RemoveUnit(unit);
  }

  /**
   * Address: 0x00700EB0 (FUN_00700EB0, Moho::CArmyImpl::GetUnits)
   *
   * What it does:
   * Resets `outUnits`, then unions all per-category cached unit sets whose
   * blueprint ordinals are selected in `filterBuckets`.
   */
  void* CArmyImpl::GetUnits(void* const outUnits, void* const filterBuckets)
  {
    auto* const resultSet = static_cast<SEntitySetTemplateUnit*>(outUnits);
    if (resultSet == nullptr) {
      return nullptr;
    }

    resultSet->ListResetLinks();
    resultSet->mVec.RebindInlineNoFree();

    if (filterBuckets == nullptr || Simulation == nullptr || Simulation->mRules == nullptr) {
      return resultSet;
    }

    auto* const categorySet = static_cast<const EntityCategorySet*>(filterBuckets);
    const BVIntSet& categoryOrdinals = categorySet->Bits();
    CategoryRuleCursor cursor{};
    (void)InitializeCategoryRuleCursor(&cursor, Simulation->mRules, categoryOrdinals);
    const unsigned int sentinel = categoryOrdinals.Max();

    for (unsigned int ordinal = cursor.currentOrdinal; ordinal != sentinel;
         ordinal = cursor.categoryOrdinals->GetNext(ordinal)) {
      const RBlueprint* const blueprint = cursor.rules->GetBlueprintFromOrdinal(static_cast<int>(ordinal));
      if (blueprint == nullptr) {
        continue;
      }

      const auto* const entityBlueprint = reinterpret_cast<const REntityBlueprint*>(blueprint);
      const std::uint32_t categoryBitIndex = entityBlueprint->mCategoryBitIndex;
      if (categoryBitIndex < UnitCategoryBaseIndex || categoryBitIndex > UnitCategoryMaxIndex) {
        continue;
      }

      if (UnitCategorySetsBegin == nullptr) {
        continue;
      }

      const std::size_t relativeIndex = static_cast<std::size_t>(categoryBitIndex - UnitCategoryBaseIndex);
      SEntitySetTemplateUnit* const set = UnitCategorySetsBegin + relativeIndex;
      if (UnitCategorySetsEnd != nullptr && set >= UnitCategorySetsEnd) {
        continue;
      }

      if (set->mVec.begin() == set->mVec.end()) {
        continue;
      }

      resultSet->AddRange(set->mVec.begin(), set->mVec.end());
    }

    return resultSet;
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
   * Address: 0x006FE1B0 (FUN_006FE1B0, Moho::CArmyImpl::AddBuildRestriction)
   *
   * What it does:
   * Removes category bits from the army-level build-allow set and marks
   * all army units dirty for sync-game-data refresh.
   */
  void CArmyImpl::AddBuildRestriction(void* const restriction)
  {
    if (restriction == nullptr) {
      return;
    }

    auto* const categorySet = static_cast<const EntityCategorySet*>(restriction);
    CategoryWordRangeAsBitset(ArmyBuildCategoryFilterWords(*this)).RemoveAllFrom(&categorySet->Bits());
    MarkAllArmyUnitsNeedSyncGameData(*this);
  }

  /**
   * Address: 0x006FE220 (FUN_006FE220, Moho::CArmyImpl::RemoveBuildRestriction)
   *
   * What it does:
   * Adds category bits back into the army-level build-allow set and marks
   * all army units dirty for sync-game-data refresh.
   */
  void CArmyImpl::RemoveBuildRestriction(void* const restriction)
  {
    if (restriction == nullptr) {
      return;
    }

    auto* const categorySet = static_cast<const EntityCategorySet*>(restriction);
    (void)EntityCategory::Add(&ArmyBuildCategoryFilterWords(*this), categorySet);
    MarkAllArmyUnitsNeedSyncGameData(*this);
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
