#include "moho/sim/CPlatoon.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/EntityCategorySetVectorReflection.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/ai/IAiTransport.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/IArmy.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/CUnitCommand.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace moho
{
  template <>
  class CScrLuaMetatableFactory<CPlatoon> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CPlatoon>) == 0x08, "CScrLuaMetatableFactory<CPlatoon> size must be 0x08"
  );
} // namespace moho

namespace
{
  using moho::ESquadClass;
  using moho::EUnitState;
  using moho::CSquad;
  using moho::SEntitySetTemplateUnit;
  using moho::EntityCategorySet;
  using moho::Unit;

  constexpr ESquadClass kAllSquadsClass = static_cast<ESquadClass>(6);
  constexpr ESquadClass kUnassignedSquadClass = static_cast<ESquadClass>(0);
  // Sentinel entity id for ground-target commands (mirrors the value in
  // CCommandLuaFunctionRegistrations.cpp; the engine uses -0x10000000).
  constexpr std::int32_t kGroundTargetEntitySentinel = -0x10000000;
  // All-squad-classes sentinel used by the patrol/attack/move Lua bindings: applies
  // to every assigned squad class. Not one of the ESquadClass enum's named members.
  constexpr std::int32_t kAllSquadClassesSentinel = 6;
  constexpr std::uintptr_t kSquadUnitOwnerBias = 0x8;
  constexpr int kLuaNumberTypeTag = 3;

  constexpr const char* kCanConsiderFormingPlatoonHelpText = "CPlatoon:CanConsiderFormingPlatoon()";
  constexpr const char* kGetPlatoonUnitsHelpText = "platoon:GetPlatoonUnits()";
  constexpr const char* kCanFormPlatoonHelpText = "CPlatoon:CanFormPlatoon()";
  constexpr const char* kFormPlatoonHelpText = "CPlatoon:FormPlatoon()";
  constexpr const char* kSetPrioritizedTargetListHelpText = "CPlatoon:SetPrioritizedTargetList()";
  constexpr const char* kFindClosestUnitToBaseHelpText = "CPlatoon:FindClosestUnitToBase()";
  constexpr const char* kCanAttackTargetHelpText = "CPlatoon:CanAttackTarget()";
  constexpr const char* kAttackTargetHelpText = "CPlatoon:AttackTarget()";
  constexpr const char* kMoveToTargetHelpText = "CPlatoon:MoveToTarget()";
  constexpr const char* kLoadUnitsHelpText = "CPlatoon:LoadUnits()";
  constexpr const char* kFindPrioritizedUnitHelpText = "CPlatoon:FindPrioritizedUnit()";
  constexpr const char* kFindClosestUnitHelpText = "CPlatoon:FindClosestUnit()";
  constexpr const char* kFindFurthestUnitHelpText = "CPlatoon:FindFurthestUnit()";
  constexpr const char* kIsOpponentAIRunningHelpText = "CPlatoon:IsOpponentAIRunning()";
  constexpr const char* kGetPersonalityHelpText = "CPlatoon:GetPersonality()";
  constexpr const char* kGetBrainHelpText = "CPlatoon:GetBrain()";
  constexpr const char* kGetFactionIndexHelpText = "CPlatoon:GetFactionIndex()";
  constexpr const char* kUniquelyNamePlatoonHelpText = "CPlatoon:UniquelyNamePlatoon()";
  constexpr const char* kGetPlatoonUniqueNameHelpText = "CPlatoon:GetPlatoonUniqueName()";
  constexpr const char* kGetAIPlanHelpText = "CPlatoon:GetAIPlan()";
  constexpr const char* kSwitchAIPlanHelpText = "CPlatoon:SwitchAIPlan()";
  constexpr const char* kGetPlatoonPositionHelpText = "CPlatoon:GetPlatoonPosition()";
  constexpr const char* kGetSquadPositionHelpText = "CPlatoon:GetSquadPosition()";
  constexpr const char* kGetSquadUnitsHelpText = "CPlatoon:GetSquadUnits()";
  constexpr const char* kIsAttackingHelpText = "CPlatoon:IsAttacking()";
  constexpr const char* kIsMovingHelpText = "CPlatoon:IsMoving()";
  constexpr const char* kIsPatrollingHelpText = "CPlatoon:IsPatrolling()";
  constexpr const char* kIsFerryingHelpText = "CPlatoon:IsFerrying()";
  constexpr const char* kDisbandOnIdleHelpText = "CPlatoon:DisbandOnIdle()";
  constexpr const char* kIsCommandsActiveHelpText = "CPlatoon:IsCommandsActive()";
  constexpr const char* kFindHighestValueUnitHelpText = "CPlatoon:FindHighestValueUnit()";
  constexpr const char* kStopHelpText = "CPlatoon:Stop()";
  constexpr const char* kMoveToLocationHelpText = "CPlatoon:MoveToLocation()";
  constexpr const char* kAggressiveMoveToLocationHelpText = "CPlatoon:AggressiveMoveToLocation()";
  constexpr const char* kFerryToLocationHelpText = "CPlatoon:FerryToLocation()";
  constexpr const char* kUnloadUnitsAtLocationHelpText = "CPlatoon:UnloadUnitsAtLocation()";
  constexpr const char* kUnloadAllAtLocationHelpText = "CPlatoon:UnloadAllAtLocation()";
  constexpr const char* kPatrolHelpText = "CPlatoon:Patrol()";
  constexpr const char* kGuardTargetHelpText = "CPlatoon:GuardTarget()";
  constexpr const char* kDestroyHelpText = "CPlatoon:Destroy()";
  constexpr const char* kGetFerryBeaconsHelpText = "CPlatoon:GetFerryBeacons()";
  constexpr const char* kUseFerryBeaconHelpText = "CPlatoon:UseFerryBeacon()";
  constexpr const char* kUseTeleporterHelpText = "CPlatoon:UseTeleporter()";
  constexpr const char* kSetPlatoonFormationOverrideHelpText = "CPlatoon:SetPlatoonFormationOverride()";
  constexpr const char* kGetPlatoonLifetimeStatsHelpText = "CPlatoon:GetPlatoonLifetimeStats()";
  constexpr const char* kCalculatePlatoonThreatHelpText = "CPlatoon:CalculatePlatoonThreat()";
  constexpr const char* kCalculatePlatoonThreatAroundPositionHelpText =
    "CPlatoon:CalculatePlatoonThreatAroundPosition()";
  constexpr const char* kPlatoonCategoryCountAroundPositionHelpText =
    "Count how many units fit the specified category around a position";
  constexpr const char* kPlatoonCategoryCountHelpText = "Count how many units fit the specified category";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

  struct SerializerConstructHelperRuntime
  {
    void* mVtable;
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(SerializerConstructHelperRuntime, mHelperNext) == 0x04,
    "SerializerConstructHelperRuntime::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerializerConstructHelperRuntime, mHelperPrev) == 0x08,
    "SerializerConstructHelperRuntime::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SerializerConstructHelperRuntime, mConstructCallback) == 0x0C,
    "SerializerConstructHelperRuntime::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerializerConstructHelperRuntime, mDeleteCallback) == 0x10,
    "SerializerConstructHelperRuntime::mDeleteCallback offset must be 0x10"
  );
  static_assert(
    sizeof(SerializerConstructHelperRuntime) == 0x14,
    "SerializerConstructHelperRuntime size must be 0x14"
  );

  struct SerializerSaveLoadHelperRuntime
  {
    void* mVtable;
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(SerializerSaveLoadHelperRuntime, mHelperNext) == 0x04,
    "SerializerSaveLoadHelperRuntime::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerializerSaveLoadHelperRuntime, mHelperPrev) == 0x08,
    "SerializerSaveLoadHelperRuntime::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SerializerSaveLoadHelperRuntime, mLoadCallback) == 0x0C,
    "SerializerSaveLoadHelperRuntime::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerializerSaveLoadHelperRuntime, mSaveCallback) == 0x10,
    "SerializerSaveLoadHelperRuntime::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(SerializerSaveLoadHelperRuntime) == 0x14,
    "SerializerSaveLoadHelperRuntime size must be 0x14"
  );

  SerializerConstructHelperRuntime gCSquadConstructHelper{};
  SerializerConstructHelperRuntime gCPlatoonConstructHelper{};
  SerializerSaveLoadHelperRuntime gCSquadSerializerHelper{};
  SerializerSaveLoadHelperRuntime gCPlatoonSerializerHelper{};

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

  /**
   * Address: 0x0072AA20 (FUN_0072AA20)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CSquad`.
   */
  [[nodiscard]] gpg::RType* CachedCSquadType()
  {
    if (moho::CSquad::sType == nullptr) {
      moho::CSquad::sType = gpg::LookupRType(typeid(moho::CSquad));
    }
    return moho::CSquad::sType;
  }

  /**
   * Address: 0x00723AA0 (FUN_00723AA0)
   *
   * What it does:
   * Resolves and caches RTTI for one `CPlatoon` lane.
   */
  [[nodiscard]] gpg::RType* CachedCPlatoonType()
  {
    if (moho::CPlatoon::sType == nullptr) {
      moho::CPlatoon::sType = gpg::LookupRType(typeid(moho::CPlatoon));
    }
    return moho::CPlatoon::sType;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectTypeForCPlatoonSerializer()
  {
    if (moho::CScriptObject::sType == nullptr) {
      moho::CScriptObject::sType = gpg::LookupRType(typeid(moho::CScriptObject));
    }
    return moho::CScriptObject::sType;
  }

  [[nodiscard]] gpg::RType* CachedUnitSetTypeForCSquadSerializer()
  {
    static gpg::RType* sUnitSetType = nullptr;
    if (sUnitSetType == nullptr) {
      sUnitSetType = gpg::LookupRType(typeid(moho::SEntitySetTemplateUnit));
    }
    return sUnitSetType;
  }

  [[nodiscard]] gpg::RType* CachedESquadClassTypeForCSquadSerializer()
  {
    static gpg::RType* sSquadClassType = nullptr;
    if (sSquadClassType == nullptr) {
      sSquadClassType = gpg::LookupRType(typeid(moho::ESquadClass));
    }
    return sSquadClassType;
  }

  [[nodiscard]] gpg::RType* CachedEntityCategorySetVectorTypeForCSquadSerializer()
  {
    static gpg::RType* sCategoryVectorType = nullptr;
    if (sCategoryVectorType == nullptr) {
      sCategoryVectorType = gpg::LookupRType(typeid(msvc8::vector<moho::EntityCategorySet>));
    }
    return sCategoryVectorType;
  }

  /**
   * Address: 0x0072ABD0 (FUN_0072ABD0)
   *
   * What it does:
   * Registers `CScriptObject` as reflected base at zero offset for the
   * platoon runtime type descriptor lane.
   */
  [[maybe_unused]] void AddBase_CSCcriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectTypeForCPlatoonSerializer();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00724B90 (FUN_00724B90)
   *
   * What it does:
   * Thin thunk lane that forwards to `AddBase_CSCcriptObject`.
   */
  [[maybe_unused]] void AddBase_CSCcriptObjectThunk(gpg::RType* const typeInfo)
  {
    AddBase_CSCcriptObject(typeInfo);
  }

  void RegisterConstructCallbacks(
    gpg::RType* const type,
    const gpg::RType::construct_func_t constructCallback,
    const gpg::RType::delete_func_t deleteCallback
  )
  {
    GPG_ASSERT(type != nullptr);
    if (type == nullptr) {
      return;
    }

    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == constructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == deleteCallback);
    type->serConstructFunc_ = constructCallback;
    type->deleteFunc_ = deleteCallback;
  }

  struct PlatoonPriorityEntry
  {
    std::int32_t payload = 0; // +0x00
    float priority = 0.0f; // +0x04
  };
  static_assert(sizeof(PlatoonPriorityEntry) == 0x8, "PlatoonPriorityEntry size must be 0x8");

  struct PlatoonUnitSearchEntry
  {
    moho::Unit* unit = nullptr; // +0x00
    float distanceSq = 0.0f; // +0x04
  };
  static_assert(sizeof(PlatoonUnitSearchEntry) == 0x8, "PlatoonUnitSearchEntry size must be 0x8");

  /**
   * Address: 0x00733AB0 (FUN_00733AB0)
   *
   * What it does:
   * Fills one `[destinationBegin, destinationEnd)` range with a repeated
   * platoon-priority entry.
   */
  [[maybe_unused]] PlatoonPriorityEntry* FillPlatoonPriorityEntryRange(
    PlatoonPriorityEntry* destinationBegin,
    PlatoonPriorityEntry* const destinationEnd,
    const PlatoonPriorityEntry& value
  ) noexcept
  {
    while (destinationBegin != destinationEnd) {
      *destinationBegin = value;
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x00733AD0 (FUN_00733AD0)
   *
   * What it does:
   * Copies one platoon-priority range backward into destination storage.
   */
  [[maybe_unused]] PlatoonPriorityEntry* CopyPlatoonPriorityEntryRangeBackward(
    PlatoonPriorityEntry* destinationEnd,
    const PlatoonPriorityEntry* const sourceBegin,
    const PlatoonPriorityEntry* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

  struct PlatoonTreeNodeFlag45Runtime
  {
    PlatoonTreeNodeFlag45Runtime* left; // +0x00
    PlatoonTreeNodeFlag45Runtime* parent; // +0x04
    PlatoonTreeNodeFlag45Runtime* right; // +0x08
    std::uint8_t reserved0C_0F[0x04]; // +0x0C
    std::uint8_t payload_10_2B[0x1C]; // +0x10
    std::uint8_t sentinel44; // +0x2C
    std::uint8_t isNil45; // +0x2D
  };
  static_assert(offsetof(PlatoonTreeNodeFlag45Runtime, isNil45) == 0x2D, "PlatoonTreeNodeFlag45Runtime::isNil45 offset");

  /**
   * Address: 0x00736450 (FUN_00736450)
   *
   * What it does:
   * Returns the rightmost node reachable from a flag-45 RB-tree head.
   */
  [[maybe_unused]] PlatoonTreeNodeFlag45Runtime* FindPlatoonTreeRightmostNode(
    PlatoonTreeNodeFlag45Runtime* head
  ) noexcept
  {
    PlatoonTreeNodeFlag45Runtime* cursor = head->right;
    while (cursor->isNil45 == 0u) {
      head = cursor;
      cursor = head->right;
    }
    return head;
  }

  /**
   * Address: 0x00736470 (FUN_00736470)
   *
   * What it does:
   * Returns the leftmost node reachable from a flag-45 RB-tree head.
   */
  [[maybe_unused]] PlatoonTreeNodeFlag45Runtime* FindPlatoonTreeLeftmostNode(
    PlatoonTreeNodeFlag45Runtime* head
  ) noexcept
  {
    PlatoonTreeNodeFlag45Runtime* cursor = head->left;
    if (cursor->isNil45 != 0u) {
      return head;
    }

    do {
      head = cursor;
      cursor = head->left;
    } while (cursor->isNil45 == 0u);
    return head;
  }

  /**
   * Address: 0x00734460 (FUN_00734460)
   *
   * What it does:
   * Inserts one `{payload, priority}` heap entry by promoting parents while
   * preserving max-heap ordering within the bounded lane.
   */
  [[nodiscard]] std::int32_t InsertPlatoonPriorityEntryByPromotingParents(
    PlatoonPriorityEntry* const heap,
    int insertionIndex,
    const int lowerBoundIndex,
    const std::int32_t payload,
    const float priority
  ) noexcept
  {
    int parentIndex = (insertionIndex - 1) / 2;
    while (lowerBoundIndex < insertionIndex) {
      if (priority <= heap[parentIndex].priority) {
        break;
      }

      heap[insertionIndex] = heap[parentIndex];
      insertionIndex = parentIndex;
      parentIndex = (parentIndex - 1) / 2;
    }

    heap[insertionIndex].payload = payload;
    heap[insertionIndex].priority = priority;
    return payload;
  }

  /**
   * Address: 0x00734350 (FUN_00734350)
   *
   * What it does:
   * Sifts one heap gap down through max-priority children, then reinserts the
   * pending `{payload, priority}` pair via parent-promotion into the bounded
   * lane used by platoon target-priority sorting.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t SiftDownPlatoonPriorityEntryAndReinsert(
    int startIndex,
    const int heapSize,
    PlatoonPriorityEntry* const heap,
    const std::int32_t payload,
    const float priority
  ) noexcept
  {
    const int originalIndex = startIndex;
    int childIndex = (startIndex * 2) + 2;
    bool childEqualsHeapBoundary = (childIndex == heapSize);

    while (childIndex < heapSize) {
      const int leftChildIndex = childIndex - 1;
      if (heap[leftChildIndex].priority > heap[childIndex].priority) {
        childIndex = leftChildIndex;
      }

      heap[startIndex] = heap[childIndex];
      startIndex = childIndex;
      childIndex = (childIndex * 2) + 2;
      childEqualsHeapBoundary = (childIndex == heapSize);
    }

    if (childEqualsHeapBoundary) {
      heap[startIndex] = heap[heapSize - 1];
      startIndex = heapSize - 1;
    }

    return InsertPlatoonPriorityEntryByPromotingParents(
      heap,
      startIndex,
      originalIndex,
      payload,
      priority
    );
  }

  struct CSquadRuntimeView
  {
    std::uint8_t pad_0000_0010[0x10];
    void** mUnitSlotBegin;
    void** mUnitSlotEnd;
    std::uint8_t pad_0018_0030[0x18];
    ESquadClass mSquadClass;
  };
  static_assert(offsetof(CSquadRuntimeView, mUnitSlotBegin) == 0x10, "CSquadRuntimeView::mUnitSlotBegin offset");
  static_assert(offsetof(CSquadRuntimeView, mUnitSlotEnd) == 0x14, "CSquadRuntimeView::mUnitSlotEnd offset");
  static_assert(offsetof(CSquadRuntimeView, mSquadClass) == 0x30, "CSquadRuntimeView::mSquadClass offset");

  struct CPlatoonRuntimeView
  {
    std::uint8_t pad_0000_0038[0x38];
    moho::IArmy* mArmy;
    std::uint8_t pad_003C_0040[0x04];
    CSquadRuntimeView** mSquadStart;
    CSquadRuntimeView** mSquadEnd;
    std::uint8_t pad_0048_008C[0x44];
    msvc8::string mPlan;
    msvc8::string mUniqueName;
    std::uint8_t pad_00C4_00E0[0x1C];
    std::uint8_t mDisbandOnIdle;
    std::uint8_t pad_00E1_00E4[0x03];
    std::int32_t mLifetimeStat1;
    std::int32_t mLifetimeStat2;
    float mLifetimeStat3;
    float mLifetimeStat4;
    LuaPlus::LuaObject mLuaUnitList;
    std::uint8_t mHasLuaList;
  };
  static_assert(offsetof(CPlatoonRuntimeView, mArmy) == 0x38, "CPlatoonRuntimeView::mArmy offset");
  static_assert(offsetof(CPlatoonRuntimeView, mSquadStart) == 0x40, "CPlatoonRuntimeView::mSquadStart offset");
  static_assert(offsetof(CPlatoonRuntimeView, mSquadEnd) == 0x44, "CPlatoonRuntimeView::mSquadEnd offset");
  static_assert(offsetof(CPlatoonRuntimeView, mPlan) == 0x8C, "CPlatoonRuntimeView::mPlan offset");
  static_assert(offsetof(CPlatoonRuntimeView, mUniqueName) == 0xA8, "CPlatoonRuntimeView::mUniqueName offset");
  static_assert(
    offsetof(CPlatoonRuntimeView, mDisbandOnIdle) == 0xE0, "CPlatoonRuntimeView::mDisbandOnIdle offset"
  );
  static_assert(offsetof(CPlatoonRuntimeView, mLifetimeStat1) == 0xE4, "CPlatoonRuntimeView::mLifetimeStat1 offset");
  static_assert(offsetof(CPlatoonRuntimeView, mLifetimeStat2) == 0xE8, "CPlatoonRuntimeView::mLifetimeStat2 offset");
  static_assert(offsetof(CPlatoonRuntimeView, mLifetimeStat3) == 0xEC, "CPlatoonRuntimeView::mLifetimeStat3 offset");
  static_assert(offsetof(CPlatoonRuntimeView, mLifetimeStat4) == 0xF0, "CPlatoonRuntimeView::mLifetimeStat4 offset");
  static_assert(offsetof(CPlatoonRuntimeView, mLuaUnitList) == 0xF4, "CPlatoonRuntimeView::mLuaUnitList offset");
  static_assert(offsetof(CPlatoonRuntimeView, mHasLuaList) == 0x108, "CPlatoonRuntimeView::mHasLuaList offset");

  [[nodiscard]] moho::Unit* DecodeSquadUnit(void* const slotValue) noexcept
  {
    const auto raw = reinterpret_cast<std::uintptr_t>(slotValue);
    if (raw <= kSquadUnitOwnerBias) {
      return nullptr;
    }

    return reinterpret_cast<moho::Unit*>(raw - kSquadUnitOwnerBias);
  }

  [[nodiscard]] CSquadRuntimeView* FindSquadByClass(
    CPlatoonRuntimeView& platoonRuntime,
    const ESquadClass squadClass
  ) noexcept
  {
    for (CSquadRuntimeView** squadLane = platoonRuntime.mSquadStart; squadLane != platoonRuntime.mSquadEnd; ++squadLane) {
      CSquadRuntimeView* const squadView = *squadLane;
      if (!squadView || squadView->mSquadClass != squadClass) {
        continue;
      }

      return squadView;
    }

    return nullptr;
  }

  [[nodiscard]] bool SquadContainsUnit(const CSquadRuntimeView* const squad, const Unit* const targetUnit) noexcept
  {
    if (!squad || !targetUnit) {
      return false;
    }

    for (void** unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
      if (DecodeSquadUnit(*unitSlot) == targetUnit) {
        return true;
      }
    }

    return false;
  }

  void BuildPlatoonUnitSet(const CPlatoonRuntimeView& platoonRuntime, SEntitySetTemplateUnit& outSet);

  [[nodiscard]] bool ComputeSquadCenter(const CSquadRuntimeView* const squad, Wm3::Vector3f& outCenter) noexcept
  {
    if (!squad) {
      return false;
    }

    reinterpret_cast<const moho::CSquad*>(squad)->GetCenter(&outCenter);
    return true;
  }

  [[nodiscard]] bool ComputePlatoonCenter(const CPlatoonRuntimeView& platoonRuntime, Wm3::Vector3f& outCenter) noexcept
  {
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(platoonRuntime, platoonUnits);

    float sumX = 0.0f;
    float sumY = 0.0f;
    float sumZ = 0.0f;
    std::uint32_t unitCount = 0u;

    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!unit) {
        continue;
      }

      const Wm3::Vec3f& unitPosition = unit->GetPosition();
      sumX += unitPosition.x;
      sumY += unitPosition.y;
      sumZ += unitPosition.z;
      ++unitCount;
    }

    if (unitCount == 0u) {
      return false;
    }

    const float inverseCount = 1.0f / static_cast<float>(unitCount);
    outCenter.x = sumX * inverseCount;
    outCenter.y = sumY * inverseCount;
    outCenter.z = sumZ * inverseCount;
    return true;
  }

  /**
   * Address: 0x00725770 (FUN_00725770, sub_725770)
   *
   * What it does:
   * Rebuilds one sorted unique unit-entity set by merging all squad unit lanes
   * currently referenced by the platoon.
   */
  void BuildPlatoonUnitSet(const CPlatoonRuntimeView& platoonRuntime, SEntitySetTemplateUnit& outSet)
  {
    outSet.Clear();
    outSet.ListResetLinks();

    for (CSquadRuntimeView* const* squadLane = platoonRuntime.mSquadStart; squadLane != platoonRuntime.mSquadEnd; ++squadLane) {
      const CSquadRuntimeView* const squad = *squadLane;
      if (!squad || squad->mUnitSlotBegin == squad->mUnitSlotEnd) {
        continue;
      }

      for (void* const* unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
        (void)outSet.AddUnit(DecodeSquadUnit(*unitSlot));
      }
    }
  }

  /**
   * Address: 0x0072A210 (FUN_0072A210, sub_72A210)
   *
   * What it does:
   * Reads the platoon's owned squad pointers from the archive and appends each
   * recovered squad into the platoon's squad storage until the archive returns
   * a null pointer lane.
   */
  [[nodiscard]] gpg::ReadArchive* ReadPlatoonSquadsFromArchive(
    gpg::ReadArchive* const archive,
    moho::CPlatoon* const platoon
  )
  {
    if (archive == nullptr || platoon == nullptr) {
      return archive;
    }

    moho::CSquad* loadedSquad = nullptr;
    gpg::RRef ownerRef{};
    archive->ReadPointerOwned_CSquad(&loadedSquad, &ownerRef);
    while (loadedSquad != nullptr) {
      platoon->mSquadList.PushBack(loadedSquad);

      loadedSquad = nullptr;
      ownerRef = {};
      archive->ReadPointerOwned_CSquad(&loadedSquad, &ownerRef);
    }

    return archive;
  }

  /**
   * Address: 0x0072A290 (FUN_0072A290)
   *
   * What it does:
   * Writes each squad pointer lane as `owned`, then emits a null-squad
   * `unowned` terminator lane for platoon squad-list serialization.
   */
  [[maybe_unused]] void WritePlatoonSquadPointersToArchive(
    gpg::WriteArchive* const archive,
    moho::CPlatoon* const platoon
  )
  {
    const gpg::RRef ownerRef{};

    for (moho::CSquad** squadIt = platoon->mSquadList.begin(); squadIt != platoon->mSquadList.end(); ++squadIt) {
      gpg::RRef squadRef{};
      squadRef.mObj = *squadIt;
      squadRef.mType = CachedCSquadType();
      gpg::WriteRawPointer(archive, squadRef, gpg::TrackedPointerState::Owned, ownerRef);
    }

    gpg::RRef terminatorRef{};
    terminatorRef.mObj = nullptr;
    terminatorRef.mType = CachedCSquadType();
    gpg::WriteRawPointer(archive, terminatorRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  /**
   * Address: 0x00733480 (FUN_00733480, sub_733480)
   *
   * What it does:
   * Appends one platoon unit-search entry to the bounded result lane used by
   * `FormPlatoon()` candidate filtering.
   */
  [[maybe_unused]] void AppendPlatoonUnitSearchEntry(
    std::vector<PlatoonUnitSearchEntry>& entries,
    moho::Unit* const unit,
    const float distanceSq
  )
  {
    entries.push_back(PlatoonUnitSearchEntry{unit, distanceSq});
  }

  /**
   * Address: 0x00723A50 (FUN_00723A50, copy_CSquadUnits_into_EntitySet)
   *
   * What it does:
   * Copy-constructs destination `SEntitySetTemplateUnit` from one squad's
   * `mUnits` lane and returns destination.
   */
  [[nodiscard]] SEntitySetTemplateUnit*
  CopyCSquadUnitsIntoEntitySet(SEntitySetTemplateUnit* const destination, const CSquad* const squad)
  {
    if (destination == nullptr || squad == nullptr) {
      return destination;
    }

    return ::new (destination) SEntitySetTemplateUnit(squad->mUnits);
  }

  enum class PlatoonThreatType : std::int32_t
  {
    Air = 0,
    Surface = 1,
    Sub = 2,
    Economy = 3,
    Unknown = -1,
  };

  [[nodiscard]] PlatoonThreatType ParsePlatoonThreatType(const char* const threatTypeName) noexcept
  {
    if (threatTypeName == nullptr) {
      return PlatoonThreatType::Unknown;
    }

    if (::_stricmp(threatTypeName, "Air") == 0) {
      return PlatoonThreatType::Air;
    }
    if (::_stricmp(threatTypeName, "Surface") == 0) {
      return PlatoonThreatType::Surface;
    }
    if (::_stricmp(threatTypeName, "Sub") == 0) {
      return PlatoonThreatType::Sub;
    }
    if (::_stricmp(threatTypeName, "Economy") == 0) {
      return PlatoonThreatType::Economy;
    }

    return PlatoonThreatType::Unknown;
  }

  [[nodiscard]] bool BlueprintMatchesCategory(
    const moho::RUnitBlueprint* const blueprint,
    const moho::EntityCategorySet* const categorySet
  ) noexcept
  {
    if (!blueprint || !categorySet) {
      return false;
    }
    return categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  }

  [[nodiscard]] float ResolveBlueprintThreatValue(
    const moho::RUnitBlueprint& blueprint,
    const PlatoonThreatType threatType
  ) noexcept
  {
    switch (threatType) {
      case PlatoonThreatType::Air:
        return blueprint.Defense.AirThreatLevel;
      case PlatoonThreatType::Surface:
        return blueprint.Defense.SurfaceThreatLevel;
      case PlatoonThreatType::Sub:
        return blueprint.Defense.SubThreatLevel;
      case PlatoonThreatType::Economy:
        return blueprint.Defense.EconomyThreatLevel;
      case PlatoonThreatType::Unknown:
      default:
        return blueprint.Defense.AirThreatLevel + blueprint.Defense.SurfaceThreatLevel + blueprint.Defense.SubThreatLevel
          + blueprint.Defense.EconomyThreatLevel;
    }
  }

  [[nodiscard]] bool IsThreatCandidateUnit(const moho::Unit* const unit) noexcept
  {
    return unit && !unit->IsDead() && !unit->DestroyQueued();
  }

  void DestroyOwnedSquad(moho::CSquad* const squad) noexcept
  {
    if (squad == nullptr) {
      return;
    }

    auto** const vtable = *reinterpret_cast<void***>(squad);
    if (vtable == nullptr || vtable[2] == nullptr) {
      operator delete(squad);
      return;
    }

    using DeletingDtor = void(__thiscall*)(void*, int);
    const auto deletingDtor = reinterpret_cast<DeletingDtor>(vtable[2]);
    deletingDtor(squad, 1);
  }

  [[nodiscard]] float ReadSquaredRadiusArg(LuaPlus::LuaState* const state, const int stackIndex)
  {
    LuaPlus::LuaStackObject radiusArg(state, stackIndex);
    if (lua_type(state->m_state, stackIndex) != kLuaNumberTypeTag) {
      LuaPlus::LuaStackObject::TypeError(&radiusArg, "number");
    }

    const float radius = static_cast<float>(lua_tonumber(state->m_state, stackIndex));
    return radius * radius;
  }

  /**
   * Address: 0x00724820 (FUN_00724820, Moho::CSquad::Stop)
   *
   * What it does:
   * Iterates one squad's unit slot vector and stops each live unit by clearing
   * its command queue and stopping its attacker controller when present.
   */
  void StopSquad(CSquadRuntimeView* const squad)
  {
    if (!squad) {
      return;
    }

    for (void** unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
      moho::Unit* const unit = DecodeSquadUnit(*unitSlot);
      if (!unit || unit->IsDead()) {
        continue;
      }

      if (moho::CUnitCommandQueue* const commandQueue = unit->CommandQueue; commandQueue) {
        commandQueue->ClearCommandQueue();
      }

      if (moho::CAiAttackerImpl* const attacker = unit->AiAttacker; attacker) {
        attacker->Stop();
      }
    }
  }

  /**
   * Address: 0x00724150 (FUN_00724150, Moho::CSquad::RemoveUnit)
   *
   * What it does:
   * Searches one squad's unit slot vector for a matching entity, removes the
   * matched slot by compacting trailing entries, and preserves first-match
   * behavior.
   */
  void RemoveUnitFromSquad(CSquadRuntimeView* const squad, const moho::Entity* const entity)
  {
    if (!squad || !entity) {
      return;
    }

    void** const begin = squad->mUnitSlotBegin;
    void** const end = squad->mUnitSlotEnd;
    if (begin == end) {
      return;
    }

    void** match = begin;
    for (; match != end; ++match) {
      const moho::Unit* const unit = DecodeSquadUnit(*match);
      if (unit != nullptr && static_cast<const moho::Entity*>(unit) == entity) {
        break;
      }
    }

    if (match == end) {
      return;
    }

    const std::ptrdiff_t tailCount = end - (match + 1);
    if (tailCount > 0) {
      const std::size_t byteCount = static_cast<std::size_t>(tailCount) * sizeof(void*);
      memmove_s(match, byteCount, match + 1, byteCount);
    }

    squad->mUnitSlotEnd = end - 1;
  }

  /**
   * Address: 0x007241C0 (FUN_007241C0)
   *
   * What it does:
   * Removes every entity referenced by `units` from `squad` using
   * `RemoveUnitFromSquad` one-by-one.
   */
  [[maybe_unused]] void RemoveUnitSetMembersFromSquad(
    CSquadRuntimeView& squad,
    const SEntitySetTemplateUnit& units
  )
  {
    for (moho::Entity* const* unitIt = units.mVec.begin(); unitIt != units.mVec.end(); ++unitIt) {
      const Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*unitIt);
      RemoveUnitFromSquad(&squad, unit != nullptr ? static_cast<const moho::Entity*>(unit) : nullptr);
    }
  }

  /**
   * Address: 0x007241F0 (FUN_007241F0)
   *
   * What it does:
   * Appends the source unit range into destination set and invalidates the
   * platoon's cached Lua unit-list flag.
   */
  [[maybe_unused]] void AppendUnitSetRangeAndInvalidateLuaCache(
    const SEntitySetTemplateUnit& sourceUnits,
    SEntitySetTemplateUnit& destinationUnits,
    CPlatoonRuntimeView& platoonRuntime
  )
  {
    destinationUnits.AddRange(sourceUnits.mVec.begin(), sourceUnits.mVec.end());
    platoonRuntime.mHasLuaList = 0u;
  }

  /**
   * Address: 0x00724810 (FUN_00724810, Moho::ApplySquadPrioritizedTargetList)
   *
   * IDA signature:
   * int __userpurge sub_724810@<eax>(
   *   std::vector_EntityCategory *a1@<eax>,   // source category vector
   *   int a2);                                // CSquad*
   *
   * What it does:
   * One-shot register-order wrapper that forwards `categorySource` into
   * `CSquad::SetPrioritizedTargetList`. The binary emitted this trampoline
   * because the caller threads the source vector pointer through `eax` and
   * the squad pointer through the stack lane, while `SetPrioritizedTargetList`
   * expects `&mCats` (squad+0x50) in `eax`.
   */
  void ApplySquadPrioritizedTargetList(
    CSquad& squad,
    const msvc8::vector<EntityCategorySet>& categorySource
  )
  {
    squad.SetPrioritizedTargetList(categorySource);
  }

  /**
   * Address: 0x00725990 (FUN_00725990, Moho::ApplyPlatoonSquadPrioritizedTargetList)
   *
   * IDA signature:
   * int __fastcall sub_725990(
   *   int a1,                                 // CPlatoon*
   *   int a2,                                 // ESquadClass (squadClass selector)
   *   std::vector_EntityCategory *a3);        // source category vector
   *
   * What it does:
   * Walks the platoon's squad-pointer vector (`mSquadStart..mSquadEnd`) until
   * one squad reports the requested `squadClass`, then forwards
   * `categorySource` into that squad's `SetPrioritizedTargetList`. Missing or
   * mismatched squads short-circuit to no-op.
   */
  void ApplyPlatoonSquadPrioritizedTargetList(
    CPlatoonRuntimeView& platoonRuntime,
    const ESquadClass squadClass,
    const msvc8::vector<EntityCategorySet>& categorySource
  )
  {
    for (CSquadRuntimeView** squadLane = platoonRuntime.mSquadStart; squadLane != platoonRuntime.mSquadEnd; ++squadLane) {
      CSquadRuntimeView* const squadRuntime = *squadLane;
      if (squadRuntime == nullptr || squadRuntime->mSquadClass != squadClass) {
        continue;
      }
      auto& squad = *reinterpret_cast<CSquad*>(squadRuntime);
      ApplySquadPrioritizedTargetList(squad, categorySource);
      return;
    }
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandType()
  {
    return moho::CUnitCommand::StaticGetClass();
  }

  [[nodiscard]] gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int stackTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, stackTop);
    return out;
  }

  [[nodiscard]] moho::CScriptObject** ExtractScriptObjectSlot(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, moho::CScriptObject::GetPointerType());
    return static_cast<moho::CScriptObject**>(upcast.mObj);
  }

  /**
   * Address: 0x006F8D80 (FUN_006F8D80, func_GetCUnitCommandOpt)
   *
   * What it does:
   * Resolves one Lua game-object handle to an optional `CUnitCommand*`,
   * raising Lua type errors on invalid/non-command userdata.
   */
  [[nodiscard]] moho::CUnitCommand* func_GetCUnitCommandOpt(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* const state
  )
  {
    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlot(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCUnitCommandType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CUnitCommand*>(upcast.mObj);
  }
} // namespace

namespace moho
{
  CScrLuaMetatableFactory<CPlatoon> CScrLuaMetatableFactory<CPlatoon>::sInstance{};

  int cfunc_CPlatoonGetPersonality(lua_State* luaContext);
  int cfunc_CPlatoonGetBrain(lua_State* luaContext);
  int cfunc_CPlatoonGetFactionIndex(lua_State* luaContext);
  int cfunc_CPlatoonGetPersonalityL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGetBrainL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGetFactionIndexL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUniquelyNamePlatoon(lua_State* luaContext);
  int cfunc_CPlatoonGetPlatoonUniqueName(lua_State* luaContext);
  int cfunc_CPlatoonGetAIPlan(lua_State* luaContext);
  int cfunc_CPlatoonSwitchAIPlan(lua_State* luaContext);
  int cfunc_CPlatoonGetPlatoonPosition(lua_State* luaContext);
  int cfunc_CPlatoonGetSquadPosition(lua_State* luaContext);
  int cfunc_CPlatoonGetSquadUnits(lua_State* luaContext);

  int cfunc_CPlatoonGetPlatoonUnitsL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonCanFormPlatoonL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFormPlatoonL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonSetPrioritizedTargetListL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindPrioritizedUnitL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindClosestUnitL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindClosestUnitToBaseL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindFurthestUnitL(LuaPlus::LuaState* state);
  /**
   * Address: 0x0072F790 (FUN_0072F790, cfunc_CPlatoonCanAttackTargetL)
   *
   * What it does:
   * Resolves `(platoon, squadClass, targetUnit)` from Lua, locates the
   * matching squad lane, and returns whether that squad can attack the
   * requested unit.
   */
  int cfunc_CPlatoonCanAttackTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonAttackTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonMoveToTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindHighestValueUnitL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonStopL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonMoveToLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonAggressiveMoveToLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFerryToLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUnloadUnitsAtLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUnloadAllAtLocationL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonPatrolL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGuardTargetL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonDestroyL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGetFerryBeaconsL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUseFerryBeaconL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonUseTeleporterL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonSetPlatoonFormationOverrideL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonGetPlatoonLifetimeStatsL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonFindPrioritizedUnit(lua_State* luaContext);
  int cfunc_CPlatoonFindClosestUnit(lua_State* luaContext);
  int cfunc_CPlatoonFindFurthestUnit(lua_State* luaContext);
  int cfunc_CPlatoonGuardTarget(lua_State* luaContext);
  int cfunc_CPlatoonDestroy(lua_State* luaContext);
  int cfunc_CPlatoonGetFerryBeacons(lua_State* luaContext);
  int cfunc_CPlatoonUseFerryBeacon(lua_State* luaContext);
  int cfunc_CPlatoonUseTeleporter(lua_State* luaContext);
  int cfunc_CPlatoonSetPlatoonFormationOverride(lua_State* luaContext);
  int cfunc_CPlatoonGetPlatoonLifetimeStats(lua_State* luaContext);
  int cfunc_CPlatoonCalculatePlatoonThreatL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonPlatoonCategoryCountAroundPositionL(LuaPlus::LuaState* state);
  int cfunc_CPlatoonPlatoonCategoryCountL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0072A780 (FUN_0072A780, Moho::InstanceCounter<Moho::CPlatoon>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for CPlatoon instance
   * counting (`Instance Counts_<type-name-without-underscores>`).
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::CPlatoon>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::CPlatoon).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  /**
   * Address: 0x0072A370 (FUN_0072A370)
   *
   * What it does:
   * Increments the global `CPlatoon` instance-counter stat and returns the
   * input platoon pointer unchanged.
   */
  [[maybe_unused]] CPlatoon* MarkCPlatoonInstanceConstructed(CPlatoon* const platoon)
  {
    if (StatItem* const statItem = InstanceCounter<CPlatoon>::GetStatItem(); statItem != nullptr) {
#if defined(_WIN32)
      InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), 1);
#else
      statItem->mPrimaryValueBits += 1;
#endif
    }
    return platoon;
  }

  CScrLuaMetatableFactory<CPlatoon>& CScrLuaMetatableFactory<CPlatoon>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x0072AC30 (FUN_0072AC30)
   *
   * What it does:
   * Returns cached `CPlatoon` metatable object from Lua object-factory
   * storage.
   */
  [[maybe_unused]] LuaPlus::LuaObject* func_GetCPlatoonFactory(
    LuaPlus::LuaObject* const object,
    LuaPlus::LuaState* const state
  )
  {
    if (object == nullptr) {
      return nullptr;
    }

    *object = CScrLuaMetatableFactory<CPlatoon>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x00725060 (FUN_00725060, func_LoadPlatoon)
   *
   * IDA signature:
   * LuaPlus::LuaObject* __thiscall func_LoadPlatoon(
   *     LuaPlus::LuaState* state, LuaPlus::LuaObject* outObject);
   *
   * What it does:
   * Imports `/lua/platoon.lua` and stores its `Platoon` field into the
   * caller-provided `outObject`. When the module/class is missing, logs the
   * fallback diagnostic and writes the `CPlatoon` metatable factory into
   * `outObject` so `CPlatoon` can still bind into Lua.
   *
   * Callsite evidence (per CLAUDE.md callsite verification rule):
   *  - code xref from Moho::CPlatoon::CPlatoon ctor (FUN_00724CC0) at 0x00724D24
   */
  LuaPlus::LuaObject* func_LoadPlatoon(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const outObject
  )
  {
    *outObject = LuaPlus::LuaObject{};

    LuaPlus::LuaObject platoonModule = SCR_Import(state, "/lua/platoon.lua");
    if (!platoonModule.IsNil()) {
      LuaPlus::LuaObject platoonClass = platoonModule.GetByName("Platoon");
      *outObject = platoonClass;
    }

    if (outObject->IsNil()) {
      gpg::Logf(" can't find Platoon, using CPlatoon directly");
      LuaPlus::LuaObject fallbackFactory;
      (void)func_GetCPlatoonFactory(&fallbackFactory, state);
      *outObject = fallbackFactory;
    }

    return outObject;
  }

  /**
   * Address: 0x0072B1D0 (FUN_0072B1D0)
   *
   * What it does:
   * Rebinds the startup metatable-factory index lane for
   * `CScrLuaMetatableFactory<CPlatoon>` and returns that singleton.
   */
  [[maybe_unused]] CScrLuaMetatableFactory<CPlatoon>* startup_CScrLuaMetatableFactory_CPlatoon_Index()
  {
    auto& instance = CScrLuaMetatableFactory<CPlatoon>::Instance();
    instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CPlatoon>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x00723AC0 (FUN_00723AC0, Moho::CPlatoon::GetClass)
   */
  gpg::RType* CPlatoon::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CPlatoon));
    }
    return sType;
  }

  /**
   * Address: 0x00723AE0 (FUN_00723AE0, Moho::CPlatoon::GetDerivedObjectRef)
   */
  gpg::RRef CPlatoon::GetDerivedObjectRef()
  {
    gpg::RRef objectRef{};
    objectRef.mObj = this;
    objectRef.mType = GetClass();
    return objectRef;
  }

  /**
   * Address: 0x0072A300 (FUN_0072A300, Moho::CPlatoon::operator new)
   */
  CPlatoon* CPlatoon::Create(
    Sim* const sim,
    CArmyImpl* const army,
    const char* const platoonName,
    const char* const aiPlan
  )
  {
    return new (std::nothrow) CPlatoon(sim, army, platoonName, aiPlan);
  }

  /**
   * Address: 0x00724BA0 (FUN_00724BA0, Moho::CPlatoon::CPlatoon)
   */
  CPlatoon::CPlatoon()
    : CScriptObject()
    , mSim(nullptr)
    , mArmy(nullptr)
    , mUnknown_0x03C(0u)
    , mSquadList()
    , mName()
    , mPlan()
    , mUniqueName()
    , mFormation()
    , mDisbandOnIdle(0u)
    , mPad_0x0E1{0u, 0u, 0u}
    , mLifetimeStat1(0)
    , mLifetimeStat2(0)
    , mLifetimeStat3(0.0f)
    , mLifetimeStat4(0.0f)
    , mLuaUnitList()
    , mHasLuaList(0u)
    , mPad_0x109{0u, 0u, 0u, 0u, 0u, 0u, 0u}
  {
    if (StatItem* const statItem = InstanceCounter<CPlatoon>::GetStatItem(); statItem != nullptr) {
#if defined(_WIN32)
      InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), 1);
#else
      statItem->mPrimaryValueBits += 1;
#endif
    }
  }

  namespace
  {
    [[nodiscard]] LuaPlus::LuaObject ResolvePlatoonLuaClassForCtor(LuaPlus::LuaState* const state)
    {
      LuaPlus::LuaObject platoonClass{};
      (void)func_LoadPlatoon(state, &platoonClass);
      return platoonClass;
    }
  }

  /**
   * Address: 0x00724CC0 (FUN_00724CC0, Moho::CPlatoon::CPlatoon)
   */
  CPlatoon::CPlatoon(Sim* const sim, CArmyImpl* const army, const char* const platoonName, const char* const aiPlan)
    : CScriptObject(
      ResolvePlatoonLuaClassForCtor(sim ? sim->mLuaState : nullptr),
      LuaPlus::LuaObject{},
      LuaPlus::LuaObject{},
      LuaPlus::LuaObject{}
    )
    , mSim(sim)
    , mArmy(army)
    , mUnknown_0x03C(0u)
    , mSquadList()
    , mName()
    , mPlan()
    , mUniqueName()
    , mFormation()
    , mDisbandOnIdle(0u)
    , mPad_0x0E1{0u, 0u, 0u}
    , mLifetimeStat1(0)
    , mLifetimeStat2(0)
    , mLifetimeStat3(0.0f)
    , mLifetimeStat4(0.0f)
    , mLuaUnitList()
    , mHasLuaList(0u)
    , mPad_0x109{0u, 0u, 0u, 0u, 0u, 0u, 0u}
  {
    if (StatItem* const statItem = InstanceCounter<CPlatoon>::GetStatItem(); statItem != nullptr) {
#if defined(_WIN32)
      InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), 1);
#else
      statItem->mPrimaryValueBits += 1;
#endif
    }

    if (platoonName != nullptr) {
      mName.assign(platoonName);
    }

    if (aiPlan != nullptr) {
      mPlan.assign(aiPlan);
    }

    const char* planArg = mPlan.c_str();
    CallbackStr("OnCreate", &planArg);
  }

  /**
   * Address: 0x0072A0C0 (FUN_0072A0C0)
   *
   * What it does:
   * Forwards one platoon serializer construct thunk lane to
   * `CPlatoon::ConstructForSerializer`.
   */
  [[maybe_unused]] void ConstructCPlatoonForSerializerThunk(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    CPlatoon::ConstructForSerializer(result);
  }

  /**
   * Address: 0x0072A0D0 (FUN_0072A0D0, sub_72A0D0)
   */
  void CPlatoon::ConstructForSerializer(gpg::SerConstructResult* const result)
  {
    auto* const object = new (std::nothrow) CPlatoon();
    gpg::RRef objectRef{};
    gpg::RRef_CPlatoon(&objectRef, object);
    result->SetUnowned(objectRef, 0u);
  }

  void ConstructCSquadForSerializer(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    void* const storage = ::operator new(sizeof(CSquad), std::nothrow);
    CSquad* squad = nullptr;
    if (storage != nullptr) {
      squad = static_cast<CSquad*>(storage);
      squad->mSim = nullptr;
      squad->mPad_0x04 = 0u;
      ::new (&squad->mUnits) SEntitySetTemplateUnit();
      squad->mSquadClass = ESquadClass::Unassigned;
      ::new (&squad->mName) msvc8::string();
      ::new (&squad->mCats) msvc8::vector<EntityCategorySet>();
    }

    if (result == nullptr) {
      return;
    }

    gpg::RRef objectRef{};
    objectRef.mObj = squad;
    objectRef.mType = CachedCSquadType();
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x0072AB70 (FUN_0072AB70)
   *
   * What it does:
   * Single-argument serializer-construct adapter that forwards directly to
   * `ConstructCSquadForSerializer` (FUN_00724920).  Used by the 4-arg
   * reflection-construct thunk below and by RType construct-callback slots
   * that supply only the `SerConstructResult` pointer.
   */
  int ConstructCSquadForSerializerAlias(gpg::SerConstructResult* const result)
  {
    ConstructCSquadForSerializer(nullptr, 0, 0, result);
    return 0;
  }

  int ConstructCSquadForSerializerThunk(const int, const int, const int, gpg::SerConstructResult* const result)
  {
    return ConstructCSquadForSerializerAlias(result);
  }

  /**
   * Address: 0x0072AB80 (FUN_0072AB80)
   *
   * What it does:
   * Builds one reflected `RRef` for `squad` and copies it into `outRef`.
   */
  [[maybe_unused]] gpg::RRef* AssignCSquadRef(gpg::RRef& outRef, CSquad* const squad)
  {
    outRef.mObj = squad;
    outRef.mType = CachedCSquadType();
    return &outRef;
  }

  /**
   * Address: 0x0072AC70 (FUN_0072AC70)
   *
   * What it does:
   * Serializer construct adapter that forwards to
   * `CPlatoon::ConstructForSerializer`.
   */
  [[maybe_unused]] int ConstructCPlatoonForSerializerAlias(gpg::SerConstructResult* const result)
  {
    CPlatoon::ConstructForSerializer(result);
    return 0;
  }

  /**
   * Address: 0x0072B200 (FUN_0072B200)
   *
   * What it does:
   * Deserializes one `CSquad` payload lane in binary order:
   * `mSim`, `mUnits`, `mSquadClass`, `mName`, then `mCats`.
   */
  [[maybe_unused]] void DeserializeCSquadSerializerPayload(
    gpg::ReadArchive* const archive,
    CSquad* const squad
  )
  {
    gpg::RRef ownerRef{};
    archive->ReadPointer_Sim(&squad->mSim, &ownerRef);
    archive->Read(CachedUnitSetTypeForCSquadSerializer(), &squad->mUnits, ownerRef);

    ownerRef = {};
    archive->Read(CachedESquadClassTypeForCSquadSerializer(), &squad->mSquadClass, ownerRef);
    archive->ReadString(&squad->mName);

    ownerRef = {};
    archive->Read(CachedEntityCategorySetVectorTypeForCSquadSerializer(), &squad->mCats, ownerRef);
  }

  /**
   * Address: 0x0072ABB0 (FUN_0072ABB0)
   *
   * What it does:
   * Thunk lane that forwards to `DeserializeCSquadSerializerPayload`.
   */
  [[maybe_unused]] void DeserializeCSquadSerializerPayloadThunkA(
    gpg::ReadArchive* const archive,
    CSquad* const squad
  )
  {
    DeserializeCSquadSerializerPayload(archive, squad);
  }

  /**
   * Address: 0x0072B0A0 (FUN_0072B0A0)
   * Address: 0x007CFB00 (FUN_007CFB00)
   *
   * What it does:
   * Duplicate thunk lane forwarding to `DeserializeCSquadSerializerPayload`.
   */
  [[maybe_unused]] void DeserializeCSquadSerializerPayloadThunkB(
    gpg::ReadArchive* const archive,
    CSquad* const squad
  )
  {
    DeserializeCSquadSerializerPayload(archive, squad);
  }

  /**
   * Address: 0x0072B2E0 (FUN_0072B2E0)
   *
   * What it does:
   * Serializes one `CSquad` payload lane in binary order:
   * `mSim`, `mUnits`, `mSquadClass`, `mName`, then `mCats`.
   */
  [[maybe_unused]] void SerializeCSquadSerializerPayload(
    CSquad* const squad,
    gpg::WriteArchive* const archive
  )
  {
    gpg::RRef ownerRef{};
    gpg::RRef simRef{};
    gpg::AssignSimRef(&simRef, squad->mSim);
    gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, ownerRef);

    ownerRef = {};
    archive->Write(CachedUnitSetTypeForCSquadSerializer(), &squad->mUnits, ownerRef);

    ownerRef = {};
    archive->Write(CachedESquadClassTypeForCSquadSerializer(), &squad->mSquadClass, ownerRef);
    archive->WriteString(&squad->mName);

    ownerRef = {};
    archive->Write(CachedEntityCategorySetVectorTypeForCSquadSerializer(), &squad->mCats, ownerRef);
  }

  /**
   * Address: 0x0072ABC0 (FUN_0072ABC0)
   *
   * What it does:
   * Thunk lane that forwards to `SerializeCSquadSerializerPayload`.
   */
  [[maybe_unused]] void SerializeCSquadSerializerPayloadThunkA(
    CSquad* const squad,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCSquadSerializerPayload(squad, archive);
  }

  /**
   * Address: 0x0072B0B0 (FUN_0072B0B0)
   *
   * What it does:
   * Duplicate thunk lane forwarding to `SerializeCSquadSerializerPayload`.
   */
  [[maybe_unused]] void SerializeCSquadSerializerPayloadThunkB(
    CSquad* const squad,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCSquadSerializerPayload(squad, archive);
  }

  /**
   * Address: 0x0072B3C0 (FUN_0072B3C0)
   *
   * What it does:
   * Deserializes one `CPlatoon` payload lane in binary order:
   * CScriptObject base, sim/army pointers, squad list, strings, and stat lanes.
   */
  [[maybe_unused]] void DeserializeCPlatoonSerializerPayload(
    CPlatoon* const platoon,
    gpg::ReadArchive* const archive
  )
  {
    gpg::RRef ownerRef{};
    archive->Read(CachedCScriptObjectTypeForCPlatoonSerializer(), platoon, ownerRef);

    ownerRef = {};
    archive->ReadPointer_Sim(&platoon->mSim, &ownerRef);

    ownerRef = {};
    SimArmy* army = nullptr;
    archive->ReadPointer_SimArmy(&army, &ownerRef);
    platoon->mArmy = reinterpret_cast<IArmy*>(army);

    (void)ReadPlatoonSquadsFromArchive(archive, platoon);
    archive->ReadString(&platoon->mName);
    archive->ReadString(&platoon->mPlan);
    archive->ReadString(&platoon->mUniqueName);
    archive->ReadString(&platoon->mFormation);

    bool disbandOnIdle = false;
    archive->ReadBool(&disbandOnIdle);
    platoon->mDisbandOnIdle = disbandOnIdle ? 1u : 0u;
    archive->ReadInt(&platoon->mLifetimeStat1);
    archive->ReadInt(&platoon->mLifetimeStat2);
    archive->ReadFloat(&platoon->mLifetimeStat3);
    archive->ReadFloat(&platoon->mLifetimeStat4);
  }

  /**
   * Address: 0x0072B0C0 (FUN_0072B0C0)
   *
   * What it does:
   * Thunk lane that forwards to `DeserializeCPlatoonSerializerPayload`.
   */
  [[maybe_unused]] void DeserializeCPlatoonSerializerPayloadThunk(
    CPlatoon* const platoon,
    gpg::ReadArchive* const archive
  )
  {
    DeserializeCPlatoonSerializerPayload(platoon, archive);
  }

  /**
   * Address: 0x0072ACB0 (FUN_0072ACB0)
   *
   * What it does:
   * Secondary thunk lane that forwards to `DeserializeCPlatoonSerializerPayload`.
   */
  [[maybe_unused]] void DeserializeCPlatoonSerializerPayloadThunkB(
    CPlatoon* const platoon,
    gpg::ReadArchive* const archive
  )
  {
    DeserializeCPlatoonSerializerPayload(platoon, archive);
  }

  /**
   * Address: 0x0072B4D0 (FUN_0072B4D0)
   *
   * What it does:
   * Serializes one `CPlatoon` payload lane in binary order:
   * CScriptObject base, sim/army pointers, squad list, strings, and stat lanes.
   */
  [[maybe_unused]] void SerializeCPlatoonSerializerPayload(
    CPlatoon* const platoon,
    gpg::WriteArchive* const archive
  )
  {
    gpg::RRef ownerRef{};
    archive->Write(CachedCScriptObjectTypeForCPlatoonSerializer(), platoon, ownerRef);

    ownerRef = {};
    gpg::RRef simRef{};
    gpg::AssignSimRef(&simRef, platoon->mSim);
    gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, ownerRef);

    ownerRef = {};
    gpg::RRef armyRef{};
    gpg::RRef_SimArmy(&armyRef, reinterpret_cast<SimArmy*>(platoon->mArmy));
    gpg::WriteRawPointer(archive, armyRef, gpg::TrackedPointerState::Unowned, ownerRef);

    WritePlatoonSquadPointersToArchive(archive, platoon);

    archive->WriteString(&platoon->mName);
    archive->WriteString(&platoon->mPlan);
    archive->WriteString(&platoon->mUniqueName);
    archive->WriteString(&platoon->mFormation);
    archive->WriteBool(platoon->mDisbandOnIdle != 0u);
    archive->WriteInt(platoon->mLifetimeStat1);
    archive->WriteInt(platoon->mLifetimeStat2);
    archive->WriteFloat(platoon->mLifetimeStat3);
    archive->WriteFloat(platoon->mLifetimeStat4);
  }

  /**
   * Address: 0x0072B0D0 (FUN_0072B0D0)
   *
   * What it does:
   * Tail-jump thunk lane that forwards directly to
   * `SerializeCPlatoonSerializerPayload`.
   */
  [[maybe_unused]] void SerializeCPlatoonSerializerPayloadThunkB(
    CPlatoon* const platoon,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCPlatoonSerializerPayload(platoon, archive);
  }

  /**
   * Address: 0x0072ACC0 (FUN_0072ACC0)
   *
   * What it does:
   * Thunk lane that forwards to `SerializeCPlatoonSerializerPayload`.
   */
  [[maybe_unused]] void SerializeCPlatoonSerializerPayloadThunk(
    CPlatoon* const platoon,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCPlatoonSerializerPayload(platoon, archive);
  }

  /**
   * Address: 0x007249B0 (FUN_007249B0, Moho::CSquadSerializer::Deserialize)
   *
   * What it does:
   * Forwards one CSquad serializer-load callback lane to
   * `DeserializeCSquadSerializerPayload`.
   */
  [[maybe_unused]] void DeserializeCSquadSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    DeserializeCSquadSerializerPayload(archive, reinterpret_cast<CSquad*>(static_cast<std::uintptr_t>(objectPtr)));
  }

  /**
   * Address: 0x007249C0 (FUN_007249C0, Moho::CSquadSerializer::Serialize)
   *
   * What it does:
   * Forwards one CSquad serializer-save callback lane to
   * `SerializeCSquadSerializerPayload`.
   */
  [[maybe_unused]] void SerializeCSquadSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    SerializeCSquadSerializerPayload(
      reinterpret_cast<CSquad*>(static_cast<std::uintptr_t>(objectPtr)),
      archive
    );
  }

  /**
   * Address: 0x0072A160 (FUN_0072A160, Moho::CPlatoonSerializer::Deserialize)
   *
   * What it does:
   * Forwards one CPlatoon serializer-load callback lane to
   * `DeserializeCPlatoonSerializerPayload`.
   */
  [[maybe_unused]] void DeserializeCPlatoonSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    DeserializeCPlatoonSerializerPayload(
      reinterpret_cast<CPlatoon*>(static_cast<std::uintptr_t>(objectPtr)),
      archive
    );
  }

  /**
   * Address: 0x0072A170 (FUN_0072A170, Moho::CPlatoonSerializer::Serialize)
   *
   * What it does:
   * Forwards one CPlatoon serializer-save callback lane to
   * `SerializeCPlatoonSerializerPayload`.
   */
  [[maybe_unused]] void SerializeCPlatoonSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    SerializeCPlatoonSerializerPayload(
      reinterpret_cast<CPlatoon*>(static_cast<std::uintptr_t>(objectPtr)),
      archive
    );
  }

  /**
   * Address: 0x0072AB50 (FUN_0072AB50, sub_72AB50)
   *
   * IDA signature:
   * void __cdecl sub_72AB50(Moho::CSquad* a1);
   *
   * What it does:
   * Serializer delete-callback for CSquad instances: destroys the squad and frees
   * its storage. Address-taken into `gCSquadConstructHelper.mDeleteCallback`.
   */
  void DeleteConstructedCSquadForSerializer(void* const objectPtr)
  {
    auto* const squad = static_cast<CSquad*>(objectPtr);
    if (squad == nullptr) {
      return;
    }

    squad->~CSquad();
    ::operator delete(squad);
  }

  void DeleteConstructedCPlatoonForSerializer(void* const objectPtr)
  {
    if (objectPtr == nullptr) {
      return;
    }

    delete static_cast<CPlatoon*>(objectPtr);
  }

  /**
   * Address: 0x00724880 (FUN_00724880)
   *
   * What it does:
   * Initializes startup CSquad construct-helper links and binds construct/delete
   * callbacks for serializer-owned squad objects.
   */
  [[nodiscard]] SerializerConstructHelperRuntime* InitializeCSquadConstructHelper()
  {
    InitializeHelperNode(gCSquadConstructHelper);
    gCSquadConstructHelper.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCSquadForSerializerThunk);
    gCSquadConstructHelper.mDeleteCallback = &DeleteConstructedCSquadForSerializer;
    RegisterConstructCallbacks(
      CachedCSquadType(),
      gCSquadConstructHelper.mConstructCallback,
      gCSquadConstructHelper.mDeleteCallback
    );
    return &gCSquadConstructHelper;
  }

  /**
   * Address: 0x0072A540 (FUN_0072A540)
   *
   * What it does:
   * Reinitializes the CSquad generic construct-helper lane with the same
   * construct/delete callback pair.
   */
  [[nodiscard]] SerializerConstructHelperRuntime* InitializeCSquadGenericConstructHelper()
  {
    return InitializeCSquadConstructHelper();
  }

  /**
   * Address: 0x0072A030 (FUN_0072A030)
   *
   * What it does:
   * Initializes startup CPlatoon construct-helper links and binds
   * serializer construct/delete callbacks.
   */
  [[nodiscard]] SerializerConstructHelperRuntime* InitializeCPlatoonConstructHelper()
  {
    InitializeHelperNode(gCPlatoonConstructHelper);
    gCPlatoonConstructHelper.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCPlatoonForSerializerThunk);
    gCPlatoonConstructHelper.mDeleteCallback = &DeleteConstructedCPlatoonForSerializer;
    RegisterConstructCallbacks(
      CachedCPlatoonType(),
      gCPlatoonConstructHelper.mConstructCallback,
      gCPlatoonConstructHelper.mDeleteCallback
    );
    return &gCPlatoonConstructHelper;
  }

  /**
   * Address: 0x0072A660 (FUN_0072A660)
   *
   * What it does:
   * Reinitializes the CPlatoon generic construct-helper lane with the same
   * construct/delete callback pair.
   */
  [[nodiscard]] SerializerConstructHelperRuntime* InitializeCPlatoonGenericConstructHelper()
  {
    return InitializeCPlatoonConstructHelper();
  }

  /**
   * Address: 0x0072A570 (FUN_0072A570, CSquadConstruct::RegisterConstructFunction)
   *
   * IDA signature:
   * void __thiscall sub_72A570(SerializerConstructHelperRuntime *this);
   *
   * What it does:
   * Virtual-method body installed in the `CSquadConstruct` helper vtable.
   * Lazily resolves the `CSquad` reflection descriptor, asserts the construct
   * callback slot is empty, and publishes this helper's construct/delete
   * callbacks to the descriptor.
   *
   * Notes:
   * Mirrors the binary's single `!type->mSerConstructFunc` assert (no separate
   * delete-slot assert) so it diverges from the shared
   * `RegisterConstructCallbacks` helper.
   */
  [[maybe_unused]] void CSquadConstructRegisterConstructFunction(
    SerializerConstructHelperRuntime* const helper
  )
  {
    constexpr const char* kSquadConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSquadSerializationConstructLine = 231;
    constexpr const char* kSquadSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = CachedCSquadType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(
        kSquadConstructAssertText,
        kSquadSerializationConstructLine,
        kSquadSerializationSourcePath
      );
    }
    type->serConstructFunc_ = helper->mConstructCallback;
    type->deleteFunc_ = helper->mDeleteCallback;
  }

  /**
   * Address: 0x0072A690 (FUN_0072A690, CPlatoonConstruct::RegisterConstructFunction)
   *
   * IDA signature:
   * void __thiscall sub_72A690(SerializerConstructHelperRuntime *this);
   *
   * What it does:
   * Virtual-method body installed in the `CPlatoonConstruct` helper vtable.
   * Lazily resolves the `CPlatoon` reflection descriptor, asserts the
   * construct callback slot is empty, and publishes this helper's
   * construct/delete callbacks to the descriptor.
   *
   * Notes:
   * Mirrors the binary's single `!type->mSerConstructFunc` assert (no separate
   * delete-slot assert) so it diverges from the shared
   * `RegisterConstructCallbacks` helper.
   */
  [[maybe_unused]] void CPlatoonConstructRegisterConstructFunction(
    SerializerConstructHelperRuntime* const helper
  )
  {
    constexpr const char* kPlatoonConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kPlatoonSerializationConstructLine = 231;
    constexpr const char* kPlatoonSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = CachedCPlatoonType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(
        kPlatoonConstructAssertText,
        kPlatoonSerializationConstructLine,
        kPlatoonSerializationSourcePath
      );
    }
    type->serConstructFunc_ = helper->mConstructCallback;
    type->deleteFunc_ = helper->mDeleteCallback;
  }

  /**
   * Address: 0x007249D0 (FUN_007249D0)
   *
   * What it does:
   * Initializes startup CSquad save/load-helper links and binds serializer
   * callback lanes.
   */
  [[nodiscard]] SerializerSaveLoadHelperRuntime* InitializeCSquadSerializerHelperStoragePrimary()
  {
    InitializeHelperNode(gCSquadSerializerHelper);
    gCSquadSerializerHelper.mLoadCallback = &DeserializeCSquadSerializerCallback;
    gCSquadSerializerHelper.mSaveCallback = &SerializeCSquadSerializerCallback;
    return &gCSquadSerializerHelper;
  }

  /**
   * Address: 0x0072A5C0 (FUN_0072A5C0)
   *
   * What it does:
   * Reinitializes CSquad save/load-helper links and callback lanes.
   */
  [[nodiscard]] SerializerSaveLoadHelperRuntime* InitializeCSquadSerializerHelperStorageSecondary()
  {
    InitializeHelperNode(gCSquadSerializerHelper);
    gCSquadSerializerHelper.mLoadCallback = &DeserializeCSquadSerializerCallback;
    gCSquadSerializerHelper.mSaveCallback = &SerializeCSquadSerializerCallback;
    return &gCSquadSerializerHelper;
  }

  /**
   * Address: 0x0072A180 (FUN_0072A180)
   *
   * What it does:
   * Initializes startup CPlatoon save/load-helper links and binds serializer
   * callback lanes.
   */
  [[nodiscard]] SerializerSaveLoadHelperRuntime* InitializeCPlatoonSerializerHelperStoragePrimary()
  {
    InitializeHelperNode(gCPlatoonSerializerHelper);
    gCPlatoonSerializerHelper.mLoadCallback = &DeserializeCPlatoonSerializerCallback;
    gCPlatoonSerializerHelper.mSaveCallback = &SerializeCPlatoonSerializerCallback;
    return &gCPlatoonSerializerHelper;
  }

  /**
   * Address: 0x0072A6E0 (FUN_0072A6E0)
   *
   * What it does:
   * Reinitializes CPlatoon save/load-helper links and callback lanes.
   */
  [[nodiscard]] SerializerSaveLoadHelperRuntime* InitializeCPlatoonSerializerHelperStorageSecondary()
  {
    InitializeHelperNode(gCPlatoonSerializerHelper);
    gCPlatoonSerializerHelper.mLoadCallback = &DeserializeCPlatoonSerializerCallback;
    gCPlatoonSerializerHelper.mSaveCallback = &SerializeCPlatoonSerializerCallback;
    return &gCPlatoonSerializerHelper;
  }

  /**
   * Address: 0x00724EB0 (FUN_00724EB0, Moho::CPlatoon::~CPlatoon)
   */
  CPlatoon::~CPlatoon()
  {
    for (CSquad** squadIt = mSquadList.begin(); squadIt != mSquadList.end(); ++squadIt) {
      DestroyOwnedSquad(*squadIt);
    }
    mSquadList.ResetStorageToInline();

    if (StatItem* const statItem = InstanceCounter<CPlatoon>::GetStatItem(); statItem != nullptr) {
#if defined(_WIN32)
      InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), -1);
#else
      statItem->mPrimaryValueBits -= 1;
#endif
    }
  }

  /**
   * Address: 0x00725630 (FUN_00725630, Moho::CPlatoon::GetSquad)
   *
   * What it does:
   * Returns the first squad lane matching `squadClass`, or null when absent.
   */
  CSquad* CPlatoon::GetSquad(const ESquadClass squadClass)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    CSquadRuntimeView* const squadView = FindSquadByClass(runtimeView, squadClass);
    return reinterpret_cast<CSquad*>(squadView);
  }

  /**
   * Address: 0x00725660 (FUN_00725660, Moho::CPlatoon::CountUnassignedUnitsWithBP)
   *
   * What it does:
   * Returns the count of live unassigned-squad units whose blueprint id
   * matches `blueprintId`, or zero when no unassigned squad exists.
   */
  int CPlatoon::CountUnassignedUnitsWithBP(const char* const blueprintId)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    CSquadRuntimeView* const squadView = FindSquadByClass(runtimeView, ESquadClass::Unassigned);
    if (squadView == nullptr) {
      return 0;
    }

    return reinterpret_cast<CSquad*>(squadView)->CountUnitsWithBP(blueprintId);
  }

  /**
   * Address: 0x007256A0 (FUN_007256A0, Moho::CPlatoon::CountUnassignedUnitsInCategory)
   *
   * What it does:
   * Returns the count of live unassigned-squad units matching `categorySet`,
   * or zero when no unassigned squad exists.
   */
  int CPlatoon::CountUnassignedUnitsInCategory(const EntityCategorySet* const categorySet)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    CSquadRuntimeView* const squadView = FindSquadByClass(runtimeView, ESquadClass::Unassigned);
    if (squadView == nullptr) {
      return 0;
    }

    return reinterpret_cast<CSquad*>(squadView)->CountUnitsInCategory(categorySet);
  }

  /**
   * Address: 0x007256E0 (FUN_007256E0, Moho::CPlatoon::GetUnassignedUnitsInCategory)
   *
   * What it does:
   * Walks platoon squad lanes to find the first `SQUADCLASS_Unassigned` squad
   * and forwards category-filtered appends into `outUnits`.
   */
  void CPlatoon::GetUnassignedUnitsInCategory(
    const EntityCategorySet* const categorySet, const int maxCount, SEntitySetTemplateUnit& outUnits
  )
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    for (CSquadRuntimeView** squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      CSquadRuntimeView* const squadView = *squadLane;
      if (squadView == nullptr || squadView->mSquadClass != ESquadClass::Unassigned) {
        continue;
      }

      reinterpret_cast<CSquad*>(squadView)->AppendUnitsInCategory(categorySet, maxCount, outUnits);
      return;
    }
  }

  /**
   * Address: 0x00725730 (FUN_00725730, Moho::CPlatoon::GetUnassignedUnitsWithBP)
   *
   * What it does:
   * Looks up this platoon's `SQUADCLASS_Unassigned` squad (if any) and
   * forwards the blueprint-id filter and `maxCount` cap to
   * `CSquad::AppendUnitsWithBP`, which appends the matching live units into
   * `outUnits`. No-op when the platoon has no unassigned squad.
   */
  void CPlatoon::GetUnassignedUnitsWithBP(
    const char* const blueprintId, const int maxCount, SEntitySetTemplateUnit& outUnits
  )
  {
    CSquad* const unassignedSquad = GetSquad(ESquadClass::Unassigned);
    if (unassignedSquad == nullptr) {
      return;
    }
    unassignedSquad->AppendUnitsWithBP(blueprintId, maxCount, outUnits);
  }

  /**
   * Address: 0x00725840 (FUN_00725840, sub_725840)
   */
  int CPlatoon::CountAllSquadUnitSlots() const
  {
    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    int unitSlotCount = 0;
    for (CSquadRuntimeView* const* squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      const CSquadRuntimeView* const squad = *squadLane;
      unitSlotCount += static_cast<int>(squad->mUnitSlotEnd - squad->mUnitSlotBegin);
    }
    return unitSlotCount;
  }

  /**
   * Address: 0x007253B0 (FUN_007253B0, Moho::CPlatoon::RemoveUnit)
   *
   * What it does:
   * Clears the platoon Lua unit cache flag, walks each squad lane, and removes
   * the first matching entity from the owning squad.
   */
  void CPlatoon::RemoveUnit(Entity* const unit)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    runtimeView.mHasLuaList = 0u;

    for (CSquadRuntimeView** squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      CSquadRuntimeView* const squadView = *squadLane;
      if (!squadView) {
        continue;
      }

      for (void** unitSlot = squadView->mUnitSlotBegin; unitSlot != squadView->mUnitSlotEnd; ++unitSlot) {
        const moho::Unit* const squadUnit = DecodeSquadUnit(*unitSlot);
        if (squadUnit != nullptr && static_cast<const moho::Entity*>(squadUnit) == unit) {
          RemoveUnitFromSquad(squadView, unit);
          return;
        }
      }
    }
  }

  /**
   * Address: 0x007251D0 (FUN_007251D0, Moho::CPlatoon::IsInPlatoon)
   *
   * What it does:
   * Returns whether the provided unit pointer is currently present in any
   * squad lane of this platoon.
   */
  bool CPlatoon::IsInPlatoon(const Unit* const unit) const
  {
    if (!unit) {
      return false;
    }

    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (CSquadRuntimeView* const* squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      if (SquadContainsUnit(*squadLane, unit)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00725220 (FUN_00725220, Moho::CPlatoon::GetSquadClass)
   *
   * What it does:
   * Scans all squad lanes and returns the class of the first squad containing
   * the provided unit; otherwise returns `SQUADCLASS_Unassigned`.
   */
  ESquadClass CPlatoon::GetSquadClass(const Unit* const unit) const
  {
    if (!unit) {
      return kUnassignedSquadClass;
    }

    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (CSquadRuntimeView* const* squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      const CSquadRuntimeView* const squadView = *squadLane;
      if (SquadContainsUnit(squadView, unit)) {
        return squadView->mSquadClass;
      }
    }

    return kUnassignedSquadClass;
  }

  /**
   * Address: 0x00725280 (FUN_00725280, sub_725280)
   *
   * What it does:
   * Finds the first squad lane matching `squadClass`, appends every entry in
   * `units` into that squad's entity set, and clears the Lua unit-list cache
   * validity flag on this platoon.
   */
  void CPlatoon::AppendUnitsToSquad(const ESquadClass squadClass, const SEntitySetTemplateUnit& units)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    for (CSquadRuntimeView** squadLane = runtimeView.mSquadStart; squadLane != runtimeView.mSquadEnd; ++squadLane) {
      CSquadRuntimeView* const squadView = *squadLane;
      if (squadView == nullptr || squadView->mSquadClass != squadClass) {
        continue;
      }

      reinterpret_cast<CSquad*>(squadView)->mUnits.AddRange(units.mVec.begin(), units.mVec.end());
      break;
    }

    runtimeView.mHasLuaList = 0u;
  }

  /**
   * Address: 0x007252D0 (FUN_007252D0, sub_7252D0)
   *
   * What it does:
   * Builds a one-unit temporary set around `unit`, forwards into
   * `AppendUnitsToSquad`, and preserves the Lua unit-list cache invalidation
   * side effect for this platoon.
   */
  void CPlatoon::AppendUnitToSquad(const ESquadClass squadClass, Unit* const unit)
  {
    SEntitySetTemplateUnit singleUnitSet{};
    (void)singleUnitSet.AddUnit(unit);
    AppendUnitsToSquad(squadClass, singleUnitSet);
  }

  /**
   * Address: 0x00729F90 (FUN_00729F90, Moho::CPlatoon::SquadHasState)
   *
   * What it does:
   * Returns whether the requested squad class has at least one unit in the
   * requested state (`SQUADCLASS_all` checks all assigned classes 1..5).
   */
  bool CPlatoon::SquadHasState(const ESquadClass squadClass, CPlatoon* const platoon, const EUnitState state)
  {
    if (!platoon) {
      return false;
    }

    for (std::int32_t checkedClass = 1; checkedClass < static_cast<std::int32_t>(kAllSquadsClass); ++checkedClass) {
      if (squadClass != kAllSquadsClass && static_cast<std::int32_t>(squadClass) != checkedClass) {
        continue;
      }

      // Preserve original call lane: this method always queries GetSquad using
      // the incoming squadClass token, even during SQUADCLASS_all scanning.
      CSquad* const squad = platoon->GetSquad(squadClass);
      if (squad != nullptr && squad->HasUnitWithState(state)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x007261B0 (FUN_007261B0, Moho::CPlatoon::Stop)
   *
   * What it does:
   * Stops all non-unassigned squads when `squadClass == 6`, otherwise stops the
   * first squad matching the requested class.
   */
  void CPlatoon::Stop(const ESquadClass squadClass)
  {
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    if (squadClass == kAllSquadsClass) {
      for (CSquadRuntimeView** squad = runtimeView.mSquadStart; squad != runtimeView.mSquadEnd; ++squad) {
        CSquadRuntimeView* const squadView = *squad;
        if (squadView && squadView->mSquadClass != kUnassignedSquadClass) {
          StopSquad(squadView);
        }
      }
      return;
    }

    for (CSquadRuntimeView** squad = runtimeView.mSquadStart; squad != runtimeView.mSquadEnd; ++squad) {
      CSquadRuntimeView* const squadView = *squad;
      if (!squadView || squadView->mSquadClass != squadClass) {
        continue;
      }

      StopSquad(squadView);
      return;
    }
  }

  /**
   * Address: 0x00728A70 (FUN_00728A70, Moho::CPlatoon::LoadUnits)
   *
   * What it does:
   * Scans assigned squads for payload/transport candidates, reserves load slots
   * per transport, issues `UNITCOMMAND_TransportLoadUnits`, and returns issued
   * command weak-links.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::LoadUnits(const EntityCategorySet* const categorySet)
  {
    constexpr const char* kTransportationCategoryName = "TRANSPORTATION";

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};
    SEntitySetTemplateUnit transportUnits{};
    SEntitySetTemplateUnit unitsToLoad{};

    for (int squadClassValue = 1; squadClassValue < static_cast<int>(kAllSquadsClass); ++squadClassValue) {
      CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassValue));
      if (squad == nullptr) {
        continue;
      }

      const SEntitySetTemplateUnit squadUnits(squad->mUnits);

      for (Entity* const* unitEntry = squadUnits.mVec.begin(); unitEntry != squadUnits.mVec.end(); ++unitEntry) {
        Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*unitEntry);
        if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt()) {
          continue;
        }

        if (!unit->IsInCategory(kTransportationCategoryName)
            && EntityCategory::HasBlueprint(unit->GetBlueprint(), categorySet)) {
          (void)unitsToLoad.AddUnit(unit);
        }
      }

      for (Entity* const* unitEntry = squadUnits.mVec.begin(); unitEntry != squadUnits.mVec.end(); ++unitEntry) {
        Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*unitEntry);
        if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt()) {
          continue;
        }

        if (unit->IsInCategory(kTransportationCategoryName)) {
          (void)transportUnits.AddUnit(unit);
        }
      }
    }

    if (transportUnits.Empty() || unitsToLoad.Empty()) {
      gpg::Logf(
        "Cannot perform load operation. Attempted to load %d units onto %d transports",
        static_cast<int>(unitsToLoad.Size()),
        static_cast<int>(transportUnits.Size())
      );
      return issuedCommands;
    }

    SEntitySetTemplateUnit assignedUnits{};
    for (Entity* const* transportEntry = transportUnits.mVec.begin(); transportEntry != transportUnits.mVec.end();
         ++transportEntry) {
      Unit* const transportUnit = SEntitySetTemplateUnit::UnitFromEntry(*transportEntry);
      if (transportUnit == nullptr) {
        continue;
      }

      IAiTransport* const aiTransport = transportUnit->AiTransport;
      if (aiTransport == nullptr) {
        continue;
      }

      SEntitySetTemplateUnit commandUnits{};
      for (Entity* const* unitEntry = unitsToLoad.mVec.begin(); unitEntry != unitsToLoad.mVec.end(); ++unitEntry) {
        Unit* const loadUnit = SEntitySetTemplateUnit::UnitFromEntry(*unitEntry);
        if (loadUnit == nullptr || assignedUnits.ContainsUnit(loadUnit)) {
          continue;
        }

        if (aiTransport->TransportAssignSlot(loadUnit, -1)) {
          (void)commandUnits.AddUnit(loadUnit);
          (void)assignedUnits.AddUnit(loadUnit);
        }
      }

      for (Entity* const* unitEntry = commandUnits.mVec.begin(); unitEntry != commandUnits.mVec.end(); ++unitEntry) {
        Unit* const reservedUnit = SEntitySetTemplateUnit::UnitFromEntry(*unitEntry);
        aiTransport->TransportRemoveUnitReservation(reservedUnit);
      }

      (void)commandUnits.AddUnit(transportUnit);

      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(transportUnit->GetEntityId());
      commandIssueData.mTarget.mPos.x = 0.0f;
      commandIssueData.mTarget.mPos.y = 0.0f;
      commandIssueData.mTarget.mPos.z = 0.0f;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, commandUnits, commandIssueData, false);
      if (issuedCommand != nullptr) {
        InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x007247A0 (FUN_007247A0, Moho::CSquad::UnitHasOrder)
   *
   * What it does:
   * Returns true when the squad has no live unit with an active command at
   * queue-head; returns false as soon as one active queued command is found.
   */
  [[nodiscard]] bool SquadHasNoActiveOrders(const CSquadRuntimeView* const squad) noexcept
  {
    if (!squad) {
      return true;
    }

    for (void** unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
      Unit* const unit = DecodeSquadUnit(*unitSlot);
      if (!unit || unit->IsDead()) {
        continue;
      }

      const CUnitCommandQueue* const commandQueue = unit->CommandQueue;
      if (!commandQueue || commandQueue->mCommandVec.empty()) {
        continue;
      }

      const WeakPtr<CUnitCommand>& commandLink = commandQueue->mCommandVec.front();
      if (commandLink.GetObjectPtr() != nullptr) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x00729FE0 (FUN_00729FE0, Moho::CPlatoon::SquadsHaveOrders)
   *
   * What it does:
   * Scans assigned squad classes (1..5) and returns true only when each
   * present squad has no active orders.
   */
  bool CPlatoon::AssignedSquadsAreIdle() const
  {
    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(this);

    for (std::int32_t squadClass = 1; squadClass < static_cast<std::int32_t>(kAllSquadsClass); ++squadClass) {
      CSquadRuntimeView* matchingSquad = nullptr;
      for (CSquadRuntimeView** squad = runtimeView.mSquadStart; squad != runtimeView.mSquadEnd; ++squad) {
        CSquadRuntimeView* const squadView = *squad;
        if (!squadView || static_cast<std::int32_t>(squadView->mSquadClass) != squadClass) {
          continue;
        }

        matchingSquad = squadView;
        break;
      }

      if (matchingSquad && !SquadHasNoActiveOrders(matchingSquad)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x00725150 (FUN_00725150, Moho::CPlatoon::SwitchAIPlan)
   *
   * What it does:
   * Replaces platoon plan string and dispatches script `OnDestroy/OnCreate`
   * when the plan text changes.
   */
  void CPlatoon::SwitchAIPlan(const char* const planName)
  {
    const char* const normalizedPlan = (planName != nullptr) ? planName : "";
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    if (runtimeView.mPlan == normalizedPlan) {
      return;
    }

    auto* const scriptObject = reinterpret_cast<CScriptObject*>(this);
    scriptObject->RunScript("OnDestroy");

    runtimeView.mPlan.assign(normalizedPlan);

    const char* callbackArg = normalizedPlan;
    scriptObject->CallbackStr("OnCreate", &callbackArg);
  }

  /**
   * Address: 0x0072B720 (FUN_0072B720, Moho::CPlatoon::GetArmy)
   *
   * What it does:
   * Returns this platoon's owning army lane.
   */
  IArmy* CPlatoon::GetArmy() const
  {
    return mArmy;
  }

  /**
   * Address: 0x0072B7A0 (FUN_0072B7A0, Moho::CPlatoon::GetLifetimeStat1)
   *
   * What it does:
   * Returns the first integer lifetime-stat lane.
   */
  std::int32_t CPlatoon::GetLifetimeStat1() const
  {
    return mLifetimeStat1;
  }

  /**
   * Address: 0x0072B7B0 (FUN_0072B7B0, Moho::CPlatoon::GetLifetimeStat2)
   *
   * What it does:
   * Returns the second integer lifetime-stat lane.
   */
  std::int32_t CPlatoon::GetLifetimeStat2() const
  {
    return mLifetimeStat2;
  }

  /**
   * Address: 0x0072B790 (FUN_0072B790, sub_72B790)
   */
  CPlatoon* CPlatoon::MarkDisbandOnIdle()
  {
    mDisbandOnIdle = 1u;
    return this;
  }

  /**
   * Address: 0x0072B7C0 (FUN_0072B7C0, sub_72B7C0)
   */
  float CPlatoon::GetLifetimeStat3() const
  {
    return mLifetimeStat3;
  }

  /**
   * Address: 0x0072B7D0 (FUN_0072B7D0, sub_72B7D0)
   */
  float CPlatoon::GetLifetimeStat4() const
  {
    return mLifetimeStat4;
  }

  /**
   * Address: 0x0072B7F0 (FUN_0072B7F0, sub_72B7F0)
   */
  bool CPlatoon::HasLuaUnitList() const
  {
    return mHasLuaList != 0u;
  }

  /**
   * Address: 0x00736D70 (FUN_00736D70, sub_736D70)
   */
  CPlatoon* CPlatoon::AddLifetimeStat3(const float delta)
  {
    mLifetimeStat3 += delta;
    return this;
  }

  /**
   * Address: 0x00736D90 (FUN_00736D90, sub_736D90)
   */
  CPlatoon* CPlatoon::AddLifetimeStat4(const float delta)
  {
    mLifetimeStat4 += delta;
    return this;
  }

  /**
   * Address: 0x0072B730 (FUN_0072B730, Moho::CPlatoon::SetPlatoonFormationOverride)
   *
   * What it does:
   * Replaces the platoon formation override string lane.
   */
  void CPlatoon::SetPlatoonFormationOverride(const msvc8::string& formationName)
  {
    mFormation = formationName;
  }

  /**
   * Address: 0x00725410 (FUN_00725410, Moho::CPlatoon::PullUnassignedUnitsFrom)
   *
   * What it does:
   * Moves this platoon's current unit set into the army-pool platoon
   * unassigned lane and invalidates Lua unit-list caches on both platoons.
   */
  void CPlatoon::PullUnassignedUnitsFrom(CPlatoon* const armyPool)
  {
    constexpr const char* kArmyPoolName = "ArmyPool";

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(this);
    runtimeView.mHasLuaList = 0u;

    if (armyPool == nullptr || runtimeView.mArmy == nullptr) {
      return;
    }

    auto& armyPoolRuntimeView = *reinterpret_cast<CPlatoonRuntimeView*>(armyPool);
    if (FindSquadByClass(armyPoolRuntimeView, kUnassignedSquadClass) == nullptr) {
      return;
    }

    SEntitySetTemplateUnit unitsToTransfer{};
    BuildPlatoonUnitSet(runtimeView, unitsToTransfer);
    if (unitsToTransfer.mVec.empty()) {
      return;
    }

    runtimeView.mArmy->AssignUnitsToPlatoon(&unitsToTransfer, kArmyPoolName);
    runtimeView.mHasLuaList = 0u;
    armyPoolRuntimeView.mHasLuaList = 0u;
  }

  /**
   * Address: 0x00BDAE70 (FUN_00BDAE70, register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards startup registration to `func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef()
  {
    return func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();
  }

  /**
   * Address: 0x0072B810 (FUN_0072B810, cfunc_CPlatoonIsOpponentAIRunning)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonIsOpponentAIRunningL`.
   */
  int cfunc_CPlatoonIsOpponentAIRunning(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsOpponentAIRunningL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072B830 (FUN_0072B830, func_CPlatoonIsOpponentAIRunning_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsOpponentAIRunning()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsOpponentAIRunning_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsOpponentAIRunning",
      &cfunc_CPlatoonIsOpponentAIRunning,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsOpponentAIRunningHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072B970 (FUN_0072B970, cfunc_CPlatoonGetPersonality)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPersonalityL`.
   */
  int cfunc_CPlatoonGetPersonality(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPersonalityL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072B9F0 (FUN_0072B9F0, cfunc_CPlatoonGetPersonalityL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning brain personality object, or
   * `nil` when no personality exists.
   */
  int cfunc_CPlatoonGetPersonalityL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetPersonalityHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    CAiPersonality* const personality = runtimeView.mArmy->GetArmyBrain()->mPersonality;

    if (personality != nullptr) {
      personality->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
    }

    return 1;
  }

  /**
   * Address: 0x0072B990 (FUN_0072B990, func_CPlatoonGetPersonality_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPersonality()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPersonality_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPersonality",
      &cfunc_CPlatoonGetPersonality,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPersonalityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BAD0 (FUN_0072BAD0, cfunc_CPlatoonGetBrain)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetBrainL`.
   */
  int cfunc_CPlatoonGetBrain(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetBrainL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BB50 (FUN_0072BB50, cfunc_CPlatoonGetBrainL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning army-brain Lua object.
   */
  int cfunc_CPlatoonGetBrainL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetBrainHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    runtimeView.mArmy->GetArmyBrain()->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072BAF0 (FUN_0072BAF0, func_CPlatoonGetBrain_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetBrain()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetBrain_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetBrain",
      &cfunc_CPlatoonGetBrain,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetBrainHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BC10 (FUN_0072BC10, cfunc_CPlatoonGetFactionIndex)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetFactionIndexL`.
   */
  int cfunc_CPlatoonGetFactionIndex(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetFactionIndexL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BC90 (FUN_0072BC90, cfunc_CPlatoonGetFactionIndexL)
   *
   * What it does:
   * Resolves one platoon and returns one-based faction index from the owning
   * army brain.
   */
  int cfunc_CPlatoonGetFactionIndexL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetFactionIndexHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    const CAiBrain* const brain = runtimeView.mArmy->GetArmyBrain();

    lua_pushnumber(state->m_state, static_cast<float>(brain->mArmy->FactionIndex + 1));
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072BC30 (FUN_0072BC30, func_CPlatoonGetFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetFactionIndex()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetFactionIndex_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetFactionIndex",
      &cfunc_CPlatoonGetFactionIndex,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetFactionIndexHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BD60 (FUN_0072BD60, cfunc_CPlatoonUniquelyNamePlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonUniquelyNamePlatoonL`.
   */
  int cfunc_CPlatoonUniquelyNamePlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUniquelyNamePlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BD80 (FUN_0072BD80, func_CPlatoonUniquelyNamePlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UniquelyNamePlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUniquelyNamePlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UniquelyNamePlatoon",
      &cfunc_CPlatoonUniquelyNamePlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUniquelyNamePlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BDE0 (FUN_0072BDE0, cfunc_CPlatoonUniquelyNamePlatoonL)
   *
   * What it does:
   * Resolves `(platoon, uniqueName)` and stores the provided platoon unique
   * name when argument #2 is a string.
   */
  int cfunc_CPlatoonUniquelyNamePlatoonL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kUniquelyNamePlatoonHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject uniqueNameObject(LuaPlus::LuaStackObject(state, 2));
    if (platoon != nullptr && uniqueNameObject.IsString()) {
      auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
      runtimeView.mUniqueName.assign(uniqueNameObject.GetString());
    }

    return 1;
  }

  /**
   * Address: 0x0072BEF0 (FUN_0072BEF0, cfunc_CPlatoonGetPlatoonUniqueName)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetPlatoonUniqueNameL`.
   */
  int cfunc_CPlatoonGetPlatoonUniqueName(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonUniqueNameL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BF10 (FUN_0072BF10, func_CPlatoonGetPlatoonUniqueName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonUniqueName()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonUniqueName_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonUniqueName",
      &cfunc_CPlatoonGetPlatoonUniqueName,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonUniqueNameHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BF70 (FUN_0072BF70, cfunc_CPlatoonGetPlatoonUniqueNameL)
   *
   * What it does:
   * Resolves one platoon and pushes its unique-name string.
   */
  int cfunc_CPlatoonGetPlatoonUniqueNameL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kGetPlatoonUniqueNameHelpText,
        1,
        argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(platoon);

    lua_pushstring(state->m_state, runtimeView.mUniqueName.c_str());
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072C040 (FUN_0072C040, cfunc_CPlatoonGetAIPlan)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetAIPlanL`.
   */
  int cfunc_CPlatoonGetAIPlan(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetAIPlanL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C060 (FUN_0072C060, func_CPlatoonGetAIPlan_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetAIPlan()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetAIPlan_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetAIPlan",
      &cfunc_CPlatoonGetAIPlan,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetAIPlanHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C0C0 (FUN_0072C0C0, cfunc_CPlatoonGetAIPlanL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning army-brain AI-plan string.
   */
  int cfunc_CPlatoonGetAIPlanL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetAIPlanHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(platoon);
    const CAiBrain* const armyBrain = runtimeView.mArmy->GetArmyBrain();

    lua_pushstring(state->m_state, armyBrain->mCurrentPlan.c_str());
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072C190 (FUN_0072C190, cfunc_CPlatoonSwitchAIPlan)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonSwitchAIPlanL`.
   */
  int cfunc_CPlatoonSwitchAIPlan(lua_State* const luaContext)
  {
    return cfunc_CPlatoonSwitchAIPlanL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C1B0 (FUN_0072C1B0, func_CPlatoonSwitchAIPlan_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SwitchAIPlan()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSwitchAIPlan_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SwitchAIPlan",
      &cfunc_CPlatoonSwitchAIPlan,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kSwitchAIPlanHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C210 (FUN_0072C210, cfunc_CPlatoonSwitchAIPlanL)
   *
   * What it does:
   * Resolves `(platoon, planName)` and switches AI plan when argument #2 is
   * a string.
   */
  int cfunc_CPlatoonSwitchAIPlanL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSwitchAIPlanHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject aiPlanObject(LuaPlus::LuaStackObject(state, 2));
    if (aiPlanObject.IsString()) {
      platoon->SwitchAIPlan(aiPlanObject.GetString());
    }

    return 1;
  }

  /**
   * Address: 0x0072C300 (FUN_0072C300, cfunc_CPlatoonGetPlatoonPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetPlatoonPositionL`.
   */
  int cfunc_CPlatoonGetPlatoonPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C380 (FUN_0072C380, cfunc_CPlatoonGetPlatoonPositionL)
   *
   * What it does:
   * Resolves one platoon and returns the average world position of all units
   * currently present in its squad lanes.
   */
  int cfunc_CPlatoonGetPlatoonPositionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetPlatoonPositionHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    const auto& runtimeView = *reinterpret_cast<const CPlatoonRuntimeView*>(platoon);

    Wm3::Vector3f platoonCenter{};
    if (!ComputePlatoonCenter(runtimeView, platoonCenter)) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3<float>>(state, platoonCenter);
    centerObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072C320 (FUN_0072C320, func_CPlatoonGetPlatoonPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonPosition",
      &cfunc_CPlatoonGetPlatoonPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C5C0 (FUN_0072C5C0, cfunc_CPlatoonGetSquadPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetSquadPositionL`.
   */
  int cfunc_CPlatoonGetSquadPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetSquadPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C640 (FUN_0072C640, cfunc_CPlatoonGetSquadPositionL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns the average world position
   * of units currently present in the selected squad.
   */
  int cfunc_CPlatoonGetSquadPositionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetSquadPositionHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    CSquadRuntimeView* const squad = FindSquadByClass(runtimeView, squadClass);
    if (!squad) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    if (runtimeView.mArmy != nullptr) {
      (void)runtimeView.mArmy->GetArmyBrain();
    }

    Wm3::Vector3f squadCenter{};
    if (!ComputeSquadCenter(squad, squadCenter)) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3<float>>(state, squadCenter);
    centerObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072C5E0 (FUN_0072C5E0, func_CPlatoonGetSquadPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetSquadPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetSquadPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetSquadPosition",
      &cfunc_CPlatoonGetSquadPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetSquadPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C7D0 (FUN_0072C7D0, cfunc_CPlatoonGetSquadUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetSquadUnitsL`.
   */
  int cfunc_CPlatoonGetSquadUnits(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetSquadUnitsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C850 (FUN_0072C850, cfunc_CPlatoonGetSquadUnitsL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns a Lua array of unit objects
   * for members currently present in the selected squad.
   */
  int cfunc_CPlatoonGetSquadUnitsL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetSquadUnitsHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    CSquadRuntimeView* const squad = FindSquadByClass(runtimeView, squadClass);
    if (!squad) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    LuaPlus::LuaObject unitTable{};
    unitTable.AssignNewTable(state, 0, 0u);

    int unitIndex = 1;
    for (void** unitSlot = squad->mUnitSlotBegin; unitSlot != squad->mUnitSlotEnd; ++unitSlot) {
      Unit* const unit = DecodeSquadUnit(*unitSlot);
      if (!unit) {
        continue;
      }

      LuaPlus::LuaObject unitObject = unit->GetLuaObject();
      unitTable.Insert(unitIndex, unitObject);
      ++unitIndex;
    }

    unitTable.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072C7F0 (FUN_0072C7F0, func_CPlatoonGetSquadUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetSquadUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetSquadUnits_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetSquadUnits",
      &cfunc_CPlatoonGetSquadUnits,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetSquadUnitsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072B890 (FUN_0072B890, cfunc_CPlatoonIsOpponentAIRunningL)
   *
   * What it does:
   * Resolves one platoon and returns the `AI_RunOpponentAI` sim-convar state.
   */
  int cfunc_CPlatoonIsOpponentAIRunningL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kIsOpponentAIRunningHelpText,
        1,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);

    IArmy* const army = runtimeView.mArmy;
    Sim* const sim = army ? army->GetSim() : nullptr;

    CSimConVarBase* const runOpponentAiConVar = GetAI_RunOpponentAI_SimConVarDef();
    CSimConVarInstanceBase* const runOpponentAiVar = (sim && runOpponentAiConVar) ? sim->GetSimVar(runOpponentAiConVar)
                                                                                   : nullptr;
    const void* const runOpponentAiStorage = runOpponentAiVar ? runOpponentAiVar->GetValueStorage() : nullptr;
    const bool shouldRunOpponentAi =
      runOpponentAiStorage && (*reinterpret_cast<const std::uint8_t*>(runOpponentAiStorage) != 0u);

    lua_pushboolean(state->m_state, shouldRunOpponentAi ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072CC00 (FUN_0072CC00, cfunc_CPlatoonCanConsiderFormingPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanConsiderFormingPlatoonL`.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanConsiderFormingPlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072CC80 (FUN_0072CC80, cfunc_CPlatoonCanConsiderFormingPlatoonL)
   *
   * What it does:
   * Validates one `CPlatoon` method call and returns whether arg#3 matches
   * the first element of arg#2 case-insensitively.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoonL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kCanConsiderFormingPlatoonHelpText,
        3,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    (void)SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaObject compareTable(LuaPlus::LuaStackObject(state, 2));
    const char* inputString = lua_tostring(state->m_state, 3);
    if (!inputString) {
      LuaPlus::LuaStackObject typeErrorArg(state, 3);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }

    std::string inputText(inputString ? inputString : "");
    LuaPlus::LuaObject compareObject = compareTable[1];
    const char* compareString = compareObject.GetString();

    const int compareResult = _memicmp(inputText.c_str(), compareString, inputText.size());
    lua_pushboolean(state->m_state, compareResult ? 0 : 1);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x00731690 (FUN_00731690, cfunc_CPlatoonDisbandOnIdle)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonDisbandOnIdleL`.
   */
  int cfunc_CPlatoonDisbandOnIdle(lua_State* const luaContext)
  {
    return cfunc_CPlatoonDisbandOnIdleL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731710 (FUN_00731710, cfunc_CPlatoonDisbandOnIdleL)
   *
   * What it does:
   * Resolves one `CPlatoon` object from Lua and sets its disband-on-idle flag.
   */
  int cfunc_CPlatoonDisbandOnIdleL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kDisbandOnIdleHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    platoon->MarkDisbandOnIdle();
    return 0;
  }

  /**
   * Address: 0x007316B0 (FUN_007316B0, func_CPlatoonDisbandOnIdle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:DisbandOnIdle()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonDisbandOnIdle_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "DisbandOnIdle",
      &cfunc_CPlatoonDisbandOnIdle,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kDisbandOnIdleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731F00 (FUN_00731F00, cfunc_CPlatoonIsCommandsActive)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsCommandsActiveL`.
   */
  int cfunc_CPlatoonIsCommandsActive(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsCommandsActiveL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731F80 (FUN_00731F80, cfunc_CPlatoonIsCommandsActiveL)
   *
   * What it does:
   * Resolves `(platoon, commandsTable)` and returns true when any listed
   * command object is currently live.
   */
  int cfunc_CPlatoonIsCommandsActiveL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kIsCommandsActiveHelpText,
        2,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    (void)SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaObject commandsObject(LuaPlus::LuaStackObject(state, 2));
    const int commandCount = commandsObject.GetCount();
    for (int commandIndex = 1; commandIndex <= commandCount; ++commandIndex) {
      const LuaPlus::LuaObject commandObject = commandsObject[commandIndex];
      if (func_GetCUnitCommandOpt(commandObject, state)) {
        lua_pushboolean(state->m_state, 1);
        (void)lua_gettop(state->m_state);
        return 1;
      }
    }

    lua_pushboolean(state->m_state, 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x00731F20 (FUN_00731F20, func_CPlatoonIsCommandsActive_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsCommandsActive()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsCommandsActive_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsCommandsActive",
      &cfunc_CPlatoonIsCommandsActive,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsCommandsActiveHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E240 (FUN_0072E240, cfunc_CPlatoonIsAttacking)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsAttackingL`.
   */
  int cfunc_CPlatoonIsAttacking(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsAttackingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E260 (FUN_0072E260, func_CPlatoonIsAttacking_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsAttacking()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsAttacking_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsAttacking",
      &cfunc_CPlatoonIsAttacking,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsAttackingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E2C0 (FUN_0072E2C0, cfunc_CPlatoonIsAttackingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Attacking`.
   */
  int cfunc_CPlatoonIsAttackingL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIsAttackingHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Attacking);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072E3E0 (FUN_0072E3E0, cfunc_CPlatoonIsMoving)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsMovingL`.
   */
  int cfunc_CPlatoonIsMoving(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsMovingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E400 (FUN_0072E400, func_CPlatoonIsMoving_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsMoving()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsMoving_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsMoving",
      &cfunc_CPlatoonIsMoving,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsMovingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E460 (FUN_0072E460, cfunc_CPlatoonIsMovingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Moving`.
   */
  int cfunc_CPlatoonIsMovingL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIsMovingHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Moving);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072E580 (FUN_0072E580, cfunc_CPlatoonIsPatrolling)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsPatrollingL`.
   */
  int cfunc_CPlatoonIsPatrolling(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsPatrollingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E5A0 (FUN_0072E5A0, func_CPlatoonIsPatrolling_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsPatrolling()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsPatrolling_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsPatrolling",
      &cfunc_CPlatoonIsPatrolling,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsPatrollingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E600 (FUN_0072E600, cfunc_CPlatoonIsPatrollingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Patrolling`.
   */
  int cfunc_CPlatoonIsPatrollingL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIsPatrollingHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Patrolling);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072E720 (FUN_0072E720, cfunc_CPlatoonIsFerrying)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsFerryingL`.
   */
  int cfunc_CPlatoonIsFerrying(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsFerryingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E740 (FUN_0072E740, func_CPlatoonIsFerrying_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsFerrying()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsFerrying_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsFerrying",
      &cfunc_CPlatoonIsFerrying,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsFerryingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E7A0 (FUN_0072E7A0, cfunc_CPlatoonIsFerryingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Ferrying`.
   */
  int cfunc_CPlatoonIsFerryingL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIsFerryingHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Ferrying);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072C9B0 (FUN_0072C9B0, cfunc_CPlatoonGetPlatoonUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPlatoonUnitsL`.
   */
  int cfunc_CPlatoonGetPlatoonUnits(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonUnitsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C9D0 (FUN_0072C9D0, func_CPlatoonGetPlatoonUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonUnits_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonUnits",
      &cfunc_CPlatoonGetPlatoonUnits,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonUnitsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072CA30 (FUN_0072CA30, cfunc_CPlatoonGetPlatoonUnitsL)
   *
   * What it does:
   * Resolves one platoon and returns a cached Lua table containing all
   * currently tracked platoon units.
   */
  int cfunc_CPlatoonGetPlatoonUnitsL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetPlatoonUnitsHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      LuaPlus::LuaObject emptyUnits{};
      emptyUnits.AssignNewTable(state, 0, 0);
      emptyUnits.PushStack(state);
      return 1;
    }

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    if (runtimeView.mHasLuaList == 0u) {
      SEntitySetTemplateUnit platoonUnits{};
      BuildPlatoonUnitSet(runtimeView, platoonUnits);

      runtimeView.mLuaUnitList.AssignNewTable(state, static_cast<int>(platoonUnits.Size()), 0);
      std::int32_t luaIndex = 1;
      for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
        Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
        if (!unit) {
          continue;
        }

        LuaPlus::LuaObject unitObject = unit->GetLuaObject();
        runtimeView.mLuaUnitList.Insert(luaIndex, unitObject);
        ++luaIndex;
      }

      runtimeView.mHasLuaList = 1u;
    }

    runtimeView.mLuaUnitList.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072CC20 (FUN_0072CC20, func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanConsiderFormingPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanConsiderFormingPlatoon",
      &cfunc_CPlatoonCanConsiderFormingPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanConsiderFormingPlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072CEF0 (FUN_0072CEF0, cfunc_CPlatoonCanFormPlatoonL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonCanFormPlatoonL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Implements `CPlatoon:CanFormPlatoon(template, sizeMultiplier[, center, radius])`.
   * A platoon template is `{name, aiPlan, {unitFilter, perSquadCount}, ...}`; the
   * leading name/plan strings are extracted (as the binary does) but do not feed
   * the feasibility test. For each squad spec the required count is
   * `floor(sizeMultiplier * perSquadCount)`. With <=4 args the check counts every
   * unassigned unit matching the filter (blueprint id or category); with 5 args it
   * counts only unassigned, live units within `radius` of `center`. If any squad
   * spec has fewer available units than required the platoon cannot be formed and
   * the callback returns `false`; otherwise it returns `true` when at least one
   * unit was counted across all specs.
   */
  int cfunc_CPlatoonCanFormPlatoonL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 3 || argumentCount > 5) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected between %d and %d args, but got %d", kCanFormPlatoonHelpText, 3, 5, argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject templatesObject(LuaPlus::LuaStackObject(state, 2));
    const LuaPlus::LuaObject sizeObject(LuaPlus::LuaStackObject(state, 3));

    // The binary reads the template's leading name (index 1) and AI-plan (index 2)
    // strings before scanning the squad specs. They are not consumed by the
    // feasibility test, but the extraction is a preserved side effect.
    const LuaPlus::LuaObject nameObject = templatesObject[1];
    const msvc8::string platoonName(nameObject.GetString());
    const LuaPlus::LuaObject planObject = templatesObject[2];
    const msvc8::string platoonPlan(planObject.GetString());
    (void)platoonName;
    (void)platoonPlan;

    if (!templatesObject.IsTable()) {
      LuaPlus::LuaState::Error(state, "Attempted to pass in a non table as a platoon template");
      lua_pushboolean(state->m_state, 0);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    const int templateCount = templatesObject.GetCount();
    int totalAvailable = 0;
    for (int specIndex = 1; specIndex <= templateCount; ++specIndex) {
      const LuaPlus::LuaObject squadSpec = templatesObject[specIndex];
      if (!squadSpec.IsTable()) {
        continue;  // skip the leading name/plan string entries
      }

      const LuaPlus::LuaObject unitFilter = squadSpec[1];
      const LuaPlus::LuaObject countObject = squadSpec[2];
      // The binary reads the size multiplier as a float and multiplies in float
      // (x87 float*float), so narrow before the multiply to avoid a double-rounding
      // that could shift the floor result by one at boundary values.
      const float scaledSize =
        static_cast<float>(sizeObject.GetNumber()) * static_cast<float>(countObject.GetInteger());
      const int requiredSize = static_cast<int>(std::floor(scaledSize));

      if (argumentCount <= 4) {
        int available;
        if (unitFilter.IsString()) {
          available = platoon->CountUnassignedUnitsWithBP(unitFilter.GetString());
        } else {
          const EntityCategorySet* const category = func_GetCObj_EntityCategory(unitFilter);
          available = platoon->CountUnassignedUnitsInCategory(category);
        }
        totalAvailable += available;
        if (available < requiredSize) {
          lua_pushboolean(state->m_state, 0);
          (void)lua_gettop(state->m_state);
          return 1;
        }
      } else {
        SEntitySetTemplateUnit candidates{};
        if (unitFilter.IsString()) {
          platoon->GetUnassignedUnitsWithBP(unitFilter.GetString(), 1000, candidates);
        } else {
          const EntityCategorySet* const category = func_GetCObj_EntityCategory(unitFilter);
          platoon->GetUnassignedUnitsInCategory(category, 1000, candidates);
        }

        const LuaPlus::LuaObject centerObject(LuaPlus::LuaStackObject(state, 4));
        const Wm3::Vector3f center = SCR_FromLuaCopy<Wm3::Vector3<float>>(centerObject);

        LuaPlus::LuaStackObject radiusArg(state, 5);
        if (lua_type(state->m_state, 5) != 3 /* LUA_TNUMBER */) {
          LuaPlus::LuaStackObject::TypeError(&radiusArg, "number");
        }
        const float radius = static_cast<float>(lua_tonumber(state->m_state, 5));

        int inRadius = 0;
        for (Entity* const* entityIt = candidates.mVec.begin(); entityIt != candidates.mVec.end(); ++entityIt) {
          Entity* const entity = *entityIt;
          if (entity == nullptr) {
            continue;
          }
          // Entries are unassigned units; Entity is the +8 base subobject of Unit,
          // so the static downcast performs the -8 adjustment the binary emits.
          Unit* const unit = static_cast<Unit*>(entity);
          if (unit == nullptr) {
            continue;
          }
          if (unit->IsDead() || unit->DestroyQueued() || unit->IsBeingBuilt()) {
            continue;
          }
          const Wm3::Vec3f& unitPosition = unit->GetPosition();
          const float deltaX = unitPosition.x - center.x;
          const float deltaZ = unitPosition.z - center.z;
          if (radius > std::sqrt(deltaX * deltaX + deltaZ * deltaZ)) {
            ++inRadius;
            ++totalAvailable;
          }
        }
        if (inRadius < requiredSize) {
          lua_pushboolean(state->m_state, 0);
          (void)lua_gettop(state->m_state);
          return 1;
        }
      }
    }

    lua_pushboolean(state->m_state, totalAvailable != 0 ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072CE70 (FUN_0072CE70, cfunc_CPlatoonCanFormPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanFormPlatoonL`.
   */
  int cfunc_CPlatoonCanFormPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanFormPlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072CE90 (FUN_0072CE90, func_CPlatoonCanFormPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanFormPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanFormPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanFormPlatoon",
      &cfunc_CPlatoonCanFormPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanFormPlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072D870 (FUN_0072D870, cfunc_CPlatoonFormPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFormPlatoonL`.
   */
  int cfunc_CPlatoonFormPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFormPlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072D890 (FUN_0072D890, func_CPlatoonFormPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FormPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFormPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FormPlatoon",
      &cfunc_CPlatoonFormPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFormPlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E940 (FUN_0072E940, cfunc_CPlatoonSetPrioritizedTargetListL)
   *
   * What it does:
   * Resolves `(platoon, squadClass, categoryTable)` from Lua, copies category
   * entries into a temporary prioritized-category vector, then replaces the
   * matching squad's prioritized target list.
   */
  int cfunc_CPlatoonSetPrioritizedTargetListL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kSetPrioritizedTargetListHelpText,
        3,
        argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    msvc8::vector<EntityCategorySet> prioritizedCategories{};
    const LuaPlus::LuaObject categoryTable(LuaPlus::LuaStackObject(state, 3));
    if (categoryTable.IsTable()) {
      const int categoryCount = categoryTable.GetCount();
      for (int categoryIndex = 1; categoryIndex <= categoryCount; ++categoryIndex) {
        const LuaPlus::LuaObject categoryObject = categoryTable[categoryIndex];
        if (EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); categorySet != nullptr) {
          // Route per-T push_back through the canonical helper (FUN_006DB010)
          // so the MSVC8 vector<EntityCategorySet>::push_back template
          // emission symbol shape is preserved.
          moho::PushBackEntityCategorySetVector(prioritizedCategories, *categorySet);
        }
      }

      auto& runtime = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
      ApplyPlatoonSquadPrioritizedTargetList(runtime, squadClass, prioritizedCategories);
    }

    return 0;
  }

  /**
   * Address: 0x0072E8C0 (FUN_0072E8C0, cfunc_CPlatoonSetPrioritizedTargetList)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonSetPrioritizedTargetListL`.
   */
  int cfunc_CPlatoonSetPrioritizedTargetList(lua_State* const luaContext)
  {
    return cfunc_CPlatoonSetPrioritizedTargetListL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E8E0 (FUN_0072E8E0, func_CPlatoonSetPrioritizedTargetList_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SetPrioritizedTargetList()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSetPrioritizedTargetList_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetPrioritizedTargetList",
      &cfunc_CPlatoonSetPrioritizedTargetList,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kSetPrioritizedTargetListHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072EB30 (FUN_0072EB30, cfunc_CPlatoonFindPrioritizedUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindPrioritizedUnitL`.
   */
  int cfunc_CPlatoonFindPrioritizedUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindPrioritizedUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072EB50 (FUN_0072EB50, func_CPlatoonFindPrioritizedUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindPrioritizedUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindPrioritizedUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindPrioritizedUnit",
      &cfunc_CPlatoonFindPrioritizedUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindPrioritizedUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072EDE0 (FUN_0072EDE0, cfunc_CPlatoonFindClosestUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindClosestUnitL`.
   */
  int cfunc_CPlatoonFindClosestUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindClosestUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072EE00 (FUN_0072EE00, func_CPlatoonFindClosestUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindClosestUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindClosestUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindClosestUnit",
      &cfunc_CPlatoonFindClosestUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindClosestUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F020 (FUN_0072F020, cfunc_CPlatoonFindClosestUnitToBase)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindClosestUnitToBaseL`.
   */
  int cfunc_CPlatoonFindClosestUnitToBase(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindClosestUnitToBaseL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F040 (FUN_0072F040, func_CPlatoonFindClosestUnitToBase_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindClosestUnitToBase()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindClosestUnitToBase_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindClosestUnitToBase",
      &cfunc_CPlatoonFindClosestUnitToBase,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindClosestUnitToBaseHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F290 (FUN_0072F290, cfunc_CPlatoonFindFurthestUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindFurthestUnitL`.
   */
  int cfunc_CPlatoonFindFurthestUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindFurthestUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F2B0 (FUN_0072F2B0, func_CPlatoonFindFurthestUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindFurthestUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindFurthestUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindFurthestUnit",
      &cfunc_CPlatoonFindFurthestUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindFurthestUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F4D0 (FUN_0072F4D0, cfunc_CPlatoonFindHighestValueUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindHighestValueUnitL`.
   */
  int cfunc_CPlatoonFindHighestValueUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindHighestValueUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F4F0 (FUN_0072F4F0, func_CPlatoonFindHighestValueUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindHighestValueUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindHighestValueUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindHighestValueUnit",
      &cfunc_CPlatoonFindHighestValueUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindHighestValueUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F790 (FUN_0072F790, cfunc_CPlatoonCanAttackTargetL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonCanAttackTargetL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, squadClass, targetUnit)`, finds the first squad in
   * the requested class, and forwards the target to `CSquad::CanAttackTarget`.
   * When the class is absent the Lua callback returns no values.
   */
  int cfunc_CPlatoonCanAttackTargetL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCanAttackTargetHelpText, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    gpg::RRef_ESquadClass(&enumRef, &squadClass);

    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    CSquadRuntimeView* const squadView = FindSquadByClass(runtimeView, squadClass);
    if (squadView == nullptr) {
      return 0;
    }

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 3));
    Unit* const targetUnit = SCR_FromLua_Unit(targetObject);
    const bool canAttack = reinterpret_cast<CSquad*>(squadView)->CanAttackTarget(targetUnit);

    lua_pushboolean(state->m_state, canAttack ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072F710 (FUN_0072F710, cfunc_CPlatoonCanAttackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanAttackTargetL`.
   */
  int cfunc_CPlatoonCanAttackTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanAttackTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F730 (FUN_0072F730, func_CPlatoonCanAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanAttackTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanAttackTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanAttackTarget",
      &cfunc_CPlatoonCanAttackTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanAttackTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F940 (FUN_0072F940, cfunc_CPlatoonStop)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonStopL`.
   */
  int cfunc_CPlatoonStop(lua_State* const luaContext)
  {
    return cfunc_CPlatoonStopL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F9C0 (FUN_0072F9C0, cfunc_CPlatoonStopL)
   *
   * What it does:
   * Resolves `(platoon [, squadClass])` and dispatches `CPlatoon::Stop` with
   * default squad class `6` (all squads) when arg#2 is omitted.
   */
  int cfunc_CPlatoonStopL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kStopHelpText,
        1,
        2,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = kAllSquadsClass;
    if (argumentCount > 1) {
      gpg::RRef enumRef{};
      gpg::RRef_ESquadClass(&enumRef, &squadClass);

      const char* squadClassName = lua_tostring(state->m_state, 2);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 2);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }

      SCR_GetEnum(state, squadClassName, enumRef);
    }

    platoon->Stop(squadClass);
    return 0;
  }

  /**
   * Address: 0x0072F960 (FUN_0072F960, func_CPlatoonStop_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Stop()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonStop_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Stop",
      &cfunc_CPlatoonStop,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kStopHelpText
    );
    return &binder;
  }

  /**
   * What it does:
   * Issues one attack order over `units` against `target`. When a formation
   * script resolved and the set holds more than one unit, issues
   * UNITCOMMAND_FormAttack carrying the formation script index + identity
   * orientation; otherwise a plain UNITCOMMAND_Attack. The target is an entity
   * (AITARGET_Entity, zero position). Appends the issued command (if any) to
   * `issuedCommands`. Shared by both CPlatoon::AttackTarget dispatch branches.
   */
  static void IssuePlatoonAttackCommand(
    Sim* const sim,
    SEntitySetTemplateUnit& units,
    Entity* const target,
    const int formationScriptIndex,
    msvc8::vector<WeakPtr<CUnitCommand>>& issuedCommands
  )
  {
    const bool useFormation = formationScriptIndex >= 0 && units.Size() > 1u;

    SSTICommandIssueData commandIssueData(
      useFormation ? EUnitCommandType::UNITCOMMAND_FormAttack : EUnitCommandType::UNITCOMMAND_Attack
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(target->id_);
    commandIssueData.mTarget.mPos.x = 0.0f;
    commandIssueData.mTarget.mPos.y = 0.0f;
    commandIssueData.mTarget.mPos.z = 0.0f;

    if (useFormation) {
      commandIssueData.unk38 = formationScriptIndex;  // FormAttack formation-script lane
      commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
      commandIssueData.unk4C = 1.0f;                   // FormAttack orientation weight
    }

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
    if (issuedCommand != nullptr) {
      InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
    }
  }

  /**
   * Address: 0x00727F50 (FUN_00727F50, Moho::CPlatoon::AttackTarget)
   *
   * IDA signature:
   * void __stdcall CPlatoon::AttackTarget(CPlatoon *this,
   *     msvc8::vector<WeakPtr<CUnitCommand>> *outCommands, Entity *target,
   *     ESquadClass squadClass)
   *
   * What it does:
   * Orders the platoon to attack `target`. If the platoon has a named formation
   * it attacks as one formation set (whole platoon); otherwise it attacks with
   * each requested attack-capable squad class independently (Attack and Artillery
   * only -- classes 1..2, or both when `squadClass` is the all-classes sentinel).
   * Each set is issued as FormAttack when a formation script resolves and it holds
   * more than one unit, else a plain Attack. Returns the issued command weak-links.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::AttackTarget(Entity* const target, const ESquadClass squadClass)
  {
    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;

    if (mFormation.empty()) {
      // Per-squad attack: only the Attack (1) and Artillery (2) squad classes.
      const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
      for (std::int32_t squadClassIndex = 1; squadClassIndex <= 2; ++squadClassIndex) {
        if (static_cast<std::int32_t>(squadClass) != kAllSquadClassesSentinel &&
            static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
          CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
          if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
            continue;
          }

          SEntitySetTemplateUnit squadUnits{};
          CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
          const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
          IssuePlatoonAttackCommand(mSim, squadUnits, target, formationScriptIndex, issuedCommands);
          break;
        }
      }
    } else {
      // Platoon-wide formation attack.
      SEntitySetTemplateUnit platoonUnits{};
      BuildPlatoonUnitSet(*reinterpret_cast<const CPlatoonRuntimeView*>(this), platoonUnits);
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonAttackCommand(mSim, platoonUnits, target, formationScriptIndex, issuedCommands);
    }

    return issuedCommands;
  }

  /**
   * Address: 0x0072FB60 (FUN_0072FB60, cfunc_CPlatoonAttackTargetL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonAttackTargetL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, targetEntity[, squadClass])` and issues the attack via
   * `CPlatoon::AttackTarget`, returning the issued commands as a Lua array. The
   * squad class defaults to the all-classes sentinel; arg 3 overrides it.
   */
  int cfunc_CPlatoonAttackTargetL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kAttackTargetHelpText, 2, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const target = SCR_FromLua_Entity(targetObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(kAllSquadClassesSentinel);
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      gpg::RRef_ESquadClass(&enumRef, &squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->AttackTarget(target, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x0072FAE0 (FUN_0072FAE0, cfunc_CPlatoonAttackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonAttackTargetL`.
   */
  int cfunc_CPlatoonAttackTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonAttackTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072FB00 (FUN_0072FB00, func_CPlatoonAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:AttackTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonAttackTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "AttackTarget",
      &cfunc_CPlatoonAttackTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kAttackTargetHelpText
    );
    return &binder;
  }

  /**
   * What it does:
   * Adds each pointer-word in `[begin, end)` to `dest` as a `Unit*` (the stored
   * entity word maps to its owning unit by the -8 Entity-subobject adjustment;
   * a null word adds a null lane). Mirrors the compiler-emitted range-add the
   * transport-move branch uses (FUN_006F8F10) -- an unconditional add, unlike
   * SEntitySetTemplateUnit::AddRange which filters to live units.
   */
  static void AddUnitPointerRangeToSet(
    SEntitySetTemplateUnit& dest,
    Entity* const* const begin,
    Entity* const* const end
  )
  {
    for (Entity* const* cursor = begin; cursor != end; ++cursor) {
      Unit* const unit = (*cursor != nullptr) ? static_cast<Unit*>(*cursor) : nullptr;
      (void)dest.AddUnit(unit);
    }
  }

  /**
   * What it does:
   * Issues one move order over `units` toward the entity `target`. When a
   * formation script resolved and the set holds more than one unit, issues
   * UNITCOMMAND_FormMove carrying the formation script index + identity
   * orientation; otherwise a plain UNITCOMMAND_Move. Appends the issued command
   * (if any) to `issuedCommands`.
   */
  static void IssuePlatoonMoveCommand(
    Sim* const sim,
    SEntitySetTemplateUnit& units,
    Entity* const target,
    const int formationScriptIndex,
    msvc8::vector<WeakPtr<CUnitCommand>>& issuedCommands
  )
  {
    const bool useFormation = formationScriptIndex >= 0 && units.Size() > 1u;

    SSTICommandIssueData commandIssueData(
      useFormation ? EUnitCommandType::UNITCOMMAND_FormMove : EUnitCommandType::UNITCOMMAND_Move
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(target->id_);
    commandIssueData.mTarget.mPos.x = 0.0f;
    commandIssueData.mTarget.mPos.y = 0.0f;
    commandIssueData.mTarget.mPos.z = 0.0f;

    if (useFormation) {
      commandIssueData.unk38 = formationScriptIndex;  // FormMove formation-script lane
      commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
      commandIssueData.unk4C = 1.0f;                   // FormMove orientation weight
    }

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
    if (issuedCommand != nullptr) {
      InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
    }
  }

  /**
   * Address: 0x00727740 (FUN_00727740, Moho::CPlatoon::MoveToTarget)
   *
   * IDA signature:
   * void __stdcall CPlatoon::MoveToTarget(CPlatoon *this,
   *     msvc8::vector<WeakPtr<CUnitCommand>> *outCommands, Entity *target,
   *     char useTransports, ESquadClass squadClass)
   *
   * What it does:
   * Orders the platoon to move to an entity target. Dispatches three ways:
   *   - useTransports: gathers the requested squad classes' units into one move
   *     set, plus every alive TRANSPORTATION unit across all classes, and issues a
   *     single UNITCOMMAND_Move to the combined set.
   *   - else if a named formation exists: moves the whole platoon as one formation
   *     set (FormMove / Move by the usual threshold).
   *   - else: moves each requested squad class independently (classes 1..5).
   * Returns the issued command weak-links.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::MoveToTarget(
    Entity* const target, const bool useTransports, const ESquadClass squadClass
  )
  {
    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);

    if (useTransports) {
      SEntitySetTemplateUnit transports{};
      SEntitySetTemplateUnit moveSet{};

      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
          CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
          if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
            continue;
          }

          SEntitySetTemplateUnit squadUnits{};
          CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);

          // Collect alive transports from every class.
          for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
            Entity* const entity = *entry;
            if (entity == nullptr) {
              continue;
            }
            Unit* const unit = static_cast<Unit*>(entity);
            if (unit == nullptr || unit->IsDead()) {
              continue;
            }
            if (unit->IsInCategory("TRANSPORTATION")) {
              (void)transports.AddUnit(unit);
            }
          }

          // Only the requested classes' units join the move set.
          if (static_cast<std::int32_t>(squadClass) == kAllSquadClassesSentinel ||
              static_cast<std::int32_t>(squadClass) == squadClassIndex) {
            AddUnitPointerRangeToSet(moveSet, squadUnits.mVec.begin(), squadUnits.mVec.end());
          }
          break;
        }
      }

      if (!moveSet.Empty()) {
        if (!transports.Empty()) {
          AddUnitPointerRangeToSet(moveSet, transports.mVec.begin(), transports.mVec.end());
        }
        IssuePlatoonMoveCommand(mSim, moveSet, target, -1, issuedCommands);
      }
    } else if (!mFormation.empty()) {
      SEntitySetTemplateUnit platoonUnits{};
      BuildPlatoonUnitSet(runtime, platoonUnits);
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonMoveCommand(mSim, platoonUnits, target, formationScriptIndex, issuedCommands);
    } else {
      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        if (static_cast<std::int32_t>(squadClass) != kAllSquadClassesSentinel &&
            static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
          CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
          if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
            continue;
          }

          SEntitySetTemplateUnit squadUnits{};
          CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
          const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
          IssuePlatoonMoveCommand(mSim, squadUnits, target, formationScriptIndex, issuedCommands);
          break;
        }
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x0072FE30 (FUN_0072FE30, cfunc_CPlatoonMoveToTargetL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonMoveToTargetL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, targetEntity, useTransports[, squadClass])` and issues the
   * move via `CPlatoon::MoveToTarget`, returning the issued commands as a Lua
   * array. The squad class defaults to the all-classes sentinel; arg 4 overrides.
   */
  int cfunc_CPlatoonMoveToTargetL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 4) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kMoveToTargetHelpText, 2, 4, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const target = SCR_FromLua_Entity(targetObject, state);

    LuaPlus::LuaStackObject useTransportsArg(state, 3);
    const bool useTransports = useTransportsArg.GetBoolean();

    ESquadClass squadClass = static_cast<ESquadClass>(kAllSquadClassesSentinel);
    if (lua_gettop(state->m_state) > 3) {
      gpg::RRef enumRef{};
      gpg::RRef_ESquadClass(&enumRef, &squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 4);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 4);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->MoveToTarget(target, useTransports, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x0072FDB0 (FUN_0072FDB0, cfunc_CPlatoonMoveToTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonMoveToTargetL`.
   */
  int cfunc_CPlatoonMoveToTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonMoveToTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072FDD0 (FUN_0072FDD0, func_CPlatoonMoveToTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:MoveToTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonMoveToTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "MoveToTarget",
      &cfunc_CPlatoonMoveToTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kMoveToTargetHelpText
    );
    return &binder;
  }

  /**
   * What it does:
   * Issues one move order over `units` toward the ground point `target`. When a
   * formation script resolved and the set holds more than one unit, issues
   * UNITCOMMAND_FormMove carrying the formation script index + identity
   * orientation; otherwise a plain UNITCOMMAND_Move. Appends the issued command
   * (if any) to `issuedCommands`.
   */
  static void IssuePlatoonMoveToLocationCommand(
    Sim* const sim,
    SEntitySetTemplateUnit& units,
    const Wm3::Vector3f& target,
    const int formationScriptIndex,
    msvc8::vector<WeakPtr<CUnitCommand>>& issuedCommands
  )
  {
    const bool useFormation = formationScriptIndex >= 0 && units.Size() > 1u;

    SSTICommandIssueData commandIssueData(
      useFormation ? EUnitCommandType::UNITCOMMAND_FormMove : EUnitCommandType::UNITCOMMAND_Move
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
    commandIssueData.mTarget.mPos = target;

    if (useFormation) {
      commandIssueData.unk38 = formationScriptIndex;  // FormMove formation-script lane
      commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
      commandIssueData.unk4C = 1.0f;                   // FormMove orientation weight
    }

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
    if (issuedCommand != nullptr) {
      InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
    }
  }

  /**
   * Address: 0x00726DE0 (FUN_00726DE0, Moho::CPlatoon::MoveToLocation)
   *
   * IDA signature:
   * void __stdcall CPlatoon::MoveToLocation(CPlatoon *this,
   *     msvc8::vector<WeakPtr<CUnitCommand>> *outCommands, Wm3::Vector3f *pos,
   *     char useTransports, ESquadClass squadClass)
   *
   * What it does:
   * Orders the platoon to move to a ground point (first snapped to the map/water
   * surface elevation). Dispatches three ways, mirroring MoveToTarget:
   *   - useTransports: gathers the requested squad classes' units plus every alive
   *     TRANSPORTATION unit across all classes into one move set, issues a single
   *     UNITCOMMAND_Move to the ground point.
   *   - else if a named formation exists: moves the whole platoon as one formation
   *     set (FormMove / Move by the usual threshold).
   *   - else: moves each requested squad class independently (classes 1..5).
   * Returns the issued command weak-links.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::MoveToLocation(
    Wm3::Vector3f& pos, const bool useTransports, const ESquadClass squadClass
  )
  {
    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(pos.x, pos.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    pos.y = surfaceElevation;

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);

    if (useTransports) {
      SEntitySetTemplateUnit transports{};
      SEntitySetTemplateUnit moveSet{};

      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
          CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
          if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
            continue;
          }

          SEntitySetTemplateUnit squadUnits{};
          CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);

          for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
            Entity* const entity = *entry;
            if (entity == nullptr) {
              continue;
            }
            Unit* const unit = static_cast<Unit*>(entity);
            if (unit == nullptr || unit->IsDead()) {
              continue;
            }
            if (unit->IsInCategory("TRANSPORTATION")) {
              (void)transports.AddUnit(unit);
            }
          }

          if (static_cast<std::int32_t>(squadClass) == kAllSquadClassesSentinel ||
              static_cast<std::int32_t>(squadClass) == squadClassIndex) {
            AddUnitPointerRangeToSet(moveSet, squadUnits.mVec.begin(), squadUnits.mVec.end());
          }
          break;
        }
      }

      if (!moveSet.Empty()) {
        if (!transports.Empty()) {
          AddUnitPointerRangeToSet(moveSet, transports.mVec.begin(), transports.mVec.end());
        }
        IssuePlatoonMoveToLocationCommand(mSim, moveSet, pos, -1, issuedCommands);
      }
    } else if (!mFormation.empty()) {
      SEntitySetTemplateUnit platoonUnits{};
      BuildPlatoonUnitSet(runtime, platoonUnits);
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonMoveToLocationCommand(mSim, platoonUnits, pos, formationScriptIndex, issuedCommands);
    } else {
      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        if (static_cast<std::int32_t>(squadClass) != kAllSquadClassesSentinel &&
            static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
          CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
          if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
            continue;
          }

          SEntitySetTemplateUnit squadUnits{};
          CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
          const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
          IssuePlatoonMoveToLocationCommand(mSim, squadUnits, pos, formationScriptIndex, issuedCommands);
          break;
        }
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00730120 (FUN_00730120, cfunc_CPlatoonMoveToLocationL)
   *
   * IDA signature:
   * int __usercall cfunc_CPlatoonMoveToLocationL@<eax>(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, point, useTransports[, squadClass])`, validates the point,
   * and issues the move via `CPlatoon::MoveToLocation`, returning the issued
   * commands as a Lua array. The squad class defaults to the all-classes sentinel.
   */
  int cfunc_CPlatoonMoveToLocationL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 4) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kMoveToLocationHelpText, 2, 4, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    Wm3::Vector3f targetPoint = SCR_FromLuaCopy<Wm3::Vector3<float>>(locationObject);

    LuaPlus::LuaStackObject useTransportsArg(state, 3);
    const bool useTransports = useTransportsArg.GetBoolean();

    if (!IsValidVector3f(targetPoint)) {
      // NB: the binary's literal reads "Platoon:MoveToTarget" here -- an original-source
      // copy-paste artifact in the MoveToLocation worker; preserved verbatim for 1:1.
      LuaPlus::LuaState::Error(state, "Platoon:MoveToTarget Passed in an invalid target point");
    }

    ESquadClass squadClass = static_cast<ESquadClass>(kAllSquadClassesSentinel);
    if (lua_gettop(state->m_state) > 3) {
      gpg::RRef enumRef{};
      gpg::RRef_ESquadClass(&enumRef, &squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 4);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 4);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->MoveToLocation(targetPoint, useTransports, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x007300A0 (FUN_007300A0, cfunc_CPlatoonMoveToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonMoveToLocationL`.
   */
  int cfunc_CPlatoonMoveToLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonMoveToLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007300C0 (FUN_007300C0, func_CPlatoonMoveToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:MoveToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonMoveToLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "MoveToLocation",
      &cfunc_CPlatoonMoveToLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kMoveToLocationHelpText
    );
    return &binder;
  }

  /**
   * Issues one aggressive-move order to a prepared unit set at `pos`.
   *
   * Unlike Move/Patrol, AggressiveMove always selects the Form* variant whenever a
   * formation script exists (`formationScriptIndex >= 0`) with no unit-count gate,
   * and always writes the orientation lane (script lane clamped to >= 0, zero
   * quaternion, weight 1.0f) regardless of the chosen variant.
   */
  static void IssuePlatoonAggressiveMoveCommand(
    Sim* const sim,
    SEntitySetTemplateUnit& units,
    const Wm3::Vector3f& pos,
    const int formationScriptIndex,
    msvc8::vector<WeakPtr<CUnitCommand>>& issuedCommands
  )
  {
    SSTICommandIssueData commandIssueData(
      formationScriptIndex >= 0 ? EUnitCommandType::UNITCOMMAND_FormAggressiveMove
                                : EUnitCommandType::UNITCOMMAND_AggressiveMove
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
    commandIssueData.mTarget.mPos = pos;
    commandIssueData.unk38 = formationScriptIndex > 0 ? formationScriptIndex : 0;  // formation-script lane, clamped to >= 0
    commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
    commandIssueData.unk4C = 1.0f;                                                 // orientation weight

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
    if (issuedCommand != nullptr) {
      InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
    }
  }

  /**
   * Address: 0x007268E0 (FUN_007268E0, Moho::CPlatoon::AggressiveMoveToLocation)
   *
   * IDA signature:
   * std::vector<WeakPtr<CUnitCommand>>* __userpurge
   *   CPlatoon::AggressiveMoveToLocation(float* point@<edi>, CPlatoon* this,
   *                                      std::vector* out, ESquadClass squadClass);
   *
   * What it does:
   * Snaps `pos` to the terrain/water surface, then orders an aggressive move there.
   * If the platoon has a named formation it moves the whole platoon as one
   * formation set; otherwise it moves each requested squad class (1..5)
   * independently. Every command is a FormAggressiveMove when the target set has a
   * formation script, else a plain AggressiveMove. Returns the issued command
   * weak-links.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::AggressiveMoveToLocation(Wm3::Vector3f& pos, const ESquadClass squadClass)
  {
    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(pos.x, pos.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    pos.y = surfaceElevation;

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);

    if (mFormation.empty()) {
      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        if (static_cast<std::int32_t>(squadClass) != kAllSquadClassesSentinel &&
            static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
          CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
          if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
            continue;
          }

          SEntitySetTemplateUnit squadUnits{};
          CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
          const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
          IssuePlatoonAggressiveMoveCommand(mSim, squadUnits, pos, formationScriptIndex, issuedCommands);
          break;
        }
      }
    } else {
      SEntitySetTemplateUnit platoonUnits{};
      BuildPlatoonUnitSet(runtime, platoonUnits);
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonAggressiveMoveCommand(mSim, platoonUnits, pos, formationScriptIndex, issuedCommands);
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00730420 (FUN_00730420, cfunc_CPlatoonAggressiveMoveToLocationL)
   *
   * What it does:
   * Parses `(platoon, location[, squadClass])`, validates the point, issues the
   * aggressive-move orders via `CPlatoon::AggressiveMoveToLocation`, returns the
   * issued commands as a Lua array, then releases the weak command links.
   */
  int cfunc_CPlatoonAggressiveMoveToLocationL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kAggressiveMoveToLocationHelpText, 2, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    Wm3::Vector3f targetPoint = SCR_FromLuaCopy<Wm3::Vector3<float>>(locationObject);
    if (!IsValidVector3f(targetPoint)) {
      LuaPlus::LuaState::Error(state, "Platoon:AggressiveMoveToLocation Passed in an invalid target point");
    }

    ESquadClass squadClass = static_cast<ESquadClass>(kAllSquadClassesSentinel);
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      gpg::RRef_ESquadClass(&enumRef, &squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->AggressiveMoveToLocation(targetPoint, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x007303A0 (FUN_007303A0, cfunc_CPlatoonAggressiveMoveToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonAggressiveMoveToLocationL`.
   */
  int cfunc_CPlatoonAggressiveMoveToLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonAggressiveMoveToLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007303C0 (FUN_007303C0, func_CPlatoonAggressiveMoveToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:AggressiveMoveToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonAggressiveMoveToLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "AggressiveMoveToLocation",
      &cfunc_CPlatoonAggressiveMoveToLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kAggressiveMoveToLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00728700 (FUN_00728700, Moho::CPlatoon::FerryToLocation)
   *
   * What it does:
   * Snaps `targetPos.y` to the terrain/water surface, collects transport-capable
   * (and alive, not-being-built) units across all squad classes, and issues a
   * single `UNITCOMMAND_Ferry` to that ground point.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::FerryToLocation(Wm3::Vector3f& targetPos)
  {
    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(targetPos.x, targetPos.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    targetPos.y = surfaceElevation;

    SEntitySetTemplateUnit transports{};
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
        CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
        if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
          continue;
        }

        SEntitySetTemplateUnit squadUnits{};
        CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entry);
          if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt()) {
            continue;
          }
          if (unit->IsInCategory("TRANSPORTATION")) {
            (void)transports.AddUnit(unit);
          }
        }
        break;
      }
    }

    if (!transports.Empty()) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Ferry);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
      commandIssueData.mTarget.mPos = targetPos;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, transports, commandIssueData, false);
      if (issuedCommand != nullptr) {
        InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00730700 (FUN_00730700, cfunc_CPlatoonFerryToLocationL)
   *
   * What it does:
   * Parses `(platoon, location)`, validates the point, issues the ferry orders
   * via `CPlatoon::FerryToLocation`, returns the issued commands as a Lua array,
   * then releases the weak command links.
   */
  int cfunc_CPlatoonFerryToLocationL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kFerryToLocationHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    Wm3::Vector3f targetPos = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);
    if (!IsValidVector3f(targetPos)) {
      LuaPlus::LuaState::Error(state, "Platoon:FerryToLocation Passed in an invalid target point");
    }

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->FerryToLocation(targetPos);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00730680 (FUN_00730680, cfunc_CPlatoonFerryToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFerryToLocationL`.
   */
  int cfunc_CPlatoonFerryToLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFerryToLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007306A0 (FUN_007306A0, func_CPlatoonFerryToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FerryToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFerryToLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FerryToLocation",
      &cfunc_CPlatoonFerryToLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFerryToLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007308F0 (FUN_007308F0, cfunc_CPlatoonLoadUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonLoadUnitsL`.
   */
  int cfunc_CPlatoonLoadUnits(lua_State* const luaContext)
  {
    return cfunc_CPlatoonLoadUnitsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00730910 (FUN_00730910, func_CPlatoonLoadUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:LoadUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonLoadUnits_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "LoadUnits",
      &cfunc_CPlatoonLoadUnits,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kLoadUnitsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00730970 (FUN_00730970, cfunc_CPlatoonLoadUnitsL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonLoadUnitsL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, category)`, issues platoon transport-load commands,
   * builds a Lua array of resulting command objects, and unlinks temporary
   * weak-command lanes before returning.
   */
  int cfunc_CPlatoonLoadUnitsL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kLoadUnitsHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->LoadUnits(categorySet);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x007291C0 (FUN_007291C0, Moho::CPlatoon::UnloadUnitsAtLocation)
   *
   * IDA signature:
   * gpg::fastvector_shared_ptr_CUnitCommand* __stdcall
   *   CPlatoon::UnloadUnitsAtLocation(CPlatoon* this, gpg::fastvector* out,
   *                                   EntityCategory* category, float* point);
   *
   * What it does:
   * Snaps `pos` to the terrain/water surface, then walks every squad class (1..5)
   * looking for alive, not-being-built transport/carrier units. For each such
   * carrier it inspects the units it currently holds (attached entities); every
   * held unit whose blueprint category-bit index is a member of `category` is
   * added to the unload set, and if a carrier gave up at least one held unit the
   * carrier itself is added too. Finally issues one
   * UNITCOMMAND_TransportUnloadSpecificUnits to the snapped ground point.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::UnloadUnitsAtLocation(const EntityCategorySet* const category, Wm3::Vector3f& pos)
  {
    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(pos.x, pos.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    pos.y = surfaceElevation;

    SEntitySetTemplateUnit unitsToUnload{};
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
        CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
        if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
          continue;
        }

        SEntitySetTemplateUnit squadUnits{};
        CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          Unit* const carrier = SEntitySetTemplateUnit::UnitFromEntry(*entry);
          if (carrier == nullptr || carrier->IsDead() || carrier->IsBeingBuilt()) {
            continue;
          }
          if (!carrier->IsInCategory("TRANSPORTATION") && !carrier->IsInCategory("CARRIER")) {
            continue;
          }

          bool carrierGaveUpAUnit = false;
          for (Entity* const attachedEntity : carrier->GetAttachedEntities()) {
            Unit* const heldUnit = attachedEntity->IsUnit();
            if (heldUnit == nullptr) {
              continue;
            }
            const std::uint32_t ordinal = heldUnit->GetBlueprint()->mCategoryBitIndex;
            if (category->mBits.Contains(ordinal)) {
              (void)unitsToUnload.AddUnit(heldUnit);
              carrierGaveUpAUnit = true;
            }
          }
          if (carrierGaveUpAUnit) {
            (void)unitsToUnload.AddUnit(carrier);
          }
        }
        break;
      }
    }

    if (!unitsToUnload.Empty()) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
      commandIssueData.mTarget.mPos = pos;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, unitsToUnload, commandIssueData, false);
      if (issuedCommand != nullptr) {
        InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00730B90 (FUN_00730B90, cfunc_CPlatoonUnloadUnitsAtLocationL)
   *
   * What it does:
   * Parses `(platoon, category, location)`, resolves the reflected
   * `EntityCategorySet`, validates the point, issues the unload orders via
   * `CPlatoon::UnloadUnitsAtLocation`, returns the issued commands as a Lua array,
   * then releases the weak command links.
   */
  int cfunc_CPlatoonUnloadUnitsAtLocationL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kUnloadUnitsAtLocationHelpText, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const category = func_GetCObj_EntityCategory(categoryObject);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 3));
    Wm3::Vector3f targetPos = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);
    if (!IsValidVector3f(targetPos)) {
      LuaPlus::LuaState::Error(state, "Platoon:UnloadUnitsAtLocation Passed in an invalid target point");
    }

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->UnloadUnitsAtLocation(category, targetPos);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00730B10 (FUN_00730B10, cfunc_CPlatoonUnloadUnitsAtLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUnloadUnitsAtLocationL`.
   */
  int cfunc_CPlatoonUnloadUnitsAtLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUnloadUnitsAtLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00730B30 (FUN_00730B30, func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UnloadUnitsAtLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UnloadUnitsAtLocation",
      &cfunc_CPlatoonUnloadUnitsAtLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUnloadUnitsAtLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00729690 (FUN_00729690, Moho::CPlatoon::UnloadAllAtLocation)
   *
   * What it does:
   * Collects transport/carrier units (alive, not-being-built) across all squad
   * classes and issues one `UNITCOMMAND_TransportUnloadUnits` to `targetPos`.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::UnloadAllAtLocation(const Wm3::Vector3f& targetPos)
  {
    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    SEntitySetTemplateUnit carriers{};
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
        CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
        if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
          continue;
        }

        SEntitySetTemplateUnit squadUnits{};
        CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entry);
          if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt()) {
            continue;
          }
          if (unit->IsInCategory("TRANSPORTATION") || unit->IsInCategory("CARRIER")) {
            (void)carriers.AddUnit(unit);
          }
        }
        break;
      }
    }

    if (!carriers.Empty()) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportUnloadUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
      commandIssueData.mTarget.mPos = targetPos;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, carriers, commandIssueData, false);
      if (issuedCommand != nullptr) {
        InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00730E30 (FUN_00730E30, cfunc_CPlatoonUnloadAllAtLocationL)
   *
   * What it does:
   * Parses `(platoon, location)`, validates the point, issues the unload orders
   * via `CPlatoon::UnloadAllAtLocation`, returns the issued commands as a Lua
   * array, then releases the weak command links.
   */
  int cfunc_CPlatoonUnloadAllAtLocationL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected %d args, but got %d", kUnloadAllAtLocationHelpText, 2, argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    const Wm3::Vector3f targetPos = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);
    if (!IsValidVector3f(targetPos)) {
      LuaPlus::LuaState::Error(state, "Platoon:UnloadAllAtLocation Passed in an invalid target point");
    }

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->UnloadAllAtLocation(targetPos);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00730DB0 (FUN_00730DB0, cfunc_CPlatoonUnloadAllAtLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUnloadAllAtLocationL`.
   */
  int cfunc_CPlatoonUnloadAllAtLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUnloadAllAtLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00730DD0 (FUN_00730DD0, func_CPlatoonUnloadAllAtLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UnloadAllAtLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUnloadAllAtLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UnloadAllAtLocation",
      &cfunc_CPlatoonUnloadAllAtLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUnloadAllAtLocationHelpText
    );
    return &binder;
  }

  /**
   * What it does:
   * Issues one patrol order over `units` toward `target`. When a valid formation
   * script resolved and the set holds more than one unit, issues
   * UNITCOMMAND_FormPatrol carrying the formation script index and an identity
   * orientation; otherwise a plain UNITCOMMAND_Patrol. Shared by both
   * CPlatoon::Patrol dispatch branches.
   */
  static void IssuePlatoonPatrolCommand(
    Sim* const sim,
    SEntitySetTemplateUnit& units,
    const Wm3::Vector3f& target,
    const int formationScriptIndex
  )
  {
    const bool useFormation = formationScriptIndex >= 0 && units.Size() > 1u;

    SSTICommandIssueData commandIssueData(
      useFormation ? EUnitCommandType::UNITCOMMAND_FormPatrol : EUnitCommandType::UNITCOMMAND_Patrol
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
    commandIssueData.mTarget.mPos = target;

    if (useFormation) {
      commandIssueData.unk38 = formationScriptIndex;  // FormPatrol formation-script lane
      commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
      commandIssueData.unk4C = 1.0f;                   // FormPatrol orientation weight
    }

    (void)IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
  }

  /**
   * Address: 0x00726420 (FUN_00726420, Moho::CPlatoon::Patrol)
   *
   * IDA signature:
   * void __userpurge CPlatoon::Patrol(Wm3::Vector3f *target@<edi>, CPlatoon *this,
   *                                   ESquadClass squadClass)
   *
   * What it does:
   * Issues a patrol order for the platoon toward `target`, first snapping the
   * point to the map/water surface elevation. If the platoon has a named
   * formation it patrols the whole platoon as one formation set; otherwise it
   * patrols each requested squad class independently (Attack..Scout, or every
   * class when `squadClass` is the all-classes sentinel 6). Each set is issued as
   * FormPatrol when a formation script resolves and it holds more than one unit,
   * else a plain Patrol.
   */
  void CPlatoon::Patrol(Wm3::Vector3f& target, const ESquadClass squadClass)
  {
    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(target.x, target.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    target.y = surfaceElevation;

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;

    // Platoon-wide formation patrol.
    if (!mFormation.empty()) {
      SEntitySetTemplateUnit platoonUnits{};
      BuildPlatoonUnitSet(*reinterpret_cast<const CPlatoonRuntimeView*>(this), platoonUnits);
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonPatrolCommand(mSim, platoonUnits, target, formationScriptIndex);
      return;
    }

    // Per-squad-class patrol: each requested class patrols on its own.
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      if (static_cast<std::int32_t>(squadClass) != kAllSquadClassesSentinel &&
          static_cast<std::int32_t>(squadClass) != squadClassIndex) {
        continue;
      }

      for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
        CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
        if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
          continue;
        }

        SEntitySetTemplateUnit squadUnits{};
        CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
        const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
        IssuePlatoonPatrolCommand(mSim, squadUnits, target, formationScriptIndex);
        break;
      }
    }
  }

  /**
   * Address: 0x00731370 (FUN_00731370, cfunc_CPlatoonPatrolL)
   *
   * IDA signature:
   * int __usercall cfunc_CPlatoonPatrolL@<eax>(LuaPlus::LuaState *state@<ebx>)
   *
   * What it does:
   * Resolves `(platoon, targetPoint[, squadClass])`, validates the point, and
   * issues the patrol via `CPlatoon::Patrol`. The squad class defaults to the
   * all-classes sentinel and is only read from arg 3 when supplied.
   */
  int cfunc_CPlatoonPatrolL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kPatrolHelpText, 2, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Wm3::Vector3f targetPoint = SCR_FromLuaCopy<Wm3::Vector3<float>>(targetObject);
    if (!IsValidVector3f(targetPoint)) {
      LuaPlus::LuaState::Error(state, "Platoon:Patrol Passed in an invalid target point");
    }

    ESquadClass squadClass = static_cast<ESquadClass>(kAllSquadClassesSentinel);
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      gpg::RRef_ESquadClass(&enumRef, &squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    platoon->Patrol(targetPoint, squadClass);
    return 0;
  }

  /**
   * Address: 0x007312F0 (FUN_007312F0, cfunc_CPlatoonPatrol)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonPatrolL`.
   */
  int cfunc_CPlatoonPatrol(lua_State* const luaContext)
  {
    return cfunc_CPlatoonPatrolL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731310 (FUN_00731310, func_CPlatoonPatrol_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Patrol()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPatrol_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Patrol",
      &cfunc_CPlatoonPatrol,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kPatrolHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00728420 (FUN_00728420, func_IssueGuardTargetToPlatoon)
   *
   * What it does:
   * Issues `UNITCOMMAND_Guard` (target = `guardTarget`) on the platoon's units
   * and returns the created command links. When the platoon has no formation
   * name it issues one command per matching squad class (1..2, or all when
   * `kAllSquadsClass`); otherwise it issues a single command on the whole merged
   * platoon unit set.
   */
  static msvc8::vector<WeakPtr<CUnitCommand>> IssueGuardTargetToPlatoon(
    CPlatoon* const platoon,
    Unit* const guardTarget,
    const ESquadClass squadClass
  )
  {
    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    const auto issueGuardOnUnits = [&](SEntitySetTemplateUnit& units) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Guard);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(guardTarget->GetEntityId());
      commandIssueData.mTarget.mPos.x = 0.0f;
      commandIssueData.mTarget.mPos.y = 0.0f;
      commandIssueData.mTarget.mPos.z = 0.0f;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(platoon->mSim, units, commandIssueData, false);
      if (issuedCommand != nullptr) {
        InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
      }
    };

    if (platoon->mFormation.empty()) {
      const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(platoon);
      for (std::int32_t squadClassIndex = 1; squadClassIndex <= 2; ++squadClassIndex) {
        if (squadClass != kAllSquadsClass && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
          CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
          if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
            continue;
          }

          SEntitySetTemplateUnit squadUnits{};
          CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
          issueGuardOnUnits(squadUnits);
          break;
        }
      }
    } else {
      SEntitySetTemplateUnit formationUnits{};
      BuildPlatoonUnitSet(*reinterpret_cast<const CPlatoonRuntimeView*>(platoon), formationUnits);
      issueGuardOnUnits(formationUnits);
    }

    return issuedCommands;
  }

  /**
   * Address: 0x007310A0 (FUN_007310A0, cfunc_CPlatoonGuardTargetL)
   *
   * What it does:
   * Parses `(platoon, targetUnit, [squadClass])`, issues guard orders on the
   * platoon via `IssueGuardTargetToPlatoon`, returns the issued commands as a
   * Lua array, then releases the weak command links.
   */
  int cfunc_CPlatoonGuardTargetL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kGuardTargetHelpText,
        2,
        3,
        argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Unit* const guardTarget = SCR_FromLua_Unit(targetObject);

    ESquadClass squadClass = kAllSquadsClass;
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      gpg::RRef_ESquadClass(&enumRef, &squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }

      SCR_GetEnum(state, squadClassName, enumRef);
    }

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = IssueGuardTargetToPlatoon(platoon, guardTarget, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00731020 (FUN_00731020, cfunc_CPlatoonGuardTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGuardTargetL`.
   */
  int cfunc_CPlatoonGuardTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGuardTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731040 (FUN_00731040, func_CPlatoonGuardTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GuardTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGuardTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GuardTarget",
      &cfunc_CPlatoonGuardTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGuardTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00726210 (FUN_00726210, sub_726210, CPlatoon destroy-squads helper)
   *
   * What it does:
   * Clears the platoon's cached Lua unit list, then for each matching squad
   * class detaches every unit from its squad and queues `UNITCOMMAND_DestroySelf`
   * on the live members.
   */
  static void DestroyPlatoonSquads(CPlatoon* const platoon, const ESquadClass squadClass)
  {
    auto& runtime = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    runtime.mHasLuaList = 0u;

    SEntitySetTemplateUnit doomedUnits{};
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      if (squadClass != kAllSquadsClass && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
        continue;
      }

      for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
        CSquadRuntimeView* const squadView = *squadLane;
        if (squadView == nullptr || static_cast<std::int32_t>(squadView->mSquadClass) != squadClassIndex) {
          continue;
        }

        SEntitySetTemplateUnit squadUnits{};
        CopyCSquadUnitsIntoEntitySet(&squadUnits, reinterpret_cast<const CSquad*>(squadView));

        // Live members get the destroy order; every member is detached from the squad.
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entry);
          if (unit != nullptr && !unit->IsDead()) {
            (void)doomedUnits.AddUnit(unit);
          }
        }
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          RemoveUnitFromSquad(squadView, SEntitySetTemplateUnit::UnitFromEntry(*entry));
        }
        break;
      }
    }

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_DestroySelf);
    (void)IssueCommandToSelectedUnits(platoon->mSim, doomedUnits, commandIssueData, false);
  }

  /**
   * Address: 0x00731570 (FUN_00731570, cfunc_CPlatoonDestroyL)
   *
   * What it does:
   * Parses `(platoon, [squadClass])`, and when the platoon is still alive,
   * destroys the selected squads via `DestroyPlatoonSquads`.
   */
  int cfunc_CPlatoonDestroyL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected between %d and %d args, but got %d", kDestroyHelpText, 1, 2, argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (platoon != nullptr) {
      ESquadClass squadClass = kAllSquadsClass;
      if (lua_gettop(state->m_state) > 1) {
        gpg::RRef enumRef{};
        gpg::RRef_ESquadClass(&enumRef, &squadClass);

        const char* const squadClassName = lua_tostring(state->m_state, 2);
        if (squadClassName == nullptr) {
          LuaPlus::LuaStackObject typeErrorArg(state, 2);
          LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
        }

        SCR_GetEnum(state, squadClassName, enumRef);
      }

      DestroyPlatoonSquads(platoon, squadClass);
    }

    return 0;
  }

  /**
   * Address: 0x007314F0 (FUN_007314F0, cfunc_CPlatoonDestroy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonDestroyL`.
   */
  int cfunc_CPlatoonDestroy(lua_State* const luaContext)
  {
    return cfunc_CPlatoonDestroyL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731510 (FUN_00731510, func_CPlatoonDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Destroy()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonDestroy_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Destroy",
      &cfunc_CPlatoonDestroy,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kDestroyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00725870 (FUN_00725870, Moho::CPlatoon::GetFerryBeacons)
   *
   * IDA signature:
   * SEntitySetTemplateUnit* __stdcall CPlatoon::GetFerryBeacons(CPlatoon* this,
   *                                                             SEntitySetTemplateUnit* out);
   *
   * What it does:
   * Collects the ferry-beacon units the platoon is currently ferrying to: for every
   * platoon unit in the Ferrying state, the beacon named by the head of its command
   * queue (Unit::GetTransportFerryBeacon) is added to `outBeacons` (deduplicated by
   * the entity set). The decompiler mislabels the result as `std::map_uint_Entity`;
   * it is the intrusive unit set the callback then exposes to Lua.
   */
  void CPlatoon::GetFerryBeacons(SEntitySetTemplateUnit& outBeacons)
  {
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(runtime, platoonUnits);

    for (Entity* const* entry = platoonUnits.mVec.begin(); entry != platoonUnits.mVec.end(); ++entry) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entry);
      if (unit == nullptr || !unit->IsUnitState(EUnitState::UNITSTATE_Ferrying)) {
        continue;
      }
      if (Unit* const beacon = unit->GetTransportFerryBeacon()) {
        (void)outBeacons.AddUnit(beacon);
      }
    }
  }

  /**
   * Address: 0x00731840 (FUN_00731840, cfunc_CPlatoonGetFerryBeaconsL)
   *
   * What it does:
   * Parses `(platoon)`, gathers the platoon's ferry beacons via
   * `CPlatoon::GetFerryBeacons`, and returns them as a Lua array of unit objects.
   */
  int cfunc_CPlatoonGetFerryBeaconsL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetFerryBeaconsHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    SEntitySetTemplateUnit ferryBeacons{};
    platoon->GetFerryBeacons(ferryBeacons);

    LuaPlus::LuaObject beaconTable{};
    beaconTable.AssignNewTable(state, static_cast<int>(ferryBeacons.Size()), 0);

    int beaconIndex = 1;
    for (Entity* const* entry = ferryBeacons.mVec.begin(); entry != ferryBeacons.mVec.end(); ++entry) {
      Unit* const beacon = SEntitySetTemplateUnit::UnitFromEntry(*entry);
      if (beacon == nullptr) {
        continue;
      }
      LuaPlus::LuaObject beaconObject = beacon->GetLuaObject();
      beaconTable.Insert(beaconIndex, beaconObject);
      ++beaconIndex;
    }

    beaconTable.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x007317C0 (FUN_007317C0, cfunc_CPlatoonGetFerryBeacons)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetFerryBeaconsL`.
   */
  int cfunc_CPlatoonGetFerryBeacons(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetFerryBeaconsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007317E0 (FUN_007317E0, func_CPlatoonGetFerryBeacons_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetFerryBeacons()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetFerryBeacons_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetFerryBeacons",
      &cfunc_CPlatoonGetFerryBeacons,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetFerryBeaconsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00729A70 (FUN_00729A70, Moho::CPlatoon::UseFerryBeacon)
   *
   * IDA signature:
   * gpg::fastvector_shared_ptr_CUnitCommand* __userpurge
   *   CPlatoon::UseFerryBeacon(EntityCategory* cat@<edi>, CPlatoon* this,
   *                            gpg::fastvector* out, int beacon);
   *
   * What it does:
   * Scans every squad class (1..5) of the platoon and collects the alive,
   * not-being-built, mobile units whose blueprint ordinal is a member of
   * `category` into a single set, then issues one UNITCOMMAND_TransportLoadUnits
   * targeted at the ferry-beacon entity so those units load onto the beacon.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::UseFerryBeacon(const EntityCategorySet* const category, Unit* const beacon)
  {
    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    SEntitySetTemplateUnit loadableUnits{};
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
        CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
        if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
          continue;
        }

        SEntitySetTemplateUnit squadUnits{};
        CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entry);
          if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt() || !unit->IsMobile()) {
            continue;
          }
          // The category bitset is keyed by the blueprint's category-bit index
          // (REntityBlueprint::mCategoryBitIndex, +0x5C -- the decompiler's
          // "mBlueprintOrdinal" on the RUnitBlueprint returned by GetBlueprint).
          const std::uint32_t ordinal = unit->GetBlueprint()->mCategoryBitIndex;
          if (category->mBits.Contains(ordinal)) {
            (void)loadableUnits.AddUnit(unit);
          }
        }
        break;
      }
    }

    if (!loadableUnits.Empty()) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(beacon->id_);
      commandIssueData.mTarget.mPos.x = 0.0f;
      commandIssueData.mTarget.mPos.y = 0.0f;
      commandIssueData.mTarget.mPos.z = 0.0f;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, loadableUnits, commandIssueData, false);
      if (issuedCommand != nullptr) {
        InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00731A30 (FUN_00731A30, cfunc_CPlatoonUseFerryBeaconL)
   *
   * What it does:
   * Parses `(platoon, category, beacon)`, resolves the reflected `EntityCategorySet`
   * and the beacon unit, issues the load orders via `CPlatoon::UseFerryBeacon`,
   * returns the issued commands as a Lua array, then releases the weak command links.
   */
  int cfunc_CPlatoonUseFerryBeaconL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kUseFerryBeaconHelpText, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const category = func_GetCObj_EntityCategory(categoryObject);

    const LuaPlus::LuaObject beaconObject(LuaPlus::LuaStackObject(state, 3));
    Unit* const beacon = SCR_FromLua_Unit(beaconObject);

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->UseFerryBeacon(category, beacon);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x007319B0 (FUN_007319B0, cfunc_CPlatoonUseFerryBeacon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUseFerryBeaconL`.
   */
  int cfunc_CPlatoonUseFerryBeacon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUseFerryBeaconL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007319D0 (FUN_007319D0, func_CPlatoonUseFerryBeacon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UseFerryBeacon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUseFerryBeacon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UseFerryBeacon",
      &cfunc_CPlatoonUseFerryBeacon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUseFerryBeaconHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00729D20 (FUN_00729D20, Moho::CPlatoon::UseTeleporter)
   *
   * What it does:
   * Accumulates units from the matching squad classes (1..5, or all when
   * `kAllSquadsClass`) into one set, appends the teleporter unit, and issues a
   * single `UNITCOMMAND_TransportLoadUnits` targeting the teleporter. Returns
   * the issued command weak-links.
   */
  msvc8::vector<WeakPtr<CUnitCommand>> CPlatoon::UseTeleporter(Unit* const teleporter, const ESquadClass squadClass)
  {
    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    SEntitySetTemplateUnit selectedUnits{};
    const auto& runtime = *reinterpret_cast<const CPlatoonRuntimeView*>(this);
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      if (squadClass != kAllSquadsClass && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
        continue;
      }

      for (CSquadRuntimeView* const* squadLane = runtime.mSquadStart; squadLane != runtime.mSquadEnd; ++squadLane) {
        CSquad* const squad = reinterpret_cast<CSquad*>(*squadLane);
        if (squad == nullptr || static_cast<std::int32_t>(squad->mSquadClass) != squadClassIndex) {
          continue;
        }

        SEntitySetTemplateUnit squadUnits{};
        CopyCSquadUnitsIntoEntitySet(&squadUnits, squad);
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          (void)selectedUnits.AddUnit(SEntitySetTemplateUnit::UnitFromEntry(*entry));
        }
        break;
      }
    }

    if (!selectedUnits.Empty() && teleporter != nullptr) {
      (void)selectedUnits.AddUnit(teleporter);

      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(teleporter->GetEntityId());
      commandIssueData.mTarget.mPos.x = 0.0f;
      commandIssueData.mTarget.mPos.y = 0.0f;
      commandIssueData.mTarget.mPos.z = 0.0f;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, selectedUnits, commandIssueData, false);
      if (issuedCommand != nullptr) {
        InsertWeakPtrVectorObjectAt(issuedCommands, issuedCommand, issuedCommands.size());
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00731CB0 (FUN_00731CB0, cfunc_CPlatoonUseTeleporterL)
   *
   * What it does:
   * Parses `(platoon, teleporterUnit, [squadClass])`, issues the teleporter-load
   * orders via `CPlatoon::UseTeleporter`, returns the issued commands as a Lua
   * array, then releases the weak command links.
   */
  int cfunc_CPlatoonUseTeleporterL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kUseTeleporterHelpText,
        2,
        3,
        argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject teleporterObject(LuaPlus::LuaStackObject(state, 2));
    Unit* const teleporter = SCR_FromLua_Unit(teleporterObject);

    ESquadClass squadClass = kAllSquadsClass;
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      gpg::RRef_ESquadClass(&enumRef, &squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }

      SCR_GetEnum(state, squadClassName, enumRef);
    }

    msvc8::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->UseTeleporter(teleporter, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    int commandIndex = 1;
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(commandIndex, command->mArgs);
      ++commandIndex;
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00731C30 (FUN_00731C30, cfunc_CPlatoonUseTeleporter)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUseTeleporterL`.
   */
  int cfunc_CPlatoonUseTeleporter(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUseTeleporterL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731C50 (FUN_00731C50, func_CPlatoonUseTeleporter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UseTeleporter()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUseTeleporter_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UseTeleporter",
      &cfunc_CPlatoonUseTeleporter,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUseTeleporterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00732140 (FUN_00732140, cfunc_CPlatoonSetPlatoonFormationOverrideL)
   *
   * What it does:
   * Resolves `(platoon, formationName)` from Lua, maps `"None"` to empty text,
   * and stores the formation override lane.
   */
  int cfunc_CPlatoonSetPlatoonFormationOverrideL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kSetPlatoonFormationOverrideHelpText,
        2,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaStackObject formationArg(state, 2);
    const char* formationText = lua_tostring(state->m_state, 2);
    if (formationText == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&formationArg, "string");
      formationText = "";
    }

    msvc8::string formationOverride{};
    if (_stricmp(formationText, "None") != 0) {
      formationOverride.assign(formationText);
    }

    platoon->SetPlatoonFormationOverride(formationOverride);
    return 0;
  }

  /**
   * Address: 0x007320C0 (FUN_007320C0, cfunc_CPlatoonSetPlatoonFormationOverride)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonSetPlatoonFormationOverrideL`.
   */
  int cfunc_CPlatoonSetPlatoonFormationOverride(lua_State* const luaContext)
  {
    return cfunc_CPlatoonSetPlatoonFormationOverrideL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007320E0 (FUN_007320E0, func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SetPlatoonFormationOverride()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetPlatoonFormationOverride",
      &cfunc_CPlatoonSetPlatoonFormationOverride,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kSetPlatoonFormationOverrideHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007322D0 (FUN_007322D0, cfunc_CPlatoonGetPlatoonLifetimeStats)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPlatoonLifetimeStatsL`.
   */
  int cfunc_CPlatoonGetPlatoonLifetimeStats(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonLifetimeStatsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732350 (FUN_00732350, cfunc_CPlatoonGetPlatoonLifetimeStatsL)
   *
   * What it does:
   * Resolves one platoon and pushes its four persisted lifetime stat lanes, or
   * `nil` when the platoon object is absent.
   */
  int cfunc_CPlatoonGetPlatoonLifetimeStatsL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetPlatoonLifetimeStatsHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (platoon == nullptr) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    lua_pushnumber(state->m_state, static_cast<float>(platoon->GetLifetimeStat1()));
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, static_cast<float>(platoon->GetLifetimeStat2()));
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, platoon->GetLifetimeStat3());
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, platoon->GetLifetimeStat4());
    (void)lua_gettop(state->m_state);
    return 4;
  }

  /**
   * Address: 0x007322F0 (FUN_007322F0, func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonLifetimeStats()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonLifetimeStats",
      &cfunc_CPlatoonGetPlatoonLifetimeStats,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonLifetimeStatsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007324A0 (FUN_007324A0, cfunc_CPlatoonCalculatePlatoonThreat)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCalculatePlatoonThreatL`.
   */
  int cfunc_CPlatoonCalculatePlatoonThreat(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCalculatePlatoonThreatL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732520 (FUN_00732520, cfunc_CPlatoonCalculatePlatoonThreatL)
   *
   * What it does:
   * Resolves `(platoon, threatType, category)` and returns total threat across
   * live platoon units matching the requested category.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCalculatePlatoonThreatHelpText, 3, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaStackObject threatTypeArg(state, 2);
    const char* const threatTypeName = lua_tostring(state->m_state, 2);
    if (threatTypeName == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&threatTypeArg, "string");
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 3));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);
    const PlatoonThreatType threatType = ParsePlatoonThreatType(threatTypeName);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(runtimeView, platoonUnits);

    float totalThreat = 0.0f;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (!BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        continue;
      }

      totalThreat += ResolveBlueprintThreatValue(*unitBlueprint, threatType);
    }

    lua_pushnumber(state->m_state, totalThreat);
    return 1;
  }

  /**
   * Address: 0x007324C0 (FUN_007324C0, func_CPlatoonCalculatePlatoonThreat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CalculatePlatoonThreat()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCalculatePlatoonThreat_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CalculatePlatoonThreat",
      &cfunc_CPlatoonCalculatePlatoonThreat,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCalculatePlatoonThreatHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007328E0 (FUN_007328E0, cfunc_CPlatoonCalculatePlatoonThreatAroundPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL`.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732960 (FUN_00732960, cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL)
   *
   * What it does:
   * Resolves `(platoon, threatType, category, position, radius)` and returns
   * category-filtered threat from live platoon units within 2D radius.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 5) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kCalculatePlatoonThreatAroundPositionHelpText,
        5,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaStackObject threatTypeArg(state, 2);
    const char* const threatTypeName = lua_tostring(state->m_state, 2);
    if (threatTypeName == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&threatTypeArg, "string");
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 3));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 4));
    const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);
    const float radiusSq = ReadSquaredRadiusArg(state, 5);
    const PlatoonThreatType threatType = ParsePlatoonThreatType(threatTypeName);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(runtimeView, platoonUnits);

    float totalThreat = 0.0f;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const Wm3::Vector3f& unitPosition = unit->GetPosition();
      const float dx = position.x - unitPosition.x;
      const float dz = position.z - unitPosition.z;
      if ((dx * dx + dz * dz) > radiusSq) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (!BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        continue;
      }

      totalThreat += ResolveBlueprintThreatValue(*unitBlueprint, threatType);
    }

    lua_pushnumber(state->m_state, totalThreat);
    return 1;
  }

  /**
   * Address: 0x00732900 (FUN_00732900, func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CalculatePlatoonThreatAroundPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CalculatePlatoonThreatAroundPosition",
      &cfunc_CPlatoonCalculatePlatoonThreatAroundPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCalculatePlatoonThreatAroundPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00732E40 (FUN_00732E40, cfunc_CPlatoonPlatoonCategoryCountAroundPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonPlatoonCategoryCountAroundPositionL`.
   */
  int cfunc_CPlatoonPlatoonCategoryCountAroundPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonPlatoonCategoryCountAroundPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732EC0 (FUN_00732EC0, cfunc_CPlatoonPlatoonCategoryCountAroundPositionL)
   *
   * What it does:
   * Resolves `(platoon, category, position, radius)` and counts live platoon
   * units matching the category within 2D radius.
   */
  int cfunc_CPlatoonPlatoonCategoryCountAroundPositionL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kPlatoonCategoryCountAroundPositionHelpText,
        4,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);
    LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 3));
    const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);
    const float radiusSq = ReadSquaredRadiusArg(state, 4);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(runtimeView, platoonUnits);

    int matchingCount = 0;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const Wm3::Vector3f& unitPosition = unit->GetPosition();
      const float dx = position.x - unitPosition.x;
      const float dz = position.z - unitPosition.z;
      if ((dx * dx + dz * dz) > radiusSq) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        ++matchingCount;
      }
    }

    lua_pushnumber(state->m_state, static_cast<float>(matchingCount));
    return 1;
  }

  /**
   * Address: 0x00732E60 (FUN_00732E60, func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:PlatoonCategoryCountAroundPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "PlatoonCategoryCountAroundPosition",
      &cfunc_CPlatoonPlatoonCategoryCountAroundPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kPlatoonCategoryCountAroundPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007331C0 (FUN_007331C0, cfunc_CPlatoonPlatoonCategoryCount)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonPlatoonCategoryCountL`.
   */
  int cfunc_CPlatoonPlatoonCategoryCount(lua_State* const luaContext)
  {
    return cfunc_CPlatoonPlatoonCategoryCountL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00733240 (FUN_00733240, cfunc_CPlatoonPlatoonCategoryCountL)
   *
   * What it does:
   * Resolves `(platoon, category)` and counts live platoon units matching
   * that category.
   */
  int cfunc_CPlatoonPlatoonCategoryCountL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kPlatoonCategoryCountHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    auto& runtimeView = *reinterpret_cast<CPlatoonRuntimeView*>(platoon);
    SEntitySetTemplateUnit platoonUnits{};
    BuildPlatoonUnitSet(runtimeView, platoonUnits);

    int matchingCount = 0;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        ++matchingCount;
      }
    }

    lua_pushnumber(state->m_state, static_cast<float>(matchingCount));
    return 1;
  }

  /**
   * Address: 0x007331E0 (FUN_007331E0, func_CPlatoonPlatoonCategoryCount_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:PlatoonCategoryCount()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPlatoonCategoryCount_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "PlatoonCategoryCount",
      &cfunc_CPlatoonPlatoonCategoryCount,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kPlatoonCategoryCountHelpText
    );
    return &binder;
  }
} // namespace moho

namespace
{
  struct CPlatoonLuaBindingBootstrap
  {
    CPlatoonLuaBindingBootstrap()
    {
      (void)moho::InitializeCSquadSerializerHelperStoragePrimary();
      (void)moho::InitializeCSquadSerializerHelperStorageSecondary();
      (void)moho::InitializeCPlatoonSerializerHelperStoragePrimary();
      (void)moho::InitializeCPlatoonSerializerHelperStorageSecondary();
      (void)moho::InitializeCSquadConstructHelper();
      (void)moho::InitializeCSquadGenericConstructHelper();
      (void)moho::InitializeCPlatoonConstructHelper();
      (void)moho::InitializeCPlatoonGenericConstructHelper();
      (void)moho::register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();
      (void)moho::func_CPlatoonGetPlatoonUnits_LuaFuncDef();
      (void)moho::func_CPlatoonCanFormPlatoon_LuaFuncDef();
      (void)moho::func_CPlatoonFormPlatoon_LuaFuncDef();
      (void)moho::func_CPlatoonIsOpponentAIRunning_LuaFuncDef();
      (void)moho::func_CPlatoonDisbandOnIdle_LuaFuncDef();
      (void)moho::func_CPlatoonIsCommandsActive_LuaFuncDef();
      (void)moho::func_CPlatoonIsAttacking_LuaFuncDef();
      (void)moho::func_CPlatoonIsMoving_LuaFuncDef();
      (void)moho::func_CPlatoonIsPatrolling_LuaFuncDef();
      (void)moho::func_CPlatoonIsFerrying_LuaFuncDef();
      (void)moho::func_CPlatoonSetPrioritizedTargetList_LuaFuncDef();
      (void)moho::func_CPlatoonFindPrioritizedUnit_LuaFuncDef();
      (void)moho::func_CPlatoonFindClosestUnit_LuaFuncDef();
      (void)moho::func_CPlatoonFindClosestUnitToBase_LuaFuncDef();
      (void)moho::func_CPlatoonFindFurthestUnit_LuaFuncDef();
      (void)moho::func_CPlatoonFindHighestValueUnit_LuaFuncDef();
      (void)moho::func_CPlatoonCanAttackTarget_LuaFuncDef();
      (void)moho::func_CPlatoonStop_LuaFuncDef();
      (void)moho::func_CPlatoonAttackTarget_LuaFuncDef();
      (void)moho::func_CPlatoonMoveToTarget_LuaFuncDef();
      (void)moho::func_CPlatoonMoveToLocation_LuaFuncDef();
      (void)moho::func_CPlatoonAggressiveMoveToLocation_LuaFuncDef();
      (void)moho::func_CPlatoonFerryToLocation_LuaFuncDef();
      (void)moho::func_CPlatoonLoadUnits_LuaFuncDef();
      (void)moho::func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef();
      (void)moho::func_CPlatoonUnloadAllAtLocation_LuaFuncDef();
      (void)moho::func_CPlatoonPatrol_LuaFuncDef();
      (void)moho::func_CPlatoonGuardTarget_LuaFuncDef();
      (void)moho::func_CPlatoonDestroy_LuaFuncDef();
      (void)moho::func_CPlatoonGetFerryBeacons_LuaFuncDef();
      (void)moho::func_CPlatoonUseFerryBeacon_LuaFuncDef();
      (void)moho::func_CPlatoonUseTeleporter_LuaFuncDef();
      (void)moho::func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef();
      (void)moho::func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef();
      (void)moho::func_CPlatoonCalculatePlatoonThreat_LuaFuncDef();
      (void)moho::func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef();
      (void)moho::func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef();
      (void)moho::func_CPlatoonPlatoonCategoryCount_LuaFuncDef();
    }
  };

  [[maybe_unused]] CPlatoonLuaBindingBootstrap gCPlatoonLuaBindingBootstrap;
} // namespace
