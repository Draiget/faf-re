#include "moho/unit/tasks/CUnitAssistMoveTask.h"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SOCellPos.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitLoadUnits.h"
#include "moho/unit/tasks/CUnitMoveTask.h"
#include "moho/unit/tasks/CUnitUnloadUnits.h"

namespace
{
  constexpr std::uintptr_t kInvalidEntitySlot = 0x8u;
  constexpr std::uint64_t kUnitStateMaskAssistMoving = (1ull << static_cast<std::uint32_t>(moho::UNITSTATE_AssistMoving));

  [[nodiscard]] bool IsUsableUnitSlot(const moho::Unit* const unit) noexcept
  {
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(unit);
    return raw != 0u && raw != kInvalidEntitySlot;
  }

  [[nodiscard]] bool IsZeroVector(const Wm3::Vector3f& value) noexcept
  {
    return value.x == 0.0f && value.y == 0.0f && value.z == 0.0f;
  }

  [[nodiscard]] moho::CUnitCommand* ResolveCurrentCommand(moho::Unit* const unit) noexcept
  {
    if (unit == nullptr || unit->CommandQueue == nullptr) {
      return nullptr;
    }
    return unit->CommandQueue->GetCurrentCommand();
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSNavGoalType()
  {
    gpg::RType* type = moho::SNavGoal::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SNavGoal));
      moho::SNavGoal::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitAssistMoveTaskType()
  {
    gpg::RType* type = moho::CUnitAssistMoveTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitAssistMoveTask));
      moho::CUnitAssistMoveTask::sType = type;
    }
    return type;
  }

  void ReadBoolIntoByteLane(gpg::ReadArchive* const archive, std::uint8_t& lane) noexcept
  {
    bool value = false;
    archive->ReadBool(&value);
    lane = value ? 1u : 0u;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitAssistMoveTask::sType = nullptr;

  /**
   * Address: 0x005F0CF0 (FUN_005F0CF0)
   *
   * What it does:
   * Builds one default assist-move task lane with zeroed dispatch/goal state.
   */
  CUnitAssistMoveTask::CUnitAssistMoveTask()
    : CCommandTask()
    , mDispatchTask(nullptr)
    , mMoveGoal{}
    , mMoveGoalWorldPosition{0.0f, 0.0f, 0.0f}
    , mHasPathFindingPickupCandidate(0)
    , mPad65_67{0, 0, 0}
  {
  }

  /**
   * Address: 0x005F0BC0 (FUN_005F0BC0, Moho::CUnitAssistMoveTask::CUnitAssistMoveTask)
   *
   * What it does:
   * Initializes one assist-move task from parent command-task context and
   * cached move-goal payload, then enables `UNITSTATE_AssistMoving`.
   */
  CUnitAssistMoveTask::CUnitAssistMoveTask(CCommandTask* const dispatchTask, const SNavGoal& moveGoal)
    : CCommandTask(dispatchTask)
    , mDispatchTask(dispatchTask)
    , mMoveGoal(moveGoal)
    , mMoveGoalWorldPosition{0.0f, 0.0f, 0.0f}
    , mHasPathFindingPickupCandidate(0)
    , mPad65_67{0, 0, 0}
  {
    if (mUnit == nullptr || mUnit->SimulationRef == nullptr) {
      mTaskState = TASKSTATE_Complete;
      return;
    }

    const SOCellPos moveGoalCell{
      static_cast<std::int16_t>(mMoveGoal.minX),
      static_cast<std::int16_t>(mMoveGoal.minZ),
    };
    const SFootprint& footprint = mUnit->GetFootprint();
    mMoveGoalWorldPosition = COORDS_ToWorldPos(
      mUnit->SimulationRef->mMapData,
      moveGoalCell,
      static_cast<ELayer>(static_cast<std::uint8_t>(footprint.mOccupancyCaps)),
      static_cast<int>(footprint.mSizeX),
      static_cast<int>(footprint.mSizeZ)
    );

    mUnit->mUnitVarDat.mUnitStates |= kUnitStateMaskAssistMoving;
    mTaskState = (mUnit->AiTransport != nullptr) ? TASKSTATE_Preparing : TASKSTATE_Complete;
  }

  /**
   * Address: 0x005F0D40 (FUN_005F0D40, Moho::CUnitAssistMoveTask::~CUnitAssistMoveTask)
   * Address: 0x005F0CD0 (FUN_005F0CD0, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   *
   * What it does:
   * Clears assist-move unit state and loaded-unit command queues, then
   * unreserves transport unattached slots.
   */
  CUnitAssistMoveTask::~CUnitAssistMoveTask()
  {
    if (mUnit == nullptr) {
      return;
    }

    mUnit->mUnitVarDat.mUnitStates &= ~kUnitStateMaskAssistMoving;

    IAiTransport* const transport = mUnit->AiTransport;
    if (transport == nullptr) {
      return;
    }

    const EntitySetTemplate<Unit> loadedUnits = transport->TransportGetLoadedUnits(true);
    for (Unit* const loadedUnit : loadedUnits) {
      if (!IsUsableUnitSlot(loadedUnit) || loadedUnit->IsDead()) {
        continue;
      }

      if (loadedUnit->CommandQueue != nullptr) {
        loadedUnit->CommandQueue->ClearCommandQueue();
      }
    }

    transport->TransportUnreserveUnattachedSpots();
  }

  /**
   * Address: 0x005F1060 (FUN_005F1060, Moho::CUnitAssistMoveTask::GetEntitiesAlreadyAtLoc)
   *
   * What it does:
   * Builds one candidate set of loadable allied mobile land units near
   * this assist task's context and writes filtered results into `outUnits`.
   */
  SEntitySetTemplateUnit* CUnitAssistMoveTask::GetEntitiesAlreadyAtLoc(SEntitySetTemplateUnit* const outUnits)
  {
    if (outUnits == nullptr) {
      return nullptr;
    }

    outUnits->ListResetLinks();
    outUnits->mVec.RebindInlineNoFree();

    mHasPathFindingPickupCandidate = 0;
    if (
      mUnit == nullptr
      || mSim == nullptr
      || mSim->mRules == nullptr
      || mUnit->SimulationRef == nullptr
      || mUnit->SimulationRef->mRules == nullptr
      || mUnit->ArmyRef == nullptr
      || mUnit->AiTransport == nullptr
    ) {
      return outUnits;
    }

    const RUnitBlueprint* const unitBlueprint = mUnit->GetBlueprint();
    const float guardScanRadius = (unitBlueprint != nullptr) ? unitBlueprint->AI.GuardScanRadius : 0.0f;

    const EntityCategorySet* const landCategory = mSim->mRules->GetEntityCategory("LAND");
    const EntityCategorySet* const mobileCategory = mUnit->SimulationRef->mRules->GetEntityCategory("MOBILE");
    if (landCategory == nullptr || mobileCategory == nullptr) {
      return outUnits;
    }

    EntityCategorySet mobileLandCategory{};
    (void)EntityCategory::Mul(&mobileLandCategory, mobileCategory, landCategory);

    SEntitySetTemplateUnit allMobileLandUnits{};
    (void)mUnit->ArmyRef->GetUnits(&allMobileLandUnits, &mobileLandCategory);

    SEntitySetTemplateUnit pickupCandidates{};
    Wm3::Vector3f maxDistancePosition{0.0f, 0.0f, 0.0f};
    float maxDistanceScore = 0.0f;

    CUnitCommand* const ownerCommand = ResolveCurrentCommand(mUnit);
    for (Entity* const unitEntry : allMobileLandUnits.mVec) {
      Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(unitEntry);
      if (candidate == nullptr) {
        continue;
      }

      if (candidate->IsDead() || candidate->DestroyQueued() || candidate->IsBeingBuilt()) {
        continue;
      }

      IAiNavigator* const candidateNavigator = candidate->AiNavigator;
      if (candidateNavigator == nullptr) {
        continue;
      }

      if (ResolveCurrentCommand(candidate) != ownerCommand) {
        continue;
      }

      if (candidate->GetTransportedBy() != nullptr) {
        continue;
      }

      if (candidate->AssignedTransportRef.GetObjectPtr() != nullptr) {
        continue;
      }

      if (candidate->IsUnitState(UNITSTATE_TransportLoading)) {
        continue;
      }

      if (!mUnit->AiTransport->TransportCanCarryUnit(candidate)) {
        continue;
      }

      const RUnitBlueprint* const candidateBlueprint = candidate->GetBlueprint();
      if (!mUnit->AiTransport->TransportHasSpaceFor(candidateBlueprint)) {
        continue;
      }

      if (candidate->IsUnitState(UNITSTATE_PathFinding)) {
        mHasPathFindingPickupCandidate = 1;
        continue;
      }

      if (!candidate->NeedsPickup(this)) {
        continue;
      }

      (void)pickupCandidates.AddUnit(candidate);

      const Wm3::Vector3f& candidatePosition = candidate->GetPosition();
      const Wm3::Vector3f candidateGoalPosition = candidateNavigator->GetGoalPos();

      const float goalDx = candidateGoalPosition.x - candidatePosition.x;
      const float goalDz = candidateGoalPosition.z - candidatePosition.z;
      const float goalDistance = static_cast<float>(std::sqrt((goalDx * goalDx) + (goalDz * goalDz)));

      const Wm3::Vector3f& ownerPosition = mUnit->GetPosition();
      const float ownerDx = ownerPosition.x - candidatePosition.x;
      const float ownerDz = ownerPosition.z - candidatePosition.z;
      const float ownerDistance = static_cast<float>(std::sqrt((ownerDx * ownerDx) + (ownerDz * ownerDz)));

      const float score = goalDistance - (ownerDistance * 0.33000001f);
      if (score > maxDistanceScore) {
        maxDistanceScore = score;
        maxDistancePosition = candidatePosition;
      }
    }

    if (!IsZeroVector(maxDistancePosition)) {
      for (Entity* const unitEntry : pickupCandidates.mVec) {
        Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(unitEntry);
        if (candidate == nullptr) {
          continue;
        }

        const Wm3::Vector3f& candidatePosition = candidate->GetPosition();
        const float dx = maxDistancePosition.x - candidatePosition.x;
        const float dz = maxDistancePosition.z - candidatePosition.z;
        const float distance = static_cast<float>(std::sqrt((dx * dx) + (dz * dz)));
        if (guardScanRadius > distance) {
          (void)outUnits->AddUnit(candidate);
        }
      }
    }

    return outUnits;
  }

  /**
   * Address: 0x005F14E0 (FUN_005F14E0, Moho::CUnitAssistMoveTask::Wait)
   *
   * What it does:
   * Collects eligible pickup units near the assist goal and dispatches
   * load-task or unload-task progression state transitions.
   */
  void CUnitAssistMoveTask::Wait()
  {
    if (mUnit == nullptr || mUnit->AiTransport == nullptr) {
      mTaskState = TASKSTATE_Complete;
      return;
    }

    SEntitySetTemplateUnit candidateUnits{};
    (void)GetEntitiesAlreadyAtLoc(&candidateUnits);

    if (!candidateUnits.Empty()) {
      mUnit->AiTransport->TransportUnreserveUnattachedSpots();
      (void)CUnitLoadUnits::Create(mDispatchTask, &candidateUnits);
      return;
    }

    if (mHasPathFindingPickupCandidate != 0u) {
      mTaskState = TASKSTATE_Preparing;
      return;
    }

    const EntitySetTemplate<Unit> loadedUnits = mUnit->AiTransport->TransportGetLoadedUnits(false);
    mTaskState = loadedUnits.Empty() ? TASKSTATE_Processing : TASKSTATE_Starting;
  }

  /**
   * Address: 0x005F15D0 (FUN_005F15D0, Moho::CUnitAssistMoveTask::Start)
   *
   * What it does:
   * Chooses unload target cell from carried-unit command context and
   * dispatches one `CUnitUnloadUnits` child task.
   */
  void CUnitAssistMoveTask::Start()
  {
    if (mUnit == nullptr || mUnit->AiTransport == nullptr) {
      mTaskState = TASKSTATE_Complete;
      return;
    }

    CUnitCommand* const ownerCommand = ResolveCurrentCommand(mUnit);
    const EntitySetTemplate<Unit> loadedUnits = mUnit->AiTransport->TransportGetLoadedUnits(true);

    std::int16_t accumulatedX = 0;
    std::int16_t accumulatedZ = 0;
    std::int32_t matchedUnitCount = 0;

    for (Unit* const loadedUnit : loadedUnits) {
      if (!IsUsableUnitSlot(loadedUnit) || loadedUnit->IsDead()) {
        continue;
      }

      CUnitCommand* const loadedCommand = ResolveCurrentCommand(loadedUnit);
      if (loadedCommand == nullptr || loadedCommand != ownerCommand) {
        continue;
      }

      SOCellPos commandPosition{};
      (void)CUnitCommand::GetPosition(loadedCommand, loadedUnit, &commandPosition);
      accumulatedX = static_cast<std::int16_t>(accumulatedX + commandPosition.x);
      accumulatedZ = static_cast<std::int16_t>(accumulatedZ + commandPosition.z);
      ++matchedUnitCount;
    }

    SOCellPos unloadCell{};
    if (matchedUnitCount > 0) {
      unloadCell.x = static_cast<std::int16_t>(static_cast<std::int32_t>(accumulatedX) / matchedUnitCount);
      unloadCell.z = static_cast<std::int16_t>(static_cast<std::int32_t>(accumulatedZ) / matchedUnitCount);
    } else if (ownerCommand != nullptr) {
      (void)CUnitCommand::GetPosition(ownerCommand, mUnit, &unloadCell);
    } else {
      unloadCell.x = static_cast<std::int16_t>(mMoveGoal.minX);
      unloadCell.z = static_cast<std::int16_t>(mMoveGoal.minZ);
    }

    SNavGoal unloadGoal{};
    unloadGoal.minX = static_cast<std::int32_t>(unloadCell.x);
    unloadGoal.minZ = static_cast<std::int32_t>(unloadCell.z);
    unloadGoal.maxX = unloadGoal.minX + 1;
    unloadGoal.maxZ = unloadGoal.minZ + 1;
    unloadGoal.aux0 = 0;
    unloadGoal.aux1 = 0;
    unloadGoal.aux2 = 0;
    unloadGoal.aux3 = 0;
    unloadGoal.aux4 = 0;

    SEntitySetTemplateUnit commandUnits{};
    (void)CUnitUnloadUnits::Create(mDispatchTask, &unloadGoal, &commandUnits, nullptr);

    mTaskState = TASKSTATE_Preparing;
  }

  /**
   * Address: 0x005F1920 (FUN_005F1920, CUnitAssistMoveTask::IssueMoveTaskAndComplete)
   *
   * What it does:
   * Dispatches one move task using this assist task's cached goal and
   * parent dispatch lane, then marks this task complete.
   */
  void CUnitAssistMoveTask::IssueMoveTaskAndComplete()
  {
    NewMoveTask(mMoveGoal, mDispatchTask, 0, nullptr, 0);
    mTaskState = TASKSTATE_Complete;
  }

  /**
   * Address: 0x005F1950 (FUN_005F1950, Moho::CUnitAssistMoveTask::TaskTick)
   *
   * What it does:
   * Advances assist-move task state through wait/start/process transitions.
   */
  int CUnitAssistMoveTask::Execute()
  {
    switch (mTaskState) {
      case TASKSTATE_Preparing:
        mTaskState = TASKSTATE_Waiting;
        return 3;

      case TASKSTATE_Waiting:
        Wait();
        return 1;

      case TASKSTATE_Starting:
        Start();
        return 1;

      case TASKSTATE_Processing:
        IssueMoveTaskAndComplete();
        return 1;

      case TASKSTATE_Complete:
        return -1;

      default:
        return 1;
    }
  }

  /**
   * Address: 0x005F19D0 (FUN_005F19D0, Moho::CUnitAssistMoveTask::operator new)
   *
   * What it does:
   * Allocates one assist-move task and forwards constructor arguments.
   */
  CUnitAssistMoveTask* CUnitAssistMoveTask::Create(CCommandTask* const dispatchTask, const SNavGoal* const moveGoal)
  {
    if (moveGoal == nullptr) {
      return nullptr;
    }

    void* const storage = ::operator new(sizeof(CUnitAssistMoveTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitAssistMoveTask(dispatchTask, *moveGoal);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x005F1F30 (FUN_005F1F30, CUnitAssistMoveTask serializer load callback body)
   *
   * What it does:
   * Deserializes base command-task, dispatch pointer, move-goal payload,
   * goal world-position vector, and pathfinding-candidate flag.
   */
  void CUnitAssistMoveTask::MemberDeserialize(gpg::ReadArchive* const archive, int, const gpg::RRef&)
  {
    if (archive == nullptr || this == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    gpg::RRef dispatchTaskRef{};
    archive->ReadPointer(&mDispatchTask, &dispatchTaskRef);

    archive->Read(CachedSNavGoalType(), &mMoveGoal, ownerRef);
    archive->Read(CachedVector3fType(), &mMoveGoalWorldPosition, ownerRef);
    ReadBoolIntoByteLane(archive, mHasPathFindingPickupCandidate);
  }

  /**
   * Address: 0x005F2010 (FUN_005F2010, CUnitAssistMoveTask serializer save callback body)
   *
   * What it does:
   * Serializes base command-task, dispatch pointer, move-goal payload,
   * goal world-position vector, and pathfinding-candidate flag.
   */
  void CUnitAssistMoveTask::MemberSerialize(gpg::WriteArchive* const archive, int, const gpg::RRef&) const
  {
    if (archive == nullptr || this == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);

    gpg::RRef dispatchTaskRef{};
    (void)gpg::RRef_CCommandTask(&dispatchTaskRef, mDispatchTask);
    gpg::WriteRawPointer(archive, dispatchTaskRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedSNavGoalType(), &mMoveGoal, ownerRef);
    archive->Write(CachedVector3fType(), &mMoveGoalWorldPosition, ownerRef);
    archive->WriteBool(mHasPathFindingPickupCandidate != 0u);
  }

} // namespace moho

namespace moho
{
} // namespace moho

namespace
{
} // namespace

namespace gpg
{
  /**
   * Address: 0x005F1D80 (FUN_005F1D80, gpg::RRef_CUnitAssistMoveTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitAssistMoveTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitAssistMoveTask(gpg::RRef* const outRef, moho::CUnitAssistMoveTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitAssistMoveTaskType());
    return outRef;
  }

  /**
   * Address: 0x005F1D30 (FUN_005F1D30)
   *
   * What it does:
   * Builds one temporary `RRef_CUnitAssistMoveTask` and copies its
   * `(mObj,mType)` pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_CUnitAssistMoveTask(
    gpg::RRef* const outPair,
    moho::CUnitAssistMoveTask* const value
  )
  {
    if (!outPair) {
      return nullptr;
    }

    gpg::RRef typedRef{};
    (void)gpg::RRef_CUnitAssistMoveTask(&typedRef, value);
    *outPair = typedRef;
    return outPair;
  }
} // namespace gpg

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CUnitAssistMoveTask>`, vtable 0x00E1F538.
   *
   * Address: 0x00BCF270 (FUN_00BCF270 -- constructs the global and registers its destructor.)
   * Address: 0x00BF8FF0 (FUN_00BF8FF0 -- the global's destructor.)
   * Address: 0x005F1D20 (FUN_005F1D20 -- an unreferenced copy of `Serialize`.)
   * Address: 0x005F1D70 (FUN_005F1D70 -- an unreferenced copy of `Serialize`.)
   * Address: 0x005F1A70 (FUN_005F1A70 -- `Init`.)
   * Address: 0x005F0B00 (FUN_005F0B00 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x005F0B10 (FUN_005F0B10 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CUnitAssistMoveTaskSerializer : gpg::SerSaveLoadHelper<CUnitAssistMoveTask>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B0984 -- process-global `CUnitAssistMoveTaskSerializer` singleton.
  moho::CUnitAssistMoveTaskSerializer gCUnitAssistMoveTaskSerializer;
} // namespace
