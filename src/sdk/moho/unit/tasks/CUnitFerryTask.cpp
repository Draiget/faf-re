#include "moho/unit/tasks/CUnitFerryTask.h"

#include <cmath>
#include <memory>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/entity/Entity.h"
#include "moho/path/SNavGoal.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitCommandWeakPtrReflection.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitLoadUnits.h"
#include "moho/unit/tasks/CUnitMoveTask.h"
#include "moho/unit/tasks/CUnitUnloadUnits.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskFerryTaskFlags = (1ull << 20) | (1ull << 32);
  constexpr std::uint64_t kUnitStateMaskFerryTaskAssigned = (1ull << 20);
  constexpr const char* kFactoryCategoryName = "FACTORY";
  constexpr const char* kFerryBeaconCategoryName = "FERRYBEACON";
  constexpr const char* kOnFerryPointSetScriptName = "OnFerryPointSet";

  [[nodiscard]] gpg::RType* CachedCUnitFerryTaskType()
  {
    gpg::RType* type = moho::CUnitFerryTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitFerryTask));
      moho::CUnitFerryTask::sType = type;
    }
    return type;
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
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  void MarkOwnerFerryTaskAssigned(moho::Unit* const ownerUnit)
  {
    if (ownerUnit == nullptr) {
      return;
    }

    ownerUnit->UnitStateMask |= kUnitStateMaskFerryTaskAssigned;
  }

  void RunOwnerFerryPointSetScript(moho::Unit* const ownerUnit)
  {
    if (ownerUnit == nullptr) {
      return;
    }

    ownerUnit->RunScript(kOnFerryPointSetScriptName);
  }

  [[nodiscard]] bool IsLiveFactoryWithBuilder(const moho::Unit* const unit)
  {
    return unit != nullptr && unit->IsInCategory(kFactoryCategoryName) && unit->AiBuilder != nullptr && !unit->IsDead();
  }

  void ResolveFactoryTransportOwner(moho::WeakPtr<moho::Unit>& ferryUnitRef)
  {
    while (true) {
      moho::Unit* const ferryUnit = ferryUnitRef.GetObjectPtr();
      if (ferryUnit == nullptr) {
        break;
      }

      if (ferryUnit->IsInCategory(kFactoryCategoryName)) {
        return;
      }

      ferryUnitRef.Set(ferryUnit->GetTransportedBy());
    }
  }

  // Owns the teardown of one local route-command vector. The binary destroys
  // these locals with `WeakPtr_CUnitCommand::destruct_range` (FUN_005A2270)
  // followed by `operator delete`; `msvc8::vector`'s own destructor does not
  // unlink the intrusive weak nodes, so this guard is the one owner of that
  // teardown on every exit path (including exceptions, matching the binary's
  // SEH unwind funclets).
  struct ScopedRouteCommandVector
  {
    msvc8::vector<moho::WeakPtr<moho::CUnitCommand>> commands{};

    ScopedRouteCommandVector() = default;
    ScopedRouteCommandVector(const ScopedRouteCommandVector&) = delete;
    ScopedRouteCommandVector& operator=(const ScopedRouteCommandVector&) = delete;

    ~ScopedRouteCommandVector()
    {
      moho::ResetWeakPtrCUnitCommandVectorStorage(commands);
    }
  };

  /**
   * Address: 0x005FB910 (FUN_005FB910, std::vector_WeakPtr_CUnitCommand::move)
   *
   * What it does:
   * Route-command replacement lane used by `CUnitFerryTask::GetUnitCommands`.
   * The binary's vector-assign body replaces `destination` with a relinked
   * copy of `source` — but only when `source` is non-empty and distinct;
   * an empty (or self) source leaves the destination payload untouched, which
   * is the fallback GetUnitCommands relies on to keep the owner-queue copy.
   */
  void ReplaceWithRouteCommandsIfAny(
    msvc8::vector<moho::WeakPtr<moho::CUnitCommand>>& destination,
    const msvc8::vector<moho::WeakPtr<moho::CUnitCommand>>& source
  )
  {
    if (&destination == &source || source.empty()) {
      return;
    }

    (void)moho::CopyWeakPtrCUnitCommandVector(source, destination);
  }


  /**
   * Fills `outUnits` with the owner army's units matching a named entity
   * category. Sole owner of this file's one interface wart: the legacy
   * `IArmy::GetUnits(void*, void*)` slot is untyped and non-const, so the
   * const view returned by `GetEntityCategory` has to shed const at this
   * boundary. `CArmyImpl::GetUnits` only reads the category filter.
   */
  void CollectArmyUnitsInCategory(
    moho::Unit& ownerUnit,
    const char* const categoryName,
    moho::SEntitySetTemplateUnit& outUnits
  )
  {
    const moho::CategoryWordRangeView* const category =
      ownerUnit.SimulationRef->mRules->GetEntityCategory(categoryName);
    (void)ownerUnit.ArmyRef->GetUnits(&outUnits, const_cast<moho::CategoryWordRangeView*>(category));
  }
}

namespace moho
{
  gpg::RType* CUnitFerryTask::sType = nullptr;

  /**
   * Address: 0x0060DD70 (FUN_0060DD70, Moho::CUnitFerryTask::CUnitFerryTask)
   *
   * What it does:
   * Initializes one ferry task from dispatch-position context, snapshots
   * transport loaded-state into task-state, and binds head-command beacon
   * ownership when present.
   */
  CUnitFerryTask::CUnitFerryTask(IAiCommandDispatchImpl* const dispatch, const Wm3::Vector3f& ferryPosition)
    : CCommandTask(static_cast<CCommandTask*>(dispatch))
    , mDispatch(dispatch)
    , mCommandIndex(0)
    , mFollowsExistingRoute(false)
    , mPos(ferryPosition)
    , mRouteUnit()
    , mFerryUnit()
    , mBeacon()
  {
    MarkOwnerFerryTaskAssigned(mUnit);

    bool hasLoadedUnits = false;
    if (mUnit != nullptr && mUnit->AiTransport != nullptr) {
      const EntitySetTemplate<Unit> loadedUnits = mUnit->AiTransport->TransportGetLoadedUnits(false);
      hasLoadedUnits = !loadedUnits.Empty();
    }
    mTaskState = hasLoadedUnits ? TASKSTATE_Waiting : TASKSTATE_Complete;

    if (mUnit == nullptr || mUnit->CommandQueue == nullptr || mUnit->CommandQueue->mCommandVec.empty()) {
      return;
    }

    CUnitCommand* const headCommand = mUnit->CommandQueue->mCommandVec.front().GetObjectPtr();
    if (headCommand == nullptr) {
      return;
    }

    if (Unit* const existingBeacon = headCommand->mUnit.GetObjectPtr(); existingBeacon != nullptr) {
      // The command already carries a beacon (a second ferry task on the same
      // order), so adopt it rather than spawning a duplicate.
      mBeacon.Set(existingBeacon);
      return;
    }

    const RUnitBlueprint* const ownerBlueprint = mUnit->GetBlueprint();
    if (ownerBlueprint == nullptr || ownerBlueprint->AI.BeaconName.empty()) {
      return;
    }

    RResId beaconResId{};
    (void)gpg::STR_CopyFilename(&beaconResId.name, &ownerBlueprint->AI.BeaconName);

    RUnitBlueprint* const beaconBlueprint = mUnit->SimulationRef->mRules->GetUnitBlueprint(beaconResId);
    if (beaconBlueprint == nullptr) {
      return;
    }

    const Wm3::Vec3f beaconPos = headCommand->mTarget.GetTargetPosGun(false);
    mBeacon.Set(
      CUnitCommand::CreateFerryBeacon(
        beaconBlueprint, *headCommand, mUnit->ArmyRef, beaconPos.x, beaconPos.y, beaconPos.z
      )
    );
    RunOwnerFerryPointSetScript(mUnit);
  }

  /**
   * Address: 0x0060DFC0 (FUN_0060DFC0, Moho::CUnitFerryTask::CUnitFerryTask)
   *
   * What it does:
   * Initializes one ferry-task lane from parent command-task context and one
   * target unit, resolves ferry/beacon ownership, then publishes the ferry
   * script hook and completes immediately.
   */
  CUnitFerryTask::CUnitFerryTask(CCommandTask* const parentTask, Unit* const targetUnit)
    : CCommandTask(parentTask)
    , mDispatch(static_cast<IAiCommandDispatchImpl*>(parentTask))
    , mCommandIndex(0)
    , mFollowsExistingRoute(false)
    , mPos(targetUnit != nullptr ? targetUnit->GetPosition() : Wm3::Vector3f{})
    , mRouteUnit()
    , mFerryUnit()
    , mBeacon()
  {
    mRouteUnit.Set(targetUnit);
    MarkOwnerFerryTaskAssigned(mUnit);

    if (IsLiveFactoryWithBuilder(targetUnit)) {
      mFerryUnit.Set(targetUnit);
    } else if (targetUnit != nullptr && targetUnit->IsUnitState(UNITSTATE_Attached)) {
      mFollowsExistingRoute = true;
      mFerryUnit.Set(targetUnit);
      ResolveFactoryTransportOwner(mFerryUnit);
    } else if (targetUnit != nullptr && targetUnit->IsInCategory(kFerryBeaconCategoryName)) {
      mFollowsExistingRoute = true;
      mBeacon.Set(targetUnit);
      mPos = targetUnit->GetPosition();
    }

    RunOwnerFerryPointSetScript(mUnit);
    mTaskState = TASKSTATE_Complete;
  }

  /**
   * Address: 0x0060E2C0 (FUN_0060E2C0, Moho::CUnitFerryTask::~CUnitFerryTask)
   *
   * What it does:
   * Aborts active unit navigation, clears ferry task owner-state bits, and
   * unlinks all ferry-task weak-unit ownership lanes.
   */
  CUnitFerryTask::~CUnitFerryTask()
  {
    Unit* const ownerUnit = mUnit;
    if (ownerUnit != nullptr) {
      if (IAiNavigator* const navigator = ownerUnit->AiNavigator; navigator != nullptr) {
        navigator->AbortMove();
      }

      ownerUnit->UnitStateMask &= ~kUnitStateMaskFerryTaskFlags;
    }

    mBeacon.UnlinkFromOwnerChain();
    mFerryUnit.UnlinkFromOwnerChain();
    mRouteUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x0060F790 (FUN_0060F790, Moho::CUnitFerryTask::operator new)
   *
   * What it does:
   * Allocates one ferry-task object and forwards dispatch-position context
   * into in-place construction.
   */
  CUnitFerryTask* CUnitFerryTask::CreateFromDispatch(
    IAiCommandDispatchImpl* const dispatch,
    const Wm3::Vector3f& ferryPosition
  )
  {
    auto* const raw = static_cast<CUnitFerryTask*>(::operator new(sizeof(CUnitFerryTask)));
    auto guard = std::unique_ptr<CUnitFerryTask, void (*)(CUnitFerryTask*)>(raw, [](CUnitFerryTask* p) {
      ::operator delete(p);
    });
    return std::construct_at(guard.release(), dispatch, ferryPosition);
  }

  /**
   * Address: 0x0060F7E0 (FUN_0060F7E0, Moho::CUnitFerryTask::operator new)
   *
   * What it does:
   * Allocates one ferry-task object and forwards constructor arguments into
   * in-place construction.
   */
  CUnitFerryTask* CUnitFerryTask::Create(
    CCommandTask* parentTask,
    Unit* targetUnit
  )
  {
    auto* raw = static_cast<CUnitFerryTask*>(::operator new(sizeof(CUnitFerryTask)));
    auto guard = std::unique_ptr<CUnitFerryTask, void (*)(CUnitFerryTask*)>(raw, [](CUnitFerryTask* p) {
      ::operator delete(p);
    });
    return std::construct_at(guard.release(), parentTask, targetUnit);
  }

  /**
   * Address: 0x0060E3A0 (FUN_0060E3A0, Moho::CUnitFerryTask::FilterTransportableUnits)
   *
   * IDA signature:
   * Moho::EntitySetTemplate_Entity *__stdcall
   * Moho::CUnitFerryTask::FilterTransportableUnits(
   *   Moho::CUnitFerryTask *a1, Moho::EntitySetTemplate_Entity *set);
   *
   * What it does:
   * Scans the owner army's LAND units and adds every candidate this ferry can
   * pick up right now.
   *
   * Asm-verified field/dispatch evidence:
   * - `[this+1Ch]` owner unit; `[unit+150h]`/`[unit+154h]` = Entity
   *   SimulationRef/ArmyRef; rules at `[sim+8C8h]`; `GetEntityCategory` =
   *   rules vtbl `+0x58`; `GetUnits` = army vtbl `+0x9C` (0x0060E3EF-0x0060E429).
   * - Candidate gates: IsDead (+0x28), DestroyQueued (+0x2C), IsBeingBuilt
   *   (+0x34), IsUnitState (+0x3C) with 0x15 (UNITSTATE_WaitForFerry), 7
   *   (UNITSTATE_WaitingForTransport), 0x0E (UNITSTATE_Attached); assigned
   *   transport slot raw test `[unit+4C8h]` (0x0060E4A1).
   * - Owner transport gates through `[unit+55Ch]` (Unit::AiTransport):
   *   TransportCanCarryUnit slot +0x24, TransportHasSpaceFor slot +0x28 fed
   *   from candidate GetBlueprint (+0x1C) (0x0060E58A-0x0060E5BC).
   * - Focus resolution: `Unit::GetFocusEntity` + Entity vtbl slot 4 `IsUnit`
   *   (`[vtbl+10h]`, 0x0060E5DE).
   * - Route-transport suppression via `mRouteUnit` (`[this+48h]`): its
   *   AiTransport (`+55Ch`) TransportHasSpaceFor (slot +0x28) and the route
   *   unit's own IsUnitState(+0x3C) with 2 = UNITSTATE_Moving
   *   (0x0060E724-0x0060E75D).
   */
  void CUnitFerryTask::FilterTransportableUnits(SEntitySetTemplateUnit& outUnits)
  {
    Unit* const ownerUnit = mUnit;

    SEntitySetTemplateUnit landUnits{};
    CollectArmyUnitsInCategory(*ownerUnit, "LAND", landUnits);

    for (Entity* const entry : landUnits.mVec) {
      Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(entry);
      if (candidate == nullptr) {
        continue;
      }

      if (candidate->IsDead() || candidate->DestroyQueued() || candidate->IsBeingBuilt()) {
        continue;
      }

      if (!candidate->IsUnitState(UNITSTATE_WaitForFerry)) {
        continue;
      }

      // Candidates that already have an assigned transport are spoken for.
      if (candidate->GetFerryUnit() != nullptr) {
        continue;
      }

      if (candidate->IsUnitState(UNITSTATE_WaitingForTransport) || candidate->IsUnitState(UNITSTATE_Attached)) {
        continue;
      }

      // Commander riders are excluded unless this ferry is rated for them.
      bool candidateExcluded = false;
      if (!ownerUnit->IsInCategory("CANTRANSPORTCOMMANDER")) {
        candidateExcluded = candidate->IsInCategory("COMMAND");
      }
      if (candidateExcluded) {
        continue;
      }

      if (!ownerUnit->AiTransport->TransportCanCarryUnit(candidate)) {
        continue;
      }

      if (!ownerUnit->AiTransport->TransportHasSpaceFor(candidate->GetBlueprint())
          || candidate->GetFocusEntity() == nullptr) {
        continue;
      }

      Unit* const focusUnit = candidate->GetFocusEntity()->IsUnit();
      if (focusUnit == nullptr) {
        continue;
      }

      if (focusUnit->IsInCategory("FERRYBEACON") && mBeacon.HasValue()) {
        // Beacon-bound route: the candidate must be waiting at our beacon.
        if (focusUnit != mBeacon.GetObjectPtr()) {
          continue;
        }
      } else {
        // Factory-rally route: only valid while no beacon is bound and the
        // candidate is focused on our ferry factory.
        if (!(focusUnit->IsInCategory("FACTORY") && !mBeacon.HasValue())) {
          continue;
        }

        if (mFerryUnit.GetObjectPtr() != focusUnit) {
          continue;
        }

        if (mFollowsExistingRoute) {
          if (Unit* const routeUnit = mRouteUnit.GetObjectPtr(); routeUnit != nullptr) {
            // While the route transport still has room for this candidate and
            // is not underway, leave the candidate for that transport.
            if (routeUnit->AiTransport->TransportHasSpaceFor(candidate->GetBlueprint())
                && !routeUnit->IsUnitState(UNITSTATE_Moving)) {
              continue;
            }
          }
        }
      }

      (void)outUnits.AddUnit(candidate);
    }
  }

  /**
   * Address: 0x0060E7E0 (FUN_0060E7E0, Moho::CUnitFerryTask::HasNewUnit)
   *
   * IDA signature:
   * bool __stdcall Moho::CUnitFerryTask::HasNewUnit(Moho::CUnitFerryTask *arg0);
   *
   * What it does:
   * Reports whether a transportable unit is about to head for this ferry.
   *
   * Asm-verified evidence:
   * - Ferry factory head command: `[this+50h]` decoded, CommandQueue at
   *   `[unit+4B4h]`, vector lanes `+0x10/+0x14` (mCommandVec at queue+0x0C),
   *   head command type `[cmd+98h] == 7` (UNITCOMMAND_BuildFactory), build
   *   blueprint `[cmd+60h]` (mConstDat.blueprint) (0x0060E800-0x0060E83B).
   * - Blueprint check: RRef_REntityBlueprint + RRef UpCast to RUnitBlueprint
   *   (FUN_00527AD0) feeding owner AiTransport (`[unit+55Ch]`)
   *   TransportHasSpaceFor slot +0x28 (0x0060E844-0x0060E877).
   * - Army scan: LAND category units; candidate gates IsDead/DestroyQueued/
   *   IsBeingBuilt/IsUnitState(0x0E Attached); creator slot `[unit+4B8h]`
   *   compared against `mFerryUnit` (0x0060E91B-0x0060E93A); owner
   *   TransportHasSpaceFor for candidate blueprint; candidate queue
   *   GetNextCommand type `[cmd+98h] == 0x16` (UNITCOMMAND_TransportLoadUnits)
   *   (0x0060E95E-0x0060E96D).
   *
   * Caller contract (mirrored from the binary, which dereferences without a
   * guard): `mFerryUnit` resolves to a live unit — `HasNextUnitToLoad` checks
   * `HasValue()` immediately before calling.
   */
  bool CUnitFerryTask::HasNewUnit()
  {
    Unit* const ferryUnit = mFerryUnit.GetObjectPtr();
    CUnitCommandQueue* const ferryQueue = ferryUnit->CommandQueue;

    if (!ferryQueue->mCommandVec.empty()) {
      CUnitCommand* const headCommand = ferryQueue->mCommandVec.front().GetObjectPtr();
      if (headCommand != nullptr && headCommand->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_BuildFactory) {
        // Binary does an RTTI-checked upcast (gpg::RRef_REntityBlueprint at
        // 0x0060E844 + gpg::RRef::UpCast_RUnitBlueprint, FUN_00527AD0, via
        // RUnitBlueprint::sType2). Factory build commands always carry unit
        // blueprints (RUnitBlueprint derives from REntityBlueprint), so the
        // checked cast resolves to a static upcast for all reachable inputs —
        // same treatment as IAiCommandDispatchImpl::DispatchQueuedCommand.
        const auto* const buildBlueprint =
          static_cast<const RUnitBlueprint*>(headCommand->mConstDat.blueprint);

        if (mUnit->AiTransport->TransportHasSpaceFor(buildBlueprint)) {
          return true;
        }
      }
    }

    SEntitySetTemplateUnit landUnits{};
    CollectArmyUnitsInCategory(*mUnit, "LAND", landUnits);

    for (Entity* const entry : landUnits.mVec) {
      Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(entry);
      if (candidate == nullptr) {
        continue;
      }

      if (candidate->IsDead() || candidate->DestroyQueued() || candidate->IsBeingBuilt()
          || candidate->IsUnitState(UNITSTATE_Attached)) {
        continue;
      }

      if (candidate->GetCreator() != mFerryUnit.GetObjectPtr()) {
        continue;
      }

      if (!mUnit->AiTransport->TransportHasSpaceFor(candidate->GetBlueprint())) {
        continue;
      }

      CUnitCommand* const nextCommand = candidate->CommandQueue->GetNextCommand();
      if (nextCommand != nullptr && nextCommand->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_TransportLoadUnits) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x0060E9F0 (FUN_0060E9F0, Moho::CUnitFerryTask::HasNextUnitToLoad)
   *
   * IDA signature:
   * bool __thiscall Moho::CUnitFerryTask::HasNextUnitToLoad(Moho::CUnitFerryTask *this);
   *
   * What it does:
   * Spawns a `CUnitLoadUnits` child task when transportables are waiting;
   * otherwise decides from loaded cargo whether the route continues.
   *
   * Asm-verified evidence:
   * - `CUnitLoadUnits::operator new(mDispatch@[this+30h], &set)` when the
   *   filtered set is non-empty (0x0060EA29).
   * - `mFerryUnit` HasValue gate (`[this+50h]`, null/sentinel-4 tests) before
   *   `HasNewUnit` (0x0060EA75-0x0060EA82).
   * - Loaded cargo via owner AiTransport (`[unit+55Ch]`)
   *   `TransportGetLoadedUnits(false)` (0x0060EA8F).
   * - Rewind lanes: ferry bound -> `mCommandIndex = 0`; unbound ->
   *   `mCommandIndex = 1`; both set `mTaskState = TASKSTATE_Waiting`
   *   (0x0060EAEC-0x0060EB15, `[this+34h]` / `[this+24h]`).
   */
  bool CUnitFerryTask::HasNextUnitToLoad()
  {
    SEntitySetTemplateUnit transportables{};
    FilterTransportableUnits(transportables);

    if (!transportables.Empty()) {
      (void)CUnitLoadUnits::Create(mDispatch, &transportables);
      return true;
    }

    if (mFerryUnit.HasValue() && HasNewUnit()) {
      return false;
    }

    const EntitySetTemplate<Unit> loadedUnits = mUnit->AiTransport->TransportGetLoadedUnits(false);
    if (loadedUnits.Empty()) {
      return false;
    }

    mCommandIndex = mFerryUnit.HasValue() ? 0 : 1;
    mTaskState = TASKSTATE_Waiting;
    return true;
  }

  /**
   * Address: 0x0060EB50 (FUN_0060EB50, Moho::CUnitFerryTask::GetUnitCommands)
   *
   * IDA signature:
   * void __stdcall sub_60EB50(Moho::CUnitFerryTask *a1, std::vector_WeakPtr_CUnitCommand *a2);
   *
   * What it does:
   * Materializes the command list describing this ferry's route.
   *
   * Asm-verified evidence:
   * - Own-queue copy: `vector_WeakPtr_CUnitCommand::cpy` (FUN_005DB610) from
   *   `mUnit->CommandQueue->mCommandVec` (queue+0x0C) into the out vector
   *   (0x0060EB79-0x0060EB8B).
   * - Ferry branch (`[this+50h]` HasValue): builder read as
   *   `[slotRaw+550h]` = decoded unit `+0x554` (Unit::AiBuilder), queue via
   *   vtbl slot +0x20 (IAiBuilder::BuilderGetFactoryCommandQueue), then the
   *   vector-assign lane FUN_005FB910 (0x0060EBAB-0x0060EBD6). The binary
   *   dereferences the builder without a null guard — mirrored here.
   * - Route-unit branch: `mFollowsExistingRoute` byte `[this+38h]`
   *   (0x0060EBDB); beacon `[this+58h]` empty/sentinel or decoded
   *   `mRouteUnit` (`[this+48h]`) != decoded beacon -> assign from
   *   `routeUnit->CommandQueue->mCommandVec` (queue+0x0C, unguarded decode at
   *   0x0060ED31-0x0060ED4B).
   * - Beacon branch: TRANSPORTATION army scan; candidate gates
   *   IsDead/DestroyQueued/IsBeingBuilt + IsUnitState(0x14 UNITSTATE_Ferrying)
   *   (0x0060ECA1); `GetCurrentCommand` + `CUnitCommand::GetFerryBeacon`
   *   (FUN_0060DAE0) compared against decoded beacon (0x0060ECB1-0x0060ECCD);
   *   on match, assign from that transport's queue (0x0060ECFC-0x0060ED0A).
   */
  void CUnitFerryTask::GetUnitCommands(msvc8::vector<WeakPtr<CUnitCommand>>& outCommands)
  {
    (void)CopyWeakPtrCUnitCommandVector(mUnit->CommandQueue->mCommandVec, outCommands);

    if (mFerryUnit.HasValue()) {
      // The binary reads the builder queue without a null guard right after
      // the HasValue test; ferry units always carry a builder here.
      Unit* const ferryUnit = mFerryUnit.GetObjectPtr();
      ReplaceWithRouteCommandsIfAny(outCommands, ferryUnit->AiBuilder->BuilderGetFactoryCommandQueue());
      return;
    }

    if (!mFollowsExistingRoute) {
      return;
    }

    Unit* const routeUnit = mRouteUnit.GetObjectPtr();
    if (!mBeacon.HasValue() || routeUnit != mBeacon.GetObjectPtr()) {
      // Route defined by the clicked unit's own queue (unguarded queue decode
      // in the binary — the route unit was bound at construction).
      ReplaceWithRouteCommandsIfAny(outCommands, routeUnit->CommandQueue->mCommandVec);
      return;
    }

    // The route source IS the beacon: adopt the queue of whichever army
    // transport is currently ferrying to that beacon.
    SEntitySetTemplateUnit transports{};
    CollectArmyUnitsInCategory(*mUnit, "TRANSPORTATION", transports);

    for (Entity* const entry : transports.mVec) {
      Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(entry);
      if (candidate == nullptr) {
        continue;
      }

      if (candidate->IsDead() || candidate->DestroyQueued() || candidate->IsBeingBuilt()) {
        continue;
      }

      if (!candidate->IsUnitState(UNITSTATE_Ferrying)) {
        continue;
      }

      CUnitCommand* const currentCommand = candidate->CommandQueue->GetCurrentCommand();
      if (currentCommand == nullptr) {
        continue;
      }

      if (currentCommand->GetFerryBeacon() != mBeacon.GetObjectPtr()) {
        continue;
      }

      ReplaceWithRouteCommandsIfAny(outCommands, candidate->CommandQueue->mCommandVec);
      break;
    }
  }

  /**
   * Address: 0x0060ED70 (FUN_0060ED70, sub_60ED70)
   *
   * IDA signature:
   * void __stdcall sub_60ED70(Moho::CUnitFerryTask *arg0);
   *
   * What it does:
   * Waiting-phase worker: advances the ferry along its route.
   *
   * Asm-verified evidence:
   * - `mCommandIndex` (`[this+34h]`, 0x0060EDB6) against `count - 1`.
   * - Dropoff-type gate `[cmd+98h]` against 2 (UNITCOMMAND_Move, ferry bound)
   *   at 0x0060EE04 and 0x11 (UNITCOMMAND_Ferry, no ferry) at 0x0060EE1A,
   *   with `mFerryUnit` (`[this+50h]`) HasValue tested per disjunct
   *   (0x0060EDF6/0x0060EE0C).
   * - Pickup target `[cmd+11Ch]` (mTarget) -> GetTargetPosGun(false)
   *   (0x0060EE23); SFootprint::ToCellPos + SNavGoal(SOCellPos) ctor;
   *   `NewMoveTask(goal, mDispatch@[this+30h], 0, pickupCmd, 0)`;
   *   `++mCommandIndex` (0x0060EE6B).
   * - Null command link rewinds `mCommandIndex = 0` (0x0060EE90); all
   *   non-advancing paths set `mTaskState = TASKSTATE_Starting`
   *   (`[this+24h]`, 0x0060EE95).
   */
  void CUnitFerryTask::MoveToNextRoutePoint()
  {
    ScopedRouteCommandVector routeCommands{};
    GetUnitCommands(routeCommands.commands);

    const auto commandCount = static_cast<std::int32_t>(routeCommands.commands.size());
    const std::int32_t index = mCommandIndex;

    if (index < commandCount - 1) {
      CUnitCommand* const pickupCommand =
        routeCommands.commands[static_cast<std::size_t>(index)].GetObjectPtr();
      CUnitCommand* const dropoffCommand =
        routeCommands.commands[static_cast<std::size_t>(index) + 1u].GetObjectPtr();

      if (pickupCommand != nullptr && dropoffCommand != nullptr) {
        // With a ferry unit bound the dropoff leg is a plain move; a
        // beacon-only route encodes it as a ferry command.
        if ((mFerryUnit.HasValue() && dropoffCommand->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_Move)
            || (!mFerryUnit.HasValue() && dropoffCommand->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_Ferry)) {
          const Wm3::Vec3f pickupPos = pickupCommand->mTarget.GetTargetPosGun(false);
          const SNavGoal goal(mUnit->GetFootprint().ToCellPos(pickupPos));
          NewMoveTask(goal, mDispatch, 0, pickupCommand, 0);
          ++mCommandIndex;
          return;
        }
      } else {
        mCommandIndex = 0;
      }
    }

    mTaskState = TASKSTATE_Starting;
  }

  /**
   * Address: 0x0060EED0 (FUN_0060EED0, sub_60EED0)
   *
   * IDA signature:
   * void __usercall sub_60EED0(int a1@<esi>);
   *
   * What it does:
   * Starting-phase worker: unloads cargo at the current route point.
   *
   * Asm-verified evidence:
   * - Index clamp on `[this+34h]` (mCommandIndex, 0x0060EF14/0x0060EF27):
   *   min against `count - 1`, then floor at 0 — stored back before use.
   * - Command target `mTarget` at command+0x11C (`p_value + 284` in the
   *   decompile) -> GetTargetPosGun(false).
   * - Unload goal: one cell at target minus half footprint (owner Entity at
   *   `[this+1Ch] + 8`, 0x0060EF51) — the inlined
   *   SFootprint::ToCellPos + SNavGoal(SOCellPos) pair.
   * - `CUnitUnloadUnits::operator new(mDispatch@[this+30h], &goal,
   *   &emptyUnitSet, command)` (0x0060F031); empty set built on the stack.
   * - Null command link rewinds `mCommandIndex = 0` (0x0060F06C); always ends
   *   in `mTaskState = TASKSTATE_Processing` (`[this+24h] = 3`, 0x0060F071).
   */
  void CUnitFerryTask::IssueUnloadAtRoutePoint()
  {
    ScopedRouteCommandVector routeCommands{};
    GetUnitCommands(routeCommands.commands);

    const auto commandCount = static_cast<std::int32_t>(routeCommands.commands.size());

    std::int32_t index = mCommandIndex;
    const std::int32_t lastIndex = commandCount - 1;
    if (index >= lastIndex) {
      index = lastIndex;
    }
    if (index <= 0) {
      index = 0;
    }
    mCommandIndex = index;

    CUnitCommand* const routeCommand =
      routeCommands.commands[static_cast<std::size_t>(index)].GetObjectPtr();
    if (routeCommand == nullptr) {
      mCommandIndex = 0;
    } else {
      const Wm3::Vec3f targetPos = routeCommand->mTarget.GetTargetPosGun(false);
      const SNavGoal unloadGoal(mUnit->GetFootprint().ToCellPos(targetPos));

      SCommandUnitSet commandUnits{};
      (void)CUnitUnloadUnits::Create(mDispatch, &unloadGoal, &commandUnits, routeCommand);
    }

    mTaskState = TASKSTATE_Processing;
  }

  /**
   * Address: 0x0060F0B0 (FUN_0060F0B0, sub_60F0B0)
   *
   * IDA signature:
   * void __stdcall sub_60F0B0(Moho::CUnitFerryTask *arg0);
   *
   * What it does:
   * Processing-phase worker: heads back to the previous route point.
   *
   * Asm-verified evidence:
   * - Entry gate `mCommandIndex > 0` then pre-decrement (`[this+34h]`,
   *   0x0060F0CE-0x0060F0E0).
   * - Same clamp lanes as the unload worker (0x0060F107-0x0060F11A).
   * - Target from `mTarget` -> GetTargetPosGun(false); inlined
   *   ToCellPos + SNavGoal cell rect; `NewMoveTask(goal, mDispatch, 0,
   *   routeCommand, 0)` (0x0060F1BF) and an early return that leaves
   *   `mTaskState` untouched.
   * - Dead command link rewinds `mCommandIndex = 0` (0x0060F21B); the
   *   no-previous-point path sets `mTaskState = TASKSTATE_Complete`
   *   (`[this+24h] = 4`, 0x0060F229).
   */
  void CUnitFerryTask::MoveToPreviousRoutePoint()
  {
    if (mCommandIndex > 0) {
      --mCommandIndex;

      ScopedRouteCommandVector routeCommands{};
      GetUnitCommands(routeCommands.commands);

      const auto commandCount = static_cast<std::int32_t>(routeCommands.commands.size());

      std::int32_t index = mCommandIndex;
      const std::int32_t lastIndex = commandCount - 1;
      if (index >= lastIndex) {
        index = lastIndex;
      }
      if (index <= 0) {
        index = 0;
      }
      mCommandIndex = index;

      CUnitCommand* const routeCommand =
        routeCommands.commands[static_cast<std::size_t>(index)].GetObjectPtr();
      if (routeCommand != nullptr) {
        const Wm3::Vec3f targetPos = routeCommand->mTarget.GetTargetPosGun(false);
        const SNavGoal goal(mUnit->GetFootprint().ToCellPos(targetPos));
        NewMoveTask(goal, mDispatch, 0, routeCommand, 0);
        return;
      }

      mCommandIndex = 0;
    }

    mTaskState = TASKSTATE_Complete;
  }

  /**
   * Address: 0x0060F240 (FUN_0060F240, sub_60F240)
   *
   * IDA signature:
   * Moho::TDatListItem_EntitySetTemplate_Entity *__usercall sub_60F240@<eax>(int ebx0@<ebx>);
   *
   * What it does:
   * Complete-phase worker: either the round trip is done (grounded close to
   * the route anchor) or the ferry flies back to `mPos` to restart the cycle.
   *
   * Asm-verified evidence:
   * - 2D distance from owner GetPosition (unit vtbl +0x14, 0x0060F25D) to
   *   `mPos` (`[this+3Ch]`/`[this+44h]`, 0x0060F26A/0x0060F273).
   * - Grounded gate `[unit+120h] == 1` (Entity::mCurrentLayer == LAYER_Land,
   *   0x0060F29C-0x0060F2A5; contrast TaskTick's `== 0x10` LAYER_Air check at
   *   0x0060F688).
   * - Arrival radius: owner GetBlueprint (vtbl +0x1C, 0x0060F2AC) float at
   *   blueprint+0x380 = RUnitBlueprint::Air (+0x368) + 0x18 =
   *   `RUnitBlueprintAir::StartTurnDistance` (`comiss xmm0, [eax+380h]`,
   *   0x0060F2B7).
   * - Return goal: inlined ToCellPos + SNavGoal cell rect around `mPos`;
   *   `goal.mLayer` (offset +0x20) forced to 1 only when the filtered
   *   transportable set is empty (0x0060F376-0x0060F380);
   *   `NewMoveTask(goal, mDispatch@[this+30h], 0, nullptr, 1)` (0x0060F393).
   * - Both paths finish in `mTaskState = TASKSTATE_Preparing`
   *   (`[this+24h] = 0`, 0x0060F3C3/0x0060F3DE).
   */
  void CUnitFerryTask::ResumeFerryRoute()
  {
    const Wm3::Vec3f& ownerPos = mUnit->GetPosition();
    const float deltaZ = ownerPos.z - mPos.z;
    const float deltaX = ownerPos.x - mPos.x;
    const float distance = std::sqrt((deltaZ * deltaZ) + (deltaX * deltaX));

    if (mUnit->mCurrentLayer == LAYER_Land
        && distance <= mUnit->GetBlueprint()->Air.StartTurnDistance) {
      mTaskState = TASKSTATE_Preparing;
      return;
    }

    SNavGoal goal(mUnit->GetFootprint().ToCellPos(mPos));

    SEntitySetTemplateUnit transportables{};
    FilterTransportableUnits(transportables);

    // Binary stores the set-empty flag straight into the goal's layer lane
    // (1 == LAYER_Land when nothing is waiting, 0 == LAYER_None otherwise).
    goal.mLayer = transportables.Empty() ? LAYER_Land : LAYER_None;

    NewMoveTask(goal, mDispatch, 0, nullptr, 1);

    mTaskState = TASKSTATE_Preparing;
  }

  /**
   * Address: 0x0060F400 (FUN_0060F400, Moho::CUnitFerryTask::TaskTick)
   * VFTable SLOT: 1 (CTask::Execute), ??_7CUnitFerryTask@Moho@@6B@ + 0x04
   *
   * IDA signature:
   * int __thiscall Moho::CUnitFerryTask::TaskTick(Moho::CUnitFerryTask *this);
   *
   * What it does:
   * Per-tick ferry state machine (see header). Return values: -1 abort,
   * 1 keep ticking, 10 idle delay from the Preparing phase.
   *
   * Asm-verified evidence:
   * - Guards: `mFollowsExistingRoute` byte `[this+38h]` (0x0060F40F) with
   *   beacon `[this+58h]` empty -> route unit `[this+48h]` must resolve, be
   *   alive (IsDead vtbl +0x28) and be IsUnitState(0x14 UNITSTATE_Ferrying)
   *   (vtbl +0x3C, 0x0060F456-0x0060F45B); otherwise ferry `[this+50h]` or
   *   beacon must resolve alive (0x0060F46C-0x0060F4C9).
   * - Beacon warp: current command's `mTarget` (cmd+0x11C) GetTargetPosGun
   *   vs beacon GetPosition 2D distance > 1.0 (fcomip at 0x0060F55A) ->
   *   VTransform{(0,0,0), quat(1,0,0,0)} (0x0060F5A5), pos.x/pos.z from a
   *   second GetTargetPosGun pass, pos.y from `STIMap::GetSurface`
   *   (map at `[sim+8CCh]`, 0x0060F5E1) of a third pass, then Entity Warp
   *   (Entity subobject at unit+8, vtbl slot +0x44, 0x0060F614-0x0060F620).
   * - `mPos` snapshot from beacon GetPosition (0x0060F637-0x0060F645).
   * - Switch on `mTaskState` (`[this+24h]`, jumptable 0x0060F659). Every case
   *   RMWs the owner 64-bit state mask at `[unit+4A0h]`, toggling bit 32
   *   (`[unit+4A4h]` bit 0) = UNITSTATE_ForceSpeedThrough: cleared for
   *   Preparing/Starting/Complete, set for Waiting/Processing
   *   (0x0060F663-0x0060F75B).
   * - Preparing: HasNextUnitToLoad -> 1; else when `[unit+120h] == 0x10`
   *   (LAYER_Air) issue `NewMoveTask(SNavGoal(ToCellPos(mPos)), mDispatch,
   *   0, nullptr, 1)` with `goal.mLayer = 1` (LAYER_Land, stack slot +0x20 at
   *   0x0060F6B7) and return 10 (0x0060F6CB).
   */
  int CUnitFerryTask::Execute()
  {
    if (mFollowsExistingRoute && !mBeacon.HasValue()) {
      // Following another unit's route with no beacon bound: the route unit
      // must still be alive and actively ferrying.
      if (!mRouteUnit.HasValue()) {
        return -1;
      }
      Unit* const routeUnit = mRouteUnit.GetObjectPtr();
      if (routeUnit->IsDead()) {
        return -1;
      }
      if (!routeUnit->IsUnitState(UNITSTATE_Ferrying)) {
        return -1;
      }
    } else if (!mFerryUnit.HasValue()) {
      if (!mBeacon.HasValue()) {
        return -1;
      }
      if (mBeacon.GetObjectPtr()->IsDead()) {
        return -1;
      }
    } else {
      if (mFerryUnit.GetObjectPtr()->IsDead()) {
        return -1;
      }
    }

    if (mBeacon.HasValue()) {
      if (CUnitCommand* const currentCommand = mUnit->CommandQueue->GetCurrentCommand();
          currentCommand != nullptr) {
        Unit* const beaconUnit = mBeacon.GetObjectPtr();
        CAiTarget& commandTarget = currentCommand->mTarget;

        const Wm3::Vec3f targetPos = commandTarget.GetTargetPosGun(false);
        const Wm3::Vec3f& beaconPos = beaconUnit->GetPosition();
        const float deltaZ = targetPos.z - beaconPos.z;
        const float deltaX = targetPos.x - beaconPos.x;

        if (std::sqrt((deltaZ * deltaZ) + (deltaX * deltaX)) > 1.0f) {
          // The beacon drifted off the command target: warp it back onto the
          // target position, snapped to the terrain surface.
          VTransform warpTransform(Wm3::Vector3f(0.0f, 0.0f, 0.0f), Wm3::Quaternionf(1.0f, 0.0f, 0.0f, 0.0f));

          const Wm3::Vec3f warpPos = commandTarget.GetTargetPosGun(false);
          warpTransform.pos_.x = warpPos.x;
          warpTransform.pos_.z = warpPos.z;

          const Wm3::Vec3f surfaceProbePos = commandTarget.GetTargetPosGun(false);
          warpTransform.pos_.y = mUnit->SimulationRef->mMapData->GetSurface(surfaceProbePos);

          beaconUnit->Warp(warpTransform);
        }

        mPos = beaconUnit->GetPosition();
      }
    }

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        mUnit->UnitStateMask &= ~(1ull << UNITSTATE_ForceSpeedThrough);

        if (HasNextUnitToLoad()) {
          return 1;
        }

        if (mUnit->mCurrentLayer == LAYER_Air) {
          SNavGoal goal(mUnit->GetFootprint().ToCellPos(mPos));
          goal.mLayer = LAYER_Land;
          NewMoveTask(goal, mDispatch, 0, nullptr, 1);
        }

        return 10;
      }

      case TASKSTATE_Waiting: {
        mUnit->UnitStateMask |= (1ull << UNITSTATE_ForceSpeedThrough);
        MoveToNextRoutePoint();
        return 1;
      }

      case TASKSTATE_Starting: {
        mUnit->UnitStateMask &= ~(1ull << UNITSTATE_ForceSpeedThrough);
        IssueUnloadAtRoutePoint();
        return 1;
      }

      case TASKSTATE_Processing: {
        mUnit->UnitStateMask |= (1ull << UNITSTATE_ForceSpeedThrough);
        MoveToPreviousRoutePoint();
        return 1;
      }

      case TASKSTATE_Complete: {
        mUnit->UnitStateMask &= ~(1ull << UNITSTATE_ForceSpeedThrough);
        ResumeFerryRoute();
        return 1;
      }

      default:
        return 1;
    }
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00610650 (FUN_00610650, gpg::RRef_CUnitFerryTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitFerryTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitFerryTask(gpg::RRef* const outRef, moho::CUnitFerryTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitFerryTaskType());
    return outRef;
  }

  /**
   * Address: 0x006105B0 (FUN_006105B0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitFerryTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitFerryTaskRef(gpg::RRef* const outRef, moho::CUnitFerryTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitFerryTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg
