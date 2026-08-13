#include "moho/unit/tasks/CUnitPatrolTask.h"
#include "moho/unit/tasks/CUnitPatrolTaskTypeInfo.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <typeinfo>

#include "Wm3Box3.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/CAiTransportImpl.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/EntityDb.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/task/CCommandTask.h"
#include "moho/task/ETaskStatus.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CUnitAttackTargetTask.h"
#include "moho/unit/tasks/CUnitRepairTask.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitPatrolTaskType()
  {
    gpg::RType* type = moho::CUnitPatrolTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitPatrolTask));
      moho::CUnitPatrolTask::sType = type;
    }
    return type;
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

  [[nodiscard]] gpg::RType* CachedBox3fType()
  {
    // Box3f has no class-static `sType`; mirror the binary's dedicated
    // `Wm3__Box3f__RType` global with a file-static lazily-resolved cache.
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Box3<float>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEntitySetTemplateEntityType()
  {
    gpg::RType* type = moho::EntitySetTemplate<moho::Entity>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntitySetTemplate<moho::Entity>));
      moho::EntitySetTemplate<moho::Entity>::sType = type;
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

  /**
   * Shared 90-degree yaw quaternion used by the patrol search-box builder.
   *
   * The binary reads this rotation from the `flt_10B1A44` global (populated once
   * at static-init by FUN_00BD11C0 as `{w=cos(45deg), x=sin(45deg)*0,
   * y=sin(45deg), z=0}` -> a pure +Y rotation of 90 degrees). Modeled here as the
   * equivalent named constant so the recovered behavior uses a typed quaternion
   * instead of a raw data-address dereference.
   */
  const Wm3::Quaternionf kSearchBoxYawQuat{0.70710677f, 0.0f, 0.70710677f, 0.0f};

  /**
   * Length threshold (`dword_DFF0AC` = 0.001f) below which the patrol leg
   * direction is treated as degenerate and replaced with the `+Z` fallback.
   */
  constexpr float kPatrolLegMinLength = 0.001f;

  /**
   * Returns the formation-status broadcaster ring head embedded in an
   * `IFormationInstance`. Mirrors `NavigatorListenerHead` in CUnitMoveTask: the
   * instance stores its self-linked `Broadcaster` node immediately after the
   * interface vtable pointer (binary `formationInstance + 0x04`; the interface's
   * own ctor FUN_00569450 self-links it). The recovered header models
   * `IFormationInstance` as vtable-only, so the typed ring head is recovered
   * through this narrow accessor rather than an inline offset in the ctor body.
   */
  [[nodiscard]] moho::Broadcaster* FormationStatusBroadcasterHead(
    moho::IFormationInstance* const formationInstance
  ) noexcept
  {
    if (formationInstance == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<moho::Broadcaster*>(reinterpret_cast<char*>(formationInstance) + sizeof(void*));
  }

  /**
   * Resolves the queue-head (`front == true`) or queue-tail command from the
   * owner unit's command queue, returning null when the queue is empty or the
   * weak slot is expired. Mirrors the binary's `_Myfirst`/`_Mylast` guard plus
   * weak-owner decode (the `count>>3` empty-check and the `-4` owner adjustment
   * that `WeakPtr::GetObjectPtr` performs).
   */
  [[nodiscard]] moho::CUnitCommand* ResolvePatrolQueueCommand(
    moho::CUnitCommandQueue* const commandQueue,
    const bool front
  ) noexcept
  {
    if (commandQueue == nullptr || commandQueue->mCommandVec.empty()) {
      return nullptr;
    }

    const moho::WeakPtr<moho::CUnitCommand>& slot =
      front ? commandQueue->mCommandVec.front() : commandQueue->mCommandVec.back();
    return slot.GetObjectPtr();
  }
} // namespace

namespace moho
{
  // Forward declaration mirroring the file-local decl in QuaternionMath.cpp
  // (0x0062FA80, Moho::MultQuadVec): rotate `vec` by conjugate(`quat`) into
  // `dest`. Not published in a header yet, so declared here for the patrol
  // search-box builder that invokes it by name.
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);

  gpg::RType* CUnitPatrolTask::sType = nullptr;

  /**
   * Address: 0x0061B0B0 (FUN_0061B0B0, Moho::CUnitPatrolTask::CUnitPatrolTask default ctor)
   *
   * What it does:
   * Default-constructs one patrol-task lane. The embedded `Listener<...>` and
   * `EntitySetTemplate<Entity>` members self-link their intrusive nodes (the
   * binary's `a1+56/60`, `a1+72/76`, `a1+200/204` self-link stores), and the
   * scalar goal / flag / search-box / tick lanes are zero-cleared. Used by the
   * SerConstruct reflection callback (FUN_0061AD10) which then deserializes
   * payload fields via the archive `Read` path.
   */
  CUnitPatrolTask::CUnitPatrolTask() noexcept
    : CCommandTask()
    , mFirstCommand(nullptr)
    , mCommandEventListener()
    , mReserved40(0)
    , mFormationStatusListener()
    , mDispatch(nullptr)
    , mBoundCommand(nullptr)
    , mFormationInstance(nullptr)
    , mGoal{}
    , mMoving(false)
    , mNavStalled(false)
    , mInFormation(false)
    , mPad83(0)
    , mSearchBox{}
    , mTickCounter(0)
    , mPadC4{}
    , mMembership()
  {
  }

  /**
   * Address: 0x0061AE50 (FUN_0061AE50, Moho::CUnitPatrolTask::CUnitPatrolTask)
   * Mangled: ??0CUnitPatrolTask@Moho@@QAE@PAVCCommandTask@1@PBXPAVIFormationInstance@1@_N@Z
   *
   * IDA signature:
   * Moho::CUnitPatrolTask* __thiscall CUnitPatrolTask(
   *   CUnitPatrolTask* this, CCommandTask* dispatchTask, const void* goalPayload,
   *   IFormationInstance* formationInstance, bool inFormation);
   *
   * What it does:
   * Constructs one active patrol task. Runs the `CCommandTask` base ctor,
   * publishes the task/listener identity, self-links the two embedded listener
   * nodes and the per-army `EntitySetTemplate<Entity>` membership node, copies
   * the navigator goal payload, sets the formation-mode flag, resolves the queue
   * head command, splices the command-event listener into that command's
   * broadcaster ring, links the membership node into `mUnit->mSim->mEntityDB`'s
   * registered-set list, splices the formation-status listener into the bound
   * formation instance's broadcaster ring, refreshes navigator speed-through
   * state, issues one desired-target clear on immobile need-unpack attackers,
   * builds the oriented `mSearchBox`, and enters the Preparing task state.
   */
  CUnitPatrolTask::CUnitPatrolTask(
    CCommandTask* const dispatchTask,
    const void* const goalPayload,
    IFormationInstance* const formationInstance,
    const bool inFormation
  )
    : CCommandTask(dispatchTask)
    , mFirstCommand(nullptr)
    , mCommandEventListener()
    , mReserved40(0)
    , mFormationStatusListener()
    , mDispatch(static_cast<IAiCommandDispatchImpl*>(dispatchTask))
    , mBoundCommand(nullptr)
    , mFormationInstance(formationInstance)
    , mGoal{}
    , mMoving(false)
    , mNavStalled(false)
    , mInFormation(inFormation)
    , mPad83(0)
    , mSearchBox{}
    , mTickCounter(0)
    , mPadC4{}
    , mMembership()
  {
    // Copy the navigator goal payload (const void* -> SNavGoal), matching the
    // binary's `rep movsd` of 9 dwords (0x24 bytes) from the goal argument.
    if (goalPayload != nullptr) {
      mGoal = *static_cast<const SNavGoal*>(goalPayload);
    }

    // Publish the task identity + set the owner-unit patrol state bit and enter
    // the linking sequence. The base ctor already resolved `mUnit` from dispatch.
    Unit* const unit = mUnit;

    // Owner unit gains the patrol move-state bit (0x1000). The binary loads and
    // writes back the high dword unchanged, so the 64-bit mask stays intact.
    unit->UnitStateMask |= static_cast<std::uint64_t>(0x1000u);

    // Resolve the queue-head command and store it as the bound patrol command
    // (binary `this + 0x54`, the command the search-box builder later reads as
    // the leg-start). The binary leaves `mFirstCommand` (+0x30) untouched here;
    // we initialized it to null above.
    CUnitCommandQueue* const commandQueue = unit->CommandQueue;
    CUnitCommand* const frontCommand = ResolvePatrolQueueCommand(commandQueue, /*front=*/true);
    mBoundCommand = frontCommand;

    // Splice the command-event listener node into the front command's
    // broadcaster ring (the command derives Broadcaster at offset 0). When the
    // queue is empty the binary splices before a null head; here the ring head
    // falls back to the node's own self-linked broadcaster to stay well-defined.
    Broadcaster* const commandBroadcasterHead = (frontCommand != nullptr)
      ? static_cast<Broadcaster*>(frontCommand)
      : &mCommandEventListener.mListenerLink;
    mCommandEventListener.mListenerLink.ListLinkBefore(commandBroadcasterHead);

    // Link the per-army membership node into the sim entity DB's registered-set
    // list (binary `mUnit->mSim->mEntityDB + 0x18`).
    CEntityDb* const entityDb = unit->SimulationRef->mEntityDB;
    mMembership.ListLinkBefore(
      reinterpret_cast<EntitySetTemplate<Entity>*>(&entityDb->mRegisteredEntitySets)
    );

    // When a formation instance is bound, splice the formation-status listener
    // into that instance's broadcaster ring.
    if (mFormationInstance != nullptr) {
      if (Broadcaster* const formationHead = FormationStatusBroadcasterHead(mFormationInstance);
          formationHead != nullptr) {
        mFormationStatusListener.mListenerLink.ListLinkBefore(formationHead);
      }
    }

    // Refresh navigator speed-through state when the unit still has a navigator.
    if (unit->AiNavigator != nullptr) {
      unit->UpdateSpeedThroughStatus();
    }

    // Immobile need-unpack attackers get their desired target cleared so the
    // pack/unpack transition is not held by a stale attack target.
    if (unit->IsUnitState(UNITSTATE_Immobile)) {
      if (const RUnitBlueprint* const blueprint = unit->GetBlueprint();
          blueprint != nullptr && blueprint->AI.NeedUnpack) {
        if (CAiAttackerImpl* const attacker = unit->AiAttacker; attacker != nullptr) {
          CAiTarget clearTarget{};
          clearTarget.targetType = EAiTargetType::AITARGET_None;
          clearTarget.position = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
          clearTarget.targetPoint = -1;
          clearTarget.targetIsMobile = false;
          attacker->SetDesiredTarget(&clearTarget);
        }
      }
    }

    // Build the oriented search box, then enter the Preparing state.
    RecomputePatrolSearchBox();
    mTaskState = TASKSTATE_Preparing;
  }

  /**
   * Address: 0x0061B140 (FUN_0061B140, Moho::CUnitPatrolTask::~CUnitPatrolTask)
   * Mangled: ??1CUnitPatrolTask@Moho@@QAE@@Z
   *
   * IDA signature:
   * void __thiscall Moho::CUnitPatrolTask::~CUnitPatrolTask(Moho::CUnitPatrolTask *this);
   *
   * What it does:
   * Complete-object destructor. Detaches this patrol task from the owner unit's
   * listener/navigator state and clears the transient patrol move state before
   * base `CCommandTask` teardown. See the header block for the full binary-order
   * teardown sequence.
   *
   * The MSVC per-sub-object vtable restores and the second, unconditional
   * listener relinks at the binary head/tail (0x0061B15E, 0x0061B28E..0x0061B2CC)
   * are dead stores to the dying object's own memory; together with the embedded
   * `EntitySetTemplate<Entity>` membership teardown (0x0061B258..0x0061B28C, i.e.
   * `~EntitySetTemplate<Entity>()` on `mMembership`) they are handled implicitly
   * by the C++ destructor and are not reproduced as raw pointer arithmetic.
   */
  CUnitPatrolTask::~CUnitPatrolTask()
  {
    // (1) Unconditionally unlink the command-event listener lane
    // (0x0061B17A: splice prev/next, then self-relink the node).
    mCommandEventListener.mListenerLink.ListUnlink();

    // (2) Navigator branch: stop honoring the formation, and abort the active
    // move only when the unit's current and previous positions compare equal
    // (0x0061B192..0x0061B1CF: `Wm3::Vector3::Compare` returns nonzero for an
    // approximate match, and the binary branches to `AbortMove` on nonzero).
    if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
      navigator->IgnoreFormation(false);
      if (Wm3::Vector3f::Compare(&mUnit->Position, &mUnit->PrevPosition)) {
        navigator->AbortMove();
      }
    }

    // (3) Formation-status listener lane: unlink only when a formation instance
    // is bound (0x0061B1CF: `cmp [esi+58h], 0`).
    if (mFormationInstance != nullptr) {
      mFormationStatusListener.mListenerLink.ListUnlink();
    }

    // (4) Clear the two patrol move-state bits on the owner unit
    // (0x0061B1ED / 0x0061B206: `&= ~0x2000000` then `&= ~0x1000`; the binary's
    // read-back of the high dword is a no-op, so the 64-bit masks stay intact).
    mUnit->UnitStateMask &= ~static_cast<std::uint64_t>(0x2000000u);
    mUnit->UnitStateMask &= ~static_cast<std::uint64_t>(0x1000u);

    // (5) Reset the owner unit's guarded position to the zero vector
    // (0x0061B21F..0x0061B250: three `movss` stores from the shared `vec0`
    // zero-vector global into `Unit::GuardedPos`).
    mUnit->GuardedPos = Wm3::Vector3f::Zero();
  }

  namespace
  {
    /**
     * Address: 0x0061B610 (FUN_0061B610)
     *
     * IDA signature:
     * bool __usercall sub_61B610@<al>(CUnitPatrolTask* this@<ebx>);
     *
     * What it does:
     * Patrol-arrival test: returns true when the (optionally speed-expanded)
     * goal rectangle still covers the owner unit's footprint-aligned grid
     * origin. When a move is in flight (`mMoving`), the goal rectangle is
     * inflated by ceil(mInfoCache.mFormationTopSpeed) cells before the
     * containment test.
     */
    [[nodiscard]] bool PatrolGoalCoversUnitOrigin(const CUnitPatrolTask& task)
    {
      Unit* const unit = task.mUnit;

      std::int32_t minX = task.mGoal.minX;
      std::int32_t minZ = task.mGoal.minZ;
      std::int32_t maxX = task.mGoal.maxX;
      std::int32_t maxZ = task.mGoal.maxZ;

      if (task.mMoving) {
        const float topSpeed = unit->mInfoCache.mFormationTopSpeed;
        const auto expand = static_cast<std::int32_t>(std::ceil(topSpeed));
        minX -= expand;
        minZ -= expand;
        maxX += expand;
        maxZ += expand;
      }

      const SFootprint& footprint = unit->GetFootprint();
      const Wm3::Vec3f& position = unit->GetPosition();
      const auto originX = static_cast<std::int16_t>(
        static_cast<int>(position.x - static_cast<float>(footprint.mSizeX) * 0.5f)
      );
      const auto originZ = static_cast<std::int16_t>(
        static_cast<int>(position.z - static_cast<float>(footprint.mSizeZ) * 0.5f)
      );

      return minX <= originX && maxX >= originX && minZ <= originZ && maxZ >= originZ;
    }
  } // namespace

  /**
   * Address: 0x0061B710 (FUN_0061B710, Moho::CUnitPatrolTask::FindTarget)
   *
   * IDA signature:
   * Moho::Entity* __stdcall FindTarget(Moho::CUnitPatrolTask* this);
   *
   * What it does:
   * Builds a scratch weak-ref collector from the owner unit's in-range blips
   * whose collision shape overlaps the patrol search box, asks the owner
   * attacker for the best enemy (primary weapon, guard-scan radius), and
   * returns that enemy only when it lies within guard-scan radius. The
   * collector is torn down (intrusive weak links unspliced) on all exits.
   */
  Entity* CUnitPatrolTask::FindTarget()
  {
    Unit* const unit = mUnit;
    if (unit->AiAttacker == nullptr) {
      return nullptr;
    }

    // Scratch collector of blips overlapping the patrol search box. Its
    // destructor performs the intrusive weak-ref range-unlink teardown that the
    // binary open-codes (sub_61CA70 + operator delete[]).
    gpg::core::FastVectorN<SWeakRefSlot, 20> overlappingBlips;

    const gpg::core::FastVectorN<SWeakRefSlot, 20>& blips = unit->mBlipsInRange;
    const std::ptrdiff_t blipCount = blips.end() - blips.begin();
    for (std::ptrdiff_t i = 0; i < blipCount; ++i) {
      Entity* const blip = unit->mBlipsInRange.begin()[i].ResolveObjectPtr<Entity>();
      if (blip == nullptr || blip->Dead || blip->DestroyQueuedFlag) {
        continue;
      }

      EntityCollisionUpdater* const collisionShape = blip->CollisionExtents;
      if (collisionShape == nullptr) {
        continue;
      }

      CollisionResult collision{};
      if (collisionShape->CollideBox(&mSearchBox, &collision)) {
        collision.sourceEntity = blip;
        // Stage a weak-ref node on the blip, append it to the collector (whose
        // intrusive push_back splices a second link into the blip's owner chain),
        // then unlink the staging node — mirroring sub_61C5E0 + sub_5A6DE0.
        SWeakRefSlot blipSlot{};
        blipSlot.ResetObjectPtr<Entity>(blip);
        overlappingBlips.push_back(blipSlot);
        blipSlot.AsWeakPtr<Entity>().UnlinkFromOwnerChain();
      }
    }

    CAiAttackerImpl* const attacker = unit->AiAttacker;
    UnitWeapon* const primaryWeapon = attacker->GetPrimaryWeapon();
    const float guardScanRadius = unit->GetBlueprint()->AI.GuardScanRadius;
    Entity* const bestEnemy = attacker->FindBestEnemy(primaryWeapon, &overlappingBlips, guardScanRadius, 0);
    if (bestEnemy != nullptr) {
      const Wm3::Vec3f& selfPos = unit->GetPosition();
      const float dz = bestEnemy->Position.z - selfPos.z;
      const float dx = bestEnemy->Position.x - selfPos.x;
      const float distance = std::sqrt(dz * dz + dx * dx);
      if (distance > unit->GetBlueprint()->AI.GuardScanRadius) {
        return nullptr;
      }
    }

    return bestEnemy;
  }

  /**
   * Address: 0x0061B9C0 (FUN_0061B9C0)
   *
   * IDA signature:
   * Moho::Entity* __stdcall sub_61B9C0(CUnitPatrolTask* this);
   *
   * What it does:
   * Scores COGrid entities inside the patrol search box for reclaim (props) or
   * opportunistic attack (units), honoring the PATROLHELPER precondition, the
   * COMMAND/SACU_BEHAVIOR formation opt-out, the army no-rush zone, alliance,
   * reclaimable category, map bounds, guard-return radius, and a per-candidate
   * distance weight. Returns the nearest weighted candidate, or null.
   *
   * Note: the army no-rush-zone extents used for the reclaim (v40) / attack
   * (v39) mass/energy gate are read from the army's no-rush lane fields
   * (`StartPosition`/`NoRushOffset*`/`NoRushTicks`/`NoRushRadius`) exactly as
   * the binary computes them via the CArmyImpl no-rush accessor; the half-range
   * abs-value math mirrors the `fild`/`fchs`/`*0.5` sequence at 0x0061BB60.
   */
  Entity* CUnitPatrolTask::EvaluatePatrolReclaimAttack()
  {
    Unit* const unit = mUnit;

    // Only patrol-helper-capable units run the reclaim/attack sweep.
    if (!unit->IsInCategory("PATROLHELPER")) {
      return nullptr;
    }

    // Formation members that are commander/SACU units opt out of the sweep.
    if (mInFormation) {
      if (unit->IsInCategory("COMMAND") || unit->IsInCategory("SACU_BEHAVIOR")) {
        return nullptr;
      }
    }

    CArmyImpl* const army = unit->ArmyRef;

    // No-rush zone extents: start position offset by the per-army no-rush offset,
    // gated by whether the army still has no-rush time remaining.
    const float noRushCenterX = army->StartPosition.X() + army->NoRushOffsetX;
    const float noRushCenterZ = army->StartPosition.Y() + army->NoRushOffsetY;
    const bool massReclaimZoneOpen = army->StartPosition.X() > (army->NoRushRadius * 0.75f);
    const bool energyReclaimZoneOpen = army->StartPosition.Y() > (army->NoRushRadius * 0.75f);

    gpg::core::FastVectorN<CollisionResult, 10> collisions;
    Sim* const sim = unit->SimulationRef;
    sim->mOGrid->CollectEntitiesInBox(
      collisions,
      static_cast<EEntityType>(ENTITYTYPE_Unit | ENTITYTYPE_Prop),
      mSearchBox
    );

    Entity* bestCandidate = nullptr;
    float bestWeightedDistanceSq = std::numeric_limits<float>::infinity();

    const std::ptrdiff_t count = collisions.end() - collisions.begin();
    for (std::ptrdiff_t i = 0; i < count; ++i) {
      Entity* const candidate = collisions.begin()[i].sourceEntity;
      Unit* const candidateUnit = candidate->IsUnit();
      float weight = 1.0f;

      if (candidateUnit == nullptr || candidate->IsBeingBuilt()) {
        // Prop / non-unit reclaim branch.
        if (candidate == nullptr) {
          continue;
        }
        if (!unit->IsInCategory("RECLAIM")) {
          continue;
        }
        if (!candidate->IsInCategory("RECLAIMABLE")) {
          continue;
        }
        if (massReclaimZoneOpen || energyReclaimZoneOpen) {
          const auto* const propBlueprint =
            reinterpret_cast<const RPropBlueprint*>(candidate->BluePrint);
          bool hasReclaimValue = false;
          if (!massReclaimZoneOpen) {
            hasReclaimValue = propBlueprint->Economy.ReclaimEnergyMax > 0.0f;
          }
          if ((energyReclaimZoneOpen || propBlueprint->Economy.ReclaimMassMax <= 0.0f) && !hasReclaimValue) {
            continue;
          }
        }
        weight = 1.0f;
      } else {
        // Unit attack/reclaim branch.
        if (candidateUnit == unit) {
          continue;
        }
        if (Wm3::Vector3f::Compare(&candidate->PrevPosition, &candidate->Position)) {
          continue; // stationary — already at rest, ignore
        }
        if (candidate->mCurrentLayer == LAYER_Air) {
          continue;
        }

        const EAlliance alliance = unit->ArmyRef->GetAllianceWith(candidate->ArmyRef);
        if (alliance == ALLIANCE_Neutral) {
          continue;
        }
        if (alliance == ALLIANCE_Enemy) {
          if (!candidate->IsInCategory("RECLAIMABLE")) {
            continue;
          }
          weight = 0.5f;
        } else {
          // Allied damaged unit inside an open no-rush zone -> assist-reclaim.
          if (!massReclaimZoneOpen || !energyReclaimZoneOpen
              || candidate->Health >= (candidate->MaxHealth * 0.9f)
              || candidateUnit->IsUnitState(UNITSTATE_BeingReclaimed)) {
            continue;
          }
          weight = 2.0f;
        }
      }

      // Skip entities already tracked in the per-army membership set.
      if (mMembership.Contains(candidate)) {
        continue;
      }

      const bool wholeMap = army->UseWholeMap();
      if (!candidate->SimulationRef->mMapData->IsWithin(candidate->Position, 1.0f, wholeMap)) {
        continue;
      }

      // Guard-return radius gate around the no-rush center.
      if (army->NoRushTicks > 0) {
        const float ddz = noRushCenterX - candidate->Position.z;
        const float ddx = noRushCenterZ - candidate->Position.x;
        const float noRushDistance = std::sqrt(ddz * ddz + ddx * ddx);
        if (noRushDistance > army->NoRushRadius) {
          continue;
        }
      }

      // Weighted squared distance from this unit to the candidate; keep nearest.
      const Wm3::Vec3f& selfPos = unit->GetPosition();
      const float dx = selfPos.x - candidate->Position.x;
      const float dy = selfPos.y - candidate->Position.y;
      const float dz = selfPos.z - candidate->Position.z;
      const float weightedDistanceSq = (dx * dx + dy * dy + dz * dz) * weight;
      if (bestWeightedDistanceSq > weightedDistanceSq) {
        bestWeightedDistanceSq = weightedDistanceSq;
        bestCandidate = candidate;
      }
    }

    return bestCandidate;
  }

  /**
   * Address: 0x0061B2F0 (FUN_0061B2F0, Moho::CUnitPatrolTask::RecomputePatrolSearchBox)
   *
   * IDA signature:
   * void __stdcall RecomputePatrolSearchBox(Moho::CUnitPatrolTask* this);
   *
   * What it does:
   * Rebuilds the oriented world-space `mSearchBox` for the current patrol leg.
   * See the header block for the full lane-by-lane description.
   */
  void CUnitPatrolTask::RecomputePatrolSearchBox()
  {
    Unit* const unit = mUnit;
    CUnitCommandQueue* const commandQueue = unit->CommandQueue;

    // Cache the owner's guard-scan radius, used for the box's fixed lateral
    // extent and as the base of the along-leg extent (binary `v28` = read from
    // `GetBlueprint()->AI` +0x00, i.e. `RUnitBlueprintAI::GuardScanRadius`).
    const float guardScanRadius = unit->GetBlueprint()->AI.GuardScanRadius;

    // Queue head/tail commands: only used to gate the leg-end branch below. The
    // binary resolves both weak slots (`v24` = head, `a1` = tail) up front.
    CUnitCommand* const queueHeadCommand = ResolvePatrolQueueCommand(commandQueue, /*front=*/true);
    CUnitCommand* const queueTailCommand = ResolvePatrolQueueCommand(commandQueue, /*front=*/false);

    STIMap* const map = unit->SimulationRef->mMapData;

    // Leg-start world position: the patrol's bound command (binary `this + 0x54`)
    // resolved to a cell then converted via the owner footprint's layer/size.
    CUnitCommand* const legStartCommand = mBoundCommand;
    const SFootprint& startFootprint = unit->GetFootprint();
    SOCellPos startCell{};
    const SOCellPos* const startPosCell = CUnitCommand::GetPosition(legStartCommand, unit, &startCell);
    const Wm3::Vector3f startPos = COORDS_ToWorldPos(
      map,
      *startPosCell,
      static_cast<ELayer>(static_cast<std::uint8_t>(startFootprint.mOccupancyCaps)),
      startFootprint.mSizeX,
      startFootprint.mSizeZ
    );

    // Leg-end reference position: the queue-tail command's world position when it
    // is a distinct Patrol/FormPatrol command (binary type 16/18); otherwise the
    // owner unit's own current position. The type is read via the named
    // `mVarDat.mCmdType` field, consistent with every other recovered task.
    Wm3::Vector3f endPos;
    if (queueTailCommand != nullptr && queueTailCommand != queueHeadCommand
        && (queueTailCommand->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_Patrol
            || queueTailCommand->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_FormPatrol)) {
      const SFootprint& tailFootprint = unit->GetFootprint();
      SOCellPos tailCell{};
      const SOCellPos* const tailPosCell = CUnitCommand::GetPosition(queueTailCommand, unit, &tailCell);
      endPos = COORDS_ToWorldPos(
        map,
        *tailPosCell,
        static_cast<ELayer>(static_cast<std::uint8_t>(tailFootprint.mOccupancyCaps)),
        tailFootprint.mSizeX,
        tailFootprint.mSizeZ
      );
    } else {
      endPos = unit->GetPosition();
    }

    // Leg direction (start minus end), flattened onto the XZ plane.
    Wm3::Vector3f direction{startPos.x - endPos.x, 0.0f, startPos.z - endPos.z};

    // Leg half-length gate: the binary squares the flattened deltas (the y term
    // is always 0*0) and takes the sqrt; below 0.001 the direction degenerates
    // to the fixed `+Z` fallback, otherwise it is normalized in place.
    const float legLength = std::sqrt((direction.z * direction.z) + (0.0f * 0.0f) + (direction.x * direction.x));
    if (legLength >= kPatrolLegMinLength) {
      Wm3::Vector3f::Normalize(&direction);
    } else {
      direction.x = 0.0f;
      direction.y = 0.0f;
      direction.z = 1.0f;
    }

    // Lateral axis: the leg direction rotated 90 degrees about +Y.
    Wm3::Vector3f lateralAxis;
    MultQuadVec(&lateralAxis, &direction, &kSearchBoxYawQuat);

    // Fill the oriented box. Center is the leg midpoint (each lane * 0.5);
    // axis0 = lateral, axis1 = +Y, axis2 = direction; extents are
    // {guardScanRadius, 100.0, guardScanRadius + legHalfLength}.
    mSearchBox.Center.x = (startPos.x + endPos.x) * 0.5f;
    mSearchBox.Center.y = (endPos.y * 2.0f) * 0.5f;
    mSearchBox.Center.z = (startPos.z + endPos.z) * 0.5f;

    mSearchBox.Axis[0] = lateralAxis;
    mSearchBox.Axis[1] = Wm3::Vector3f{0.0f, 1.0f, 0.0f};
    mSearchBox.Axis[2] = direction;

    mSearchBox.Extent[0] = guardScanRadius;
    mSearchBox.Extent[1] = 100.0f;
    mSearchBox.Extent[2] = guardScanRadius + (legLength * 0.5f);
  }

  /**
   * Address: 0x0061C130 (FUN_0061C130, Moho::CUnitPatrolTask::TaskTick / CTask::Execute slot 1)
   *
   * IDA signature:
   * int __thiscall TaskTick(Moho::CUnitPatrolTask* this);
   *
   * What it does:
   * One patrol tick. Terminates when the navigator is gone or a stalled move is
   * in flight; otherwise, in priority order: hand off to a refuel platform,
   * hand off to a best-enemy attack task, evaluate a patrol reclaim/attack
   * candidate (repair-if-allied else reclaim), or resubmit the patrol navigator
   * goal. Wires all four callees (FindPlatform, FindTarget, the reclaim/attack
   * evaluator, and the arrival test) by name.
   */
  int CUnitPatrolTask::Execute()
  {
    Unit* const unit = mUnit;
    (void)unit->GetBlueprint();

    IAiNavigator* const navigator = unit->AiNavigator;
    if (navigator == nullptr || (mMoving && mNavStalled)) {
      return TASKSTATUS_Done;
    }

    ++mTickCounter;
    if (mTaskState != TASKSTATE_Preparing) {
      return 7;
    }

    // Refuel/repair platform handoff (only when not formation-bound).
    if (mFormationInstance == nullptr) {
      if (Unit* const platform = unit->FindPlatform(); platform != nullptr) {
        if (IAiTransport* const platformTransport = platform->AiTransport; platformTransport != nullptr) {
          platformTransport->TransportResetReservation();
        }
        mDispatch->IssueRefuelTask(platform);
        mMoving = false;
        return 7;
      }
    }

    // Best-enemy attack handoff.
    if (Entity* const enemy = FindTarget(); enemy != nullptr) {
      unit->GuardedPos = unit->GetPosition();

      CAiTarget attackTarget{};
      attackTarget.UpdateTarget(enemy);
      (void)CAttackTargetTask::Create(mDispatch, &attackTarget, nullptr);
      mMoving = false;
      return 7;
    }

    // Patrol reclaim/attack evaluation.
    Entity* const reclaimCandidate = EvaluatePatrolReclaimAttack();
    if (reclaimCandidate == nullptr) {
      if (unit->IsUnitState(UNITSTATE_NeedToTerminateTask)) {
        return TASKSTATUS_Done;
      }
      if (mMoving && PatrolGoalCoversUnitOrigin(*this) && mTickCounter > 3) {
        if (mFormationInstance == nullptr || unit->mInfoCache.mHasFormationSpeedData) {
          return TASKSTATUS_Done;
        }
      } else if (navigator->GetStatus() == AINAVSTATUS_Idle || !mMoving) {
        navigator->SetGoal(mGoal);
        unit->UpdateSpeedThroughStatus();
        mMoving = true;
        mNavStalled = false;
      }
      return 7;
    }

    // Allied unit within range -> repair; otherwise reclaim.
    if (Unit* const candidateUnit = reclaimCandidate->IsUnit(); candidateUnit != nullptr) {
      CArmyImpl* const candidateArmy = reclaimCandidate->ArmyRef;
      if (unit->ArmyRef->GetAllianceWith(candidateArmy) == ALLIANCE_Ally) {
        // Spawn the repair sub-task the binary spawns here (0x0061C130 ->
        // CUnitRepairTask operator new `_0` at 0x005F8DA0 -> ctor 0x005F8C80).
        (void)CUnitRepairTask::Allocate(mDispatch, candidateUnit, false);
        mMoving = false;
        return 7;
      }
    }

    (void)mMembership.Add(reclaimCandidate);
    CAiTarget reclaimTarget{};
    reclaimTarget.UpdateTarget(reclaimCandidate);
    mDispatch->IssueReclaimTask(reclaimTarget);
    mMoving = false;
    return 7;
  }

  /**
   * Address: 0x0061CF50 (FUN_0061CF50, Moho::CUnitPatrolTask::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall MemberDeserialize(CUnitPatrolTask* this@<ecx>, gpg::ReadArchive* archive@<eax>);
   *
   * What it does:
   * Loads patrol-task state from an archive in binary lane order:
   *   1. base `CCommandTask` sub-object (by reflected type).
   *   2. `mDispatch` via `ReadPointer_CCommandTask` (IAiCommandDispatchImpl is a
   *      CCommandTask).
   *   3. `mBoundCommand` via `ReadPointer_CUnitCommand`.
   *   4. `mFormationInstance` via `ReadPointer_IFormationInstance`.
   *   5. `mGoal` (`SNavGoal`) by reflected type.
   *   6. `mMoving` / `mNavStalled` / `mInFormation` via the virtual `ReadBool`
   *      archive slot (vtbl +0x38).
   *   7. `mSearchBox` (`Box3f`) by reflected type.
   *   8. `mTickCounter` via the virtual `ReadInt` archive slot (vtbl +0x24).
   *   9. `mMembership` (`EntitySetTemplate<Entity>`) by reflected type.
   */
  void CUnitPatrolTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};

    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    CCommandTask* dispatchTask = static_cast<CCommandTask*>(mDispatch);
    archive->ReadPointer_CCommandTask(&dispatchTask, &ownerRef);
    mDispatch = static_cast<IAiCommandDispatchImpl*>(dispatchTask);

    archive->ReadPointer_CUnitCommand(&mBoundCommand, &ownerRef);

    archive->ReadPointer_IFormationInstance(&mFormationInstance, &ownerRef);

    archive->Read(CachedSNavGoalType(), &mGoal, ownerRef);

    archive->ReadBool(&mMoving);
    archive->ReadBool(&mNavStalled);
    archive->ReadBool(&mInFormation);

    archive->Read(CachedBox3fType(), &mSearchBox, ownerRef);
    archive->ReadInt(&mTickCounter);
    archive->Read(CachedEntitySetTemplateEntityType(), &mMembership, ownerRef);
  }

  /**
   * Address: 0x0061D0C0 (FUN_0061D0C0, Moho::CUnitPatrolTask::MemberSerialize)
   *
   * IDA signature:
   * void __usercall MemberSerialize(CUnitPatrolTask* this@<eax>, gpg::WriteArchive* archive@<esi>);
   *
   * What it does:
   * Line-for-line mirror of `MemberDeserialize` over the identical field set and
   * order: base sub-object via reflected `Write`, the three tracked pointer
   * lanes via `RRef_*` + `WriteRawPointer(... Unowned ...)`, the goal payload via
   * reflected `Write`, the three flags via the virtual `WriteBool` slot, the
   * search box via reflected `Write`, the tick counter via the virtual
   * `WriteInt` slot, and the membership node via reflected `Write`.
   */
  void CUnitPatrolTask::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};

    archive->Write(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    gpg::RRef pointerRef{};
    (void)gpg::RRef_CCommandTask(&pointerRef, static_cast<CCommandTask*>(mDispatch));
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    (void)gpg::RRef_CUnitCommand(&pointerRef, mBoundCommand);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    (void)gpg::RRef_IFormationInstance(&pointerRef, mFormationInstance);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedSNavGoalType(), &mGoal, ownerRef);

    archive->WriteBool(mMoving);
    archive->WriteBool(mNavStalled);
    archive->WriteBool(mInFormation);

    archive->Write(CachedBox3fType(), &mSearchBox, ownerRef);
    archive->WriteInt(mTickCounter);
    archive->Write(CachedEntitySetTemplateEntityType(), &mMembership, ownerRef);
  }

  /**
   * Address: 0x0061C480 (FUN_0061C480, Moho::CUnitPatrolTask::operator new)
   *
   * What it does:
   * Allocates one patrol-task object and forwards constructor arguments into
   * in-place construction.
   */
  CUnitPatrolTask* CUnitPatrolTask::Create(
    CCommandTask* const dispatchTask,
    const void* const goalPayload,
    const bool inFormation
  )
  {
    void* const storage = ::operator new(sizeof(CUnitPatrolTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitPatrolTask(dispatchTask, goalPayload, nullptr, inFormation);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x0061C4E0 (FUN_0061C4E0, Moho::CUnitPatrolTask::operator new `_0` overload)
   * Mangled: ??2CUnitPatrolTask@Moho@@QAE@@Z_0
   *
   * What it does:
   * Formation-instance allocation overload used by
   * `IAiCommandDispatchImpl::DispatchTask` when an existing
   * `IFormationInstance` must be bound to the new patrol task.
   */
  CUnitPatrolTask* CUnitPatrolTask::CreateWithFormation(
    CCommandTask* const dispatchTask,
    const void* const goalPayload,
    IFormationInstance* const formationInstance
  )
  {
    void* const storage = ::operator new(sizeof(CUnitPatrolTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitPatrolTask(dispatchTask, goalPayload, formationInstance, false);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  struct CUnitPatrolFormationListenerRuntimeView
  {
    std::uint8_t reserved00_3C[0x3D]{};
    std::uint8_t needsListenerResync = 0; // +0x3D
  };
  static_assert(
    offsetof(CUnitPatrolFormationListenerRuntimeView, needsListenerResync) == 0x3D,
    "CUnitPatrolFormationListenerRuntimeView::needsListenerResync offset must be 0x3D"
  );

  /**
   * Address: 0x0061C470 (FUN_0061C470)
   *
   * What it does:
   * Decrements one formation-listener countdown lane and marks listener-resync
   * state when this call consumes the last pending count.
   */
  [[maybe_unused]] int CUnitPatrolTaskConsumeFormationListenerCountdown(
    CUnitPatrolFormationListenerRuntimeView* const listenerRuntime,
    const int pendingCount
  ) noexcept
  {
    const int result = pendingCount - 1;
    if (pendingCount == 1 && listenerRuntime != nullptr) {
      listenerRuntime->needsListenerResync = 1;
    }
    return result;
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0061CCA0 (FUN_0061CCA0, gpg::RRef_CUnitPatrolTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitPatrolTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitPatrolTask(gpg::RRef* const outRef, moho::CUnitPatrolTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitPatrolTaskType());
    return outRef;
  }

  /**
   * Address: 0x0061CBF0 (FUN_0061CBF0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitPatrolTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitPatrolTaskRef(gpg::RRef* const outRef, moho::CUnitPatrolTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitPatrolTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg

namespace
{
  /**
   * Runtime view of the binary `SerSaveLoadHelper<CUnitPatrolTask>` global.
   *
   * Binary layout (0x14 bytes):
   * - +0x00: vtable pointer / intrusive-list head (`SerSaveLoadHelperListRuntime`)
   * - +0x04: `mNext`
   * - +0x08: `mPrev`
   * - +0x0C: `mSerLoadFunc` (published to the reflection descriptor's
   *          `serLoadFunc_` by `InstallMohoCUnitPatrolTaskSerializerCallbacks`)
   * - +0x10: `mSerSaveFunc` (published to `serSaveFunc_`)
   */
  struct CUnitPatrolTaskSerializerHelperNode
  {
    gpg::SerSaveLoadHelperListRuntime mListLinks{};
    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(
    offsetof(CUnitPatrolTaskSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "CUnitPatrolTaskSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitPatrolTaskSerializerHelperNode, mSerSaveFunc) == 0x10,
    "CUnitPatrolTaskSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(CUnitPatrolTaskSerializerHelperNode) == 0x14,
    "CUnitPatrolTaskSerializerHelperNode size must be 0x14"
  );

  CUnitPatrolTaskSerializerHelperNode gCUnitPatrolTaskSerializer{};

  /**
   * Address: 0x0061ADF0 (FUN_0061ADF0)
   *
   * What it does:
   * Unlinks `CUnitPatrolTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitPatrolTaskSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitPatrolTaskSerializer.mListLinks);
  }

  /**
   * Address: 0x0061AE20 (FUN_0061AE20)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitPatrolTaskSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitPatrolTaskSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitPatrolTaskSerializer.mListLinks);
  }

  /**
   * Address: 0x0061ADA0 (FUN_0061ADA0, Moho::CUnitPatrolTaskSerializer::Deserialize)
   *
   * IDA signature:
   * int __cdecl Deserialize(ReadArchive* archive, void* objectPtr, int version, RRef* ownerRef);
   *
   * What it does:
   * Reflection load-callback facade for `CUnitPatrolTask`. Forwards the
   * reflected object pointer to the class member load body; `version` and the
   * owner-ref lane are unused by the member (mirrors the binary tail-jump).
   */
  void CUnitPatrolTaskSerializerDeserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitPatrolTask*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0061ADB0 (FUN_0061ADB0, Moho::CUnitPatrolTaskSerializer::Serialize)
   *
   * IDA signature:
   * int __cdecl Serialize(WriteArchive* archive, void* objectPtr, int version, RRef* ownerRef);
   *
   * What it does:
   * Reflection save-callback facade for `CUnitPatrolTask`. Forwards the
   * reflected object pointer to the class member save body; `version` and the
   * owner-ref lane are unused by the member (mirrors the binary tail-jump).
   */
  void CUnitPatrolTaskSerializerSerialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitPatrolTask*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberSerialize(archive);
  }

  struct SerConstructHelperView
  {
    void* mVftable;
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(SerConstructHelperView, mConstructCallback) == 0x0C,
    "SerConstructHelperView::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerConstructHelperView, mDeleteCallback) == 0x10,
    "SerConstructHelperView::mDeleteCallback offset must be 0x10"
  );

  /**
   * Address: 0x0061C660 (FUN_0061C660, gpg::SerConstructHelper<Moho::CUnitPatrolTask>::Init)
   *
   * IDA signature:
   * void __thiscall sub_61C660(SerConstructHelperView *this);
   *
   * What it does:
   * Virtual-method body installed in both the
   * `Moho::CUnitPatrolTaskConstruct` and
   * `gpg::SerConstructHelper<Moho::CUnitPatrolTask>` vtables. Lazily resolves
   * the `CUnitPatrolTask` reflection descriptor, asserts the construct
   * callback slot is empty, and publishes this helper's construct/delete
   * callbacks to the descriptor.
   *
   * Notes:
   * Mirrors the binary's single `!type->mSerConstructFunc` assert (no separate
   * delete-slot assert); intentionally diverges from the broader
   * `RegisterConstructCallbacks` helper used in other subsystems.
   */
  [[maybe_unused]] gpg::RType::construct_func_t InitCUnitPatrolTaskConstructHelper(
    const SerConstructHelperView& helper
  )
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = CachedCUnitPatrolTaskType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = helper.mConstructCallback;
    type->deleteFunc_ = helper.mDeleteCallback;
    return helper.mConstructCallback;
  }

  /**
   * Address: 0x0061AD10 (FUN_0061AD10, Moho::CUnitPatrolTaskConstruct::Construct)
   *
   * What it does:
   * Allocates one `CUnitPatrolTask` instance via `operator new(0xF0u)`,
   * default-constructs it, wraps the result in a typed `gpg::RRef_CUnitPatrolTask`,
   * and publishes the payload as an unowned construct result through
   * `gpg::SerConstructResult::SetUnowned`. Invoked by the reflection
   * subsystem during archive replay when a patrol-task instance must be
   * materialized before its fields are streamed in.
   */
  void ConstructCUnitPatrolTaskSerializerCallback(void* const constructResultStorage)
  {
    auto* const result = static_cast<gpg::SerConstructResult*>(constructResultStorage);
    if (result == nullptr) {
      return;
    }

    auto* const task = new (std::nothrow) moho::CUnitPatrolTask{};
    gpg::RRef taskRef{};
    (void)gpg::RRef_CUnitPatrolTask(&taskRef, task);
    result->SetUnowned(taskRef, 0u);
  }

  /**
   * Address: 0x0061ADC0 (FUN_0061ADC0, Moho::CUnitPatrolTaskConstruct::Deconstruct)
   *
   * What it does:
   * Releases one heap-owned `CUnitPatrolTask` instance via the standard
   * scalar `delete` expression; mirrors the binary's reflection-side
   * destructor lane that fires when the construct result is discarded.
   */
  void DestructCUnitPatrolTaskSerializerCallback(void* const taskStorage)
  {
    delete static_cast<moho::CUnitPatrolTask*>(taskStorage);
  }

  /**
   * Static-init driver that installs `ConstructCUnitPatrolTaskSerializerCallback`
   * and `DestructCUnitPatrolTaskSerializerCallback` into the cached
   * `CUnitPatrolTask` reflection descriptor's lifecycle slots. The binary
   * registers the equivalent helper via a static-init-time
   * `SerConstructHelper<CUnitPatrolTask>` global; in modern source the same
   * effect is achieved by a file-scope dummy whose ctor invokes
   * `InitCUnitPatrolTaskConstructHelper` once at load time. This is the
   * source-level invocation chain that makes
   * `InitCUnitPatrolTaskConstructHelper` (and the inner pair of
   * Construct/Destruct callbacks) non-orphan.
   */
  struct CUnitPatrolTaskConstructHelperRegistrar
  {
    CUnitPatrolTaskConstructHelperRegistrar() noexcept
    {
      // Ensure the CUnitPatrolTask reflection descriptor is pre-registered
      // before we publish lifecycle callbacks into it. The binary defers
      // this through its `SerConstructHelper<CUnitPatrolTask>` global ctor
      // chain; in the modern build we call `preregister_CUnitPatrolTaskTypeInfo`
      // explicitly to make the order TU-static-init-safe.
      (void)moho::preregister_CUnitPatrolTaskTypeInfo();

      SerConstructHelperView helper{};
      helper.mVftable = nullptr;
      helper.mNext = nullptr;
      helper.mPrev = nullptr;
      helper.mConstructCallback = &ConstructCUnitPatrolTaskSerializerCallback;
      helper.mDeleteCallback = &DestructCUnitPatrolTaskSerializerCallback;
      (void)InitCUnitPatrolTaskConstructHelper(helper);

      // Publish the load/save reflection callbacks. This binds both facade
      // trampolines (FUN_0061ADA0 / FUN_0061ADB0) by name so the member bodies
      // (FUN_0061CF50 / FUN_0061D0C0) are reachable, and self-links the
      // intrusive helper node exactly like the binary's
      // `SerSaveLoadHelper<CUnitPatrolTask>` static-init registrar
      // (mirrors register_CThrustManipulatorSerializer). The engine install
      // path `InstallMohoCUnitPatrolTaskSerializerCallbacks` copies these into
      // the reflection descriptor's `serLoadFunc_` / `serSaveFunc_`.
      (void)UnlinkCUnitPatrolTaskSerializerNodePrimary();
      gCUnitPatrolTaskSerializer.mSerLoadFunc = &CUnitPatrolTaskSerializerDeserialize;
      gCUnitPatrolTaskSerializer.mSerSaveFunc = &CUnitPatrolTaskSerializerSerialize;
    }
  };

  [[maybe_unused]] const CUnitPatrolTaskConstructHelperRegistrar gCUnitPatrolTaskConstructHelperRegistrar{};
} // namespace
