#include "moho/unit/tasks/CUnitCarrierRetrieve.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"

namespace
{
  // CarrierRetrieve sets bit 0x100 in Unit::mUnitVarDat.mUnitStates while the
  // task is active (sibling Launch task uses bit 0x200). The dtor (recovered
  // elsewhere) pairs with this set.
  constexpr std::uint64_t kUnitStateMaskCarrierRetrieve = 0x0000000000000100ull;

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedEntitySetTemplateUnitType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SEntitySetTemplateUnit));
    }
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00605D10 (FUN_00605D10, Moho::CUnitCarrierRetrieve::CUnitCarrierRetrieve)
   *
   * IDA signature:
   * Moho::CUnitCarrierRetrieve *__userpurge sub_605D10@<eax>(
   *     Moho::CCommandTask *parent@<edi>,
   *     Moho::CUnitCarrierRetrieve *arg0,
   *     Moho::EntitySetTemplate_Entity *a2);
   *
   * What it does:
   * Initializes one retrieve-task from parent dispatch context, copies the
   * tracked-unit set template into the task's local storage, runs the
   * unit's `OnStartTransportLoading` script callback, then registers the
   * tracked-unit set into the simulation entity DB and flips the unit's
   * "carrier-retrieve in progress" state bit (0x100). The dtor clears the
   * state bit on teardown.
   */
  CUnitCarrierRetrieve::CUnitCarrierRetrieve(
    CCommandTask* const parentTask,
    const SEntitySetTemplateUnit& trackedUnits
  )
    : CCommandTask(parentTask)
    , mRetrievalComplete(false)
    , mPad31_37{}
    , mTrackedUnits(trackedUnits)
  {
    if (mUnit == nullptr) {
      return;
    }

    (void)mUnit->RunScript("OnStartTransportLoading");

    if (mUnit->SimulationRef != nullptr && mUnit->SimulationRef->mEntityDB != nullptr) {
      mUnit->SimulationRef->mEntityDB->RegisterEntitySet(mTrackedUnits);
      mUnit->UnitStateMask |= kUnitStateMaskCarrierRetrieve;
    }
  }

  /**
   * Address: 0x00605DD0 (FUN_00605DD0, ??1CUnitCarrierRetrieve@Moho@@QAE@@Z)
   * Address: 0x00606220 (FUN_00606220, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   *
   * IDA signature:
   * void __stdcall Moho::CUnitCarrierRetrieve::~CUnitCarrierRetrieve(
   *     Moho::CUnitCarrierRetrieve *this);
   *
   * What it does:
   * Tears down one retrieve-task. Runs `OnStopTransportLoading` on the
   * owning unit, releases the transport reservation, and clears the
   * carrier-retrieve "in progress" state bit (0x100) that the ctor set.
   * Dispatch result is written next: success path (`mRetrievalComplete`)
   * stores `EAiResult` value 1, failure path stores 2 after first asking
   * every still-living tracked unit's AI navigator to abort its in-flight
   * motion (so transports that never finished the load no longer keep
   * the loaders trying to dock).
   *
   * Member subobject (`mTrackedUnits`, which is an intrusive node + inline
   * vector wrapper) and the base `CCommandTask` destructor then run via
   * the standard C++ teardown chain; the binary inlines the SBO-vector
   * teardown and the intrusive-list unlink but the C++ source expresses
   * those as the implicit member dtor invocation.
   */
  CUnitCarrierRetrieve::~CUnitCarrierRetrieve()
  {
    if (mUnit != nullptr) {
      (void)mUnit->RunScript("OnStopTransportLoading");
      mUnit->AiTransport->TransportResetReservation();
      mUnit->UnitStateMask &= ~kUnitStateMaskCarrierRetrieve;
    }

    if (mRetrievalComplete) {
      *mDispatchResult = static_cast<EAiResult>(1);
    } else {
      // Walk every tracked-unit slot and have the still-living loaders
      // drop their in-flight navigator commands. This matches the binary's
      // per-slot SEntitySetTemplate_Unit::UnitFromEntry + Unit::IsDead +
      // Unit::AiNavigator->AbortMove() chain (the IDA pseudocode renders
      // the vtable+0x28 dispatch as `(*v4 + 40)(v4)` and the AiNavigator
      // pointer load as `v4[339]` at +0x54C).
      for (Entity** it = mTrackedUnits.mVec.start_; it != mTrackedUnits.mVec.end_; ++it) {
        Entity* const tracked = *it;
        if (tracked == nullptr) {
          continue;
        }

        Unit* const trackedUnit = SEntitySetTemplateUnit::UnitFromEntry(tracked);
        if (trackedUnit == nullptr || trackedUnit->IsDead()) {
          continue;
        }

        if (trackedUnit->AiNavigator != nullptr) {
          trackedUnit->AiNavigator->AbortMove();
        }
      }
      *mDispatchResult = static_cast<EAiResult>(2);
    }
  }

  /**
   * Address: 0x00606450 (FUN_00606450, Moho::CUnitCarrierRetrieve::operator new)
   *
   * IDA signature:
   * Moho::CUnitCarrierRetrieve *__usercall sub_606450@<eax>(
   *     Moho::CCommandTask *parent@<edi>,
   *     Moho::EntitySetTemplate_Entity *a2);
   *
   * What it does:
   * Allocates one retrieve-task (0x60 bytes) via `operator new`, then
   * forwards `parentTask` and `trackedUnits` into in-place construction.
   * On allocation failure returns `nullptr`; on constructor throw the
   * allocation is released before the exception propagates. Mirrors the
   * sibling `CUnitCarrierLaunch::Create` RAII shape.
   */
  CUnitCarrierRetrieve* CUnitCarrierRetrieve::Create(
    CCommandTask* const parentTask,
    const SEntitySetTemplateUnit& trackedUnits
  )
  {
    void* const storage = ::operator new(sizeof(CUnitCarrierRetrieve));
    if (storage == nullptr) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitCarrierRetrieve(parentTask, trackedUnits);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x00605EF0 (FUN_00605EF0, Moho::CUnitCarrierRetrieve::TaskTick)
   *
   * IDA signature:
   * int __thiscall sub_605EF0(Moho::CUnitCarrierRetrieve *this);
   *
   * What it does:
   * Drives the carrier-retrieve state machine across four cases:
   *
   *   Pre-switch guard: aborts the task immediately (returns -1) when the
   *     owning unit is dead or null, or when the task has already advanced
   *     to Starting AND the unit is in `UNITSTATE_MovingDown`.
   *
   *   TASKSTATE_Preparing: walks every tracked-unit slot, checking that
   *     each loaded unit is still alive, not destroy-queued, not attached,
   *     and that its current queued command still matches the carrier's
   *     own current command. If any loaded unit's current command diverges
   *     from the carrier's, the tick returns 1 (cooperative interrupt).
   *     When every loaded unit still tracks the carrier's command, the
   *     handler then specializes by carrier motion type:
   *       * surfacing-sub carriers (`Physics.MotionType ==
   *         RULEUMT_SurfacingSub`) currently submerged (`Entity::mCurrentLayer
   *         == LAYER_Sub`) compute the surface goal cell from the carrier's
   *         current footprint position, set `UnitMotion->SetNewTargetLayer
   *         (LAYER_Water)`, advance to Waiting, and return 1 to wait for
   *         the surface motion to complete;
   *       * all other carriers ask `AiNavigator->AbortMove()` (when
   *         present) to release any pre-existing path, advance to Starting,
   *         and fall through to the default return-1 lane.
   *
   *   TASKSTATE_Waiting: when the carrier reaches `LAYER_Water` or
   *     `LAYER_Air`, asks `AiTransport->TransportResetReservation()` to
   *     drop pre-launch storage bookkeeping and advances to Starting.
   *     Returns 1 either way.
   *
   *   TASKSTATE_Starting: builds a transient set of tracked units that
   *     are still actively loading (alive, in `UNITSTATE_TransportLoading`,
   *     and either focused on the carrier itself or not focused on it at
   *     all), then removes each from `mTrackedUnits`. When the resulting
   *     tracked set is empty the handler flips `mRetrievalComplete` to
   *     true and returns -1 (task complete); otherwise it returns 10 to
   *     sleep nine frames before the next tick.
   *
   *   Default (mTaskState >= TASKSTATE_Processing): returns 1.
   */
  int CUnitCarrierRetrieve::Execute()
  {
    if (mUnit == nullptr) {
      return -1;
    }

    if (mUnit->IsDead()) {
      return -1;
    }

    if (mTaskState >= TASKSTATE_Starting && mUnit->IsUnitState(UNITSTATE_MovingDown)) {
      return -1;
    }

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        // Snapshot the carrier's current command head so we can detect any
        // tracked unit that drifted onto a different command in the gap
        // between the load order issuing and this tick.
        CUnitCommand* const carrierCommand =
          (mUnit->CommandQueue != nullptr) ? mUnit->CommandQueue->GetCurrentCommand() : nullptr;

        for (Entity** it = mTrackedUnits.mVec.start_; it != mTrackedUnits.mVec.end_; ++it) {
          Entity* const tracked = *it;
          if (tracked == nullptr) {
            continue;
          }

          Unit* const trackedUnit = SEntitySetTemplateUnit::UnitFromEntry(tracked);
          if (trackedUnit == nullptr) {
            continue;
          }

          if (trackedUnit->IsDead() || trackedUnit->IsBeingBuilt()
              || trackedUnit->IsUnitState(UNITSTATE_Attached) || trackedUnit->DestroyQueued()) {
            continue;
          }

          CUnitCommand* const trackedCommand = (trackedUnit->CommandQueue != nullptr)
            ? trackedUnit->CommandQueue->GetCurrentCommand()
            : nullptr;
          if (trackedCommand != carrierCommand) {
            // A tracked unit broke off to a different command -- treat the
            // batched retrieve as interrupted and yield without changing
            // state. The next tick re-evaluates the survivors.
            return 1;
          }
        }

        const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
        if (blueprint->Physics.MotionType == RULEUMT_SurfacingSub
            && mUnit->mCurrentLayer == LAYER_Sub) {
          // Surfacing-submarine carrier waiting underwater: convert the
          // carrier's world position into footprint-anchored cell coords
          // (only the cell is consumed by SNavGoal), aim the motion lane at
          // the water layer, and wait for the surface motion in Waiting.
          const SFootprint& footprint = mUnit->GetFootprint();
          const Wm3::Vec3f& worldPos = mUnit->GetPosition();
          const SOCellPos surfaceCell = footprint.ToCellPos(worldPos);
          SNavGoal surfaceGoal(surfaceCell);
          (void)surfaceGoal;

          mUnit->UnitMotion->SetNewTargetLayer(LAYER_Water);
          mTaskState = TASKSTATE_Waiting;
          return 1;
        }

        // Land/water carriers: drop any pre-existing navigator path and
        // proceed straight to Starting on the next dispatch tick.
        if (mUnit->AiNavigator != nullptr) {
          mUnit->AiNavigator->AbortMove();
        }
        mTaskState = TASKSTATE_Starting;
        return 1;
      }

      case TASKSTATE_Waiting: {
        // Wait for the surfacing/landing motion to bring the carrier onto
        // a transport-friendly layer before dropping pickup reservations.
        const ELayer layer = mUnit->mCurrentLayer;
        if (layer == LAYER_Water || layer == LAYER_Air) {
          mUnit->AiTransport->TransportResetReservation();
          mTaskState = TASKSTATE_Starting;
        }
        return 1;
      }

      case TASKSTATE_Starting: {
        // Collect every tracked unit that is still actively loading and
        // either focused on the carrier or not focused on anything; then
        // remove each from the tracked set so it stops counting toward
        // the retrieve quorum. When the tracked set drains to empty, mark
        // the retrieve as complete and tell the dispatcher we're done.
        SEntitySetTemplateUnit completedSet{};

        Entity* const ownerEntity = (mUnit != nullptr) ? static_cast<Entity*>(mUnit) : nullptr;

        for (Entity** it = mTrackedUnits.mVec.start_; it != mTrackedUnits.mVec.end_; ++it) {
          Entity* const tracked = *it;
          if (tracked == nullptr) {
            // Null sentinel slots feed through the binary's Add path to
            // keep slot accounting consistent with the original.
            (void)completedSet.AddUnit(nullptr);
            continue;
          }

          Unit* const trackedUnit = SEntitySetTemplateUnit::UnitFromEntry(tracked);
          if (trackedUnit == nullptr) {
            (void)completedSet.AddUnit(nullptr);
            continue;
          }

          if (trackedUnit->IsDead() || !trackedUnit->IsUnitState(UNITSTATE_TransportLoading)) {
            (void)completedSet.AddUnit(trackedUnit);
            continue;
          }

          // Focus-points-at-carrier check (binary FocusEntityRef vs
          // mUnit->Entity comparison). A unit focused on the carrier and
          // not the carrier itself is still attaching/loading -- skip it
          // and leave it in the tracked set for the next tick.
          Entity* const focusedEntity = trackedUnit->FocusEntityRef.ResolveObjectPtr<Entity>();
          const bool focusedOnCarrier = (focusedEntity == ownerEntity);
          if (focusedOnCarrier && trackedUnit != mUnit) {
            continue;
          }

          (void)completedSet.AddUnit(trackedUnit);
        }

        // Drain the completed set out of mTrackedUnits. The Remove call
        // matches the binary's per-entry SEntitySetTemplate_Unit::Remove
        // dispatch (the IDA listing labels the address "Contains", but
        // the body is the erase lane recovered as RemoveUnit).
        for (Entity** it = completedSet.mVec.start_; it != completedSet.mVec.end_; ++it) {
          Unit* const completedUnit = (*it != nullptr) ? SEntitySetTemplateUnit::UnitFromEntry(*it) : nullptr;
          (void)mTrackedUnits.RemoveUnit(completedUnit);
        }

        if (mTrackedUnits.Empty()) {
          mRetrievalComplete = true;
          return -1;
        }

        // Tracked retrieves still in flight: sleep nine frames before the
        // next tick (matches the binary's `return 10` => mPendingFrames=9).
        return 10;
      }

      default:
        return 1;
    }
  }

  /**
   * Address: 0x006085A0 (FUN_006085A0, Moho::CUnitCarrierRetrieve::MemberDeserialize)
   *
   * What it does:
   * Deserializes one retrieve-task payload: base `CCommandTask` state,
   * retrieval-complete flag, and tracked transport-unit set.
   */
  void CUnitCarrierRetrieve::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), this, ownerRef);
    archive->ReadBool(&mRetrievalComplete);

    const gpg::RRef trackedUnitsOwnerRef{};
    archive->Read(CachedEntitySetTemplateUnitType(), &mTrackedUnits, trackedUnitsOwnerRef);
  }

  /**
   * Address: 0x00608630 (FUN_00608630, Moho::CUnitCarrierRetrieve::MemberSerialize)
   *
   * What it does:
   * Serializes one retrieve-task payload: base `CCommandTask` state,
   * retrieval-complete flag, and tracked transport-unit set.
   */
  void CUnitCarrierRetrieve::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), this, ownerRef);
    archive->WriteBool(mRetrievalComplete);

    const gpg::RRef trackedUnitsOwnerRef{};
    archive->Write(CachedEntitySetTemplateUnitType(), &mTrackedUnits, trackedUnitsOwnerRef);
  }

  /**
   * Address: 0x00607E80 (FUN_00607E80)
   *
   * What it does:
   * Preserves one deserialize thunk lane for `CUnitCarrierRetrieve` serializer
   * callback registration.
   */
  [[maybe_unused]] void CUnitCarrierRetrieveMemberDeserializeAdapterLaneA(
    CUnitCarrierRetrieve* const task,
    gpg::ReadArchive* const archive
  )
  {
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00608030 (FUN_00608030)
   *
   * What it does:
   * Alternate deserialize thunk lane for `CUnitCarrierRetrieve` serializer
   * callback registration.
   */
  [[maybe_unused]] void CUnitCarrierRetrieveMemberDeserializeAdapterLaneB(
    CUnitCarrierRetrieve* const task,
    gpg::ReadArchive* const archive
  )
  {
    task->MemberDeserialize(archive);
  }
} // namespace moho

namespace
{
  // The binary global is 0x14 bytes (vtable + mNext/mPrev + load/save
  // callback lanes) - `gpg::SerSaveLoadHelperListRuntime` only models the
  // leading 0x0C-byte intrusive-list header shared by every
  // SerHelperBase-derived serializer, so it undersized this global (same
  // bug found and fixed for several sibling serializers this session).
  struct CUnitCarrierRetrieveSerializerHelper
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    gpg::RType::load_func_t mLoadCallback = nullptr;
    gpg::RType::save_func_t mSaveCallback = nullptr;
  };
  static_assert(
    offsetof(CUnitCarrierRetrieveSerializerHelper, mNext) == 0x04,
    "CUnitCarrierRetrieveSerializerHelper::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitCarrierRetrieveSerializerHelper, mPrev) == 0x08,
    "CUnitCarrierRetrieveSerializerHelper::mPrev offset must be 0x08"
  );
  static_assert(
    sizeof(CUnitCarrierRetrieveSerializerHelper) == 0x14, "CUnitCarrierRetrieveSerializerHelper size must be 0x14"
  );

  CUnitCarrierRetrieveSerializerHelper gCUnitCarrierRetrieveSerializer{};

  [[nodiscard]] gpg::SerSaveLoadHelperListRuntime& AsSerSaveLoadHelperListRuntime(
    CUnitCarrierRetrieveSerializerHelper& helper
  ) noexcept
  {
    return *reinterpret_cast<gpg::SerSaveLoadHelperListRuntime*>(&helper);
  }

  /**
   * Address: 0x006063F0 (FUN_006063F0)
   *
   * What it does:
   * Unlinks `CUnitCarrierRetrieveSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCarrierRetrieveSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gCUnitCarrierRetrieveSerializer));
  }

  /**
   * Address: 0x00606420 (FUN_00606420)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitCarrierRetrieveSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCarrierRetrieveSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gCUnitCarrierRetrieveSerializer));
  }

  void DeserializeCUnitCarrierRetrieveSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<moho::CUnitCarrierRetrieve*>(static_cast<std::uintptr_t>(objectPtr))->MemberDeserialize(archive);
  }

  void SerializeCUnitCarrierRetrieveSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<const moho::CUnitCarrierRetrieve*>(static_cast<std::uintptr_t>(objectPtr))
      ->MemberSerialize(archive);
  }

  void cleanup_CUnitCarrierRetrieveSerializer_atexit()
  {
    (void)UnlinkCUnitCarrierRetrieveSerializerNodePrimary();
  }

  /**
   * Address: 0x00BD0220 (FUN_00BD0220, register_CUnitCarrierRetrieveSerializer)
   *
   * What it does:
   * Initializes the global CUnitCarrierRetrieve serializer helper callbacks
   * and installs process-exit cleanup.
   */
  void register_CUnitCarrierRetrieveSerializer()
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gCUnitCarrierRetrieveSerializer.mNext);
    gCUnitCarrierRetrieveSerializer.mNext = self;
    gCUnitCarrierRetrieveSerializer.mPrev = self;
    gCUnitCarrierRetrieveSerializer.mLoadCallback = &DeserializeCUnitCarrierRetrieveSerializerCallback;
    gCUnitCarrierRetrieveSerializer.mSaveCallback = &SerializeCUnitCarrierRetrieveSerializerCallback;
    (void)std::atexit(&cleanup_CUnitCarrierRetrieveSerializer_atexit);
  }

  struct CUnitCarrierRetrieveSerializerStartupBootstrap
  {
    CUnitCarrierRetrieveSerializerStartupBootstrap()
    {
      register_CUnitCarrierRetrieveSerializer();
    }
  };

  [[maybe_unused]] CUnitCarrierRetrieveSerializerStartupBootstrap gCUnitCarrierRetrieveSerializerStartupBootstrap;
} // namespace
