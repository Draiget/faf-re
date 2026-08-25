#include "moho/unit/tasks/CUnitCarrierLaunch.h"

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <new>
#include <type_traits>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiTransport.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/math/Vector3f.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitCarrierRetrieve.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskCarrierLaunch = 0x0000000000000200ull;

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCarrierLaunchType()
  {
    gpg::RType* type = moho::CUnitCarrierLaunch::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCarrierLaunch));
      moho::CUnitCarrierLaunch::sType = type;
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
  gpg::RType* CUnitCarrierLaunch::sType = nullptr;

  /**
   * Address: 0x00606E10 (FUN_00606E10, Moho::CUnitCarrierLaunch::CUnitCarrierLaunch)
   *
   * What it does:
   * Initializes one detached carrier-launch task with empty launch-goal state
   * and an unregistered carried-unit set.
   */
  CUnitCarrierLaunch::CUnitCarrierLaunch()
    : CCommandTask()
    , mLaunchGoal()
    , mHasCarrierTransportedUnit(false)
    , mPad55{}
    , mCarriedUnits()
  {}

  /**
   * Address: 0x00606E60 (FUN_00606E60, Moho::CUnitCarrierLaunch::CUnitCarrierLaunch)
   *
   * What it does:
   * Initializes one carrier-launch task from parent dispatch context, copies
   * launch-goal state, collects candidate carried units, and links the set
   * into the simulation registered-set lane.
   */
  CUnitCarrierLaunch::CUnitCarrierLaunch(
    CCommandTask* const parentTask,
    const SNavGoal& launchGoal,
    const SCommandUnitSet& commandUnits
  )
    : CCommandTask(parentTask)
    , mLaunchGoal(launchGoal)
    , mHasCarrierTransportedUnit(false)
    , mPad55{}
    , mCarriedUnits()
  {
    for (CScriptObject* const entry : commandUnits.mVec) {
      if (!SCommandUnitSet::IsUsableEntry(entry)) {
        continue;
      }

      Unit* const candidate = SCommandUnitSet::UnitFromEntry(entry);
      if (!candidate || candidate->IsDead() || candidate == mUnit) {
        continue;
      }

      Unit* const transportOwner = candidate->GetTransportedBy();
      if (!transportOwner) {
        continue;
      }

      mHasCarrierTransportedUnit = true;
      if (transportOwner == mUnit) {
        (void)mCarriedUnits.AddUnit(candidate);
      }
    }

    if (mUnit && mUnit->SimulationRef && mUnit->SimulationRef->mEntityDB) {
      mUnit->SimulationRef->mEntityDB->RegisterEntitySet(mCarriedUnits);
      mUnit->UnitStateMask |= kUnitStateMaskCarrierLaunch;
    }
  }

  /**
   * Address: 0x00606F90 (FUN_00606F90, Moho::CUnitCarrierLaunch::~CUnitCarrierLaunch)
   * Address: 0x00607450 (FUN_00607450, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   *
   * What it does:
   * Clears the carrier-launch unit-state bit before member/base teardown.
   */
  CUnitCarrierLaunch::~CUnitCarrierLaunch()
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~kUnitStateMaskCarrierLaunch;
    }
  }

  /**
   * Address: 0x00607680 (FUN_00607680, Moho::CUnitCarrierLaunch::operator new)
   *
   * What it does:
   * Allocates one carrier-launch task and forwards constructor arguments into
   * in-place construction.
   */
  CUnitCarrierLaunch* CUnitCarrierLaunch::Create(
    CCommandTask* const parentTask,
    const SNavGoal* const launchGoal,
    const SCommandUnitSet* const commandUnits
  )
  {
    void* const storage = ::operator new(sizeof(CUnitCarrierLaunch));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitCarrierLaunch(parentTask, *launchGoal, *commandUnits);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x00607000 (FUN_00607000, Moho::CUnitCarrierLaunch::TaskTick)
   *
   * IDA signature:
   * int __thiscall sub_607000(Moho::CUnitCarrierLaunch *this);
   *
   * What it does:
   * Drives the carrier-launch state machine across four cases:
   *
   *   TASKSTATE_Preparing: either confirms the ctor already populated the
   *     carried-unit set (mHasCarrierTransportedUnit + non-empty
   *     mCarriedUnits) or pulls stored units from the transport on first
   *     entry, then spawns a sibling CUnitCarrierRetrieve task to handle
   *     the unload phase and advances state. Returns 1 to keep the task
   *     queue running; returns -1 directly when mCarriedUnits is empty.
   *
   *   TASKSTATE_Waiting: converts the launch-goal cell into a world
   *     position via the unit's footprint, issues a Ground "Guard"
   *     command to the carried-unit set centered on that position with
   *     identity orientation (scale=1.0), resets the transport
   *     reservation, advances state. Returns 0.
   *
   *   TASKSTATE_Starting: pops the first carried unit, removes it from
   *     transport storage (capturing the unloaded transform), pushes the
   *     unloaded transform onto the unit and advances its coordinates
   *     twice to settle the change, then seeds CUnitMotion with an
   *     immediate velocity derived from the unloaded orientation scaled
   *     by the blueprint's maximum-speed field. Transitions to Processing
   *     when the carried-unit set is empty. Returns 3.
   *
   *   TASKSTATE_Processing (and the empty-carry shortcut): returns -1 to
   *     signal task completion to the dispatcher.
   *
   *   default: returns 1.
   */
  int CUnitCarrierLaunch::Execute()
  {
    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        if (mHasCarrierTransportedUnit) {
          // Carried set was seeded by the ctor from the command's units.
          // An empty set here means there is nothing to launch.
          if (mCarriedUnits.mVec.start_ == mCarriedUnits.mVec.end_) {
            return -1; // matches the binary's LABEL_4 / TASKSTATE_Processing exit
          }
        } else {
          // First entry: pull every unit currently stored inside the
          // transport into the carried set so subsequent ticks can
          // unload them one at a time. The binary calls the raw
          // `fastvector_Entity::AddAll`; the modern equivalent that
          // preserves element ordering and type safety is the
          // typed `AddUnits(const EntitySetTemplate<Unit>&)` helper.
          const EntitySetTemplate<Unit> stored = mUnit->AiTransport->TransportGetStoredUnits();
          mCarriedUnits.AddUnits(stored);
        }

        // Spawn the sibling retrieve task that drives the unload-and-
        // wait flow on the receiving side. The retrieve task is created
        // with an empty tracked-unit set; the Starting case populates
        // the binary's tracked set lazily as units are released.
        SEntitySetTemplateUnit emptyTracked{};
        (void)CUnitCarrierRetrieve::Create(this, emptyTracked);

        mTaskState = TASKSTATE_Waiting;
        return 1;
      }

      case TASKSTATE_Waiting: {
        // Convert the launch goal cell (mPos1.x0, mPos1.z0) into a world
        // position centered on the unit's footprint, then issue a Ground
        // "Guard" command to the carried-unit set at that position.
        SOCellPos launchCell{};
        launchCell.x = static_cast<std::int16_t>(mLaunchGoal.mPos1.x0);
        launchCell.z = static_cast<std::int16_t>(mLaunchGoal.mPos1.z0);

        const SFootprint& footprint = mUnit->GetFootprint();
        const Wm3::Vector3f worldPos = COORDS_ToWorldPos(
          mUnit->SimulationRef->mMapData,
          launchCell,
          footprint
        );

        SSTICommandIssueData command(EUnitCommandType::UNITCOMMAND_Guard);
        command.mTarget.mType = EAiTargetType::AITARGET_Ground;
        command.mTarget.mEnt = 0xF0000000u;
        command.mTarget.mPos.x = worldPos.x;
        command.mTarget.mPos.y = worldPos.y;
        command.mTarget.mPos.z = worldPos.z;
        command.unk38 = 0;
        command.mOri = Zeroed<Wm3::Quaternionf>();
        command.unk4C = 1.0f;

        (void)IssueCommandToSelectedUnits(mUnit->SimulationRef, mCarriedUnits, command, true);

        mTaskState = TASKSTATE_Starting;
        mUnit->AiTransport->TransportResetReservation();
        return 0;
      }

      case TASKSTATE_Starting: {
        Entity** const start = mCarriedUnits.mVec.start_;
        Entity** const end = mCarriedUnits.mVec.end_;
        if (start == end) {
          // No more units to launch; transition to the terminal state.
          mTaskState = TASKSTATE_Processing;
          return 3;
        }

        Unit* const next = (*start != nullptr) ? SEntitySetTemplateUnit::UnitFromEntry(*start) : nullptr;

        // Pop the first unit into a one-element tracked set (matches the
        // binary's transient v25/searchSlot pair).
        SEntitySetTemplateUnit firstUnit{};
        (void)firstUnit.AddUnit(next);

        // Capture the transform produced by removing the unit from the
        // transport so we can re-settle the unit at that pose. The binary
        // initializes the orient quaternion to identity (1,0,0,0) before
        // calling the transport, then overwrites with the result.
        VTransform unloadTransform{};
        unloadTransform.orient_.w = 1.0f;
        unloadTransform.orient_.x = 0.0f;
        unloadTransform.orient_.y = 0.0f;
        unloadTransform.orient_.z = 0.0f;
        unloadTransform.pos_ = Wm3::Vector3f{};
        mUnit->AiTransport->TransportRemoveFromStorage(next, unloadTransform);

        next->SetPendingTransform(unloadTransform, 1.0f);
        next->AdvanceCoords();
        next->AdvanceCoords();
        (void)mCarriedUnits.ContainsUnit(next); // matches the binary's containment probe

        // Compute initial velocity: (1 - 2*(qx*qx + qz*qz)) * blueprint.maxSpeed
        // along (qx, qy, qz). The quaternion encodes the spawn-facing
        // direction; this projects the "forward" axis onto world space.
        const float qx = unloadTransform.orient_.x;
        const float qz = unloadTransform.orient_.z;
        const float scale = 1.0f - ((qx * qx) + (qz * qz)) * 2.0f;
        const RUnitBlueprint* const blueprint = next->GetBlueprint();
        const float maxSpeed =
          *reinterpret_cast<const float*>(reinterpret_cast<const char*>(blueprint) + 880);

        Wm3::Vector3f velocity{};
        velocity.x = scale * maxSpeed;
        velocity.y = scale * maxSpeed;
        velocity.z = scale * maxSpeed;
        next->UnitMotion->SetImmediateVelocity(velocity, unloadTransform.orient_);

        return 3;
      }

      case TASKSTATE_Processing:
        return -1;

      default:
        return 1;
    }
  }

  /**
   * Address: 0x00608950 (FUN_00608950, Moho::CUnitCarrierLaunch::MemberDeserialize)
   *
   * What it does:
   * Deserializes the `CCommandTask` base, launch goal, launch-state bool, and
   * carried-unit set.
   */
  void CUnitCarrierLaunch::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), this, ownerRef);

    const gpg::RRef launchGoalOwnerRef{};
    archive->Read(CachedSNavGoalType(), &mLaunchGoal, launchGoalOwnerRef);
    archive->ReadBool(&mHasCarrierTransportedUnit);

    const gpg::RRef carriedUnitsOwnerRef{};
    archive->Read(CachedEntitySetTemplateUnitType(), &mCarriedUnits, carriedUnitsOwnerRef);
  }

  /**
   * Address: 0x00608A10 (FUN_00608A10, Moho::CUnitCarrierLaunch::MemberSerialize)
   *
   * What it does:
   * Serializes the `CCommandTask` base, launch goal, launch-state bool, and
   * carried-unit set.
   */
  void CUnitCarrierLaunch::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), this, ownerRef);

    const gpg::RRef launchGoalOwnerRef{};
    archive->Write(CachedSNavGoalType(), &mLaunchGoal, launchGoalOwnerRef);
    archive->WriteBool(mHasCarrierTransportedUnit);

    const gpg::RRef carriedUnitsOwnerRef{};
    archive->Write(CachedEntitySetTemplateUnitType(), &mCarriedUnits, carriedUnitsOwnerRef);
  }

  /**
   * Address: 0x00607F80 (FUN_00607F80)
   *
   * What it does:
   * Preserves one deserialize thunk lane for `CUnitCarrierLaunch` serializer
   * callback registration.
   */
  [[maybe_unused]] void CUnitCarrierLaunchMemberDeserializeAdapterLaneA(
    CUnitCarrierLaunch* const task,
    gpg::ReadArchive* const archive
  )
  {
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00608070 (FUN_00608070)
   * Address: 0x0060C990 (FUN_0060C990)
   *
   * What it does:
   * Alternate deserialize thunk lane for `CUnitCarrierLaunch` serializer
   * callback registration.
   */
  [[maybe_unused]] void CUnitCarrierLaunchMemberDeserializeAdapterLaneB(
    CUnitCarrierLaunch* const task,
    gpg::ReadArchive* const archive
  )
  {
    task->MemberDeserialize(archive);
  }
} // namespace moho

namespace
{
  /**
   * VFTABLE: 0x00E20118 (`??_7CUnitCarrierLaunchSerializer@Moho@@6B@`)
   * Also installed as: 0x00E20120 (`??_7?$SerSaveLoadHelper@VCUnitCarrierLaunch@Moho@@@gpg@@6B@`)
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CUnitCarrierLaunch>
   *
   * Binary layout: vtable@0x00 (`gpg::SerHelperBase`), intrusive link pair
   * @0x04-0x0B (`moho::TDatListItem`, inherited via `SerHelperBase`),
   * load/save callback lanes@0x0C-0x13. Total 0x14 bytes, matching every
   * other `SerHelperBase`-derived serializer in this codebase.
   */
  class CUnitCarrierLaunchSerializerHelperNode : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD02E0 (FUN_00BD02E0, dynamic initializer for the global
     * `CUnitCarrierLaunchSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields and installs process-exit
     * cleanup via `atexit`.
     */
    CUnitCarrierLaunchSerializerHelperNode();

    /**
     * Address: 0x006078B0 (FUN_006078B0, gpg::SerSaveLoadHelper<Moho::CUnitCarrierLaunch>::Init)
     *
     * What it does:
     * Resolves `CUnitCarrierLaunch` RTTI and installs this helper's
     * load/save callbacks into the reflected type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };
  static_assert(
    offsetof(CUnitCarrierLaunchSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "CUnitCarrierLaunchSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCarrierLaunchSerializerHelperNode, mSerSaveFunc) == 0x10,
    "CUnitCarrierLaunchSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(CUnitCarrierLaunchSerializerHelperNode) == 0x14,
    "CUnitCarrierLaunchSerializerHelperNode size must be 0x14"
  );

  CUnitCarrierLaunchSerializerHelperNode gCUnitCarrierLaunchSerializer;

  /**
   * Address: 0x00607620 (FUN_00607620)
   *
   * What it does:
   * Unlinks `CUnitCarrierLaunchSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  void UnlinkCUnitCarrierLaunchSerializerNodePrimary()
  {
    gCUnitCarrierLaunchSerializer.ResetLinks();
  }

  /**
   * Address: 0x00607650 (FUN_00607650)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitCarrierLaunchSerializer` helper storage.
   */
  [[maybe_unused]] void UnlinkCUnitCarrierLaunchSerializerNodeSecondary()
  {
    gCUnitCarrierLaunchSerializer.ResetLinks();
  }

  /**
   * Address: 0x006075D0 (FUN_006075D0, Moho::CUnitCarrierLaunchSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `CUnitCarrierLaunch`. Forwards the
   * reflected object pointer to `CUnitCarrierLaunch::MemberDeserialize`;
   * `version` and the owner-ref lane are unused by the member (mirrors the
   * binary tail call).
   */
  void DeserializeCUnitCarrierLaunchSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitCarrierLaunch*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006075E0 (FUN_006075E0, Moho::CUnitCarrierLaunchSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `CUnitCarrierLaunch`. Forwards the
   * reflected object pointer to `CUnitCarrierLaunch::MemberSerialize`;
   * `version` and the owner-ref lane are unused by the member (mirrors the
   * binary tail call).
   */
  void SerializeCUnitCarrierLaunchSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitCarrierLaunch*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BF9A50 (FUN_00BF9A50, Moho::CUnitCarrierLaunchSerializer::~CUnitCarrierLaunchSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the `CUnitCarrierLaunchSerializer` helper
   * node, matching the sibling unlink lanes used across other serializer
   * registrars.
   */
  void cleanup_CUnitCarrierLaunchSerializer_atexit()
  {
    UnlinkCUnitCarrierLaunchSerializerNodePrimary();
  }

  CUnitCarrierLaunchSerializerHelperNode::CUnitCarrierLaunchSerializerHelperNode()
    : mSerLoadFunc(&DeserializeCUnitCarrierLaunchSerializerCallback)
    , mSerSaveFunc(&SerializeCUnitCarrierLaunchSerializerCallback)
  {
    (void)std::atexit(&cleanup_CUnitCarrierLaunchSerializer_atexit);
  }

  void CUnitCarrierLaunchSerializerHelperNode::Init()
  {
    gpg::RType* const type = CachedCUnitCarrierLaunchType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }
} // namespace
