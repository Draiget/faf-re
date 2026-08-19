#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Box3.h"
#include "moho/entity/Entity.h"
#include "moho/misc/Listener.h"
#include "moho/path/SNavGoal.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/ECommandEvent.h"

namespace gpg
{
  class RRef;
  class RType;
}

namespace moho
{
  class CCommandTask;
  class CUnitCommand;
  class Entity;
  class IAiCommandDispatchImpl;
  class IFormationInstance;

  /**
   * Layout-only carrier for the `CUnitCommand*` slot that sits between
   * `CCommandTask` and the first `Listener<T>` base (complete-object +0x30).
   * Multiple inheritance lays out non-virtual bases back-to-back in
   * declaration order, so this 4-byte base positions
   * `Listener<ECommandEvent>` at exactly +0x34.
   */
  struct CUnitPatrolTaskCommandSlot
  {
    CUnitCommand* mFirstCommand = nullptr; // +0x00 (complete-object +0x30)
  };
  static_assert(sizeof(CUnitPatrolTaskCommandSlot) == 0x04, "CUnitPatrolTaskCommandSlot size must be 0x04");

  /**
   * Layout-only carrier for the reserved dword between the two `Listener<T>`
   * bases (complete-object +0x40), positioning `Listener<EFormationdStatus>`
   * at exactly +0x44.
   */
  struct CUnitPatrolTaskReservedSlot
  {
    std::uint32_t mReserved40 = 0u; // +0x00 (complete-object +0x40)
  };
  static_assert(sizeof(CUnitPatrolTaskReservedSlot) == 0x04, "CUnitPatrolTaskReservedSlot size must be 0x04");

  /**
   * Runtime owner for the patrol/target command task.
   *
   * Layout recovered from the two constructors (default `FUN_0061B0B0`,
   * arg `FUN_0061AE50`) and the four behavior bodies (`FUN_0061B610`,
   * `FindTarget` `FUN_0061B710`, `FUN_0061B9C0`, `TaskTick` `FUN_0061C130`).
   * The binary object derives `CCommandTask` and multiply-inherits
   * `Listener<ECommandEvent>` (+0x34) and `Listener<EFormationdStatus>`
   * (+0x44), each real secondary vtables dispatched through their own
   * `OnEvent` override, plus a per-army `EntitySetTemplate<Entity>`
   * membership node. Complete-object size stays 0xF0.
   *
   * VFTABLE: `CUnitPatrolTask` primary vtable (TaskTick == CTask::Execute slot 1).
   */
  class CUnitPatrolTask
    : public CCommandTask
    , public CUnitPatrolTaskCommandSlot
    , public Listener<ECommandEvent>
    , public CUnitPatrolTaskReservedSlot
    , public Listener<EFormationdStatus>
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0061B0B0 (FUN_0061B0B0, Moho::CUnitPatrolTask::CUnitPatrolTask default ctor)
     *
     * What it does:
     * Default-constructs one patrol-task lane. Publishes the task/listener
     * vtables, self-links the two listener intrusive nodes and the embedded
     * `EntitySetTemplate<Entity>` membership node, and zero-clears the goal /
     * flag / search-box payload. Used by the SerConstruct reflection callback
     * (FUN_0061AD10) which then deserializes payload fields via the archive
     * `Read` path.
     */
    CUnitPatrolTask() noexcept;

    /**
     * Address: 0x0061AE50 (FUN_0061AE50, Moho::CUnitPatrolTask::CUnitPatrolTask)
     *
     * What it does:
     * Initializes one patrol-task lane from dispatch context, goal payload,
     * optional formation instance, and formation-mode flag.
     */
    CUnitPatrolTask(
      CCommandTask* dispatchTask,
      const void* goalPayload,
      IFormationInstance* formationInstance,
      bool inFormation
    );

    /**
     * Address: 0x0061B140 (FUN_0061B140, Moho::CUnitPatrolTask::~CUnitPatrolTask)
     * Mangled: ??1CUnitPatrolTask@Moho@@QAE@@Z
     *
     * IDA signature:
     * void __thiscall Moho::CUnitPatrolTask::~CUnitPatrolTask(Moho::CUnitPatrolTask *this);
     *
     * What it does:
     * Complete-object destructor. In binary order: (1) unconditionally unlink the
     * command-event listener lane; (2) if the owner unit still has a navigator,
     * stop honoring its formation, and abort the active move when the current
     * and previous positions compare equal; (3) when a formation instance
     * is bound, unlink the formation-status listener lane; (4) clear the owner
     * unit's two patrol move-state bits (0x2000000 and 0x1000) in `UnitStateMask`;
     * (5) reset the owner unit's `GuardedPos` to the zero vector. The embedded
     * `EntitySetTemplate<Entity>` membership node and the final listener relinks
     * are torn down implicitly by the C++ destructor. Base `CCommandTask`
     * teardown runs implicitly after this body.
     *
     * The MSVC per-sub-object vtable restores at the binary head/tail are dead
     * stores to the dying object's own memory and carry no observable side
     * effect; they are expressed implicitly by the C++ destructor and are not
     * reproduced as raw vtable-address writes. Because this dtor is virtual, the
     * vtable slot-0 scalar-deleting destructor (FUN_0061B090) is MSVC
     * auto-generated and needs no hand-written body.
     */
    ~CUnitPatrolTask() override;

    /**
     * Address: 0x0061C480 (FUN_0061C480, Moho::CUnitPatrolTask::operator new)
     *
     * What it does:
     * Allocates one patrol-task object and forwards constructor arguments into
     * in-place construction.
     */
    [[nodiscard]] static CUnitPatrolTask* Create(
      CCommandTask* dispatchTask,
      const void* goalPayload,
      bool inFormation
    );

    /**
     * Address: 0x0061C4E0 (FUN_0061C4E0, Moho::CUnitPatrolTask::operator new `_0` overload)
     * Mangled: ??2CUnitPatrolTask@Moho@@QAE@@Z_0
     *
     * What it does:
     * Formation-instance allocation overload. Called by
     * `IAiCommandDispatchImpl::DispatchTask` when the task dispatch lane has
     * an existing `IFormationInstance` to bind rather than a simple
     * "in-formation" flag. Allocates 0xF0 bytes and in-place constructs with
     * the formation-instance lane set and `inFormation=false`.
     */
    [[nodiscard]] static CUnitPatrolTask* CreateWithFormation(
      CCommandTask* dispatchTask,
      const void* goalPayload,
      IFormationInstance* formationInstance
    );

    /**
     * Address: 0x0061C130 (FUN_0061C130, Moho::CUnitPatrolTask::TaskTick)
     *
     * IDA signature:
     * int __thiscall TaskTick(Moho::CUnitPatrolTask* this);
     *
     * VFTable SLOT: 1 (CTask::Execute)
     *
     * What it does:
     * Advances one patrol tick: refuel/repair-platform handoff, best-enemy
     * attack handoff, patrol reclaim/attack evaluation, and navigator goal
     * resubmission. Returns a scheduler status word (7 = wait, -1 = done).
     */
    int Execute() override;

    /**
     * Address: 0x0061C3E0 (FUN_0061C3E0, Moho::CUnitPatrolTask::OnEvent)
     * Primary vtable: `Listener<ECommandEvent>` secondary slot 1
     * (`??_7CUnitPatrolTask@Moho@@6B?$Listener@W4ECommandEvent@Moho@@@Moho@@@` + 0x04).
     *
     * What it does:
     * Rebuilds `mGoal` as a 1-cell rect around the bound command's resolved
     * cell position (`CUnitCommand::GetPosition(mBoundCommand, mUnit, ...)`):
     * `{minX=cellX, minZ=cellZ, maxX=cellX+1, maxZ=cellZ+1}` with the
     * remaining five aux dwords zeroed. When the owner unit still has a
     * navigator and the task is mid-move, pushes the new goal
     * (`AiNavigator->SetGoal(mGoal)`). Always finishes by rebuilding the
     * search box (`RecomputePatrolSearchBox`).
     */
    void OnEvent(ECommandEvent event) override;

    /**
     * Address: 0x0061C470 (FUN_0061C470, Moho::CUnitPatrolTask::OnEvent)
     * Primary vtable: `Listener<EFormationdStatus>` secondary slot 1
     * (`??_7CUnitPatrolTask@Moho@@6B?$Listener@W4EFormationdStatus@Moho@@@Moho@@@` + 0x04).
     *
     * What it does:
     * Sets `mNavStalled` when the formation reports it has reached its goal
     * (`event == FORMATIONSTATUS_FormationAtGoal`); ignores every other
     * status.
     */
    void OnEvent(EFormationdStatus event) override;

    /**
     * Address: 0x0061CF50 (FUN_0061CF50, Moho::CUnitPatrolTask::MemberDeserialize)
     *
     * IDA signature:
     * void __usercall MemberDeserialize(CUnitPatrolTask* this@<ecx>, gpg::ReadArchive* archive@<eax>);
     *
     * What it does:
     * Loads patrol-task state from an archive in binary lane order: the base
     * `CCommandTask` sub-object (by reflected type), the dispatch / formation
     * binding / formation instance pointer lanes, the navigator goal payload,
     * the three boolean state flags, the search box, the tick counter, and the
     * per-army membership node.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0061D0C0 (FUN_0061D0C0, Moho::CUnitPatrolTask::MemberSerialize)
     *
     * IDA signature:
     * void __usercall MemberSerialize(CUnitPatrolTask* this@<eax>, gpg::WriteArchive* archive@<esi>);
     *
     * What it does:
     * Line-for-line mirror of `MemberDeserialize`: saves the same field set in
     * the same order using the reflection write path, `RRef_*` + WriteRawPointer
     * for the tracked pointer lanes, and the virtual `WriteBool`/`WriteInt`
     * archive slots for the scalar lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

  private:
    /**
     * Address: 0x0061B710 (FUN_0061B710, Moho::CUnitPatrolTask::FindTarget)
     *
     * What it does:
     * Collects in-range blips that overlap the patrol search box, then asks the
     * owner attacker for the best enemy within guard-scan radius. Returns that
     * enemy entity, or null.
     */
    [[nodiscard]] Entity* FindTarget();

    /**
     * Address: 0x0061B9C0 (FUN_0061B9C0)
     *
     * What it does:
     * Scores COGrid entities within the patrol search box for reclaim/attack
     * handling. Applies the PATROLHELPER/COMMAND/SACU_BEHAVIOR gates, the army
     * no-rush zone, per-entity alliance/reclaimable checks, map-bounds and
     * guard-return-radius gating, and returns the nearest weighted candidate
     * entity, or null when none qualifies.
     */
    [[nodiscard]] Entity* EvaluatePatrolReclaimAttack();

    /**
     * Address: 0x0061B2F0 (FUN_0061B2F0, Moho::CUnitPatrolTask::RecomputePatrolSearchBox)
     *
     * IDA signature:
     * void __stdcall RecomputePatrolSearchBox(Moho::CUnitPatrolTask* this);
     *
     * What it does:
     * Rebuilds the oriented world-space `mSearchBox` (Wm3::Box3f) covering the
     * patrol leg. Resolves the queue front command and (when the tail command is
     * a Patrol/FormPatrol family, type 16/18) the queue back command to two
     * world positions via `COORDS_ToWorldPos` using the owner unit's footprint
     * layer/size. Builds the leg direction (front minus tail, y flattened),
     * normalizes it (or falls back to `+Z` below the 0.001 length threshold),
     * rotates it 90 degrees about Y (the shared `kSearchBoxYawQuat`) to form the
     * lateral axis, and fills the box: center is the leg midpoint, axes are
     * `{lateral, +Y, direction}`, and extents are
     * `{guardScanRadius, 100.0, guardScanRadius + legHalfLength}` where
     * `guardScanRadius = GetBlueprint()->AI.GuardScanRadius`. The leg-start cell
     * comes from the bound patrol command (`mBoundCommand`); the leg-end cell
     * from the queue-tail command only when it is a distinct Patrol/FormPatrol.
     */
    void RecomputePatrolSearchBox();

  public:
    // --- Derived fields (replace the former opaque mPadding[0xF0]) ---
    //
    // 0x30 (mFirstCommand), 0x34 (Listener<ECommandEvent>), 0x40 (reserved),
    // and 0x44 (Listener<EFormationdStatus>) now come from the base-class
    // chain declared above - see CUnitPatrolTaskCommandSlot,
    // CUnitPatrolTaskReservedSlot, and the two Listener<T> bases.

    // 0x50: dispatch owner used to issue refuel/reclaim/attack/repair sub-tasks.
    IAiCommandDispatchImpl* mDispatch;

    // 0x54: the patrol command this task is bound to - the queue-head command at
    // construction time, and the leg-start reference every search-box rebuild
    // resolves through `CUnitCommand::GetPosition`.
    CUnitCommand* mBoundCommand;

    // 0x58: bound formation instance (null when patrolling without a formation).
    IFormationInstance* mFormationInstance;

    // 0x5C: navigator goal rectangle payload (copied from ctor goal argument).
    SNavGoal mGoal;

    // 0x80: task has an active navigator move in flight.
    bool mMoving;
    // 0x81: navigator reported a stall on the current move.
    bool mNavStalled;
    // 0x82: task is operating in formation-follow mode.
    bool mInFormation;
    std::uint8_t mPad83;

    // 0x84: world-space search box used for the patrol reclaim/attack query.
    Wm3::Box3f mSearchBox;

    // 0xC0: per-tick counter (incremented every tick; patrol-arrival gate uses > 3).
    std::int32_t mTickCounter;
    std::uint8_t mPadC4[4];

    // 0xC8: per-army entity-membership node (`v29`): an intrusive
    // `EntitySetTemplate<Entity>` linked into `mUnit->mSim->mEntityDB`.
    // (This is the +0xC8..0xF0 union: the default ctor self-links this node and
    // the arg ctor links it into the sim entity DB; it is NOT a goal-payload
    // copy — the goal lives at mGoal@0x5C.)
    EntitySetTemplate<Entity> mMembership;
  };

  static_assert(sizeof(CUnitPatrolTask) == 0xF0, "CUnitPatrolTask size must be 0xF0");
  // The four-base chain (CCommandTask + CommandSlot + Listener<ECommandEvent>
  // + ReservedSlot + Listener<EFormationdStatus>) must land mDispatch, the
  // first genuinely non-standard-layout member, at exactly +0x50 - offsetof
  // on a member from a non-first base is not portable, so this checks the
  // running byte total the same way instead.
  static_assert(
    sizeof(CCommandTask) + sizeof(CUnitPatrolTaskCommandSlot) + sizeof(Listener<ECommandEvent>)
        + sizeof(CUnitPatrolTaskReservedSlot) + sizeof(Listener<EFormationdStatus>)
      == 0x50,
    "CUnitPatrolTask base-class chain must total 0x50 bytes"
  );
  static_assert(offsetof(CUnitPatrolTask, mDispatch) == 0x50, "CUnitPatrolTask::mDispatch offset must be 0x50");
  static_assert(
    offsetof(CUnitPatrolTask, mBoundCommand) == 0x54, "CUnitPatrolTask::mBoundCommand offset must be 0x54"
  );
  static_assert(
    offsetof(CUnitPatrolTask, mFormationInstance) == 0x58, "CUnitPatrolTask::mFormationInstance offset must be 0x58"
  );
  static_assert(offsetof(CUnitPatrolTask, mGoal) == 0x5C, "CUnitPatrolTask::mGoal offset must be 0x5C");
  static_assert(offsetof(CUnitPatrolTask, mMoving) == 0x80, "CUnitPatrolTask::mMoving offset must be 0x80");
  static_assert(offsetof(CUnitPatrolTask, mNavStalled) == 0x81, "CUnitPatrolTask::mNavStalled offset must be 0x81");
  static_assert(offsetof(CUnitPatrolTask, mInFormation) == 0x82, "CUnitPatrolTask::mInFormation offset must be 0x82");
  static_assert(offsetof(CUnitPatrolTask, mSearchBox) == 0x84, "CUnitPatrolTask::mSearchBox offset must be 0x84");
  static_assert(offsetof(CUnitPatrolTask, mTickCounter) == 0xC0, "CUnitPatrolTask::mTickCounter offset must be 0xC0");
  static_assert(offsetof(CUnitPatrolTask, mMembership) == 0xC8, "CUnitPatrolTask::mMembership offset must be 0xC8");
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
  gpg::RRef* RRef_CUnitPatrolTask(gpg::RRef* outRef, moho::CUnitPatrolTask* value);

  /**
   * Address: 0x0061CBF0 (FUN_0061CBF0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitPatrolTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitPatrolTaskRef(gpg::RRef* outRef, moho::CUnitPatrolTask* value);
} // namespace gpg
