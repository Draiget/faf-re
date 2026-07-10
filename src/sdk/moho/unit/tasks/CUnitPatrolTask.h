#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Box3.h"
#include "moho/entity/Entity.h"
#include "moho/path/SNavGoal.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/Broadcaster.h"

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
   * Layout-compatible embedded listener sub-object slot.
   *
   * In the binary `CUnitPatrolTask` multiply-inherits `Listener<ECommandEvent>`
   * and `Listener<EFormationdStatus>` and overrides their `OnEvent` receivers.
   * The abstract `Listener<T>` template cannot be a concrete member, so the two
   * intrusive slots are modeled here as a byte-for-byte-identical concrete
   * struct (secondary vtable pointer + self-linked `Broadcaster` node). The
   * default ctor self-links the node exactly like the binary
   * (`a1+56/60`, `a1+72/76`).
   */
  struct CUnitPatrolListenerSlot
  {
    void* mVftable = nullptr; // +0x00 secondary Listener<T> vtable pointer
    Broadcaster mListenerLink; // +0x04 self-linked broadcaster node
  };
  static_assert(sizeof(CUnitPatrolListenerSlot) == 0x0C, "CUnitPatrolListenerSlot size must be 0x0C");
  static_assert(
    offsetof(CUnitPatrolListenerSlot, mListenerLink) == 0x04, "CUnitPatrolListenerSlot::mListenerLink offset must be 0x04"
  );

  /**
   * Runtime owner for the patrol/target command task.
   *
   * Layout recovered from the two constructors (default `FUN_0061B0B0`,
   * arg `FUN_0061AE50`) and the four behavior bodies (`FUN_0061B610`,
   * `FindTarget` `FUN_0061B710`, `FUN_0061B9C0`, `TaskTick` `FUN_0061C130`).
   * The binary object derives `CCommandTask` and embeds two intrusive
   * `Listener<...>` sub-objects plus a per-army `EntitySetTemplate<Entity>`
   * membership node. Complete-object size stays 0xF0.
   *
   * VFTABLE: `CUnitPatrolTask` primary vtable (TaskTick == CTask::Execute slot 1).
   */
  class CUnitPatrolTask : public CCommandTask
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

  public:
    // --- Derived fields (replace the former opaque mPadding[0xF0]) ---

    // 0x30: first live command lane resolved from the unit command queue
    // (`v0` in the ctor: mCommandQueue front command, or null).
    CUnitCommand* mFirstCommand;

    // 0x34: intrusive command-event listener sub-object (vtable + broadcaster node).
    CUnitPatrolListenerSlot mCommandEventListener;

    // 0x40: reserved dword between the two listener sub-objects.
    std::uint32_t mReserved40;

    // 0x44: intrusive formation-status listener sub-object.
    CUnitPatrolListenerSlot mFormationStatusListener;

    // 0x50: dispatch owner used to issue refuel/reclaim/attack/repair sub-tasks.
    IAiCommandDispatchImpl* mDispatch;

    // 0x54: formation binding lane (derived from the owner's formation cache).
    void* mFormationBinding;

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
  static_assert(offsetof(CUnitPatrolTask, mFirstCommand) == 0x30, "CUnitPatrolTask::mFirstCommand offset must be 0x30");
  static_assert(
    offsetof(CUnitPatrolTask, mCommandEventListener) == 0x34,
    "CUnitPatrolTask::mCommandEventListener offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitPatrolTask, mFormationStatusListener) == 0x44,
    "CUnitPatrolTask::mFormationStatusListener offset must be 0x44"
  );
  static_assert(offsetof(CUnitPatrolTask, mDispatch) == 0x50, "CUnitPatrolTask::mDispatch offset must be 0x50");
  static_assert(
    offsetof(CUnitPatrolTask, mFormationBinding) == 0x54, "CUnitPatrolTask::mFormationBinding offset must be 0x54"
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
