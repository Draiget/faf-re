#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/Listener.h"
#include "moho/misc/WeakPtr.h"
#include "moho/path/SNavGoal.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/ECommandEvent.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class RType;
  class WriteArchive;
}

namespace moho
{
  class CUnitCommand;
  enum class EUnitCommandType : std::int32_t;
  enum EAiNavigatorEvent : std::int32_t;
  enum EFormationdStatus : std::int32_t;
  struct SOCellPos;

  /**
   * Layout-only carrier for the reserved dword between `CCommandTask` and the
   * first `Listener<T>` base (complete-object +0x30). Multiple inheritance
   * lays out non-virtual bases back-to-back in declaration order, so this
   * 4-byte base positions `Listener<EAiNavigatorEvent>` at exactly +0x34.
   */
  struct CUnitMoveTaskReservedSlot30
  {
    std::uint32_t mUnknown0030 = 0u; // +0x00 (complete-object +0x30)
  };
  static_assert(sizeof(CUnitMoveTaskReservedSlot30) == 0x04, "CUnitMoveTaskReservedSlot30 size must be 0x04");

  /**
   * Layout-only carrier for the reserved dword between
   * `Listener<EAiNavigatorEvent>` and `Listener<EFormationdStatus>`
   * (complete-object +0x40), positioning `Listener<EFormationdStatus>` at
   * exactly +0x44.
   */
  struct CUnitMoveTaskReservedSlot40
  {
    std::uint32_t mUnknown0040 = 0u; // +0x00 (complete-object +0x40)
  };
  static_assert(sizeof(CUnitMoveTaskReservedSlot40) == 0x04, "CUnitMoveTaskReservedSlot40 size must be 0x04");

  /**
   * Layout-only carrier for the reserved dword between
   * `Listener<EFormationdStatus>` and `Listener<ECommandEvent>`
   * (complete-object +0x50), positioning `Listener<ECommandEvent>` at
   * exactly +0x54.
   */
  struct CUnitMoveTaskReservedSlot50
  {
    std::uint32_t mUnknown0050 = 0u; // +0x00 (complete-object +0x50)
  };
  static_assert(sizeof(CUnitMoveTaskReservedSlot50) == 0x04, "CUnitMoveTaskReservedSlot50 size must be 0x04");

  class CUnitMoveTask
    : public CCommandTask
    , public CUnitMoveTaskReservedSlot30
    , public Listener<EAiNavigatorEvent>
    , public CUnitMoveTaskReservedSlot40
    , public Listener<EFormationdStatus>
    , public CUnitMoveTaskReservedSlot50
    , public Listener<ECommandEvent>
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0061A750 (FUN_0061A750)
     *
     * What it does:
     * Deserializes move-task runtime state (base command-task lane, dispatch
     * command pointer, move goal, command weak-link lane, and state flags).
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0061A880 (FUN_0061A880)
     *
     * What it does:
     * Serializes move-task runtime state (base command-task lane, dispatch
     * command pointer, move goal, command weak-link lane, and state flags).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00618030 (FUN_00618030, Moho::CUnitMoveTask::CUnitMoveTask)
     *
     * What it does:
     * Initializes one detached move-task with self-linked listener nodes and
     * empty dispatch/goal/command lanes.
     */
    CUnitMoveTask();

    /**
     * Address: 0x006180E0 (FUN_006180E0, Moho::CUnitMoveTask::CUnitMoveTask)
     *
     * What it does:
     * Initializes move-task dispatch state, links navigator-listener lane, and
     * seeds one initial movement goal from command/target context.
     */
    CUnitMoveTask(
      CCommandTask* dispatchTask,
      const SNavGoal& moveGoal,
      std::uint8_t requiresTransportCategoryCheck,
      CUnitCommand* sourceCommand,
      std::uint8_t moveVariant
    );

    /**
     * Address: 0x00618700 (FUN_00618700, Moho::CUnitMoveTask::~CUnitMoveTask)
     * Mangled: ??1CUnitMoveTask@Moho@@QAE@XZ
     *
     * IDA signature:
     * void __thiscall Moho::CUnitMoveTask::~CUnitMoveTask(Moho::CUnitMoveTask *this);
     *
     * What it does:
     * Complete-object destructor. Detaches all three intrusive listener lanes
     * (command-event, formation-status, navigator), splices the ferry-transport
     * weak link and the command weak reference out of their owner chains, clears
     * the owner unit's move-in-progress state bit, and re-derives the
     * next-command instant flag before running base command-task teardown.
     */
    ~CUnitMoveTask() override;

    /**
     * Address: 0x00618A00 (FUN_00618A00, sub_618A00)
     *
     * What it does:
     * Returns true when the unit is in a single-command lane suitable for
     * dynamic target-position move-goal derivation.
     */
    [[nodiscard]] bool ShouldUseCurrentCommandTargetPosition() const;

    /**
     * Address: 0x00618A70 (FUN_00618A70, Moho::CUnitMoveTask::OnEvent)
     *
     * What it does:
     * Issues a follow-up call-transport task once for the owning unit when
     * ferry-assigned transport context is valid, and unlinks the navigator
     * listener lane before dispatching.
     */
    int Execute() override;

    /**
     * Address: 0x00618BB0 (FUN_00618BB0, Moho::CUnitMoveTask::OnEvent)
     * Primary vtable: `Listener<EAiNavigatorEvent>` secondary slot 0
     * (`??_7CUnitMoveTask@Moho@@6B?$Listener@W4EAiNavigatorEvent@Moho@@@Moho@@@`).
     *
     * What it does:
     * Applies navigator-event result transitions, clears instant-command lane,
     * and resumes owner-thread execution immediately.
     */
    void OnEvent(EAiNavigatorEvent event) override;

    /**
     * Address: 0x00618C30 (FUN_00618C30, nullsub_54)
     * Primary vtable: `Listener<EFormationdStatus>` secondary slot 0
     * (`??_7CUnitMoveTask@Moho@@6B?$Listener@W4EFormationdStatus@Moho@@@Moho@@@`).
     *
     * What it does:
     * Intentional no-op; `CUnitMoveTask` does not react to formation-status
     * events (unlike sibling command tasks such as `CUnitPatrolTask`).
     */
    void OnEvent(EFormationdStatus event) override;

    /**
     * Address: 0x00618C40 (FUN_00618C40, Moho::CUnitMoveTask::OnEvent)
     * Primary vtable: `Listener<ECommandEvent>` secondary slot 0
     * (`??_7CUnitMoveTask@Moho@@6B?$Listener@W4ECommandEvent@Moho@@@Moho@@@`).
     *
     * What it does:
     * Rebuilds `mMoveGoal` from the bound command whenever this task is not
     * itself a ferry-transport move variant (`mMoveVariant == 0`), the unit
     * still has a navigator, and the command weak reference still resolves.
     * When the task has already prepared a dynamic (target-tracking) goal
     * (`mHasPreparedDynamicGoal`), re-derives the goal from the command's live
     * world position: coerces it through `Unit::PrepareMove` (honoring the
     * owning army's whole-map override), re-samples the footprint-relative
     * cell from the adjusted position, and - when this task still holds an
     * O-grid occupancy reservation - re-reserves it at the new position.
     * Otherwise takes the simpler static path: derives the goal directly from
     * the command's cell position with no whole-map/occupancy handling. Both
     * paths push the rebuilt goal to the unit's navigator. `mMoveGoal.mLayer`
     * is preserved across the dynamic-path rebuild.
     */
    void OnEvent(ECommandEvent event) override;

  public:
    CCommandTask* mDispatchTask; // 0x60
    SNavGoal mMoveGoal; // 0x64
    WeakPtr<CUnitCommand> mCommandRef; // 0x88
    std::uint8_t mNextCmdIsInstant; // 0x90
    std::uint8_t mRequiresTransportCategoryCheck; // 0x91
    std::uint8_t mIsOccupying; // 0x92
    std::uint8_t mTransportDispatchIssued; // 0x93
    std::uint8_t mMoveVariant; // 0x94
    std::uint8_t mHasPreparedDynamicGoal; // 0x95
    std::uint8_t mPad_0096_0098[2]; // 0x96
  };

  static_assert(sizeof(CUnitMoveTask) == 0x98, "CUnitMoveTask size must be 0x98");
  // The seven-base chain (CCommandTask + ReservedSlot30 + Listener<EAiNavigatorEvent>
  // + ReservedSlot40 + Listener<EFormationdStatus> + ReservedSlot50 +
  // Listener<ECommandEvent>) must land mDispatchTask, the first genuinely
  // non-standard-layout member, at exactly +0x60 - offsetof on a member from a
  // non-first base is not portable, so this checks the running byte total instead.
  static_assert(
    sizeof(CCommandTask) + sizeof(CUnitMoveTaskReservedSlot30) + sizeof(Listener<EAiNavigatorEvent>)
        + sizeof(CUnitMoveTaskReservedSlot40) + sizeof(Listener<EFormationdStatus>)
        + sizeof(CUnitMoveTaskReservedSlot50) + sizeof(Listener<ECommandEvent>)
      == 0x60,
    "CUnitMoveTask base-class chain must total 0x60 bytes"
  );
  static_assert(offsetof(CUnitMoveTask, mDispatchTask) == 0x60, "CUnitMoveTask::mDispatchTask offset must be 0x60");
  static_assert(offsetof(CUnitMoveTask, mMoveGoal) == 0x64, "CUnitMoveTask::mMoveGoal offset must be 0x64");
  static_assert(offsetof(CUnitMoveTask, mCommandRef) == 0x88, "CUnitMoveTask::mCommandRef offset must be 0x88");
  static_assert(offsetof(CUnitMoveTask, mNextCmdIsInstant) == 0x90, "CUnitMoveTask::mNextCmdIsInstant offset must be 0x90");
  static_assert(
    offsetof(CUnitMoveTask, mRequiresTransportCategoryCheck) == 0x91,
    "CUnitMoveTask::mRequiresTransportCategoryCheck offset must be 0x91"
  );
  static_assert(
    offsetof(CUnitMoveTask, mIsOccupying) == 0x92,
    "CUnitMoveTask::mIsOccupying offset must be 0x92"
  );
  static_assert(
    offsetof(CUnitMoveTask, mTransportDispatchIssued) == 0x93,
    "CUnitMoveTask::mTransportDispatchIssued offset must be 0x93"
  );
  static_assert(offsetof(CUnitMoveTask, mMoveVariant) == 0x94, "CUnitMoveTask::mMoveVariant offset must be 0x94");
  static_assert(
    offsetof(CUnitMoveTask, mHasPreparedDynamicGoal) == 0x95,
    "CUnitMoveTask::mHasPreparedDynamicGoal offset must be 0x95"
  );

  /**
   * Address: 0x006189C0 (FUN_006189C0, Moho::CommandIsInstant)
   *
   * What it does:
   * Returns whether one unit command type is treated as an instant command lane
   * by move-task teardown/relink logic.
   */
  [[nodiscard]] bool CommandIsInstant(EUnitCommandType commandType) noexcept;

  /**
   * Address: 0x006190A0 (FUN_006190A0, Moho::NewMoveTask)
   *
   * What it does:
   * Sets one navigator goal for `dispatchTask->mUnit`, then allocates and
   * constructs one `CUnitMoveTask` when navigator state is available.
   */
  void NewMoveTask(
    const SNavGoal& goal,
    CCommandTask* dispatchTask,
    std::uint8_t requiresTransportCategoryCheck,
    CUnitCommand* sourceCommand,
    std::uint8_t moveVariant
  );

  /**
   * Address: 0x0061A3C0 (FUN_0061A3C0)
   *
   * What it does:
   * Thin alias lane that forwards one `(task, archive)` pair into
   * `CUnitMoveTask::MemberSerialize`.
   */
  void CUnitMoveTaskMemberSerializeAlias(const CUnitMoveTask* task, gpg::WriteArchive* archive);
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0061A3F0 (FUN_0061A3F0, gpg::RRef_CUnitMoveTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitMoveTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitMoveTask(gpg::RRef* outRef, moho::CUnitMoveTask* value);

  /**
   * Address: 0x0061A350 (FUN_0061A350)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitMoveTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitMoveTaskRef(gpg::RRef* outRef, moho::CUnitMoveTask* value);
} // namespace gpg
