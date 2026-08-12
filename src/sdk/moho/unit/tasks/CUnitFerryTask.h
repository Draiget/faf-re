#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RRef;
  class RType;
}

namespace moho
{
  class CUnitCommand;
  class IAiCommandDispatchImpl;
  struct SEntitySetTemplateUnit;
  class Unit;

  /**
   * Runtime owner for ferry task command lanes.
   */
  class CUnitFerryTask : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0060E2C0 (FUN_0060E2C0, Moho::CUnitFerryTask::~CUnitFerryTask)
     *
     * What it does:
     * Aborts active navigation for the owner unit, clears ferry-task state bits,
     * and unlinks ferry/beacon weak-reference lanes before base-task teardown.
     */
    ~CUnitFerryTask() override;

    /**
     * Address: 0x0060DD70 (FUN_0060DD70, Moho::CUnitFerryTask::CUnitFerryTask)
     *
     * What it does:
     * Initializes one ferry task from dispatch + world-position context,
     * snapshots transport-load state, and binds current ferry-beacon command
     * ownership when present.
     */
    CUnitFerryTask(IAiCommandDispatchImpl* dispatch, const Wm3::Vector3f& ferryPosition);

    /**
     * Address: 0x0060DFC0 (FUN_0060DFC0, Moho::CUnitFerryTask::CUnitFerryTask)
     *
     * What it does:
     * Initializes one ferry-task lane from parent command-task and target-unit
     * payload context.
     */
    CUnitFerryTask(CCommandTask* parentTask, Unit* targetUnit);

    /**
     * Address: 0x0060F790 (FUN_0060F790, Moho::CUnitFerryTask::operator new)
     *
     * What it does:
     * Allocates one ferry-task object and forwards dispatch-position context
     * into in-place construction.
     */
    [[nodiscard]] static CUnitFerryTask* CreateFromDispatch(
      IAiCommandDispatchImpl* dispatch,
      const Wm3::Vector3f& ferryPosition
    );

    /**
     * Address: 0x0060F7E0 (FUN_0060F7E0, Moho::CUnitFerryTask::operator new)
     *
     * What it does:
     * Allocates one ferry-task object and forwards constructor arguments into
     * in-place construction.
     */
    [[nodiscard]] static CUnitFerryTask* Create(CCommandTask* parentTask, Unit* targetUnit);

    /**
     * Address: 0x0060E3A0 (FUN_0060E3A0, Moho::CUnitFerryTask::FilterTransportableUnits)
     *
     * IDA signature:
     * Moho::EntitySetTemplate_Entity *__stdcall
     * Moho::CUnitFerryTask::FilterTransportableUnits(
     *   Moho::CUnitFerryTask *a1, Moho::EntitySetTemplate_Entity *set);
     *
     * What it does:
     * Collects the owner army's LAND units that are waiting for a ferry
     * (`UNITSTATE_WaitForFerry`, no assigned transport, not attached/loading),
     * that this ferry can carry and has space for, and whose focus entity
     * matches this task's beacon (or ferry factory when no beacon is bound).
     */
    void FilterTransportableUnits(SEntitySetTemplateUnit& outUnits);

    /**
     * Address: 0x0060E7E0 (FUN_0060E7E0, Moho::CUnitFerryTask::HasNewUnit)
     *
     * IDA signature:
     * bool __stdcall Moho::CUnitFerryTask::HasNewUnit(Moho::CUnitFerryTask *arg0);
     *
     * What it does:
     * Returns true when an upcoming transportable unit is headed to this
     * ferry: either the ferry factory's head build command produces a
     * blueprint the transport has space for, or a live army LAND unit created
     * by the ferry factory queues a `UNITCOMMAND_TransportLoadUnits` command
     * next. Caller contract: `mFerryUnit` resolves to a live unit.
     */
    [[nodiscard]] bool HasNewUnit();

    /**
     * Address: 0x0060E9F0 (FUN_0060E9F0, Moho::CUnitFerryTask::HasNextUnitToLoad)
     *
     * IDA signature:
     * bool __thiscall Moho::CUnitFerryTask::HasNextUnitToLoad(Moho::CUnitFerryTask *this);
     *
     * What it does:
     * When transportable units are waiting, spawns a `CUnitLoadUnits` child
     * task and reports true. Otherwise reports true only when units are
     * already loaded (and no new unit is inbound from the ferry factory),
     * rewinding `mCommandIndex` and entering `TASKSTATE_Waiting`.
     */
    [[nodiscard]] bool HasNextUnitToLoad();

    /**
     * Address: 0x0060EB50 (FUN_0060EB50, Moho::CUnitFerryTask::GetUnitCommands)
     *
     * IDA signature:
     * void __stdcall sub_60EB50(Moho::CUnitFerryTask *a1, std::vector_WeakPtr_CUnitCommand *a2);
     *
     * What it does:
     * Copies the owner unit's queued commands into `outCommands`, then
     * replaces them with the route source when one exists: the ferry
     * factory's builder queue, the route unit's own command queue, or the
     * queue of an army TRANSPORTATION unit currently ferrying to the same
     * beacon. An empty route source leaves the own-queue copy in place.
     */
    void GetUnitCommands(msvc8::vector<WeakPtr<CUnitCommand>>& outCommands);

    /**
     * Address: 0x0060F400 (FUN_0060F400, Moho::CUnitFerryTask::TaskTick)
     * VFTable SLOT: 1 (CTask::Execute), ??_7CUnitFerryTask@Moho@@6B@ + 0x04
     *
     * IDA signature:
     * int __thiscall Moho::CUnitFerryTask::TaskTick(Moho::CUnitFerryTask *this);
     *
     * What it does:
     * Per-tick ferry state machine. Aborts (-1) when the route/ferry/beacon
     * liveness guards fail; warps the beacon onto the current command target
     * when it drifted more than 1.0 world unit; snapshots `mPos` from the
     * beacon; then dispatches on `mTaskState` (load-next / move-next /
     * unload / move-back / resume) while toggling the owner unit's
     * `UNITSTATE_ForceSpeedThrough` state bit per phase.
     */
    int Execute() override;

  private:
    /**
     * Address: 0x0060ED70 (FUN_0060ED70, sub_60ED70)
     *
     * IDA signature:
     * void __stdcall sub_60ED70(Moho::CUnitFerryTask *arg0);
     *
     * What it does:
     * Waiting-phase worker. Reads route commands, and when the pair at
     * `mCommandIndex` (pickup) / `mCommandIndex + 1` (dropoff) matches the
     * route shape (`UNITCOMMAND_Move` dropoff with a ferry unit bound,
     * `UNITCOMMAND_Ferry` dropoff without one) issues a move to the pickup
     * target cell and advances the index; otherwise enters
     * `TASKSTATE_Starting`.
     */
    void MoveToNextRoutePoint();

    /**
     * Address: 0x0060EED0 (FUN_0060EED0, sub_60EED0)
     *
     * IDA signature:
     * void __usercall sub_60EED0(int a1@<esi>);
     *
     * What it does:
     * Starting-phase worker. Clamps `mCommandIndex` into the route range,
     * builds a one-cell unload goal at that command's target (offset by half
     * the owner footprint), spawns a `CUnitUnloadUnits` child task, and
     * enters `TASKSTATE_Processing`.
     */
    void IssueUnloadAtRoutePoint();

    /**
     * Address: 0x0060F0B0 (FUN_0060F0B0, sub_60F0B0)
     *
     * IDA signature:
     * void __stdcall sub_60F0B0(Moho::CUnitFerryTask *arg0);
     *
     * What it does:
     * Processing-phase worker. Steps `mCommandIndex` back one route point and
     * issues a move to that command's target cell; with no previous point (or
     * a dead command link) enters `TASKSTATE_Complete`.
     */
    void MoveToPreviousRoutePoint();

    /**
     * Address: 0x0060F240 (FUN_0060F240, sub_60F240)
     *
     * IDA signature:
     * Moho::TDatListItem_EntitySetTemplate_Entity *__usercall sub_60F240@<eax>(int ebx0@<ebx>);
     *
     * What it does:
     * Complete-phase worker. When the owner unit is grounded (`LAYER_Land`)
     * within `RUnitBlueprintAir::StartTurnDistance` of `mPos`, simply
     * restarts the cycle; otherwise issues a move back to `mPos` (flagging
     * the goal layer when no transportable unit is waiting) and restarts at
     * `TASKSTATE_Preparing`.
     */
    void ResumeFerryRoute();

  public:
    IAiCommandDispatchImpl* mDispatch; // 0x30
    std::int32_t mCommandIndex;        // 0x34
    // 0x38: set only by the (parentTask, targetUnit) constructor when the
    // target already belongs to a ferry route (an attached rider or a
    // FERRYBEACON). When set, route commands come from `mRouteUnit` (or the
    // transport ferrying to the same beacon) instead of the owner queue.
    // Asm evidence: byte tests `[this+38h]` at 0x0060E6F6 / 0x0060EBDB /
    // 0x0060F40F.
    bool mFollowsExistingRoute;        // 0x38
    std::uint8_t mPadding39[3];        // 0x39
    Wm3::Vector3f mPos;                // 0x3C
    // 0x48: the unit the ferry command targeted; when
    // `mFollowsExistingRoute` is set its command queue defines the route
    // (asm: dword loads `[this+48h]` at 0x0060EBFB / 0x0060F421-0x0060F456).
    WeakPtr<Unit> mRouteUnit;          // 0x48
    WeakPtr<Unit> mFerryUnit;          // 0x50
    WeakPtr<Unit> mBeacon;             // 0x58
  };

  static_assert(sizeof(CUnitFerryTask) == 0x60, "CUnitFerryTask size must be 0x60");
  static_assert(offsetof(CUnitFerryTask, mDispatch) == 0x30, "CUnitFerryTask::mDispatch offset must be 0x30");
  static_assert(
    offsetof(CUnitFerryTask, mCommandIndex) == 0x34,
    "CUnitFerryTask::mCommandIndex offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitFerryTask, mFollowsExistingRoute) == 0x38,
    "CUnitFerryTask::mFollowsExistingRoute offset must be 0x38"
  );
  static_assert(offsetof(CUnitFerryTask, mPos) == 0x3C, "CUnitFerryTask::mPos offset must be 0x3C");
  static_assert(offsetof(CUnitFerryTask, mRouteUnit) == 0x48, "CUnitFerryTask::mRouteUnit offset must be 0x48");
  static_assert(offsetof(CUnitFerryTask, mFerryUnit) == 0x50, "CUnitFerryTask::mFerryUnit offset must be 0x50");
  static_assert(offsetof(CUnitFerryTask, mBeacon) == 0x58, "CUnitFerryTask::mBeacon offset must be 0x58");
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
  gpg::RRef* RRef_CUnitFerryTask(gpg::RRef* outRef, moho::CUnitFerryTask* value);

  /**
   * Address: 0x006105B0 (FUN_006105B0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitFerryTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitFerryTaskRef(gpg::RRef* outRef, moho::CUnitFerryTask* value);
} // namespace gpg
