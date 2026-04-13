#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/IAiCommandDispatch.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class SerConstructResult;
  class RRef;
} // namespace gpg

namespace moho
{
  class CUnitCommandQueue;
  class CAiTarget;
  struct SNavGoal;
  class Unit;

  enum ETaskStatus : std::int32_t;

  /**
   * VFTABLE: 0x00E1B3AC
   * COL:  0x00E70540
   *
   * RTTI hierarchy evidence:
   * - base `CCommandTask` at +0x00 (FUN_005998B0).
   * - base `IAiCommandDispatch` at +0x30 (FUN_00599910).
   * - base `Listener<EUnitCommandQueueStatus>` at +0x34 (FUN_00599970).
   */
  class IAiCommandDispatchImpl : public CCommandTask, public IAiCommandDispatch, public Listener<EUnitCommandQueueStatus>
  {
  public:
    /**
     * Address: 0x005990B0 (FUN_005990B0, ??0IAiCommandDispatchImpl@Moho@@AAE@XZ)
     *
     * What it does:
     * Initializes base command-task/listener lanes and clears dispatch state
     * with no bound command queue.
     */
    IAiCommandDispatchImpl();

    /**
     * Address: 0x00598D00 (FUN_00598D00, ??0IAiCommandDispatchImpl@Moho@@QAE@PAVUnit@1@PAVCTaskThread@1@PAW4EAiResult@1@@Z)
     *
     * What it does:
     * Binds this dispatch task to one unit, creates one task-thread lane on
     * the simulation task stage, and links this object as queue-status
     * listener into the unit command queue broadcaster ring.
     */
    explicit IAiCommandDispatchImpl(Unit* unit);

    /**
     * Address: 0x005990F0 (FUN_005990F0, scalar deleting thunk)
     * Address: 0x00598DD0 (FUN_00598DD0, ??1IAiCommandDispatchImpl@Moho@@QAE@@Z)
     *
     * VFTable SLOT: 0
     */
    ~IAiCommandDispatchImpl() override;

    /**
     * Address: 0x00598E80 (FUN_00598E80, ?TaskTick@IAiCommandDispatchImpl@Moho@@UAE?AW4ETaskStatus@2@XZ)
     *
     * VFTable SLOT: 1
     *
     * What it does:
     * Drives the command-dispatch task state machine, starting queue-head
     * dispatch when the unit is ready and consuming queue-result transitions
     * when the linked command task finishes.
     */
    virtual ETaskStatus TaskTick();

    /**
     * Address: 0x00599030 (FUN_00599030, ?OnEvent@IAiCommandDispatchImpl@Moho@@UAEXW4EUnitCommandQueueStatus@2@@Z)
     *
     * VFTable SLOT: 2
     *
     * What it does:
     * Handles queue-status events from the owner command queue by either
     * refreshing unit speed-through status on insertion or interrupting active
     * subtasks when queue clear/refresh events arrive.
     */
    void OnEvent(EUnitCommandQueueStatus event) override;

    /**
     * Address: 0x0060A490 (FUN_0060A490, Moho::IAiCommandDispatchImpl::Stop)
     *
     * What it does:
     * Stops active attacker/silo-side work on the owned unit, requests a UI
     * refresh, and marks the dispatch result as stopped.
     */
    int Stop();

    /**
     * Address: 0x0060B850 (FUN_0060B850, Moho::IAiCommandDispatchImpl::KillSelf)
     *
     * What it does:
     * Routes the owned unit through the standard `Entity::Kill` path using the
     * damage reason lane observed in the binary.
     */
    int KillSelf();

    /**
     * Address: 0x0060B890 (FUN_0060B890, Moho::IAiCommandDispatchImpl::SetNewTargetLayer)
     *
     * What it does:
     * Applies a new movement layer to the owned unit's motion controller from
     * the recovered navigation goal payload.
     */
    void SetNewTargetLayer(const SNavGoal& goal);

    /**
     * Address: 0x00606D80 (FUN_00606D80, Moho::IAiCommandDispatchImpl::IssueCarrierLandTask)
     *
     * What it does:
     * Validates a carrier target, reports illegal carriers, and schedules the
     * recovered carrier-land task lane.
     */
    void IssueCarrierLandTask(Unit* unit);

    /**
     * Address: 0x0061EF60 (FUN_0061EF60, Moho::IAiCommandDispatchImpl::IssueReclaimTask)
     *
     * What it does:
     * Validates the reclaim target entity lane and schedules the recovered
     * reclaim task using the target's gun position.
     */
    void IssueReclaimTask(const CAiTarget& target);

    /**
     * Address: 0x006012B0 (FUN_006012B0, Moho::IAiCommandDispatchImpl::IssueCallTeleportTask)
     *
     * What it does:
     * Validates one candidate unit for teleport-call support and either emits
     * a warning for illegal categories or allocates one `CUnitCallTeleport`
     * task bound to this dispatch context.
     */
    void IssueCallTeleportTask(Unit* unit);

    /**
     * Address: 0x00601CE0 (FUN_00601CE0, Moho::IAiCommandDispatchImpl::IssueCallAirStagingPlatformTask)
     *
     * What it does:
     * Validates one candidate unit for air-staging-call support and either
     * emits a warning for illegal categories or allocates one
     * `CUnitCallAirStagingPlatform` task bound to this dispatch context.
     */
    void IssueCallAirStagingPlatformTask(Unit* unit);

    /**
     * Address: 0x006007C0 (FUN_006007C0, Moho::IAiCommandDispatchImpl::IssueCallLandTransportTask)
     *
     * What it does:
     * Validates one candidate unit for land-transport-call support and either
     * emits an illegal-transport warning or allocates one
     * `CUnitCallLandTransport` task bound to this dispatch context.
     */
    void IssueCallLandTransportTask(Unit* unit);

    /**
     * Address: 0x00622110 (FUN_00622110, Moho::IAiCommandDispatchImpl::IssueRefuelTask)
     *
     * What it does:
     * Validates one candidate unit for refuel dispatch (alive, not being
     * built, and backed by an air-staging transport) and allocates one
     * `CUnitRefuel` task bound to this dispatch context.
     */
    void IssueRefuelTask(Unit* unit);

    /**
     * Address: 0x00599330 (FUN_00599330, Moho::IAiCommandDispatchImpl::MemberConstruct)
     *
     * What it does:
     * Allocates one recovered command-dispatch object and stores it as an
     * unowned construct result payload.
     */
    static void MemberConstruct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x00599C80 (FUN_00599C80, Moho::IAiCommandDispatchImpl::MemberDeserialize)
     *
     * What it does:
     * Loads reflected `CCommandTask` base state, dispatch state byte, and
     * `CUnitCommandQueue*` pointer lane.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, IAiCommandDispatchImpl* object);

    /**
     * Address: 0x00599CF0 (FUN_00599CF0, Moho::IAiCommandDispatchImpl::MemberSerialize)
     *
     * What it does:
     * Saves reflected `CCommandTask` base state, dispatch state byte, and
     * `CUnitCommandQueue*` pointer lane.
     */
    static void MemberSerialize(const IAiCommandDispatchImpl* object, gpg::WriteArchive* archive);

  public:
    static gpg::RType* sType;

    std::uint8_t mState; // +0x40
    std::uint8_t mPadding41[3]{};
    CUnitCommandQueue* mCommandQueue; // +0x44
  };

  static_assert(sizeof(IAiCommandDispatchImpl) == 0x48, "IAiCommandDispatchImpl size must be 0x48");
  static_assert(offsetof(IAiCommandDispatchImpl, mState) == 0x40, "IAiCommandDispatchImpl::mState offset must be 0x40");
  static_assert(
    offsetof(IAiCommandDispatchImpl, mCommandQueue) == 0x44, "IAiCommandDispatchImpl::mCommandQueue offset must be 0x44"
  );

  /**
   * Address: 0x00599470 (FUN_00599470, ?AI_CreateCommandDispatch@Moho@@YAPAVIAiCommandDispatch@1@PAVUnit@1@_N@Z)
   *
   * What it does:
   * Allocates one `IAiCommandDispatchImpl`, warms the built-task child lane
   * used by unit start-up dispatch flow, and returns the `IAiCommandDispatch`
   * base view.
   */
  [[nodiscard]] IAiCommandDispatch* AI_CreateCommandDispatch(Unit* unit);
} // namespace moho
