#pragma once

#include <cstddef>

namespace gpg
{
  class RRef;
  class RType;
}

namespace moho
{
  class CCommandTask;
  class IFormationInstance;

  /**
   * Runtime owner shell for patrol-task command lanes.
   */
  class CUnitPatrolTask
  {
  public:
    static gpg::RType* sType;

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

  private:
    unsigned char mPadding[0xF0];
  };

  static_assert(sizeof(CUnitPatrolTask) == 0xF0, "CUnitPatrolTask size must be 0xF0");
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
