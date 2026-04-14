#include "moho/unit/tasks/CUnitPatrolTask.h"

#include <new>

namespace moho
{
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
} // namespace moho
