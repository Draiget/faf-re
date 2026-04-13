#include "moho/unit/tasks/CUnitMeleeAttackTargetTask.h"

#include <new>

namespace moho
{
  /**
   * Address: 0x00615510 (FUN_00615510, Moho::CUnitMeleeAttackTargetTask::operator new)
   *
   * What it does:
   * Allocates one melee attack-target task and forwards into dispatch-bound
   * constructor lane with formation-ignore enabled.
   */
  CUnitMeleeAttackTargetTask* CUnitMeleeAttackTargetTask::Create(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    CAiFormationInstance* const formation
  )
  {
    void* const storage = ::operator new(sizeof(CUnitMeleeAttackTargetTask), std::nothrow);
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitMeleeAttackTargetTask(dispatchTask, target, formation, true);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }
} // namespace moho
