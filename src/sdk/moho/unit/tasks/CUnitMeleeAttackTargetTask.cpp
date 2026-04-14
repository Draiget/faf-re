#include "moho/unit/tasks/CUnitMeleeAttackTargetTask.h"

#include <new>

namespace
{
  [[nodiscard]] moho::CUnitMeleeAttackTargetTask* CreateMeleeAttackTargetTask(
    moho::CCommandTask* const dispatchTask,
    moho::CAiTarget* const target,
    moho::CAiFormationInstance* const formation,
    const bool ignoreFormation
  )
  {
    void* const storage = ::operator new(sizeof(moho::CUnitMeleeAttackTargetTask), std::nothrow);
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) moho::CUnitMeleeAttackTargetTask(dispatchTask, target, formation, ignoreFormation);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006154B0 (FUN_006154B0, Moho::CUnitMeleeAttackTargetTask::operator new)
   *
   * What it does:
   * Allocates one melee attack-target task and forwards into dispatch-bound
   * constructor lane with formation-ignore disabled.
   */
  CUnitMeleeAttackTargetTask* CUnitMeleeAttackTargetTask::CreateRespectFormation(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    CAiFormationInstance* const formation
  )
  {
    return CreateMeleeAttackTargetTask(dispatchTask, target, formation, false);
  }

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
    return CreateMeleeAttackTargetTask(dispatchTask, target, formation, true);
  }
} // namespace moho
