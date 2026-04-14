#include "moho/unit/tasks/CUnitFerryTask.h"

#include <new>

namespace moho
{
  /**
   * Address: 0x0060F7E0 (FUN_0060F7E0, Moho::CUnitFerryTask::operator new)
   *
   * What it does:
   * Allocates one ferry-task object and forwards constructor arguments into
   * in-place construction.
   */
  CUnitFerryTask* CUnitFerryTask::Create(CCommandTask* const parentTask, CUnitCommand* const command)
  {
    void* const storage = ::operator new(sizeof(CUnitFerryTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitFerryTask(parentTask, command);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }
} // namespace moho
