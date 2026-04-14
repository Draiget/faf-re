#include "moho/unit/tasks/CUnitSacrificeTask.h"

#include <new>

namespace moho
{
  /**
   * Address: 0x005FB8B0 (FUN_005FB8B0, Moho::CUnitSacrificeTask::operator new)
   *
   * What it does:
   * Allocates one sacrifice-task object and forwards constructor arguments
   * into in-place construction.
   */
  CUnitSacrificeTask* CUnitSacrificeTask::Create(CCommandTask* const parentTask, CUnitCommand* const command)
  {
    void* const storage = ::operator new(sizeof(CUnitSacrificeTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitSacrificeTask(parentTask, command);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }
} // namespace moho
