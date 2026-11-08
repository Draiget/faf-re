#pragma once

// Wakes a command task's thread so it runs on the next tick, for the attack tasks.

#include "moho/task/CTaskThread.h"
#include "moho/unit/tasks/CUnitAttackTargetTask.h"

namespace moho
{
  inline void WakeOwnerThreadForImmediateTick(moho::CCommandTask* const commandTask)
  {
    if (commandTask == nullptr || commandTask->mOwnerThread == nullptr) {
      return;
    }

    moho::CTaskThread* const ownerThread = commandTask->mOwnerThread;
    ownerThread->mPendingFrames = 0;
    if (ownerThread->mStaged) {
      ownerThread->Unstage();
    }
  }
} // namespace moho
