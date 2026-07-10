#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Return value of task-tick virtual methods (`ITask::Execute` / `TaskTick`,
   * vtable slot 1). The scheduler interprets the signed value as follows:
   *   <= -2 : terminal / suspend outcomes (Delay/Abort/Suspend)
   *      -1 : the task finished this tick (Done)
   *       0 : reschedule immediately on the next beat (Reschedule)
   *       1 : wait one beat, then tick again (Wait)
   *   >=  2 : wait (value - 1) beats before ticking again
   *
   * Recovered from the acquire-target task scheduler (FUN_005D8D10), whose normal
   * return is `ceil(TargetCheckInterval * 10)` clamped to at least 1, plus 1 — i.e.
   * a "wait N-1 beats" value in the `>= 2` band.
   */
  enum ETaskStatus : std::int32_t
  {
    TASKSTATUS_Delay = -4,
    TASKSTATUS_Abort = -3,
    TASKSTATUS_Suspend = -2,
    TASKSTATUS_Done = -1,
    TASKSTATUS_Reschedule = 0,
    TASKSTATUS_Wait = 1,
  };

  static_assert(sizeof(ETaskStatus) == 0x4, "ETaskStatus size must be 4 bytes");
} // namespace moho
