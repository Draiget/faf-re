#pragma once

// Cross-subsystem bridges used by the recovered `cfunc_DecreaseBuildCountInQueueL`
// Lua worker (FUN_00836980, moho/sim/Sim.cpp). The worker walks the UI-owned
// factory build queue (owned by moho/ui/UiRuntimeTypes.cpp) and resolves the
// per-helper effective build count (owned by moho/unit/core/UserUnit.cpp), while
// the worker body itself lives beside its sibling `cfunc_DeleteCommandL` in
// Sim.cpp. These two free functions expose just enough of each owning
// translation unit's file-local state to keep the worker 1:1 without duplicating
// the build-queue / command-issue-helper layouts.

#include <cstdint>

#include "moho/command/CmdDefs.h"
#include "moho/command/CommandIssueHelper.h"

namespace moho
{
  // Resolves the queued-command id range [*outBegin, *outEnd) for the factory
  // build-queue item at the given 1-based queue index into the current build
  // queue. Sets both outputs to nullptr when the queue is empty or the index is
  // out of range. Defined in UiRuntimeTypes.cpp, which owns `sCurrentBuildQueue`.
  void CurrentBuildQueueItemCommands(int oneBasedQueueIndex, const CmdId** outBegin, const CmdId** outEnd) noexcept;

  // Resolves one effective queued-build count for a command-issue helper
  // (baseline count adjusted by the helper's queued increase/decrease update
  // events). Bridges to the recovered ResolveHelperBuildCount (FUN_008B4220) in
  // UserUnit.cpp, which owns the helper event-ring decomposition.
  std::int32_t QueuedBuildCommandCount(const UserCommandIssueHelper& helper) noexcept;
}
