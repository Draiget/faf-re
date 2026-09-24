#include "moho/ai/LAiAttackerImpl.h"

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/task/CTaskThread.h"
#include "platform/Platform.h"

/**
 * Address: 0x005D5F30 (FUN_005D5F30, Moho::LAiAttackerImpl::LAiAttackerImpl)
 *
 * What it does:
 * Initializes detached task lanes and binds the owning attacker-impl pointer;
 * the CTask and LAiAttackerImpl instance counts come from their
 * `InstanceCounter` bases.
 */
moho::LAiAttackerImpl::LAiAttackerImpl(CAiAttackerImpl* const owner)
  : CTask(nullptr, false)
  , mReserved18(0u)
  , cImpl(owner)
{
}

/**
 * Address: 0x005D5FD0 (FUN_005D5FD0, Moho::LAiAttackerImpl::dtr)
 * Address: 0x005D5FF0 (FUN_005D5FF0, destructor body helper)
 */
moho::LAiAttackerImpl::~LAiAttackerImpl() = default;

/**
 * Address: 0x005D5FB0 (FUN_005D5FB0, Moho::LAiAttackerImpl::TaskTick)
 */
int moho::LAiAttackerImpl::Execute()
{
  cImpl->GetTaskStage()->UserFrame();
  return 1;
}
