#include "moho/ai/LAiAttackerImpl.h"

#include <string>
#include <typeinfo>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/task/CTaskThread.h"
#include "platform/Platform.h"

namespace
{
  void DecrementLAiAttackerImplStatCounter()
  {
    moho::StatItem* const stat = moho::InstanceCounter<moho::LAiAttackerImpl>::GetStatItem();
    if (stat == nullptr) {
      return;
    }

    (void)InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&stat->mPrimaryValueBits), -1L);
  }
} // namespace

/**
 * Address: 0x005DCB30 (FUN_005DCB30, Moho::InstanceCounter<Moho::LAiAttackerImpl>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for LAiAttackerImpl
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::LAiAttackerImpl>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::LAiAttackerImpl).name());
  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x005D5FD0 (FUN_005D5FD0, Moho::LAiAttackerImpl::dtr)
 * Address: 0x005D5FF0 (FUN_005D5FF0, destructor body helper)
 */
moho::LAiAttackerImpl::~LAiAttackerImpl()
{
  DecrementLAiAttackerImplStatCounter();
}

/**
 * Address: 0x005D5FB0 (FUN_005D5FB0, Moho::LAiAttackerImpl::TaskTick)
 */
int moho::LAiAttackerImpl::Execute()
{
  cImpl->GetTaskStage()->UserFrame();
  return 1;
}
