// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/ai/LAiAttackerImpl.h"

#include <string>
#include <typeinfo>

#include "moho/misc/InstanceCounter.h"
#include "moho/misc/Stats.h"

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
