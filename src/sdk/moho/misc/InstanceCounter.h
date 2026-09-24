#pragma once
#include <intrin.h>
#include <typeinfo>

#include "legacy/containers/String.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"

namespace moho
{
  /**
   * Live-instance count of `T`, kept in the engine stat
   * `"Instance Counts_" + typeid(T).name()` (underscores dropped).
   *
   * A counted class lists `InstanceCounter<Self>` as its last base; RTTI shows
   * it on thirty classes (`Entity` at mdisp 104, `CAiBrain` at 52, `CTask` at
   * 5, ...). It is empty, so it takes no bytes when it follows a non-empty
   * base. Its constructor and destructor are the whole mechanism: every
   * counted class's constructors add one and its destructor takes one away,
   * and the class bodies never mention the stat.
   *
   * This tree used to give the template a `static std::atomic<int> s_count`
   * that nothing read, and hand-wrote the real stat update into roughly ninety
   * constructor and destructor bodies, next to thirty-one copies of
   * `GetStatItem`. All of that is this one template now (2026-09-24).
   */
  template <class T>
  class InstanceCounter
  {
  public:
    /**
     * Address: 0x004C7BA0 (FUN_004C7BA0, `InstanceCounter<CScriptObject>`)
     * Address: 0x0050E060 (FUN_0050E060, `InstanceCounter<RBlueprint>`)
     * Address: 0x00659960 (FUN_00659960, `InstanceCounter<IEffect>`)
     * Address: 0x006746B0 (FUN_006746B0, `InstanceCounter<CollisionBeamEntity>`)
     * Address: 0x006959B0 (FUN_006959B0, `InstanceCounter<MotorFallDown>`)
     * Address: 0x00696BD0 (FUN_00696BD0, `InstanceCounter<MotorSinkAway>`)
     * Address: 0x006E95B0 (FUN_006E95B0, `InstanceCounter<CUnitCommand>`)
     * Address: 0x0072A370 (FUN_0072A370, `InstanceCounter<CPlatoon>`)
     * Address: 0x00739B00 (FUN_00739B00, `InstanceCounter<CDamage>`)
     * Address: 0x0077A160 (FUN_0077A160, `InstanceCounter<CDecalHandle>`)
     *
     * What it does:
     * `lock xadd` of +1 into the stat's integer value (+0x24), then returns
     * `this`. Every counted class inlines this into its own constructors;
     * the out-of-line copies above have no callers. They were `[[maybe_unused]]`
     * "IncrementXInstanceCounterPassThrough" helpers until 2026-09-24.
     */
    InstanceCounter() noexcept
    {
      (void)::_InterlockedExchangeAdd(
        reinterpret_cast<volatile long*>(&GetStatItem()->mPrimaryValueBits), 1L);
    }

    /**
     * Copies count as a new live instance; the destructor will take them away.
     */
    InstanceCounter(const InstanceCounter&) noexcept
      : InstanceCounter()
    {}

    InstanceCounter& operator=(const InstanceCounter&) noexcept = default;

    /**
     * Address: 0x006959D0 (FUN_006959D0, `InstanceCounter<MotorFallDown>`)
     * Address: 0x00696BF0 (FUN_00696BF0, `InstanceCounter<MotorSinkAway>`)
     *
     * What it does:
     * `lock xadd` of -1 into the stat's integer value. Inlined into every
     * counted class's destructor ahead of its other bases' destructors; the
     * two out-of-line copies above have no callers.
     */
    ~InstanceCounter() noexcept
    {
      (void)::_InterlockedExchangeAdd(
        reinterpret_cast<volatile long*>(&GetStatItem()->mPrimaryValueBits), -1L);
    }

    /**
     * Address: 0x0040AB50 (FUN_0040AB50, Moho::InstanceCounter<Moho::CTask>::GetStatItem)
     * Address: 0x0040AC80 (FUN_0040AC80, Moho::InstanceCounter<Moho::CTaskThread>::GetStatItem)
     * Address: 0x004C1060 (FUN_004C1060, Moho::InstanceCounter<Moho::ScrDiskWatcherTask>::GetStatItem)
     * Address: 0x004C7DC0 (FUN_004C7DC0, Moho::InstanceCounter<Moho::CScriptObject>::GetStatItem)
     * Address: 0x004CB2A0 (FUN_004CB2A0, Moho::InstanceCounter<Moho::CScriptEvent>::GetStatItem)
     * Address: 0x004CB370 (FUN_004CB370, Moho::InstanceCounter<Moho::CLuaTask>::GetStatItem)
     * Address: 0x004CB460 (FUN_004CB460, Moho::InstanceCounter<Moho::CWaitForTask>::GetStatItem)
     * Address: 0x0050E0C0 (FUN_0050E0C0, Moho::InstanceCounter<Moho::RBlueprint>::GetStatItem)
     * Address: 0x0052CA60 (FUN_0052CA60, Moho::InstanceCounter<Moho::RRuleGameRules>::GetStatItem)
     * Address: 0x0057EC10 (FUN_0057EC10, Moho::InstanceCounter<Moho::CAiBrain>::GetStatItem)
     * Address: 0x00599740 (FUN_00599740, Moho::InstanceCounter<Moho::CCommandTask>::GetStatItem)
     * Address: 0x005A7870 (FUN_005A7870, Moho::InstanceCounter<Moho::CAiNavigatorImpl>::GetStatItem)
     * Address: 0x005B93F0 (FUN_005B93F0, Moho::InstanceCounter<Moho::CAiPersonality>::GetStatItem)
     * Address: 0x005C5390 (FUN_005C5390, Moho::InstanceCounter<Moho::ReconBlip>::GetStatItem)
     * Address: 0x005D3F20 (FUN_005D3F20, Moho::InstanceCounter<Moho::CAiSteeringImpl>::GetStatItem)
     * Address: 0x005DCB30 (FUN_005DCB30, Moho::InstanceCounter<Moho::LAiAttackerImpl>::GetStatItem)
     * Address: 0x005DCC20 (FUN_005DCC20, Moho::InstanceCounter<Moho::CAcquireTargetTask>::GetStatItem)
     * Address: 0x0064C080 (FUN_0064C080, Moho::InstanceCounter<Moho::CDamage>::GetStatItem)
     * Address: 0x00657C40 (FUN_00657C40, Moho::InstanceCounter<Moho::IEffect>::GetStatItem)
     * Address: 0x00675070 (FUN_00675070, Moho::InstanceCounter<Moho::CollisionBeamEntity>::GetStatItem)
     * Address: 0x0067CBC0 (FUN_0067CBC0, Moho::InstanceCounter<Moho::Entity>::GetStatItem)
     * Address: 0x00695BC0 (FUN_00695BC0, Moho::InstanceCounter<Moho::MotorFallDown>::GetStatItem)
     * Address: 0x00696D90 (FUN_00696D90, Moho::InstanceCounter<Moho::MotorSinkAway>::GetStatItem)
     * Address: 0x0069EDF0 (FUN_0069EDF0, Moho::InstanceCounter<Moho::Projectile>::GetStatItem)
     * Address: 0x006AEBF0 (FUN_006AEBF0, Moho::InstanceCounter<Moho::Unit>::GetStatItem)
     * Address: 0x006DC240 (FUN_006DC240, Moho::InstanceCounter<Moho::CFireWeaponTask>::GetStatItem)
     * Address: 0x006EA340 (FUN_006EA340, Moho::InstanceCounter<Moho::CUnitCommand>::GetStatItem)
     * Address: 0x006FAAD0 (FUN_006FAAD0, Moho::InstanceCounter<Moho::Prop>::GetStatItem)
     * Address: 0x0072A780 (FUN_0072A780, Moho::InstanceCounter<Moho::CPlatoon>::GetStatItem)
     * Address: 0x00776E90 (FUN_00776E90, Moho::InstanceCounter<Moho::Shield>::GetStatItem)
     * Address: 0x0077ADC0 (FUN_0077ADC0, Moho::InstanceCounter<Moho::CDecalHandle>::GetStatItem)
     *
     * What it does:
     * On first use builds `"Instance Counts_"` plus `typeid(T).name()` with
     * every `_` dropped (0x0040AEF0 appends one character at a time), asks
     * `GetEngineStats()` (0x00408940) for that item, creating it (0x0040C200),
     * and caches it in a per-`T` static. The binary does not null-check the
     * engine stats; `GetEngineStats` creates them on first call.
     */
    [[nodiscard]] static StatItem* GetStatItem()
    {
      static StatItem* sStatItem = nullptr;
      if (sStatItem == nullptr) {
        msvc8::string statPath("Instance Counts_");
        for (const char* name = typeid(T).name(); *name != '\0'; ++name) {
          if (*name != '_') {
            (void)statPath.append(1u, *name);
          }
        }
        sStatItem = GetEngineStats()->GetItem(statPath.c_str(), true);
      }
      return sStatItem;
    }
  };
} // namespace moho
