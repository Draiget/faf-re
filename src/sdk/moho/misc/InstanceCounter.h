#pragma once
#include <atomic>
#include <string>

namespace moho
{
  class StatItem;
  class CScriptObject;
  class CScriptEvent;
  class CLuaTask;
  class CCommandTask;
  class CWaitForTask;
  class CAcquireTargetTask;
  class IEffect;
  class MotorSinkAway;
  class CTask;
  class CTaskThread;
  class ScrDiskWatcherTask;
  class Entity;
  class CDamage;
  class CAiBrain;
  class LAiAttackerImpl;
  class CAiNavigatorImpl;
  class CAiPersonality;
  class CAiSteeringImpl;
  class ReconBlip;
  class Projectile;
  class Unit;
  class Prop;
  class CPlatoon;
  class Shield;
  class CDecalHandle;
  class CUnitCommand;
  struct RBlueprint;
  class RRuleGameRules;

  template <class T>
  struct InstanceCounter
  {
    InstanceCounter() noexcept
    {
      ++s_count;
    }
    InstanceCounter(const InstanceCounter&) noexcept
    {
      ++s_count;
    }
    ~InstanceCounter() noexcept
    {
      --s_count;
    }
    InstanceCounter& operator=(const InstanceCounter&) = delete;

    [[nodiscard]] static StatItem* GetStatItem();

    static std::atomic<int> s_count;
  };

  template <class T>
  StatItem* InstanceCounter<T>::GetStatItem()
  {
    return nullptr;
  }

  template <class T>
  std::atomic<int> InstanceCounter<T>::s_count{0};

  [[nodiscard]] inline std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  /**
   * Address: 0x004C7DC0 (FUN_004C7DC0, Moho::InstanceCounter<Moho::CScriptObject>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CScriptObject>::GetStatItem();

  /**
   * Address: 0x0064C080 (FUN_0064C080, Moho::InstanceCounter<Moho::CDamage>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CDamage>::GetStatItem();

  /**
   * Address: 0x004CB2A0 (FUN_004CB2A0, Moho::InstanceCounter<Moho::CScriptEvent>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CScriptEvent>::GetStatItem();

  /**
   * Address: 0x004CB370 (FUN_004CB370, Moho::InstanceCounter<Moho::CLuaTask>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CLuaTask>::GetStatItem();

  /**
   * Address: 0x00599740 (FUN_00599740, Moho::InstanceCounter<Moho::CCommandTask>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CCommandTask>::GetStatItem();

  /**
   * Address: 0x004CB460 (FUN_004CB460, Moho::InstanceCounter<Moho::CWaitForTask>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CWaitForTask>::GetStatItem();

  /**
   * Address: 0x005DCC20 (FUN_005DCC20, Moho::InstanceCounter<Moho::CAcquireTargetTask>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CAcquireTargetTask>::GetStatItem();

  /**
   * Address: 0x00657C40 (FUN_00657C40, Moho::InstanceCounter<Moho::IEffect>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<IEffect>::GetStatItem();

  /**
   * Address: 0x00696D90 (FUN_00696D90, Moho::InstanceCounter<Moho::MotorSinkAway>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<MotorSinkAway>::GetStatItem();

  /**
   * Address: 0x0040AB50 (FUN_0040AB50, Moho::InstanceCounter<Moho::CTask>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CTask>::GetStatItem();

  /**
   * Address: 0x0040AC80 (FUN_0040AC80, Moho::InstanceCounter<Moho::CTaskThread>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CTaskThread>::GetStatItem();

  /**
   * Address: 0x004C1060 (FUN_004C1060, Moho::InstanceCounter<Moho::ScrDiskWatcherTask>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<ScrDiskWatcherTask>::GetStatItem();

  /**
   * Address: 0x0067CBC0 (FUN_0067CBC0, Moho::InstanceCounter<Moho::Entity>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<Entity>::GetStatItem();

  /**
   * Address: 0x0057EC10 (FUN_0057EC10, Moho::InstanceCounter<Moho::CAiBrain>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CAiBrain>::GetStatItem();

  /**
   * Address: 0x005DCB30 (FUN_005DCB30, Moho::InstanceCounter<Moho::LAiAttackerImpl>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<LAiAttackerImpl>::GetStatItem();

  /**
   * Address: 0x005A7870 (FUN_005A7870, Moho::InstanceCounter<Moho::CAiNavigatorImpl>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CAiNavigatorImpl>::GetStatItem();

  /**
   * Address: 0x005B93F0 (FUN_005B93F0, Moho::InstanceCounter<Moho::CAiPersonality>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CAiPersonality>::GetStatItem();

  /**
   * Address: 0x005D3F20 (FUN_005D3F20, Moho::InstanceCounter<Moho::CAiSteeringImpl>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CAiSteeringImpl>::GetStatItem();

  /**
   * Address: 0x005C5390 (FUN_005C5390, Moho::InstanceCounter<Moho::ReconBlip>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<ReconBlip>::GetStatItem();

  /**
   * Address: 0x0069EDF0 (FUN_0069EDF0, Moho::InstanceCounter<Moho::Projectile>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<Projectile>::GetStatItem();

  /**
   * Address: 0x006AEBF0 (FUN_006AEBF0, Moho::InstanceCounter<Moho::Unit>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<Unit>::GetStatItem();

  /**
   * Address: 0x006FAAD0 (FUN_006FAAD0, Moho::InstanceCounter<Moho::Prop>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<Prop>::GetStatItem();

  /**
   * Address: 0x0072A780 (FUN_0072A780, Moho::InstanceCounter<Moho::CPlatoon>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CPlatoon>::GetStatItem();

  /**
   * Address: 0x00776E90 (FUN_00776E90, Moho::InstanceCounter<Moho::Shield>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<Shield>::GetStatItem();

  /**
   * Address: 0x0077ADC0 (FUN_0077ADC0, Moho::InstanceCounter<Moho::CDecalHandle>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CDecalHandle>::GetStatItem();

  /**
   * Address: 0x006EA340 (FUN_006EA340, Moho::InstanceCounter<Moho::CUnitCommand>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CUnitCommand>::GetStatItem();

  /**
   * Address: 0x0050E0C0 (FUN_0050E0C0, Moho::InstanceCounter<Moho::RBlueprint>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<RBlueprint>::GetStatItem();

  /**
   * Address: 0x0052CA60 (FUN_0052CA60, Moho::InstanceCounter<Moho::RRuleGameRules>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<RRuleGameRules>::GetStatItem();
} // namespace moho
