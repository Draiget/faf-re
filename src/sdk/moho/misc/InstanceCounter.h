#pragma once
#include <atomic>

namespace moho
{
  class StatItem;
  class CScriptObject;
  class CLuaTask;
  class CTask;
  class CTaskThread;
  class ScrDiskWatcherTask;

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

  /**
   * Address: 0x004C7DC0 (FUN_004C7DC0, Moho::InstanceCounter<Moho::CScriptObject>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CScriptObject>::GetStatItem();

  /**
   * Address: 0x004CB370 (FUN_004CB370, Moho::InstanceCounter<Moho::CLuaTask>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<CLuaTask>::GetStatItem();

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
} // namespace moho
