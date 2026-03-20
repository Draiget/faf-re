#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/mutex.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class StatItem;
  class CArmyStatItem;

  template <class T>
  class Stats
  {
  public:
    using item_type = T;

    /**
     * Address family: Stats<T>::slot0 (for `StatItem`: 0x0040B2E0).
     */
    virtual void Delete(const char* statPath) = 0;

  protected:
    ~Stats() = default;
  };

  template <>
  class Stats<StatItem>
  {
  public:
    using item_type = StatItem;

    /**
     * Address: 0x0040A0A0 (FUN_0040A0A0, Moho::Stats_StatItem::Stats_StatItem)
     */
    Stats();

    /**
     * Address: 0x00406600 (FUN_00406600, Moho::Stats_StatItem::~Stats_StatItem)
     */
    ~Stats();

    /**
     * Address: 0x0040B2E0 (FUN_0040B2E0, Moho::Stats_StatItem::Delete)
     *
     * VFTable SLOT: 0
     */
    virtual void Delete(const char* statPath);

    /**
     * Address: 0x0040C200 (FUN_0040C200, Moho::Stats_StatItem::GetItem)
     */
    [[nodiscard]] StatItem* GetItem(gpg::StrArg statPath, bool allowCreate);

    /**
     * Address: 0x00417B60 (FUN_00417B60, Moho::EngineStats::GetItem3)
     */
    [[nodiscard]] StatItem* GetFloatItem(gpg::StrArg statPath);

    /**
     * Address: 0x00417C50 (FUN_00417C50, Moho::EngineStats::GetItem_0)
     */
    [[nodiscard]] StatItem* GetStringItem(gpg::StrArg statPath);

    static gpg::RType* sType;

  private:
    Stats(const Stats&) = delete;
    Stats& operator=(const Stats&) = delete;

  public:
    StatItem* mItem;    // +0x04
    boost::mutex mLock; // +0x08
    std::uint8_t pad_000D[3];
  };

  static_assert(offsetof(Stats<StatItem>, mItem) == 0x04, "Stats<StatItem>::mItem offset must be 0x04");
  static_assert(offsetof(Stats<StatItem>, mLock) == 0x08, "Stats<StatItem>::mLock offset must be 0x08");
  static_assert(sizeof(Stats<StatItem>) == 0x10, "Stats<StatItem> size must be 0x10");

  template <>
  class Stats<CArmyStatItem>
  {
  public:
    using item_type = CArmyStatItem;

    /**
     * Address: 0x007014A0 (FUN_007014A0, Stats<CArmyStatItem> constructor)
     */
    Stats();

    /**
     * Address: 0x006FD850 (FUN_006FD850, Stats<CArmyStatItem> destructor core)
     */
    ~Stats();

    /**
     * Address: 0x00703D70 (FUN_00703D70, delete-by-path helper)
     *
     * VFTable SLOT: 0
     */
    virtual void Delete(const char* statPath);

    /**
     * Address: 0x00594400 (FUN_00594400, token traversal helper)
     */
    [[nodiscard]] CArmyStatItem* TraverseTables(gpg::StrArg statPath, bool allowCreate);

  private:
    /**
     * Address: 0x005953A0 (FUN_005953A0, token walk)
     */
    [[nodiscard]] static CArmyStatItem*
    WalkTokenPath(CArmyStatItem* root, const msvc8::vector<msvc8::string>& tokens, bool allowCreate, bool* didCreate);

    Stats(const Stats&) = delete;
    Stats& operator=(const Stats&) = delete;

  public:
    CArmyStatItem* mItem; // +0x04
    boost::mutex mLock;   // +0x08
    std::uint8_t pad_000D[3];
  };

  static_assert(offsetof(Stats<CArmyStatItem>, mItem) == 0x04, "Stats<CArmyStatItem>::mItem offset must be 0x04");
  static_assert(offsetof(Stats<CArmyStatItem>, mLock) == 0x08, "Stats<CArmyStatItem>::mLock offset must be 0x08");
  static_assert(sizeof(Stats<CArmyStatItem>) == 0x10, "Stats<CArmyStatItem> size must be 0x10");

  template <class T>
  class StatsRType;
} // namespace moho
