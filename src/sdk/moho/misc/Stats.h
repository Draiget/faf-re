#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/mutex.h"
#include "boost/scoped_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"

struct lua_State;
namespace LuaPlus
{
  class LuaState;
  class LuaObject;
}

namespace moho
{
  class StatItem;
  class CArmyStatItem;
  class CScrLuaInitForm;

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
       * Address: 0x0040C200 (FUN_0040C200)
     */
    [[nodiscard]] StatItem* GetItem(gpg::StrArg statPath, bool allowCreate);

    /**
       * Address: 0x00417B60 (FUN_00417B60)
     */
    [[nodiscard]] StatItem* GetFloatItem(gpg::StrArg statPath);

    /**
       * Address: 0x00417C50 (FUN_00417C50)
     */
    [[nodiscard]] StatItem* GetStringItem(gpg::StrArg statPath);

    /**
       * Address: 0x00436290 (FUN_00436290)
     */
    [[nodiscard]] StatItem* GetIntItem(gpg::StrArg statPath);

    static gpg::RType* sType;

  private:
    Stats(const Stats&) = delete;
    Stats& operator=(const Stats&) = delete;

  public:
    StatItem* mItem;      // +0x04
    boost::mutex* mLock;  // +0x08 (runtime-owned lock pointer, ABI cell)
    std::uint8_t pad_000D[3];
  };

  static_assert(offsetof(Stats<StatItem>, mItem) == 0x04, "Stats<StatItem>::mItem offset must be 0x04");
  static_assert(offsetof(Stats<StatItem>, mLock) == 0x08, "Stats<StatItem>::mLock offset must be 0x08");
  static_assert(sizeof(Stats<StatItem>) == 0x10, "Stats<StatItem> size must be 0x10");
  using Stats_StatItem = Stats<StatItem>;

  /**
   * Complete EngineStats object that extends `Stats<StatItem>` with logging state.
   *
   * Address: 0x004088C0 (FUN_004088C0, Moho::EngineStats::EngineStats)
   * Address: 0x00407DC0 (FUN_00407DC0, Moho::EngineStats::~EngineStats)
   */
  class EngineStats final : public Stats<StatItem>
  {
  public:
    /**
     * Address: 0x004088C0 (FUN_004088C0, Moho::EngineStats::EngineStats)
     */
    EngineStats();

    /**
     * Address: 0x00407DC0 (FUN_00407DC0, Moho::EngineStats::~EngineStats)
     */
    ~EngineStats();

    /**
      * Alias of FUN_00417B60 (non-canonical helper lane).
     */
    [[nodiscard]] StatItem* GetItem3(gpg::StrArg statPath);

    /**
      * Alias of FUN_00417C50 (non-canonical helper lane).
     */
    [[nodiscard]] StatItem* GetItem_0(gpg::StrArg statPath);

    /**
      * Alias of FUN_00436290 (non-canonical helper lane).
     */
    [[nodiscard]] StatItem* GetItem2(gpg::StrArg statPath);

    /**
     * Address: 0x00417D60 (FUN_00417D60, Moho::EngineStats::FindItem)
     *
     * What it does:
     * Resolves one stats path through the float-item lane and creates missing
     * nodes as needed.
     */
    [[nodiscard]] StatItem* FindItem(const char* statPath);

    /**
     * Address: 0x00415660 (FUN_00415660, Moho::EngineStats::EndLogging)
     *
     * What it does:
     * Finalizes stats logging, writes the SupComMark report to the resolved
     * log file, clears captured sample history, and returns composite score.
     */
    [[nodiscard]] float EndLogging();

  public:
    msvc8::string mLogFileName;   // +0x10
    msvc8::string mResolvedLogFilePath; // +0x2C
    std::int32_t mLogFrameCount;  // +0x48
    std::uint8_t mIsLogging;      // +0x4C
    std::uint8_t mPad4D[3];       // +0x4D
  };

  static_assert(offsetof(EngineStats, mLogFileName) == 0x10, "EngineStats::mLogFileName offset must be 0x10");
  static_assert(
    offsetof(EngineStats, mResolvedLogFilePath) == 0x2C,
    "EngineStats::mResolvedLogFilePath offset must be 0x2C"
  );
  static_assert(offsetof(EngineStats, mLogFrameCount) == 0x48, "EngineStats::mLogFrameCount offset must be 0x48");
  static_assert(offsetof(EngineStats, mIsLogging) == 0x4C, "EngineStats::mIsLogging offset must be 0x4C");
  static_assert(sizeof(EngineStats) == 0x50, "EngineStats size must be 0x50");

  /**
   * The engine-stats singleton. `GetEngineStats` creates it on first use.
   *
   * It is declared `static` in this header, so every translation unit that
   * includes the header gets a copy of its own, exactly as the binary's did:
   * 306 of them, each constant-initialized with a dynamic initializer whose
   * only job is to register its destructor (`if (p) delete p;` through
   * `~EngineStats`). Only StatItem.cpp's copy (0x010A67B8) is ever set.
   *
   * Address: 0x0040AB20 (FUN_0040AB20, `scoped_ptr<EngineStats>::swap` cloned
   *   with `this` bound to StatItem.cpp's copy; no callers)
   * Address: 0x00BC2EC0 (FUN_00BC2EC0, dynamic initializer of the copy at 0x010A66C4)
   * Address: 0x00BEE0C0 (FUN_00BEE0C0, that copy's atexit destructor)
   * Address: 0x00BC2FB0 (FUN_00BC2FB0, dynamic initializer of the copy at 0x010A67B8)
   * Address: 0x00BEE290 (FUN_00BEE290, that copy's atexit destructor)
   * Address: 0x00BC33C0 (FUN_00BC33C0, dynamic initializer of the copy at 0x010A7464)
   * Address: 0x00BEE7B0 (FUN_00BEE7B0, that copy's atexit destructor)
   * Address: 0x00BC33D0 (FUN_00BC33D0, dynamic initializer of the copy at 0x010A7494)
   * Address: 0x00BEE7D0 (FUN_00BEE7D0, that copy's atexit destructor)
   * Address: 0x00BC3560 (FUN_00BC3560, dynamic initializer of the copy at 0x010A74C0)
   * Address: 0x00BEE8B0 (FUN_00BEE8B0, that copy's atexit destructor)
   * Address: 0x00BC35D0 (FUN_00BC35D0, dynamic initializer of the copy at 0x010A765C)
   * Address: 0x00BEE8D0 (FUN_00BEE8D0, that copy's atexit destructor)
   * Address: 0x00BC3780 (FUN_00BC3780, dynamic initializer of the copy at 0x010A766C)
   * Address: 0x00BEEA90 (FUN_00BEEA90, that copy's atexit destructor)
   * Address: 0x00BC37F0 (FUN_00BC37F0, dynamic initializer of the copy at 0x010A767C)
   * Address: 0x00BEEAB0 (FUN_00BEEAB0, that copy's atexit destructor)
   * Address: 0x00BC3880 (FUN_00BC3880, dynamic initializer of the copy at 0x010A77A4)
   * Address: 0x00BEEAD0 (FUN_00BEEAD0, that copy's atexit destructor)
   * Address: 0x00BC3B30 (FUN_00BC3B30, dynamic initializer of the copy at 0x010A7804)
   * Address: 0x00BEEE50 (FUN_00BEEE50, that copy's atexit destructor)
   * Address: 0x00BC3C40 (FUN_00BC3C40, dynamic initializer of the copy at 0x010A7820)
   * Address: 0x00BEEEB0 (FUN_00BEEEB0, that copy's atexit destructor)
   * Address: 0x00BC3C90 (FUN_00BC3C90, dynamic initializer of the copy at 0x010A7830)
   * Address: 0x00BEEF10 (FUN_00BEEF10, that copy's atexit destructor)
   * Address: 0x00BC3FE0 (FUN_00BC3FE0, dynamic initializer of the copy at 0x010A7918)
   * Address: 0x00BEF120 (FUN_00BEF120, that copy's atexit destructor)
   * Address: 0x00BC4050 (FUN_00BC4050, dynamic initializer of the copy at 0x010A7930)
   * Address: 0x00BEF170 (FUN_00BEF170, that copy's atexit destructor)
   * Address: 0x00BC40E0 (FUN_00BC40E0, dynamic initializer of the copy at 0x010A79A4)
   * Address: 0x00BEF1D0 (FUN_00BEF1D0, that copy's atexit destructor)
   * Address: 0x00BC4260 (FUN_00BC4260, dynamic initializer of the copy at 0x010A7A28)
   * Address: 0x00BEF350 (FUN_00BEF350, that copy's atexit destructor)
   * Address: 0x00BC42D0 (FUN_00BC42D0, dynamic initializer of the copy at 0x010A7AD0)
   * Address: 0x00BEF370 (FUN_00BEF370, that copy's atexit destructor)
   * Address: 0x00BC44D0 (FUN_00BC44D0, dynamic initializer of the copy at 0x010A7AE0)
   * Address: 0x00BEF520 (FUN_00BEF520, that copy's atexit destructor)
   * Address: 0x00BC44E0 (FUN_00BC44E0, dynamic initializer of the copy at 0x010A7AF0)
   * Address: 0x00BEF540 (FUN_00BEF540, that copy's atexit destructor)
   * Address: 0x00BC45B0 (FUN_00BC45B0, dynamic initializer of the copy at 0x010A7BB4)
   * Address: 0x00BEF560 (FUN_00BEF560, that copy's atexit destructor)
   * Address: 0x00BC4680 (FUN_00BC4680, dynamic initializer of the copy at 0x010A7BE8)
   * Address: 0x00BEF580 (FUN_00BEF580, that copy's atexit destructor)
   * Address: 0x00BC46A0 (FUN_00BC46A0, dynamic initializer of the copy at 0x010A7C00)
   * Address: 0x00BEF600 (FUN_00BEF600, that copy's atexit destructor)
   * Address: 0x00BC4770 (FUN_00BC4770, dynamic initializer of the copy at 0x010A7C24)
   * Address: 0x00BEF620 (FUN_00BEF620, that copy's atexit destructor)
   * Address: 0x00BC48E0 (FUN_00BC48E0, dynamic initializer of the copy at 0x010A7CAC)
   * Address: 0x00BEF700 (FUN_00BEF700, that copy's atexit destructor)
   * Address: 0x00BC49B0 (FUN_00BC49B0, dynamic initializer of the copy at 0x010A7D34)
   * Address: 0x00BEF7B0 (FUN_00BEF7B0, that copy's atexit destructor)
   * Address: 0x00BC4A80 (FUN_00BC4A80, dynamic initializer of the copy at 0x010A7D44)
   * Address: 0x00BEF860 (FUN_00BEF860, that copy's atexit destructor)
   * Address: 0x00BC4B50 (FUN_00BC4B50, dynamic initializer of the copy at 0x010A7D54)
   * Address: 0x00BEF880 (FUN_00BEF880, that copy's atexit destructor)
   * Address: 0x00BC4B60 (FUN_00BC4B60, dynamic initializer of the copy at 0x010A7D5C)
   * Address: 0x00BEF8A0 (FUN_00BEF8A0, that copy's atexit destructor)
   * Address: 0x00BC5170 (FUN_00BC5170, dynamic initializer of the copy at 0x010A7E74)
   * Address: 0x00BEFD30 (FUN_00BEFD30, that copy's atexit destructor)
   * Address: 0x00BC5240 (FUN_00BC5240, dynamic initializer of the copy at 0x010A809C)
   * Address: 0x00BEFD50 (FUN_00BEFD50, that copy's atexit destructor)
   * Address: 0x00BC5520 (FUN_00BC5520, dynamic initializer of the copy at 0x010A8710)
   * Address: 0x00BF0010 (FUN_00BF0010, that copy's atexit destructor)
   * Address: 0x00BC5820 (FUN_00BC5820, dynamic initializer of the copy at 0x010A87C0)
   * Address: 0x00BF01E0 (FUN_00BF01E0, that copy's atexit destructor)
   * Address: 0x00BC58E0 (FUN_00BC58E0, dynamic initializer of the copy at 0x010A87C4)
   * Address: 0x00BF0290 (FUN_00BF0290, that copy's atexit destructor)
   * Address: 0x00BC58F0 (FUN_00BC58F0, dynamic initializer of the copy at 0x010A87C8)
   * Address: 0x00BF02C0 (FUN_00BF02C0, that copy's atexit destructor)
   * Address: 0x00BC5960 (FUN_00BC5960, dynamic initializer of the copy at 0x010A8854)
   * Address: 0x00BF02E0 (FUN_00BF02E0, that copy's atexit destructor)
   * Address: 0x00BC5C80 (FUN_00BC5C80, dynamic initializer of the copy at 0x010A89C8)
   * Address: 0x00BF0650 (FUN_00BF0650, that copy's atexit destructor)
   * Address: 0x00BC5D40 (FUN_00BC5D40, dynamic initializer of the copy at 0x010A8A20)
   * Address: 0x00BF06B0 (FUN_00BF06B0, that copy's atexit destructor)
   * Address: 0x00BC5DC0 (FUN_00BC5DC0, dynamic initializer of the copy at 0x010A8A58)
   * Address: 0x00BF06D0 (FUN_00BF06D0, that copy's atexit destructor)
   * Address: 0x00BC5ED0 (FUN_00BC5ED0, dynamic initializer of the copy at 0x010A8A7C)
   * Address: 0x00BF07C0 (FUN_00BF07C0, that copy's atexit destructor)
   * Address: 0x00BC5F50 (FUN_00BC5F50, dynamic initializer of the copy at 0x010A8AAC)
   * Address: 0x00BF07E0 (FUN_00BF07E0, that copy's atexit destructor)
   * Address: 0x00BC5FF0 (FUN_00BC5FF0, dynamic initializer of the copy at 0x010A8BB8)
   * Address: 0x00BF0900 (FUN_00BF0900, that copy's atexit destructor)
   * Address: 0x00BC60F0 (FUN_00BC60F0, dynamic initializer of the copy at 0x010A8D54)
   * Address: 0x00BF0A40 (FUN_00BF0A40, that copy's atexit destructor)
   * Address: 0x00BC63C0 (FUN_00BC63C0, dynamic initializer of the copy at 0x010A91C8)
   * Address: 0x00BF0C70 (FUN_00BF0C70, that copy's atexit destructor)
   * Address: 0x00BC66D0 (FUN_00BC66D0, dynamic initializer of the copy at 0x010A9254)
   * Address: 0x00BF0D40 (FUN_00BF0D40, that copy's atexit destructor)
   * Address: 0x00BC6770 (FUN_00BC6770, dynamic initializer of the copy at 0x010A9268)
   * Address: 0x00BF0D60 (FUN_00BF0D60, that copy's atexit destructor)
   * Address: 0x00BC6830 (FUN_00BC6830, dynamic initializer of the copy at 0x010A9390)
   * Address: 0x00BF0DD0 (FUN_00BF0DD0, that copy's atexit destructor)
   * Address: 0x00BC6B70 (FUN_00BC6B70, dynamic initializer of the copy at 0x010A95B4)
   * Address: 0x00BF11B0 (FUN_00BF11B0, that copy's atexit destructor)
   * Address: 0x00BC71B0 (FUN_00BC71B0, dynamic initializer of the copy at 0x010A9B54)
   * Address: 0x00BF1800 (FUN_00BF1800, that copy's atexit destructor)
   * Address: 0x00BC71C0 (FUN_00BC71C0, dynamic initializer of the copy at 0x010A9B74)
   * Address: 0x00BF1820 (FUN_00BF1820, that copy's atexit destructor)
   * Address: 0x00BC7300 (FUN_00BC7300, dynamic initializer of the copy at 0x010A9BE8)
   * Address: 0x00BF1890 (FUN_00BF1890, that copy's atexit destructor)
   * Address: 0x00BC7430 (FUN_00BC7430, dynamic initializer of the copy at 0x010A9BFC)
   * Address: 0x00BF1990 (FUN_00BF1990, that copy's atexit destructor)
   * Address: 0x00BC74A0 (FUN_00BC74A0, dynamic initializer of the copy at 0x010A9D1C)
   * Address: 0x00BF19B0 (FUN_00BF19B0, that copy's atexit destructor)
   * Address: 0x00BC7770 (FUN_00BC7770, dynamic initializer of the copy at 0x010A9E30)
   * Address: 0x00BF1C80 (FUN_00BF1C80, that copy's atexit destructor)
   * Address: 0x00BC7840 (FUN_00BC7840, dynamic initializer of the copy at 0x010A9E40)
   * Address: 0x00BF1CA0 (FUN_00BF1CA0, that copy's atexit destructor)
   * Address: 0x00BC78B0 (FUN_00BC78B0, dynamic initializer of the copy at 0x010A9EDC)
   * Address: 0x00BF1CE0 (FUN_00BF1CE0, that copy's atexit destructor)
   * Address: 0x00BC7BF0 (FUN_00BC7BF0, dynamic initializer of the copy at 0x010AA3C0)
   * Address: 0x00BF2050 (FUN_00BF2050, that copy's atexit destructor)
   * Address: 0x00BC7EA0 (FUN_00BC7EA0, dynamic initializer of the copy at 0x010AA5B8)
   * Address: 0x00BF2380 (FUN_00BF2380, that copy's atexit destructor)
   * Address: 0x00BC7F50 (FUN_00BC7F50, dynamic initializer of the copy at 0x010AA62C)
   * Address: 0x00BF23A0 (FUN_00BF23A0, that copy's atexit destructor)
   * Address: 0x00BC8040 (FUN_00BC8040, dynamic initializer of the copy at 0x010AA7B4)
   * Address: 0x00BF2420 (FUN_00BF2420, that copy's atexit destructor)
   * Address: 0x00BC8220 (FUN_00BC8220, dynamic initializer of the copy at 0x010AA8AC)
   * Address: 0x00BF26E0 (FUN_00BF26E0, that copy's atexit destructor)
   * Address: 0x00BC82D0 (FUN_00BC82D0, dynamic initializer of the copy at 0x010AA8BC)
   * Address: 0x00BF27F0 (FUN_00BF27F0, that copy's atexit destructor)
   * Address: 0x00BC8500 (FUN_00BC8500, dynamic initializer of the copy at 0x010AAB5C)
   * Address: 0x00BF2BE0 (FUN_00BF2BE0, that copy's atexit destructor)
   * Address: 0x00BC85E0 (FUN_00BC85E0, dynamic initializer of the copy at 0x010AACDC)
   * Address: 0x00BF2DB0 (FUN_00BF2DB0, that copy's atexit destructor)
   * Address: 0x00BC8740 (FUN_00BC8740, dynamic initializer of the copy at 0x010AAE1C)
   * Address: 0x00BF2FB0 (FUN_00BF2FB0, that copy's atexit destructor)
   * Address: 0x00BC88A0 (FUN_00BC88A0, dynamic initializer of the copy at 0x010AB2B4)
   * Address: 0x00BF31B0 (FUN_00BF31B0, that copy's atexit destructor)
   * Address: 0x00BC8D50 (FUN_00BC8D50, dynamic initializer of the copy at 0x010ABA84)
   * Address: 0x00BF3930 (FUN_00BF3930, that copy's atexit destructor)
   * Address: 0x00BC9050 (FUN_00BC9050, dynamic initializer of the copy at 0x010ABB4C)
   * Address: 0x00BF3B00 (FUN_00BF3B00, that copy's atexit destructor)
   * Address: 0x00BC9310 (FUN_00BC9310, dynamic initializer of the copy at 0x010ABCF0)
   * Address: 0x00BF3DE0 (FUN_00BF3DE0, that copy's atexit destructor)
   * Address: 0x00BC9380 (FUN_00BC9380, dynamic initializer of the copy at 0x010ABD00)
   * Address: 0x00BF3E00 (FUN_00BF3E00, that copy's atexit destructor)
   * Address: 0x00BC9430 (FUN_00BC9430, dynamic initializer of the copy at 0x010ABDEC)
   * Address: 0x00BF3F10 (FUN_00BF3F10, that copy's atexit destructor)
   * Address: 0x00BC9580 (FUN_00BC9580, dynamic initializer of the copy at 0x010AC054)
   * Address: 0x00BF4170 (FUN_00BF4170, that copy's atexit destructor)
   * Address: 0x00BC9880 (FUN_00BC9880, dynamic initializer of the copy at 0x010AC2CC)
   * Address: 0x00BF4460 (FUN_00BF4460, that copy's atexit destructor)
   * Address: 0x00BC9A20 (FUN_00BC9A20, dynamic initializer of the copy at 0x010AC454)
   * Address: 0x00BF4760 (FUN_00BF4760, that copy's atexit destructor)
   * Address: 0x00BC9C10 (FUN_00BC9C10, dynamic initializer of the copy at 0x010AC644)
   * Address: 0x00BF4930 (FUN_00BF4930, that copy's atexit destructor)
   * Address: 0x00BC9DE0 (FUN_00BC9DE0, dynamic initializer of the copy at 0x010AC654)
   * Address: 0x00BF4BD0 (FUN_00BF4BD0, that copy's atexit destructor)
   * Address: 0x00BC9DF0 (FUN_00BC9DF0, dynamic initializer of the copy at 0x010AC77C)
   * Address: 0x00BF4BF0 (FUN_00BF4BF0, that copy's atexit destructor)
   * Address: 0x00BC9F50 (FUN_00BC9F50, dynamic initializer of the copy at 0x010AC8A4)
   * Address: 0x00BF4D30 (FUN_00BF4D30, that copy's atexit destructor)
   * Address: 0x00BCA280 (FUN_00BCA280, dynamic initializer of the copy at 0x010ACA98)
   * Address: 0x00BF50B0 (FUN_00BF50B0, that copy's atexit destructor)
   * Address: 0x00BCA3B0 (FUN_00BCA3B0, dynamic initializer of the copy at 0x010ACB44)
   * Address: 0x00BF51A0 (FUN_00BF51A0, that copy's atexit destructor)
   * Address: 0x00BCA430 (FUN_00BCA430, dynamic initializer of the copy at 0x010ACDFC)
   * Address: 0x00BF51C0 (FUN_00BF51C0, that copy's atexit destructor)
   * Address: 0x00BCA780 (FUN_00BCA780, dynamic initializer of the copy at 0x010ACEE8)
   * Address: 0x00BF5600 (FUN_00BF5600, that copy's atexit destructor)
   * Address: 0x00BCA990 (FUN_00BCA990, dynamic initializer of the copy at 0x010AD100)
   * Address: 0x00BF5790 (FUN_00BF5790, that copy's atexit destructor)
   * Address: 0x00BCA9A0 (FUN_00BCA9A0, dynamic initializer of the copy at 0x010AD110)
   * Address: 0x00BF57B0 (FUN_00BF57B0, that copy's atexit destructor)
   * Address: 0x00BCAA10 (FUN_00BCAA10, dynamic initializer of the copy at 0x010AD300)
   * Address: 0x00BF57D0 (FUN_00BF57D0, that copy's atexit destructor)
   * Address: 0x00BCAD60 (FUN_00BCAD60, dynamic initializer of the copy at 0x010AD404)
   * Address: 0x00BF5EC0 (FUN_00BF5EC0, that copy's atexit destructor)
   * Address: 0x00BCADD0 (FUN_00BCADD0, dynamic initializer of the copy at 0x010AD414)
   * Address: 0x00BF5EE0 (FUN_00BF5EE0, that copy's atexit destructor)
   * Address: 0x00BCAE60 (FUN_00BCAE60, dynamic initializer of the copy at 0x010AD6E4)
   * Address: 0x00BF5F60 (FUN_00BF5F60, that copy's atexit destructor)
   * Address: 0x00BCB4D0 (FUN_00BCB4D0, dynamic initializer of the copy at 0x010AE09C)
   * Address: 0x00BF6440 (FUN_00BF6440, that copy's atexit destructor)
   * Address: 0x00BCBB60 (FUN_00BCBB60, dynamic initializer of the copy at 0x010AE298)
   * Address: 0x00BF64F0 (FUN_00BF64F0, that copy's atexit destructor)
   * Address: 0x00BCBE10 (FUN_00BCBE10, dynamic initializer of the copy at 0x010AE39C)
   * Address: 0x00BF65E0 (FUN_00BF65E0, that copy's atexit destructor)
   * Address: 0x00BCBF40 (FUN_00BCBF40, dynamic initializer of the copy at 0x010AE4DC)
   * Address: 0x00BF6720 (FUN_00BF6720, that copy's atexit destructor)
   * Address: 0x00BCC230 (FUN_00BCC230, dynamic initializer of the copy at 0x010AE658)
   * Address: 0x00BF69E0 (FUN_00BF69E0, that copy's atexit destructor)
   * Address: 0x00BCC380 (FUN_00BCC380, dynamic initializer of the copy at 0x010AE6CC)
   * Address: 0x00BF6C40 (FUN_00BF6C40, that copy's atexit destructor)
   * Address: 0x00BCC3F0 (FUN_00BCC3F0, dynamic initializer of the copy at 0x010AEABC)
   * Address: 0x00BF6C60 (FUN_00BF6C60, that copy's atexit destructor)
   * Address: 0x00BCCA60 (FUN_00BCCA60, dynamic initializer of the copy at 0x010AEDB0)
   * Address: 0x00BF70C0 (FUN_00BF70C0, that copy's atexit destructor)
   * Address: 0x00BCCDD0 (FUN_00BCCDD0, dynamic initializer of the copy at 0x010AEE34)
   * Address: 0x00BF7300 (FUN_00BF7300, that copy's atexit destructor)
   * Address: 0x00BCD080 (FUN_00BCD080, dynamic initializer of the copy at 0x010AF0AC)
   * Address: 0x00BF73F0 (FUN_00BF73F0, that copy's atexit destructor)
   * Address: 0x00BCD3B0 (FUN_00BCD3B0, dynamic initializer of the copy at 0x010AF1AC)
   * Address: 0x00BF7600 (FUN_00BF7600, that copy's atexit destructor)
   * Address: 0x00BCD6C0 (FUN_00BCD6C0, dynamic initializer of the copy at 0x010AF6E8)
   * Address: 0x00BF7770 (FUN_00BF7770, that copy's atexit destructor)
   * Address: 0x00BCD980 (FUN_00BCD980, dynamic initializer of the copy at 0x010AFADC)
   * Address: 0x00BF7790 (FUN_00BF7790, that copy's atexit destructor)
   * Address: 0x00BCDFA0 (FUN_00BCDFA0, dynamic initializer of the copy at 0x010AFD24)
   * Address: 0x00BF7D80 (FUN_00BF7D80, that copy's atexit destructor)
   * Address: 0x00BCE1B0 (FUN_00BCE1B0, dynamic initializer of the copy at 0x010AFE28)
   * Address: 0x00BF8020 (FUN_00BF8020, that copy's atexit destructor)
   * Address: 0x00BCE4E0 (FUN_00BCE4E0, dynamic initializer of the copy at 0x010B0318)
   * Address: 0x00BF81C0 (FUN_00BF81C0, that copy's atexit destructor)
   * Address: 0x00BCEB60 (FUN_00BCEB60, dynamic initializer of the copy at 0x010B054C)
   * Address: 0x00BF8850 (FUN_00BF8850, that copy's atexit destructor)
   * Address: 0x00BCECA0 (FUN_00BCECA0, dynamic initializer of the copy at 0x010B0878)
   * Address: 0x00BF8940 (FUN_00BF8940, that copy's atexit destructor)
   * Address: 0x00BCF0C0 (FUN_00BCF0C0, dynamic initializer of the copy at 0x010B09B8)
   * Address: 0x00BF8F70 (FUN_00BF8F70, that copy's atexit destructor)
   * Address: 0x00BCF310 (FUN_00BCF310, dynamic initializer of the copy at 0x010B0A1C)
   * Address: 0x00BF9020 (FUN_00BF9020, that copy's atexit destructor)
   * Address: 0x00BCF520 (FUN_00BCF520, dynamic initializer of the copy at 0x010B0D00)
   * Address: 0x00BF9160 (FUN_00BF9160, that copy's atexit destructor)
   * Address: 0x00BCFAB0 (FUN_00BCFAB0, dynamic initializer of the copy at 0x010B0F0C)
   * Address: 0x00BF95A0 (FUN_00BF95A0, that copy's atexit destructor)
   * Address: 0x00BCFE20 (FUN_00BCFE20, dynamic initializer of the copy at 0x010B10B0)
   * Address: 0x00BF9800 (FUN_00BF9800, that copy's atexit destructor)
   * Address: 0x00BD0070 (FUN_00BD0070, dynamic initializer of the copy at 0x010B1254)
   * Address: 0x00BF98B0 (FUN_00BF98B0, that copy's atexit destructor)
   * Address: 0x00BD0380 (FUN_00BD0380, dynamic initializer of the copy at 0x010B1434)
   * Address: 0x00BF9A80 (FUN_00BF9A80, that copy's atexit destructor)
   * Address: 0x00BD0750 (FUN_00BD0750, dynamic initializer of the copy at 0x010B15BC)
   * Address: 0x00BF9D20 (FUN_00BF9D20, that copy's atexit destructor)
   * Address: 0x00BD0A00 (FUN_00BD0A00, dynamic initializer of the copy at 0x010B1794)
   * Address: 0x00BF9E60 (FUN_00BF9E60, that copy's atexit destructor)
   * Address: 0x00BD0C50 (FUN_00BD0C50, dynamic initializer of the copy at 0x010B185C)
   * Address: 0x00BF9F10 (FUN_00BF9F10, that copy's atexit destructor)
   * Address: 0x00BD0EA0 (FUN_00BD0EA0, dynamic initializer of the copy at 0x010B199C)
   * Address: 0x00BF9FC0 (FUN_00BF9FC0, that copy's atexit destructor)
   * Address: 0x00BD1150 (FUN_00BD1150, dynamic initializer of the copy at 0x010B1A78)
   * Address: 0x00BFA100 (FUN_00BFA100, that copy's atexit destructor)
   * Address: 0x00BD1380 (FUN_00BD1380, dynamic initializer of the copy at 0x010B1B2C)
   * Address: 0x00BFA1E0 (FUN_00BFA1E0, that copy's atexit destructor)
   * Address: 0x00BD1630 (FUN_00BD1630, dynamic initializer of the copy at 0x010B1BF4)
   * Address: 0x00BFA290 (FUN_00BFA290, that copy's atexit destructor)
   * Address: 0x00BD1880 (FUN_00BD1880, dynamic initializer of the copy at 0x010B1C2C)
   * Address: 0x00BFA340 (FUN_00BFA340, that copy's atexit destructor)
   * Address: 0x00BD1950 (FUN_00BD1950, dynamic initializer of the copy at 0x010B1D44)
   * Address: 0x00BFA3F0 (FUN_00BFA3F0, that copy's atexit destructor)
   * Address: 0x00BD1AA0 (FUN_00BD1AA0, dynamic initializer of the copy at 0x010B1F4C)
   * Address: 0x00BFA4A0 (FUN_00BFA4A0, that copy's atexit destructor)
   * Address: 0x00BD1DD0 (FUN_00BD1DD0, dynamic initializer of the copy at 0x010B2014)
   * Address: 0x00BFA700 (FUN_00BFA700, that copy's atexit destructor)
   * Address: 0x00BD2180 (FUN_00BD2180, dynamic initializer of the copy at 0x010B2258)
   * Address: 0x00BFA8B0 (FUN_00BFA8B0, that copy's atexit destructor)
   * Address: 0x00BD23F0 (FUN_00BD23F0, dynamic initializer of the copy at 0x010B2368)
   * Address: 0x00BFA990 (FUN_00BFA990, that copy's atexit destructor)
   * Address: 0x00BD2540 (FUN_00BD2540, dynamic initializer of the copy at 0x010B24B4)
   * Address: 0x00BFAA40 (FUN_00BFAA40, that copy's atexit destructor)
   * Address: 0x00BD26B0 (FUN_00BD26B0, dynamic initializer of the copy at 0x010B25A0)
   * Address: 0x00BFAAF0 (FUN_00BFAAF0, that copy's atexit destructor)
   * Address: 0x00BD2830 (FUN_00BD2830, dynamic initializer of the copy at 0x010B26F0)
   * Address: 0x00BFABA0 (FUN_00BFABA0, that copy's atexit destructor)
   * Address: 0x00BD2AF0 (FUN_00BD2AF0, dynamic initializer of the copy at 0x010B2848)
   * Address: 0x00BFAC50 (FUN_00BFAC50, that copy's atexit destructor)
   * Address: 0x00BD2D40 (FUN_00BD2D40, dynamic initializer of the copy at 0x010B2B10)
   * Address: 0x00BFAF70 (FUN_00BFAF70, that copy's atexit destructor)
   * Address: 0x00BD2FA0 (FUN_00BD2FA0, dynamic initializer of the copy at 0x010B2CD0)
   * Address: 0x00BFB0E0 (FUN_00BFB0E0, that copy's atexit destructor)
   * Address: 0x00BD3180 (FUN_00BD3180, dynamic initializer of the copy at 0x010B2DC4)
   * Address: 0x00BFB190 (FUN_00BFB190, that copy's atexit destructor)
   * Address: 0x00BD32D0 (FUN_00BD32D0, dynamic initializer of the copy at 0x010B3000)
   * Address: 0x00BFB240 (FUN_00BFB240, that copy's atexit destructor)
   * Address: 0x00BD35F0 (FUN_00BD35F0, dynamic initializer of the copy at 0x010B306C)
   * Address: 0x00BFB2F0 (FUN_00BFB2F0, that copy's atexit destructor)
   * Address: 0x00BD3730 (FUN_00BD3730, dynamic initializer of the copy at 0x010B313C)
   * Address: 0x00BFB3A0 (FUN_00BFB3A0, that copy's atexit destructor)
   * Address: 0x00BD3820 (FUN_00BD3820, dynamic initializer of the copy at 0x010B3268)
   * Address: 0x00BFB450 (FUN_00BFB450, that copy's atexit destructor)
   * Address: 0x00BD3AC0 (FUN_00BD3AC0, dynamic initializer of the copy at 0x010B32D8)
   * Address: 0x00BFB650 (FUN_00BFB650, that copy's atexit destructor)
   * Address: 0x00BD3BB0 (FUN_00BD3BB0, dynamic initializer of the copy at 0x010B3438)
   * Address: 0x00BFB680 (FUN_00BFB680, that copy's atexit destructor)
   * Address: 0x00BD3C00 (FUN_00BD3C00, dynamic initializer of the copy at 0x010B3640)
   * Address: 0x00BFB6C0 (FUN_00BFB6C0, that copy's atexit destructor)
   * Address: 0x00BD3D30 (FUN_00BD3D30, dynamic initializer of the copy at 0x010B375C)
   * Address: 0x00BFB710 (FUN_00BFB710, that copy's atexit destructor)
   * Address: 0x00BD3DF0 (FUN_00BD3DF0, dynamic initializer of the copy at 0x010B384C)
   * Address: 0x00BFB830 (FUN_00BFB830, that copy's atexit destructor)
   * Address: 0x00BD3EE0 (FUN_00BD3EE0, dynamic initializer of the copy at 0x010B3A58)
   * Address: 0x00BFB860 (FUN_00BFB860, that copy's atexit destructor)
   * Address: 0x00BD40B0 (FUN_00BD40B0, dynamic initializer of the copy at 0x010B3AF0)
   * Address: 0x00BFB9A0 (FUN_00BFB9A0, that copy's atexit destructor)
   * Address: 0x00BD41A0 (FUN_00BD41A0, dynamic initializer of the copy at 0x010B3BEC)
   * Address: 0x00BFBC90 (FUN_00BFBC90, that copy's atexit destructor)
   * Address: 0x00BD4450 (FUN_00BD4450, dynamic initializer of the copy at 0x010B3C84)
   * Address: 0x00BFBF30 (FUN_00BFBF30, that copy's atexit destructor)
   * Address: 0x00BD4500 (FUN_00BD4500, dynamic initializer of the copy at 0x010B3D68)
   * Address: 0x00BFBF80 (FUN_00BFBF80, that copy's atexit destructor)
   * Address: 0x00BD46B0 (FUN_00BD46B0, dynamic initializer of the copy at 0x010B3FDC)
   * Address: 0x00BFC180 (FUN_00BFC180, that copy's atexit destructor)
   * Address: 0x00BD48A0 (FUN_00BD48A0, dynamic initializer of the copy at 0x010B40BC)
   * Address: 0x00BFC1A0 (FUN_00BFC1A0, that copy's atexit destructor)
   * Address: 0x00BD49B0 (FUN_00BD49B0, dynamic initializer of the copy at 0x010B4270)
   * Address: 0x00BFC280 (FUN_00BFC280, that copy's atexit destructor)
   * Address: 0x00BD4E10 (FUN_00BD4E10, dynamic initializer of the copy at 0x010B440C)
   * Address: 0x00BFC610 (FUN_00BFC610, that copy's atexit destructor)
   * Address: 0x00BD5170 (FUN_00BD5170, dynamic initializer of the copy at 0x010B4534)
   * Address: 0x00BFCA50 (FUN_00BFCA50, that copy's atexit destructor)
   * Address: 0x00BD5290 (FUN_00BD5290, dynamic initializer of the copy at 0x010B4D0C)
   * Address: 0x00BFCC80 (FUN_00BFCC80, that copy's atexit destructor)
   * Address: 0x00BD5760 (FUN_00BD5760, dynamic initializer of the copy at 0x010B4F74)
   * Address: 0x00BFCCA0 (FUN_00BFCCA0, that copy's atexit destructor)
   * Address: 0x00BD59D0 (FUN_00BD59D0, dynamic initializer of the copy at 0x010B51F4)
   * Address: 0x00BFCF90 (FUN_00BFCF90, that copy's atexit destructor)
   * Address: 0x00BD5D40 (FUN_00BD5D40, dynamic initializer of the copy at 0x010B5304)
   * Address: 0x00BFD1F0 (FUN_00BFD1F0, that copy's atexit destructor)
   * Address: 0x00BD5F50 (FUN_00BD5F50, dynamic initializer of the copy at 0x010B53BC)
   * Address: 0x00BFD3C0 (FUN_00BFD3C0, that copy's atexit destructor)
   * Address: 0x00BD5FC0 (FUN_00BD5FC0, dynamic initializer of the copy at 0x010B53CC)
   * Address: 0x00BFD3E0 (FUN_00BFD3E0, that copy's atexit destructor)
   * Address: 0x00BD6100 (FUN_00BD6100, dynamic initializer of the copy at 0x010B55E0)
   * Address: 0x00BFD4F0 (FUN_00BFD4F0, that copy's atexit destructor)
   * Address: 0x00BD6500 (FUN_00BD6500, dynamic initializer of the copy at 0x010B5680)
   * Address: 0x00BFD820 (FUN_00BFD820, that copy's atexit destructor)
   * Address: 0x00BD65D0 (FUN_00BD65D0, dynamic initializer of the copy at 0x010B5A38)
   * Address: 0x00BFD840 (FUN_00BFD840, that copy's atexit destructor)
   * Address: 0x00BD6800 (FUN_00BD6800, dynamic initializer of the copy at 0x010B5C54)
   * Address: 0x00BFD860 (FUN_00BFD860, that copy's atexit destructor)
   * Address: 0x00BD6C80 (FUN_00BD6C80, dynamic initializer of the copy at 0x010B5CC0)
   * Address: 0x00BFDD30 (FUN_00BFDD30, that copy's atexit destructor)
   * Address: 0x00BD6D70 (FUN_00BD6D70, dynamic initializer of the copy at 0x010B5F7C)
   * Address: 0x00BFDE10 (FUN_00BFDE10, that copy's atexit destructor)
   * Address: 0x00BD72C0 (FUN_00BD72C0, dynamic initializer of the copy at 0x010B61C0)
   * Address: 0x00BFE0D0 (FUN_00BFE0D0, that copy's atexit destructor)
   * Address: 0x00BD7530 (FUN_00BD7530, dynamic initializer of the copy at 0x010B6224)
   * Address: 0x00BFE150 (FUN_00BFE150, that copy's atexit destructor)
   * Address: 0x00BD7780 (FUN_00BD7780, dynamic initializer of the copy at 0x010B72BC)
   * Address: 0x00BFE170 (FUN_00BFE170, that copy's atexit destructor)
   * Address: 0x00BD8450 (FUN_00BD8450, dynamic initializer of the copy at 0x010B764C)
   * Address: 0x00BFE3D0 (FUN_00BFE3D0, that copy's atexit destructor)
   * Address: 0x00BD8520 (FUN_00BD8520, dynamic initializer of the copy at 0x010B7C20)
   * Address: 0x00BFE510 (FUN_00BFE510, that copy's atexit destructor)
   * Address: 0x00BD8C30 (FUN_00BD8C30, dynamic initializer of the copy at 0x010B7E60)
   * Address: 0x00BFE920 (FUN_00BFE920, that copy's atexit destructor)
   * Address: 0x00BD8D70 (FUN_00BD8D70, dynamic initializer of the copy at 0x010B7E80)
   * Address: 0x00BFEAC0 (FUN_00BFEAC0, that copy's atexit destructor)
   * Address: 0x00BD8DE0 (FUN_00BD8DE0, dynamic initializer of the copy at 0x010B7E90)
   * Address: 0x00BFEAE0 (FUN_00BFEAE0, that copy's atexit destructor)
   * Address: 0x00BD8E50 (FUN_00BD8E50, dynamic initializer of the copy at 0x010B7EA0)
   * Address: 0x00BFEB00 (FUN_00BFEB00, that copy's atexit destructor)
   * Address: 0x00BD8E60 (FUN_00BD8E60, dynamic initializer of the copy at 0x010B7F3C)
   * Address: 0x00BFEB20 (FUN_00BFEB20, that copy's atexit destructor)
   * Address: 0x00BD9070 (FUN_00BD9070, dynamic initializer of the copy at 0x010B8618)
   * Address: 0x00BFEE80 (FUN_00BFEE80, that copy's atexit destructor)
   * Address: 0x00BD9610 (FUN_00BD9610, dynamic initializer of the copy at 0x010B8768)
   * Address: 0x00BFF0C0 (FUN_00BFF0C0, that copy's atexit destructor)
   * Address: 0x00BD9950 (FUN_00BD9950, dynamic initializer of the copy at 0x010B8844)
   * Address: 0x00BFF260 (FUN_00BFF260, that copy's atexit destructor)
   * Address: 0x00BD99C0 (FUN_00BD99C0, dynamic initializer of the copy at 0x010B88C0)
   * Address: 0x00BFF280 (FUN_00BFF280, that copy's atexit destructor)
   * Address: 0x00BD9AB0 (FUN_00BD9AB0, dynamic initializer of the copy at 0x010B89DC)
   * Address: 0x00BFF2A0 (FUN_00BFF2A0, that copy's atexit destructor)
   * Address: 0x00BD9C80 (FUN_00BD9C80, dynamic initializer of the copy at 0x010B8E90)
   * Address: 0x00BFF4D0 (FUN_00BFF4D0, that copy's atexit destructor)
   * Address: 0x00BD9FD0 (FUN_00BD9FD0, dynamic initializer of the copy at 0x010B90B4)
   * Address: 0x00BFF550 (FUN_00BFF550, that copy's atexit destructor)
   * Address: 0x00BDA370 (FUN_00BDA370, dynamic initializer of the copy at 0x010B94FC)
   * Address: 0x00BFFC70 (FUN_00BFFC70, that copy's atexit destructor)
   * Address: 0x00BDA8A0 (FUN_00BDA8A0, dynamic initializer of the copy at 0x010B95F4)
   * Address: 0x00C00360 (FUN_00C00360, that copy's atexit destructor)
   * Address: 0x00BDAAF0 (FUN_00BDAAF0, dynamic initializer of the copy at 0x010B9818)
   * Address: 0x00C00410 (FUN_00C00410, that copy's atexit destructor)
   * Address: 0x00BDAD20 (FUN_00BDAD20, dynamic initializer of the copy at 0x010B9D04)
   * Address: 0x00C005F0 (FUN_00C005F0, that copy's atexit destructor)
   * Address: 0x00BDB120 (FUN_00BDB120, dynamic initializer of the copy at 0x010BA12C)
   * Address: 0x00C00610 (FUN_00C00610, that copy's atexit destructor)
   * Address: 0x00BDB640 (FUN_00BDB640, dynamic initializer of the copy at 0x010BA324)
   * Address: 0x00C00AC0 (FUN_00C00AC0, that copy's atexit destructor)
   * Address: 0x00BDB850 (FUN_00BDB850, dynamic initializer of the copy at 0x010BA3E0)
   * Address: 0x00C00B80 (FUN_00C00B80, that copy's atexit destructor)
   * Address: 0x00BDB960 (FUN_00BDB960, dynamic initializer of the copy at 0x010BA5DC)
   * Address: 0x00C00C60 (FUN_00C00C60, that copy's atexit destructor)
   * Address: 0x00BDBE60 (FUN_00BDBE60, dynamic initializer of the copy at 0x010BAC0C)
   * Address: 0x00C011F0 (FUN_00C011F0, that copy's atexit destructor)
   * Address: 0x00BDC490 (FUN_00BDC490, dynamic initializer of the copy at 0x010BAF3C)
   * Address: 0x00C01450 (FUN_00C01450, that copy's atexit destructor)
   * Address: 0x00BDC730 (FUN_00BDC730, dynamic initializer of the copy at 0x010BB0E8)
   * Address: 0x00C01950 (FUN_00C01950, that copy's atexit destructor)
   * Address: 0x00BDC8F0 (FUN_00BDC8F0, dynamic initializer of the copy at 0x010BB194)
   * Address: 0x00C01A30 (FUN_00C01A30, that copy's atexit destructor)
   * Address: 0x00BDCA40 (FUN_00BDCA40, dynamic initializer of the copy at 0x010BB26C)
   * Address: 0x00C01C00 (FUN_00C01C00, that copy's atexit destructor)
   * Address: 0x00BDCB50 (FUN_00BDCB50, dynamic initializer of the copy at 0x010BB364)
   * Address: 0x00C01D70 (FUN_00C01D70, that copy's atexit destructor)
   * Address: 0x00BDCC80 (FUN_00BDCC80, dynamic initializer of the copy at 0x010BB4A0)
   * Address: 0x00C01E20 (FUN_00C01E20, that copy's atexit destructor)
   * Address: 0x00BDCDD0 (FUN_00BDCDD0, dynamic initializer of the copy at 0x010BB58C)
   * Address: 0x00C01FC0 (FUN_00C01FC0, that copy's atexit destructor)
   * Address: 0x00BDCFA0 (FUN_00BDCFA0, dynamic initializer of the copy at 0x010BB90C)
   * Address: 0x00C02110 (FUN_00C02110, that copy's atexit destructor)
   * Address: 0x00BDD290 (FUN_00BDD290, dynamic initializer of the copy at 0x010BBA28)
   * Address: 0x00C02430 (FUN_00C02430, that copy's atexit destructor)
   * Address: 0x00BDD450 (FUN_00BDD450, dynamic initializer of the copy at 0x010BBB5C)
   * Address: 0x00C02510 (FUN_00C02510, that copy's atexit destructor)
   * Address: 0x00BDD600 (FUN_00BDD600, dynamic initializer of the copy at 0x010BBB94)
   * Address: 0x00C02620 (FUN_00C02620, that copy's atexit destructor)
   * Address: 0x00BDD790 (FUN_00BDD790, dynamic initializer of the copy at 0x010BBD34)
   * Address: 0x00C027A0 (FUN_00C027A0, that copy's atexit destructor)
   * Address: 0x00BDD960 (FUN_00BDD960, dynamic initializer of the copy at 0x010BC13C)
   * Address: 0x00C02A90 (FUN_00C02A90, that copy's atexit destructor)
   * Address: 0x00BDDBB0 (FUN_00BDDBB0, dynamic initializer of the copy at 0x010BC224)
   * Address: 0x00C02B10 (FUN_00C02B10, that copy's atexit destructor)
   * Address: 0x00BDDD30 (FUN_00BDDD30, dynamic initializer of the copy at 0x010BC5D4)
   * Address: 0x00C02B90 (FUN_00C02B90, that copy's atexit destructor)
   * Address: 0x00BDDF40 (FUN_00BDDF40, dynamic initializer of the copy at 0x010BC7BC)
   * Address: 0x00C02C20 (FUN_00C02C20, that copy's atexit destructor)
   * Address: 0x00BDE0B0 (FUN_00BDE0B0, dynamic initializer of the copy at 0x010BC92C)
   * Address: 0x00C02CD0 (FUN_00C02CD0, that copy's atexit destructor)
   * Address: 0x00BDE220 (FUN_00BDE220, dynamic initializer of the copy at 0x010BCD90)
   * Address: 0x00C02D80 (FUN_00C02D80, that copy's atexit destructor)
   * Address: 0x00BDE4B0 (FUN_00BDE4B0, dynamic initializer of the copy at 0x010BCE54)
   * Address: 0x00C02E00 (FUN_00C02E00, that copy's atexit destructor)
   * Address: 0x00BDE540 (FUN_00BDE540, dynamic initializer of the copy at 0x010BCFAC)
   * Address: 0x00C02E30 (FUN_00C02E30, that copy's atexit destructor)
   * Address: 0x00BDE670 (FUN_00BDE670, dynamic initializer of the copy at 0x010BD004)
   * Address: 0x00C02EB0 (FUN_00C02EB0, that copy's atexit destructor)
   * Address: 0x00BDE770 (FUN_00BDE770, dynamic initializer of the copy at 0x010BD124)
   * Address: 0x00C02F30 (FUN_00C02F30, that copy's atexit destructor)
   * Address: 0x00BDE900 (FUN_00BDE900, dynamic initializer of the copy at 0x010BD17C)
   * Address: 0x00C02FB0 (FUN_00C02FB0, that copy's atexit destructor)
   * Address: 0x00BDEAD0 (FUN_00BDEAD0, dynamic initializer of the copy at 0x010BD52C)
   * Address: 0x00C03030 (FUN_00C03030, that copy's atexit destructor)
   * Address: 0x00BDEBA0 (FUN_00BDEBA0, dynamic initializer of the copy at 0x010BD68C)
   * Address: 0x00C03090 (FUN_00C03090, that copy's atexit destructor)
   * Address: 0x00BDECC0 (FUN_00BDECC0, dynamic initializer of the copy at 0x010BD69C)
   * Address: 0x00C03110 (FUN_00C03110, that copy's atexit destructor)
   * Address: 0x00BDEE30 (FUN_00BDEE30, dynamic initializer of the copy at 0x010BD894)
   * Address: 0x00C03190 (FUN_00C03190, that copy's atexit destructor)
   * Address: 0x00BDEF70 (FUN_00BDEF70, dynamic initializer of the copy at 0x010BDA9C)
   * Address: 0x00C03210 (FUN_00C03210, that copy's atexit destructor)
   * Address: 0x00BDF100 (FUN_00BDF100, dynamic initializer of the copy at 0x010BDBB8)
   * Address: 0x00C03290 (FUN_00C03290, that copy's atexit destructor)
   * Address: 0x00BDF230 (FUN_00BDF230, dynamic initializer of the copy at 0x010BDBEC)
   * Address: 0x00C032F0 (FUN_00C032F0, that copy's atexit destructor)
   * Address: 0x00BDF8C0 (FUN_00BDF8C0, dynamic initializer of the copy at 0x010BE008)
   * Address: 0x00C036B0 (FUN_00C036B0, that copy's atexit destructor)
   * Address: 0x00BDF910 (FUN_00BDF910, dynamic initializer of the copy at 0x010BE03C)
   * Address: 0x00C03700 (FUN_00C03700, that copy's atexit destructor)
   * Address: 0x00BDFA70 (FUN_00BDFA70, dynamic initializer of the copy at 0x010BE04C)
   * Address: 0x00C03780 (FUN_00C03780, that copy's atexit destructor)
   * Address: 0x00BDFB20 (FUN_00BDFB20, dynamic initializer of the copy at 0x010BE108)
   * Address: 0x00C037D0 (FUN_00C037D0, that copy's atexit destructor)
   * Address: 0x00BDFBF0 (FUN_00BDFBF0, dynamic initializer of the copy at 0x010BE18C)
   * Address: 0x00C03880 (FUN_00C03880, that copy's atexit destructor)
   * Address: 0x00BDFCC0 (FUN_00BDFCC0, dynamic initializer of the copy at 0x010BE4EC)
   * Address: 0x00C038E0 (FUN_00C038E0, that copy's atexit destructor)
   * Address: 0x00BDFFD0 (FUN_00BDFFD0, dynamic initializer of the copy at 0x010BE5D4)
   * Address: 0x00C03A20 (FUN_00C03A20, that copy's atexit destructor)
   * Address: 0x00BE0040 (FUN_00BE0040, dynamic initializer of the copy at 0x010BE5E4)
   * Address: 0x00C03A40 (FUN_00C03A40, that copy's atexit destructor)
   * Address: 0x00BE00B0 (FUN_00BE00B0, dynamic initializer of the copy at 0x010BE5F4)
   * Address: 0x00C03A60 (FUN_00C03A60, that copy's atexit destructor)
   * Address: 0x00BE0120 (FUN_00BE0120, dynamic initializer of the copy at 0x010BE604)
   * Address: 0x00C03A80 (FUN_00C03A80, that copy's atexit destructor)
   * Address: 0x00BE0190 (FUN_00BE0190, dynamic initializer of the copy at 0x010BE614)
   * Address: 0x00C03AA0 (FUN_00C03AA0, that copy's atexit destructor)
   * Address: 0x00BE02A0 (FUN_00BE02A0, dynamic initializer of the copy at 0x010BE624)
   * Address: 0x00C03AF0 (FUN_00C03AF0, that copy's atexit destructor)
   * Address: 0x00BE0310 (FUN_00BE0310, dynamic initializer of the copy at 0x010BE650)
   * Address: 0x00C03B10 (FUN_00C03B10, that copy's atexit destructor)
   * Address: 0x00BE0440 (FUN_00BE0440, dynamic initializer of the copy at 0x010BE660)
   * Address: 0x00C03C10 (FUN_00C03C10, that copy's atexit destructor)
   * Address: 0x00BE04B0 (FUN_00BE04B0, dynamic initializer of the copy at 0x010BEEF0)
   * Address: 0x00C03C30 (FUN_00C03C30, that copy's atexit destructor)
   * Address: 0x00BE0940 (FUN_00BE0940, dynamic initializer of the copy at 0x010BEFE8)
   * Address: 0x00C03EC0 (FUN_00C03EC0, that copy's atexit destructor)
   * Address: 0x00BE0A10 (FUN_00BE0A10, dynamic initializer of the copy at 0x010BEFF8)
   * Address: 0x00C03EE0 (FUN_00C03EE0, that copy's atexit destructor)
   * Address: 0x00BE0A60 (FUN_00BE0A60, dynamic initializer of the copy at 0x010BF014)
   * Address: 0x00C03F30 (FUN_00C03F30, that copy's atexit destructor)
   * Address: 0x00BE0CF0 (FUN_00BE0CF0, dynamic initializer of the copy at 0x010BF06C)
   * Address: 0x00C04090 (FUN_00C04090, that copy's atexit destructor)
   * Address: 0x00BE0D90 (FUN_00BE0D90, dynamic initializer of the copy at 0x010BF084)
   * Address: 0x00C04110 (FUN_00C04110, that copy's atexit destructor)
   * Address: 0x00BE0E40 (FUN_00BE0E40, dynamic initializer of the copy at 0x010BF094)
   * Address: 0x00C04160 (FUN_00C04160, that copy's atexit destructor)
   * Address: 0x00BE0FD0 (FUN_00BE0FD0, dynamic initializer of the copy at 0x010BF0A4)
   * Address: 0x00C042E0 (FUN_00C042E0, that copy's atexit destructor)
   * Address: 0x00BE1320 (FUN_00BE1320, dynamic initializer of the copy at 0x010BF610)
   * Address: 0x00C04490 (FUN_00C04490, that copy's atexit destructor)
   * Address: 0x00BE1CB0 (FUN_00BE1CB0, dynamic initializer of the copy at 0x010BF648)
   * Address: 0x00C04B40 (FUN_00C04B40, that copy's atexit destructor)
   * Address: 0x00BE1F50 (FUN_00BE1F50, dynamic initializer of the copy at 0x010BF664)
   * Address: 0x00C04D30 (FUN_00C04D30, that copy's atexit destructor)
   * Address: 0x00BE2060 (FUN_00BE2060, dynamic initializer of the copy at 0x010BF744)
   * Address: 0x00C04E00 (FUN_00C04E00, that copy's atexit destructor)
   * Address: 0x00BE3100 (FUN_00BE3100, dynamic initializer of the copy at 0x010C0E78)
   * Address: 0x00C05950 (FUN_00C05950, that copy's atexit destructor)
   * Address: 0x00BE3290 (FUN_00BE3290, dynamic initializer of the copy at 0x010C1668)
   * Address: 0x00C05A90 (FUN_00C05A90, that copy's atexit destructor)
   * Address: 0x00BE3740 (FUN_00BE3740, dynamic initializer of the copy at 0x010C1900)
   * Address: 0x00C05CD0 (FUN_00C05CD0, that copy's atexit destructor)
   * Address: 0x00BE3890 (FUN_00BE3890, dynamic initializer of the copy at 0x010C1910)
   * Address: 0x00C05D80 (FUN_00C05D80, that copy's atexit destructor)
   * Address: 0x00BE3900 (FUN_00BE3900, dynamic initializer of the copy at 0x010C1920)
   * Address: 0x00C05DA0 (FUN_00C05DA0, that copy's atexit destructor)
   * Address: 0x00BE3970 (FUN_00BE3970, dynamic initializer of the copy at 0x010C1930)
   * Address: 0x00C05DC0 (FUN_00C05DC0, that copy's atexit destructor)
   * Address: 0x00BE3A40 (FUN_00BE3A40, dynamic initializer of the copy at 0x010C19B8)
   * Address: 0x00C05DE0 (FUN_00C05DE0, that copy's atexit destructor)
   * Address: 0x00BE3AD0 (FUN_00BE3AD0, dynamic initializer of the copy at 0x010C19C8)
   * Address: 0x00C05E10 (FUN_00C05E10, that copy's atexit destructor)
   * Address: 0x00BE3B40 (FUN_00BE3B40, dynamic initializer of the copy at 0x010C19D8)
   * Address: 0x00C05E30 (FUN_00C05E30, that copy's atexit destructor)
   * Address: 0x00BE3BB0 (FUN_00BE3BB0, dynamic initializer of the copy at 0x010C19E8)
   * Address: 0x00C05E50 (FUN_00C05E50, that copy's atexit destructor)
   * Address: 0x00BE3EE0 (FUN_00BE3EE0, dynamic initializer of the copy at 0x010C19F8)
   * Address: 0x00C06080 (FUN_00C06080, that copy's atexit destructor)
   * Address: 0x00BE4650 (FUN_00BE4650, dynamic initializer of the copy at 0x010C1A68)
   * Address: 0x00C065E0 (FUN_00C065E0, that copy's atexit destructor)
   * Address: 0x00BE46C0 (FUN_00BE46C0, dynamic initializer of the copy at 0x010C1AC0)
   * Address: 0x00C06680 (FUN_00C06680, that copy's atexit destructor)
   * Address: 0x00BE4790 (FUN_00BE4790, dynamic initializer of the copy at 0x010C3754)
   * Address: 0x00C066A0 (FUN_00C066A0, that copy's atexit destructor)
   * Address: 0x00BE4980 (FUN_00BE4980, dynamic initializer of the copy at 0x010C3DE8)
   * Address: 0x00C06820 (FUN_00C06820, that copy's atexit destructor)
   * Address: 0x00BE4E00 (FUN_00BE4E00, dynamic initializer of the copy at 0x010C3FF0)
   * Address: 0x00C06850 (FUN_00C06850, that copy's atexit destructor)
   * Address: 0x00BE4E70 (FUN_00BE4E70, dynamic initializer of the copy at 0x010C40B4)
   * Address: 0x00C06870 (FUN_00C06870, that copy's atexit destructor)
   * Address: 0x00BE4ED0 (FUN_00BE4ED0, dynamic initializer of the copy at 0x010C4194)
   * Address: 0x00C06890 (FUN_00C06890, that copy's atexit destructor)
   * Address: 0x00BE5000 (FUN_00BE5000, dynamic initializer of the copy at 0x010C41C8)
   * Address: 0x00C06910 (FUN_00C06910, that copy's atexit destructor)
   * Address: 0x00BE50D0 (FUN_00BE50D0, dynamic initializer of the copy at 0x010C41D8)
   * Address: 0x00C06930 (FUN_00C06930, that copy's atexit destructor)
   * Address: 0x00BE5180 (FUN_00BE5180, dynamic initializer of the copy at 0x010C4218)
   * Address: 0x00C06980 (FUN_00C06980, that copy's atexit destructor)
   * Address: 0x00BE51C0 (FUN_00BE51C0, dynamic initializer of the copy at 0x010C422C)
   * Address: 0x00C069C0 (FUN_00C069C0, that copy's atexit destructor)
   * Address: 0x00BE5280 (FUN_00BE5280, dynamic initializer of the copy at 0x010C4254)
   * Address: 0x00C06B00 (FUN_00C06B00, that copy's atexit destructor)
   * Address: 0x00BE5360 (FUN_00BE5360, dynamic initializer of the copy at 0x010C4274)
   * Address: 0x00C06B30 (FUN_00C06B30, that copy's atexit destructor)
   * Address: 0x00BE53B0 (FUN_00BE53B0, dynamic initializer of the copy at 0x010C4304)
   * Address: 0x00C06B80 (FUN_00C06B80, that copy's atexit destructor)
   * Address: 0x00BE5B80 (FUN_00BE5B80, dynamic initializer of the copy at 0x010C4320)
   * Address: 0x00C07170 (FUN_00C07170, that copy's atexit destructor)
   * Address: 0x00BE5D30 (FUN_00BE5D30, dynamic initializer of the copy at 0x010C4330)
   * Address: 0x00C07290 (FUN_00C07290, that copy's atexit destructor)
   * Address: 0x00BE5F60 (FUN_00BE5F60, dynamic initializer of the copy at 0x010C4388)
   * Address: 0x00C07400 (FUN_00C07400, that copy's atexit destructor)
   * Address: 0x00BE6070 (FUN_00BE6070, dynamic initializer of the copy at 0x010C4404)
   * Address: 0x00C07490 (FUN_00C07490, that copy's atexit destructor)
   * Address: 0x00BE62D0 (FUN_00BE62D0, dynamic initializer of the copy at 0x010C4434)
   * Address: 0x00C075B0 (FUN_00C075B0, that copy's atexit destructor)
   * Address: 0x00BE6360 (FUN_00BE6360, dynamic initializer of the copy at 0x010C448C)
   * Address: 0x00C07690 (FUN_00C07690, that copy's atexit destructor)
   * Address: 0x00BE6450 (FUN_00BE6450, dynamic initializer of the copy at 0x010C475C)
   * Address: 0x00C07710 (FUN_00C07710, that copy's atexit destructor)
   * Address: 0x00BE6690 (FUN_00BE6690, dynamic initializer of the copy at 0x010C483C)
   * Address: 0x00C07790 (FUN_00C07790, that copy's atexit destructor)
   * Address: 0x00BE6C30 (FUN_00BE6C30, dynamic initializer of the copy at 0x010C4AF4)
   * Address: 0x00C07AF0 (FUN_00C07AF0, that copy's atexit destructor)
   * Address: 0x00BE6D10 (FUN_00BE6D10, dynamic initializer of the copy at 0x010C4B70)
   * Address: 0x00C07B60 (FUN_00C07B60, that copy's atexit destructor)
   * Address: 0x00BE6D30 (FUN_00BE6D30, dynamic initializer of the copy at 0x010C4B80)
   * Address: 0x00C07B80 (FUN_00C07B80, that copy's atexit destructor)
   * Address: 0x00BE6E10 (FUN_00BE6E10, dynamic initializer of the copy at 0x010C4BB4)
   * Address: 0x00C07BA0 (FUN_00C07BA0, that copy's atexit destructor)
   * Address: 0x00BE6E20 (FUN_00BE6E20, dynamic initializer of the copy at 0x010C4BC4)
   * Address: 0x00C07BC0 (FUN_00C07BC0, that copy's atexit destructor)
   * Address: 0x00BE6F50 (FUN_00BE6F50, dynamic initializer of the copy at 0x010C4DC0)
   * Address: 0x00C07C40 (FUN_00C07C40, that copy's atexit destructor)
   * Address: 0x00BE7120 (FUN_00BE7120, dynamic initializer of the copy at 0x010C4E58)
   * Address: 0x00C07E10 (FUN_00C07E10, that copy's atexit destructor)
   * Address: 0x00BE7140 (FUN_00BE7140, dynamic initializer of the copy at 0x010C4E8C)
   * Address: 0x00C07E40 (FUN_00C07E40, that copy's atexit destructor)
   * Address: 0x00BE71F0 (FUN_00BE71F0, dynamic initializer of the copy at 0x010C4F54)
   * Address: 0x00C07E90 (FUN_00C07E90, that copy's atexit destructor)
   * Address: 0x00BE7590 (FUN_00BE7590, dynamic initializer of the copy at 0x010C4FD4)
   * Address: 0x00C080E0 (FUN_00C080E0, that copy's atexit destructor)
   * Address: 0x00BE7670 (FUN_00BE7670, dynamic initializer of the copy at 0x010C4FE8)
   * Address: 0x00C08120 (FUN_00C08120, that copy's atexit destructor)
   * Address: 0x00BE7680 (FUN_00BE7680, dynamic initializer of the copy at 0x010C51C4)
   * Address: 0x00C08140 (FUN_00C08140, that copy's atexit destructor)
   * Address: 0x00BE79F0 (FUN_00BE79F0, dynamic initializer of the copy at 0x010C52F0)
   * Address: 0x00C08370 (FUN_00C08370, that copy's atexit destructor)
   * Address: 0x00BE7D80 (FUN_00BE7D80, dynamic initializer of the copy at 0x010C5300)
   * Address: 0x00C084B0 (FUN_00C084B0, that copy's atexit destructor)
   * Address: 0x00BE7E30 (FUN_00BE7E30, dynamic initializer of the copy at 0x010C54E8)
   * Address: 0x00C08500 (FUN_00C08500, that copy's atexit destructor)
   * Address: 0x00BE80A0 (FUN_00BE80A0, dynamic initializer of the copy at 0x010C5540)
   * Address: 0x00C08600 (FUN_00C08600, that copy's atexit destructor)
   * Address: 0x00BE80B0 (FUN_00BE80B0, dynamic initializer of the copy at 0x010C5550)
   * Address: 0x00C08620 (FUN_00C08620, that copy's atexit destructor)
   * Address: 0x00BE81C0 (FUN_00BE81C0, dynamic initializer of the copy at 0x010C5560)
   * Address: 0x00C08670 (FUN_00C08670, that copy's atexit destructor)
   * Address: 0x00BE8230 (FUN_00BE8230, dynamic initializer of the copy at 0x010C5570)
   * Address: 0x00C08690 (FUN_00C08690, that copy's atexit destructor)
   * Address: 0x00BE82A0 (FUN_00BE82A0, dynamic initializer of the copy at 0x010C5580)
   * Address: 0x00C086B0 (FUN_00C086B0, that copy's atexit destructor)
   * Address: 0x00BE82B0 (FUN_00BE82B0, dynamic initializer of the copy at 0x010C5590)
   * Address: 0x00C086D0 (FUN_00C086D0, that copy's atexit destructor)
   * Address: 0x00BE8380 (FUN_00BE8380, dynamic initializer of the copy at 0x010C5AB0)
   * Address: 0x00C086F0 (FUN_00C086F0, that copy's atexit destructor)
   * Address: 0x00BE8660 (FUN_00BE8660, dynamic initializer of the copy at 0x010C5B2C)
   * Address: 0x00C08710 (FUN_00C08710, that copy's atexit destructor)
   * Address: 0x00BE86D0 (FUN_00BE86D0, dynamic initializer of the copy at 0x010C6020)
   * Address: 0x00C08730 (FUN_00C08730, that copy's atexit destructor)
   * Address: 0x00BE89B0 (FUN_00BE89B0, dynamic initializer of the copy at 0x010C60E4)
   * Address: 0x00C087E0 (FUN_00C087E0, that copy's atexit destructor)
   * Address: 0x00BE8AC0 (FUN_00BE8AC0, dynamic initializer of the copy at 0x010C60F4)
   * Address: 0x00C08850 (FUN_00C08850, that copy's atexit destructor)
   * Address: 0x00BE8B30 (FUN_00BE8B30, dynamic initializer of the copy at 0x010C61DC)
   * Address: 0x00C08870 (FUN_00C08870, that copy's atexit destructor)
   * Address: 0x00BE8CF0 (FUN_00BE8CF0, dynamic initializer of the copy at 0x010C6290)
   * Address: 0x00C08A70 (FUN_00C08A70, that copy's atexit destructor)
   */
  static boost::scoped_ptr<EngineStats> sEngineStats;

  /**
   * Address: 0x00408940 (FUN_00408940, Moho::GetEngineStats)
   */
  [[nodiscard]] EngineStats* GetEngineStats();

  /**
   * Address: 0x0047A5E0 (FUN_0047A5E0, Moho::LOG_GenerateFilenamePrefix)
   *
   * What it does:
   * Builds a local-time filename prefix as `YYYY-MM-DD.HH-MM`.
   */
  [[nodiscard]] msvc8::string LOG_GenerateFilenamePrefix();

  /**
   * Address: 0x00415E60 (FUN_00415E60, Moho::STAT_Frame)
   *
   * What it does:
   * Advances one stats frame by applying frame pulse clears and capturing
   * per-item logging samples when logging is active.
   */
  void STAT_Frame();

  /**
   * Address: 0x0041B390 (FUN_0041B390, Moho::STAT_GetLuaTable)
   *
   * What it does:
   * Serializes one `StatItem` tree node into a Lua table, recursively emitting
   * child tables under `Children`.
   */
  void STAT_GetLuaTable(LuaPlus::LuaState* state, StatItem* item, LuaPlus::LuaObject& outObject);

  /**
   * Address: 0x004162C0 (FUN_004162C0, Moho::CON_ClearStats)
   *
   * What it does:
   * Clears a stats subtree selected from the console argument vector and
   * forwards to the engine stats delete path.
   */
  void CON_ClearStats(const msvc8::vector<msvc8::string>& args);

  /**
   * Address: 0x004163A0 (FUN_004163A0, Moho::CON_BeginLoggingStats)
   *
   * What it does:
   * Selects a logging file name from console args, resets the logging frame
   * counter, and enables stats logging.
   */
  void CON_BeginLoggingStats(const msvc8::vector<msvc8::string>& args);

  /**
   * Address: 0x00415EC0 (FUN_00415EC0, Moho::CON_PrintStats)
   *
   * What it does:
   * Exercises and prints a debug stats subtree from the console command lane.
   */
  void CON_PrintStats(const msvc8::vector<msvc8::string>& args);

  /**
   * Address: 0x00834F90 (FUN_00834F90, Moho::ShowStats)
   *
   * What it does:
   * Imports `/lua/debug/EngineStats.lua` and calls its `Toggle` entry with
   * the requested stats mode token (default `"all"`).
   */
  void ShowStats(const msvc8::vector<msvc8::string>& args);

  /**
   * Address: 0x00835160 (FUN_00835160, Moho::ShowArmyStats)
   *
   * What it does:
   * Imports `/lua/debug/ArmyStats.lua` and calls its `Show` entry with army
   * index + display mode from console args (defaults: focused army + `"all"`).
   */
  void ShowArmyStats(const msvc8::vector<msvc8::string>& args);

  /**
   * Address: 0x00416480 (FUN_00416480, Moho::CON_EndLoggingStats)
   *
   * What it does:
   * Console end-logging entry that finalizes the active stats log.
   */
  void CON_EndLoggingStats(const msvc8::vector<msvc8::string>& args);

  /**
   * Address: 0x00416490 (FUN_00416490, cfunc_BeginLoggingStats)
   *
   * What it does:
   * Lua thunk that unwraps `lua_State*` into `LuaPlus::LuaState*` and forwards
   * to the recovered Lua logging helper.
   */
  int cfunc_BeginLoggingStats(lua_State* luaContext);

  /**
   * Address: 0x00416510 (FUN_00416510, cfunc_BeginLoggingStatsL)
   *
   * What it does:
   * Lua-side begin-logging callback that validates one string argument and
   * enables engine stat logging.
   */
  int cfunc_BeginLoggingStatsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00416640 (FUN_00416640, cfunc_EndLoggingStats)
   *
   * What it does:
   * Lua thunk that unwraps `lua_State*` into `LuaPlus::LuaState*` and forwards
   * to end-logging callback.
   */
  int cfunc_EndLoggingStats(lua_State* luaContext);

  /**
   * Address: 0x004166C0 (FUN_004166C0, cfunc_EndLoggingStatsL)
   *
   * What it does:
   * Lua-side end-logging callback that finalizes stats logging and optionally
   * exits the app after showing score summary.
   */
  int cfunc_EndLoggingStatsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004164B0 (FUN_004164B0, func_BeginLoggingStats_LuaFuncDef)
   *
   * What it does:
   * Returns the global Lua binder for `BeginLoggingStats`.
   */
  [[nodiscard]] CScrLuaInitForm* func_BeginLoggingStats_LuaFuncDef();

  /**
   * Address: 0x00416660 (FUN_00416660, func_EndLoggingStats_LuaFuncDef)
   *
   * What it does:
   * Returns the global Lua binder for `EndLoggingStats`.
   */
  [[nodiscard]] CScrLuaInitForm* func_EndLoggingStats_LuaFuncDef();

  /**
   * Address: 0x00BC3540 (FUN_00BC3540, register_BeginLoggingStats_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_BeginLoggingStats_LuaFuncDef`.
   */
  void register_BeginLoggingStats_LuaFuncDef();

  /**
   * Address: 0x00BC3550 (FUN_00BC3550, register_EndLoggingStats_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_EndLoggingStats_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_EndLoggingStats_LuaFuncDef();

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

    /**
     * Address: 0x005944F0 (FUN_005944F0, func_TraverseTables2)
     *
     * What it does:
     * Create-enabled wrapper lane over token traversal used by legacy
     * CArmyStats helper callsites.
     */
    [[nodiscard]] CArmyStatItem* TraverseTablesCreate(gpg::StrArg statPath);

    /**
     * Address: 0x00706360 (FUN_00706360, sub_706360)
     * Alias:   0x00705BD0 (FUN_00705BD0, thunk)
     *
     * What it does:
     * Resolves one tokenized path, creates missing nodes, and marks newly
     * created stat items as string-typed.
     */
    [[nodiscard]] CArmyStatItem* GetStringItem(gpg::StrArg statPath);

    static gpg::RType* sType;

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
    boost::mutex* mLock;  // +0x08 (runtime-owned lock pointer, ABI cell)
    std::uint8_t pad_000D[3];
  };

  static_assert(offsetof(Stats<CArmyStatItem>, mItem) == 0x04, "Stats<CArmyStatItem>::mItem offset must be 0x04");
  static_assert(offsetof(Stats<CArmyStatItem>, mLock) == 0x08, "Stats<CArmyStatItem>::mLock offset must be 0x08");
  static_assert(sizeof(Stats<CArmyStatItem>) == 0x10, "Stats<CArmyStatItem> size must be 0x10");

  template <class T>
  class StatsRType;
} // namespace moho
