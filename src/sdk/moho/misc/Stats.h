#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/mutex.h"
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
  void CON_ClearStats(void* commandArgs);

  /**
   * Address: 0x004163A0 (FUN_004163A0, Moho::CON_BeginLoggingStats)
   *
   * What it does:
   * Selects a logging file name from console args, resets the logging frame
   * counter, and enables stats logging.
   */
  void CON_BeginLoggingStats(void* commandArgs);

  /**
   * Address: 0x00415EC0 (FUN_00415EC0, Moho::CON_PrintStats)
   *
   * What it does:
   * Exercises and prints a debug stats subtree from the console command lane.
   */
  void CON_PrintStats(void* commandArgs);

  /**
   * Address: 0x00834F90 (FUN_00834F90, Moho::ShowStats)
   *
   * What it does:
   * Imports `/lua/debug/EngineStats.lua` and calls its `Toggle` entry with
   * the requested stats mode token (default `"all"`).
   */
  void ShowStats(void* commandArgs);

  /**
   * Address: 0x00835160 (FUN_00835160, Moho::ShowArmyStats)
   *
   * What it does:
   * Imports `/lua/debug/ArmyStats.lua` and calls its `Show` entry with army
   * index + display mode from console args (defaults: focused army + `"all"`).
   */
  void ShowArmyStats(void* commandArgs);

  /**
   * Address: 0x00416480 (FUN_00416480, Moho::CON_EndLoggingStats)
   *
   * What it does:
   * Console end-logging entry that finalizes the active stats log.
   */
  void CON_EndLoggingStats(void* commandArgs);

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
