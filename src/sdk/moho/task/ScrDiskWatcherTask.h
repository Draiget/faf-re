#pragma once

#include <cstddef>
#include <cstdint>

#include "CTask.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/CDiskWatch.h"

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class ScrDiskWatcherTask : public CTask
  {
  public:
    /**
     * Address: 0x004C0B60 (FUN_004C0B60, ??0ScrDiskWatcher@Moho@@QAE@@Z)
     *
     * LuaPlus::LuaState *
     *
     * What it does:
     * Initializes a task that listens for disk-change events and dispatches
     * callbacks through the provided Lua state.
     */
    explicit ScrDiskWatcherTask(LuaPlus::LuaState* luaState);

    /**
     * Address: 0x004C0C20 (FUN_004C0C20, scalar deleting thunk)
     * Address: 0x004C0C40 (FUN_004C0C40, non-deleting body)
     */
    ~ScrDiskWatcherTask() override;

    /**
     * Address: 0x004C0CB0 (FUN_004C0CB0, ?Execute@ScrDiskWatcherTask@Moho@@UAEHXZ)
     *
     * What it does:
     * Consumes pending disk-watch events and invokes each Lua callback found
     * in `__diskwatch` with `(resolvedPath, actionCode)`.
     */
    int Execute() override;

  public:
    static gpg::RType* sType;

  public:
    std::uint32_t mReserved18;    // +0x18
    LuaPlus::LuaState* mLuaState; // +0x1C
    CDiskWatchListener mListener; // +0x20
  };

  class ScrDiskWatcherTaskSaveConstruct
  {
  public:
    /**
     * Address: 0x004C0F90 (FUN_004C0F90, sub_4C0F90)
     * Slot: 0
     *
     * What it does:
     * Binds save-construct-args callback into ScrDiskWatcherTask RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  class ScrDiskWatcherTaskConstruct
  {
  public:
    /**
     * Address: 0x004C1010 (FUN_004C1010, sub_4C1010)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into ScrDiskWatcherTask RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  class ScrDiskWatcherTaskTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004C0860 (FUN_004C0860, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~ScrDiskWatcherTaskTypeInfo() override;

    /**
     * Address: 0x004C0850 (FUN_004C0850, ?GetName@ScrDiskWatcherTaskTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004C0830 (FUN_004C0830, ?Init@ScrDiskWatcherTaskTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(ScrDiskWatcherTask) == 0x50, "ScrDiskWatcherTask size must be 0x50");
  static_assert(
    offsetof(ScrDiskWatcherTask, mReserved18) == 0x18, "ScrDiskWatcherTask::mReserved18 offset must be 0x18"
  );
  static_assert(offsetof(ScrDiskWatcherTask, mLuaState) == 0x1C, "ScrDiskWatcherTask::mLuaState offset must be 0x1C");
  static_assert(offsetof(ScrDiskWatcherTask, mListener) == 0x20, "ScrDiskWatcherTask::mListener offset must be 0x20");
  static_assert(sizeof(ScrDiskWatcherTaskSaveConstruct) == 0x10, "ScrDiskWatcherTaskSaveConstruct size must be 0x10");
  static_assert(sizeof(ScrDiskWatcherTaskConstruct) == 0x14, "ScrDiskWatcherTaskConstruct size must be 0x14");
  static_assert(sizeof(ScrDiskWatcherTaskTypeInfo) == 0x64, "ScrDiskWatcherTaskTypeInfo size must be 0x64");
} // namespace moho
