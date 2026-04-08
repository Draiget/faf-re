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

namespace gpg
{
  class SerConstructResult;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00BC5F60 (FUN_00BC5F60, ScrDiskWatcherTask startup type-info registration)
   *
   * What it does:
   * Registers `ScrDiskWatcherTask` reflected type descriptor and schedules
   * type-info cleanup at process exit.
   */
  void register_ScrDiskWatcherTaskTypeInfo();

  /**
   * Address: 0x00BC5F80 (FUN_00BC5F80, ScrDiskWatcherTask startup save-construct registration)
   *
   * What it does:
   * Registers save-construct callback helper for `ScrDiskWatcherTask`.
   */
  void register_ScrDiskWatcherTaskSaveConstruct();

  /**
   * Address: 0x00BC5FB0 (FUN_00BC5FB0, ScrDiskWatcherTask startup construct registration)
   *
   * What it does:
   * Registers construct/delete callback helper for `ScrDiskWatcherTask`.
   */
  void register_ScrDiskWatcherTaskConstruct();

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
     * Address: 0x004C0AB0 (FUN_004C0AB0, ScrDiskWatcherTask construct callback)
     *
     * What it does:
     * Constructs one `ScrDiskWatcherTask` from archived LuaState pointer lane
     * and returns it through unowned construct-result storage.
     */
    static void Construct(
      gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result
    );

    /**
     * Address: 0x004C11F0 (FUN_004C11F0, ScrDiskWatcherTask delete callback)
     *
     * What it does:
     * Deletes one constructed `ScrDiskWatcherTask` object through virtual dtor.
     */
    static void Delete(void* objectPtr);

    /**
     * Address: 0x004C0940 (FUN_004C0940, ScrDiskWatcherTask save-construct callback)
     *
     * What it does:
     * Saves LuaState constructor-args lane as unowned tracked pointer.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive, int objectPtr, int version, gpg::SerSaveConstructArgsResult* result
    );

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
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
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
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
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

  private:
    /**
     * Address: 0x004C1150 (FUN_004C1150, Moho::ScrDiskWatcherTaskTypeInfo::AddBase_CTask)
     *
     * What it does:
     * Adds reflected `CTask` base lane to `ScrDiskWatcherTask` type metadata.
     */
    static void AddBase_CTask(gpg::RType* typeInfo);
  };

  static_assert(sizeof(ScrDiskWatcherTask) == 0x50, "ScrDiskWatcherTask size must be 0x50");
  static_assert(
    offsetof(ScrDiskWatcherTask, mReserved18) == 0x18, "ScrDiskWatcherTask::mReserved18 offset must be 0x18"
  );
  static_assert(offsetof(ScrDiskWatcherTask, mLuaState) == 0x1C, "ScrDiskWatcherTask::mLuaState offset must be 0x1C");
  static_assert(offsetof(ScrDiskWatcherTask, mListener) == 0x20, "ScrDiskWatcherTask::mListener offset must be 0x20");
  static_assert(
    offsetof(ScrDiskWatcherTaskSaveConstruct, mHelperNext) == 0x04,
    "ScrDiskWatcherTaskSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ScrDiskWatcherTaskSaveConstruct, mHelperPrev) == 0x08,
    "ScrDiskWatcherTaskSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ScrDiskWatcherTaskSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "ScrDiskWatcherTaskSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(ScrDiskWatcherTaskConstruct, mHelperNext) == 0x04,
    "ScrDiskWatcherTaskConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ScrDiskWatcherTaskConstruct, mHelperPrev) == 0x08,
    "ScrDiskWatcherTaskConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ScrDiskWatcherTaskConstruct, mSerConstructFunc) == 0x0C,
    "ScrDiskWatcherTaskConstruct::mSerConstructFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(ScrDiskWatcherTaskConstruct, mDeleteFunc) == 0x10,
    "ScrDiskWatcherTaskConstruct::mDeleteFunc offset must be 0x10"
  );
  static_assert(sizeof(ScrDiskWatcherTaskSaveConstruct) == 0x10, "ScrDiskWatcherTaskSaveConstruct size must be 0x10");
  static_assert(sizeof(ScrDiskWatcherTaskConstruct) == 0x14, "ScrDiskWatcherTaskConstruct size must be 0x14");
  static_assert(sizeof(ScrDiskWatcherTaskTypeInfo) == 0x64, "ScrDiskWatcherTaskTypeInfo size must be 0x64");
} // namespace moho
