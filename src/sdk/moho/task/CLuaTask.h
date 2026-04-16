#pragma once

#include <cstddef>
#include <cstdint>

#include "CTask.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"

namespace moho
{
  class CScrLuaInitForm;

  /**
   * Address: 0x004D33A0 (FUN_004D33A0,
   * ?SCR_Traceback@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PAVLuaState@LuaPlus@@VStrArg@gpg@@@Z)
   *
   * LuaPlus::LuaState *, gpg::StrArg
   *
   * What it does:
   * Pushes lua traceback text for the provided message and returns it.
   */
  [[nodiscard]]
  msvc8::string SCR_Traceback(LuaPlus::LuaState* state, gpg::StrArg message);

  class CLuaTask : public CTask
  {
  public:
    /**
     * Address: 0x004C9570 (FUN_004C9570, ??0CLuaTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes Lua task ownership on the provided thread stack, adopts one
     * pending `LuaState*` lane from `newState`, and binds back-reference.
     */
    CLuaTask(CTaskThread* thread, LuaPlus::LuaState** newState);

    /**
     * Address: 0x004C9990 (FUN_004C9990, scalar deleting thunk)
     * Address: 0x004C9610 (FUN_004C9610, non-deleting body)
     *
     * VFTable SLOT: 0
     */
    ~CLuaTask() override;

    /**
     * Address: 0x004C9700 (FUN_004C9700, ?Execute@CLuaTask@Moho@@UAEHXZ)
     *
     * What it does:
     * Resumes coroutine state, handles thread-destroy race protection, and
     * returns next wake tick (-1 on completion/error).
     */
    int Execute() override;

    /**
     * Address: 0x004CC2B0 (FUN_004CC2B0, Moho::CLuaTask::MemberDeserialize)
     *
     * What it does:
     * Loads base `CTask` lane, owned `LuaState*`, and resume-argument count.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004CC320 (FUN_004CC320, Moho::CLuaTask::MemberSerialize)
     *
     * What it does:
     * Saves base `CTask` lane, owned `LuaState*`, and resume-argument count.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

  public:
    // 0x18: reserved/unknown dword (constructor 0x004C9570 does not initialize it).
    std::uint32_t mReserved18;
    LuaPlus::LuaState* mLuaState; // 0x1C
    std::int32_t mResumeArgCount; // 0x20
    bool* mExecuteDestroyedFlag;  // 0x24
  };

  class CLuaTaskConstruct
  {
  public:
    /**
     * Address: 0x004CAF60 (FUN_004CAF60, sub_4CAF60)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into CLuaTask RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  class CLuaTaskSerializer
  {
  public:
    /**
     * Address: 0x004CAFE0 (FUN_004CAFE0, sub_4CAFE0)
     * Slot: 0
     *
     * What it does:
     * Binds load/save serializer callbacks into CLuaTask RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CLuaTaskTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004C9A60 (FUN_004C9A60, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CLuaTaskTypeInfo() override;

    /**
     * Address: 0x004C9A50 (FUN_004C9A50, ?GetName@CLuaTaskTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004C9A30 (FUN_004C9A30, ?Init@CLuaTaskTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CLuaTask) == 0x28, "CLuaTask size must be 0x28");
  static_assert(offsetof(CLuaTask, mReserved18) == 0x18, "CLuaTask::mReserved18 offset must be 0x18");
  static_assert(offsetof(CLuaTask, mLuaState) == 0x1C, "CLuaTask::mLuaState offset must be 0x1C");
  static_assert(offsetof(CLuaTask, mResumeArgCount) == 0x20, "CLuaTask::mResumeArgCount offset must be 0x20");
  static_assert(
    offsetof(CLuaTask, mExecuteDestroyedFlag) == 0x24, "CLuaTask::mExecuteDestroyedFlag offset must be 0x24"
  );
  static_assert(sizeof(CLuaTaskConstruct) == 0x14, "CLuaTaskConstruct size must be 0x14");
  static_assert(sizeof(CLuaTaskSerializer) == 0x14, "CLuaTaskSerializer size must be 0x14");
  static_assert(sizeof(CLuaTaskTypeInfo) == 0x64, "CLuaTaskTypeInfo size must be 0x64");

  /**
   * Address: 0x004CA890 (FUN_004CA890, cfunc_WaitFor)
   *
   * What it does:
   * Unwraps Lua binding callback context and forwards to `cfunc_WaitForL`.
   */
  int cfunc_WaitFor(lua_State* luaContext);

  /**
   * Address: 0x004CA910 (FUN_004CA910, cfunc_WaitForL)
   *
   * What it does:
   * Validates one event argument, pushes a `CWaitForTask` above the current
   * Lua task on the owner thread stack, then yields for one frame tick lane.
   */
  int cfunc_WaitForL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004CA8B0 (FUN_004CA8B0, func_WaitFor_LuaFuncDef)
   *
   * What it does:
   * Publishes the global core-lane Lua binder definition for `WaitFor`.
   */
  CScrLuaInitForm* func_WaitFor_LuaFuncDef();

  /**
   * Address: 0x00BC6320 (FUN_00BC6320, register_WaitFor_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_WaitFor_LuaFuncDef`.
   */
  CScrLuaInitForm* register_WaitFor_LuaFuncDef();

  /**
   * Address: 0x004C9D00 (FUN_004C9D00, cfunc_ForkThread)
   *
   * What it does:
   * Unwraps Lua binding callback context and forwards to `cfunc_ForkThreadL`.
   */
  int cfunc_ForkThread(lua_State* luaContext);

  /**
   * Address: 0x004C9D80 (FUN_004C9D80, cfunc_ForkThreadL)
   *
   * What it does:
   * Spawns one Lua task thread from function + args and returns the coroutine
   * thread object to the calling state.
   */
  int cfunc_ForkThreadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004C9D20 (FUN_004C9D20, func_ForkThread_LuaFuncDef)
   *
   * What it does:
   * Publishes the global core-lane Lua binder definition for `ForkThread`.
   */
  CScrLuaInitForm* func_ForkThread_LuaFuncDef();

  /**
   * Address: 0x00BC6200 (FUN_00BC6200, register_ForkThread_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_ForkThread_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ForkThread_LuaFuncDef();

  /**
   * Address: 0x004C9FE0 (FUN_004C9FE0, cfunc_KillThread)
   *
   * What it does:
   * Unwraps Lua binding callback context and forwards to `cfunc_KillThreadL`.
   */
  int cfunc_KillThread(lua_State* luaContext);

  /**
   * Address: 0x004CA060 (FUN_004CA060, cfunc_KillThreadL)
   *
   * What it does:
   * Validates one thread argument and destroys a ForkThread-created task thread.
   */
  int cfunc_KillThreadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004CA000 (FUN_004CA000, func_KillThread_LuaFuncDef)
   *
   * What it does:
   * Publishes the global core-lane Lua binder definition for `KillThread`.
   */
  CScrLuaInitForm* func_KillThread_LuaFuncDef();

  /**
   * Address: 0x00BC6210 (FUN_00BC6210, register_KillThread_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_KillThread_LuaFuncDef`.
   */
  CScrLuaInitForm* register_KillThread_LuaFuncDef();

  /**
   * Address: 0x004CAA70 (FUN_004CAA70, cfunc_SuspendCurrentThread)
   *
   * What it does:
   * Unwraps binding context and forwards to `cfunc_SuspendCurrentThreadL`.
   */
  int cfunc_SuspendCurrentThread(lua_State* luaContext);

  /**
   * Address: 0x004CAAF0 (FUN_004CAAF0, cfunc_SuspendCurrentThreadL)
   *
   * What it does:
   * Validates zero args and suspends the current ForkThread-created task.
   */
  int cfunc_SuspendCurrentThreadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004CAA90 (FUN_004CAA90, func_SuspendCurrentThread_LuaFuncDef)
   *
   * What it does:
   * Publishes the global core-lane Lua binder definition for
   * `SuspendCurrentThread`.
   */
  CScrLuaInitForm* func_SuspendCurrentThread_LuaFuncDef();

  /**
   * Address: 0x00BC6330 (FUN_00BC6330, register_SuspendCurrentThread_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_SuspendCurrentThread_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SuspendCurrentThread_LuaFuncDef();

  /**
   * Address: 0x004CAB90 (FUN_004CAB90, cfunc_ResumeThread)
   *
   * What it does:
   * Unwraps binding context and forwards to `cfunc_ResumeThreadL`.
   */
  int cfunc_ResumeThread(lua_State* luaContext);

  /**
   * Address: 0x004CAC10 (FUN_004CAC10, cfunc_ResumeThreadL)
   *
   * What it does:
   * Validates one coroutine-thread argument, clears thread wait staging, and
   * resumes a ForkThread-created task thread on the next scheduler frame.
   */
  int cfunc_ResumeThreadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004CABB0 (FUN_004CABB0, func_ResumeThread_LuaFuncDef)
   *
   * What it does:
   * Publishes the global core-lane Lua binder definition for `ResumeThread`.
   */
  CScrLuaInitForm* func_ResumeThread_LuaFuncDef();

  /**
   * Address: 0x00BC6340 (FUN_00BC6340, register_ResumeThread_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_ResumeThread_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ResumeThread_LuaFuncDef();

  /**
   * Address: 0x004CAD60 (FUN_004CAD60, cfunc_CurrentThread)
   *
   * What it does:
   * Unwraps binding context and forwards to `cfunc_CurrentThreadL`.
   */
  int cfunc_CurrentThread(lua_State* luaContext);

  /**
   * Address: 0x004CADE0 (FUN_004CADE0, cfunc_CurrentThreadL)
   *
   * What it does:
   * Pushes a Lua thread-handle object for the currently running task thread.
   */
  int cfunc_CurrentThreadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004CAD80 (FUN_004CAD80, func_CurrentThread_LuaFuncDef)
   *
   * What it does:
   * Publishes the global core-lane Lua binder definition for `CurrentThread`.
   */
  CScrLuaInitForm* func_CurrentThread_LuaFuncDef();

  /**
   * Address: 0x00BC6350 (FUN_00BC6350, register_CurrentThread_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_CurrentThread_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CurrentThread_LuaFuncDef();

  /**
   * Address: 0x00BC6160 (FUN_00BC6160, CLuaTask startup type-info registration)
   *
   * What it does:
   * Pre-registers `CLuaTask` reflected type metadata and schedules type-info
   * cleanup at process exit.
   */
  void register_CLuaTaskTypeInfo();

  /**
   * Address: 0x00BC6180 (FUN_00BC6180, CLuaTask startup construct registration)
   *
   * What it does:
   * Initializes construct/delete callback helper lanes for `CLuaTask` and
   * schedules intrusive helper cleanup at process exit.
   */
  void register_CLuaTaskConstruct();

  /**
   * Address: 0x00BC61C0 (FUN_00BC61C0, register_CLuaTaskSerializer)
   *
   * What it does:
   * Initializes startup serializer callback lanes for `CLuaTask` and schedules
   * intrusive helper cleanup at process exit.
   */
  void register_CLuaTaskSerializer();

  /**
     * Address: 0x004C9CA0 (FUN_004C9CA0)
     * Address: 0x004C9CD0 (FUN_004C9CD0)
   *
   * What it does:
   * Unlinks static serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CLuaTaskSerializer();
} // namespace moho
