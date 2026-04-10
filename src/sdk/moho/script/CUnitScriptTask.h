#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/Listener.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"

namespace moho
{
  class CScrLuaInitForm;
  class CUnitCommand;
  class IAiCommandDispatchImpl;

  /**
   * VFTABLE: 0x00E20C38
   * COL: 0x00E7A09C
   *
   * RTTI hierarchy evidence:
   * - base `CCommandTask` at +0x00 (FUN_00622D80/AddBase_CCommandTask).
   * - base `CScriptObject` at +0x30 (FUN_00622D80/AddBase_CScriptObject).
   * - base `Listener<ECommandEvent>` at +0x64 (FUN_00622D80/AddBase_Listener_ECommandEvent).
   */
  class CUnitScriptTask : public CCommandTask, public CScriptObject, public Listener<ECommandEvent>
  {
  public:
    /**
     * Address: 0x00622810 (FUN_00622810, default ctor)
     *
     * What it does:
     * Constructs command-task/script-object/listener subobjects and clears
     * script-task runtime members.
     */
    CUnitScriptTask();

    /**
     * Address: 0x006228B0 (FUN_006228B0, dispatch ctor lane)
     *
     * What it does:
     * Constructs a script task bound to one dispatch task context, resolves the
     * current source command, links command-event listener lanes, creates Lua
     * task object state, and runs `OnCreate(sourceArgs)`.
     */
    CUnitScriptTask(IAiCommandDispatchImpl* dispatchTask, const LuaPlus::LuaObject& sourceArgs);

    /**
     * Address: 0x00622F70 (FUN_00622F70, Moho::CUnitScriptTask::operator new)
     *
     * What it does:
     * Allocates one script-task object and constructs it from dispatch/source
     * Lua arguments.
     */
    [[nodiscard]] static CUnitScriptTask* Create(IAiCommandDispatchImpl* dispatchTask, LuaPlus::LuaObject* sourceArgs);

    /**
     * Address: 0x00622D00 (FUN_00622D00, scalar deleting thunk)
     * Address: 0x00623140 (FUN_00623140, non-deleting body)
     *
     * VFTable SLOT: 0
     */
    ~CUnitScriptTask() override;

    /**
     * Address: 0x006227D0 (FUN_006227D0, ?GetClass@CUnitScriptTask@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 0 (CScriptObject subobject)
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x006227F0 (FUN_006227F0, ?GetDerivedObjectRef@CUnitScriptTask@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 1 (CScriptObject subobject)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00624450 (FUN_00624450, Moho::CUnitScriptTask::MemberDeserialize)
     *
     * What it does:
     * Loads command-task/script-object base lanes plus source-command and Lua
     * payload members from archive storage.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CUnitScriptTask* task, int version);

    /**
     * Address: 0x00624550 (FUN_00624550, Moho::CUnitScriptTask::MemberSerialize)
     *
     * What it does:
     * Saves command-task/script-object base lanes plus source-command and Lua
     * payload members into archive storage.
     */
    static void MemberSerialize(CUnitScriptTask* task, gpg::WriteArchive* archive, int version);

    /**
     * Address: 0x00622FC0 (FUN_00622FC0, CUnitScriptTask primary-slot update)
     *
     * VFTable SLOT: 1 (primary CTask/CCommandTask chain)
     *
     * What it does:
     * Executes `TaskTick` script callback with weak-guard handling and returns
     * integer script result (`-1` on callback exception).
     */
    int Execute() override;

    /**
     * Listener slot body is still under active recovery; current wiring keeps
     * script-task updates routed through `Execute()`.
     */
    void OnEvent(ECommandEvent event) override;

  public:
    static gpg::RType* sType;

    CUnitCommand* mSourceCommand;      // +0x70
    LuaPlus::LuaObject mSourceLuaObj;  // +0x74
    LuaPlus::LuaObject mTaskClassLua;  // +0x88
    msvc8::string mTaskScriptPath;     // +0x9C
  };

  /**
   * VFTABLE: 0x00E20C00
   * COL: 0x00E7A0D0
   */
  template <>
  class CScrLuaMetatableFactory<CUnitScriptTask> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00623B50 (FUN_00623B50, ?Create@?$CScrLuaMetatableFactory@VCUnitScriptTask@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     *
     * What it does:
     * Builds the metatable object used for `CUnitScriptTask` Lua userdata.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CUnitScriptTask>) == 0x8,
    "CScrLuaMetatableFactory<CUnitScriptTask> size must be 0x8"
  );

  /**
   * Address: 0x006233C0 (FUN_006233C0, cfunc_CUnitScriptTaskGetUnit)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUnitScriptTaskGetUnitL`.
   */
  int cfunc_CUnitScriptTaskGetUnit(lua_State* luaContext);

  /**
   * Address: 0x006233E0 (FUN_006233E0, func_CUnitScriptTaskGetUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUnitScriptTask:GetUnit()` Lua binder.
   */
  CScrLuaInitForm* func_CUnitScriptTaskGetUnit_LuaFuncDef();

  /**
   * Address: 0x00623440 (FUN_00623440, cfunc_CUnitScriptTaskGetUnitL)
   *
   * What it does:
   * Resolves one `CUnitScriptTask` and pushes owner-unit Lua userdata.
   */
  int cfunc_CUnitScriptTaskGetUnitL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006234F0 (FUN_006234F0, cfunc_CUnitScriptTaskSetAIResult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUnitScriptTaskSetAIResultL`.
   */
  int cfunc_CUnitScriptTaskSetAIResult(lua_State* luaContext);

  /**
   * Address: 0x00623510 (FUN_00623510, func_CUnitScriptTaskSetAIResult_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUnitScriptTask:SetAIResult(result)` Lua binder.
   */
  CScrLuaInitForm* func_CUnitScriptTaskSetAIResult_LuaFuncDef();

  /**
   * Address: 0x00623570 (FUN_00623570, cfunc_CUnitScriptTaskSetAIResultL)
   *
   * What it does:
   * Resolves one `CUnitScriptTask` and writes one integer AI-result lane.
   */
  int cfunc_CUnitScriptTaskSetAIResultL(LuaPlus::LuaState* state);

  static_assert(sizeof(CUnitScriptTask) == 0xB8, "CUnitScriptTask size must be 0xB8");
  static_assert(
    offsetof(CUnitScriptTask, mSourceCommand) == 0x70, "CUnitScriptTask::mSourceCommand offset must be 0x70"
  );
  static_assert(offsetof(CUnitScriptTask, mSourceLuaObj) == 0x74, "CUnitScriptTask::mSourceLuaObj offset must be 0x74");
  static_assert(offsetof(CUnitScriptTask, mTaskClassLua) == 0x88, "CUnitScriptTask::mTaskClassLua offset must be 0x88");
  static_assert(
    offsetof(CUnitScriptTask, mTaskScriptPath) == 0x9C, "CUnitScriptTask::mTaskScriptPath offset must be 0x9C"
  );
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006242A0 (FUN_006242A0, gpg::RRef_CUnitScriptTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitScriptTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitScriptTask(gpg::RRef* outRef, moho::CUnitScriptTask* value);
} // namespace gpg
