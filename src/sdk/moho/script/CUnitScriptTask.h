#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/misc/Listener.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"

namespace moho
{
  class CUnitCommand;

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
