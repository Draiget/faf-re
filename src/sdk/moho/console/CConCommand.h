#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CScrLuaInitForm;

  struct ConCommandArgsView
  {
    const msvc8::string* begin = nullptr;
    const msvc8::string* end = nullptr;

    [[nodiscard]] std::size_t Count() const noexcept;
    [[nodiscard]] const msvc8::string* At(std::size_t index) const noexcept;
  };

  /**
   * VFTABLE: 0x00E01700
   * COL:     0x00E5E318
   */
  class CConCommand
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall in base CConCommand vtable)
     *
     * What it does:
     * Type-specific console command handler entry point.
     */
    virtual void Handle(void* commandArgs) = 0;

    const char* mName;              // 0x04
    const char* mDescription;       // 0x08
    std::uintptr_t mHandlerOrValue; // 0x0C (callback pointer / typed value pointer)

  protected:
    CConCommand() noexcept = default;

    /**
     * Address: 0x0041E580 (FUN_0041E580)
     *
     * const char* name, const char* description
     *
     * What it does:
     * Initializes base command metadata and registers the command when name is
     * present.
     */
    CConCommand(const char* name, const char* description) noexcept;
  };

  static_assert(sizeof(CConCommand) == 0x10, "CConCommand size must be 0x10");
  static_assert(offsetof(CConCommand, mName) == 0x04, "CConCommand::mName offset must be 0x04");
  static_assert(offsetof(CConCommand, mDescription) == 0x08, "CConCommand::mDescription offset must be 0x08");
  static_assert(offsetof(CConCommand, mHandlerOrValue) == 0x0C, "CConCommand::mHandlerOrValue offset must be 0x0C");

  // Address-backed startup convar payloads.
  extern bool con_TestVarBool;
  extern int con_TestVar;
  extern std::uint8_t con_TestVarUByte;
  extern float con_TestVarFloat;
  extern msvc8::string con_TestVarStr;
  extern int recon_debug;

  /**
   * Address: 0x0041E390 (FUN_0041E390)
   *
   * What it does:
   * Registers command definition in the process-global console command table by command name.
   */
  void RegisterConCommand(CConCommand& command);

  /**
   * Address: 0x0041E4E0 (FUN_0041E4E0)
   *
   * What it does:
   * Unregisters command definition from the process-global console command table by command name.
   */
  void UnregisterConCommand(CConCommand& command);

  /**
   * Address: 0x0041E5A0 (FUN_0041E5A0)
   *
   * What it does:
   * Base unwind/teardown helper that removes command registration when name is set.
   */
  void TeardownConCommandRegistration(CConCommand& command);

  /**
   * Address: 0x0041BFF0 (FUN_0041BFF0, ?CON_ParseCommand@Moho@@YAXVStrArg@gpg@@AAV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@AAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@5@@Z)
   *
   * const char* commandText, vector<string>& tokens, string& remainder
   *
   * What it does:
   * Parses one command lane from `commandText`, emits parsed tokens, and
   * returns the post-`;` remainder for chained execution.
   */
  void CON_ParseCommand(const char* commandText, msvc8::vector<msvc8::string>& tokens, msvc8::string& remainder);

  /**
   * Address: 0x0041C4D0 (FUN_0041C4D0, ?CON_UnparseCommand@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@3@@Z)
   *
   * vector<string> const&
   *
   * What it does:
   * Rebuilds one command line from tokens, quoting/escaping tokens that need
   * protection.
   */
  [[nodiscard]] msvc8::string CON_UnparseCommand(const msvc8::vector<msvc8::string>& tokens);

  /**
   * Address: 0x0041C600 (FUN_0041C600, ?CON_GetCommandList@Moho@@YAXAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_N@Z)
   *
   * string&, bool includeDescriptions
   *
   * What it does:
   * Appends the current command table dump to `outText`.
   */
  void CON_GetCommandList(msvc8::string& outText, bool includeDescriptions);

  /**
   * Address: 0x0041C770 (FUN_0041C770, ?CON_GetFindTextMatches@Moho@@YA?BV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@PBD@Z)
   *
   * const char* prefix
   *
   * What it does:
   * Returns sorted command-name matches whose prefix case-insensitively
   * matches `prefix`.
   */
  [[nodiscard]] msvc8::vector<msvc8::string> CON_GetFindTextMatches(const char* prefix);

  /**
   * Address: 0x0041C990 (FUN_0041C990, ?CON_Printf@Moho@@YAXPBDZZ)
   *
   * What it does:
   * Formats one console line and routes it to output handlers (direct on main
   * thread, async otherwise).
   */
  void CON_Printf(const char* format, ...);

  /**
   * Address: 0x0041CC90 (FUN_0041CC90)
   *
   * What it does:
   * Tokenizes and executes a single console command text line through the global registry.
   */
  void ExecuteConsoleCommandText(const char* commandText);

  /**
   * Address: 0x0041CC90 (FUN_0041CC90, ?CON_Execute@Moho@@YAXPBD@Z)
   *
   * What it does:
   * Public console-execution entry point; forwards to command tokenizer/dispatcher.
   */
  void CON_Execute(const char* commandText);

  /**
   * Address: 0x0041D100 (FUN_0041D100, ?CON_Executef@Moho@@YAXPBDZZ)
   *
   * What it does:
   * Formats a console command string with varargs and executes it.
   */
  void CON_Executef(const char* format, ...);

  /**
   * Address: 0x0041D270 (FUN_0041D270, ?CON_ExecuteSave@Moho@@YAXPBD@Z)
   *
   * What it does:
   * Pushes a command into history stack (max 0x64 entries) and executes it.
   */
  void CON_ExecuteSave(const char* commandText);

  /**
   * Address: 0x0041D370 (FUN_0041D370, ?CON_ExecuteLastCommand@Moho@@YAXXZ)
   *
   * What it does:
   * Re-executes the most recent saved console command, when present.
   */
  void CON_ExecuteLastCommand();

  /**
   * Address: 0x0041D3C0 (FUN_0041D3C0, ?CON_GetExecuteStack@Moho@@YAABV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@XZ)
   *
   * What it does:
   * Returns the process-global saved execute command stack.
   */
  [[nodiscard]] const msvc8::vector<msvc8::string>& CON_GetExecuteStack();

  /**
   * Address: 0x0041D3D0 (FUN_0041D3D0, ?CON_FindCommand@Moho@@YAPAVCConCommand@1@PBD@Z)
   *
   * What it does:
   * Finds one registered console command by exact command-name key.
   */
  [[nodiscard]] CConCommand* CON_FindCommand(const char* commandName);

  /**
   * Address: 0x0083DA90 (FUN_0083DA90, cfunc_ConTextMatches)
   *
   * What it does:
   * Lua callback thunk that unwraps `LuaPlus::LuaState*` and dispatches to
   * `cfunc_ConTextMatchesL`.
   */
  int cfunc_ConTextMatches(lua_State* luaContext);

  /**
   * Address: 0x0083DB10 (FUN_0083DB10, cfunc_ConTextMatchesL)
   *
   * What it does:
   * Returns a Lua table of console-command text matches for one input prefix.
   */
  int cfunc_ConTextMatchesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0083DAB0 (FUN_0083DAB0, func_ConTextMatches_LuaFuncDef)
   *
   * What it does:
   * Returns/creates Lua binder definition for global `ConTextMatches`.
   */
  CScrLuaInitForm* func_ConTextMatches_LuaFuncDef();

  /**
   * Address: 0x0041CB60 (FUN_0041CB60, cfunc_ConExecute)
   *
   * What it does:
   * Lua callback thunk that unwraps `LuaPlus::LuaState*` and dispatches to
   * `cfunc_ConExecuteL`.
   */
  int cfunc_ConExecute(lua_State* luaContext);

  /**
   * Address: 0x0041CBE0 (FUN_0041CBE0, cfunc_ConExecuteL)
   *
   * What it does:
   * Validates one string Lua argument and executes it as a console command.
   */
  int cfunc_ConExecuteL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0041D180 (FUN_0041D180, cfunc_ConExecuteSave)
   *
   * What it does:
   * Lua callback thunk that unwraps `LuaPlus::LuaState*` and dispatches to
   * `cfunc_ConExecuteSaveL`.
   */
  int cfunc_ConExecuteSave(lua_State* luaContext);

  /**
   * Address: 0x0041D200 (FUN_0041D200, cfunc_ConExecuteSaveL)
   *
   * What it does:
   * Validates one string Lua argument, saves command into history, and executes it.
   */
  int cfunc_ConExecuteSaveL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0041CB80 (FUN_0041CB80, func_ConExecute_LuaFuncDef)
   *
   * What it does:
   * Returns/creates Lua binder definition for global `ConExecute`.
   */
  CScrLuaInitForm* func_ConExecute_LuaFuncDef();

  /**
   * Address: 0x0041D1A0 (FUN_0041D1A0, func_ConExecuteSave_LuaFuncDef)
   *
   * What it does:
   * Returns/creates Lua binder definition for global `ConExecuteSave`.
   */
  CScrLuaInitForm* func_ConExecuteSave_LuaFuncDef();

  /**
   * Address: 0x0041EE10 (FUN_0041EE10, Moho::CON_Echo)
   *
   * What it does:
   * Prints the concatenated command arguments (`arg1..argN`) back to the
   * console output channel.
   */
  void CON_Echo(void* commandArgs);

  /**
   * Address: 0x0041EF40 (FUN_0041EF40, Moho::CON_ListCommands)
   *
   * What it does:
   * Emits one formatted line per registered command.
   */
  void CON_ListCommands(void* commandArgs);

  /**
   * Address: 0x0047A670 (FUN_0047A670, Moho::CON_Log)
   *
   * What it does:
   * Joins command tokens from index 1 with spaces and emits one info-severity
   * log line.
   */
  void CON_Log(void* commandArgs);

  /**
   * Address: 0x0047A700 (FUN_0047A700, Moho::CON_Debug_Warn)
   *
   * What it does:
   * Joins command tokens from index 1 with spaces and emits one warn-severity
   * log line.
   */
  void CON_Debug_Warn(void* commandArgs);

  /**
   * Address: 0x0047A790 (FUN_0047A790, Moho::CON_Debug_Error)
   *
   * What it does:
   * Joins command tokens from index 1 with spaces and terminates through
   * `gpg::Die("%s", ...)`.
   */
  void CON_Debug_Error(void* commandArgs);

  /**
   * Address: 0x0047A810 (FUN_0047A810, Moho::CON_Debug_Assert)
   *
   * What it does:
   * Debug no-op callback slot.
   */
  void CON_Debug_Assert(void* commandArgs);

  /**
   * Address: 0x0047A820 (FUN_0047A820, Moho::CON_Debug_Crash)
   *
   * What it does:
   * Intentionally crashes by writing zero to absolute address 0.
   */
  void CON_Debug_Crash(void* commandArgs);

  /**
   * Address: 0x0047A830 (FUN_0047A830, Moho::CON_Debug_Throw)
   *
   * What it does:
   * Throws `std::exception` with fixed debug text.
   */
  void CON_Debug_Throw(void* commandArgs);

  /**
   * Address: 0x007B5A40 (FUN_007B5A40, Moho::CON_PopupCreateUnitMenu)
   *
   * What it does:
   * Opens Lua `createunit` dialog at current cursor screen position, or prints
   * localized no-session text when no world session is active.
   */
  void CON_PopupCreateUnitMenu(void* commandArgs);

  /**
   * Address: 0x00833F90 (FUN_00833F90, Moho::CON_TeleportSelectedUnits)
   *
   * What it does:
   * Teleports currently selected units owned by the focus army to cursor world
   * position, preserving each unit orientation and recomputing spawn elevation.
   */
  void CON_TeleportSelectedUnits(void* commandArgs);

  /**
   * Address: 0x00834A80 (FUN_00834A80, Moho::UI_MakeSelectionSet)
   *
   * What it does:
   * Validates one selection-set name argument and calls
   * `/lua/ui/game/selection.lua:AddCurrentSelectionSet(name)`.
   */
  void UI_MakeSelectionSet(void* commandArgs);

  /**
   * Address: 0x00834C10 (FUN_00834C10, Moho::UI_ApplySelectionSet)
   *
   * What it does:
   * Validates one selection-set name argument and calls
   * `/lua/ui/game/selection.lua:ApplySelectionSet(name)`.
   */
  void UI_ApplySelectionSet(void* commandArgs);

  /**
   * Address: 0x0043D360 (FUN_0043D360, Moho::CON_ren_MipSkipLevels)
   *
   * What it does:
   * Parses one `ren_MipSkipLevels` value argument and applies clamped
   * non-negative mip-skip state to active D3D device resources.
   */
  void CON_ren_MipSkipLevels(void* commandArgs);

  /**
   * Address: 0x0043D400 (FUN_0043D400, Moho::CON_DumpPreloadedTextures)
   *
   * What it does:
   * Opens `PreloadedTextures.txt`, asks active D3D resources to dump preloaded
   * texture state into it, then closes the stream.
   */
  void CON_DumpPreloadedTextures(void* commandArgs);

  /**
   * Address: <shared helper for recovered handlers>
   *
   * What it does:
   * Adapts wire-format command argument payload into begin/end token view.
   */
  [[nodiscard]] ConCommandArgsView GetConCommandArgsView(const void* commandArgs) noexcept;

  template <typename T>
  class TConVar final : public CConCommand
  {
  public:
    TConVar(const char* name, const char* description, T* value) noexcept
    {
      mName = name;
      mDescription = description;
      mHandlerOrValue = reinterpret_cast<std::uintptr_t>(value);
    }

    void Handle(void* commandArgs) override;

    [[nodiscard]]
    T* ValuePtr() const noexcept
    {
      return reinterpret_cast<T*>(mHandlerOrValue);
    }
  };

  /**
   * Address: <synthetic generic fallback>
   *
   * What it does:
   * Generic handler fallback; real binary behavior is provided via explicit
   * specializations below.
   */
  template <typename T>
  inline void TConVar<T>::Handle(void* commandArgs)
  {
    (void)commandArgs;
  }

  /**
   * Address: 0x0041F9C0 (FUN_0041F9C0, sub_41F9C0)
   * Address: 0x1001ED50 (FUN_1001ED50)
   *
   * What it does:
   * Handles bool console-convar commands.
   */
  template <>
  void TConVar<bool>::Handle(void* commandArgs);

  /**
   * Address: 0x0041FA10 (FUN_0041FA10, sub_41FA10)
   * Address: 0x1001EDB0 (FUN_1001EDB0)
   *
   * What it does:
   * Handles int console-convar commands.
   */
  template <>
  void TConVar<int>::Handle(void* commandArgs);

  /**
   * Address: 0x0041FAC0 (FUN_0041FAC0, sub_41FAC0)
   * Address: 0x1001EE50 (FUN_1001EE50)
   *
   * What it does:
   * Handles uint8 console-convar commands.
   */
  template <>
  void TConVar<std::uint8_t>::Handle(void* commandArgs);

  /**
   * Address: 0x0041FB50 (FUN_0041FB50, sub_41FB50)
   * Address: 0x1001EEF0 (FUN_1001EEF0)
   *
   * What it does:
   * Handles float console-convar commands.
   */
  template <>
  void TConVar<float>::Handle(void* commandArgs);

  /**
   * Address: 0x103C8880 (FUN_103C8880)
   *
   * What it does:
   * Handles uint32 console-convar commands.
   */
  template <>
  void TConVar<std::uint32_t>::Handle(void* commandArgs);

  /**
   * Address: 0x0041FBE0 (FUN_0041FBE0, sub_41FBE0)
   * Address: 0x1001EF90 (FUN_1001EF90)
   *
   * What it does:
   * Handles string console-convar commands.
   */
  template <>
  void TConVar<msvc8::string>::Handle(void* commandArgs);

  static_assert(sizeof(TConVar<bool>) == 0x10, "TConVar<bool> size must be 0x10");
  static_assert(sizeof(TConVar<int>) == 0x10, "TConVar<int> size must be 0x10");
  static_assert(sizeof(TConVar<std::uint8_t>) == 0x10, "TConVar<uint8_t> size must be 0x10");
  static_assert(sizeof(TConVar<float>) == 0x10, "TConVar<float> size must be 0x10");
  static_assert(sizeof(TConVar<std::uint32_t>) == 0x10, "TConVar<uint32_t> size must be 0x10");
  static_assert(sizeof(TConVar<msvc8::string>) == 0x10, "TConVar<string> size must be 0x10");
} // namespace moho
