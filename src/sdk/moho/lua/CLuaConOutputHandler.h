#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/IConOutputHandler.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E01738
   * COL:     0x00E5E078
   *
   * Multi-inheritance layout:
   * - +0x00 IConOutputHandler
   * - +0x0C gpg::RObject
   */
  class CLuaConOutputHandler final : public IConOutputHandler, public gpg::RObject
  {
  public:
    /**
     * Address: 0x0041E840 (FUN_0041E840, ??0CLuaConOutputHandler@Moho@@QAE@ABVLuaObject@LuaPlus@@@Z)
     *
     * What it does:
     * Initializes intrusive-list linkage and stores one Lua callback object.
     */
    explicit CLuaConOutputHandler(const LuaPlus::LuaObject& callback);

    /**
     * Address: 0x0041E8D0 (FUN_0041E8D0, deleting-thunk chain via 0x004228B0)
     * Address: 0x0041E940 (FUN_0041E940, non-deleting body)
     *
     * VFTable SLOT: 2 (gpg::RObject subobject)
     */
    ~CLuaConOutputHandler() override;

    /**
     * Address: 0x0041E800 (FUN_0041E800, ?GetClass@CLuaConOutputHandler@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 0 (gpg::RObject subobject)
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0041E820 (FUN_0041E820, ?GetDerivedObjectRef@CLuaConOutputHandler@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 1 (gpg::RObject subobject)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0041E8B0 (FUN_0041E8B0, sub_41E8B0)
     *
     * VFTable SLOT: 0 (IConOutputHandler subobject)
     *
     * What it does:
     * Forwards one console line into stored Lua callback.
     */
    void Handle(const char* text) override;

  public:
    static gpg::RType* sType;
    LuaPlus::LuaFunction<void> mCallback; // +0x10
  };

  /**
   * VFTABLE: 0x00E017B8
   * COL:     0x00E5DD98
   */
  template <>
  class CScrLuaMetatableFactory<CLuaConOutputHandler*> final : public CScrLuaObjectFactory
  {
  public:
    /**
     * Address: 0x1001FDE0 (FUN_1001FDE0, MohoEngine.dll)
     *
     * What it does:
     * Initializes object-factory metadata for CLuaConOutputHandler userdata.
     */
    CScrLuaMetatableFactory();

    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00420DA0 (FUN_00420DA0)
     *
     * What it does:
     * Builds a simple metatable (`__index = self`) for handler userdata.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  /**
   * VFTABLE: 0x00E01750
   * COL:     0x00E5E014
   */
  class CLuaConOutputHandlerTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0041EA50 (FUN_0041EA50, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CLuaConOutputHandlerTypeInfo() override;

    /**
     * Address: 0x0041EA40 (FUN_0041EA40, ?GetName@CLuaConOutputHandlerTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0041EA10 (FUN_0041EA10, ?Init@CLuaConOutputHandlerTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;

  private:
    /**
     * Address: 0x004208B0 (FUN_004208B0, Moho::CLuaConOutputHandlerTypeInfo::AddBase_RObject)
     *
     * What it does:
     * Registers `gpg::RObject` as base class at offset `+0x0C`.
     */
    static void AddBaseRObject(gpg::RType* typeInfo);
  };

  /**
   * VFTABLE: 0x00E01758
   * COL:     0x00E5DFBC
   */
  using AddConsoleOutputReciever_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E01760
   * COL:     0x00E5DF6C
   */
  using RemoveConsoleOutputReciever_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x00420910 (FUN_00420910, sub_420910)
   *
   * What it does:
   * Wraps a native handler pointer into Lua userdata with CLuaConOutputHandler
   * metatable.
   */
  [[nodiscard]]
  LuaPlus::LuaObject SCR_CreateLuaConOutputHandlerObject(LuaPlus::LuaState* state, CLuaConOutputHandler* handler);

  /**
   * Address: 0x004209D0 (FUN_004209D0, func_GetCObj_ConOutputHandler)
   *
   * What it does:
   * Resolves `_c_object` from Lua table/userdata payload and returns pointer
   * slot (`CLuaConOutputHandler**`) encoded in userdata RTTI reference.
   */
  [[nodiscard]]
  CLuaConOutputHandler** SCR_GetLuaConOutputHandlerSlot(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x0041EB00 (FUN_0041EB00, cfunc_AddConsoleOutputReciever)
   *
   * What it does:
   * Unwraps Lua binding context and dispatches to LuaState overload.
   */
  int cfunc_AddConsoleOutputReciever(lua_State* luaContext);

  /**
   * Address: 0x0041EB80 (FUN_0041EB80, cfunc_AddConsoleOutputRecieverL)
   *
   * What it does:
   * Adds one Lua callback receiver and returns wrapped userdata.
   */
  int cfunc_AddConsoleOutputRecieverL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0041ED00 (FUN_0041ED00, cfunc_RemoveConsoleOutputReciever)
   *
   * What it does:
   * Unwraps Lua binding context and dispatches to LuaState overload.
   */
  int cfunc_RemoveConsoleOutputReciever(lua_State* luaContext);

  /**
   * Address: 0x0041ED80 (FUN_0041ED80, cfunc_RemoveConsoleOutputRecieverL)
   *
   * What it does:
   * Removes one registered output receiver and destroys it.
   */
  int cfunc_RemoveConsoleOutputRecieverL(LuaPlus::LuaState* state);

  static_assert(
    offsetof(CLuaConOutputHandler, mCallback) == 0x10, "CLuaConOutputHandler::mCallback offset must be 0x10"
  );
  static_assert(sizeof(CLuaConOutputHandler) == 0x24, "CLuaConOutputHandler size must be 0x24");
  static_assert(
    sizeof(CScrLuaMetatableFactory<CLuaConOutputHandler*>) == 0x08,
    "CScrLuaMetatableFactory<CLuaConOutputHandler*> size must be 0x08"
  );
  static_assert(sizeof(CLuaConOutputHandlerTypeInfo) == 0x64, "CLuaConOutputHandlerTypeInfo size must be 0x64");
} // namespace moho
