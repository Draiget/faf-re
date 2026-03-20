#include "moho/lua/CLuaConOutputHandler.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"

namespace gpg
{
  gpg::RRef REF_UpcastPtr(const gpg::RRef& source, const gpg::RType* targetType);
}

namespace
{
  constexpr std::uintptr_t kLuaBindingStateOffset = 0x44;
  constexpr const char* kAddConOutputReceiverHelp = "AddConsoleOutputReciever";
  constexpr const char* kRemoveConOutputReceiverHelp = "RemoveConsoleOutputReciever";

  gpg::RType* CachedCLuaConOutputHandlerType()
  {
    if (!moho::CLuaConOutputHandler::sType) {
      moho::CLuaConOutputHandler::sType = gpg::LookupRType(typeid(moho::CLuaConOutputHandler));
    }
    return moho::CLuaConOutputHandler::sType;
  }

  gpg::RType* CachedRObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::RObject));
    }
    return cached;
  }

  /**
   * Address: 0x004210F0 (FUN_004210F0, Moho::CLuaConOututHandlerPtr::GetClass)
   *
   * What it does:
   * Returns/caches reflection type descriptor for `CLuaConOutputHandler*`.
   */
  gpg::RType* CachedCLuaConOutputHandlerPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CLuaConOutputHandler*));
    }
    return cached;
  }

  gpg::RRef MakeConOutputHandlerPointerRef(moho::CLuaConOutputHandler* handler)
  {
    gpg::RRef ref{};
    ref.mObj = handler;
    ref.mType = CachedCLuaConOutputHandlerPointerType();
    return ref;
  }

  LuaPlus::LuaObject GetTableFieldByName(const LuaPlus::LuaObject& tableObject, const char* fieldName)
  {
    LuaPlus::LuaObject out;
    LuaPlus::LuaState* const state = tableObject.GetActiveState();
    if (!state) {
      return out;
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(tableObject).PushStack(lstate);
    lua_pushstring(lstate, fieldName ? fieldName : "");
    lua_gettable(lstate, -2);
    out = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(lstate, top);
    return out;
  }

  /**
   * Address: 0x00907BC0 (FUN_00907BC0, LuaPlus::LuaObject::GetUserData)
   *
   * What it does:
   * Recreates LuaPlus userdata extraction shape:
   * - `mObj` is pointer to userdata value slot (pointer-to-pointer payload),
   * - `mType` is reflection type stored next to that slot.
   */
  gpg::RRef ExtractUserDataSlotRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData) {
      auto* const bytes = static_cast<std::uint8_t*>(rawUserData);
      out.mObj = rawUserData;
      out.mType = *reinterpret_cast<gpg::RType**>(bytes + sizeof(void*));
    }
    lua_settop(lstate, top);
    return out;
  }

  void ValidateLuaArgCount(LuaPlus::LuaState* const state, const char* const help, const int expectedCount)
  {
    const int actualCount = lua_gettop(state->m_state);
    if (actualCount != expectedCount) {
      luaL_error(state->m_state, "%s\n  expected %d args, but got %d", help, expectedCount, actualCount);
    }
  }

  [[nodiscard]]
  bool IsLuaFunctionLike(const LuaPlus::LuaState* const state, const int stackIndex)
  {
    return (lua_type(state->m_state, stackIndex) | 1) == LUA_TFUNCTION;
  }

  /**
   * Address: 0x00420830 (FUN_00420830, func_LuaCallStr)
   *
   * What it does:
   * Calls callback with one string argument and restores prior stack top.
   */
  void LuaCallStr(const LuaPlus::LuaObject& callback, const char* text)
  {
    lua_State* const activeState = callback.GetActiveCState();
    const int savedTop = lua_gettop(activeState);
    const_cast<LuaPlus::LuaObject&>(callback).PushStack(activeState);
    lua_pushstring(activeState, text ? text : "");
    lua_call(activeState, 1, 1);
    lua_settop(activeState, savedTop);
  }
} // namespace

namespace moho
{
  gpg::RType* CLuaConOutputHandler::sType = nullptr;
  CScrLuaMetatableFactory<CLuaConOutputHandler*> CScrLuaMetatableFactory<CLuaConOutputHandler*>::sInstance{};
} // namespace moho

/**
 * Address: 0x0041E840 (FUN_0041E840, ??0CLuaConOutputHandler@Moho@@QAE@ABVLuaObject@LuaPlus@@@Z)
 */
moho::CLuaConOutputHandler::CLuaConOutputHandler(const LuaPlus::LuaObject& callback)
  : IConOutputHandler()
  , mCallback(callback)
{}

/**
 * Address: 0x0041E8D0 (FUN_0041E8D0, deleting-thunk chain via 0x004228B0)
 * Address: 0x0041E940 (FUN_0041E940, non-deleting body)
 */
moho::CLuaConOutputHandler::~CLuaConOutputHandler() = default;

/**
 * Address: 0x0041E800 (FUN_0041E800, ?GetClass@CLuaConOutputHandler@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* moho::CLuaConOutputHandler::GetClass() const
{
  return CachedCLuaConOutputHandlerType();
}

/**
 * Address: 0x0041E820 (FUN_0041E820, ?GetDerivedObjectRef@CLuaConOutputHandler@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef moho::CLuaConOutputHandler::GetDerivedObjectRef()
{
  gpg::RRef out{};
  out.mObj = this;
  out.mType = GetClass();
  return out;
}

/**
 * Address: 0x0041E8B0 (FUN_0041E8B0, sub_41E8B0)
 */
void moho::CLuaConOutputHandler::Handle(const char* const text)
{
  LuaCallStr(mCallback, text);
}

/**
 * Address: 0x1001FDE0 (FUN_1001FDE0, MohoEngine.dll)
 */
moho::CScrLuaMetatableFactory<moho::CLuaConOutputHandler*>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

moho::CScrLuaMetatableFactory<moho::CLuaConOutputHandler*>&
moho::CScrLuaMetatableFactory<moho::CLuaConOutputHandler*>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00420DA0 (FUN_00420DA0)
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CLuaConOutputHandler*>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x0041EA50 (FUN_0041EA50, scalar deleting destructor thunk)
 */
moho::CLuaConOutputHandlerTypeInfo::~CLuaConOutputHandlerTypeInfo() = default;

/**
 * Address: 0x0041EA40 (FUN_0041EA40, ?GetName@CLuaConOutputHandlerTypeInfo@Moho@@UBEPBDXZ)
 */
const char* moho::CLuaConOutputHandlerTypeInfo::GetName() const
{
  return "CLuaConOutputHandler";
}

/**
 * Address: 0x004208B0 (FUN_004208B0, Moho::CLuaConOutputHandlerTypeInfo::AddBase_RObject)
 */
void moho::CLuaConOutputHandlerTypeInfo::AddBaseRObject(gpg::RType* const typeInfo)
{
  gpg::RType* const rObjectType = CachedRObjectType();
  gpg::RField baseField{};
  baseField.mName = rObjectType->GetName();
  baseField.mType = rObjectType;
  baseField.mOffset = 0x0C;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
 * Address: 0x0041EA10 (FUN_0041EA10, ?Init@CLuaConOutputHandlerTypeInfo@Moho@@UAEXXZ)
 */
void moho::CLuaConOutputHandlerTypeInfo::Init()
{
  size_ = sizeof(CLuaConOutputHandler);
  AddBaseRObject(this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00420910 (FUN_00420910, sub_420910)
 */
LuaPlus::LuaObject
moho::SCR_CreateLuaConOutputHandlerObject(LuaPlus::LuaState* const state, CLuaConOutputHandler* const handler)
{
  LuaPlus::LuaObject out;
  LuaPlus::LuaObject metatable = CScrLuaMetatableFactory<CLuaConOutputHandler*>::Instance().Get(state);
  out.AssignNewUserData(state, MakeConOutputHandlerPointerRef(handler));
  out.SetMetaTable(metatable);
  return out;
}

/**
 * Address: 0x004209D0 (FUN_004209D0, func_GetCObj_ConOutputHandler)
 */
moho::CLuaConOutputHandler** moho::SCR_GetLuaConOutputHandlerSlot(const LuaPlus::LuaObject& object)
{
  LuaPlus::LuaObject payload(object);
  if (payload.IsTable()) {
    payload = GetTableFieldByName(payload, "_c_object");
  }

  if (!payload.IsUserData()) {
    return nullptr;
  }

  const gpg::RRef userDataRef = ExtractUserDataSlotRef(payload);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CachedCLuaConOutputHandlerPointerType());
  return static_cast<CLuaConOutputHandler**>(upcast.mObj);
}

/**
 * Address: 0x0041EB00 (FUN_0041EB00, cfunc_AddConsoleOutputReciever)
 */
int moho::cfunc_AddConsoleOutputReciever(const int luaContext)
{
  auto* const state =
    *reinterpret_cast<LuaPlus::LuaState**>(static_cast<std::uintptr_t>(luaContext) + kLuaBindingStateOffset);
  return cfunc_AddConsoleOutputRecieverL(state);
}

/**
 * Address: 0x0041EB80 (FUN_0041EB80, cfunc_AddConsoleOutputRecieverL)
 */
int moho::cfunc_AddConsoleOutputRecieverL(LuaPlus::LuaState* const state)
{
  ValidateLuaArgCount(state, kAddConOutputReceiverHelp, 1);
  if (!IsLuaFunctionLike(state, 1)) {
    gpg::Warnf("AddConsoleOutputReciever received an object that was not a function!");
    return 0;
  }

  const LuaPlus::LuaObject callback(LuaPlus::LuaStackObject(state, 1));
  auto* const handler = new CLuaConOutputHandler(callback);
  LuaPlus::LuaObject wrapped = SCR_CreateLuaConOutputHandlerObject(state, handler);

  // Binary unlinks first, then links at tail (`consoleoutputhandlers.prev` path).
  handler->ListUnlink();
  handler->ListLinkBefore(&CON_GetOutputHandlers());

  wrapped.PushStack(state);
  return 1;
}

/**
 * Address: 0x0041ED00 (FUN_0041ED00, cfunc_RemoveConsoleOutputReciever)
 */
int moho::cfunc_RemoveConsoleOutputReciever(const int luaContext)
{
  auto* const state =
    *reinterpret_cast<LuaPlus::LuaState**>(static_cast<std::uintptr_t>(luaContext) + kLuaBindingStateOffset);
  return cfunc_RemoveConsoleOutputRecieverL(state);
}

/**
 * Address: 0x0041ED80 (FUN_0041ED80, cfunc_RemoveConsoleOutputRecieverL)
 */
int moho::cfunc_RemoveConsoleOutputRecieverL(LuaPlus::LuaState* const state)
{
  ValidateLuaArgCount(state, kRemoveConOutputReceiverHelp, 1);

  const LuaPlus::LuaObject payload(LuaPlus::LuaStackObject(state, 1));
  CLuaConOutputHandler** const slot = SCR_GetLuaConOutputHandlerSlot(payload);
  GPG_ASSERT(slot != nullptr);
  if (!slot) {
    return 0;
  }

  CLuaConOutputHandler* const handler = *slot;
  GPG_ASSERT(handler != nullptr);
  if (!handler) {
    return 0;
  }

  handler->ListUnlink();
  delete handler;
  return 0;
}
