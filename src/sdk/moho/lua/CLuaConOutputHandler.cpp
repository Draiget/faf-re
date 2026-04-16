#include "moho/lua/CLuaConOutputHandler.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace
{
  constexpr const char* kAddConOutputReceiverHelp = "handler AddConsoleOutputReciever(func(text))";
  constexpr const char* kRemoveConOutputReceiverHelp = "RemoveConsoleOutputReciever(handler)";

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("user"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet sSet("user");
    return sSet;
  }

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

  /**
   * Address: 0x00420FF0 (FUN_00420FF0, sub_420FF0)
   * Address: 0x00421BA0 (FUN_00421BA0, sub_421BA0)
   *
   * What it does:
   * Builds `gpg::RRef` for `CLuaConOutputHandler*` userdata payload.
   */
  gpg::RRef MakeConOutputHandlerPointerRef(moho::CLuaConOutputHandler* handler)
  {
    gpg::RRef ref{};
    ref.mObj = handler;
    ref.mType = CachedCLuaConOutputHandlerPointerType();
    return ref;
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

  /**
   * Address: 0x0041C8B0 (FUN_0041C8B0, sub_41C8B0)
   * Address: 0x0041FC90 (FUN_0041FC90, sub_41FC90)
   *
   * What it does:
   * Unlinks handler from its current list position and relinks it at the tail
   * of the global console output handler list.
   */
  void RelinkConOutputHandlerTail(moho::CLuaConOutputHandler* const handler)
  {
    if (handler == nullptr) {
      return;
    }

    handler->ListLinkBefore(&moho::CON_GetOutputHandlers());
  }

  template <typename TObject>
  void MaterializeReflectionSingleton(TObject& singleton)
  {
    (void)singleton;
  }
} // namespace

namespace moho
{
  gpg::RType* CLuaConOutputHandler::sType = nullptr;
  CLuaConOutputHandlerTypeInfo gCLuaConOutputHandlerTypeInfo{};
  CScrLuaMetatableFactory<CLuaConOutputHandler*> CScrLuaMetatableFactory<CLuaConOutputHandler*>::sInstance{};

  /**
   * Address: 0x00BC3B10 (FUN_00BC3B10, register_CScrLuaMetatableFactory_CLuaConOutputHandler)
   *
   * What it does:
   * Reallocates startup metatable-factory index lane for
   * `CScrLuaMetatableFactory<CLuaConOutputHandler*>`.
   */
  void RegisterCLuaConOutputHandlerFactoryIndexBootstrap()
  {
    const std::int32_t index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<CLuaConOutputHandler*>::Instance().SetFactoryObjectIndexForRecovery(index);
  }

  /**
   * Address: 0x00BC38D0 (FUN_00BC38D0, register_CLuaConOutputHandlerTypeInfo)
   *
   * What it does:
   * Materializes the global reflection descriptor for CLuaConOutputHandler.
   */
  void RegisterCLuaConOutputHandlerTypeInfoBootstrap()
  {
    MaterializeReflectionSingleton(gCLuaConOutputHandlerTypeInfo);
  }
} // namespace moho

namespace
{
  struct CLuaConOutputHandlerTypeInfoBootstrap
  {
    CLuaConOutputHandlerTypeInfoBootstrap()
    {
      moho::RegisterCLuaConOutputHandlerFactoryIndexBootstrap();
      moho::RegisterCLuaConOutputHandlerTypeInfoBootstrap();
    }
  };

  CLuaConOutputHandlerTypeInfoBootstrap gCLuaConOutputHandlerTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x0041E840 (FUN_0041E840, ??0CLuaConOutputHandler@Moho@@QAE@ABVLuaObject@LuaPlus@@@Z)
 */
moho::CLuaConOutputHandler::CLuaConOutputHandler(const LuaPlus::LuaObject& callback)
  : IConOutputHandler()
  , mCallback(callback)
{}

/**
 * Address: 0x0041E9B0 (FUN_0041E9B0, ??0CLuaConOutputHandlerTypeInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Preregisters the CLuaConOutputHandler RTTI descriptor for global lookup.
 */
moho::CLuaConOutputHandlerTypeInfo::CLuaConOutputHandlerTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(moho::CLuaConOutputHandler), this);
}

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
 * Address: 0x00421B60 (FUN_00421B60, sub_421B60 helper lane)
  * Alias of FUN_004220D0 (non-canonical helper lane).
 */
gpg::RRef moho::CLuaConOutputHandler::GetDerivedObjectRef()
{
  gpg::RRef out{};
  gpg::RRef_CLuaConOutputHandler(&out, this);
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
  * Alias of FUN_1001FDE0 (non-canonical helper lane).
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
 * Address: 0x0041EB20 (FUN_0041EB20, func_AddConsoleOutputReciever_LuaFuncDef)
 *
 * What it does:
 * Returns the binder definition used to expose AddConsoleOutputReciever to Lua.
 */
moho::CScrLuaInitForm* moho::func_AddConsoleOutputReciever_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AddConsoleOutputReciever",
    &moho::cfunc_AddConsoleOutputReciever,
    nullptr,
    "<global>",
    kAddConOutputReceiverHelp
  );
  return &binder;
}

/**
 * Address: 0x0041ED20 (FUN_0041ED20, func_RemoveConsoleOutputReciever_LuaFuncDef)
 *
 * What it does:
 * Returns the binder definition used to expose RemoveConsoleOutputReciever to Lua.
 */
moho::CScrLuaInitForm* moho::func_RemoveConsoleOutputReciever_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RemoveConsoleOutputReciever",
    &moho::cfunc_RemoveConsoleOutputReciever,
    nullptr,
    "<global>",
    kRemoveConOutputReceiverHelp
  );
  return &binder;
}

/**
 * Address: 0x00BC38F0 (FUN_00BC38F0, register_AddConsoleOutputReciever_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_AddConsoleOutputReciever_LuaFuncDef()
{
  return func_AddConsoleOutputReciever_LuaFuncDef();
}

/**
 * Address: 0x00BC3900 (FUN_00BC3900, register_RemoveConsoleOutputReciever_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_RemoveConsoleOutputReciever_LuaFuncDef()
{
  return func_RemoveConsoleOutputReciever_LuaFuncDef();
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
 * Address: 0x00421020 (FUN_00421020, sub_421020 helper lane)
 */
moho::CLuaConOutputHandler** moho::SCR_GetLuaConOutputHandlerSlot(const LuaPlus::LuaObject& object)
{
  LuaPlus::LuaObject payload(object);
  if (payload.IsTable()) {
    payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
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
int moho::cfunc_AddConsoleOutputReciever(lua_State* const luaContext)
{
  auto* const state = moho::SCR_ResolveBindingState(luaContext);
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

  RelinkConOutputHandlerTail(handler);

  wrapped.PushStack(state);
  return 1;
}

/**
 * Address: 0x0041ED00 (FUN_0041ED00, cfunc_RemoveConsoleOutputReciever)
 */
int moho::cfunc_RemoveConsoleOutputReciever(lua_State* const luaContext)
{
  auto* const state = moho::SCR_ResolveBindingState(luaContext);
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
