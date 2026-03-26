#include "moho/lua/CScrLuaObjectFactory.h"

#include "gpg/core/streams/MemBufferStream.h"

namespace
{
  constexpr const char* kFactoryObjectsGlobalName = "__factory_objects";
}

namespace moho
{
  int32_t CScrLuaObjectFactory::sNumIds = 0;
  CScrLuaMetatableFactory<CScriptObject*> CScrLuaMetatableFactory<CScriptObject*>::sInstance{};

  /**
   * Address: 0x100C3290 (?SCR_CreateSimpleMetatable@Moho@@YA?AVLuaObject@LuaPlus@@PAVLuaState@3@@Z)
   */
  LuaPlus::LuaObject SCR_CreateSimpleMetatable(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject metatable;
    metatable.AssignNewTable(state, 0, 0);
    metatable.SetObject("__index", metatable);
    return metatable;
  }

  LuaPlus::LuaObject SCR_ImportLuaModule(LuaPlus::LuaState* const state, const char* const modulePath)
  {
    if (!state || !modulePath || !*modulePath) {
      return {};
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return {};
    }

    const int savedTop = lua_gettop(lstate);
    lua_getglobal(lstate, "import");
    if (!lua_isfunction(lstate, -1)) {
      lua_settop(lstate, savedTop);
      return {};
    }

    lua_pushstring(lstate, modulePath);
    if (lua_pcall(lstate, 1, 1, 0) != 0) {
      lua_settop(lstate, savedTop);
      return {};
    }

    LuaPlus::LuaObject moduleObject{LuaPlus::LuaStackObject(state, -1)};
    lua_settop(lstate, savedTop);
    return moduleObject;
  }

  LuaPlus::LuaObject
  SCR_GetLuaTableField(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& tableObj, const char* const fieldName)
  {
    if (!state || !fieldName || !*fieldName || tableObj.IsNil()) {
      return {};
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return {};
    }

    const int savedTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(tableObj).PushStack(lstate);
    lua_pushstring(lstate, fieldName);
    lua_gettable(lstate, -2);
    LuaPlus::LuaObject result{LuaPlus::LuaStackObject(state, -1)};
    lua_settop(lstate, savedTop);
    return result;
  }

  /**
   * Address: 0x004D2F70 (FUN_004D2F70)
   */
  msvc8::string SCR_ToString(const LuaPlus::LuaObject& object)
  {
    gpg::MemBufferStream stream(256u);
    LuaPlus::LuaObject copy = object;
    (void)copy.ToByteStream(stream);

    const std::size_t serializedSize = stream.BytesWritten();
    if (serializedSize == 0u || stream.mWriteStart == nullptr) {
      return {};
    }

    return msvc8::string(stream.mWriteStart, serializedSize);
  }

  /**
   * Address: 0x10015880 (FUN_10015880, ??0CScrLuaObjectFactory@Moho@@QAE@XZ)
   */
  CScrLuaObjectFactory::CScrLuaObjectFactory()
    : mFactoryObjectIndex(++sNumIds)
  {}

  /**
   * Address: 0x100158A0 (FUN_100158A0, ??0CScrLuaObjectFactory@Moho@@QAE@ABV01@@Z)
   */
  CScrLuaObjectFactory::CScrLuaObjectFactory(const CScrLuaObjectFactory& other)
    : mFactoryObjectIndex(other.mFactoryObjectIndex)
  {}

  /**
   * Address: 0x100158C0 (FUN_100158C0, ??4CScrLuaObjectFactory@Moho@@QAEAAV01@ABV01@@Z)
   */
  CScrLuaObjectFactory& CScrLuaObjectFactory::operator=(const CScrLuaObjectFactory& other)
  {
    mFactoryObjectIndex = other.mFactoryObjectIndex;
    return *this;
  }

  /**
   * Helper constructor for specializations that already recovered explicit
   * factory-object indices.
   */
  CScrLuaObjectFactory::CScrLuaObjectFactory(const int32_t factoryObjectIndex)
    : mFactoryObjectIndex(factoryObjectIndex)
  {}

  int32_t CScrLuaObjectFactory::AllocateFactoryObjectIndex()
  {
    return ++sNumIds;
  }

  /**
   * Address: 0x100BE9E0 (?Get@CScrLuaObjectFactory@Moho@@QAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
   */
  LuaPlus::LuaObject CScrLuaObjectFactory::Get(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject factoryObjects;
    factoryObjects = state->GetGlobal(kFactoryObjectsGlobalName);
    if (factoryObjects.IsNil()) {
      factoryObjects.AssignNewTable(state, 0, 0);
      LuaPlus::LuaObject globals = state->GetGlobals();
      globals.SetObject(kFactoryObjectsGlobalName, factoryObjects);
    }

    LuaPlus::LuaObject value = factoryObjects.GetByIndex(mFactoryObjectIndex);
    if (value.IsNil()) {
      value = Create(state);
      factoryObjects.SetObject(mFactoryObjectIndex, value);
    }

    return value;
  }

  CScrLuaMetatableFactory<CScriptObject*>& CScrLuaMetatableFactory<CScriptObject*>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x100BA690
   * (?Create@?$CScrLuaMetatableFactory@PAVCScriptObject@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<CScriptObject*>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x100BA630 (FUN_100BA630, ??0?$CScrLuaMetatableFactory@PAVCScriptObject@Moho@@@Moho@@QAE@XZ)
   */
  CScrLuaMetatableFactory<CScriptObject*>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory()
  {}
} // namespace moho
