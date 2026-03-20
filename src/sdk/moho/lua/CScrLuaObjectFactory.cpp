#include "moho/lua/CScrLuaObjectFactory.h"

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
