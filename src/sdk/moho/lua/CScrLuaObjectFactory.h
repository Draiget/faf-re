#pragma once

#include <cstdint>

#include "lua/LuaObject.h"

namespace moho
{
  class CScriptObject;

  /**
   * Address: 0x100C3290 (?SCR_CreateSimpleMetatable@Moho@@YA?AVLuaObject@LuaPlus@@PAVLuaState@3@@Z)
   *
   * Creates a table metatable and sets __index = self.
   */
  LuaPlus::LuaObject SCR_CreateSimpleMetatable(LuaPlus::LuaState* state);

  class CScrLuaObjectFactory
  {
  public:
    /**
     * Address: 0x10015880 (FUN_10015880, ??0CScrLuaObjectFactory@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes the base factory and assigns a unique cached object index.
     */
    CScrLuaObjectFactory();

    /**
     * Address: 0x100158A0 (FUN_100158A0, ??0CScrLuaObjectFactory@Moho@@QAE@ABV01@@Z)
     *
     * What it does:
     * Copy-constructs base factory state by copying only the cached object index.
     */
    CScrLuaObjectFactory(const CScrLuaObjectFactory& other);

    /**
     * Address: 0x100158C0 (FUN_100158C0, ??4CScrLuaObjectFactory@Moho@@QAEAAV01@ABV01@@Z)
     *
     * What it does:
     * Assigns only the cached object index.
     */
    CScrLuaObjectFactory& operator=(const CScrLuaObjectFactory& other);

  protected:
    /**
     * Helper constructor for already-recovered specializations that allocate
     * their own index externally before base construction.
     */
    explicit CScrLuaObjectFactory(int32_t factoryObjectIndex);

  public:
    /**
     * Helper used by metatable-factory constructors that follow:
     * `this[1] = ++CScrLuaObjectFactory::sNumIds`.
     */
    static int32_t AllocateFactoryObjectIndex();

    /**
     * Address: 0x100BE9E0 (?Get@CScrLuaObjectFactory@Moho@@QAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     */
    LuaPlus::LuaObject Get(LuaPlus::LuaState* state);

  protected:
    virtual LuaPlus::LuaObject Create(LuaPlus::LuaState* state) = 0;

  private:
    static int32_t sNumIds;
    int32_t mFactoryObjectIndex;
  };
  static_assert(sizeof(CScrLuaObjectFactory) == 0x8, "CScrLuaObjectFactory must be 0x8");

  template <typename T>
  class CScrLuaMetatableFactory;

  template <>
  class CScrLuaMetatableFactory<CScriptObject*> final : public CScrLuaObjectFactory
  {
  public:
    /**
     * Returns the process-global metatable factory instance.
     */
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x100BA690
     * (?Create@?$CScrLuaMetatableFactory@PAVCScriptObject@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    /**
     * Address: 0x100BA630 (FUN_100BA630, ??0?$CScrLuaMetatableFactory@PAVCScriptObject@Moho@@@Moho@@QAE@XZ)
     *
     * What it does:
     * Constructs the CScriptObject metatable factory and assigns its cache index.
     */
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };
  static_assert(
    sizeof(CScrLuaMetatableFactory<CScriptObject*>) == 0x8, "CScrLuaMetatableFactory<CScriptObject*> must be 0x8"
  );
} // namespace moho
