#pragma once

#include <cstdint>

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"

namespace gpg
{
  class RRef;
}

namespace moho
{
  class CScriptObject;

  /**
   * Address: 0x004D22D0 (FUN_004D22D0, ?SCR_CreateSimpleMetatable@Moho@@YA?AVLuaObject@LuaPlus@@PAVLuaState@3@@Z)
   * Alias:   0x100C3290 (alt lane)
   *
   * Creates a table metatable and sets __index = self.
   */
  LuaPlus::LuaObject SCR_CreateSimpleMetatable(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D3250 (FUN_004D3250, ?SCR_Import@Moho@@YA?AVLuaObject@LuaPlus@@PAVLuaState@3@VStrArg@gpg@@@Z)
   *
   * What it does:
   * Calls global `import(modulePath)` and returns the resulting Lua object
   * while restoring the caller's original Lua stack top.
   */
  [[nodiscard]] LuaPlus::LuaObject SCR_Import(LuaPlus::LuaState* state, gpg::StrArg modulePath);

  /**
   * Imports a Lua module by calling global `import(modulePath)`.
   * Returns nil object on lookup/call failure.
   */
  [[nodiscard]] LuaPlus::LuaObject SCR_ImportLuaModule(LuaPlus::LuaState* state, const char* modulePath);

  /**
   * Reads one table field via raw stack gettable flow.
   * Returns nil object when table/state/field are invalid.
   */
  [[nodiscard]] LuaPlus::LuaObject
  SCR_GetLuaTableField(LuaPlus::LuaState* state, const LuaPlus::LuaObject& tableObj, const char* fieldName);

  /**
   * Address: 0x004D2F70 (FUN_004D2F70, ?SCR_ToString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVLuaObject@LuaPlus@@@Z)
   *
   * What it does:
   * Serializes one Lua object with SCR byte-stream encoding and returns the raw encoded bytes as `msvc8::string`.
   */
  [[nodiscard]] msvc8::string SCR_ToString(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x004D23D0 (FUN_004D23D0, ?SCR_QuoteLuaString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@@Z)
   *
   * What it does:
   * Returns a Lua-quoted/escaped string literal choosing `'` or `"` based on
   * source contents and escaping control/non-printable bytes.
   */
  [[nodiscard]] msvc8::string SCR_QuoteLuaString(gpg::StrArg text);

  /**
   * Address: 0x004CF0B0 (FUN_004CF0B0, ?SCR_RObjectToLuaMerge@Moho@@YAXABVRRef@gpg@@AAVLuaObject@LuaPlus@@@Z)
   *
   * What it does:
   * Recursively merges one reflected source object/reference into an existing
   * Lua object, handling primitive upcasts, pointers, indexed ranges, and named
   * reflected fields.
   */
  void SCR_RObjectToLuaMerge(const gpg::RRef& source, LuaPlus::LuaObject& destination);

  /**
   * Address: 0x004CF4A0 (FUN_004CF4A0, ?SCR_RObjectToLua@Moho@@...)
   *
   * What it does:
   * Builds one Lua object initialized as `nil` and merges a reflected source
   * reference into it.
   */
  [[nodiscard]] LuaPlus::LuaObject SCR_RObjectToLua(const gpg::RRef& source, LuaPlus::LuaState* state);

  /**
   * Address: 0x004CF510 (FUN_004CF510, ?SCR_LuaBuildObject@Moho@@YA_NVLuaObject@LuaPlus@@ABVRRef@gpg@@_N@Z)
   *
   * What it does:
   * Recursively applies one Lua value/table into a reflected destination reference,
   * handling lexical, indexed, enum-flag, and named-field paths with warning logs.
   */
  [[nodiscard]] bool SCR_LuaBuildObject(LuaPlus::LuaObject valueObject, const gpg::RRef& destination, bool ignoreMissingFields);

  /**
   * Address: 0x004D2550 (FUN_004D2550, ?SCR_GetEnum@Moho@@YAXPAVLuaState@LuaPlus@@VStrArg@gpg@@AAVRRef@5@@Z)
   *
   * What it does:
   * Writes one enum lexical value into a reflected destination and, on failure,
   * raises a Lua error listing all valid enum option names.
   */
  void SCR_GetEnum(LuaPlus::LuaState* state, gpg::StrArg enumString, gpg::RRef& ref);

  /**
   * Address: 0x004CDBA0 (FUN_004CDBA0, ?SCR_LuaDoString@Moho@@YA_NPAVLuaState@LuaPlus@@VStrArg@gpg@@PAVLuaObject@3@@Z)
   *
   * What it does:
   * Loads and executes one Lua chunk from `scriptText`, warns on compile/runtime
   * failures, and restores the caller's original Lua stack top.
   */
  [[nodiscard]] bool SCR_LuaDoString(const char* scriptText, LuaPlus::LuaState* state);

  /**
   * Address: 0x004CEA20 (FUN_004CEA20, ?SCR_LuaDoScript@Moho@@YA_NPAVLuaState@LuaPlus@@VStrArg@gpg@@PAVLuaObject@3@@Z)
   *
   * What it does:
   * Executes one resolved script file through `func_LuaDoScript`, restores the
   * caller's Lua stack top, and reports exceptions with file-context warnings.
   */
  [[nodiscard]] bool SCR_LuaDoScript(LuaPlus::LuaState* state, gpg::StrArg scriptPath, LuaPlus::LuaObject* outEnvironment);

  /**
   * Address: 0x004CECD0 (FUN_004CECD0, Moho::SCR_LuaDoFileConcat)
   *
   * What it does:
   * Concatenates and executes one ordered Lua file list as a single chunk,
   * optionally setting one table environment before execution.
   */
  void SCR_LuaDoFileConcat(
    LuaPlus::LuaState* state,
    LuaPlus::LuaObject* outEnvironment,
    msvc8::vector<msvc8::string> files
  );

  /**
   * Address: 0x004CE2C0 (FUN_004CE2C0, func_LuaDoScript)
   *
   * What it does:
   * Resolves one script path, appends hook/mod overrides, then executes the
   * concatenated file chain.
   */
  void func_LuaDoScript(LuaPlus::LuaState* state, const char* scriptPath, LuaPlus::LuaObject* outEnvironment);

  /**
   * Address: 0x004CDF60 (FUN_004CDF60, Moho::SCR_AddHookDirectory)
   *
   * What it does:
   * Adds one hook-directory prefix used when resolving doscript hook variants.
   */
  void SCR_AddHookDirectory(const char* hookDirectory);

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
     * Recovery helper:
     * Overrides the cached factory index lane on an already-materialized factory object.
     */
    void SetFactoryObjectIndexForRecovery(const int32_t factoryObjectIndex) noexcept
    {
      mFactoryObjectIndex = factoryObjectIndex;
    }

    /**
     * Address: 0x004CCE70 (FUN_004CCE70, FA exe)
     * Address: 0x100BE9E0 (?Get@CScrLuaObjectFactory@Moho@@QAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
     *
     * What it does:
     * Returns one cached factory object from global `__factory_objects`,
     * creating/storing a new entry when the indexed slot is nil.
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
  class CScrLuaMetatableFactory : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance()
    {
      static CScrLuaMetatableFactory sInstance{};
      return sInstance;
    }

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override
    {
      return SCR_CreateSimpleMetatable(state);
    }

  private:
    CScrLuaMetatableFactory() = default;
  };

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

  /**
   * Address: 0x00BC60D0 (FUN_00BC60D0)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<CScriptObject*>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_CScriptObject_Index();
} // namespace moho
