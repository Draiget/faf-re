#pragma once

#include <cstddef>

#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace moho
{
  class CScrLuaClassBinder : public CScrLuaInitForm
  {
  public:
    /**
     * Address: 0x10015A10 (FUN_10015A10)
     *
     * CScrLuaInitFormSet &, char const *, CScrLuaObjectFactory *, char const *, char const *
     *
     * IDA signature:
     * Moho::CScrLuaClassBinder *__thiscall Moho::CScrLuaClassBinder::CScrLuaClassBinder(
     *     Moho::CScrLuaClassBinder *this,
     *     struct Moho::CScrLuaInitFormSet *a2,
     *     const char *a3,
     *     struct Moho::CScrLuaObjectFactory *a4,
     *     const char *a5,
     *     const char *a6)
     *
     * What it does:
     * Creates a class/object binder that publishes a factory object at a dotted Lua path.
     */
    CScrLuaClassBinder(
      CScrLuaInitFormSet& set,
      const char* name,
      CScrLuaObjectFactory* classFactory,
      const char* groupName,
      const char* docString
    );

    /**
     * Address: 0x10015A50 (FUN_10015A50)
     *
     * CScrLuaClassBinder &, CScrLuaClassBinder const &
     *
     * What it does:
     * Copy-constructs class binder metadata and class factory pointer.
     */
    CScrLuaClassBinder(const CScrLuaClassBinder& other);

    /**
     * Address: 0x100BEF20 (FUN_100BEF20)
     * Address: 0x004CD460 (FUN_004CD460, Moho::CScrLuaClassBinder::Run)
     *
     * LuaState *
     *
     * What it does:
     * Walks/creates nested tables for dotted prefixes and stores the factory object at the final segment.
     */
    void Run(LuaPlus::LuaState* state) override;

  public:
    CScrLuaObjectFactory* mClassFactory; // +0x14
  };
  static_assert(
    offsetof(CScrLuaClassBinder, mClassFactory) == 0x14, "CScrLuaClassBinder::mClassFactory offset must be 0x14"
  );
  static_assert(sizeof(CScrLuaClassBinder) == 0x18, "CScrLuaClassBinder size must be 0x18");
} // namespace moho
