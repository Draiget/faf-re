#pragma once

#include <cstddef>

#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace moho
{
  class CScrLuaBaseClassSpec : public CScrLuaInitForm
  {
  public:
    /**
     * Address: 0x10015A90 (FUN_10015A90)
     *
     * CScrLuaInitFormSet &, CScrLuaObjectFactory *, CScrLuaObjectFactory *, char const *, char const *
     *
     * IDA signature:
     * Moho::CScrLuaBaseClassSpec *__thiscall Moho::CScrLuaBaseClassSpec::CScrLuaBaseClassSpec(
     *     Moho::CScrLuaBaseClassSpec *this,
     *     struct Moho::CScrLuaInitFormSet *a2,
     *     struct Moho::CScrLuaObjectFactory *a3,
     *     struct Moho::CScrLuaObjectFactory *a4,
     *     const char *a5,
     *     const char *a6)
     *
     * What it does:
     * Creates a base-class spec form with fixed symbol name "base" and two factory references.
     */
    CScrLuaBaseClassSpec(
      CScrLuaInitFormSet& set,
      CScrLuaObjectFactory* derivedClassFactory,
      CScrLuaObjectFactory* baseClassFactory,
      const char* groupName,
      const char* docString
    );

    /**
     * Address: 0x10015AE0 (FUN_10015AE0)
     *
     * CScrLuaBaseClassSpec &, CScrLuaBaseClassSpec const &
     *
     * What it does:
     * Copy-constructs base-class spec metadata and both factory pointers.
     */
    CScrLuaBaseClassSpec(const CScrLuaBaseClassSpec& other);

    /**
     * Address: 0x100BF090 (FUN_100BF090)
     *
     * LuaState *
     *
     * What it does:
     * Appends the base class object into the derived class base-list table.
     */
    void Run(LuaPlus::LuaState* state) override;

  public:
    CScrLuaObjectFactory* mDerivedClassFactory; // +0x14
    CScrLuaObjectFactory* mBaseClassFactory;    // +0x18
  };
  static_assert(
    offsetof(CScrLuaBaseClassSpec, mDerivedClassFactory) == 0x14,
    "CScrLuaBaseClassSpec::mDerivedClassFactory offset must be 0x14"
  );
  static_assert(
    offsetof(CScrLuaBaseClassSpec, mBaseClassFactory) == 0x18,
    "CScrLuaBaseClassSpec::mBaseClassFactory offset must be 0x18"
  );
  static_assert(sizeof(CScrLuaBaseClassSpec) == 0x1C, "CScrLuaBaseClassSpec size must be 0x1C");
} // namespace moho
