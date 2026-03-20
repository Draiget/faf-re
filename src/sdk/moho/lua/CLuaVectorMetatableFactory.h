#pragma once

#include "moho/lua/CScrLuaObjectFactory.h"

namespace moho
{
  /**
   * VFTABLE: 0x107298EC (MohoEngine.dll)
   * COL:     0x107BF590
   *
   * What it does:
   * Owns the shared Lua metatable used by vector-like Lua tables
   * (`Vector`, `Vector2`, `Quaternion` conversion helpers).
   */
  class CLuaVectorMetatableFactory final : public CScrLuaObjectFactory
  {
  public:
    /**
     * Address: 0x100C1210 (startup init chunk, MohoEngine.dll)
     *
     * What it does:
     * Initializes the singleton factory object and assigns
     * a unique `CScrLuaObjectFactory` cache index.
     */
    CLuaVectorMetatableFactory();

    [[nodiscard]]
    static CLuaVectorMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x100C1180 (FUN_100C1180, sub_100C1180, MohoEngine.dll)
     * Address: 0x004CFA40 (FUN_004CFA40, sub_4CFA40, ForgedAlliance.exe mirror)
     *
     * What it does:
     * Creates vector metatable and binds metamethods:
     * - `__index` -> vector component getter (`x`,`y`,`z`)
     * - `__newindex` -> vector component setter (`x`,`y`,`z`)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CLuaVectorMetatableFactory sInstance;
  };

  static_assert(sizeof(CLuaVectorMetatableFactory) == 0x08, "CLuaVectorMetatableFactory size must be 0x08");
} // namespace moho
