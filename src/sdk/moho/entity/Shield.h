#pragma once

#include "Entity.h"
#include "moho/lua/CScrLuaBinderFwd.h"

struct lua_State;

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  /**
   * VFTABLE: 0x00E3705C
   * COL: 0x00E90F9C
   */
  class Shield : public Entity
  {
  public:
    /**
     * Address: 0x00776590 (FUN_00776590, ??0Shield@Moho@@QAE@@ZZ)
     *
     * What it does:
     * Serializer construction lane: initializes Shield with default collision
     * bucket flags under one simulation owner.
     */
    explicit Shield(Sim* sim);

    /**
     * Address: 0x00776490 (FUN_00776490, ??0Shield@Moho@@QAE@@Z)
     *
     * What it does:
     * Lua construction lane: reserves one Shield-family entity id using the
     * provided source index, binds Lua object state, and links into
     * `Sim::mShields`.
     */
    Shield(Sim* sim, const LuaPlus::LuaObject& luaObject, std::uint32_t armySourceIndex);

    /**
     * Address: 0x007762F0 (FUN_007762F0)
     *
     * What it does:
     * Returns cached reflection descriptor for Shield.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x00776310 (FUN_00776310)
     *
     * What it does:
     * Packs {this, GetClass()} as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00776570 (FUN_00776570)
     *
     * What it does:
     * Unlinks this shield from Sim shield-list, then runs base entity teardown.
     */
    ~Shield() override;

    /**
     * Address: 0x00776330 (FUN_00776330)
     *
     * What it does:
     * Runtime type probe override for shield entities.
     */
    Shield* IsShield() override;
  };

  /**
   * Address: 0x00776A20 (FUN_00776A20, cfunc__c_CreateShield)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc__c_CreateShieldL`.
   */
  int cfunc__c_CreateShield(lua_State* luaContext);

  /**
   * Address: 0x00776A40 (FUN_00776A40, func__c_CreateShield_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder metadata for `_c_CreateShield`.
   */
  CScrLuaInitForm* func__c_CreateShield_LuaFuncDef();

  /**
   * Address: 0x00776AA0 (FUN_00776AA0, cfunc__c_CreateShieldL)
   *
   * What it does:
   * Validates `(luaobj, spec)`, derives shield source index from optional
   * `spec.Owner`, creates one `Shield`, and pushes its Lua object.
   */
  int cfunc__c_CreateShieldL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E3713C
   * COL: 0x00E90E54
   */
  class ShieldSaveConstruct
  {
  public:
    /**
     * Address: 0x00776D20 (FUN_00776D20, sub_776D20)
     *
     * What it does:
     * Binds save-construct-args callback into Shield RTTI (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  /**
   * VFTABLE: 0x00E3714C
   * COL: 0x00E90DA8
   */
  class ShieldConstruct
  {
  public:
    /**
     * Address: 0x00776DA0 (FUN_00776DA0, sub_776DA0)
     *
     * What it does:
     * Binds construct/delete callbacks into Shield RTTI (`serConstructFunc_`, `deleteFunc_`).
     */
    virtual void RegisterConstructFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  /**
   * VFTABLE: 0x00E3715C
   * COL: 0x00E90CFC
   */
  class ShieldSerializer
  {
  public:
    /**
     * Address: 0x00776E20 (FUN_00776E20, sub_776E20)
     *
     * What it does:
     * Binds load/save serializer callbacks into Shield RTTI (`serLoadFunc_`, `serSaveFunc_`).
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  /**
   * VFTABLE: 0x00E37104
   * COL: 0x00E90F38
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class ShieldTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x007763E0 (FUN_007763E0, sub_7763E0)
     * Slot: 2
     *
     * What it does:
     * Scalar deleting destructor thunk for ShieldTypeInfo.
     */
    ~ShieldTypeInfo() override;

    /**
     * Address: 0x007763D0 (FUN_007763D0)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for Shield.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x007763A0 (FUN_007763A0)
     * Slot: 9
     *
     * What it does:
     * Sets Shield size and registers Entity base-field metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(Shield) == 0x270, "Shield size must be 0x270");
  static_assert(sizeof(ShieldSaveConstruct) == 0x10, "ShieldSaveConstruct size must be 0x10");
  static_assert(sizeof(ShieldConstruct) == 0x14, "ShieldConstruct size must be 0x14");
  static_assert(sizeof(ShieldSerializer) == 0x14, "ShieldSerializer size must be 0x14");
  static_assert(sizeof(ShieldTypeInfo) == 0x64, "ShieldTypeInfo size must be 0x64");
} // namespace moho
