#pragma once

#include "Entity.h"
#include "moho/lua/CScrLuaBinderFwd.h"

struct lua_State;

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  class WriteArchive;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E3705C
   * COL: 0x00E90F9C
   */
  class Shield : public Entity
  {
  public:
    static gpg::RType* sPointerType;

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
     * Address: 0x0074E5D0 (FUN_0074E5D0, Moho::Shield::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches reflected RTTI for `Shield*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x00776310 (FUN_00776310)
     *
     * What it does:
     * Packs {this, GetClass()} as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00776570 (FUN_00776570, deleting dtor thunk)
     * Address: 0x00776600 (FUN_00776600, non-deleting dtor core)
     *
     * What it does:
     * Unlinks this shield from Sim shield-list and decrements the shield
     * instance-stat lane before base entity teardown.
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
   * Address: 0x00776860 (FUN_00776860)
   *
   * What it does:
   * Reads one owning `Sim*` lane from archive, constructs one `Shield`, and
   * returns it through serializer construct-result output.
   */
  void ConstructShieldForSerializerFromArchive(gpg::ReadArchive* archive, gpg::SerConstructResult* result);

  /**
   * Address: 0x00776840 (FUN_00776840)
   *
   * What it does:
   * Serializer construct-callback thunk that forwards to
   * `ConstructShieldForSerializerFromArchive`.
   */
  void ConstructShieldSerializerThunk(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::SerConstructResult* result
  );

  /**
   * VFTABLE: 0x00E3713C
   * COL: 0x00E90E54
   */
  class ShieldSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDD520 (FUN_00BDD520, dynamic initializer for the global
     * `ShieldSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field to `SaveConstructArgs`.
     */
    ShieldSaveConstruct();

    /**
     * Address: 0x00C02590 (FUN_00C02590, dynamic-initializer atexit target)
     *
     * What it does:
     * Unlinks this helper node from the intrusive helper list.
     */
    ~ShieldSaveConstruct();

    /**
     * Address: 0x007766B0 (FUN_007766B0, Moho::ShieldSaveConstruct::SaveConstructArgs)
     *
     * What it does:
     * Writes the owning `Sim*` (read from the `Shield` object's inherited
     * `Entity::SimulationRef` field at +0x148) as an unowned tracked pointer.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive, int objectPtr, int version, gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x00776D20 (FUN_00776D20, Moho::ShieldSaveConstruct::Init)
     *
     * What it does:
     * Binds save-construct-args callback into Shield RTTI (`serSaveConstructArgsFunc_`).
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  static_assert(
    offsetof(ShieldSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "ShieldSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );

  /**
   * VFTABLE: 0x00E3714C
   * COL: 0x00E90DA8
   */
  class ShieldConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDD550 (FUN_00BDD550, dynamic initializer for the global
     * `ShieldConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    ShieldConstruct();

    /**
     * Address: 0x00C025C0 (FUN_00C025C0, dynamic-initializer atexit target)
     *
     * What it does:
     * Unlinks this helper node from the intrusive helper list.
     */
    ~ShieldConstruct();

    /**
     * Address: 0x00776DA0 (FUN_00776DA0, Moho::ShieldConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into Shield RTTI (`serConstructFunc_`, `deleteFunc_`).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  static_assert(
    offsetof(ShieldConstruct, mSerConstructFunc) == 0x0C,
    "ShieldConstruct::mSerConstructFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(ShieldConstruct, mDeleteFunc) == 0x10, "ShieldConstruct::mDeleteFunc offset must be 0x10"
  );

  /**
   * VFTABLE: 0x00E3715C
   * COL: 0x00E90CFC
   */
  class ShieldSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDD590 (FUN_00BDD590, dynamic initializer for the global
     * `ShieldSerializer` singleton)
     */
    ShieldSerializer();

    /**
     * Address: 0x00C025F0 (FUN_00C025F0, dynamic-initializer atexit target)
     *
     * What it does:
     * Unlinks this helper node from the intrusive helper list.
     */
    ~ShieldSerializer();

    /**
     * Address: 0x00776910 (FUN_00776910, Moho::ShieldSerializer::Deserialize)
     *
     * What it does:
     * `Shield` declares no fields beyond its inherited `Entity` state, so its
     * load callback simply redispatches through `Entity`'s own reflected
     * read path instead of walking Shield-specific members.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00776950 (FUN_00776950, Moho::ShieldSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00776E20 (FUN_00776E20, Moho::ShieldSerializer::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into Shield RTTI (`serLoadFunc_`, `serSaveFunc_`).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(
    offsetof(ShieldSerializer, mSerLoadFunc) == 0x0C, "ShieldSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(ShieldSerializer, mSerSaveFunc) == 0x10, "ShieldSerializer::mSerSaveFunc offset must be 0x10"
  );

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
