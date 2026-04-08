#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/BVSet.h"

struct lua_State;

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class RBlueprint;
  class REntityBlueprint;
  class CScrLuaInitForm;

  /**
   * Reflection helper value serialized ahead of category bitset payload.
   *
   * Address: 0x0052B780 (FUN_0052B780, EntityCategoryHelperTypeInfo::Init)
   */
  struct EntityCategoryHelper
  {
    static gpg::RType* sType;

    std::uint32_t mWordUniverseHandle{0}; // +0x00

    /**
     * Address family:
     * - 0x005563D2/0x00556870/0x005567F0 callsites (lazy cache usage)
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();
  };
  static_assert(sizeof(EntityCategoryHelper) == 0x04, "EntityCategoryHelper size must be 0x04");

  using EntityCategorySet = BVSet<const RBlueprint*, EntityCategoryHelper>;
  static_assert(sizeof(EntityCategorySet) == 0x28, "EntityCategorySet size must be 0x28");

  /**
   * Address family:
   * - 0x005567F0 (FUN_005567F0, SerSave)
   * - 0x00556870 (FUN_00556870, SerLoad)
   */
  class EntityCategory
  {
  public:
    /**
     * Address: 0x005567F0 (FUN_005567F0, Moho::EntityCategory::SerSave)
     *
     * What it does:
     * Serializes helper dword (+0x00) and BVIntSet payload (+0x08).
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int unused, gpg::RRef* ownerRef);

    /**
     * Address: 0x00556870 (FUN_00556870, Moho::EntityCategory::SerLoad)
     *
     * What it does:
     * Deserializes helper dword (+0x00) and BVIntSet payload (+0x08).
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int unused, gpg::RRef* ownerRef);

    /**
     * Address: 0x0056A9D0 (FUN_0056A9D0, Moho::EntityCategory::HasBlueprint)
     *
     * What it does:
     * Returns whether one blueprint category-bit index is present in the given
     * category-set bitfield.
     */
    [[nodiscard]] static bool HasBlueprint(const REntityBlueprint* blueprint, const EntityCategorySet* categorySet);

    /**
     * Address: 0x00557710 (FUN_00557710, Moho::EntityCategory::Sub)
     *
     * What it does:
     * Computes `lhs - rhs` into `out`.
     */
    static EntityCategorySet* Sub(EntityCategorySet* out, const EntityCategorySet* lhs, const EntityCategorySet* rhs);

    /**
     * Address: 0x005577B0 (FUN_005577B0, Moho::EntityCategory::Mul)
     *
     * What it does:
     * Computes `lhs & rhs` into `out`.
     */
    static EntityCategorySet* Mul(EntityCategorySet* out, const EntityCategorySet* lhs, const EntityCategorySet* rhs);
  };

  /**
   * VFTABLE: 0x00E16294
   * COL: 0x00E6A070
   */
  class EntityCategoryHelperTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0052B720 (FUN_0052B720, Moho::EntityCategoryHelperTypeInfo::EntityCategoryHelperTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `EntityCategoryHelper`.
     */
    EntityCategoryHelperTypeInfo();

    /**
     * Address: 0x0052B7B0 (FUN_0052B7B0, deleting dtor thunk)
     * Slot: 2
     */
    ~EntityCategoryHelperTypeInfo() override;

    /**
     * Address: 0x0052B7A0 (FUN_0052B7A0, Moho::EntityCategoryHelperTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0052B780 (FUN_0052B780, Moho::EntityCategoryHelperTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;
  };
  static_assert(sizeof(EntityCategoryHelperTypeInfo) == 0x64, "EntityCategoryHelperTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E162C4
   * COL: 0x00E69FD8
   */
  class EntityCategoryHelperSerializer
  {
  public:
    /**
     * Address: 0x00BF3AD0 (FUN_00BF3AD0, Moho::EntityCategoryHelperSerializer::dtr)
     *
     * What it does:
     * Unlinks the serializer helper node from the intrusive helper list.
     */
    ~EntityCategoryHelperSerializer();

    /**
     * Address: 0x0052C8E0 (FUN_0052C8E0, gpg::SerSaveLoadHelper_EntityCategoryHelper::Init)
     *
     * What it does:
     * Registers helper load/save callbacks on `EntityCategoryHelper` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };
  static_assert(sizeof(EntityCategoryHelperSerializer) == 0x14, "EntityCategoryHelperSerializer size must be 0x14");

  /**
   * Address: 0x00BC8F10 (FUN_00BC8F10, register_EntityCategoryHelperTypeInfoStartup)
   *
   * What it does:
   * Materializes and startup-registers `EntityCategoryHelperTypeInfo`.
   */
  int register_EntityCategoryHelperTypeInfoStartup();

  /**
   * Address: 0x00BC8F30 (FUN_00BC8F30, register_EntityCategoryHelperSerializer)
   *
   * What it does:
   * Initializes serializer helper links/callbacks and registers teardown.
   */
  void register_EntityCategoryHelperSerializer();

  /**
   * Address: 0x005575E0 (FUN_005575E0, func_GetCObj_EntityCategory)
   *
   * What it does:
   * Resolves one Lua value/table to a reflected `EntityCategorySet*` userdata payload.
   */
  [[nodiscard]] EntityCategorySet* func_GetCObj_EntityCategory(const LuaPlus::LuaObject& valueObject);

  /**
   * Address: 0x00533150 (FUN_00533150, func_NewEntityCategory)
   *
   * What it does:
   * Wraps one `EntityCategorySet*` in Lua userdata and applies the category metatable.
   */
  LuaPlus::LuaObject*
    func_NewEntityCategory(LuaPlus::LuaState* state, LuaPlus::LuaObject* out, EntityCategorySet* value);

  /**
   * Address: 0x00557670 (FUN_00557670, func_EntityCategoryAdd)
   *
   * What it does:
   * Computes `lhs | rhs` into `out`.
   */
  EntityCategorySet* func_EntityCategoryAdd(
    const EntityCategorySet* lhs,
    EntityCategorySet* out,
    const EntityCategorySet* rhs
  );

  /**
   * Address: 0x005556B0 (FUN_005556B0, cfunc_EntityCategory__add)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntityCategory__addL`.
   */
  int cfunc_EntityCategory__add(lua_State* luaContext);

  /**
   * Address: 0x00555730 (FUN_00555730, cfunc_EntityCategory__addL)
   *
   * What it does:
   * Builds one category union from `(cat1, cat2)` and returns a new Lua category userdata.
   */
  int cfunc_EntityCategory__addL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005556D0 (FUN_005556D0, func_EntityCategory__add_LuaFuncDef)
   *
   * What it does:
   * Publishes the `EntityCategory.__add` Lua binder.
   */
  CScrLuaInitForm* func_EntityCategory__add_LuaFuncDef();

  /**
   * Address: 0x00BC9E80 (FUN_00BC9E80, register_EntityCategory__add_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_EntityCategory__add_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategory__add_LuaFuncDef();

  /**
   * Address: 0x00555840 (FUN_00555840, cfunc_EntityCategory__sub)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntityCategory__subL`.
   */
  int cfunc_EntityCategory__sub(lua_State* luaContext);

  /**
   * Address: 0x005558C0 (FUN_005558C0, cfunc_EntityCategory__subL)
   *
   * What it does:
   * Builds one category subtraction from `(cat1, cat2)` and returns a new Lua category userdata.
   */
  int cfunc_EntityCategory__subL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00555860 (FUN_00555860, func_EntityCategory__sub_LuaFuncDef)
   *
   * What it does:
   * Publishes the `EntityCategory.__sub` Lua binder.
   */
  CScrLuaInitForm* func_EntityCategory__sub_LuaFuncDef();

  /**
   * Address: 0x00BC9E90 (FUN_00BC9E90, register_EntityCategory__sub_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_EntityCategory__sub_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategory__sub_LuaFuncDef();

  /**
   * Address: 0x005559D0 (FUN_005559D0, cfunc_EntityCategory__mul)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_EntityCategory__mulL`.
   */
  int cfunc_EntityCategory__mul(lua_State* luaContext);

  /**
   * Address: 0x00555A50 (FUN_00555A50, cfunc_EntityCategory__mulL)
   *
   * What it does:
   * Builds one category intersection from `(cat1, cat2)` and returns a new Lua category userdata.
   */
  int cfunc_EntityCategory__mulL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005559F0 (FUN_005559F0, func_EntityCategory__mul_LuaFuncDef)
   *
   * What it does:
   * Publishes the `EntityCategory.__mul` Lua binder.
   */
  CScrLuaInitForm* func_EntityCategory__mul_LuaFuncDef();

  /**
   * Address: 0x00BC9EA0 (FUN_00BC9EA0, register_EntityCategory__mul_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_EntityCategory__mul_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategory__mul_LuaFuncDef();

  /**
   * Address: 0x00555D70 (FUN_00555D70, cfunc_EntityCategoryEmpty)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EntityCategoryEmptyL`.
   */
  int cfunc_EntityCategoryEmpty(lua_State* luaContext);

  /**
   * Address: 0x00555DF0 (FUN_00555DF0, cfunc_EntityCategoryEmptyL)
   *
   * What it does:
   * Returns whether one entity-category set has no selected category bits.
   */
  int cfunc_EntityCategoryEmptyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00555D90 (FUN_00555D90, func_EntityCategoryEmpty_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EntityCategoryEmpty`.
   */
  CScrLuaInitForm* func_EntityCategoryEmpty_LuaFuncDef();

  /**
   * Address: 0x00BC9EC0 (FUN_00BC9EC0, register_EntityCategoryEmpty_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_EntityCategoryEmpty_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryEmpty_LuaFuncDef();

  /**
   * Address: 0x0055B610 (FUN_0055B610, cfunc_SecondsPerTick)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_SecondsPerTickL`.
   */
  int cfunc_SecondsPerTick(lua_State* luaContext);

  /**
   * Address: 0x0055B690 (FUN_0055B690, cfunc_SecondsPerTickL)
   *
   * What it does:
   * Pushes the fixed simulation step duration (`0.1` seconds).
   */
  int cfunc_SecondsPerTickL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0055B630 (FUN_0055B630, func_SecondsPerTick_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SecondsPerTick`.
   */
  CScrLuaInitForm* func_SecondsPerTick_LuaFuncDef();

  /**
   * Address: 0x00BCA3C0 (FUN_00BCA3C0, register_SecondsPerTick_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_SecondsPerTick_LuaFuncDef`.
   */
  void register_SecondsPerTick_LuaFuncDef();
} // namespace moho
