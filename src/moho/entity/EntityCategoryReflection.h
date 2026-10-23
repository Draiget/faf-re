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
  class RRuleGameRules;
  struct RBlueprint;
  struct REntityBlueprint;
  class CScrLuaInitForm;

  /**
   * Reflection helper value serialized ahead of category bitset payload.
   *
   * Address: 0x0052B780 (FUN_0052B780, EntityCategoryHelperTypeInfo::Init)
   */
  struct EntityCategoryHelper
  {
    static gpg::RType* sType;

    RRuleGameRules* mRules{nullptr}; // +0x00

    /** Inlined block from FUN_0052B860: reads the unowned rules pointer. */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /** Inlined block from FUN_0052B890: writes the unowned rules pointer. */
    void MemberSerialize(gpg::WriteArchive* archive) const;

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
   * Address: 0x0052CBD0 (FUN_0052CBD0, Moho::EntityCategory::end)
   *
   * What it does:
   * Legacy iterator payload for category-word traversal; stores universe handle,
   * bitset owner, and one current bit index cursor.
   */
  struct EntityCategoryIterator
  {
    RRuleGameRules* mRules; // +0x00
    BVIntSet* mSet;                    // +0x04
    std::int32_t mCurBit;              // +0x08
  };
  static_assert(sizeof(EntityCategoryIterator) == 0x0C, "EntityCategoryIterator size must be 0x0C");

  /**
   * Address: 0x0052CBD0 (FUN_0052CBD0, Moho::EntityCategory::end)
   *
   * What it does:
   * Builds the legacy past-end iterator view for one category set by wiring
   * universe handle, bitset pointer, and `Max()`-equivalent cursor (`wordEnd * 32`).
   */
  [[nodiscard]] EntityCategoryIterator*
    BuildEntityCategoryEndIterator(EntityCategoryIterator* out, EntityCategorySet* categorySet) noexcept;

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
    static void SerSave(gpg::WriteArchive* archive, std::intptr_t objectPtr, int unused, gpg::RRef* ownerRef);

    /**
     * Address: 0x00556870 (FUN_00556870, Moho::EntityCategory::SerLoad)
     *
     * What it does:
     * Deserializes helper dword (+0x00) and BVIntSet payload (+0x08).
     */
    static void SerLoad(gpg::ReadArchive* archive, std::intptr_t objectPtr, int unused, gpg::RRef* ownerRef);

    /**
     * Address: 0x0052BB50 (FUN_0052BB50, Moho::EntityCategory::Add)
     *
     * What it does:
     * Iterates every set bit in `source` as a rules-ordinal lane, remaps that
     * ordinal through `GetBlueprintFromOrdinal()->mBlueprintOrdinal`, and sets
     * the remapped bit in `out`.
     */
    static EntityCategorySet* Add(EntityCategorySet* out, const EntityCategorySet* source);

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
   * Canonical SerSaveLoadHelper<EntityCategoryHelper>, vtable 0x00E162C4.
   * FUN_0052B860/0052B890 are its emitted callbacks, not EntityCategory's.
   * CRT construction: FUN_00BC8F30; Init: FUN_0052C8E0;
   * destruction: FUN_00BF3AD0. See the reconstruction report.
   */
  struct EntityCategoryHelperSerializer : gpg::SerSaveLoadHelper<EntityCategoryHelper>
  {};
  static_assert(sizeof(EntityCategoryHelperSerializer) == 0x14, "EntityCategoryHelperSerializer size must be 0x14");

  /**
   * Address: 0x00BC8F10 (FUN_00BC8F10, register_EntityCategoryHelperTypeInfoStartup)
   *
   * What it does:
   * Materializes and startup-registers `EntityCategoryHelperTypeInfo`.
   */
  void register_EntityCategoryHelperTypeInfoStartup();

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
   * Address: 0x00BC9E60 (FUN_00BC9E60, register_EntityCategory)
   *
   * What it does:
   * Registers the class binder that publishes moho.EntityCategory, so Lua
   * save setup can export its native metatable methods by name.
   */
  CScrLuaInitForm* register_EntityCategory();

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
  CScrLuaInitForm* register_SecondsPerTick_LuaFuncDef();

  /**
   * Address: 0x00555B60 (FUN_00555B60, cfunc_EntityCategoryGetUnitList)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EntityCategoryGetUnitListL`.
   */
  int cfunc_EntityCategoryGetUnitList(lua_State* luaContext);

  /**
   * Address: 0x00555BE0 (FUN_00555BE0, cfunc_EntityCategoryGetUnitListL)
   *
   * What it does:
   * Builds a Lua array of blueprint id strings for every category ordinal set
   * in the argument `EntityCategory`, resolving each ordinal to its blueprint
   * through the owning game-rules `GetBlueprintFromOrdinal`.
   */
  int cfunc_EntityCategoryGetUnitListL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00555B80 (FUN_00555B80, func_EntityCategoryGetUnitList_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EntityCategoryGetUnitList`.
   */
  CScrLuaInitForm* func_EntityCategoryGetUnitList_LuaFuncDef();

  /**
   * Address: 0x00BC9EB0 (FUN_00BC9EB0, register_EntityCategoryGetUnitList_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_EntityCategoryGetUnitList_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryGetUnitList_LuaFuncDef();
} // namespace moho
