#include "moho/entity/EntityCategoryReflection.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"
#include "moho/containers/BVIntSet.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kEntityCategoryLuaClassName = "EntityCategory";
  constexpr const char* kEntityCategoryAddHelpText = "Generate a category list that is the sum of both categories";
  constexpr const char* kEntityCategorySubHelpText = "Generate a category list of units that is of cat1 but not of cat2";
  constexpr const char* kEntityCategoryMulHelpText = "Generate a category list that is an intersection of cat1 and cat2";
  constexpr const char* kEntityCategoryEmptyHelpText = "Test for an empty category";
  constexpr const char* kSecondsPerTickHelpText = "SecondsPerTick() - Return how many seconds in a tick";
  constexpr const char* kEntityCategoryGetUnitListHelpText = "Get a list of units blueprint names from a category";

  [[nodiscard]] gpg::RType* CachedBVIntSetType()
  {
    if (!moho::BVIntSet::sType) {
      moho::BVIntSet::sType = gpg::LookupRType(typeid(moho::BVIntSet));
    }
    return moho::BVIntSet::sType;
  }

  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Core"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("Core");
    return fallbackSet;
  }

  class EntityCategoryLuaMetatableFactory final : public moho::CScrLuaObjectFactory
  {
  public:
    [[nodiscard]] static EntityCategoryLuaMetatableFactory& Instance()
    {
      static EntityCategoryLuaMetatableFactory sInstance;
      return sInstance;
    }

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* const state) override
    {
      return moho::SCR_CreateSimpleMetatable(state);
    }

  private:
    EntityCategoryLuaMetatableFactory()
      : moho::CScrLuaObjectFactory(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex())
    {}
  };
  static_assert(sizeof(EntityCategoryLuaMetatableFactory) == 0x8, "EntityCategoryLuaMetatableFactory size must be 0x8");

  /**
   * Address: 0x00537070 (FUN_00537070)
   *
   * What it does:
   * Rebinds the startup metatable-factory index lane for the entity-category
   * Lua metatable factory singleton and returns that singleton.
   */
  [[maybe_unused]] EntityCategoryLuaMetatableFactory* startup_EntityCategoryLuaMetatableFactory_Index()
  {
    auto& instance = EntityCategoryLuaMetatableFactory::Instance();
    instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }

  /**
   * Address: 0x00BC8F70 (FUN_00BC8F70, register_EntityCategoryLuaMetatableFactoryIndexStartup)
   *
   * What it does:
   * Allocates the startup factory-object index used by entity-category Lua
   * metatable objects and stores it on the singleton factory.
   */
  int register_EntityCategoryLuaMetatableFactoryIndexStartup()
  {
    const int index = moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    EntityCategoryLuaMetatableFactory::Instance().SetFactoryObjectIndexForRecovery(index);
    return index;
  }

  /**
   * The reflected reference is assembled from the userdata HEADER, not read out
   * of its payload. This fork carries the `gpg::RType*` in `Udata::len`, and the
   * value itself starts one header past the allocation, which is exactly what
   * `LuaPlus::LuaObject::GetUserData` (0x00907540) does:
   *
   *     lea edx, [ecx+10h]   ; mObj  = payload, laid out after the header
   *     mov ecx, [ecx+0Ch]   ; mType = Udata::len reinterpreted as RType*
   *
   * Reading `*(gpg::RRef*)lua_touserdata(...)` instead - as this helper used to -
   * takes the first eight payload bytes as if they were a reference. For a
   * `_c_object` slot those bytes are the `CScriptObject*` value followed by
   * whatever the allocator left, so every upcast failed and each caller reported
   * "Expected a game object" for a perfectly good object.
   */
  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    if (!userDataObject.IsUserData()) {
      return gpg::RRef{};
    }

    return userDataObject.GetUserData();
  }

  [[nodiscard]] gpg::RType* CachedEntityCategorySetType()
  {
    if (!moho::EntityCategorySet::sType) {
      moho::EntityCategorySet::sType = gpg::LookupRType(typeid(moho::EntityCategorySet));
    }
    return moho::EntityCategorySet::sType;
  }

  [[nodiscard]] moho::RRuleGameRulesImpl* ResolveCategoryRules(const moho::EntityCategorySet& categorySet) noexcept
  {
    return reinterpret_cast<moho::RRuleGameRulesImpl*>(
      static_cast<std::uintptr_t>(categorySet.mUniverse.mWordUniverseHandle)
    );
  }

  /**
   * Address: 0x00533310 (FUN_00533310, sub_533310)
   *
   * What it does:
   * Walks source category ordinals in `[position, endOrdinalExclusive)`,
   * remaps each ordinal via `GetBlueprintFromOrdinal()->mBlueprintOrdinal`,
   * then sets the mapped bit in `out`.
   */
  void AddMappedBlueprintOrdinalBits(
    moho::EntityCategorySet* const out,
    moho::RRuleGameRulesImpl* const rules,
    const moho::BVIntSet& sourceBits,
    unsigned int position,
    const unsigned int endOrdinalExclusive
  )
  {
    if (position == endOrdinalExclusive) {
      return;
    }

    moho::BVIntSet& outBits = out->mBits;
    do {
      moho::RBlueprint* const blueprint = rules->GetBlueprintFromOrdinal(static_cast<int>(position));
      const auto mappedOrdinal = static_cast<unsigned int>(blueprint->mBlueprintOrdinal);

      outBits.EnsureBounds(mappedOrdinal, mappedOrdinal + 1u);
      const unsigned int relativeWord = (mappedOrdinal >> 5u) - outBits.mFirstWordIndex;
      outBits.mWords.start_[relativeWord] |= (1u << (mappedOrdinal & 0x1Fu));

      position = sourceBits.GetNext(position);
    } while (position != endOrdinalExclusive);
  }

  /**
   * Address: 0x00557920 (FUN_00557920, gpg::RRef::TryUpcast_EntityCategory)
   *
   * What it does:
   * Upcasts one reflected reference to `EntityCategorySet*` and throws
   * `BadRefCast` with source/target type names on mismatch.
   */
  [[nodiscard]] moho::EntityCategorySet* TryUpcastEntityCategoryOrThrow(const gpg::RRef& source)
  {
    gpg::RType* const entityCategoryType = CachedEntityCategorySetType();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, entityCategoryType);
    auto* const categorySet = static_cast<moho::EntityCategorySet*>(upcast.mObj);
    if (!categorySet) {
      const char* const sourceName = source.mType ? source.mType->GetName() : "null";
      const char* const targetName = entityCategoryType->GetName();
      throw gpg::BadRefCast(nullptr, sourceName, targetName);
    }

    return categorySet;
  }

  alignas(moho::EntityCategoryHelperTypeInfo)
    unsigned char gEntityCategoryHelperTypeInfoStorage[sizeof(moho::EntityCategoryHelperTypeInfo)];
  bool gEntityCategoryHelperTypeInfoConstructed = false;

  // Address: 0x010ABA0C -- process-global `EntityCategoryHelperSerializer` singleton.
  moho::EntityCategoryHelperSerializer gEntityCategoryHelperSerializer;

  [[nodiscard]] moho::EntityCategoryHelperTypeInfo& AcquireEntityCategoryHelperTypeInfo()
  {
    if (!gEntityCategoryHelperTypeInfoConstructed) {
      new (gEntityCategoryHelperTypeInfoStorage) moho::EntityCategoryHelperTypeInfo();
      gEntityCategoryHelperTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::EntityCategoryHelperTypeInfo*>(gEntityCategoryHelperTypeInfoStorage);
  }

  void cleanup_EntityCategoryHelperTypeInfo()
  {
    if (!gEntityCategoryHelperTypeInfoConstructed) {
      return;
    }

    AcquireEntityCategoryHelperTypeInfo().~EntityCategoryHelperTypeInfo();
    gEntityCategoryHelperTypeInfoConstructed = false;
  }

  struct EntityCategoryHelperRegistration
  {
    EntityCategoryHelperRegistration()
    {
      (void)register_EntityCategoryLuaMetatableFactoryIndexStartup();
      (void)moho::register_EntityCategoryHelperTypeInfoStartup();
    }
  };

  EntityCategoryHelperRegistration gEntityCategoryHelperRegistration;
} // namespace

  namespace moho
{
  gpg::RType* EntityCategoryHelper::sType = nullptr;

  /**
   * Address: 0x0052D8D0 (FUN_0052D8D0)
   *
   * What it does:
   * Lazily resolves and caches RTTI metadata for `EntityCategoryHelper`.
   */
  gpg::RType* EntityCategoryHelper::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(EntityCategoryHelper));
    }
    return sType;
  }

  /**
   * Address: 0x0052CBD0 (FUN_0052CBD0, Moho::EntityCategory::end)
   *
   * What it does:
   * Builds one past-end legacy category iterator payload from category set
   * storage (`firstWordIndex + wordCount`, then `* 32`).
   */
  EntityCategoryIterator*
  BuildEntityCategoryEndIterator(EntityCategoryIterator* const out, EntityCategorySet* const categorySet) noexcept
  {
    if (out == nullptr || categorySet == nullptr) {
      return out;
    }

    BVIntSet* const bits = &categorySet->mBits;

    std::size_t wordCount = 0u;
    if (bits->mWords.start_ != nullptr && bits->mWords.end_ != nullptr && bits->mWords.end_ >= bits->mWords.start_) {
      wordCount = static_cast<std::size_t>(bits->mWords.end_ - bits->mWords.start_);
    }

    const std::uint32_t endWordIndex = bits->mFirstWordIndex + static_cast<std::uint32_t>(wordCount);
    out->mWordUniverseHandle = categorySet->mUniverse.mWordUniverseHandle;
    out->mSet = bits;
    out->mCurBit = static_cast<std::int32_t>(endWordIndex << 5u);
    return out;
  }

  /**
   * Address: 0x005575E0 (FUN_005575E0, func_GetCObj_EntityCategory)
   */
  EntityCategorySet* func_GetCObj_EntityCategory(const LuaPlus::LuaObject& valueObject)
  {
    LuaPlus::LuaObject payload(valueObject);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(payload);
    return TryUpcastEntityCategoryOrThrow(userDataRef);
  }

  /**
   * Address: 0x00533150 (FUN_00533150, func_NewEntityCategory)
   */
  LuaPlus::LuaObject*
    func_NewEntityCategory(LuaPlus::LuaState* const state, LuaPlus::LuaObject* const out, EntityCategorySet* const value)
  {
    LuaPlus::LuaObject metatable = EntityCategoryLuaMetatableFactory::Instance().Get(state);
    gpg::RRef categoryRef{};
    (void)gpg::RRef_EntityCategory(&categoryRef, value);
    out->AssignNewUserData(state, categoryRef);
    out->SetMetaTable(metatable);
    return out;
  }

  /**
   * Address: 0x00BC9E60 (FUN_00BC9E60, register_EntityCategory)
   *
   * What it does:
   * Reads and returns the current head of the `Core` Lua init-form set. See
   * the declaration in `EntityCategoryReflection.h` for the full evidence
   * trail on why the binary's list-prepend half is not reproduced here.
   */
  CScrLuaInitForm* register_EntityCategory()
  {
    CScrLuaInitFormSet& coreSet = CoreLuaInitSet();
    CScrLuaInitForm* const previousHead = coreSet.mForms;
    // Prepend intentionally omitted - the anchor's real identity cannot be
    // recovered from available evidence (see header doc comment), and a
    // placeholder object would corrupt the list per the already-diagnosed
    // register_CAiAttackerImplLuaInitFormAnchor case in CAiAttackerImpl.cpp.
    return previousHead;
  }

  /**
   * Address: 0x00557670 (FUN_00557670, func_EntityCategoryAdd)
   */
  EntityCategorySet* func_EntityCategoryAdd(
    const EntityCategorySet* const lhs,
    EntityCategorySet* const out,
    const EntityCategorySet* const rhs
  )
  {
    out->mUniverse = lhs->mUniverse;
    BVIntSet unionBits{};
    (void)lhs->mBits.Union(&unionBits, &rhs->mBits);
    out->mBits = unionBits;
    return out;
  }

  /**
   * Address: 0x0052BB50 (FUN_0052BB50, Moho::EntityCategory::Add)
   *
   * What it does:
   * Iterates each source category ordinal and ORs the corresponding
   * `RBlueprint::mBlueprintOrdinal` bit into `out`.
   */
  EntityCategorySet* EntityCategory::Add(EntityCategorySet* const out, const EntityCategorySet* const source)
  {
    const unsigned int endOrdinalExclusive = source->mBits.Max();
    const unsigned int firstOrdinal = source->mBits.GetNext(std::numeric_limits<unsigned int>::max());

    AddMappedBlueprintOrdinalBits(out, ResolveCategoryRules(*source), source->mBits, firstOrdinal, endOrdinalExclusive);
    return out;
  }

  /**
   * Address: 0x0056A9D0 (FUN_0056A9D0, Moho::EntityCategory::HasBlueprint)
   *
   * What it does:
   * Returns whether one blueprint category-bit index is present in the given
   * category-set bitfield.
   */
  bool EntityCategory::HasBlueprint(const REntityBlueprint* const blueprint, const EntityCategorySet* const categorySet)
  {
    return blueprint != nullptr && categorySet != nullptr && categorySet->mBits.Contains(blueprint->mCategoryBitIndex);
  }

  /**
   * Address: 0x00557710 (FUN_00557710, Moho::EntityCategory::Sub)
   */
  EntityCategorySet*
    EntityCategory::Sub(EntityCategorySet* const out, const EntityCategorySet* const lhs, const EntityCategorySet* const rhs)
  {
    out->mUniverse = lhs->mUniverse;
    BVIntSet subtractionBits{};
    (void)lhs->mBits.Subtract(&subtractionBits, &rhs->mBits);
    out->mBits = subtractionBits;
    return out;
  }

  /**
   * Address: 0x005577B0 (FUN_005577B0, Moho::EntityCategory::Mul)
   */
  EntityCategorySet*
    EntityCategory::Mul(EntityCategorySet* const out, const EntityCategorySet* const lhs, const EntityCategorySet* const rhs)
  {
    out->mUniverse = lhs->mUniverse;
    BVIntSet intersectionBits{};
    (void)lhs->mBits.Intersect(&intersectionBits, &rhs->mBits);
    out->mBits = intersectionBits;
    return out;
  }

  /**
   * Address: 0x005556B0 (FUN_005556B0, cfunc_EntityCategory__add)
   */
  int cfunc_EntityCategory__add(lua_State* const luaContext)
  {
    return cfunc_EntityCategory__addL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00555730 (FUN_00555730, cfunc_EntityCategory__addL)
   */
  int cfunc_EntityCategory__addL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryAddHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject lhsObject(LuaPlus::LuaStackObject(state, 1));
    EntityCategorySet* const lhs = func_GetCObj_EntityCategory(lhsObject);

    const LuaPlus::LuaObject rhsObject(LuaPlus::LuaStackObject(state, 2));
    EntityCategorySet* const rhs = func_GetCObj_EntityCategory(rhsObject);

    EntityCategorySet result{};
    (void)func_EntityCategoryAdd(lhs, &result, rhs);

    LuaPlus::LuaObject out;
    (void)func_NewEntityCategory(state, &out, &result);
    out.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x005556D0 (FUN_005556D0, func_EntityCategory__add_LuaFuncDef)
   */
  CScrLuaInitForm* func_EntityCategory__add_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "__add",
      &moho::cfunc_EntityCategory__add,
      &EntityCategoryLuaMetatableFactory::Instance(),
      kEntityCategoryLuaClassName,
      kEntityCategoryAddHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BC9E80 (FUN_00BC9E80, register_EntityCategory__add_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityCategory__add_LuaFuncDef()
  {
    return func_EntityCategory__add_LuaFuncDef();
  }

  /**
   * Address: 0x00555840 (FUN_00555840, cfunc_EntityCategory__sub)
   */
  int cfunc_EntityCategory__sub(lua_State* const luaContext)
  {
    return cfunc_EntityCategory__subL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x005558C0 (FUN_005558C0, cfunc_EntityCategory__subL)
   */
  int cfunc_EntityCategory__subL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategorySubHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject lhsObject(LuaPlus::LuaStackObject(state, 1));
    EntityCategorySet* const lhs = func_GetCObj_EntityCategory(lhsObject);

    const LuaPlus::LuaObject rhsObject(LuaPlus::LuaStackObject(state, 2));
    EntityCategorySet* const rhs = func_GetCObj_EntityCategory(rhsObject);

    EntityCategorySet result{};
    (void)EntityCategory::Sub(&result, lhs, rhs);

    LuaPlus::LuaObject out;
    (void)func_NewEntityCategory(state, &out, &result);
    out.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00555860 (FUN_00555860, func_EntityCategory__sub_LuaFuncDef)
   */
  CScrLuaInitForm* func_EntityCategory__sub_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "__sub",
      &moho::cfunc_EntityCategory__sub,
      &EntityCategoryLuaMetatableFactory::Instance(),
      kEntityCategoryLuaClassName,
      kEntityCategorySubHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BC9E90 (FUN_00BC9E90, register_EntityCategory__sub_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityCategory__sub_LuaFuncDef()
  {
    return func_EntityCategory__sub_LuaFuncDef();
  }

  /**
   * Address: 0x005559D0 (FUN_005559D0, cfunc_EntityCategory__mul)
   */
  int cfunc_EntityCategory__mul(lua_State* const luaContext)
  {
    return cfunc_EntityCategory__mulL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00555A50 (FUN_00555A50, cfunc_EntityCategory__mulL)
   */
  int cfunc_EntityCategory__mulL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryMulHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject lhsObject(LuaPlus::LuaStackObject(state, 1));
    EntityCategorySet* const lhs = func_GetCObj_EntityCategory(lhsObject);

    const LuaPlus::LuaObject rhsObject(LuaPlus::LuaStackObject(state, 2));
    EntityCategorySet* const rhs = func_GetCObj_EntityCategory(rhsObject);

    EntityCategorySet result{};
    (void)EntityCategory::Mul(&result, lhs, rhs);

    LuaPlus::LuaObject out;
    (void)func_NewEntityCategory(state, &out, &result);
    out.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x005559F0 (FUN_005559F0, func_EntityCategory__mul_LuaFuncDef)
   */
  CScrLuaInitForm* func_EntityCategory__mul_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "__mul",
      &moho::cfunc_EntityCategory__mul,
      &EntityCategoryLuaMetatableFactory::Instance(),
      kEntityCategoryLuaClassName,
      kEntityCategoryMulHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BC9EA0 (FUN_00BC9EA0, register_EntityCategory__mul_LuaFuncDef)
   */
  CScrLuaInitForm* register_EntityCategory__mul_LuaFuncDef()
  {
    return func_EntityCategory__mul_LuaFuncDef();
  }

  /**
   * Address: 0x00555D70 (FUN_00555D70, cfunc_EntityCategoryEmpty)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_EntityCategoryEmptyL`.
   */
  int cfunc_EntityCategoryEmpty(lua_State* const luaContext)
  {
    return cfunc_EntityCategoryEmptyL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00555DF0 (FUN_00555DF0, cfunc_EntityCategoryEmptyL)
   *
   * What it does:
   * Returns whether one entity-category set has no selected category bits.
   */
  int cfunc_EntityCategoryEmptyL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryEmptyHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
    EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);
    const bool isEmpty = (categorySet->mBits.mWords.start_ == categorySet->mBits.mWords.end_);
    lua_pushboolean(state->m_state, isEmpty ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x00555D90 (FUN_00555D90, func_EntityCategoryEmpty_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EntityCategoryEmpty`.
   */
  CScrLuaInitForm* func_EntityCategoryEmpty_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "EntityCategoryEmpty",
      &moho::cfunc_EntityCategoryEmpty,
      nullptr,
      "<global>",
      kEntityCategoryEmptyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BC9EC0 (FUN_00BC9EC0, register_EntityCategoryEmpty_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_EntityCategoryEmpty_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryEmpty_LuaFuncDef()
  {
    return func_EntityCategoryEmpty_LuaFuncDef();
  }

  /**
   * Address: 0x0055B610 (FUN_0055B610, cfunc_SecondsPerTick)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_SecondsPerTickL`.
   */
  int cfunc_SecondsPerTick(lua_State* const luaContext)
  {
    return cfunc_SecondsPerTickL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0055B690 (FUN_0055B690, cfunc_SecondsPerTickL)
   *
   * What it does:
   * Pushes the fixed simulation step duration (`0.1` seconds).
   */
  int cfunc_SecondsPerTickL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 0) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSecondsPerTickHelpText, 0, argumentCount);
    }

    lua_pushnumber(state->m_state, 0.1f);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0055B630 (FUN_0055B630, func_SecondsPerTick_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SecondsPerTick`.
   */
  CScrLuaInitForm* func_SecondsPerTick_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "SecondsPerTick",
      &moho::cfunc_SecondsPerTick,
      nullptr,
      "<global>",
      kSecondsPerTickHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BCA3C0 (FUN_00BCA3C0, register_SecondsPerTick_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_SecondsPerTick_LuaFuncDef`.
   */
  void register_SecondsPerTick_LuaFuncDef()
  {
    (void)func_SecondsPerTick_LuaFuncDef();
  }

  /**
   * Address: 0x00555B60 (FUN_00555B60, cfunc_EntityCategoryGetUnitList)
   *
   * IDA signature:
   * int __cdecl cfunc_EntityCategoryGetUnitList(int a1);
   *
   * What it does:
   * Unwraps the raw Lua callback context (`lua_State`) into its owning
   * `LuaState` wrapper and forwards to the typed worker.
   */
  int cfunc_EntityCategoryGetUnitList(lua_State* const luaContext)
  {
    return cfunc_EntityCategoryGetUnitListL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00555BE0 (FUN_00555BE0, cfunc_EntityCategoryGetUnitListL)
   *
   * IDA signature:
   * int __usercall cfunc_EntityCategoryGetUnitListL@<eax>(LuaPlus::LuaState *a1@<ebx>);
   *
   * What it does:
   * Validates a single `EntityCategory` argument, then walks every set ordinal
   * in its bitset. For each ordinal it resolves the owning game-rules object
   * (packed as the category's word-universe handle) and calls
   * `GetBlueprintFromOrdinal(ordinal)` to obtain the blueprint, appending the
   * blueprint id string into a freshly created Lua array. Pushes and returns
   * that array (one Lua result).
   */
  int cfunc_EntityCategoryGetUnitListL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryGetUnitListHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
    EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    LuaPlus::LuaObject resultTable;
    resultTable.AssignNewTable(state, 0, 0);

    const BVIntSet& bits = categorySet->mBits;
    moho::RRuleGameRulesImpl* const rules = ResolveCategoryRules(*categorySet);
    const unsigned int endOrdinalExclusive = bits.Max();

    int insertIndex = 1;
    for (unsigned int ordinal = bits.GetNext(std::numeric_limits<unsigned int>::max()); ordinal != endOrdinalExclusive;
         ordinal = bits.GetNext(ordinal)) {
      RBlueprint* const blueprint = rules->GetBlueprintFromOrdinal(static_cast<int>(ordinal));

      LuaPlus::LuaObject nameObject;
      nameObject.AssignString(state, blueprint->mBlueprintId.c_str());
      resultTable.Insert(insertIndex++, nameObject);
    }

    resultTable.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00555B80 (FUN_00555B80, func_EntityCategoryGetUnitList_LuaFuncDef)
   *
   * What it does:
   * Publishes the `EntityCategoryGetUnitList` global Lua binder into the core
   * init-form set.
   */
  CScrLuaInitForm* func_EntityCategoryGetUnitList_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "EntityCategoryGetUnitList",
      &moho::cfunc_EntityCategoryGetUnitList,
      nullptr,
      "<global>",
      kEntityCategoryGetUnitListHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BC9EB0 (FUN_00BC9EB0, register_EntityCategoryGetUnitList_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_EntityCategoryGetUnitList_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityCategoryGetUnitList_LuaFuncDef()
  {
    return func_EntityCategoryGetUnitList_LuaFuncDef();
  }

  /**
   * Address: 0x005567F0 (FUN_005567F0, Moho::EntityCategory::SerSave)
   */
  void EntityCategory::SerSave(gpg::WriteArchive* archive, const int objectPtr, const int, gpg::RRef* ownerRef)
  {
    auto* const set = reinterpret_cast<EntityCategorySet*>(objectPtr);
    GPG_ASSERT(set != nullptr);
    if (!set) {
      return;
    }

    auto* const helper = reinterpret_cast<EntityCategoryHelper*>(set);
    const gpg::RRef owner = ownerRef ? *ownerRef : NullOwnerRef();

    archive->Write(EntityCategoryHelper::StaticGetClass(), helper, owner);
    archive->Write(CachedBVIntSetType(), &set->mBits, NullOwnerRef());
  }

  /**
   * Address: 0x00556870 (FUN_00556870, Moho::EntityCategory::SerLoad)
   */
  void EntityCategory::SerLoad(gpg::ReadArchive* archive, const int objectPtr, const int, gpg::RRef* ownerRef)
  {
    auto* const set = reinterpret_cast<EntityCategorySet*>(objectPtr);
    GPG_ASSERT(set != nullptr);
    if (!set) {
      return;
    }

    auto* const helper = reinterpret_cast<EntityCategoryHelper*>(set);
    const gpg::RRef owner = ownerRef ? *ownerRef : NullOwnerRef();

    archive->Read(EntityCategoryHelper::StaticGetClass(), helper, owner);
    archive->Read(CachedBVIntSetType(), &set->mBits, NullOwnerRef());
  }

  /**
   * Address: 0x0052B720 (FUN_0052B720, Moho::EntityCategoryHelperTypeInfo::EntityCategoryHelperTypeInfo)
   */
  EntityCategoryHelperTypeInfo::EntityCategoryHelperTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(EntityCategoryHelper), this);
  }

  /**
   * Address: 0x0052B7B0 (FUN_0052B7B0, deleting dtor thunk)
   */
  EntityCategoryHelperTypeInfo::~EntityCategoryHelperTypeInfo() = default;

  /**
   * Address: 0x0052B7A0 (FUN_0052B7A0, Moho::EntityCategoryHelperTypeInfo::GetName)
   */
  const char* EntityCategoryHelperTypeInfo::GetName() const
  {
    return "EntityCategoryHelper";
  }

  /**
   * Address: 0x0052B780 (FUN_0052B780, Moho::EntityCategoryHelperTypeInfo::Init)
   */
  void EntityCategoryHelperTypeInfo::Init()
  {
    size_ = sizeof(EntityCategoryHelper);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BF3AD0 (FUN_00BF3AD0, Moho::EntityCategoryHelperSerializer::~EntityCategoryHelperSerializer)
   */
  EntityCategoryHelperSerializer::~EntityCategoryHelperSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0052C8E0 (FUN_0052C8E0, Moho::EntityCategoryHelperSerializer::Init)
   */
  void EntityCategoryHelperSerializer::Init()
  {
    gpg::RType* const type = EntityCategoryHelper::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x00BC8F10 (FUN_00BC8F10, register_EntityCategoryHelperTypeInfoStartup)
   */
  int register_EntityCategoryHelperTypeInfoStartup()
  {
    (void)AcquireEntityCategoryHelperTypeInfo();
    return std::atexit(&cleanup_EntityCategoryHelperTypeInfo);
  }

  /**
   * Address: 0x00BC8F30 (FUN_00BC8F30, dynamic initializer for the global
   * `EntityCategoryHelperSerializer` singleton)
   */
  EntityCategoryHelperSerializer::EntityCategoryHelperSerializer()
    : mSerLoadFunc(&EntityCategory::SerLoad)
    , mSerSaveFunc(&EntityCategory::SerSave)
  {}
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EntityCategoryHelperTypeInfoStartup_887a87, moho::register_EntityCategoryHelperTypeInfoStartup)

namespace
{
  /**
   * Drives this file's Lua binder registrations.
   *
   * In the shipped binary each `register_*_LuaFuncDef` thunk is a
   * compiler-generated dynamic initializer, so the CRT's static-init array
   * calls every one of them before `main`. Nothing in this tree reproduces
   * that array, so a recovered thunk that no source line names is simply
   * never run - the binder is never constructed, the form never joins its
   * init-form set, and the global it publishes is missing at runtime with no
   * diagnostic beyond FAF's own "access to nonexistent global variable".
   *
   * This object is that call, and it is also the source-level invocation
   * that keeps the thunks out of the linker's dead-strip.
   */
  struct EntityCategoryReflectionLuaBinderBootstrap
  {
    EntityCategoryReflectionLuaBinderBootstrap()
    {
      (void)::moho::register_EntityCategory();
      (void)::moho::register_EntityCategory__add_LuaFuncDef();
      (void)::moho::register_EntityCategory__sub_LuaFuncDef();
      (void)::moho::register_EntityCategory__mul_LuaFuncDef();
      (void)::moho::register_EntityCategoryEmpty_LuaFuncDef();
      (void)::moho::register_EntityCategoryGetUnitList_LuaFuncDef();
    }
  };

  const EntityCategoryReflectionLuaBinderBootstrap gEntityCategoryReflectionLuaBinderBootstrap{};
} // namespace
