#include "moho/entity/EntityCategoryReflection.h"

#include <cstdlib>
#include <cstring>
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

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kEntityCategoryLuaClassName = "EntityCategory";
  constexpr const char* kEntityCategoryAddHelpText = "Generate a category list that is the sum of both categories";
  constexpr const char* kEntityCategorySubHelpText = "Generate a category list of units that is of cat1 but not of cat2";
  constexpr const char* kEntityCategoryMulHelpText = "Generate a category list that is an intersection of cat1 and cat2";
  constexpr const char* kEntityCategoryEmptyHelpText = "Test for an empty category";
  constexpr const char* kSecondsPerTickHelpText = "SecondsPerTick() - Return how many seconds in a tick";

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
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("core"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("core");
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

  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (lstate == nullptr) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData != nullptr) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, top);
    return out;
  }

  [[nodiscard]] gpg::RType* CachedEntityCategorySetType()
  {
    if (!moho::EntityCategorySet::sType) {
      moho::EntityCategorySet::sType = gpg::LookupRType(typeid(moho::EntityCategorySet));
    }
    return moho::EntityCategorySet::sType;
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

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mNext = self;
    helper.mPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    auto* const next = helper.mNext;
    auto* const prev = helper.mPrev;
    if (next != nullptr && prev != nullptr) {
      next->mPrev = prev;
      prev->mNext = next;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  void cleanup_EntityCategoryHelperSerializerAtexit()
  {
    gEntityCategoryHelperSerializer.~EntityCategoryHelperSerializer();
  }

  struct EntityCategoryHelperRegistration
  {
    EntityCategoryHelperRegistration()
    {
      (void)moho::register_EntityCategoryHelperTypeInfoStartup();
      moho::register_EntityCategoryHelperSerializer();
    }
  };

  EntityCategoryHelperRegistration gEntityCategoryHelperRegistration;
} // namespace

namespace moho
{
  gpg::RType* EntityCategoryHelper::sType = nullptr;

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
   * Address: 0x00BF3AD0 (FUN_00BF3AD0, Moho::EntityCategoryHelperSerializer::dtr)
   */
  EntityCategoryHelperSerializer::~EntityCategoryHelperSerializer()
  {
    (void)UnlinkHelperNode(gEntityCategoryHelperSerializer);
  }

  /**
   * Address: 0x0052C8E0 (FUN_0052C8E0, gpg::SerSaveLoadHelper_EntityCategoryHelper::Init)
   */
  void EntityCategoryHelperSerializer::RegisterSerializeFunctions()
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
   * Address: 0x00BC8F30 (FUN_00BC8F30, register_EntityCategoryHelperSerializer)
   */
  void register_EntityCategoryHelperSerializer()
  {
    InitializeHelperNode(gEntityCategoryHelperSerializer);
    gEntityCategoryHelperSerializer.mSerLoadFunc = &EntityCategory::SerLoad;
    gEntityCategoryHelperSerializer.mSerSaveFunc = &EntityCategory::SerSave;
    gEntityCategoryHelperSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_EntityCategoryHelperSerializerAtexit);
  }
} // namespace moho
