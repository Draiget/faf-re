#include "moho/serialization/CPrefetchSet.h"

#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/utils/Global.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "lua/LuaTableIterator.h"

namespace
{
  constexpr const char* kCreatePrefetchSetHelpText = "create an empty prefetch set";
  constexpr const char* kPrefetchSetUpdateHelpText =
    "CPrefetchSet:Update({d3d_textures=..., batch_textures=..., models=..., anims=...})";
  constexpr const char* kPrefetchSetResetHelpText = "CPrefetchSet:Reset()";
  moho::CScrLuaInitForm* gRecoveredCoreLuaInitFormPrev_CPrefetchSetStartup = nullptr;
  moho::CScrLuaInitForm* gRecoveredCoreLuaInitFormAnchor_CPrefetchSetStartup = nullptr;

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet* FindLuaInitFormSetByName(const char* const setName) noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, setName) == 0) {
        return set;
      }
    }

    return nullptr;
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardPrefetchSetLuaRegistrationThunk() noexcept
  {
    return Target();
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const raw = lua_touserdata(lstate, -1);
    if (raw) {
      out = *static_cast<gpg::RRef*>(raw);
    }
    lua_settop(lstate, top);
    return out;
  }

  /**
   * Address: 0x004A8660 (FUN_004A8660, gpg::RRef::TryUpcast_CPrefetchSet)
   *
   * What it does:
   * Upcasts one reflected reference to `CPrefetchSet*` and throws
   * `BadRefCast` on mismatch.
   */
  [[nodiscard]] moho::CPrefetchSet* TryUpcastCPrefetchSetOrThrow(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, moho::CPrefetchSet::StaticGetClass());
    auto* const prefetchSet = static_cast<moho::CPrefetchSet*>(upcast.mObj);
    if (!prefetchSet) {
      throw gpg::BadRefCast("type error");
    }
    return prefetchSet;
  }

  void ValidateArgCount(LuaPlus::LuaState* const state, const char* const helpText, const int expected)
  {
    const int actual = lua_gettop(state->m_state);
    if (actual != expected) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        helpText ? helpText : "",
        expected,
        actual
      );
    }
  }
} // namespace

namespace moho
{
  gpg::RType* CPrefetchSet::sType = nullptr;
  CScrLuaMetatableFactory<CPrefetchSet> CScrLuaMetatableFactory<CPrefetchSet>::sInstance{};

  gpg::RType* CPrefetchSet::StaticGetClass()
  {
    EnsurePrefetchSetTypeRegistration();
    if (!sType) {
      sType = gpg::LookupRType(typeid(CPrefetchSet));
    }
    return sType;
  }

  /**
   * Address: 0x004A5290 (FUN_004A5290, Moho::CPrefetchset::Update)
   */
  void CPrefetchSet::Update(LuaPlus::LuaObject prefetchTable, LuaPlus::LuaState* const state)
  {
    msvc8::vector<PrefetchHandleBase> nextHandles{};

    LuaPlus::LuaTableIterator kindIterator(&prefetchTable, 1);
    while (!kindIterator.m_isDone) {
      LuaPlus::LuaObject& kindKeyObject = kindIterator.GetKey();
      const char* const prefetchKind = kindKeyObject.GetString();

      gpg::RType* const prefetchType = RES_FindPrefetchType(prefetchKind);
      if (!prefetchType) {
        if (state) {
          LuaPlus::LuaState::Error(
            state,
            "Unknown kind of resource in prefetch set: %s",
            prefetchKind ? prefetchKind : "<null>"
          );
        }
        kindIterator.Next();
        continue;
      }

      LuaPlus::LuaObject& valuesTable = kindIterator.GetValue();
      LuaPlus::LuaTableIterator valuesIterator(&valuesTable, 1);
      while (!valuesIterator.m_isDone) {
        LuaPlus::LuaObject& valueObject = valuesIterator.GetValue();
        const char* const resourcePath = valueObject.GetString();

        PrefetchHandleBase handle{};
        RES_PrefetchResource(&handle.mPtr, resourcePath, prefetchType);
        nextHandles.push_back(handle);

        valuesIterator.Next();
      }

      kindIterator.Next();
    }

    mHandles = nextHandles;
  }

  void CPrefetchSet::Reset()
  {
    mHandles.clear();
  }

  CScrLuaMetatableFactory<CPrefetchSet>& CScrLuaMetatableFactory<CPrefetchSet>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x004A5FC0 (FUN_004A5FC0, Moho::CScrLuaMetatableFactory<Moho::CPrefetchSet>::Create)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<CPrefetchSet>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x004A7D20 (FUN_004A7D20, func_CreatePrefetchSet)
   */
  LuaPlus::LuaObject func_CreatePrefetchSet(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject out;
    if (!state) {
      return out;
    }

    LuaPlus::LuaObject metatable = CScrLuaMetatableFactory<CPrefetchSet>::Instance().Get(state);

    gpg::RType* const type = CPrefetchSet::StaticGetClass();
    if (!type) {
      return out;
    }

    gpg::RRef objectRef{};
    if (type->newRefFunc_) {
      objectRef = type->newRefFunc_();
    } else {
      objectRef = gpg::RRef{new (std::nothrow) CPrefetchSet(), type};
    }

    out.AssignNewUserData(state, objectRef);
    out.SetMetaTable(metatable);
    return out;
  }

  /**
   * Address: 0x004A7DD0 (FUN_004A7DD0, func_GetCObj_CPrefetchSet)
    * Alias of FUN_004A8660 (non-canonical helper lane).
   */
  CPrefetchSet* func_GetCObj_CPrefetchSet(LuaPlus::LuaObject object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    return TryUpcastCPrefetchSetOrThrow(userDataRef);
  }

  /**
   * Address: 0x004A5700 (FUN_004A5700, cfunc_CreatePrefetchSet)
   */
  int cfunc_CreatePrefetchSet(lua_State* const luaContext)
  {
    return cfunc_CreatePrefetchSetL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x004A5780 (FUN_004A5780, cfunc_CreatePrefetchSetL)
   */
  int cfunc_CreatePrefetchSetL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    ValidateArgCount(state, kCreatePrefetchSetHelpText, 0);

    LuaPlus::LuaObject created = func_CreatePrefetchSet(state);
    created.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x004A5720 (FUN_004A5720, func_CreatePrefetchSet_LuaFuncDef)
   */
  CScrLuaInitForm* func_CreatePrefetchSet_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "CreatePrefetchSet",
      &cfunc_CreatePrefetchSet,
      nullptr,
      "<global>",
      kCreatePrefetchSetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BC59D0 (FUN_00BC59D0, register_CreatePrefetchSet_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CreatePrefetchSet_LuaFuncDef` to
   * `func_CreatePrefetchSet_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreatePrefetchSet_LuaFuncDef()
  {
    return ForwardPrefetchSetLuaRegistrationThunk<&func_CreatePrefetchSet_LuaFuncDef>();
  }

  /**
   * Address: 0x004A5810 (FUN_004A5810, cfunc_CPrefetchSetUpdate)
   */
  int cfunc_CPrefetchSetUpdate(lua_State* const luaContext)
  {
    return cfunc_CPrefetchSetUpdateL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x004A5890 (FUN_004A5890, cfunc_CPrefetchSetUpdateL)
   */
  int cfunc_CPrefetchSetUpdateL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    ValidateArgCount(state, kPrefetchSetUpdateHelpText, 2);

    LuaPlus::LuaObject tableArg(LuaPlus::LuaStackObject(state, 2));
    LuaPlus::LuaObject selfArg(LuaPlus::LuaStackObject(state, 1));
    CPrefetchSet* const prefetchSet = func_GetCObj_CPrefetchSet(selfArg);
    GPG_ASSERT(prefetchSet != nullptr);
    if (!prefetchSet) {
      return 0;
    }

    prefetchSet->Update(tableArg, state);
    return 0;
  }

  /**
   * Address: 0x004A5830 (FUN_004A5830, func_CPrefetchSetUpdate_LuaFuncDef)
   */
  CScrLuaInitForm* func_CPrefetchSetUpdate_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "Update",
      &cfunc_CPrefetchSetUpdate,
      &CScrLuaMetatableFactory<CPrefetchSet>::Instance(),
      "CPrefetchSet",
      kPrefetchSetUpdateHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BC5A00 (FUN_00BC5A00, register_CPrefetchSetUpdate_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CPrefetchSetUpdate_LuaFuncDef` to
   * `func_CPrefetchSetUpdate_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CPrefetchSetUpdate_LuaFuncDef()
  {
    return ForwardPrefetchSetLuaRegistrationThunk<&func_CPrefetchSetUpdate_LuaFuncDef>();
  }

  /**
   * Address: 0x004A5950 (FUN_004A5950, cfunc_CPrefetchSetReset)
   */
  int cfunc_CPrefetchSetReset(lua_State* const luaContext)
  {
    return cfunc_CPrefetchSetResetL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x004A59D0 (FUN_004A59D0, cfunc_CPrefetchSetResetL)
   */
  int cfunc_CPrefetchSetResetL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    ValidateArgCount(state, kPrefetchSetResetHelpText, 1);

    LuaPlus::LuaObject selfArg(LuaPlus::LuaStackObject(state, 1));
    CPrefetchSet* const prefetchSet = func_GetCObj_CPrefetchSet(selfArg);
    GPG_ASSERT(prefetchSet != nullptr);
    if (!prefetchSet) {
      return 0;
    }

    prefetchSet->Reset();
    return 0;
  }

  /**
   * Address: 0x004A5970 (FUN_004A5970, func_CPrefetchSetReset_LuaFuncDef)
   */
  CScrLuaInitForm* func_CPrefetchSetReset_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "Reset",
      &cfunc_CPrefetchSetReset,
      &CScrLuaMetatableFactory<CPrefetchSet>::Instance(),
      "CPrefetchSet",
      kPrefetchSetResetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BC5A10 (FUN_00BC5A10, register_CPrefetchSetReset_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CPrefetchSetReset_LuaFuncDef` to
   * `func_CPrefetchSetReset_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CPrefetchSetReset_LuaFuncDef()
  {
    return ForwardPrefetchSetLuaRegistrationThunk<&func_CPrefetchSetReset_LuaFuncDef>();
  }

  /**
   * Address: 0x00BC5A40 (FUN_00BC5A40, sub_BC5A40)
   *
   * What it does:
   * Allocates one Lua metatable-factory index and stores it in
   * `CScrLuaMetatableFactory<CPrefetchSet>::sInstance`.
   */
  int register_CScrLuaMetatableFactory_CPrefetchSet_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<CPrefetchSet>::Instance().SetFactoryObjectIndexForRecovery(index);
    return index;
  }

  /**
   * Address: 0x00BC59E0 (FUN_00BC59E0, sub_BC59E0)
   *
   * What it does:
   * Saves current `core` Lua-init form chain head and relinks it to the
   * recovered CPrefetchSet startup anchor lane.
   */
  CScrLuaInitForm* register_core_CoreInits_mForms_CPrefetchSetAnchor()
  {
    CScrLuaInitFormSet* coreSet = FindLuaInitFormSetByName("core");
    if (coreSet == nullptr) {
      coreSet = &CoreLuaInitSet();
    }

    CScrLuaInitForm* const result = coreSet->mForms;
    gRecoveredCoreLuaInitFormPrev_CPrefetchSetStartup = result;
    coreSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gRecoveredCoreLuaInitFormAnchor_CPrefetchSetStartup);
    return result;
  }
} // namespace moho

namespace
{
  struct CPrefetchSetLuaStartupBootstrap
  {
    CPrefetchSetLuaStartupBootstrap()
    {
      (void)moho::register_core_CoreInits_mForms_CPrefetchSetAnchor();
      (void)moho::register_CScrLuaMetatableFactory_CPrefetchSet_Index();
      (void)moho::register_CreatePrefetchSet_LuaFuncDef();
      (void)moho::register_CPrefetchSetUpdate_LuaFuncDef();
      (void)moho::register_CPrefetchSetReset_LuaFuncDef();
    }
  };

  [[maybe_unused]] CPrefetchSetLuaStartupBootstrap gCPrefetchSetLuaStartupBootstrap;
} // namespace
