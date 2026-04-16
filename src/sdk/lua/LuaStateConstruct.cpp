#include "lua/LuaStateConstruct.h"

#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"

extern "C" lua_State* luaE_newthread(lua_State* state);
extern "C" LClosure* luaF_newLclosure(lua_State* state, int nelems, LuaPlus::TObject* environment);
extern "C" UpVal* luaF_newupval(lua_State* state);
extern "C" Proto* luaF_newproto(lua_State* state);
extern "C" TString* luaS_newlstr(lua_State* state, const char* str, std::size_t len);
extern "C" void luaC_link(lua_State* L, GCObject* object, int typeTag);

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetOwned(const RRef& ref, unsigned int flags);
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace LuaPlus
{
  namespace
  {
    struct UpValSerializerRuntimeObject
    {
      std::uint32_t reserved00;
      std::uint32_t reserved04;
      TObject serializedValue;
    };

    static_assert(
      offsetof(UpValSerializerRuntimeObject, serializedValue) == 0x08,
      "UpValSerializerRuntimeObject::serializedValue offset must be 0x08"
    );
    static_assert(sizeof(UpValSerializerRuntimeObject) == 0x10, "UpValSerializerRuntimeObject size must be 0x10");

    [[nodiscard]] gpg::RType* CachedLuaTObjectType() noexcept
    {
      static gpg::RType* cached = nullptr;
      if (!cached) {
        cached = gpg::LookupRType(typeid(TObject));
      }
      return cached;
    }
  } // namespace

  extern "C" void* luaM_realloc(lua_State* L, void* oldblock, lu_mem oldsize, lu_mem size);

  [[nodiscard]] Udata* AllocateTypedUserdata(lua_State* const state, gpg::RType* const type)
  {
    const std::size_t userdataSize = sizeof(Udata) + static_cast<std::size_t>(type->size_);
    Udata* const userdata = static_cast<Udata*>(luaM_realloc(state, nullptr, 0u, userdataSize));

    void* const payload = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
    std::memset(payload, 0, static_cast<std::size_t>(type->size_));

    userdata->len = reinterpret_cast<std::size_t>(type);
    userdata->tt = LUA_TUSERDATA;
    userdata->marked = (type->dtrFunc_ != nullptr) ? 2u : 0u;
    userdata->metatable = static_cast<Table*>(state->l_G->_defaultmeta.value.p);
    userdata->next = state->l_G->rootudata;
    state->l_G->rootudata = reinterpret_cast<GCObject*>(userdata);
    return userdata;
  }

  /**
   * Address: 0x00921280 (FUN_00921280, TStringConstruct::Construct)
   *
   * What it does:
   * Reads one serialized string lane from archive, interns it in the owner Lua
   * state, and returns it as an owned construct ref.
   */
  void TStringConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int,
    gpg::RRef* const ref,
    gpg::SerConstructResult* const result
  )
  {
    lua_State* const state = ref->TryUpcastLuaThreadState();

    msvc8::string serializedValue{};
    archive->ReadString(&serializedValue);

    TString* const stringObject = luaS_newlstr(
      state,
      serializedValue.raw_data_unsafe(),
      serializedValue.size()
    );

    gpg::RRef ownedRef{};
    (void)gpg::RRef_TString(&ownedRef, stringObject);
    result->SetOwned(ownedRef, 0u);
  }

  /**
   * Address: 0x0091E3C0 (FUN_0091E3C0, TStringConstruct::Deserialize)
   *
   * What it does:
   * Releases one constructed Lua string lane through global delete.
   */
  void TStringConstruct::Deconstruct(void* const objectPtr)
  {
    operator delete(objectPtr);
  }

  /**
   * Address: 0x0091E3F0 (FUN_0091E3F0, TableConstruct::Deconstruct)
   *
   * What it does:
   * Releases one constructed Lua table lane through global delete.
   */
  void TableConstruct::Deconstruct(void* const objectPtr)
  {
    operator delete(objectPtr);
  }

  /**
   * Address: 0x00920A80 (FUN_00920A80, LClosureConstruct::Construct)
   *
   * What it does:
   * Reads one upvalue-count lane from the archive, allocates one new Lua
   * closure bound to the owner thread globals table, and returns it owned.
   */
  void LClosureConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int,
    gpg::RRef* const ref,
    gpg::SerConstructResult* const result
  )
  {
    lua_State* const state = ref->TryUpcastLuaThreadState();

    unsigned __int8 upvalueCount = 0u;
    archive->ReadUByte(&upvalueCount);

    LClosure* const closure = luaF_newLclosure(state, static_cast<int>(upvalueCount), &state->_gt);

    gpg::RRef ownedRef{};
    (void)gpg::RRef_LClosure(&ownedRef, closure);
    result->SetOwned(ownedRef, 0u);
  }

  /**
   * Address: 0x0091E400 (FUN_0091E400, LClosureConstruct::Deconstruct)
   *
   * What it does:
   * Releases one constructed Lua closure lane through global delete.
   */
  void LClosureConstruct::Deconstruct(void* const objectPtr)
  {
    operator delete(objectPtr);
  }

  /**
   * Address: 0x00920B10 (FUN_00920B10, UpValConstruct::Construct)
   *
   * What it does:
   * Allocates one open upvalue lane in the owner Lua state and returns it as
   * an owned construct ref.
   */
  void UpValConstruct::Construct(
    gpg::ReadArchive* const,
    const int,
    gpg::RRef* const ref,
    gpg::SerConstructResult* const result
  )
  {
    lua_State* const state = ref->TryUpcastLuaThreadState();
    UpVal* const upvalue = luaF_newupval(state);

    gpg::RRef ownedRef{};
    (void)gpg::RRef_UpVal(&ownedRef, upvalue);
    result->SetOwned(ownedRef, 0u);
  }

  /**
   * Address: 0x0091E410 (FUN_0091E410, UpValConstruct::Deconstruct)
   *
   * What it does:
   * Releases one constructed Lua upvalue lane through global delete.
   */
  void UpValConstruct::Deconstruct(void* const objectPtr)
  {
    operator delete(objectPtr);
  }

  /**
   * Address: 0x0091F050 (recovered, mirrors lfunc.c::luaF_newupval pattern)
   *
   * What it does:
   * Allocates one fresh UpVal node through the Lua allocator, marks it as
   * `LUA_TUPVALUE` (closed) with `value` initialized to nil and `v` pointing
   * to its own internal `value` slot, and links it into the GC root list.
   * Used by `UpValConstruct::Construct` during deserialization.
   */
  extern "C" UpVal* luaF_newupval(lua_State* const state)
  {
    auto* const upvalue = static_cast<UpVal*>(
      luaM_realloc(state, nullptr, 0u, static_cast<lu_mem>(sizeof(UpVal)))
    );
    upvalue->tt = static_cast<lu_byte>(LUA_TUPVALUE);
    upvalue->marked = 1u;
    upvalue->v = &upvalue->value;
    upvalue->value.tt = LUA_TNIL;
    luaC_link(state, reinterpret_cast<GCObject*>(upvalue), LUA_TUPVALUE);
    return upvalue;
  }

  /**
   * Address: 0x00920B60 (FUN_00920B60, UpValSerializer::Deserialize)
   *
   * What it does:
   * Deserializes one `TObject` payload lane for an UpVal serializer runtime
   * record.
   */
  void UpValSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const runtimeObject =
      reinterpret_cast<UpValSerializerRuntimeObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
    if (!archive || !runtimeObject) {
      return;
    }

    gpg::RType* const tObjectType = CachedLuaTObjectType();
    if (!tObjectType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Read(tObjectType, &runtimeObject->serializedValue, owner);
  }

  /**
   * Address: 0x00920BA0 (FUN_00920BA0, UpValSerializer::Serialize)
   *
   * What it does:
   * Serializes one `TObject` payload lane from an UpVal serializer runtime
   * record.
   */
  void UpValSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const runtimeObject =
      reinterpret_cast<UpValSerializerRuntimeObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
    if (!archive || !runtimeObject) {
      return;
    }

    gpg::RType* const tObjectType = CachedLuaTObjectType();
    if (!tObjectType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Write(tObjectType, &runtimeObject->serializedValue, owner);
  }

  /**
   * Address: 0x00920C20 (FUN_00920C20, ProtoConstruct::Construct)
   *
   * What it does:
   * Allocates one empty Lua function prototype in the owner Lua state and
   * returns it as an owned construct ref.
   */
  void ProtoConstruct::Construct(
    gpg::ReadArchive* const,
    const int,
    gpg::RRef* const ref,
    gpg::SerConstructResult* const result
  )
  {
    lua_State* const state = ref->TryUpcastLuaThreadState();
    Proto* const proto = luaF_newproto(state);

    gpg::RRef ownedRef{};
    (void)gpg::RRef_Proto(&ownedRef, proto);
    result->SetOwned(ownedRef, 0u);
  }

  /**
   * Address: 0x0091E420 (FUN_0091E420, ProtoConstruct::Deconstruct)
   *
   * What it does:
   * Releases one constructed Lua proto lane through global delete.
   */
  void ProtoConstruct::Deconstruct(void* const objectPtr)
  {
    operator delete(objectPtr);
  }

  /**
   * Address: 0x0090B860 (FUN_0090B860, LuaPlus::LuaStateConstruct::Construct)
   *
   * What it does:
   * Allocates one `LuaPlus::LuaState` wrapper lane and publishes it as an
   * unowned construct result.
   */
  void LuaStateConstruct::Construct(
    gpg::ReadArchive* const,
    const int,
    gpg::RRef* const,
    gpg::SerConstructResult* const result
  )
  {
    LuaState* const state = new LuaState(static_cast<LuaState*>(nullptr));
    gpg::RRef stateRef{};
    (void)gpg::RRef_LuaState(&stateRef, state);
    result->SetUnowned(stateRef, 0u);
  }

  /**
   * Address: 0x0090B1C0 (FUN_0090B1C0, LuaPlus::LuaStateConstruct::Deconstruct)
   *
   * What it does:
   * Destroys one `LuaPlus::LuaState` wrapper lane and releases its storage.
   */
  void LuaStateConstruct::Deconstruct(void* const objectPtr)
  {
    if (objectPtr == nullptr) {
      return;
    }

    auto* const state = static_cast<LuaState*>(objectPtr);
    state->~LuaState();
    ::operator delete(state);
  }

  /**
   * Address: 0x00920C70 (FUN_00920C70, lua_StateConstruct::Construct)
   *
   * What it does:
   * Reads one ownership hint from archive slot 14 (`ReadBool`); when true it
   * returns the source state as unowned, otherwise creates a new Lua thread and
   * returns it as owned.
   */
  void lua_StateConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int,
    gpg::RRef* const ref,
    gpg::SerConstructResult* const result
  )
  {
    lua_State* const state = ref->TryUpcastLuaThreadState();

    bool isUnowned = false;
    archive->ReadBool(&isUnowned);

    if (isUnowned) {
      gpg::RRef stateRef{};
      (void)gpg::RRef_lua_State(&stateRef, state);
      result->SetUnowned(stateRef, 1u);
      return;
    }

    lua_State* const newThread = luaE_newthread(state);
    gpg::RRef ownedRef{};
    (void)gpg::RRef_lua_State(&ownedRef, newThread);
    result->SetOwned(ownedRef, 0u);
  }

  /**
   * Address: 0x0091E430 (FUN_0091E430, lua_StateConstruct::Deconstruct)
   *
   * What it does:
   * Releases one constructed Lua thread-state lane through global delete.
   */
  void lua_StateConstruct::Deconstruct(void* const objectPtr)
  {
    operator delete(objectPtr);
  }

  /**
   * Address: 0x00920D30 (FUN_00920D30, UdataConstruct::Construct)
   *
   * What it does:
   * Reads one userdata payload type-handle from archive, allocates one typed
   * Lua userdata object in the owner Lua state, and returns it as owned.
   */
  void UdataConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int,
    gpg::RRef* const ref,
    gpg::SerConstructResult* const result
  )
  {
    lua_State* const state = ref->TryUpcastLuaThreadState();
    const gpg::TypeHandle typeHandle = archive->ReadTypeHandle();

    Udata* const userdata = AllocateTypedUserdata(state, typeHandle.type);
    gpg::RRef ownedRef{};
    (void)gpg::RRef_Udata(&ownedRef, userdata);
    result->SetOwned(ownedRef, 0u);
  }

  /**
   * Address: 0x0091E440 (FUN_0091E440, UdataConstruct::Deconstruct)
   *
   * What it does:
   * Releases one constructed Lua userdata lane through global delete.
   */
  void UdataConstruct::Deconstruct(void* const objectPtr)
  {
    operator delete(objectPtr);
  }

  /**
   * Address: 0x0090B670 (FUN_0090B670, LuaPlus::LuaStateConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for
   * `LuaPlus::LuaState`.
   */
  void LuaStateConstruct::RegisterConstructFunction()
  {
    static gpg::RType* sLuaStateType = nullptr;
    if (sLuaStateType == nullptr) {
      sLuaStateType = gpg::LookupRType(typeid(LuaState));
    }

    GPG_ASSERT(sLuaStateType->serConstructFunc_ == nullptr);
    sLuaStateType->serConstructFunc_ = reinterpret_cast<gpg::RType::construct_func_t>(mConstruct);
    sLuaStateType->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(mDeconstruct);
  }

  /**
   * Address: 0x00920180 (FUN_00920180, lua_StateConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `lua_State`.
   */
  void lua_StateConstruct::RegisterConstructFunction()
  {
    static gpg::RType* sLuaThreadType = nullptr;
    if (sLuaThreadType == nullptr) {
      sLuaThreadType = gpg::LookupRType(typeid(lua_State));
    }

    GPG_ASSERT(sLuaThreadType->serConstructFunc_ == nullptr);
    sLuaThreadType->serConstructFunc_ = reinterpret_cast<gpg::RType::construct_func_t>(mConstruct);
    sLuaThreadType->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(mDeconstruct);
  }

  /**
   * Address: 0x0091F9B0 (FUN_0091F9B0, TStringConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `TString`.
   */
  void TStringConstruct::RegisterConstructFunction()
  {
    static gpg::RType* sTStringType = nullptr;
    if (sTStringType == nullptr) {
      sTStringType = gpg::LookupRType(typeid(TString));
    }

    GPG_ASSERT(sTStringType->serConstructFunc_ == nullptr);
    sTStringType->serConstructFunc_ = reinterpret_cast<gpg::RType::construct_func_t>(mConstruct);
    sTStringType->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(mDeconstruct);
  }

  /**
   * Address: 0x0091FB40 (FUN_0091FB40, TableConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Table`.
   */
  void TableConstruct::RegisterConstructFunction()
  {
    static gpg::RType* sTableType = nullptr;
    if (sTableType == nullptr) {
      sTableType = gpg::LookupRType(typeid(Table));
    }

    GPG_ASSERT(sTableType->serConstructFunc_ == nullptr);
    sTableType->serConstructFunc_ = reinterpret_cast<gpg::RType::construct_func_t>(mConstruct);
    sTableType->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(mDeconstruct);
  }

  /**
   * Address: 0x0091FCD0 (FUN_0091FCD0, LClosureConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `LClosure`.
   */
  void LClosureConstruct::RegisterConstructFunction()
  {
    static gpg::RType* sLClosureType = nullptr;
    if (sLClosureType == nullptr) {
      sLClosureType = gpg::LookupRType(typeid(LClosure));
    }

    GPG_ASSERT(sLClosureType->serConstructFunc_ == nullptr);
    sLClosureType->serConstructFunc_ = reinterpret_cast<gpg::RType::construct_func_t>(mConstruct);
    sLClosureType->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(mDeconstruct);
  }

  /**
   * Address: 0x0091FE60 (FUN_0091FE60, UpValConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `UpVal`.
   */
  void UpValConstruct::RegisterConstructFunction()
  {
    static gpg::RType* sUpValType = nullptr;
    if (sUpValType == nullptr) {
      sUpValType = gpg::LookupRType(typeid(UpVal));
    }

    GPG_ASSERT(sUpValType->serConstructFunc_ == nullptr);
    sUpValType->serConstructFunc_ = reinterpret_cast<gpg::RType::construct_func_t>(mConstruct);
    sUpValType->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(mDeconstruct);
  }

  /**
   * Address: 0x0091FFF0 (FUN_0091FFF0, ProtoConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Proto`.
   */
  void ProtoConstruct::RegisterConstructFunction()
  {
    static gpg::RType* sProtoType = nullptr;
    if (sProtoType == nullptr) {
      sProtoType = gpg::LookupRType(typeid(Proto));
    }

    GPG_ASSERT(sProtoType->serConstructFunc_ == nullptr);
    sProtoType->serConstructFunc_ = reinterpret_cast<gpg::RType::construct_func_t>(mConstruct);
    sProtoType->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(mDeconstruct);
  }

  /**
   * Address: 0x00920310 (FUN_00920310, UdataConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Udata`.
   */
  void UdataConstruct::RegisterConstructFunction()
  {
    static gpg::RType* sUdataType = nullptr;
    if (sUdataType == nullptr) {
      sUdataType = gpg::LookupRType(typeid(Udata));
    }

    GPG_ASSERT(sUdataType->serConstructFunc_ == nullptr);
    sUdataType->serConstructFunc_ = reinterpret_cast<gpg::RType::construct_func_t>(mConstruct);
    sUdataType->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(mDeconstruct);
  }
} // namespace LuaPlus

namespace
{
  LuaPlus::LuaStateConstruct gLuaStateConstructHelper{};

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
  void UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mNext != nullptr && helper.mPrev != nullptr) {
      helper.mNext->mPrev = helper.mPrev;
      helper.mPrev->mNext = helper.mNext;
    }

    InitializeHelperNode(helper);
  }

  /**
   * Address: 0x00C09850 (FUN_00C09850, LuaPlus::LuaStateConstruct::~LuaStateConstruct)
   *
   * What it does:
   * Unlinks the global LuaState construct helper from intrusive helper links.
   */
  void cleanup_LuaStateConstruct()
  {
    UnlinkHelperNode(gLuaStateConstructHelper);
  }

  /**
   * Address: 0x00BE9FC0 (FUN_00BE9FC0, register_LuaStateConstruct)
   *
   * What it does:
   * Initializes LuaState construct helper callbacks and schedules teardown.
   */
  void register_LuaStateConstruct()
  {
    InitializeHelperNode(gLuaStateConstructHelper);
    gLuaStateConstructHelper.mConstruct = &LuaPlus::LuaStateConstruct::Construct;
    gLuaStateConstructHelper.mDeconstruct = &LuaPlus::LuaStateConstruct::Deconstruct;
    gLuaStateConstructHelper.RegisterConstructFunction();
    (void)std::atexit(&cleanup_LuaStateConstruct);
  }

  struct LuaStateConstructBootstrap
  {
    LuaStateConstructBootstrap()
    {
      register_LuaStateConstruct();
    }
  };

  [[maybe_unused]] LuaStateConstructBootstrap gLuaStateConstructBootstrap{};
} // namespace
