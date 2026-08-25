#include "lua/LuaStateConstruct.h"

#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"

extern "C" lua_State* luaE_newthread(lua_State* state);
extern "C" LClosure* luaF_newLclosure(lua_State* state, int nelems, LuaPlus::TObject* environment);
extern "C" UpVal* luaF_newupval(lua_State* state);
extern "C" Proto* luaF_newproto(lua_State* state);
extern "C" TString* luaS_newlstr(lua_State* state, const char* str, std::size_t len);
extern "C" Table* luaH_new(lua_State* state, int narray, int lnhash);
extern "C" const LuaPlus::TObject* luaH_getstr(Table* t, TString* key);
extern "C" void luaC_link(lua_State* L, GCObject* object, int typeTag);
// Lua nil sentinel TObject (defined with C linkage in LuaObject.cpp). Declared
// extern "C" at global scope so unqualified use inside namespace LuaPlus binds
// to the same `_luaO_nilobject` symbol.
extern "C" const LuaPlus::TObject luaO_nilobject;

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
   * Address: 0x0091E3C0 (FUN_0091E3C0, TStringConstruct::Deconstruct)
   *
   * What it does:
   * Releases one constructed Lua string lane through global delete.
   */
  void TStringConstruct::Deconstruct(void* const objectPtr)
  {
    operator delete(objectPtr);
  }

  /**
   * Address: 0x00BEA230 (FUN_00BEA230, dynamic initializer for the global
   * `TStringConstruct` singleton)
   */
  TStringConstruct::TStringConstruct()
    : mConstruct(&TStringConstruct::Construct)
    , mDeconstruct(&TStringConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00C09A30 (FUN_00C09A30, TStringConstruct::~TStringConstruct)
   */
  TStringConstruct::~TStringConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00922190 (FUN_00922190, TableConstruct::Construct)
   *
   * What it does:
   * Reads one boolean ownership hint from the archive. When the bool is true,
   * the saved table was originally registered by name: reads the saved TString
   * key from the archive, looks it up in the owner Lua state's globals under
   * `"__serialize_object_for_name"`, fails with `SerializationError` if the
   * named entry is missing or is not a `Table`, and republishes the existing
   * `Table*` through the construct result as a shared/named ref (flags bit 0
   * set, clearing the owned-shared-flag byte). Otherwise reads `narray`
   * (int) + `lnhash` (ubyte) shape hints saved by
   * `SerializeTableSaveConstructPayload`, allocates a fresh empty Lua `Table`
   * in the owner state via `luaH_new`, and republishes it as a freshly-owned
   * ref (flags = 0).
   */
  void TableConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int,
    gpg::RRef* const ref,
    gpg::SerConstructResult* const result
  )
  {
    lua_State* const state = ref->TryUpcastLuaThreadState();

    bool isNamedReference = false;
    archive->ReadBool(&isNamedReference);

    if (isNamedReference) {
      TString* serializedName = nullptr;
      (void)archive->ReadPointer_TString(&serializedName, ref);

      TString* const serializeMapName = luaS_newlstr(state, "__serialize_object_for_name", 0x1Bu);
      const TObject* const serializeMapObject =
        luaH_getstr(static_cast<Table*>(state->_gt.value.p), serializeMapName);

      const TObject* const resolvedObject = (serializeMapObject->tt == LUA_TTABLE)
        ? luaH_getstr(static_cast<Table*>(serializeMapObject->value.p), serializedName)
        : &luaO_nilobject;

      const int resolvedType = resolvedObject->tt;
      if (resolvedType == LUA_TNIL) {
        throw gpg::SerializationError("Named script object not found");
      }
      if (resolvedType != LUA_TTABLE) {
        throw gpg::SerializationError("Named script object was a table on save but isn't on load.");
      }

      gpg::RRef sharedRef{};
      (void)gpg::RRef_Table(&sharedRef, static_cast<Table*>(resolvedObject->value.p));
      result->SetOwned(sharedRef, 1u);
      return;
    }

    int narray = 0;
    archive->ReadInt(&narray);
    unsigned __int8 lnhash = 0u;
    archive->ReadUByte(&lnhash);

    Table* const newTable = luaH_new(state, narray, static_cast<int>(lnhash));

    gpg::RRef ownedRef{};
    (void)gpg::RRef_Table(&ownedRef, newTable);
    result->SetOwned(ownedRef, 0u);
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
   * Address: 0x00BEA340 (FUN_00BEA340, dynamic initializer for the global
   * `TableConstruct` singleton)
   */
  TableConstruct::TableConstruct()
    : mConstruct(&TableConstruct::Construct)
    , mDeconstruct(&TableConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00C09AC0 (FUN_00C09AC0, TableConstruct::~TableConstruct)
   */
  TableConstruct::~TableConstruct()
  {
    ResetLinks();
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
   * Address: 0x00BEA450 (FUN_00BEA450, dynamic initializer for the global
   * `LClosureConstruct` singleton)
   */
  LClosureConstruct::LClosureConstruct()
    : mConstruct(&LClosureConstruct::Construct)
    , mDeconstruct(&LClosureConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00C09B50 (FUN_00C09B50, LClosureConstruct::~LClosureConstruct)
   */
  LClosureConstruct::~LClosureConstruct()
  {
    ResetLinks();
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
   * Address: 0x00BEA560 (FUN_00BEA560, dynamic initializer for the global
   * `UpValConstruct` singleton)
   */
  UpValConstruct::UpValConstruct()
    : mConstruct(&UpValConstruct::Construct)
    , mDeconstruct(&UpValConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00C09BE0 (FUN_00C09BE0, UpValConstruct::~UpValConstruct)
   */
  UpValConstruct::~UpValConstruct()
  {
    ResetLinks();
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
   * Address: 0x00BEA5A0 (FUN_00BEA5A0, dynamic initializer for the global
   * `UpValSerializer` singleton)
   */
  UpValSerializer::UpValSerializer()
    : mDeserialize(&UpValSerializer::Deserialize)
    , mSerialize(&UpValSerializer::Serialize)
  {}

  /**
   * Address: 0x00C09C10 (FUN_00C09C10, UpValSerializer::~UpValSerializer)
   */
  UpValSerializer::~UpValSerializer()
  {
    ResetLinks();
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
   * Address: 0x00BEA670 (FUN_00BEA670, dynamic initializer for the global
   * `ProtoConstruct` singleton)
   */
  ProtoConstruct::ProtoConstruct()
    : mConstruct(&ProtoConstruct::Construct)
    , mDeconstruct(&ProtoConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00C09C70 (FUN_00C09C70, ProtoConstruct::~ProtoConstruct)
   */
  ProtoConstruct::~ProtoConstruct()
  {
    ResetLinks();
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
   * Address: 0x00BE9FC0 (FUN_00BE9FC0, dynamic initializer for the global
   * `LuaStateConstruct` singleton)
   */
  LuaStateConstruct::LuaStateConstruct()
    : mConstruct(&LuaStateConstruct::Construct)
    , mDeconstruct(&LuaStateConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00C09850 (FUN_00C09850, LuaPlus::LuaStateConstruct::~LuaStateConstruct)
   */
  LuaStateConstruct::~LuaStateConstruct()
  {
    ResetLinks();
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
   * Address: 0x00BEA780 (FUN_00BEA780, dynamic initializer for the global
   * `lua_StateConstruct` singleton)
   */
  lua_StateConstruct::lua_StateConstruct()
    : mConstruct(&lua_StateConstruct::Construct)
    , mDeconstruct(&lua_StateConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00C09D00 (FUN_00C09D00, lua_StateConstruct::~lua_StateConstruct)
   */
  lua_StateConstruct::~lua_StateConstruct()
  {
    ResetLinks();
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
   * Address: 0x00BEA890 (FUN_00BEA890, dynamic initializer for the global
   * `UdataConstruct` singleton)
   */
  UdataConstruct::UdataConstruct()
    : mConstruct(&UdataConstruct::Construct)
    , mDeconstruct(&UdataConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00C09D90 (FUN_00C09D90, UdataConstruct::~UdataConstruct)
   */
  UdataConstruct::~UdataConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0090B670 (FUN_0090B670, LuaPlus::LuaStateConstruct::Init)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for
   * `LuaPlus::LuaState`.
   */
  void LuaStateConstruct::Init()
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
   * Address: 0x00920180 (FUN_00920180, lua_StateConstruct::Init)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `lua_State`.
   */
  void lua_StateConstruct::Init()
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
   * Address: 0x0091F9B0 (FUN_0091F9B0, TStringConstruct::Init)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `TString`.
   */
  void TStringConstruct::Init()
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
   * Address: 0x0091FB40 (FUN_0091FB40, TableConstruct::Init)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Table`.
   */
  void TableConstruct::Init()
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
   * Address: 0x0091FCD0 (FUN_0091FCD0, LClosureConstruct::Init)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `LClosure`.
   */
  void LClosureConstruct::Init()
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
   * Address: 0x0091FE60 (FUN_0091FE60, UpValConstruct::Init)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `UpVal`.
   */
  void UpValConstruct::Init()
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
   * Address: 0x0091FEE0 (FUN_0091FEE0, UpValSerializer::Init)
   *
   * What it does:
   * Binds load/save callbacks into reflected RTTI for `UpVal`.
   */
  void UpValSerializer::Init()
  {
    static gpg::RType* sUpValType = nullptr;
    if (sUpValType == nullptr) {
      sUpValType = gpg::LookupRType(typeid(UpVal));
    }

    GPG_ASSERT(sUpValType->serLoadFunc_ == nullptr);
    sUpValType->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(sUpValType->serSaveFunc_ == nullptr);
    sUpValType->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x0091FFF0 (FUN_0091FFF0, ProtoConstruct::Init)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Proto`.
   */
  void ProtoConstruct::Init()
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
   * Address: 0x00920310 (FUN_00920310, UdataConstruct::Init)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Udata`.
   */
  void UdataConstruct::Init()
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
  // Address: 0x00F8E5E4 -- process-global `LuaStateConstruct` singleton.
  LuaPlus::LuaStateConstruct gLuaStateConstruct;

  // Address: 0x00F8E754 -- process-global `lua_StateConstruct` singleton.
  LuaPlus::lua_StateConstruct gLuaThreadStateConstruct;

  // Address: 0x00F8E704 -- process-global `TStringConstruct` singleton.
  LuaPlus::TStringConstruct gTStringConstruct;

  // Address: 0x00F8E9AC -- process-global `TableConstruct` singleton.
  LuaPlus::TableConstruct gTableConstruct;

  // Address: 0x00F8EB24 -- process-global `LClosureConstruct` singleton.
  LuaPlus::LClosureConstruct gLClosureConstruct;

  // Address: 0x00F8E7F4 -- process-global `UpValConstruct` singleton.
  LuaPlus::UpValConstruct gUpValConstruct;

  // Address: 0x00F8EA34 -- process-global `UpValSerializer` singleton.
  LuaPlus::UpValSerializer gUpValSerializer;

  // Address: 0x00F8E740 -- process-global `ProtoConstruct` singleton.
  LuaPlus::ProtoConstruct gProtoConstruct;

  // Address: 0x00F8E718 -- process-global `UdataConstruct` singleton.
  LuaPlus::UdataConstruct gUdataConstruct;
} // namespace
