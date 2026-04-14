#include "lua/LuaStateConstruct.h"

#include <cstring>
#include <cstddef>
#include <cstdint>
#include <new>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "lua/LuaObject.h"

extern "C" lua_State* luaE_newthread(lua_State* state);
extern "C" LClosure* luaF_newLclosure(lua_State* state, int nelems, LuaPlus::TObject* environment);
extern "C" UpVal* luaF_newupval(lua_State* state);
extern "C" Proto* luaF_newproto(lua_State* state);

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

  void* luaM_realloc(lua_State* L, void* oldblock, lu_mem oldsize, lu_mem size);

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
   * Address: 0x00920C70 (FUN_00920C70, lua_StateConstruct::Construct)
   *
   * What it does:
   * Reads one ownership hint from archive slot 14 (`ReadBool`); when true it
   * returns the source state as unowned, otherwise creates a new Lua thread and
   * returns it as owned.
   */
  void LuaStateConstruct::Construct(
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
  void LuaStateConstruct::Deconstruct(void* const objectPtr)
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
} // namespace LuaPlus
