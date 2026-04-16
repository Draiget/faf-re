#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class SerConstructResult;
  class WriteArchive;
} // namespace gpg

namespace LuaPlus
{
  /**
   * VFTABLE: 0x00D44EE0
   */
  class LuaStateConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0090B860 (FUN_0090B860, LuaPlus::LuaStateConstruct::Construct)
     *
     * What it does:
     * Allocates one `LuaPlus::LuaState` wrapper lane and publishes it as an
     * unowned construct result.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0090B1C0 (FUN_0090B1C0, LuaPlus::LuaStateConstruct::Deconstruct)
     *
     * What it does:
     * Destroys one `LuaPlus::LuaState` wrapper lane and releases its storage.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0090B670 (FUN_0090B670, LuaPlus::LuaStateConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for
     * `LuaPlus::LuaState`.
     */
    void RegisterConstructFunction();

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(LuaStateConstruct, vftable_) == 0x00, "LuaStateConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(LuaStateConstruct, mNext) == 0x04, "LuaStateConstruct::mNext offset must be 0x04");
  static_assert(offsetof(LuaStateConstruct, mPrev) == 0x08, "LuaStateConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(LuaStateConstruct, mConstruct) == 0x0C, "LuaStateConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(LuaStateConstruct, mDeconstruct) == 0x10, "LuaStateConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(LuaStateConstruct) == 0x14, "LuaStateConstruct size must be 0x14");

  /**
   * VFTABLE: 0x00D46AA8
   */
  class lua_StateConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920C70 (FUN_00920C70, lua_StateConstruct::Construct)
     *
     * What it does:
     * Reads one ownership flag from the archive and either aliases the owner
     * lua state as unowned or allocates one child thread and returns it owned.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0091E430 (FUN_0091E430, lua_StateConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed Lua thread-state lane through global delete.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x00920180 (FUN_00920180, lua_StateConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `lua_State`.
     */
    void RegisterConstructFunction();

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(lua_StateConstruct, vftable_) == 0x00, "lua_StateConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(lua_StateConstruct, mNext) == 0x04, "lua_StateConstruct::mNext offset must be 0x04");
  static_assert(offsetof(lua_StateConstruct, mPrev) == 0x08, "lua_StateConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(lua_StateConstruct, mConstruct) == 0x0C, "lua_StateConstruct::mConstruct offset must be 0x0C");
  static_assert(
    offsetof(lua_StateConstruct, mDeconstruct) == 0x10,
    "lua_StateConstruct::mDeconstruct offset must be 0x10"
  );
  static_assert(sizeof(lua_StateConstruct) == 0x14, "lua_StateConstruct size must be 0x14");

  /**
   * VFTABLE: 0x00D46AB8
   */
  class TStringConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00921280 (FUN_00921280, TStringConstruct::Construct)
     *
     * What it does:
     * Reads one serialized string lane, interns it in the owner Lua state, and
     * returns the resulting `TString` as an owned construct ref.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0091E3C0 (FUN_0091E3C0, TStringConstruct::Deserialize)
     *
     * What it does:
     * Releases one constructed Lua string lane through global delete.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0091F9B0 (FUN_0091F9B0, TStringConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `TString`.
     */
    void RegisterConstructFunction();

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(TStringConstruct, vftable_) == 0x00, "TStringConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(TStringConstruct, mNext) == 0x04, "TStringConstruct::mNext offset must be 0x04");
  static_assert(offsetof(TStringConstruct, mPrev) == 0x08, "TStringConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(TStringConstruct, mConstruct) == 0x0C, "TStringConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(TStringConstruct, mDeconstruct) == 0x10, "TStringConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(TStringConstruct) == 0x14, "TStringConstruct size must be 0x14");

  /**
   * VFTABLE: 0x00D47028
   */
  class TableConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0091E3F0 (FUN_0091E3F0, TableConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed Lua table lane through global delete.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0091FB40 (FUN_0091FB40, TableConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `Table`.
     */
    void RegisterConstructFunction();

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(TableConstruct, vftable_) == 0x00, "TableConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(TableConstruct, mNext) == 0x04, "TableConstruct::mNext offset must be 0x04");
  static_assert(offsetof(TableConstruct, mPrev) == 0x08, "TableConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(TableConstruct, mConstruct) == 0x0C, "TableConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(TableConstruct, mDeconstruct) == 0x10, "TableConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(TableConstruct) == 0x14, "TableConstruct size must be 0x14");

  /**
   * VFTABLE: 0x00D44F90
   * COL: 0x00E518E0
   */
  class LClosureConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920A80 (FUN_00920A80, LClosureConstruct::Construct)
     *
     * What it does:
     * Reads one upvalue-count lane from the archive, allocates one new Lua
     * closure bound to the owner thread globals table, and returns it owned.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0091E400 (FUN_0091E400, LClosureConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed Lua closure lane through global delete.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0091FCD0 (FUN_0091FCD0, LClosureConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `LClosure`.
     */
    void RegisterConstructFunction();

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(LClosureConstruct, vftable_) == 0x00, "LClosureConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(LClosureConstruct, mNext) == 0x04, "LClosureConstruct::mNext offset must be 0x04");
  static_assert(offsetof(LClosureConstruct, mPrev) == 0x08, "LClosureConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(LClosureConstruct, mConstruct) == 0x0C, "LClosureConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(LClosureConstruct, mDeconstruct) == 0x10, "LClosureConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(LClosureConstruct) == 0x14, "LClosureConstruct size must be 0x14");

  class UpValConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920B10 (FUN_00920B10, UpValConstruct::Construct)
     *
     * What it does:
     * Allocates one open upvalue lane in the owner Lua state and returns it as
     * an owned construct ref.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0091E410 (FUN_0091E410, UpValConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed Lua upvalue lane through global delete.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0091FE60 (FUN_0091FE60, UpValConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `UpVal`.
     */
    void RegisterConstructFunction();

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(UpValConstruct, vftable_) == 0x00, "UpValConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(UpValConstruct, mNext) == 0x04, "UpValConstruct::mNext offset must be 0x04");
  static_assert(offsetof(UpValConstruct, mPrev) == 0x08, "UpValConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(UpValConstruct, mConstruct) == 0x0C, "UpValConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(UpValConstruct, mDeconstruct) == 0x10, "UpValConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(UpValConstruct) == 0x14, "UpValConstruct size must be 0x14");

  /**
   * VFTABLE: 0x00D46A78
   */
  class UpValSerializer
  {
  public:
    /**
     * Address: 0x00920B60 (FUN_00920B60, UpValSerializer::Deserialize)
     *
     * What it does:
     * Deserializes one `TObject` payload lane for an UpVal serializer runtime
     * record.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00920BA0 (FUN_00920BA0, UpValSerializer::Serialize)
     *
     * What it does:
     * Serializes one `TObject` payload lane from an UpVal serializer runtime
     * record.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  class ProtoConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920C20 (FUN_00920C20, ProtoConstruct::Construct)
     *
     * What it does:
     * Allocates one empty Lua function prototype in the owner Lua state and
     * returns it as an owned construct ref.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0091E420 (FUN_0091E420, ProtoConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed Lua proto lane through global delete.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0091FFF0 (FUN_0091FFF0, ProtoConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `Proto`.
     */
    void RegisterConstructFunction();

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(ProtoConstruct, vftable_) == 0x00, "ProtoConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(ProtoConstruct, mNext) == 0x04, "ProtoConstruct::mNext offset must be 0x04");
  static_assert(offsetof(ProtoConstruct, mPrev) == 0x08, "ProtoConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(ProtoConstruct, mConstruct) == 0x0C, "ProtoConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(ProtoConstruct, mDeconstruct) == 0x10, "ProtoConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(ProtoConstruct) == 0x14, "ProtoConstruct size must be 0x14");

  /**
   * VFTABLE: 0x00D44F80
   * COL: 0x00E518D0
   */
  class UdataConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920D30 (FUN_00920D30, UdataConstruct::Construct)
     *
     * What it does:
     * Reads one userdata payload type-handle, allocates one typed Lua userdata
     * object in the owner Lua state, and returns it as an owned construct ref.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0091E440 (FUN_0091E440, UdataConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed Lua userdata lane through global delete.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x00920310 (FUN_00920310, UdataConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `Udata`.
     */
    void RegisterConstructFunction();

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(UdataConstruct, vftable_) == 0x00, "UdataConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(UdataConstruct, mNext) == 0x04, "UdataConstruct::mNext offset must be 0x04");
  static_assert(offsetof(UdataConstruct, mPrev) == 0x08, "UdataConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(UdataConstruct, mConstruct) == 0x0C, "UdataConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(UdataConstruct, mDeconstruct) == 0x10, "UdataConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(UdataConstruct) == 0x14, "UdataConstruct size must be 0x14");
} // namespace LuaPlus
