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
  class LuaStateConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00BE9FC0 (FUN_00BE9FC0, dynamic initializer for the global
     * `LuaStateConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    LuaStateConstruct();

    /**
     * Address: 0x00C09850 (FUN_00C09850, LuaPlus::LuaStateConstruct::~LuaStateConstruct)
     */
    ~LuaStateConstruct();

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
     * Address: 0x0090B670 (FUN_0090B670, LuaPlus::LuaStateConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for
     * `LuaPlus::LuaState`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct;              // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(LuaStateConstruct, mConstruct) == 0x0C, "LuaStateConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(LuaStateConstruct, mDeconstruct) == 0x10, "LuaStateConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(LuaStateConstruct) == 0x14, "LuaStateConstruct size must be 0x14");

  class lua_StateConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00BEA780 (FUN_00BEA780, dynamic initializer for the global
     * `lua_StateConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    lua_StateConstruct();

    /**
     * Address: 0x00C09D00 (FUN_00C09D00, lua_StateConstruct::~lua_StateConstruct)
     */
    ~lua_StateConstruct();

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
     * Address: 0x00920180 (FUN_00920180, lua_StateConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `lua_State`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct;              // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(lua_StateConstruct, mConstruct) == 0x0C, "lua_StateConstruct::mConstruct offset must be 0x0C");
  static_assert(
    offsetof(lua_StateConstruct, mDeconstruct) == 0x10,
    "lua_StateConstruct::mDeconstruct offset must be 0x10"
  );
  static_assert(sizeof(lua_StateConstruct) == 0x14, "lua_StateConstruct size must be 0x14");

  class TStringConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00BEA230 (FUN_00BEA230, dynamic initializer for the global
     * `TStringConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    TStringConstruct();

    /**
     * Address: 0x00C09A30 (FUN_00C09A30, TStringConstruct::~TStringConstruct)
     */
    ~TStringConstruct();

    /**
     * Address: 0x00921280 (FUN_00921280, TStringConstruct::Construct)
     *
     * What it does:
     * Reads one serialized string lane, interns it in the owner Lua state, and
     * returns the resulting `TString` as an owned construct ref.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0091E3C0 (FUN_0091E3C0, TStringConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed Lua string lane through global delete.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0091F9B0 (FUN_0091F9B0, TStringConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `TString`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct;              // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(TStringConstruct, mConstruct) == 0x0C, "TStringConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(TStringConstruct, mDeconstruct) == 0x10, "TStringConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(TStringConstruct) == 0x14, "TStringConstruct size must be 0x14");

  class TableConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00BEA340 (FUN_00BEA340, dynamic initializer for the global
     * `TableConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields. A dead, zero-xref COMDAT duplicate of
     * this dynamic initializer sits at 0x00923380 (not `__xc_a`-reachable);
     * this is the real one.
     */
    TableConstruct();

    /**
     * Address: 0x00C09AC0 (FUN_00C09AC0, TableConstruct::~TableConstruct)
     */
    ~TableConstruct();

    /**
     * Address: 0x00922190 (FUN_00922190, TableConstruct::Construct)
     *
     * What it does:
     * Reads one boolean ownership hint from the archive; when true it resolves a
     * named-script-object reference through the Lua global
     * `__serialize_object_for_name` registry and republishes the existing
     * `Table*` as a shared/named construct ref, otherwise it reads the saved
     * `narray`/`lnhash` shape and allocates a fresh empty Lua `Table` in the
     * owner state, returning it as an owned construct ref.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x0091E3F0 (FUN_0091E3F0, TableConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed Lua table lane through global delete.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0091FB40 (FUN_0091FB40, TableConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `Table`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct;              // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(TableConstruct, mConstruct) == 0x0C, "TableConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(TableConstruct, mDeconstruct) == 0x10, "TableConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(TableConstruct) == 0x14, "TableConstruct size must be 0x14");

  class LClosureConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00BEA450 (FUN_00BEA450, dynamic initializer for the global
     * `LClosureConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    LClosureConstruct();

    /**
     * Address: 0x00C09B50 (FUN_00C09B50, LClosureConstruct::~LClosureConstruct)
     */
    ~LClosureConstruct();

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
     * Address: 0x0091FCD0 (FUN_0091FCD0, LClosureConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `LClosure`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct;              // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(LClosureConstruct, mConstruct) == 0x0C, "LClosureConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(LClosureConstruct, mDeconstruct) == 0x10, "LClosureConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(LClosureConstruct) == 0x14, "LClosureConstruct size must be 0x14");

  class UpValConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00BEA560 (FUN_00BEA560, dynamic initializer for the global
     * `UpValConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    UpValConstruct();

    /**
     * Address: 0x00C09BE0 (FUN_00C09BE0, UpValConstruct::~UpValConstruct)
     */
    ~UpValConstruct();

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
     * Address: 0x0091FE60 (FUN_0091FE60, UpValConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `UpVal`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct;              // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(UpValConstruct, mConstruct) == 0x0C, "UpValConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(UpValConstruct, mDeconstruct) == 0x10, "UpValConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(UpValConstruct) == 0x14, "UpValConstruct size must be 0x14");

  class UpValSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BEA5A0 (FUN_00BEA5A0, dynamic initializer for the global
     * `UpValSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    UpValSerializer();

    /**
     * Address: 0x00C09C10 (FUN_00C09C10, UpValSerializer::~UpValSerializer)
     */
    ~UpValSerializer();

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

    /**
     * Address: 0x0091FEE0 (FUN_0091FEE0, UpValSerializer::Init)
     *
     * What it does:
     * Binds load/save callbacks into reflected RTTI for `UpVal`. ICF-folded
     * with the (unconstructed, dead) `gpg::SerSaveLoadHelper<UpVal>::Init`
     * COMDAT -- both compile to byte-identical code at this one address, but
     * only this class's global instance is ever actually constructed
     * (confirmed via `vtable_writers`: `UpValSerializer`'s ctor at 0x00BEA5A0
     * writes `??_7UpValSerializer@@6B@`; no ctor writes
     * `??_7?$SerSaveLoadHelper@UUpVal@@@gpg@@6B@` anywhere in the binary).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(UpValSerializer, mDeserialize) == 0x0C, "UpValSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(UpValSerializer, mSerialize) == 0x10, "UpValSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(UpValSerializer) == 0x14, "UpValSerializer size must be 0x14");

  class ProtoConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00BEA670 (FUN_00BEA670, dynamic initializer for the global
     * `ProtoConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    ProtoConstruct();

    /**
     * Address: 0x00C09C70 (FUN_00C09C70, ProtoConstruct::~ProtoConstruct)
     */
    ~ProtoConstruct();

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
     * Address: 0x0091FFF0 (FUN_0091FFF0, ProtoConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `Proto`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct;              // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(ProtoConstruct, mConstruct) == 0x0C, "ProtoConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(ProtoConstruct, mDeconstruct) == 0x10, "ProtoConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(ProtoConstruct) == 0x14, "ProtoConstruct size must be 0x14");

  class UdataConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00BEA890 (FUN_00BEA890, dynamic initializer for the global
     * `UdataConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    UdataConstruct();

    /**
     * Address: 0x00C09D90 (FUN_00C09D90, UdataConstruct::~UdataConstruct)
     */
    ~UdataConstruct();

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
     * Address: 0x00920310 (FUN_00920310, UdataConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `Udata`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct;              // +0x0C
    gpg::RType::delete_func_t mDeconstruct; // +0x10
  };

  static_assert(offsetof(UdataConstruct, mConstruct) == 0x0C, "UdataConstruct::mConstruct offset must be 0x0C");
  static_assert(offsetof(UdataConstruct, mDeconstruct) == 0x10, "UdataConstruct::mDeconstruct offset must be 0x10");
  static_assert(sizeof(UdataConstruct) == 0x14, "UdataConstruct size must be 0x14");
} // namespace LuaPlus
