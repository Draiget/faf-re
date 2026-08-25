#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

struct LClosure;
struct UpVal;
struct Proto;
struct TString;
struct Table;
struct Udata;
struct lua_State;

namespace gpg
{
  class WriteArchive;
  class RRef;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace LuaPlus
{
  class LuaState;

  class LuaStateSaveConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, LuaState*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

    /**
     * Address: 0x00BE9F90 (FUN_00BE9F90, dynamic initializer for the global
     * `LuaStateSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct callback field.
     */
    LuaStateSaveConstruct();

    /**
     * Address: 0x00C09820 (FUN_00C09820, LuaPlus::LuaStateSaveConstruct::~LuaStateSaveConstruct)
     */
    ~LuaStateSaveConstruct();

    /**
     * Address: 0x0090BC50 (FUN_0090BC50, LuaPlus::LuaStateSaveConstruct::Construct)
     *
     * What it does:
     * Validates that the serialized LuaState is not the main-thread/root state
     * and marks save-construct ownership as unowned.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      LuaState* state,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x0090B5F0 (FUN_0090B5F0, LuaPlus::LuaStateSaveConstruct::Init)
     *
     * What it does:
     * Binds the save-construct-args callback into reflected RTTI for
     * `LuaPlus::LuaState`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct; // +0x0C
  };

  static_assert(offsetof(LuaStateSaveConstruct, mConstruct) == 0x0C, "LuaStateSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(LuaStateSaveConstruct) == 0x10, "LuaStateSaveConstruct size must be 0x10");

  class LClosureSaveConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, LClosure*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

    /**
     * Address: 0x00BEA420 (FUN_00BEA420, dynamic initializer for the global
     * `LClosureSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct callback field.
     */
    LClosureSaveConstruct();

    /**
     * Address: 0x00C09B20 (FUN_00C09B20, LClosureSaveConstruct::~LClosureSaveConstruct)
     */
    ~LClosureSaveConstruct();

    /**
     * Address: 0x0091F490 (FUN_0091F490, LClosureSaveConstruct::Construct)
     *
     * What it does:
     * Writes one closure upvalue-count lane to save-construct args and marks
     * the tracked-pointer ownership as owned.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      LClosure* closure,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x0091FC50 (FUN_0091FC50, LClosureSaveConstruct::Init)
     *
     * What it does:
     * Binds the save-construct-args callback into reflected RTTI for
     * `LClosure`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct; // +0x0C
  };

  static_assert(offsetof(LClosureSaveConstruct, mConstruct) == 0x0C, "LClosureSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(LClosureSaveConstruct) == 0x10, "LClosureSaveConstruct size must be 0x10");

  class UpValSaveConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, UpVal*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

    /**
     * Address: 0x00BEA530 (FUN_00BEA530, dynamic initializer for the global
     * `UpValSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct callback field.
     */
    UpValSaveConstruct();

    /**
     * Address: 0x00C09BB0 (FUN_00C09BB0, UpValSaveConstruct::~UpValSaveConstruct)
     */
    ~UpValSaveConstruct();

    /**
     * Address: 0x0091E510 (FUN_0091E510, UpValSaveConstruct::Construct)
     *
     * What it does:
     * Marks one upvalue save-construct lane as owned.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      UpVal* upvalue,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x0091FDE0 (FUN_0091FDE0, UpValSaveConstruct::Init)
     *
     * What it does:
     * Binds the save-construct-args callback into reflected RTTI for `UpVal`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct; // +0x0C
  };

  static_assert(offsetof(UpValSaveConstruct, mConstruct) == 0x0C, "UpValSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(UpValSaveConstruct) == 0x10, "UpValSaveConstruct size must be 0x10");

  class ProtoSaveConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, Proto*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

    /**
     * Address: 0x00BEA640 (FUN_00BEA640, dynamic initializer for the global
     * `ProtoSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct callback field.
     */
    ProtoSaveConstruct();

    /**
     * Address: 0x00C09C40 (FUN_00C09C40, ProtoSaveConstruct::~ProtoSaveConstruct)
     */
    ~ProtoSaveConstruct();

    /**
     * Address: 0x0091E520 (FUN_0091E520, ProtoSaveConstruct::Construct)
     *
     * What it does:
     * Marks one proto save-construct lane as owned.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      Proto* proto,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x0091FF70 (FUN_0091FF70, ProtoSaveConstruct::Init)
     *
     * What it does:
     * Binds the save-construct-args callback into reflected RTTI for `Proto`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct; // +0x0C
  };

  static_assert(offsetof(ProtoSaveConstruct, mConstruct) == 0x0C, "ProtoSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(ProtoSaveConstruct) == 0x10, "ProtoSaveConstruct size must be 0x10");

  class TStringSaveConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, TString*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

    /**
     * Address: 0x00BEA200 (FUN_00BEA200, dynamic initializer for the global
     * `TStringSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct callback field. A dead, zero-xref COMDAT duplicate of this
     * dynamic initializer sits at 0x009232E0 (not `__xc_a`-reachable); this
     * is the real one.
     */
    TStringSaveConstruct();

    /**
     * Address: 0x00C09A00 (FUN_00C09A00, TStringSaveConstruct::~TStringSaveConstruct)
     */
    ~TStringSaveConstruct();

    /**
     * Address: 0x009220A0 (FUN_009220A0, TStringSaveConstruct::Construct)
     *
     * What it does:
     * Forwards one TString save-construct lane into the string payload writer.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      TString* value,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x0091F930 (FUN_0091F930, TStringSaveConstruct::Init)
     *
     * What it does:
     * Binds the save-construct-args callback into reflected RTTI for
     * `TString`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct; // +0x0C
  };

  static_assert(offsetof(TStringSaveConstruct, mConstruct) == 0x0C, "TStringSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(TStringSaveConstruct) == 0x10, "TStringSaveConstruct size must be 0x10");

  class TableSaveConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, Table*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

    /**
     * Address: 0x00BEA310 (FUN_00BEA310, dynamic initializer for the global
     * `TableSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct callback field. A dead, zero-xref COMDAT duplicate of this
     * dynamic initializer sits at 0x00923360 (not `__xc_a`-reachable); this
     * is the real one.
     */
    TableSaveConstruct();

    /**
     * Address: 0x00C09A90 (FUN_00C09A90, TableSaveConstruct::~TableSaveConstruct)
     */
    ~TableSaveConstruct();

    /**
     * Address: 0x00922180 (FUN_00922180, TableSaveConstruct::Construct)
     *
     * What it does:
     * Forwards one table save-construct lane into table-header payload writer.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      Table* value,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x0091FAC0 (FUN_0091FAC0, TableSaveConstruct::Init)
     *
     * What it does:
     * Binds the save-construct-args callback into reflected RTTI for `Table`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct; // +0x0C
  };

  static_assert(offsetof(TableSaveConstruct, mConstruct) == 0x0C, "TableSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(TableSaveConstruct) == 0x10, "TableSaveConstruct size must be 0x10");

  class UdataSaveConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, Udata*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

    /**
     * Address: 0x00BEA860 (FUN_00BEA860, dynamic initializer for the global
     * `UdataSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct callback field.
     */
    UdataSaveConstruct();

    /**
     * Address: 0x00C09D60 (FUN_00C09D60, UdataSaveConstruct::~UdataSaveConstruct)
     */
    ~UdataSaveConstruct();

    /**
     * Address: 0x0091E530 (FUN_0091E530, UdataSaveConstruct::Construct)
     *
     * What it does:
     * Writes one userdata payload-type handle lane into archive type-refcounts
     * and marks save-construct ownership as owned.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      Udata* value,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x00920290 (FUN_00920290, UdataSaveConstruct::Init)
     *
     * What it does:
     * Binds the save-construct-args callback into reflected RTTI for
     * `Udata`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct; // +0x0C
  };

  static_assert(offsetof(UdataSaveConstruct, mConstruct) == 0x0C, "UdataSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(UdataSaveConstruct) == 0x10, "UdataSaveConstruct size must be 0x10");

  class lua_StateSaveConstruct : public gpg::SerHelperBase
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, lua_State*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

    /**
     * Address: 0x00BEA750 (FUN_00BEA750, dynamic initializer for the global
     * `lua_StateSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct callback field. A dead, zero-xref COMDAT duplicate of this
     * dynamic initializer sits at 0x009235B0 (not `__xc_a`-reachable); this
     * is the real one.
     */
    lua_StateSaveConstruct();

    /**
     * Address: 0x00C09CD0 (FUN_00C09CD0, lua_StateSaveConstruct::~lua_StateSaveConstruct)
     */
    ~lua_StateSaveConstruct();

    /**
     * Address: 0x00922610 (FUN_00922610, lua_StateSaveConstruct::Construct)
     *
     * What it does:
     * Forwards one lua_State save-construct lane into thread ownership writer.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      lua_State* value,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x00920100 (FUN_00920100, lua_StateSaveConstruct::Init)
     *
     * What it does:
     * Binds the save-construct-args callback into reflected RTTI for
     * `lua_State`.
     */
    void Init() override;

  public:
    construct_fn_t mConstruct; // +0x0C
  };

  static_assert(offsetof(lua_StateSaveConstruct, mConstruct) == 0x0C, "lua_StateSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(lua_StateSaveConstruct) == 0x10, "lua_StateSaveConstruct size must be 0x10");
} // namespace LuaPlus
