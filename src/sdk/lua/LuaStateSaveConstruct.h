#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

struct LClosure;
struct UpVal;
struct Proto;
struct TString;
struct Table;
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

  /**
   * VFTABLE: 0x00D44F4C
   * COL: 0x00E5189C
   */
  class LuaStateSaveConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, LuaState*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

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

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(LuaStateSaveConstruct, vftable_) == 0x00, "LuaStateSaveConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(LuaStateSaveConstruct, mNext) == 0x04, "LuaStateSaveConstruct::mNext offset must be 0x04");
  static_assert(offsetof(LuaStateSaveConstruct, mPrev) == 0x08, "LuaStateSaveConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(LuaStateSaveConstruct, mConstruct) == 0x0C, "LuaStateSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(LuaStateSaveConstruct) == 0x10, "LuaStateSaveConstruct size must be 0x10");

  /**
   * VFTABLE: 0x00D46A68
   */
  class LClosureSaveConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, LClosure*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

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

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(LClosureSaveConstruct, vftable_) == 0x00, "LClosureSaveConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(LClosureSaveConstruct, mNext) == 0x04, "LClosureSaveConstruct::mNext offset must be 0x04");
  static_assert(offsetof(LClosureSaveConstruct, mPrev) == 0x08, "LClosureSaveConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(LClosureSaveConstruct, mConstruct) == 0x0C, "LClosureSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(LClosureSaveConstruct) == 0x10, "LClosureSaveConstruct size must be 0x10");

  /**
   * VFTABLE: 0x00D46A70
   */
  class UpValSaveConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, UpVal*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

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

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(UpValSaveConstruct, vftable_) == 0x00, "UpValSaveConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(UpValSaveConstruct, mNext) == 0x04, "UpValSaveConstruct::mNext offset must be 0x04");
  static_assert(offsetof(UpValSaveConstruct, mPrev) == 0x08, "UpValSaveConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(UpValSaveConstruct, mConstruct) == 0x0C, "UpValSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(UpValSaveConstruct) == 0x10, "UpValSaveConstruct size must be 0x10");

  /**
   * VFTABLE: 0x00D46A80
   */
  class ProtoSaveConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, Proto*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

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

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(ProtoSaveConstruct, vftable_) == 0x00, "ProtoSaveConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(ProtoSaveConstruct, mNext) == 0x04, "ProtoSaveConstruct::mNext offset must be 0x04");
  static_assert(offsetof(ProtoSaveConstruct, mPrev) == 0x08, "ProtoSaveConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(ProtoSaveConstruct, mConstruct) == 0x0C, "ProtoSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(ProtoSaveConstruct) == 0x10, "ProtoSaveConstruct size must be 0x10");

  class TStringSaveConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, TString*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

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

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(TStringSaveConstruct, vftable_) == 0x00, "TStringSaveConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(TStringSaveConstruct, mNext) == 0x04, "TStringSaveConstruct::mNext offset must be 0x04");
  static_assert(offsetof(TStringSaveConstruct, mPrev) == 0x08, "TStringSaveConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(TStringSaveConstruct, mConstruct) == 0x0C, "TStringSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(TStringSaveConstruct) == 0x10, "TStringSaveConstruct size must be 0x10");

  class TableSaveConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, Table*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

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

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(TableSaveConstruct, vftable_) == 0x00, "TableSaveConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(TableSaveConstruct, mNext) == 0x04, "TableSaveConstruct::mNext offset must be 0x04");
  static_assert(offsetof(TableSaveConstruct, mPrev) == 0x08, "TableSaveConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(TableSaveConstruct, mConstruct) == 0x0C, "TableSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(TableSaveConstruct) == 0x10, "TableSaveConstruct size must be 0x10");

  class lua_StateSaveConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, lua_State*, int version, gpg::RRef* ownerRef, gpg::SerSaveConstructArgsResult*);

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

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(lua_StateSaveConstruct, vftable_) == 0x00, "lua_StateSaveConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(lua_StateSaveConstruct, mNext) == 0x04, "lua_StateSaveConstruct::mNext offset must be 0x04");
  static_assert(offsetof(lua_StateSaveConstruct, mPrev) == 0x08, "lua_StateSaveConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(lua_StateSaveConstruct, mConstruct) == 0x0C, "lua_StateSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(lua_StateSaveConstruct) == 0x10, "lua_StateSaveConstruct size must be 0x10");
} // namespace LuaPlus
