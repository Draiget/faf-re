#include "lua/LuaStateSaveConstruct.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetOwned(unsigned int flags);
    void SetUnowned(unsigned int flags);
  };
} // namespace gpg

namespace LuaPlus
{
  extern "C"
  {
    TString* luaS_newlstr(lua_State* L, const char* str, size_t len);
    const TObject* luaH_get(Table* t, const TObject* key);
    const TObject* luaH_getstr(Table* t, TString* key);
  }

  namespace
  {
    struct LClosureSaveConstructRuntimeView
    {
      std::uint8_t reserved00[0x08];
      std::uint8_t upvalueCount;
    };

    static_assert(
      offsetof(LClosureSaveConstructRuntimeView, upvalueCount) == 0x08,
      "LClosureSaveConstructRuntimeView::upvalueCount offset must be 0x08"
    );

    /**
     * Address: 0x00921500 (FUN_00921500, sub_921500)
     *
     * What it does:
     * Serializes one TString payload into archive string lane and marks
     * save-construct ownership as owned.
     */
    void SerializeTStringSaveConstructPayload(
      gpg::WriteArchive* const archive,
      TString* const value,
      gpg::SerSaveConstructArgsResult* const result
    )
    {
      msvc8::string serializedValue(value->str, value->len);
      archive->WriteString(&serializedValue);
      result->SetOwned(0u);
    }

    /**
     * Address: 0x00921590 (FUN_00921590, sub_921590)
     *
     * What it does:
     * Serializes one table save-construct descriptor either as named reference
     * or as raw table shape metadata (array size + hash log2 size).
     */
    void SerializeTableSaveConstructPayload(
      gpg::WriteArchive* const archive,
      Table* const value,
      gpg::RRef* const ownerRef,
      gpg::SerSaveConstructArgsResult* const result
    )
    {
      lua_State* const ownerState = ownerRef->TryUpcastLuaThreadState();
      TObject key{};
      key.tt = value->tt;
      key.value.p = value;

      TString* const serializeMapName = luaS_newlstr(ownerState, "__serialize_name_for_object", 0x1Bu);
      const TObject* const serializeMapObject = luaH_getstr(static_cast<Table*>(ownerState->_gt.value.p), serializeMapName);
      if (serializeMapObject->tt == LUA_TTABLE) {
        const TObject* const resolvedName = luaH_get(static_cast<Table*>(serializeMapObject->value.p), &key);
        if (resolvedName->tt == LUA_TSTRING) {
          archive->WriteBool(true);

          gpg::RRef nameRef{};
          (void)gpg::RRef_TString(&nameRef, static_cast<TString*>(resolvedName->value.p));
          gpg::WriteRawPointer(archive, nameRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
          result->SetOwned(1u);
          return;
        }

        if (resolvedName->tt != LUA_TNIL) {
          throw gpg::SerializationError("__serialize_name_for_object table must contain only string values");
        }
      }

      archive->WriteBool(false);
      archive->WriteInt(value->sizearray);
      archive->WriteUByte(value->lsizenode);
      result->SetOwned(0u);
    }

    /**
     * Address: 0x00921630 (FUN_00921630, sub_921630)
     *
     * What it does:
     * Serializes one lua_State save-construct ownership lane and enforces
     * thread consistency checks for main-thread and active C-call cases.
     */
    void SerializeLuaThreadSaveConstructPayload(
      gpg::WriteArchive* const archive,
      lua_State* const value,
      gpg::RRef* const ownerRef,
      gpg::SerSaveConstructArgsResult* const result
    )
    {
      lua_State* const ownerState = ownerRef->TryUpcastLuaThreadState();
      if (value->l_G->mainthread != ownerState) {
        throw gpg::SerializationError("Consistency check failed: value.l_G->mainthread == &state");
      }

      const bool isMainThread = (value == ownerState);
      archive->WriteBool(isMainThread);
      if (isMainThread) {
        result->SetUnowned(1u);
        return;
      }

      if (value->nCcalls != 0u) {
        throw gpg::SerializationError("cannot save a Lua thread with active C calls");
      }

      result->SetOwned(0u);
    }

    /**
     * Address: 0x0090BA20 (FUN_0090BA20)
     *
     * What it does:
     * Validates that a save-construct `LuaState` lane is not the root/main
     * thread and marks the construct result as unowned.
     */
    void ApplyLuaStateSaveConstructCompatibilityLane(
      LuaState* const state,
      gpg::SerSaveConstructArgsResult* const result
    )
    {
      if (state->m_rootState == state) {
        throw gpg::SerializationError("Consistency check failed: !isMainThread");
      }

      result->SetUnowned(0u);
    }
  } // namespace

  /**
   * Address: 0x0090BC50 (FUN_0090BC50, LuaPlus::LuaStateSaveConstruct::Construct)
   *
   * What it does:
   * Validates that the serialized LuaState is not the main-thread/root state
   * and marks save-construct ownership as unowned.
   */
  void LuaStateSaveConstruct::Construct(
    gpg::WriteArchive* const,
    LuaState* const state,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    ApplyLuaStateSaveConstructCompatibilityLane(state, result);
  }

  /**
   * Address: 0x00BE9F90 (FUN_00BE9F90, dynamic initializer for the global
   * `LuaStateSaveConstruct` singleton)
   */
  LuaStateSaveConstruct::LuaStateSaveConstruct()
    : mConstruct(&LuaStateSaveConstruct::Construct)
  {}

  /**
   * Address: 0x00C09820 (FUN_00C09820, LuaPlus::LuaStateSaveConstruct::~LuaStateSaveConstruct)
   */
  LuaStateSaveConstruct::~LuaStateSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0091E510 (FUN_0091E510, UpValSaveConstruct::Construct)
   *
   * What it does:
   * Marks one upvalue save-construct lane as owned.
   */
  void UpValSaveConstruct::Construct(
    gpg::WriteArchive* const,
    UpVal* const,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    result->SetOwned(0u);
  }

  /**
   * Address: 0x00BEA530 (FUN_00BEA530, dynamic initializer for the global
   * `UpValSaveConstruct` singleton)
   */
  UpValSaveConstruct::UpValSaveConstruct()
    : mConstruct(&UpValSaveConstruct::Construct)
  {}

  /**
   * Address: 0x00C09BB0 (FUN_00C09BB0, UpValSaveConstruct::~UpValSaveConstruct)
   */
  UpValSaveConstruct::~UpValSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0091E520 (FUN_0091E520, ProtoSaveConstruct::Construct)
   *
   * What it does:
   * Marks one proto save-construct lane as owned.
   */
  void ProtoSaveConstruct::Construct(
    gpg::WriteArchive* const,
    Proto* const,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    result->SetOwned(0u);
  }

  /**
   * Address: 0x00BEA640 (FUN_00BEA640, dynamic initializer for the global
   * `ProtoSaveConstruct` singleton)
   */
  ProtoSaveConstruct::ProtoSaveConstruct()
    : mConstruct(&ProtoSaveConstruct::Construct)
  {}

  /**
   * Address: 0x00C09C40 (FUN_00C09C40, ProtoSaveConstruct::~ProtoSaveConstruct)
   */
  ProtoSaveConstruct::~ProtoSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0091E530 (FUN_0091E530, UdataSaveConstruct::Construct)
   *
   * What it does:
   * Writes one userdata payload-type handle lane into archive type-refcounts
   * and marks save-construct ownership as owned.
   */
  void UdataSaveConstruct::Construct(
    gpg::WriteArchive* const archive,
    Udata* const value,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    const auto* const payloadType = reinterpret_cast<const gpg::RType*>(value->len);
    archive->WriteRefCounts(payloadType);
    result->SetOwned(0u);
  }

  /**
   * Address: 0x00BEA860 (FUN_00BEA860, dynamic initializer for the global
   * `UdataSaveConstruct` singleton)
   */
  UdataSaveConstruct::UdataSaveConstruct()
    : mConstruct(&UdataSaveConstruct::Construct)
  {}

  /**
   * Address: 0x00C09D60 (FUN_00C09D60, UdataSaveConstruct::~UdataSaveConstruct)
   */
  UdataSaveConstruct::~UdataSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0091F490 (FUN_0091F490, LClosureSaveConstruct::Construct)
   *
   * What it does:
   * Writes one closure upvalue-count lane to save-construct args and marks
   * the tracked-pointer ownership as owned.
   */
  void LClosureSaveConstruct::Construct(
    gpg::WriteArchive* const archive,
    LClosure* const closure,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    const auto* const closureView = reinterpret_cast<const LClosureSaveConstructRuntimeView*>(closure);
    archive->WriteUByte(closureView->upvalueCount);
    result->SetOwned(0u);
  }

  /**
   * Address: 0x00BEA420 (FUN_00BEA420, dynamic initializer for the global
   * `LClosureSaveConstruct` singleton)
   */
  LClosureSaveConstruct::LClosureSaveConstruct()
    : mConstruct(&LClosureSaveConstruct::Construct)
  {}

  /**
   * Address: 0x00C09B20 (FUN_00C09B20, LClosureSaveConstruct::~LClosureSaveConstruct)
   */
  LClosureSaveConstruct::~LClosureSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x009220A0 (FUN_009220A0, TStringSaveConstruct::Construct)
   *
   * What it does:
   * Forwards one TString save-construct lane into serialized-string payload.
   */
  void TStringSaveConstruct::Construct(
    gpg::WriteArchive* const archive,
    TString* const value,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SerializeTStringSaveConstructPayload(archive, value, result);
  }

  /**
   * Address: 0x00BEA200 (FUN_00BEA200, dynamic initializer for the global
   * `TStringSaveConstruct` singleton)
   */
  TStringSaveConstruct::TStringSaveConstruct()
    : mConstruct(&TStringSaveConstruct::Construct)
  {}

  /**
   * Address: 0x00C09A00 (FUN_00C09A00, TStringSaveConstruct::~TStringSaveConstruct)
   */
  TStringSaveConstruct::~TStringSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00922180 (FUN_00922180, TableSaveConstruct::Construct)
   *
   * What it does:
   * Forwards one table save-construct lane into table payload serializer.
   */
  void TableSaveConstruct::Construct(
    gpg::WriteArchive* const archive,
    Table* const value,
    const int,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SerializeTableSaveConstructPayload(archive, value, ownerRef, result);
  }

  /**
   * Address: 0x00BEA310 (FUN_00BEA310, dynamic initializer for the global
   * `TableSaveConstruct` singleton)
   */
  TableSaveConstruct::TableSaveConstruct()
    : mConstruct(&TableSaveConstruct::Construct)
  {}

  /**
   * Address: 0x00C09A90 (FUN_00C09A90, TableSaveConstruct::~TableSaveConstruct)
   */
  TableSaveConstruct::~TableSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00922610 (FUN_00922610, lua_StateSaveConstruct::Construct)
   *
   * What it does:
   * Forwards one lua_State save-construct lane into thread ownership serializer.
   */
  void lua_StateSaveConstruct::Construct(
    gpg::WriteArchive* const archive,
    lua_State* const value,
    const int,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SerializeLuaThreadSaveConstructPayload(archive, value, ownerRef, result);
  }

  /**
   * Address: 0x00BEA750 (FUN_00BEA750, dynamic initializer for the global
   * `lua_StateSaveConstruct` singleton)
   */
  lua_StateSaveConstruct::lua_StateSaveConstruct()
    : mConstruct(&lua_StateSaveConstruct::Construct)
  {}

  /**
   * Address: 0x00C09CD0 (FUN_00C09CD0, lua_StateSaveConstruct::~lua_StateSaveConstruct)
   */
  lua_StateSaveConstruct::~lua_StateSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0090B5F0 (FUN_0090B5F0, LuaPlus::LuaStateSaveConstruct::Init)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for
   * `LuaPlus::LuaState`.
   */
  void LuaStateSaveConstruct::Init()
  {
    static gpg::RType* sLuaStateType = nullptr;
    if (sLuaStateType == nullptr) {
      sLuaStateType = gpg::LookupRType(typeid(LuaState));
    }

    GPG_ASSERT(sLuaStateType->serSaveConstructArgsFunc_ == nullptr);
    sLuaStateType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091F930 (FUN_0091F930, TStringSaveConstruct::Init)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `TString`.
   */
  void TStringSaveConstruct::Init()
  {
    static gpg::RType* sTStringType = nullptr;
    if (sTStringType == nullptr) {
      sTStringType = gpg::LookupRType(typeid(TString));
    }

    GPG_ASSERT(sTStringType->serSaveConstructArgsFunc_ == nullptr);
    sTStringType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091FAC0 (FUN_0091FAC0, TableSaveConstruct::Init)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `Table`.
   */
  void TableSaveConstruct::Init()
  {
    static gpg::RType* sTableType = nullptr;
    if (sTableType == nullptr) {
      sTableType = gpg::LookupRType(typeid(Table));
    }

    GPG_ASSERT(sTableType->serSaveConstructArgsFunc_ == nullptr);
    sTableType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091FC50 (FUN_0091FC50, LClosureSaveConstruct::Init)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `LClosure`.
   */
  void LClosureSaveConstruct::Init()
  {
    static gpg::RType* sLClosureType = nullptr;
    if (sLClosureType == nullptr) {
      sLClosureType = gpg::LookupRType(typeid(LClosure));
    }

    GPG_ASSERT(sLClosureType->serSaveConstructArgsFunc_ == nullptr);
    sLClosureType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091FDE0 (FUN_0091FDE0, UpValSaveConstruct::Init)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `UpVal`.
   */
  void UpValSaveConstruct::Init()
  {
    static gpg::RType* sUpValType = nullptr;
    if (sUpValType == nullptr) {
      sUpValType = gpg::LookupRType(typeid(UpVal));
    }

    GPG_ASSERT(sUpValType->serSaveConstructArgsFunc_ == nullptr);
    sUpValType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091FF70 (FUN_0091FF70, ProtoSaveConstruct::Init)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `Proto`.
   */
  void ProtoSaveConstruct::Init()
  {
    static gpg::RType* sProtoType = nullptr;
    if (sProtoType == nullptr) {
      sProtoType = gpg::LookupRType(typeid(Proto));
    }

    GPG_ASSERT(sProtoType->serSaveConstructArgsFunc_ == nullptr);
    sProtoType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x00920100 (FUN_00920100, lua_StateSaveConstruct::Init)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for
   * `lua_State`.
   */
  void lua_StateSaveConstruct::Init()
  {
    static gpg::RType* sLuaThreadType = nullptr;
    if (sLuaThreadType == nullptr) {
      sLuaThreadType = gpg::LookupRType(typeid(lua_State));
    }

    GPG_ASSERT(sLuaThreadType->serSaveConstructArgsFunc_ == nullptr);
    sLuaThreadType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x00920290 (FUN_00920290, UdataSaveConstruct::Init)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `Udata`.
   */
  void UdataSaveConstruct::Init()
  {
    static gpg::RType* sUdataType = nullptr;
    if (sUdataType == nullptr) {
      sUdataType = gpg::LookupRType(typeid(Udata));
    }

    GPG_ASSERT(sUdataType->serSaveConstructArgsFunc_ == nullptr);
    sUdataType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }
} // namespace LuaPlus

namespace
{
  // Address: 0x00F8E5C0 -- process-global `LuaStateSaveConstruct` singleton.
  LuaPlus::LuaStateSaveConstruct gLuaStateSaveConstruct;

  // Address: 0x00F8E6E0 -- process-global `lua_StateSaveConstruct` singleton.
  LuaPlus::lua_StateSaveConstruct gLuaThreadStateSaveConstruct;

  // Address: 0x00F8E89C -- process-global `TStringSaveConstruct` singleton.
  LuaPlus::TStringSaveConstruct gTStringSaveConstruct;

  // Address: 0x00F8E87C -- process-global `TableSaveConstruct` singleton.
  LuaPlus::TableSaveConstruct gTableSaveConstruct;

  // Address: 0x00F8E88C -- process-global `LClosureSaveConstruct` singleton.
  LuaPlus::LClosureSaveConstruct gLClosureSaveConstruct;

  // Address: 0x00F8E924 -- process-global `UpValSaveConstruct` singleton.
  LuaPlus::UpValSaveConstruct gUpValSaveConstruct;

  // Address: 0x00F8EA24 -- process-global `ProtoSaveConstruct` singleton.
  LuaPlus::ProtoSaveConstruct gProtoSaveConstruct;

  // Address: 0x00F8E86C -- process-global `UdataSaveConstruct` singleton.
  LuaPlus::UdataSaveConstruct gUdataSaveConstruct;
} // namespace
