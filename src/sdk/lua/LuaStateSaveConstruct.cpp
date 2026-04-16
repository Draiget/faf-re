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
   * Address: 0x009232E0 (FUN_009232E0)
   *
   * What it does:
   * Initializes TString save-construct helper links and binds the construct
   * callback lane.
   */
  TStringSaveConstruct::TStringSaveConstruct()
    : vftable_(nullptr),
      mNext(nullptr),
      mPrev(nullptr),
      mConstruct(&TStringSaveConstruct::Construct)
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&mNext);
    mNext = self;
    mPrev = self;
  }

  /**
   * Address: 0x00923360 (FUN_00923360)
   *
   * What it does:
   * Initializes table save-construct helper links and binds the construct
   * callback lane.
   */
  TableSaveConstruct::TableSaveConstruct()
    : vftable_(nullptr),
      mNext(nullptr),
      mPrev(nullptr),
      mConstruct(&TableSaveConstruct::Construct)
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&mNext);
    mNext = self;
    mPrev = self;
  }

  /**
   * Address: 0x009235B0 (FUN_009235B0)
   *
   * What it does:
   * Initializes lua-thread save-construct helper links and binds the
   * construct callback lane.
   */
  lua_StateSaveConstruct::lua_StateSaveConstruct()
    : vftable_(nullptr),
      mNext(nullptr),
      mPrev(nullptr),
      mConstruct(&lua_StateSaveConstruct::Construct)
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&mNext);
    mNext = self;
    mPrev = self;
  }

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
   * Address: 0x0090B5F0 (FUN_0090B5F0, LuaPlus::LuaStateSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for
   * `LuaPlus::LuaState`.
   */
  void LuaStateSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    static gpg::RType* sLuaStateType = nullptr;
    if (sLuaStateType == nullptr) {
      sLuaStateType = gpg::LookupRType(typeid(LuaState));
    }

    GPG_ASSERT(sLuaStateType->serSaveConstructArgsFunc_ == nullptr);
    sLuaStateType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091F930 (FUN_0091F930, TStringSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `TString`.
   */
  void TStringSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    static gpg::RType* sTStringType = nullptr;
    if (sTStringType == nullptr) {
      sTStringType = gpg::LookupRType(typeid(TString));
    }

    GPG_ASSERT(sTStringType->serSaveConstructArgsFunc_ == nullptr);
    sTStringType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091FAC0 (FUN_0091FAC0, TableSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `Table`.
   */
  void TableSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    static gpg::RType* sTableType = nullptr;
    if (sTableType == nullptr) {
      sTableType = gpg::LookupRType(typeid(Table));
    }

    GPG_ASSERT(sTableType->serSaveConstructArgsFunc_ == nullptr);
    sTableType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091FC50 (FUN_0091FC50, LClosureSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `LClosure`.
   */
  void LClosureSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    static gpg::RType* sLClosureType = nullptr;
    if (sLClosureType == nullptr) {
      sLClosureType = gpg::LookupRType(typeid(LClosure));
    }

    GPG_ASSERT(sLClosureType->serSaveConstructArgsFunc_ == nullptr);
    sLClosureType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091FDE0 (FUN_0091FDE0, UpValSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `UpVal`.
   */
  void UpValSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    static gpg::RType* sUpValType = nullptr;
    if (sUpValType == nullptr) {
      sUpValType = gpg::LookupRType(typeid(UpVal));
    }

    GPG_ASSERT(sUpValType->serSaveConstructArgsFunc_ == nullptr);
    sUpValType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x0091FF70 (FUN_0091FF70, ProtoSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `Proto`.
   */
  void ProtoSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    static gpg::RType* sProtoType = nullptr;
    if (sProtoType == nullptr) {
      sProtoType = gpg::LookupRType(typeid(Proto));
    }

    GPG_ASSERT(sProtoType->serSaveConstructArgsFunc_ == nullptr);
    sProtoType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x00920100 (FUN_00920100, lua_StateSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for
   * `lua_State`.
   */
  void lua_StateSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    static gpg::RType* sLuaThreadType = nullptr;
    if (sLuaThreadType == nullptr) {
      sLuaThreadType = gpg::LookupRType(typeid(lua_State));
    }

    GPG_ASSERT(sLuaThreadType->serSaveConstructArgsFunc_ == nullptr);
    sLuaThreadType->serSaveConstructArgsFunc_ = reinterpret_cast<gpg::RType::save_construct_args_func_t>(mConstruct);
  }

  /**
   * Address: 0x00920290 (FUN_00920290, UdataSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds the save-construct-args callback into reflected RTTI for `Udata`.
   */
  void UdataSaveConstruct::RegisterSaveConstructArgsFunction()
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
  LuaPlus::UdataSaveConstruct gUdataSaveConstructHelper{};

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
   * Address: 0x00C09D60 (FUN_00C09D60, UdataSaveConstruct::~UdataSaveConstruct)
   *
   * What it does:
   * Unlinks the global Udata save-construct helper from intrusive helper
   * links.
   */
  void cleanup_UdataSaveConstruct()
  {
    UnlinkHelperNode(gUdataSaveConstructHelper);
  }

  /**
   * Address: 0x00BEA860 (FUN_00BEA860, register_UdataSaveConstruct)
   *
   * What it does:
   * Initializes Udata save-construct helper callback and schedules teardown.
   */
  void register_UdataSaveConstruct()
  {
    InitializeHelperNode(gUdataSaveConstructHelper);
    gUdataSaveConstructHelper.mConstruct = &LuaPlus::UdataSaveConstruct::Construct;
    gUdataSaveConstructHelper.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&cleanup_UdataSaveConstruct);
  }

  struct UdataSaveConstructBootstrap
  {
    UdataSaveConstructBootstrap()
    {
      register_UdataSaveConstruct();
    }
  };

  [[maybe_unused]] UdataSaveConstructBootstrap gUdataSaveConstructBootstrap{};
} // namespace
