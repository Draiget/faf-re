#include "lua/LuaStateSaveConstruct.h"

#include <cstddef>
#include <cstdint>

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
    if (state->m_rootState == state) {
      throw gpg::SerializationError("Consistency check failed: !isMainThread");
    }

    result->SetUnowned(0u);
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
} // namespace LuaPlus
