#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "moho/audio/CSndVar.h"

struct lua_State;

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
}

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
}

namespace moho
{
  class AudioEngine;
  class CScrLuaInitForm;
  class CSndParams;

  /**
   * Shared ambient-loop handle lane used to bind one `CSndParams` descriptor to
   * one loop-tracking record.
   *
   * Layout recovered from FUN_004DF2B0 (`func_GetSndLoop`) and
   * FUN_004E0140 (`SND_GetSharedAmbientHandle`) allocation and field stores.
   */
  struct HSndEntityLoop
  {
    void* mListLinkHead;     // +0x00
    std::int32_t mLoopIndex; // +0x04
    CSndParams* mParams;     // +0x08
  };

  static_assert(offsetof(HSndEntityLoop, mListLinkHead) == 0x00, "HSndEntityLoop::mListLinkHead offset must be 0x00");
  static_assert(offsetof(HSndEntityLoop, mLoopIndex) == 0x04, "HSndEntityLoop::mLoopIndex offset must be 0x04");
  static_assert(offsetof(HSndEntityLoop, mParams) == 0x08, "HSndEntityLoop::mParams offset must be 0x08");
  static_assert(sizeof(HSndEntityLoop) == 0x0C, "HSndEntityLoop size must be 0x0C");

  /**
   * Parsed bank/cue playback descriptor used by user-side audio playback.
   *
   * Layout recovered from FUN_004E0740 callsites and field access in
   * CUserSoundManager methods.
   */
  class CSndParams
  {
  public:
    inline static gpg::RType* sType = nullptr;
    inline static gpg::RType* sType2 = nullptr;
    static gpg::RType* sPointerType;

    /**
     * Address: 0x004E0740 (FUN_004E0740)
     *
     * msvc8::string const&, msvc8::string const&, Moho::CSndVar*,
     * Moho::CSndVar*, boost::weak_ptr<Moho::AudioEngine> const&
     *
     * What it does:
     * Stores bank/cue strings, optional variable selectors, and captures
     * engine ownership for later playback.
     */
    CSndParams(
      const msvc8::string& bankName,
      const msvc8::string& cueName,
      CSndVar* lodCutoffVar,
      CSndVar* rpcLoopVar,
      const boost::weak_ptr<AudioEngine>& engine
    );

    /**
     * Address: 0x004E5310 (FUN_004E5310, Moho::CSndParams::dtr)
     *
     * What it does:
     * Releases retained weak-engine/string lanes for one sound-parameter
     * descriptor instance.
     */
    ~CSndParams();

    /**
     * Address: 0x004E5A70 (FUN_004E5A70, Moho::CSndParams::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for `CSndParams*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x004E0820 (FUN_004E0820)
     *
     * boost::shared_ptr<Moho::AudioEngine>* outEngine
     *
     * What it does:
     * Copies/returns the retained playback engine handle for this cue set.
     */
    boost::shared_ptr<AudioEngine>* GetEngine(boost::shared_ptr<AudioEngine>* outEngine) const;

  private:
    /**
     * Address: 0x004E0930 (FUN_004E0930)
     *
     * What it does:
     * Resolves bank/cue ids and returns a strong `AudioEngine` handle when the
     * current descriptor can be bound to one loaded engine.
     */
    [[nodiscard]] boost::shared_ptr<AudioEngine> DoResolve() const;

  public:
    msvc8::string mBank;                    // +0x00
    msvc8::string mCue;                     // +0x1C
    CSndVar* mLodCutoff;                    // +0x38
    CSndVar* mRpcLoopVariable;              // +0x3C
    mutable std::uint32_t mResolvePolicy;   // +0x40
    mutable std::uint16_t mBankId;          // +0x44
    mutable std::uint16_t mCueId;           // +0x46
    mutable boost::weak_ptr<AudioEngine> mEngine; // +0x48
  };

  static_assert(offsetof(CSndParams, mBank) == 0x00, "CSndParams::mBank offset must be 0x00");
  static_assert(offsetof(CSndParams, mCue) == 0x1C, "CSndParams::mCue offset must be 0x1C");
  static_assert(offsetof(CSndParams, mLodCutoff) == 0x38, "CSndParams::mLodCutoff offset must be 0x38");
  static_assert(offsetof(CSndParams, mRpcLoopVariable) == 0x3C, "CSndParams::mRpcLoopVariable offset must be 0x3C");
  static_assert(offsetof(CSndParams, mResolvePolicy) == 0x40, "CSndParams::mResolvePolicy offset must be 0x40");
  static_assert(offsetof(CSndParams, mBankId) == 0x44, "CSndParams::mBankId offset must be 0x44");
  static_assert(offsetof(CSndParams, mCueId) == 0x46, "CSndParams::mCueId offset must be 0x46");
  static_assert(offsetof(CSndParams, mEngine) == 0x48, "CSndParams::mEngine offset must be 0x48");
  static_assert(sizeof(CSndParams) == 0x50, "CSndParams size must be 0x50");

  /**
   * VFTABLE: 0x00E0BA98
   *
   * Demangled: gpg::SerConstructHelper<class Moho::CSndParams>
   *
   * What it does:
   * Reflection construct/delete helper for `CSndParams`: `Construct` resolves
   * a `SParamKey` payload back to the (possibly-shared) cached `CSndParams`
   * instance; `Deconstruct` deletes a heap-owned one.
   */
  class CSndParamsConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC69F0 (FUN_00BC69F0, dynamic initializer for the global
     * `CSndParamsConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the construct/delete callback fields.
     */
    CSndParamsConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CSndParamsConstruct();

    /**
     * Address: 0x004E0E10 (FUN_004E0E10, Moho::CSndParamsConstruct::Construct)
     *
     * What it does:
     * Deserializes one `SParamKey`, resolves/creates the matching cached
     * `CSndParams` instance, and returns it as an owned construct result.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x004E4CA0 (FUN_004E4CA0, Moho::CSndParamsConstruct::Deconstruct)
     *
     * What it does:
     * Destroys one reflected `CSndParams` object and releases its allocation.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x004E1E30 (FUN_004E1E30, gpg::SerConstructHelper<Moho::CSndParams>::Init)
     *
     * What it does:
     * Installs construct/delete callbacks into `CSndParams` RTTI. Dispatched
     * by `gpg::SerHelperBase::InitNewHelpers` when this helper is drained
     * from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;         // +0x10
  };

  static_assert(
    offsetof(CSndParamsConstruct, mConstructCallback) == 0x0C,
    "CSndParamsConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CSndParamsConstruct, mDeleteCallback) == 0x10, "CSndParamsConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CSndParamsConstruct) == 0x14, "CSndParamsConstruct size must be 0x14");

  /**
   * VFTABLE: 0x00E0BA88
   *
   * Demangled: gpg::SerSaveConstructHelper<class Moho::CSndParams>
   *
   * What it does:
   * Reflection save-construct-args helper for `CSndParams`: serializes the
   * live descriptor into its `SParamKey` payload for later `Construct`.
   */
  class CSndParamsSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC69C0 (FUN_00BC69C0, dynamic initializer for the global
     * `CSndParamsSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field.
     */
    CSndParamsSaveConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CSndParamsSaveConstruct();

    /**
     * Address: 0x004E0CD0 (FUN_004E0CD0, Moho::CSndParamsSaveConstruct::SaveConstructArgs)
     * Address: 0x004E0C50 (FUN_004E0C50, thin thunk stored in the ctor;
     * tail-calls the body above)
     *
     * What it does:
     * Serializes one live `CSndParams` descriptor into its `SParamKey`
     * payload.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive,
      int objectPtr,
      int version,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x004E1DB0 (FUN_004E1DB0, gpg::SerSaveConstructHelper<Moho::CSndParams>::Init)
     *
     * What it does:
     * Binds the save-construct-args callback lane into `CSndParams` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(CSndParamsSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CSndParamsSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CSndParamsSaveConstruct) == 0x10, "CSndParamsSaveConstruct size must be 0x10");

  /**
   * Address: 0x004E4A80 (FUN_004E4A80, func_NewCSndParams)
   *
   * What it does:
   * Wraps one `CSndParams*` slot as Lua userdata and assigns the
   * `CSndParams` metatable before returning the destination Lua object.
   */
  LuaPlus::LuaObject*
  func_NewCSndParams(LuaPlus::LuaState* state, LuaPlus::LuaObject* outObject, CSndParams** paramsSlot);

  /**
   * Address: 0x004E4B40 (FUN_004E4B40, func_GetCObj_CSndParams)
   *
   * What it does:
   * Resolves one Lua object/table `_c_object` payload and returns the
   * underlying `CSndParams*` slot pointer.
   */
  CSndParams** func_GetCObj_CSndParams(LuaPlus::LuaObject object);

  /**
   * Address: 0x004DFD90 (FUN_004DFD90, cfunc_Sound)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_SoundL`.
   */
  int cfunc_Sound(lua_State* luaContext);

  /**
   * Address: 0x004DFE10 (FUN_004DFE10, cfunc_SoundL)
   *
   * What it does:
   * Builds one `CSndParams` from `{Cue,Bank,LodCutoff}` and returns it to Lua.
   */
  int cfunc_SoundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004DFDB0 (FUN_004DFDB0, func_Sound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `Sound`.
   */
  CScrLuaInitForm* func_Sound_LuaFuncDef();

  /**
   * Address: 0x004DFED0 (FUN_004DFED0, cfunc_RPCSound)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_RPCSoundL`.
   */
  int cfunc_RPCSound(lua_State* luaContext);

  /**
   * Address: 0x004DFF50 (FUN_004DFF50, cfunc_RPCSoundL)
   *
   * What it does:
   * Builds one RPC-loop-enabled `CSndParams` from Lua and returns it.
   */
  int cfunc_RPCSoundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004DFEF0 (FUN_004DFEF0, func_RPCSound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `RPCSound`.
   */
  CScrLuaInitForm* func_RPCSound_LuaFuncDef();

  /**
   * Address: 0x004E0010 (FUN_004E0010, cfunc_GetCueBank)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetCueBankL`.
   */
  int cfunc_GetCueBank(lua_State* luaContext);

  /**
   * Address: 0x004E0090 (FUN_004E0090, cfunc_GetCueBankL)
   *
   * What it does:
   * Extracts cue/bank strings from one `CSndParams` Lua object and returns both.
   */
  int cfunc_GetCueBankL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004E0140 (FUN_004E0140, ?SND_GetSharedAmbientHandle@Moho@@...)
   *
   * What it does:
   * Returns one process-global shared ambient-loop handle for the supplied
   * `CSndParams` descriptor.
   */
  HSndEntityLoop* SND_GetSharedAmbientHandle(CSndParams* params);

  /**
   * Address: 0x004E0030 (FUN_004E0030, func_GetCueBank_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetCueBank`.
   */
  CScrLuaInitForm* func_GetCueBank_LuaFuncDef();
} // namespace moho
