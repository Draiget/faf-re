#include "moho/audio/CSndParams.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/audio/AudioEngine.h"
#include "moho/audio/SParamKey.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetOwned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetOwned(unsigned int value);
  };
} // namespace gpg

namespace
{
  constexpr std::uint32_t kResolvePolicyUnresolved = 0u;
  constexpr std::uint32_t kResolvePolicyResolved = 1u;
  constexpr std::uint32_t kResolvePolicyMissingEngine = 2u;
  constexpr std::uint32_t kResolvePolicyMissingCue = 3u;
  constexpr std::uint32_t kResolvePolicyMissingBank = 4u;
  constexpr std::uint32_t kSndParamsHashSalt = 0x7BEF2693u;

  constexpr int kSndParamsUnreachableLine = 387;
  constexpr const char* kSndParamsSourcePath = "c:\\work\\rts\\main\\code\\src\\core\\SndParams.cpp";

  std::recursive_mutex gSndParamsRegistryMutex;
  std::vector<moho::CSndParams*> gSndParamsRegistry;
  std::unordered_multimap<std::uint32_t, moho::CSndParams*> gSndParamsHashCache;
  std::mutex gSharedAmbientLoopMutex;
  std::unordered_map<moho::CSndParams*, std::unique_ptr<moho::HSndEntityLoop>> gSharedAmbientLoopsByParams;
  moho::HSndEntityLoop gDefaultSharedAmbientLoop{nullptr, -1, nullptr};

  /**
   * Address: 0x004DFA50 (FUN_004DFA50, func_RegisterCSndParams)
   *
   * What it does:
   * Registers one `CSndParams` instance into the process-global parameter
   * registry lane guarded by the sound-parameter mutex.
   */
  void RegisterSndParamsInstance(moho::CSndParams* const params)
  {
    if (params == nullptr) {
      return;
    }

    std::lock_guard<std::recursive_mutex> lock(gSndParamsRegistryMutex);
    gSndParamsRegistry.push_back(params);
  }

  /**
   * Address: 0x004E14C0 (FUN_004E14C0)
   *
   * What it does:
   * Promotes one weak `AudioEngine` handle to a shared handle when the engine
   * is still alive.
   */
  [[nodiscard]] boost::shared_ptr<moho::AudioEngine>
  LockWeakAudioEngine(const boost::weak_ptr<moho::AudioEngine>& weakEngine)
  {
    return weakEngine.lock();
  }

  constexpr const char* kSoundHelpText = "Sound( {cue,bank,cutoff} ) - Make a sound parameters object";
  constexpr const char* kRpcSoundHelpText = "RPCSound( {cue,bank,cutoff} ) - Make a sound parameters object";
  constexpr const char* kGetCueBankHelpText = "cue,bank = GetCueBank(params)";

  constexpr int kSerializationSaveConstructLine = 189;
  constexpr int kSerializationConstructLine = 231;
  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
  constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";

  struct SerSaveConstructHelperView
  {
    void* mVftable;
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(SerSaveConstructHelperView, mSaveConstructArgsCallback) == 0x0C,
    "SerSaveConstructHelperView::mSaveConstructArgsCallback offset must be 0x0C"
  );

  struct SerConstructHelperView
  {
    void* mVftable;
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(SerConstructHelperView, mConstructCallback) == 0x0C,
    "SerConstructHelperView::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerConstructHelperView, mDeleteCallback) == 0x10,
    "SerConstructHelperView::mDeleteCallback offset must be 0x10"
  );

  [[nodiscard]] gpg::RType* ResolveCSndParamsType2()
  {
    gpg::RType* type = moho::CSndParams::sType2;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CSndParams));
      moho::CSndParams::sType2 = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveSParamKeyType()
  {
    gpg::RType* type = moho::SParamKey::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::SParamKey));
      moho::SParamKey::sType = type;
    }
    return type;
  }

  [[nodiscard]] msvc8::string SndVarNameOrEmpty(const moho::CSndVar* const value)
  {
    return value != nullptr ? value->mName : msvc8::string("");
  }

  [[nodiscard]] std::uint32_t HashStringWithSalt(const msvc8::string& value, const std::uint32_t salt)
  {
    const std::string hashInput(value.c_str(), value.size());
    return gpg::Hash(hashInput, salt);
  }

  [[nodiscard]] std::uint32_t HashSParamKey(const moho::SParamKey& key)
  {
    std::uint32_t hash = HashStringWithSalt(key.mCueName, kSndParamsHashSalt);
    hash = HashStringWithSalt(key.mBankName, hash);
    hash = HashStringWithSalt(key.mLodCutoffVariableName, hash);
    hash = HashStringWithSalt(key.mRpcLoopVariableName, hash);
    return hash;
  }

  /**
   * Address: 0x004DEBB0 (FUN_004DEBB0)
   *
   * What it does:
   * Copies one live `CSndParams` descriptor into its serializable `SParamKey`
   * key representation.
   */
  [[nodiscard]] moho::SParamKey BuildSParamKeyFromParams(const moho::CSndParams& params)
  {
    moho::SParamKey key{};
    key.mCueName = params.mCue;
    key.mBankName = params.mBank;
    key.mLodCutoffVariableName = SndVarNameOrEmpty(params.mLodCutoff);
    key.mRpcLoopVariableName = SndVarNameOrEmpty(params.mRpcLoopVariable);
    return key;
  }

  /**
   * Address: 0x004DEDF0 (FUN_004DEDF0)
   *
   * What it does:
   * Returns true when two sound-parameter keys match across all four string
   * lanes (`Cue`, `Bank`, `LodCutoff`, `RPC loop var`).
   */
  [[nodiscard]] bool SParamKeyMatches(const moho::SParamKey& lhs, const moho::SParamKey& rhs)
  {
    return lhs.mCueName == rhs.mCueName && lhs.mBankName == rhs.mBankName
      && lhs.mLodCutoffVariableName == rhs.mLodCutoffVariableName
      && lhs.mRpcLoopVariableName == rhs.mRpcLoopVariableName;
  }

  [[nodiscard]] moho::CSndParams* FindCachedSndParamsByHashLocked(const moho::SParamKey& key, const std::uint32_t hash)
  {
    const auto [first, last] = gSndParamsHashCache.equal_range(hash);
    for (auto it = first; it != last; ++it) {
      moho::CSndParams* const params = it->second;
      if (params == nullptr) {
        continue;
      }

      const moho::SParamKey cachedKey = BuildSParamKeyFromParams(*params);
      if (SParamKeyMatches(cachedKey, key)) {
        return params;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x004E1FD0 (FUN_004E1FD0)
   *
   * What it does:
   * Inserts one `(hash -> CSndParams*)` cache association into the global
   * sound-parameter lookup lane.
   */
  void InsertSndParamsCacheEntryLocked(const std::uint32_t hash, moho::CSndParams* const params)
  {
    gSndParamsHashCache.emplace(hash, params);
  }

  /**
   * Address: 0x004DF790 (FUN_004DF790, func_GetCSndParams)
   *
   * What it does:
   * Looks up one `CSndParams` by hashed `SParamKey` and creates/registers a new
   * descriptor when no matching key is cached.
   */
  [[nodiscard]] moho::CSndParams* FindOrCreateSndParamsByKey(const moho::SParamKey& key)
  {
    std::lock_guard<std::recursive_mutex> lock(gSndParamsRegistryMutex);

    const std::uint32_t hash = HashSParamKey(key);
    if (moho::CSndParams* const cached = FindCachedSndParamsByHashLocked(key, hash); cached != nullptr) {
      return cached;
    }

    moho::CSndVar* const lodCutoffVar = moho::SND_FindOrCreateVariable(key.mLodCutoffVariableName);
    moho::CSndVar* const rpcLoopVar = moho::SND_FindOrCreateVariable(key.mRpcLoopVariableName);
    const boost::weak_ptr<moho::AudioEngine> weakEngine{};
    moho::CSndParams* const created =
      new moho::CSndParams(key.mBankName, key.mCueName, lodCutoffVar, rpcLoopVar, weakEngine);
    InsertSndParamsCacheEntryLocked(hash, created);
    return created;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext != nullptr ? luaContext->stateUserData : nullptr;
  }

  /**
   * Address: 0x004DF2B0 (FUN_004DF2B0, func_GetSndLoop)
   *
   * What it does:
   * Returns one cached ambient-loop handle for the provided `CSndParams`
   * descriptor, creating and caching a new handle on first use.
   */
  [[nodiscard]] moho::HSndEntityLoop* GetOrCreateSharedAmbientLoop(moho::CSndParams* const params)
  {
    if (params == nullptr) {
      return &gDefaultSharedAmbientLoop;
    }

    std::lock_guard<std::mutex> lock(gSharedAmbientLoopMutex);

    const auto it = gSharedAmbientLoopsByParams.find(params);
    if (it != gSharedAmbientLoopsByParams.end()) {
      return it->second.get();
    }

    auto created = std::make_unique<moho::HSndEntityLoop>();
    created->mListLinkHead = nullptr;
    created->mLoopIndex = -1;
    created->mParams = params;

    moho::HSndEntityLoop* const handle = created.get();
    gSharedAmbientLoopsByParams.emplace(params, std::move(created));
    return handle;
  }

  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const rawState = userDataObject.GetActiveCState();
    if (rawState == nullptr) {
      return out;
    }

    const int stackTop = lua_gettop(rawState);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(rawState);
    void* const rawUserData = lua_touserdata(rawState, -1);
    if (rawUserData != nullptr) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(rawState, stackTop);
    return out;
  }

  [[nodiscard]] msvc8::string ReadRequiredTableStringField(
    LuaPlus::LuaState* const state,
    const int tableIndex,
    const char* const fieldName
  )
  {
    lua_State* const rawState = state->m_state;
    const int savedTop = lua_gettop(rawState);
    lua_pushstring(rawState, fieldName);
    lua_gettable(rawState, tableIndex);
    LuaPlus::LuaStackObject fieldObject(state, lua_gettop(rawState));
    const char* const fieldValue = lua_tostring(rawState, fieldObject.m_stackIndex);
    if (fieldValue == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&fieldObject, "string");
    }

    const msvc8::string out = fieldValue != nullptr ? msvc8::string(fieldValue) : msvc8::string("");
    lua_settop(rawState, savedTop);
    return out;
  }

  [[nodiscard]] msvc8::string ReadOptionalTableStringField(
    LuaPlus::LuaState* const state,
    const int tableIndex,
    const char* const fieldName
  )
  {
    lua_State* const rawState = state->m_state;
    const int savedTop = lua_gettop(rawState);
    lua_pushstring(rawState, fieldName);
    lua_gettable(rawState, tableIndex);
    LuaPlus::LuaStackObject fieldObject(state, lua_gettop(rawState));

    LuaPlus::LuaObject fieldValueObject(fieldObject);
    if (fieldValueObject.IsNil()) {
      lua_settop(rawState, savedTop);
      return msvc8::string("");
    }

    const char* const fieldValue = lua_tostring(rawState, fieldObject.m_stackIndex);
    if (fieldValue == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&fieldObject, "string");
    }

    const msvc8::string out = fieldValue != nullptr ? msvc8::string(fieldValue) : msvc8::string("");
    lua_settop(rawState, savedTop);
    return out;
  }

  /**
   * Address: 0x004DF510 (FUN_004DF510, func_CSndParamsObject)
   *
   * What it does:
   * Parses one Lua `{Cue,Bank,LodCutoff}` table into `SParamKey`, optionally
   * mirrors `Cue` into RPC loop variable lane, then resolves cached params.
   */
  [[nodiscard]] moho::CSndParams* BuildSndParamsFromLuaTable(
    LuaPlus::LuaStackObject& tableObject,
    const bool hasRpcLoopVar
  )
  {
    moho::SParamKey key{};
    key.mCueName = ReadRequiredTableStringField(tableObject.m_state, tableObject.m_stackIndex, "Cue");
    key.mBankName = ReadRequiredTableStringField(tableObject.m_state, tableObject.m_stackIndex, "Bank");
    key.mLodCutoffVariableName = ReadOptionalTableStringField(tableObject.m_state, tableObject.m_stackIndex, "LodCutoff");
    key.mRpcLoopVariableName = hasRpcLoopVar ? key.mCueName : msvc8::string("");
    return FindOrCreateSndParamsByKey(key);
  }

  class CSndParamsPointerMetatableFactory final : public moho::CScrLuaObjectFactory
  {
  public:
    static CSndParamsPointerMetatableFactory& Instance()
    {
      static CSndParamsPointerMetatableFactory sInstance;
      return sInstance;
    }

  protected:
    /**
     * Address: 0x004E53D0 (FUN_004E53D0)
     *
     * What it does:
     * Builds the Lua metatable shell used for `CSndParams*` userdata objects.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* const state) override
    {
      return moho::SCR_CreateSimpleMetatable(state);
    }

  private:
    CSndParamsPointerMetatableFactory()
      : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
    {}
  };
  static_assert(sizeof(CSndParamsPointerMetatableFactory) == 0x8, "CSndParamsPointerMetatableFactory size must be 0x8");

  /**
   * Address: 0x004E5510 (FUN_004E5510, gpg::RRef::TryUpcast_CSndParams_P)
   *
   * What it does:
   * Upcasts one reflected reference to a `CSndParams*` slot and throws
   * `BadRefCast` on mismatch.
   */
  [[nodiscard]] moho::CSndParams** TryUpcastCSndParamsSlotOrThrow(const gpg::RRef& source)
  {
    gpg::RType* const targetType = moho::CSndParams::GetPointerType();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, targetType);
    auto* const paramsSlot = static_cast<moho::CSndParams**>(upcast.mObj);
    if (!paramsSlot) {
      const char* const sourceName = source.mType ? source.mType->GetName() : "null";
      const char* const targetName = targetType ? targetType->GetName() : "null";
      throw gpg::BadRefCast(nullptr, sourceName, targetName);
    }
    return paramsSlot;
  }

  /**
   * Address: 0x004E0CD0 (FUN_004E0CD0)
   *
   * What it does:
   * Serializes one `CSndParams` construct payload through `SParamKey`.
   */
  void SaveConstructArgs_CSndParams(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const params = reinterpret_cast<moho::CSndParams*>(objectPtr);
    const moho::SParamKey key = BuildSParamKeyFromParams(*params);
    const gpg::RRef ownerRef{};
    archive->Write(ResolveSParamKeyType(), &key, ownerRef);
    result->SetOwned(1u);
  }

  /**
   * Address: 0x004E0C50 (FUN_004E0C50)
   *
   * What it does:
   * Thin thunk forwarding CSndParams save-construct serialization.
   */
  void SaveConstructArgs_CSndParamsThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_CSndParams(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x004E0E10 (FUN_004E0E10)
   *
   * What it does:
   * Deserializes `SParamKey`, resolves/creates one matching `CSndParams`, and
   * returns it as an owned construct result.
   */
  void Construct_CSndParams(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    moho::SParamKey key{};
    const gpg::RRef ownerRef{};
    archive->Read(ResolveSParamKeyType(), &key, ownerRef);
    moho::CSndParams* const params = FindOrCreateSndParamsByKey(key);

    gpg::RRef paramsRef{};
    gpg::RRef_CSndParams(&paramsRef, params);
    result->SetOwned(paramsRef, 1u);
  }

  /**
   * Address: 0x004E4CA0 (FUN_004E4CA0, Moho::CSndParamsConstruct::Deconstruct)
   *
   * What it does:
   * Destroys one reflected `CSndParams` object and releases its allocation.
   */
  void Delete_CSndParams(void* const objectPtr)
  {
    auto* const params = static_cast<moho::CSndParams*>(objectPtr);
    if (params == nullptr) {
      return;
    }
    delete params;
  }

  /**
   * Address: 0x004E1DB0 (FUN_004E1DB0)
   *
   * What it does:
   * Binds one CSndParams save-construct callback into RTTI.
   */
  [[nodiscard]] gpg::RType* InitCSndParamsSaveConstructHelper(const SerSaveConstructHelperView& helper)
  {
    gpg::RType* const type = ResolveCSndParamsType2();
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure(kSaveConstructAssertText, kSerializationSaveConstructLine, kSerializationSourcePath);
    }
    type->serSaveConstructArgsFunc_ = helper.mSaveConstructArgsCallback;
    return type;
  }

  /**
   * Address: 0x004E1E30 (FUN_004E1E30)
   *
   * What it does:
   * Binds one CSndParams construct callback and delete callback into RTTI.
   */
  [[nodiscard]] gpg::RType::construct_func_t InitCSndParamsConstructHelper(const SerConstructHelperView& helper)
  {
    gpg::RType* const type = ResolveCSndParamsType2();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = helper.mConstructCallback;
    type->deleteFunc_ = helper.mDeleteCallback;
    return helper.mConstructCallback;
  }

  void RegisterCSndParamsSerializationCallbacks()
  {
    const SerSaveConstructHelperView saveHelper{
      .mVftable = nullptr,
      .mNext = nullptr,
      .mPrev = nullptr,
      .mSaveConstructArgsCallback =
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_CSndParamsThunk),
    };
    (void)InitCSndParamsSaveConstructHelper(saveHelper);

    const SerConstructHelperView constructHelper{
      .mVftable = nullptr,
      .mNext = nullptr,
      .mPrev = nullptr,
      .mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&Construct_CSndParams),
      .mDeleteCallback = &Delete_CSndParams,
    };
    (void)InitCSndParamsConstructHelper(constructHelper);
  }

  struct CSndParamsSerializationBootstrap
  {
    CSndParamsSerializationBootstrap()
    {
      RegisterCSndParamsSerializationCallbacks();
    }
  };

  [[maybe_unused]] CSndParamsSerializationBootstrap gCSndParamsSerializationBootstrap;
} // namespace

namespace moho
{
  gpg::RType* CSndParams::sPointerType = nullptr;

  /**
   * Address: 0x004E4A80 (FUN_004E4A80, func_NewCSndParams)
   *
   * What it does:
   * Wraps one `CSndParams*` slot in Lua userdata and attaches the
   * `CSndParams` metatable.
   */
  LuaPlus::LuaObject*
  func_NewCSndParams(LuaPlus::LuaState* const state, LuaPlus::LuaObject* const outObject, CSndParams** const paramsSlot)
  {
    LuaPlus::LuaObject metatable = CSndParamsPointerMetatableFactory::Instance().Get(state);
    *outObject = LuaPlus::LuaObject();

    gpg::RRef paramsRef{};
    gpg::RRef_CSndParams_P(&paramsRef, paramsSlot);
    outObject->AssignNewUserData(state, paramsRef);
    outObject->SetMetaTable(metatable);
    return outObject;
  }

  /**
   * Address: 0x004E4B40 (FUN_004E4B40, func_GetCObj_CSndParams)
   *
   * What it does:
   * Resolves one Lua object/table `_c_object` lane and returns the
   * `CSndParams*` slot pointer.
   */
  CSndParams** func_GetCObj_CSndParams(LuaPlus::LuaObject object)
  {
    if (object.IsTable()) {
      object = object.GetByName("_c_object");
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(object);
    return TryUpcastCSndParamsSlotOrThrow(userDataRef);
  }

  /**
   * Address: 0x004E0740 (FUN_004E0740)
   * Mangled: ??0CSndParams@Moho@@QAE@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0PAVCSndVar@1@1ABV?$weak_ptr@VAudioEngine@Moho@@@boost@@@Z
   *
   * What it does:
   * Caches cue/bank names, optional cue variables, and one weak engine handle
   * used by lazy cue resolution.
   */
  CSndParams::CSndParams(
    const msvc8::string& bankName,
    const msvc8::string& cueName,
    CSndVar* const lodCutoffVar,
    CSndVar* const rpcLoopVar,
    const boost::weak_ptr<AudioEngine>& engine
  )
    : mBank(bankName)
    , mCue(cueName)
    , mLodCutoff(lodCutoffVar)
    , mRpcLoopVariable(rpcLoopVar)
    , mResolvePolicy(kResolvePolicyUnresolved)
    , mBankId(0xFFFFu)
    , mCueId(0xFFFFu)
    , mEngine(engine)
  {
    RegisterSndParamsInstance(this);
  }

  /**
   * Address: 0x004E5310 (FUN_004E5310, Moho::CSndParams::dtr)
   *
   * What it does:
   * Releases one `CSndParams` descriptor's owned string and weak-engine lanes.
   */
  CSndParams::~CSndParams() = default;

  /**
   * Address: 0x004E5A70 (FUN_004E5A70, Moho::CSndParams::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches the reflection descriptor for `CSndParams*`.
   */
  gpg::RType* CSndParams::GetPointerType()
  {
    gpg::RType* cached = sPointerType;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(CSndParams*));
      sPointerType = cached;
    }

    return cached;
  }

  /**
   * Address: 0x004E0820 (FUN_004E0820)
   *
   * What it does:
   * Returns a resolved engine handle according to cached resolve state and
   * current sound-configuration availability.
   */
  boost::shared_ptr<AudioEngine>* CSndParams::GetEngine(boost::shared_ptr<AudioEngine>* const outEngine) const
  {
    if (outEngine == nullptr) {
      return outEngine;
    }

    const SoundConfiguration* const configuration = sSoundConfiguration;
    if (configuration == nullptr || configuration->mEngines.mStart == nullptr ||
        configuration->mEngines.mFinish == nullptr || configuration->mEngines.mStart == configuration->mEngines.mFinish ||
        configuration->mNoSound != 0u) {
      *outEngine = {};
      return outEngine;
    }

    boost::shared_ptr<AudioEngine> resolvedEngine = LockWeakAudioEngine(mEngine);
    switch (mResolvePolicy) {
    case kResolvePolicyUnresolved:
      *outEngine = DoResolve();
      break;

    case kResolvePolicyResolved:
      if (resolvedEngine.get() != nullptr) {
        *outEngine = resolvedEngine;
      } else {
        *outEngine = DoResolve();
      }
      break;

    case kResolvePolicyMissingEngine:
      *outEngine = {};
      break;

    case kResolvePolicyMissingCue:
    case kResolvePolicyMissingBank:
      if (resolvedEngine.get() != nullptr) {
        *outEngine = {};
      } else {
        *outEngine = DoResolve();
      }
      break;

    default:
      gpg::HandleAssertFailure("Reached the supposably unreachable.", kSndParamsUnreachableLine, kSndParamsSourcePath);
      *outEngine = {};
      break;
    }

    return outEngine;
  }

  /**
   * Address: 0x004E0930 (FUN_004E0930)
   * Mangled: ?DoResolve@CSndParams@Moho@@ABE?AV?$shared_ptr@VAudioEngine@Moho@@@boost@@XZ
   *
   * What it does:
   * Resolves one engine/bank/cue tuple and caches ids/resolve policy for
   * subsequent cue playback requests.
   */
  boost::shared_ptr<AudioEngine> CSndParams::DoResolve() const
  {
    boost::shared_ptr<AudioEngine> resolvedEngine = LockWeakAudioEngine(mEngine);
    if (resolvedEngine.get() == nullptr) {
      resolvedEngine = SND_FindEngine(mBank.c_str());
      mEngine = resolvedEngine;

      if (resolvedEngine.get() == nullptr) {
        gpg::Warnf("Error resolving bank '%s' to audio engine", mBank.c_str());
        mResolvePolicy = kResolvePolicyMissingEngine;
        return {};
      }
    }

    if (!resolvedEngine->GetBankIndex(mBank.c_str(), &mBankId)) {
      gpg::Warnf("Error resolving bank '%s'", mBank.c_str());
      mResolvePolicy = kResolvePolicyMissingBank;
      return {};
    }

    if (!resolvedEngine->GetCueIndex(mCue.c_str(), mBankId, &mCueId)) {
      gpg::Warnf("Error resolving cue '%s' in bank '%s'", mCue.c_str(), mBank.c_str());
      mResolvePolicy = kResolvePolicyMissingCue;
      return {};
    }

    if (mLodCutoff != nullptr && mLodCutoff->mResolved == 0u) {
      (void)mLodCutoff->DoResolve();
    }

    if (mRpcLoopVariable != nullptr && mRpcLoopVariable->mResolved == 0u) {
      (void)mRpcLoopVariable->DoResolve();
    }

    mResolvePolicy = kResolvePolicyResolved;
    return resolvedEngine;
  }

  /**
   * Address: 0x004DFD90 (FUN_004DFD90, cfunc_Sound)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_SoundL`.
   */
  int cfunc_Sound(lua_State* const luaContext)
  {
    return cfunc_SoundL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x004DFE10 (FUN_004DFE10, cfunc_SoundL)
   *
   * What it does:
   * Builds one `CSndParams` from a Lua `{Cue,Bank,LodCutoff}` table and
   * returns it as a Lua object.
   */
  int cfunc_SoundL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSoundHelpText, 1, argumentCount);
    }

    LuaPlus::LuaStackObject paramsTable(state, 1);
    CSndParams* const params = BuildSndParamsFromLuaTable(paramsTable, false);
    LuaPlus::LuaObject wrapped{};
    CSndParams* paramsSlot = params;
    (void)func_NewCSndParams(state, &wrapped, &paramsSlot);
    wrapped.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x004DFDB0 (FUN_004DFDB0, func_Sound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `Sound`.
   */
  CScrLuaInitForm* func_Sound_LuaFuncDef()
  {
    static CScrLuaBinder binder(CoreLuaInitSet(), "Sound", &cfunc_Sound, nullptr, "<global>", kSoundHelpText);
    return &binder;
  }

  /**
   * Address: 0x004DFED0 (FUN_004DFED0, cfunc_RPCSound)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_RPCSoundL`.
   */
  int cfunc_RPCSound(lua_State* const luaContext)
  {
    return cfunc_RPCSoundL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x004DFF50 (FUN_004DFF50, cfunc_RPCSoundL)
   *
   * What it does:
   * Builds one RPC-loop-enabled `CSndParams` from Lua and returns it.
   */
  int cfunc_RPCSoundL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kRpcSoundHelpText, 1, argumentCount);
    }

    LuaPlus::LuaStackObject paramsTable(state, 1);
    CSndParams* const params = BuildSndParamsFromLuaTable(paramsTable, true);
    LuaPlus::LuaObject wrapped{};
    CSndParams* paramsSlot = params;
    (void)func_NewCSndParams(state, &wrapped, &paramsSlot);
    wrapped.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x004DFEF0 (FUN_004DFEF0, func_RPCSound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `RPCSound`.
   */
  CScrLuaInitForm* func_RPCSound_LuaFuncDef()
  {
    static CScrLuaBinder binder(CoreLuaInitSet(), "RPCSound", &cfunc_RPCSound, nullptr, "<global>", kRpcSoundHelpText);
    return &binder;
  }

  /**
   * Address: 0x004E0010 (FUN_004E0010, cfunc_GetCueBank)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetCueBankL`.
   */
  int cfunc_GetCueBank(lua_State* const luaContext)
  {
    return cfunc_GetCueBankL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x004E0090 (FUN_004E0090, cfunc_GetCueBankL)
   *
   * What it does:
   * Extracts cue/bank strings from one `CSndParams` Lua object and returns both.
   */
  int cfunc_GetCueBankL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetCueBankHelpText, 1, argumentCount);
    }

    LuaPlus::LuaStackObject paramsArg(state, 1);
    LuaPlus::LuaObject paramsObject(paramsArg);
    CSndParams** const paramsSlot = func_GetCObj_CSndParams(paramsObject);
    CSndParams* const params = *paramsSlot;

    lua_pushstring(state->m_state, params->mCue.c_str());
    lua_pushstring(state->m_state, params->mBank.c_str());
    return 2;
  }

  /**
   * Address: 0x004E0140 (FUN_004E0140, ?SND_GetSharedAmbientHandle@Moho@@...)
   *
   * What it does:
   * Thin API wrapper around the shared ambient-loop cache lookup path.
   */
  HSndEntityLoop* SND_GetSharedAmbientHandle(CSndParams* const params)
  {
    return GetOrCreateSharedAmbientLoop(params);
  }

  /**
   * Address: 0x004E0030 (FUN_004E0030, func_GetCueBank_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetCueBank`.
   */
  CScrLuaInitForm* func_GetCueBank_LuaFuncDef()
  {
    static CScrLuaBinder
      binder(CoreLuaInitSet(), "GetCueBank", &cfunc_GetCueBank, nullptr, "<global>", kGetCueBankHelpText);
    return &binder;
  }
} // namespace moho
