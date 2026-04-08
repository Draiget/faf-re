#include "moho/audio/CSndVar.h"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <string>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/audio/AudioEngine.h"

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
  constexpr std::uint32_t kSndVarHashSalt = 0x7BEF2693u;

  std::recursive_mutex gSndVarRegistryMutex;
  std::vector<moho::CSndVar*> gSndVarRegistry;
  std::unordered_multimap<std::uint32_t, moho::CSndVar*> gSndVarNameCache;

  [[nodiscard]] std::uint32_t HashSndVarName(const msvc8::string& name)
  {
    const std::string hashInput(name.c_str(), name.size());
    return gpg::Hash(hashInput, kSndVarHashSalt);
  }

  [[nodiscard]] moho::CSndVar*
  FindCachedSndVarByNameLocked(const msvc8::string& variableName, const std::uint32_t nameHash)
  {
    const auto [first, last] = gSndVarNameCache.equal_range(nameHash);
    for (auto it = first; it != last; ++it) {
      moho::CSndVar* const entry = it->second;
      if (entry != nullptr && entry->mName.view() == variableName.view()) {
        return entry;
      }
    }

    return nullptr;
  }

  void RemoveCachedSndVarByPointerLocked(const moho::CSndVar* const value)
  {
    for (auto it = gSndVarNameCache.begin(); it != gSndVarNameCache.end();) {
      if (it->second == value) {
        it = gSndVarNameCache.erase(it);
      } else {
        ++it;
      }
    }
  }

  /**
   * Address: 0x004DF990 (FUN_004DF990, func_RegisterCSndVar)
   *
   * What it does:
   * Registers one `CSndVar` instance in the process-global variable-name lane.
   */
  void RegisterSndVarInstance(moho::CSndVar* const value)
  {
    std::lock_guard<std::recursive_mutex> lock(gSndVarRegistryMutex);
    gSndVarRegistry.push_back(value);
  }

  /**
   * Address: 0x004DFA20 (FUN_004DFA20)
   *
   * What it does:
   * Removes one `CSndVar` instance from the process-global variable-name lane.
   */
  void UnregisterSndVarInstance(const moho::CSndVar* const value)
  {
    std::lock_guard<std::recursive_mutex> lock(gSndVarRegistryMutex);
    RemoveCachedSndVarByPointerLocked(value);
    const auto it = std::remove(gSndVarRegistry.begin(), gSndVarRegistry.end(), value);
    gSndVarRegistry.erase(it, gSndVarRegistry.end());
  }

  /**
   * Address: 0x004DFAE0 (FUN_004DFAE0)
   *
   * What it does:
   * Returns the registered variable name for one resolved variable id, or an
   * empty string when no matching descriptor is present.
   */
  msvc8::string LookupSndVarNameById(const std::uint16_t variableId)
  {
    std::lock_guard<std::recursive_mutex> lock(gSndVarRegistryMutex);
    for (const moho::CSndVar* const entry : gSndVarRegistry) {
      if (entry != nullptr && entry->mState == variableId) {
        return entry->mName;
      }
    }

    return msvc8::string("");
  }

  [[nodiscard]] gpg::RType* ResolveCSndVarType()
  {
    gpg::RType* type = moho::CSndVar::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CSndVar));
      moho::CSndVar::sType = type;
    }
    return type;
  }

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

  /**
   * Address: 0x004E0430 (FUN_004E0430)
   *
   * What it does:
   * Saves one `CSndVar` construct argument payload (`mName`) into archive.
   */
  void SaveConstructArgs_CSndVar(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const sndVar = reinterpret_cast<moho::CSndVar*>(objectPtr);
    archive->WriteString(&sndVar->mName);
    result->SetOwned(1u);
  }

  /**
   * Address: 0x004E0560 (FUN_004E0560)
   *
   * What it does:
   * Reads one variable-name construct arg, interns/creates `CSndVar`, and
   * returns it as an owned reflection result.
   */
  void Construct_CSndVar(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    msvc8::string variableName{};
    archive->ReadString(&variableName);

    moho::CSndVar* const sndVar = moho::SND_FindOrCreateVariable(variableName);
    gpg::RRef ref{};
    ref.mObj = sndVar;
    ref.mType = sndVar != nullptr ? ResolveCSndVarType() : nullptr;
    result->SetOwned(ref, 1u);
  }

  /**
   * Address: 0x004E4BD0 (FUN_004E4BD0)
   *
   * What it does:
   * Destroys one reflected `CSndVar` object allocated by construct callback.
   */
  void Delete_CSndVar(void* const objectPtr)
  {
    auto* const sndVar = static_cast<moho::CSndVar*>(objectPtr);
    if (sndVar == nullptr) {
      return;
    }

    sndVar->~CSndVar();
    ::operator delete(sndVar);
  }

  /**
   * Address: 0x004E1CB0 (FUN_004E1CB0)
   *
   * What it does:
   * Binds one CSndVar save-construct callback into RTTI.
   */
  [[nodiscard]] gpg::RType* InitCSndVarSaveConstructHelper(const SerSaveConstructHelperView& helper)
  {
    gpg::RType* const type = ResolveCSndVarType();
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure(kSaveConstructAssertText, kSerializationSaveConstructLine, kSerializationSourcePath);
    }
    type->serSaveConstructArgsFunc_ = helper.mSaveConstructArgsCallback;
    return type;
  }

  /**
   * Address: 0x004E1D30 (FUN_004E1D30)
   *
   * What it does:
   * Binds one CSndVar construct callback and delete callback into RTTI.
   */
  [[nodiscard]] gpg::RType::construct_func_t InitCSndVarConstructHelper(const SerConstructHelperView& helper)
  {
    gpg::RType* const type = ResolveCSndVarType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = helper.mConstructCallback;
    type->deleteFunc_ = helper.mDeleteCallback;
    return helper.mConstructCallback;
  }

  /**
   * Address: 0x004E1D00 (FUN_004E1D00)
   *
   * What it does:
   * Builds one static CSndVar construct-helper view carrying construct/delete
   * callback lanes used by serialization registration.
   */
  [[nodiscard]] const SerConstructHelperView& BuildCSndVarConstructHelper()
  {
    static const SerConstructHelperView helper{
      .mVftable = nullptr,
      .mNext = nullptr,
      .mPrev = nullptr,
      .mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&Construct_CSndVar),
      .mDeleteCallback = &Delete_CSndVar,
    };
    return helper;
  }

  void RegisterCSndVarSerializationCallbacks()
  {
    const SerSaveConstructHelperView saveHelper{
      .mVftable = nullptr,
      .mNext = nullptr,
      .mPrev = nullptr,
      .mSaveConstructArgsCallback = reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_CSndVar),
    };
    (void)InitCSndVarSaveConstructHelper(saveHelper);

    const SerConstructHelperView& constructHelper = BuildCSndVarConstructHelper();
    (void)InitCSndVarConstructHelper(constructHelper);
  }

  struct CSndVarSerializationBootstrap
  {
    CSndVarSerializationBootstrap()
    {
      RegisterCSndVarSerializationCallbacks();
    }
  };

  [[maybe_unused]] CSndVarSerializationBootstrap gCSndVarSerializationBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x004DF390 (FUN_004DF390, func_NewCSndVar)
   *
   * msvc8::string const&
   *
   * What it does:
   * Returns one interned `CSndVar` for the supplied variable name.
   */
  CSndVar* SND_FindOrCreateVariable(const msvc8::string& variableName)
  {
    if (variableName.empty()) {
      return nullptr;
    }

    std::lock_guard<std::recursive_mutex> lock(gSndVarRegistryMutex);

    const std::uint32_t nameHash = HashSndVarName(variableName);
    if (CSndVar* const cached = FindCachedSndVarByNameLocked(variableName, nameHash); cached != nullptr) {
      return cached;
    }

    CSndVar* const created = new CSndVar(variableName.c_str());
    gSndVarNameCache.emplace(nameHash, created);
    return created;
  }

  /**
   * Address: 0x004E02B0 (FUN_004E02B0)
   *
   * What it does:
   * Initializes one unresolved sound-variable descriptor and registers it in
   * the global variable-name lane.
   */
  CSndVar::CSndVar(const char* const name)
    : mState(0xFFFFu)
    , mResolved(0u)
    , mReserved03(0u)
    , mName()
  {
    mName.assign_owned(name);
    RegisterSndVarInstance(this);
  }

  /**
   * Address: 0x004E0330 (FUN_004E0330)
   *
   * What it does:
   * Unregisters one descriptor and tears down owned name storage.
   */
  CSndVar::~CSndVar()
  {
    UnregisterSndVarInstance(this);
    mName.tidy(true, 0u);
    mState = 0xFFFFu;
    mResolved = 0u;
    mReserved03 = 0u;
  }

  /**
   * Address: 0x004E0390 (FUN_004E0390)
   *
   * What it does:
   * Resolves one global XACT variable index by name and caches the result.
   */
  bool CSndVar::DoResolve() const
  {
    mResolved = 1u;
    if (SND_GetGlobalVarIndex(mName.c_str(), &mState)) {
      return true;
    }

    const SoundConfiguration* const configuration = sSoundConfiguration;
    if (configuration != nullptr && configuration->mEngines.mStart != nullptr &&
        configuration->mEngines.mStart != configuration->mEngines.mFinish && configuration->mNoSound == 0u) {
      gpg::Warnf("SND: Couldn't find variable %s", mName.c_str());
    }

    return false;
  }

  /**
   * Address: 0x004E0150 (FUN_004E0150, ?SND_GetVariableName@Moho@@...)
   *
   * int variableId
   *
   * What it does:
   * Returns the registered name for one global sound variable id.
   */
  msvc8::string SND_GetVariableName(const int variableId)
  {
    return LookupSndVarNameById(static_cast<std::uint16_t>(variableId));
  }
} // namespace moho
