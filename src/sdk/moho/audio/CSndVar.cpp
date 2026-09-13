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
#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
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
  msvc8::list<moho::CSndVar*> gSndVarRegistry;
  // A multimap, and the shipped insert (0x004E2110) is the proof: it descends
  // `key < node->key ? left : right` and links, then returns `{node, true}` --
  // that is `_Tree::insert`'s `if (_Multi)` branch, which never probes for an
  // equivalent key. Node 0x18, key at node+0x0C, the variable pointer at
  // node+0x10, colour/nil at +0x14/+0x15.
  msvc8::multimap<std::uint32_t, moho::CSndVar*> gSndVarNameCache;

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
   * `push_back` on the `msvc8::list<CSndVar*>` registry instantiates the
   * generic `list<T>::insert` node-buy/`_Incsize` pair (see
   * `Address: 0x004E3490` cited on `msvc8::list<T>::insert` in
   * legacy/containers/Vector.h) -- the same emission shape as the sibling
   * `msvc8::list<CSndParams*>` registry's `FUN_004E32D0`/`FUN_004E3310` pair
   * used by `func_RegisterCSndParams` (CSndParams.cpp).
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
    for (auto it = gSndVarRegistry.begin(); it != gSndVarRegistry.end();) {
      if (*it == value) {
        it = gSndVarRegistry.erase(it);
      } else {
        ++it;
      }
    }
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

  // Address: 0x00BC6960 (dynamic initializer for the global `CSndVarConstruct`
  // singleton, __xc_a-reachable) -- MSVC's own compiler-generated dynamic
  // initializer for this global runs the real `Moho::CSndVarConstruct` ctor
  // (calls `gpg::SerHelperBase::SerHelperBase`, binds `mConstructCallback`/
  // `mDeleteCallback`, installs the vtable) and registers the real mangled
  // destructor (`??1CSndVarConstruct@Moho@@QAE@@Z`, 0x00BF0F30) via `atexit`.
  // Dead zero-xref duplicate ctor that installs a distinct byte-identical
  // copy of the `gpg::SerConstructHelper<CSndVar>` template's own vtable
  // instead of the real class vtable: 0x004E1D00 (prior recovery
  // misidentified this as a "BuildCSndVarConstructHelper" view builder).
  moho::CSndVarConstruct gCSndVarConstruct;

  // Address: 0x00BC6930 (dynamic initializer for the global
  // `CSndVarSaveConstruct` singleton, __xc_a-reachable) -- same shape as
  // `gCSndVarConstruct` above; registers the real mangled destructor
  // (`??1CSndVarSaveConstruct@Moho@@QAE@@Z`, 0x00BF0F00) via `atexit`.
  // Prior recovery modeled both of these globals' wiring via
  // `SerConstructHelperView`/`SerSaveConstructHelperView` raw structs
  // (`void* mVftable` field, no real base) passed by value into
  // `InitCSndVarConstructHelper`/`InitCSndVarSaveConstructHelper` from a
  // `RegisterCSndVarSerializationCallbacks()` bootstrap function with no
  // address citation of its own -- i.e. the reflection callbacks were never
  // actually installed by any code path the binary itself runs. These
  // globals' own static initialization fixes that.
  moho::CSndVarSaveConstruct gCSndVarSaveConstruct;
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
    (void)gSndVarNameCache.insert({nameHash, created});
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
   * Address: 0x004E0560 (FUN_004E0560, Moho::CSndVarConstruct::Construct)
   */
  void CSndVarConstruct::Construct(
    gpg::ReadArchive* const archive, const int, gpg::RRef* const, gpg::SerConstructResult* const result
  )
  {
    msvc8::string variableName{};
    archive->ReadString(&variableName);

    CSndVar* const sndVar = SND_FindOrCreateVariable(variableName);
    gpg::RRef ref{};
    ref.mObj = sndVar;
    ref.mType = sndVar != nullptr ? ResolveCSndVarType() : nullptr;
    result->SetOwned(ref, 1u);
  }

  /**
   * Address: 0x004E4BD0 (FUN_004E4BD0, Moho::CSndVarConstruct::Deconstruct)
   */
  void CSndVarConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const sndVar = static_cast<CSndVar*>(objectPtr);
    if (sndVar == nullptr) {
      return;
    }

    sndVar->~CSndVar();
    ::operator delete(sndVar);
  }

  /**
   * Address: 0x00BC6960 (FUN_00BC6960, dynamic initializer for the global
   * `CSndVarConstruct` singleton)
   */
  CSndVarConstruct::CSndVarConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CSndVarConstruct::Construct))
    , mDeleteCallback(&CSndVarConstruct::Deconstruct)
  {}

  CSndVarConstruct::~CSndVarConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x004E1D30 (FUN_004E1D30, gpg::SerConstructHelper<Moho::CSndVar>::Init)
   */
  void CSndVarConstruct::Init()
  {
    gpg::RType* const type = ResolveCSndVarType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x004E0430 (FUN_004E0430, Moho::CSndVarSaveConstruct::SaveConstructArgs)
   */
  void CSndVarSaveConstruct::SaveConstructArgs(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const sndVar = reinterpret_cast<CSndVar*>(objectPtr);
    archive->WriteString(&sndVar->mName);
    result->SetOwned(1u);
  }

  /**
   * Address: 0x00BC6930 (FUN_00BC6930, dynamic initializer for the global
   * `CSndVarSaveConstruct` singleton)
   */
  CSndVarSaveConstruct::CSndVarSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CSndVarSaveConstruct::SaveConstructArgs)
      )
  {}

  CSndVarSaveConstruct::~CSndVarSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x004E1CB0 (FUN_004E1CB0, gpg::SerSaveConstructHelper<Moho::CSndVar>::Init)
   */
  void CSndVarSaveConstruct::Init()
  {
    gpg::RType* const type = ResolveCSndVarType();
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure(kSaveConstructAssertText, kSerializationSaveConstructLine, kSerializationSourcePath);
    }
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
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
