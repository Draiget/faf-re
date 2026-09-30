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

namespace
{
  constexpr std::uint32_t kSndVarHashSalt = 0x7BEF2693u;

  /**
   * The two globals below are the `CSndVar` half of the sound subsystem's
   * seven-global run at 0x010A9288..0x010A92D7. The whole run shares one
   * constructor group (0x004DFC80) and one destructor group (0x004DF0E0),
   * driven by the `??__E` initializer at 0x00BC68A0 -- so in the shipped build
   * all seven lived in one translation unit, and CSndParams.cpp carries the
   * full account of that run and of the node layouts.
   *
   * The lock that guards both of these in the binary is the single
   * `boost::mutex` at 0x010A92D0, defined in CSndParams.cpp as
   * `gSharedAmbientLoopMutex`; `gSndVarRegistryMutex` below has no counterpart
   * there.
   */

  std::recursive_mutex gSndVarRegistryMutex;

  /**
   * Address: 0x010A92B8 (`msvc8::list<CSndVar*>`; `_Myhead` 0x010A92BC,
   *   `_Mysize` 0x010A92C0). Node `_Buynode` 0x004E2610 over
   *   `allocator<_Node>::allocate` 0x004E4FF0 (0x0C bytes: `_Next` +0x00,
   *   `_Prev` +0x04, the `CSndVar*` at +0x08), self-linked by the constructor
   *   group at 0x004DFD44. Reached by `RegisterSndVarInstance` (0x004DF990),
   *   `UnregisterSndVarInstance` (0x004DFA20) and `LookupSndVarNameById`
   *   (0x004DFAE0).
   */
  msvc8::list<moho::CSndVar*> gSndVarRegistry;

  /**
   * Address: 0x010A9294 (`msvc8::multimap<std::uint32_t, CSndVar*>`; `_Myhead`
   *   0x010A9298, `_Mysize` 0x010A929C). Node `_Buynode` 0x004E3FD0 over
   *   `allocator<_Node>::allocate` 0x004E51F0 (0x18 bytes), initialised by the
   *   constructor group at 0x004DFCD2. `SND_FindOrCreateVariable` (0x004DF390)
   *   is its only reader, and reaches it by the container's base address
   *   rather than by `_Myhead` -- which is why a search for 0x010A9298 alone
   *   finds nothing but the constructor and destructor groups.
   *
   * A multimap, and the shipped insert (0x004E2110) is the proof: it descends
   * `key < node->key ? left : right` and links, then returns `{node, true}` --
   * that is `_Tree::insert`'s `if (_Multi)` branch, which never probes for an
   * equivalent key. Key at node+0x0C, the variable pointer at node+0x10.
   */
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

    const SoundConfiguration* const configuration = sSoundConfiguration.get();
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

namespace moho
{
  void CSndVar::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    msvc8::string name;
    archive.ReadString(&name);
    result.SetOwned(gpg::MakeRRef(SND_FindOrCreateVariable(name)), 1u);
  }

  void CSndVar::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    archive.WriteString(&mName);
    result.SetOwned(1u);
  }

  /**
   * `gpg::SerSaveConstructHelper<CSndVar>`, vtable 0x00E0BA38.
   *
   * Address: 0x00BC6930 (FUN_00BC6930 -- constructs the global and registers its destructor.)
   * Address: 0x00BF0F00 (FUN_00BF0F00 -- the global's destructor.)
   * Address: 0x004E1CB0 (FUN_004E1CB0 -- `Init`.)
   * Address: 0x004E0430 (FUN_004E0430 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct CSndVarSaveConstruct : gpg::SerSaveConstructHelper<CSndVar>
  {};

  /**
   * `gpg::SerConstructHelper<CSndVar>`, vtable 0x00E0BA48.
   *
   * Address: 0x00BC6960 (FUN_00BC6960 -- constructs the global and registers its destructor.)
   * Address: 0x00BF0F30 (FUN_00BF0F30 -- the global's destructor.)
   * Address: 0x004E1D30 (FUN_004E1D30 -- `Init`.)
   * Address: 0x004E0560 (FUN_004E0560 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x004E4BD0 (FUN_004E4BD0 -- `Delete`.)
   */
  struct CSndVarConstruct : gpg::SerConstructHelper<CSndVar>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A9378 -- process-global `CSndVarSaveConstruct` singleton.
  moho::CSndVarSaveConstruct gCSndVarSaveConstruct;

  // Address: 0x010A94CC -- process-global `CSndVarConstruct` singleton.
  moho::CSndVarConstruct gCSndVarConstruct;
} // namespace
