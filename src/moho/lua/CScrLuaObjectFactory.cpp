#include "moho/lua/CScrLuaObjectFactory.h"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <unordered_map>
#include <unordered_set>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/exceptions/StdExcept.h"
#include "lua/LuaTableIterator.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/lua/ScriptChunkCache.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/CVFSImpl.h"

// The Lua core's own table and string primitives (defined in lua/LuaObject.cpp), for SCR_Copy's
// table walk.
extern "C"
{
  Table* luaH_new(lua_State* L, int narray, int lnhash);
  TString* luaS_newlstr(lua_State* L, const char* str, size_t len);
  int luaO_log2(unsigned int x);
  void luaV_settable(lua_State* L, const LuaPlus::TObject* t, LuaPlus::TObject* key, LuaPlus::TObject* val);
}

namespace
{
  constexpr const char* kFactoryObjectsGlobalName = "__factory_objects";
  bool lua_SessionSharedBlueprints = true;
  moho::TConVar<bool> gTConVar_lua_SessionSharedBlueprints(
    "lua_SessionSharedBlueprints",
    "The session's Lua copy of the blueprints keeps one table for each blueprint, reached by its number and by its id "
    "as in the rules' own state (1, the default), or two separate copies (0). The sim's copy always has two.",
    &lua_SessionSharedBlueprints
  );

  thread_local std::unordered_map<const void*, LuaPlus::LuaObject>* tCopiedTables = nullptr;

  constexpr const char* kActiveModsGlobalName = "__active_mods";
  constexpr const char* kLocationFieldName = "location";
  constexpr const char* kHookDirFieldName = "hookdir";
  constexpr const char* kDefaultHookDirPath = "/hook";
  constexpr const char kConcatSyntheticNewline[] = "\n";
  std::int32_t gRecoveredCScrLuaMetatableFactoryCScriptObjectIndex = 0;
  fa::vector<fa::string> gScriptHookDirectories{};

  struct LuaFileLoaderDat final
  {
    gpg::MemBuffer<const char> buf{};
    bool done{false};
  };
  static_assert(sizeof(LuaFileLoaderDat) == 0x14, "LuaFileLoaderDat size must be 0x14");

  struct LuaConcatLoadData final
  {
    gpg::MemBuffer<const char> currentChunk{};
    const fa::vector<fa::string>* files{nullptr};
    std::uint32_t nextFileIndex{0};
    bool pendingTrailingNewline{false};
  };
  static_assert(sizeof(LuaConcatLoadData) == 0x1C, "LuaConcatLoadData size must be 0x1C");



  [[nodiscard]] const char* ReflectedTypeNameOrNull(const gpg::RType* const type) noexcept
  {
    return type ? type->GetName() : "null";
  }

  [[nodiscard]] const char* LuaObjectTypeName(const LuaPlus::LuaObject& object)
  {
    lua_State* const lstate = object.GetActiveCState();
    if (!lstate) {
      return "unknown";
    }
    return lua_typename(lstate, object.m_object.tt);
  }

  [[nodiscard]] bool LuaObjectTryToString(const LuaPlus::LuaObject& object, std::string& outText)
  {
    LuaPlus::LuaState* const activeState = object.GetActiveState();
    if (!activeState) {
      return false;
    }

    lua_State* const lstate = activeState->GetCState();
    if (!lstate) {
      return false;
    }

    const int savedTop = lua_gettop(lstate);
    object.PushStack(activeState);
    const char* const valueText = lua_tostring(lstate, -1);
    const bool convertible = valueText != nullptr;
    if (convertible) {
      outText.assign(valueText);
    }
    lua_settop(lstate, savedTop);
    return convertible;
  }

  bool sim_BlueprintFieldShortcuts = true;
  moho::TConVar<bool> gTConVar_sim_BlueprintFieldShortcuts(
    "sim_BlueprintFieldShortcuts",
    "Blueprint fields: a number goes straight into a float field, and a plain value is set without the field's "
    "log context (1, the default), or every value goes through its text with the context built first (0). Same "
    "values and warnings either way.",
    &sim_BlueprintFieldShortcuts
  );

  bool sim_BlueprintCopyDirect = true;
  moho::TConVar<bool> gTConVar_sim_BlueprintCopyDirect(
    "sim_BlueprintCopyDirect",
    "Copy the rules' blueprint tables into a session or sim Lua state by walking them directly (1, the default), or "
    "through a LuaObject per key and value (0). Same tables, laid out alike, either way.",
    &sim_BlueprintCopyDirect
  );

  /**
   * Engine addition: a Lua number stored into a `float` without its text. The text path prints the
   * number with tostring's "%.14g" and reads it back with `atof` before narrowing to float; both
   * CRT calls round correctly and 14 digits are far finer than a float's spacing, so it returns
   * the same float for every value but a NaN, which keeps the text path.
   */
  [[nodiscard]] bool TrySetFloatDirectly(const LuaPlus::LuaObject& value, const gpg::RRef& destination)
  {
    static const gpg::RType* const floatType = gpg::LookupRType(typeid(float));
    if (!sim_BlueprintFieldShortcuts || value.m_object.tt != LUA_TNUMBER || destination.mType != floatType || std::isnan(value.m_object.value.n)) {
      return false;
    }
    *static_cast<float*>(destination.mObj) = value.m_object.value.n;
    return true;
  }

  /**
   * Engine addition: SCR_LuaBuildObject's conversion of a plain value - a string or number through
   * `SetLexical`, a boolean as "1" or "0" - without its warnings. Neither path logs or writes
   * anything but the destination, so a failed value can be converted again in full.
   */
  [[nodiscard]] bool TrySetPlainValue(const LuaPlus::LuaObject& value, const gpg::RRef& destination)
  {
    if (TrySetFloatDirectly(value, destination)) {
      return true;
    }
    std::string lexicalValue;
    if (LuaObjectTryToString(value, lexicalValue)) {
      return destination.mType->SetLexical(destination, lexicalValue.c_str());
    }
    if (value.IsBoolean()) {
      return destination.mType->SetLexical(destination, value.GetBoolean() ? "1" : "0");
    }
    return false;
  }

  bool sim_BlueprintTableShortcuts = true;
  moho::TConVar<bool> gTConVar_sim_BlueprintTableShortcuts(
    "sim_BlueprintTableShortcuts",
    "Blueprint fields: a table is first built without the field's log context and set again inside it only if "
    "something in it cannot be set (1, the default), or always built inside the context (0). Same values and "
    "warnings either way.",
    &sim_BlueprintTableShortcuts
  );

  /**
   * Engine addition: SCR_LuaBuildObject for a field's table without the log context it formats for
   * every table field, and without its warnings: it stops at the first value it cannot set and
   * returns false, and the caller builds the field again in full, inside the context. Every write is
   * an assignment from the table (array sizes included), so building it again gives the same object
   * and the same warnings. Enum flag tables keep the full path.
   */
  [[nodiscard]] bool TryBuildQuietly(LuaPlus::LuaObject value, const gpg::RRef& destination)
  {
    if (!value.IsTable()) {
      return TrySetPlainValue(value, destination);
    }
    if (destination.mType->IsEnumType()) {
      return false;
    }

    if (const gpg::RIndexed* const indexedType = destination.mType->IsIndexed()) {
      const int count = value.GetN();
      if (static_cast<int>(indexedType->GetCount(destination.mObj)) != count) {
        indexedType->SetCount(destination.mObj, count);
      }
      for (int index = 0; index < count; ++index) {
        if (!TryBuildQuietly(value[index + 1], indexedType->SubscriptIndex(destination.mObj, index))) {
          return false;
        }
      }
      return true;
    }

    // As SCR_LuaBuildObject with ignoreMissingFields, which every nested table is built with.
    LuaPlus::LuaTableIterator iter(&value, 1);
    while (!iter.m_isDone) {
      std::string keyName;
      if (!LuaObjectTryToString(LuaPlus::LuaObject(iter.GetKey()), keyName)) {
        return false;
      }
      if (const gpg::RField* const field = destination.mType->GetFieldNamed(keyName.c_str())) {
        const gpg::RRef fieldDestination{static_cast<std::uint8_t*>(destination.mObj) + field->mOffset, field->mType};
        if (!TryBuildQuietly(LuaPlus::LuaObject(iter.GetValue()), fieldDestination)) {
          return false;
        }
      }
      iter.Next();
    }
    return true;
  }

  /**
   * Address: 0x004D4C40 (FUN_004D4C40)
   *
   * What it does:
   * Upcasts one reflected reference to `float` and returns the typed pointee
   * on success, otherwise null.
   */
  [[nodiscard]] const float* TryUpcastFloatScalar(const gpg::RRef& source)
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(float));
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, sType);
    return upcast.mObj != nullptr ? static_cast<const float*>(upcast.mObj) : nullptr;
  }

  /**
   * Address: 0x004D4C80 (FUN_004D4C80)
   *
   * What it does:
   * Upcasts one reflected reference to `int` and returns the typed pointee on
   * success, otherwise null.
   */
  [[nodiscard]] const int* TryUpcastIntScalar(const gpg::RRef& source)
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(int));
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, sType);
    return upcast.mObj != nullptr ? static_cast<const int*>(upcast.mObj) : nullptr;
  }

  /**
   * Address: 0x004D4CC0 (FUN_004D4CC0, func_CastUint)
   *
   * What it does:
   * Upcasts one reflected reference to `unsigned int` and returns the typed
   * pointee on success, otherwise null.
   */
  [[nodiscard]] const unsigned int* TryUpcastUnsignedIntScalar(const gpg::RRef& source)
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(unsigned int));
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, sType);
    return upcast.mObj != nullptr ? static_cast<const unsigned int*>(upcast.mObj) : nullptr;
  }

  /**
   * Address: 0x004D4D00 (FUN_004D4D00, func_CastChar)
   *
   * What it does:
   * Upcasts one reflected reference to `char` and returns the typed pointee on
   * success, otherwise null.
   */
  [[nodiscard]] const char* TryUpcastCharScalar(const gpg::RRef& source)
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(char));
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, sType);
    return upcast.mObj != nullptr ? static_cast<const char*>(upcast.mObj) : nullptr;
  }

  /**
   * Address: 0x004D4D40 (FUN_004D4D40, func_CastUchar)
   *
   * What it does:
   * Upcasts one reflected reference to `unsigned char` and returns the typed
   * pointee on success, otherwise null.
   */
  [[nodiscard]] const unsigned char* TryUpcastUnsignedCharScalar(const gpg::RRef& source)
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(unsigned char));
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, sType);
    return upcast.mObj != nullptr ? static_cast<const unsigned char*>(upcast.mObj) : nullptr;
  }

  /**
   * Address: 0x004D4D80 (FUN_004D4D80, func_CastBool)
   *
   * What it does:
   * Upcasts one reflected reference to `bool` and returns the typed pointee on
   * success, otherwise null.
   */
  [[nodiscard]] const bool* TryUpcastBoolScalar(const gpg::RRef& source)
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(bool));
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, sType);
    return upcast.mObj != nullptr ? static_cast<const bool*>(upcast.mObj) : nullptr;
  }

  [[nodiscard]] LuaPlus::LuaObject MakeNilObject(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject nilObject{};
    if (state != nullptr) {
      nilObject.AssignNil(state);
    }
    return nilObject;
  }

  [[nodiscard]] bool ResolveMountedScriptPath(const char* const sourcePath, fa::string& outPath)
  {
    moho::FILE_EnsureWaitHandleSet();
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
      outPath.assign_owned(sourcePath != nullptr ? sourcePath : "");
      return !outPath.empty();
    }

    waitHandleSet->mHandle->FindFile(&outPath, sourcePath != nullptr ? sourcePath : "", nullptr);
    return !outPath.empty();
  }

  /**
   * Engine addition: `lua_HookProbeCache`. Every doscript looks for a hook file under each hook
   * directory and each active mod, and nearly all of those lookups find nothing, after walking every
   * mount. One listing per hook directory and file extension answers them. A listing lasts until
   * the file lookups are invalidated, and it isn't used with /EnableDiskWatch, where files come and
   * go, or with /nohookcache.
   */
  bool lua_HookProbeCache = true;
  moho::TConVar<bool> gTConVar_lua_HookProbeCache(
    "lua_HookProbeCache",
    "Answer doscript's hook file lookups from one listing per hook directory (1, the default), or look each one up "
    "through every mount (0). Same files either way. /nohookcache turns it off at startup.",
    &lua_HookProbeCache
  );

  [[nodiscard]] bool HookProbeVerify()
  {
    static const bool verify = [] {
      const char* const value = std::getenv("FAF_HOOK_PROBE_VERIFY");
      return value != nullptr && value[0] == '1';
    }();
    return verify;
  }

  /** False when no file can be there, so that the lookup can be skipped. */
  [[nodiscard]] bool HookFileMightExist(const char* const hookRoot, const char* const hookPath, const char* const scriptPath)
  {
    static const bool startupOff =
      moho::CFG_GetArgOption("/EnableDiskWatch", 0u, nullptr) || moho::CFG_GetArgOption("/nohookcache", 0u, nullptr);
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    if (!lua_HookProbeCache || startupOff || waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr || scriptPath == nullptr || scriptPath[0] != '/') {
      return true;
    }

    std::string root(hookRoot != nullptr ? hookRoot : "");
    root.append(hookPath != nullptr ? hookPath : "");
    std::string path = root + scriptPath;
    for (char& c : path) {
      if (c >= 'A' && c <= 'Z') {
        c = static_cast<char>(c - 'A' + 'a');
      } else if (c == '\\') {
        return true;
      }
    }
    if (path.find("//") != std::string::npos || path.find("/.") != std::string::npos) {
      return true;
    }

    // STR_MatchWildcard never matches a pattern that ends in `*`, as in the binary, so each listing
    // is of one extension: `*.lua`. Paths without a plain extension take the full lookup.
    const std::size_t lastSlash = path.rfind('/');
    const std::size_t lastDot = path.rfind('.');
    if (lastDot == std::string::npos || lastDot < lastSlash || lastDot + 1U == path.size() || path.find_first_of("*?") != std::string::npos) {
      return true;
    }
    const std::string pattern = "*" + path.substr(lastDot);
    const std::string listingKey = root + "|" + pattern;

    static std::mutex sMutex;
    static std::unordered_map<std::string, std::unordered_set<std::string>> sListings;
    static std::uint64_t sGeneration = 0;
    const std::lock_guard<std::mutex> lock(sMutex);
    const std::uint64_t generation = moho::DISK_FileLookupGeneration();
    if (generation != sGeneration) {
      sListings.clear();
      sGeneration = generation;
    }
    auto listing = sListings.find(listingKey);
    if (listing == sListings.end()) {
      fa::vector<fa::string> files;
      waitHandleSet->mHandle->EnumerateFiles(root.c_str(), pattern.c_str(), true, &files);
      std::unordered_set<std::string> names;
      names.reserve(files.size());
      for (const fa::string& file : files) {
        names.emplace(file.c_str());
      }
      listing = sListings.emplace(listingKey, std::move(names)).first;
    }
    return listing->second.count(path) != 0U;
  }

  void TryAppendHookScriptPath(
    fa::vector<fa::string>& outFiles,
    const char* const scriptPath,
    const fa::string& candidatePath,
    const bool mightExist
  )
  {
    if (!mightExist && !HookProbeVerify()) {
      return;
    }
    fa::string resolvedPath{};
    if (!ResolveMountedScriptPath(candidatePath.c_str(), resolvedPath) || resolvedPath.empty()) {
      return;
    }
    if (!mightExist) {
      gpg::Warnf("hook probe verify: the listing misses %s", candidatePath.c_str());
    }

    gpg::Logf("Hooked %s with %s", scriptPath != nullptr ? scriptPath : "", candidatePath.c_str());
    outFiles.push_back(resolvedPath);
  }

  [[nodiscard]] fa::string BuildHookCandidatePath(
    const char* const rootPath,
    const char* const hookPath,
    const char* const scriptPath
  )
  {
    fa::string candidate(rootPath != nullptr ? rootPath : "");
    candidate.append(hookPath != nullptr ? hookPath : "");
    candidate.append(scriptPath != nullptr ? scriptPath : "");
    return candidate;
  }

  void CollectActiveModHookScripts(
    LuaPlus::LuaState* const state,
    const char* const scriptPath,
    fa::vector<fa::string>& outFiles
  )
  {
    const LuaPlus::LuaObject activeMods = state->GetGlobal(kActiveModsGlobalName);
    if (!activeMods) {
      return;
    }

    for (int modIndex = 1;; ++modIndex) {
      const LuaPlus::LuaObject modObject = activeMods[modIndex];
      if (!modObject) {
        break;
      }

      const LuaPlus::LuaObject locationObject = modObject[kLocationFieldName];
      if (!locationObject) {
        continue;
      }

      const char* const modLocation = locationObject.ToString();
      if (modLocation == nullptr || *modLocation == '\0') {
        continue;
      }

      const LuaPlus::LuaObject hookDirObject = modObject[kHookDirFieldName];
      const char* hookDir = hookDirObject ? hookDirObject.ToString() : kDefaultHookDirPath;
      if (hookDir == nullptr || *hookDir == '\0') {
        hookDir = kDefaultHookDirPath;
      }

      const fa::string candidatePath = BuildHookCandidatePath(modLocation, hookDir, scriptPath);
      TryAppendHookScriptPath(outFiles, scriptPath, candidatePath, HookFileMightExist(modLocation, hookDir, scriptPath));
    }
  }

  /**
   * Address: 0x004CDCF0 (FUN_004CDCF0, func_LuaFileLoader)
   *
   * What it does:
   * Returns one mapped-file chunk exactly once for `lua_load`, then reports EOF.
   */
  const char* func_LuaFileLoader(
    lua_State* const state, void* const userData, std::size_t* const outSize
  )
  {
    (void)state;
    auto* const loaderData = static_cast<LuaFileLoaderDat*>(userData);

    const char* const begin = loaderData->buf.mBegin;
    if (begin == nullptr) {
      return nullptr;
    }

    const std::size_t byteCount = static_cast<std::size_t>(loaderData->buf.mEnd - begin);
    if (byteCount == 0u || loaderData->done) {
      return nullptr;
    }

    *outSize = byteCount;
    loaderData->done = true;
    return loaderData->buf.mBegin;
  }

  /**
   * Address: 0x004CDD40 (FUN_004CDD40, sub_4CDD40)
   *
   * What it does:
   * Streams concatenated script data to `lua_load`, mapping each file in order
   * and injecting one synthetic newline between chunks when needed.
   */
  const char* ReadLoadConcatChunk(LuaConcatLoadData* const data, std::size_t* const outSize)
  {
    if (data->pendingTrailingNewline) {
      data->pendingTrailingNewline = false;
      *outSize = 1u;
      return kConcatSyntheticNewline;
    }

    while (true) {
      const fa::vector<fa::string>* const files = data->files;
      if (files == nullptr || data->nextFileIndex >= files->size()) {
        return nullptr;
      }

      const fa::string& filePath = (*files)[data->nextFileIndex];
      ++data->nextFileIndex;

      data->currentChunk = moho::DISK_MemoryMapFile(filePath.c_str());
      if (data->currentChunk.mBegin == nullptr) {
        gpg::Warnf("Can't open lua file \"%s\"", filePath.c_str());
        continue;
      }

      if (data->currentChunk.mEnd == data->currentChunk.mBegin) {
        continue;
      }

      data->pendingTrailingNewline = data->currentChunk.mEnd[-1] != '\n';
      *outSize = static_cast<std::size_t>(data->currentChunk.mEnd - data->currentChunk.mBegin);
      return data->currentChunk.mBegin;
    }
  }

  /**
   * Address: 0x004CDF40 (FUN_004CDF40, func_LoadConcat)
   *
   * What it does:
   * Lua chunk-reader shim that forwards concat-loader state into
   * `ReadLoadConcatChunk`.
   */
  const char* func_LoadConcat(lua_State* const state, void* const userData, std::size_t* const outSize)
  {
    (void)state;
    if (userData == nullptr) {
      return nullptr;
    }

    return ReadLoadConcatChunk(static_cast<LuaConcatLoadData*>(userData), outSize);
  }

  /**
   * Address: 0x004CEEB0 (FUN_004CEEB0, func_ParseNumList)
   *
   * What it does:
   * Parses a Lua key->bool table into a `|`-delimited lexical enum string and
   * writes it through the reflected destination type.
   */
  [[nodiscard]] bool ParseEnumFlagTable(LuaPlus::LuaObject tableObject, const gpg::RRef& destination)
  {
    std::string lexicalValue;

    LuaPlus::LuaState* const activeState = tableObject.GetActiveState();
    LuaPlus::LuaTableIterator iter(&tableObject, 1);
    while (!iter.m_isDone) {
      LuaPlus::LuaObject keyObject(iter.GetKey());
      std::string keyText;
      if (!LuaObjectTryToString(keyObject, keyText)) {
        gpg::Die("Bad key for lua enum, expected string, got %s", LuaObjectTypeName(keyObject));
      }

      LuaPlus::LuaObject valueObject(iter.GetValue());
      valueObject.PushStack(activeState);
      const bool includeKey = lua_toboolean(activeState->m_state, -1) != 0;
      lua_settop(activeState->m_state, -2);

      if (includeKey) {
        if (!lexicalValue.empty()) {
          lexicalValue.push_back('|');
        }
        lexicalValue += keyText;
      }

      iter.Next();
    }

    if (lexicalValue.empty()) {
      lexicalValue = "0";
    }

    if (!destination.mType->SetLexical(destination, lexicalValue.c_str())) {
      gpg::Die(
        "Invalid value for %s at %p: %s",
        ReflectedTypeNameOrNull(destination.mType),
        destination.mObj,
        lexicalValue.c_str()
      );
    }

    return true;
  }
}

namespace moho
{
  int32_t CScrLuaObjectFactory::sNumIds = 0;
  CScrLuaMetatableFactory<CScriptObject*> CScrLuaMetatableFactory<CScriptObject*>::sInstance{};

  /**
   * Address: 0x00BC60D0 (FUN_00BC60D0)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered `CScrLuaMetatableFactory<CScriptObject*>` startup index lane.
   */
  int register_CScrLuaMetatableFactory_CScriptObject_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<CScriptObject*>::Instance().SetFactoryObjectIndexForRecovery(index);
    gRecoveredCScrLuaMetatableFactoryCScriptObjectIndex = index;
    return index;
  }

  /**
   * Address: 0x004C8500 (FUN_004C8500)
   *
   * What it does:
   * Initializes the `CScriptObject*` metatable-factory singleton index lane
   * and returns that singleton address.
   */
  [[maybe_unused]] CScrLuaMetatableFactory<CScriptObject*>* InitializeCScriptObjectMetatableFactorySingleton()
  {
    (void)register_CScrLuaMetatableFactory_CScriptObject_Index();
    return &CScrLuaMetatableFactory<CScriptObject*>::Instance();
  }

  /**
   * Address: 0x004D22D0 (FUN_004D22D0, ?SCR_CreateSimpleMetatable@Moho@@YA?AVLuaObject@LuaPlus@@PAVLuaState@3@@Z)
   * Alias:   0x100C3290 (alt lane)
   */
  LuaPlus::LuaObject SCR_CreateSimpleMetatable(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject metatable;
    metatable.AssignNewTable(state, 0, 0);
    metatable.SetObject("__index", metatable);
    return metatable;
  }

  /**
   * Engine addition: see the header.
   */
  void SCR_ExpectExactArgs(LuaPlus::LuaState* const state, const int expectedArgs, const char* const helpText)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != expectedArgs) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", helpText, expectedArgs, argumentCount);
    }
  }

  /**
   * Address: 0x004D2380 (FUN_004D2380, ?SCR_ExpectArgs@Moho@@YAXPAVLuaState@LuaPlus@@HHPBD@Z)
   *
   * What it does:
   * Validates Lua argument count in `[minArgs, maxArgs]` (or `>= minArgs`
   * when `maxArgs == -1`) and raises LuaState::Error with `helpText` on
   * mismatch.
   */
  void SCR_ExpectArgs(
    LuaPlus::LuaState* const state,
    const int maxArgs,
    const int minArgs,
    const char* const helpText
  )
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < minArgs || (maxArgs != -1 && argumentCount > maxArgs)) {
      if (maxArgs == -1) {
        LuaPlus::LuaState::Error(
          state,
          "%s\n  expected at least %d args, but got %d",
          helpText,
          minArgs,
          argumentCount
        );
      } else {
        LuaPlus::LuaState::Error(
          state,
          "%s\n  expected between %d and %d args, but got %d",
          helpText,
          minArgs,
          maxArgs,
          argumentCount
        );
      }
    }
  }

  /**
   * Address: 0x004D3250 (FUN_004D3250, ?SCR_Import@Moho@@YA?AVLuaObject@LuaPlus@@PAVLuaState@3@VStrArg@gpg@@@Z)
   *
   * What it does:
   * Calls global `import(modulePath)` and returns its result, restoring the
   * Lua stack top on the way out (LuaAutoBlock, unwind action 0x00B81F10).
   * A script error while importing is caught (runtime_error, FuncInfo
   * 0x00ED0CA4), logged as "Error importing %s:\n%s", and answers nil.
   */
  LuaPlus::LuaObject SCR_Import(LuaPlus::LuaState* const state, const gpg::StrArg modulePath)
  {
    const LuaPlus::LuaAutoBlock autoBlock(state);
    try {
      lua_State* const lstate = state->m_state;
      lua_pushstring(lstate, "import");
      lua_gettable(lstate, LUA_GLOBALSINDEX);
      lua_pushstring(lstate, modulePath);
      lua_call(lstate, 1, 1);
      return LuaPlus::LuaObject(state, -1);
    } catch (const fa::runtime_error& error) {
      gpg::Warnf("Error importing %s:\n%s", modulePath, error.what());
      return LuaPlus::LuaObject(state);
    }
  }

  LuaPlus::LuaObject SCR_ImportLuaModule(LuaPlus::LuaState* const state, const char* const modulePath)
  {
    if (!state || !modulePath || !*modulePath) {
      return {};
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return {};
    }

    const int savedTop = lua_gettop(lstate);
    lua_getglobal(lstate, "import");
    if (!lua_isfunction(lstate, -1)) {
      lua_settop(lstate, savedTop);
      return {};
    }

    lua_pushstring(lstate, modulePath);
    if (LuaCallProtected(lstate, 1, 1) != 0) {
      lua_settop(lstate, savedTop);
      return {};
    }

    LuaPlus::LuaObject moduleObject{LuaPlus::LuaStackObject(state, -1)};
    lua_settop(lstate, savedTop);
    return moduleObject;
  }

  /**
   * Every engine call site this stands in for reads the field with
   * LuaPlus::LuaObject::GetByName, behind an IsTable check where the receiver
   * could be anything else (see the "_c_object" unwrapping in FUN_004209D0 and
   * FUN_004A7DD0, and the module lookups in FUN_0057A350 / FUN_005B7220). That
   * is a raw table read: no __index metamethod runs, so a key the table does
   * not hold itself is simply nil instead of being escalated to the module
   * environment chain, which in the shipped Lua ends at a handler that raises.
   */
  LuaPlus::LuaObject
  SCR_GetLuaTableField(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& tableObj, const char* const fieldName)
  {
    if (!state || !fieldName || !*fieldName || !tableObj.IsTable()) {
      return {};
    }

    return tableObj.GetByName(fieldName);
  }

  LuaPlus::LuaObject SCR_GetLuaTableFieldOrThrow(
    const LuaPlus::LuaObject& tableObj,
    const char* const fieldName,
    const char* const missingTableMessage,
    const char* const missingFieldFormat
  )
  {
    if (tableObj.IsNil()) {
      throw std::runtime_error(missingTableMessage != nullptr ? missingTableMessage : "Lua table is unavailable.");
    }

    if (!tableObj.IsTable()) {
      throw std::runtime_error(
        gpg::STR_Printf(
          missingFieldFormat != nullptr ? missingFieldFormat : "Lua table field \"%s\" is unavailable.",
          fieldName != nullptr ? fieldName : ""
        )
          .c_str()
      );
    }

    LuaPlus::LuaState* const state = tableObj.GetActiveState();
    LuaPlus::LuaObject fieldObject = SCR_GetLuaTableField(state, tableObj, fieldName);
    if (fieldObject.IsNil()) {
      throw std::runtime_error(
        gpg::STR_Printf(
          missingFieldFormat != nullptr ? missingFieldFormat : "Lua table field \"%s\" is unavailable.",
          fieldName != nullptr ? fieldName : ""
        )
          .c_str()
      );
    }

    return fieldObject;
  }

  /**
   * Address: 0x004D23D0 (FUN_004D23D0, ?SCR_QuoteLuaString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@@Z)
   *
   * What it does:
   * Returns one Lua-quoted string literal with escaping for matching quote
   * char, backslash, tab/newline, and non-printable bytes.
   */
  fa::string SCR_QuoteLuaString(const gpg::StrArg text)
  {
    const char* const source = text != nullptr ? text : "";

    fa::string quoted{};
    const char quoteChar = std::strchr(source, '\'') != nullptr ? '"' : '\'';
    quoted.push_back(quoteChar);

    for (const char* cursor = source; *cursor != '\0'; ++cursor) {
      const char ch = *cursor;
      if (ch == quoteChar || ch == '\\') {
        quoted.push_back('\\');
        quoted.push_back(ch);
        continue;
      }

      if (ch == '\n') {
        quoted.append("\\n");
        continue;
      }

      if (ch == '\t') {
        quoted.append("\\t");
        continue;
      }

      const unsigned char u = static_cast<unsigned char>(ch);
      if (u < 32u || u > 126u) {
        quoted.append(gpg::STR_Printf("\\%03d", static_cast<int>(static_cast<signed char>(ch))).view());
        continue;
      }

      quoted.push_back(ch);
    }

    quoted.push_back(quoteChar);
    return quoted;
  }

  /**
   * Address: 0x004D2F70 (FUN_004D2F70)
   */
  fa::string SCR_ToString(const LuaPlus::LuaObject& object)
  {
    gpg::MemBufferStream stream(256u);
    LuaPlus::LuaObject copy = object;
    (void)copy.ToByteStream(stream);

    const std::size_t serializedSize = stream.BytesWritten();
    if (serializedSize == 0u || stream.mWriteStart == nullptr) {
      return {};
    }

    return fa::string(stream.mWriteStart, serializedSize);
  }

  /**
   * Address: 0x004D31D0 (FUN_004D31D0, ?SCR_ToBool@Moho@@YA_NABVLuaObject@LuaPlus@@@Z)
   *
   * What it does:
   * Converts one Lua object to bool using Moho script semantics:
   * numeric non-zero is true; case-insensitive string `"true"`, `"on"`, or
   * `"yes"` is true; every other value is false.
   */
  bool SCR_ToBool(const LuaPlus::LuaObject& object)
  {
    if (object.IsNumber()) {
      return object.GetInteger() != 0;
    }

    if (object.IsString()) {
      const char* const valueTrue = object.GetString();
      if (_stricmp(valueTrue, "true") == 0) {
        return true;
      }

      const char* const valueOn = object.GetString();
      if (_stricmp(valueOn, "on") == 0) {
        return true;
      }

      const char* const valueYes = object.GetString();
      if (_stricmp(valueYes, "yes") == 0) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x004D26D0 (FUN_004D26D0, ?SCR_Copy@Moho@@YA?AVLuaObject@LuaPlus@@ABV23@PAVLuaState@3@@Z)
   *
   * What it does:
   * Deep-copies one Lua object into `state`, recursively cloning tables and
   * cloning userdata with reflected move handlers when crossing root-state
   * boundaries.
   */
  namespace
  {
    /**
     * Engine addition: SCR_Copy's table case without a LuaObject per key and value. The entries
     * are visited in LuaTableIterator's order - the array part, then the hash nodes - and created
     * and inserted through the same luaH_new / luaS_newlstr / luaV_settable calls in the same
     * sequence, so every copied table is laid out, and iterates, exactly as before. A nested table
     * is inserted before it is filled, so it is reachable from the anchored root should a userdata
     * copy run the collector; anything but a boolean, number, string or table goes through SCR_Copy.
     */
    void CopyTableEntries(
      lua_State* const L, const Table* const source, const LuaPlus::TObject& target,
      LuaPlus::LuaState* const sourceState, LuaPlus::LuaState* const targetState
    )
    {
      // `holder` keeps a value copied through SCR_Copy alive until it is in the table.
      const auto copy = [&](const LuaPlus::TObject& value, LuaPlus::LuaObject& holder) {
        LuaPlus::TObject out = value; // a boolean or number is the same value in either universe
        if (value.tt == LUA_TSTRING) {
          const char* const text = static_cast<const TString*>(value.value.p)->str;
          TString* const interned = luaS_newlstr(L, text, std::strlen(text));
          out.tt = interned->tt;
          out.value.p = interned;
        } else if (value.tt != LUA_TBOOLEAN && value.tt != LUA_TNUMBER) {
          LuaPlus::LuaObject original{};
          original.AssignTObject(sourceState, const_cast<LuaPlus::TObject*>(&value));
          holder = SCR_Copy(original, targetState);
          out = holder.m_object;
        }
        return out;
      };
      const auto copyEntry = [&](const LuaPlus::TObject& key, const LuaPlus::TObject& value) {
        LuaPlus::LuaObject keyHolder{};
        LuaPlus::TObject keyCopy = copy(key, keyHolder);
        if (value.tt == LUA_TTABLE) {
          // lua_SessionSharedBlueprints: inside an SCR_CopySharedTablesScope a table reached twice is
          // copied once, as SCR_Copy's own table case does (keyed, as there, by lua_topointer's answer).
          const void* const sharedKey = static_cast<const void*>(value.value.p);
          if (tCopiedTables != nullptr) {
            if (const auto found = tCopiedTables->find(sharedKey); found != tCopiedTables->end()) {
              LuaPlus::TObject shared = found->second.m_object;
              luaV_settable(L, &target, &keyCopy, &shared);
              return;
            }
          }
          Table* const childTable = luaH_new(L, 0, luaO_log2(0u) + 1);
          LuaPlus::TObject child{};
          child.tt = childTable->tt;
          child.value.p = childTable;
          luaV_settable(L, &target, &keyCopy, &child);
          if (tCopiedTables != nullptr) {
            LuaPlus::LuaObject held{};
            held.AssignTObject(targetState, &child);
            tCopiedTables->emplace(sharedKey, held);
          }
          CopyTableEntries(L, static_cast<const Table*>(value.value.p), child, sourceState, targetState);
          return;
        }
        LuaPlus::LuaObject valueHolder{};
        LuaPlus::TObject valueCopy = copy(value, valueHolder);
        luaV_settable(L, &target, &keyCopy, &valueCopy);
      };

      for (int index = 0; index < source->sizearray; ++index) {
        if (source->array[index].tt != LUA_TNIL) {
          copyEntry(LuaPlus::TObject(index + 1), source->array[index]);
        }
      }
      for (int index = 0; index < (1 << source->lsizenode); ++index) {
        if (source->node[index].i_val.tt != LUA_TNIL) {
          copyEntry(source->node[index].Key(), source->node[index].i_val);
        }
      }
    }
  } // namespace

  SCR_CopySharedTablesScope::SCR_CopySharedTablesScope()
  {
    if (lua_SessionSharedBlueprints && tCopiedTables == nullptr) {
      tCopiedTables = new std::unordered_map<const void*, LuaPlus::LuaObject>();
      mActive = true;
    }
  }

  SCR_CopySharedTablesScope::~SCR_CopySharedTablesScope()
  {
    if (mActive) {
      delete tCopiedTables;
      tCopiedTables = nullptr;
    }
  }

  LuaPlus::LuaObject SCR_Copy(const LuaPlus::LuaObject& source, LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject out{};
    if (source.m_state == nullptr) {
      return out;
    }

    switch (source.Type()) {
      case LUA_TNIL:
        out.AssignNil(state);
        return out;

      case LUA_TBOOLEAN:
        out.AssignBoolean(state, source.GetBoolean());
        return out;

      case LUA_TNUMBER:
        out.AssignNumber(state, source.GetNumber());
        return out;

      case LUA_TSTRING:
        if (source.m_state == state->m_rootState) {
          out = source;
        } else {
          out.AssignString(state, source.GetString());
        }
        return out;

      case LUA_TTABLE: {
        const void* sharedKey = nullptr;
        if (tCopiedTables != nullptr) {
          LuaPlus::LuaState* const sourceState = source.GetActiveState();
          lua_State* const rawSource = sourceState->GetCState();
          const int savedTop = lua_gettop(rawSource);
          source.PushStack(sourceState);
          sharedKey = lua_topointer(rawSource, -1);
          lua_settop(rawSource, savedTop);
          const auto found = tCopiedTables->find(sharedKey);
          if (found != tCopiedTables->end()) {
            return found->second;
          }
        }
        out.AssignNewTable(state, 0, 0);
        if (sharedKey != nullptr) {
          tCopiedTables->emplace(sharedKey, out);
        }
        // Engine addition (sim_BlueprintCopyDirect): across universes - the rules' blueprints into a
        // session or sim state - the entries are copied directly (CopyTableEntries), which builds
        // the same tables.
        if (sim_BlueprintCopyDirect && source.m_state != state->m_rootState) {
          CopyTableEntries(
            out.GetActiveCState(), static_cast<const Table*>(source.m_object.value.p), out.m_object, source.m_state, state
          );
          return out;
        }
        LuaPlus::LuaObject mutableSource(source);
        for (LuaPlus::LuaTableIterator iter(mutableSource, 1); !iter.m_isDone; iter.Next()) {
          const LuaPlus::LuaObject keyCopy = SCR_Copy(iter.GetKey(), state);
          const LuaPlus::LuaObject valueCopy = SCR_Copy(iter.GetValue(), state);
          out.SetObject(keyCopy, valueCopy);
        }
        return out;
      }

      case LUA_TUSERDATA:
        if (source.m_state == state->m_rootState) {
          out = source;
          return out;
        }

        {
          // The reference lives in the userdata HEADER, not in its payload:
          // `Udata::len` carries the `gpg::RType*` and the value itself starts
          // one header further on. Reading `*(gpg::RRef*)lua_touserdata(...)`
          // instead took the first eight payload bytes as if they were a
          // reference, so this clone copied from a bogus address through
          // whatever type those bytes happened to spell.
          const gpg::RRef userDataRef = source.GetUserData();

          if (userDataRef.mType->movRefFunc_ == nullptr) {
            gpg::Die("Can't clone %s userdata.", userDataRef.mType->GetName());
          }

          (void)out.AssignNewUserData(state, userDataRef);
        }
        return out;

      default:
        if (source.m_state != state->m_rootState) {
          gpg::Die(
            "Can't copy lua objects of type %s from one state to another.",
            source.TypeName()
          );
        }

        out = source;
        return out;
    }
  }

  /**
   * Address: 0x004CF0B0 (FUN_004CF0B0, ?SCR_RObjectToLuaMerge@Moho@@YAXABVRRef@gpg@@AAVLuaObject@LuaPlus@@@Z)
   *
   * What it does:
   * Recursively merges one reflected source object/reference into an existing
   * Lua object, handling primitive upcasts, pointers, indexed ranges, and
   * named reflected fields.
   */
  void SCR_RObjectToLuaMerge(const gpg::RRef& source, LuaPlus::LuaObject& destination)
  {
    LuaPlus::LuaState* const state = destination.GetActiveState();
    if (state == nullptr || source.mType == nullptr) {
      return;
    }

    if (const float* const value = TryUpcastFloatScalar(source); value != nullptr) {
      destination.AssignNumber(state, *value);
      return;
    }

    if (const int* const value = TryUpcastIntScalar(source); value != nullptr) {
      destination.AssignNumber(state, static_cast<double>(*value));
      return;
    }

    if (const unsigned int* const value = TryUpcastUnsignedIntScalar(source); value != nullptr) {
      destination.AssignNumber(state, static_cast<double>(*value));
      return;
    }

    if (const char* const value = TryUpcastCharScalar(source); value != nullptr) {
      destination.AssignNumber(state, static_cast<double>(*value));
      return;
    }

    if (const unsigned char* const value = TryUpcastUnsignedCharScalar(source); value != nullptr) {
      destination.AssignNumber(state, static_cast<double>(*value));
      return;
    }

    if (const bool* const value = TryUpcastBoolScalar(source); value != nullptr) {
      destination.AssignBoolean(state, *value);
      return;
    }

    if (source.mType->IsPointer() != nullptr) {
      if (source.GetCount() > 0u) {
        SCR_RObjectToLuaMerge(source[0], destination);
      } else {
        destination.AssignNil(state);
      }
      return;
    }

    if (source.mType->IsIndexed() != nullptr) {
      const int count = static_cast<int>(source.GetCount());
      if (!destination.IsTable()) {
        destination.AssignNewTable(state, count, 0u);
      }

      const int existingCount = destination.GetN();
      for (int index = 1; index <= count; ++index) {
        LuaPlus::LuaObject elementObject = destination[index];
        SCR_RObjectToLuaMerge(source[static_cast<unsigned int>(index - 1)], elementObject);
        destination.SetObject(index, elementObject);
      }

      if (existingCount > count) {
        LuaPlus::LuaObject nilObject = MakeNilObject(state);
        for (int index = count + 1; index <= existingCount; ++index) {
          destination.SetObject(index, nilObject);
        }
      }
      return;
    }

    const int fieldCount = source.GetNumFields();
    if (fieldCount > 0) {
      if (!destination.IsTable()) {
        destination.AssignNewTable(state, 0, static_cast<unsigned int>(fieldCount));
      }

      for (int fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex) {
        const char* const fieldName = source.GetFieldName(fieldIndex);
        if (fieldName == nullptr || *fieldName == '\0') {
          continue;
        }

        LuaPlus::LuaObject fieldObject = destination[fieldName];
        SCR_RObjectToLuaMerge(source.GetField(fieldIndex), fieldObject);
        destination.SetObject(fieldName, fieldObject);
      }
      return;
    }

    const fa::string lexicalValue = source.GetLexical();
    destination.AssignString(state, lexicalValue.c_str());
  }

  /**
   * Address: 0x004CF4A0 (FUN_004CF4A0, ?SCR_RObjectToLua@Moho@@...)
   *
   * What it does:
   * Builds one Lua object initialized as `nil` and merges one reflected source
   * reference into it.
   */
  LuaPlus::LuaObject SCR_RObjectToLua(const gpg::RRef& source, LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject out{};
    out.AssignNil(state);
    SCR_RObjectToLuaMerge(source, out);
    return out;
  }

  /**
   * Address: 0x004D2550 (FUN_004D2550, ?SCR_GetEnum@Moho@@YAXPAVLuaState@LuaPlus@@VStrArg@gpg@@AAVRRef@5@@Z)
   *
   * What it does:
   * Parses one enum lexical token into the destination reflected reference.
   * When parsing fails, builds a full "Valid Options" list from the enum
   * descriptor and raises a Lua error.
   */
  void SCR_GetEnum(LuaPlus::LuaState* const state, const gpg::StrArg enumString, gpg::RRef& ref)
  {
    const char* const lexicalValue = enumString != nullptr ? enumString : "";
    if (ref.SetLexical(lexicalValue)) {
      return;
    }

    fa::string validOptions{};
    if (const gpg::REnumType* const enumType = ref.mType != nullptr ? ref.mType->IsEnumType() : nullptr; enumType) {
      const fa::vector<gpg::REnumType::ROptionValue>& options = enumType->GetEnumOptions();
      for (const gpg::REnumType::ROptionValue* it = options.begin(); it != options.end(); ++it) {
        validOptions.append(gpg::STR_Printf("   %s\n", it->mName != nullptr ? it->mName : "").view());
      }
    }

    const fa::string errorMessage =
      gpg::STR_Printf("Invalid enum value %s\nValid Options are:\n%s", lexicalValue, validOptions.c_str());
    LuaPlus::LuaState::Error(state, "%s", errorMessage.c_str());
  }

  /**
   * Address: 0x004CDBA0 (FUN_004CDBA0, ?SCR_LuaDoString@Moho@@YA_NPAVLuaState@LuaPlus@@VStrArg@gpg@@PAVLuaObject@3@@Z)
   *
   * What it does:
   * Loads and executes one Lua chunk from `scriptText`, warns on compile/runtime
   * failures, and restores the caller's original Lua stack top.
   */
  bool SCR_LuaDoString(const char* const scriptText, LuaPlus::LuaState* const state)
  {
    if (!scriptText || !state || !state->m_state) {
      return false;
    }

    lua_State* const rawState = state->m_state;
    const int savedTop = lua_gettop(rawState);
    const int loadStatus = luaL_loadbuffer(rawState, scriptText, std::strlen(scriptText), scriptText);
    const int runStatus = (loadStatus == 0) ? LuaCallProtected(rawState, 0, LUA_MULTRET) : 0;

    if (loadStatus != 0 || runStatus != 0) {
      LuaPlus::LuaStackObject errorObject{};
      errorObject.m_state = state;
      errorObject.m_stackIndex = -1;

      const char* errorText = lua_tostring(rawState, -1);
      if (errorText == nullptr) {
        LuaPlus::LuaStackObject::TypeError(&errorObject, "string");
        errorText = lua_tostring(rawState, -1);
      }

      gpg::Warnf("Error running lua command: %s", errorText != nullptr ? errorText : "<unknown>");
      lua_settop(rawState, savedTop);
      return false;
    }

    lua_settop(rawState, savedTop);
    return true;
  }

  /**
   * Address: 0x004CE020 (FUN_004CE020, ?SCR_LuaDoFile@Moho@@YA_NPAVLuaState@LuaPlus@@VStrArg@gpg@@PAVLuaObject@3@@Z)
   *
   * IDA signature:
   * bool __usercall Moho::SCR_LuaDoFile@<al>(LuaPlus::LuaState *state@<edi>, const char *filename, LuaPlus::LuaObject *env);
   *
   * What it does:
   * Memory-maps `filename` via DISK_MemoryMapFile, builds an `@filename` chunk
   * label, lua_loads the buffer through the single-shot file loader, optionally
   * sets a caller fenv, runs the chunk, and restores the saved Lua stack top
   * on every exit path. Logs Warnf with file context for open / load / run
   * failures and returns false in those cases.
   */
  bool SCR_LuaDoFile(LuaPlus::LuaState* const state, const char* const filename, LuaPlus::LuaObject* const env)
  {
    if (state == nullptr || state->m_state == nullptr || filename == nullptr) {
      return false;
    }

    lua_State* const rawState = state->m_state;
    const int savedTop = lua_gettop(rawState);

    // Map the script source into memory.
    gpg::MemBuffer<const char> mappedFile = moho::DISK_MemoryMapFile(filename);
    if (mappedFile.mBegin == nullptr) {
      gpg::Warnf("Can't open lua file \"%s\"", filename);
      lua_settop(rawState, savedTop);
      return false;
    }

    // Drive lua_load with the single-shot file loader.
    LuaFileLoaderDat loaderData{};
    loaderData.buf = mappedFile;
    loaderData.done = false;

    const fa::string chunkName = gpg::STR_Printf("@%s", filename);
    const int loadStatus = lua_load(
      rawState,
      reinterpret_cast<lua_Chunkreader>(func_LuaFileLoader),
      &loaderData,
      chunkName.c_str()
    );

    if (loadStatus != 0) {
      LuaPlus::LuaStackObject errorObject{};
      errorObject.m_state = state;
      errorObject.m_stackIndex = -1;

      const char* errorText = lua_tostring(rawState, -1);
      if (errorText == nullptr) {
        LuaPlus::LuaStackObject::TypeError(&errorObject, "string");
      }

      gpg::Warnf("Loading \"%s\" failed: %s", filename, errorText);
      lua_settop(rawState, savedTop);
      return false;
    }

    if (env != nullptr) {
      env->PushStack(state);
      lua_setfenv(rawState, -2);
    }

    // `lua_call` is this fork's protected call and returns the status directly
    // (see LuaPrimitives.h). Reaching for the prebuilt lua_pcall instead put a
    // stock-layout walker over our lua_State and, because that one protects
    // with setjmp, let the C++ error unwind straight past here.
    if (LuaCallProtected(rawState, 0, 0) != 0) {
      LuaPlus::LuaStackObject errorStackObject{};
      errorStackObject.m_state = state;
      errorStackObject.m_stackIndex = -1;
      const char* const errorText = errorStackObject.GetString();
      gpg::Warnf("Running \"%s\" failed: %s", filename, errorText);
      lua_settop(rawState, savedTop);
      return false;
    }

    lua_settop(rawState, savedTop);
    return true;
  }

  /**
   * Address: 0x004CEA20 (FUN_004CEA20, ?SCR_LuaDoScript@Moho@@YA_NPAVLuaState@LuaPlus@@VStrArg@gpg@@PAVLuaObject@3@@Z)
   *
   * What it does:
   * Executes one script path through `func_LuaDoScript`, restores the Lua
   * stack top on both success/failure paths, and reports caught exceptions.
   */
  bool SCR_LuaDoScript(
    LuaPlus::LuaState* const state,
    const gpg::StrArg scriptPath,
    LuaPlus::LuaObject* const outEnvironment
  )
  {
    if (state == nullptr || state->m_state == nullptr) {
      return false;
    }

    const char* const filePath = scriptPath != nullptr ? scriptPath : "";
    lua_State* const rawState = state->m_state;
    const int savedTop = lua_gettop(rawState);

    try {
      func_LuaDoScript(state, filePath, outEnvironment);
    } catch (const std::exception& exception) {
      gpg::Warnf("Error in file %s : %s", filePath, exception.what() != nullptr ? exception.what() : "");
      lua_settop(rawState, savedTop);
      return false;
    } catch (...) {
      gpg::Warnf("Error in file %s : %s", filePath, "<unknown>");
      lua_settop(rawState, savedTop);
      return false;
    }

    lua_settop(rawState, savedTop);
    return true;
  }

  /**
   * Address: 0x004CECD0 (FUN_004CECD0, Moho::SCR_LuaDoFileConcat)
   *
   * What it does:
   * Concatenates mapped script files, compiles the merged chunk, optionally
   * applies one environment table, then executes the loaded chunk.
   */
  void SCR_LuaDoFileConcat(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const outEnvironment,
    fa::vector<fa::string> files
  )
  {
    if (files.empty()) {
      gpg::Warnf("SCR_LuaDoFileConcat: No files specified");
      return;
    }

    LuaConcatLoadData loadData{};
    loadData.files = &files;
    loadData.nextFileIndex = 0;
    loadData.pendingTrailingNewline = false;

    const fa::string chunkName = gpg::STR_Printf("@%s", files.front().c_str());
    int loadStatus = 0;
    if (SCR_ScriptChunkCacheActive()) {
      // Engine addition (res_ScriptChunkCache): the text lua_load would stream, then its function
      // from the script cache when that holds the same text.
      std::string source;
      std::size_t blockSize = 0;
      while (const char* const block = ReadLoadConcatChunk(&loadData, &blockSize)) {
        source.append(block, blockSize);
      }
      loadStatus = SCR_LoadScriptChunk(state->m_state, source, chunkName.c_str());
    } else {
      loadStatus = lua_load(
        state->m_state,
        reinterpret_cast<lua_Chunkreader>(func_LoadConcat),
        &loadData,
        chunkName.c_str()
      );
    }
    if (loadStatus != 0) {
      LuaPlus::LuaStackObject errorObject{};
      errorObject.m_state = state;
      errorObject.m_stackIndex = -1;

      const char* const errorText = lua_tostring(state->m_state, -1);
      if (errorText == nullptr) {
        LuaPlus::LuaStackObject::TypeError(&errorObject, "string");
      }

      gpg::Warnf(
        "SCR_LuaDoFileConcat: Loading \"%s\" failed: %s",
        files.front().c_str(),
        errorText
      );
      return;
    }

    if (outEnvironment != nullptr) {
      outEnvironment->PushStack(state);
      lua_setfenv(state->m_state, -2);
    }

    // Unprotected on purpose: the binary reaches the exported lua_call here,
    // not the status-returning one. Swallowing the error leaves the module's
    // environment holding only what import() seeded it with, and every later
    // lookup into that module quietly takes a fallback path instead.
    LuaCallUnprotected(state->m_state, 0, 0);
  }

  /**
   * Address: 0x004CE2C0 (FUN_004CE2C0, func_LuaDoScript)
   *
   * What it does:
   * Resolves a base script path, appends legacy hook directories and active-mod
   * hook overlays, then executes the concatenated file chain.
   */
  void func_LuaDoScript(
    LuaPlus::LuaState* const state,
    const char* const scriptPath,
    LuaPlus::LuaObject* const outEnvironment
  )
  {
    if (state == nullptr || scriptPath == nullptr || *scriptPath == '\0') {
      return;
    }

    fa::string resolvedPath{};
    if (!ResolveMountedScriptPath(scriptPath, resolvedPath) || resolvedPath.empty()) {
      const fa::string errorText = gpg::STR_Printf("Unable to find file %s", scriptPath);
      LuaPlus::LuaState::Error(state, "%s", errorText.c_str());
    }

    fa::vector<fa::string> files{};
    files.push_back(resolvedPath);

    for (const fa::string& hookDirectory : gScriptHookDirectories) {
      const fa::string candidatePath = BuildHookCandidatePath(hookDirectory.c_str(), "", scriptPath);
      TryAppendHookScriptPath(files, scriptPath, candidatePath, HookFileMightExist(hookDirectory.c_str(), "", scriptPath));
    }

    CollectActiveModHookScripts(state, scriptPath, files);
    SCR_LuaDoFileConcat(state, outEnvironment, files);
  }

  /**
   * Address: 0x004CDF60 (FUN_004CDF60, Moho::SCR_AddHookDirectory)
   *
   * What it does:
   * Registers one hook directory prefix used during `doscript` hook lookup.
   */
  void SCR_AddHookDirectory(const char* const hookDirectory)
  {
    gScriptHookDirectories.push_back(fa::string(hookDirectory != nullptr ? hookDirectory : ""));
  }

  /**
   * Address: 0x004CF510 (FUN_004CF510, ?SCR_LuaBuildObject@Moho@@YA_NVLuaObject@LuaPlus@@ABVRRef@gpg@@_N@Z)
   *
   * What it does:
   * Recursively applies Lua values into one reflected destination object using
   * lexical conversion, indexed recursion, enum-flag parsing, and field walks.
   */
  bool SCR_LuaBuildObject(
    LuaPlus::LuaObject valueObject, const gpg::RRef& destination, const bool ignoreMissingFields
  )
  {
    if (TrySetFloatDirectly(valueObject, destination)) {
      return true;
    }
    std::string lexicalValue;
    if (LuaObjectTryToString(valueObject, lexicalValue)) {
      if (destination.mType->SetLexical(destination, lexicalValue.c_str())) {
        return true;
      }

      gpg::Warnf(
        "Invalid value for %s at %p: %s %s",
        ReflectedTypeNameOrNull(destination.mType),
        destination.mObj,
        LuaObjectTypeName(valueObject),
        lexicalValue.c_str()
      );
      return false;
    }

    if (valueObject.IsBoolean()) {
      const char* const booleanValue = valueObject.GetBoolean() ? "1" : "0";
      if (destination.mType->SetLexical(destination, booleanValue)) {
        return true;
      }

      gpg::Warnf(
        "Invalid value for %s at %p: %s %s",
        ReflectedTypeNameOrNull(destination.mType),
        destination.mObj,
        LuaObjectTypeName(valueObject),
        booleanValue
      );
      return false;
    }

    if (!valueObject.IsTable()) {
      gpg::Warnf(
        "Invalid type for %s at %p: %s",
        ReflectedTypeNameOrNull(destination.mType),
        destination.mObj,
        LuaObjectTypeName(valueObject)
      );
      return false;
    }

    if (destination.mType->IsEnumType()) {
      return ParseEnumFlagTable(valueObject, destination);
    }

    const gpg::RIndexed* const indexedType = destination.mType->IsIndexed();
    if (indexedType) {
      const int count = valueObject.GetN();
      if (static_cast<int>(indexedType->GetCount(destination.mObj)) != count) {
        indexedType->SetCount(destination.mObj, count);
      }

      bool recovered = true;
      for (int index = 0; index < count; ++index) {
        gpg::RRef elementDestination = indexedType->SubscriptIndex(destination.mObj, index);
        LuaPlus::LuaObject elementValue = valueObject[index + 1];
        if (!SCR_LuaBuildObject(elementValue, elementDestination, true)) {
          recovered = false;
        }
      }
      return recovered;
    }

    bool recovered = true;
    (void)valueObject.GetActiveState();
    LuaPlus::LuaTableIterator iter(&valueObject, 1);
    while (!iter.m_isDone) {
      LuaPlus::LuaObject keyObject(iter.GetKey());
      std::string keyName;
      if (!LuaObjectTryToString(keyObject, keyName)) {
        gpg::Warnf(
          "Bad key initializing %s at %p, expected string but got %s",
          ReflectedTypeNameOrNull(destination.mType),
          destination.mObj,
          LuaObjectTypeName(keyObject)
        );
        recovered = false;
      } else {
        const gpg::RField* const field = destination.mType->GetFieldNamed(keyName.c_str());
        if (field) {
          gpg::RRef fieldDestination{
            static_cast<std::uint8_t*>(destination.mObj) + field->mOffset,
            field->mType,
          };

          LuaPlus::LuaObject fieldValue(iter.GetValue());
          // Engine addition: a plain value (sim_BlueprintFieldShortcuts) or a table
          // (sim_BlueprintTableShortcuts) is set without the field's log context, whose formatted
          // text cost a third of blueprint loading; one that fails is set again inside the
          // context, so its warnings read as before.
          const bool quietlySet = fieldValue.IsTable()
            ? sim_BlueprintTableShortcuts && TryBuildQuietly(fieldValue, fieldDestination)
            : sim_BlueprintFieldShortcuts && TrySetPlainValue(fieldValue, fieldDestination);
          if (!quietlySet) {
            const fa::string fieldContext = gpg::STR_Printf(
              "Initializing field %s of %s at %p",
              keyName.c_str(),
              destination.GetName(),
              destination.mObj
            );
            gpg::ScopedLogContext scope(fieldContext);

            if (!SCR_LuaBuildObject(fieldValue, fieldDestination, true)) {
              recovered = false;
            }
          }
        } else if (!ignoreMissingFields) {
          gpg::Warnf(
            "No such field %s in %s at %p",
            keyName.c_str(),
            destination.GetName(),
            destination.mObj
          );
          recovered = false;
        }
      }

      iter.Next();
    }

    return recovered;
  }

  /**
    * Alias of FUN_10015880 (non-canonical helper lane).
   */
  CScrLuaObjectFactory::CScrLuaObjectFactory()
    : mFactoryObjectIndex(++sNumIds)
  {}

  /**
   * Address: 0x100158A0 (FUN_100158A0, ??0CScrLuaObjectFactory@Moho@@QAE@ABV01@@Z)
   */
  CScrLuaObjectFactory::CScrLuaObjectFactory(const CScrLuaObjectFactory& other)
    : mFactoryObjectIndex(other.mFactoryObjectIndex)
  {}

  /**
   * Address: 0x100158C0 (FUN_100158C0, ??4CScrLuaObjectFactory@Moho@@QAEAAV01@ABV01@@Z)
   */
  CScrLuaObjectFactory& CScrLuaObjectFactory::operator=(const CScrLuaObjectFactory& other)
  {
    mFactoryObjectIndex = other.mFactoryObjectIndex;
    return *this;
  }

  /**
   * Helper constructor for specializations that already recovered explicit
   * factory-object indices.
   */
  CScrLuaObjectFactory::CScrLuaObjectFactory(const int32_t factoryObjectIndex)
    : mFactoryObjectIndex(factoryObjectIndex)
  {}

  int32_t CScrLuaObjectFactory::AllocateFactoryObjectIndex()
  {
    return ++sNumIds;
  }

  /**
   * Address: 0x004CCE70 (FUN_004CCE70, FA exe)
   * Address: 0x100BE9E0 (?Get@CScrLuaObjectFactory@Moho@@QAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
   *
   * What it does:
   * Looks up `__factory_objects`, lazily creates the table when missing, and
   * memoizes one object per factory index via `Create(state)`.
   */
  LuaPlus::LuaObject CScrLuaObjectFactory::Get(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject factoryObjects;
    factoryObjects = state->GetGlobal(kFactoryObjectsGlobalName);
    if (factoryObjects.IsNil()) {
      factoryObjects.AssignNewTable(state, 0, 0);
      LuaPlus::LuaObject globals = state->GetGlobals();
      globals.SetObject(kFactoryObjectsGlobalName, factoryObjects);
    }

    LuaPlus::LuaObject value = factoryObjects.GetByIndex(mFactoryObjectIndex);
    if (value.IsNil()) {
      value = Create(state);
      factoryObjects.SetObject(mFactoryObjectIndex, value);
    }

    return value;
  }

  CScrLuaMetatableFactory<CScriptObject*>& CScrLuaMetatableFactory<CScriptObject*>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x100BA690
   * (?Create@?$CScrLuaMetatableFactory@PAVCScriptObject@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<CScriptObject*>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x100BA630 (FUN_100BA630, ??0?$CScrLuaMetatableFactory@PAVCScriptObject@Moho@@@Moho@@QAE@XZ)
   */
  CScrLuaMetatableFactory<CScriptObject*>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory()
  {}
} // namespace moho
