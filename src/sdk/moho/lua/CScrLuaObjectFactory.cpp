#include "moho/lua/CScrLuaObjectFactory.h"

#include <cstdint>
#include <cstring>
#include <exception>
#include <string>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaTableIterator.h"
#include "moho/misc/FileWaitHandleSet.h"

namespace
{
  constexpr const char* kFactoryObjectsGlobalName = "__factory_objects";
  constexpr const char* kActiveModsGlobalName = "__active_mods";
  constexpr const char* kLocationFieldName = "location";
  constexpr const char* kHookDirFieldName = "hookdir";
  constexpr const char* kDefaultHookDirPath = "/hook";
  constexpr const char kConcatSyntheticNewline[] = "\n";
  std::int32_t gRecoveredCScrLuaMetatableFactoryCScriptObjectIndex = 0;
  msvc8::vector<msvc8::string> gScriptHookDirectories{};

  struct LuaFileLoaderDat final
  {
    gpg::MemBuffer<const char> buf{};
    bool done{false};
  };
  static_assert(sizeof(LuaFileLoaderDat) == 0x14, "LuaFileLoaderDat size must be 0x14");

  struct LuaConcatLoadData final
  {
    gpg::MemBuffer<const char> currentChunk{};
    const msvc8::vector<msvc8::string>* files{nullptr};
    std::uint32_t nextFileIndex{0};
    bool pendingTrailingNewline{false};
  };
  static_assert(sizeof(LuaConcatLoadData) == 0x1C, "LuaConcatLoadData size must be 0x1C");

  [[nodiscard]] std::uint32_t AsAddress32(const void* const value) noexcept
  {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(value));
  }

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

  template <typename TValue>
  [[nodiscard]] const TValue* TryUpcastScalar(const gpg::RRef& source)
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(TValue));
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, sType);
    return upcast.mObj != nullptr ? static_cast<const TValue*>(upcast.mObj) : nullptr;
  }

  [[nodiscard]] LuaPlus::LuaObject MakeNilObject(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject nilObject{};
    if (state != nullptr) {
      nilObject.AssignNil(state);
    }
    return nilObject;
  }

  [[nodiscard]] bool ResolveMountedScriptPath(const char* const sourcePath, msvc8::string& outPath)
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

  void TryAppendHookScriptPath(
    msvc8::vector<msvc8::string>& outFiles,
    const char* const scriptPath,
    const msvc8::string& candidatePath
  )
  {
    msvc8::string resolvedPath{};
    if (!ResolveMountedScriptPath(candidatePath.c_str(), resolvedPath) || resolvedPath.empty()) {
      return;
    }

    gpg::Logf("Hooked %s with %s", scriptPath != nullptr ? scriptPath : "", candidatePath.c_str());
    outFiles.push_back(resolvedPath);
  }

  [[nodiscard]] msvc8::string BuildHookCandidatePath(
    const char* const rootPath,
    const char* const hookPath,
    const char* const scriptPath
  )
  {
    msvc8::string candidate(rootPath != nullptr ? rootPath : "");
    candidate.append(hookPath != nullptr ? hookPath : "");
    candidate.append(scriptPath != nullptr ? scriptPath : "");
    return candidate;
  }

  void CollectActiveModHookScripts(
    LuaPlus::LuaState* const state,
    const char* const scriptPath,
    msvc8::vector<msvc8::string>& outFiles
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

      const msvc8::string candidatePath = BuildHookCandidatePath(modLocation, hookDir, scriptPath);
      TryAppendHookScriptPath(outFiles, scriptPath, candidatePath);
    }
  }

  /**
   * Address: 0x004CDCF0 (FUN_004CDCF0, func_LuaFileLoader)
   *
   * What it does:
   * Returns one mapped-file chunk exactly once for `lua_load`, then reports EOF.
   */
  [[maybe_unused]] const char* func_LuaFileLoader(
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
      const msvc8::vector<msvc8::string>* const files = data->files;
      if (files == nullptr || data->nextFileIndex >= files->size()) {
        return nullptr;
      }

      const msvc8::string& filePath = (*files)[data->nextFileIndex];
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
        "Invalid value for %s at 0x%08x: %s",
        ReflectedTypeNameOrNull(destination.mType),
        AsAddress32(destination.mObj),
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
   * Address: 0x004D3250 (FUN_004D3250, ?SCR_Import@Moho@@YA?AVLuaObject@LuaPlus@@PAVLuaState@3@VStrArg@gpg@@@Z)
   *
   * What it does:
   * Calls global `import(modulePath)`, captures the returned value as
   * `LuaObject`, then restores the previous Lua stack top.
   */
  LuaPlus::LuaObject SCR_Import(LuaPlus::LuaState* const state, const gpg::StrArg modulePath)
  {
    lua_State* const lstate = state->m_state;
    const int savedTop = lua_gettop(lstate);

    lua_pushstring(lstate, "import");
    lua_gettable(lstate, LUA_GLOBALSINDEX);
    lua_pushstring(lstate, modulePath);
    lua_call(lstate, 1, 1);

    LuaPlus::LuaObject result(state, -1);
    lua_settop(lstate, savedTop);
    return result;
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
    if (lua_pcall(lstate, 1, 1, 0) != 0) {
      lua_settop(lstate, savedTop);
      return {};
    }

    LuaPlus::LuaObject moduleObject{LuaPlus::LuaStackObject(state, -1)};
    lua_settop(lstate, savedTop);
    return moduleObject;
  }

  LuaPlus::LuaObject
  SCR_GetLuaTableField(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& tableObj, const char* const fieldName)
  {
    if (!state || !fieldName || !*fieldName || tableObj.IsNil()) {
      return {};
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return {};
    }

    const int savedTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(tableObj).PushStack(lstate);
    lua_pushstring(lstate, fieldName);
    lua_gettable(lstate, -2);
    LuaPlus::LuaObject result{LuaPlus::LuaStackObject(state, -1)};
    lua_settop(lstate, savedTop);
    return result;
  }

  /**
   * Address: 0x004D23D0 (FUN_004D23D0, ?SCR_QuoteLuaString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@@Z)
   *
   * What it does:
   * Returns one Lua-quoted string literal with escaping for matching quote
   * char, backslash, tab/newline, and non-printable bytes.
   */
  msvc8::string SCR_QuoteLuaString(const gpg::StrArg text)
  {
    const char* const source = text != nullptr ? text : "";

    msvc8::string quoted{};
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
  msvc8::string SCR_ToString(const LuaPlus::LuaObject& object)
  {
    gpg::MemBufferStream stream(256u);
    LuaPlus::LuaObject copy = object;
    (void)copy.ToByteStream(stream);

    const std::size_t serializedSize = stream.BytesWritten();
    if (serializedSize == 0u || stream.mWriteStart == nullptr) {
      return {};
    }

    return msvc8::string(stream.mWriteStart, serializedSize);
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

    if (const float* const value = TryUpcastScalar<float>(source); value != nullptr) {
      destination.AssignNumber(state, *value);
      return;
    }

    if (const int* const value = TryUpcastScalar<int>(source); value != nullptr) {
      destination.AssignNumber(state, static_cast<double>(*value));
      return;
    }

    if (const unsigned int* const value = TryUpcastScalar<unsigned int>(source); value != nullptr) {
      destination.AssignNumber(state, static_cast<double>(*value));
      return;
    }

    if (const signed char* const value = TryUpcastScalar<signed char>(source); value != nullptr) {
      destination.AssignNumber(state, static_cast<double>(*value));
      return;
    }

    if (const unsigned char* const value = TryUpcastScalar<unsigned char>(source); value != nullptr) {
      destination.AssignNumber(state, static_cast<double>(*value));
      return;
    }

    if (const bool* const value = TryUpcastScalar<bool>(source); value != nullptr) {
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

    const msvc8::string lexicalValue = source.GetLexical();
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

    msvc8::string validOptions{};
    if (const gpg::REnumType* const enumType = ref.mType != nullptr ? ref.mType->IsEnumType() : nullptr; enumType) {
      const msvc8::vector<gpg::REnumType::ROptionValue>& options = enumType->GetEnumOptions();
      for (const gpg::REnumType::ROptionValue* it = options.begin(); it != options.end(); ++it) {
        validOptions.append(gpg::STR_Printf("   %s\n", it->mName != nullptr ? it->mName : "").view());
      }
    }

    const msvc8::string errorMessage =
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
    const int runStatus = (loadStatus == 0) ? lua_pcall(rawState, 0, LUA_MULTRET, 0) : 0;

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
    msvc8::vector<msvc8::string> files
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

    const msvc8::string chunkName = gpg::STR_Printf("@%s", files.front().c_str());
    const int loadStatus = lua_load(state->m_state, func_LoadConcat, &loadData, chunkName.c_str());
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

    lua_call(state->m_state, 0, 0);
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

    msvc8::string resolvedPath{};
    if (!ResolveMountedScriptPath(scriptPath, resolvedPath) || resolvedPath.empty()) {
      const msvc8::string errorText = gpg::STR_Printf("Unable to find file %s", scriptPath);
      LuaPlus::LuaState::Error(state, "%s", errorText.c_str());
    }

    msvc8::vector<msvc8::string> files{};
    files.push_back(resolvedPath);

    for (const msvc8::string& hookDirectory : gScriptHookDirectories) {
      const msvc8::string candidatePath = BuildHookCandidatePath(hookDirectory.c_str(), "", scriptPath);
      TryAppendHookScriptPath(files, scriptPath, candidatePath);
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
    gScriptHookDirectories.push_back(msvc8::string(hookDirectory != nullptr ? hookDirectory : ""));
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
    std::string lexicalValue;
    if (LuaObjectTryToString(valueObject, lexicalValue)) {
      if (destination.mType->SetLexical(destination, lexicalValue.c_str())) {
        return true;
      }

      gpg::Warnf(
        "Invalid value for %s at 0x%08x: %s %s",
        ReflectedTypeNameOrNull(destination.mType),
        AsAddress32(destination.mObj),
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
        "Invalid value for %s at 0x%08x: %s %s",
        ReflectedTypeNameOrNull(destination.mType),
        AsAddress32(destination.mObj),
        LuaObjectTypeName(valueObject),
        booleanValue
      );
      return false;
    }

    if (!valueObject.IsTable()) {
      gpg::Warnf(
        "Invalid type for %s at 0x%08x: %s",
        ReflectedTypeNameOrNull(destination.mType),
        AsAddress32(destination.mObj),
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
          "Bad key initializing %s at 0x%08x, expected string but got %s",
          ReflectedTypeNameOrNull(destination.mType),
          AsAddress32(destination.mObj),
          LuaObjectTypeName(keyObject)
        );
        recovered = false;
      } else {
        const gpg::RField* const field = destination.mType->GetFieldNamed(keyName.c_str());
        if (field) {
          const msvc8::string fieldContext = gpg::STR_Printf(
            "Initializing field %s of %s at 0x%08x",
            keyName.c_str(),
            destination.GetName(),
            AsAddress32(destination.mObj)
          );
          gpg::ScopedLogContext scope(fieldContext);

          gpg::RRef fieldDestination{
            static_cast<std::uint8_t*>(destination.mObj) + field->mOffset,
            field->mType,
          };

          LuaPlus::LuaObject fieldValue(iter.GetValue());
          if (!SCR_LuaBuildObject(fieldValue, fieldDestination, true)) {
            recovered = false;
          }
        } else if (!ignoreMissingFields) {
          gpg::Warnf(
            "No such field %s in %s at 0x%08x",
            keyName.c_str(),
            destination.GetName(),
            AsAddress32(destination.mObj)
          );
          recovered = false;
        }
      }

      iter.Next();
    }

    return recovered;
  }

  /**
   * Address: 0x10015880 (FUN_10015880, ??0CScrLuaObjectFactory@Moho@@QAE@XZ)
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
