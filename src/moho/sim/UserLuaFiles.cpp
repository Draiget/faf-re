#include "moho/sim/UserLuaPrivate.h"

namespace
{
  [[nodiscard]] fa::string BuildSpecialFilePathDirectory(const moho::ESpecialFileType type)
  {
    switch (type) {
      case moho::ESpecialFileType::SaveGame:
      case moho::ESpecialFileType::CampaignSave:
        return USER_GetSaveGameDir();
      case moho::ESpecialFileType::Replay:
        return USER_GetReplayDir();
      case moho::ESpecialFileType::Screenshot:
        return USER_GetScreenshotDir();
    }
    return fa::string{};
  }
  [[nodiscard]] fa::string BuildSpecialFilePathExtension(const moho::ESpecialFileType type)
  {
    switch (type) {
      case moho::ESpecialFileType::SaveGame:
        return USER_GetSaveGameExt();
      case moho::ESpecialFileType::Replay:
        return USER_GetReplayExt();
      case moho::ESpecialFileType::Screenshot:
        return fa::string("bmp");
      case moho::ESpecialFileType::CampaignSave:
        return USER_GetCampaignSaveExt();
    }
    return fa::string{};
  }
  constexpr const char* kCopyCurrentReplayHelpText =
    "CopyCurrentReplay(string profile, string newFilename) - copy the current replay to another file";
  constexpr const char* kGetSpecialFileInfoHelpText =
    "table GetSpecialFileInfo(string profileName, string basename, string type) - get information on a profile based file, nil if unable to find";
  constexpr const char* kGetSpecialFilePathHelpText =
    "string GetSpecialFilePath(string profilename, string filename, string type) - Given the base name of a special file, retuns the complete path";
  constexpr const char* kGetSpecialFilesHelpText =
    "table GetSpecialFiles(string type)- returns a table of strings which are the names of files in special locations (currently SaveFile, Replay)";
  constexpr const char* kGetSpecialFolderHelpText = "string GetSpecialFolder(string type)";
  constexpr const char* kRemoveProfileDirectoriesHelpText =
    "RemoveProfileDirectories(string profile) - Removes the profile directory and all special files";
  constexpr const char* kRemoveSpecialFileHelpText =
    "RemoveSpecialFile(string profilename, string basename, string type) - remove a profile based file from the disc";
  [[noreturn]] void ThrowInvalidSpecialFileType(const char* const lexical)
  {
    throw std::runtime_error(gpg::STR_Printf("Invalid special file type %s", lexical != nullptr ? lexical : "").to_std());
  }
  [[nodiscard]] bool TryParseSpecialFileType(
    const char* const lexical,
    moho::ESpecialFileType& outType
  ) noexcept
  {
    if (lexical == nullptr) {
      return false;
    }

    const std::string_view text(lexical);
    if (text == "SaveGame" || text == "SFT_SaveGame") {
      outType = moho::ESpecialFileType::SaveGame;
      return true;
    }
    if (text == "Replay" || text == "SFT_Replay") {
      outType = moho::ESpecialFileType::Replay;
      return true;
    }
    if (text == "Screenshot" || text == "SFT_Screenshot") {
      outType = moho::ESpecialFileType::Screenshot;
      return true;
    }
    if (text == "CampaignSave" || text == "SFT_CampaignSave") {
      outType = moho::ESpecialFileType::CampaignSave;
      return true;
    }

    char* end = nullptr;
    const long numericValue = std::strtol(lexical, &end, 10);
    if (end != lexical && end != nullptr && *end == '\0' && numericValue >= 0 && numericValue <= 3) {
      outType = static_cast<moho::ESpecialFileType>(numericValue);
      return true;
    }

    return false;
  }
}


/**
 * Address: 0x008440A0 (FUN_008440A0, cfunc_GetSpecialFiles)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFilesL`.
 */
int moho::cfunc_GetSpecialFiles(lua_State* const luaContext)
{
  return cfunc_GetSpecialFilesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008440C0 (FUN_008440C0, func_GetSpecialFiles_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFiles`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFiles_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSpecialFiles",
    &moho::cfunc_GetSpecialFiles,
    nullptr,
    "<global>",
    kGetSpecialFilesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00844120 (FUN_00844120, cfunc_GetSpecialFilesL)
 *
 * What it does:
 * Resolves one special-file type and returns a Lua table containing grouped
 * profile file basenames plus directory/extension metadata.
 */
int moho::cfunc_GetSpecialFilesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetSpecialFilesHelpText);

  const LuaPlus::LuaStackObject typeArg(state, 1);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 1);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  std::string directory{};
  std::string extension{};
  fa::map<fa::string, fa::vector<fa::string>> filesByProfile{};
  USER_GetSpecialFiles(specialFileType, directory, extension, filesByProfile);

  LuaPlus::LuaObject filesTable(state);
  filesTable.AssignNewTable(state, 0, 0);

  for (const auto& [profileName, profileFiles] : filesByProfile) {
    LuaPlus::LuaObject profileTable(state);
    profileTable.AssignNewTable(state, 0, 0);

    std::int32_t fileIndex = 1;
    for (const fa::string& fileNameWithExtension : profileFiles) {
      const fa::string baseFileName = FILE_Base(fileNameWithExtension.c_str(), true);
      profileTable.SetString(fileIndex, baseFileName.c_str());
      ++fileIndex;
    }

    filesTable.SetObject(profileName.c_str(), profileTable);
  }

  LuaPlus::LuaObject result(state);
  result.AssignNewTable(state, 0, 0);
  result.SetObject("files", filesTable);
  result.SetString("directory", directory.c_str());
  result.SetString("extension", extension.c_str());
  result.PushStack(state);
  return 1;
}

/**
 * Address: 0x00844540 (FUN_00844540, cfunc_GetSpecialFilePath)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFilePathL`.
 */
int moho::cfunc_GetSpecialFilePath(lua_State* const luaContext)
{
  return cfunc_GetSpecialFilePathL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00844560 (FUN_00844560, func_GetSpecialFilePath_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFilePath`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFilePath_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSpecialFilePath",
    &moho::cfunc_GetSpecialFilePath,
    nullptr,
    "<global>",
    kGetSpecialFilePathHelpText
  );
  return &binder;
}

/**
 * Address: 0x008445C0 (FUN_008445C0, cfunc_GetSpecialFilePathL)
 *
 * What it does:
 * Resolves `(profile, filename, specialType)` and pushes one absolute
 * user-special-file path (`directory\\profile\\filename.extension`).
 */
int moho::cfunc_GetSpecialFilePathL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kGetSpecialFilePathHelpText);

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(rawState, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject fileNameArg(state, 2);
  const char* const fileName = lua_tostring(rawState, 2);
  if (fileName == nullptr) {
    fileNameArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject typeArg(state, 3);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 3);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const fa::string directory = BuildSpecialFilePathDirectory(specialFileType);
  const fa::string extension = BuildSpecialFilePathExtension(specialFileType);
  const fa::string fullPath = directory + "\\" + profileName + "\\" + fileName + "." + extension;

  lua_pushstring(rawState, fullPath.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00844C30 (FUN_00844C30, cfunc_GetSpecialFolder)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFolderL`.
 */
int moho::cfunc_GetSpecialFolder(lua_State* const luaContext)
{
  return cfunc_GetSpecialFolderL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00844C50 (FUN_00844C50, func_GetSpecialFolder_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFolder`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFolder_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSpecialFolder",
    &moho::cfunc_GetSpecialFolder,
    nullptr,
    "<global>",
    kGetSpecialFolderHelpText
  );
  return &binder;
}

/**
 * Address: 0x00844CB0 (FUN_00844CB0, cfunc_GetSpecialFolderL)
 *
 * What it does:
 * Resolves one special-file type and pushes the matching root folder path.
 */
int moho::cfunc_GetSpecialFolderL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetSpecialFolderHelpText);

  const LuaPlus::LuaStackObject typeArg(state, 1);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 1);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const fa::string directory = BuildSpecialFilePathDirectory(specialFileType);
  lua_pushstring(rawState, directory.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00844F10 (FUN_00844F10, cfunc_RemoveSpecialFile)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_RemoveSpecialFileL`.
 */
int moho::cfunc_RemoveSpecialFile(lua_State* const luaContext)
{
  return cfunc_RemoveSpecialFileL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00844F30 (FUN_00844F30, func_RemoveSpecialFile_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RemoveSpecialFile`.
 */
moho::CScrLuaInitForm* moho::func_RemoveSpecialFile_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "RemoveSpecialFile",
    &moho::cfunc_RemoveSpecialFile,
    nullptr,
    "<global>",
    kRemoveSpecialFileHelpText
  );
  return &binder;
}

/**
 * Address: 0x00844F90 (FUN_00844F90, cfunc_RemoveSpecialFileL)
 *
 * What it does:
 * Builds one profile-scoped special-file path and recycles it from disk.
 */
int moho::cfunc_RemoveSpecialFileL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kRemoveSpecialFileHelpText);

  const LuaPlus::LuaStackObject typeArg(state, 3);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 3);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  fa::string directory;
  fa::string extension;
  switch (specialFileType) {
    case moho::ESpecialFileType::SaveGame:
      directory = USER_GetSaveGameDir();
      extension = USER_GetSaveGameExt();
      break;
    case moho::ESpecialFileType::Replay:
      directory = USER_GetReplayDir();
      extension = USER_GetReplayExt();
      break;
    case moho::ESpecialFileType::CampaignSave:
      directory = USER_GetSaveGameDir();
      extension = USER_GetCampaignSaveExt();
      break;
    case moho::ESpecialFileType::Screenshot:
    default:
      ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(rawState, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject baseNameArg(state, 2);
  const char* const baseName = lua_tostring(rawState, 2);
  if (baseName == nullptr) {
    baseNameArg.TypeError("string");
  }

  const fa::string fullPath = directory + profileName + "\\" + baseName + "." + extension;
  DISK_Recycle(fullPath.c_str());
  return 0;
}

/**
 * Address: 0x00845540 (FUN_00845540, cfunc_GetSpecialFileInfo)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFileInfoL`.
 */
int moho::cfunc_GetSpecialFileInfo(lua_State* const luaContext)
{
  return cfunc_GetSpecialFileInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00845560 (FUN_00845560, func_GetSpecialFileInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFileInfo`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFileInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSpecialFileInfo",
    &moho::cfunc_GetSpecialFileInfo,
    nullptr,
    "<global>",
    kGetSpecialFileInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x008455C0 (FUN_008455C0, cfunc_GetSpecialFileInfoL)
 *
 * What it does:
 * Returns metadata table for one profile-scoped special file, or `nil` when
 * the file does not exist.
 */
int moho::cfunc_GetSpecialFileInfoL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kGetSpecialFileInfoHelpText);

  const LuaPlus::LuaStackObject typeArg(state, 3);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 3);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  fa::string directory;
  fa::string extension;
  switch (specialFileType) {
    case moho::ESpecialFileType::SaveGame:
      directory = USER_GetSaveGameDir();
      extension = USER_GetSaveGameExt();
      break;
    case moho::ESpecialFileType::Replay:
      directory = USER_GetReplayDir();
      extension = USER_GetReplayExt();
      break;
    case moho::ESpecialFileType::CampaignSave:
      directory = USER_GetSaveGameDir();
      extension = USER_GetCampaignSaveExt();
      break;
    case moho::ESpecialFileType::Screenshot:
    default:
      ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(rawState, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject baseNameArg(state, 2);
  const char* const baseName = lua_tostring(rawState, 2);
  if (baseName == nullptr) {
    baseNameArg.TypeError("string");
  }

  const fa::string fullPath = directory + profileName + "\\" + baseName + "." + extension;
  const std::wstring widePath = gpg::STR_Utf8ToWide(fullPath.c_str());

  WIN32_FILE_ATTRIBUTE_DATA attributeData{};
  if (::GetFileAttributesExW(widePath.c_str(), GetFileExInfoStandard, &attributeData) == FALSE) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject fileInfo(state);
  fileInfo.AssignNewTable(state, 0, 0u);
  fileInfo.SetBoolean("IsFolder", (attributeData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0u);
  fileInfo.SetBoolean("ReadOnly", (attributeData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0u);
  fileInfo.SetInteger("SizeBytes", static_cast<std::int32_t>(attributeData.nFileSizeLow));

  ULARGE_INTEGER writeTimeStamp{};
  writeTimeStamp.LowPart = attributeData.ftLastWriteTime.dwLowDateTime;
  writeTimeStamp.HighPart = attributeData.ftLastWriteTime.dwHighDateTime;
  const fa::string stampText = gpg::STR_Printf("%016llx", static_cast<unsigned long long>(writeTimeStamp.QuadPart));
  fileInfo.SetString("TimeStamp", stampText.c_str());

  FILETIME localWriteFileTime{};
  SYSTEMTIME localWriteTime{};
  (void)::FileTimeToLocalFileTime(&attributeData.ftLastWriteTime, &localWriteFileTime);
  (void)::FileTimeToSystemTime(&localWriteFileTime, &localWriteTime);

  LuaPlus::LuaObject writeTimeTable(state);
  writeTimeTable.AssignNewTable(state, 0, 0u);
  writeTimeTable.SetInteger("year", static_cast<std::int32_t>(localWriteTime.wYear));
  writeTimeTable.SetInteger("month", static_cast<std::int32_t>(localWriteTime.wMonth));
  writeTimeTable.SetInteger("mday", static_cast<std::int32_t>(localWriteTime.wDay));
  writeTimeTable.SetInteger("wday", static_cast<std::int32_t>(localWriteTime.wDayOfWeek));
  writeTimeTable.SetInteger("hour", static_cast<std::int32_t>(localWriteTime.wHour));
  writeTimeTable.SetInteger("minute", static_cast<std::int32_t>(localWriteTime.wMinute));
  writeTimeTable.SetInteger("second", static_cast<std::int32_t>(localWriteTime.wSecond));
  fileInfo.SetObject("WriteTime", writeTimeTable);

  fileInfo.PushStack(state);
  return 1;
}

/**
 * Address: 0x00845DF0 (FUN_00845DF0, cfunc_RemoveProfileDirectories)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_RemoveProfileDirectoriesL`.
 */
int moho::cfunc_RemoveProfileDirectories(lua_State* const luaContext)
{
  return cfunc_RemoveProfileDirectoriesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00845E10 (FUN_00845E10, func_RemoveProfileDirectories_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RemoveProfileDirectories`.
 */
moho::CScrLuaInitForm* moho::func_RemoveProfileDirectories_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "RemoveProfileDirectories",
    &moho::cfunc_RemoveProfileDirectories,
    nullptr,
    "<global>",
    kRemoveProfileDirectoriesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00845E70 (FUN_00845E70, cfunc_RemoveProfileDirectoriesL)
 *
 * What it does:
 * Recycles replay/save profile-scoped directories and companion lanes for one
 * profile string.
 */
int moho::cfunc_RemoveProfileDirectoriesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kRemoveProfileDirectoriesHelpText);

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(state->m_state, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  // Binary lane calls replay/save directory helpers twice each before recycling.
  const fa::string replayProfilePathA = USER_GetReplayDir() + profileName;
  const fa::string saveProfilePathA = USER_GetSaveGameDir() + profileName;
  const fa::string replayProfilePathB = USER_GetReplayDir() + profileName;
  const fa::string saveProfilePathB = USER_GetSaveGameDir() + profileName;

  DISK_Recycle(replayProfilePathA.c_str());
  DISK_Recycle(saveProfilePathA.c_str());
  DISK_Recycle(replayProfilePathB.c_str());
  DISK_Recycle(saveProfilePathB.c_str());
  return 0;
}

/**
 * Address: 0x00846200 (FUN_00846200, cfunc_CopyCurrentReplay)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_CopyCurrentReplayL`.
 */
int moho::cfunc_CopyCurrentReplay(lua_State* const luaContext)
{
  return cfunc_CopyCurrentReplayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846220 (FUN_00846220, func_CopyCurrentReplay_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CopyCurrentReplay`.
 */
moho::CScrLuaInitForm* moho::func_CopyCurrentReplay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "CopyCurrentReplay",
    &moho::cfunc_CopyCurrentReplay,
    nullptr,
    "<global>",
    kCopyCurrentReplayHelpText
  );
  return &binder;
}

/**
 * Address: 0x00846280 (FUN_00846280, cfunc_CopyCurrentReplayL)
 *
 * What it does:
 * Copies the localized `LastGame` replay from one profile lane to a new replay
 * filename in that profile.
 */
int moho::cfunc_CopyCurrentReplayL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 2, kCopyCurrentReplayHelpText);

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(state->m_state, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject filenameArg(state, 2);
  const char* const newFilename = lua_tostring(state->m_state, 2);
  if (newFilename == nullptr) {
    filenameArg.TypeError("string");
  }

  const fa::string replayDirectory = USER_GetReplayDir();
  const fa::string replayExtension = USER_GetReplayExt();
  const fa::string localizedLastGame = Loc(USER_GetLuaState(), "<LOC Engine0030>LastGame");
  const fa::string replayPrefix = replayDirectory + profileName + "\\";

  const fa::string sourcePath = replayPrefix + localizedLastGame + "." + replayExtension;
  const fa::string destinationPath = replayPrefix + newFilename + "." + replayExtension;

  const std::wstring destinationWide = gpg::STR_Utf8ToWide(destinationPath.c_str());
  const std::wstring sourceWide = gpg::STR_Utf8ToWide(sourcePath.c_str());
  if (::CopyFileW(sourceWide.c_str(), destinationWide.c_str(), FALSE) == FALSE) {
    const fa::string lastError = WIN_GetLastError();
    gpg::Logf("Unable to copy replay file: %s", lastError.c_str());
  }
  return 0;
}
