#include "moho/misc/StartupHelpers.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <direct.h>

#include <Windows.h>
#include <mmsystem.h>
#include <mmreg.h>
#include <dsound.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <Shlwapi.h>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/d3d10/DeviceD3D10.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaTableIterator.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/client/Localization.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/XFileError.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/SpecialFileType.h"
#include "moho/ui/CUIManager.h"

extern int __argc;
extern char** __argv;

namespace
{
  std::mutex gDiskPathStateLock;
  std::filesystem::path gLaunchDirectory;
  std::filesystem::path gDataPathScriptFile;
  std::vector<std::wstring> gAllowedProtocols;
  moho::SAppIdentity gAppIdentity{};
  std::uint8_t gAqtimeInstrumentationMode = 1;
  std::once_flag gAppIdentityInitOnce;
  moho::CMovieManager* gMovieManager = nullptr;
  moho::IUserPrefs* gPreferences = nullptr;

  constexpr const char* kOptionPrefixes[] = {"/", "-", "+", "\\"};
  constexpr const char* kAdapterAliases[] = {"adapter"};
  constexpr const char* kMaximizeAliases[] = {"maximize", "maximized"};
  constexpr const char* kDualAliases[] = {"dual", "multi", "two"};
  constexpr const char* kHeadAliases[] = {"head", "monitor", "mon", "display"};
  constexpr const char* kFullscreenAliases[] = {"fullscreen"};
  constexpr const char* kWindowedAliases[] = {"windowed", "window", "size"};

  constexpr moho::CfgAliasSet kOptionPrefixesSet{kOptionPrefixes, sizeof(kOptionPrefixes) / sizeof(kOptionPrefixes[0])};
  constexpr moho::CfgAliasSet kAdapterAliasesSet{kAdapterAliases, sizeof(kAdapterAliases) / sizeof(kAdapterAliases[0])};
  constexpr moho::CfgAliasSet kMaximizeAliasesSet{
    kMaximizeAliases, sizeof(kMaximizeAliases) / sizeof(kMaximizeAliases[0])
  };
  constexpr moho::CfgAliasSet kDualAliasesSet{kDualAliases, sizeof(kDualAliases) / sizeof(kDualAliases[0])};
  constexpr moho::CfgAliasSet kHeadAliasesSet{kHeadAliases, sizeof(kHeadAliases) / sizeof(kHeadAliases[0])};
  constexpr moho::CfgAliasSet kFullscreenAliasesSet{
    kFullscreenAliases, sizeof(kFullscreenAliases) / sizeof(kFullscreenAliases[0])
  };
  constexpr moho::CfgAliasSet kWindowedAliasesSet{
    kWindowedAliases, sizeof(kWindowedAliases) / sizeof(kWindowedAliases[0])
  };
  constexpr char kUserPrefsModulePath[] = "/lua/user/prefs.lua";
  constexpr char kOptionsLogicModulePath[] = "/lua/options/optionslogic.lua";
  constexpr char kGetOptionMethodName[] = "GetOption";
  constexpr char kGetCurrentProfileMethodName[] = "GetCurrentProfile";
  constexpr char kProfileNameFieldName[] = "Name";
  constexpr char kProfilesExistMethodName[] = "ProfilesExist";
  constexpr char kCreateProfileMethodName[] = "CreateProfile";
  constexpr char kApplyMethodName[] = "Apply";
  constexpr char kSetCustomDataMethodName[] = "SetCustomData";
  constexpr char kUserPrefsLuaRunErrorPrefix[] = "Error running '/lua/user/prefs.lua' : %s";
  constexpr char kUserPrefsGetOptionLuaRunErrorPrefix[] = "Error running '/lua/user/prefs.lua:GetOption' : %s";
  constexpr char kOptionsApplyLuaRunErrorPrefix[] = "Error running '/lua/options/optionslogic.lua':Apply %s";
  constexpr char kOptionsSetCustomDataLuaRunErrorPrefix[] =
    "Error running '/lua/options/optionslogic.lua':OPTIONS_SetCustomData %s";
  constexpr char kPrimaryAdapterKey[] = "primary_adapter";
  constexpr char kSecondaryAdapterKey[] = "secondary_adapter";
  constexpr char kFidelityPresetsKey[] = "fidelity_presets";
  constexpr char kFidelityKey[] = "fidelity";
  constexpr char kShadowQualityKey[] = "shadow_quality";
  constexpr char kAntiAliasingKey[] = "antialiasing";
  constexpr char kWindowedModeKey[] = "windowed";
  constexpr char kDisabledModeKey[] = "disabled";
  constexpr char kCommandLineOverrideModeKey[] = "overridden";
  constexpr char kGetCommandLineArgHelpText[] = "CommandArgTable GetCommandLineArg(option, number)";
  constexpr char kHasCommandLineArgHelpText[] = "HasCommandLineArg(option)";
  constexpr char kSHGetFolderPathHelpText[] = "(name, create?) -- Interface to Win32 SHGetFolderPath api";
  constexpr char kGetTextureDimensionsHelpText[] = "width, height GetTextureDimensions(filename, border = 1)";
  constexpr char kSetMovieVolumeHelpText[] = "SetMovieVolume(volume): 0.0 - 2.0";
  constexpr char kGetMovieVolumeHelpText[] = "GetMovieVolume()";
  constexpr char kGetMovieDurationHelpText[] = "GetMovieDuration(localFileName)";
  constexpr char kGetAntiAliasingOptionsHelpText[] = "obj GetAntiAliasingOptions()";
  constexpr char kGetOptionsHelpText[] = "obj GetOptions()";
  constexpr char kGetPreferenceHelpText[] = "obj GetPreference(string, [default])";
  constexpr char kSetPreferenceHelpText[] = "SetPreference(string, obj)";
  constexpr char kSavePreferencesHelpText[] = "SavePreferences()";
  constexpr char kDebugFacilitiesEnabledHelpText[] =
    "bool DebugFacilitiesEnabled() - returns true if debug facilities are enabled.";
  constexpr char kUnknownShGetFolderPathIdErrorText[] = "Unknown id for SHGetFolderPath: %s";
  constexpr char kShGetFolderPathFailedErrorText[] = "SHGetFolderPath failed: %x";
  constexpr char kLuaExpectedArgRangeWarning[] = "%s\n  expected between %d and %d args, but got %d";
  constexpr char kUnreachableAssertText[] = "Reached the supposably unreachable.";
  constexpr char kScrUnsafeSourcePath[] = "c:\\work\\rts\\main\\code\\src\\core\\ScrUnsafe.cpp";
  constexpr int kScrUnsafeUnknownPathLine = 95;
  constexpr float kLuaMovieVolumeHardClamp = 2.0f;
  constexpr float kLuaMovieVolumeMax = 1.0f;
  constexpr float kLuaMovieVolumeDbFloor = -10000.0f;
  constexpr float kMovieSofdecVideoRefreshHz = 59.939999f;
  constexpr float kWordFloatScale = 65536.0f;
  constexpr std::int32_t kSofdecHeaderTypeMovie = 1;
  constexpr std::int32_t kSofdecHeaderTypeMovieAlt = 3;

  /**
   * Address: 0x008C8700 (FUN_008C8700, func_CpyFile)
   *
   * What it does:
   * Replaces destination with source when destination already exists; otherwise
   * moves source to destination, logging Win32 error codes on failure.
   */
  [[maybe_unused]] void CopyOrReplacePreferenceFile(const wchar_t* const sourcePath, const wchar_t* const destinationPath)
  {
    if (sourcePath == nullptr || destinationPath == nullptr) {
      return;
    }

    if (::PathFileExistsW(destinationPath) != FALSE) {
      if (::ReplaceFileW(destinationPath, sourcePath, nullptr, 0u, nullptr, nullptr) == FALSE) {
        const DWORD errorCode = ::GetLastError();
        gpg::Warnf(
          "unable to replace file %s with %s [error %x]",
          reinterpret_cast<const char*>(destinationPath),
          reinterpret_cast<const char*>(sourcePath),
          errorCode
        );
      }
      return;
    }

    if (::MoveFileW(sourcePath, destinationPath) == FALSE) {
      const DWORD errorCode = ::GetLastError();
      gpg::Warnf(
        "unable to move file to %s from %s [error %x]",
        reinterpret_cast<const char*>(destinationPath),
        reinterpret_cast<const char*>(sourcePath),
        errorCode
      );
    }
  }

  struct SofdecHeaderInfoRuntimeView
  {
    std::int32_t headerValid = 0;            // +0x00
    std::int32_t streamType = 0;             // +0x04
    std::int32_t reserved08 = 0;             // +0x08
    std::int32_t reserved0C = 0;             // +0x0C
    std::int32_t frameRateTimes1000 = 0;     // +0x10
    std::int32_t frameCount = 0;             // +0x14
    std::int32_t reserved18 = 0;             // +0x18
    std::int32_t reserved1C = 0;             // +0x1C
    std::int32_t reserved20 = 0;             // +0x20
    std::int32_t reserved24 = 0;             // +0x24
    std::int32_t reserved28 = 0;             // +0x28
  };

  static_assert(offsetof(SofdecHeaderInfoRuntimeView, headerValid) == 0x00, "headerValid offset must be 0x00");
  static_assert(offsetof(SofdecHeaderInfoRuntimeView, streamType) == 0x04, "streamType offset must be 0x04");
  static_assert(
    offsetof(SofdecHeaderInfoRuntimeView, frameRateTimes1000) == 0x10,
    "frameRateTimes1000 offset must be 0x10"
  );
  static_assert(offsetof(SofdecHeaderInfoRuntimeView, frameCount) == 0x14, "frameCount offset must be 0x14");
  static_assert(sizeof(SofdecHeaderInfoRuntimeView) == 0x2C, "SofdecHeaderInfoRuntimeView size must be 0x2C");

  struct SofdecCreateInfoRuntimeView
  {
    std::int32_t headerWord0 = 0;          // +0x00
    std::int32_t headerWord1 = 0;          // +0x04
    std::int32_t frameRateTimes1000 = 0;   // +0x08
    std::int32_t height = 0;               // +0x0C
    std::int32_t width = 0;                // +0x10
    std::int32_t frameCount = 0;           // +0x14
    std::int32_t extraFrameMetric = 0;     // +0x18
  };
  static_assert(sizeof(SofdecCreateInfoRuntimeView) == 0x1C, "SofdecCreateInfoRuntimeView size must be 0x1C");

  extern "C" void SFD_AnalyCreInf(const char* buffer, std::int32_t size, SofdecCreateInfoRuntimeView* outInfo);
  extern "C" std::int32_t mwsfcre_DecideFtypeByHdrInf(const SofdecCreateInfoRuntimeView* headerInfo);
  extern "C" std::int32_t mwsfdcre_IsPlayableByHdrInf(const SofdecHeaderInfoRuntimeView* headerInfo);
  extern "C" void
    MWSFFRM_AnalyzeSofdecHeader(const char* buffer, std::int32_t size, SofdecHeaderInfoRuntimeView* headerInfo);
  extern "C" void MWSFSVM_Error(const char* message);

  /**
   * Address: 0x00AC8DF0 (FUN_00AC8DF0, mwPlyGetHdrInf)
   *
   * What it does:
   * Parses Sofdec header lanes from a mapped movie buffer, fills the runtime
   * header-info struct used by `MOV_GetDuration`, and reports invalid input
   * through Sofdec error sink lanes.
   */
  extern "C" std::int32_t mwPlyGetHdrInf(const char* const buffer, const std::int32_t size, void* const outHeaderInfo)
  {
    SofdecHeaderInfoRuntimeView parsedHeader{};
    std::memset(&parsedHeader, 0, sizeof(parsedHeader));
    if (outHeaderInfo != nullptr) {
      std::memset(outHeaderInfo, 0, sizeof(SofdecHeaderInfoRuntimeView));
    }

    if (buffer == nullptr || outHeaderInfo == nullptr) {
      MWSFSVM_Error("E204161 mwPlyGetHdrInf");
      return 0;
    }

    if (size <= 0) {
      MWSFSVM_Error("E204162 mwPlyGetHdrInf");
      return 0;
    }

    SofdecCreateInfoRuntimeView createInfo{};
    std::memset(&createInfo, 0, sizeof(createInfo));
    SFD_AnalyCreInf(buffer, size, &createInfo);
    if (createInfo.headerWord0 == 0 || createInfo.headerWord1 == 0) {
      parsedHeader.headerValid = 0;
      std::memcpy(outHeaderInfo, &parsedHeader, sizeof(parsedHeader));
      return 0;
    }

    parsedHeader.streamType = mwsfcre_DecideFtypeByHdrInf(&createInfo);
    parsedHeader.frameRateTimes1000 = createInfo.frameRateTimes1000;
    parsedHeader.reserved18 = createInfo.height;
    parsedHeader.reserved1C = createInfo.width;
    parsedHeader.frameCount = createInfo.frameCount;
    parsedHeader.reserved24 = createInfo.extraFrameMetric;
    MWSFFRM_AnalyzeSofdecHeader(buffer, size, &parsedHeader);
    parsedHeader.headerValid = mwsfdcre_IsPlayableByHdrInf(&parsedHeader);
    std::memcpy(outHeaderInfo, &parsedHeader, sizeof(parsedHeader));
    return parsedHeader.headerValid;
  }

  struct UnsafePathEntry
  {
    const char* key = nullptr;
    int csidl = 0;
  };

  constexpr UnsafePathEntry kUnsafePaths[] = {
    {"DESKTOP", 0},
    {"PERSONAL", 5},
    {"CSIDL_FAVORITES", 6},
    {"CSIDL_STARTUP", 7},
    {"CSIDL_RECENT", 8},
    {"SENDTO", 9},
    {"BITBUCKET", 10},
    {"STARTMENU", 11},
    {"MYDOCUMENTS", 12},
    {"MYMUSIC", 13},
    {"MYVIDEO", 14},
    {"DESKTOPDIRECTORY", 16},
    {"FONTS", 20},
    {"TEMPLATES", 21},
    {"COMMON_STARTMENU", 22},
    {"COMMON_PROGRAMS", 23},
    {"COMMON_STARTUP", 24},
    {"COMMON_DESKTOPDIRECTORY", 25},
    {"APPDATA", 26},
    {"LOCAL_APPDATA", 28},
    {"COMMON_FAVORITES", 31},
    {"COMMON_APPDATA", 35},
    {"PROGRAM_FILES", 38},
    {"MYPICTURES", 39},
    {"PROFILE", 40},
    {"SYSTEMX86", 41},
    {"PROGRAM_FILESX86", 42},
    {"PROGRAM_FILES_COMMON", 43},
    {"PROGRAM_FILES_COMMONX86", 44},
    {"COMMON_TEMPLATES", 45},
    {"COMMON_DOCUMENTS", 46},
    {"COMMON_MUSIC", 53},
    {"COMMON_PICTURES", 54},
    {"COMMON_VIDEO", 55},
    {nullptr, 0}
  };

  wchar_t gShGetFolderPathBuffer[MAX_PATH]{};

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingLuaState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("user");
    return sSet;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UnsafeLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("unsafe");
    return sSet;
  }

  [[nodiscard]] const UnsafePathEntry* FindUnsafePathByKey(const char* const key) noexcept
  {
    if (key == nullptr) {
      return nullptr;
    }

    for (const UnsafePathEntry& entry : kUnsafePaths) {
      if (entry.key == nullptr) {
        break;
      }

      if (std::strcmp(key, entry.key) == 0) {
        return &entry;
      }
    }

    return nullptr;
  }

  template <lua_CFunction TFunction>
  void RegisterProcessControlLuaFunction(lua_State* const state, const char* const globalName) noexcept
  {
    if (state == nullptr || globalName == nullptr || globalName[0] == '\0') {
      return;
    }

    lua_pushstring(state, globalName);
    lua_pushcclosure(state, TFunction, 0);
    lua_settable(state, LUA_GLOBALSINDEX);
  }

  [[nodiscard]] float MaskWordToFloat(const std::uint32_t value) noexcept
  {
    const std::uint32_t low = value & 0xFFFFu;
    const std::uint32_t high = value >> 16u;
    return (static_cast<float>(high) * kWordFloatScale) + static_cast<float>(low);
  }

  /**
   * Address: 0x0128BC2E (FUN_0128BC2E, lua_SetProcessPriority)
   *
   * What it does:
   * Reads one numeric priority-class argument from Lua and calls
   * `SetPriorityClass` on the current process.
   */
  int __cdecl lua_SetProcessPriority(lua_State* const state)
  {
    if (state == nullptr) {
      return 0;
    }

    const auto priorityClass = static_cast<DWORD>(static_cast<std::uint32_t>(luaL_checknumber(state, 1)));
    const HMODULE kernelModule = ::GetModuleHandleA("kernel32.dll");
    using SetPriorityClassFn = BOOL(WINAPI*)(HANDLE, DWORD);
    auto* const setPriorityClass = kernelModule != nullptr
      ? reinterpret_cast<SetPriorityClassFn>(::GetProcAddress(kernelModule, "SetPriorityClass"))
      : nullptr;
    const BOOL result = setPriorityClass != nullptr ? setPriorityClass(::GetCurrentProcess(), priorityClass) : FALSE;
    lua_pushboolean(state, result != FALSE ? 1 : 0);
    return 1;
  }

  /**
   * Address: 0x0128BCAF (FUN_0128BCAF, lua_SetProcessAffinity)
   *
   * What it does:
   * Reads one numeric affinity mask argument from Lua and applies it to
   * the current process.
   */
  int __cdecl lua_SetProcessAffinity(lua_State* const state)
  {
    if (state == nullptr) {
      return 0;
    }

    const DWORD_PTR affinityMask = static_cast<DWORD_PTR>(static_cast<std::uint32_t>(luaL_checknumber(state, 1)));
    const BOOL result = ::SetProcessAffinityMask(::GetCurrentProcess(), affinityMask);
    lua_pushboolean(state, result != FALSE ? 1 : 0);
    return 1;
  }

  /**
   * Address: 0x0128BD11 (FUN_0128BD11, lua_GetProcessAffinity)
   *
   * What it does:
   * Pushes `GetProcessAffinityMask` success flag plus current process/system
   * affinity masks as Lua numbers.
   */
  int __cdecl lua_GetProcessAffinity(lua_State* const state)
  {
    if (state == nullptr) {
      return 0;
    }

    DWORD_PTR processAffinityMask = 0;
    DWORD_PTR systemAffinityMask = 0;
    const BOOL result = ::GetProcessAffinityMask(::GetCurrentProcess(), &processAffinityMask, &systemAffinityMask);
    lua_pushboolean(state, result != FALSE ? 1 : 0);
    lua_pushnumber(state, MaskWordToFloat(static_cast<std::uint32_t>(processAffinityMask)));
    lua_pushnumber(state, MaskWordToFloat(static_cast<std::uint32_t>(systemAffinityMask)));
    return 3;
  }

  /**
   * Address: 0x0128E107 (FUN_0128E107, patch_InitLuaState)
   *
   * What it does:
   * Injects process-control Lua globals into an initialized Lua state.
   */
  void patch_InitLuaState(LuaPlus::LuaState* const state, const std::int32_t standardLibraries)
  {
    (void)standardLibraries;
    if (state == nullptr || state->m_state == nullptr) {
      return;
    }

    RegisterProcessControlLuaFunction<lua_GetProcessAffinity>(state->m_state, "GetProcessAffinityMask");
    RegisterProcessControlLuaFunction<lua_SetProcessAffinity>(state->m_state, "SetProcessAffinityMask");
    RegisterProcessControlLuaFunction<lua_SetProcessPriority>(state->m_state, "SetProcessPriority");
  }

  [[nodiscard]] const msvc8::string& SaveGameDirName()
  {
    static const msvc8::string kSaveGameDir("savegames");
    return kSaveGameDir;
  }

  [[nodiscard]] const msvc8::string& SaveGameExtName()
  {
    static const msvc8::string kSaveGameExt("SaveGame");
    return kSaveGameExt;
  }

  [[nodiscard]] const msvc8::string& ReplayDirName()
  {
    static const msvc8::string kReplayDir("replays");
    return kReplayDir;
  }

  [[nodiscard]] const msvc8::string& ReplayExtName()
  {
    static const msvc8::string kReplayExt("Replay");
    return kReplayExt;
  }

  [[nodiscard]] const msvc8::string& CampaignSaveExtName()
  {
    static const msvc8::string kCampaignSaveExt("CampaignSave");
    return kCampaignSaveExt;
  }

  [[nodiscard]] const msvc8::string& ScreenshotDirName()
  {
    static const msvc8::string kScreenshotDir("screenshots");
    return kScreenshotDir;
  }

  /**
   * Address: 0x00874C10 (FUN_00874C10, `func_GpgSofDecError`)
   *
   * IDA signature:
   * int __cdecl func_GpgSofDecError(char* ignored, const char* message);
   *
   * What it does:
   * Routes Sofdec middleware errors into gpg warning logs.
   */
  int __cdecl GpgSofDecError(std::uint32_t /*ignored*/, const char* const message)
  {
    gpg::Warnf("SofDec error: %s", message != nullptr ? message : "");
    return 0;
  }

  [[nodiscard]]
  std::filesystem::path MakeAbsolutePath(const std::filesystem::path& path)
  {
    std::error_code ec;
    std::filesystem::path absolutePath = std::filesystem::absolute(path, ec);
    if (ec) {
      return {};
    }

    std::filesystem::path canonicalPath = std::filesystem::weakly_canonical(absolutePath, ec);
    if (ec) {
      return absolutePath;
    }

    return canonicalPath;
  }

  void SetIdentityString(msvc8::string& out, const char* const value)
  {
    out.assign_owned(value != nullptr ? value : "");
  }

  [[nodiscard]] bool IsValidAliasSet(const moho::CfgAliasSet& aliases)
  {
    return aliases.values != nullptr && aliases.count != 0;
  }

  [[nodiscard]] bool TryGetAliasedArgOption(
    const std::string& option, const std::uint32_t requiredArgCount, msvc8::vector<msvc8::string>* const outArgs
  )
  {
    if (option.empty()) {
      return false;
    }
    return moho::CFG_GetArgOption(option.c_str(), requiredArgCount, outArgs);
  }

  [[noreturn]] void ThrowStartupFileError(const char* const functionName, const char* const message)
  {
    std::uint32_t callstack[32]{};
    const std::uint32_t frameCount = moho::PLAT_GetCallStack(nullptr, 32u, callstack);
    const msvc8::string errorText = gpg::STR_Printf(
      "%s: %s", functionName != nullptr ? functionName : "Moho::File", message != nullptr ? message : "File error."
    );
    throw moho::XFileError(errorText.to_std(), callstack, frameCount);
  }

  [[noreturn]] void ThrowFileDirRuntimeError(const char* const runtimeApiName)
  {
    const msvc8::string errnoDescription = moho::FILE_GetErrorFromErrno(errno);
    const msvc8::string detail =
      gpg::STR_Printf("%s error: %s", runtimeApiName != nullptr ? runtimeApiName : "_getcwd", errnoDescription.c_str());
    ThrowStartupFileError("Moho::FILE_Dir", detail.c_str());
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveStartupLuaState()
  {
    if (moho::g_UIManager != nullptr && moho::g_UIManager->mLuaState != nullptr) {
      return moho::g_UIManager->mLuaState;
    }

    return moho::USER_GetLuaState();
  }

  /**
   * Address: 0x0045C2A0 (FUN_0045C2A0, sub_45C2A0)
   *
   * What it does:
   * Returns the first element pointer for the allowed-protocol storage lane.
   */
  [[nodiscard]]
  const std::wstring* AllowedProtocolsBeginUnsafe()
  {
    return gAllowedProtocols.empty() ? nullptr : gAllowedProtocols.data();
  }

  /**
   * Address: 0x0045C2C0 (FUN_0045C2C0, sub_45C2C0)
   *
   * What it does:
   * Returns one-past-last pointer for the allowed-protocol storage lane.
   */
  [[nodiscard]]
  const std::wstring* AllowedProtocolsEndUnsafe()
  {
    return gAllowedProtocols.empty() ? nullptr : gAllowedProtocols.data() + gAllowedProtocols.size();
  }

  /**
   * Address: 0x0045C2D0 (FUN_0045C2D0, sub_45C2D0)
   *
   * What it does:
   * Returns the count of configured allowed URL protocols.
   */
  [[nodiscard]]
  std::size_t AllowedProtocolsCountUnsafe()
  {
    return gAllowedProtocols.size();
  }

  /**
   * Address: 0x0045B540 (FUN_0045B540, func_GetProtocols)
   *
   * What it does:
   * Copies the process-global allowed protocol list into one output vector.
   */
  void CopyAllowedProtocols(std::vector<std::wstring>& outProtocols)
  {
    std::lock_guard<std::mutex> lock(gDiskPathStateLock);
    outProtocols.clear();
    const std::size_t count = AllowedProtocolsCountUnsafe();
    if (count == 0u) {
      return;
    }

    const std::wstring* const first = AllowedProtocolsBeginUnsafe();
    const std::wstring* const last = AllowedProtocolsEndUnsafe();
    if (first == nullptr || last == nullptr || first > last) {
      return;
    }

    outProtocols.assign(first, last);
  }

  [[nodiscard]]
  std::vector<std::wstring> CollectAllowedProtocolsFromLua(LuaPlus::LuaState* const state)
  {
    std::vector<std::wstring> protocols;
    if (state == nullptr) {
      return protocols;
    }

    LuaPlus::LuaObject protocolTable = state->GetGlobal("protocols");
    if (!protocolTable.IsTable()) {
      return protocols;
    }

    LuaPlus::LuaTableIterator iter(&protocolTable, 1);
    while (iter) {
      const char* const protocolName = iter.GetValue().GetString();
      if (protocolName != nullptr && protocolName[0] != '\0') {
        protocols.push_back(gpg::STR_Utf8ToWide(protocolName));
      }
      iter.Next();
    }

    return protocols;
  }

  [[nodiscard]] LuaPlus::LuaObject ImportLuaModule(LuaPlus::LuaState* const state, const char* const modulePath)
  {
    if (state == nullptr || modulePath == nullptr || modulePath[0] == '\0') {
      return LuaPlus::LuaObject{};
    }

    return moho::SCR_ImportLuaModule(state, modulePath);
  }

  [[nodiscard]]
  LuaPlus::LuaObject GetLuaModuleFunction(
    LuaPlus::LuaState* const state, const LuaPlus::LuaObject& moduleObject, const char* const methodName
  )
  {
    if (state == nullptr || methodName == nullptr || methodName[0] == '\0' || moduleObject.IsNil()) {
      return LuaPlus::LuaObject{};
    }

    return moho::SCR_GetLuaTableField(state, moduleObject, methodName);
  }

  [[nodiscard]] LuaPlus::LuaObject QueryOptionValue(const char* const key)
  {
    if (key == nullptr || key[0] == '\0') {
      return LuaPlus::LuaObject{};
    }

    LuaPlus::LuaState* const state = ResolveStartupLuaState();
    if (state == nullptr) {
      return LuaPlus::LuaObject{};
    }

    const LuaPlus::LuaObject prefsModule = ImportLuaModule(state, kUserPrefsModulePath);
    const LuaPlus::LuaObject getOptionFn = GetLuaModuleFunction(state, prefsModule, kGetOptionMethodName);
    if (getOptionFn.IsNil()) {
      return LuaPlus::LuaObject{};
    }

    LuaPlus::LuaFunction<LuaPlus::LuaObject> getOptionCallable(getOptionFn);
    return getOptionCallable(key);
  }

  [[nodiscard]] bool TryParseBooleanText(const char* const text, bool* const outValue)
  {
    if (text == nullptr || outValue == nullptr) {
      return false;
    }

    if (
      gpg::STR_CompareNoCase(text, "true") == 0 || gpg::STR_CompareNoCase(text, "yes") == 0 ||
      gpg::STR_CompareNoCase(text, "on") == 0 || std::strcmp(text, "1") == 0
    ) {
      *outValue = true;
      return true;
    }

    if (
      gpg::STR_CompareNoCase(text, "false") == 0 || gpg::STR_CompareNoCase(text, "no") == 0 ||
      gpg::STR_CompareNoCase(text, "off") == 0 || std::strcmp(text, "0") == 0
    ) {
      *outValue = false;
      return true;
    }

    return false;
  }

  [[nodiscard]] msvc8::string BuildModeLabel(const gpg::gal::HeadAdapterMode& mode)
  {
    return gpg::STR_Printf("%ux%u(%u)", mode.width, mode.height, mode.refreshRate);
  }

  [[nodiscard]] msvc8::string BuildModeKey(const gpg::gal::HeadAdapterMode& mode)
  {
    return gpg::STR_Printf("%u,%u,%u", mode.width, mode.height, mode.refreshRate);
  }

  [[nodiscard]] bool IsModeAboveWindowMinimum(const gpg::gal::HeadAdapterMode& mode)
  {
    return mode.width >= static_cast<std::uint32_t>(moho::wnd_DefaultCreateWidth) &&
      mode.height >= static_cast<std::uint32_t>(moho::wnd_DefaultCreateHeight);
  }

  [[nodiscard]]
  bool HasMode(const msvc8::vector<gpg::gal::HeadAdapterMode>& acceptedModes, const gpg::gal::HeadAdapterMode& mode)
  {
    const gpg::gal::HeadAdapterMode* const start = acceptedModes.begin();
    const gpg::gal::HeadAdapterMode* const finish = acceptedModes.end();
    if (start == nullptr || finish == nullptr) {
      return false;
    }

    for (const gpg::gal::HeadAdapterMode* it = start; it != finish; ++it) {
      if (it->width == mode.width && it->height == mode.height && it->refreshRate == mode.refreshRate) {
        return true;
      }
    }

    return false;
  }

  [[nodiscard]] msvc8::vector<gpg::gal::HeadAdapterMode> CollectAdapterModes(const std::uint32_t headIndex)
  {
    msvc8::vector<gpg::gal::HeadAdapterMode> modes;

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return modes;
    }

    gpg::gal::DeviceContext* const context = device->GetDeviceContext();
    if (context == nullptr || headIndex >= static_cast<std::uint32_t>(context->GetHeadCount())) {
      return modes;
    }

    const gpg::gal::Head& head = context->GetHead(headIndex);
    const gpg::gal::HeadAdapterMode* const sourceBegin = head.adapterModes.begin();
    const gpg::gal::HeadAdapterMode* const sourceEnd = head.adapterModes.end();
    if (sourceBegin == nullptr || sourceEnd == nullptr) {
      return modes;
    }

    for (const gpg::gal::HeadAdapterMode* it = sourceBegin; it != sourceEnd; ++it) {
      if (!IsModeAboveWindowMinimum(*it)) {
        continue;
      }
      if (HasMode(modes, *it)) {
        continue;
      }
      modes.push_back(*it);
    }

    return modes;
  }

  [[nodiscard]] LuaPlus::LuaObject BuildOptionRoot(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject root(state);
    root.AssignNewTable(state, 0, 0);

    LuaPlus::LuaObject states(state);
    states.AssignNewTable(state, 0, 0);
    root.SetObject("states", states);

    return root;
  }

  void AddOptionStateString(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const statesTable,
    const std::int32_t index,
    const char* const text,
    const char* const key
  )
  {
    if (state == nullptr || statesTable == nullptr) {
      return;
    }

    LuaPlus::LuaObject stateEntry(state);
    stateEntry.AssignNewTable(state, 0, 0);
    stateEntry.SetString("text", text != nullptr ? text : "");
    stateEntry.SetString("key", key != nullptr ? key : "");
    statesTable->SetObject(index, stateEntry);
  }

  void AddOptionStateInteger(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const statesTable,
    const std::int32_t index,
    const char* const text,
    const std::int32_t key
  )
  {
    if (state == nullptr || statesTable == nullptr) {
      return;
    }

    LuaPlus::LuaObject stateEntry(state);
    stateEntry.AssignNewTable(state, 0, 0);
    stateEntry.SetString("text", text != nullptr ? text : "");
    stateEntry.SetInteger("key", key);
    statesTable->SetObject(index, stateEntry);
  }

  void RefreshFidelitySupportLanes(const gpg::gal::DeviceContext* const context)
  {
    if (context == nullptr) {
      return;
    }

    moho::graphics_FidelitySupported = context->mPixelShaderProfile > 5 ? 2 : 1;
    moho::shadow_FidelitySupported = context->mPixelShaderProfile > 5 ? 3 : 2;
  }

  [[nodiscard]] LuaPlus::LuaObject
  QueryOptionValueWithLocalOverride(LuaPlus::LuaObject* const localOverrideRoot, const msvc8::string& key)
  {
    if (localOverrideRoot != nullptr && !localOverrideRoot->IsNil()) {
      const LuaPlus::LuaObject localValue = localOverrideRoot->GetByName(key.c_str());
      if (!localValue.IsNil()) {
        return localValue;
      }
    }
    return QueryOptionValue(key.c_str());
  }

  [[nodiscard]] bool TryGetBooleanFromLuaValue(const LuaPlus::LuaObject& value, bool* const outValue)
  {
    if (outValue == nullptr || value.IsNil()) {
      return false;
    }

    if (value.IsBoolean()) {
      *outValue = value.GetBoolean();
      return true;
    }
    if (value.IsNumber()) {
      *outValue = value.GetNumber() != 0.0;
      return true;
    }

    return TryParseBooleanText(value.GetString(), outValue);
  }

  [[nodiscard]] bool TryGetIntegerFromLuaValue(const LuaPlus::LuaObject& value, std::int32_t* const outValue)
  {
    if (outValue == nullptr || value.IsNil()) {
      return false;
    }

    if (value.IsNumber()) {
      *outValue = static_cast<std::int32_t>(value.GetNumber());
      return true;
    }
    if (value.IsBoolean()) {
      *outValue = value.GetBoolean() ? 1 : 0;
      return true;
    }

    const char* const text = value.GetString();
    if (text == nullptr || text[0] == '\0') {
      return false;
    }

    *outValue = static_cast<std::int32_t>(std::atoi(text));
    return true;
  }

  [[nodiscard]] bool TryGetNumberFromLuaValue(const LuaPlus::LuaObject& value, float* const outValue)
  {
    if (outValue == nullptr || value.IsNil()) {
      return false;
    }

    if (value.IsNumber()) {
      *outValue = static_cast<float>(value.GetNumber());
      return true;
    }
    if (value.IsBoolean()) {
      *outValue = value.GetBoolean() ? 1.0f : 0.0f;
      return true;
    }

    const char* const text = value.GetString();
    if (text == nullptr || text[0] == '\0') {
      return false;
    }

    *outValue = std::strtof(text, nullptr);
    return true;
  }

  [[nodiscard]] bool TryGetHexFromLuaValue(const LuaPlus::LuaObject& value, std::uint32_t* const outValue)
  {
    if (outValue == nullptr || value.IsNil()) {
      return false;
    }

    if (value.IsNumber()) {
      *outValue = static_cast<std::uint32_t>(value.GetNumber());
      return true;
    }

    const char* const text = value.GetString();
    if (text == nullptr || text[0] == '\0') {
      return false;
    }

    *outValue = static_cast<std::uint32_t>(std::strtoul(text, nullptr, 0));
    return true;
  }

  [[nodiscard]] bool TryGetStringFromLuaValue(const LuaPlus::LuaObject& value, msvc8::string* const outValue)
  {
    if (outValue == nullptr || value.IsNil()) {
      return false;
    }

    if (value.IsString()) {
      outValue->assign_owned(value.GetString());
      return true;
    }
    if (value.IsNumber()) {
      *outValue = gpg::STR_Printf("%d", static_cast<std::int32_t>(value.GetNumber()));
      return true;
    }
    if (value.IsBoolean()) {
      outValue->assign_owned(value.GetBoolean() ? "true" : "false");
      return true;
    }
    return false;
  }

  /**
   * Address: 0x008C7C30 (FUN_008C7C30, Moho::CUserPrefs::StringObject)
   *
   * What it does:
   * Builds one Lua string object using the preferences Lua state.
   */
  [[nodiscard]] LuaPlus::LuaObject BuildPreferenceStringObject(
    LuaPlus::LuaState* const state, const msvc8::string& value
  )
  {
    LuaPlus::LuaObject out;
    out.AssignString(state, value.c_str() != nullptr ? value.c_str() : "");
    return out;
  }

  /**
   * Address: 0x008C7CB0 (FUN_008C7CB0, Moho::CUserPrefs::StringArrObject)
   *
   * What it does:
   * Builds one Lua array object from a string vector, inserting one
   * `StringObject` element per index starting at 1.
   */
  [[nodiscard]] LuaPlus::LuaObject BuildPreferenceStringArrayObject(
    LuaPlus::LuaState* const state, const msvc8::vector<msvc8::string>& values
  )
  {
    LuaPlus::LuaObject out;
    out.AssignNewTable(state, 0, 0);

    const msvc8::string* const begin = values.begin();
    const msvc8::string* const end = values.end();
    if (begin == nullptr || end == nullptr) {
      return out;
    }

    int luaIndex = 1;
    for (const msvc8::string* it = begin; it != end; ++it, ++luaIndex) {
      LuaPlus::LuaObject itemObject = BuildPreferenceStringObject(state, *it);
      out.Insert(luaIndex, itemObject);
    }

    return out;
  }

  /**
   * Address: 0x008C7AE0 (FUN_008C7AE0, Moho::CUserPrefs::BooleanObject)
   *
   * What it does:
   * Builds one Lua boolean object using the preferences Lua state.
   */
  [[nodiscard]] LuaPlus::LuaObject BuildPreferenceBooleanObject(LuaPlus::LuaState* const state, const bool value)
  {
    LuaPlus::LuaObject out;
    out.AssignBoolean(state, value);
    return out;
  }

  /**
   * Address: 0x008C7B50 (FUN_008C7B50, Moho::CUserPrefs::IntegerObject)
   *
   * What it does:
   * Builds one Lua integer object using the preferences Lua state.
   */
  [[nodiscard]] LuaPlus::LuaObject BuildPreferenceIntegerObject(
    LuaPlus::LuaState* const state, const std::int32_t value
  )
  {
    LuaPlus::LuaObject out;
    out.AssignInteger(state, value);
    return out;
  }

  /**
   * Address: 0x008C7BC0 (FUN_008C7BC0, Moho::CUserPrefs::NumberObject)
   *
   * What it does:
   * Builds one Lua number object using the preferences Lua state.
   */
  [[nodiscard]] LuaPlus::LuaObject BuildPreferenceNumberObject(
    LuaPlus::LuaState* const state, const float value
  )
  {
    LuaPlus::LuaObject out;
    out.AssignNumber(state, value);
    return out;
  }

  /**
   * Address: 0x008C7D60 (FUN_008C7D60)
   *
   * What it does:
   * Copy-constructs one Lua object lane from an existing source object.
   */
  [[nodiscard]] LuaPlus::LuaObject BuildPreferenceCopiedObject(const LuaPlus::LuaObject& source)
  {
    return LuaPlus::LuaObject(source);
  }

  /**
   * Address: 0x008CBFB0 (FUN_008CBFB0, Moho::CUserPrefs::SetBooleanRecursive)
   *
   * What it does:
   * Splits dotted option path (`a.b.c`), walks/creates nested Lua tables, and
   * writes the final leaf as a Lua boolean object.
   */
  void SetPreferenceBooleanRecursive(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const rootTable,
    const msvc8::string& dottedKey,
    const bool value
  )
  {
    if (state == nullptr || rootTable == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> tokens;
    msvc8::string token;
    const char* cursor = dottedKey.c_str();
    while (gpg::STR_GetToken(cursor, ".", token)) {
      tokens.push_back(token);
    }

    const msvc8::string* const begin = tokens.begin();
    const msvc8::string* const end = tokens.end();
    if (begin == nullptr || end == nullptr || begin == end) {
      return;
    }

    LuaPlus::LuaObject current(*rootTable);
    int index = 0;
    const int count = static_cast<int>(tokens.size());
    for (const msvc8::string* it = begin; it != end; ++it, ++index) {
      const char* const keyText = it->c_str() != nullptr ? it->c_str() : "";
      LuaPlus::LuaObject lane = current[keyText];

      if (index >= (count - 1)) {
        LuaPlus::LuaObject boolObject = BuildPreferenceBooleanObject(state, value);
        current.SetObject(keyText, boolObject);
      } else {
        if (lane.IsNil()) {
          lane.AssignNewTable(state, 0, 0);
          current.SetObject(keyText, lane);
        }
        current = current[keyText];
      }
    }
  }

  /**
   * Address: 0x008CC210 (FUN_008CC210, Moho::CUserPrefs::SetIntegerRecursive)
   *
   * What it does:
   * Splits dotted option path (`a.b.c`), walks/creates nested Lua tables, and
   * writes the final leaf as a Lua integer object.
   */
  void SetPreferenceIntegerRecursive(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const rootTable,
    const msvc8::string& dottedKey,
    const std::int32_t value
  )
  {
    if (state == nullptr || rootTable == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> tokens;
    msvc8::string token;
    const char* cursor = dottedKey.c_str();
    while (gpg::STR_GetToken(cursor, ".", token)) {
      tokens.push_back(token);
    }

    const msvc8::string* const begin = tokens.begin();
    const msvc8::string* const end = tokens.end();
    if (begin == nullptr || end == nullptr || begin == end) {
      return;
    }

    LuaPlus::LuaObject current(*rootTable);
    int index = 0;
    const int count = static_cast<int>(tokens.size());
    for (const msvc8::string* it = begin; it != end; ++it, ++index) {
      const char* const keyText = it->c_str() != nullptr ? it->c_str() : "";
      LuaPlus::LuaObject lane = current[keyText];

      if (index >= (count - 1)) {
        LuaPlus::LuaObject integerObject = BuildPreferenceIntegerObject(state, value);
        current.SetObject(keyText, integerObject);
      } else {
        if (lane.IsNil()) {
          lane.AssignNewTable(state, 0, 0);
          current.SetObject(keyText, lane);
        }
        current = current[keyText];
      }
    }
  }

  /**
   * Address: 0x008CC470 (FUN_008CC470, Moho::CUserPrefs::SetNumberRecursive)
   *
   * What it does:
   * Splits dotted option path (`a.b.c`), walks/creates nested Lua tables, and
   * writes the final leaf as a Lua number object.
   */
  void SetPreferenceNumberRecursive(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const rootTable,
    const msvc8::string& dottedKey,
    const float value
  )
  {
    if (state == nullptr || rootTable == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> tokens;
    msvc8::string token;
    const char* cursor = dottedKey.c_str();
    while (gpg::STR_GetToken(cursor, ".", token)) {
      tokens.push_back(token);
    }

    const msvc8::string* const begin = tokens.begin();
    const msvc8::string* const end = tokens.end();
    if (begin == nullptr || end == nullptr || begin == end) {
      return;
    }

    LuaPlus::LuaObject current(*rootTable);
    int index = 0;
    const int count = static_cast<int>(tokens.size());
    for (const msvc8::string* it = begin; it != end; ++it, ++index) {
      const char* const keyText = it->c_str() != nullptr ? it->c_str() : "";
      LuaPlus::LuaObject lane = current[keyText];

      if (index >= (count - 1)) {
        LuaPlus::LuaObject numberObject = BuildPreferenceNumberObject(state, value);
        current.SetObject(keyText, numberObject);
      } else {
        if (lane.IsNil()) {
          lane.AssignNewTable(state, 0, 0);
          current.SetObject(keyText, lane);
        }
        current = current[keyText];
      }
    }
  }

  /**
   * Address: 0x008CC6D0 (FUN_008CC6D0, Moho::CUserPrefs::SetStringRecursive)
   *
   * What it does:
   * Splits dotted option path (`a.b.c`) and walks/creates nested Lua tables,
   * then writes the final leaf as a Lua string object.
   */
  void SetPreferenceStringRecursive(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const rootTable,
    const msvc8::string& dottedKey,
    const msvc8::string& value
  )
  {
    if (state == nullptr || rootTable == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> tokens;
    msvc8::string token;
    const char* cursor = dottedKey.c_str();
    while (gpg::STR_GetToken(cursor, ".", token)) {
      tokens.push_back(token);
    }

    const msvc8::string* const begin = tokens.begin();
    const msvc8::string* const end = tokens.end();
    if (begin == nullptr || end == nullptr || begin == end) {
      return;
    }

    LuaPlus::LuaObject current(*rootTable);
    int index = 0;
    const int count = static_cast<int>(tokens.size());
    for (const msvc8::string* it = begin; it != end; ++it, ++index) {
      const char* const keyText = it->c_str() != nullptr ? it->c_str() : "";
      LuaPlus::LuaObject lane = current[keyText];

      if (index >= (count - 1)) {
        LuaPlus::LuaObject stringObject = BuildPreferenceStringObject(state, value);
        current.SetObject(keyText, stringObject);
      } else {
        if (lane.IsNil()) {
          lane.AssignNewTable(state, 0, 0);
          current.SetObject(keyText, lane);
        }
        current = current[keyText];
      }
    }
  }

  /**
   * Address: 0x008CC930 (FUN_008CC930, Moho::CUserPrefs::SetStringArrRecursive)
   *
   * What it does:
   * Splits dotted option path (`a.b.c`) and walks/creates nested Lua tables,
   * then writes the final leaf as a Lua string-array object.
   */
  void SetPreferenceStringArrayRecursive(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const rootTable,
    const msvc8::string& dottedKey,
    const msvc8::vector<msvc8::string>& values
  )
  {
    if (state == nullptr || rootTable == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> tokens;
    msvc8::string token;
    const char* cursor = dottedKey.c_str();
    while (gpg::STR_GetToken(cursor, ".", token)) {
      tokens.push_back(token);
    }

    const msvc8::string* const begin = tokens.begin();
    const msvc8::string* const end = tokens.end();
    if (begin == nullptr || end == nullptr || begin == end) {
      return;
    }

    LuaPlus::LuaObject current(*rootTable);
    int index = 0;
    const int count = static_cast<int>(tokens.size());
    for (const msvc8::string* it = begin; it != end; ++it, ++index) {
      const char* const keyText = it->c_str() != nullptr ? it->c_str() : "";
      LuaPlus::LuaObject lane = current[keyText];

      if (index >= (count - 1)) {
        LuaPlus::LuaObject arrayObject = BuildPreferenceStringArrayObject(state, values);
        current.SetObject(keyText, arrayObject);
      } else {
        if (lane.IsNil()) {
          lane.AssignNewTable(state, 0, 0);
          current.SetObject(keyText, lane);
        }
        current = current[keyText];
      }
    }
  }

  /**
   * Address: 0x008CCBA0 (FUN_008CCBA0, Moho::CUserPrefs::SetObjectRecursive)
   *
   * What it does:
   * Splits dotted option path (`a.b.c`) and walks/creates nested Lua tables,
   * then writes the final leaf as a copied Lua object lane.
   */
  void SetPreferenceObjectRecursive(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const rootTable,
    const msvc8::string& dottedKey,
    const LuaPlus::LuaObject& value
  )
  {
    if (state == nullptr || rootTable == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> tokens;
    msvc8::string token;
    const char* cursor = dottedKey.c_str();
    while (gpg::STR_GetToken(cursor, ".", token)) {
      tokens.push_back(token);
    }

    const msvc8::string* const begin = tokens.begin();
    const msvc8::string* const end = tokens.end();
    if (begin == nullptr || end == nullptr || begin == end) {
      return;
    }

    LuaPlus::LuaObject current(*rootTable);
    int index = 0;
    const int count = static_cast<int>(tokens.size());
    for (const msvc8::string* it = begin; it != end; ++it, ++index) {
      const char* const keyText = it->c_str() != nullptr ? it->c_str() : "";
      LuaPlus::LuaObject lane = current[keyText];

      if (index >= (count - 1)) {
        LuaPlus::LuaObject copiedObject = BuildPreferenceCopiedObject(value);
        current.SetObject(keyText, copiedObject);
      } else {
        if (lane.IsNil()) {
          lane.AssignNewTable(state, 0, 0);
          current.SetObject(keyText, lane);
        }
        current = current[keyText];
      }
    }
  }

  class CUserPrefsRuntime final : public moho::IUserPrefs
  {
  public:
    /**
     * Address: 0x008C7410 (FUN_008C7410, Moho::IUserPrefs::IUserPrefs)
     *
     * What it does:
     * Initializes preferences state storage (strings + Lua state/object) and
     * creates an empty root preference table.
     */
    CUserPrefsRuntime()
      : mPreferencesFilePath()
      , mPreferencesProfileName()
      , mState(LuaPlus::LuaState::LIB_BASE)
      , mRoot()
    {
      mRoot.AssignNewTable(&mState, 0, 0);
    }

    ~CUserPrefsRuntime() = default;

    msvc8::string* GetStr1() override
    {
      return &mPreferencesFilePath;
    }

    msvc8::string* GetStr2() override
    {
      return &mPreferencesProfileName;
    }

    void RefreshCurrentProfile() override
    {
      const LuaPlus::LuaObject currentProfile = QueryOptionValue("profile.current");
      if (currentProfile.IsNil()) {
        return;
      }

      msvc8::string profileName;
      if (TryGetStringFromLuaValue(currentProfile, &profileName)) {
        mPreferencesProfileName = profileName;
      }
    }

    bool GetBoolean(const msvc8::string& key, const bool fallback) override
    {
      bool valueAsBool = fallback;
      const LuaPlus::LuaObject value = QueryOptionValueWithLocalOverride(&mRoot, key);
      if (TryGetBooleanFromLuaValue(value, &valueAsBool)) {
        return valueAsBool;
      }
      return fallback;
    }

    std::int32_t GetInteger(const msvc8::string& key, const std::int32_t fallback) override
    {
      std::int32_t valueAsInteger = fallback;
      const LuaPlus::LuaObject value = QueryOptionValueWithLocalOverride(&mRoot, key);
      if (TryGetIntegerFromLuaValue(value, &valueAsInteger)) {
        return valueAsInteger;
      }
      return fallback;
    }

    float GetNumber(const msvc8::string& key, const float fallback) override
    {
      float valueAsNumber = fallback;
      const LuaPlus::LuaObject value = QueryOptionValueWithLocalOverride(&mRoot, key);
      if (TryGetNumberFromLuaValue(value, &valueAsNumber)) {
        return valueAsNumber;
      }
      return fallback;
    }

    /**
     * Address: 0x008C7710 (FUN_008C7710, Moho::CUserPrefs::GetHex)
     *
     * What it does:
     * Reads one preference value as Lua string-convertible text and parses it
     * as hexadecimal (optional `0x` prefix), returning fallback on conversion failure.
     */
    std::uint32_t GetHex(const msvc8::string& key, const std::uint32_t fallback) override
    {
      const LuaPlus::LuaObject value = QueryOptionValueWithLocalOverride(&mRoot, key);
      if (!value.IsConvertibleToString()) {
        return fallback;
      }

      const char* hexText = value.ToString();
      if (hexText == nullptr || hexText[0] == '\0') {
        return fallback;
      }

      if (_strnicmp(hexText, "0x", 2) == 0) {
        hexText += 2;
      }

      return static_cast<std::uint32_t>(gpg::STR_Xtoi(hexText));
    }

    msvc8::string GetString(const msvc8::string& key, const msvc8::string& fallback) override
    {
      msvc8::string valueAsString;
      valueAsString = fallback;

      const LuaPlus::LuaObject value = QueryOptionValueWithLocalOverride(&mRoot, key);
      if (TryGetStringFromLuaValue(value, &valueAsString)) {
        return valueAsString;
      }

      return fallback;
    }

    msvc8::vector<msvc8::string>
    GetStringArr(const msvc8::string& key, const msvc8::vector<msvc8::string>& fallback) override
    {
      const LuaPlus::LuaObject value = QueryOptionValueWithLocalOverride(&mRoot, key);
      if (value.IsNil() || !value.IsTable()) {
        return fallback;
      }

      msvc8::vector<msvc8::string> outValues;
      const int count = value.GetN();
      if (count <= 0) {
        return fallback;
      }

      for (int index = 1; index <= count; ++index) {
        msvc8::string itemValue;
        if (!TryGetStringFromLuaValue(value.GetByIndex(index), &itemValue)) {
          continue;
        }
        outValues.push_back(itemValue);
      }

      return outValues.empty() ? fallback : outValues;
    }

    void SetBoolean(const msvc8::string& key, const bool value) override
    {
      SetPreferenceBooleanRecursive(&mState, &mRoot, key, value);
    }

    void SetInteger(const msvc8::string& key, const std::int32_t value) override
    {
      SetPreferenceIntegerRecursive(&mState, &mRoot, key, value);
    }

    void SetNumber(const msvc8::string& key, const float value) override
    {
      SetPreferenceNumberRecursive(&mState, &mRoot, key, value);
    }

    void SetHex(const msvc8::string& key, const std::uint32_t value) override
    {
      const msvc8::string valueText = gpg::STR_Printf("0x%08x", static_cast<unsigned int>(value));
      SetPreferenceStringRecursive(&mState, &mRoot, key, valueText);
    }

    void SetString(const msvc8::string& key, const msvc8::string& value) override
    {
      SetPreferenceStringRecursive(&mState, &mRoot, key, value);
    }

    void SetStringArr(const msvc8::string& key, const msvc8::vector<msvc8::string>& values) override
    {
      SetPreferenceStringArrayRecursive(&mState, &mRoot, key, values);
    }

    /**
     * Address: 0x008C7EA0 (FUN_008C7EA0, Moho::CUserPrefs::LookupCurrentOption)
     *
     * What it does:
     * Resolves one option value from the currently selected profile:
     * `profile.profiles[profile.current].options[key]`.
     */
    [[nodiscard]] LuaPlus::LuaObject LookupCurrentOptionObject(const msvc8::string& key)
    {
      LuaPlus::LuaObject currentProfile = mRoot.Lookup("profile.current");
      if (currentProfile.IsNil()) {
        return currentProfile;
      }

      LuaPlus::LuaObject profiles = mRoot.Lookup("profile.profiles");
      if (profiles.IsNil()) {
        return profiles;
      }

      const int profileIndex = static_cast<int>(currentProfile.GetNumber());
      LuaPlus::LuaObject profileObject = profiles[profileIndex];
      LuaPlus::LuaObject optionsObject = profileObject.Lookup("options");
      if (optionsObject.IsNil() || !optionsObject.IsTable()) {
        return optionsObject;
      }

      return optionsObject.Lookup(key.c_str());
    }

    /**
     * Address: 0x008C8040 (FUN_008C8040, Moho::CUserPrefs::LookupKey)
     *
     * What it does:
     * Resolves one root preference table entry by key from `mRoot`.
     */
    [[nodiscard]] LuaPlus::LuaObject LookupKeyObject(const msvc8::string& key)
    {
      if (mRoot.IsNil()) {
        return LuaPlus::LuaObject(mRoot);
      }

      return mRoot.Lookup(key.c_str());
    }

    bool LookupCurrentOption(msvc8::string* const outOption, const msvc8::string& key) override
    {
      if (outOption == nullptr) {
        return false;
      }

      const LuaPlus::LuaObject optionObject = LookupCurrentOptionObject(key);
      return TryGetStringFromLuaValue(optionObject, outOption);
    }

    bool LookupKey(msvc8::string* const outOption, const msvc8::string& key) override
    {
      if (outOption == nullptr) {
        return false;
      }

      const LuaPlus::LuaObject optionObject = LookupKeyObject(key);
      return TryGetStringFromLuaValue(optionObject, outOption);
    }

    void* GetPreferenceTable() override
    {
      return &mRoot;
    }

    void SetObject(const msvc8::string& key, void* const valueObject) override
    {
      SetPreferenceObjectRecursive(&mState, &mRoot, key, *static_cast<LuaPlus::LuaObject*>(valueObject));
    }

    void* GetState() override
    {
      return &mState;
    }

  private:
    msvc8::string mPreferencesFilePath;
    msvc8::string mPreferencesProfileName;
    LuaPlus::LuaState mState;
    LuaPlus::LuaObject mRoot;
  };

  static_assert(sizeof(CUserPrefsRuntime) == 0x84, "CUserPrefsRuntime size must be 0x84");
} // namespace

std::int32_t moho::wnd_MinCmdLineWidth = 1024;
std::int32_t moho::wnd_MinCmdLineHeight = 720;
std::int32_t moho::wnd_MinDragWidth = 1024;
std::int32_t moho::wnd_MinDragHeight = 768;
std::int32_t moho::wnd_DefaultCreateWidth = 1024;
std::int32_t moho::wnd_DefaultCreateHeight = 768;

std::int32_t moho::graphics_Fidelity = 1;
std::int32_t moho::graphics_FidelitySupported = 1;
std::int32_t moho::shadow_Fidelity = 2;
std::int32_t moho::shadow_FidelitySupported = 2;
bool moho::d3d_UseRefRast = false;
bool moho::d3d_ForceSoftwareVP = false;
bool moho::d3d_NoPureDevice = false;
bool moho::d3d_ForceDirect3DDebugEnabled = false;
bool moho::d3d_WindowsCursor = false;
std::uint32_t moho::sAdapterNotCLOverridden = 1;
bool moho::sDeviceLock = false;

const moho::CfgAliasSet& moho::CFG_GetOptionPrefixes()
{
  return kOptionPrefixesSet;
}

const moho::CfgAliasSet& moho::CFG_GetAdapterOptionAliases()
{
  return kAdapterAliasesSet;
}

const moho::CfgAliasSet& moho::CFG_GetMaximizeOptionAliases()
{
  return kMaximizeAliasesSet;
}

const moho::CfgAliasSet& moho::CFG_GetDualOptionAliases()
{
  return kDualAliasesSet;
}

const moho::CfgAliasSet& moho::CFG_GetHeadOptionAliases()
{
  return kHeadAliasesSet;
}

const moho::CfgAliasSet& moho::CFG_GetFullscreenOptionAliases()
{
  return kFullscreenAliasesSet;
}

const moho::CfgAliasSet& moho::CFG_GetWindowedOptionAliases()
{
  return kWindowedAliasesSet;
}

/**
 * Address: 0x008CFF00 (FUN_008CFF00, func_FindOptionAmong)
 *
 * What it does:
 * Scans prefixed alias pairs (`prefix + left + right`) and returns true on the
 * first command-line option that resolves through `CFG_GetArgOption`.
 */
bool moho::CFG_GetArgOptionComposedAliases(
  const CfgAliasSet& leftAliases,
  const CfgAliasSet& rightAliases,
  const std::uint32_t requiredArgCount,
  msvc8::vector<msvc8::string>* const outArgs
)
{
  if (!IsValidAliasSet(leftAliases) || !IsValidAliasSet(rightAliases)) {
    return false;
  }

  const CfgAliasSet& prefixes = CFG_GetOptionPrefixes();
  for (std::size_t prefixIdx = 0; prefixIdx < prefixes.count; ++prefixIdx) {
    const char* const prefix = prefixes.values[prefixIdx];
    if (prefix == nullptr) {
      continue;
    }

    for (std::size_t leftIdx = 0; leftIdx < leftAliases.count; ++leftIdx) {
      const char* const left = leftAliases.values[leftIdx];
      if (left == nullptr || left[0] == '\0') {
        continue;
      }

      for (std::size_t rightIdx = 0; rightIdx < rightAliases.count; ++rightIdx) {
        const char* const right = rightAliases.values[rightIdx];
        if (right == nullptr || right[0] == '\0') {
          continue;
        }

        std::string option;
        option.reserve(std::strlen(prefix) + std::strlen(left) + std::strlen(right));
        option.append(prefix);
        option.append(left);
        option.append(right);
        if (TryGetAliasedArgOption(option, requiredArgCount, outArgs)) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Address family:
 * - 0x008D00E0 (FUN_008D00E0)
 * - 0x008D0260 (FUN_008D0260)
 * - 0x008D02D0 (FUN_008D02D0)
 *
 * What it does:
 * Scans prefixed single aliases (`prefix + alias`) and returns true on the
 * first command-line option that resolves through `CFG_GetArgOption`.
 */
bool moho::CFG_GetArgOptionAliases(
  const CfgAliasSet& aliases, const std::uint32_t requiredArgCount, msvc8::vector<msvc8::string>* const outArgs
)
{
  if (!IsValidAliasSet(aliases)) {
    return false;
  }

  const CfgAliasSet& prefixes = CFG_GetOptionPrefixes();
  for (std::size_t prefixIdx = 0; prefixIdx < prefixes.count; ++prefixIdx) {
    const char* const prefix = prefixes.values[prefixIdx];
    if (prefix == nullptr) {
      continue;
    }

    for (std::size_t aliasIdx = 0; aliasIdx < aliases.count; ++aliasIdx) {
      const char* const alias = aliases.values[aliasIdx];
      if (alias == nullptr || alias[0] == '\0') {
        continue;
      }

      std::string option;
      option.reserve(std::strlen(prefix) + std::strlen(alias));
      option.append(prefix);
      option.append(alias);
      if (TryGetAliasedArgOption(option, requiredArgCount, outArgs)) {
        return true;
      }
    }
  }

  return false;
}

bool moho::CFG_HasMaximizeOption()
{
  return CFG_GetArgOptionAliases(CFG_GetMaximizeOptionAliases(), 0, nullptr);
}

/**
 * Address: 0x008CD6C0 (Resolution::Resolution parser body)
 *
 * What it does:
 * Parses `width,height,fps` CSV text into three integer lanes.
 */
bool moho::CFG_ParseResolutionTriple(const gpg::StrArg value, ResolutionTriple* const outResolution)
{
  if (outResolution == nullptr) {
    return false;
  }

  outResolution->width = 0;
  outResolution->height = 0;
  outResolution->framesPerSecond = 0;

  const char* cursor = value != nullptr ? value : "";
  if (cursor[0] == '\0') {
    return false;
  }

  msvc8::string token;
  msvc8::vector<msvc8::string> tokens;
  while (gpg::STR_GetToken(cursor, ",", token)) {
    tokens.push_back(token);
  }

  if (tokens.size() != 3) {
    return false;
  }

  outResolution->width = std::atoi(tokens[0].c_str());
  outResolution->height = std::atoi(tokens[1].c_str());
  outResolution->framesPerSecond = std::atoi(tokens[2].c_str());
  return true;
}

/**
 * Address context:
 * - 0x008CE0A0 constructor path initializes these global identity lanes.
 *
 * What it does:
 * Writes fixed app/company/pref strings and 4-word savegame id tuple.
 */
void moho::APP_InitializeIdentity()
{
  std::call_once(gAppIdentityInitOnce, [] {
    SetIdentityString(gAppIdentity.mCompanyName, "Gas Powered Games");
    SetIdentityString(gAppIdentity.mProductName, "Supreme Commander Forged Alliance");
    SetIdentityString(gAppIdentity.mPreferencePrefix, "SCFA");
    gAppIdentity.mGameIdParts[0] = 0xFA42B43A;
    gAppIdentity.mGameIdParts[1] = 0x68BC5B02;
    gAppIdentity.mGameIdParts[2] = 0x4F701F15;
    gAppIdentity.mGameIdParts[3] = 0x7C3E8FB0;
  });
}

const msvc8::string& moho::APP_GetCompanyName()
{
  APP_InitializeIdentity();
  return gAppIdentity.mCompanyName;
}

const msvc8::string& moho::APP_GetProductName()
{
  APP_InitializeIdentity();
  return gAppIdentity.mProductName;
}

const msvc8::string& moho::APP_GetPreferencePrefix()
{
  APP_InitializeIdentity();
  return gAppIdentity.mPreferencePrefix;
}

std::uint32_t moho::APP_GetGameIdPart(const std::size_t index)
{
  APP_InitializeIdentity();
  if (index >= 4) {
    return 0;
  }
  return gAppIdentity.mGameIdParts[index];
}

/**
 * Address: 0x009071C0 (FUN_009071C0)
 *
 * What it does:
 * Stores the AQtime instrumentation mode byte used by startup gates.
 */
void moho::APP_SetAqtimeInstrumentationMode(const std::uint8_t mode)
{
  gAqtimeInstrumentationMode = mode;
}

std::uint8_t moho::APP_GetAqtimeInstrumentationMode()
{
  return gAqtimeInstrumentationMode;
}

/**
 * Address: 0x0041B560 (FUN_0041B560)
 * Mangled:
 * ?CFG_GetArgOption@Moho@@YA_NVStrArg@gpg@@IPAV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@@Z
 *
 * What it does:
 * Finds a command-line option case-insensitively and optionally copies
 * its following positional arguments.
 */
bool moho::CFG_GetArgOption(
  const gpg::StrArg option, const std::uint32_t requiredArgCount, msvc8::vector<msvc8::string>* const outArgs
)
{
  if (option == nullptr || option[0] == '\0') {
    return false;
  }

  for (int index = 1; index < __argc; ++index) {
    const char* const argument = __argv[index];
    if (argument == nullptr || gpg::STR_CompareNoCase(argument, option) != 0) {
      continue;
    }

    const int availableArgCount = __argc - index - 1;
    if (availableArgCount < 0 || static_cast<std::uint32_t>(availableArgCount) < requiredArgCount) {
      continue;
    }

    if (outArgs != nullptr) {
      outArgs->clear();
      outArgs->reserve(requiredArgCount);
      for (std::uint32_t argIndex = 0; argIndex < requiredArgCount; ++argIndex) {
        const char* const value = __argv[index + 1 + static_cast<int>(argIndex)];
        outArgs->push_back(msvc8::string(value != nullptr ? value : ""));
      }
    }

    return true;
  }

  return false;
}

/**
 * Address: 0x0041B690 (FUN_0041B690)
 * Mangled:
 * ?CFG_GetArgs@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
 *
 * What it does:
 * Concatenates process command-line arguments (argv[1..]) with single-space
 * separators and trims the trailing separator.
 */
msvc8::string moho::CFG_GetArgs()
{
  std::string joinedArgs;
  for (int index = 1; index < __argc; ++index) {
    if (__argv == nullptr || __argv[index] == nullptr) {
      continue;
    }

    joinedArgs.append(__argv[index]);
    joinedArgs.push_back(' ');
  }

  if (!joinedArgs.empty()) {
    joinedArgs.pop_back();
  }

  msvc8::string result;
  result.assign_owned(joinedArgs);
  return result;
}

/**
 * Address: 0x0041B810 (FUN_0041B810, cfunc_GetCommandLineArgL)
 *
 * What it does:
 * Resolves one command-line option with requested argument count. Returns a
 * Lua array table of copied argument strings when found, otherwise returns
 * boolean false.
 */
int moho::cfunc_GetCommandLineArgL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetCommandLineArgHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject optionArg(state, 1);
  const char* const optionText = optionArg.GetString();
  gpg::Logf(optionText != nullptr ? optionText : "");

  LuaPlus::LuaStackObject requestedCountArg(state, 2);
  const int requestedArgCount = requestedCountArg.GetInteger();

  msvc8::vector<msvc8::string> optionValues;
  const bool foundOption = CFG_GetArgOption(optionText, static_cast<std::uint32_t>(requestedArgCount), &optionValues);

  LuaPlus::LuaObject result(state);
  if (foundOption) {
    result.AssignNewTable(state, requestedArgCount, 0);

    if (requestedArgCount > 0) {
      const int cappedCount = std::min(requestedArgCount, static_cast<int>(optionValues.size()));
      for (int index = 0; index < cappedCount; ++index) {
        LuaPlus::LuaObject value(state);
        value.AssignString(state, optionValues[static_cast<std::size_t>(index)].c_str());
        result.SetObject(index + 1, value);
      }
    }
  } else {
    result.AssignBoolean(state, false);
  }

  result.PushStack(state);
  return 1;
}

/**
 * Address: 0x0041B790 (FUN_0041B790, cfunc_GetCommandLineArg)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetCommandLineArgL`.
 */
int moho::cfunc_GetCommandLineArg(lua_State* const luaContext)
{
  return cfunc_GetCommandLineArgL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x0041B7B0 (FUN_0041B7B0, func_GetCommandLineArg_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `GetCommandLineArg`.
 */
moho::CScrLuaInitForm* moho::func_GetCommandLineArg_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetCommandLineArg",
    &moho::cfunc_GetCommandLineArg,
    nullptr,
    "<global>",
    kGetCommandLineArgHelpText
  );
  return &binder;
}

/**
 * Address: 0x0041BAA0 (FUN_0041BAA0, cfunc_HasCommandLineArgL)
 *
 * What it does:
 * Resolves one command-line option and pushes whether it is present.
 */
int moho::cfunc_HasCommandLineArgL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kHasCommandLineArgHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject optionArg(state, 1);
  const char* const optionText = optionArg.GetString();

  msvc8::vector<msvc8::string> optionValues;
  const bool foundOption = CFG_GetArgOption(optionText, 0, &optionValues);
  lua_pushboolean(rawState, foundOption ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0041BA20 (FUN_0041BA20, cfunc_HasCommandLineArg)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_HasCommandLineArgL`.
 */
int moho::cfunc_HasCommandLineArg(lua_State* const luaContext)
{
  return cfunc_HasCommandLineArgL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x0041BA40 (FUN_0041BA40, func_HasCommandLineArg_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `HasCommandLineArg`.
 */
moho::CScrLuaInitForm* moho::func_HasCommandLineArg_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "HasCommandLineArg",
    &moho::cfunc_HasCommandLineArg,
    nullptr,
    "<global>",
    kHasCommandLineArgHelpText
  );
  return &binder;
}

/**
 * Address: 0x004D6940 (FUN_004D6940, cfunc_SHGetFolderPathL)
 *
 * What it does:
 * Resolves one unsafe-path id (`DESKTOP`, `APPDATA`, etc.) into a CSIDL and
 * pushes the resolved path string with a trailing backslash.
 */
int moho::cfunc_SHGetFolderPathL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSHGetFolderPathHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject idArg(state, 1);
  const char* keyText = lua_tostring(rawState, 1);
  if (keyText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&idArg, "string");
    keyText = "";
  }

  const UnsafePathEntry* const pathEntry = FindUnsafePathByKey(keyText);
  if (pathEntry == nullptr) {
    LuaPlus::LuaState::Error(state, kUnknownShGetFolderPathIdErrorText, keyText);
    gpg::HandleAssertFailure(kUnreachableAssertText, kScrUnsafeUnknownPathLine, kScrUnsafeSourcePath);
    return 0;
  }

  const HRESULT status = ::SHGetFolderPathW(nullptr, pathEntry->csidl, nullptr, 0, gShGetFolderPathBuffer);
  if (status != S_OK) {
    LuaPlus::LuaState::Error(state, kShGetFolderPathFailedErrorText, status);
  }

  msvc8::string utf8Path = gpg::STR_WideToUtf8(gShGetFolderPathBuffer);
  if (utf8Path.empty() || utf8Path[utf8Path.size() - 1u] != '\\') {
    utf8Path.push_back('\\');
  }

  lua_pushstring(rawState, utf8Path.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x004D68C0 (FUN_004D68C0, cfunc_SHGetFolderPath)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_SHGetFolderPathL`.
 */
int moho::cfunc_SHGetFolderPath(lua_State* const luaContext)
{
  return cfunc_SHGetFolderPathL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x004D68E0 (FUN_004D68E0, func_SHGetFolderPath_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the unsafe Lua binder definition for `SHGetFolderPath`.
 */
moho::CScrLuaInitForm* moho::func_SHGetFolderPath_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UnsafeLuaInitSet(),
    "SHGetFolderPath",
    &moho::cfunc_SHGetFolderPath,
    nullptr,
    "<global>",
    kSHGetFolderPathHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC3800 (FUN_00BC3800, register_GetCommandLineArg_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_GetCommandLineArg_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_GetCommandLineArg_LuaFuncDef()
{
  return func_GetCommandLineArg_LuaFuncDef();
}

/**
 * Address: 0x00BC3810 (FUN_00BC3810, register_HasCommandLineArg_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_HasCommandLineArg_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_HasCommandLineArg_LuaFuncDef()
{
  return func_HasCommandLineArg_LuaFuncDef();
}

/**
 * Address: 0x00BC63D0 (FUN_00BC63D0, register_coreInitFormSet)
 *
 * What it does:
 * Links the core init-form set at the head of `CScrLuaInitFormSet::sSets`
 * and returns the previous head.
 */
moho::CScrLuaInitFormSet* moho::register_coreInitFormSet()
{
  CScrLuaInitFormSet* const previousHead = CScrLuaInitFormSet::sSets;
  CScrLuaInitFormSet& coreSet = CoreLuaInitSet();
  coreSet.mNextSet = previousHead;
  CScrLuaInitFormSet::sSets = &coreSet;
  return previousHead;
}

/**
 * Address: 0x00BC63F0 (FUN_00BC63F0, register_userInitFormSet)
 *
 * What it does:
 * Links the user init-form set at the head of `CScrLuaInitFormSet::sSets`
 * and returns the previous head.
 */
moho::CScrLuaInitFormSet* moho::register_userInitFormSet()
{
  CScrLuaInitFormSet* const previousHead = CScrLuaInitFormSet::sSets;
  CScrLuaInitFormSet& userSet = UserLuaInitSet();
  userSet.mNextSet = previousHead;
  CScrLuaInitFormSet::sSets = &userSet;
  return previousHead;
}

/**
 * Address: 0x00BC66E0 (FUN_00BC66E0, register_unsafeInitFormSet)
 *
 * What it does:
 * Links the unsafe init-form set at the head of `CScrLuaInitFormSet::sSets`
 * and returns the previous head.
 */
moho::CScrLuaInitFormSet* moho::register_unsafeInitFormSet()
{
  CScrLuaInitFormSet* const previousHead = CScrLuaInitFormSet::sSets;
  CScrLuaInitFormSet& unsafeSet = UnsafeLuaInitSet();
  unsafeSet.mNextSet = previousHead;
  CScrLuaInitFormSet::sSets = &unsafeSet;
  return previousHead;
}

/**
 * Address: 0x00BC6700 (FUN_00BC6700, register_SHGetFolderPath_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_SHGetFolderPath_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_SHGetFolderPath_LuaFuncDef()
{
  return func_SHGetFolderPath_LuaFuncDef();
}

/**
 * Address: 0x00780AF0 (FUN_00780AF0, cfunc_GetTextureDimensionsL)
 *
 * What it does:
 * Loads one texture by filename and optional border and returns
 * `(width, height)` on success, otherwise `nil`.
 */
int moho::cfunc_GetTextureDimensionsL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgRangeWarning, kGetTextureDimensionsHelpText, 1, 2, argumentCount);
  }

  std::uint32_t border = 1u;
  if (lua_gettop(rawState) >= 2) {
    LuaPlus::LuaStackObject borderArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&borderArg, "integer");
    }

    const double borderAsDouble = lua_tonumber(rawState, 3);
    const auto borderAsSignedInt = static_cast<int>(borderAsDouble);
    border = static_cast<std::uint32_t>(borderAsSignedInt);
  }

  LuaPlus::LuaStackObject filenameArg(state, 1);
  const char* filename = lua_tostring(rawState, 1);
  if (filename == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&filenameArg, "string");
    filename = "";
  }

  boost::shared_ptr<CD3DBatchTexture> texture = CD3DBatchTexture::FromFile(filename, border);
  if (texture) {
    lua_pushnumber(rawState, static_cast<float>(static_cast<int>(texture->mWidth)));
    (void)lua_gettop(rawState);
    lua_pushnumber(rawState, static_cast<float>(static_cast<int>(texture->mHeight)));
    (void)lua_gettop(rawState);
    return 2;
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00780A70 (FUN_00780A70, cfunc_GetTextureDimensions)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetTextureDimensionsL`.
 */
int moho::cfunc_GetTextureDimensions(lua_State* const luaContext)
{
  return cfunc_GetTextureDimensionsL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x00780A90 (FUN_00780A90, func_GetTextureDimensions_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for
 * `GetTextureDimensions` in the user init set.
 */
moho::CScrLuaInitForm* moho::func_GetTextureDimensions_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetTextureDimensions",
    &moho::cfunc_GetTextureDimensions,
    nullptr,
    "<global>",
    kGetTextureDimensionsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00874FA0 (FUN_00874FA0, cfunc_SetMovieVolume)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_SetMovieVolumeL`.
 */
int moho::cfunc_SetMovieVolume(lua_State* const luaContext)
{
  return cfunc_SetMovieVolumeL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x00874FC0 (FUN_00874FC0, func_SetMovieVolume_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `SetMovieVolume`.
 */
moho::CScrLuaInitForm* moho::func_SetMovieVolume_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetMovieVolume",
    &moho::cfunc_SetMovieVolume,
    nullptr,
    "<global>",
    kSetMovieVolumeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00875020 (FUN_00875020, cfunc_SetMovieVolumeL)
 *
 * What it does:
 * Reads one volume argument, validates numeric type, and applies movie-volume
 * transform through process-global movie manager lane when present.
 */
int moho::cfunc_SetMovieVolumeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSetMovieVolumeHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject volumeArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    volumeArg.TypeError("number");
  }

  const float requestedVolume = static_cast<float>(lua_tonumber(rawState, 1));
  if (gMovieManager != nullptr) {
    gMovieManager->SetVolumeFromLua(requestedVolume);
  }
  return 0;
}

/**
 * Address: 0x00875100 (FUN_00875100, cfunc_GetMovieVolume)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetMovieVolumeL`.
 */
int moho::cfunc_GetMovieVolume(lua_State* const luaContext)
{
  return cfunc_GetMovieVolumeL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x00875120 (FUN_00875120, func_GetMovieVolume_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `GetMovieVolume`.
 */
moho::CScrLuaInitForm* moho::func_GetMovieVolume_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetMovieVolume",
    &moho::cfunc_GetMovieVolume,
    nullptr,
    "<global>",
    kGetMovieVolumeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00875180 (FUN_00875180, cfunc_GetMovieVolumeL)
 *
 * What it does:
 * Validates zero-argument call shape and returns current movie-volume lane
 * (fallback `1.0` when no movie manager exists).
 */
int moho::cfunc_GetMovieVolumeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetMovieVolumeHelpText, 0, argumentCount);
  }

  float volume = 1.0f;
  if (gMovieManager != nullptr) {
    volume = gMovieManager->GetVolumeForLua();
  }

  lua_pushnumber(rawState, volume);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008753A0 (FUN_008753A0, cfunc_GetMovieDuration)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetMovieDurationL`.
 */
int moho::cfunc_GetMovieDuration(lua_State* const luaContext)
{
  return cfunc_GetMovieDurationL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008753C0 (FUN_008753C0, func_GetMovieDuration_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `GetMovieDuration`
 * in the core init set.
 */
moho::CScrLuaInitForm* moho::func_GetMovieDuration_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "GetMovieDuration",
    &moho::cfunc_GetMovieDuration,
    nullptr,
    "<global>",
    kGetMovieDurationHelpText
  );
  return &binder;
}

/**
 * Address: 0x00875420 (FUN_00875420, cfunc_GetMovieDurationL)
 *
 * What it does:
 * Reads one movie path argument, validates string type, and returns
 * duration in seconds through `MOV_GetDuration`.
 */
int moho::cfunc_GetMovieDurationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected %d args, but got %d", kGetMovieDurationHelpText, 1, argumentCount
    );
  }

  LuaPlus::LuaStackObject moviePathArg(state, 1);
  const char* moviePath = lua_tostring(rawState, 1);
  if (moviePath == nullptr) {
    moviePathArg.TypeError("string");
    moviePath = "";
  }

  const float durationSeconds = MOV_GetDuration(moviePath);
  lua_pushnumber(rawState, durationSeconds);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C9660 (FUN_008C9660, cfunc_GetAntiAliasingOptions)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetAntiAliasingOptionsL`.
 */
int moho::cfunc_GetAntiAliasingOptions(lua_State* const luaContext)
{
  return cfunc_GetAntiAliasingOptionsL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008C9680 (FUN_008C9680, func_GetAntiAliasingOptions_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for
 * `GetAntiAliasingOptions` in the user init set.
 */
moho::CScrLuaInitForm* moho::func_GetAntiAliasingOptions_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetAntiAliasingOptions",
    &moho::cfunc_GetAntiAliasingOptions,
    nullptr,
    "<global>",
    kGetAntiAliasingOptionsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C96E0 (FUN_008C96E0, cfunc_GetAntiAliasingOptionsL)
 *
 * What it does:
 * Builds and returns a Lua array-like table of anti-aliasing option keys from
 * active head sample modes (`0` disabled plus packed mode entries).
 */
int moho::cfunc_GetAntiAliasingOptionsL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected %d args, but got %d", kGetAntiAliasingOptionsHelpText, 0, argumentCount
    );
  }

  LuaPlus::LuaObject optionsTable(state);
  optionsTable.AssignNewTable(state, 0, 0);
  optionsTable.SetInteger(1, 0);

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  gpg::gal::DeviceContext* const context = device ? device->GetDeviceContext() : nullptr;
  const gpg::gal::Head* const head =
    (context != nullptr && context->GetHeadCount() > 0) ? &context->GetHead(0) : nullptr;

  if (head != nullptr) {
    const gpg::gal::HeadSampleOption* const begin = head->mStrs.begin();
    const gpg::gal::HeadSampleOption* const end = head->mStrs.end();
    if (begin != nullptr && end != nullptr) {
      std::int32_t tableIndex = 2;
      for (const gpg::gal::HeadSampleOption* it = begin; it != end; ++it) {
        const std::uint32_t packedMode =
          static_cast<std::uint32_t>(it->sampleType) | (static_cast<std::uint32_t>(it->sampleQuality) << 5u);
        optionsTable.SetInteger(tableIndex++, static_cast<std::int32_t>(packedMode));
      }
    }
  }

  optionsTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C9490 (FUN_008C9490, cfunc_GetOptions)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetOptionsL`.
 */
int moho::cfunc_GetOptions(lua_State* const luaContext)
{
  return cfunc_GetOptionsL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008C94B0 (FUN_008C94B0, func_GetOptions_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `GetOptions` in the
 * user init set.
 */
moho::CScrLuaInitForm* moho::func_GetOptions_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetOptions",
    &moho::cfunc_GetOptions,
    nullptr,
    "<global>",
    "obj GetOptions()"
  );
  return &binder;
}

/**
 * Address: 0x008C9510 (FUN_008C9510, cfunc_GetOptionsL)
 *
 * What it does:
 * Reads one options key string and pushes the current preference value.
 */
int moho::cfunc_GetOptionsL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetOptionsHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject keyArg(state, 1);
  const char* keyText = lua_tostring(rawState, 1);
  if (keyText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&keyArg, "string");
    keyText = "";
  }

  msvc8::string optionKey{};
  optionKey.assign_owned(keyText);

  LuaPlus::LuaObject valueObject(state);
  valueObject.AssignNil(state);

  if (IUserPrefs* const preferences = USER_GetPreferences(); preferences != nullptr) {
    msvc8::string optionValue{};
    if (preferences->LookupCurrentOption(&optionValue, optionKey)) {
      valueObject.AssignString(state, optionValue.c_str());
    }
  }

  valueObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C9850 (FUN_008C9850, cfunc_GetPreference)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetPreferenceL`.
 */
int moho::cfunc_GetPreference(lua_State* const luaContext)
{
  return cfunc_GetPreferenceL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008C9870 (FUN_008C9870, func_GetPreference_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `GetPreference`
 * in the user init set.
 */
moho::CScrLuaInitForm* moho::func_GetPreference_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetPreference",
    &moho::cfunc_GetPreference,
    nullptr,
    "<global>",
    kGetPreferenceHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C98D0 (FUN_008C98D0, cfunc_GetPreferenceL)
 *
 * What it does:
 * Resolves one preference key and returns its Lua object value, with optional
 * default object fallback from arg #2.
 */
int moho::cfunc_GetPreferenceL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgRangeWarning, kGetPreferenceHelpText, 1, 2, argumentCount);
  }

  lua_settop(rawState, 2);

  LuaPlus::LuaStackObject keyArg(state, 1);
  const char* keyText = lua_tostring(rawState, 1);
  if (keyText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&keyArg, "string");
    keyText = "";
  }

  msvc8::string key;
  key.assign_owned(keyText);

  LuaPlus::LuaObject preferenceObject(state);
  preferenceObject.AssignNil(state);

  if (IUserPrefs* const preferences = USER_GetPreferences(); preferences != nullptr) {
    LuaPlus::LuaObject* const preferenceTable = static_cast<LuaPlus::LuaObject*>(preferences->GetPreferenceTable());
    if (preferenceTable != nullptr) {
      preferenceObject = preferenceTable->Lookup(key.c_str());
    }
  }

  if (preferenceObject.IsNil()) {
    preferenceObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 2));
  }

  preferenceObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C9A50 (FUN_008C9A50, cfunc_SetPreference)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_SetPreferenceL`.
 */
int moho::cfunc_SetPreference(lua_State* const luaContext)
{
  return cfunc_SetPreferenceL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008C9A70 (FUN_008C9A70, func_SetPreference_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `SetPreference`
 * in the user init set.
 */
moho::CScrLuaInitForm* moho::func_SetPreference_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetPreference",
    &moho::cfunc_SetPreference,
    nullptr,
    "<global>",
    kSetPreferenceHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C9AD0 (FUN_008C9AD0, cfunc_SetPreferenceL)
 *
 * What it does:
 * Reads `(key, value)` from Lua and stores the preference object under `key`.
 */
int moho::cfunc_SetPreferenceL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSetPreferenceHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject valueObject(LuaPlus::LuaStackObject(state, 2));

  LuaPlus::LuaStackObject keyArg(state, 1);
  const char* keyText = lua_tostring(rawState, 1);
  if (keyText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&keyArg, "string");
    keyText = "";
  }

  msvc8::string key;
  key.assign_owned(keyText);

  if (IUserPrefs* const preferences = USER_GetPreferences(); preferences != nullptr) {
    preferences->SetObject(key, &valueObject);
  }

  return 0;
}

/**
 * Address: 0x008C9C30 (FUN_008C9C30, cfunc_SavePreferences)
 *
 * What it does:
 * Validates zero-argument call shape and persists current user preferences.
 */
int moho::cfunc_SavePreferences(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSavePreferencesHelpText, 0, argumentCount);
  }

  USER_SavePreferences();
  return 0;
}

/**
 * Address: 0x008C9C70 (FUN_008C9C70, func_SavePreferences_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `SavePreferences`
 * in the user init set.
 */
moho::CScrLuaInitForm* moho::func_SavePreferences_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SavePreferences",
    &moho::cfunc_SavePreferences,
    nullptr,
    "<global>",
    kSavePreferencesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BE8BF0 (FUN_00BE8BF0, register_SavePreferences_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_SavePreferences_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_SavePreferences_LuaFuncDef()
{
  return func_SavePreferences_LuaFuncDef();
}

/**
 * Address: 0x008CAEA0 (FUN_008CAEA0, cfunc_DebugFacilitiesEnabled)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_DebugFacilitiesEnabledL`.
 */
int moho::cfunc_DebugFacilitiesEnabled(lua_State* const luaContext)
{
  return cfunc_DebugFacilitiesEnabledL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008CAEC0 (FUN_008CAEC0, func_DebugFacilitiesEnabled_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for
 * `DebugFacilitiesEnabled` in the user init set.
 */
moho::CScrLuaInitForm* moho::func_DebugFacilitiesEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DebugFacilitiesEnabled",
    &moho::cfunc_DebugFacilitiesEnabled,
    nullptr,
    "<global>",
    kDebugFacilitiesEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BE8CE0 (FUN_00BE8CE0, j_func_DebugFacilitiesEnabled_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_DebugFacilitiesEnabled_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::j_func_DebugFacilitiesEnabled_LuaFuncDef()
{
  return func_DebugFacilitiesEnabled_LuaFuncDef();
}

/**
 * Address: 0x008CAF20 (FUN_008CAF20, cfunc_DebugFacilitiesEnabledL)
 *
 * What it does:
 * Validates zero-argument call shape and returns whether debug facilities
 * are enabled.
 */
int moho::cfunc_DebugFacilitiesEnabledL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected %d args, but got %d", kDebugFacilitiesEnabledHelpText, 0, argumentCount
    );
  }

  lua_pushboolean(rawState, USER_DebugFacilitiesEnabled() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

namespace
{
  constexpr std::uint32_t kInvalidPathBoundary = std::numeric_limits<std::uint32_t>::max();

  struct PathComponentCursor
  {
    msvc8::string mToken;                 // +0x00
    const msvc8::string* mPath = nullptr; // +0x1C
    std::uint32_t mOffset = 0;            // +0x20
  };

  static_assert(offsetof(PathComponentCursor, mToken) == 0x00, "PathComponentCursor::mToken offset must be 0x00");
  static_assert(offsetof(PathComponentCursor, mPath) == 0x1C, "PathComponentCursor::mPath offset must be 0x1C");
  static_assert(offsetof(PathComponentCursor, mOffset) == 0x20, "PathComponentCursor::mOffset offset must be 0x20");
  static_assert(sizeof(PathComponentCursor) == 0x24, "PathComponentCursor size must be 0x24");

  [[nodiscard]] bool IsSlashToken(const char ch) noexcept
  {
    return ch == '/' || ch == '\\';
  }

  [[nodiscard]] std::uint32_t ClampPathIndex(const msvc8::string& path, std::uint32_t index) noexcept
  {
    const std::uint32_t size = static_cast<std::uint32_t>(path.size());
    return index > size ? size : index;
  }

  /**
   * Address: 0x0045FBA0 (FUN_0045FBA0, func_StringFilenameAppendSlash)
   *
   * What it does:
   * Appends one trailing `/` separator unless path already ends in `:` or `/`.
   */
  void func_StringFilenameAppendSlash(msvc8::string* const path)
  {
    if (path == nullptr || path->empty()) {
      return;
    }

    const char last = (*path)[path->size() - 1u];
    if (last != ':' && last != '/') {
      (void)path->append(1u, '/');
    }
  }

  /**
   * Address: 0x0045E4E0 (FUN_0045E4E0, func_StringAppendFilename)
   *
   * What it does:
   * Appends one filename segment, normalizing `\\` separators into `/`.
   */
  msvc8::string* func_StringAppendFilename(const char* source, msvc8::string* const path)
  {
    if (path == nullptr) {
      return nullptr;
    }

    const char* cursor = source != nullptr ? source : "";
    if (cursor[0] == '/' && cursor[1] == '/' && cursor[2] == ':') {
      cursor += 3;
    }

    if (!path->empty() && cursor[0] != '\0' && !IsSlashToken(cursor[0])) {
      func_StringFilenameAppendSlash(path);
    }

    for (char token = cursor[0]; token != '\0'; token = *++cursor) {
      const char normalized = token == '\\' ? '/' : token;
      (void)path->append(1u, normalized);
    }

    return path;
  }

  /**
   * Address: 0x0045FC20 (FUN_0045FC20, PathRootBoundaryIndex)
   *
   * What it does:
   * Returns root-boundary index for one path prefix window, or `-1` when
   * no root boundary exists.
   */
  [[nodiscard]] std::uint32_t PathRootBoundaryIndex(const msvc8::string& path, const std::uint32_t upto)
  {
    const std::uint32_t clamped = ClampPathIndex(path, upto);
    const std::size_t size = path.size();

    if (clamped > 2u && size > 2u) {
      if (path[1] == ':' && path[2] == '/') {
        return 2u;
      }
    }

    if (clamped == 2u) {
      if (size > 1u && path[0] == '/' && path[1] == '/') {
        return kInvalidPathBoundary;
      }

      if (size == 0u) {
        return kInvalidPathBoundary;
      }
      return path[0] == '/' ? 0u : kInvalidPathBoundary;
    }

    if (clamped > 3u && size > 2u) {
      if (path[0] == '/' && path[1] == '/' && path[2] == '/') {
        const std::size_t serverSplit = path.find('/', 2u);
        if (serverSplit == msvc8::string::npos || serverSplit >= clamped) {
          return kInvalidPathBoundary;
        }
        return static_cast<std::uint32_t>(serverSplit);
      }
    }

    if (clamped == 0u) {
      return kInvalidPathBoundary;
    }

    return (!path.empty() && path[0] == '/') ? 0u : kInvalidPathBoundary;
  }

  /**
   * Address: 0x004606B0 (FUN_004606B0, func_StringSearchFromEnd)
   *
   * What it does:
   * Searches backwards for one token sequence and returns the final-match
   * index at or before `max`.
   */
  [[nodiscard]]
  std::uint32_t func_StringSearchFromEnd(
    const std::uint32_t max, const msvc8::string& path, const char* const search, const std::uint32_t searchLen
  )
  {
    const std::uint32_t size = static_cast<std::uint32_t>(path.size());
    if (searchLen == 0u) {
      return max < size ? max : size;
    }
    if (search == nullptr || searchLen > size) {
      return kInvalidPathBoundary;
    }

    std::uint32_t pos = size - searchLen;
    if (max < pos) {
      pos = max;
    }

    for (;;) {
      bool matches = true;
      for (std::uint32_t i = 0u; i < searchLen; ++i) {
        if (path[static_cast<std::size_t>(pos + i)] != search[i]) {
          matches = false;
          break;
        }
      }

      if (matches) {
        return pos;
      }
      if (pos == 0u) {
        return kInvalidPathBoundary;
      }
      --pos;
    }
  }

  /**
   * Address: 0x0045FD00 (FUN_0045FD00, func_PathFilenamePos)
   *
   * What it does:
   * Returns start index of the final filename segment in one path.
   */
  [[nodiscard]] std::uint32_t func_PathFilenamePos(const msvc8::string& path, const std::uint32_t upto)
  {
    const std::uint32_t clamped = ClampPathIndex(path, upto);
    if (clamped == 2u && path.size() > 1u && path[0] == '/' && path[1] == '/') {
      return 0u;
    }

    if (clamped > 0u && static_cast<std::size_t>(clamped - 1u) < path.size() && path[clamped - 1u] == '/') {
      return clamped - 1u;
    }

    const char slashToken = '/';
    const std::uint32_t slashPos =
      clamped == 0u ? kInvalidPathBoundary : func_StringSearchFromEnd(clamped - 1u, path, &slashToken, 1u);
    if (slashPos != kInvalidPathBoundary) {
      if (slashPos == 1u && !path.empty() && path[0] == '/') {
        return 0u;
      }
      return slashPos + 1u;
    }

    const char backslashToken = '\\';
    const std::uint32_t backslashPos =
      clamped == 0u ? kInvalidPathBoundary : func_StringSearchFromEnd(clamped - 1u, path, &backslashToken, 1u);
    if (backslashPos != kInvalidPathBoundary) {
      if (backslashPos == 1u && !path.empty() && path[0] == '/') {
        return 0u;
      }
      return backslashPos + 1u;
    }

    const char colonToken = ':';
    const std::uint32_t colonSearchStart = clamped > 1u ? (clamped - 2u) : 0u;
    const std::uint32_t colonPos = func_StringSearchFromEnd(colonSearchStart, path, &colonToken, 1u);
    if (colonPos == kInvalidPathBoundary) {
      return 0u;
    }
    if (colonPos == 1u && !path.empty() && path[0] == '/') {
      return 0u;
    }
    return static_cast<std::uint32_t>(colonPos + 1u);
  }

  /**
   * Address: 0x00460760 (FUN_00460760, PathRootBoundaryToken)
   *
   * What it does:
   * Returns one-character root token at current root boundary, or empty
   * token when boundary is absent.
   */
  [[nodiscard]] msvc8::string PathRootBoundaryToken(const msvc8::string& path)
  {
    const std::uint32_t rootBoundary = PathRootBoundaryIndex(path, static_cast<std::uint32_t>(path.size()));
    if (rootBoundary == kInvalidPathBoundary || rootBoundary >= path.size()) {
      return msvc8::string{};
    }
    return path.substr(rootBoundary, 1u);
  }

  /**
   * Address: 0x0045FA90 (FUN_0045FA90, PathHasRootBoundaryToken)
   *
   * What it does:
   * Returns true when a path has one root-boundary token.
   */
  [[nodiscard]] bool PathHasRootBoundaryToken(const msvc8::string& path)
  {
    return !PathRootBoundaryToken(path).empty();
  }

  /**
   * Address: 0x004608D0 (FUN_004608D0, ParsePathRootTokenSpan)
   *
   * What it does:
   * Parses one leading root token span and reports token start/length.
   */
  [[nodiscard]]
  void ParsePathRootTokenSpan(const msvc8::string& path, std::uint32_t* const outStart, std::uint32_t* const outLength)
  {
    if (outStart != nullptr) {
      *outStart = 0u;
    }
    if (outLength != nullptr) {
      *outLength = 0u;
    }

    const std::uint32_t size = static_cast<std::uint32_t>(path.size());
    if (size == 0u) {
      return;
    }

    if (size >= 2u && path[0] == '/' && path[1] == '/') {
      if (size == 2u || path[2] != '/') {
        std::uint32_t cursor = 2u;
        std::uint32_t length = 2u;
        while (cursor < size) {
          const char token = path[cursor];
          if (token == ':' || token == '/') {
            break;
          }
          ++length;
          ++cursor;
        }

        if (cursor < size && path[cursor] == ':') {
          ++length;
        }

        if (outLength != nullptr) {
          *outLength = length;
        }
        return;
      }
    }

    if (path[0] != '/') {
      std::uint32_t length = 0u;
      std::uint32_t cursor = 0u;
      while (cursor < size) {
        const char token = path[cursor];
        if (token == ':' || token == '/') {
          break;
        }
        ++length;
        ++cursor;
      }

      if (cursor < size && path[cursor] == ':') {
        ++length;
      }

      if (outLength != nullptr) {
        *outLength = length;
      }
      return;
    }

    std::uint32_t start = 0u;
    while ((start + 1u) < size && path[start + 1u] == '/') {
      ++start;
    }
    if (outStart != nullptr) {
      *outStart = start;
    }
    if (outLength != nullptr) {
      *outLength = 1u;
    }
  }

  /**
   * Address: 0x0045FAD0 (FUN_0045FAD0, InitPathPrefixCursor)
   *
   * What it does:
   * Extracts one leading root/prefix token and initializes path cursor state.
   */
  [[nodiscard]] PathComponentCursor InitPathPrefixCursor(const msvc8::string& path)
  {
    PathComponentCursor cursor{};
    cursor.mPath = &path;

    std::uint32_t rootStart = 0u;
    std::uint32_t rootLength = 0u;
    ParsePathRootTokenSpan(path, &rootStart, &rootLength);

    cursor.mOffset = rootStart;
    cursor.mToken = path.substr(rootStart, rootLength);
    return cursor;
  }

  /**
   * Address: 0x0045FA50 (FUN_0045FA50, PathHasLeadingPrefixToken)
   *
   * What it does:
   * Returns true when path has one non-empty leading root/prefix token.
   */
  [[nodiscard]] bool PathHasLeadingPrefixToken(const msvc8::string& path)
  {
    return !InitPathPrefixCursor(path).mToken.empty();
  }

  /**
   * Address: 0x0045F7A0 (FUN_0045F7A0, GetDriveOrUncPathPrefixToken)
   *
   * What it does:
   * Returns one leading root token only when token is UNC-like (`//...`) or
   * drive-like (`...:`); otherwise returns empty token.
   */
  [[nodiscard]] msvc8::string GetDriveOrUncPathPrefixToken(const msvc8::string& path)
  {
    const PathComponentCursor prefixCursor = InitPathPrefixCursor(path);
    if (prefixCursor.mOffset == path.size()) {
      return msvc8::string{};
    }

    const msvc8::string& token = prefixCursor.mToken;
    if (token.size() > 1u && token[0] == '/' && token[1] == '/') {
      return token;
    }
    if (!token.empty() && token[token.size() - 1u] == ':') {
      return token;
    }
    return msvc8::string{};
  }

  /**
   * Address: 0x0045F9E0 (FUN_0045F9E0, PathHasDriveOrUncRootAndBoundary)
   *
   * What it does:
   * Returns true when path has both a root/prefix token and root-boundary
   * marker token.
   */
  [[nodiscard]] bool PathHasDriveOrUncRootAndBoundary(const msvc8::string& path)
  {
    return !GetDriveOrUncPathPrefixToken(path).empty() && !PathRootBoundaryToken(path).empty();
  }

  /**
   * Address: 0x0045F780 (FUN_0045F780, TrimPathToDirectory)
   *
   * What it does:
   * Truncates one path string to directory portion.
   */
  msvc8::string* TrimPathToDirectory(msvc8::string* const path)
  {
    if (path == nullptr) {
      return nullptr;
    }

    const std::uint32_t splitPos = func_PathFilenamePos(*path, static_cast<std::uint32_t>(path->size()));
    const msvc8::string trimmed = path->substr(0u, splitPos);
    path->assign_owned(trimmed.view());
    return path;
  }

  /**
   * Address: 0x00460840 (FUN_00460840, IsCollapsiblePathSlashBoundary)
   *
   * What it does:
   * Returns true when a slash boundary at `index` can be treated as a
   * collapsible path separator (non-root edge case).
   */
  [[nodiscard]] bool IsCollapsiblePathSlashBoundary(const msvc8::string& path, const std::uint32_t index)
  {
    if (path.empty()) {
      return false;
    }

    std::uint32_t cursor = index;
    while (cursor != 0u && path[cursor - 1u] == '/') {
      --cursor;
    }

    if (cursor == 0u) {
      return false;
    }

    if (cursor > 2u && path.size() > 1u && path[1] == '/') {
      const std::size_t split = path.find('/', 2u);
      if (split != msvc8::string::npos && split == cursor) {
        return false;
      }
    }

    if (cursor == 2u) {
      return path.size() > 1u && path[1] != ':';
    }
    return true;
  }

  /**
   * Address: 0x0045F8C0 (FUN_0045F8C0, GetPathBasenameOrDot)
   *
   * What it does:
   * Returns basename token for one path; emits `.` for root-edge paths.
   */
  [[nodiscard]] msvc8::string GetPathBasenameOrDot(const msvc8::string& path)
  {
    const std::uint32_t size = static_cast<std::uint32_t>(path.size());
    std::uint32_t split = func_PathFilenamePos(path, size);

    if (size != 0u && split != 0u && split < path.size() && path[split] == '/' && IsCollapsiblePathSlashBoundary(path, split)) {
      return msvc8::string(".");
    }

    return path.substr(split);
  }

  /**
   * Address: 0x0045FB80 (FUN_0045FB80, InitReversePathComponentCursor)
   *
   * What it does:
   * Initializes reverse path-component cursor for one source path.
   */
  [[nodiscard]] PathComponentCursor InitReversePathComponentCursor(const msvc8::string& path)
  {
    PathComponentCursor cursor{};
    cursor.mPath = &path;
    cursor.mOffset = static_cast<std::uint32_t>(path.size());
    return cursor;
  }

  /**
   * Address: 0x0045F420 (FUN_0045F420, CopyPathComponentCursor)
   *
   * What it does:
   * Copies one path-component cursor state.
   */
  [[nodiscard]] PathComponentCursor CopyPathComponentCursor(const PathComponentCursor& other)
  {
    PathComponentCursor cursor{};
    cursor.mToken = other.mToken;
    cursor.mPath = other.mPath;
    cursor.mOffset = other.mOffset;
    return cursor;
  }

  /**
   * Address: 0x00461220 (FUN_00461220, SetPathTokenMarker)
   *
   * What it does:
   * Replaces one cursor token with a single-character marker (`/` or `.`).
   */
  msvc8::string* SetPathTokenMarker(msvc8::string* const outToken, const char marker)
  {
    if (outToken == nullptr) {
      return nullptr;
    }

    outToken->clear();
    (void)outToken->append(1u, marker);
    return outToken;
  }

  /**
   * Address: 0x00460F00 (FUN_00460F00, AdvancePathComponentCursor)
   *
   * What it does:
   * Advances one forward path-component cursor from its current token to the
   * next token/separator marker in the same source path.
   */
  [[nodiscard]] PathComponentCursor& AdvancePathComponentCursor(PathComponentCursor& cursor)
  {
    if (cursor.mPath == nullptr) {
      cursor.mToken.clear();
      cursor.mOffset = 0u;
      return cursor;
    }

    const msvc8::string& path = *cursor.mPath;
    const std::uint32_t tokenSize = static_cast<std::uint32_t>(cursor.mToken.size());
    const bool keepDoubleSlashMarker =
      tokenSize > 2u && cursor.mToken[0] == '/' && cursor.mToken[1] == '/' && cursor.mToken[2] != '/';

    cursor.mOffset = ClampPathIndex(path, cursor.mOffset + tokenSize);
    const std::uint32_t pathSize = static_cast<std::uint32_t>(path.size());
    if (cursor.mOffset == pathSize) {
      cursor.mToken.clear();
      return cursor;
    }

    if (path[cursor.mOffset] == '/') {
      if (keepDoubleSlashMarker || (!cursor.mToken.empty() && cursor.mToken[cursor.mToken.size() - 1u] == ':')) {
        (void)SetPathTokenMarker(&cursor.mToken, '/');
        return cursor;
      }

      while (cursor.mOffset != pathSize && path[cursor.mOffset] == '/') {
        ++cursor.mOffset;
      }

      if (cursor.mOffset == pathSize && IsCollapsiblePathSlashBoundary(path, cursor.mOffset)) {
        --cursor.mOffset;
        (void)SetPathTokenMarker(&cursor.mToken, '.');
        return cursor;
      }
    }

    const std::size_t split = path.find('/', cursor.mOffset);
    const std::uint32_t tokenStart = cursor.mOffset;
    const std::uint32_t tokenLength =
      split == msvc8::string::npos ? (pathSize - tokenStart) : static_cast<std::uint32_t>(split - tokenStart);
    cursor.mToken = path.substr(tokenStart, tokenLength);
    return cursor;
  }

  /**
   * Address: 0x004610D0 (FUN_004610D0, AdvanceReversePathComponentCursor)
   *
   * What it does:
   * Advances one reverse path-component cursor and updates the current token.
   */
  [[nodiscard]] PathComponentCursor& AdvanceReversePathComponentCursor(PathComponentCursor& cursor)
  {
    if (cursor.mPath == nullptr) {
      cursor.mToken.clear();
      cursor.mOffset = 0u;
      return cursor;
    }

    const msvc8::string& path = *cursor.mPath;
    std::uint32_t pathIndex = ClampPathIndex(path, cursor.mOffset);
    const std::uint32_t rootBoundary = PathRootBoundaryIndex(path, pathIndex);
    const std::uint32_t size = static_cast<std::uint32_t>(path.size());

    if (pathIndex == size && size > 1u && path[pathIndex - 1u] == '/' && IsCollapsiblePathSlashBoundary(path, pathIndex)) {
      --pathIndex;
      cursor.mOffset = pathIndex;
      (void)SetPathTokenMarker(&cursor.mToken, '.');
      return cursor;
    }

    if (pathIndex > 0u) {
      std::uint32_t tail = pathIndex - 1u;
      while (pathIndex > 0u) {
        if (tail == rootBoundary) {
          break;
        }
        if (path[pathIndex - 1u] != '/') {
          break;
        }
        --pathIndex;
        if (tail == 0u) {
          break;
        }
        --tail;
      }
    }

    const std::uint32_t tokenStart = func_PathFilenamePos(path, pathIndex);
    cursor.mOffset = tokenStart;
    cursor.mToken = path.substr(tokenStart, pathIndex - tokenStart);
    return cursor;
  }

  /**
   * Address: 0x0045F670 (FUN_0045F670, PostIncrementReversePathComponentCursor)
   *
   * What it does:
   * Copies one path-component cursor and advances source cursor backwards.
   */
  [[nodiscard]] PathComponentCursor PostIncrementReversePathComponentCursor(PathComponentCursor& source)
  {
    PathComponentCursor copied = CopyPathComponentCursor(source);
    (void)AdvanceReversePathComponentCursor(source);
    return copied;
  }

  /**
   * Address: 0x0045F590 (FUN_0045F590, BuildNormalizedCursorPathToken)
   *
   * What it does:
   * Builds one normalized path from cursor token using filename-append rules.
   */
  [[nodiscard]] msvc8::string BuildNormalizedCursorPathToken(const PathComponentCursor& cursor)
  {
    msvc8::string output{};
    (void)func_StringAppendFilename(cursor.mToken.c_str(), &output);
    return output;
  }

  /**
   * Address: 0x0045FDD0 (FUN_0045FDD0, PathComponentCursorNotEqual)
   *
   * What it does:
   * Returns true when two path-component cursors are positioned differently.
   */
  [[nodiscard]] bool PathComponentCursorNotEqual(const PathComponentCursor& lhs, const PathComponentCursor& rhs)
  {
    return lhs.mPath != rhs.mPath || lhs.mOffset != rhs.mOffset;
  }

  /**
   * Address: 0x0045FE00 (FUN_0045FE00, PathComponentCursorEqual)
   *
   * What it does:
   * Returns true when two path-component cursors are at identical position.
   */
  [[nodiscard]] bool PathComponentCursorEqual(const PathComponentCursor& lhs, const PathComponentCursor& rhs)
  {
    return lhs.mPath == rhs.mPath && lhs.mOffset == rhs.mOffset;
  }

  /**
   * Address: 0x0045FE20 (FUN_0045FE20, AppendRelativePathToken)
   *
   * What it does:
   * Appends one relative token onto a base path using filename-append
   * normalization rules.
   */
  [[nodiscard]] msvc8::string AppendRelativePathToken(const msvc8::string& basePath, const msvc8::string& relativePath)
  {
    msvc8::string appended = basePath;
    (void)func_StringAppendFilename(relativePath.c_str(), &appended);
    return appended;
  }

  /**
   * Address: 0x0045E550 (FUN_0045E550, path slash-normalize helper)
   *
   * What it does:
   * Copies one path into Windows-style slash form (`/` -> `\\`) while keeping
   * root-boundary collapse semantics for leading-prefix lanes.
   */
  [[maybe_unused]] msvc8::string* NormalizePathToWindowsSlashes(
    const msvc8::string& source,
    msvc8::string* const out
  )
  {
    if (out == nullptr) {
      return nullptr;
    }

    out->clear();
    const std::uint32_t size = static_cast<std::uint32_t>(source.size());
    const std::uint32_t rootBoundary = PathRootBoundaryIndex(source, size);
    bool allowRootCollapse = (rootBoundary != kInvalidPathBoundary);

    for (std::uint32_t index = 0u; index < size; ++index) {
      if (index == 0u && size > 1u && source[0] == '/' && source[1] == '/' &&
          (size == 2u || (source[2] != '/' && source[2] != '\\'))) {
        (void)out->append(1u, '\\');
        (void)out->append(1u, '\\');
        index = 1u;
        continue;
      }

      const char token = source[index];
      const bool skipCollapsedSlash = allowRootCollapse && !out->empty() && (*out)[out->size() - 1u] == '\\' && token == '/';
      if (!skipCollapsedSlash) {
        (void)out->append(1u, token == '/' ? '\\' : token);
        if (index > rootBoundary && token == '/') {
          allowRootCollapse = false;
        }
      }
    }

    return out;
  }

  /**
   * Address: 0x0045E6C0 (FUN_0045E6C0, path directory-prefix helper)
   *
   * What it does:
   * Builds normalized directory prefix text for one input path using filename
   * split/root-boundary rules from the startup path helper lane.
   */
  [[maybe_unused]] msvc8::string* BuildNormalizedDirectoryPrefix(
    const msvc8::string& path,
    msvc8::string* const out
  )
  {
    if (out == nullptr) {
      return nullptr;
    }

    const std::uint32_t size = static_cast<std::uint32_t>(path.size());
    std::uint32_t split = func_PathFilenamePos(path, size);

    bool splitOnSlash = false;
    if (size != 0u && split < path.size()) {
      splitOnSlash = path[split] == '/';
    }

    const std::uint32_t rootBoundary = PathRootBoundaryIndex(path, split);
    while (split > 0u) {
      const std::uint32_t previous = split - 1u;
      if (previous == rootBoundary) {
        break;
      }
      if (path[previous] != '/') {
        break;
      }
      --split;
    }

    msvc8::string prefix;
    if (split == 1u && rootBoundary == 0u && splitOnSlash) {
      prefix.clear();
    } else {
      const msvc8::string slice = path.substr(0u, split);
      (void)func_StringAppendFilename(slice.c_str(), &prefix);
    }

    out->assign_owned(prefix.view());
    return out;
  }

  /**
   * Address: 0x0045E870 (FUN_0045E870, CollapsePathComponentsInPlace)
   *
   * What it does:
   * Collapses one path in place by resolving `.`/`..` component lanes while
   * preserving root/prefix boundary behavior from the startup filename lane.
   */
  [[maybe_unused]] msvc8::string* CollapsePathComponentsInPlace(msvc8::string* const path)
  {
    if (path == nullptr || path->empty()) {
      return path;
    }

    msvc8::string collapsedPath{};
    const PathComponentCursor prefixCursor = InitPathPrefixCursor(*path);
    PathComponentCursor reverseCursor = InitReversePathComponentCursor(*path);
    const PathComponentCursor endCursor = PostIncrementReversePathComponentCursor(reverseCursor);

    PathComponentCursor current = CopyPathComponentCursor(prefixCursor);
    while (PathComponentCursorNotEqual(current, endCursor)) {
      const bool isDotToken = current.mToken == ".";
      if (!isDotToken || PathComponentCursorEqual(current, prefixCursor) || PathComponentCursorEqual(current, reverseCursor)) {
        bool collapsedParent = false;
        const bool isParentToken = current.mToken == "..";
        if (!collapsedPath.empty() && isParentToken) {
          const msvc8::string baseToken = GetPathBasenameOrDot(collapsedPath);
          bool canCollapse = false;
          if (!baseToken.empty()) {
            if (baseToken.size() == 1u) {
              const char token0 = baseToken[0];
              canCollapse = token0 != '.' && token0 != '/';
            } else if (baseToken.size() != 2u) {
              canCollapse = true;
            } else if (baseToken[0] != '.') {
              const char token1 = baseToken[1];
              canCollapse = token1 != '.' && token1 != ':';
            }
          }

          if (canCollapse) {
            (void)TrimPathToDirectory(&collapsedPath);
            const std::uint32_t collapsedSize = static_cast<std::uint32_t>(collapsedPath.size());
            if (collapsedSize != 0u && collapsedPath[collapsedSize - 1u] == '/') {
              const std::uint32_t rootBoundary = PathRootBoundaryIndex(collapsedPath, collapsedSize);
              if (rootBoundary == kInvalidPathBoundary || rootBoundary != collapsedSize - 1u) {
                collapsedPath.erase(collapsedPath.size() - 1u, 1u);
              }
            }

            if (collapsedPath.empty()) {
              PathComponentCursor lookahead = CopyPathComponentCursor(current);
              (void)AdvancePathComponentCursor(lookahead);
              if (PathComponentCursorNotEqual(lookahead, endCursor) && PathComponentCursorEqual(lookahead, reverseCursor) &&
                  reverseCursor.mToken == ".") {
                (void)func_StringAppendFilename(".", &collapsedPath);
              }
            }

            collapsedParent = true;
          }
        }

        if (!collapsedParent) {
          (void)func_StringAppendFilename(current.mToken.c_str(), &collapsedPath);
        }
      }

      (void)AdvancePathComponentCursor(current);
    }

    if (collapsedPath.empty()) {
      (void)func_StringAppendFilename(".", &collapsedPath);
    }
    path->assign_owned(collapsedPath.view());
    return path;
  }

  /**
   * Address: 0x0045EC70 (FUN_0045EC70, path resolve helper)
   *
   * What it does:
   * Resolves one path token against a base path, preserving drive/UNC/absolute
   * rules from the startup filename helper chain.
   */
  [[maybe_unused]] msvc8::string* ResolvePathAgainstBase(
    const msvc8::string& basePath,
    const msvc8::string& path,
    msvc8::string* const out
  )
  {
    if (out == nullptr) {
      return nullptr;
    }

    if (path.empty() || PathHasDriveOrUncRootAndBoundary(path)) {
      out->assign_owned(path.view());
      return out;
    }

    if (PathHasLeadingPrefixToken(path)) {
      out->assign_owned(AppendRelativePathToken(basePath, path).view());
      return out;
    }

    if (PathHasRootBoundaryToken(path)) {
      const msvc8::string basePrefix = GetDriveOrUncPathPrefixToken(basePath);
      msvc8::string normalizedPrefix;
      (void)func_StringAppendFilename(basePrefix.c_str(), &normalizedPrefix);
      out->assign_owned(AppendRelativePathToken(normalizedPrefix, path).view());
      return out;
    }

    out->assign_owned(AppendRelativePathToken(basePath, path).view());
    return out;
  }

  /**
   * Address: 0x0045F600 (FUN_0045F600, SetPathPointerLane)
   *
   * What it does:
   * Stores one path pointer lane in a single-word helper wrapper.
   */
  void SetPathPointerLane(const msvc8::string*& outPath, const msvc8::string* const path) noexcept
  {
    outPath = path;
  }

  /**
   * Address: 0x0045F700 (FUN_0045F700, IdentityPointerLaneA)
   *
   * What it does:
   * Identity helper (compiler artifact).
   */
  template <typename T>
  [[nodiscard]] T* IdentityPointerLaneA(T* const value) noexcept
  {
    return value;
  }

  /**
   * Address: 0x0045F710 (FUN_0045F710, IdentityPointerLaneB)
   *
   * What it does:
   * Identity helper (compiler artifact).
   */
  template <typename T>
  [[nodiscard]] T* IdentityPointerLaneB(T* const value) noexcept
  {
    return value;
  }
} // namespace

/**
 * Address: 0x00457D40 (FUN_00457D40, sub_457D40)
 *
 * What it does:
 * Wraps startup path resolution with `(path, basePath)` parameter order used
 * by VFS/data-path setup callsites.
 */
msvc8::string* moho::PATH_ResolveAgainstBase(
  const msvc8::string& path,
  const msvc8::string& basePath,
  msvc8::string* const outPath
)
{
  return ResolvePathAgainstBase(basePath, path, outPath);
}

/**
 * Address: 0x0046AE90 (FUN_0046AE90, sub_46AE90)
 * Address: 0x0046B4B0 (FUN_0046B4B0, sub_46B4B0)
 * Address: 0x0046BA60 (FUN_0046BA60, sub_46BA60)
 *
 * What it does:
 * Compares two canonicalized paths by reverse component order. The comparison
 * starts from the leaf token and walks toward each path root.
 */
bool moho::PATH_ReverseComponentLess(const msvc8::string& lhs, const msvc8::string& rhs)
{
  PathComponentCursor lhsCursor = InitReversePathComponentCursor(lhs);
  PathComponentCursor lhsEnd = InitPathPrefixCursor(lhs);
  PathComponentCursor rhsCursor = InitReversePathComponentCursor(rhs);
  PathComponentCursor rhsEnd = InitPathPrefixCursor(rhs);

  while (PathComponentCursorNotEqual(lhsCursor, lhsEnd) && PathComponentCursorNotEqual(rhsCursor, rhsEnd)) {
    const msvc8::string lhsToken = BuildNormalizedCursorPathToken(lhsCursor);
    const msvc8::string rhsToken = BuildNormalizedCursorPathToken(rhsCursor);
    if (lhsToken.view() < rhsToken.view()) {
      return true;
    }
    if (rhsToken.view() < lhsToken.view()) {
      return false;
    }

    (void)AdvanceReversePathComponentCursor(lhsCursor);
    (void)AdvanceReversePathComponentCursor(rhsCursor);
  }

  return PathComponentCursorEqual(lhsCursor, lhsEnd) && PathComponentCursorNotEqual(rhsCursor, rhsEnd);
}

/**
 * Address: 0x00410760 (FUN_00410760)
 * Mangled:
 * ?FILE_SuggestedExt@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@0@Z
 *
 * What it does:
 * Returns `inputPath` unchanged when it already has an extension, otherwise
 * appends `suggestedExt` (with leading `.` normalization).
 */
msvc8::string moho::FILE_SuggestedExt(const gpg::StrArg inputPath, const gpg::StrArg suggestedExt)
{
  msvc8::string output;
  output.assign_owned(inputPath != nullptr ? inputPath : "");
  if (output.empty()) {
    return output;
  }

  const std::string path = output.to_std();
  const std::size_t slashPos = path.find_last_of("/\\");
  const std::size_t dotPos = path.find_last_of('.');
  const bool hasExtension = dotPos != std::string::npos && (slashPos == std::string::npos || dotPos > slashPos);
  if (hasExtension) {
    return output;
  }

  const char* ext = suggestedExt != nullptr ? suggestedExt : "";
  if (ext[0] == '\0') {
    return output;
  }

  if (ext[0] != '.') {
    output.append(1, '.');
  }
  output.append(ext, std::strlen(ext));
  return output;
}

/**
 * Address: 0x0040FA50 (FUN_0040FA50)
 * Mangled: ?FILE_IsLocal@Moho@@YA_NVStrArg@gpg@@@Z
 *
 * What it does:
 * Returns true when path begins with a single local-root slash (`/`) and is
 * not UNC-like (`//`) and not slash-drive (`/:` form).
 */
bool moho::FILE_IsLocal(const gpg::StrArg filename)
{
  if (filename == nullptr) {
    return false;
  }
  if (filename[0] != '/') {
    return false;
  }

  const char second = filename[1];
  return second != ':' && second != '/';
}

/**
 * Address: 0x0040FFC0 (FUN_0040FFC0, Moho::FILE_MakeAbsolute)
 * Mangled:
 * ?FILE_MakeAbsolute@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@0@Z
 *
 * What it does:
 * Resolves one resource path against one base directory path, preserving
 * drive/UNC prefixes and validating incompatible base/target combinations.
 */
msvc8::string moho::FILE_MakeAbsolute(const gpg::StrArg dir, const gpg::StrArg filename)
{
  if (dir == nullptr || dir[0] == '\0') {
    ThrowStartupFileError("Moho::FILE_MakeAbsolute", "Null argument.");
  }
  if (filename == nullptr || filename[0] == '\0') {
    ThrowStartupFileError("Moho::FILE_MakeAbsolute", "Null argument.");
  }

  msvc8::string dirStr;
  dirStr.assign_owned(dir);
  msvc8::string fileStr;
  fileStr.assign_owned(filename);
  gpg::STR_Replace(dirStr, "\\", "/", std::numeric_limits<unsigned int>::max());
  gpg::STR_Replace(fileStr, "\\", "/", std::numeric_limits<unsigned int>::max());

  const bool fileUnc = FILE_HasUNC(fileStr.c_str());
  const bool fileDrive = FILE_HasDrive(fileStr.c_str());
  const bool dirUnc = FILE_HasUNC(dirStr.c_str());
  const bool dirDrive = FILE_HasDrive(dirStr.c_str());

  if (!fileUnc && !fileDrive) {
    const char* const basePath = fileStr.c_str();
    if (basePath[0] != '/') {
      ThrowStartupFileError("Moho::FILE_MakeAbsolute", "base path must be absolute");
    }
  }

  if (dirUnc) {
    const char* const basePath = fileStr.c_str();
    if (basePath[0] == '/' && !fileUnc) {
      ThrowStartupFileError("Moho::FILE_MakeAbsolute", "UNC absolute path incompatible with posix-style base");
    }
  }

  if (dirDrive) {
    const char* const basePath = fileStr.c_str();
    if (basePath[0] == '/' && !fileUnc) {
      ThrowStartupFileError("Moho::FILE_MakeAbsolute", "Path with drive letter incompatible with posix-style base");
    }
  }

  if (fileUnc) {
    const char* const inputPath = dirStr.c_str();
    if (inputPath[0] == '/' && !dirUnc) {
      ThrowStartupFileError("Moho::FILE_MakeAbsolute", "posix-style absolute path incompatible with UNC base");
    }
  }

  dirStr = gpg::STR_Chop(dirStr.c_str(), '/');
  fileStr = gpg::STR_Chop(fileStr.c_str(), '/');

  if (dirUnc || dirDrive) {
    return dirStr;
  }

  msvc8::string builder;
  if (fileUnc || fileDrive) {
    const std::string fileText = fileStr.to_std();
    const std::size_t prefixLen = std::min<std::size_t>(2u, fileText.size());
    builder.assign_owned(fileText.substr(0u, prefixLen));
    fileStr.assign_owned(fileText.substr(prefixLen));
  }

  if (!FILE_IsAbsolute(dirStr.c_str())) {
    if (builder.empty() && !FILE_IsAbsolute(fileStr.c_str())) {
      builder.append(1u, '/');
    }
    builder.append(fileStr.c_str(), fileStr.size());
    builder.append(1u, '/');
  }

  builder.append(dirStr.c_str(), dirStr.size());
  return builder;
}

/**
 * Address: 0x0040FDC0 (FUN_0040FDC0)
 *
 * What it does:
 * Returns true when `filename` starts with `<alpha>:` drive prefix.
 */
bool moho::FILE_HasDrive(const gpg::StrArg filename)
{
  if (filename == nullptr || filename[0] == '\0') {
    return false;
  }

  const char driveLetter = filename[0];
  const bool isAlphaDrive = (driveLetter >= 'A' && driveLetter <= 'Z') || (driveLetter >= 'a' && driveLetter <= 'z');
  return isAlphaDrive && filename[1] == ':';
}

/**
 * Address: 0x0040FEB0 (FUN_0040FEB0)
 *
 * What it does:
 * Returns true when `filename` starts with UNC prefix (`//` or `\\`).
 */
bool moho::FILE_HasUNC(const gpg::StrArg filename)
{
  if (filename == nullptr || filename[0] == '\0' || filename[1] == '\0') {
    return false;
  }

  const char first = filename[0];
  const char second = filename[1];
  return (first == '/' && second == '/') || (first == '\\' && second == '\\');
}

/**
 * Address: 0x0040FD60 (FUN_0040FD60)
 *
 * What it does:
 * Returns true when `filename` is an absolute path.
 */
bool moho::FILE_IsAbsolute(const gpg::StrArg filename)
{
  if (filename == nullptr || filename[0] == '\0') {
    return false;
  }

  if (FILE_HasUNC(filename)) {
    return true;
  }

  const char firstToken = FILE_HasDrive(filename) ? filename[2] : filename[0];
  return firstToken == '/' || firstToken == '\\';
}

/**
 * Address: 0x0040FAF0 (FUN_0040FAF0)
 * Mangled: ?GetDrive@Moho@@YAHVStrArg@gpg@@@Z
 *
 * What it does:
 * Parses alphabetical drive prefix and returns 1..26 (`A/a` -> 1). Throws
 * `XFileError` for null argument, missing drive prefix, or invalid drive char.
 */
int moho::GetDrive(const gpg::StrArg filename)
{
  if (filename == nullptr || filename[0] == '\0') {
    ThrowStartupFileError("Moho::GetDrive", "Null argument.");
  }
  if (!FILE_HasDrive(filename)) {
    ThrowStartupFileError("Moho::GetDrive", "No drive.");
  }

  const char drive = filename[0];
  if (drive >= 'A' && drive <= 'Z') {
    return (drive - 'A') + 1;
  }
  if (drive >= 'a' && drive <= 'z') {
    return (drive - 'a') + 1;
  }

  ThrowStartupFileError("Moho::GetDrive", "Invalid drive.");
}

/**
 * Address: 0x00410650 (FUN_00410650)
 * Mangled: ?FILE_Ext@Moho@@YAPBDVStrArg@gpg@@@Z
 *
 * What it does:
 * Returns extension pointer (characters after final `.` in the last path
 * segment) or null when no extension exists.
 */
const char* moho::FILE_Ext(const gpg::StrArg filename)
{
  if (filename == nullptr || filename[0] == '\0') {
    ThrowStartupFileError("Moho::FILE_Ext", "Null argument.");
  }

  const char* cursor = filename + std::strlen(filename);
  while (cursor > filename) {
    const char token = *--cursor;
    if (token == '/' || token == '\\') {
      break;
    }
    if (token == '.') {
      return cursor + 1;
    }
  }
  return nullptr;
}

/**
 * Address: 0x004108B0 (FUN_004108B0)
 * Mangled:
 * ?FILE_ForcedExt@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@0@Z
 *
 * What it does:
 * Rebuilds `filename` with forced extension: removes existing extension from
 * last path segment, then appends `.` + `ext` when `ext` is non-empty.
 */
msvc8::string moho::FILE_ForcedExt(const gpg::StrArg filename, const gpg::StrArg ext)
{
  if (filename == nullptr || filename[0] == '\0') {
    ThrowStartupFileError("Moho::FILE_ForcedExt", "Null argument.");
  }

  msvc8::string output;
  const char* const extension = FILE_Ext(filename);
  const std::size_t baseLength =
    extension != nullptr ? static_cast<std::size_t>(extension - filename - 1) : std::strlen(filename);
  output.append(filename, baseLength);

  if (ext != nullptr && ext[0] != '\0') {
    output.append(1u, '.');
    output.append(ext, std::strlen(ext));
  }
  return output;
}

/**
 * Address: 0x00410A10 (FUN_00410A10)
 * Mangled:
 * ?FILE_DirPrefix@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@_N@Z
 *
 * What it does:
 * Normalizes slash separators and returns path-directory prefix text.
 */
msvc8::string moho::FILE_DirPrefix(const gpg::StrArg filename, const bool /*unusedFlag*/)
{
  if (filename == nullptr || filename[0] == '\0') {
    ThrowStartupFileError("Moho::FILE_DirPrefix", "Null argument.");
  }

  msvc8::string normalized;
  normalized.assign_owned(filename);
  gpg::STR_Replace(normalized, "\\", "/", std::numeric_limits<unsigned int>::max());

  const std::string normalizedStd = normalized.to_std();
  const std::size_t slashPos = normalizedStd.find_last_of('/');
  if (slashPos == std::string::npos) {
    msvc8::string out;
    out.assign_owned("");
    return out;
  }

  const std::size_t dotPos = normalizedStd.find_last_of('.');
  if (dotPos == std::string::npos || dotPos <= slashPos) {
    if (slashPos == (normalizedStd.size() - 1u)) {
      if (!(FILE_HasDrive(normalized.c_str()) && slashPos == 2u)) {
        normalized.assign_owned(normalizedStd.substr(0, slashPos));
      }
    }
    return normalized;
  }

  const std::size_t prefixLen = FILE_HasDrive(normalized.c_str()) && slashPos == 2u ? 3u : slashPos;
  msvc8::string out;
  out.assign_owned(normalizedStd.substr(0, prefixLen));
  return out;
}

/**
 * Address: 0x00410C60 (FUN_00410C60)
 * Mangled:
 * ?FILE_Dir@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@@Z
 *
 * What it does:
 * Resolves a system-directory path prefix from a potentially relative filename.
 */
msvc8::string moho::FILE_Dir(const gpg::StrArg filename)
{
  if (filename == nullptr || filename[0] == '\0') {
    ThrowStartupFileError("Moho::FILE_Dir", "Null argument.");
  }
  if (filename[0] == '/' && filename[1] != ':' && filename[1] != '/') {
    ThrowStartupFileError("Moho::FILE_Dir", "System path expected, got local.");
  }

  msvc8::string fileStr;
  fileStr.assign_owned(filename);
  gpg::STR_Replace(fileStr, "\\", "/", std::numeric_limits<unsigned int>::max());

  const bool hasDrive = FILE_HasDrive(filename);
  const bool hasUnc = FILE_HasUNC(filename);
  constexpr int kPathBufferLen = 260;
  char cwdBuffer[kPathBufferLen]{};
  char resolvedBuffer[kPathBufferLen]{};

  if (hasDrive || hasUnc) {
    const std::string normalized = fileStr.to_std();
    const char* resolvedPath = nullptr;
    if (normalized.size() <= 2u) {
      if (_getdcwd(GetDrive(filename), cwdBuffer, kPathBufferLen) == nullptr) {
        ThrowFileDirRuntimeError("_getdcwd");
      }
      resolvedPath = cwdBuffer;
    } else if (normalized[2] == '/' || hasUnc) {
      resolvedPath = filename;
    } else {
      if (_getdcwd(GetDrive(filename), cwdBuffer, kPathBufferLen) == nullptr) {
        ThrowFileDirRuntimeError("_getdcwd");
      }
      const std::string suffix = normalized.substr(2u);
      std::snprintf(resolvedBuffer, sizeof(resolvedBuffer), "%s/%s", cwdBuffer, suffix.c_str());
      resolvedPath = resolvedBuffer;
    }
    return FILE_DirPrefix(resolvedPath);
  }

  if (!fileStr.empty() && fileStr.c_str()[0] != '/') {
    if (_getcwd(cwdBuffer, kPathBufferLen) == nullptr) {
      ThrowFileDirRuntimeError("_getcwd");
    }
    std::snprintf(resolvedBuffer, sizeof(resolvedBuffer), "%s/%s", cwdBuffer, fileStr.c_str());
    return FILE_DirPrefix(resolvedBuffer);
  }

  const char driveChar = static_cast<char>(_getdrive() + 0x60);
  const msvc8::string absolutePath = gpg::STR_Printf("%c:%s", driveChar, fileStr.c_str());
  return FILE_DirPrefix(absolutePath.c_str());
}

/**
 * Address: 0x004111C0 (FUN_004111C0)
 * Mangled:
 * ?FILE_Base@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@_N@Z
 *
 * What it does:
 * Returns the final path segment and optionally strips extension text.
 */
msvc8::string moho::FILE_Base(const gpg::StrArg filename, const bool stripExtension)
{
  if (filename == nullptr || filename[0] == '\0') {
    ThrowStartupFileError("Moho::FILE_Base", "Null argument.");
  }

  const char* base = filename;
  for (const char* cursor = filename; *cursor != '\0'; ++cursor) {
    if (*cursor == '/' || *cursor == '\\') {
      base = cursor + 1;
    }
  }

  std::size_t baseLength = std::strlen(base);
  if (stripExtension) {
    const char* lastDot = nullptr;
    for (const char* cursor = base; *cursor != '\0'; ++cursor) {
      if (*cursor == '.') {
        lastDot = cursor;
      }
    }
    if (lastDot != nullptr) {
      baseLength = static_cast<std::size_t>(lastDot - base);
    }
  }

  msvc8::string out;
  out.append(base, baseLength);
  return out;
}

/**
 * Address: 0x004115A0 (FUN_004115A0)
 * Mangled:
 * ?FILE_CollapsePath@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@PA_N@Z
 *
 * What it does:
 * Canonicalizes separators and collapses `.` / `..` path components.
 */
msvc8::string moho::FILE_CollapsePath(const gpg::StrArg filename, bool* const success)
{
  if (filename == nullptr || filename[0] == '\0') {
    ThrowStartupFileError("Moho::FILE_CollapsePath", "Null argument.");
  }

  msvc8::string fileStr;
  fileStr.assign_owned(filename);
  gpg::STR_Replace(fileStr, "\\", "/", std::numeric_limits<unsigned int>::max());

  const std::string normalized = fileStr.to_std();
  std::string mutablePath = normalized;

  if (success != nullptr) {
    *success = true;
  }

  const bool hasUnc = FILE_HasUNC(filename);
  const bool hasDrive = FILE_HasDrive(filename);
  msvc8::vector<msvc8::string> components;

  msvc8::string out;
  if (hasUnc || hasDrive) {
    out.assign_owned(normalized.substr(0, std::min<std::size_t>(2u, normalized.size())));
  }

  char* cursor = mutablePath.empty() ? nullptr : mutablePath.data();
  if (cursor != nullptr && (hasUnc || hasDrive)) {
    cursor += std::min<std::size_t>(2u, mutablePath.size());
  }

  if (cursor != nullptr && cursor[0] != '\0') {
    for (;;) {
      char* separator = std::strchr(cursor, '/');
      if (separator != nullptr) {
        *separator = '\0';
      }

      if (cursor[0] != '\0') {
        if (cursor[0] == '.' && cursor[1] == '\0') {
          // Skip no-op segment.
        } else if (cursor[0] == '.' && cursor[1] == '.' && cursor[2] == '\0') {
          if (components.empty()) {
            const bool isAbsoluteSlashRoot = !normalized.empty() && normalized[0] == '/' && !hasUnc;
            const bool isAbsoluteDriveRoot = hasDrive && normalized.size() > 2u && normalized[2] == '/';
            if (!isAbsoluteSlashRoot && !isAbsoluteDriveRoot) {
              msvc8::string unresolvedParent;
              unresolvedParent.assign_owned(cursor);
              components.push_back(unresolvedParent);
              if (success != nullptr) {
                *success = false;
              }
            }
          } else {
            components.pop_back();
          }
        } else {
          msvc8::string component;
          component.assign_owned(cursor);
          components.push_back(component);
        }
      }

      if (separator == nullptr || separator[1] == '\0') {
        break;
      }
      cursor = separator + 1;
    }
  }

  const bool isSlashAbsolute = !normalized.empty() && normalized[0] == '/' && !hasUnc;
  if (isSlashAbsolute || hasDrive) {
    out.append(1u, '/');
  }

  for (std::size_t index = 0; index < components.size(); ++index) {
    const msvc8::string& component = components[index];
    out.append(component.c_str(), component.size());
    if ((index + 1u) < components.size() || FILE_HasDrive(component.c_str())) {
      out.append(1u, '/');
    }
  }

  return out;
}

/**
 * Address: 0x00411A20 (FUN_00411A20)
 * Mangled:
 * ?FILE_GetErrorFromErrno@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@H@Z
 *
 * What it does:
 * Maps platform errno values from disk helpers to human-readable text.
 */
msvc8::string moho::FILE_GetErrorFromErrno(const int err)
{
  msvc8::string description;
  switch (err) {
  case 2:
    description.assign_owned("File not found");
    break;
  case 13:
    description.assign_owned("Access denied");
    break;
  case 17:
    description.assign_owned("Path already exists");
    break;
  case 22:
    description.assign_owned("Invalid characters in file name");
    break;
  case 24:
    description.assign_owned("Too many open files.");
    break;
  default:
    description.assign_owned("Unknown disk error");
    break;
  }

  return description;
}

/**
 * Address: 0x008C9D10 (FUN_008C9D10)
 *
 * What it does:
 * Returns local-appdata path suffix:
 * `<LocalAppData>\\Gas Powered Games\\Supreme Commander Forged Alliance`.
 */
msvc8::string moho::USER_GetAppLocalDataDir()
{
  msvc8::string outDir;

  wchar_t localAppDataPath[MAX_PATH]{};
  if (::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppDataPath) < 0) {
    return outDir;
  }

  std::filesystem::path appLocalDir(localAppDataPath);
  appLocalDir /= "Gas Powered Games";
  appLocalDir /= "Supreme Commander Forged Alliance";
  outDir.assign_owned(appLocalDir.generic_string());
  return outDir;
}

/**
 * Address: 0x008C9F90 (FUN_008C9F90)
 *
 * What it does:
 * Returns `<USER_GetAppLocalDataDir()> + "\\cache"` and ensures the cache
 * directory exists.
 */
msvc8::string moho::USER_GetAppCacheDir()
{
  msvc8::string outDir;
  const msvc8::string appLocalDir = USER_GetAppLocalDataDir();
  if (appLocalDir.empty()) {
    return outDir;
  }

  std::filesystem::path cachePath(appLocalDir.c_str());
  cachePath /= "cache";

  std::error_code createDirectoryError;
  std::filesystem::create_directories(cachePath, createDirectoryError);

  outDir.assign_owned(cachePath.generic_string());
  return outDir;
}

/**
 * Address: 0x008CA070 (FUN_008CA070)
 *
 * What it does:
 * Deletes cache directory contents using silent shell delete flags.
 */
void moho::USER_PurgeAppCacheDir()
{
  const msvc8::string cachePath = USER_GetAppCacheDir();
  if (cachePath.empty()) {
    return;
  }

  std::string deletePattern(cachePath.c_str());
  for (char& character : deletePattern) {
    if (character == '/') {
      character = '\\';
    }
  }

  if (!deletePattern.empty() && deletePattern.back() != '\\') {
    deletePattern += '\\';
  }
  deletePattern += '*';

  // SHFileOperation expects a double-null terminated multi-string.
  deletePattern.push_back('\0');

  SHFILEOPSTRUCTA operation{};
  operation.wFunc = FO_DELETE;
  operation.pFrom = deletePattern.c_str();
  operation.fFlags = FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI;
  if (::SHFileOperationA(&operation) != 0) {
    gpg::Warnf("USER_PurgeAppCacheDir: cache purge failed for \"%s\".", deletePattern.c_str());
  }
}

/**
 * Address: 0x008CAF70 (FUN_008CAF70, func_OpenDocuments)
 *
 * What it does:
 * Ensures user documents directories exist for:
 * `<Documents>\\My Games\\<Company>\\<Product>`.
 */
void moho::USER_EnsureDocumentDirectories()
{
  wchar_t documentsPath[MAX_PATH]{};
  if (::SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, documentsPath) < 0) {
    gpg::Warnf("Unable to get My Documents root");
    return;
  }

  std::wstring documentPath(documentsPath);

  const std::wstring myGamesName = gpg::STR_Utf8ToWide(
    moho::Loc(moho::USER_GetLuaState(), "<LOC Engine0020>My Games").c_str()
  );
  documentPath.append(L"\\");
  documentPath.append(myGamesName);
  if (::CreateDirectoryW(documentPath.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    gpg::Warnf("Unable to create document path: %s", reinterpret_cast<const char*>(documentPath.c_str()));
  }

  const std::wstring companyNameWide = gpg::STR_Utf8ToWide(APP_GetCompanyName().c_str());
  documentPath.append(L"\\");
  documentPath.append(companyNameWide);
  if (::CreateDirectoryW(documentPath.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    gpg::Warnf("Unable to create document path: %s", reinterpret_cast<const char*>(documentPath.c_str()));
  }

  const std::wstring productNameWide = gpg::STR_Utf8ToWide(APP_GetProductName().c_str());
  documentPath.append(L"\\");
  documentPath.append(productNameWide);
  if (::CreateDirectoryW(documentPath.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    gpg::Warnf("Unable to create document path: %s", reinterpret_cast<const char*>(documentPath.c_str()));
  }
}

/**
 * Address: 0x008C9E20 (FUN_008C9E20)
 *
 * What it does:
 * Returns user documents path suffix:
 * `<Documents>\\My Games\\<Company>\\<Product>\\`.
 */
msvc8::string moho::USER_GetAppDocDir()
{
  msvc8::string outDir;

  wchar_t documentsPath[MAX_PATH]{};
  if (::SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, documentsPath) < 0) {
    return outDir;
  }

  outDir = gpg::STR_WideToUtf8(documentsPath);
  outDir.push_back('\\');
  (void)outDir.append(moho::Loc(moho::USER_GetLuaState(), "<LOC Engine0020>My Games").view());
  outDir.push_back('\\');
  (void)outDir.append(APP_GetCompanyName().view());
  outDir.push_back('\\');
  (void)outDir.append(APP_GetProductName().view());
  outDir.push_back('\\');
  return outDir;
}

/**
 * Address: 0x008CA2D0 (FUN_008CA2D0)
 *
 * What it does:
 * Returns `<USER_GetAppDocDir()> + "savegames\\"`.
 */
msvc8::string moho::USER_GetSaveGameDir()
{
  return USER_GetAppDocDir() + SaveGameDirName() + "\\";
}

/**
 * Address: 0x008CA380 (FUN_008CA380)
 *
 * What it does:
 * Returns `<APP preference prefix> + "SaveGame"`.
 */
msvc8::string moho::USER_GetSaveGameExt()
{
  return APP_GetPreferencePrefix() + SaveGameExtName();
}

/**
 * Address: 0x008CA3A0 (FUN_008CA3A0)
 *
 * What it does:
 * Returns `<USER_GetAppDocDir()> + "replays\\"`.
 */
msvc8::string moho::USER_GetReplayDir()
{
  return USER_GetAppDocDir() + ReplayDirName() + "\\";
}

/**
 * Address: 0x008CA450 (FUN_008CA450)
 *
 * What it does:
 * Returns `<APP preference prefix> + "Replay"`.
 */
msvc8::string moho::USER_GetReplayExt()
{
  return APP_GetPreferencePrefix() + ReplayExtName();
}

/**
 * Address: 0x008CA470 (FUN_008CA470)
 *
 * What it does:
 * Returns `<APP preference prefix> + "CampaignSave"`.
 */
msvc8::string moho::USER_GetCampaignSaveExt()
{
  return APP_GetPreferencePrefix() + CampaignSaveExtName();
}

/**
 * Address: 0x008CA490 (FUN_008CA490)
 *
 * What it does:
 * Returns `<USER_GetAppDocDir()> + "screenshots\\"` and ensures the
 * screenshot directory exists.
 */
msvc8::string moho::USER_GetScreenshotDir()
{
  msvc8::string outDir = USER_GetAppDocDir() + ScreenshotDirName() + "\\";
  const std::wstring widePath = gpg::STR_Utf8ToWide(outDir.c_str());
  if (::CreateDirectoryW(widePath.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    throw std::runtime_error(gpg::STR_Printf("Unable to create directory %s", outDir.c_str()).to_std());
  }
  return outDir;
}

/**
 * Address: 0x008CA650 (FUN_008CA650, USER_GetSpecialFiles)
 *
 * ESpecialFileType, std::string &, std::string &,
 * std::map<std::string,std::vector<std::string>> &
 *
 * What it does:
 * Resolves the special-file directory/extension pair, ensures the root
 * folder exists, then groups profile-scoped files by profile directory.
 */
void moho::USER_GetSpecialFiles(
  const ESpecialFileType specialFileType,
  std::string& outDirectory,
  std::string& outExtension,
  std::map<std::string, std::vector<std::string>>& outFilesByProfile
)
{
  switch (specialFileType) {
    case ESpecialFileType::SaveGame:
      outDirectory = USER_GetSaveGameDir().to_std();
      outExtension = USER_GetSaveGameExt().to_std();
      break;
    case ESpecialFileType::Replay:
      outDirectory = USER_GetReplayDir().to_std();
      outExtension = USER_GetReplayExt().to_std();
      break;
    case ESpecialFileType::CampaignSave:
      outDirectory = USER_GetSaveGameDir().to_std();
      outExtension = USER_GetCampaignSaveExt().to_std();
      break;
    case ESpecialFileType::Screenshot:
    default:
      {
        ESpecialFileType reflectedType = specialFileType;
        gpg::RRef enumRef{};
        gpg::RRef_ESpecialFileType(&enumRef, &reflectedType);
        const msvc8::string lexical = enumRef.GetLexical();
        throw std::runtime_error(gpg::STR_Printf("Invalid special file type %s", lexical.c_str()).to_std());
      }
  }

  const std::wstring wideDirectory = gpg::STR_Utf8ToWide(outDirectory.c_str());
  if (::CreateDirectoryW(wideDirectory.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    throw std::runtime_error(gpg::STR_Printf("Unable to create directory %s", outDirectory.c_str()).to_std());
  }

  const std::wstring profilePattern = gpg::STR_Utf8ToWide((outDirectory + "*").c_str());
  WIN32_FIND_DATAW profileFindData{};
  const HANDLE profileFindHandle = ::FindFirstFileW(profilePattern.c_str(), &profileFindData);
  if (profileFindHandle == INVALID_HANDLE_VALUE) {
    return;
  }

  do {
    if ((profileFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0u) {
      continue;
    }

    const std::string profileName = gpg::STR_WideToUtf8(profileFindData.cFileName).to_std();
    const std::string filePattern = outDirectory + profileName + "\\*." + outExtension;
    const std::wstring wideFilePattern = gpg::STR_Utf8ToWide(filePattern.c_str());

    WIN32_FIND_DATAW fileFindData{};
    const HANDLE fileFindHandle = ::FindFirstFileW(wideFilePattern.c_str(), &fileFindData);
    if (fileFindHandle == INVALID_HANDLE_VALUE) {
      continue;
    }

    do {
      const std::string fileName = gpg::STR_WideToUtf8(fileFindData.cFileName).to_std();
      outFilesByProfile[profileName].push_back(fileName);
    } while (::FindNextFileW(fileFindHandle, &fileFindData) != FALSE);

    if (::GetLastError() != ERROR_NO_MORE_FILES) {
      ::FindClose(fileFindHandle);
      throw std::runtime_error("Error finding files");
    }

    ::FindClose(fileFindHandle);
  } while (::FindNextFileW(profileFindHandle, &profileFindData) != FALSE);

  if (::GetLastError() != ERROR_NO_MORE_FILES) {
    ::FindClose(profileFindHandle);
    throw std::runtime_error("Error finding prefs directories");
  }

  ::FindClose(profileFindHandle);
}

/**
 * Address: 0x008CAE20 (FUN_008CAE20)
 *
 * What it does:
 * Returns startup preference toggle `debug.enable_debug_facilities`.
 */
bool moho::USER_DebugFacilitiesEnabled()
{
  static const msvc8::string kDebugFacilitiesKey("debug.enable_debug_facilities");
  if (IUserPrefs* const preferences = USER_GetPreferences(); preferences != nullptr) {
    return preferences->GetBoolean(kDebugFacilitiesKey, false);
  }
  return false;
}

/**
 * Address: 0x008CE220 (FUN_008CE220, func_FindMapScenario)
 *
 * What it does:
 * Returns `/maps/<map>/<map>_scenario.lua` for plain map tokens, or the
 * input unchanged when it is already a path-like scenario reference.
 */
msvc8::string moho::FindMapScenario(const gpg::StrArg mapName)
{
  msvc8::string scenarioPath;
  scenarioPath.assign_owned(mapName != nullptr ? mapName : "");

  if (scenarioPath.empty()) {
    return scenarioPath;
  }

  const char* const rawMapName = scenarioPath.c_str();
  if (rawMapName == nullptr || std::strchr(rawMapName, '/') != nullptr || std::strchr(rawMapName, '\\') != nullptr) {
    return scenarioPath;
  }

  return gpg::STR_Printf("/maps/%s/%s_scenario.lua", rawMapName, rawMapName);
}

/**
 * Address: 0x008CE2A0 (FUN_008CE2A0, func_StartCommandLineSession)
 *
 * What it does:
 * Imports `/lua/SinglePlayerLaunch.lua` and invokes
 * `StartCommandLineSession(mapName, isPerfTest)`.
 */
bool moho::StartCommandLineSession(const gpg::StrArg mapName, const bool isPerfTest)
{
  const char* const effectiveMapName = mapName != nullptr ? mapName : "";

  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    if (state == nullptr) {
      throw std::runtime_error("USER_GetLuaState() returned null.");
    }

    const LuaPlus::LuaObject launchModule = SCR_ImportLuaModule(state, "/lua/SinglePlayerLaunch.lua");
    if (launchModule.IsNil()) {
      throw std::runtime_error("Unable to import '/lua/SinglePlayerLaunch.lua'.");
    }

    const LuaPlus::LuaObject launchFunction = SCR_GetLuaTableField(state, launchModule, "StartCommandLineSession");
    if (launchFunction.IsNil()) {
      throw std::runtime_error("Missing StartCommandLineSession Lua entrypoint.");
    }

    LuaPlus::LuaFunction<void> startCommandLineSession(launchFunction);
    startCommandLineSession(effectiveMapName, isPerfTest);
    return true;
  } catch (const std::exception& exception) {
    const msvc8::string message = gpg::STR_Printf(
      "Unable to launch %s:\n%s", effectiveMapName, exception.what() != nullptr ? exception.what() : ""
    );
    WIN_OkBox("Ack!", message.c_str());
    return false;
  } catch (...) {
    const msvc8::string message = gpg::STR_Printf("Unable to launch %s:\nunknown error", effectiveMapName);
    WIN_OkBox("Ack!", message.c_str());
    return false;
  }
}

namespace
{
  /**
   * Address: 0x004583D0 (FUN_004583D0, func_FWaitSetError)
   *
   * What it does:
   * Maps one `errno` value to disk-error text and publishes it to the
   * thread-local file wait-handle error slot.
   */
  void func_FWaitSetError(const int err)
  {
    const msvc8::string errorDescription = moho::FILE_GetErrorFromErrno(err);
    if (msvc8::string* const errorSlot = moho::FWaitHandleSet::GetErrorString(); errorSlot != nullptr) {
      errorSlot->assign_owned(errorDescription.view());
    }
  }

  /**
   * Address: 0x0045A930 (FUN_0045A930, func_StringSetFilename2)
   *
   * What it does:
   * Initializes destination string storage and canonicalizes one filesystem
   * path token.
   */
  msvc8::string* func_StringSetFilename2(msvc8::string* const out, const gpg::StrArg sourcePath)
  {
    return gpg::STR_InitFilename(out, sourcePath != nullptr ? sourcePath : "");
  }

  /**
   * Address: 0x0045A8D0 (FUN_0045A8D0, SetCanonicalFilenameFromString)
   *
   * What it does:
   * Initializes destination string storage from one source string and
   * canonicalizes it as a filesystem token.
   */
  msvc8::string* SetCanonicalFilenameFromString(msvc8::string* const out, const msvc8::string& sourcePath)
  {
    return func_StringSetFilename2(out, sourcePath.c_str());
  }
} // namespace

/**
 * Address: 0x0045A670 (FUN_0045A670)
 * Mangled:
 * ?DISK_GetLaunchDir@Moho@@YA?AV?$basic_path@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@Upath_traits@filesystem@boost@@@filesystem@boost@@XZ
 *
 * What it does:
 * Resolves executable launch directory from `argv[0]`.
 */
std::filesystem::path moho::DISK_GetLaunchDir()
{
  std::array<char, MAX_PATH> executablePathBuffer{};
  const char* const argv0 = (__argv != nullptr && __argv[0] != nullptr) ? __argv[0] : ".";
  if (_fullpath(executablePathBuffer.data(), argv0, executablePathBuffer.size()) == nullptr) {
    executablePathBuffer.fill('\0');
    executablePathBuffer[0] = '.';
  }

  msvc8::string launchPath{};
  (void)func_StringSetFilename2(&launchPath, executablePathBuffer.data());
  const msvc8::string launchDirText = FILE_DirPrefix(launchPath.c_str());
  return std::filesystem::path(launchDirText.c_str());
}

/**
 * Address: 0x0045A770 (FUN_0045A770)
 * Mangled: ?DISK_CreateFolder@Moho@@YA_NVStrArg@gpg@@@Z
 *
 * What it does:
 * Attempts to create one folder and stores wait-handle error text on failure.
 */
bool moho::DISK_CreateFolder(const gpg::StrArg sourcePath)
{
  const char* const folderPath = sourcePath != nullptr ? sourcePath : "";
  if (_mkdir(folderPath) == 0) {
    return true;
  }

  func_FWaitSetError(errno);
  return false;
}

/**
 * Address: 0x0045A7A0 (FUN_0045A7A0)
 * Mangled: ?DISK_Recycle@Moho@@YAXVStrArg@gpg@@@Z
 *
 * What it does:
 * Moves one file/folder path into shell recycle bin without UI prompts.
 */
void moho::DISK_Recycle(const gpg::StrArg sourcePath)
{
  SHFILEOPSTRUCTW fileOperation{};
  fileOperation.wFunc = FO_DELETE;
  fileOperation.fFlags = FOF_SILENT | FOF_NOCONFIRMATION | FOF_ALLOWUNDO | FOF_NOERRORUI;

  const std::wstring widePath = gpg::STR_Utf8ToWide(sourcePath != nullptr ? sourcePath : "");
  std::array<wchar_t, MAX_PATH + 2> recyclePath{};
  const std::size_t copyCount = (std::min)(widePath.size(), recyclePath.size() - 2);
  std::copy_n(widePath.c_str(), copyCount, recyclePath.data());
  recyclePath[copyCount] = L'\0';
  recyclePath[copyCount + 1] = L'\0';

  fileOperation.pFrom = recyclePath.data();
  fileOperation.pTo = nullptr;
  (void)::SHFileOperationW(&fileOperation);
}

/**
 * Address: 0x00459DE0 (FUN_00459DE0)
 * Mangled:
 * ?DISK_SetupDataAndSearchPaths@Moho@@YA_NV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV?$basic_path@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@Upath_traits@filesystem@boost@@@filesystem@boost@@@Z
 *
 * What it does:
 * Validates and records launch-directory/data-script bootstrap paths for
 * early startup services.
 */
bool moho::DISK_SetupDataAndSearchPaths(const msvc8::string& dataPathScriptName, const std::filesystem::path& launchDir)
{
  const std::filesystem::path absoluteLaunchDirectory =
    MakeAbsolutePath(launchDir.empty() ? std::filesystem::current_path() : launchDir);
  if (absoluteLaunchDirectory.empty()) {
    return false;
  }

  std::filesystem::path scriptPath(dataPathScriptName.c_str());
  if (scriptPath.empty()) {
    return false;
  }
  if (!scriptPath.is_absolute()) {
    scriptPath = absoluteLaunchDirectory / scriptPath;
  }
  const std::filesystem::path absoluteScriptPath = MakeAbsolutePath(scriptPath);
  if (absoluteScriptPath.empty()) {
    return false;
  }

  std::error_code ec;
  if (!std::filesystem::exists(absoluteScriptPath, ec) || ec) {
    return false;
  }

  std::vector<std::wstring> allowedProtocols;
  if (LuaPlus::LuaState* const startupState = ResolveStartupLuaState(); startupState != nullptr) {
    patch_InitLuaState(startupState, 2);
    allowedProtocols = CollectAllowedProtocolsFromLua(startupState);
  }

  {
    std::lock_guard<std::mutex> lock(gDiskPathStateLock);
    gLaunchDirectory = absoluteLaunchDirectory;
    gDataPathScriptFile = absoluteScriptPath;
    gAllowedProtocols = std::move(allowedProtocols);
  }

  return true;
}

/**
 * Address: 0x00459DA0 (FUN_00459DA0,
 * ?DISK_GetAllowedProtocols@Moho@@YA?AV?$vector@V?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@V?$allocator@V?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@2@@std@@XZ)
 *
 * What it does:
 * Returns a by-value copy of startup-configured allowed URL protocol names.
 */
std::vector<std::wstring> moho::DISK_GetAllowedProtocols()
{
  std::vector<std::wstring> protocols;
  CopyAllowedProtocols(protocols);
  return protocols;
}

std::filesystem::path moho::DISK_GetLaunchDirectory()
{
  std::lock_guard<std::mutex> lock(gDiskPathStateLock);
  return gLaunchDirectory;
}

std::filesystem::path moho::DISK_GetDataPathScriptFile()
{
  std::lock_guard<std::mutex> lock(gDiskPathStateLock);
  return gDataPathScriptFile;
}

/**
 * Address: 0x00874AF0 (FUN_00874AF0, `Moho::CMovieManager::CMovieManager`)
 *
 * What it does:
 * Initializes movie-audio runtime ownership lanes and Sofdec middleware setup.
 */
moho::CMovieManager::CMovieManager()
{
  CreateDirectSound();

  ::ADXPC_SetupSoundDirectSound8(mDirectSound);
  ::ADXPC_SetupFileSystem(nullptr);
  ::ADXM_SetupThrd(nullptr);

  moho::MwsfdInitPrm initParams{};
  initParams.vhz = kMovieSofdecVideoRefreshHz;
  initParams.disp_cycle = 1;
  initParams.disp_latency = 1;
  initParams.dec_svr = moho::MWSFD_DEC_SVR_MAIN;

  ::ADXM_SetCbErr(&GpgSofDecError, 0);
  ::mwPlyInitSfdFx(&initParams);
  mVolume = 0.0f;
}

/**
 * Address: 0x00874990 (FUN_00874990, `func_CreateDirectSound`)
 *
 * What it does:
 * Creates DirectSound runtime state and primary sound buffer unless
 * `/nosound` startup flag is present.
 */
void moho::CMovieManager::CreateDirectSound()
{
  if (CFG_GetArgOption("/nosound", 0, nullptr)) {
    return;
  }

  if (FAILED(::DirectSoundCreate(nullptr, &mDirectSound, nullptr))) {
    gpg::Logf("Failed to create DirectSound.");
    return;
  }

  const HWND mainWindowHandle =
    sMainWindow != nullptr ? reinterpret_cast<HWND>(static_cast<std::uintptr_t>(sMainWindow->GetHandle())) : nullptr;
  if (mainWindowHandle == nullptr || FAILED(mDirectSound->SetCooperativeLevel(mainWindowHandle, DSSCL_PRIORITY))) {
    gpg::Warnf("Failed to set cooperative level.");
    ReleaseDirectSoundObjects();
    return;
  }

  WAVEFORMATEX waveFormat{};
  waveFormat.wFormatTag = WAVE_FORMAT_PCM;
  waveFormat.nChannels = 2;
  waveFormat.nSamplesPerSec = 48000;
  waveFormat.nAvgBytesPerSec = 192000;
  waveFormat.nBlockAlign = 4;
  waveFormat.wBitsPerSample = 16;

  DSBUFFERDESC bufferDesc{};
  bufferDesc.dwSize = sizeof(bufferDesc);
  bufferDesc.dwFlags = DSBCAPS_CTRLVOLUME;
  bufferDesc.dwBufferBytes = 576000;
  bufferDesc.lpwfxFormat = &waveFormat;
  if (FAILED(mDirectSound->CreateSoundBuffer(&bufferDesc, &mPrimarySoundBuffer, nullptr))) {
    gpg::Warnf("Failed to create primary sound buffer.");
    ReleaseDirectSoundObjects();
  }
}

void moho::CMovieManager::ReleaseDirectSoundObjects()
{
  if (mPrimarySoundBuffer != nullptr) {
    mPrimarySoundBuffer->Release();
    mPrimarySoundBuffer = nullptr;
  }
  if (mDirectSound != nullptr) {
    mDirectSound->Release();
    mDirectSound = nullptr;
  }
}

/**
 * Address context:
 * - `0x00875020` (`cfunc_SetMovieVolumeL`) applies this transform when
 *   script code sets movie volume.
 */
void moho::CMovieManager::SetVolumeFromLua(const float requestedVolume)
{
  float clampedVolume = requestedVolume;
  if (clampedVolume >= kLuaMovieVolumeHardClamp) {
    clampedVolume = kLuaMovieVolumeHardClamp;
  }
  if (clampedVolume < 0.0f) {
    clampedVolume = 0.0f;
  }
  if (clampedVolume >= kLuaMovieVolumeMax) {
    clampedVolume = kLuaMovieVolumeMax;
  }

  mVolume =
    static_cast<float>(static_cast<std::int32_t>(kLuaMovieVolumeDbFloor - (clampedVolume * kLuaMovieVolumeDbFloor)));
}

/**
 * Address context:
 * - `0x00875180` (`cfunc_GetMovieVolumeL`) reads this stored lane.
 */
float moho::CMovieManager::GetVolumeForLua() const
{
  return mVolume;
}

/**
 * Address: 0x00875290 (FUN_00875290, `Moho::CMovieManager::Destroy`)
 *
 * What it does:
 * Shuts down movie Sofdec middleware, releases COM interfaces, and destroys this instance.
 */
void moho::CMovieManager::Destroy()
{
  ::mwPlyFinishSfdFx();
  ::ADXM_Finish();
  ReleaseDirectSoundObjects();
  delete this;
}

/**
 * Address: 0x008C9110 (FUN_008C9110)
 * Mangled: ?USER_GetPreferences@Moho@@YAPAVIUserPrefs@1@XZ
 *
 * What it does:
 * Returns process-global user-preferences object, creating default runtime
 * state on first use.
 */
moho::IUserPrefs* moho::USER_GetPreferences()
{
  if (gPreferences != nullptr) {
    return gPreferences;
  }

  gpg::Warnf("preferences not loaded prior to first use, creating defaults");
  gPreferences = new CUserPrefsRuntime{};
  return gPreferences;
}

/**
 * Address: 0x008C68A0 (FUN_008C68A0)
 * Mangled: ?OPTIONS_GetInt@Moho@@YAHVStrArg@gpg@@@Z
 *
 * What it does:
 * Reads one options value from `/lua/user/prefs.lua:GetOption` and returns it
 * as an integer lane.
 */
std::int32_t moho::OPTIONS_GetInt(const gpg::StrArg key)
{
  IUserPrefs* const preferences = USER_GetPreferences();
  if (preferences == nullptr) {
    return 0;
  }

  msvc8::string optionKey;
  optionKey.assign_owned(key != nullptr ? key : "");
  return preferences->GetInteger(optionKey, 0);
}

/**
 * Address: 0x008C6AB0 (FUN_008C6AB0)
 * Mangled:
 * ?OPTIONS_GetString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@@Z
 *
 * What it does:
 * Reads one options value from `/lua/user/prefs.lua:GetOption` and returns it
 * as an owned `msvc8::string`.
 */
msvc8::string moho::OPTIONS_GetString(const gpg::StrArg key)
{
  IUserPrefs* const preferences = USER_GetPreferences();
  if (preferences == nullptr) {
    msvc8::string fallback;
    fallback.assign_owned("");
    return fallback;
  }

  msvc8::string optionKey;
  optionKey.assign_owned(key != nullptr ? key : "");

  msvc8::string fallback;
  fallback.assign_owned("");
  return preferences->GetString(optionKey, fallback);
}

/**
 * Address: 0x008C6BF0 (FUN_008C6BF0)
 * Mangled: ?OPTIONS_GetBool@Moho@@YA_NVStrArg@gpg@@@Z
 *
 * What it does:
 * Invokes `/lua/user/prefs.lua:GetOption(key)` and returns the value as one
 * boolean lane; on Lua bridge failure logs a warning and returns `false`.
 */
bool moho::OPTIONS_GetBool(const gpg::StrArg key)
{
  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
    LuaPlus::LuaObject getOptionFnObject = prefsModule[kGetOptionMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> getOptionFn(getOptionFnObject);
    LuaPlus::LuaObject optionValue = getOptionFn(key);
    return optionValue.GetBoolean();
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsGetOptionLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
    return false;
  }
}

/**
 * Address: 0x008C6CF0 (FUN_008C6CF0)
 * Mangled: ?OPTIONS_Apply@Moho@@YAXXZ
 *
 * What it does:
 * Invokes `/lua/options/optionslogic.lua:Apply()` and discards the return
 * object. Lua bridge failures are logged without aborting startup flow.
 */
void moho::OPTIONS_Apply()
{
  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject optionsModule = SCR_Import(state, kOptionsLogicModulePath);
    LuaPlus::LuaObject applyFnObject = optionsModule[kApplyMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> applyFn(applyFnObject);
    LuaPlus::LuaObject callResult = applyFn();
    (void)callResult;
  } catch (const std::exception& exception) {
    gpg::Warnf(kOptionsApplyLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
  }
}

/**
 * Address: 0x008C6DC0 (FUN_008C6DC0)
 * Mangled: ?OPTIONS_SetCustomData@Moho@@YAXVStrArg@gpg@@ABVLuaObject@LuaPlus@@1@Z
 *
 * What it does:
 * Invokes `/lua/options/optionslogic.lua:SetCustomData` for one option key
 * using `(customData, defaultValue)` Lua object lanes.
 */
void moho::OPTIONS_SetCustomData(
  const gpg::StrArg key,
  const LuaPlus::LuaObject& customData,
  const LuaPlus::LuaObject& defaultValue
)
{
  try {
    LuaPlus::LuaState* const state = customData.GetActiveState();
    LuaPlus::LuaObject optionsModule = SCR_Import(state, kOptionsLogicModulePath);
    LuaPlus::LuaObject setCustomDataFnObject = optionsModule[kSetCustomDataMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> setCustomDataFn(setCustomDataFnObject);
    LuaPlus::LuaObject callResult = setCustomDataFn(key, customData, defaultValue);
    (void)callResult;
  } catch (const std::exception& exception) {
    gpg::Warnf(kOptionsSetCustomDataLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
  }
}

/**
 * Address: 0x008C6EC0 (FUN_008C6EC0)
 * Mangled: ?OPTIONS_CreateInitialProfileIfNeeded@Moho@@YAXVStrArg@gpg@@@Z
 *
 * What it does:
 * Executes `/lua/user/prefs.lua` profile bootstrap:
 * - `ProfilesExist()`
 * - `CreateProfile(profileName)` when profiles are missing.
 */
void moho::OPTIONS_CreateInitialProfileIfNeeded(const gpg::StrArg profileName)
{
  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
    LuaPlus::LuaObject profilesExistFnObject = prefsModule[kProfilesExistMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> profilesExistFn(profilesExistFnObject);
    LuaPlus::LuaObject profilesExistResult = profilesExistFn();

    if (!profilesExistResult.GetBoolean()) {
      prefsModule = SCR_Import(state, kUserPrefsModulePath);
      LuaPlus::LuaObject createProfileFnObject = prefsModule[kCreateProfileMethodName];
      LuaPlus::LuaFunction<LuaPlus::LuaObject> createProfileFn(createProfileFnObject);
      LuaPlus::LuaObject createProfileResult = createProfileFn(profileName);
      (void)createProfileResult;
    }
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
  }
}

/**
 * Address: 0x008C7040 (FUN_008C7040)
 * Mangled:
 * ?OPTIONS_GetCurrentProfileName@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
 *
 * What it does:
 * Invokes `/lua/user/prefs.lua:GetCurrentProfile()` and returns the profile
 * `Name` field.
 */
msvc8::string moho::OPTIONS_GetCurrentProfileName()
{
  msvc8::string profileName{};
  profileName.assign_owned("");

  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
    LuaPlus::LuaObject getCurrentProfileFnObject = prefsModule[kGetCurrentProfileMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> getCurrentProfileFn(getCurrentProfileFnObject);
    LuaPlus::LuaObject currentProfileObject = getCurrentProfileFn();
    LuaPlus::LuaObject profileNameObject = currentProfileObject[kProfileNameFieldName];

    const char* const profileNameText = profileNameObject.GetString();
    profileName.assign_owned(profileNameText != nullptr ? profileNameText : "");
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
  }

  return profileName;
}

/**
 * Address: 0x008D21E0 (FUN_008D21E0)
 *
 * What it does:
 * Publishes primary-adapter option states and default selection data for the
 * startup options UI.
 */
void moho::SetupPrimaryAdapterSettings()
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  if (gpg::gal::Device* const device = gpg::gal::Device::GetInstance()) {
    RefreshFidelitySupportLanes(device->GetDeviceContext());
  }

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");

  if (sAdapterNotCLOverridden != 0) {
    AddOptionStateString(state, &statesTable, 1, "<LOC OPTIONS_0070>Windowed", kWindowedModeKey);

    msvc8::vector<gpg::gal::HeadAdapterMode> modes = CollectAdapterModes(0);
    std::int32_t nextStateIndex = 2;
    const gpg::gal::HeadAdapterMode* const begin = modes.begin();
    const gpg::gal::HeadAdapterMode* const end = modes.end();
    if (begin != nullptr && end != nullptr) {
      for (const gpg::gal::HeadAdapterMode* it = begin; it != end; ++it) {
        const msvc8::string label = BuildModeLabel(*it);
        const msvc8::string value = BuildModeKey(*it);
        AddOptionStateString(state, &statesTable, nextStateIndex, label.c_str(), value.c_str());
        ++nextStateIndex;
      }
    }

    LuaPlus::LuaObject defaultValue(state);
    defaultValue.AssignString(state, "1024,768,60");
    OPTIONS_SetCustomData(kPrimaryAdapterKey, optionRoot, defaultValue);
    return;
  }

  AddOptionStateString(state, &statesTable, 1, "<LOC _Command_Line_Override>", kCommandLineOverrideModeKey);

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignString(state, kCommandLineOverrideModeKey);
  OPTIONS_SetCustomData(kPrimaryAdapterKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D26D0 (FUN_008D26D0)
 *
 * What it does:
 * Publishes secondary-adapter option states. When command-line adapter
 * override is active, publishes only the override lane.
 */
void moho::SetupSecondaryAdapterSettings(const bool adapterNotCommandLineOverridden)
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");

  if (sAdapterNotCLOverridden == 0) {
    AddOptionStateString(state, &statesTable, 1, "<LOC _Command_Line_Override>", kCommandLineOverrideModeKey);

    LuaPlus::LuaObject defaultValue(state);
    defaultValue.AssignString(state, kCommandLineOverrideModeKey);
    OPTIONS_SetCustomData(kSecondaryAdapterKey, optionRoot, defaultValue);
    return;
  }

  AddOptionStateString(state, &statesTable, 1, "<LOC _Disabled>", kDisabledModeKey);
  std::int32_t nextStateIndex = 2;

  if (!adapterNotCommandLineOverridden) {
    msvc8::vector<gpg::gal::HeadAdapterMode> modes = CollectAdapterModes(1);
    const gpg::gal::HeadAdapterMode* const begin = modes.begin();
    const gpg::gal::HeadAdapterMode* const end = modes.end();
    if (begin != nullptr && end != nullptr) {
      for (const gpg::gal::HeadAdapterMode* it = begin; it != end; ++it) {
        const msvc8::string label = BuildModeLabel(*it);
        const msvc8::string value = BuildModeKey(*it);
        AddOptionStateString(state, &statesTable, nextStateIndex, label.c_str(), value.c_str());
        ++nextStateIndex;
      }
    }
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignString(state, kDisabledModeKey);
  OPTIONS_SetCustomData(kSecondaryAdapterKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D2B90 (FUN_008D2B90)
 *
 * What it does:
 * Publishes fidelity-preset option states and default preset selection.
 */
void moho::CreateFidelityPresets()
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
  RefreshFidelitySupportLanes(context);

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");

  AddOptionStateInteger(state, &statesTable, 1, "<LOC _Low>", 0);
  AddOptionStateInteger(state, &statesTable, 2, "<LOC _Medium>", 1);

  std::int32_t nextStateIndex = 3;
  if (graphics_FidelitySupported > 1) {
    AddOptionStateInteger(state, &statesTable, nextStateIndex, "<LOC _High>", 2);
    ++nextStateIndex;
  }

  if (context != nullptr && context->mPixelShaderProfile > 8) {
    AddOptionStateInteger(state, &statesTable, nextStateIndex, "<LOC _Ultra>", 3);
    ++nextStateIndex;
  }

  AddOptionStateInteger(state, &statesTable, nextStateIndex, "<LOC _Custom>", 4);

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 1.0);
  OPTIONS_SetCustomData(kFidelityPresetsKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D2E20 (FUN_008D2E20)
 *
 * What it does:
 * Publishes fidelity option states and default selection.
 */
void moho::SetupFidelitySettings()
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
  RefreshFidelitySupportLanes(context);

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");

  AddOptionStateInteger(state, &statesTable, 1, "<LOC _Low>", 0);
  AddOptionStateInteger(state, &statesTable, 2, "<LOC _Medium>", 1);

  if (graphics_FidelitySupported > 1) {
    AddOptionStateInteger(state, &statesTable, 3, "<LOC _High>", 2);
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 1.0);
  OPTIONS_SetCustomData(kFidelityKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D3010 (FUN_008D3010)
 *
 * What it does:
 * Publishes shadow-quality option states and default selection.
 */
void moho::SetupShadowQualitySettings()
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
  RefreshFidelitySupportLanes(context);

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");

  AddOptionStateInteger(state, &statesTable, 1, "<LOC _Off>", 0);
  AddOptionStateInteger(state, &statesTable, 2, "<LOC _Low>", 1);
  AddOptionStateInteger(state, &statesTable, 3, "<LOC _Medium>", 2);

  if (shadow_FidelitySupported > 2) {
    AddOptionStateInteger(state, &statesTable, 4, "<LOC _High>", 3);
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 1.0);
  OPTIONS_SetCustomData(kShadowQualityKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D3250 (FUN_008D3250)
 *
 * What it does:
 * Publishes anti-aliasing option states from active head sample-options list.
 */
void moho::SetupAntiAliasingSettings()
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");
  AddOptionStateInteger(state, &statesTable, 1, "<LOC OPTIONS_0029>Off", 0);

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
  if (context != nullptr && context->GetHeadCount() > 0) {
    const gpg::gal::Head& head = context->GetHead(0);
    const gpg::gal::HeadSampleOption* const begin = head.mStrs.begin();
    const gpg::gal::HeadSampleOption* const end = head.mStrs.end();
    if (begin != nullptr && end != nullptr) {
      std::int32_t nextStateIndex = 2;
      for (const gpg::gal::HeadSampleOption* it = begin; it != end; ++it) {
        const std::uint32_t packedMode = it->sampleType | (it->sampleQuality << 5);
        AddOptionStateInteger(
          state, &statesTable, nextStateIndex, it->label.c_str(), static_cast<std::int32_t>(packedMode)
        );
        ++nextStateIndex;
      }
    }
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 0.0);
  OPTIONS_SetCustomData(kAntiAliasingKey, optionRoot, defaultValue);
}

/**
 * Address: 0x00874C20 (FUN_00874C20)
 *
 * What it does:
 * Recreates process-global movie-manager ownership lane.
 */
void moho::SetupBasicMovieManager()
{
  CMovieManager* const manager = new CMovieManager{};
  if (manager != gMovieManager && gMovieManager != nullptr) {
    gMovieManager->Destroy();
  }

  gMovieManager = manager;
}

/**
 * Address: 0x00874D30 (FUN_00874D30, `Moho::MOV_GetDuration`)
 *
 * What it does:
 * Resolves one movie path through mounted VFS state, parses Sofdec header
 * metadata, and returns duration in seconds for valid SFD payloads.
 */
float moho::MOV_GetDuration(const gpg::StrArg sourcePath)
{
  if (gMovieManager == nullptr) {
    gpg::Warnf("Movie component not initialized.");
    return 0.0f;
  }

  const char* const requestedPath = sourcePath != nullptr ? sourcePath : "";
  FILE_EnsureWaitHandleSet();
  FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();

  msvc8::string resolvedPath{};
  (void)waitHandleSet->mHandle->FindFile(&resolvedPath, requestedPath, nullptr);
  if (resolvedPath.empty()) {
    gpg::Warnf("Movie file \"%s\" doesn't exist.", requestedPath);
    return 0.0f;
  }

  const gpg::MemBuffer<const char> mappedMovieData = DISK_MemoryMapFile(resolvedPath.c_str());
  if (mappedMovieData.mBegin == nullptr) {
    return 0.0f;
  }

  SofdecHeaderInfoRuntimeView headerInfo{};
  std::memset(&headerInfo, 0, sizeof(headerInfo));
  const std::int32_t mappedByteCount = static_cast<std::int32_t>(mappedMovieData.mEnd - mappedMovieData.mBegin);
  (void)mwPlyGetHdrInf(mappedMovieData.mBegin, mappedByteCount, &headerInfo);

  const bool validType =
    (headerInfo.streamType == kSofdecHeaderTypeMovie || headerInfo.streamType == kSofdecHeaderTypeMovieAlt);
  if (validType && headerInfo.headerValid != 0 && headerInfo.frameRateTimes1000 != 0) {
    return static_cast<float>(headerInfo.frameCount) / (static_cast<float>(headerInfo.frameRateTimes1000) * 0.001f);
  }

  gpg::Warnf("%s is not a valid SFD file.", requestedPath);
  return 0.0f;
}

/**
 * Address: 0x008E6B60 (FUN_008E6B60, func_CreateDeviceD3D)
 *
 * What it does:
 * Refreshes fidelity-support lanes, replaces the global GAL backend singleton,
 * and dispatches typed backend startup by requested API token.
 */
void moho::CreateDeviceD3D(gpg::gal::DeviceContext* const context)
{
  if (context == nullptr) {
    return;
  }

  RefreshFidelitySupportLanes(context);

  if (context->mDeviceType != 1 && context->mDeviceType != 2) {
    throw gpg::gal::Error(
      msvc8::string("c:\\work\\rts\\main\\code\\src\\libs\\gpggal\\Device.cpp"),
      135,
      msvc8::string("unknown API requested")
    );
  }

  gpg::gal::Device::DestroyInstance();

  if (context->mDeviceType == 1) {
    gpg::gal::Device* const backend = gpg::gal::CreateDeviceD3D9Backend();
    gpg::gal::Device::SetInstance(backend);
    gpg::gal::InitializeDeviceD3D9Backend(backend, context);
  } else {
    gpg::gal::Device* const backend = gpg::gal::CreateDeviceD3D10Backend();
    gpg::gal::Device::SetInstance(backend);
    gpg::gal::InitializeDeviceD3D10Backend(backend, context);
  }

  if (gpg::gal::Device::GetInstance() == nullptr) {
    gpg::Warnf("CreateDeviceD3D: backend device instance is unavailable for type %d.", context->mDeviceType);
  }
}

