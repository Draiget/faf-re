#include "moho/misc/StartupHelpers.h"

#include <algorithm>
#include <exception>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>

#include <Windows.h>
#include <mmreg.h>
#include <mmsystem.h>
#include <dsound.h>
#include <shellapi.h>
#include <ShlObj.h>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/backends/d3d10/DeviceD3D10.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/app/WinApp.h"
#include "moho/client/Localization.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/ui/CUIManager.h"

extern int __argc;
extern char** __argv;

namespace
{
  std::mutex gDiskPathStateLock;
  std::filesystem::path gLaunchDirectory;
  std::filesystem::path gDataPathScriptFile;
  moho::SAppIdentity gAppIdentity{};
  std::uint8_t gAqtimeInstrumentationMode = 1;
  std::once_flag gAppIdentityInitOnce;
  std::int32_t gGraphicsFidelitySupported = 1;
  std::int32_t gShadowFidelitySupported = 2;
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
    kMaximizeAliases,
    sizeof(kMaximizeAliases) / sizeof(kMaximizeAliases[0])
  };
  constexpr moho::CfgAliasSet kDualAliasesSet{kDualAliases, sizeof(kDualAliases) / sizeof(kDualAliases[0])};
  constexpr moho::CfgAliasSet kHeadAliasesSet{kHeadAliases, sizeof(kHeadAliases) / sizeof(kHeadAliases[0])};
  constexpr moho::CfgAliasSet kFullscreenAliasesSet{
    kFullscreenAliases,
    sizeof(kFullscreenAliases) / sizeof(kFullscreenAliases[0])
  };
  constexpr moho::CfgAliasSet kWindowedAliasesSet{
    kWindowedAliases,
    sizeof(kWindowedAliases) / sizeof(kWindowedAliases[0])
  };
  constexpr char kUserPrefsModulePath[] = "/lua/user/prefs.lua";
  constexpr char kOptionsLogicModulePath[] = "/lua/options/optionslogic.lua";
  constexpr char kGetOptionMethodName[] = "GetOption";
  constexpr char kSetCustomDataMethodName[] = "SetCustomData";
  constexpr char kPrimaryAdapterKey[] = "primary_adapter";
  constexpr char kSecondaryAdapterKey[] = "secondary_adapter";
  constexpr char kFidelityPresetsKey[] = "fidelity_presets";
  constexpr char kFidelityKey[] = "fidelity";
  constexpr char kShadowQualityKey[] = "shadow_quality";
  constexpr char kAntiAliasingKey[] = "antialiasing";
  constexpr char kWindowedModeKey[] = "windowed";
  constexpr char kDisabledModeKey[] = "disabled";
  constexpr char kCommandLineOverrideModeKey[] = "overridden";
  constexpr float kLuaMovieVolumeHardClamp = 2.0f;
  constexpr float kLuaMovieVolumeMax = 1.0f;
  constexpr float kLuaMovieVolumeDbFloor = -10000.0f;
  constexpr float kMovieSofdecVideoRefreshHz = 59.939999f;

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
    const std::string& option,
    const std::uint32_t requiredArgCount,
    msvc8::vector<msvc8::string>* const outArgs
  )
  {
    if (option.empty()) {
      return false;
    }
    return moho::CFG_GetArgOption(option.c_str(), requiredArgCount, outArgs);
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveStartupLuaState()
  {
    if (moho::g_UIManager != nullptr && moho::g_UIManager->mLuaState != nullptr) {
      return moho::g_UIManager->mLuaState;
    }

    return moho::USER_GetLuaState();
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

    if (gpg::STR_CompareNoCase(text, "true") == 0 || gpg::STR_CompareNoCase(text, "yes") == 0 ||
        gpg::STR_CompareNoCase(text, "on") == 0 || std::strcmp(text, "1") == 0) {
      *outValue = true;
      return true;
    }

    if (gpg::STR_CompareNoCase(text, "false") == 0 || gpg::STR_CompareNoCase(text, "no") == 0 ||
        gpg::STR_CompareNoCase(text, "off") == 0 || std::strcmp(text, "0") == 0) {
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
  bool HasMode(
    const msvc8::vector<gpg::gal::HeadAdapterMode>& acceptedModes, const gpg::gal::HeadAdapterMode& mode
  )
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

  void OptionsSetCustomData(
    LuaPlus::LuaState* const state,
    const char* const optionKey,
    const LuaPlus::LuaObject& optionRoot,
    const LuaPlus::LuaObject& defaultValue
  )
  {
    if (state == nullptr || optionKey == nullptr || optionKey[0] == '\0') {
      return;
    }

    const LuaPlus::LuaObject optionsModule = ImportLuaModule(state, kOptionsLogicModulePath);
    const LuaPlus::LuaObject setCustomDataFn = GetLuaModuleFunction(state, optionsModule, kSetCustomDataMethodName);
    if (setCustomDataFn.IsNil()) {
      return;
    }

    LuaPlus::LuaFunction<void> setCustomDataCallable(setCustomDataFn);
    setCustomDataCallable(optionKey, defaultValue, optionRoot);
  }

  void RefreshFidelitySupportLanes(const gpg::gal::DeviceContext* const context)
  {
    if (context == nullptr) {
      return;
    }

    gGraphicsFidelitySupported = context->mPixelShaderProfile > 5 ? 2 : 1;
    gShadowFidelitySupported = context->mPixelShaderProfile > 5 ? 3 : 2;
  }

  [[nodiscard]] LuaPlus::LuaObject QueryOptionValueWithLocalOverride(
    LuaPlus::LuaObject* const localOverrideRoot,
    const msvc8::string& key
  )
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

  class CUserPrefsRuntime final : public moho::IUserPrefs
  {
  public:
    CUserPrefsRuntime()
      : mPreferencesFilePath()
      , mPreferencesProfileName()
      , mState()
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

    std::uint32_t GetHex(const msvc8::string& key, const std::uint32_t fallback) override
    {
      std::uint32_t valueAsHex = fallback;
      const LuaPlus::LuaObject value = QueryOptionValueWithLocalOverride(&mRoot, key);
      if (TryGetHexFromLuaValue(value, &valueAsHex)) {
        return valueAsHex;
      }
      return fallback;
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

    msvc8::vector<msvc8::string> GetStringArr(
      const msvc8::string& key,
      const msvc8::vector<msvc8::string>& fallback
    ) override
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
      mRoot.SetInteger(key.c_str(), value ? 1 : 0);
    }

    void SetInteger(const msvc8::string& key, const std::int32_t value) override
    {
      mRoot.SetInteger(key.c_str(), value);
    }

    void SetNumber(const msvc8::string& key, const float value) override
    {
      mRoot.SetNumber(key.c_str(), value);
    }

    void SetHex(const msvc8::string& key, const std::uint32_t value) override
    {
      mRoot.SetString(key.c_str(), gpg::STR_Printf("0x%X", value).c_str());
    }

    void SetString(const msvc8::string& key, const msvc8::string& value) override
    {
      mRoot.SetString(key.c_str(), value.c_str());
    }

    void SetStringArr(const msvc8::string& key, const msvc8::vector<msvc8::string>& values) override
    {
      LuaPlus::LuaObject table(&mState);
      table.AssignNewTable(&mState, 0, 0);

      const msvc8::string* const begin = values.begin();
      const msvc8::string* const end = values.end();
      if (begin != nullptr && end != nullptr) {
        int luaIndex = 1;
        for (const msvc8::string* it = begin; it != end; ++it) {
          table.SetString(luaIndex, it->c_str());
          ++luaIndex;
        }
      }

      mRoot.SetObject(key.c_str(), table);
    }

    bool LookupCurrentOption(msvc8::string* const outOption, const msvc8::string& key) override
    {
      if (outOption == nullptr) {
        return false;
      }

      const msvc8::string fallback;
      *outOption = GetString(key, fallback);
      return !outOption->empty();
    }

    bool LookupKey(msvc8::string* const outOption, const msvc8::string& key) override
    {
      return LookupCurrentOption(outOption, key);
    }

    void* GetPreferenceTable() override
    {
      return &mRoot;
    }

    void SetObject(const msvc8::string& key, void* const valueObject) override
    {
      mRoot.SetInteger(
        key.c_str(),
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(valueObject))
      );
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
  const bool isAlphaDrive =
    (driveLetter >= 'A' && driveLetter <= 'Z') || (driveLetter >= 'a' && driveLetter <= 'z');
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
    const msvc8::string message =
      gpg::STR_Printf("Unable to launch %s:\n%s", effectiveMapName, exception.what() != nullptr ? exception.what() : "");
    WIN_OkBox("Ack!", message.c_str());
    return false;
  } catch (...) {
    const msvc8::string message = gpg::STR_Printf("Unable to launch %s:\nunknown error", effectiveMapName);
    WIN_OkBox("Ack!", message.c_str());
    return false;
  }
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
bool moho::DISK_SetupDataAndSearchPaths(
  const msvc8::string& dataPathScriptName, const std::filesystem::path& launchDir
)
{
  const std::filesystem::path absoluteLaunchDirectory = MakeAbsolutePath(
    launchDir.empty() ? std::filesystem::current_path() : launchDir
  );
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

  std::lock_guard<std::mutex> lock(gDiskPathStateLock);
  gLaunchDirectory = absoluteLaunchDirectory;
  gDataPathScriptFile = absoluteScriptPath;
  return true;
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

  const HWND mainWindowHandle = sMainWindow != nullptr
                                  ? reinterpret_cast<HWND>(static_cast<std::uintptr_t>(sMainWindow->GetHandle()))
                                  : nullptr;
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

  mVolume = static_cast<float>(
    static_cast<std::int32_t>(kLuaMovieVolumeDbFloor - (clampedVolume * kLuaMovieVolumeDbFloor))
  );
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
    OptionsSetCustomData(state, kPrimaryAdapterKey, optionRoot, defaultValue);
    return;
  }

  AddOptionStateString(
    state,
    &statesTable,
    1,
    "<LOC _Command_Line_Override>",
    kCommandLineOverrideModeKey
  );

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignString(state, kCommandLineOverrideModeKey);
  OptionsSetCustomData(state, kPrimaryAdapterKey, optionRoot, defaultValue);
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
    AddOptionStateString(
      state,
      &statesTable,
      1,
      "<LOC _Command_Line_Override>",
      kCommandLineOverrideModeKey
    );

    LuaPlus::LuaObject defaultValue(state);
    defaultValue.AssignString(state, kCommandLineOverrideModeKey);
    OptionsSetCustomData(state, kSecondaryAdapterKey, optionRoot, defaultValue);
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
  OptionsSetCustomData(state, kSecondaryAdapterKey, optionRoot, defaultValue);
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
  if (gGraphicsFidelitySupported > 1) {
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
  OptionsSetCustomData(state, kFidelityPresetsKey, optionRoot, defaultValue);
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

  if (gGraphicsFidelitySupported > 1) {
    AddOptionStateInteger(state, &statesTable, 3, "<LOC _High>", 2);
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 1.0);
  OptionsSetCustomData(state, kFidelityKey, optionRoot, defaultValue);
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

  if (gShadowFidelitySupported > 2) {
    AddOptionStateInteger(state, &statesTable, 4, "<LOC _High>", 3);
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 1.0);
  OptionsSetCustomData(state, kShadowQualityKey, optionRoot, defaultValue);
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
          state,
          &statesTable,
          nextStateIndex,
          it->label.c_str(),
          static_cast<std::int32_t>(packedMode)
        );
        ++nextStateIndex;
      }
    }
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 0.0);
  OptionsSetCustomData(state, kAntiAliasingKey, optionRoot, defaultValue);
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
