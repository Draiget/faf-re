#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/audio/SofdecRuntime.h"

struct lua_State;
struct IDirectSoundBuffer;

namespace gpg::gal
{
  class DeviceContext;
} // namespace gpg::gal

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CMovieManager;
  class CScrLuaInitForm;
  class CScrLuaInitFormSet;
  enum ESpecialFileType : std::int32_t;

  struct CfgAliasSet
  {
    const char* const* values = nullptr;
    std::size_t count = 0;
  };

  [[nodiscard]] const CfgAliasSet& CFG_GetOptionPrefixes();
  [[nodiscard]] const CfgAliasSet& CFG_GetAdapterOptionAliases();
  [[nodiscard]] const CfgAliasSet& CFG_GetMaximizeOptionAliases();
  [[nodiscard]] const CfgAliasSet& CFG_GetDualOptionAliases();
  [[nodiscard]] const CfgAliasSet& CFG_GetHeadOptionAliases();
  [[nodiscard]] const CfgAliasSet& CFG_GetFullscreenOptionAliases();
  [[nodiscard]] const CfgAliasSet& CFG_GetWindowedOptionAliases();

  /**
   * Address: 0x008CFF00 (FUN_008CFF00)
   *
   * What it does:
   * Tries prefixed command-line options formed as:
   * `prefix + leftAlias + rightAlias`.
   */
  bool CFG_GetArgOptionComposedAliases(
    const CfgAliasSet& leftAliases,
    const CfgAliasSet& rightAliases,
    std::uint32_t requiredArgCount,
    msvc8::vector<msvc8::string>* outArgs
  );

  /**
   * Address family:
   * - 0x008D00E0 (FUN_008D00E0)
   * - 0x008D0260 (FUN_008D0260)
   * - 0x008D02D0 (FUN_008D02D0)
   *
   * What it does:
   * Tries prefixed command-line options formed as:
   * `prefix + alias`.
   */
  bool CFG_GetArgOptionAliases(
    const CfgAliasSet& aliases, std::uint32_t requiredArgCount, msvc8::vector<msvc8::string>* outArgs
  );

  /**
   * Address: 0x008D00E0 (FUN_008D00E0)
   *
   * What it does:
   * Returns true when any maximize alias is present.
   */
  [[nodiscard]] bool CFG_HasMaximizeOption();

  struct ResolutionTriple
  {
    std::int32_t width = 0;
    std::int32_t height = 0;
    std::int32_t framesPerSecond = 0;
  };

  static_assert(sizeof(ResolutionTriple) == 0xC, "ResolutionTriple size must be 0xC");

  /**
   * Address: 0x008CD6C0 (Resolution::Resolution parser body)
   *
   * What it does:
   * Parses `width,height,fps` CSV text into three integer lanes.
   */
  bool CFG_ParseResolutionTriple(gpg::StrArg value, ResolutionTriple* outResolution);

  /**
   * VFTABLE ownership:
   * - `USER_GetPreferences()` returns `IUserPrefs*` in startup/log-window paths.
   *
   * Evidence:
   * - `CUserPrefs` vtable emit (`dumps/emit/moho/misc/CUserPrefs.h`)
   * - `FUN_008C7540..FUN_008C8610` (`CUserPrefs` method family)
   * - `FUN_004F4270` (`WWinLogWindow` ctor) callsites:
   *   - slot 3 (`GetBoolean`)
   *   - slot 4 (`GetInteger`)
   *   - slot 7 (`GetString`)
   */
  class IUserPrefs
  {
  public:
    virtual msvc8::string* GetStr1() = 0;
    virtual msvc8::string* GetStr2() = 0;
    virtual void RefreshCurrentProfile() = 0;
    virtual bool GetBoolean(const msvc8::string& key, bool fallback) = 0;
    virtual std::int32_t GetInteger(const msvc8::string& key, std::int32_t fallback) = 0;
    virtual float GetNumber(const msvc8::string& key, float fallback) = 0;
    virtual std::uint32_t GetHex(const msvc8::string& key, std::uint32_t fallback) = 0;
    virtual msvc8::string GetString(const msvc8::string& key, const msvc8::string& fallback) = 0;
    virtual msvc8::vector<msvc8::string> GetStringArr(
      const msvc8::string& key,
      const msvc8::vector<msvc8::string>& fallback
    ) = 0;
    virtual void SetBoolean(const msvc8::string& key, bool value) = 0;
    virtual void SetInteger(const msvc8::string& key, std::int32_t value) = 0;
    virtual void SetNumber(const msvc8::string& key, float value) = 0;
    virtual void SetHex(const msvc8::string& key, std::uint32_t value) = 0;
    virtual void SetString(const msvc8::string& key, const msvc8::string& value) = 0;
    virtual void SetStringArr(const msvc8::string& key, const msvc8::vector<msvc8::string>& values) = 0;
    virtual bool LookupCurrentOption(msvc8::string* outOption, const msvc8::string& key) = 0;
    virtual bool LookupKey(msvc8::string* outOption, const msvc8::string& key) = 0;
    /**
     * Address: 0x008C8020 (FUN_008C8020, Moho::CUserPrefs::GetPreferenceTable)
     *
     * IDA signature:
     * LuaPlus::LuaObject *__thiscall GetPreferenceTable(CUserPrefs *this, LuaPlus::LuaObject *retBuf);
     *
     * What it does:
     * Returns a copy of the root preference table Lua object.
     */
    virtual LuaPlus::LuaObject GetPreferenceTable() = 0;
    virtual void SetObject(const msvc8::string& key, void* valueObject) = 0;
    virtual void* GetState() = 0;
  };

  static_assert(sizeof(IUserPrefs) == 0x4, "IUserPrefs size must be 0x4");

  /**
   * Address: 0x008C9110
   * Mangled: ?USER_GetPreferences@Moho@@YAPAVIUserPrefs@1@XZ
   */
  [[nodiscard]] IUserPrefs* USER_GetPreferences();

  /**
   * Address: 0x008C68A0
   * Mangled: ?OPTIONS_GetInt@Moho@@YAHVStrArg@gpg@@@Z
   */
  [[nodiscard]] std::int32_t OPTIONS_GetInt(gpg::StrArg key);

  /**
   * Address: 0x008C6AB0
   * Mangled:
   * ?OPTIONS_GetString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@@Z
   */
  [[nodiscard]] msvc8::string OPTIONS_GetString(gpg::StrArg key);

  /**
   * Address: 0x008C6BF0 (FUN_008C6BF0)
   * Mangled: ?OPTIONS_GetBool@Moho@@YA_NVStrArg@gpg@@@Z
   *
   * What it does:
   * Reads one options value from `/lua/user/prefs.lua:GetOption` and returns it
   * as a boolean lane.
   */
  [[nodiscard]] bool OPTIONS_GetBool(gpg::StrArg key);

  /**
   * Address: 0x008C6CF0 (FUN_008C6CF0)
   * Mangled: ?OPTIONS_Apply@Moho@@YAXXZ
   *
   * What it does:
   * Invokes `/lua/options/optionslogic.lua:Apply()` and keeps execution
   * alive on Lua bridge failures.
   */
  void OPTIONS_Apply();

  /**
   * Address: 0x008C6DC0 (FUN_008C6DC0)
   * Mangled: ?OPTIONS_SetCustomData@Moho@@YAXVStrArg@gpg@@ABVLuaObject@LuaPlus@@1@Z
   *
   * What it does:
   * Invokes `/lua/options/optionslogic.lua:SetCustomData` for one option key
   * using `(customData, defaultValue)` Lua object lanes.
   */
  void OPTIONS_SetCustomData(
    gpg::StrArg key,
    const LuaPlus::LuaObject& customData,
    const LuaPlus::LuaObject& defaultValue
  );

  /**
   * Address: 0x008C6EC0 (FUN_008C6EC0)
   * Mangled: ?OPTIONS_CreateInitialProfileIfNeeded@Moho@@YAXVStrArg@gpg@@@Z
   *
   * What it does:
   * Executes `/lua/user/prefs.lua` profile bootstrap:
   * - `ProfilesExist()`
   * - `CreateProfile(profileName)` when profiles are missing.
   */
  void OPTIONS_CreateInitialProfileIfNeeded(gpg::StrArg profileName);

  /**
   * Address: 0x008C7040 (FUN_008C7040)
   * Mangled:
   * ?OPTIONS_GetCurrentProfileName@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
   *
   * What it does:
   * Invokes `/lua/user/prefs.lua:GetCurrentProfile()` and returns the
   * profile `Name` field.
   */
  [[nodiscard]] msvc8::string OPTIONS_GetCurrentProfileName();

  /**
   * Address: 0x008D21E0 (FUN_008D21E0)
   *
   * What it does:
   * Publishes primary-adapter option states for the startup options UI.
   */
  void SetupPrimaryAdapterSettings();

  /**
   * Address: 0x008D26D0 (FUN_008D26D0)
   *
   * What it does:
   * Publishes secondary-adapter option states and honors command-line override
   * lanes used by startup device bootstrap.
   */
  void SetupSecondaryAdapterSettings(bool adapterNotCommandLineOverridden);

  /**
   * Address: 0x008D2B90 (FUN_008D2B90)
   *
   * What it does:
   * Publishes fidelity-preset option states (`Low/Medium/High/Ultra/Custom`).
   */
  void CreateFidelityPresets();

  /**
   * Address: 0x008D2E20 (FUN_008D2E20)
   *
   * What it does:
   * Publishes base fidelity option states (`Low/Medium[/High]`).
   */
  void SetupFidelitySettings();

  /**
   * Address: 0x008D3010 (FUN_008D3010)
   *
   * What it does:
   * Publishes shadow-quality option states.
   */
  void SetupShadowQualitySettings();

  /**
   * Address: 0x008D3250 (FUN_008D3250)
   *
   * What it does:
   * Publishes anti-aliasing option states from active head sample modes.
   */
  void SetupAntiAliasingSettings();

  /**
   * Address: 0x00874C20 (FUN_00874C20)
   *
   * What it does:
   * Recreates the process-global movie manager singleton lane.
   */
  void SetupBasicMovieManager();

  /**
   * Address: 0x00874D30 (FUN_00874D30, `Moho::MOV_GetDuration`)
   *
   * What it does:
   * Resolves one movie path through the mounted VFS, reads SFD header metadata,
   * and returns movie duration in seconds (`0.0f` on missing/invalid data).
   */
  [[nodiscard]] float MOV_GetDuration(gpg::StrArg sourcePath);

  /**
   * Address: 0x008E6B60 (func_CreateDeviceD3D)
   *
   * What it does:
   * Builds backend device singleton from the supplied gal context.
   */
  void CreateDeviceD3D(gpg::gal::DeviceContext* context);

  /**
   * Address context:
   * - `FUN_00874C20` allocates this runtime owner with `operator new(0x0C)`.
   */
  class CMovieManager
  {
  public:
    /**
     * Address: 0x00874AF0 (FUN_00874AF0, `Moho::CMovieManager::CMovieManager`)
     *
     * What it does:
     * Initializes movie-audio runtime ownership lanes and Sofdec middleware setup.
     */
    CMovieManager();

    /**
     * Address: 0x00875290 (FUN_00875290, `Moho::CMovieManager::Destroy`)
     *
     * What it does:
     * Shuts down movie Sofdec middleware, releases COM interfaces, and destroys this instance.
     */
    void Destroy();

    /**
     * Address context:
     * - `cfunc_SetMovieVolumeL` (`0x00875020`) writes this transformed value.
     *
     * What it does:
     * Applies recovered Lua movie-volume clamp/conversion into `mVolume`.
     */
    void SetVolumeFromLua(float requestedVolume);

    /**
     * Address context:
     * - `cfunc_GetMovieVolumeL` (`0x00875180`) reads this lane.
     *
     * What it does:
     * Returns the stored movie-volume lane for Lua callback paths.
     */
    [[nodiscard]] float GetVolumeForLua() const;

  private:
    /**
     * Address: 0x00874990 (FUN_00874990, `func_CreateDirectSound`)
     *
     * What it does:
     * Creates DirectSound runtime state and primary sound buffer unless
     * `/nosound` startup flag is present.
     */
    void CreateDirectSound();

    void ReleaseDirectSoundObjects();

    IDirectSound* mDirectSound = nullptr;
    IDirectSoundBuffer* mPrimarySoundBuffer = nullptr;
    float mVolume = 0.0f;
  };

  static_assert(sizeof(CMovieManager) == 0xC, "CMovieManager size must be 0xC");

  // Address-backed startup window defaults from FA globals.
  extern std::int32_t wnd_MinCmdLineWidth;
  extern std::int32_t wnd_MinCmdLineHeight;
  extern std::int32_t wnd_MinDragWidth;
  extern std::int32_t wnd_MinDragHeight;
  extern std::int32_t wnd_DefaultCreateWidth;
  extern std::int32_t wnd_DefaultCreateHeight;

  // Address-backed startup flags from FA globals.
  extern std::int32_t graphics_Fidelity;
  extern std::int32_t graphics_FidelitySupported;
  extern std::int32_t shadow_Fidelity;
  extern std::int32_t shadow_FidelitySupported;
  extern bool d3d_UseRefRast;
  extern bool d3d_ForceSoftwareVP;
  extern bool d3d_NoPureDevice;
  extern bool d3d_ForceDirect3DDebugEnabled;
  extern bool d3d_WindowsCursor;
  extern std::uint32_t sAdapterNotCLOverridden;
  extern bool sDeviceLock;

  struct SAppIdentity
  {
    msvc8::string mCompanyName;
    msvc8::string mProductName;
    msvc8::string mPreferencePrefix;
    std::uint32_t mGameIdParts[4]{};
  };
  static_assert(sizeof(SAppIdentity) == 0x64, "SAppIdentity size must be 0x64");

  /**
   * Address context:
   * - 0x008CE0A0 constructor path initializes these global identity lanes.
   *
   * What it does:
   * Writes fixed app/company/pref strings and 4-word savegame id tuple.
   */
  void APP_InitializeIdentity();

  [[nodiscard]] const msvc8::string& APP_GetCompanyName();
  [[nodiscard]] const msvc8::string& APP_GetProductName();
  [[nodiscard]] const msvc8::string& APP_GetPreferencePrefix();

  /**
   * Returns one dword from the fixed savegame id tuple:
   * index 0..3 => `game_id_1..4`.
   */
  [[nodiscard]] std::uint32_t APP_GetGameIdPart(std::size_t index);

  /**
   * Address: 0x009071C0 (FUN_009071C0)
   *
   * What it does:
   * Stores the AQtime instrumentation mode byte used by startup gates.
   */
  void APP_SetAqtimeInstrumentationMode(std::uint8_t mode);

  /**
   * Address context: reads/writes against the same global lane as 0x009071C0.
   *
   * What it does:
   * Returns the current AQtime instrumentation mode byte.
   */
  [[nodiscard]] std::uint8_t APP_GetAqtimeInstrumentationMode();

  /**
   * Address: 0x0041B560 (FUN_0041B560)
   * Mangled:
   * ?CFG_GetArgOption@Moho@@YA_NVStrArg@gpg@@IPAV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@@Z
   *
   * What it does:
   * Finds a command-line option case-insensitively and optionally copies
   * its following positional arguments.
   */
  bool CFG_GetArgOption(gpg::StrArg option, std::uint32_t requiredArgCount, msvc8::vector<msvc8::string>* outArgs);

  /**
   * Address: 0x0041B690 (FUN_0041B690)
   * Mangled:
   * ?CFG_GetArgs@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
   *
   * What it does:
   * Concatenates process command-line arguments (argv[1..]) with single-space
   * separators and trims the trailing separator.
   */
  msvc8::string CFG_GetArgs();

  /**
   * Address: 0x0041B790 (FUN_0041B790, cfunc_GetCommandLineArg)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` to `LuaPlus::LuaState*` and
   * forwards to `cfunc_GetCommandLineArgL`.
   */
  int cfunc_GetCommandLineArg(lua_State* luaContext);

  /**
   * Address: 0x0041B810 (FUN_0041B810, cfunc_GetCommandLineArgL)
   *
   * What it does:
   * Resolves one command-line option with requested argument count; returns a
   * Lua array table on success or `false` when the option is missing.
   */
  int cfunc_GetCommandLineArgL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0041B7B0 (FUN_0041B7B0, func_GetCommandLineArg_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder for `GetCommandLineArg`.
   */
  [[nodiscard]] CScrLuaInitForm* func_GetCommandLineArg_LuaFuncDef();

  /**
   * Address: 0x0041BA20 (FUN_0041BA20, cfunc_HasCommandLineArg)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` to `LuaPlus::LuaState*` and
   * forwards to `cfunc_HasCommandLineArgL`.
   */
  int cfunc_HasCommandLineArg(lua_State* luaContext);

  /**
   * Address: 0x0041BAA0 (FUN_0041BAA0, cfunc_HasCommandLineArgL)
   *
   * What it does:
   * Returns Lua boolean indicating whether a command-line option is present.
   */
  int cfunc_HasCommandLineArgL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0041BA40 (FUN_0041BA40, func_HasCommandLineArg_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder for `HasCommandLineArg`.
   */
  [[nodiscard]] CScrLuaInitForm* func_HasCommandLineArg_LuaFuncDef();

  /**
   * Address: 0x00BC3800 (FUN_00BC3800, register_GetCommandLineArg_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_GetCommandLineArg_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_GetCommandLineArg_LuaFuncDef();

  /**
   * Address: 0x00BC3810 (FUN_00BC3810, register_HasCommandLineArg_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_HasCommandLineArg_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_HasCommandLineArg_LuaFuncDef();

  /**
   * Address: 0x004D68C0 (FUN_004D68C0, cfunc_SHGetFolderPath)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_SHGetFolderPathL`.
   */
  int cfunc_SHGetFolderPath(lua_State* luaContext);

  /**
   * Address: 0x004D6940 (FUN_004D6940, cfunc_SHGetFolderPathL)
   *
   * What it does:
   * Resolves one unsafe-path id string into a CSIDL value and pushes the
   * resolved folder path with trailing `\\`.
   */
  int cfunc_SHGetFolderPathL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004D68E0 (FUN_004D68E0, func_SHGetFolderPath_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for `SHGetFolderPath`
   * in the unsafe init set.
   */
  [[nodiscard]] CScrLuaInitForm* func_SHGetFolderPath_LuaFuncDef();

  /**
   * Address: 0x00BC63D0 (FUN_00BC63D0, register_coreInitFormSet)
   *
   * What it does:
   * Links the process-global core Lua init-form set at the head of
   * `CScrLuaInitFormSet::sSets` and returns the previous head.
   */
  [[nodiscard]] CScrLuaInitFormSet* register_coreInitFormSet();

  /**
   * Address: 0x00BC63F0 (FUN_00BC63F0, register_userInitFormSet)
   *
   * What it does:
   * Links the process-global user Lua init-form set at the head of
   * `CScrLuaInitFormSet::sSets` and returns the previous head.
   */
  [[nodiscard]] CScrLuaInitFormSet* register_userInitFormSet();

  /**
   * Address: 0x00BC66E0 (FUN_00BC66E0, register_unsafeInitFormSet)
   *
   * What it does:
   * Links the process-global unsafe Lua init-form set at the head of
   * `CScrLuaInitFormSet::sSets` and returns the previous head.
   */
  [[nodiscard]] CScrLuaInitFormSet* register_unsafeInitFormSet();

  /**
   * Address: 0x00BC6700 (FUN_00BC6700, register_SHGetFolderPath_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_SHGetFolderPath_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_SHGetFolderPath_LuaFuncDef();

  /**
   * Address: 0x00780A70 (FUN_00780A70, cfunc_GetTextureDimensions)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_GetTextureDimensionsL`.
   */
  int cfunc_GetTextureDimensions(lua_State* luaContext);

  /**
   * Address: 0x00780AF0 (FUN_00780AF0, cfunc_GetTextureDimensionsL)
   *
   * What it does:
   * Loads one texture by filename and optional border and returns
   * `(width, height)` on success, otherwise `nil`.
   */
  int cfunc_GetTextureDimensionsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00780A90 (FUN_00780A90, func_GetTextureDimensions_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for
   * `GetTextureDimensions` in the user init set.
   */
  [[nodiscard]] CScrLuaInitForm* func_GetTextureDimensions_LuaFuncDef();

  /**
   * Address: 0x00874FA0 (FUN_00874FA0, cfunc_SetMovieVolume)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_SetMovieVolumeL`.
   */
  int cfunc_SetMovieVolume(lua_State* luaContext);

  /**
   * Address: 0x00874FC0 (FUN_00874FC0, func_SetMovieVolume_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for `SetMovieVolume`.
   */
  [[nodiscard]] CScrLuaInitForm* func_SetMovieVolume_LuaFuncDef();

  /**
   * Address: 0x00875020 (FUN_00875020, cfunc_SetMovieVolumeL)
   *
   * What it does:
   * Reads one volume argument, validates numeric type, and applies movie-volume
   * transform through process-global movie manager lane when present.
   */
  int cfunc_SetMovieVolumeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00875100 (FUN_00875100, cfunc_GetMovieVolume)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_GetMovieVolumeL`.
   */
  int cfunc_GetMovieVolume(lua_State* luaContext);

  /**
   * Address: 0x00875120 (FUN_00875120, func_GetMovieVolume_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for `GetMovieVolume`.
   */
  [[nodiscard]] CScrLuaInitForm* func_GetMovieVolume_LuaFuncDef();

  /**
   * Address: 0x00875180 (FUN_00875180, cfunc_GetMovieVolumeL)
   *
   * What it does:
   * Validates zero-argument call shape and returns current movie-volume lane
   * (fallback `1.0` when no movie manager exists).
   */
  int cfunc_GetMovieVolumeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008753A0 (FUN_008753A0, cfunc_GetMovieDuration)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_GetMovieDurationL`.
   */
  int cfunc_GetMovieDuration(lua_State* luaContext);

  /**
   * Address: 0x008753C0 (FUN_008753C0, func_GetMovieDuration_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for `GetMovieDuration`
   * in the core init set.
   */
  [[nodiscard]] CScrLuaInitForm* func_GetMovieDuration_LuaFuncDef();

  /**
   * Address: 0x00875420 (FUN_00875420, cfunc_GetMovieDurationL)
   *
   * What it does:
   * Reads one movie path argument, validates string type, and returns
   * duration in seconds through `MOV_GetDuration`.
   */
  int cfunc_GetMovieDurationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C9490 (FUN_008C9490, cfunc_GetOptions)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_GetOptionsL`.
   */
  int cfunc_GetOptions(lua_State* luaContext);

  /**
   * Address: 0x008C9660 (FUN_008C9660, cfunc_GetAntiAliasingOptions)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_GetAntiAliasingOptionsL`.
   */
  int cfunc_GetAntiAliasingOptions(lua_State* luaContext);

  /**
   * Address: 0x008C9680 (FUN_008C9680, func_GetAntiAliasingOptions_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for
   * `GetAntiAliasingOptions` in the user init set.
   */
  [[nodiscard]] CScrLuaInitForm* func_GetAntiAliasingOptions_LuaFuncDef();

  /**
   * Address: 0x008C96E0 (FUN_008C96E0, cfunc_GetAntiAliasingOptionsL)
   *
   * What it does:
   * Builds and returns a Lua table of supported anti-aliasing modes for the
   * primary render head.
   */
  int cfunc_GetAntiAliasingOptionsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C94B0 (FUN_008C94B0, func_GetOptions_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for `GetOptions` in the
   * user init set.
   */
  [[nodiscard]] CScrLuaInitForm* func_GetOptions_LuaFuncDef();

  /**
   * Address: 0x008C9510 (FUN_008C9510, cfunc_GetOptionsL)
   *
   * What it does:
   * Reads one options key string and returns the current user preference value
   * as a Lua object.
   */
  int cfunc_GetOptionsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C9850 (FUN_008C9850, cfunc_GetPreference)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_GetPreferenceL`.
   */
  int cfunc_GetPreference(lua_State* luaContext);

  /**
   * Address: 0x008C98D0 (FUN_008C98D0, cfunc_GetPreferenceL)
   *
   * What it does:
   * Resolves one preference key and returns its Lua object value, with optional
   * default object fallback from arg #2.
   */
  int cfunc_GetPreferenceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C9870 (FUN_008C9870, func_GetPreference_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for `GetPreference`
   * in the user init set.
   */
  [[nodiscard]] CScrLuaInitForm* func_GetPreference_LuaFuncDef();

  /**
   * Address: 0x008C9A50 (FUN_008C9A50, cfunc_SetPreference)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_SetPreferenceL`.
   */
  int cfunc_SetPreference(lua_State* luaContext);

  /**
   * Address: 0x008C9AD0 (FUN_008C9AD0, cfunc_SetPreferenceL)
   *
   * What it does:
   * Writes one user preference object lane from `(key, value)` Lua args.
   */
  int cfunc_SetPreferenceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C9A70 (FUN_008C9A70, func_SetPreference_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for `SetPreference`
   * in the user init set.
   */
  [[nodiscard]] CScrLuaInitForm* func_SetPreference_LuaFuncDef();

  /**
   * Address: 0x008C9C30 (FUN_008C9C30, cfunc_SavePreferences)
   *
   * What it does:
   * Validates zero-argument call shape and persists current user preferences.
   */
  int cfunc_SavePreferences(lua_State* luaContext);

  /**
   * Address: 0x008C9C70 (FUN_008C9C70, func_SavePreferences_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for `SavePreferences`
   * in the user init set.
   */
  [[nodiscard]] CScrLuaInitForm* func_SavePreferences_LuaFuncDef();

  /**
   * Address: 0x008CAEA0 (FUN_008CAEA0, cfunc_DebugFacilitiesEnabled)
   *
   * What it does:
   * Lua C callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_DebugFacilitiesEnabledL`.
   */
  int cfunc_DebugFacilitiesEnabled(lua_State* luaContext);

  /**
   * Address: 0x008CAF20 (FUN_008CAF20, cfunc_DebugFacilitiesEnabledL)
   *
   * What it does:
   * Validates zero-argument call shape and returns whether debug facilities
   * are enabled.
   */
  int cfunc_DebugFacilitiesEnabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008CAEC0 (FUN_008CAEC0, func_DebugFacilitiesEnabled_LuaFuncDef)
   *
   * What it does:
   * Returns/creates the global Lua binder definition for
   * `DebugFacilitiesEnabled` in the user init set.
   */
  [[nodiscard]] CScrLuaInitForm* func_DebugFacilitiesEnabled_LuaFuncDef();

  /**
   * Address: 0x00BE8BF0 (FUN_00BE8BF0, register_SavePreferences_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_SavePreferences_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_SavePreferences_LuaFuncDef();

  /**
   * Address: 0x00BE8CE0 (FUN_00BE8CE0, j_func_DebugFacilitiesEnabled_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_DebugFacilitiesEnabled_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* j_func_DebugFacilitiesEnabled_LuaFuncDef();

  /**
   * Address: 0x00410760 (FUN_00410760)
   * Mangled:
   * ?FILE_SuggestedExt@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@0@Z
   *
   * What it does:
   * Returns `inputPath` unchanged when it already has an extension, otherwise
   * appends `suggestedExt` (with leading `.` normalization).
   */
  msvc8::string FILE_SuggestedExt(gpg::StrArg inputPath, gpg::StrArg suggestedExt);

  /**
   * Address: 0x0040FA50 (FUN_0040FA50)
   *
   * What it does:
   * Returns true when path starts with a single local-root slash (`/`) and is
   * not UNC-style.
   */
  [[nodiscard]] bool FILE_IsLocal(gpg::StrArg filename);

  /**
   * Address: 0x0040FDC0 (FUN_0040FDC0)
   *
   * What it does:
   * Returns true when `filename` starts with `<alpha>:` drive prefix.
   */
  [[nodiscard]] bool FILE_HasDrive(gpg::StrArg filename);

  /**
   * Address: 0x0040FEB0 (FUN_0040FEB0)
   *
   * What it does:
   * Returns true when `filename` starts with UNC prefix (`//` or `\\`).
   */
  [[nodiscard]] bool FILE_HasUNC(gpg::StrArg filename);

  /**
   * Address: 0x0040FD60 (FUN_0040FD60)
   *
   * What it does:
   * Returns true when `filename` is an absolute path.
   */
  [[nodiscard]] bool FILE_IsAbsolute(gpg::StrArg filename);

  /**
   * Address: 0x0040FFC0 (FUN_0040FFC0, Moho::FILE_MakeAbsolute)
   *
   * What it does:
   * Combines one resource path (`dir`) with one base directory path
   * (`filename`) while preserving drive/UNC semantics and emitting the same
   * validation failures as the original startup helper.
   */
  [[nodiscard]] msvc8::string FILE_MakeAbsolute(gpg::StrArg dir, gpg::StrArg filename);

  /**
   * Address: 0x00457D40 (FUN_00457D40, sub_457D40)
   *
   * std::string const &,std::string const &,std::string *
   *
   * What it does:
   * Resolves one path token against one base path and stores the resolved text
   * in `outPath`.
   */
  msvc8::string* PATH_ResolveAgainstBase(
    const msvc8::string& path, const msvc8::string& basePath, msvc8::string* outPath
  );

  /**
   * Address: 0x0040FAF0 (FUN_0040FAF0)
   *
   * What it does:
   * Parses alphabetical drive prefix and returns 1..26 (`A/a` -> 1), throwing
   * `XFileError` on malformed input.
   */
  [[nodiscard]] int GetDrive(gpg::StrArg filename);

  /**
   * Address: 0x00410650 (FUN_00410650)
   *
   * What it does:
   * Returns pointer to extension text in the final path segment, or null when
   * no extension exists.
   */
  [[nodiscard]] const char* FILE_Ext(gpg::StrArg filename);

  /**
   * Address: 0x004108B0 (FUN_004108B0)
   *
   * What it does:
   * Forces a filename extension by removing existing extension and appending
   * `.` + `ext` when provided.
   */
  [[nodiscard]] msvc8::string FILE_ForcedExt(gpg::StrArg filename, gpg::StrArg ext);

  /**
   * Address: 0x00410A10 (FUN_00410A10)
   * Mangled:
   * ?FILE_DirPrefix@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@_N@Z
   *
   * What it does:
   * Normalizes slashes and returns directory prefix text for `filename`.
   */
  [[nodiscard]] msvc8::string FILE_DirPrefix(gpg::StrArg filename, bool unusedFlag = false);

  /**
   * Address: 0x00410C60 (FUN_00410C60)
   * Mangled:
   * ?FILE_Dir@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@@Z
   *
   * What it does:
   * Builds a normalized system-directory path for `filename`.
   */
  [[nodiscard]] msvc8::string FILE_Dir(gpg::StrArg filename);

  /**
   * Address: 0x004111C0 (FUN_004111C0)
   * Mangled:
   * ?FILE_Base@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@_N@Z
   *
   * What it does:
   * Returns final path segment text, optionally stripping extension.
   */
  [[nodiscard]] msvc8::string FILE_Base(gpg::StrArg filename, bool stripExtension);

  /**
   * Address: 0x004115A0 (FUN_004115A0)
   * Mangled:
   * ?FILE_CollapsePath@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@PA_N@Z
   *
   * What it does:
   * Collapses `.`/`..` path segments and normalizes separators.
   */
  [[nodiscard]] msvc8::string FILE_CollapsePath(gpg::StrArg filename, bool* success);

  /**
   * Address: 0x0046AE90 (FUN_0046AE90, sub_46AE90)
   * Address: 0x0046B4B0 (FUN_0046B4B0, sub_46B4B0)
   * Address: 0x0046BA60 (FUN_0046BA60, sub_46BA60)
   *
   * What it does:
   * Compares two canonical path strings by reverse component order (leaf
   * token first, then parent tokens toward root).
   */
  [[nodiscard]] bool PATH_ReverseComponentLess(const msvc8::string& lhs, const msvc8::string& rhs);

  /**
   * Address: 0x00411A20 (FUN_00411A20)
   * Mangled:
   * ?FILE_GetErrorFromErrno@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@H@Z
   *
   * What it does:
   * Maps CRT errno values used by FILE_* path helpers to user-facing text.
   */
  [[nodiscard]] msvc8::string FILE_GetErrorFromErrno(int err);

  /**
   * Address: 0x008C9D10 (FUN_008C9D10)
   *
   * What it does:
   * Returns local-appdata path suffix:
   * `<LocalAppData>\\Gas Powered Games\\Supreme Commander Forged Alliance`.
   */
  [[nodiscard]] msvc8::string USER_GetAppLocalDataDir();

  /**
   * Address: 0x008C9F90 (FUN_008C9F90)
   *
   * What it does:
   * Returns `<USER_GetAppLocalDataDir()> + "\\cache"` and ensures the
   * cache directory exists.
   */
  [[nodiscard]] msvc8::string USER_GetAppCacheDir();

  /**
   * Address: 0x008CA070 (FUN_008CA070)
   *
   * What it does:
   * Deletes cache directory contents using silent shell delete flags.
   */
  void USER_PurgeAppCacheDir();

  /**
   * Address: 0x008C9E20 (FUN_008C9E20)
   *
   * What it does:
   * Returns user documents path suffix:
   * `<Documents>\\My Games\\<Company>\\<Product>\\`.
   */
  [[nodiscard]] msvc8::string USER_GetAppDocDir();

  /**
   * Address: 0x008CAF70 (FUN_008CAF70, func_OpenDocuments)
   *
   * What it does:
   * Ensures the user document tree exists by creating:
   * `<Documents>\\My Games\\<Company>\\<Product>`.
   */
  void USER_EnsureDocumentDirectories();

  /**
   * Address: 0x008CA2D0 (FUN_008CA2D0)
   *
   * What it does:
   * Returns `<USER_GetAppDocDir()> + "savegames\\"`.
   */
  [[nodiscard]] msvc8::string USER_GetSaveGameDir();

  /**
   * Address: 0x008CA380 (FUN_008CA380)
   *
   * What it does:
   * Returns `<APP preference prefix> + "SaveGame"`.
   */
  [[nodiscard]] msvc8::string USER_GetSaveGameExt();

  /**
   * Address: 0x008CA3A0 (FUN_008CA3A0)
   *
   * What it does:
   * Returns `<USER_GetAppDocDir()> + "replays\\"`.
   */
  [[nodiscard]] msvc8::string USER_GetReplayDir();

  /**
   * Address: 0x008CA450 (FUN_008CA450)
   *
   * What it does:
   * Returns `<APP preference prefix> + "Replay"`.
   */
  [[nodiscard]] msvc8::string USER_GetReplayExt();

  /**
   * Address: 0x008CA470 (FUN_008CA470)
   *
   * What it does:
   * Returns `<APP preference prefix> + "CampaignSave"`.
   */
  [[nodiscard]] msvc8::string USER_GetCampaignSaveExt();

  /**
   * Address: 0x008CA490 (FUN_008CA490)
   *
   * What it does:
   * Returns `<USER_GetAppDocDir()> + "screenshots\\"` and ensures the
   * screenshot directory exists.
   */
  [[nodiscard]] msvc8::string USER_GetScreenshotDir();

  /**
   * Address: 0x008CA650 (FUN_008CA650, USER_GetSpecialFiles)
   *
   * ESpecialFileType, std::string &, std::string &,
   * std::map<std::string,std::vector<std::string>> &
   *
   * What it does:
   * Resolves special-file directory/extension lanes and groups matching
   * profile-scoped filenames by profile name.
   */
  void USER_GetSpecialFiles(
    ESpecialFileType specialFileType,
    std::string& outDirectory,
    std::string& outExtension,
    std::map<std::string, std::vector<std::string>>& outFilesByProfile
  );

  /**
   * Address: 0x008CAE20 (FUN_008CAE20)
   *
   * What it does:
   * Returns startup preference toggle `debug.enable_debug_facilities`.
   */
  [[nodiscard]] bool USER_DebugFacilitiesEnabled();

  /**
   * Address: 0x008C91A0 (FUN_008C91A0, USER_SavePreferences)
   *
   * What it does:
   * Serializes current user preferences to disk and atomically replaces
   * the persisted prefs file with the newly written snapshot.
   */
  void USER_SavePreferences();

  /**
   * Address: 0x008CE220 (FUN_008CE220, func_FindMapScenario)
   *
   * What it does:
   * Returns `/maps/<map>/<map>_scenario.lua` for plain map tokens, or the
   * input unchanged when it is already a path-like scenario reference.
   */
  [[nodiscard]] msvc8::string FindMapScenario(gpg::StrArg mapName);

  /**
   * Address: 0x008CE2A0 (FUN_008CE2A0, func_StartCommandLineSession)
   *
   * What it does:
   * Imports `/lua/SinglePlayerLaunch.lua` and invokes
   * `StartCommandLineSession(mapName, isPerfTest)`.
   */
  [[nodiscard]] bool StartCommandLineSession(gpg::StrArg mapName, bool isPerfTest);

  /**
   * Address: 0x0045A670 (FUN_0045A670)
   * Mangled:
   * ?DISK_GetLaunchDir@Moho@@YA?AV?$basic_path@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@Upath_traits@filesystem@boost@@@filesystem@boost@@XZ
   *
   * What it does:
   * Resolves executable launch directory from `argv[0]`.
   */
  [[nodiscard]] std::filesystem::path DISK_GetLaunchDir();

  /**
   * Address: 0x0045A770 (FUN_0045A770)
   * Mangled: ?DISK_CreateFolder@Moho@@YA_NVStrArg@gpg@@@Z
   *
   * What it does:
   * Attempts to create one folder and stores wait-handle error text on failure.
   */
  [[nodiscard]] bool DISK_CreateFolder(gpg::StrArg sourcePath);

  /**
   * Address: 0x0045A7A0 (FUN_0045A7A0)
   * Mangled: ?DISK_Recycle@Moho@@YAXVStrArg@gpg@@@Z
   *
   * What it does:
   * Moves one file/folder path into shell recycle bin without UI prompts.
   */
  void DISK_Recycle(gpg::StrArg sourcePath);

  /**
   * Address: 0x00459DE0 (FUN_00459DE0)
   * Mangled:
   * ?DISK_SetupDataAndSearchPaths@Moho@@YA_NV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV?$basic_path@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@Upath_traits@filesystem@boost@@@filesystem@boost@@@Z
   *
   * What it does:
   * Validates and records launch-directory/data-script bootstrap paths for
   * early startup services.
   */
  bool DISK_SetupDataAndSearchPaths(const msvc8::string& dataPathScriptName, const std::filesystem::path& launchDir);

  /**
   * Address: 0x00459DA0 (FUN_00459DA0, ?DISK_GetAllowedProtocols@Moho@@YA?AV?$vector@V?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@V?$allocator@V?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@2@@std@@XZ)
   *
   * What it does:
   * Returns a copy of startup-configured URL protocols allowed by the disk layer.
   */
  [[nodiscard]] std::vector<std::wstring> DISK_GetAllowedProtocols();

  [[nodiscard]] std::filesystem::path DISK_GetLaunchDirectory();
  [[nodiscard]] std::filesystem::path DISK_GetDataPathScriptFile();
} // namespace moho
