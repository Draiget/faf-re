#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/audio/SofdecRuntime.h"

struct IDirectSoundBuffer;

namespace gpg::gal
{
  class DeviceContext;
} // namespace gpg::gal

namespace moho
{
  class CMovieManager;

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
    virtual void* GetPreferenceTable() = 0;
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
   * Address: 0x008CAE20 (FUN_008CAE20)
   *
   * What it does:
   * Returns startup preference toggle `debug.enable_debug_facilities`.
   */
  [[nodiscard]] bool USER_DebugFacilitiesEnabled();

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
   * Address: 0x00459DE0 (FUN_00459DE0)
   * Mangled:
   * ?DISK_SetupDataAndSearchPaths@Moho@@YA_NV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV?$basic_path@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@Upath_traits@filesystem@boost@@@filesystem@boost@@@Z
   *
   * What it does:
   * Validates and records launch-directory/data-script bootstrap paths for
   * early startup services.
   */
  bool DISK_SetupDataAndSearchPaths(const msvc8::string& dataPathScriptName, const std::filesystem::path& launchDir);

  [[nodiscard]] std::filesystem::path DISK_GetLaunchDirectory();
  [[nodiscard]] std::filesystem::path DISK_GetDataPathScriptFile();
} // namespace moho
