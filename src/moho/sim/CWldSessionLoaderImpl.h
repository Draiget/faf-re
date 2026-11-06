#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"
#include "moho/sim/WldSessionInfo.h"

namespace moho
{
  /**
   * Engine addition (plan WPR.35): whether a loaded session's Lua state gets a copy of the
   * blueprints. A program with no UI turns this off before it loads anything.
   */
  void WLD_SetSessionKeepsBlueprints(bool keep) noexcept;

  /**
   * Engine addition (`wld_EarlyCommandLineSession`): while held, a session's load waits before
   * SessionInit.lua, which needs the UI frames. `WLD_StartPendingSessionLoad` holds it, as that load
   * starts before the app has the frames, and `WLD_DoPreload` lets it go once they exist. Stopping
   * the load also ends the wait.
   */
  void WLD_HoldSessionScripts(bool hold) noexcept;

  /**
   * Engine addition (`wld_EarlyCommandLineSession`): while held, code on a load's threads that needs the
   * graphics device (a unit blueprint's strategic icons, `REntityBlueprint::OnInitBlueprint`) waits in
   * `WLD_WaitForDeviceUse`. `WLD_StartPendingSessionLoad` holds it, as that load starts before the app
   * has created its device, and `CScApp::Init` lets it go once `CreateDevice` returns, either way.
   * Otherwise a unit registered while the device is still being created gets no icons, or on
   * Direct3D 9 its texture call fails ("Invalid call") and the rules with it.
   */
  void WLD_HoldDeviceUse(bool hold) noexcept;

  /** Engine addition: returns once `WLD_HoldDeviceUse` holds nothing (at once on the holding thread). */
  void WLD_WaitForDeviceUse() noexcept;

  class CWldMap;
  class RRuleGameRules;

  /**
   * Engine addition (`wld_StartSimEarly`): the rules and the map of `scenario` once its load has both
   * and has started building the sim's Lua state, so a session can start its sim while the rest of
   * the load (the session's copy of the rules and SessionInit.lua) is still running. False until
   * then, and always for a load with the switch off or without an early map (`wld_LoadMapEarly`).
   * Both stay the scenario's; nothing else in the load changes them.
   */
  [[nodiscard]] bool WLD_GetEarlySimInputs(
    const SWldScenarioInfo* scenario, RRuleGameRules** outRules, CWldMap** outMap
  ) noexcept;

  // Every virtual below except the destructor is pure. IWldSessionLoader's
  // vftable (0x00E49FA4) has all 7 of its slots pointing at _purecall
  // (0x00A82547), so this interface contributes no bodies; the stubs that used
  // to define them in EngineMethodStubs2.cpp were inventing behaviour.
  class IWldSessionLoader
  {
  protected:
    /**
     * Address: 0x00885630 (FUN_00885630)
     *
     * What it does:
     * Installs the base `IWldSessionLoader` vtable lane and returns `this` --
     * `mov <obj>.__vftable, offset ??_7IWldSessionLoader@Moho@@6B@` then
     * `mov eax, <obj>`. That is exactly what MSVC emits for this abstract
     * base's constructor, which the derived loader runs before overwriting
     * the lane with its own vtable. Protected because the class is abstract:
     * only a derived constructor may run it.
     */
    IWldSessionLoader() = default;

  public:
    /**
     * Address: 0x00885450 (FUN_00885450, ??1IWldSessionLoader@Moho@@QAE@@Z)
     *
     * What it does:
     * Restores the base `IWldSessionLoader` vtable lane during base
     * destruction.
     *
     * Not virtual: ??_7IWldSessionLoader@Moho@@6B@ (0x00E49FA4) is seven slots
     * and all seven are `_purecall`, so the interface has no destructor slot;
     * CWldSessionLoaderImpl's table (0x00E49FC4) is seven too and starts at
     * SetCreated. Declaring this virtual added an eighth slot at index 0 and
     * displaced SetCreated, GetScenarioInfo, CreateScenarioInfo, IsLoaded and
     * LoadGameData by one each. Nothing deletes through an
     * `IWldSessionLoader*`.
     */
    ~IWldSessionLoader();

    /**
     * Address: 0x00885890 (FUN_00885890, ?SetCreated@CWldSessionLoaderImpl@Moho@@UAEXXZ)
     */
    virtual void SetCreated() = 0;

    /**
     * Address: 0x008858A0 (FUN_008858A0, ?GetScenarioInfo@CWldSessionLoaderImpl@Moho@@...)
     *
     * What it does:
     * Reorders requested scenario into MRU position and optionally marks it as active game-data source.
     */
    virtual SWldScenarioInfo* GetScenarioInfo(const char* mapName, fa::string* gameMods, bool setGameData) = 0;

    /**
     * Address: 0x00885920 (FUN_00885920, ?CreateScenarioInfo@CWldSessionLoaderImpl@Moho@@...)
     */
    virtual SWldScenarioInfo* CreateScenarioInfo(const char* mapName, fa::string* gameMods) = 0;

    /**
     * Address: 0x00885970 (FUN_00885970, ?IsLoaded@CWldSessionLoaderImpl@Moho@@...)
     */
    virtual bool IsLoaded() = 0;

    /**
     * Address: 0x008859B0 (FUN_008859B0, ?LoadGameData@CWldSessionLoaderImpl@Moho@@...)
     */
    virtual SWldGameData* LoadGameData(SWldGameData* outData) = 0;

    /**
     * Address: 0x00885AD0 (FUN_00885AD0, ?Func5@CWldSessionLoaderImpl@Moho@@...)
     *
     * What it does:
     * Drives background scenario-load scheduling and eviction.
     */
    virtual void Update() = 0;

    /**
     * Address: 0x008856E0 (FUN_008856E0, ?Func6@CWldSessionLoaderImpl@Moho@@...)
     *
     * What it does:
     * Finalizes loader runtime and destroys all scenario entries.
     */
    virtual void Finalize() = 0;
  };

  class CWldSessionLoaderImpl final : public IWldSessionLoader
  {
  public:
    /**
       * Address: 0x008855B0 (FUN_008855B0)
     */
    CWldSessionLoaderImpl();

    /**
     * Address: 0x00885660 (FUN_00885660, ??1CWldSessionLoaderImpl@Moho@@QAE@@Z_0)
     */
    ~CWldSessionLoaderImpl();

    /**
     * Address: 0x00885890 (FUN_00885890)
     */
    void SetCreated() override;

    /**
     * Address: 0x008858A0 (FUN_008858A0)
     */
    SWldScenarioInfo* GetScenarioInfo(const char* mapName, fa::string* gameMods, bool setGameData) override;

    /**
     * Address: 0x00885920 (FUN_00885920)
     */
    SWldScenarioInfo* CreateScenarioInfo(const char* mapName, fa::string* gameMods) override;

    /**
     * Address: 0x00885970 (FUN_00885970)
     */
    bool IsLoaded() override;

    /**
     * Address: 0x008859B0 (FUN_008859B0)
     */
    SWldGameData* LoadGameData(SWldGameData* outData) override;

    /**
     * Address: 0x00885AD0 (FUN_00885AD0)
     */
    void Update() override;

    /**
     * Address: 0x008856E0 (FUN_008856E0)
     */
    void Finalize() override;

  private:
    /**
     * Address: 0x00886200 (FUN_00886200, func_GetScenarioInfo)
     */
    SWldScenarioInfo* FindOrCreateScenarioInfo(const char* mapName, const fa::string& gameMods);

    /**
     * Address: 0x00886170 (FUN_00886170, func_MoveGameData)
     */
    static SWldGameData* MoveGameData(SWldScenarioInfo* source, SWldGameData* outData);

  public:
    bool mCreated;                                      // 0x04
    bool mLoaded;                                       // 0x05
    bool mFinalized;                                    // 0x06
    std::uint8_t mPad07;                                // 0x07
    TDatListItem<SWldScenarioInfo, void> mScenarioHead; // 0x08
    SWldScenarioInfo* mGameData;                        // 0x10
    SWldScenarioInfo* mActiveLoadScenario;              // 0x14
  };

  static_assert(sizeof(CWldSessionLoaderImpl) == 0x18, "CWldSessionLoaderImpl size must be 0x18");
  static_assert(
    offsetof(CWldSessionLoaderImpl, mCreated) == 0x04, "CWldSessionLoaderImpl::mCreated offset must be 0x04"
  );
  static_assert(offsetof(CWldSessionLoaderImpl, mLoaded) == 0x05, "CWldSessionLoaderImpl::mLoaded offset must be 0x05");
  static_assert(
    offsetof(CWldSessionLoaderImpl, mFinalized) == 0x06, "CWldSessionLoaderImpl::mFinalized offset must be 0x06"
  );
  static_assert(
    offsetof(CWldSessionLoaderImpl, mScenarioHead) == 0x08, "CWldSessionLoaderImpl::mScenarioHead offset must be 0x08"
  );
  static_assert(
    offsetof(CWldSessionLoaderImpl, mGameData) == 0x10, "CWldSessionLoaderImpl::mGameData offset must be 0x10"
  );
  static_assert(
    offsetof(CWldSessionLoaderImpl, mActiveLoadScenario) == 0x14,
    "CWldSessionLoaderImpl::mActiveLoadScenario offset must be 0x14"
  );

  /**
    * Alias of FUN_008855B0 (non-canonical helper lane).
   */
  CWldSessionLoaderImpl* GetWldSessionLoader();
} // namespace moho
