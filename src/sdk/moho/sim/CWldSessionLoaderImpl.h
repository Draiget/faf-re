#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"
#include "moho/sim/WldSessionInfo.h"

namespace moho
{
  class IWldSessionLoader
  {
  public:
    /**
     * Address: 0x00885660 tail (??1IWldSessionLoader@Moho@@QAE@@Z)
     */
    virtual ~IWldSessionLoader() = default;

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
    virtual SWldScenarioInfo* GetScenarioInfo(const char* mapName, msvc8::string* gameMods, bool setGameData) = 0;

    /**
     * Address: 0x00885920 (FUN_00885920, ?CreateScenarioInfo@CWldSessionLoaderImpl@Moho@@...)
     */
    virtual SWldScenarioInfo* CreateScenarioInfo(const char* mapName, msvc8::string* gameMods) = 0;

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
     * Address: 0x008855B0 init path (FUN_008855B0, func_GetWldSessionLoader)
     */
    CWldSessionLoaderImpl();

    /**
     * Address: 0x00885660 (FUN_00885660, ??1CWldSessionLoaderImpl@Moho@@QAE@@Z_0)
     */
    ~CWldSessionLoaderImpl() override;

    /**
     * Address: 0x00885890 (FUN_00885890)
     */
    void SetCreated() override;

    /**
     * Address: 0x008858A0 (FUN_008858A0)
     */
    SWldScenarioInfo* GetScenarioInfo(const char* mapName, msvc8::string* gameMods, bool setGameData) override;

    /**
     * Address: 0x00885920 (FUN_00885920)
     */
    SWldScenarioInfo* CreateScenarioInfo(const char* mapName, msvc8::string* gameMods) override;

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
    SWldScenarioInfo* FindOrCreateScenarioInfo(const char* mapName, const msvc8::string& gameMods);

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
   * Address: 0x008855B0 (FUN_008855B0, func_GetWldSessionLoader)
   */
  CWldSessionLoaderImpl* GetWldSessionLoader();
} // namespace moho
