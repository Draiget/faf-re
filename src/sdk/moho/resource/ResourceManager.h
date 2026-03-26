#pragma once

#include <mutex>

#include "boost/condition.h"
#include "boost/recursive_mutex.h"
#include "boost/thread.h"
#include "moho/misc/CDiskWatch.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E07604
   * COL: 0x00E62184
   *
   * Recovered startup-facing resource-manager surface used by the WinMain
   * bootstrap chain.
   */
  class ResourceManager final : public CDiskWatchListener
  {
  public:
    /**
     * Address: 0x004A9DD0 (FUN_004A9DD0)
     * Mangled: ??0ResourceManager@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes singleton resource-manager startup state.
     */
    ResourceManager();

    /**
     * Address: 0x004A9C00 (FUN_004A9C00)
     * Mangled context: teardown helper used by singleton cleanup.
     */
    ~ResourceManager() override;

    /**
     * Address: 0x00461DC0 (?OnEvent@CDiskWatchListener@Moho@@EAEXABUSDiskWatchEvent@2@@Z)
     */
    void OnEvent(const SDiskWatchEvent& event) override;

    /**
     * Address: 0x004AA090 (FUN_004AA090)
     *
     * What it does:
     * Marks factory bootstrap as active and drains pending startup hooks.
     */
    void ActivatePendingFactories();

    /**
     * Address: 0x004AA160 (FUN_004AA160, sub_4AA160)
     *
     * What it does:
     * Clears the worker-running flag, wakes worker wait conditions, then joins
     * and releases the worker thread object.
     */
    void ShutdownBackgroundThread();

    [[nodiscard]] bool AreFactoriesActivated() const;

  private:
    mutable std::mutex mFactoryMutex;
    bool mFactoriesActivated = false;
    boost::recursive_mutex mWorkerLock;
    bool mWorkerRunning = false;
    boost::condition mWorkerWakeCondition;
    boost::condition mWorkerIdleCondition;
    boost::thread* mWorkerThread = nullptr;
  };

  /**
   * Address: 0x004A9BA0 (func_EnsureResourceManager)
   *
   * What it does:
   * Ensures singleton creation for startup paths that require a live manager.
   */
  void RES_EnsureResourceManager();

  [[nodiscard]] ResourceManager* RES_GetResourceManager();

  /**
   * Address: 0x004AA090 (FUN_004AA090)
   *
   * What it does:
   * Executes the startup pending-factory activation phase on the singleton.
   */
  void RES_ActivatePendingFactories();

  /**
   * Address: 0x004ABEB0 (FUN_004ABEB0, ?RES_Exit@Moho@@YAXXZ)
   *
   * What it does:
   * Ensures the singleton exists and runs resource-manager worker shutdown.
   */
  void RES_Exit();
} // namespace moho
