#include "moho/resource/ResourceManager.h"

#include <cstdlib>
#include <mutex>

namespace
{
  std::once_flag sResourceManagerOnce;
  moho::ResourceManager* sPResourceManager = nullptr;

  void DestroyResourceManager()
  {
    delete sPResourceManager;
    sPResourceManager = nullptr;
  }

  void EnsureResourceManagerOnce()
  {
    if (sPResourceManager != nullptr) {
      return;
    }

    sPResourceManager = new moho::ResourceManager();
    std::atexit(&DestroyResourceManager);
  }
} // namespace

/**
 * Address: 0x004A9DD0 (FUN_004A9DD0)
 * Mangled: ??0ResourceManager@Moho@@QAE@@Z
 *
 * What it does:
 * Initializes singleton resource-manager startup state.
 */
moho::ResourceManager::ResourceManager()
  : CDiskWatchListener(nullptr)
  , mFactoryMutex()
  , mFactoriesActivated(false)
  , mWorkerLock()
  , mWorkerRunning(false)
  , mWorkerWakeCondition()
  , mWorkerIdleCondition()
  , mWorkerThread(nullptr)
{
}

/**
 * Address: 0x004A9C00 (FUN_004A9C00)
 * Mangled context: teardown helper used by singleton cleanup.
 */
moho::ResourceManager::~ResourceManager() = default;

/**
 * Address: 0x00461DC0 (?OnEvent@CDiskWatchListener@Moho@@EAEXABUSDiskWatchEvent@2@@Z)
 */
void moho::ResourceManager::OnEvent(const SDiskWatchEvent& event)
{
  CDiskWatchListener::OnEvent(event);
}

/**
 * Address: 0x004AA090 (FUN_004AA090)
 *
 * What it does:
 * Marks factory bootstrap as active and drains pending startup hooks.
 */
void moho::ResourceManager::ActivatePendingFactories()
{
  std::lock_guard<std::mutex> lock(mFactoryMutex);
  mFactoriesActivated = true;
}

/**
 * Address: 0x004AA160 (FUN_004AA160, sub_4AA160)
 *
 * What it does:
 * Clears the worker-running flag, wakes worker wait conditions, then joins
 * and releases the worker thread object.
 */
void moho::ResourceManager::ShutdownBackgroundThread()
{
  boost::thread* workerToDestroy = nullptr;
  {
    boost::recursive_mutex::scoped_lock lock(mWorkerLock);
    mWorkerRunning = false;

    if (mWorkerThread != nullptr) {
      mWorkerWakeCondition.notify_all();
      mWorkerIdleCondition.notify_all();
      workerToDestroy = mWorkerThread;
    }
  }

  if (workerToDestroy != nullptr) {
    try {
      workerToDestroy->join();
    } catch (...) {
      // Boost 1.34 does not expose joinable(); preserve best-effort shutdown.
    }
    mWorkerThread = nullptr;
    delete workerToDestroy;
  }
}

bool moho::ResourceManager::AreFactoriesActivated() const
{
  std::lock_guard<std::mutex> lock(mFactoryMutex);
  return mFactoriesActivated;
}

/**
 * Address: 0x004A9BA0 (func_EnsureResourceManager)
 *
 * What it does:
 * Ensures singleton creation for startup paths that require a live manager.
 */
void moho::RES_EnsureResourceManager()
{
  std::call_once(sResourceManagerOnce, &EnsureResourceManagerOnce);
}

moho::ResourceManager* moho::RES_GetResourceManager()
{
  RES_EnsureResourceManager();
  return sPResourceManager;
}

/**
 * Address: 0x004AA090 (FUN_004AA090)
 *
 * What it does:
 * Executes the startup pending-factory activation phase on the singleton.
 */
void moho::RES_ActivatePendingFactories()
{
  ResourceManager* const manager = RES_GetResourceManager();
  if (manager != nullptr) {
    manager->ActivatePendingFactories();
  }
}

/**
 * Address: 0x004ABEB0 (FUN_004ABEB0, ?RES_Exit@Moho@@YAXXZ)
 *
 * What it does:
 * Ensures the singleton exists and runs resource-manager worker shutdown.
 */
void moho::RES_Exit()
{
  ResourceManager* const manager = RES_GetResourceManager();
  if (manager != nullptr) {
    manager->ShutdownBackgroundThread();
  }
}
