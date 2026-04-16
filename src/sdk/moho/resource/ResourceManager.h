#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "boost/condition.h"
#include "boost/recursive_mutex.h"
#include "boost/shared_ptr.h"
#include "boost/thread.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/misc/CDiskWatch.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CResourceWatcher;
  class PrefetchData;
  struct PrefetchRequestRuntime;
  class ResourceFactoryBase;

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
     * Address: 0x004A9B90 (FUN_004A9B90)
     *
     * What it does:
     * Overrides disk-watch filtering and accepts every incoming event.
     */
    bool FilterEvent(const SDiskWatchEvent& event) override;

    /**
     * Address: 0x004AB780 (FUN_004AB780, ?OnDiskWatchEvent@ResourceManager@Moho@@UAEXABUSDiskWatchEvent@2@@Z)
     *
     * What it does:
     * Invalidates cached request/prefetch lanes for one changed path and
     * notifies attached resource watchers.
     */
    void OnDiskWatchEvent(const SDiskWatchEvent& event) override;

    /**
       * Address: 0x004AA090 (FUN_004AA090)
     *
     * What it does:
     * Marks factory bootstrap as active and drains pending startup hooks.
     */
    void ActivatePendingFactories();

    /**
     * Address: 0x004A9F30 (FUN_004A9F30)
     *
     * What it does:
     * Registers one factory into the pending lane before activation, then
     * stores it in the active keyed registry once bootstrap is live.
     */
    void AttachFactory(ResourceFactoryBase* factory);

    /**
     * Address: 0x004A9FC0 (FUN_004A9FC0)
     *
     * What it does:
     * Removes one factory from both the pending bootstrap lane and the active
     * keyed registry.
     */
    void DetachFactory(ResourceFactoryBase* factory);

    /**
     * Address: 0x004AB600 (FUN_004AB600)
     *
     * What it does:
     * Returns one active factory registration lane by registration-key lookup.
     */
    [[nodiscard]] ResourceFactoryBase* FindFactoryByRegistrationKey(unsigned int registrationKey);

    /**
     * Address: 0x004AB620 (FUN_004AB620, func_ManageWatchedResources)
     *
     * What it does:
     * Flushes and destroys watched-resource nodes for one watcher object while
     * preserving lock/inline-storage reset semantics.
     */
    void ManageWatchedResources(CResourceWatcher* watcher);

    /**
     * Address: 0x004AA160 (FUN_004AA160, sub_4AA160)
     *
     * What it does:
     * Clears the worker-running flag, wakes worker wait conditions, then joins
     * and releases the worker thread object.
     */
    void ShutdownBackgroundThread();

    /**
     * Address: 0x004AAC20 (FUN_004AAC20, Moho::ResourceManager::CreatePrefetchData)
     *
     * boost::shared_ptr<Moho::PrefetchData> &,const char *,gpg::RType *
     *
     * What it does:
     * Canonicalizes one prefetch path, resolves/creates one prefetch request
     * runtime lane, and returns the shared prefetch payload handle.
     */
    boost::shared_ptr<PrefetchData>* CreatePrefetchData(
      boost::shared_ptr<PrefetchData>* outPrefetchData, const char* path, gpg::RType* resourceType
    );

    /**
     * Address: 0x004AA220 (FUN_004AA220, Moho::ResourceManager::GetResource)
     *
     * boost::weak_ptr<gpg::RObject> &,const char *,Moho::CResourceWatcher *,gpg::RType *
     *
     * What it does:
     * Canonicalizes one resource path, wires optional watcher ownership, then
     * resolves one weak resource handle from the runtime request lane.
     */
    boost::SharedCountPair* GetResource(
      boost::SharedCountPair* outResource,
      const char* path,
      CResourceWatcher* resourceWatcher,
      gpg::RType* resourceType
    );

    [[nodiscard]] bool AreFactoriesActivated() const;

  private:
    /**
     * Address: 0x004AB180 (FUN_004AB180, func_PrefetchThread)
     *
     * What it does:
     * Worker-thread loop that drains queued prefetch payloads and runs factory
     * preload dispatch while coordinating with load/idle conditions.
     */
    void PrefetchThreadMain();

    /**
     * Address: 0x004AA690 (FUN_004AA690)
     *
     * What it does:
     * Waits for in-flight work, dispatches one factory load/finish lane, then
     * publishes the resolved weak pair for one request runtime entry.
     */
    boost::SharedCountPair* ResolvePendingResourceRequest(
      boost::SharedCountPair* outResource,
      PrefetchRequestRuntime& request,
      boost::recursive_mutex::scoped_lock& workerLock
    );

    using PendingFactoryRegistrations = std::vector<ResourceFactoryBase*>;
    using ActiveFactoryRegistrations = std::map<unsigned int, ResourceFactoryBase*>;

    mutable boost::recursive_mutex mFactoryMutex;
    bool mFactoriesActivated = false;
    PendingFactoryRegistrations mPendingFactoryRegistrations;
    ActiveFactoryRegistrations mActiveFactoryRegistrationsByKey;
    boost::recursive_mutex mWorkerLock;
    bool mWorkerRunning = false;
    boost::condition mWorkerWakeCondition;
    boost::condition mWorkerIdleCondition;
    boost::thread* mWorkerThread = nullptr;
    std::uint32_t mActiveLoadCount = 0;
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
   * Address: 0x004ABEE0 (FUN_004ABEE0, ?RES_GetResource@Moho@@...)
   *
   * What it does:
   * Ensures singleton initialization and forwards one resource lookup into
   * `ResourceManager::GetResource`.
   */
  boost::SharedCountPair* RES_GetResource(
    boost::SharedCountPair* outResource,
    const char* path,
    CResourceWatcher* resourceWatcher,
    gpg::RType* resourceType
  );

  template <class TResource>
  boost::weak_ptr<TResource>* RES_GetResource(
    boost::weak_ptr<TResource>* outResource,
    const char* path,
    CResourceWatcher* resourceWatcher,
    gpg::RType* resourceType
  )
  {
    (void)RES_GetResource(
      reinterpret_cast<boost::SharedCountPair*>(outResource),
      path,
      resourceWatcher,
      resourceType
    );
    return outResource;
  }

  /**
    * Alias of FUN_004AA090 (non-canonical helper lane).
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
