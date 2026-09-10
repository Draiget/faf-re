#pragma once

#include <chrono>
#include <cstdint>

#include "legacy/containers/Map.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/PrefetchRuntime.h"

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
  class ResourceFactoryBase;

  /**
   * Address: 0x004AD8B0 (FUN_004AD8B0)
   *
   * What it does:
   * Orders prefetch requests by case-insensitive resource id, then by the
   * resource-type pointer -- `_stricmp` over the two `RResId` strings, then an
   * unsigned compare of the two `gpg::RType*` slots at `+0x1C`.
   */
  struct PrefetchRequestLess
  {
    [[nodiscard]] bool operator()(
      const PrefetchRequestRuntime& lhs,
      const PrefetchRequestRuntime& rhs
    ) const noexcept
    {
      const int compare = _stricmp(lhs.mResourceId.name.c_str(), rhs.mResourceId.name.c_str());
      return (compare < 0) || (compare == 0 && lhs.mResourceType < rhs.mResourceType);
    }
  };

  // The node is 0x50 with the colour byte at +0x4C, so the value is the whole
  // 0x40 `PrefetchRequestRuntime`: the request *is* the element, keyed on the
  // id and type stored inside it (0x004AD790 reads the candidate's string
  // through value+0x04 / value+0x18 and its type through value+0x1C).
  using PrefetchRequestSet = msvc8::set<PrefetchRequestRuntime, PrefetchRequestLess>;
  static_assert(sizeof(PrefetchRequestSet) == 0x0C, "PrefetchRequestSet size must be 0x0C");

  /**
   * What it does:
   * The prefetch worker's weak-pair ring: a block table plus a read cursor and
   * a queued count. `PrefetchThreadMain` reaches it as `[this+0x7C]`
   * (`0x004AB34A`) and reads the block count through `[this+0x84]`.
   */
  struct PrefetchWeakPairRingQueueRuntime
  {
    std::uint32_t mReserved00 = 0U;                       // +0x00
    boost::SharedCountPair** mChunkPairBlocks = nullptr;   // +0x04
    std::uint32_t mChunkCount = 0U;                        // +0x08
    std::uint32_t mReadCursor = 0U;                        // +0x0C
    std::uint32_t mQueuedCount = 0U;                       // +0x10
  };

  static_assert(
    offsetof(PrefetchWeakPairRingQueueRuntime, mChunkPairBlocks) == 0x04,
    "PrefetchWeakPairRingQueueRuntime::mChunkPairBlocks offset must be 0x04"
  );
  static_assert(
    offsetof(PrefetchWeakPairRingQueueRuntime, mChunkCount) == 0x08,
    "PrefetchWeakPairRingQueueRuntime::mChunkCount offset must be 0x08"
  );
  static_assert(
    offsetof(PrefetchWeakPairRingQueueRuntime, mReadCursor) == 0x0C,
    "PrefetchWeakPairRingQueueRuntime::mReadCursor offset must be 0x0C"
  );
  static_assert(
    offsetof(PrefetchWeakPairRingQueueRuntime, mQueuedCount) == 0x10,
    "PrefetchWeakPairRingQueueRuntime::mQueuedCount offset must be 0x10"
  );
  static_assert(
    sizeof(PrefetchWeakPairRingQueueRuntime) == 0x14,
    "PrefetchWeakPairRingQueueRuntime size must be 0x14"
  );

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
     * Address: 0x00461DC0 (FUN_00461DC0, ?OnEvent@CDiskWatchListener@Moho@@EAEXABUSDiskWatchEvent@2@@Z)
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

    using PendingFactoryRegistrations = msvc8::vector<ResourceFactoryBase*, false>;
    using ActiveFactoryRegistrations = msvc8::map<std::uint32_t, ResourceFactoryBase*>;

    // Shipped layout, read out of the constructor (0x004A9DD0, writing into
    // `Moho::sResourceManager` at 0x01104160) and out of the methods that reach
    // these fields directly:
    //
    //   +0x00  CDiskWatchListener base
    //   +0x30  boost::recursive_mutex -- ONE lock. 0x004A9F30, 0x004AA090,
    //          0x004AA160, 0x004AA220 and 0x004AB780 all lock this same
    //          object, and the constructor runs exactly one
    //          `recursive_mutex::recursive_mutex`, so there is no separate
    //          factory lock and worker lock.
    //   +0x40  mPendingFactoryRegistrations -- {first, last, end}, no proxy
    //          word, so the no-debug-proxy vector.
    //   +0x4C  mActiveFactoryRegistrationsByKey (0x004AB600: `add ecx, 4Ch`,
    //          then the mapped value at node+0x10).
    //   +0x58  mFactoriesActivated -- ONE byte. 0x004AA090 sets it, 0x004AA160
    //          clears it, and `PrefetchThreadMain`'s loop condition
    //          (0x004AB1E4) reads it: the worker runs exactly while the
    //          factories are up.
    //   +0x5C  mActiveLoadCount (0x004AA690: `add [edi+5Ch], 1` on entry and
    //          `add [esi+5Ch], -1` on the way out).
    //   +0x60  the last-resolve timestamp -- a 0x10-byte `boost::xtime` that
    //          `xtime_get` fills (0x004A9EE5, 0x004AAB40).
    //   +0x70  mPrefetchRequests (0x004AB780: `add edi, 70h`).
    //   +0x7C  mPrefetchPayloadQueue (0x004AB34A: `lea ebp, [ebx+7Ch]`), 0x14
    //          bytes, ending exactly where the first condition begins.
    //   +0x90  mWorkerWakeCondition, +0xA8 mWorkerIdleCondition (both notified
    //          from 0x004AA160).
    //   +0xC0  mWorkerThread (0x004AA160 joins and frees it).
    //
    // No offset asserts here: the boost members come from the modern vendored
    // boost, whose `recursive_mutex` and `condition` are not the 2007 sizes, so
    // an assert would pin this build's layout rather than the shipped one. The
    // timestamp stays a `steady_clock::time_point` for the same reason.
    mutable boost::recursive_mutex mLock;
    PendingFactoryRegistrations mPendingFactoryRegistrations;
    ActiveFactoryRegistrations mActiveFactoryRegistrationsByKey;
    bool mFactoriesActivated = false;
    std::uint32_t mActiveLoadCount = 0;
    std::chrono::steady_clock::time_point mLastResolveTime{};
    PrefetchRequestSet mPrefetchRequests;
    PrefetchWeakPairRingQueueRuntime mPrefetchPayloadQueue{};
    boost::condition mWorkerWakeCondition;
    boost::condition mWorkerIdleCondition;
    boost::thread* mWorkerThread = nullptr;
  };

  /**
   * Address: 0x004A9BA0 (FUN_004A9BA0, func_EnsureResourceManager)
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
