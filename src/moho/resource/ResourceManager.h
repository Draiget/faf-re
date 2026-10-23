#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "boost/condition.h"
#include "boost/recursive_mutex.h"
#include "boost/scoped_ptr.h"
#include "boost/shared_ptr.h"
#include "boost/thread.h"
#include "boost/xtime.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/Deque.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/containers/TDatList.h"
#include "moho/misc/CDiskWatch.h"
#include "moho/resource/RResId.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CResourceWatcher;
  class PrefetchData;
  class PrefetchHandleBase;
  class ResourceFactoryBase;

  /**
   * One watcher's interest in one resource. It sits on two lists at once: the
   * record's watch list (this node's links) and the watcher's own vector of
   * watch pointers, which is how either side can find and free it.
   */
  struct ResourceWatch : TDatListItem<ResourceWatch, void>
  {
    /**
     * Address: 0x004A99C0 (FUN_004A99C0)
     */
    ResourceWatch(gpg::StrArg path, CResourceWatcher* watcher);

    msvc8::string mPath;          // +0x08
    CResourceWatcher* mWatcher;   // +0x24 (cleared when the watcher dies mid-notification)
    bool mNotifying;              // +0x28 (set while `OnDiskWatchEvent` holds this node)
  };

  static_assert(offsetof(ResourceWatch, mPath) == 0x08, "ResourceWatch::mPath offset must be 0x08");
  static_assert(offsetof(ResourceWatch, mWatcher) == 0x24, "ResourceWatch::mWatcher offset must be 0x24");
  static_assert(offsetof(ResourceWatch, mNotifying) == 0x28, "ResourceWatch::mNotifying offset must be 0x28");
  static_assert(sizeof(ResourceWatch) == 0x2C, "ResourceWatch size must be 0x2C");

  /**
   * The manager's record for one (path, type) pair: the loaded resource (held
   * weakly, so it unloads once its last user lets go), the prefetch payload,
   * the load state, and who wants to hear about the file changing.
   */
  struct ResourceRecord
  {
    /**
     * Address: 0x004A9A40 (FUN_004A9A40)
     *
     * What it does:
     * A fresh, idle record for `name`; also the probe every lookup builds.
     */
    ResourceRecord(gpg::StrArg name, const gpg::RType* type);

    /**
     * Address: 0x004A9AA0 (FUN_004A9AA0)
     *
     * What it does:
     * Copies only the key; the copy starts idle with an empty watch list. The
     * record set's node builder (0x004AED80) inlines the same body.
     */
    ResourceRecord(const ResourceRecord& other);
    ResourceRecord& operator=(const ResourceRecord&) = delete;

    RResId mId;                                   // +0x00
    const gpg::RType* mType;                      // +0x1C
    bool mLoading;                                // +0x20
    bool mReloadPending;                          // +0x21 (the file changed while it was loading)
    boost::weak_ptr<void> mResource;              // +0x24
    bool mLoadFailed;                             // +0x2C
    boost::weak_ptr<PrefetchData> mPrefetch;      // +0x30
    TDatList<ResourceWatch, void> mWatches;       // +0x38
  };

  static_assert(offsetof(ResourceRecord, mType) == 0x1C, "ResourceRecord::mType offset must be 0x1C");
  static_assert(offsetof(ResourceRecord, mLoading) == 0x20, "ResourceRecord::mLoading offset must be 0x20");
  static_assert(offsetof(ResourceRecord, mReloadPending) == 0x21, "ResourceRecord::mReloadPending offset must be 0x21");
  static_assert(offsetof(ResourceRecord, mResource) == 0x24, "ResourceRecord::mResource offset must be 0x24");
  static_assert(offsetof(ResourceRecord, mLoadFailed) == 0x2C, "ResourceRecord::mLoadFailed offset must be 0x2C");
  static_assert(offsetof(ResourceRecord, mPrefetch) == 0x30, "ResourceRecord::mPrefetch offset must be 0x30");
  static_assert(offsetof(ResourceRecord, mWatches) == 0x38, "ResourceRecord::mWatches offset must be 0x38");
  static_assert(sizeof(ResourceRecord) == 0x40, "ResourceRecord size must be 0x40");

  /**
   * Address: 0x004AD8B0 (FUN_004AD8B0)
   *
   * What it does:
   * Orders records by case-insensitive name, then by the type pointer.
   */
  struct ResourceRecordLess
  {
    [[nodiscard]] bool operator()(const ResourceRecord& lhs, const ResourceRecord& rhs) const noexcept
    {
      const int compare = _stricmp(lhs.mId.name.c_str(), rhs.mId.name.c_str());
      return compare < 0 || (compare == 0 && lhs.mType < rhs.mType);
    }
  };

  // The node is 0x50 with the colour byte at +0x4C: the record itself is the
  // element (0x004AD790 reads the candidate's name through value+0x04/+0x18
  // and its type through value+0x1C).
  using ResourceRecordSet = msvc8::set<ResourceRecord, ResourceRecordLess>;

  /**
   * VFTABLE: 0x00E07604
   * COL: 0x00E62184
   *
   * Loads, caches and hot-reloads every file-backed resource. A resource is
   * held weakly, so it lives exactly as long as someone holds what
   * `GetResource` returned; a prefetch handle holds its resource strongly
   * through its `PrefetchData`, which is what keeps a prefetch set loaded.
   */
  class ResourceManager final : public CDiskWatchListener
  {
  public:
    /**
     * Address: 0x004A9DD0 (FUN_004A9DD0, ??0ResourceManager@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds the empty manager on `Moho::sResourceManager` (0x01104160),
     * stamps the last-load time, and registers with the disk watch.
     */
    ResourceManager();

    /**
     * Address: 0x004A9C00 (FUN_004A9C00)
     *
     * What it does:
     * Member teardown only: the worker thread object is deleted first (the
     * last member), then the conditions, queue, records, factory map and
     * pending list, the lock and the disk-watch listener base.
     */
    ~ResourceManager();

    /**
     * Address: 0x004A9B90 (FUN_004A9B90)
     */
    bool FilterEvent(const SDiskWatchEvent& event) override;

    /**
     * Address: 0x004AB780 (FUN_004AB780, ?OnDiskWatchEvent@ResourceManager@Moho@@UAEXABUSDiskWatchEvent@2@@Z)
     *
     * What it does:
     * Forgets every record for the changed path (whatever its type), drops the
     * prefetched data, and tells each watcher; a load in flight is flagged to
     * run again.
     */
    void OnDiskWatchEvent(const SDiskWatchEvent& event) override;

    /**
     * Address: 0x004AA090 (FUN_004AA090)
     *
     * What it does:
     * Starts the manager: `Init`s every factory attached so far and registers
     * it under its resource type.
     */
    void ActivatePendingFactories();

    /**
     * Address: 0x004A9F30 (FUN_004A9F30, Moho::ResourceManager::AttachFactory)
     */
    void AttachFactory(ResourceFactoryBase* factory);

    /**
     * Address: 0x004A9FC0 (FUN_004A9FC0)
     */
    void DetachFactory(ResourceFactoryBase* factory);

    /**
     * Address: 0x004AB600 (FUN_004AB600)
     *
     * What it does:
     * The factory registered for `type`. There is no miss check: a record is
     * only ever made for a registered type.
     */
    [[nodiscard]] ResourceFactoryBase* FindFactory(const gpg::RType* type);

    /**
     * Address: 0x004AB620 (FUN_004AB620, func_ManageWatchedResources)
     *
     * What it does:
     * `~CResourceWatcher`'s half of the watch bookkeeping: frees each of the
     * watcher's watches, except one `OnDiskWatchEvent` is still holding, which
     * is only detached so the event loop frees it.
     */
    void DetachWatcher(CResourceWatcher* watcher);

    /**
     * Address: 0x004AA160 (FUN_004AA160)
     *
     * What it does:
     * Stops the manager: clears the running flag, wakes the prefetch thread
     * and anything waiting on a load, then joins and deletes the thread.
     */
    void ShutdownBackgroundThread();

    /**
     * Address: 0x004AAC20 (FUN_004AAC20, func_CreatePrefetchData)
     * Address: 0x004AF050 (FUN_004AF050 -- `boost::bind(&ResourceManager::PrefetchThread,
     *   this)`: the `bind_t` built from the member pointer, its `this` adjustment and the
     *   manager; formerly `StoreThreeDwordLanes_004AF050` in moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-30.)
     * Address: 0x004AF070 (FUN_004AF070 -- `boost::function0<void>`'s constructor from that
     *   `bind_t`, the argument `boost::thread` takes; formerly
     *   `InitializePrefetchThreadCallable_004AF070`.)
     * Address: 0x004AF810 (FUN_004AF810 -- its `assign_to`: installs the static invoker/manager
     *   pair (0x010C7B08) on first use and stores the functor in place; formerly
     *   `AssignPrefetchThreadCallableVtable_004AF810`.)
     * Address: 0x004AFB20 (FUN_004AFB20 -- the in-buffer placement of the functor; formerly
     *   `BuildPrefetchThreadCallablePayload_004AFB20`.)
     * Address: 0x004AFDE0 (FUN_004AFDE0 -- the invoker: calls the bound member through its
     *   adjusted `this`; formerly `InvokePrefetchThreadCallable_004AFDE0`.)
     * Address: 0x004AFDF0 (FUN_004AFDF0 -- the functor manager (clone, destroy, type check,
     *   type query); formerly `ManagePrefetchThreadCallable_004AFDF0`.)
     * Address: 0x004AFB00 (FUN_004AFB00 -- an unreferenced register-shape install of that static
     *   pair; formerly `InitializePrefetchThreadCallableVtableGlobal_004AFB00`.)
     * Address: 0x004AFC30 (FUN_004AFC30 -- a second such install; unreferenced.)
     * Address: 0x004AFD20 (FUN_004AFD20 -- a third such install; unreferenced.)
     *
     * What it does:
     * Returns the record's prefetch handle for `path`, creating it when there
     * is none, and queues it for the prefetch thread (starting the thread on
     * first use) unless the resource is already loaded.
     */
    [[nodiscard]] PrefetchHandleBase PrefetchResource(gpg::StrArg path, const gpg::RType* type);

    /**
     * Address: 0x004AA220 (FUN_004AA220, Moho::ResourceManager::GetResource)
     *
     * What it does:
     * Resolves `path` (VFS paths through the mounted file system), finds or
     * makes its record, registers `watcher` for changes to it, and loads it.
     */
    [[nodiscard]] boost::shared_ptr<void> GetResource(gpg::StrArg path, CResourceWatcher* watcher, const gpg::RType* type);

  private:
    /**
     * Address: 0x004AB180 (FUN_004AB180, func_PrefetchThread)
     * Address: 0x004AEF30 (FUN_004AEF30 -- `boost::condition::wait<recursive_mutex::scoped_lock>`,
     *   out of line for the wait on `mLoadFinished` (0x004AB2A3); `lock_error` unless the lock
     *   is held; formerly `WaitConditionWithScopedRecursiveLock_004AEF30` in moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-30.)
     *
     * What it does:
     * The prefetch worker: while the manager runs, takes queued prefetches
     * one at a time and preloads each, keeping out of the way of foreground
     * loads and disk activity.
     */
    void PrefetchThread();

    /**
     * Address: 0x004AA690 (FUN_004AA690)
     *
     * What it does:
     * Waits out a load in progress, then returns the record's live resource,
     * loading it (from prefetched data when there is some) when there is none
     * and it has not failed before. The lock is dropped around the factory
     * call; a file change during the load makes it load again.
     */
    [[nodiscard]] boost::shared_ptr<void> LoadRecord(ResourceRecord& record, boost::recursive_mutex::scoped_lock& lock);

    mutable boost::recursive_mutex mLock;                                     // +0x30
    msvc8::vector<ResourceFactoryBase*> mPendingFactories;                    // +0x3C
    msvc8::map<const gpg::RType*, ResourceFactoryBase*> mFactories;           // +0x4C
    bool mRunning;                                                            // +0x58
    int mLoadsInProgress;                                                     // +0x5C
    boost::xtime mLastLoadTime;                                               // +0x60
    ResourceRecordSet mRecords;                                               // +0x70
    msvc8::deque<boost::weak_ptr<PrefetchData>> mPrefetchQueue;               // +0x7C
    boost::condition mPrefetchQueued;                                         // +0x90
    boost::condition mLoadFinished;                                           // +0xA8
    boost::scoped_ptr<boost::thread> mPrefetchThread;                         // +0xC0
  };

  // The members end at 0xC4; `boost::xtime`'s 64-bit `sec` makes the class
  // 8-aligned, which rounds it to 0xC8.
  static_assert(sizeof(ResourceManager) == 0xC8, "ResourceManager size must be 0xC8");

  /**
   * Address: 0x004A9BA0 (FUN_004A9BA0, func_EnsureResourceManager)
   * Address: 0x00BF05B0 (FUN_00BF05B0, ??1ResourceManager@Moho@@QAE@@Z -- the
   *   function-local instance's `atexit` destructor.)
   *
   * What it does:
   * The `boost::call_once` target that builds the one manager, a function-
   * local static, and publishes it.
   */
  void RES_EnsureResourceManager();

  /**
   * What it does:
   * The manager, built on first use; every `RES_*` entry point and every
   * factory constructor inlines this.
   */
  [[nodiscard]] ResourceManager* RES_GetResourceManager();

  /**
   * Address: 0x004ABEE0 (FUN_004ABEE0, ?RES_GetResource@Moho@@YA?AV?$shared_ptr@X@boost@@VStrArg@gpg@@PAVCResourceWatcher@1@PBVRType@5@@Z)
   *
   * What it does:
   * `ResourceManager::GetResource` on the singleton; the result owns the
   * resource. Callers `static_pointer_cast` it to the type they asked for.
   */
  [[nodiscard]] boost::shared_ptr<void> RES_GetResource(
    gpg::StrArg path, CResourceWatcher* resourceWatcher, const gpg::RType* resourceType
  );

  /**
   * Address: 0x004ABE80 (FUN_004ABE80)
   *
   * What it does:
   * `ResourceManager::ActivatePendingFactories` on the singleton;
   * `IWinApp`'s startup (0x004F1BA0) inlines it.
   */
  void RES_ActivatePendingFactories();

  /**
   * Address: 0x004ABEB0 (FUN_004ABEB0, ?RES_Exit@Moho@@YAXXZ)
   *
   * What it does:
   * `ResourceManager::ShutdownBackgroundThread` on the singleton.
   */
  void RES_Exit();

  extern bool res_EnablePrefetching;
  extern int res_PrefetcherActivityDelay;
  extern int res_AfterPrefetchDelay;
  extern bool res_SpewLoadSpam;
} // namespace moho
