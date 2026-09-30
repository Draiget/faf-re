#include "moho/resource/ResourceManager.h"

#include <algorithm>

#include <Windows.h>

#include "boost/bind.hpp"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/CResourceWatcher.h"
#include "moho/resource/ResourceFactory.h"
#include "moho/serialization/PrefetchHandleBase.h"

namespace moho
{
  bool res_EnablePrefetching = true;     // 0x00F58027
  int res_PrefetcherActivityDelay = 3;   // 0x00F58DA4, seconds
  int res_AfterPrefetchDelay = 250;      // 0x00F58DA8, milliseconds
  bool res_SpewLoadSpam = false;         // 0x010A6394
} // namespace moho

namespace
{
  // `boost::TIME_UTC`. Spelled by value: C11's `TIME_UTC` macro (also 1) is
  // back in force once boost/thread/xtime.hpp restores it, and hides boost's
  // enumerator everywhere outside that header.
  constexpr int kClockUtc = 1;

  moho::ResourceManager* sResourceManager = nullptr; // 0x010A6398
  boost::once_flag sResourceManagerOnce = BOOST_ONCE_INIT; // 0x010A639C

  /**
   * Address: 0x00BC5AC0 (FUN_00BC5AC0, dynamic initializer for `gTConVar_res_SpewLoadSpam`)
   * Address: 0x00BF04F0 (FUN_00BF04F0, dynamic atexit destructor for `gTConVar_res_SpewLoadSpam`)
   */
  moho::TConVar<bool> gTConVar_res_SpewLoadSpam(
    "res_SpewLoadSpam", "If true, spew spam with each resource load.", &moho::res_SpewLoadSpam
  );

  /**
   * Address: 0x00BC5B00 (FUN_00BC5B00, dynamic initializer for `gTConVar_res_EnablePrefetching`)
   * Address: 0x00BF0520 (FUN_00BF0520, dynamic atexit destructor for `gTConVar_res_EnablePrefetching`)
   */
  moho::TConVar<bool> gTConVar_res_EnablePrefetching(
    "res_EnablePrefetching", "If true, enable prefetching.", &moho::res_EnablePrefetching
  );

  /**
   * Address: 0x00BC5B40 (FUN_00BC5B40, dynamic initializer for `gTConVar_res_PrefetcherActivityDelay`)
   * Address: 0x00BF0550 (FUN_00BF0550, dynamic atexit destructor for `gTConVar_res_PrefetcherActivityDelay`)
   */
  moho::TConVar<int> gTConVar_res_PrefetcherActivityDelay(
    "res_PrefetcherActivityDelay",
    "Number of seconds to delay prefetching after there is foreground disk activity.",
    &moho::res_PrefetcherActivityDelay
  );

  /**
   * Address: 0x00BC5B80 (FUN_00BC5B80, dynamic initializer for `gTConVar_res_AfterPrefetchDelay`)
   * Address: 0x00BF0580 (FUN_00BF0580, dynamic atexit destructor for `gTConVar_res_AfterPrefetchDelay`)
   */
  moho::TConVar<int> gTConVar_res_AfterPrefetchDelay(
    "res_AfterPrefetchDelay",
    "Number of milliseconds to nap after prefetching something.  So the prefetcher thread doesn't bog us down too much.",
    &moho::res_AfterPrefetchDelay
  );

  /**
   * MSVC8's `std::set<T>::iterator` was mutable -- the const-element rule came
   * with C++11 -- and the shipped code updates a record in place through it.
   * `msvc8::set` follows the modern rule, so those writes go through this one
   * accessor; the two ordering fields are never touched.
   */
  [[nodiscard]] moho::ResourceRecord& Record(const moho::ResourceRecordSet::iterator it) noexcept
  {
    return const_cast<moho::ResourceRecord&>(*it);
  }

  /**
   * `/dir/file` names a file in the mounted file system; anything else not
   * starting with a single `/` (a relative name, or `//host/...`) is used as
   * given.
   */
  [[nodiscard]] bool IsLiteralName(const char* const path) noexcept
  {
    return path != nullptr && path[0] != '\0' && (path[0] != '/' || path[1] == '/');
  }

  /**
   * Where the mounted file system puts `path`; empty when it has no such file.
   */
  [[nodiscard]] msvc8::string FindMountedFile(const char* const path)
  {
    msvc8::string found;
    (void)moho::FILE_GetWaitHandleSet()->mHandle->FindFile(&found, path, nullptr);
    return found;
  }

  /**
   * Sleeps until `until` with the manager unlocked.
   */
  void SleepUnlocked(boost::recursive_mutex::scoped_lock& lock, const boost::xtime& until)
  {
    lock.unlock();
    boost::thread::sleep(until);
    lock.lock();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004A99C0 (FUN_004A99C0)
   */
  ResourceWatch::ResourceWatch(const gpg::StrArg path, CResourceWatcher* const watcher)
    : mPath(path)
    , mWatcher(watcher)
    , mNotifying(false)
  {}

  /**
   * Address: 0x004A9A40 (FUN_004A9A40)
   */
  ResourceRecord::ResourceRecord(const gpg::StrArg name, const gpg::RType* const type)
    : mId{msvc8::string(name)}
    , mType(type)
    , mLoading(false)
    , mReloadPending(false)
    , mLoadFailed(false)
  {}

  /**
   * Address: 0x004A9AA0 (FUN_004A9AA0)
   */
  ResourceRecord::ResourceRecord(const ResourceRecord& other)
    : mId(other.mId)
    , mType(other.mType)
    , mLoading(false)
    , mReloadPending(false)
    , mLoadFailed(false)
  {}

  /**
   * Address: 0x004A9DD0 (FUN_004A9DD0, ??0ResourceManager@Moho@@QAE@@Z)
   */
  ResourceManager::ResourceManager()
    : CDiskWatchListener(nullptr)
    , mRunning(false)
    , mLoadsInProgress(0)
  {
    boost::xtime_get(&mLastLoadTime, kClockUtc);
    DISK_AddWatchListener(this);
  }

  /**
   * Address: 0x004A9C00 (FUN_004A9C00)
   */
  ResourceManager::~ResourceManager() = default;

  /**
   * Address: 0x004A9B90 (FUN_004A9B90)
   *
   * What it does:
   * Takes every event: the records decide what a path means.
   */
  bool ResourceManager::FilterEvent(const SDiskWatchEvent&)
  {
    return true;
  }

  /**
   * Address: 0x004AB780 (FUN_004AB780, ?OnDiskWatchEvent@ResourceManager@Moho@@UAEXABUSDiskWatchEvent@2@@Z)
   *
   * What it does:
   * Every record for the path, of any type, forgets its resource, its load
   * failure and its prefetched data; a load in progress is told to run again.
   * The watchers are gathered first and told afterwards, still under the lock.
   * A watch whose watcher died during its own callback is freed here, since
   * `DetachWatcher` left it for this loop.
   */
  void ResourceManager::OnDiskWatchEvent(const SDiskWatchEvent& event)
  {
    boost::recursive_mutex::scoped_lock lock(mLock);

    const ResourceRecordSet::iterator first = mRecords.lower_bound(ResourceRecord(event.mPath.c_str(), nullptr));
    const ResourceRecordSet::iterator last = mRecords.upper_bound(
      ResourceRecord(event.mPath.c_str(), reinterpret_cast<const gpg::RType*>(~std::uintptr_t{0}))
    );
    if (first == last) {
      return;
    }

    gpg::fastvector_n<ResourceWatch*, 8> changed;
    for (ResourceRecordSet::iterator it = first; it != last; ++it) {
      ResourceRecord& record = Record(it);
      if (record.mLoading) {
        record.mReloadPending = true;
      }
      record.mResource.reset();
      record.mLoadFailed = false;

      const boost::shared_ptr<PrefetchData> prefetch = boost::LockWeak(record.mPrefetch);
      if (prefetch) {
        prefetch->mPrefetchData.reset();
        prefetch->mResource.reset();
      }

      for (ResourceWatch* const watch : record.mWatches.owners()) {
        watch->mNotifying = true;
        changed.push_back(watch);
      }
    }

    for (ResourceWatch* const watch : changed) {
      if (watch->mWatcher != nullptr) {
        watch->mWatcher->OnResourceChanged(watch->mPath.c_str());
        watch->mNotifying = false;
      } else {
        delete watch;
      }
    }
  }

  /**
   * Address: 0x004AA090 (FUN_004AA090)
   */
  void ResourceManager::ActivatePendingFactories()
  {
    boost::recursive_mutex::scoped_lock lock(mLock);
    mRunning = true;
    for (ResourceFactoryBase* const factory : mPendingFactories) {
      factory->Init();
      mFactories.insert(std::make_pair(factory->mResourceType, factory));
    }
    mPendingFactories.clear();
  }

  /**
   * Address: 0x004A9F30 (FUN_004A9F30, Moho::ResourceManager::AttachFactory)
   *
   * What it does:
   * Before the manager starts, a factory waits in the pending list; after, it
   * registers under its resource type straight away.
   */
  void ResourceManager::AttachFactory(ResourceFactoryBase* const factory)
  {
    boost::recursive_mutex::scoped_lock lock(mLock);
    if (mRunning) {
      mFactories.insert(std::make_pair(factory->mResourceType, factory));
    } else {
      mPendingFactories.push_back(factory);
    }
  }

  /**
   * Address: 0x004A9FC0 (FUN_004A9FC0)
   */
  void ResourceManager::DetachFactory(ResourceFactoryBase* const factory)
  {
    boost::recursive_mutex::scoped_lock lock(mLock);

    const auto registered = mFactories.find(factory->mResourceType);
    if (registered != mFactories.end()) {
      mFactories.erase(registered);
    }

    const auto pending = std::find(mPendingFactories.begin(), mPendingFactories.end(), factory);
    if (pending != mPendingFactories.end()) {
      mPendingFactories.erase(pending);
    }
  }

  /**
   * Address: 0x004AB600 (FUN_004AB600)
   */
  ResourceFactoryBase* ResourceManager::FindFactory(const gpg::RType* const type)
  {
    return mFactories.find(type)->second;
  }

  /**
   * Address: 0x004AB620 (FUN_004AB620, func_ManageWatchedResources)
   */
  void ResourceManager::DetachWatcher(CResourceWatcher* const watcher)
  {
    boost::recursive_mutex::scoped_lock lock(mLock);
    for (ResourceWatch* const watch : watcher->mWatches) {
      if (watch->mNotifying) {
        watch->mWatcher = nullptr;
      } else {
        delete watch;
      }
    }
    watcher->mWatches.ResetStorageToInline();
  }

  /**
   * Address: 0x004AA160 (FUN_004AA160)
   */
  void ResourceManager::ShutdownBackgroundThread()
  {
    boost::recursive_mutex::scoped_lock lock(mLock);
    mRunning = false;
    if (mPrefetchThread) {
      mPrefetchQueued.notify_all();
      mLoadFinished.notify_all();
      lock.unlock();
      mPrefetchThread->join();
      mPrefetchThread.reset();
    }
  }

  /**
   * Address: 0x004AB180 (FUN_004AB180, func_PrefetchThread)
   *
   * What it does:
   * Runs at idle priority. Waits while prefetching is switched off (checking
   * every ten seconds), while the queue is empty, while a foreground load is
   * running, and for `res_PrefetcherActivityDelay` seconds after the last
   * one. Then it takes the front prefetch and, unless the resource is already
   * loaded, loading, or known to fail, preloads it with the manager unlocked.
   * A file change during the preload puts it back at the front of the queue.
   * After each preload it naps `res_AfterPrefetchDelay` milliseconds.
   */
  void ResourceManager::PrefetchThread()
  {
    gpg::SetThreadName(0xFFFFFFFFu, "Prefetcher thread.");
    (void)::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_IDLE);

    boost::recursive_mutex::scoped_lock lock(mLock);
    while (mRunning) {
      if (!res_EnablePrefetching) {
        boost::xtime until;
        boost::xtime_get(&until, kClockUtc);
        until.sec += 10;
        SleepUnlocked(lock, until);
        continue;
      }

      if (mPrefetchQueue.empty()) {
        mPrefetchQueued.wait(lock);
        continue;
      }

      if (mLoadsInProgress != 0) {
        mLoadFinished.wait(lock);
        continue;
      }

      boost::xtime now;
      boost::xtime_get(&now, kClockUtc);
      boost::xtime quietUntil = mLastLoadTime;
      quietUntil.sec += res_PrefetcherActivityDelay;
      if (boost::xtime_cmp(now, quietUntil) < 0) {
        SleepUnlocked(lock, quietUntil);
        continue;
      }

      const boost::shared_ptr<PrefetchData> prefetch = boost::LockWeak(mPrefetchQueue.front());
      mPrefetchQueue.pop_front();
      if (!prefetch) {
        continue;
      }

      ResourceRecord* const record = prefetch->mRecord;
      if (record->mLoading || record->mLoadFailed) {
        continue;
      }

      prefetch->mResource = boost::LockWeak(record->mResource);
      if (prefetch->mResource) {
        continue;
      }

      ResourceFactoryBase* const factory = FindFactory(record->mType);
      record->mLoading = true;
      lock.unlock();
      if (res_SpewLoadSpam) {
        gpg::Debugf("Prefetching %s resource from %s", record->mType->GetName(), record->mId.name.c_str());
      }
      prefetch->mPrefetchData = factory->Preload(record->mId.name.c_str(), factory->mPrefetchType);
      lock.lock();

      if (record->mReloadPending) {
        record->mReloadPending = false;
        mPrefetchQueue.push_front(prefetch);
      }
      mLoadFinished.notify_all();
      record->mLoading = false;

      boost::xtime napUntil;
      boost::xtime_get(&napUntil, kClockUtc);
      napUntil.nsec += res_AfterPrefetchDelay * 1000000;
      while (napUntil.nsec >= 1000000000) {
        napUntil.nsec -= 1000000000;
        ++napUntil.sec;
      }
      SleepUnlocked(lock, napUntil);
    }
  }

  /**
   * Address: 0x004AAC20 (FUN_004AAC20, func_CreatePrefetchData)
   */
  PrefetchHandleBase ResourceManager::PrefetchResource(const gpg::StrArg path, const gpg::RType* const type)
  {
    boost::recursive_mutex::scoped_lock lock(mLock);

    const msvc8::string name = IsLiteralName(path) ? msvc8::string(path) : FindMountedFile(path);
    if (name.empty()) {
      return PrefetchHandleBase();
    }

    ResourceRecord& record = Record(mRecords.insert(ResourceRecord(name.c_str(), type)).first);

    boost::shared_ptr<PrefetchData> prefetch = boost::LockWeak(record.mPrefetch);
    if (!prefetch) {
      prefetch = boost::shared_ptr<PrefetchData>(new PrefetchData(&record));
      record.mPrefetch = prefetch;
    }

    if (const boost::shared_ptr<void> resource = boost::LockWeak(record.mResource); !resource) {
      mPrefetchQueue.push_back(prefetch);
      if (mPrefetchThread) {
        mPrefetchQueued.notify_all();
      } else {
        mPrefetchThread.reset(new boost::thread(boost::bind(&ResourceManager::PrefetchThread, this)));
      }
    }

    PrefetchHandleBase handle(prefetch);
    return handle;
  }

  /**
   * Address: 0x004AA220 (FUN_004AA220, Moho::ResourceManager::GetResource)
   *
   * What it does:
   * A name that is neither literal nor a VFS path (empty, or `/:`...) is
   * rejected with a warning; a VFS path the mounted file system has no file
   * for loads as nothing. A watcher is registered once per record, under the
   * path the caller gave.
   */
  boost::shared_ptr<void> ResourceManager::GetResource(
    const gpg::StrArg path, CResourceWatcher* const watcher, const gpg::RType* const type
  )
  {
    boost::recursive_mutex::scoped_lock lock(mLock);

    msvc8::string name;
    if (IsLiteralName(path)) {
      name = path;
    } else if (path != nullptr && path[0] == '/' && path[1] != ':' && path[1] != '/') {
      name = FindMountedFile(path);
      if (name.empty()) {
        return boost::shared_ptr<void>();
      }
    } else {
      gpg::Warnf("GetResource: Invalid name \"%s\"", path);
      return boost::shared_ptr<void>();
    }

    ResourceRecord& record = Record(mRecords.insert(ResourceRecord(name.c_str(), type)).first);

    if (watcher != nullptr) {
      bool watching = false;
      for (const ResourceWatch* const watch : record.mWatches.owners()) {
        if (watch->mWatcher == watcher) {
          watching = true;
          break;
        }
      }
      if (!watching) {
        ResourceWatch* const watch = new ResourceWatch(path, watcher);
        record.mWatches.push_back(watch);
        watcher->mWatches.push_back(watch);
      }
    }

    return LoadRecord(record, lock);
  }

  /**
   * Address: 0x004AA690 (FUN_004AA690)
   */
  boost::shared_ptr<void> ResourceManager::LoadRecord(ResourceRecord& record, boost::recursive_mutex::scoped_lock& lock)
  {
    const boost::shared_ptr<PrefetchData> prefetch = boost::LockWeak(record.mPrefetch);
    while (record.mLoading) {
      mLoadFinished.wait(lock);
    }

    boost::shared_ptr<void> resource = boost::LockWeak(record.mResource);
    if (resource || record.mLoadFailed) {
      return resource;
    }

    ResourceFactoryBase* const factory = FindFactory(record.mType);
    record.mLoading = true;
    ++mLoadsInProgress;
    while (true) {
      lock.unlock();
      if (prefetch && prefetch->mPrefetchData) {
        if (res_SpewLoadSpam) {
          gpg::Debugf("Finishing %s resource prefetched from %s", record.mType->GetName(), record.mId.name.c_str());
        }
        resource = factory->LoadFrom(record.mId.name.c_str(), record.mType, prefetch->mPrefetchData, factory->mPrefetchType);
        prefetch->mPrefetchData.reset();
      } else {
        if (res_SpewLoadSpam) {
          gpg::Debugf("Loading %s resource from %s", record.mType->GetName(), record.mId.name.c_str());
        }
        resource = factory->Load(record.mId.name.c_str(), record.mType);
      }
      if (prefetch) {
        prefetch->mResource = resource;
      }
      lock.lock();

      if (!record.mReloadPending) {
        break;
      }
      record.mReloadPending = false;
    }

    boost::AssignWeakFromShared(record.mResource, resource);
    if (!resource) {
      record.mLoadFailed = true;
    }
    record.mLoading = false;
    --mLoadsInProgress;
    boost::xtime_get(&mLastLoadTime, kClockUtc);
    mLoadFinished.notify_all();
    return resource;
  }

  /**
   * Address: 0x004A9BA0 (FUN_004A9BA0, func_EnsureResourceManager)
   * Address: 0x00BF05B0 (FUN_00BF05B0, ??1ResourceManager@Moho@@QAE@@Z)
   */
  void RES_EnsureResourceManager()
  {
    static ResourceManager sInstance; // 0x01104160
    sResourceManager = &sInstance;
  }

  ResourceManager* RES_GetResourceManager()
  {
    if (sResourceManager == nullptr) {
      boost::call_once(&RES_EnsureResourceManager, sResourceManagerOnce);
    }
    return sResourceManager;
  }

  /**
   * Address: 0x004ABEE0 (FUN_004ABEE0, ?RES_GetResource@Moho@@YA?AV?$shared_ptr@X@boost@@VStrArg@gpg@@PAVCResourceWatcher@1@PBVRType@5@@Z)
   */
  boost::shared_ptr<void> RES_GetResource(
    const gpg::StrArg path, CResourceWatcher* const resourceWatcher, const gpg::RType* const resourceType
  )
  {
    return RES_GetResourceManager()->GetResource(path, resourceWatcher, resourceType);
  }

  /**
   * Address: 0x004ABE80 (FUN_004ABE80)
   */
  void RES_ActivatePendingFactories()
  {
    RES_GetResourceManager()->ActivatePendingFactories();
  }

  /**
   * Address: 0x004ABEB0 (FUN_004ABEB0, ?RES_Exit@Moho@@YAXXZ)
   */
  void RES_Exit()
  {
    RES_GetResourceManager()->ShutdownBackgroundThread();
  }
} // namespace moho
