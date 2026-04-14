#include "PathTables.h"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "moho/path/ClusterMap.h"

#ifdef _WIN32
#include <windows.h>
#endif

template <typename T>
struct LegacyVectorStorage
{
  T* mFirst;
  T* mLast;
  T* mEnd;
};

static_assert(sizeof(LegacyVectorStorage<std::uint8_t>) == 0x0C, "LegacyVectorStorage size must be 0x0C");

namespace
{
  struct PathQueueIntrusiveNode
  {
    PathQueueIntrusiveNode* mNext;
    PathQueueIntrusiveNode* mPrev;
  };

  struct PathQueueOwnedNodeLane
  {
    std::uint32_t mFlags;
    PathQueueIntrusiveNode* mSentinel;
    std::uint32_t mCount;
  };

  struct PathQueuePointerTriplet
  {
    void* mFirst;
    void* mLast;
    void* mCapacity;
  };

  struct PathQueueImplBaseRuntime
  {
    PathQueueOwnedNodeLane mOwnedNodes;           // +0x00
    std::uint32_t mOwnedNodeCountMirror;          // +0x0C
    void* mClusterVectorProxy;                    // +0x10
    PathQueuePointerTriplet mClusters;            // +0x14
    std::uint32_t mClusterBucketMask;             // +0x20
    std::uint32_t mClusterBucketMaxIndex;         // +0x24
    std::uint8_t mPad28[0x04];                    // +0x28
    PathQueuePointerTriplet mBucketA;             // +0x2C
    std::uint8_t mPad38[0x04];                    // +0x38
    PathQueuePointerTriplet mBucketB;             // +0x3C
    std::int32_t mBucketBDefaultCost;             // +0x48
    PathQueueIntrusiveNode mTraveler;             // +0x4C
    std::uint32_t mTravelerCount;                 // +0x54
    std::uint8_t mPad58[0x10];                    // +0x58
    PathQueuePointerTriplet mPending;             // +0x68
  };

  static_assert(sizeof(PathQueueIntrusiveNode) == 0x08, "PathQueueIntrusiveNode size must be 0x08");
  static_assert(sizeof(PathQueueOwnedNodeLane) == 0x0C, "PathQueueOwnedNodeLane size must be 0x0C");
  static_assert(sizeof(PathQueuePointerTriplet) == 0x0C, "PathQueuePointerTriplet size must be 0x0C");
  static_assert(sizeof(PathQueueImplBaseRuntime) == 0x74, "PathQueueImplBaseRuntime size must be 0x74");
  static_assert(offsetof(PathQueueImplBaseRuntime, mClusters) == 0x14, "PathQueueImplBaseRuntime::mClusters offset must be 0x14");
  static_assert(offsetof(PathQueueImplBaseRuntime, mBucketA) == 0x2C, "PathQueueImplBaseRuntime::mBucketA offset must be 0x2C");
  static_assert(offsetof(PathQueueImplBaseRuntime, mBucketB) == 0x3C, "PathQueueImplBaseRuntime::mBucketB offset must be 0x3C");
  static_assert(offsetof(PathQueueImplBaseRuntime, mTraveler) == 0x4C, "PathQueueImplBaseRuntime::mTraveler offset must be 0x4C");
  static_assert(offsetof(PathQueueImplBaseRuntime, mPending) == 0x68, "PathQueueImplBaseRuntime::mPending offset must be 0x68");

  [[nodiscard]] PathQueueIntrusiveNode* AllocatePathQueueSentinel()
  {
    auto* const sentinel = static_cast<PathQueueIntrusiveNode*>(::operator new(sizeof(PathQueueIntrusiveNode), std::nothrow));
    if (sentinel == nullptr) {
      return nullptr;
    }

    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    return sentinel;
  }

  void InitializePathQueueImplBase(PathQueueImplBaseRuntime& implBase)
  {
    std::memset(&implBase, 0, sizeof(PathQueueImplBaseRuntime));

    // Address: 0x00767600 (FUN_00767600, sub_767600)
    implBase.mOwnedNodes.mSentinel = AllocatePathQueueSentinel();
    implBase.mClusterBucketMask = 1u;
    implBase.mClusterBucketMaxIndex = 1u;

    // Address: 0x00766CE0 (FUN_00766CE0, sub_766CE0)
    implBase.mBucketBDefaultCost = -1;

    // Address: 0x00765B90 (FUN_00765B90, ??0ImplBase@PathQueue@Moho@@QAE@@Z)
    implBase.mTraveler.mNext = &implBase.mTraveler;
    implBase.mTraveler.mPrev = &implBase.mTraveler;
  }
} // namespace

namespace moho
{
  struct PathQueue::Impl
  {
    std::int32_t mSize;                     // +0x00
    PathQueueIntrusiveNode mHeightSentinel; // +0x04
    PathQueueImplBaseRuntime mBase;         // +0x0C
    std::uint8_t mPad80[0x08];              // +0x80
  };

  static_assert(sizeof(PathQueue::Impl) == 0x88, "PathQueue::Impl size must be 0x88");
  static_assert(offsetof(PathQueue::Impl, mSize) == 0x00, "PathQueue::Impl::mSize offset must be 0x00");
  static_assert(offsetof(PathQueue::Impl, mBase) == 0x0C, "PathQueue::Impl::mBase offset must be 0x0C");

  struct PathTablesImpl
  {
    /**
     * Address: 0x0076BA40 (FUN_0076BA40, ??0Impl@PathTables@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes source/map vector lanes to null range state and constructs
     * the cluster-cache smart pointer lane.
     */
    PathTablesImpl();

    std::int32_t mWidth;                                      // +0x00
    std::int32_t mHeight;                                     // +0x04
    std::int32_t mUnknown08;                                  // +0x08
    LegacyVectorStorage<std::uint8_t> mSources;               // +0x0C
    std::int32_t mUnknown18;                                  // +0x18
    LegacyVectorStorage<moho::ClusterMap*> mMaps;             // +0x1C
    gpg::HaStar::ClusterCache mClusterCache;                  // +0x28
  };

  static_assert(sizeof(PathTablesImpl) == 0x30, "PathTablesImpl size must be 0x30");
  static_assert(offsetof(PathTablesImpl, mSources) == 0x0C, "PathTablesImpl::mSources offset must be 0x0C");
  static_assert(offsetof(PathTablesImpl, mMaps) == 0x1C, "PathTablesImpl::mMaps offset must be 0x1C");
  static_assert(offsetof(PathTablesImpl, mClusterCache) == 0x28, "PathTablesImpl::mClusterCache offset must be 0x28");
} // namespace moho

namespace
{
  bool gGenPathWarmupPending = true;

  [[nodiscard]] bool IsGenPathEnabled()
  {
#ifdef _WIN32
    const char* const commandLine = ::GetCommandLineA();
    return commandLine && std::strstr(commandLine, "/genpath");
#else
    return false;
#endif
  }

  template <typename T>
  void ResetLegacyVectorStorage(LegacyVectorStorage<T>& storage)
  {
    if (storage.mFirst) {
      operator delete(storage.mFirst);
    }

    storage.mFirst = nullptr;
    storage.mLast = nullptr;
    storage.mEnd = nullptr;
  }

  template <typename Fn>
  void ForEachClusterMap(moho::PathTablesImpl* impl, Fn&& fn)
  {
    if (!impl) {
      return;
    }

    for (moho::ClusterMap** it = impl->mMaps.mFirst; it != impl->mMaps.mLast; ++it) {
      moho::ClusterMap* const map = *it;
      if (!map) {
        continue;
      }

      fn(map);
    }
  }

  /**
   * Address: 0x0076CF30 (FUN_0076CF30, ??1Impl@PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * Destroys impl-owned cache handles and releases the source/map vector storage buffers.
   */
  void DestroyPathTablesImpl(moho::PathTablesImpl* impl)
  {
    if (!impl) {
      return;
    }

    impl->mClusterCache.~ClusterCache();
    ResetLegacyVectorStorage(impl->mMaps);
    ResetLegacyVectorStorage(impl->mSources);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00765D30 (FUN_00765D30, ??0PathQueue@Moho@@QA@Z)
   *
   * What it does:
   * Allocates one `PathQueue::Impl`, runs the impl initialization chain, and
   * records the requested queue-size lane.
   */
  PathQueue::PathQueue(const int size)
    : mImpl(nullptr)
  {
    // Allocation size and constructor chain from:
    // - 0x00765D30 (PathQueue::PathQueue)
    // - 0x00765B20 (PathQueue::Impl::Impl)
    // - 0x00765B90 (PathQueue::ImplBase::ImplBase)
    // - 0x00766CE0 (sub_766CE0)
    auto* const impl = static_cast<PathQueue::Impl*>(::operator new(sizeof(PathQueue::Impl), std::nothrow));
    if (impl == nullptr) {
      return;
    }

    std::memset(impl, 0, sizeof(PathQueue::Impl));
    impl->mHeightSentinel.mNext = &impl->mHeightSentinel;
    impl->mHeightSentinel.mPrev = &impl->mHeightSentinel;
    InitializePathQueueImplBase(impl->mBase);
    impl->mSize = size;
    mImpl = impl;
  }

  /**
   * Address: 0x0076BA40 (FUN_0076BA40, ??0Impl@PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * Resets impl vector lanes (`mSources`, `mMaps`) to empty null ranges.
   */
  PathTablesImpl::PathTablesImpl()
  {
    mSources.mFirst = nullptr;
    mSources.mLast = nullptr;
    mSources.mEnd = nullptr;

    mMaps.mFirst = nullptr;
    mMaps.mLast = nullptr;
    mMaps.mEnd = nullptr;
  }

  /**
   * Address: 0x0076BAC0 (FUN_0076BAC0, ??1PathTables@Moho@@QAE@@Z)
   */
  PathTables::~PathTables()
  {
    for (ClusterMap** it = mImpl->mMaps.mFirst; it != mImpl->mMaps.mLast; ++it) {
      ClusterMap* const map = *it;
      if (!map) {
        continue;
      }

      map->~ClusterMap();
      operator delete(map);
    }

    PathTablesImpl* const impl = mImpl;
    if (impl) {
      DestroyPathTablesImpl(impl);
      operator delete(impl);
    }
  }

  /**
   * Address: 0x0076BC10 (FUN_0076BC10)
   */
  void PathTables::UpdateBackground(int* budget)
  {
    if (!budget || !mImpl) {
      return;
    }

    // /genpath one-shot pass forces "unlimited" budget through every cluster once.
    if (IsGenPathEnabled() && gGenPathWarmupPending) {
      ForEachClusterMap(mImpl, [&](moho::ClusterMap* cluster) {
        *budget = INT_MAX;
        cluster->BackgroundWork(*budget);
      });
      gGenPathWarmupPending = false;
    }

    ForEachClusterMap(mImpl, [&](moho::ClusterMap* cluster) {
      cluster->BackgroundWork(*budget);
    });
  }

  /**
   * Address: 0x0076BBD0 (FUN_0076BBD0, Moho::PathQueue::DirtyClusters)
   */
  void PathTables::DirtyClusters(const gpg::Rect2i& dirtyRect)
  {
    if (!mImpl) {
      return;
    }

    for (ClusterMap** it = mImpl->mMaps.mFirst; it != mImpl->mMaps.mLast; ++it) {
      ClusterMap* const cluster = *it;
      if (!cluster) {
        continue;
      }

      cluster->DirtyRect(dirtyRect);
    }
  }

  // Static cached RType slot for the placeholder `PathQueue` type;
  // populated lazily by `gpg::RRef_PathQueue` via cached lookup.
  gpg::RType* PathQueue::sType = nullptr;
} // namespace moho
