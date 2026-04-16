#include "PathTables.h"

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <typeinfo>
#include <utility>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/path/ClusterMap.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"
#include "moho/sim/STIMap.h"

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
  constexpr const char* kSerializationHeaderPath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.h";

  struct SerSaveLoadHelperInitRuntimeView
  {
    void* mVTable = nullptr;                    // +0x00
    gpg::SerHelperBase* mHelperNext = nullptr; // +0x04
    gpg::SerHelperBase* mHelperPrev = nullptr; // +0x08
    gpg::RType::load_func_t mLoadCallback = nullptr; // +0x0C
    gpg::RType::save_func_t mSaveCallback = nullptr; // +0x10
  };
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mHelperNext) == 0x04,
    "SerSaveLoadHelperInitRuntimeView::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mHelperPrev) == 0x08,
    "SerSaveLoadHelperInitRuntimeView::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mLoadCallback) == 0x0C,
    "SerSaveLoadHelperInitRuntimeView::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mSaveCallback) == 0x10,
    "SerSaveLoadHelperInitRuntimeView::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(SerSaveLoadHelperInitRuntimeView) == 0x14,
    "SerSaveLoadHelperInitRuntimeView size must be 0x14"
  );

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

  void ResetPathQueueNodeLinks(PathQueueIntrusiveNode& node)
  {
    node.mNext = &node;
    node.mPrev = &node;
  }

  void UnlinkAndResetPathQueueNode(PathQueueIntrusiveNode& node)
  {
    PathQueueIntrusiveNode* const next = node.mNext;
    PathQueueIntrusiveNode* const prev = node.mPrev;
    next->mPrev = prev;
    prev->mNext = next;
    ResetPathQueueNodeLinks(node);
  }

  void ResetPathQueuePointerTriplet(PathQueuePointerTriplet& triplet)
  {
    if (triplet.mFirst != nullptr) {
      ::operator delete(triplet.mFirst);
    }

    triplet.mFirst = nullptr;
    triplet.mLast = nullptr;
    triplet.mCapacity = nullptr;
  }

  /**
   * Address: 0x007676A0 (FUN_007676A0, Moho::PathQueue::ImplBase::~ImplBase helper)
   *
   * What it does:
   * Clears all owned intrusive nodes under the owner sentinel, resets sentinel
   * self-links, and zeroes the tracked node-count lane.
   */
  void ClearOwnedPathQueueNodes(PathQueueOwnedNodeLane& owner)
  {
    PathQueueIntrusiveNode* const sentinel = owner.mSentinel;
    if (sentinel == nullptr) {
      owner.mCount = 0;
      return;
    }

    PathQueueIntrusiveNode* node = sentinel->mNext;
    ResetPathQueueNodeLinks(*sentinel);
    owner.mCount = 0;

    while (node != sentinel) {
      PathQueueIntrusiveNode* const next = node->mNext;
      ::operator delete(node);
      node = next;
    }
  }

  void DestroyPathQueueImplBase(PathQueueImplBaseRuntime& implBase)
  {
    // Address: 0x00765C30 (FUN_00765C30, Moho::PathQueue::ImplBase::~ImplBase)
    ResetPathQueuePointerTriplet(implBase.mBucketB);
    ResetPathQueuePointerTriplet(implBase.mBucketA);
    ResetPathQueuePointerTriplet(implBase.mClusters);
    ClearOwnedPathQueueNodes(implBase.mOwnedNodes);
    ::operator delete(implBase.mOwnedNodes.mSentinel);
    implBase.mOwnedNodes.mSentinel = nullptr;
  }

  void DestroyPathQueueImpl(PathQueueImplBaseRuntime& implBase)
  {
    // Address: 0x00765BE0 (FUN_00765BE0), PathQueue implementation teardown prefix.
    ResetPathQueuePointerTriplet(implBase.mPending);
    UnlinkAndResetPathQueueNode(implBase.mTraveler);
    DestroyPathQueueImplBase(implBase);
  }

  struct PathQueueWorkHeapEntry
  {
    float totalCost;            // +0x00
    std::uint32_t lane04;       // +0x04
    std::uint32_t handleIndex;  // +0x08
  };
  static_assert(sizeof(PathQueueWorkHeapEntry) == 0x0C, "PathQueueWorkHeapEntry size must be 0x0C");
  static_assert(offsetof(PathQueueWorkHeapEntry, handleIndex) == 0x08, "PathQueueWorkHeapEntry::handleIndex offset must be 0x08");

  struct PathQueueWorkHeapRuntimeView
  {
    std::uint32_t lane00;                 // +0x00
    PathQueueWorkHeapEntry* entries;      // +0x04
    std::uint8_t pad08[0x0C];             // +0x08
    std::uint32_t* indexByHandle;         // +0x14
  };
  static_assert(sizeof(PathQueueWorkHeapRuntimeView) == 0x18, "PathQueueWorkHeapRuntimeView size must be 0x18");
  static_assert(offsetof(PathQueueWorkHeapRuntimeView, entries) == 0x04, "PathQueueWorkHeapRuntimeView::entries offset must be 0x04");
  static_assert(
    offsetof(PathQueueWorkHeapRuntimeView, indexByHandle) == 0x14,
    "PathQueueWorkHeapRuntimeView::indexByHandle offset must be 0x14"
  );

  /**
   * Address: 0x00769600 (FUN_00769600)
   *
   * What it does:
   * Sifts one open-heap entry upward by `totalCost` in the `PathQueue::Work`
   * lane and keeps the external `handle -> heapIndex` map synchronized.
   */
  [[maybe_unused]] std::uintptr_t PathQueueSiftWorkHeapEntryUpByCost(
    std::uint32_t heapIndex,
    PathQueueWorkHeapRuntimeView* const heap
  ) noexcept
  {
    std::uintptr_t result = heapIndex;
    if (heapIndex == 0u || heap == nullptr || heap->entries == nullptr) {
      return result;
    }

    while (true) {
      PathQueueWorkHeapEntry* const entries = heap->entries;
      result = reinterpret_cast<std::uintptr_t>(entries);

      const std::uint32_t parentIndex = (heapIndex - 1u) >> 1u;
      if (entries[heapIndex].totalCost > entries[parentIndex].totalCost) {
        break;
      }

      PathQueueWorkHeapEntry savedParent = entries[parentIndex];
      entries[parentIndex] = entries[heapIndex];
      entries[heapIndex] = savedParent;

      if (heap->indexByHandle != nullptr) {
        heap->indexByHandle[entries[parentIndex].handleIndex] = parentIndex;
        heap->indexByHandle[entries[heapIndex].handleIndex] = heapIndex;
        result = reinterpret_cast<std::uintptr_t>(heap->indexByHandle);
      }

      heapIndex = parentIndex;
      if (heapIndex == 0u) {
        break;
      }
    }

    return result;
  }

  struct LegacyVectorStorageRuntime12
  {
    std::uint32_t lane00;                 // +0x00
    PathQueueWorkHeapEntry* begin;        // +0x04
    PathQueueWorkHeapEntry* end;          // +0x08
    PathQueueWorkHeapEntry* capacityEnd;  // +0x0C
  };
  static_assert(sizeof(LegacyVectorStorageRuntime12) == 0x10, "LegacyVectorStorageRuntime12 size must be 0x10");

  /**
   * Address: 0x00769860 (FUN_00769860)
   * Address: 0x0076C400 (FUN_0076C400)
   *
   * What it does:
   * Returns the logical element count for one 12-byte legacy vector lane.
   */
  [[maybe_unused]] std::int32_t CountLegacyVector12ElementsRuntime(
    const LegacyVectorStorageRuntime12* const vector
  ) noexcept
  {
    if (vector == nullptr || vector->begin == nullptr) {
      return 0;
    }

    return static_cast<std::int32_t>(vector->end - vector->begin);
  }

  /**
   * Address: 0x00769C30 (FUN_00769C30)
   *
   * What it does:
   * Swaps two work-heap entries and refreshes the handle-index lookup lane.
   */
  [[maybe_unused]] std::uint32_t* SwapPathQueueWorkHeapEntriesAndSyncIndicesRuntime(
    const std::uint32_t firstIndex,
    PathQueueWorkHeapRuntimeView* const heap,
    const std::uint32_t secondIndex
  ) noexcept
  {
    if (heap == nullptr || heap->entries == nullptr || heap->indexByHandle == nullptr) {
      return heap != nullptr ? heap->indexByHandle : nullptr;
    }

    PathQueueWorkHeapEntry& first = heap->entries[firstIndex];
    PathQueueWorkHeapEntry& second = heap->entries[secondIndex];
    std::swap(first, second);

    heap->indexByHandle[first.handleIndex] = firstIndex;
    heap->indexByHandle[second.handleIndex] = secondIndex;
    return heap->indexByHandle;
  }

  /**
   * Address: 0x0076AAB0 (FUN_0076AAB0)
   *
   * What it does:
   * Writes one repeated 12-byte work-heap entry into `[begin,end)`.
   */
  [[maybe_unused]] PathQueueWorkHeapEntry* FillPathQueueWorkHeapEntryRangeRuntime(
    PathQueueWorkHeapEntry* begin,
    PathQueueWorkHeapEntry* const end,
    const PathQueueWorkHeapEntry* const value
  ) noexcept
  {
    if (value == nullptr) {
      return begin;
    }

    for (; begin != end; ++begin) {
      *begin = *value;
    }
    return begin;
  }

  /**
   * Address: 0x0076AAD0 (FUN_0076AAD0)
   *
   * What it does:
   * Copies one 12-byte work-heap range backward into destination tail lanes.
   */
  [[maybe_unused]] PathQueueWorkHeapEntry* CopyPathQueueWorkHeapEntryRangeBackwardRuntime(
    PathQueueWorkHeapEntry* destinationEnd,
    const PathQueueWorkHeapEntry* sourceEnd,
    const PathQueueWorkHeapEntry* const sourceBegin
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      --destinationEnd;
      --sourceEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }
} // namespace

namespace moho
{
  struct PathQueue::Impl
  {
    /**
     * Address: 0x00765B20 (FUN_00765B20, ??0Impl@PathQueue@Moho@@QAE@@Z_0)
     * Mangled: ??0Impl@PathQueue@Moho@@QAE@@Z_0
     *
     * What it does:
     * Initializes one `PathQueue::Impl` lane to empty state by zeroing queue
     * size, self-linking the height sentinel, and constructing the ImplBase
     * runtime owner lanes.
     */
    Impl();

    std::int32_t mSize;                     // +0x00
    PathQueueIntrusiveNode mHeightSentinel; // +0x04
    PathQueueImplBaseRuntime mBase;         // +0x0C
    std::uint8_t mPad80[0x08];              // +0x80
  };

  static_assert(sizeof(PathQueue::Impl) == 0x88, "PathQueue::Impl size must be 0x88");
  static_assert(offsetof(PathQueue::Impl, mSize) == 0x00, "PathQueue::Impl::mSize offset must be 0x00");
  static_assert(offsetof(PathQueue::Impl, mBase) == 0x0C, "PathQueue::Impl::mBase offset must be 0x0C");

  namespace
  {
    struct PathQueueRuntimeView
    {
      PathQueue::Impl* mImpl;
    };
    static_assert(sizeof(PathQueueRuntimeView) == sizeof(PathQueue), "PathQueue runtime view size must match PathQueue");
    static_assert(offsetof(PathQueueRuntimeView, mImpl) == 0x00, "PathQueueRuntimeView::mImpl offset must be 0x00");

    [[nodiscard]] gpg::RRef BuildPathQueueRefFromRuntime(PathQueueRuntimeView* const runtime) noexcept
    {
      gpg::RRef objectRef{};
      (void)gpg::RRef_PathQueue(&objectRef, reinterpret_cast<PathQueue*>(runtime));
      return objectRef;
    }

    [[nodiscard]] gpg::RType* ResolvePathQueueImplType() noexcept
    {
      static gpg::RType* sType = nullptr;
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(PathQueue::Impl));
        if (sType == nullptr) {
          sType = gpg::REF_FindTypeNamed("Moho::PathQueue::Impl");
        }
        if (sType == nullptr) {
          sType = gpg::REF_FindTypeNamed("PathQueue::Impl");
        }
        if (sType == nullptr) {
          sType = gpg::REF_FindTypeNamed("PathQueue_Impl");
        }
      }
      return sType;
    }

    [[nodiscard]] gpg::RRef BuildPathQueueImplRef(PathQueue::Impl* const impl) noexcept
    {
      gpg::RRef objectRef{};
      objectRef.mObj = impl;
      objectRef.mType = ResolvePathQueueImplType();
      return objectRef;
    }

    /**
     * Address: 0x00767900 (FUN_00767900, Moho::PathQueueTypeInfo::Delete)
     *
     * What it does:
     * Deletes one `PathQueue` owner lane and tears down the owned `Impl`
     * payload when present.
     */
    void DeletePathQueueRefCallback(void* const objectStorage)
    {
      auto* const runtime = static_cast<PathQueueRuntimeView*>(objectStorage);
      if (runtime == nullptr) {
        return;
      }

      if (runtime->mImpl != nullptr) {
        auto* const impl = runtime->mImpl;
        DestroyPathQueueImpl(impl->mBase);
        UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
        ::operator delete(impl);
        runtime->mImpl = nullptr;
      }

      ::operator delete(runtime);
    }

    /**
     * Address: 0x00767990 (FUN_00767990, Moho::PathQueueTypeInfo::Destruct)
     *
     * What it does:
     * Destroys one in-place `PathQueue` owner lane and tears down the owned
     * `Impl` payload when present.
     */
    void DestructPathQueueRefCallback(void* const objectStorage)
    {
      auto* const runtime = static_cast<PathQueueRuntimeView*>(objectStorage);
      if (runtime == nullptr || runtime->mImpl == nullptr) {
        return;
      }

      auto* const impl = runtime->mImpl;
      DestroyPathQueueImpl(impl->mBase);
      UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
      ::operator delete(impl);
      runtime->mImpl = nullptr;
    }

    /**
     * Address: 0x007678C0 (FUN_007678C0, Moho::PathQueueTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one zeroed `PathQueue` owner lane and returns it as a typed
     * reflection reference.
     */
    [[nodiscard]] gpg::RRef NewPathQueueRefCallback()
    {
      auto* const runtime = static_cast<PathQueueRuntimeView*>(::operator new(sizeof(PathQueueRuntimeView), std::nothrow));
      if (runtime != nullptr) {
        runtime->mImpl = nullptr;
      }
      return BuildPathQueueRefFromRuntime(runtime);
    }

    /**
     * Address: 0x00767950 (FUN_00767950, Moho::PathQueueTypeInfo::CtrRef)
     *
     * What it does:
     * Initializes one caller-provided `PathQueue` storage lane to null-impl
     * state and returns it as a typed reflection reference.
     */
    [[nodiscard]] gpg::RRef ConstructPathQueueRefCallback(void* const objectStorage)
    {
      auto* const runtime = static_cast<PathQueueRuntimeView*>(objectStorage);
      if (runtime != nullptr) {
        runtime->mImpl = nullptr;
      }
      return BuildPathQueueRefFromRuntime(runtime);
    }

    /**
     * Address: 0x00767A50 (FUN_00767A50, Moho::PathQueueImplTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `PathQueue::Impl` lane after running teardown.
     */
    void DeletePathQueueImplRefCallback(void* const objectStorage)
    {
      auto* const impl = static_cast<PathQueue::Impl*>(objectStorage);
      if (impl == nullptr) {
        return;
      }

      DestroyPathQueueImpl(impl->mBase);
      UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
      ::operator delete(impl);
    }

    /**
     * Address: 0x00767B00 (FUN_00767B00, Moho::PathQueueImplTypeInfo::Destruct)
     *
     * What it does:
     * Destroys one in-place `PathQueue::Impl` lane without releasing owner
     * storage.
     */
    void DestructPathQueueImplRefCallback(void* const objectStorage)
    {
      auto* const impl = static_cast<PathQueue::Impl*>(objectStorage);
      if (impl == nullptr) {
        return;
      }

      DestroyPathQueueImpl(impl->mBase);
      UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
    }

    /**
     * Address: 0x007679D0 (FUN_007679D0, Moho::PathQueueImplTypeInfo::NewRef)
     *
     * What it does:
     * Allocates and constructs one `PathQueue::Impl` payload and returns it as
     * a typed reflection reference.
     */
    [[nodiscard]] gpg::RRef NewPathQueueImplRefCallback()
    {
      auto* const impl = static_cast<PathQueue::Impl*>(::operator new(sizeof(PathQueue::Impl), std::nothrow));
      if (impl != nullptr) {
        ::new (impl) PathQueue::Impl();
      }
      return BuildPathQueueImplRef(impl);
    }

    /**
     * Address: 0x00767A90 (FUN_00767A90, Moho::PathQueueImplTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `PathQueue::Impl` payload in caller-provided storage and
     * returns it as a typed reflection reference.
     */
    [[nodiscard]] gpg::RRef ConstructPathQueueImplRefCallback(void* const objectStorage)
    {
      auto* const impl = static_cast<PathQueue::Impl*>(objectStorage);
      if (impl != nullptr) {
        ::new (impl) PathQueue::Impl();
      }
      return BuildPathQueueImplRef(impl);
    }

    /**
     * Address: 0x00767030 (FUN_00767030)
     *
     * What it does:
     * Binds `PathQueue` reflection lifecycle callbacks (`new/ctor/delete/dtr`)
     * into one destination `gpg::RType` lane.
     */
    [[nodiscard]] gpg::RType* BindPathQueueTypeInfoLifecycleCallbacks(gpg::RType* const typeInfo) noexcept
    {
      return gpg::BindRTypeLifecycleCallbacks(
        typeInfo,
        &NewPathQueueRefCallback,
        &ConstructPathQueueRefCallback,
        &DeletePathQueueRefCallback,
        &DestructPathQueueRefCallback
      );
    }

    /**
     * Address: 0x007670F0 (FUN_007670F0)
     *
     * What it does:
     * Binds `PathQueue::Impl` reflection lifecycle callbacks
     * (`new/ctor/delete/dtr`) into one destination `gpg::RType` lane.
     */
    [[nodiscard]] gpg::RType* BindPathQueueImplTypeInfoLifecycleCallbacks(gpg::RType* const typeInfo) noexcept
    {
      return gpg::BindRTypeLifecycleCallbacks(
        typeInfo,
        &NewPathQueueImplRefCallback,
        &ConstructPathQueueImplRefCallback,
        &DeletePathQueueImplRefCallback,
        &DestructPathQueueImplRefCallback
      );
    }

    /**
     * Address: 0x00767140 (FUN_00767140, gpg::SerSaveLoadHelper_PathQueue_Impl::Init)
     *
     * What it does:
     * Resolves reflected type metadata for `PathQueue::Impl`, installs
     * serializer callbacks from helper storage, and returns the load callback.
     */
    [[nodiscard]] gpg::RType::load_func_t InstallPathQueueImplSerializerCallbacks(
      SerSaveLoadHelperInitRuntimeView* const helper
    )
    {
      static gpg::RType* type = nullptr;
      if (type == nullptr) {
        type = gpg::LookupRType(typeid(PathQueue::Impl));
      }

      if (type->serLoadFunc_ != nullptr) {
        gpg::HandleAssertFailure("!type->mSerLoadFunc", 84, kSerializationHeaderPath);
      }

      const bool saveWasNull = type->serSaveFunc_ == nullptr;
      const gpg::RType::load_func_t loadCallback = helper->mLoadCallback;
      type->serLoadFunc_ = loadCallback;

      if (!saveWasNull) {
        gpg::HandleAssertFailure("!type->mSerSaveFunc", 87, kSerializationHeaderPath);
      }

      type->serSaveFunc_ = helper->mSaveCallback;
      return loadCallback;
    }

    class PathQueueTypeInfo final : public gpg::RType
    {
    public:
      /**
       * Address: 0x007668B0 (FUN_007668B0, Moho::PathQueueTypeInfo::GetName)
       */
      [[nodiscard]] const char* GetName() const override
      {
        return "PathQueue";
      }

      /**
       * Address: 0x00766870 (FUN_00766870, Moho::PathQueueTypeInfo::Init)
       */
      void Init() override
      {
        size_ = sizeof(PathQueue);
        (void)BindPathQueueTypeInfoLifecycleCallbacks(this);
        gpg::RType::Init();
        Finish();
      }
    };

    class PathQueueImplTypeInfo final : public gpg::RType
    {
    public:
      /**
       * Address: 0x00766AF0 (FUN_00766AF0, Moho::PathQueueImplTypeInfo::GetName)
       */
      [[nodiscard]] const char* GetName() const override
      {
        return "PathQueueImpl";
      }

      /**
       * Address: 0x00766AB0 (FUN_00766AB0, Moho::PathQueueImplTypeInfo::Init)
       */
      void Init() override
      {
        size_ = sizeof(PathQueue::Impl);
        (void)BindPathQueueImplTypeInfoLifecycleCallbacks(this);
        gpg::RType::Init();
        Finish();
      }
    };
  } // namespace

  /**
   * Address: 0x00766810 (FUN_00766810)
   *
   * What it does:
   * Constructs and preregisters the reflected type-info object for
   * `moho::PathQueue`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* RegisterPathQueueTypeInfo()
  {
    static PathQueueTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(PathQueue), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00766A50 (FUN_00766A50)
   *
   * What it does:
   * Constructs and preregisters the reflected type-info object for
   * `moho::PathQueue::Impl`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* RegisterPathQueueImplTypeInfo()
  {
    static PathQueueImplTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(PathQueue::Impl), &typeInfo);
    return &typeInfo;
  }

  namespace
  {
    struct PathQueueTypeInfoBootstrap
    {
      PathQueueTypeInfoBootstrap()
      {
        (void)RegisterPathQueueTypeInfo();
        (void)RegisterPathQueueImplTypeInfo();
      }
    };

    [[maybe_unused]] PathQueueTypeInfoBootstrap gPathQueueTypeInfoBootstrap;
  } // namespace

  struct OccupySourceBinding final : public gpg::HaStar::IOccupationSource
  {
    COGrid* mGrid;                // +0x04
    SNamedFootprint* mFootprint;  // +0x08

    /**
     * Address: 0x0076B750 (FUN_0076B750, ??0OccupySourceBinding@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Initializes one path occupation-source binding with null grid and
     * null footprint owners.
     */
    OccupySourceBinding();

    /**
     * Address: 0x0076B760 (FUN_0076B760, ??0OccupySourceBinding@Moho@@QAE@@Z_1)
     *
     * What it does:
     * Initializes one path occupation-source binding with explicit grid and
     * footprint owners.
     */
    OccupySourceBinding(COGrid* grid, SNamedFootprint* footprint);

    /**
     * Address: 0x0076CB50 (FUN_0076CB50, ??0OccupySourceBinding@Moho@@QAE@@Z)
     *
     * What it does:
     * Copy-constructs one path occupation-source binding owner pair.
     */
    OccupySourceBinding(const OccupySourceBinding& other);

    /**
     * Address: 0x0076B770 (FUN_0076B770, Moho::OccupySourceBinding::GetOccupyData)
     *
     * What it does:
     * Builds one 9-lane HaStar occupation mask neighborhood for the supplied
     * world cell using footprint occupancy filtering.
     */
    void GetOccupationData(int worldX, int worldY, gpg::HaStar::OccupationData& outData) override;
  };

  static_assert(sizeof(OccupySourceBinding) == 0x0C, "OccupySourceBinding size must be 0x0C");
  static_assert(offsetof(OccupySourceBinding, mGrid) == 0x04, "OccupySourceBinding::mGrid offset must be 0x04");
  static_assert(
    offsetof(OccupySourceBinding, mFootprint) == 0x08, "OccupySourceBinding::mFootprint offset must be 0x08"
  );

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
    LegacyVectorStorage<OccupySourceBinding> mSources;        // +0x0C
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

  struct BindingPayloadLane3Runtime
  {
    std::uint32_t lane0;
    std::uint32_t lane1;
    std::uint32_t lane2;
  };
  static_assert(sizeof(BindingPayloadLane3Runtime) == 0x0C, "BindingPayloadLane3Runtime size must be 0x0C");

  [[nodiscard]] bool IsGenPathEnabled()
  {
#ifdef _WIN32
    const char* const commandLine = ::GetCommandLineA();
    return commandLine && std::strstr(commandLine, "/genpath");
#else
    return false;
#endif
  }

  /**
   * Address: 0x0076C430 (FUN_0076C430)
   *
   * What it does:
   * Copies one trailing `OccupySourceBinding` payload range (`{mGrid,mFootprint}`)
   * into destination slots, commits owner `mEnd`, and returns destination begin.
   */
  [[maybe_unused]] void CopyOccupySourceBindingTailRangeAndCommitRuntime(
    LegacyVectorStorage<moho::OccupySourceBinding>* const owner,
    moho::OccupySourceBinding** const outDestinationBegin,
    moho::OccupySourceBinding* destinationBegin,
    const moho::OccupySourceBinding* sourceBegin
  ) noexcept
  {
    moho::OccupySourceBinding* const destinationStart = destinationBegin;
    if (owner != nullptr && destinationBegin != sourceBegin) {
      const moho::OccupySourceBinding* const sourceEnd = owner->mEnd;
      while (sourceBegin != sourceEnd) {
        destinationBegin->mGrid = sourceBegin->mGrid;
        destinationBegin->mFootprint = sourceBegin->mFootprint;
        ++destinationBegin;
        ++sourceBegin;
      }
      owner->mEnd = destinationBegin;
    }

    if (outDestinationBegin != nullptr) {
      *outDestinationBegin = destinationStart;
    }
  }

  /**
   * Address: 0x0076CD30 (FUN_0076CD30)
   *
   * What it does:
   * Writes one repeated `OccupySourceBinding` payload pair
   * (`{mGrid,mFootprint}`) into `[destinationBegin,destinationEnd)`.
   */
  [[maybe_unused]] std::uint32_t* FillOccupySourceBindingPayloadRangeRuntime(
    std::uint32_t* destinationBegin,
    const std::uint32_t* const destinationEnd,
    const moho::OccupySourceBinding* const sourceBinding
  ) noexcept
  {
    if (destinationBegin == nullptr || destinationEnd == nullptr || sourceBinding == nullptr) {
      return destinationBegin;
    }
    if (destinationBegin == destinationEnd) {
      return destinationBegin;
    }

    auto* write = reinterpret_cast<BindingPayloadLane3Runtime*>(destinationBegin);
    auto* const end = reinterpret_cast<const BindingPayloadLane3Runtime*>(destinationEnd);
    while (write != end) {
      write->lane1 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(sourceBinding->mGrid));
      write->lane2 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(sourceBinding->mFootprint));
      ++write;
    }
    return reinterpret_cast<std::uint32_t*>(const_cast<BindingPayloadLane3Runtime*>(end)) + 2;
  }

  /**
   * Address: 0x0076CD60 (FUN_0076CD60)
   *
   * What it does:
   * Copies `OccupySourceBinding` payload pairs (`{mGrid,mFootprint}`) backward
   * from source range into destination tail slots.
   */
  [[maybe_unused]] std::uint32_t* CopyOccupySourceBindingPayloadRangeBackwardRuntime(
    std::uint32_t* destinationEnd,
    const std::uint32_t* sourceEnd,
    const std::uint32_t* const sourceBegin
  ) noexcept
  {
    auto* destination = reinterpret_cast<BindingPayloadLane3Runtime*>(destinationEnd);
    auto* source = reinterpret_cast<const BindingPayloadLane3Runtime*>(sourceEnd);
    auto* const begin = reinterpret_cast<const BindingPayloadLane3Runtime*>(sourceBegin);

    while (begin != source) {
      --destination;
      --source;
      destination->lane1 = source->lane1;
      destination->lane2 = source->lane2;
    }

    return reinterpret_cast<std::uint32_t*>(destination);
  }

  struct OccupationDataRuntimeView
  {
    std::uint16_t mLayers[9];
    std::uint16_t mPad;
  };
  static_assert(
    sizeof(OccupationDataRuntimeView) == sizeof(gpg::HaStar::OccupationData),
    "OccupationDataRuntimeView size must match OccupationData"
  );

  template <typename T>
  bool ResizeLegacyVectorStorage(LegacyVectorStorage<T>& storage, const std::size_t count, const T& fillValue)
  {
    if (count == 0u) {
      storage.mFirst = nullptr;
      storage.mLast = nullptr;
      storage.mEnd = nullptr;
      return true;
    }

    auto* const begin = static_cast<T*>(::operator new(sizeof(T) * count, std::nothrow));
    if (begin == nullptr) {
      storage.mFirst = nullptr;
      storage.mLast = nullptr;
      storage.mEnd = nullptr;
      return false;
    }

    T* current = begin;
    for (std::size_t i = 0; i < count; ++i, ++current) {
      ::new (current) T(fillValue);
    }

    storage.mFirst = begin;
    storage.mLast = begin + count;
    storage.mEnd = begin + count;
    return true;
  }

  /**
   * Address: 0x0076BFA0 (FUN_0076BFA0, sub_76BFA0)
   *
   * What it does:
   * Builds one default `OccupySourceBinding` payload (`{nullptr,nullptr}`) and
   * forwards to the generic legacy-vector resize helper for source bindings.
   */
  [[maybe_unused]] void ResizeOccupySourceStorageWithDefaultBinding(
    LegacyVectorStorage<moho::OccupySourceBinding>* const storage,
    const std::uint32_t count
  )
  {
    if (storage == nullptr) {
      return;
    }

    const moho::OccupySourceBinding defaultBinding{};
    (void)ResizeLegacyVectorStorage(*storage, static_cast<std::size_t>(count), defaultBinding);
  }

  bool ResizeLegacyPointerStorage(LegacyVectorStorage<moho::ClusterMap*>& storage, const std::size_t count)
  {
    if (count == 0u) {
      storage.mFirst = nullptr;
      storage.mLast = nullptr;
      storage.mEnd = nullptr;
      return true;
    }

    auto* const begin = static_cast<moho::ClusterMap**>(::operator new(sizeof(moho::ClusterMap*) * count, std::nothrow));
    if (begin == nullptr) {
      storage.mFirst = nullptr;
      storage.mLast = nullptr;
      storage.mEnd = nullptr;
      return false;
    }

    std::memset(begin, 0, sizeof(moho::ClusterMap*) * count);
    storage.mFirst = begin;
    storage.mLast = begin + count;
    storage.mEnd = begin + count;
    return true;
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

  struct IntrusiveListNodeRuntime
  {
    IntrusiveListNodeRuntime* next; // +0x00
    IntrusiveListNodeRuntime* prev; // +0x04
  };
  static_assert(sizeof(IntrusiveListNodeRuntime) == 0x08, "IntrusiveListNodeRuntime size must be 0x08");

  struct IntrusiveListOwnerRuntime
  {
    std::uint32_t lane00;            // +0x00
    IntrusiveListNodeRuntime* head;  // +0x04
    std::int32_t count;              // +0x08
  };
  static_assert(sizeof(IntrusiveListOwnerRuntime) == 0x0C, "IntrusiveListOwnerRuntime size must be 0x0C");
  static_assert(offsetof(IntrusiveListOwnerRuntime, head) == 0x04, "IntrusiveListOwnerRuntime::head offset must be 0x04");
  static_assert(offsetof(IntrusiveListOwnerRuntime, count) == 0x08, "IntrusiveListOwnerRuntime::count offset must be 0x08");

  /**
   * Address: 0x0076A2B0 (FUN_0076A2B0)
   *
   * What it does:
   * Unlinks one intrusive node from its owner lane, deletes that node, and
   * stores the next-node lane into `outNext`.
   */
  [[maybe_unused]] IntrusiveListNodeRuntime** UnlinkAndDeleteIntrusiveNode(
    IntrusiveListNodeRuntime** const outNext,
    IntrusiveListOwnerRuntime& owner,
    IntrusiveListNodeRuntime* const node
  ) noexcept
  {
    IntrusiveListNodeRuntime* next = node != nullptr ? node->next : nullptr;
    if (node != nullptr && node != owner.head) {
      IntrusiveListNodeRuntime* const prev = node->prev;
      if (prev != nullptr) {
        prev->next = next;
      }
      if (next != nullptr) {
        next->prev = prev;
      }
      ::operator delete(node);
      --owner.count;
    }

    if (outNext != nullptr) {
      *outNext = next;
      return outNext;
    }
    return nullptr;
  }

  /**
   * Address: 0x0076CBA0 (FUN_0076CBA0)
   *
   * What it does:
   * Fills `count` contiguous `OccupySourceBinding` lanes from one prototype
   * binding and returns one-past the final destination lane.
   */
  [[maybe_unused]] moho::OccupySourceBinding* FillOccupySourceBindingRangeFromPrototype(
    moho::OccupySourceBinding* destinationBegin,
    const std::uint32_t count,
    const moho::OccupySourceBinding* const prototype
  ) noexcept
  {
    std::uintptr_t cursor = reinterpret_cast<std::uintptr_t>(destinationBegin);
    for (std::uint32_t index = 0u; index < count; ++index) {
      if (cursor != 0u && prototype != nullptr) {
        auto* const output = reinterpret_cast<moho::OccupySourceBinding*>(cursor);
        *output = *prototype;
      }
      cursor += sizeof(moho::OccupySourceBinding);
    }
    return reinterpret_cast<moho::OccupySourceBinding*>(cursor);
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
   * Address: 0x00765B20 (FUN_00765B20, ??0Impl@PathQueue@Moho@@QAE@@Z_0)
   * Mangled: ??0Impl@PathQueue@Moho@@QAE@@Z_0
   *
   * What it does:
   * Initializes one `PathQueue::Impl` lane to empty state by zeroing queue
   * size, self-linking the height sentinel, and constructing the ImplBase
   * runtime owner lanes.
   */
  PathQueue::Impl::Impl()
    : mSize(0)
  {
    mHeightSentinel.mNext = &mHeightSentinel;
    mHeightSentinel.mPrev = &mHeightSentinel;
    InitializePathQueueImplBase(mBase);
  }

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

    ::new (impl) PathQueue::Impl();
    impl->mSize = size;
    mImpl = impl;
  }

  /**
   * Address: 0x00701AD0 (FUN_00701AD0, Moho::PathQueue::Move)
   *
   * What it does:
   * Replaces one owner slot with a new queue pointer, then tears down and
   * frees the previous queue payload when present.
   */
  void PathQueue::Move(PathQueue** const slot, PathQueue* const replacement) noexcept
  {
    PathQueue* const previous = *slot;
    *slot = replacement;

    if (previous == nullptr) {
      return;
    }

    Impl* const impl = previous->mImpl;
    if (impl != nullptr) {
      DestroyPathQueueImpl(impl->mBase);
      UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
      ::operator delete(impl);
    }

    ::operator delete(previous);
  }

  /**
   * Address: 0x0076B750 (FUN_0076B750, ??0OccupySourceBinding@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Initializes one path occupation-source binding with null grid and
   * null footprint owners.
   */
  OccupySourceBinding::OccupySourceBinding()
    : mGrid(nullptr)
    , mFootprint(nullptr)
  {
  }

  /**
   * Address: 0x0076B760 (FUN_0076B760, ??0OccupySourceBinding@Moho@@QAE@@Z_1)
   *
   * What it does:
   * Initializes one path occupation-source binding with explicit grid and
   * footprint owners.
   */
  OccupySourceBinding::OccupySourceBinding(COGrid* const grid, SNamedFootprint* const footprint)
    : mGrid(grid)
    , mFootprint(footprint)
  {
  }

  /**
   * Address: 0x0076CB50 (FUN_0076CB50, ??0OccupySourceBinding@Moho@@QAE@@Z)
   *
   * What it does:
   * Copy-constructs one path occupation-source binding owner pair.
   */
  OccupySourceBinding::OccupySourceBinding(const OccupySourceBinding& other)
    : mGrid(other.mGrid)
    , mFootprint(other.mFootprint)
  {
  }

  /**
   * Address: 0x0076B770 (FUN_0076B770, Moho::OccupySourceBinding::GetOccupyData)
   *
   * What it does:
   * Builds one 9-lane HaStar occupation mask neighborhood for the supplied
   * world cell using footprint occupancy filtering.
   */
  void OccupySourceBinding::GetOccupationData(
    const int worldX,
    const int worldY,
    gpg::HaStar::OccupationData& outData
  )
  {
    constexpr std::size_t kOccupationResultColumnCount = 9u;
    constexpr std::size_t kMaxFootprintRows = 32u;
    constexpr std::size_t kMaxRowMaskCount = kOccupationResultColumnCount + kMaxFootprintRows;

    if (mFootprint == nullptr || mGrid == nullptr) {
      outData = {};
      return;
    }

    const std::uint32_t footprintWidth = static_cast<std::uint32_t>(mFootprint->mSizeX);
    const std::uint32_t footprintHeight = static_cast<std::uint32_t>(mFootprint->mSizeZ);
    const std::uint32_t activeRowCount = footprintHeight + static_cast<std::uint32_t>(kOccupationResultColumnCount - 1u);
    const std::uint32_t widthMask = (1u << footprintWidth) - 1u;

    std::array<std::uint32_t, kMaxRowMaskCount> rowMasks{};
    for (std::uint32_t row = 0; row < activeRowCount && row < rowMasks.size(); ++row) {
      rowMasks[row] = 0x1FFu;
      for (std::uint32_t x = 0; x < (footprintWidth + static_cast<std::uint32_t>(kOccupationResultColumnCount - 1u)); ++x) {
        SOCellPos cellPos{};
        cellPos.x = static_cast<std::int16_t>(worldX + static_cast<int>(x));
        cellPos.z = static_cast<std::int16_t>(worldY + static_cast<int>(row));

        const EOccupancyCaps filteredCaps = OCCUPY_Filter(*mFootprint, *mGrid, cellPos, EOccupancyCaps::OC_ANY);
        if (filteredCaps == static_cast<EOccupancyCaps>(0u)) {
          const std::uint32_t shiftedMask = (widthMask << x) >> (footprintWidth - 1u);
          rowMasks[row] &= ~shiftedMask;
        }
      }
    }

    if (footprintHeight > 1u) {
      for (std::size_t column = 0; column < kOccupationResultColumnCount; ++column) {
        for (std::uint32_t y = 1u; y < footprintHeight; ++y) {
          rowMasks[column] &= rowMasks[column + y];
        }
      }
    }

    auto& outView = reinterpret_cast<OccupationDataRuntimeView&>(outData);
    for (std::size_t i = 0; i < kOccupationResultColumnCount; ++i) {
      outView.mLayers[i] = static_cast<std::uint16_t>(rowMasks[i]);
    }
    outView.mPad = 0u;
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
   * Address: 0x0076B8C0 (FUN_0076B8C0, ??0PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * Builds per-footprint occupation-source bindings and cluster-map lanes for
   * one `(width,height)` grid.
   */
  PathTables::PathTables(
    const SRuleFootprintsBlueprint& footprints,
    COGrid* const grid,
    const int width,
    const int height
  )
    : mImpl(static_cast<PathTablesImpl*>(::operator new(sizeof(PathTablesImpl), std::nothrow)))
  {
    if (mImpl == nullptr) {
      return;
    }

    ::new (mImpl) PathTablesImpl();
    mImpl->mWidth = width;
    mImpl->mHeight = height;

    const std::size_t footprintCount = static_cast<std::size_t>(footprints.mSize);
    const OccupySourceBinding defaultSource{};
    if (!ResizeLegacyVectorStorage(mImpl->mSources, footprintCount, defaultSource)
      || !ResizeLegacyPointerStorage(mImpl->mMaps, footprintCount)) {
      return;
    }

    const SRuleFootprintNode* const head = footprints.mHead;
    if (head == nullptr) {
      return;
    }

    const SRuleFootprintNode* node = head->next;
    std::size_t sourceIndex = 0u;
    std::size_t footprintIndex = 0u;
    while (node != nullptr && node != head && sourceIndex < footprintCount) {
      SNamedFootprint* const footprint = const_cast<SNamedFootprint*>(&node->value);
      if (footprintIndex != static_cast<std::size_t>(footprint->mIndex)) {
        gpg::HandleAssertFailure("i == fp.mIndex", 113, "c:\\work\\rts\\main\\code\\src\\sim\\PathTables.cpp");
      }

      OccupySourceBinding& source = mImpl->mSources.mFirst[sourceIndex];
      source.mGrid = grid;
      source.mFootprint = footprint;

      ClusterMap* clusterMap = nullptr;
      if (auto* const clusterStorage = static_cast<ClusterMap*>(::operator new(sizeof(ClusterMap), std::nothrow));
          clusterStorage != nullptr) {
        gpg::Rect2i area{};
        area.x0 = -1;
        area.z0 = -1;
        area.x1 = static_cast<int>(footprint->mSizeX) + 1;
        area.z1 = static_cast<int>(footprint->mSizeZ) + 1;
        clusterMap = ::new (clusterStorage) ClusterMap(
          &source,
          static_cast<unsigned int>(width),
          static_cast<unsigned int>(height),
          mImpl->mClusterCache,
          2u,
          area
        );
      }

      mImpl->mMaps.mFirst[footprintIndex] = clusterMap;
      node = node->next;
      ++sourceIndex;
      ++footprintIndex;
    }
  }

  /**
   * Address: 0x0076BAC0 (FUN_0076BAC0, ??1PathTables@Moho@@QAE@@Z)
   */
  PathTables::~PathTables()
  {
    if (mImpl == nullptr) {
      return;
    }

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
