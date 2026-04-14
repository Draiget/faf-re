#include "Cluster.h"

#include <array>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <unordered_map>
#include <vector>

#include <intrin.h>

#include "gpg/core/utils/Global.h"

namespace
{
    struct SharedCountControl
    {
        void** vtable;
        volatile long useCount;
        volatile long weakCount;
    };

    void RetainSharedCount(void* sharedCount)
    {
        if (!sharedCount) {
            return;
        }

        auto* const control = reinterpret_cast<SharedCountControl*>(sharedCount);
        _InterlockedExchangeAdd(&control->useCount, 1);
    }

    [[nodiscard]] bool ReleaseSharedCount(void* sharedCount)
    {
        if (!sharedCount) {
            return true;
        }

        auto* const control = reinterpret_cast<SharedCountControl*>(sharedCount);
        if (_InterlockedExchangeAdd(&control->useCount, -1) == 1) {
            using ControlFn = void(__thiscall*)(SharedCountControl*);
            auto* const disposeFn = reinterpret_cast<ControlFn>(control->vtable[1]);
            disposeFn(control);

            if (_InterlockedExchangeAdd(&control->weakCount, -1) == 1) {
                auto* const destroyFn = reinterpret_cast<ControlFn>(control->vtable[2]);
                destroyFn(control);
            }
            return true;
        }

        return false;
    }

    constexpr std::uint8_t kClusterSizeLog2ByLevel[] = { 0u, 3u, 5u, 7u };
    constexpr std::size_t kClusterSizeLog2Count = sizeof(kClusterSizeLog2ByLevel) / sizeof(kClusterSizeLog2ByLevel[0]);
    constexpr std::uint8_t kClusterSizeByLevel[] = { 1u, 8u, 32u, 128u };
    constexpr std::size_t kClusterSizeCount = sizeof(kClusterSizeByLevel) / sizeof(kClusterSizeByLevel[0]);

    constexpr std::uint32_t kOccupationKeySalt = 0x7BEF2693u;
    constexpr std::uint32_t kSubclusterKeySalt = 0x0001F31Du;

    struct ClusterCacheTreeLayout
    {
        std::uint8_t pad_00[0x2C];
        std::uint8_t mSubclusterTree;
    };
    static_assert(offsetof(ClusterCacheTreeLayout, mSubclusterTree) == 0x2C, "Cluster cache subcluster tree offset must be 0x2C");

    struct SubclusterTreeHeader
    {
        std::uint32_t mCompareToken;
        void* mHead;
        std::uint32_t mSize;
    };

    struct SubclusterBucketVectorStorage
    {
        void* mIteratorProxy;
        std::uint32_t* mFirst;
        std::uint32_t* mLast;
        std::uint32_t* mEnd;
    };

    struct SubclusterCacheVectorState
    {
        bool mBool;
        std::uint8_t pad_01[3];
        SubclusterTreeHeader mList;
        SubclusterBucketVectorStorage mVec;
        std::uint32_t mMask;
        std::uint32_t mMaxIndex;

        /**
         * Address: 0x00934B60 (FUN_00934B60, ??0vector_SubclusterData@@QAE@@Z)
         * Mangled: ??0vector_SubclusterData@@QAE@@Z
         *
         * What it does:
         * Initializes subcluster-cache lookup lanes with one tree sentinel,
         * nine sentinel-token bucket entries, and default mask/max values.
         */
        SubclusterCacheVectorState(bool* cacheEnabledFlag, int stackAnchorHint);
    };

    static_assert(sizeof(SubclusterTreeHeader) == 0x0C, "SubclusterTreeHeader size must be 0x0C");
    static_assert(sizeof(SubclusterBucketVectorStorage) == 0x10, "SubclusterBucketVectorStorage size must be 0x10");
    static_assert(sizeof(SubclusterCacheVectorState) == 0x28, "SubclusterCacheVectorState size must be 0x28");
    static_assert(offsetof(SubclusterCacheVectorState, mList) == 0x04, "SubclusterCacheVectorState::mList offset must be 0x04");
    static_assert(offsetof(SubclusterCacheVectorState, mVec) == 0x10, "SubclusterCacheVectorState::mVec offset must be 0x10");
    static_assert(
        offsetof(SubclusterCacheVectorState, mMask) == 0x20, "SubclusterCacheVectorState::mMask offset must be 0x20"
    );
    static_assert(
        offsetof(SubclusterCacheVectorState, mMaxIndex) == 0x24, "SubclusterCacheVectorState::mMaxIndex offset must be 0x24"
    );

    /**
     * Address: 0x009327E0 (FUN_009327E0, sub_9327E0)
     *
     * What it does:
     * Allocates and seeds one tree-head sentinel node for the subcluster cache.
     */
    [[nodiscard]] void* AllocateSubclusterTreeHead()
    {
        auto* const node = static_cast<std::uint8_t*>(::operator new(0x50u));
        *reinterpret_cast<void**>(node + 0x00) = node;
        *reinterpret_cast<void**>(node + 0x04) = node;
        return node;
    }

    /**
     * Address: 0x00932A80 (FUN_00932A80, sub_932A80)
     *
     * What it does:
     * Fills one 32-bit value range with the same sentinel token.
     */
    void FillU32Range(std::uint32_t* dst, const unsigned int count, const std::uint32_t value)
    {
        for (unsigned int i = 0; i < count; ++i) {
            dst[i] = value;
        }
    }

    /**
     * Address: 0x00934250 (FUN_00934250, sub_934250)
     *
     * What it does:
     * Initializes 32-bit bucket-vector lanes used by subcluster cache buckets.
     */
    void InitializeSubclusterBucketVector(
        SubclusterBucketVectorStorage& vectorStorage, const unsigned int count, const std::uint32_t* const fillValueRef
    )
    {
        vectorStorage.mFirst = nullptr;
        vectorStorage.mLast = nullptr;
        vectorStorage.mEnd = nullptr;

        if (count == 0u) {
            return;
        }
        if (count > 0x3FFFFFFFu) {
            throw std::bad_alloc();
        }

        auto* const values =
            static_cast<std::uint32_t*>(::operator new(static_cast<std::size_t>(count) * sizeof(std::uint32_t)));
        vectorStorage.mFirst = values;
        vectorStorage.mLast = values;
        vectorStorage.mEnd = values + count;

        FillU32Range(values, count, *fillValueRef);
        vectorStorage.mLast = values + count;
    }

    /**
     * Address: 0x00934B60 (FUN_00934B60, ??0vector_SubclusterData@@QAE@@Z)
     */
    SubclusterCacheVectorState::SubclusterCacheVectorState(bool* const cacheEnabledFlag, const int /*stackAnchorHint*/)
    {
        mBool = *cacheEnabledFlag;
        mList.mHead = AllocateSubclusterTreeHead();
        mList.mSize = 0;

        const auto treeHeadToken = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(mList.mHead));
        InitializeSubclusterBucketVector(mVec, 9u, &treeHeadToken);

        mMask = 1u;
        mMaxIndex = 1u;
    }

    struct OccupationCacheKey
    {
        std::array<std::uint8_t, 0x12> mBytes{};
    };

    struct SubclusterCacheKey
    {
        std::array<std::uint8_t, sizeof(gpg::HaStar::SubclusterData)> mBytes{};
    };

    [[nodiscard]] std::uint32_t HashBytesSalted(const void* data, const std::size_t size, const std::uint32_t salt)
    {
        const auto* const bytes = static_cast<const std::uint8_t*>(data);
        std::uint32_t hash = 2166136261u ^ salt;
        for (std::size_t i = 0; i < size; ++i) {
            hash ^= bytes[i];
            hash *= 16777619u;
        }
        return hash;
    }

    [[nodiscard]] std::uint32_t ScrambleParkMiller(const std::uint32_t input)
    {
        const std::int64_t value = static_cast<std::int64_t>(input);
        const std::int64_t quotient = value / 127773LL;
        const std::int64_t remainder = value % 127773LL;
        std::int64_t candidate = 16807LL * remainder - 2836LL * quotient;
        if (candidate < 0) {
            candidate += 0x7FFFFFFFLL;
        }
        return static_cast<std::uint32_t>(candidate);
    }

    /**
     * Address: 0x00931460 (FUN_00931460, sub_931460)
     *
     * What it does:
     * Strict-weak ordering comparator used for occupation cache keys.
     */
    [[nodiscard]] bool OccupationKeyLess(const OccupationCacheKey& lhs, const OccupationCacheKey& rhs)
    {
        return std::memcmp(lhs.mBytes.data(), rhs.mBytes.data(), lhs.mBytes.size()) < 0;
    }

    /**
     * Address: 0x00931500 (FUN_00931500, sub_931500)
     *
     * What it does:
     * Computes hash value for subcluster cache keys.
     */
    [[nodiscard]] std::uint32_t HashSubclusterKey(const SubclusterCacheKey& key)
    {
        return HashBytesSalted(key.mBytes.data(), key.mBytes.size(), kSubclusterKeySalt);
    }

    /**
     * Address: 0x00931560 (FUN_00931560, sub_931560)
     *
     * What it does:
     * Strict-weak ordering comparator used for subcluster cache keys.
     */
    [[nodiscard]] bool SubclusterKeyLess(const SubclusterCacheKey& lhs, const SubclusterCacheKey& rhs)
    {
        return std::memcmp(lhs.mBytes.data(), rhs.mBytes.data(), lhs.mBytes.size()) < 0;
    }

    /**
     * Address: 0x00932080 (FUN_00932080, sub_932080)
     *
     * What it does:
     * Computes hash value for occupation cache keys.
     */
    [[nodiscard]] std::uint32_t HashOccupationKey(const OccupationCacheKey& key)
    {
        return HashBytesSalted(key.mBytes.data(), key.mBytes.size(), kOccupationKeySalt);
    }

    struct OccupationKeyHash
    {
        [[nodiscard]] std::size_t operator()(const OccupationCacheKey& key) const noexcept
        {
            return static_cast<std::size_t>(ScrambleParkMiller(HashOccupationKey(key)));
        }
    };

    struct OccupationKeyEq
    {
        [[nodiscard]] bool operator()(const OccupationCacheKey& lhs, const OccupationCacheKey& rhs) const noexcept
        {
            return !OccupationKeyLess(lhs, rhs) && !OccupationKeyLess(rhs, lhs);
        }
    };

    struct SubclusterKeyHash
    {
        [[nodiscard]] std::size_t operator()(const SubclusterCacheKey& key) const noexcept
        {
            return static_cast<std::size_t>(ScrambleParkMiller(HashSubclusterKey(key)));
        }
    };

    struct SubclusterKeyEq
    {
        [[nodiscard]] bool operator()(const SubclusterCacheKey& lhs, const SubclusterCacheKey& rhs) const noexcept
        {
            return !SubclusterKeyLess(lhs, rhs) && !SubclusterKeyLess(rhs, lhs);
        }
    };

    struct ClusterNodeSearchState
    {
        std::int32_t mOwnerNodeIndex;        // +0x00
        std::uint32_t mPackedNodeCoordinate; // +0x04
        std::int32_t mState;                 // +0x08
        std::int32_t mHeapLane;              // +0x0C
        float mPathCost;                     // +0x10
        float mHeuristicCost;                // +0x14
        std::int32_t mOpenListHandle;        // +0x18
    };
    static_assert(sizeof(ClusterNodeSearchState) == 0x1C, "ClusterNodeSearchState size must be 0x1C");

    struct ClusterNodeSearchStateHash
    {
        [[nodiscard]] std::size_t operator()(const std::uint16_t packedCoordinate) const noexcept
        {
            return static_cast<std::size_t>(ScrambleParkMiller(static_cast<std::uint32_t>(packedCoordinate)));
        }
    };

    struct ClusterSearchScratchNode
    {
        std::int32_t mNodeIndex = 0;        // +0x00
        std::int32_t mPreviousNodeIndex = 0; // +0x04
        float mTraversalCost = 0.0f;         // +0x08
    };
    static_assert(sizeof(ClusterSearchScratchNode) == 0x0C, "ClusterSearchScratchNode size must be 0x0C");

    struct ClusterSearchScratch
    {
        std::vector<ClusterSearchScratchNode> mPendingNodes;
        std::vector<std::int32_t> mFrontierNodeIndices;
        std::int32_t mActiveNodeIndex = -1;

        /**
         * Address: 0x0092EF80 (FUN_0092EF80, struct_Ha2::Reset)
         *
         * What it does:
         * Clears search frontier/state vectors and resets the active-node
         * marker used during subcluster cluster-build traversal.
         */
        void Reset();
    };

    void ClusterSearchScratch::Reset()
    {
        mPendingNodes.clear();
        mFrontierNodeIndices.clear();
        mActiveNodeIndex = -1;
    }

    using ClusterNodeSearchStateMap =
        std::unordered_map<std::uint16_t, ClusterNodeSearchState, ClusterNodeSearchStateHash>;

    [[nodiscard]] std::uint16_t PackClusterNodeCoordinate(const std::uint8_t x, const std::uint8_t z) noexcept
    {
        return static_cast<std::uint16_t>(x) | (static_cast<std::uint16_t>(z) << 8u);
    }

    /**
     * Address: 0x00930BA0 (FUN_00930BA0, std::hash_map_unk_unk::operator[])
     *
     * What it does:
     * Returns one node-search state lane for `(x,z)` by key lookup, inserting
     * a zero-initialized state when the key is not present.
     */
    [[maybe_unused]] [[nodiscard]] ClusterNodeSearchState&
    ClusterNodeStateMapIndex(ClusterNodeSearchStateMap& stateByCoordinate, const std::uint8_t nodeX, const std::uint8_t nodeZ)
    {
        const std::uint16_t packedCoordinate = PackClusterNodeCoordinate(nodeX, nodeZ);
        const auto result = stateByCoordinate.try_emplace(packedCoordinate);
        auto it = result.first;
        if (result.second) {
            it->second = {};
        }
        return it->second;
    }

    struct FastVectorN12CharRuntime
    {
        char* start;        // +0x00
        char* end;          // +0x04
        char* capacityEnd;  // +0x08
        char* inlineOrigin; // +0x0C
    };
    static_assert(sizeof(FastVectorN12CharRuntime) == 0x10, "FastVectorN12CharRuntime size must be 0x10");
    static_assert(
        offsetof(FastVectorN12CharRuntime, capacityEnd) == 0x08,
        "FastVectorN12CharRuntime::capacityEnd offset must be 0x08"
    );
    static_assert(
        offsetof(FastVectorN12CharRuntime, inlineOrigin) == 0x0C,
        "FastVectorN12CharRuntime::inlineOrigin offset must be 0x0C"
    );

    [[maybe_unused]] void EnsureFastVectorN12CharCapacity(FastVectorN12CharRuntime& view, const unsigned int requiredCount)
    {
        const auto currentCapacity = (view.start != nullptr && view.capacityEnd != nullptr)
            ? static_cast<unsigned int>(view.capacityEnd - view.start)
            : 0u;
        if (requiredCount <= currentCapacity) {
            return;
        }

        const auto oldCount = (view.start != nullptr && view.end != nullptr)
            ? static_cast<unsigned int>(view.end - view.start)
            : 0u;
        char* const newStorage = static_cast<char*>(::operator new[](requiredCount));
        if (oldCount != 0u && view.start != nullptr) {
            std::memcpy(newStorage, view.start, oldCount);
        }

        if (view.start == view.inlineOrigin) {
            if (view.inlineOrigin != nullptr) {
                *reinterpret_cast<char**>(view.inlineOrigin) = view.capacityEnd;
            }
        }
        else if (view.start != nullptr) {
            ::operator delete[](view.start);
        }

        view.start = newStorage;
        view.end = newStorage + oldCount;
        view.capacityEnd = newStorage + requiredCount;
    }

    /**
     * Address: 0x009545D0 (FUN_009545D0, gpg::fastvector_char::Resize)
     *
     * What it does:
     * Resizes one `fastvector_n<char,12>` lane to `newSize`, truncating when
     * shrinking and fill-writing one byte value into appended slots when
     * growing.
     */
    [[maybe_unused]] void
    FastVectorN12CharResize(FastVectorN12CharRuntime& view, const unsigned int newSize, const char* const fillValue)
    {
        const auto currentSize = (view.start != nullptr && view.end != nullptr)
            ? static_cast<unsigned int>(view.end - view.start)
            : 0u;
        if (newSize < currentSize) {
            char* const newEnd = view.start + newSize;
            if (newEnd != view.end) {
                view.end = newEnd;
            }
            return;
        }
        if (newSize == currentSize) {
            return;
        }

        EnsureFastVectorN12CharCapacity(view, newSize);
        const char fillByte = fillValue ? *fillValue : '\0';
        char* const desiredEnd = view.start + newSize;
        while (view.end != desiredEnd) {
            char* const slot = view.end;
            view.end = slot + 1;
            if (slot != nullptr) {
                *slot = fillByte;
            }
        }
    }

    struct RuntimeClusterCacheStore
    {
        std::unordered_map<OccupationCacheKey, gpg::HaStar::Cluster::Data*, OccupationKeyHash, OccupationKeyEq> mOccupation;
        std::unordered_map<SubclusterCacheKey, gpg::HaStar::Cluster::Data*, SubclusterKeyHash, SubclusterKeyEq> mSubcluster;
    };

    struct CacheLookupResult
    {
        gpg::HaStar::Cluster::Data* mData{};
        bool mFound{};
    };

    struct CacheInsertResult
    {
        gpg::HaStar::Cluster::Data* mData{};
        bool mInserted{};
    };

    std::unordered_map<void*, RuntimeClusterCacheStore> gRuntimeClusterCacheStores;

    void RetainClusterData(gpg::HaStar::Cluster::Data* data)
    {
        if (data) {
            ++data->mRefs;
        }
    }

    void ReleaseClusterData(gpg::HaStar::Cluster::Data* data)
    {
        if (!data) {
            return;
        }

        --data->mRefs;
        if (data->mRefs != 0) {
            return;
        }

        if (data->mReleaseObject) {
            using ReleaseFn = void(__thiscall*)(void*, std::uint32_t);
            auto** const vtable = *reinterpret_cast<void***>(data->mReleaseObject);
            auto* const releaseFn = reinterpret_cast<ReleaseFn>(vtable[0]);
            releaseFn(data->mReleaseObject, data->mReleaseArg);
        }
        operator delete[](data);
    }

    void AssignClusterData(gpg::HaStar::Cluster& dst, const gpg::HaStar::Cluster& src)
    {
        if (dst.mData == src.mData) {
            return;
        }

        RetainClusterData(src.mData);
        ReleaseClusterData(dst.mData);
        dst.mData = src.mData;
    }

    void SetClusterData(gpg::HaStar::Cluster& dst, gpg::HaStar::Cluster::Data* data)
    {
        if (dst.mData == data) {
            return;
        }

        RetainClusterData(data);
        ReleaseClusterData(dst.mData);
        dst.mData = data;
    }

    [[nodiscard]] OccupationCacheKey MakeOccupationCacheKey(const gpg::HaStar::OccupationData& occupationData)
    {
        OccupationCacheKey key{};
        std::memcpy(key.mBytes.data(), &occupationData, key.mBytes.size());
        return key;
    }

    [[nodiscard]] SubclusterCacheKey MakeSubclusterCacheKey(const gpg::HaStar::SubclusterData& subclusterData)
    {
        SubclusterCacheKey key{};
        std::memcpy(key.mBytes.data(), &subclusterData, key.mBytes.size());
        return key;
    }

    [[nodiscard]] RuntimeClusterCacheStore& RuntimeClusterCacheForBase(void* const cacheTreeBase)
    {
        return gRuntimeClusterCacheStores[cacheTreeBase];
    }

    [[nodiscard]] void* ResolveCacheTreeBaseFromSubclusterPtr(void* const subclusterTree)
    {
        if (!subclusterTree) {
            return nullptr;
        }

        auto* const bytes = static_cast<std::uint8_t*>(subclusterTree);
        return static_cast<void*>(bytes - offsetof(ClusterCacheTreeLayout, mSubclusterTree));
    }

    void ReleaseRuntimeClusterCacheStore(void* const cacheTreeBase)
    {
        const auto it = gRuntimeClusterCacheStores.find(cacheTreeBase);
        if (it == gRuntimeClusterCacheStores.end()) {
            return;
        }

        RuntimeClusterCacheStore& store = it->second;
        for (const auto& node : store.mOccupation) {
            ReleaseClusterData(node.second);
        }
        for (const auto& node : store.mSubcluster) {
            ReleaseClusterData(node.second);
        }

        gRuntimeClusterCacheStores.erase(it);
    }

    /**
     * Address: 0x00932B70 (FUN_00932B70, sub_932B70)
     *
     * What it does:
     * Finds an occupation-key cache entry.
     */
    [[nodiscard]] CacheLookupResult FindOccupationCacheEntry(
        void* const cacheTreeBase,
        const gpg::HaStar::OccupationData& occupationData
    )
    {
        RuntimeClusterCacheStore& store = RuntimeClusterCacheForBase(cacheTreeBase);
        const OccupationCacheKey key = MakeOccupationCacheKey(occupationData);
        const auto it = store.mOccupation.find(key);
        if (it == store.mOccupation.end()) {
            return {};
        }

        CacheLookupResult result{};
        result.mData = it->second;
        result.mFound = true;
        return result;
    }

    /**
     * Address: 0x00932C60 (FUN_00932C60, sub_932C60)
     *
     * What it does:
     * Finds a subcluster-key cache entry.
     */
    [[nodiscard]] CacheLookupResult FindSubclusterCacheEntry(
        void* const cacheTreeBase,
        const gpg::HaStar::SubclusterData& subclusterData
    )
    {
        RuntimeClusterCacheStore& store = RuntimeClusterCacheForBase(cacheTreeBase);
        const SubclusterCacheKey key = MakeSubclusterCacheKey(subclusterData);
        const auto it = store.mSubcluster.find(key);
        if (it == store.mSubcluster.end()) {
            return {};
        }

        CacheLookupResult result{};
        result.mData = it->second;
        result.mFound = true;
        return result;
    }

    /**
     * Address: 0x009348A0 (FUN_009348A0, sub_9348A0)
     *
     * What it does:
     * Inserts an occupation-key cache entry and reports insertion status.
     */
    [[nodiscard]] CacheInsertResult InsertOccupationCacheEntry(
        void* const cacheTreeBase,
        const gpg::HaStar::OccupationData& occupationData,
        gpg::HaStar::Cluster::Data* const clusterData
    )
    {
        RuntimeClusterCacheStore& store = RuntimeClusterCacheForBase(cacheTreeBase);
        const OccupationCacheKey key = MakeOccupationCacheKey(occupationData);
        const auto insertResult = store.mOccupation.emplace(key, clusterData);
        const auto it = insertResult.first;
        const bool inserted = insertResult.second;
        if (inserted) {
            RetainClusterData(clusterData);
        }

        CacheInsertResult result{};
        result.mData = it->second;
        result.mInserted = inserted;
        return result;
    }

    /**
     * Address: 0x00934BE0 (FUN_00934BE0, sub_934BE0)
     *
     * What it does:
     * Inserts a subcluster-key cache entry and reports insertion status.
     */
    [[nodiscard]] CacheInsertResult InsertSubclusterCacheEntry(
        void* const cacheTreeBase,
        const gpg::HaStar::SubclusterData& subclusterData,
        gpg::HaStar::Cluster::Data* const clusterData
    )
    {
        RuntimeClusterCacheStore& store = RuntimeClusterCacheForBase(cacheTreeBase);
        const SubclusterCacheKey key = MakeSubclusterCacheKey(subclusterData);
        const auto insertResult = store.mSubcluster.emplace(key, clusterData);
        const auto it = insertResult.first;
        const bool inserted = insertResult.second;
        if (inserted) {
            RetainClusterData(clusterData);
        }

        CacheInsertResult result{};
        result.mData = it->second;
        result.mInserted = inserted;
        return result;
    }

    /**
     * Address: 0x00934F80 (FUN_00934F80, sub_934F80)
     *
     * What it does:
     * Fetches/builds occupation cache entry and returns a retained cluster handle.
     */
    gpg::HaStar::Cluster* ClusterCacheFetchFromOccupationTree(
        void* const cacheTreeBase,
        gpg::HaStar::Cluster* const outCluster,
        const gpg::HaStar::OccupationData* const occupationData
    )
    {
        if (!outCluster || !occupationData) {
            return outCluster;
        }

        const CacheLookupResult found = FindOccupationCacheEntry(cacheTreeBase, *occupationData);
        if (found.mFound) {
            SetClusterData(*outCluster, found.mData);
            return outCluster;
        }

        gpg::HaStar::Cluster built = gpg::HaStar::ClusterBuild(*occupationData);
        const CacheInsertResult inserted = InsertOccupationCacheEntry(cacheTreeBase, *occupationData, built.mData);
        if (!inserted.mInserted) {
            gpg::HandleAssertFailure(
                "ins.second",
                87,
                "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\ClusterCache.cpp"
            );
        }

        SetClusterData(*outCluster, inserted.mData);
        return outCluster;
    }

    /**
     * Address: 0x009350F0 (FUN_009350F0, sub_9350F0)
     *
     * What it does:
     * Fetches/builds subcluster cache entry and returns a retained cluster handle.
     */
    gpg::HaStar::Cluster* ClusterCacheFetchFromSubclusterTree(
        void* const subclusterTree,
        gpg::HaStar::Cluster* const outCluster,
        const gpg::HaStar::SubclusterData* const subclusterData
    )
    {
        if (!outCluster || !subclusterData) {
            return outCluster;
        }

        void* const cacheTreeBase = ResolveCacheTreeBaseFromSubclusterPtr(subclusterTree);
        const CacheLookupResult found = FindSubclusterCacheEntry(cacheTreeBase, *subclusterData);
        if (found.mFound) {
            SetClusterData(*outCluster, found.mData);
            return outCluster;
        }

        gpg::HaStar::Cluster built = gpg::HaStar::ClusterBuild(*subclusterData);
        const CacheInsertResult inserted = InsertSubclusterCacheEntry(cacheTreeBase, *subclusterData, built.mData);
        if (!inserted.mInserted) {
            gpg::HandleAssertFailure(
                "ins.second",
                87,
                "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\ClusterCache.cpp"
            );
        }

        SetClusterData(*outCluster, inserted.mData);
        return outCluster;
    }

    void DestroySubclusterStorage(gpg::HaStar::Subcluster& subcluster)
    {
        if (!subcluster.mArray) {
            subcluster.mWidth = 0;
            subcluster.mHeight = 0;
            return;
        }

        auto* const header = reinterpret_cast<std::uint32_t*>(subcluster.mArray) - 1;
        const std::uint32_t clusterCount = *header;
        for (std::uint32_t i = 0; i < clusterCount; ++i) {
            subcluster.mArray[i].~Cluster();
        }

        operator delete[](header);
        subcluster.mArray = nullptr;
        subcluster.mWidth = 0;
        subcluster.mHeight = 0;
    }

    void CreateSubclusterStorage(gpg::HaStar::Subcluster& subcluster, const int width, const int height)
    {
        subcluster.mWidth = width;
        subcluster.mHeight = height;

        const int clusterCount = width * height;
        if (clusterCount <= 0) {
            subcluster.mArray = nullptr;
            return;
        }

        const std::size_t bytes =
            sizeof(std::uint32_t) + static_cast<std::size_t>(clusterCount) * sizeof(gpg::HaStar::Cluster);
        auto* const raw = static_cast<std::uint8_t*>(operator new[](bytes));

        *reinterpret_cast<std::uint32_t*>(raw) = static_cast<std::uint32_t>(clusterCount);
        subcluster.mArray = reinterpret_cast<gpg::HaStar::Cluster*>(raw + sizeof(std::uint32_t));

        for (int i = 0; i < clusterCount; ++i) {
            new (&subcluster.mArray[i]) gpg::HaStar::Cluster();
        }
    }
}

namespace gpg::HaStar
{
/**
 * Address: 0x00765840 (FUN_00765840, ??0Cluster@HaStar@gpg@@QAE@ABV012@@Z)
 */
Cluster::Cluster(const Cluster& other)
    : mData(other.mData)
{
    RetainClusterData(mData);
}

/**
 * Address: 0x008E3450 (FUN_008E3450, ??4Cluster@HaStar@gpg@@QAEAAV012@ABV012@@Z)
 */
Cluster& Cluster::operator=(const Cluster& other)
{
    AssignClusterData(*this, other);
    return *this;
}

/**
 * Address: 0x00765860 (FUN_00765860, ??1Cluster@HaStar@gpg@@QAE@XZ)
 */
Cluster::~Cluster()
{
    ReleaseClusterData(mData);
}

/**
 * Address: 0x0092D8B0 (FUN_0092D8B0, ?QuantizeEdgeCost@Cluster@HaStar@gpg@@SAMMM@Z)
 *
 * What it does:
 * Quantizes one edge-cost ratio into a 0..31 cost bucket.
 */
float Cluster::QuantizeEdgeCost(const float a, const float b)
{
    const float scaled = std::log(a / b) * 6.0f;
    int quantized = static_cast<int>(std::ceil(scaled));
    if (quantized > 31) {
        quantized = 31;
    }
    if (quantized < 0) {
        quantized = 0;
    }
    return static_cast<float>(quantized);
}

/**
 * Address: 0x009552D0 (FUN_009552D0,
 * ?ClusterBuild@HaStar@gpg@@YA?AVCluster@12@ABUOccupationData@12@@Z)
 */
Cluster ClusterBuild(const OccupationData& occupationData)
{
    (void)occupationData;

    Cluster cluster{};
    auto* const data = static_cast<Cluster::Data*>(operator new[](sizeof(Cluster::Data)));
    data->mRefs = 1;
    data->mReleaseObject = nullptr;
    data->mReleaseArg = 0u;
    cluster.mData = data;
    return cluster;
}

/**
 * Address: 0x009310E0 (FUN_009310E0,
 * ?ClusterBuild@HaStar@gpg@@YA?AVCluster@12@ABUSubclusterData@12@@Z)
 */
Cluster ClusterBuild(const SubclusterData& subclusterData)
{
    [[maybe_unused]] ClusterSearchScratch searchScratch{};
    searchScratch.Reset();
    (void)subclusterData;

    Cluster cluster{};
    auto* const data = static_cast<Cluster::Data*>(operator new[](sizeof(Cluster::Data)));
    data->mRefs = 1;
    data->mReleaseObject = nullptr;
    data->mReleaseArg = 0u;
    cluster.mData = data;
    return cluster;
}

/**
 * Address: 0x00931FB0 (FUN_00931FB0, ??1WeakPtr_ClusterCache@Moho@@QAE@@Z)
 *
 * Note:
 * ClusterCache shares the same two-word layout as the weak/shared cache handle in the original binary.
 */
ClusterCache::~ClusterCache()
{
    const bool releasedLast = ReleaseSharedCount(mCacheRefs);
    if (!mCacheRefs || releasedLast) {
        ReleaseRuntimeClusterCacheStore(mCacheTree);
    }
    mCacheRefs = nullptr;
    mCacheTree = nullptr;
}

/**
 * Address: 0x008E3420 (FUN_008E3420, ??0struct_Subcluster@@QAE@@Z)
 */
Subcluster::Subcluster()
    : mArray(nullptr), mWidth(0), mHeight(0)
{
}

/**
 * Address: 0x008E36C0 (FUN_008E36C0, ??0struct_Subcluster@@QAE@HH@Z)
 */
Subcluster::Subcluster(const int width, const int height)
    : mArray(nullptr), mWidth(0), mHeight(0)
{
    CreateSubclusterStorage(*this, width, height);
}

/**
 * Address: 0x0076BF30 (FUN_0076BF30, ??1struct_Subcluster@@QAE@@Z)
 */
Subcluster::~Subcluster()
{
    DestroySubclusterStorage(*this);
}

/**
 * Address: 0x008E3CD0 (FUN_008E3CD0,
 * ??0ClusterMap@HaStar@gpg@@QAE@PAUIOccupationSource@12@IIABVClusterCache@12@IABV?$Rect2@H@2@@Z)
 */
ClusterMap::ClusterMap(
    IOccupationSource* const source,
    const unsigned int widthM,
    const unsigned int heightM,
    const ClusterCache& cache,
    const unsigned int numLevels,
    const gpg::Rect2i& area
)
    : mNumLevels(numLevels)
    , mWidth(0)
    , mHeight(0)
    , mSrc(source)
    , mCache(cache)
    , mLevels{}
    , mCheckLevels{}
    , mIsDone(0u)
    , pad_89{ 0u, 0u, 0u }
    , mProgress(0u)
    , mArea(area)
{
    RetainSharedCount(mCache.mCacheRefs);

    if (mNumLevels >= kClusterSizeCount) {
        gpg::HandleAssertFailure(
            "numlevels <= MAX_LEVEL",
            29,
            "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\ClusterMap.cpp"
        );
        mNumLevels = static_cast<std::uint32_t>(kClusterSizeCount - 1);
    }

    const unsigned int levelSize = kClusterSizeByLevel[mNumLevels];
    const int alignMask = ~static_cast<int>(levelSize - 1u);
    mWidth = alignMask & static_cast<int>(levelSize + widthM - 1u);
    mHeight = alignMask & static_cast<int>(levelSize + heightM - 1u);

    for (std::uint32_t level = 1u; level <= mNumLevels; ++level) {
        const unsigned int clusterSize = kClusterSizeByLevel[level];
        const unsigned int levelWidth = static_cast<unsigned int>(mWidth) / clusterSize;
        const unsigned int levelHeight = static_cast<unsigned int>(mHeight) / clusterSize;

        Subcluster& levelStorage = mLevels[level];
        DestroySubclusterStorage(levelStorage);
        CreateSubclusterStorage(levelStorage, static_cast<int>(levelWidth), static_cast<int>(levelHeight));

        mCheckLevels[level].Reset(levelWidth, levelHeight);
        mCheckLevels[level].FillRect(0, 0, static_cast<int>(levelWidth), static_cast<int>(levelHeight), true);
    }
}

/**
 * Address: 0x0076BB60 (FUN_0076BB60, ??1ClusterMap@HaStar@gpg@@QAE@@Z)
 */
ClusterMap::~ClusterMap() = default;

/**
 * Address: 0x00935420 (FUN_00935420,
 * ?FetchCluster@ClusterCache@HaStar@gpg@@QAE?AVCluster@23@ABUOccupationData@23@@Z)
 */
Cluster ClusterCache::FetchCluster(const OccupationData& occupationData)
{
    Cluster outCluster{};
    ClusterCacheFetchFromOccupationTree(mCacheTree, &outCluster, &occupationData);
    return outCluster;
}

/**
 * Address: 0x00935450 (FUN_00935450,
 * ?FetchCluster@ClusterCache@HaStar@gpg@@QAE?AVCluster@23@ABUSubclusterData@23@@Z)
 */
Cluster ClusterCache::FetchCluster(const SubclusterData& subclusterData)
{
    Cluster outCluster{};
    void* subclusterTree = nullptr;
    if (mCacheTree) {
        auto* const cacheTree = reinterpret_cast<ClusterCacheTreeLayout*>(mCacheTree);
        subclusterTree = &cacheTree->mSubclusterTree;
    }
    ClusterCacheFetchFromSubclusterTree(subclusterTree, &outCluster, &subclusterData);
    return outCluster;
}

/**
 * Address: 0x009542D0 (FUN_009542D0,
 * ?ClusterRect@HaStar@gpg@@YA?AV?$Rect2@H@2@HHEHH@Z_0)
 */
gpg::Rect2i ClusterRect(
    const int worldX,
    const int worldZ,
    const std::uint8_t level,
    const int maxClusterX,
    const int maxClusterZ
)
{
    const std::uint8_t clusterSize = (level < kClusterSizeCount)
        ? kClusterSizeByLevel[level]
        : kClusterSizeByLevel[kClusterSizeCount - 1];
    const int alignMask = -static_cast<int>(clusterSize);
    const int clusterSizeSigned = static_cast<int>(clusterSize);

    gpg::Rect2i out{};
    out.z1 = (alignMask & (clusterSizeSigned + worldZ)) + 1;
    if (out.z1 >= maxClusterZ) {
        out.z1 = maxClusterZ;
    }

    out.x1 = (alignMask & (clusterSizeSigned + worldX)) + 1;
    if (out.x1 >= maxClusterX) {
        out.x1 = maxClusterX;
    }

    out.z0 = alignMask & (worldZ - 1);
    if (out.z0 < 0) {
        out.z0 = 0;
    }

    out.x0 = alignMask & (worldX - 1);
    if (out.x0 < 0) {
        out.x0 = 0;
    }

    return out;
}

/**
 * Address: 0x00954340 (FUN_00954340,
 * ?ClusterIndexRect@HaStar@gpg@@YA?AV?$Rect2@H@2@HHEHH@Z)
 */
gpg::Rect2i ClusterIndexRect(
    const int worldX,
    const int worldZ,
    const std::uint8_t level,
    const int maxClusterX,
    const int maxClusterZ
)
{
    const std::uint8_t shift = (level < kClusterSizeLog2Count)
        ? kClusterSizeLog2ByLevel[level]
        : kClusterSizeLog2ByLevel[kClusterSizeLog2Count - 1];

    gpg::Rect2i out{};
    out.z1 = (worldZ >> shift) + 1;
    if (out.z1 >= maxClusterZ) {
        out.z1 = maxClusterZ;
    }

    out.x1 = (worldX >> shift) + 1;
    if (out.x1 >= maxClusterX) {
        out.x1 = maxClusterX;
    }

    out.z0 = (worldZ - 1) >> shift;
    if (out.z0 < 0) {
        out.z0 = 0;
    }

    out.x0 = (worldX - 1) >> shift;
    if (out.x0 < 0) {
        out.x0 = 0;
    }

    return out;
}

/**
 * Address: 0x008E33E0 (FUN_008E33E0,
 * ?ClusterIndexRect@ClusterMap@HaStar@gpg@@QBE?AV?$Rect2@H@3@HHE@Z)
 */
gpg::Rect2i ClusterMap::ClusterIndexRect(const int worldX, const int worldZ, const std::uint8_t level) const
{
    const std::uint8_t shift = (level < kClusterSizeLog2Count)
        ? kClusterSizeLog2ByLevel[level]
        : kClusterSizeLog2ByLevel[kClusterSizeLog2Count - 1];

    return gpg::HaStar::ClusterIndexRect(worldX, worldZ, level, (mWidth >> shift), (mHeight >> shift));
}

/**
 * Address: 0x008E35A0 (FUN_008E35A0,
 * ?ClusterIndexRect@ClusterMap@HaStar@gpg@@QBE?AV?$Rect2@H@3@ABV43@E@Z)
 * Alt binary: 0x10035650 (FUN_10035650, ?...@Z_0)
 */
gpg::Rect2i ClusterMap::ClusterIndexRect(const gpg::Rect2i& worldRect, const std::uint8_t level) const
{
    const std::uint8_t shift = kClusterSizeLog2ByLevel[level];

    gpg::Rect2i out{};
    out.z1 = ((worldRect.z1 - 1) >> shift) + 1;
    const int maxZ = (mHeight >> shift);
    if (out.z1 >= maxZ) {
        out.z1 = maxZ;
    }

    out.x1 = ((worldRect.x1 - 1) >> shift) + 1;
    const int maxX = (mWidth >> shift);
    if (out.x1 >= maxX) {
        out.x1 = maxX;
    }

    out.z0 = (worldRect.z0 - 1) >> shift;
    if (out.z0 < 0) {
        out.z0 = 0;
    }

    out.x0 = (worldRect.x0 - 1) >> shift;
    if (out.x0 < 0) {
        out.x0 = 0;
    }

    return out;
}

/**
 * Address: 0x008E3620 (FUN_008E3620,
 * ?DirtyRect@ClusterMap@HaStar@gpg@@QAEXABV?$Rect2@H@3@@Z_0)
 */
void ClusterMap::DirtyRect(const gpg::Rect2i& worldRect)
{
    gpg::Rect2i expandedRect{};
    expandedRect.x0 = mArea.x0 + worldRect.x0;
    expandedRect.z0 = mArea.z0 + worldRect.z0;
    expandedRect.x1 = mArea.x1 + worldRect.x1;
    expandedRect.z1 = mArea.z1 + worldRect.z1;

    mIsDone = 0u;

    if (mNumLevels == 0u) {
        return;
    }

    gpg::BitArray2D* levelBits = &mCheckLevels[1];
    for (std::uint8_t level = 1; level <= static_cast<std::uint8_t>(mNumLevels); ++level, ++levelBits) {
        const gpg::Rect2i clusterRect = ClusterIndexRect(expandedRect, level);
        levelBits->FillRect(
            clusterRect.x0,
            clusterRect.z0,
            clusterRect.x1 - clusterRect.x0,
            clusterRect.z1 - clusterRect.z0,
            true
        );
    }
}

/**
 * Address: 0x008E37D0 (FUN_008E37D0,
 * ?WorkOnCluster@ClusterMap@HaStar@gpg@@QAE_NHHHAAH@Z)
 */
bool ClusterMap::WorkOnCluster(const int width, const int height, const int level, int& budget)
{
    gpg::BitArray2D& checkLevel = mCheckLevels[level];
    const int bitMask = 1 << (height & 0x1F);
    const unsigned int rowWord = static_cast<unsigned int>(height) >> 5;
    const int bitIndex = width + static_cast<int>(rowWord * static_cast<unsigned int>(checkLevel.width));

    if ((checkLevel.ptr[bitIndex] & bitMask) == 0) {
        return true;
    }

    if (budget <= 0) {
        return false;
    }

    Cluster resolvedCluster{};

    if (level == 1) {
        OccupationData occupationData{};
        mSrc->GetOccupationData(8 * width, 8 * height, occupationData);
        resolvedCluster = mCache.FetchCluster(occupationData);
        budget -= 10;
    }
    else {
        SubclusterData subclusterData{};
        subclusterData.mLevel = level - 1;

        const Subcluster& childLevel = mLevels[level - 1];
        int writeIndex = 0;
        for (int childY = 4 * height; childY < 4 * height + 4; ++childY) {
            for (int childX = 4 * width; childX < 4 * width + 4; ++childX) {
                if (!WorkOnCluster(childX, childY, level - 1, budget)) {
                    return false;
                }

                const int childIndex = childX + childY * childLevel.mWidth;
                AssignClusterData(subclusterData.mClusters[writeIndex], childLevel.mArray[childIndex]);
                ++writeIndex;
            }
        }

        resolvedCluster = mCache.FetchCluster(subclusterData);
        budget -= 10;
    }

    Subcluster& outLevel = mLevels[level];
    const int outIndex = width + height * outLevel.mWidth;
    AssignClusterData(outLevel.mArray[outIndex], resolvedCluster);

    checkLevel.ptr[bitIndex] &= ~bitMask;
    return true;
}

/**
 * Address: 0x008E3BC0 (FUN_008E3BC0,
 * ?EnsureClusterExists@ClusterMap@HaStar@gpg@@QAEXHHH@Z)
 */
void ClusterMap::EnsureClusterExists(const int width, const unsigned int height, const int level)
{
    int clusterBudget = INT_MAX;
    while (!WorkOnCluster(width, static_cast<int>(height), level, clusterBudget)) {
        clusterBudget = INT_MAX;
    }
}

/**
 * Address: 0x008E3C00 (FUN_008E3C00,
 * ?BackgroundWork@ClusterMap@HaStar@gpg@@QAEXAAH@Z)
 */
void ClusterMap::BackgroundWork(int& budget)
{
    const bool unlimitedBudget = (budget == INT_MAX);

    while (mIsDone == 0u) {
        if (budget <= 0) {
            break;
        }

        unsigned int clusterX = 0u;
        unsigned int clusterY = 0u;
        if (mCheckLevels[mNumLevels].AnyBitSet(&clusterX, &clusterY, &mProgress)) {
            if (unlimitedBudget) {
                budget = INT_MAX;
            }

            WorkOnCluster(
                static_cast<int>(clusterX),
                static_cast<int>(clusterY),
                static_cast<int>(mNumLevels),
                budget
            );
        }
        else {
            mIsDone = 1u;
        }
    }
}
}
