#include "Cluster.h"

#include <algorithm>
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

#include "gpg/core/containers/FastVectorInsertLanes.h"
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

    struct SharedCountOwnerRuntimeView
    {
        void* payload;
        SharedCountControl* control;
    };
    static_assert(sizeof(SharedCountOwnerRuntimeView) == 0x8, "SharedCountOwnerRuntimeView size must be 0x8");
    static_assert(
      offsetof(SharedCountOwnerRuntimeView, control) == 0x4,
      "SharedCountOwnerRuntimeView::control offset must be 0x4"
    );

    /**
     * Address: 0x008E34E0 (FUN_008E34E0)
     *
     * What it does:
     * Releases one shared/weak control block referenced from owner offset
     * `+0x4`, invoking control vtable lanes when reference counters reach zero.
     */
    [[maybe_unused]] volatile long* ReleaseOwnerSharedCountControlLane(
      SharedCountOwnerRuntimeView* const owner
    )
    {
      SharedCountControl* const control = owner->control;
      volatile long* result = nullptr;
      if (control == nullptr) {
        return result;
      }

      result = &control->useCount;
      if (_InterlockedExchangeAdd(&control->useCount, -1) == 1) {
        using ControlFn = void(__thiscall*)(SharedCountControl*);
        auto* const disposeFn = reinterpret_cast<ControlFn>(control->vtable[1]);
        disposeFn(control);

        result = &control->weakCount;
        if (_InterlockedExchangeAdd(&control->weakCount, -1) == 1) {
          auto* const destroyFn = reinterpret_cast<ControlFn>(control->vtable[2]);
          destroyFn(control);
          result = reinterpret_cast<volatile long*>(control);
        }
      }

      return result;
    }

    constexpr std::uint8_t kClusterSizeLog2ByLevel[] = { 0u, 3u, 5u, 7u };
    constexpr std::size_t kClusterSizeLog2Count = sizeof(kClusterSizeLog2ByLevel) / sizeof(kClusterSizeLog2ByLevel[0]);
    constexpr std::uint8_t kClusterSizeByLevel[] = { 1u, 8u, 32u, 128u };
    constexpr std::size_t kClusterSizeCount = sizeof(kClusterSizeByLevel) / sizeof(kClusterSizeByLevel[0]);

    constexpr std::uint32_t kOccupationKeySalt = 0x7BEF2693u;
    constexpr std::uint32_t kSubclusterKeySalt = 0x0001F31Du;

    struct IOccupationSourceRuntimeView
    {
        void* mVtable = nullptr;
    };
    static_assert(sizeof(IOccupationSourceRuntimeView) == 0x04, "IOccupationSourceRuntimeView size must be 0x04");

    class OccupationSourceVTableProbe final : public gpg::HaStar::IOccupationSource
    {
    public:
        void GetOccupationData(const int, const int, gpg::HaStar::OccupationData&) override
        {
        }
    };

    [[nodiscard]] void* RecoveredOccupationSourceVTable() noexcept
    {
        static OccupationSourceVTableProbe probe;
        return *reinterpret_cast<void**>(&probe);
    }

    [[nodiscard]] gpg::HaStar::IOccupationSource* WriteOccupationSourceVTable(gpg::HaStar::IOccupationSource* const source)
    {
        auto& runtimeView = reinterpret_cast<IOccupationSourceRuntimeView&>(*source);
        runtimeView.mVtable = RecoveredOccupationSourceVTable();
        return source;
    }

    struct FastVectorShortRuntimeView
    {
        std::int16_t* start;        // +0x00
        std::int16_t* end;          // +0x04
        std::int16_t* capacity;     // +0x08
        std::int16_t* inlineOrigin; // +0x0C
    };
    static_assert(sizeof(FastVectorShortRuntimeView) == 0x10, "FastVectorShortRuntimeView size must be 0x10");

    constexpr std::array<std::uint8_t, 4> kOccupationEdgeStartBit = { 0u, 0u, 0u, 8u };
    constexpr std::array<std::uint8_t, 4> kOccupationEdgeStartLayer = { 0u, 8u, 0u, 0u };
    constexpr std::array<std::uint8_t, 4> kOccupationEdgeBitStep = { 1u, 1u, 0u, 0u };
    constexpr std::array<std::uint8_t, 4> kOccupationEdgeLayerStep = { 0u, 0u, 1u, 1u };

    void AppendPackedEdgeWord(
      FastVectorShortRuntimeView& outEdges,
      const std::uint8_t lowByte,
      const std::uint8_t highByte
    )
    {
      const std::uint16_t packed = static_cast<std::uint16_t>(lowByte)
        | static_cast<std::uint16_t>(static_cast<std::uint16_t>(highByte) << 8u);

      if (outEdges.end == outEdges.capacity) {
        auto& insertView = reinterpret_cast<gpg::core::legacy::FastVectorInsertRuntimeView&>(outEdges);
        const std::byte* const sourceBegin = reinterpret_cast<const std::byte*>(&packed);
        const std::byte* const sourceEnd = sourceBegin + sizeof(packed);
        (void)gpg::core::legacy::AppendRangeWordLane(
          insertView,
          reinterpret_cast<std::byte*>(outEdges.end),
          sourceBegin,
          sourceEnd
        );
        return;
      }

      if (outEdges.end != nullptr) {
        *outEdges.end = static_cast<std::int16_t>(packed);
      }
      ++outEdges.end;
    }

    /**
     * Address: 0x009550E0 (FUN_009550E0, gpg::HaStar::ClusterBuild occupation edge extraction lane)
     *
     * What it does:
     * Scans four occupancy edge lanes, emits packed edge-contact markers into
     * `outEdges`, sorts them, and removes duplicates in-place.
     */
    [[maybe_unused]] std::int16_t* BuildOccupationEdgeContacts(
      const gpg::HaStar::OccupationData& occupationData,
      FastVectorShortRuntimeView& outEdges
    )
    {
      for (std::uint32_t edgeIndex = 0; edgeIndex < 4u; ++edgeIndex) {
        std::uint8_t currentBit = kOccupationEdgeStartBit[edgeIndex];
        std::uint8_t currentLayer = kOccupationEdgeStartLayer[edgeIndex];
        std::uint8_t runStart = 0xFFu;
        std::uint8_t runEnd = 0xFFu;

        for (std::uint8_t step = 0u; step <= 8u; ++step) {
          const bool occupied =
            (occupationData.mWords[currentLayer] & (1u << currentBit)) != 0u;
          if (occupied) {
            runEnd = step;
            if (runStart == 0xFFu) {
              runStart = step;
            }
          }

          if (runStart != 0xFFu && (step == 8u || step != runEnd)) {
            std::uint8_t midpoint = 0u;
            if (runStart <= 4u && runEnd >= 4u) {
              midpoint = 4u;
            } else if (runStart == 0u) {
              midpoint = 0u;
            } else if (runEnd == 8u) {
              midpoint = 8u;
            } else {
              midpoint = static_cast<std::uint8_t>(
                (static_cast<std::uint32_t>(runStart)
                  + static_cast<std::uint32_t>(runEnd)
                  + (runEnd < 4u ? 1u : 0u))
                >> 1u
              );
            }

            if (kOccupationEdgeBitStep[edgeIndex] != 0u) {
              AppendPackedEdgeWord(outEdges, midpoint, currentLayer);
            } else {
              AppendPackedEdgeWord(outEdges, currentBit, midpoint);
            }

            runStart = 0xFFu;
            runEnd = 0xFFu;
          }

          currentBit = static_cast<std::uint8_t>(currentBit + kOccupationEdgeBitStep[edgeIndex]);
          currentLayer = static_cast<std::uint8_t>(currentLayer + kOccupationEdgeLayerStep[edgeIndex]);
        }
      }

      std::sort(outEdges.start, outEdges.end);
      outEdges.end = std::unique(outEdges.start, outEdges.end);
      return outEdges.end;
    }

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

        /**
         * What it does:
         * Releases the subcluster ring-list backing storage and bucket
         * vector when the container is destroyed. Mirrors the binary
         * teardown path that runs FUN_00933380 before freeing
         * `mVec.mFirst` storage.
         */
        ~SubclusterCacheVectorState();
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

    struct ClusterArray16WithTailLanesRuntimeView
    {
        gpg::HaStar::Cluster lanes[16];
        std::uint32_t lane40;
        std::uint32_t lane44;
    };
    static_assert(
        sizeof(ClusterArray16WithTailLanesRuntimeView) == 0x48,
        "ClusterArray16WithTailLanesRuntimeView size must be 0x48"
    );
    static_assert(
        offsetof(ClusterArray16WithTailLanesRuntimeView, lane40) == 0x40,
        "ClusterArray16WithTailLanesRuntimeView::lane40 offset must be 0x40"
    );
    static_assert(
        offsetof(ClusterArray16WithTailLanesRuntimeView, lane44) == 0x44,
        "ClusterArray16WithTailLanesRuntimeView::lane44 offset must be 0x44"
    );

    /**
     * Address: 0x00932500 (FUN_00932500, sub_932500)
     *
     * What it does:
     * Copy-constructs one 16-cluster lane block and copies both tail dword
     * metadata lanes.
     */
    [[maybe_unused]] ClusterArray16WithTailLanesRuntimeView* CopyConstructClusterArray16WithTailLanes(
        ClusterArray16WithTailLanesRuntimeView* const destination,
        const ClusterArray16WithTailLanesRuntimeView& source
    )
    {
        std::size_t constructedCount = 0u;
        try {
            while (constructedCount < 16u) {
                ::new (static_cast<void*>(&destination->lanes[constructedCount]))
                    gpg::HaStar::Cluster(source.lanes[constructedCount]);
                ++constructedCount;
            }
        }
        catch (...) {
            while (constructedCount != 0u) {
                --constructedCount;
                destination->lanes[constructedCount].~Cluster();
            }
            throw;
        }

        destination->lane40 = source.lane40;
        destination->lane44 = source.lane44;
        return destination;
    }

    /**
     * Address: 0x009326C0 (FUN_009326C0, sub_9326C0)
     *
     * What it does:
     * Copy-constructs one 16-cluster lane block, copies lane `+0x40`, and
     * overrides lane `+0x44` from caller-provided metadata.
     */
    [[maybe_unused]] ClusterArray16WithTailLanesRuntimeView* CopyConstructClusterArray16WithTailLanesOverrideTail44(
        ClusterArray16WithTailLanesRuntimeView* const destination,
        const ClusterArray16WithTailLanesRuntimeView& source,
        const std::uint32_t* const lane44Source
    )
    {
        ClusterArray16WithTailLanesRuntimeView* const result = CopyConstructClusterArray16WithTailLanes(destination, source);
        result->lane44 = *lane44Source;
        return result;
    }

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
     * Address: 0x00932E40 (FUN_00932E40, sub_932E40)
     *
     * What it does:
     * Dispatch adapter lane for one 32-bit range fill request.
     */
    [[maybe_unused]] void FillU32RangeDispatchA(
        std::uint32_t* const dst,
        const unsigned int count,
        const std::uint32_t value
    )
    {
        FillU32Range(dst, count, value);
    }

    /**
     * Address: 0x00933060 (FUN_00933060, sub_933060)
     *
     * What it does:
     * Fills one 32-bit value range with the same sentinel token and returns
     * one-past-end output cursor.
     */
    [[nodiscard]] std::uint32_t* FillU32RangeAndReturnEnd(
        std::uint32_t* const dst, const unsigned int count, const std::uint32_t value
    )
    {
        FillU32Range(dst, count, value);
        const auto beginAddress = reinterpret_cast<std::uintptr_t>(dst);
        const auto byteAdvance = static_cast<std::uintptr_t>(count) * sizeof(std::uint32_t);
        return reinterpret_cast<std::uint32_t*>(beginAddress + byteAdvance);
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
        // Binary codegen at `FUN_00931CE0` (0x00931CE0) combines the
        // `count > UINT_MAX/4 -> throw std::bad_alloc()` guard and the
        // `operator new(4 * count)` call into a single allocator helper
        // (`std::_Allocate<unsigned>` specialization for 4-byte elements);
        // this source expresses the same two-step behavior explicitly.
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

    void ClearSubclusterCacheRingList(SubclusterTreeHeader* header) noexcept;

    SubclusterCacheVectorState::~SubclusterCacheVectorState()
    {
        // Walk the subcluster ring and run the per-handle `~Cluster`
        // release path on every buffered 16-cluster node before freeing
        // the head sentinel itself. This is the FUN_00933380 lane the
        // binary runs from every container-teardown path.
        ClearSubclusterCacheRingList(&mList);
        ::operator delete(mList.mHead);
        mList.mHead = nullptr;

        if (mVec.mFirst != nullptr) {
            ::operator delete(mVec.mFirst);
            mVec.mFirst = nullptr;
            mVec.mLast = nullptr;
            mVec.mEnd = nullptr;
        }
    }

    /**
     * Intrusive ring-list node used by `SubclusterCacheVectorState::mList`.
     * Each non-sentinel node carries a trailing fixed-count array of 16
     * `Cluster` handles that must be destroyed via the per-handle `~Cluster`
     * release path before the node storage is freed.
     */
    struct SubclusterTreeNode
    {
        SubclusterTreeNode* mNext;                // +0x00
        SubclusterTreeNode* mPrev;                // +0x04
        gpg::HaStar::Cluster mClusters[16];       // +0x08
        // Trailing 8 bytes (+0x48..+0x4F) observed in the binary allocator
        // (`AllocateSubclusterTreeHead` at FUN_009327E0 allocates 0x50 bytes)
        // but not touched by the destroy pass; keep padding to preserve the
        // node footprint so allocations stay binary-shape-equivalent.
        std::uint8_t mTail48[0x08]{};             // +0x48
    };
    static_assert(offsetof(SubclusterTreeNode, mNext) == 0x00, "SubclusterTreeNode::mNext offset must be 0x00");
    static_assert(offsetof(SubclusterTreeNode, mPrev) == 0x04, "SubclusterTreeNode::mPrev offset must be 0x04");
    static_assert(offsetof(SubclusterTreeNode, mClusters) == 0x08, "SubclusterTreeNode::mClusters offset must be 0x08");
    static_assert(sizeof(SubclusterTreeNode) == 0x50, "SubclusterTreeNode size must be 0x50");

    /**
     * Address: 0x00933380 (FUN_00933380)
     *
     * IDA signature:
     * void __thiscall sub_933380(_DWORD *this);
     *
     * What it does:
     * Clears one subcluster-cache ring-list in place: snapshots the head
     * sentinel's `next` pointer, relinks the sentinel's `next`/`prev` to
     * self, zeros the size counter, then walks the snapshot chain
     * destroying each non-sentinel node. Each node's trailing
     * `Cluster[16]` array is run through the per-element `~Cluster`
     * destructor (binary uses `eh vector destructor iterator` with
     * element count 16 and element size 4) before the node storage is
     * released.
     *
     * The `this` parameter is a `SubclusterTreeHeader*`; its `mHead`
     * field (at +0x04) holds the sentinel node pointer. Invoked from the
     * subcluster-cache teardown lanes (binary callers 0x009335E3,
     * 0x009338D0, 0x009343B4, 0x00934500, 0x00934B60, 0x00934F07,
     * 0x009352E0).
     */
    void ClearSubclusterCacheRingList(SubclusterTreeHeader* const header) noexcept
    {
        if (header == nullptr || header->mHead == nullptr) {
            return;
        }

        auto* const sentinel = static_cast<SubclusterTreeNode*>(header->mHead);
        SubclusterTreeNode* cursor = sentinel->mNext;
        sentinel->mNext = sentinel;
        sentinel->mPrev = sentinel;
        header->mSize = 0u;

        while (cursor != sentinel) {
            SubclusterTreeNode* const nextNode = cursor->mNext;
            // Per-handle `Cluster` release (binary invokes
            // `eh vector destructor iterator` with n=16 over `cursor+0x08`).
            for (auto& clusterHandle : cursor->mClusters) {
                clusterHandle.~Cluster();
            }
            ::operator delete(cursor);
            cursor = nextNode;
        }
    }

    // Process-wide registry keyed by `ClusterCache::mCacheTree` base that
    // tracks any active subcluster ring-lists built against the cache. The
    // binary keeps these lists as `SubclusterCacheVectorState::mList` values
    // linked into the cache's lookup-bucket lane; when the outer cache is
    // released, each attached ring must be drained via FUN_00933380.
    using SubclusterRingRegistry = std::unordered_map<void*, std::vector<SubclusterTreeHeader*>>;
    [[nodiscard]] SubclusterRingRegistry& SubclusterRingsByCacheBase()
    {
        static SubclusterRingRegistry sRegistry;
        return sRegistry;
    }

    void DrainSubclusterRingsAttachedToCacheBase(void* const cacheTreeBase) noexcept
    {
        auto& registry = SubclusterRingsByCacheBase();
        const auto it = registry.find(cacheTreeBase);
        if (it == registry.end()) {
            return;
        }

        for (SubclusterTreeHeader* const header : it->second) {
            ClearSubclusterCacheRingList(header);
        }
        registry.erase(it);
    }

    [[maybe_unused]] void AttachSubclusterRingToCacheBase(
        void* const cacheTreeBase, SubclusterTreeHeader* const header
    )
    {
        if (cacheTreeBase == nullptr || header == nullptr) {
            return;
        }
        SubclusterRingsByCacheBase()[cacheTreeBase].push_back(header);
    }

    struct TripleWordValueRuntime
    {
        std::uint32_t lane0;
        std::uint32_t lane1;
        std::uint32_t lane2;
    };
    static_assert(sizeof(TripleWordValueRuntime) == 0x0C, "TripleWordValueRuntime size must be 0x0C");

    struct TripleWordVectorRuntime
    {
        std::uint32_t lane00;
        TripleWordValueRuntime* begin;
        TripleWordValueRuntime* end;
    };
    static_assert(sizeof(TripleWordVectorRuntime) == 0x0C, "TripleWordVectorRuntime size must be 0x0C");
    static_assert(offsetof(TripleWordVectorRuntime, begin) == 0x04, "TripleWordVectorRuntime::begin offset must be 0x04");
    static_assert(offsetof(TripleWordVectorRuntime, end) == 0x08, "TripleWordVectorRuntime::end offset must be 0x08");

    struct ByteCursorRuntime
    {
        std::uint8_t* cursor;
    };
    static_assert(sizeof(ByteCursorRuntime) == 0x04, "ByteCursorRuntime size must be 0x04");

    struct InlineByteCursorBuffer200Runtime
    {
        std::uint8_t* lane00;
        std::uint8_t* lane04;
        std::uint8_t* lane08;
        std::uint8_t* lane0C;
        std::uint8_t inlineStorage[200];
    };
    static_assert(sizeof(InlineByteCursorBuffer200Runtime) == 0xD8, "InlineByteCursorBuffer200Runtime size must be 0xD8");
    static_assert(
      offsetof(InlineByteCursorBuffer200Runtime, inlineStorage) == 0x10,
      "InlineByteCursorBuffer200Runtime::inlineStorage offset must be 0x10"
    );

    struct InlineByteCursorBufferRuntime
    {
      std::uint8_t* begin;        // +0x00
      std::uint8_t* current;      // +0x04
      std::uint8_t* end;          // +0x08
      std::uint8_t* inlineOrigin; // +0x0C
    };
    static_assert(sizeof(InlineByteCursorBufferRuntime) == 0x10, "InlineByteCursorBufferRuntime size must be 0x10");
    static_assert(
      offsetof(InlineByteCursorBufferRuntime, inlineOrigin) == 0x0C,
      "InlineByteCursorBufferRuntime::inlineOrigin offset must be 0x0C"
    );

    struct InlineByteCursorBuffer64Runtime
    {
      InlineByteCursorBufferRuntime state;
      std::uint8_t inlineStorage[64];
    };
    static_assert(sizeof(InlineByteCursorBuffer64Runtime) == 0x50, "InlineByteCursorBuffer64Runtime size must be 0x50");
    static_assert(
      offsetof(InlineByteCursorBuffer64Runtime, inlineStorage) == 0x10,
      "InlineByteCursorBuffer64Runtime::inlineStorage offset must be 0x10"
    );

    struct InlineByteCursorBuffer32Runtime
    {
      InlineByteCursorBufferRuntime state;
      std::uint8_t inlineStorage[32];
    };
    static_assert(sizeof(InlineByteCursorBuffer32Runtime) == 0x30, "InlineByteCursorBuffer32Runtime size must be 0x30");
    static_assert(
      offsetof(InlineByteCursorBuffer32Runtime, inlineStorage) == 0x10,
      "InlineByteCursorBuffer32Runtime::inlineStorage offset must be 0x10"
    );

    struct InlineByteCursorBuffer120Runtime
    {
      InlineByteCursorBufferRuntime state;
      std::uint8_t inlineStorage[120];
    };
    static_assert(sizeof(InlineByteCursorBuffer120Runtime) == 0x88, "InlineByteCursorBuffer120Runtime size must be 0x88");
    static_assert(
      offsetof(InlineByteCursorBuffer120Runtime, inlineStorage) == 0x10,
      "InlineByteCursorBuffer120Runtime::inlineStorage offset must be 0x10"
    );

    struct IntrusiveRingNodeRuntime
    {
      IntrusiveRingNodeRuntime* prev;
      IntrusiveRingNodeRuntime* next;
    };
    static_assert(sizeof(IntrusiveRingNodeRuntime) == 0x08, "IntrusiveRingNodeRuntime size must be 0x08");

    struct PathSearchFrontierNodeRuntime
    {
      PathSearchFrontierNodeRuntime* prev; // +0x00
      PathSearchFrontierNodeRuntime* next; // +0x04
      float pathCost;                      // +0x08
      std::uint8_t visitFlags;             // +0x0C
      std::uint8_t packedCell;             // +0x0D
      std::uint8_t pad0E[2];               // +0x0E
    };
    static_assert(sizeof(PathSearchFrontierNodeRuntime) == 0x10, "PathSearchFrontierNodeRuntime size must be 0x10");
    static_assert(
      offsetof(PathSearchFrontierNodeRuntime, pathCost) == 0x08,
      "PathSearchFrontierNodeRuntime::pathCost offset must be 0x08"
    );
    static_assert(
      offsetof(PathSearchFrontierNodeRuntime, visitFlags) == 0x0C,
      "PathSearchFrontierNodeRuntime::visitFlags offset must be 0x0C"
    );
    static_assert(
      offsetof(PathSearchFrontierNodeRuntime, packedCell) == 0x0D,
      "PathSearchFrontierNodeRuntime::packedCell offset must be 0x0D"
    );

    struct WordTableRuntime
    {
      std::uint16_t* words;
    };
    static_assert(sizeof(WordTableRuntime) == 0x04, "WordTableRuntime size must be 0x04");

    struct FourDwordWordRuntime
    {
        std::uint32_t lane00;
        std::uint32_t lane04;
        std::uint32_t lane08;
        std::uint32_t lane0C;
        std::uint16_t lane10;
        std::uint16_t pad12;
    };
    static_assert(sizeof(FourDwordWordRuntime) == 0x14, "FourDwordWordRuntime size must be 0x14");

    struct FourDwordWordAndTailRuntime
    {
        std::uint32_t lane00;
        std::uint32_t lane04;
        std::uint32_t lane08;
        std::uint32_t lane0C;
        std::uint16_t lane10;
        std::uint16_t pad12;
        std::uint32_t lane14;
    };
    static_assert(sizeof(FourDwordWordAndTailRuntime) == 0x18, "FourDwordWordAndTailRuntime size must be 0x18");

    struct DwordAndByteLanesRuntime
    {
        std::uint32_t lane00;
        std::uint8_t lane04;
    };

    struct ForwardLinkNodeRuntime
    {
        ForwardLinkNodeRuntime* lane00;
        ForwardLinkNodeRuntime* next;
    };
    static_assert(sizeof(ForwardLinkNodeRuntime) == 0x08, "ForwardLinkNodeRuntime size must be 0x08");

    struct NodeCursorRuntime
    {
        ForwardLinkNodeRuntime* node;
    };
    static_assert(sizeof(NodeCursorRuntime) == 0x04, "NodeCursorRuntime size must be 0x04");

    /**
     * Address: 0x0092DC50 (FUN_0092DC50)
     *
     * What it does:
     * Stores one triple-word vector begin cursor into `outCursor`.
     */
    [[maybe_unused]] TripleWordValueRuntime** StoreTripleWordVectorBeginCursor(
      const TripleWordVectorRuntime* const vectorState,
      TripleWordValueRuntime** const outCursor
    ) noexcept
    {
      *outCursor = vectorState->begin;
      return outCursor;
    }

    /**
     * Address: 0x0092DC60 (FUN_0092DC60)
     *
     * What it does:
     * Stores one triple-word vector end cursor into `outCursor`.
     */
    [[maybe_unused]] TripleWordValueRuntime** StoreTripleWordVectorEndCursor_A(
      const TripleWordVectorRuntime* const vectorState,
      TripleWordValueRuntime** const outCursor
    ) noexcept
    {
      *outCursor = vectorState->end;
      return outCursor;
    }

    /**
     * Address: 0x0092DE20 (FUN_0092DE20)
     *
     * What it does:
     * Returns one byte cursor advanced by eight bytes.
     */
    [[maybe_unused]] [[nodiscard]] std::uint8_t* ComputeByteCursorPlus8(
      const ByteCursorRuntime* const cursor
    ) noexcept
    {
      return cursor->cursor + 8;
    }

    /**
     * Address: 0x0092DE30 (FUN_0092DE30)
     *
     * What it does:
     * Writes one cursor advanced by `index * 12` bytes into `outCursor`.
     */
    [[maybe_unused]] ByteCursorRuntime* ComputeByteCursorPlusStride12(
      const ByteCursorRuntime* const baseCursor,
      ByteCursorRuntime* const outCursor,
      const int index
    ) noexcept
    {
      outCursor->cursor = baseCursor->cursor + static_cast<std::ptrdiff_t>(12 * index);
      return outCursor;
    }

    /**
     * Address: 0x0092DE50 (FUN_0092DE50)
     *
     * What it does:
     * Writes one cursor rewound by `index * 12` bytes into `outCursor`.
     */
    [[maybe_unused]] ByteCursorRuntime* ComputeByteCursorMinusStride12(
      const ByteCursorRuntime* const baseCursor,
      ByteCursorRuntime* const outCursor,
      const int index
    ) noexcept
    {
      outCursor->cursor = baseCursor->cursor - static_cast<std::ptrdiff_t>(12 * index);
      return outCursor;
    }

    /**
     * Address: 0x0092DE70 (FUN_0092DE70)
     *
     * What it does:
     * Writes one cursor advanced by `index * 4` bytes into `outCursor`.
     */
    [[maybe_unused]] ByteCursorRuntime* ComputeByteCursorPlusStride4(
      const ByteCursorRuntime* const baseCursor,
      ByteCursorRuntime* const outCursor,
      const int index
    ) noexcept
    {
      outCursor->cursor = baseCursor->cursor + static_cast<std::ptrdiff_t>(4 * index);
      return outCursor;
    }

    /**
     * Address: 0x0092E3C0 (FUN_0092E3C0)
     *
     * What it does:
     * Initializes one inline byte-buffer cursor block and returns `state`.
     */
    [[maybe_unused]] InlineByteCursorBuffer200Runtime* InitializeInlineByteCursorBuffer200(
      InlineByteCursorBuffer200Runtime* const state
    ) noexcept
    {
      std::uint8_t* const inlineOrigin = state->inlineStorage;
      state->lane00 = inlineOrigin;
      state->lane04 = inlineOrigin;
      state->lane08 = inlineOrigin + 200;
      state->lane0C = inlineOrigin;
      return state;
    }

    /**
     * Address: 0x009541F0 (FUN_009541F0)
     *
     * What it does:
     * Returns the current cursor lane from one inline byte-buffer state.
     */
    [[maybe_unused]] [[nodiscard]] std::uint8_t* InlineByteCursorCurrent(
      const InlineByteCursorBufferRuntime* const state
    ) noexcept
    {
      return state->current;
    }

    /**
     * Address: 0x00954200 (FUN_00954200)
     *
     * What it does:
     * Returns used-byte count (`current - begin`) for one inline byte-buffer.
     */
    [[maybe_unused]] [[nodiscard]] std::ptrdiff_t InlineByteCursorUsedBytes(
      const InlineByteCursorBufferRuntime* const state
    ) noexcept
    {
      return state->current - state->begin;
    }

    /**
     * Address: 0x00954210 (FUN_00954210)
     *
     * What it does:
     * Initializes one inline byte-buffer over `[origin, origin + capacity)`.
     */
    [[maybe_unused]] InlineByteCursorBufferRuntime* InitializeInlineByteCursorBufferRuntime(
      InlineByteCursorBufferRuntime* const state,
      std::uint8_t* const origin,
      const std::int32_t capacityBytes
    ) noexcept
    {
      state->begin = origin;
      state->current = origin;
      state->end = origin + capacityBytes;
      state->inlineOrigin = origin;
      return state;
    }

    /**
     * Address: 0x00954230 (FUN_00954230)
     *
     * What it does:
     * Returns total capacity in bytes (`end - begin`) for one inline buffer.
     */
    [[maybe_unused]] [[nodiscard]] std::ptrdiff_t InlineByteCursorCapacityBytes(
      const InlineByteCursorBufferRuntime* const state
    ) noexcept
    {
      return state->end - state->begin;
    }

    /**
     * Address: 0x009543B0 (FUN_009543B0)
     *
     * What it does:
     * Returns `begin + byteOffset` for one inline byte-buffer.
     */
    [[maybe_unused]] [[nodiscard]] std::uint8_t* InlineByteCursorAtOffset(
      const InlineByteCursorBufferRuntime* const state,
      const std::ptrdiff_t byteOffset
    ) noexcept
    {
      return state->begin + byteOffset;
    }

    /**
     * Address: 0x00954580 (FUN_00954580)
     *
     * What it does:
     * Initializes one 64-byte embedded inline buffer runtime state.
     */
    [[maybe_unused]] InlineByteCursorBuffer64Runtime* InitializeInlineByteCursorBuffer64Runtime(
      InlineByteCursorBuffer64Runtime* const state
    ) noexcept
    {
      (void)InitializeInlineByteCursorBufferRuntime(&state->state, state->inlineStorage, 64);
      return state;
    }

    /**
     * Address: 0x00954840 (FUN_00954840)
     *
     * What it does:
     * Initializes one intrusive ring node as a self-linked singleton.
     */
    [[maybe_unused]] IntrusiveRingNodeRuntime* InitializeIntrusiveRingNode_A(
      IntrusiveRingNodeRuntime* const node
    ) noexcept
    {
      node->prev = node;
      node->next = node;
      return node;
    }

    /**
     * Address: 0x00954850 (FUN_00954850)
     *
     * What it does:
     * Unlinks one intrusive ring node from neighbors and re-self-links it.
     */
    [[maybe_unused]] IntrusiveRingNodeRuntime* UnlinkIntrusiveRingNode_A(
      IntrusiveRingNodeRuntime* const node
    ) noexcept
    {
      node->prev->next = node->next;
      IntrusiveRingNodeRuntime* const previous = node->next;
      previous->prev = node->prev;
      node->next = node;
      node->prev = node;
      return previous;
    }

    /**
     * Address: 0x00954870 (FUN_00954870)
     *
     * What it does:
     * Returns the address of one 16-bit lane at `wordIndex`.
     */
    [[maybe_unused]] [[nodiscard]] std::uint16_t* ResolveWordTableEntryAddress(
      const WordTableRuntime* const table,
      const std::int32_t wordIndex
    ) noexcept
    {
      return table->words + wordIndex;
    }

    /**
     * Address: 0x00954880 (FUN_00954880)
     *
     * What it does:
     * Unlinks `node` and inserts it immediately before `anchor`.
     */
    [[maybe_unused]] IntrusiveRingNodeRuntime* RelinkIntrusiveRingNodeBeforeAnchor(
      IntrusiveRingNodeRuntime* const node,
      IntrusiveRingNodeRuntime* const anchor
    ) noexcept
    {
      node->prev->next = node->next;
      node->next->prev = node->prev;
      node->prev = anchor->prev;
      node->next = anchor;
      anchor->prev = node;
      node->prev->next = node;
      return node->prev;
    }

    /**
     * Address: 0x009548C0 (FUN_009548C0)
     *
     * What it does:
     * Alias lane that unlinks one intrusive ring node and re-self-links it.
     */
    [[maybe_unused]] IntrusiveRingNodeRuntime* UnlinkIntrusiveRingNode_B(
      IntrusiveRingNodeRuntime* const node
    ) noexcept
    {
      return UnlinkIntrusiveRingNode_A(node);
    }

    /**
     * Address: 0x009548E0 (FUN_009548E0)
     *
     * What it does:
     * Alias lane that initializes one intrusive ring node as self-linked.
     */
    [[maybe_unused]] IntrusiveRingNodeRuntime* InitializeIntrusiveRingNode_B(
      IntrusiveRingNodeRuntime* const node
    ) noexcept
    {
      return InitializeIntrusiveRingNode_A(node);
    }

    /**
     * Address: 0x00954930 (FUN_00954930)
     *
     * What it does:
     * Returns one intrusive node `next` link lane.
     */
    [[maybe_unused]] [[nodiscard]] IntrusiveRingNodeRuntime* GetIntrusiveRingNodeNext(
      const IntrusiveRingNodeRuntime* const node
    ) noexcept
    {
      return node->next;
    }

    /**
     * Address: 0x00954940 (FUN_00954940)
     *
     * What it does:
     * Initializes one path-frontier node as self-linked with zero cost/state
     * lanes.
     */
    [[maybe_unused]] PathSearchFrontierNodeRuntime* InitializePathSearchFrontierNode(
      PathSearchFrontierNodeRuntime* const node
    ) noexcept
    {
      node->next = node;
      node->prev = node;
      node->pathCost = 0.0f;
      node->visitFlags = 0;
      node->packedCell = 0;
      return node;
    }

    /**
     * Address: 0x00954980 (FUN_00954980)
     *
     * What it does:
     * Alias lane that unlinks one intrusive ring node and re-self-links it.
     */
    [[maybe_unused]] IntrusiveRingNodeRuntime* UnlinkIntrusiveRingNode_C(
      IntrusiveRingNodeRuntime* const node
    ) noexcept
    {
      return UnlinkIntrusiveRingNode_A(node);
    }

    /**
     * Address: 0x009549A0 (FUN_009549A0)
     *
     * What it does:
     * Initializes one 32-byte embedded inline buffer runtime state.
     */
    [[maybe_unused]] InlineByteCursorBuffer32Runtime* InitializeInlineByteCursorBuffer32Runtime(
      InlineByteCursorBuffer32Runtime* const state
    ) noexcept
    {
      (void)InitializeInlineByteCursorBufferRuntime(&state->state, state->inlineStorage, 32);
      return state;
    }

    /**
     * Address: 0x009549F0 (FUN_009549F0)
     *
     * What it does:
     * Initializes one 120-byte embedded inline buffer runtime state.
     */
    [[maybe_unused]] InlineByteCursorBuffer120Runtime* InitializeInlineByteCursorBuffer120Runtime(
      InlineByteCursorBuffer120Runtime* const state
    ) noexcept
    {
      (void)InitializeInlineByteCursorBufferRuntime(&state->state, state->inlineStorage, 120);
      return state;
    }

    /**
     * Address: 0x0092E490 (FUN_0092E490)
     *
     * What it does:
     * Stores one triple-word vector end cursor into `outCursor`.
     */
    [[maybe_unused]] TripleWordValueRuntime** StoreTripleWordVectorEndCursor_B(
      const TripleWordVectorRuntime* const vectorState,
      TripleWordValueRuntime** const outCursor
    ) noexcept
    {
      *outCursor = vectorState->end;
      return outCursor;
    }

    /**
     * Address: 0x0092E630 (FUN_0092E630)
     *
     * What it does:
     * Returns one byte cursor positioned one triple-word record before `end`.
     */
    [[maybe_unused]] [[nodiscard]] std::uint8_t* ComputeTripleWordEndMinusOneRecord(
      const TripleWordVectorRuntime* const vectorState
    ) noexcept
    {
      return reinterpret_cast<std::uint8_t*>(vectorState->end) - sizeof(TripleWordValueRuntime);
    }

    /**
     * Address: 0x0092E9B0 (FUN_0092E9B0)
     *
     * What it does:
     * Compacts one triple-word range forward from `readCursor` to `writeCursor`,
     * updates vector end, and stores `writeCursor` to `outCursor`.
     */
    [[maybe_unused]] TripleWordValueRuntime** CompactTripleWordRangeForward_A(
      TripleWordVectorRuntime* const vectorState,
      TripleWordValueRuntime** const outCursor,
      TripleWordValueRuntime* const writeCursor,
      TripleWordValueRuntime* readCursor
    ) noexcept
    {
      if (writeCursor != readCursor) {
        TripleWordValueRuntime* const end = vectorState->end;
        TripleWordValueRuntime* dst = writeCursor;
        if (readCursor != end) {
          do {
            *dst = *readCursor;
            ++readCursor;
            ++dst;
          } while (readCursor != end);
        }
        vectorState->end = dst;
      }

      *outCursor = writeCursor;
      return outCursor;
    }

    /**
     * Address: 0x0092EAC0 (FUN_0092EAC0)
     *
     * What it does:
     * Alias lane that compacts one triple-word range forward and updates end.
     */
    [[maybe_unused]] TripleWordValueRuntime** CompactTripleWordRangeForward_B(
      TripleWordVectorRuntime* const vectorState,
      TripleWordValueRuntime** const outCursor,
      TripleWordValueRuntime* const writeCursor,
      TripleWordValueRuntime* readCursor
    ) noexcept
    {
      return CompactTripleWordRangeForward_A(vectorState, outCursor, writeCursor, readCursor);
    }

    /**
     * Address: 0x0092ED20 (FUN_0092ED20)
     *
     * What it does:
     * Resets vector end to begin when begin/end differ.
     */
    [[maybe_unused]] void ResetTripleWordVectorEndToBegin_A(TripleWordVectorRuntime* const vectorState) noexcept
    {
      if (vectorState->begin != vectorState->end) {
        vectorState->end = vectorState->begin;
      }
    }

    /**
     * Address: 0x0092EDF0 (FUN_0092EDF0)
     *
     * What it does:
     * Alias lane that resets vector end to begin when begin/end differ.
     */
    [[maybe_unused]] void ResetTripleWordVectorEndToBegin_B(TripleWordVectorRuntime* const vectorState) noexcept
    {
      if (vectorState->begin != vectorState->end) {
        vectorState->end = vectorState->begin;
      }
    }

    /**
     * Address: 0x00931640 (FUN_00931640)
     *
     * What it does:
     * Copies one `(4 dword + 1 word)` lane bundle and binds one external tail lane.
     */
    [[maybe_unused]] FourDwordWordAndTailRuntime* CopyFourDwordWordBundleWithTailLane(
      FourDwordWordAndTailRuntime* const destination,
      const FourDwordWordRuntime* const sourceBundle,
      const std::uint32_t* const tailLaneSource
    ) noexcept
    {
      destination->lane00 = sourceBundle->lane00;
      destination->lane04 = sourceBundle->lane04;
      destination->lane08 = sourceBundle->lane08;
      destination->lane0C = sourceBundle->lane0C;
      destination->lane10 = sourceBundle->lane10;
      destination->lane14 = *tailLaneSource;
      return destination;
    }

    /**
     * Address: 0x00931670 (FUN_00931670)
     *
     * What it does:
     * Copies one 32-bit lane into destination storage.
     */
    [[maybe_unused]] std::uint32_t* CopyDwordLane_A(std::uint32_t* const destination, const std::uint32_t* const source) noexcept
    {
      *destination = *source;
      return destination;
    }

    /**
     * Address: 0x00931680 (FUN_00931680)
     *
     * What it does:
     * Copies one 8-bit lane into destination storage.
     */
    [[maybe_unused]] std::uint8_t* CopyByteLane_A(std::uint8_t* const destination, const std::uint8_t* const source) noexcept
    {
      *destination = *source;
      return destination;
    }

    /**
     * Address: 0x00931710 (FUN_00931710)
     *
     * What it does:
     * Alias lane that copies one 32-bit value.
     */
    [[maybe_unused]] std::uint32_t* CopyDwordLane_B(std::uint32_t* const destination, const std::uint32_t* const source) noexcept
    {
      *destination = *source;
      return destination;
    }

    /**
     * Address: 0x00931720 (FUN_00931720)
     *
     * What it does:
     * Alias lane that copies one 8-bit value.
     */
    [[maybe_unused]] std::uint8_t* CopyByteLane_B(std::uint8_t* const destination, const std::uint8_t* const source) noexcept
    {
      *destination = *source;
      return destination;
    }

    /**
     * Address: 0x009317D0 (FUN_009317D0)
     *
     * What it does:
     * Writes one `(dword, byte)` lane pair into destination storage.
     */
    [[maybe_unused]] DwordAndByteLanesRuntime* WriteDwordAndByteLanes_A(
      DwordAndByteLanesRuntime* const destination,
      const std::uint32_t* const dwordLaneSource,
      const std::uint8_t* const byteLaneSource
    ) noexcept
    {
      destination->lane00 = *dwordLaneSource;
      destination->lane04 = *byteLaneSource;
      return destination;
    }

    /**
     * Address: 0x00931810 (FUN_00931810)
     *
     * What it does:
     * Alias lane that writes one `(dword, byte)` pair.
     */
    [[maybe_unused]] DwordAndByteLanesRuntime* WriteDwordAndByteLanes_B(
      DwordAndByteLanesRuntime* const destination,
      const std::uint32_t* const dwordLaneSource,
      const std::uint8_t* const byteLaneSource
    ) noexcept
    {
      destination->lane00 = *dwordLaneSource;
      destination->lane04 = *byteLaneSource;
      return destination;
    }

    /**
     * Address: 0x00931930 (FUN_00931930)
     *
     * What it does:
     * Clears one node cursor lane to null.
     */
    [[maybe_unused]] NodeCursorRuntime* ClearNodeCursor_A(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = nullptr;
      return cursor;
    }

    /**
     * Address: 0x00931940 (FUN_00931940)
     *
     * What it does:
     * Advances one node cursor to `node->next`.
     */
    [[maybe_unused]] NodeCursorRuntime* AdvanceNodeCursorToNext_A(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = cursor->node->next;
      return cursor;
    }

    /**
     * Address: 0x00931960 (FUN_00931960)
     *
     * What it does:
     * Alias lane that clears one node cursor lane to null.
     */
    [[maybe_unused]] NodeCursorRuntime* ClearNodeCursor_B(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = nullptr;
      return cursor;
    }

    /**
     * Address: 0x00931970 (FUN_00931970)
     *
     * What it does:
     * Alias lane that advances one node cursor to `node->next`.
     */
    [[maybe_unused]] NodeCursorRuntime* AdvanceNodeCursorToNext_B(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = cursor->node->next;
      return cursor;
    }

    /**
     * Address: 0x009319F0 (FUN_009319F0)
     *
     * What it does:
     * Sets one node cursor lane from caller-supplied pointer.
     */
    [[maybe_unused]] NodeCursorRuntime* SetNodeCursor_A(
      NodeCursorRuntime* const cursor,
      ForwardLinkNodeRuntime* const node
    ) noexcept
    {
      cursor->node = node;
      return cursor;
    }

    /**
     * Address: 0x00931A00 (FUN_00931A00)
     *
     * What it does:
     * Alias lane that sets one node cursor from caller-supplied pointer.
     */
    [[maybe_unused]] NodeCursorRuntime* SetNodeCursor_B(
      NodeCursorRuntime* const cursor,
      ForwardLinkNodeRuntime* const node
    ) noexcept
    {
      cursor->node = node;
      return cursor;
    }

    /**
     * Address: 0x00931A50 (FUN_00931A50)
     *
     * What it does:
     * Alias lane that sets one node cursor from caller-supplied pointer.
     */
    [[maybe_unused]] NodeCursorRuntime* SetNodeCursor_C(
      NodeCursorRuntime* const cursor,
      ForwardLinkNodeRuntime* const node
    ) noexcept
    {
      cursor->node = node;
      return cursor;
    }

    /**
     * Address: 0x00931AA0 (FUN_00931AA0)
     *
     * What it does:
     * Alias lane that sets one node cursor from caller-supplied pointer.
     */
    [[maybe_unused]] NodeCursorRuntime* SetNodeCursor_D(
      NodeCursorRuntime* const cursor,
      ForwardLinkNodeRuntime* const node
    ) noexcept
    {
      cursor->node = node;
      return cursor;
    }

    /**
     * Address: 0x00932170 (FUN_00932170)
     *
     * What it does:
     * Alias lane that clears one node cursor lane to null.
     */
    [[maybe_unused]] NodeCursorRuntime* ClearNodeCursor_C(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = nullptr;
      return cursor;
    }

    /**
     * Address: 0x00932180 (FUN_00932180)
     *
     * What it does:
     * Alias lane that advances one node cursor to `node->next`.
     */
    [[maybe_unused]] NodeCursorRuntime* AdvanceNodeCursorToNext_C(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = cursor->node->next;
      return cursor;
    }

    /**
     * Address: 0x00932190 (FUN_00932190)
     *
     * What it does:
     * Alias lane that advances one node cursor to `node->lane00`.
     */
    [[maybe_unused]] NodeCursorRuntime* AdvanceNodeCursorToLane00_A(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = cursor->node->lane00;
      return cursor;
    }

    /**
     * Address: 0x009321A0 (FUN_009321A0)
     *
     * What it does:
     * Alias lane that clears one node cursor lane to null.
     */
    [[maybe_unused]] NodeCursorRuntime* ClearNodeCursor_D(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = nullptr;
      return cursor;
    }

    /**
     * Address: 0x009321B0 (FUN_009321B0)
     *
     * What it does:
     * Alias lane that advances one node cursor to `node->next`.
     */
    [[maybe_unused]] NodeCursorRuntime* AdvanceNodeCursorToNext_D(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = cursor->node->next;
      return cursor;
    }

    /**
     * Address: 0x009321C0 (FUN_009321C0)
     *
     * What it does:
     * Alias lane that advances one node cursor to `node->lane00`.
     */
    [[maybe_unused]] NodeCursorRuntime* AdvanceNodeCursorToLane00_B(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = cursor->node->lane00;
      return cursor;
    }

    struct SingleDwordLaneRuntime
    {
      std::uint32_t value = 0;
    };
    static_assert(sizeof(SingleDwordLaneRuntime) == 0x04, "SingleDwordLaneRuntime size must be 0x04");

    /**
     * Address: 0x00932210 (FUN_00932210)
     *
     * What it does:
     * Stores one 32-bit input lane into one dword lane object.
     */
    [[maybe_unused]] SingleDwordLaneRuntime* StoreSingleDwordLane_A(
      SingleDwordLaneRuntime* const lane,
      const std::uint32_t value
    ) noexcept
    {
      lane->value = value;
      return lane;
    }

    /**
     * Address: 0x00932230 (FUN_00932230)
     *
     * What it does:
     * Alias lane that stores one 32-bit input lane into one dword lane object.
     */
    [[maybe_unused]] SingleDwordLaneRuntime* StoreSingleDwordLane_B(
      SingleDwordLaneRuntime* const lane,
      const std::uint32_t value
    ) noexcept
    {
      lane->value = value;
      return lane;
    }

    /**
     * Address: 0x00932360 (FUN_00932360)
     *
     * What it does:
     * Alias lane that stores one 32-bit input lane into one dword lane object.
     */
    [[maybe_unused]] SingleDwordLaneRuntime* StoreSingleDwordLane_C(
      SingleDwordLaneRuntime* const lane,
      const std::uint32_t value
    ) noexcept
    {
      lane->value = value;
      return lane;
    }

    /**
     * Address: 0x009323B0 (FUN_009323B0)
     *
     * What it does:
     * Alias lane that stores one 32-bit input lane into one dword lane object.
     */
    [[maybe_unused]] SingleDwordLaneRuntime* StoreSingleDwordLane_D(
      SingleDwordLaneRuntime* const lane,
      const std::uint32_t value
    ) noexcept
    {
      lane->value = value;
      return lane;
    }

    struct VtableProbeRuntime
    {
      const std::uint32_t* vtable = nullptr;
    };
    static_assert(sizeof(VtableProbeRuntime) == 0x04, "VtableProbeRuntime size must be 0x04");

    /**
     * Address: 0x00932670 (FUN_00932670)
     *
     * What it does:
     * Loads the dword lane at vtable slot index 4.
     */
    [[maybe_unused]] int LoadVtableDwordSlot04(const VtableProbeRuntime* const object) noexcept
    {
      return static_cast<int>(object->vtable[4]);
    }

    /**
     * Address: 0x00932680 (FUN_00932680)
     *
     * What it does:
     * Loads the dword lane at vtable slot index 15.
     */
    [[maybe_unused]] int LoadVtableDwordSlot15(const VtableProbeRuntime* const object) noexcept
    {
      return static_cast<int>(object->vtable[15]);
    }

    /**
     * Address: 0x009326A0 (FUN_009326A0)
     *
     * What it does:
     * Alias lane that advances one node cursor to `node->lane00`.
     */
    [[maybe_unused]] NodeCursorRuntime* AdvanceNodeCursorToLane00_C(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = cursor->node->lane00;
      return cursor;
    }

    /**
     * Address: 0x009326B0 (FUN_009326B0)
     *
     * What it does:
     * Alias lane that advances one node cursor to `node->lane00`.
     */
    [[maybe_unused]] NodeCursorRuntime* AdvanceNodeCursorToLane00_D(NodeCursorRuntime* const cursor) noexcept
    {
      cursor->node = cursor->node->lane00;
      return cursor;
    }

    struct TwoDwordLaneRuntime
    {
      std::uint32_t lane00 = 0;
      std::uint32_t lane04 = 0;
    };
    static_assert(sizeof(TwoDwordLaneRuntime) == 0x08, "TwoDwordLaneRuntime size must be 0x08");
    static_assert(offsetof(TwoDwordLaneRuntime, lane04) == 0x04, "TwoDwordLaneRuntime::lane04 offset must be 0x04");

    struct TwoDwordAndPointerLaneRuntime
    {
      std::uint32_t lane00 = 0;
      const std::uint32_t* lane04Pointer = nullptr;
    };
    static_assert(
      offsetof(TwoDwordAndPointerLaneRuntime, lane04Pointer) == 0x04,
      "TwoDwordAndPointerLaneRuntime::lane04Pointer offset must be 0x04"
    );

    struct ThreeDwordAndPointerLaneRuntime
    {
      std::uint32_t lane00 = 0;
      std::uint32_t lane04 = 0;
      const std::uint32_t* lane08Pointer = nullptr;
    };
    static_assert(
      offsetof(ThreeDwordAndPointerLaneRuntime, lane08Pointer) == 0x08,
      "ThreeDwordAndPointerLaneRuntime::lane08Pointer offset must be 0x08"
    );

    /**
     * Address: 0x00932700 (FUN_00932700)
     *
     * What it does:
     * Stores one dereferenced dword lane from source `+0x04` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreDereferencedLane04_A(
      const TwoDwordAndPointerLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = *source->lane04Pointer;
      return outValue;
    }

    /**
     * Address: 0x00932710 (FUN_00932710)
     *
     * What it does:
     * Stores the dword lane at source `+0x04` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreLane04_A(
      const TwoDwordLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = source->lane04;
      return outValue;
    }

    /**
     * Address: 0x00932720 (FUN_00932720)
     *
     * What it does:
     * Alias lane that stores one dereferenced dword lane from source `+0x04`
     * into output.
     */
    [[maybe_unused]] std::uint32_t* StoreDereferencedLane04_B(
      const TwoDwordAndPointerLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = *source->lane04Pointer;
      return outValue;
    }

    /**
     * Address: 0x00932730 (FUN_00932730)
     *
     * What it does:
     * Alias lane that stores the dword lane at source `+0x04` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreLane04_B(
      const TwoDwordLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = source->lane04;
      return outValue;
    }

    /**
     * Address: 0x009327C0 (FUN_009327C0)
     *
     * What it does:
     * Alias lane that stores the dword lane at source `+0x04` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreLane04_C(
      const TwoDwordLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = source->lane04;
      return outValue;
    }

    /**
     * Address: 0x009327D0 (FUN_009327D0)
     *
     * What it does:
     * Stores the dword lane at source `+0x08` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreLane08_A(
      const ThreeDwordAndPointerLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->lane08Pointer));
      return outValue;
    }

    /**
     * Address: 0x00932800 (FUN_00932800)
     *
     * What it does:
     * Alias lane that stores the dword lane at source `+0x04` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreLane04_D(
      const TwoDwordLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = source->lane04;
      return outValue;
    }

    /**
     * Address: 0x00932810 (FUN_00932810)
     *
     * What it does:
     * Alias lane that stores the dword lane at source `+0x08` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreLane08_B(
      const ThreeDwordAndPointerLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->lane08Pointer));
      return outValue;
    }

    struct HeadAddressLaneRuntime
    {
      std::uint32_t headAddress = 0;
    };
    static_assert(sizeof(HeadAddressLaneRuntime) == 0x04, "HeadAddressLaneRuntime size must be 0x04");

    /**
     * Address: 0x00932820 (FUN_00932820)
     *
     * What it does:
     * Pops one head-address lane into output, then advances head to
     * `*currentHead`.
     */
    [[maybe_unused]] std::uint32_t* PopHeadAddressToOut_A(
      HeadAddressLaneRuntime* const head,
      std::uint32_t* const outValue
    ) noexcept
    {
      const std::uint32_t current = head->headAddress;
      outValue[0] = current;
      const auto currentAddress = static_cast<std::uintptr_t>(current);
      head->headAddress = *reinterpret_cast<const std::uint32_t*>(currentAddress);
      return outValue;
    }

    /**
     * Address: 0x00932830 (FUN_00932830)
     *
     * What it does:
     * Alias lane that pops one head-address lane into output, then advances
     * head to `*currentHead`.
     */
    [[maybe_unused]] std::uint32_t* PopHeadAddressToOut_B(
      HeadAddressLaneRuntime* const head,
      std::uint32_t* const outValue
    ) noexcept
    {
      const std::uint32_t current = head->headAddress;
      outValue[0] = current;
      const auto currentAddress = static_cast<std::uintptr_t>(current);
      head->headAddress = *reinterpret_cast<const std::uint32_t*>(currentAddress);
      return outValue;
    }

    struct DwordBaseAddressLaneRuntime
    {
      std::uint32_t baseAddress = 0;
    };
    static_assert(sizeof(DwordBaseAddressLaneRuntime) == 0x04, "DwordBaseAddressLaneRuntime size must be 0x04");

    /**
     * Address: 0x00932840 (FUN_00932840)
     *
     * What it does:
     * Computes one dword address lane as `base + index*4` and stores it into
     * output.
     */
    [[maybe_unused]] std::uint32_t* StoreDwordAddressStride4_A(
      const DwordBaseAddressLaneRuntime* const base,
      std::uint32_t* const outValue,
      const int index
    ) noexcept
    {
      outValue[0] = base->baseAddress + static_cast<std::uint32_t>(4 * index);
      return outValue;
    }

    /**
     * Address: 0x00932860 (FUN_00932860)
     *
     * What it does:
     * Alias lane that computes one dword address as `base + index*4` and
     * stores it into output.
     */
    [[maybe_unused]] std::uint32_t* StoreDwordAddressStride4_B(
      const DwordBaseAddressLaneRuntime* const base,
      std::uint32_t* const outValue,
      const int index
    ) noexcept
    {
      outValue[0] = base->baseAddress + static_cast<std::uint32_t>(4 * index);
      return outValue;
    }

    /**
     * Address: 0x00932B10 (FUN_00932B10)
     *
     * What it does:
     * Stores one dereferenced dword lane from source `+0x08` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreDereferencedLane08_A(
      const ThreeDwordAndPointerLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = *source->lane08Pointer;
      return outValue;
    }

    /**
     * Address: 0x00932B20 (FUN_00932B20)
     *
     * What it does:
     * Stores the dword lane at source `+0x08` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreLane08_C(
      const ThreeDwordAndPointerLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->lane08Pointer));
      return outValue;
    }

    /**
     * Address: 0x00932B30 (FUN_00932B30)
     *
     * What it does:
     * Alias lane that stores one dereferenced dword lane from source `+0x08`
     * into output.
     */
    [[maybe_unused]] std::uint32_t* StoreDereferencedLane08_B(
      const ThreeDwordAndPointerLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = *source->lane08Pointer;
      return outValue;
    }

    /**
     * Address: 0x00932B40 (FUN_00932B40)
     *
     * What it does:
     * Alias lane that stores the dword lane at source `+0x08` into output.
     */
    [[maybe_unused]] std::uint32_t* StoreLane08_D(
      const ThreeDwordAndPointerLaneRuntime* const source,
      std::uint32_t* const outValue
    ) noexcept
    {
      outValue[0] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->lane08Pointer));
      return outValue;
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

    struct ClusterSearchOpenHeapEntryRuntime
    {
        float mCost;                    // +0x00
        ClusterNodeSearchState* mNode;  // +0x04
        std::int32_t mHandle;           // +0x08
    };
    static_assert(sizeof(ClusterSearchOpenHeapEntryRuntime) == 0x0C, "ClusterSearchOpenHeapEntryRuntime size must be 0x0C");
    static_assert(
      offsetof(ClusterSearchOpenHeapEntryRuntime, mHandle) == 0x08,
      "ClusterSearchOpenHeapEntryRuntime::mHandle offset must be 0x08"
    );

    template <typename T>
    struct ClusterSearchRuntimeVector
    {
        void* mProxy; // +0x00
        T* mFirst;    // +0x04
        T* mLast;     // +0x08
        T* mEnd;      // +0x0C
    };

    struct ClusterSearchOpenHeapRuntime
    {
        ClusterSearchRuntimeVector<ClusterSearchOpenHeapEntryRuntime> mHeap; // +0x00
        ClusterSearchRuntimeVector<std::int32_t> mHandleToHeapIndex;         // +0x10
        std::int32_t mFreeHandleHead;                                         // +0x20
    };
    static_assert(sizeof(ClusterSearchOpenHeapRuntime) == 0x24, "ClusterSearchOpenHeapRuntime size must be 0x24");
    static_assert(offsetof(ClusterSearchOpenHeapRuntime, mHeap) == 0x00, "ClusterSearchOpenHeapRuntime::mHeap offset must be 0x00");
    static_assert(
      offsetof(ClusterSearchOpenHeapRuntime, mHandleToHeapIndex) == 0x10,
      "ClusterSearchOpenHeapRuntime::mHandleToHeapIndex offset must be 0x10"
    );
    static_assert(
      offsetof(ClusterSearchOpenHeapRuntime, mFreeHandleHead) == 0x20,
      "ClusterSearchOpenHeapRuntime::mFreeHandleHead offset must be 0x20"
    );

    [[nodiscard]] std::uint32_t OpenHeapCount(const ClusterSearchOpenHeapRuntime& openHeap) noexcept
    {
        if (openHeap.mHeap.mFirst == nullptr || openHeap.mHeap.mLast == nullptr) {
            return 0u;
        }

        return static_cast<std::uint32_t>(openHeap.mHeap.mLast - openHeap.mHeap.mFirst);
    }

    void SwapOpenHeapEntries(
      ClusterSearchOpenHeapRuntime& openHeap,
      const std::uint32_t lhsIndex,
      const std::uint32_t rhsIndex
    ) noexcept
    {
        auto* const heap = openHeap.mHeap.mFirst;
        ClusterSearchOpenHeapEntryRuntime temp = heap[lhsIndex];
        heap[lhsIndex] = heap[rhsIndex];
        heap[rhsIndex] = temp;

        auto* const heapIndexByHandle = openHeap.mHandleToHeapIndex.mFirst;
        heapIndexByHandle[heap[lhsIndex].mHandle] = static_cast<std::int32_t>(lhsIndex);
        heapIndexByHandle[heap[rhsIndex].mHandle] = static_cast<std::int32_t>(rhsIndex);
    }

    /**
     * Address: 0x0092D1A0 (FUN_0092D1A0)
     *
     * What it does:
     * Sifts one open-heap entry upward by cost and keeps handle->heap-index
     * reverse mapping synchronized after every swap.
     */
    void ClusterSearchOpenHeapSiftUp(ClusterSearchOpenHeapRuntime& openHeap, std::uint32_t heapIndex)
    {
        if (heapIndex == 0u) {
            return;
        }

        do {
            const std::uint32_t parentIndex = (heapIndex - 1u) >> 1u;
            auto* const heap = openHeap.mHeap.mFirst;
            if (heap[heapIndex].mCost > heap[parentIndex].mCost) {
                break;
            }

            SwapOpenHeapEntries(openHeap, parentIndex, heapIndex);
            heapIndex = parentIndex;
        } while (heapIndex != 0u);
    }

    /**
     * Address: 0x0092D240 (FUN_0092D240)
     *
     * What it does:
     * Sifts one open-heap entry downward inside `[0, heapCount)` and returns
     * the next left-child index probe used by the loop.
     */
    [[nodiscard]] std::uint32_t ClusterSearchOpenHeapSiftDown(
      ClusterSearchOpenHeapRuntime& openHeap,
      std::uint32_t heapIndex,
      const std::uint32_t heapCount
    )
    {
        std::uint32_t leftChild = (heapIndex * 2u) + 1u;
        std::uint32_t rightChild = leftChild + 1u;

        while (leftChild < heapCount) {
            const std::uint32_t baseIndex = heapIndex;
            std::uint32_t bestIndex = heapIndex;
            auto* const heap = openHeap.mHeap.mFirst;

            if (heap[baseIndex].mCost > heap[leftChild].mCost) {
                bestIndex = leftChild;
            }

            if (rightChild < heapCount && heap[bestIndex].mCost > heap[rightChild].mCost) {
                bestIndex = rightChild;
            }

            if (bestIndex == baseIndex) {
                break;
            }

            SwapOpenHeapEntries(openHeap, baseIndex, bestIndex);
            heapIndex = bestIndex;
            leftChild = (heapIndex * 2u) + 1u;
            rightChild = leftChild + 1u;
        }

        return leftChild;
    }

    /**
     * Address: 0x0092DCE0 (FUN_0092DCE0)
     *
     * What it does:
     * Updates one open-heap node cost by handle and rebalances the heap by
     * sifting down or up based on the old/new cost relation.
     */
    void UpdateClusterSearchOpenHeapCost(
      ClusterSearchOpenHeapRuntime& openHeap,
      const std::int32_t handle,
      const float newCost
    )
    {
        const auto* const heapIndexByHandle = openHeap.mHandleToHeapIndex.mFirst;
        const std::uint32_t heapIndex = static_cast<std::uint32_t>(heapIndexByHandle[handle]);
        auto* const heap = openHeap.mHeap.mFirst;

        const float previousCost = heap[heapIndex].mCost;
        heap[heapIndex].mCost = newCost;

        if (previousCost <= newCost) {
            const std::uint32_t heapCount = OpenHeapCount(openHeap);
            (void)ClusterSearchOpenHeapSiftDown(openHeap, heapIndex, heapCount);
            return;
        }

        ClusterSearchOpenHeapSiftUp(openHeap, heapIndex);
    }

    /**
     * Address: 0x0092EE30 (FUN_0092EE30)
     *
     * What it does:
     * Removes one open-heap node at `heapIndex`, returns its handle to the
     * free-handle chain, pops the heap tail, and returns the pre-pop count.
     */
    [[nodiscard]] std::int32_t RemoveClusterSearchOpenHeapEntryAt(
      ClusterSearchOpenHeapRuntime& openHeap,
      const std::uint32_t heapIndex
    )
    {
        auto* const heap = openHeap.mHeap.mFirst;
        const std::uint32_t heapCount = OpenHeapCount(openHeap);
        const std::uint32_t tailIndex = heapCount - 1u;

        if (heapIndex != tailIndex) {
            SwapOpenHeapEntries(openHeap, heapIndex, tailIndex);
            (void)ClusterSearchOpenHeapSiftDown(openHeap, heapIndex, tailIndex);
        }

        const std::int32_t removedHandle = openHeap.mHeap.mLast[-1].mHandle;
        auto* const heapIndexByHandle = openHeap.mHandleToHeapIndex.mFirst;
        heapIndexByHandle[removedHandle] = openHeap.mFreeHandleHead;
        openHeap.mFreeHandleHead = removedHandle;

        if (heapCount != 0u) {
            --openHeap.mHeap.mLast;
        }

        return static_cast<std::int32_t>(heapCount);
    }

    /**
     * Address: 0x0092F140 (FUN_0092F140)
     *
     * What it does:
     * Forwards to open-heap removal at index `0`, preserving the wrapper lane
     * that pops the current heap-head entry.
     */
    [[nodiscard]] std::int32_t RemoveClusterSearchOpenHeapHeadEntry(
      ClusterSearchOpenHeapRuntime& openHeap
    )
    {
        return RemoveClusterSearchOpenHeapEntryAt(openHeap, 0u);
    }

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

    template <typename T>
    [[nodiscard]] std::uint32_t RuntimeVectorCount(const ClusterSearchRuntimeVector<T>& vector) noexcept
    {
      if (vector.mFirst == nullptr || vector.mLast == nullptr) {
        return 0u;
      }
      return static_cast<std::uint32_t>(vector.mLast - vector.mFirst);
    }

    template <typename T>
    [[nodiscard]] std::uint32_t RuntimeVectorCapacity(const ClusterSearchRuntimeVector<T>& vector) noexcept
    {
      if (vector.mFirst == nullptr || vector.mEnd == nullptr) {
        return 0u;
      }
      return static_cast<std::uint32_t>(vector.mEnd - vector.mFirst);
    }

    template <typename T>
    void RuntimeVectorReserveAtLeast(ClusterSearchRuntimeVector<T>& vector, const std::uint32_t requiredCount)
    {
      const std::uint32_t oldCapacity = RuntimeVectorCapacity(vector);
      if (requiredCount <= oldCapacity) {
        return;
      }

      const std::uint32_t oldCount = RuntimeVectorCount(vector);
      std::uint32_t newCapacity = (oldCapacity != 0u) ? oldCapacity : 1u;
      while (newCapacity < requiredCount) {
        const std::uint32_t doubled = newCapacity * 2u;
        if (doubled <= newCapacity) {
          newCapacity = requiredCount;
          break;
        }
        newCapacity = doubled;
      }

      auto* const newStorage = static_cast<T*>(::operator new(static_cast<std::size_t>(newCapacity) * sizeof(T)));
      for (std::uint32_t i = 0u; i < oldCount; ++i) {
        newStorage[i] = vector.mFirst[i];
      }

      if (vector.mFirst != nullptr) {
        ::operator delete(vector.mFirst);
      }

      vector.mFirst = newStorage;
      vector.mLast = newStorage + oldCount;
      vector.mEnd = newStorage + newCapacity;
    }

    template <typename T>
    void RuntimeVectorPushBack(ClusterSearchRuntimeVector<T>& vector, const T& value)
    {
      const std::uint32_t oldCount = RuntimeVectorCount(vector);
      RuntimeVectorReserveAtLeast(vector, oldCount + 1u);
      vector.mFirst[oldCount] = value;
      vector.mLast = vector.mFirst + oldCount + 1u;
    }

    struct ClusterSearchEdgeTraversalLaneRuntime
    {
      float mAccumulatedCost;                // +0x00
      std::uint32_t mPackedNodeCoordinate;   // +0x04
      float mTraversalCost;                  // +0x08
    };
    static_assert(sizeof(ClusterSearchEdgeTraversalLaneRuntime) == 0x0C, "ClusterSearchEdgeTraversalLaneRuntime size must be 0x0C");

    using ClusterSearchEdgeTraversalVectorRuntime = ClusterSearchRuntimeVector<ClusterSearchEdgeTraversalLaneRuntime>;

    /**
     * Address: 0x009302E0 (FUN_009302E0)
     *
     * What it does:
     * Appends one 12-byte edge-traversal lane into the destination vector and
     * advances the end cursor.
     */
    [[nodiscard]] int AppendClusterSearchEdgeTraversalLane(
      ClusterSearchEdgeTraversalVectorRuntime& edgeLanes,
      const ClusterSearchEdgeTraversalLaneRuntime& lane
    )
    {
      const std::uint32_t size = RuntimeVectorCount(edgeLanes);
      if (edgeLanes.mFirst != nullptr && size < RuntimeVectorCapacity(edgeLanes)) {
        edgeLanes.mFirst[size] = lane;
        edgeLanes.mLast = edgeLanes.mFirst + size + 1u;
        return reinterpret_cast<int>(edgeLanes.mFirst + size);
      }

      RuntimeVectorPushBack(edgeLanes, lane);
      return reinterpret_cast<int>(edgeLanes.mFirst + size);
    }

    struct ClusterSearchTraversalContextRuntime
    {
      const gpg::HaStar::SubclusterData* mSubclusterData; // +0x00
    };
    static_assert(sizeof(ClusterSearchTraversalContextRuntime) == 0x04, "ClusterSearchTraversalContextRuntime size must be 0x04");

    struct ClusterSearchFrontierStateRuntime
    {
      float mAccumulatedCost; // +0x00
      std::uint8_t mNodeX;    // +0x04
      std::uint8_t mNodeZ;    // +0x05
      std::uint8_t pad06[2];  // +0x06
    };
    static_assert(sizeof(ClusterSearchFrontierStateRuntime) == 0x08, "ClusterSearchFrontierStateRuntime size must be 0x08");
    static_assert(
      offsetof(ClusterSearchFrontierStateRuntime, mNodeX) == 0x04,
      "ClusterSearchFrontierStateRuntime::mNodeX offset must be 0x04"
    );
    static_assert(
      offsetof(ClusterSearchFrontierStateRuntime, mNodeZ) == 0x05,
      "ClusterSearchFrontierStateRuntime::mNodeZ offset must be 0x05"
    );

    struct ClusterPayloadEdgeTableRuntime
    {
      std::int32_t mRefs;       // +0x00
      void* mReleaseObject;     // +0x04
      std::uint32_t mReleaseArg;// +0x08
      std::uint8_t mEdgeCount;  // +0x0C
      std::uint8_t mEdgeData[1];// +0x0D
    };
    static_assert(offsetof(ClusterPayloadEdgeTableRuntime, mEdgeCount) == 0x0C, "ClusterPayloadEdgeTableRuntime::mEdgeCount offset must be 0x0C");
    static_assert(offsetof(ClusterPayloadEdgeTableRuntime, mEdgeData) == 0x0D, "ClusterPayloadEdgeTableRuntime::mEdgeData offset must be 0x0D");

    [[nodiscard]] std::uint32_t TriangularEdgePairIndex(const std::uint32_t lhs, const std::uint32_t rhs) noexcept
    {
      if (lhs >= rhs) {
        return rhs + ((lhs * (lhs - 1u)) >> 1u);
      }
      return lhs + ((rhs * (rhs - 1u)) >> 1u);
    }

    [[nodiscard]] const std::uint8_t* EdgeCoordBase(const ClusterPayloadEdgeTableRuntime& table) noexcept
    {
      return table.mEdgeData;
    }

    [[nodiscard]] std::uint8_t EdgeCoordX(const ClusterPayloadEdgeTableRuntime& table, const std::uint32_t edgeIndex) noexcept
    {
      return EdgeCoordBase(table)[edgeIndex * 2u];
    }

    [[nodiscard]] std::uint8_t EdgeCoordZ(const ClusterPayloadEdgeTableRuntime& table, const std::uint32_t edgeIndex) noexcept
    {
      return EdgeCoordBase(table)[edgeIndex * 2u + 1u];
    }

    [[nodiscard]] std::int8_t EdgeTraversalBucketCost(
      const ClusterPayloadEdgeTableRuntime& table,
      const std::uint32_t fromEdgeIndex,
      const std::uint32_t toEdgeIndex
    ) noexcept
    {
      const std::uint32_t pairIndex = TriangularEdgePairIndex(fromEdgeIndex, toEdgeIndex);
      const std::uint32_t byteOffset = static_cast<std::uint32_t>(table.mEdgeCount) * 2u + pairIndex;
      return static_cast<std::int8_t>(EdgeCoordBase(table)[byteOffset]);
    }

    [[nodiscard]] float ComputeEdgeTraversalDistance(
      const std::uint8_t sourceX,
      const std::uint8_t sourceZ,
      const std::uint8_t targetX,
      const std::uint8_t targetZ
    ) noexcept
    {
      const float dx = std::fabs(static_cast<float>(static_cast<int>(sourceX) - static_cast<int>(targetX)));
      const float dz = std::fabs(static_cast<float>(static_cast<int>(sourceZ) - static_cast<int>(targetZ)));
      return (dz <= dx) ? (dz * 0.41421354f + dx) : (dx * 0.41421354f + dz);
    }

    [[nodiscard]] float DequantizeEdgeTraversalCost(
      const std::int8_t bucket,
      const float distance
    ) noexcept
    {
      return std::exp(static_cast<float>(bucket) / 6.0f) * distance;
    }

    [[nodiscard]] bool FindClusterEntryEdgeAtLocalCoordinate(
      const ClusterPayloadEdgeTableRuntime& table,
      const std::uint8_t localX,
      const std::uint8_t localZ,
      std::uint32_t& outEdgeIndex
    ) noexcept
    {
      const std::uint32_t edgeCount = static_cast<std::uint32_t>(table.mEdgeCount);
      for (std::uint32_t i = 0u; i < edgeCount; ++i) {
        if (EdgeCoordX(table, i) == localX && EdgeCoordZ(table, i) == localZ) {
          outEdgeIndex = i;
          return true;
        }
      }
      return false;
    }

    /**
     * Address: 0x009304F0 (FUN_009304F0)
     *
     * What it does:
     * Expands one frontier node over cluster-cell edge payloads and appends
     * reachable edge-traversal lanes into the output edge vector.
     */
    [[nodiscard]] char ExpandClusterSearchFrontierEdges(
      const ClusterSearchTraversalContextRuntime& context,
      const ClusterSearchFrontierStateRuntime* const frontier,
      ClusterSearchEdgeTraversalVectorRuntime& outEdgeLanes
    )
    {
      if (context.mSubclusterData == nullptr || frontier == nullptr) {
        return 0;
      }

      const auto& subcluster = *context.mSubclusterData;
      const std::uint8_t level = static_cast<std::uint8_t>(subcluster.mLevel);
      const std::uint8_t levelShift = kClusterSizeLog2ByLevel[level];
      const gpg::Rect2i localRect = gpg::HaStar::ClusterIndexRect(
        static_cast<int>(frontier->mNodeX),
        static_cast<int>(frontier->mNodeZ),
        level,
        4,
        4
      );

      for (int tileZ = localRect.z0; tileZ != localRect.z1; ++tileZ) {
        const std::uint8_t tileBaseZ = static_cast<std::uint8_t>(tileZ << levelShift);
        for (int tileX = localRect.x0; tileX != localRect.x1; ++tileX) {
          const std::uint32_t cellIndex = static_cast<std::uint32_t>(tileX + tileZ * 4);
          const auto* const table = reinterpret_cast<const ClusterPayloadEdgeTableRuntime*>(subcluster.mClusters[cellIndex].mData);
          if (table == nullptr || table->mEdgeCount == 0u) {
            continue;
          }

          const std::uint8_t tileBaseX = static_cast<std::uint8_t>(tileX << levelShift);
          const std::uint8_t localX = static_cast<std::uint8_t>(frontier->mNodeX - tileBaseX);
          const std::uint8_t localZ = static_cast<std::uint8_t>(frontier->mNodeZ - tileBaseZ);

          std::uint32_t sourceEdgeIndex = 0u;
          if (!FindClusterEntryEdgeAtLocalCoordinate(*table, localX, localZ, sourceEdgeIndex)) {
            continue;
          }

          const std::uint32_t edgeCount = static_cast<std::uint32_t>(table->mEdgeCount);
          for (std::uint32_t edgeIndex = 0u; edgeIndex < edgeCount; ++edgeIndex) {
            if (edgeIndex == sourceEdgeIndex) {
              continue;
            }

            const std::int8_t bucketCost = EdgeTraversalBucketCost(*table, sourceEdgeIndex, edgeIndex);
            if (bucketCost < 0) {
              continue;
            }

            const std::uint8_t sourceX = EdgeCoordX(*table, sourceEdgeIndex);
            const std::uint8_t sourceZ = EdgeCoordZ(*table, sourceEdgeIndex);
            const std::uint8_t targetX = EdgeCoordX(*table, edgeIndex);
            const std::uint8_t targetZ = EdgeCoordZ(*table, edgeIndex);
            const float traversalDistance = ComputeEdgeTraversalDistance(sourceX, sourceZ, targetX, targetZ);
            const float traversalCost = DequantizeEdgeTraversalCost(bucketCost, traversalDistance);

            ClusterSearchEdgeTraversalLaneRuntime lane{};
            lane.mAccumulatedCost = frontier->mAccumulatedCost + traversalCost;
            lane.mPackedNodeCoordinate =
              static_cast<std::uint32_t>(static_cast<std::uint8_t>(tileBaseX + targetX))
              | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(tileBaseZ + targetZ)) << 8u);
            lane.mTraversalCost = traversalCost;
            (void)AppendClusterSearchEdgeTraversalLane(outEdgeLanes, lane);
          }
        }
      }

      return 0;
    }

    [[nodiscard]] std::int32_t AcquireOrReuseClusterSearchOpenHandle(
      ClusterSearchOpenHeapRuntime& openHeap,
      const std::int32_t heapIndex
    )
    {
      const std::int32_t freeHead = openHeap.mFreeHandleHead;
      if (freeHead == -1) {
        const std::int32_t newHandle = static_cast<std::int32_t>(RuntimeVectorCount(openHeap.mHandleToHeapIndex));
        RuntimeVectorPushBack(openHeap.mHandleToHeapIndex, heapIndex);
        return newHandle;
      }

      auto* const handleToHeapIndex = openHeap.mHandleToHeapIndex.mFirst;
      openHeap.mFreeHandleHead = handleToHeapIndex[freeHead];
      handleToHeapIndex[freeHead] = heapIndex;
      return freeHead;
    }

    /**
     * Address: 0x00930820 (FUN_00930820)
     *
     * What it does:
     * Appends one open-search node lane to the heap, allocates/reuses a node
     * handle, and sifts the appended entry upward.
     */
    [[nodiscard]] std::int32_t PushClusterSearchOpenNode(
      ClusterSearchOpenHeapRuntime& openHeap,
      const float cost,
      ClusterNodeSearchState* const nodeState
    )
    {
      const std::int32_t heapIndex = static_cast<std::int32_t>(OpenHeapCount(openHeap));
      const std::int32_t handle = AcquireOrReuseClusterSearchOpenHandle(openHeap, heapIndex);

      ClusterSearchOpenHeapEntryRuntime entry{};
      entry.mCost = cost;
      entry.mNode = nodeState;
      entry.mHandle = handle;
      RuntimeVectorPushBack(openHeap.mHeap, entry);

      ClusterSearchOpenHeapSiftUp(openHeap, static_cast<std::uint32_t>(heapIndex));
      return handle;
    }

    struct ClusterSearchNeighborSeedRuntime
    {
      std::int32_t mOwnerNodeIndex; // +0x00
      std::uint8_t mNodeX;          // +0x04
      std::uint8_t mNodeZ;          // +0x05
      std::uint8_t mPad06[2];       // +0x06
    };
    static_assert(sizeof(ClusterSearchNeighborSeedRuntime) == 0x08, "ClusterSearchNeighborSeedRuntime size must be 0x08");
    static_assert(
      offsetof(ClusterSearchNeighborSeedRuntime, mNodeX) == 0x04,
      "ClusterSearchNeighborSeedRuntime::mNodeX offset must be 0x04"
    );
    static_assert(
      offsetof(ClusterSearchNeighborSeedRuntime, mNodeZ) == 0x05,
      "ClusterSearchNeighborSeedRuntime::mNodeZ offset must be 0x05"
    );

    [[nodiscard]] std::uint32_t LoadPackedNodeCoordinateLane(const ClusterSearchNeighborSeedRuntime& seed) noexcept
    {
      std::uint32_t packed = 0u;
      std::memcpy(&packed, &seed.mNodeX, sizeof(packed));
      return packed;
    }

    /**
     * Address: 0x00930C80 (FUN_00930C80)
     *
     * What it does:
     * Opens or relaxes one node-search state from neighbor seed data and
     * updates open-heap ordering/keys as needed.
     */
    void RelaxClusterSearchNeighbor(
      ClusterNodeSearchStateMap& stateByCoordinate,
      ClusterSearchOpenHeapRuntime& openHeap,
      const void* const unusedContext,
      const ClusterSearchNeighborSeedRuntime& neighborSeed,
      const float pathCost
    )
    {
      (void)unusedContext;

      ClusterNodeSearchState& nodeState =
        ClusterNodeStateMapIndex(stateByCoordinate, neighborSeed.mNodeX, neighborSeed.mNodeZ);

      if (nodeState.mState == 0) {
        nodeState.mHeuristicCost = 0.0f;
        nodeState.mHeapLane = 0;
        nodeState.mState = 1;
        nodeState.mOwnerNodeIndex = neighborSeed.mOwnerNodeIndex;
        nodeState.mPackedNodeCoordinate = LoadPackedNodeCoordinateLane(neighborSeed);
        nodeState.mPathCost = pathCost;
        nodeState.mOpenListHandle = PushClusterSearchOpenNode(openHeap, pathCost, &nodeState);
        return;
      }

      if (nodeState.mState == 1) {
        if (nodeState.mPathCost > 0.0f) {
          const float previousHeuristicCost = nodeState.mHeuristicCost;
          const std::int32_t openHandle = nodeState.mOpenListHandle;
          nodeState.mHeapLane = 0;
          nodeState.mOwnerNodeIndex = neighborSeed.mOwnerNodeIndex;
          nodeState.mPackedNodeCoordinate = LoadPackedNodeCoordinateLane(neighborSeed);
          nodeState.mPathCost = pathCost;
          UpdateClusterSearchOpenHeapCost(openHeap, openHandle, previousHeuristicCost + pathCost);
        }
        return;
      }

      if (nodeState.mState != 2) {
        gpg::HandleAssertFailure(
          "node.mState == CLOSED",
          195,
          "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/algorithms/AStarSearch.h"
        );
      }
    }

    [[nodiscard]] std::int32_t FloatToRawI32Bits(const float value) noexcept
    {
      std::int32_t rawBits = 0;
      std::memcpy(&rawBits, &value, sizeof(rawBits));
      return rawBits;
    }

    [[nodiscard]] std::int32_t PointerToRawI32Bits(ClusterNodeSearchState* const node) noexcept
    {
      return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(node));
    }

    /**
     * Address: 0x00930D60 (FUN_00930D60)
     *
     * What it does:
     * Runs the clustered A* frontier loop until the open heap is drained:
     * expand one node into edge lanes, close/pop the node, and relax all
     * discovered neighbors with heap-key updates.
     */
    [[nodiscard]] char ProcessClusterSearchOpenFrontier(
      ClusterNodeSearchStateMap& stateByCoordinate,
      ClusterSearchOpenHeapRuntime& openHeap,
      const ClusterSearchTraversalContextRuntime& context
    )
    {
      ClusterSearchEdgeTraversalVectorRuntime edgeLanes{};

      const auto releaseEdgeLanes = [&edgeLanes]() noexcept {
        if (edgeLanes.mFirst != nullptr) {
          ::operator delete[](edgeLanes.mFirst);
          edgeLanes.mFirst = nullptr;
          edgeLanes.mLast = nullptr;
          edgeLanes.mEnd = nullptr;
        }
      };

      while (OpenHeapCount(openHeap) != 0u) {
        ClusterNodeSearchState* const currentNode = openHeap.mHeap.mFirst[0].mNode;

        // The original code reuses the same storage and resets vector size each pass.
        if (edgeLanes.mFirst != edgeLanes.mLast) {
          edgeLanes.mLast = edgeLanes.mFirst;
        }

        const char expandStatus = ExpandClusterSearchFrontierEdges(
          context,
          reinterpret_cast<const ClusterSearchFrontierStateRuntime*>(currentNode),
          edgeLanes
        );
        if (expandStatus != 0) {
          releaseEdgeLanes();
          return expandStatus;
        }

        currentNode->mState = 2;
        (void)RemoveClusterSearchOpenHeapEntryAt(openHeap, 0u);

        const std::uint32_t laneCount = RuntimeVectorCount(edgeLanes);
        for (std::uint32_t laneIndex = 0u; laneIndex < laneCount; ++laneIndex) {
          const ClusterSearchEdgeTraversalLaneRuntime& lane = edgeLanes.mFirst[laneIndex];
          const std::uint8_t nodeX = static_cast<std::uint8_t>(lane.mPackedNodeCoordinate & 0xFFu);
          const std::uint8_t nodeZ = static_cast<std::uint8_t>((lane.mPackedNodeCoordinate >> 8u) & 0xFFu);
          ClusterNodeSearchState& nodeState = ClusterNodeStateMapIndex(stateByCoordinate, nodeX, nodeZ);

          const float candidatePathCost = currentNode->mPathCost + lane.mTraversalCost;

          if (nodeState.mState == 0) {
            nodeState.mState = 1;
            nodeState.mHeuristicCost = 0.0f;
            nodeState.mHeapLane = PointerToRawI32Bits(currentNode);
            nodeState.mOwnerNodeIndex = FloatToRawI32Bits(lane.mAccumulatedCost);
            nodeState.mPackedNodeCoordinate = lane.mPackedNodeCoordinate;
            nodeState.mPathCost = candidatePathCost;
            nodeState.mOpenListHandle = PushClusterSearchOpenNode(openHeap, candidatePathCost, &nodeState);
            continue;
          }

          if (nodeState.mState == 1) {
            if (nodeState.mPathCost > candidatePathCost) {
              const float heuristicCost = nodeState.mHeuristicCost;
              const std::int32_t openHandle = nodeState.mOpenListHandle;
              nodeState.mHeapLane = PointerToRawI32Bits(currentNode);
              nodeState.mOwnerNodeIndex = FloatToRawI32Bits(lane.mAccumulatedCost);
              nodeState.mPackedNodeCoordinate = lane.mPackedNodeCoordinate;
              nodeState.mPathCost = candidatePathCost;
              UpdateClusterSearchOpenHeapCost(openHeap, openHandle, heuristicCost + candidatePathCost);
            }
            continue;
          }

          if (nodeState.mState != 2) {
            gpg::HandleAssertFailure(
              "neib->mState == CLOSED",
              253,
              "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/algorithms/AStarSearch.h"
            );
          }
        }
      }

      releaseEdgeLanes();
      return 0;
    }

    struct InlineBackedByteVectorRuntime
    {
        std::uint8_t* mBegin;             // +0x00
        std::uint8_t* mEnd;               // +0x04
        std::uint8_t* mCapacityEnd;       // +0x08
        std::uint8_t* mInlineStorageLane; // +0x0C
    };
    static_assert(sizeof(InlineBackedByteVectorRuntime) == 0x10, "InlineBackedByteVectorRuntime size must be 0x10");
    static_assert(
      offsetof(InlineBackedByteVectorRuntime, mInlineStorageLane) == 0x0C,
      "InlineBackedByteVectorRuntime::mInlineStorageLane offset must be 0x0C"
    );

    [[nodiscard]] std::uint8_t* CopyByteRangeForward(
      const std::uint8_t* sourceBegin,
      const std::uint8_t* sourceEnd,
      std::uint8_t* destination
    ) noexcept
    {
      const std::uint8_t* sourceCursor = sourceBegin;
      std::uint8_t* writeCursor = destination;
      while (sourceCursor != sourceEnd) {
        if (writeCursor != nullptr) {
          *writeCursor = *sourceCursor;
        }
        ++sourceCursor;
        ++writeCursor;
      }
      return writeCursor;
    }

    /**
     * Address: 0x0092CCF0 (FUN_0092CCF0)
     *
     * What it does:
     * Reallocates one inline-backed byte vector to `newCapacity` and rebuilds
     * contents as `[oldBegin, splitPoint) + [insertBegin, insertEnd) + [splitPoint, oldEnd)`.
     */
    [[nodiscard]] int ReallocateInlineBackedByteVectorWithSplitInsert(
      InlineBackedByteVectorRuntime& vector,
      const std::uint32_t newCapacity,
      const std::uint8_t* const splitPoint,
      const std::uint8_t* const insertBegin,
      const std::uint8_t* const insertEnd
    )
    {
      std::uint8_t* const newStorage = static_cast<std::uint8_t*>(::operator new(newCapacity));
      std::uint8_t* writeCursor = newStorage;
      writeCursor = CopyByteRangeForward(vector.mBegin, splitPoint, writeCursor);
      writeCursor = CopyByteRangeForward(insertBegin, insertEnd, writeCursor);
      writeCursor = CopyByteRangeForward(splitPoint, vector.mEnd, writeCursor);

      if (vector.mBegin == vector.mInlineStorageLane) {
        if (vector.mInlineStorageLane != nullptr) {
          *reinterpret_cast<std::uint8_t**>(vector.mInlineStorageLane) = vector.mCapacityEnd;
        }
      }
      else if (vector.mBegin != nullptr) {
        ::operator delete[](vector.mBegin);
      }

      vector.mBegin = newStorage;
      vector.mEnd = writeCursor;
      vector.mCapacityEnd = newStorage + newCapacity;
      return static_cast<int>(newCapacity);
    }

    [[nodiscard]] std::uint8_t* ShiftByteRangeLeftAndCommitEnd(
      InlineBackedByteVectorRuntime& vector,
      std::uint8_t* const destination,
      const std::uint8_t* const sourceBegin
    )
    {
      if (destination == sourceBegin) {
        return destination;
      }

      if (sourceBegin != vector.mEnd) {
        const std::size_t byteCount = static_cast<std::size_t>(
          reinterpret_cast<std::uintptr_t>(vector.mEnd) - reinterpret_cast<std::uintptr_t>(sourceBegin)
        );
        std::memmove(destination, sourceBegin, byteCount);
      }
      vector.mEnd = destination + static_cast<std::size_t>(
        reinterpret_cast<std::uintptr_t>(vector.mEnd) - reinterpret_cast<std::uintptr_t>(sourceBegin)
      );
      return destination;
    }

    /**
     * Address: 0x0092E410 (FUN_0092E410)
     *
     * What it does:
     * Resizes one inline-backed byte vector to `targetSize` by truncating or
     * appending fill-byte lanes, growing storage when capacity is insufficient.
     */
    [[nodiscard]] std::uint8_t* ResizeInlineBackedByteVectorWithFill(
      InlineBackedByteVectorRuntime& vector,
      const std::uint32_t targetSize,
      const std::uint8_t* const fillByte
    )
    {
      std::uint8_t* result = vector.mBegin;
      const std::uint32_t currentSize = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(vector.mEnd) - reinterpret_cast<std::uintptr_t>(vector.mBegin)
      );

      if (targetSize < currentSize) {
        return ShiftByteRangeLeftAndCommitEnd(vector, vector.mBegin + targetSize, vector.mEnd);
      }

      if (targetSize > currentSize) {
        const std::uint32_t currentCapacity = static_cast<std::uint32_t>(
          reinterpret_cast<std::uintptr_t>(vector.mCapacityEnd) - reinterpret_cast<std::uintptr_t>(vector.mBegin)
        );
        if (targetSize > currentCapacity) {
          result = vector.mBegin;
          (void)ReallocateInlineBackedByteVectorWithSplitInsert(
            vector,
            targetSize,
            result,
            result,
            result
          );
        }

        std::uint8_t* const targetEnd = vector.mBegin + targetSize;
        while (vector.mEnd != targetEnd) {
          result = vector.mEnd;
          vector.mEnd = result + 1;
          if (result != nullptr) {
            *result = *fillByte;
          }
        }
      }

      return result;
    }

    void OrderAscendingU16Pair(std::uint16_t& lhs, std::uint16_t& rhs) noexcept
    {
      if (rhs < lhs) {
        const std::uint16_t temp = lhs;
        lhs = rhs;
        rhs = temp;
      }
    }

    /**
     * Address: 0x0092E050 (FUN_0092E050)
     *
     * What it does:
     * Orders median samples for one `uint16_t` partition lane using
     * median-of-three for short spans and a ninther-style sample ordering for
     * longer spans.
     */
    [[nodiscard]] std::uintptr_t OrderU16PivotSamples(
      std::uint16_t* const begin,
      std::uint16_t* const mid,
      std::uint16_t* const endMinusOne
    ) noexcept
    {
      const std::ptrdiff_t spanElements = endMinusOne - begin;
      if (spanElements <= 40) {
        OrderAscendingU16Pair(*begin, *mid);
        OrderAscendingU16Pair(*mid, *endMinusOne);
        OrderAscendingU16Pair(*begin, *mid);
        return reinterpret_cast<std::uintptr_t>(mid);
      }

      const std::ptrdiff_t sampleStride = (spanElements + 1) / 8;
      const std::uintptr_t byteStride = static_cast<std::uintptr_t>(sampleStride * static_cast<std::ptrdiff_t>(sizeof(std::uint16_t)));

      std::uint16_t* const beginStep1 = begin + sampleStride;
      std::uint16_t* const beginStep2 = begin + sampleStride * 2;
      std::uint16_t* const midStepNeg = mid - sampleStride;
      std::uint16_t* const midStepPos = mid + sampleStride;
      std::uint16_t* const endStepNeg1 = endMinusOne - sampleStride;
      std::uint16_t* const endStepNeg2 = endMinusOne - sampleStride * 2;

      OrderAscendingU16Pair(*begin, *beginStep1);
      OrderAscendingU16Pair(*beginStep1, *beginStep2);
      OrderAscendingU16Pair(*begin, *beginStep1);

      OrderAscendingU16Pair(*midStepNeg, *mid);
      OrderAscendingU16Pair(*mid, *midStepPos);
      OrderAscendingU16Pair(*midStepNeg, *mid);

      OrderAscendingU16Pair(*endStepNeg2, *endStepNeg1);
      OrderAscendingU16Pair(*endStepNeg1, *endMinusOne);
      OrderAscendingU16Pair(*endStepNeg2, *endStepNeg1);

      OrderAscendingU16Pair(*beginStep1, *mid);
      OrderAscendingU16Pair(*mid, *endStepNeg1);
      OrderAscendingU16Pair(*beginStep1, *mid);
      return byteStride;
    }

    void SwapU16Lane(std::uint16_t& lhs, std::uint16_t& rhs) noexcept
    {
      const std::uint16_t temp = lhs;
      lhs = rhs;
      rhs = temp;
    }

    /**
     * Address: 0x0092E6E0 (FUN_0092E6E0)
     *
     * What it does:
     * Partitions one `uint16_t` range around an ordered pivot sample and
     * returns the equal-band boundaries through `outBounds`.
     */
    [[nodiscard]] std::uint16_t** PartitionU16RangeWithEqualBands(
      std::uint16_t** const outBounds,
      std::uint16_t* const begin,
      std::uint16_t* const end
    ) noexcept
    {
      std::uint16_t* leftPivot = begin + ((end - begin) / 2);
      (void)OrderU16PivotSamples(begin, leftPivot, end - 1);

      std::uint16_t* equalRight = leftPivot + 1;
      while (begin < leftPivot) {
        const std::uint16_t previousValue = *(leftPivot - 1);
        if (*leftPivot > previousValue || *leftPivot < previousValue) {
          break;
        }
        --leftPivot;
      }

      if (equalRight < end) {
        const std::uint16_t pivotValue = *leftPivot;
        while (equalRight < end) {
          if (pivotValue > *equalRight || pivotValue < *equalRight) {
            break;
          }
          ++equalRight;
        }
      }

      std::uint16_t* scanRight = equalRight;
      std::uint16_t* scanLeft = leftPivot;
      while (true) {
        while (true) {
          for (; scanRight < end; ++scanRight) {
            const std::uint16_t rightValue = *scanRight;
            if (*scanRight <= *leftPivot) {
              if (rightValue < *leftPivot) {
                break;
              }
              SwapU16Lane(*equalRight, *scanRight);
              ++equalRight;
            }
          }

          bool hitBegin = (scanLeft == begin);
          if (scanLeft > begin) {
            do {
              const std::uint16_t leftValue = *(scanLeft - 1);
              if (*leftPivot <= leftValue) {
                if (*leftPivot < leftValue) {
                  break;
                }
                --leftPivot;
                SwapU16Lane(*leftPivot, *(scanLeft - 1));
              }
              --scanLeft;
            } while (begin < scanLeft);
            hitBegin = (scanLeft == begin);
          }

          if (hitBegin) {
            break;
          }

          --scanLeft;
          if (scanRight == end) {
            --leftPivot;
            if (scanLeft != leftPivot) {
              SwapU16Lane(*scanLeft, *leftPivot);
            }
            --equalRight;
            SwapU16Lane(*leftPivot, *equalRight);
          }
          else {
            SwapU16Lane(*scanRight, *scanLeft);
            ++scanRight;
          }
        }

        if (scanRight == end) {
          break;
        }

        if (equalRight != scanRight) {
          SwapU16Lane(*leftPivot, *equalRight);
        }

        std::uint16_t* const scanRightCursor = scanRight;
        const std::uint16_t pivotValue = *leftPivot;
        *leftPivot = *scanRight;
        ++equalRight;
        ++leftPivot;
        ++scanRight;
        *scanRightCursor = pivotValue;
      }

      outBounds[1] = equalRight;
      outBounds[0] = leftPivot;
      return outBounds;
    }

    [[nodiscard]] int PushUInt16HeapEntryUpLocal(
      std::uint16_t* const heapValues,
      std::int32_t insertionIndex,
      const std::int32_t lowerBoundIndex,
      const std::uint16_t insertedValue
    ) noexcept
    {
      std::int32_t parentIndex = (insertionIndex - 1) / 2;
      if (lowerBoundIndex >= insertionIndex) {
        heapValues[insertionIndex] = insertedValue;
        return (parentIndex & 0xFFFF0000) | static_cast<int>(insertedValue);
      }

      while (lowerBoundIndex < insertionIndex) {
        const std::uint16_t parentValue = heapValues[parentIndex];
        if (parentValue >= insertedValue) {
          break;
        }

        heapValues[insertionIndex] = parentValue;
        insertionIndex = parentIndex;
        parentIndex = (parentIndex - 1) / 2;
      }

      heapValues[insertionIndex] = insertedValue;
      return parentIndex;
    }

    /**
     * Address: 0x0092D760 (FUN_0092D760)
     *
     * What it does:
     * Performs one max-heap sift-down lane and inserts `tailValue` back upward
     * into the resulting hole.
     */
    [[nodiscard]] int SiftDownAndInsertU16HeapTail(
      std::uint16_t* const heapValues,
      const std::int32_t rootIndex,
      const std::int32_t heapCount,
      const std::uint16_t tailValue
    ) noexcept
    {
      std::int32_t writeIndex = rootIndex;
      std::int32_t childIndex = 2 * rootIndex + 2;
      bool childEqualsCount = (childIndex == heapCount);

      while (childIndex < heapCount) {
        if (heapValues[childIndex] < heapValues[childIndex - 1]) {
          --childIndex;
        }

        heapValues[writeIndex] = heapValues[childIndex];
        writeIndex = childIndex;
        childIndex = 2 * childIndex + 2;
        childEqualsCount = (childIndex == heapCount);
      }

      if (childEqualsCount) {
        heapValues[writeIndex] = heapValues[heapCount - 1];
        writeIndex = heapCount - 1;
      }

      return PushUInt16HeapEntryUpLocal(heapValues, writeIndex, rootIndex, tailValue);
    }

    /**
     * Address: 0x0092E1C0 (FUN_0092E1C0)
     *
     * What it does:
     * Builds one `uint16_t` max-heap over `[begin, end)` by sift-down passes
     * from the internal-node midpoint toward the root.
     */
    [[nodiscard]] int BuildU16MaxHeapFromRange(
      std::uint16_t* const begin,
      std::uint16_t* const end
    ) noexcept
    {
      const std::int32_t elementCount = static_cast<std::int32_t>(end - begin);
      int result = elementCount;
      std::int32_t index = elementCount / 2;

      while (index > 0) {
        const std::uint16_t liftedValue = begin[index - 1];
        --index;
        result = SiftDownAndInsertU16HeapTail(begin, index, elementCount, liftedValue);
      }

      return result;
    }

    /**
     * Address: 0x0092EC40 (FUN_0092EC40)
     *
     * What it does:
     * Performs one in-place heap sort over `[begin, end)` by repeatedly moving
     * max root to the tail and restoring heap order on the shortened prefix.
     */
    [[nodiscard]] int HeapSortU16Range(
      std::uint16_t* const begin,
      std::uint16_t* const end
    ) noexcept
    {
      std::ptrdiff_t byteSpan = reinterpret_cast<std::uint8_t*>(end) - reinterpret_cast<std::uint8_t*>(begin);
      int result = static_cast<int>(byteSpan >> 1);
      if (result > 1) {
        do {
          const std::uint16_t tailValue = *reinterpret_cast<std::uint16_t*>(reinterpret_cast<std::uint8_t*>(begin) + byteSpan - 2);
          *reinterpret_cast<std::uint16_t*>(reinterpret_cast<std::uint8_t*>(begin) + byteSpan - 2) = begin[0];
          (void)SiftDownAndInsertU16HeapTail(begin, 0, static_cast<std::int32_t>((byteSpan - 2) >> 1), tailValue);
          byteSpan -= 2;
          result = static_cast<int>(byteSpan >> 1);
        } while ((byteSpan >> 1) > 1);
      }
      return result;
    }

    /**
     * Address: 0x0092E2A0 (FUN_0092E2A0)
     *
     * What it does:
     * Swaps heap root with the tail lane and restores heap order over the
     * shortened prefix.
     */
    [[nodiscard]] int ReplaceU16HeapRootWithTailAndSift(
      std::uint16_t* const begin,
      std::uint16_t* const end
    ) noexcept
    {
      const std::uint16_t tailValue = *(end - 1);
      *(end - 1) = *begin;
      return SiftDownAndInsertU16HeapTail(
        begin,
        0,
        static_cast<std::int32_t>(((reinterpret_cast<std::uint8_t*>(end) - reinterpret_cast<std::uint8_t*>(begin)) - 2) >> 1),
        tailValue
      );
    }

    /**
     * Address: 0x0092E8E0 (FUN_0092E8E0)
     *
     * What it does:
     * Conditionally performs one heap root-tail replacement/sift pass when
     * the active `uint16_t` heap span is wider than one element.
     */
    [[nodiscard]] int ReplaceU16HeapRootIfWideEnough(
      std::uint16_t* const begin,
      std::uint16_t* const end
    ) noexcept
    {
      const std::ptrdiff_t byteSpan = reinterpret_cast<std::uint8_t*>(end) - reinterpret_cast<std::uint8_t*>(begin);
      int result = static_cast<int>(byteSpan);
      if ((static_cast<int>(byteSpan) & ~1) > 2) {
        const std::uint16_t tailValue = *(end - 1);
        *(end - 1) = *begin;
        return SiftDownAndInsertU16HeapTail(begin, 0, static_cast<std::int32_t>((byteSpan - 2) >> 1), tailValue);
      }
      return result;
    }

    /**
     * Address: 0x0092E850 (FUN_0092E850)
     *
     * What it does:
     * Builds a max-heap for one `uint16_t` range when the aligned span has
     * more than one element.
     */
    [[nodiscard]] int BuildU16HeapIfWideEnough(
      std::uint16_t* const begin,
      std::uint16_t* const end
    ) noexcept
    {
      int result = static_cast<int>(reinterpret_cast<std::uintptr_t>(end));
      if ((static_cast<int>((reinterpret_cast<std::uint8_t*>(end) - reinterpret_cast<std::uint8_t*>(begin)) & ~1)) > 2) {
        return BuildU16MaxHeapFromRange(begin, end);
      }
      return result;
    }

    /**
     * Address: 0x0092EEE0 (FUN_0092EEE0)
     *
     * What it does:
     * Thunk lane forwarding directly to the `uint16_t` heap-sort range helper.
     */
    [[nodiscard]] int HeapSortU16RangeThunk(
      std::uint16_t* const begin,
      std::uint16_t* const end
    ) noexcept
    {
      return HeapSortU16Range(begin, end);
    }

    void InsertionSortU16Range(std::uint16_t* const begin, std::uint16_t* const end) noexcept
    {
      if (begin == end) {
        return;
      }

      for (std::uint16_t* cursor = begin + 1; cursor != end; ++cursor) {
        const std::uint16_t value = *cursor;
        std::uint16_t* write = cursor;

        if (value >= *begin) {
          std::uint16_t parentValue = *(cursor - 1);
          for (std::uint16_t* back = cursor - 1; value < parentValue; --back) {
            *write = parentValue;
            parentValue = *(back - 1);
            write = back;
          }
          *write = value;
        }
        else {
          for (std::uint16_t* back = cursor; back != begin;) {
            const std::uint16_t shifted = *--back;
            back[1] = shifted;
          }
          *begin = value;
        }
      }
    }

    /**
     * Address: 0x0092F4E0 (FUN_0092F4E0)
     *
     * What it does:
     * Sorts one `uint16_t` range with partition recursion under a depth budget,
     * using insertion sort for short ranges and heap fallback when budget is exhausted.
     */
    void IntroSortU16RangeWithBudget(
      std::uint16_t* begin,
      std::uint16_t* end,
      int budget
    )
    {
      std::uint16_t* rangeBegin = begin;
      std::uint16_t* rangeEnd = end;
      int elementCount = static_cast<int>(rangeEnd - rangeBegin);

      if (elementCount <= 32) {
        if (elementCount > 1) {
          InsertionSortU16Range(rangeBegin, rangeEnd);
        }
        return;
      }

      while (budget > 0) {
        std::uint16_t* bands[2]{};
        (void)PartitionU16RangeWithEqualBands(bands, rangeBegin, rangeEnd);
        std::uint16_t* const leftBoundary = bands[0];
        std::uint16_t* const rightBoundary = bands[1];

        budget = (budget / 2) + ((budget / 2) / 2);

        const int leftBytesAligned = static_cast<int>(
          (reinterpret_cast<std::uint8_t*>(leftBoundary) - reinterpret_cast<std::uint8_t*>(rangeBegin)) & ~1
        );
        const int rightBytesAligned = static_cast<int>(
          (reinterpret_cast<std::uint8_t*>(rangeEnd) - reinterpret_cast<std::uint8_t*>(rightBoundary)) & ~1
        );

        if (leftBytesAligned >= rightBytesAligned) {
          IntroSortU16RangeWithBudget(rightBoundary, rangeEnd, budget);
          rangeEnd = leftBoundary;
        }
        else {
          IntroSortU16RangeWithBudget(rangeBegin, leftBoundary, budget);
          rangeBegin = rightBoundary;
        }

        elementCount = static_cast<int>(rangeEnd - rangeBegin);
        if (elementCount <= 32) {
          if (elementCount > 1) {
            InsertionSortU16Range(rangeBegin, rangeEnd);
          }
          return;
        }
      }

      const int byteSpanAligned = static_cast<int>(
        (reinterpret_cast<std::uint8_t*>(rangeEnd) - reinterpret_cast<std::uint8_t*>(rangeBegin)) & ~1
      );
      if (byteSpanAligned > 2) {
        (void)BuildU16MaxHeapFromRange(rangeBegin, rangeEnd);
      }
      (void)HeapSortU16Range(rangeBegin, rangeEnd);
    }

    struct InlineBackedU16VectorRuntime
    {
      std::uint16_t* mStart;             // +0x00
      std::uint16_t* mEnd;               // +0x04
      std::uint16_t* mCapacity;          // +0x08
      std::uint16_t* mInlineStorageLane; // +0x0C
    };
    static_assert(sizeof(InlineBackedU16VectorRuntime) == 0x10, "InlineBackedU16VectorRuntime size must be 0x10");

    struct ClusterDataNodeListRuntime
    {
      std::int32_t mRefs;       // +0x00
      void* mReleaseObject;     // +0x04
      std::uint32_t mReleaseArg;// +0x08
      std::uint8_t mNodeCount;  // +0x0C
      std::uint8_t mNodes[1];   // +0x0D [x,z] pairs
    };
    static_assert(offsetof(ClusterDataNodeListRuntime, mNodeCount) == 0x0C, "ClusterDataNodeListRuntime::mNodeCount offset must be 0x0C");
    static_assert(offsetof(ClusterDataNodeListRuntime, mNodes) == 0x0D, "ClusterDataNodeListRuntime::mNodes offset must be 0x0D");

    void ResetInlineBackedU16Vector(InlineBackedU16VectorRuntime& vector) noexcept
    {
      if (vector.mStart != vector.mInlineStorageLane) {
        ::operator delete[](vector.mStart);
        vector.mStart = vector.mInlineStorageLane;
        vector.mCapacity = *reinterpret_cast<std::uint16_t**>(vector.mInlineStorageLane);
      }
      vector.mEnd = vector.mStart;
    }

    void EnsureInlineBackedU16CapacityForAppend(InlineBackedU16VectorRuntime& vector)
    {
      if (vector.mEnd != vector.mCapacity) {
        return;
      }

      const std::size_t count = static_cast<std::size_t>(vector.mEnd - vector.mStart);
      const std::size_t capacity = static_cast<std::size_t>(vector.mCapacity - vector.mStart);
      std::size_t newCapacity = count + 1;
      const std::size_t doubled = capacity * 2u;
      if (newCapacity < doubled) {
        newCapacity = doubled;
      }

      auto* const newStorage = static_cast<std::uint16_t*>(::operator new[](newCapacity * sizeof(std::uint16_t)));
      if (count != 0u) {
        std::memcpy(newStorage, vector.mStart, count * sizeof(std::uint16_t));
      }

      if (vector.mStart == vector.mInlineStorageLane) {
        *reinterpret_cast<std::uint16_t**>(vector.mInlineStorageLane) = vector.mCapacity;
      }
      else {
        ::operator delete[](vector.mStart);
      }

      vector.mStart = newStorage;
      vector.mEnd = newStorage + count;
      vector.mCapacity = newStorage + newCapacity;
    }

    void AppendPackedU16Node(InlineBackedU16VectorRuntime& vector, const std::uint8_t x, const std::uint8_t z)
    {
      EnsureInlineBackedU16CapacityForAppend(vector);
      if (vector.mEnd != nullptr) {
        *vector.mEnd = static_cast<std::uint16_t>(static_cast<std::uint16_t>(x) | (static_cast<std::uint16_t>(z) << 8u));
      }
      ++vector.mEnd;
    }

    /**
     * Address: 0x0092FE30 (FUN_0092FE30)
     *
     * What it does:
     * Gathers boundary nodes from 4x4 child clusters into one packed `uint16`
     * node list, then sorts and de-duplicates that packed node lane in-place.
     */
    [[maybe_unused]] [[nodiscard]] std::uint16_t* BuildSubclusterPackedNodeList(
      const gpg::HaStar::SubclusterData& subcluster,
      InlineBackedU16VectorRuntime& outNodes
    )
    {
      const std::int32_t level = subcluster.mLevel;
      const std::uint8_t levelShift = kClusterSizeLog2ByLevel[level];
      const std::uint32_t clusterMask = static_cast<std::uint32_t>(kClusterSizeByLevel[level + 1] - 1);

      ResetInlineBackedU16Vector(outNodes);

      std::uint32_t clusterIndex = 0u;
      for (std::uint32_t tileZ = 0u; tileZ < 4u; ++tileZ) {
        const std::uint32_t tileBaseZ = tileZ << levelShift;
        for (std::uint32_t tileX = 0u; tileX < 4u; ++tileX, ++clusterIndex) {
          const std::uint32_t tileBaseX = tileX << levelShift;
          const auto* const data = reinterpret_cast<const ClusterDataNodeListRuntime*>(subcluster.mClusters[clusterIndex].mData);
          if (data == nullptr || data->mNodeCount == 0u) {
            continue;
          }

          for (std::uint32_t nodeIndex = 0u; nodeIndex < data->mNodeCount; ++nodeIndex) {
            const std::uint8_t nodeXLocal = data->mNodes[nodeIndex * 2u];
            const std::uint8_t nodeZLocal = data->mNodes[nodeIndex * 2u + 1u];
            const std::uint32_t nodeX = tileBaseX + nodeXLocal;
            const std::uint32_t nodeZ = tileBaseZ + nodeZLocal;
            if ((nodeX & clusterMask) == 0u || (nodeZ & clusterMask) == 0u) {
              AppendPackedU16Node(
                outNodes,
                static_cast<std::uint8_t>(nodeX),
                static_cast<std::uint8_t>(nodeZ)
              );
            }
          }
        }
      }

      IntroSortU16RangeWithBudget(outNodes.mStart, outNodes.mEnd, static_cast<int>(outNodes.mEnd - outNodes.mStart));

      std::uint16_t* const end = outNodes.mEnd;
      std::uint16_t* result = outNodes.mStart;
      std::uint16_t* dedupEnd = end;
      std::uint16_t* write = outNodes.mStart;

      if (outNodes.mStart != end) {
        while (++result != end) {
          if (*write == *result) {
            for (++result; result != end; ++result) {
              if (*write != *result) {
                *++write = *result;
              }
            }
            dedupEnd = write + 1;
            break;
          }
          write = result;
        }
      }

      if (dedupEnd != end) {
        outNodes.mEnd = dedupEnd;
      }
      return result;
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

    /**
     * Address: 0x00954510 (FUN_00954510)
     *
     * What it does:
     * Erases one byte range `[eraseBegin, eraseEnd)` from a `fastvector_n<char,12>`
     * lane by shifting the trailing tail left and updating the end cursor.
     */
    [[maybe_unused]] [[nodiscard]] char* FastVectorN12CharEraseRange(
        FastVectorN12CharRuntime& view,
        char* const eraseBegin,
        char* const eraseEnd
    ) noexcept
    {
        if (eraseBegin != eraseEnd) {
            const std::ptrdiff_t tailSize = view.end - eraseEnd;
            char* const newEnd = eraseBegin + tailSize;
            if (tailSize > 0) {
                std::memmove(eraseBegin, eraseEnd, static_cast<std::size_t>(tailSize));
            }
            view.end = newEnd;
        }
        return eraseBegin;
    }

    /**
     * Address: 0x00954550 (FUN_00954550)
     *
     * What it does:
     * Releases dynamic storage for one `fastvector_n<char,12>` lane when active,
     * then restores the inline-storage cursor lanes.
     */
    [[maybe_unused]] [[nodiscard]] char* FastVectorN12CharReleaseHeapStorage(
        FastVectorN12CharRuntime& view
    ) noexcept
    {
        char* result = view.start;
        if (view.start == view.inlineOrigin) {
            view.end = result;
            return result;
        }

        ::operator delete[](view.start);
        view.start = view.inlineOrigin;
        if (view.inlineOrigin != nullptr) {
            result = *reinterpret_cast<char**>(view.inlineOrigin);
            view.capacityEnd = result;
        } else {
            result = nullptr;
            view.capacityEnd = nullptr;
        }
        view.end = view.start;
        return result;
    }

    using OccupationCacheRuntimeMap =
        std::unordered_map<OccupationCacheKey, gpg::HaStar::Cluster::Data*, OccupationKeyHash, OccupationKeyEq>;
    using SubclusterCacheRuntimeMap =
        std::unordered_map<SubclusterCacheKey, gpg::HaStar::Cluster::Data*, SubclusterKeyHash, SubclusterKeyEq>;

    struct RuntimeClusterCacheStore
    {
        OccupationCacheRuntimeMap mOccupation;
        SubclusterCacheRuntimeMap mSubcluster;
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

    /**
     * Address: 0x0076C0B0 (FUN_0076C0B0)
     *
     * What it does:
     * Implements the compiler-generated deleting-destructor lane for
     * `gpg::HaStar::Cluster`, handling both vector-destruct (`flags&2`) and
     * optional storage release (`flags&1`).
     */
    [[maybe_unused]] void* DestroyClusterWithDeleteFlags(gpg::HaStar::Cluster* start, const std::uint8_t flags)
    {
        if ((flags & 0x02u) != 0u) {
#if INTPTR_MAX == INT32_MAX
            static_assert(sizeof(gpg::HaStar::Cluster) == 0x04, "Cluster size must match 4-byte vector-dtor evidence");
#endif
            auto* const cookie = reinterpret_cast<std::uint32_t*>(start) - 1;
            const std::uint32_t count = *cookie;
            for (std::uint32_t index = 0u; index < count; ++index) {
                start[index].~Cluster();
            }

            if ((flags & 0x01u) != 0u) {
                ::operator delete[](cookie);
            }
            return cookie;
        }

        if (start != nullptr) {
            start->~Cluster();
        }

        if ((flags & 0x01u) != 0u) {
            ::operator delete(start);
        }
        return start;
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

    struct OccupationCacheIteratorRange
    {
        OccupationCacheRuntimeMap::iterator mFirst{};
        OccupationCacheRuntimeMap::iterator mLast{};
    };

    /**
     * Address: 0x00933EB0 (FUN_00933EB0)
     *
     * What it does:
     * Stores two source dword lanes into one two-dword destination record.
     */
    [[maybe_unused]] TwoDwordLaneRuntime* StoreTwoDwordLanesFromSources_A(
      TwoDwordLaneRuntime* const destination,
      const std::uint32_t* const sourceLane00,
      const std::uint32_t* const sourceLane04
    ) noexcept
    {
      destination->lane00 = *sourceLane00;
      destination->lane04 = *sourceLane04;
      return destination;
    }

    /**
     * Address: 0x009345B0 (FUN_009345B0)
     *
     * What it does:
     * Alias lane that stores two source dword lanes into one destination
     * two-dword record.
     */
    [[maybe_unused]] TwoDwordLaneRuntime* StoreTwoDwordLanesFromSources_B(
      TwoDwordLaneRuntime* const destination,
      const std::uint32_t* const sourceLane00,
      const std::uint32_t* const sourceLane04
    ) noexcept
    {
      destination->lane00 = *sourceLane00;
      destination->lane04 = *sourceLane04;
      return destination;
    }

    constexpr std::size_t kInitialOccupationBucketSlotCount = 9u;

    /**
     * Address: 0x00933EF0 (FUN_00933EF0, sub_933EF0)
     *
     * What it does:
     * Resolves the iterator range matching one occupation cache key.
     */
    [[maybe_unused]] OccupationCacheIteratorRange* FindOccupationCacheEquivalentRange(
        RuntimeClusterCacheStore& store,
        OccupationCacheIteratorRange& outRange,
        const gpg::HaStar::OccupationData& occupationData
    )
    {
        const OccupationCacheKey key = MakeOccupationCacheKey(occupationData);
        const auto range = store.mOccupation.equal_range(key);
        outRange.mFirst = range.first;
        outRange.mLast = range.second;
        return &outRange;
    }

    /**
     * Address: 0x00933F80 (FUN_00933F80, sub_933F80)
     *
     * What it does:
     * Erases one occupation-cache map node and returns its successor iterator.
     */
    [[maybe_unused]] OccupationCacheRuntimeMap::iterator* EraseOccupationCacheNode(
        RuntimeClusterCacheStore& store,
        OccupationCacheRuntimeMap::iterator& outNext,
        const OccupationCacheRuntimeMap::iterator nodeIt
    )
    {
        if (nodeIt == store.mOccupation.end()) {
            outNext = nodeIt;
            return &outNext;
        }

        outNext = store.mOccupation.erase(nodeIt);
        return &outNext;
    }

    /**
     * Address: 0x00934EA0 (FUN_00934EA0, sub_934EA0)
     *
     * What it does:
     * Clears occupation-cache nodes and restores default bucket-lane state.
     */
    [[maybe_unused]] int ResetOccupationCacheEntryStorage(RuntimeClusterCacheStore& store)
    {
        store.mOccupation.clear();
        store.mOccupation.rehash(kInitialOccupationBucketSlotCount);
        return 1;
    }

    /**
     * Address: 0x00935280 (FUN_00935280, sub_935280)
     *
     * What it does:
     * Erases one occupation-cache iterator range and returns the next iterator.
     */
    [[maybe_unused]] OccupationCacheRuntimeMap::iterator* EraseOccupationCacheRange(
        RuntimeClusterCacheStore& store,
        OccupationCacheRuntimeMap::iterator& outNext,
        OccupationCacheRuntimeMap::iterator first,
        const OccupationCacheRuntimeMap::iterator last
    )
    {
        if (first == store.mOccupation.begin() && last == store.mOccupation.end()) {
            (void)ResetOccupationCacheEntryStorage(store);
            outNext = store.mOccupation.begin();
            return &outNext;
        }

        while (first != last) {
            const OccupationCacheRuntimeMap::iterator eraseNode = first;
            ++first;
            OccupationCacheRuntimeMap::iterator erasedNext{};
            (void)EraseOccupationCacheNode(store, erasedNext, eraseNode);
        }

        outNext = first;
        return &outNext;
    }

    /**
     * Address: 0x00935480 (FUN_00935480, sub_935480)
     *
     * What it does:
     * Removes all occupation-cache entries matching one key and returns the
     * number of removed nodes.
     */
    [[maybe_unused]] int EraseOccupationCacheEntriesForKey(
        RuntimeClusterCacheStore& store,
        const gpg::HaStar::OccupationData& occupationData
    )
    {
        OccupationCacheIteratorRange range{};
        (void)FindOccupationCacheEquivalentRange(store, range, occupationData);

        int removedCount = 0;
        for (auto it = range.mFirst; it != range.mLast; ++it) {
            ++removedCount;
        }

        OccupationCacheRuntimeMap::iterator outNext{};
        (void)EraseOccupationCacheRange(store, outNext, range.mFirst, range.mLast);
        return removedCount;
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

    struct ClusterNodeCoordinateRuntime
    {
      std::uint8_t x;
      std::uint8_t z;
    };
    static_assert(sizeof(ClusterNodeCoordinateRuntime) == 0x02, "ClusterNodeCoordinateRuntime size must be 0x02");

    /**
     * Address: 0x0092E2E0 (FUN_0092E2E0, gpg::HaStar::Cluster::Node::CostTo)
     *
     * What it does:
     * Computes geometric node-to-node distance, quantizes traversal cost, and
     * writes one edge-cost byte into `out`.
     */
    [[maybe_unused]] std::uint8_t* QuantizeClusterNodeEdgeCost(
      std::uint8_t* const out,
      const ClusterNodeCoordinateRuntime& from,
      const ClusterNodeCoordinateRuntime& to,
      const float traversalCost
    )
    {
      const float dx = std::fabs(static_cast<float>(static_cast<int>(from.x) - static_cast<int>(to.x)));
      const float dz = std::fabs(static_cast<float>(static_cast<int>(from.z) - static_cast<int>(to.z)));
      const float distance = (dz <= dx) ? (dz * 0.41421354f + dx) : (dx * 0.41421354f + dz);
      *out = static_cast<std::uint8_t>(static_cast<int>(gpg::HaStar::Cluster::QuantizeEdgeCost(traversalCost, distance)));
      return out;
    }
}

namespace gpg::HaStar
{
/**
 * Address: 0x009315C0 (FUN_009315C0)
 *
 * What it does:
 * Initializes one `ICache` interface object by binding its vtable.
 */
ICache::ICache() = default;

/**
 * Address: 0x0076B8B0 (FUN_0076B8B0)
 *
 * IDA signature:
 * _DWORD *__usercall sub_76B8B0@<eax>(_DWORD *result@<eax>)
 *
 * What it does:
 * Writes the `IOccupationSource` vtable lane and returns the same object
 * pointer.
 */
IOccupationSource* InitializeOccupationSourceVTableCloneA(IOccupationSource* const source)
{
    return WriteOccupationSourceVTable(source);
}

/**
 * Address: 0x0076CB70 (FUN_0076CB70)
 *
 * IDA signature:
 * _DWORD *__usercall sub_76CB70@<eax>(_DWORD *result@<eax>)
 *
 * What it does:
 * Clone entry that writes the same `IOccupationSource` vtable lane and returns
 * the same object pointer.
 */
IOccupationSource* InitializeOccupationSourceVTableCloneB(IOccupationSource* const source)
{
    return WriteOccupationSourceVTable(source);
}

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
 * Address: 0x00954110 (FUN_00954110,
 * ?SetData@Cluster@HaStar@gpg@@QAEXPBUNode@123@PBUEdge@123@I@Z)
 *
 * IDA signature:
 * void __thiscall gpg::HaStar::Cluster::SetData(
 *   gpg::HaStar::Cluster *this@<ecx>,
 *   const Node *nodes, const Edge *edges, unsigned int nodeCount);
 *
 * What it does:
 * If the current payload is null, has a different node count, or is shared
 * (refcount != 1), allocates a fresh payload sized for the requested node
 * count (`header + nodeCount*2 + nodeCount*(nodeCount-1)/2`) and releases
 * the prior payload (invoking its dispose-callback when refcount hits zero).
 * Then copies `nodeCount` `Node` entries (2 bytes each) and
 * `nodeCount*(nodeCount-1)/2` `Edge` buckets (1 byte each) into the trailing
 * storage. Asserts `nodeCount < 256`.
 */
void Cluster::SetData(
    const Cluster::Node* const nodes,
    const Cluster::Edge* const edges,
    const unsigned int nodeCount
)
{
    if (nodeCount >= 0x100u) {
        gpg::HandleAssertFailure(
            "nnodes < 256",
            58,
            "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\Cluster.cpp"
        );
    }

    constexpr std::size_t kHeaderBytes = 0x0Du; // offsetof(Data, mNodes)
    const std::size_t nodeBytes = static_cast<std::size_t>(nodeCount) * sizeof(Node);
    const std::size_t edgeBytes = static_cast<std::size_t>(nodeCount) * (nodeCount - 1u) / 2u;

    Cluster::Data* payload = mData;
    const bool reuseInPlace = (payload != nullptr)
        && (static_cast<unsigned int>(payload->mNodeCount) == nodeCount)
        && (payload->mRefs == 1);

    if (!reuseInPlace) {
        const std::size_t totalBytes = kHeaderBytes + nodeBytes + edgeBytes;
        auto* const replacement = static_cast<Cluster::Data*>(::operator new[](totalBytes));
        replacement->mRefs = 1;
        replacement->mReleaseObject = nullptr;
        replacement->mReleaseArg = 0u;
        replacement->mNodeCount = static_cast<std::uint8_t>(nodeCount);

        if (mData != nullptr) {
            --mData->mRefs;
            Cluster::Data* const prior = mData;
            if (prior->mRefs == 0) {
                if (prior->mReleaseObject != nullptr) {
                    using ReleaseFn = void(__thiscall*)(void*, std::uint32_t);
                    auto** const vtable = *reinterpret_cast<void***>(prior->mReleaseObject);
                    auto* const releaseFn = reinterpret_cast<ReleaseFn>(vtable[0]);
                    releaseFn(prior->mReleaseObject, prior->mReleaseArg);
                }
                ::operator delete[](prior);
            }
        }

        mData = replacement;
        payload = replacement;
    }

    // Node array begins at `mNodes` (offset 0x0D); edges follow it.
    auto* const nodeBase = reinterpret_cast<std::byte*>(&payload->mNodes[0]);
    if (nodes != nullptr && nodeBytes != 0u) {
        std::memcpy(nodeBase, nodes, nodeBytes);
    }
    if (edges != nullptr && edgeBytes != 0u) {
        std::memcpy(nodeBase + nodeBytes, edges, edgeBytes);
    }
}

/**
 * Address: 0x009552D0 (FUN_009552D0,
 * ?ClusterBuild@HaStar@gpg@@YA?AVCluster@12@ABUOccupationData@12@@Z)
 *
 * Notes:
 * Full occupancy-cell-to-cluster extraction is still being recovered; this
 * stub preserves the binary's allocation + `SetData` wiring so the payload is
 * a valid refcounted empty cluster until the edge-extraction lane is finished.
 */
Cluster ClusterBuild(const OccupationData& occupationData)
{
    (void)occupationData;

    Cluster cluster{};
    cluster.SetData(nullptr, nullptr, 0u);
    return cluster;
}

/**
 * Address: 0x009310E0 (FUN_009310E0,
 * ?ClusterBuild@HaStar@gpg@@YA?AVCluster@12@ABUSubclusterData@12@@Z)
 *
 * Notes:
 * Full 4x4 subcluster-merge lane is still being recovered; this stub
 * preserves the binary's `SetData` wiring (empty payload) and scratch-pad
 * reset so the payload is a valid refcounted empty cluster until the child
 * merging lane is finished.
 */
Cluster ClusterBuild(const SubclusterData& subclusterData)
{
    [[maybe_unused]] ClusterSearchScratch searchScratch{};
    searchScratch.Reset();
    (void)subclusterData;

    Cluster cluster{};
    cluster.SetData(nullptr, nullptr, 0u);
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
        // Drain any ring-list-style subcluster cache buckets that were
        // attached to this cache base (binary runs FUN_00933380 over the
        // ring head before freeing the bucket vector storage).
        // `DrainSubclusterRingsAttachedToCacheBase` lives in the
        // anonymous namespace at the top of this TU (resolved via the
        // same unqualified-lookup rule used for `ReleaseRuntimeClusterCacheStore`).
        ReleaseRuntimeClusterCacheStore(mCacheTree);
        DrainSubclusterRingsAttachedToCacheBase(mCacheTree);
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
 * Address: 0x008E3C80 (FUN_008E3C80)
 */
void Subcluster::ResetStorage(const int width, const int height)
{
    DestroySubclusterStorage(*this);
    CreateSubclusterStorage(*this, width, height);
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
 * Address: 0x008E3530 (FUN_008E3530,
 * ?ClusterRect@ClusterMap@HaStar@gpg@@QBE?AV?$Rect2@H@3@ABV43@E@Z)
 */
gpg::Rect2i ClusterMap::ClusterRect(const gpg::Rect2i& worldRect, const std::uint8_t level) const
{
    const int clusterSize = static_cast<int>(kClusterSizeByLevel[level]);
    const int alignMask = -clusterSize;

    gpg::Rect2i out{};
    out.z1 = (alignMask & (worldRect.z1 + clusterSize - 1)) + 1;
    if (out.z1 >= mHeight) {
        out.z1 = mHeight;
    }

    out.x1 = (alignMask & (worldRect.x1 + clusterSize - 1)) + 1;
    if (out.x1 >= mWidth) {
        out.x1 = mWidth;
    }

    out.z0 = alignMask & (worldRect.z0 - 1);
    if (out.z0 < 0) {
        out.z0 = 0;
    }

    out.x0 = alignMask & (worldRect.x0 - 1);
    if (out.x0 < 0) {
        out.x0 = 0;
    }

    return out;
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

    (void)checkLevel.ClearBitAndReturnWord(width, static_cast<unsigned int>(height));
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
