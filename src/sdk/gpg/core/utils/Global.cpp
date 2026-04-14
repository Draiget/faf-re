#include "Global.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"

namespace moho
{
    [[nodiscard]] std::uint8_t APP_GetAqtimeInstrumentationMode();
}

namespace
{
    constexpr std::uint32_t kPageShift = 12u;
    constexpr std::uint32_t kPageSizeBytes = (1u << kPageShift);
    constexpr std::uint32_t kMaxPageIndex = 0xC0000u;
    constexpr std::uint32_t kSmallBlockClassCount = 44u;
    constexpr std::uint32_t kFreeRegionBucketCount = 256u;
    constexpr std::uint32_t kPageOwnerMapBytes = 0x3FF000u;
    constexpr std::uint32_t kPrimaryHeapReserveBytes = 0x20000000u;
    constexpr std::uint32_t kThreadCacheSizeBytes = 0x214u;
    constexpr std::uint32_t kHeapRecordSizeBytes = 0x28u;
    constexpr std::uint32_t kThreadCacheTrimBytes = 0x200000u;

    constexpr std::uintptr_t kRecordTagFree = 0u;
    constexpr std::uintptr_t kRecordTagSmallBlocks = 1u;
    constexpr std::uintptr_t kRecordTagLargeAllocation = 2u;

    struct SmallBlockNode
    {
        SmallBlockNode* next;
    };

    struct ThreadSmallBlockLane
    {
        SmallBlockNode* head;
        std::int32_t count;
        std::int32_t lowWatermark;
    };
    static_assert(sizeof(ThreadSmallBlockLane) == 0x0C, "ThreadSmallBlockLane size must be 0x0C");

    struct ThreadHeapCache
    {
        ThreadSmallBlockLane lanes[kSmallBlockClassCount];
        std::int32_t cachedBytes;
    };
    static_assert(sizeof(ThreadHeapCache) == 0x214, "ThreadHeapCache size must be 0x214");

    struct HeapRecord
    {
        std::uintptr_t recordTag;
        void* reservedBase;
        void* allocation;
        std::uint32_t sizePages;
        HeapRecord* previous;
        HeapRecord** next;
        std::int32_t kind;
        SmallBlockNode* tail;
        std::int32_t blocks;
        std::int32_t lowWatermark;
    };
    static_assert(offsetof(HeapRecord, recordTag) == 0x00, "HeapRecord::recordTag offset must be 0x00");
    static_assert(offsetof(HeapRecord, reservedBase) == 0x04, "HeapRecord::reservedBase offset must be 0x04");
    static_assert(offsetof(HeapRecord, allocation) == 0x08, "HeapRecord::allocation offset must be 0x08");
    static_assert(offsetof(HeapRecord, sizePages) == 0x0C, "HeapRecord::sizePages offset must be 0x0C");
    static_assert(offsetof(HeapRecord, previous) == 0x10, "HeapRecord::previous offset must be 0x10");
    static_assert(offsetof(HeapRecord, next) == 0x14, "HeapRecord::next offset must be 0x14");
    static_assert(offsetof(HeapRecord, kind) == 0x18, "HeapRecord::kind offset must be 0x18");
    static_assert(offsetof(HeapRecord, tail) == 0x1C, "HeapRecord::tail offset must be 0x1C");
    static_assert(offsetof(HeapRecord, blocks) == 0x20, "HeapRecord::blocks offset must be 0x20");
    static_assert(offsetof(HeapRecord, lowWatermark) == 0x24, "HeapRecord::lowWatermark offset must be 0x24");
    static_assert(sizeof(HeapRecord) == 0x28, "HeapRecord size must be 0x28");

    struct AllocatorLockToken
    {
        std::uint8_t hasLock;
    };
    static_assert(sizeof(AllocatorLockToken) == 0x01, "AllocatorLockToken size must be 0x01");

    struct SmallBlockRequestLane
    {
        SmallBlockNode* head;
        std::int32_t count;
        std::int32_t lowWatermark;
    };
    static_assert(sizeof(SmallBlockRequestLane) == 0x0C, "SmallBlockRequestLane size must be 0x0C");

    constexpr std::array<std::uint32_t, kSmallBlockClassCount> kSmallBlockSizes = {
      4u,
      8u,
      12u,
      16u,
      20u,
      24u,
      28u,
      32u,
      40u,
      48u,
      56u,
      64u,
      80u,
      96u,
      112u,
      128u,
      160u,
      192u,
      224u,
      256u,
      320u,
      384u,
      448u,
      512u,
      640u,
      768u,
      896u,
      1024u,
      1280u,
      1536u,
      1792u,
      2048u,
      2560u,
      3072u,
      3584u,
      4096u,
      5120u,
      6144u,
      7168u,
      8192u,
      10240u,
      12288u,
      14336u,
      16384u,
    };

    ThreadHeapCache* const kThreadCacheDisabled = reinterpret_cast<ThreadHeapCache*>(~std::uintptr_t(0));

    gpg::mem_hook_t gMemHook = nullptr;

    CRITICAL_SECTION gAllocatorSentinel{};
    bool gAllocatorSentinelIsCritical = false;

    std::uint32_t gAllocationType = 0;

    HeapRecord** gPageOwnerByPage = nullptr;
    std::uint8_t* gHeapBase = nullptr;
    std::uint32_t gHeapUsed = 0;

    std::uint32_t gHeapReserved = 0;
    std::uint32_t gHeapCommitted = 0;
    std::uint32_t gHeapTotal = 0;
    std::uint32_t gHeapInSmallBlocks = 0;
    std::uint32_t gHeapInUse = 0;

    HeapRecord* gFreeRegionBuckets[kFreeRegionBucketCount]{};
    HeapRecord* gSmallBlockPrototypes[kSmallBlockClassCount]{};
    HeapRecord* gExhaustedSmallBlockPrototypes[kSmallBlockClassCount]{};

    HeapRecord* gNextAvailableHeapRecord = nullptr;
    HeapRecord* gLargeAllocationList = nullptr;

    void __stdcall TlsCallback_1(void* moduleHandle, DWORD reason, void* reserved);

    struct ThreadCacheTlsDetachBridge
    {
        ~ThreadCacheTlsDetachBridge()
        {
            TlsCallback_1(nullptr, DLL_THREAD_DETACH, nullptr);
        }
    };

    thread_local ThreadHeapCache* gThreadHeapCache = nullptr;
    [[maybe_unused]] thread_local ThreadCacheTlsDetachBridge gThreadCacheTlsDetachBridge{};

    [[nodiscard]] constexpr std::uint32_t BytesToPages(const std::uint32_t bytes)
    {
        return (bytes + (kPageSizeBytes - 1u)) >> kPageShift;
    }

    [[nodiscard]] std::uint32_t AddressToPageIndex(const void* const address)
    {
        return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(address) >> kPageShift);
    }

    [[nodiscard]] HeapRecord* GetPageOwner(const void* const address)
    {
        return gPageOwnerByPage[AddressToPageIndex(address)];
    }

    void SetPageOwnerRange(void* const startAddress, const std::uint32_t pageCount, HeapRecord* const owner)
    {
        if (pageCount == 0 || startAddress == nullptr || gPageOwnerByPage == nullptr) {
            return;
        }

        const std::uint32_t start = AddressToPageIndex(startAddress);
        for (std::uint32_t page = 0; page < pageCount; ++page) {
            gPageOwnerByPage[start + page] = owner;
        }
    }

    void UnlinkRecord(HeapRecord* const record)
    {
        if (record == nullptr || record->next == nullptr) {
            return;
        }

        if (record->previous != nullptr) {
            record->previous->next = record->next;
        }
        *record->next = record->previous;
        record->previous = nullptr;
        record->next = nullptr;
    }

    void LinkRecordHead(HeapRecord*& head, HeapRecord* const record)
    {
        record->previous = head;
        if (head != nullptr) {
            head->next = &record->previous;
        }
        record->next = &head;
        head = record;
    }

    [[nodiscard]] SmallBlockNode* PopLaneNode(ThreadSmallBlockLane& lane)
    {
        SmallBlockNode* const node = lane.head;
        if (node == nullptr) {
            return nullptr;
        }

        lane.head = node->next;
        --lane.count;
        if (lane.count < lane.lowWatermark) {
            lane.lowWatermark = lane.count;
        }
        return node;
    }

    void PushLaneNode(ThreadSmallBlockLane& lane, SmallBlockNode* const node)
    {
        node->next = lane.head;
        lane.head = node;
        ++lane.count;
    }

    [[nodiscard]] ThreadSmallBlockLane& GetLane(ThreadHeapCache* const cache, const std::uint32_t kind)
    {
        return cache->lanes[kind];
    }

    [[nodiscard]] constexpr std::uint32_t GetBlockSize(const std::uint32_t kind)
    {
        return kSmallBlockSizes[kind];
    }

    [[nodiscard]] std::uint32_t ClampSizeMinusOneToBucket(std::uint32_t x);
    [[nodiscard]] std::uint32_t GetSmallBlockIndex(std::uint32_t bytes);
    [[nodiscard]] std::uint8_t* ReserveAllocatorPages(std::uint32_t pages, std::uint8_t** outReserveBase);

    [[nodiscard]] HeapRecord* ConstructHeapRecord(
      HeapRecord* object,
      void* allocation,
      std::uint32_t sizePages,
      std::uintptr_t recordTag,
      void* reservedBase,
      std::int32_t kind
    );

    [[nodiscard]] HeapRecord* PopHeapRecord(HeapRecord* node);
    [[nodiscard]] HeapRecord* InsertRecordIntoFreeBucket(HeapRecord* record);

    void SplitHeapRecord(std::uint32_t requestedPages, HeapRecord* record);
    [[nodiscard]] HeapRecord* ReleaseHeapRecord(HeapRecord* record);

    [[nodiscard]] HeapRecord* PushHeapBlock(SmallBlockNode* block, std::int32_t kind);
    void TrimThreadCache(ThreadHeapCache* cache, bool flushAll);
    void FlushCurrentThreadHeapCache();

    [[nodiscard]] bool AllocateNewBlock(std::uint32_t kindPages);
    [[nodiscard]] HeapRecord* AllocateFreeRegion(std::uint32_t pages);
    [[nodiscard]] HeapRecord* AllocateAndSplitFreeRegion(std::uint32_t pages);
    [[nodiscard]] void* AllocateLargeRegion(std::uint32_t bytes);

    void AllocateSmallBlocksAmount(SmallBlockRequestLane* request, std::uint32_t kind, std::int32_t count);

    [[nodiscard]] SmallBlockNode* AllocateInSmallBlock(std::uint32_t sizeBytes);

    [[nodiscard]] AllocatorLockToken* EnterAllocatorLock(AllocatorLockToken* token, bool shouldLock);
    void LeaveAllocatorLock(AllocatorLockToken* token);

    [[nodiscard]] SmallBlockNode* InitAllocatorSentinel(std::uint8_t* hasLockOut);

    [[nodiscard]] ThreadHeapCache* GetOrCreateThreadHeapCache();

    /**
     * Address: 0x00957C10 (FUN_00957C10, func_Sub1Cap255)
     *
     * What it does:
     * Maps page counts to free-region bucket indices `[0,255]`.
     */
    [[nodiscard]] std::uint32_t ClampSizeMinusOneToBucket(std::uint32_t x)
    {
        if (x < kFreeRegionBucketCount) {
            return x - 1u;
        }
        return kFreeRegionBucketCount - 1u;
    }

    /**
     * Address: 0x00957C30 (FUN_00957C30, func_GetSmallBlockIndex)
     *
     * What it does:
     * Returns the small-block class index for a requested byte size.
     */
    [[nodiscard]] std::uint32_t GetSmallBlockIndex(const std::uint32_t bytes)
    {
        std::uint32_t lower = 0;
        std::uint32_t upper = kSmallBlockClassCount;

        while (lower < upper) {
            const std::uint32_t middle = (lower + upper) / 2u;
            const std::uint32_t value = kSmallBlockSizes[middle];
            if (bytes >= value) {
                if (bytes <= value) {
                    return middle;
                }
                lower = middle + 1u;
            } else {
                upper = middle;
            }
        }

        return lower;
    }

    /**
     * Address: 0x00957D40 (FUN_00957D40, sub_957D40)
     *
     * What it does:
     * Reserves allocator pages from the primary heap window when possible,
     * otherwise from a new `VirtualAlloc(MEM_RESERVE)` region.
     */
    [[nodiscard]] std::uint8_t* ReserveAllocatorPages(
      const std::uint32_t pages, std::uint8_t** const outReserveBase
    )
    {
        const std::uint32_t reserveBytes = pages << kPageShift;
        if (reserveBytes + gHeapTotal <= kPrimaryHeapReserveBytes) {
            if (outReserveBase != nullptr) {
                *outReserveBase = gHeapBase;
            }
            std::uint8_t* const allocation = gHeapBase + gHeapUsed;
            gHeapUsed += reserveBytes;
            return allocation;
        }

        gHeapReserved += reserveBytes;
        std::uint8_t* const reservedBase = static_cast<std::uint8_t*>(
          ::VirtualAlloc(
            nullptr,
            reserveBytes,
            static_cast<DWORD>(gAllocationType | MEM_RESERVE),
            PAGE_READWRITE
          )
        );
        if (outReserveBase != nullptr) {
            *outReserveBase = reservedBase;
        }
        return reservedBase;
    }

    /**
     * Address: 0x00957DA0 (FUN_00957DA0, func_HeapBlockCtr)
     *
     * What it does:
     * Initializes a heap-record descriptor and assigns page-owner map entries.
     */
    [[nodiscard]] HeapRecord* ConstructHeapRecord(
      HeapRecord* const object,
      void* const allocation,
      const std::uint32_t sizePages,
      const std::uintptr_t recordTag,
      void* const reservedBase,
      const std::int32_t kind
    )
    {
        object->recordTag = recordTag;
        object->reservedBase = reservedBase;
        object->allocation = allocation;
        object->sizePages = sizePages;
        object->previous = nullptr;
        object->next = nullptr;
        object->kind = kind;
        object->tail = nullptr;
        object->blocks = 0;
        object->lowWatermark = 0;

        SetPageOwnerRange(allocation, sizePages, object);
        return object;
    }

    /**
     * Address: 0x00957E00 (FUN_00957E00, func_InitAllocatorSentinel)
     *
     * What it does:
     * Initializes allocator critical section and reserve ranges on first use.
     */
    [[nodiscard]] SmallBlockNode* InitAllocatorSentinel(std::uint8_t* const hasLockOut)
    {
        ::InitializeCriticalSectionAndSpinCount(&gAllocatorSentinel, 0xFA0u);
        ::EnterCriticalSection(&gAllocatorSentinel);

        if (hasLockOut != nullptr) {
            *hasLockOut = 1;
        }
        gAllocatorSentinelIsCritical = true;

        gPageOwnerByPage = static_cast<HeapRecord**>(
          ::VirtualAlloc(
            nullptr,
            kPageOwnerMapBytes,
            static_cast<DWORD>(gAllocationType | MEM_COMMIT),
            PAGE_READWRITE
          )
        );

        gHeapBase = static_cast<std::uint8_t*>(
          ::VirtualAlloc(
            nullptr,
            kPrimaryHeapReserveBytes,
            static_cast<DWORD>(gAllocationType | MEM_RESERVE),
            PAGE_READWRITE
          )
        );

        gHeapUsed = 0;
        gHeapReserved = kPrimaryHeapReserveBytes;

        gNextAvailableHeapRecord = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes));
        return reinterpret_cast<SmallBlockNode*>(gNextAvailableHeapRecord);
    }

    /**
     * Address: 0x00957F20 (FUN_00957F20, func_PopHeapBlock)
     *
     * What it does:
     * Unlinks a heap-record node from its intrusive list.
     */
    [[nodiscard]] HeapRecord* PopHeapRecord(HeapRecord* const node)
    {
        UnlinkRecord(node);
        return node;
    }

    /**
     * Address: 0x00957F40 (FUN_00957F40, func_Dtr0001)
     *
     * What it does:
     * Resets all per-thread small-block cache lanes and counters.
     */
    [[nodiscard]] ThreadHeapCache* ResetThreadHeapCache(ThreadHeapCache* const cache)
    {
        for (auto& lane : cache->lanes) {
            lane.head = nullptr;
            lane.count = 0;
            lane.lowWatermark = 0;
        }
        cache->cachedBytes = 0;
        return cache;
    }

    /**
     * Address: 0x00957F70 (FUN_00957F70, sub_957F70)
     *
     * What it does:
     * Optionally enters allocator critical section and marks lock state.
     */
    [[nodiscard]] AllocatorLockToken* EnterAllocatorLock(AllocatorLockToken* const token, const bool shouldLock)
    {
        token->hasLock = 0;
        if (shouldLock) {
            ::EnterCriticalSection(&gAllocatorSentinel);
            token->hasLock = 1;
        }
        return token;
    }

    /**
     * Address: 0x00957FA0 (FUN_00957FA0)
     *
     * What it does:
     * Leaves allocator critical section if lock token still owns it.
     */
    void LeaveAllocatorLock(AllocatorLockToken* const token)
    {
        if (token->hasLock != 0) {
            ::LeaveCriticalSection(&gAllocatorSentinel);
            token->hasLock = 0;
        }
    }

    /**
     * Address: 0x00957FC0 (FUN_00957FC0, sub_957FC0)
     *
     * What it does:
     * Inserts a free-region heap record into size bucket lists.
     */
    [[nodiscard]] HeapRecord* InsertRecordIntoFreeBucket(HeapRecord* const record)
    {
        const std::uint32_t bucket = ClampSizeMinusOneToBucket(record->sizePages);
        HeapRecord*& bucketHead = gFreeRegionBuckets[bucket];
        HeapRecord* insertedBefore = bucketHead;

        if (bucket == (kFreeRegionBucketCount - 1u) && insertedBefore != nullptr && record->sizePages > insertedBefore->sizePages) {
            while (insertedBefore->previous != nullptr && record->sizePages > insertedBefore->previous->sizePages) {
                insertedBefore = insertedBefore->previous;
            }

            HeapRecord** const insertionLink = &insertedBefore->previous;
            HeapRecord* const current = insertedBefore->previous;
            record->previous = current;
            if (current != nullptr) {
                current->next = &record->previous;
            }
            *insertionLink = record;
            record->next = insertionLink;
            return current;
        }

        record->previous = bucketHead;
        if (bucketHead != nullptr) {
            bucketHead->next = &record->previous;
        }
        record->next = &bucketHead;
        bucketHead = record;
        return insertedBefore;
    }

    /**
     * Address: 0x00958040 (FUN_00958040, sub_958040)
     *
     * What it does:
     * Splits a larger free-region record into requested and remainder records.
     */
    void SplitHeapRecord(const std::uint32_t requestedPages, HeapRecord* const record)
    {
        if (requestedPages >= record->sizePages) {
            return;
        }

        const std::uint32_t tailPages = record->sizePages - requestedPages;
        HeapRecord* tailRecord = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes));
        if (tailRecord == nullptr) {
            tailRecord = gNextAvailableHeapRecord;
            gNextAvailableHeapRecord = nullptr;
        }

        std::uint8_t* const tailAddress = static_cast<std::uint8_t*>(record->allocation) + (requestedPages << kPageShift);
        tailRecord->recordTag = kRecordTagFree;
        tailRecord->reservedBase = record->reservedBase;
        tailRecord->allocation = tailAddress;
        tailRecord->sizePages = tailPages;
        tailRecord->previous = nullptr;
        tailRecord->next = nullptr;
        tailRecord->kind = 0;

        SetPageOwnerRange(tailAddress, tailPages, tailRecord);
        InsertRecordIntoFreeBucket(tailRecord);

        record->sizePages = requestedPages;
        if (gNextAvailableHeapRecord == nullptr) {
            gNextAvailableHeapRecord = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes));
        }
    }

    /**
     * Address: 0x009580D0 (FUN_009580D0, func_FreeSmallBlock)
     *
     * What it does:
     * Decommits a record range and coalesces neighboring free regions.
     */
    [[nodiscard]] HeapRecord* ReleaseHeapRecord(HeapRecord* const record)
    {
        HeapRecord* mergedRight = nullptr;
        HeapRecord* mergedLeft = nullptr;

        const SIZE_T releaseBytes = static_cast<SIZE_T>(record->sizePages) << kPageShift;
        record->recordTag = kRecordTagFree;
        ::VirtualFree(record->allocation, releaseBytes, MEM_DECOMMIT);

        const std::uint32_t pageBegin = AddressToPageIndex(record->allocation);
        const std::uint32_t pageEnd = pageBegin + record->sizePages;

        if (pageEnd < kMaxPageIndex) {
            HeapRecord* const right = gPageOwnerByPage[pageEnd];
            if (right != nullptr && right->recordTag == kRecordTagFree && right->reservedBase == record->reservedBase) {
                PopHeapRecord(right);
                record->sizePages += right->sizePages;
                SetPageOwnerRange(right->allocation, right->sizePages, record);
                mergedRight = right;
            }
        }

        if (pageBegin > 0u) {
            HeapRecord* const left = gPageOwnerByPage[pageBegin - 1u];
            if (left != nullptr && left->recordTag == kRecordTagFree && left->reservedBase == record->reservedBase) {
                PopHeapRecord(left);
                record->sizePages += left->sizePages;
                record->allocation = left->allocation;
                SetPageOwnerRange(left->allocation, left->sizePages, record);
                mergedLeft = left;
            }
        }

        HeapRecord* result = InsertRecordIntoFreeBucket(record);

        if (mergedRight != nullptr) {
            const std::uint32_t recordKind = GetSmallBlockIndex(kHeapRecordSizeBytes);
            result = PushHeapBlock(reinterpret_cast<SmallBlockNode*>(mergedRight), static_cast<std::int32_t>(recordKind));
        }

        if (mergedLeft != nullptr) {
            const std::uint32_t recordKind = GetSmallBlockIndex(kHeapRecordSizeBytes);
            result = PushHeapBlock(reinterpret_cast<SmallBlockNode*>(mergedLeft), static_cast<std::int32_t>(recordKind));
        }

        return result;
    }

    /**
     * Address: 0x00958200 (FUN_00958200, func_PushHeap)
     *
     * What it does:
     * Returns one small block to its owning prototype and frees full-page prototypes.
     */
    [[nodiscard]] HeapRecord* PushHeapBlock(SmallBlockNode* const block, const std::int32_t kind)
    {
        HeapRecord* owner = GetPageOwner(block);
        if (owner->blocks == 0) {
            UnlinkRecord(owner);
            LinkRecordHead(gSmallBlockPrototypes[kind], owner);
        }

        block->next = owner->tail;
        ++owner->blocks;
        owner->tail = block;

        const std::uint32_t blockSize = GetBlockSize(static_cast<std::uint32_t>(kind));
        const std::uint32_t regionBytes = owner->sizePages << kPageShift;
        const std::uint32_t fullBlockCount = regionBytes / blockSize;

        gHeapInUse -= blockSize;
        gHeapInSmallBlocks += blockSize;

        if (static_cast<std::uint32_t>(owner->blocks) == fullBlockCount) {
            UnlinkRecord(owner);
            ReleaseHeapRecord(owner);
            gHeapCommitted -= regionBytes;
            gHeapInSmallBlocks -= regionBytes;
        }

        return owner;
    }

    /**
     * Address: 0x009582C0 (FUN_009582C0, sub_9582C0)
     *
     * What it does:
     * Trims per-thread cache lanes back into global allocator structures.
     */
    void TrimThreadCache(ThreadHeapCache* const cache, const bool flushAll)
    {
        for (std::uint32_t kind = 0; kind < kSmallBlockClassCount; ++kind) {
            ThreadSmallBlockLane& lane = cache->lanes[kind];
            const std::uint32_t blockSize = GetBlockSize(kind);

            const std::int32_t initialFlushCount = flushAll ? lane.count : ((lane.lowWatermark + 1) / 2);
            std::int32_t remainingFlush = initialFlushCount;
            while (remainingFlush > 0) {
                SmallBlockNode* const node = PopLaneNode(lane);
                PushHeapBlock(node, static_cast<std::int32_t>(kind));
                --remainingFlush;
            }

            lane.lowWatermark = lane.count;
            cache->cachedBytes -= initialFlushCount * static_cast<std::int32_t>(blockSize);
        }
    }

    /**
     * Address: 0x00958360 (FUN_00958360, sub_958360)
     *
     * What it does:
     * Flushes and releases the current thread's allocator cache object.
     */
    void FlushCurrentThreadHeapCache()
    {
        ThreadHeapCache* const cache = gThreadHeapCache;
        if (cache == nullptr) {
            return;
        }

        ::EnterCriticalSection(&gAllocatorSentinel);
        TrimThreadCache(cache, true);

        const std::uint32_t recordKind = GetSmallBlockIndex(kThreadCacheSizeBytes);
        PushHeapBlock(reinterpret_cast<SmallBlockNode*>(cache), static_cast<std::int32_t>(recordKind));

        gThreadHeapCache = kThreadCacheDisabled;
        ::LeaveCriticalSection(&gAllocatorSentinel);
    }

    /**
     * Address: 0x009583F0 (FUN_009583F0, TlsCallback_1)
     *
     * What it does:
     * On thread detach (`reason == 3`), flushes current thread allocator cache.
     */
    void __stdcall TlsCallback_1(void* const moduleHandle, const DWORD reason, void* const reserved)
    {
        (void)moduleHandle;
        (void)reserved;

        if (reason == DLL_THREAD_DETACH) {
            FlushCurrentThreadHeapCache();
        }
    }

    /**
     * Address: 0x00958400 (FUN_00958400, func_AllocateNewBlock)
     *
     * What it does:
     * Reserves additional heap pages and seeds free-region metadata records.
     */
    [[nodiscard]] bool AllocateNewBlock(const std::uint32_t kindPages)
    {
        std::uint32_t totalPages = 0;
        if (gHeapTotal == 0) {
            totalPages = 0x4000u;
        } else if (gHeapTotal <= 0x2000000u) {
            totalPages = (gHeapTotal >> kPageShift);
        } else {
            totalPages = 0x2000u;
        }

        HeapRecord* metadataRecord = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes));

        std::uint32_t requiredPages = kindPages;
        if (metadataRecord == nullptr) {
            const std::uint32_t recordKind = GetSmallBlockIndex(kHeapRecordSizeBytes);
            const std::uint32_t recordSize = GetBlockSize(recordKind);
            requiredPages = kindPages + BytesToPages(32u * recordSize);
        }

        if (totalPages < requiredPages) {
            totalPages = requiredPages;
        }

        std::uint8_t* commitAddress = nullptr;
        std::uint8_t* reserveBase = gHeapBase;

        while (true) {
            commitAddress = ReserveAllocatorPages(totalPages, &reserveBase);

            if (commitAddress != nullptr) {
                break;
            }

            if (totalPages <= requiredPages) {
                if (metadataRecord != nullptr) {
                    const std::uint32_t recordKind = GetSmallBlockIndex(kHeapRecordSizeBytes);
                    PushHeapBlock(reinterpret_cast<SmallBlockNode*>(metadataRecord), static_cast<std::int32_t>(recordKind));
                }
                return false;
            }

            totalPages >>= 1u;
            if (totalPages < requiredPages) {
                totalPages = requiredPages;
            }
        }

        gHeapTotal += (totalPages << kPageShift);

        if (metadataRecord != nullptr) {
            metadataRecord->recordTag = kRecordTagFree;
            metadataRecord->reservedBase = reserveBase;
            metadataRecord->allocation = commitAddress;
            metadataRecord->sizePages = totalPages;
            metadataRecord->previous = nullptr;
            metadataRecord->next = nullptr;
            metadataRecord->kind = 0;
            metadataRecord->tail = nullptr;
            metadataRecord->blocks = 0;
            metadataRecord->lowWatermark = 0;

            SetPageOwnerRange(commitAddress, totalPages, metadataRecord);
            ReleaseHeapRecord(metadataRecord);
            return true;
        }

        const std::uint32_t recordKind = GetSmallBlockIndex(kHeapRecordSizeBytes);
        const std::uint32_t recordSize = GetBlockSize(recordKind);
        const std::uint32_t recordPages = BytesToPages(32u * recordSize);
        const std::uint32_t recordBytes = recordPages << kPageShift;

        std::uint8_t* const recordCommit = static_cast<std::uint8_t*>(
          ::VirtualAlloc(
            commitAddress,
            recordBytes,
            static_cast<DWORD>(gAllocationType | MEM_COMMIT),
            PAGE_READWRITE
          )
        );

        if (recordCommit == nullptr) {
            return false;
        }

        gHeapCommitted += recordBytes;
        gHeapInSmallBlocks += recordBytes;

        SmallBlockNode* previousNode = nullptr;
        std::int32_t totalRecordNodes = 0;

        const std::int32_t nodeCount = static_cast<std::int32_t>(recordBytes / recordSize);
        std::uint8_t* nodeAddress = recordCommit;
        for (std::int32_t i = 0; i < nodeCount; ++i) {
            auto* const node = reinterpret_cast<SmallBlockNode*>(nodeAddress);
            node->next = previousNode;
            previousNode = node;
            ++totalRecordNodes;
            nodeAddress += recordSize;
        }

        SmallBlockNode* recordTail = nullptr;
        std::int32_t availableBlocks = totalRecordNodes;
        std::int32_t lowWatermark = 0;

        HeapRecord* const recordOwner = reinterpret_cast<HeapRecord*>(previousNode);
        if (recordOwner != nullptr) {
            availableBlocks = totalRecordNodes - 1;
            recordTail = previousNode->next;
            if (availableBlocks < 0) {
                lowWatermark = availableBlocks;
            }
        }

        HeapRecord* const newRecord = ConstructHeapRecord(
          recordOwner,
          recordCommit,
          totalPages,
          kRecordTagSmallBlocks,
          reserveBase,
          static_cast<std::int32_t>(recordKind)
        );

        newRecord->tail = recordTail;
        newRecord->blocks = availableBlocks;
        newRecord->lowWatermark = lowWatermark;

        LinkRecordHead(gSmallBlockPrototypes[recordKind], newRecord);

        SplitHeapRecord(recordPages, newRecord);
        return true;
    }

    /**
     * Address: 0x00958660 (FUN_00958660, func_AllocateSmallBlock)
     *
     * What it does:
     * Finds or grows a committed free-region record for the requested page count.
     */
    [[nodiscard]] HeapRecord* AllocateFreeRegion(const std::uint32_t pages)
    {
        std::uint32_t bucket = ClampSizeMinusOneToBucket(pages);
        bool canGrowAllocator = true;

        while (true) {
            std::uint32_t lookupBucket = bucket;
            if (bucket < (kFreeRegionBucketCount - 1u)) {
                while (lookupBucket < (kFreeRegionBucketCount - 1u) && gFreeRegionBuckets[lookupBucket] == nullptr) {
                    ++lookupBucket;
                }
            }

            HeapRecord* candidate = gFreeRegionBuckets[lookupBucket];
            if (lookupBucket == (kFreeRegionBucketCount - 1u) && candidate != nullptr) {
                while (candidate != nullptr && candidate->sizePages < pages) {
                    candidate = candidate->previous;
                }
            }

            if (candidate == nullptr) {
                if (!canGrowAllocator || !AllocateNewBlock(pages)) {
                    return nullptr;
                }
                canGrowAllocator = false;
                bucket = ClampSizeMinusOneToBucket(pages);
                continue;
            }

            UnlinkRecord(candidate);

            const SIZE_T commitBytes = static_cast<SIZE_T>(pages) << kPageShift;
            ::VirtualAlloc(
              candidate->allocation,
              commitBytes,
              static_cast<DWORD>(gAllocationType | MEM_COMMIT),
              PAGE_READWRITE
            );

            gHeapCommitted += static_cast<std::uint32_t>(commitBytes);
            return candidate;
        }
    }

    /**
     * Address: 0x00958760 (FUN_00958760, sub_958760)
     *
     * What it does:
     * Allocates a free-region record and splits any leftover pages.
     */
    [[nodiscard]] HeapRecord* AllocateAndSplitFreeRegion(const std::uint32_t pages)
    {
        HeapRecord* const block = AllocateFreeRegion(pages);
        if (block != nullptr) {
            SplitHeapRecord(pages, block);
        }
        return block;
    }

    /**
     * Address: 0x00958780 (FUN_00958780, func_AllocSmallBlock)
     *
     * What it does:
     * Allocates a large block (>= 4 KiB) and tracks it in the large-allocation list.
     */
    [[nodiscard]] void* AllocateLargeRegion(const std::uint32_t bytes)
    {
        const std::uint32_t pages = BytesToPages(bytes);
        HeapRecord* const block = AllocateFreeRegion(pages);
        if (block == nullptr) {
            return nullptr;
        }

        SplitHeapRecord(pages, block);

        block->recordTag = kRecordTagLargeAllocation;
        LinkRecordHead(gLargeAllocationList, block);

        gHeapInUse += (pages << kPageShift);
        return block->allocation;
    }

    /**
     * Address: 0x009587E0 (FUN_009587E0, func_AllocateSmallBlocksAmt)
     *
     * What it does:
     * Fills a lane with `count` blocks for one small-block class.
     */
    void AllocateSmallBlocksAmount(
      SmallBlockRequestLane* const request,
      const std::uint32_t kind,
      std::int32_t count
    )
    {
        if (count <= 0) {
            return;
        }

        const std::uint32_t blockSize = GetBlockSize(kind);
        HeapRecord* prototype = gSmallBlockPrototypes[kind];

        while (count > 0) {
            while (prototype != nullptr) {
                while (prototype->tail != nullptr) {
                    SmallBlockNode* const node = prototype->tail;
                    prototype->tail = node->next;
                    --prototype->blocks;
                    if (prototype->blocks < prototype->lowWatermark) {
                        prototype->lowWatermark = prototype->blocks;
                    }

                    node->next = request->head;
                    ++request->count;
                    request->head = node;

                    gHeapInSmallBlocks -= blockSize;
                    gHeapInUse += blockSize;

                    --count;
                    if (count == 0) {
                        return;
                    }
                }

                UnlinkRecord(prototype);
                LinkRecordHead(gExhaustedSmallBlockPrototypes[kind], prototype);
                prototype = gSmallBlockPrototypes[kind];
            }

            const std::uint32_t pages = BytesToPages(32u * blockSize);
            prototype = AllocateFreeRegion(pages);
            if (prototype == nullptr) {
                return;
            }

            prototype->tail = nullptr;
            prototype->recordTag = kRecordTagSmallBlocks;
            prototype->kind = static_cast<std::int32_t>(kind);
            prototype->blocks = 0;
            prototype->lowWatermark = 0;

            const std::uint32_t pageBytes = pages << kPageShift;
            gHeapInSmallBlocks += pageBytes;

            const std::int32_t totalBlocks = static_cast<std::int32_t>(pageBytes / blockSize);
            SmallBlockNode* node = static_cast<SmallBlockNode*>(prototype->allocation);

            const std::int32_t blocksToRequest = (count > totalBlocks) ? totalBlocks : count;
            gHeapInUse += static_cast<std::uint32_t>(blocksToRequest) * blockSize;
            gHeapInSmallBlocks -= static_cast<std::uint32_t>(blocksToRequest) * blockSize;

            for (std::int32_t i = 0; i < blocksToRequest; ++i) {
                node->next = request->head;
                ++request->count;
                request->head = node;
                node = reinterpret_cast<SmallBlockNode*>(reinterpret_cast<std::uint8_t*>(node) + blockSize);
            }

            const std::int32_t remaining = totalBlocks - blocksToRequest;
            for (std::int32_t i = 0; i < remaining; ++i) {
                node->next = prototype->tail;
                ++prototype->blocks;
                prototype->tail = node;
                node = reinterpret_cast<SmallBlockNode*>(reinterpret_cast<std::uint8_t*>(node) + blockSize);
            }

            LinkRecordHead(gSmallBlockPrototypes[kind], prototype);
            SplitHeapRecord(pages, prototype);

            count -= blocksToRequest;
        }
    }

    /**
     * Address: 0x009589E0 (FUN_009589E0, func_AllocateInSmallBlock)
     *
     * What it does:
     * Allocates one object from the small-block allocator by byte size.
     */
    [[nodiscard]] SmallBlockNode* AllocateInSmallBlock(const std::uint32_t sizeBytes)
    {
        SmallBlockRequestLane request{};
        const std::uint32_t kind = GetSmallBlockIndex(sizeBytes);
        AllocateSmallBlocksAmount(&request, kind, 1);
        return request.head;
    }

    /**
     * Address: 0x00958A20 (FUN_00958A20, sub_958A20)
     *
     * What it does:
     * Returns current thread heap-cache object, allocating it on first use.
     */
    [[nodiscard]] ThreadHeapCache* GetOrCreateThreadHeapCache()
    {
        if (gThreadHeapCache != nullptr) {
            return gThreadHeapCache;
        }

        std::uint8_t hasLock = 0;
        if (gAllocatorSentinelIsCritical) {
            ::EnterCriticalSection(&gAllocatorSentinel);
            hasLock = 1;
        } else {
            InitAllocatorSentinel(&hasLock);
        }

        SmallBlockRequestLane request{};
        const std::uint32_t kind = GetSmallBlockIndex(kThreadCacheSizeBytes);
        AllocateSmallBlocksAmount(&request, kind, 1);

        if (request.head != nullptr) {
            gThreadHeapCache = ResetThreadHeapCache(reinterpret_cast<ThreadHeapCache*>(request.head));
            if (hasLock != 0) {
                ::LeaveCriticalSection(&gAllocatorSentinel);
            }
            return gThreadHeapCache;
        }

        if (hasLock != 0) {
            ::LeaveCriticalSection(&gAllocatorSentinel);
        }
        return nullptr;
    }
}

// 0x0093EDE0
void gpg::HandleAssertFailure(const char* msg, int line, const char* file)
{
    InvokeDieHandler(STR_Printf("Failed assertion: %s\nFile: %s\nLine: %d", msg, file, line).c_str());
}

/**
 * Address: 0x00938FE0 (FUN_00938FE0, gpg::SetDieHandler)
 * Mangled: ?SetDieHandler@gpg@@YAP6AXPBD@ZP6AX0@Z@Z
 *
 * What it does:
 * Installs one process-global fatal-error callback and returns the previous
 * callback pointer.
 */
gpg::die_handler_t gpg::SetDieHandler(gpg::die_handler_t handler)
{
    const die_handler_t old = dieHandler;
    dieHandler = handler;
    return old;
}

/**
 * Address: 0x00938FF0 (FUN_00938FF0, gpg::InvokeDieHandler)
 * Mangled: ?InvokeDieHandler@gpg@@YAXPBD@Z
 *
 * What it does:
 * Invokes the active die handler callback when one is currently installed.
 */
void gpg::InvokeDieHandler(const char* msg)
{
    if (dieHandler != nullptr) {
        dieHandler(msg);
    }
}

// 0x00939000
void gpg::Die(const char* args, ...)
{
    va_list va;
    va_start(va, args);
    const msvc8::string msg = STR_Va(args, va);
    va_end(va);
    InvokeDieHandler(msg.c_str());
    __debugbreak();
    while (true)
    {
    }
}

/**
 * Address: 0x00957EF0 (FUN_00957EF0, func_SetMemHook)
 *
 * What it does:
 * Installs or clears the process-wide memory hook callback pointer.
 */
void gpg::SetMemHook(mem_hook_t hook)
{
    gMemHook = hook;
}

gpg::mem_hook_t gpg::GetMemHook()
{
    return gMemHook;
}

extern "C" void* __cdecl malloc_0(std::uint32_t size);

/**
 * Address: 0x00957A70 (FUN_00957A70, malloc)
 *
 * What it does:
 * CRT thunk wrapper that forwards directly to `malloc_0`.
 */
extern "C" void* __cdecl malloc(size_t size)
{
    return malloc_0(static_cast<std::uint32_t>(size));
}

/**
 * Address: 0x00958B20 (FUN_00958B20, malloc_0)
 *
 * What it does:
 * Allocates from thread cache/small-block allocator or from large-region path.
 */
extern "C" void* __cdecl malloc_0(const std::uint32_t size)
{
    ThreadHeapCache* const threadCache = GetOrCreateThreadHeapCache();
    SmallBlockNode* allocation = nullptr;

    if (size <= 0x4000u) {
        if (threadCache == kThreadCacheDisabled || threadCache == nullptr) {
            SmallBlockRequestLane request{};
            const std::uint32_t kind = GetSmallBlockIndex(size);
            AllocateSmallBlocksAmount(&request, kind, 1);
            allocation = request.head;
        } else {
            const std::uint32_t kind = GetSmallBlockIndex(size);
            ThreadSmallBlockLane& lane = GetLane(threadCache, kind);

            if (lane.count == 0) {
                ::EnterCriticalSection(&gAllocatorSentinel);
                AllocateSmallBlocksAmount(reinterpret_cast<SmallBlockRequestLane*>(&lane), kind, 16);

                threadCache->cachedBytes += static_cast<std::int32_t>(16u * GetBlockSize(kind));
                if (threadCache->cachedBytes >= static_cast<std::int32_t>(kThreadCacheTrimBytes)) {
                    TrimThreadCache(threadCache, false);
                }
                ::LeaveCriticalSection(&gAllocatorSentinel);
            }

            threadCache->cachedBytes -= static_cast<std::int32_t>(GetBlockSize(kind));
            allocation = PopLaneNode(lane);
        }
    } else {
        ::EnterCriticalSection(&gAllocatorSentinel);
        allocation = reinterpret_cast<SmallBlockNode*>(AllocateLargeRegion(size));
        ::LeaveCriticalSection(&gAllocatorSentinel);
    }

    if (gMemHook != nullptr) {
        gMemHook(0, static_cast<int>(size), allocation);
    }

    return allocation;
}

/**
 * Address: 0x00958C40 (FUN_00958C40, free)
 *
 * What it does:
 * Releases small-block or large allocations and updates allocator counters.
 */
extern "C" void __cdecl free(void* ptr)
{
    if (ptr == nullptr) {
        return;
    }

    HeapRecord* const record = GetPageOwner(ptr);
    if (record->recordTag == kRecordTagSmallBlocks) {
        const std::uint32_t kind = static_cast<std::uint32_t>(record->kind);
        const std::uint32_t blockSize = GetBlockSize(kind);

        if (gMemHook != nullptr) {
            gMemHook(1, static_cast<int>(blockSize), ptr);
        }

        ThreadHeapCache* const threadCache = GetOrCreateThreadHeapCache();
        if (threadCache == kThreadCacheDisabled || threadCache == nullptr) {
            ::EnterCriticalSection(&gAllocatorSentinel);
            PushHeapBlock(static_cast<SmallBlockNode*>(ptr), static_cast<std::int32_t>(kind));
            ::LeaveCriticalSection(&gAllocatorSentinel);
        } else {
            ThreadSmallBlockLane& lane = GetLane(threadCache, kind);
            PushLaneNode(lane, static_cast<SmallBlockNode*>(ptr));
            threadCache->cachedBytes += static_cast<std::int32_t>(blockSize);

            if (threadCache->cachedBytes >= static_cast<std::int32_t>(kThreadCacheTrimBytes)) {
                AllocatorLockToken token{};
                EnterAllocatorLock(&token, true);
                TrimThreadCache(threadCache, false);
                LeaveAllocatorLock(&token);
            }
        }
        return;
    }

    if (record->recordTag == kRecordTagLargeAllocation) {
        const std::uint32_t byteSize = record->sizePages << kPageShift;

        if (gMemHook != nullptr) {
            gMemHook(1, static_cast<int>(byteSize), ptr);
        }

        ::EnterCriticalSection(&gAllocatorSentinel);
        UnlinkRecord(record);
        ReleaseHeapRecord(record);
        gHeapCommitted -= byteSize;
        gHeapInUse -= byteSize;
        ::LeaveCriticalSection(&gAllocatorSentinel);
    }
}

/**
 * Address: 0x00957EA0 (FUN_00957EA0, msize)
 *
 * What it does:
 * Returns the allocation size for small-block/large-block pointers managed by
 * the recovered allocator, otherwise returns `0`.
 */
extern "C" size_t __cdecl msize(void* memblock)
{
    if (memblock == nullptr || gPageOwnerByPage == nullptr) {
        return 0;
    }

    HeapRecord* const record = GetPageOwner(memblock);
    if (record == nullptr) {
        return 0;
    }

    if (record->recordTag == kRecordTagSmallBlocks) {
        const std::uint32_t kind = static_cast<std::uint32_t>(record->kind);
        if (kind >= kSmallBlockClassCount) {
            return 0;
        }

        const std::uint32_t blockSize = GetBlockSize(kind);
        const std::uintptr_t offset = reinterpret_cast<std::uintptr_t>(memblock) -
                                      reinterpret_cast<std::uintptr_t>(record->allocation);
        return ((offset % blockSize) == 0u) ? blockSize : 0;
    }

    if (record->recordTag == kRecordTagLargeAllocation && memblock == record->allocation) {
        return static_cast<size_t>(record->sizePages) << kPageShift;
    }

    return 0;
}

/**
 * Address: 0x00957AE0 (FUN_00957AE0, _msize)
 *
 * What it does:
 * CRT thunk wrapper for `msize`.
 */
extern "C" size_t __cdecl _msize(void* memblock)
{
    return msize(memblock);
}

/**
 * Address: 0x00957B00 (FUN_00957B00, realloc)
 *
 * What it does:
 * Reallocates allocator-managed blocks with grow/shrink thresholds matching
 * recovered binary behavior.
 */
extern "C" void* __cdecl realloc(void* pblock, size_t newsize)
{
    if (pblock == nullptr) {
        return malloc_0(static_cast<std::uint32_t>(newsize));
    }

    if (newsize == 0) {
        free(pblock);
        return nullptr;
    }

    const size_t previousSize = msize(pblock);
    if (newsize > previousSize) {
        void* const grown = malloc_0(static_cast<std::uint32_t>(newsize));
        if (grown == nullptr) {
            return nullptr;
        }

        std::memcpy(grown, pblock, previousSize);
        free(pblock);
        return grown;
    }

    if (newsize <= (previousSize >> 1u)) {
        void* const shrunk = malloc_0(static_cast<std::uint32_t>(newsize));
        if (shrunk == nullptr) {
            return nullptr;
        }

        std::memcpy(shrunk, pblock, newsize);
        free(pblock);
        return shrunk;
    }

    return pblock;
}

/**
 * Address: 0x00957BA0 (FUN_00957BA0, sub_957BA0 / _expand-like)
 *
 * What it does:
 * Returns `pblock` only when it already satisfies `newsize` in place.
 */
extern "C" void* __cdecl _expand(void* pblock, size_t newsize)
{
    if (pblock == nullptr) {
        return malloc_0(static_cast<std::uint32_t>(newsize));
    }

    if (newsize == 0) {
        free(pblock);
        return nullptr;
    }

    return (msize(pblock) >= newsize) ? pblock : nullptr;
}

/**
 * Address: 0x00958D60 (FUN_00958D60, func_GetHeapInfo)
 *
 * What it does:
 * Copies allocator heap counters into `outStats` under allocator lock.
 */
void gpg::GetHeapInfo(HeapStats* const outStats)
{
    if (outStats == nullptr) {
        return;
    }

    if (!gAllocatorSentinelIsCritical) {
        (void)GetOrCreateThreadHeapCache();
    }

    ::EnterCriticalSection(&gAllocatorSentinel);
    outStats->reserved = gHeapReserved;
    outStats->committed = gHeapCommitted;
    outStats->total = gHeapTotal;
    outStats->inSmallBlocks = gHeapInSmallBlocks;
    outStats->inUse = gHeapInUse;
    ::LeaveCriticalSection(&gAllocatorSentinel);
}

bool gpg::ParseNum(const char* start, const char* end, int* dest) noexcept
{
    std::uint8_t isNegative = 0u;
    if (*start == '-') {
        isNegative = 1u;
        ++start;
    }

    int value = 0;
    int base = 10;
    if (*start == '0') {
        if (start[1] == 'x') {
            base = 16;
            start += 2;
        } else {
            base = 8;
        }
    }

    char current = *start;
    do {
        int digit = 0;
        if (static_cast<unsigned char>(current - '0') <= 9u) {
            digit = static_cast<int>(current) - '0';
        } else {
            if (static_cast<unsigned char>(current - 'a') > 0x19u
                && static_cast<unsigned char>(current - 'A') != 0u) {
                return false;
            }
            digit = static_cast<int>(current) - 'W';
        }

        if (digit >= base) {
            return false;
        }

        value = (value * base) + digit;
        current = *++start;
    } while (current != '\0' && start != end);

    if (isNegative != 0u) {
        value = -value;
    }

    *dest = value;
    return true;
}

/**
 * Address: 0x009071D0 (FUN_009071D0, gpg::SetThreadName)
 */
void gpg::SetThreadName(const unsigned int id, const char* const name)
{
    if (moho::APP_GetAqtimeInstrumentationMode() == 0u) {
        return;
    }

    struct ThreadNamePayload
    {
        std::uint32_t type;
        const char* name;
        std::uint32_t threadId;
        std::uint32_t flags;
    };
    static_assert(sizeof(ThreadNamePayload) == 0x10, "ThreadNamePayload size must be 0x10");

    ThreadNamePayload payload{};
    payload.type = 0x1000u;
    payload.name = name;
    payload.threadId = id;
    payload.flags = 0u;

    __try {
        ::RaiseException(
          0x406D1388u,
          0u,
          4u,
          reinterpret_cast<const ULONG_PTR*>(&payload)
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}
