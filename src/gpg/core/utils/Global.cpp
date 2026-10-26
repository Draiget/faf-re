#include "Global.h"
#include "gpg/core/profiling/Profiler.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <new>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"

/// Engine addition: the x86 allocator finds a size class by table (true) or by the binary's
/// binary search (false). Same class either way; `mem_SmallBlockIndexTable` (registered in Sim.cpp).
bool gpg::mem_SmallBlockIndexTable = true;

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

    /**
     * Address: 0x00957CA0 (FUN_00957CA0)
     *
     * What it does:
     * Returns the allocator lock-state byte from one lock token.
     */
    [[maybe_unused]] [[nodiscard]] std::uint8_t ReadAllocatorLockStateLane(
      const AllocatorLockToken* const token
    ) noexcept
    {
      return token->hasLock;
    }

    struct SmallBlockRequestLane
    {
        SmallBlockNode* head;
        std::int32_t count;
        std::int32_t lowWatermark;
    };
    static_assert(sizeof(SmallBlockRequestLane) == 0x0C, "SmallBlockRequestLane size must be 0x0C");

    /**
     * Address: 0x00957CF0 (FUN_00957CF0)
     *
     * What it does:
     * Resets one request lane to an empty state.
     */
    [[nodiscard]] SmallBlockRequestLane* ResetSmallBlockRequestLane(SmallBlockRequestLane* const lane) noexcept
    {
      lane->head = nullptr;
      lane->count = 0;
      lane->lowWatermark = 0;
      return lane;
    }

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

    constexpr std::uint32_t kSmallBlockWordCount = (16384u / 4u) + 1u;

    /**
     * What it does:
     * Builds the size-class lookup used by `GetSmallBlockIndex`: entry `w` is
     * the first class in `kSmallBlockSizes` whose size is `>= 4*w`.
     */
    [[nodiscard]] consteval std::array<std::uint8_t, kSmallBlockWordCount> BuildSmallBlockIndexByWord()
    {
        std::array<std::uint8_t, kSmallBlockWordCount> table{};
        std::uint32_t kind = 0;
        for (std::uint32_t word = 0; word < kSmallBlockWordCount; ++word) {
            while (kSmallBlockSizes[kind] < word * 4u) {
                ++kind;
            }
            table[word] = static_cast<std::uint8_t>(kind);
        }
        return table;
    }

    constexpr std::array<std::uint8_t, kSmallBlockWordCount> kSmallBlockIndexByWord = BuildSmallBlockIndexByWord();
    static_assert(kSmallBlockSizes[kSmallBlockClassCount - 1u] == (kSmallBlockWordCount - 1u) * 4u);
    static_assert(kSmallBlockIndexByWord[0] == 0u && kSmallBlockIndexByWord[1] == 0u && kSmallBlockIndexByWord[2] == 1u);
    static_assert(kSmallBlockIndexByWord[kSmallBlockWordCount - 1u] == kSmallBlockClassCount - 1u);

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

    thread_local ThreadHeapCache* gThreadHeapCache = nullptr;

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

    /**
     * Address: 0x00957F00 (FUN_00957F00)
     *
     * What it does:
     * Inserts `record` at list head and repairs intrusive back-links.
     */
    void LinkRecordHead(HeapRecord*& head, HeapRecord* const record)
    {
        record->previous = head;
        if (head != nullptr) {
            head->next = &record->previous;
        }
        record->next = &head;
        head = record;
    }

    /**
     * Address: 0x00957D00 (FUN_00957D00)
     *
     * What it does:
     * Pops one node from a thread-cache lane, updates count, and tracks the
     * low-watermark.
     */
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

#if defined(_M_X64)
    // x64 always allocates from a system heap. The engine allocator is the x86
    // binary's: its smallest size classes (4..28 bytes, step 4) cannot hold the
    // 8-byte free-list link a freed block carries, nor give the 16-byte
    // alignment x64 code expects from `new`, and its record, thread-cache and
    // page-map sizes are x86 byte counts. Every entry point funnels through
    // `malloc_0`/`free_0`/`msize`, so bypassing those three keeps allocation and
    // release on the same heap.

    // FAF_HIGHMEM=1 (x64 port test mode). With a large-address-aware image,
    // every free region below 4 GB is reserved from the TLS callback, before
    // the CRT starts, and the engine's system heap is a private heap created
    // afterwards. Every later allocation, thread stack and DLL then lands
    // above 4 GB, so a pointer still squeezed through a 32-bit word faults on
    // first use instead of silently aliasing. Without large-address support
    // the process cannot use memory above 2 GB at all, so the mode is skipped.
    struct HighMemoryReservation
    {
        bool requested = false;
        bool active = false;
        std::uint64_t reservedBytes = 0;
        std::uint32_t reservedRegions = 0;
        HANDLE engineHeap = nullptr;
    };

    HighMemoryReservation gHighMemoryReservation;

    [[nodiscard]] bool HighMemoryModeRequested() noexcept
    {
        char value[4] = {};
        const DWORD written = ::GetEnvironmentVariableA("FAF_HIGHMEM", value, static_cast<DWORD>(sizeof(value)));
        return written == 1u && value[0] == '1';
    }

    [[nodiscard]] bool ImageIsLargeAddressAware() noexcept
    {
        const HMODULE image = ::GetModuleHandleW(nullptr);
        const auto* const dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
        // PE header walk: the NT headers sit `e_lfanew` bytes into the image.
        const auto* const ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const std::uint8_t*>(dosHeader) + dosHeader->e_lfanew
        );
        return (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
    }

    void ReserveAddressSpaceBelow4Gb() noexcept
    {
        constexpr std::uintptr_t kLowAddressLimit = 0x100000000ull;
        constexpr std::uintptr_t kAllocationGranularity = 0x10000u;

        std::uintptr_t cursor = kAllocationGranularity;
        while (cursor < kLowAddressLimit) {
            MEMORY_BASIC_INFORMATION region{};
            if (::VirtualQuery(reinterpret_cast<const void*>(cursor), &region, sizeof(region)) == 0) {
                break;
            }

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            const std::uintptr_t regionEnd = regionBase + region.RegionSize;
            if (region.State == MEM_FREE) {
                // Reservations start on the 64 KB allocation granularity.
                const std::uintptr_t start = (regionBase + kAllocationGranularity - 1) & ~(kAllocationGranularity - 1);
                const std::uintptr_t end = (regionEnd < kLowAddressLimit) ? regionEnd : kLowAddressLimit;
                if (start < end
                    && ::VirtualAlloc(reinterpret_cast<void*>(start), end - start, MEM_RESERVE, PAGE_NOACCESS) != nullptr) {
                    gHighMemoryReservation.reservedBytes += end - start;
                    ++gHighMemoryReservation.reservedRegions;
                }
            }
            cursor = regionEnd;
        }
    }

    void BeginHighMemoryMode() noexcept
    {
        if (!HighMemoryModeRequested()) {
            return;
        }
        gHighMemoryReservation.requested = true;
        if (!ImageIsLargeAddressAware()) {
            return;
        }
        ReserveAddressSpaceBelow4Gb();
        gHighMemoryReservation.engineHeap = ::HeapCreate(0, 0, 0);
        gHighMemoryReservation.active = true;
    }

    /// The heap the x64 allocator path draws from: the FAF_HIGHMEM private heap
    /// when that mode is active, the process heap otherwise.
    [[nodiscard]] HANDLE EngineSystemHeap() noexcept
    {
        if (gHighMemoryReservation.engineHeap != nullptr) {
            return gHighMemoryReservation.engineHeap;
        }
        return ::GetProcessHeap();
    }

    // Not in the binary (x64 port, plan 3a). While a system heap serves every
    // engine block the engine allocator never starts, so its counters stay
    // zero and the `Heap_*` engine stats would read 0B. The bytes of the live
    // engine blocks are counted here instead, at the size the heap actually
    // handed out (`HeapSize`), so a block adds and removes the same amount.
    std::atomic<std::size_t> gSystemHeapBytesInUse{0u};

    [[nodiscard]] std::size_t SystemHeapSize(void* ptr) noexcept;

    [[nodiscard]] void* SystemHeapAlloc(const std::size_t size) noexcept
    {
        const std::size_t bytes = (size != 0u) ? size : 1u;
        void* const block = ::HeapAlloc(EngineSystemHeap(), 0, bytes);
        if (block != nullptr) {
            gSystemHeapBytesInUse.fetch_add(SystemHeapSize(block), std::memory_order_relaxed);
        }
        return block;
    }

    void SystemHeapFree(void* const ptr) noexcept
    {
        gSystemHeapBytesInUse.fetch_sub(SystemHeapSize(ptr), std::memory_order_relaxed);
        (void)::HeapFree(EngineSystemHeap(), 0, ptr);
    }

    [[nodiscard]] std::size_t SystemHeapSize(void* const ptr) noexcept
    {
        const SIZE_T heapSize = ::HeapSize(EngineSystemHeap(), 0, ptr);
        return (heapSize == static_cast<SIZE_T>(-1)) ? 0u : static_cast<std::size_t>(heapSize);
    }

    /**
     * Engine addition (x64 port): a size-class pool in front of the system heap for blocks of up
     * to 4 KB, the bulk of the engine's allocations (strings, list and tree nodes, small vectors).
     *
     * Every system-heap block costs `HeapAlloc`/`HeapFree` plus two `HeapSize` calls for the byte
     * count, several percent of the sim thread in a large fight. Pooled blocks come from one
     * reserved address range, carved into 64 KB spans of a single size class each, and move
     * through per-thread free lists without a lock; whole batches pass through a per-class global
     * list under a lock. Whether a pointer is pooled is a range check, so blocks from the heap
     * (larger ones, or any allocated before the pool started) are freed where they came from.
     * Pooled memory is kept for reuse, never returned to the system. `FAF_SMALLPOOL=0` turns the
     * pool off, for comparisons.
     */
    namespace small_pool
    {
        constexpr std::size_t kMaxPooledBytes = 4096u;
        constexpr std::size_t kSpanBytes = 64u * 1024u;
        constexpr std::size_t kCommitChunkBytes = 1024u * 1024u;
        constexpr std::size_t kReserveBytes = std::size_t{64} << 30;
        constexpr std::size_t kSpanCount = kReserveBytes / kSpanBytes;
        constexpr std::uint32_t kClassCount = 48u;

        /// Class sizes: 16..256 by 16, then 8 classes each by 32, 64, 128 and 256 up to 4096.
        [[nodiscard]] constexpr std::uint32_t ClassBytes(const std::uint32_t sizeClass) noexcept
        {
            if (sizeClass < 16u) {
                return (sizeClass + 1u) * 16u;
            }
            const std::uint32_t band = (sizeClass - 16u) / 8u; // 0..3
            const std::uint32_t step = 32u << band;
            const std::uint32_t bandStart = 256u << band;
            return bandStart + ((sizeClass - 16u) % 8u + 1u) * step;
        }
        static_assert(ClassBytes(0) == 16u && ClassBytes(15) == 256u && ClassBytes(16) == 288u);
        static_assert(ClassBytes(23) == 512u && ClassBytes(31) == 1024u && ClassBytes(47) == 4096u);

        /// Blocks moved between a thread and the global lists at a time.
        [[nodiscard]] constexpr std::uint32_t BatchBlocks(const std::uint32_t sizeClass) noexcept
        {
            const std::uint32_t blocks = 8192u / ClassBytes(sizeClass);
            return (blocks < 4u) ? 4u : (blocks > 256u ? 256u : blocks);
        }

        struct ClassTable
        {
            std::uint8_t classOfQuantum[kMaxPooledBytes / 16u + 1u]{};
            constexpr ClassTable()
            {
                std::uint32_t sizeClass = 0;
                for (std::uint32_t quantum = 0; quantum <= kMaxPooledBytes / 16u; ++quantum) {
                    while (ClassBytes(sizeClass) < quantum * 16u) {
                        ++sizeClass;
                    }
                    classOfQuantum[quantum] = static_cast<std::uint8_t>(sizeClass);
                }
            }
        };
        constexpr ClassTable kClassTable{};

        [[nodiscard]] std::uint32_t ClassOf(const std::size_t bytes) noexcept
        {
            return kClassTable.classOfQuantum[(bytes + 15u) / 16u];
        }

        struct FreeBlock
        {
            FreeBlock* next;      // next block of the same list or batch
            FreeBlock* nextBatch; // on a batch's first block in a global list: the next batch
        };

        struct GlobalClassLists
        {
            SRWLOCK lock = SRWLOCK_INIT;
            FreeBlock* batches = nullptr;   // full batches of BatchBlocks(class) blocks
            FreeBlock* loose = nullptr;     // blocks of no full batch
            std::uint32_t looseCount = 0;
        };

        struct ThreadLists
        {
            FreeBlock* head[kClassCount];
            std::uint32_t count[kClassCount];
            std::int64_t bytesDelta; // in-use change not yet added to gSystemHeapBytesInUse
            bool registered;
            bool retired; // thread is exiting: every block goes through the global lists
        };

        std::uintptr_t gBase = 0;
        INIT_ONCE gInitOnce = INIT_ONCE_STATIC_INIT;
        SRWLOCK gSpanLock = SRWLOCK_INIT;
        std::size_t gNextSpanOffset = 0;
        std::size_t gCommittedBytes = 0;
        std::uint8_t gSpanClass[kSpanCount];
        GlobalClassLists gGlobal[kClassCount];
        constinit thread_local ThreadLists tLists{};

        /// `/smallpool 0` on the command line (read here, before anything else runs) or FAF_SMALLPOOL=0.
        [[nodiscard]] bool TurnedOff() noexcept
        {
            char value[4] = {};
            const DWORD written = ::GetEnvironmentVariableA("FAF_SMALLPOOL", value, static_cast<DWORD>(sizeof(value)));
            if (written == 1u && value[0] == '0') {
                return true;
            }
            const wchar_t* const commandLine = ::GetCommandLineW();
            const wchar_t* const flag = (commandLine != nullptr) ? std::wcsstr(commandLine, L"/smallpool") : nullptr;
            if (flag == nullptr) {
                return false;
            }
            const wchar_t* cursor = flag + std::wcslen(L"/smallpool");
            while (*cursor == L' ' || *cursor == L'\t' || *cursor == L'=') {
                ++cursor;
            }
            return *cursor == L'0';
        }

        BOOL CALLBACK Reserve(PINIT_ONCE, PVOID, PVOID*) noexcept
        {
            if (TurnedOff()) {
                return TRUE;
            }
            // Top-down keeps the range above 4 GB, like everything else in FAF_HIGHMEM mode.
            void* const base = ::VirtualAlloc(nullptr, kReserveBytes, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);
            gBase = reinterpret_cast<std::uintptr_t>(base);
            return TRUE;
        }

        [[nodiscard]] bool Enabled() noexcept
        {
            (void)::InitOnceExecuteOnce(&gInitOnce, &Reserve, nullptr, nullptr);
            return gBase != 0;
        }

        [[nodiscard]] bool Owns(const void* const ptr) noexcept
        {
            const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(ptr);
            return gBase != 0 && address - gBase < kReserveBytes;
        }

        [[nodiscard]] std::uint32_t ClassOfBlock(const void* const ptr) noexcept
        {
            return gSpanClass[(reinterpret_cast<std::uintptr_t>(ptr) - gBase) / kSpanBytes];
        }

        void AddInUseBytes(ThreadLists& lists, const std::int64_t bytes) noexcept
        {
            lists.bytesDelta += bytes;
            if (lists.bytesDelta > 65536 || lists.bytesDelta < -65536 || lists.retired) {
                gSystemHeapBytesInUse.fetch_add(static_cast<std::size_t>(lists.bytesDelta), std::memory_order_relaxed);
                lists.bytesDelta = 0;
            }
        }

        /// A new span of `sizeClass` blocks, linked into one list; null when the range is used up.
        [[nodiscard]] FreeBlock* CarveSpan(const std::uint32_t sizeClass, std::uint32_t& outCount) noexcept
        {
            std::uintptr_t span = 0;
            ::AcquireSRWLockExclusive(&gSpanLock);
            if (gNextSpanOffset + kSpanBytes <= kReserveBytes) {
                if (gNextSpanOffset + kSpanBytes > gCommittedBytes) {
                    const std::size_t commitBytes = (kReserveBytes - gCommittedBytes < kCommitChunkBytes)
                        ? kReserveBytes - gCommittedBytes
                        : kCommitChunkBytes;
                    if (::VirtualAlloc(reinterpret_cast<void*>(gBase + gCommittedBytes), commitBytes, MEM_COMMIT, PAGE_READWRITE)
                        != nullptr) {
                        gCommittedBytes += commitBytes;
                    }
                }
                if (gNextSpanOffset + kSpanBytes <= gCommittedBytes) {
                    span = gBase + gNextSpanOffset;
                    gSpanClass[gNextSpanOffset / kSpanBytes] = static_cast<std::uint8_t>(sizeClass);
                    gNextSpanOffset += kSpanBytes;
                }
            }
            ::ReleaseSRWLockExclusive(&gSpanLock);
            if (span == 0) {
                return nullptr;
            }

            const std::size_t blockBytes = ClassBytes(sizeClass);
            const std::uint32_t blocks = static_cast<std::uint32_t>(kSpanBytes / blockBytes);
            FreeBlock* head = nullptr;
            for (std::uint32_t index = blocks; index-- > 0;) {
                auto* const block = reinterpret_cast<FreeBlock*>(span + index * blockBytes);
                block->next = head;
                head = block;
            }
            outCount = blocks;
            return head;
        }

        /// Takes a batch (or the loose blocks, or a new span) for this thread's empty list.
        [[nodiscard]] FreeBlock* Refill(const std::uint32_t sizeClass, std::uint32_t& outCount) noexcept
        {
            GlobalClassLists& global = gGlobal[sizeClass];
            ::AcquireSRWLockExclusive(&global.lock);
            FreeBlock* taken = global.batches;
            if (taken != nullptr) {
                global.batches = taken->nextBatch;
                outCount = BatchBlocks(sizeClass);
            } else if (global.loose != nullptr) {
                taken = global.loose;
                outCount = global.looseCount;
                global.loose = nullptr;
                global.looseCount = 0;
            }
            ::ReleaseSRWLockExclusive(&global.lock);
            return (taken != nullptr) ? taken : CarveSpan(sizeClass, outCount);
        }

        /// Hands the first BatchBlocks(class) blocks of this thread's list to the global lists.
        void ReturnBatch(ThreadLists& lists, const std::uint32_t sizeClass) noexcept
        {
            const std::uint32_t batch = BatchBlocks(sizeClass);
            FreeBlock* const first = lists.head[sizeClass];
            FreeBlock* last = first;
            for (std::uint32_t index = 1; index < batch; ++index) {
                last = last->next;
            }
            lists.head[sizeClass] = last->next;
            lists.count[sizeClass] -= batch;
            last->next = nullptr;

            GlobalClassLists& global = gGlobal[sizeClass];
            ::AcquireSRWLockExclusive(&global.lock);
            first->nextBatch = global.batches;
            global.batches = first;
            ::ReleaseSRWLockExclusive(&global.lock);
        }

        /// Hands every block of this thread's lists to the global lists (thread exit).
        void ReturnAll(ThreadLists& lists) noexcept
        {
            for (std::uint32_t sizeClass = 0; sizeClass < kClassCount; ++sizeClass) {
                while (lists.count[sizeClass] >= BatchBlocks(sizeClass)) {
                    ReturnBatch(lists, sizeClass);
                }
                FreeBlock* block = lists.head[sizeClass];
                if (block == nullptr) {
                    continue;
                }
                GlobalClassLists& global = gGlobal[sizeClass];
                ::AcquireSRWLockExclusive(&global.lock);
                while (block != nullptr) {
                    FreeBlock* const next = block->next;
                    block->next = global.loose;
                    global.loose = block;
                    ++global.looseCount;
                    block = next;
                }
                ::ReleaseSRWLockExclusive(&global.lock);
                lists.head[sizeClass] = nullptr;
                lists.count[sizeClass] = 0;
            }
        }

        /// Returns the thread's blocks when it exits; frees after that go straight to the global lists.
        struct ThreadExitGuard
        {
            ~ThreadExitGuard()
            {
                ThreadLists& lists = tLists;
                lists.retired = true;
                ReturnAll(lists);
                AddInUseBytes(lists, 0);
            }
        };
        thread_local ThreadExitGuard tExitGuard;

        [[nodiscard]] void* Allocate(const std::size_t bytes) noexcept
        {
            const std::uint32_t sizeClass = ClassOf(bytes != 0u ? bytes : 1u);
            ThreadLists& lists = tLists;
            if (!lists.registered) {
                lists.registered = true;
                (void)&tExitGuard; // constructs this thread's guard
            }

            if (lists.retired) {
                std::uint32_t count = 0;
                FreeBlock* const taken = Refill(sizeClass, count);
                if (taken == nullptr) {
                    return nullptr;
                }
                // Keep one block; the rest go back as loose blocks.
                lists.head[sizeClass] = taken->next;
                lists.count[sizeClass] = count - 1u;
                ReturnAll(lists);
                AddInUseBytes(lists, ClassBytes(sizeClass));
                return taken;
            }

            FreeBlock* block = lists.head[sizeClass];
            if (block == nullptr) {
                std::uint32_t count = 0;
                block = Refill(sizeClass, count);
                if (block == nullptr) {
                    return nullptr;
                }
                lists.count[sizeClass] = count;
            }
            lists.head[sizeClass] = block->next;
            --lists.count[sizeClass];
            AddInUseBytes(lists, ClassBytes(sizeClass));
            return block;
        }

        void Free(void* const ptr) noexcept
        {
            const std::uint32_t sizeClass = ClassOfBlock(ptr);
            ThreadLists& lists = tLists;
            auto* const block = static_cast<FreeBlock*>(ptr);
            block->next = lists.head[sizeClass];
            lists.head[sizeClass] = block;
            ++lists.count[sizeClass];
            AddInUseBytes(lists, -static_cast<std::int64_t>(ClassBytes(sizeClass)));
            if (lists.retired) {
                ReturnAll(lists);
            } else if (lists.count[sizeClass] >= 2u * BatchBlocks(sizeClass)) {
                ReturnBatch(lists, sizeClass);
            }
        }
    } // namespace small_pool

    /// `gpg::GetHeapInfo` for the system-heap path (not in the binary). Every
    /// figure is the engine's own live bytes; `inSmallBlocks` is 0, so
    /// `Heap_TotalCheck` (`inSmallBlocks + inUse`) still equals `Heap_Total`.
    /// `CScApp::Main` publishes these stats every frame, so this must stay a
    /// counter read: `HeapSummary` walks every block of the heap under its
    /// lock (about 260 ms for a 500 MB heap of small blocks), which stalled
    /// the main thread and every allocating thread once per frame.
    void FillSystemHeapStats(gpg::HeapStats& stats) noexcept
    {
        const std::size_t inUse = gSystemHeapBytesInUse.load(std::memory_order_relaxed);
        stats = {};
        stats.reserved = inUse;
        stats.committed = inUse;
        stats.total = inUse;
        stats.inUse = inUse;
    }
#endif

    /**
     * Address: 0x00957D20 (FUN_00957D20)
     *
     * What it does:
     * Pushes one node to the lane head and increments lane count.
     */
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
    [[nodiscard]] HeapRecord* AllocateFreeRegion(std::uint32_t pages, bool canGrow);
    [[nodiscard]] HeapRecord* AllocateAndSplitFreeRegion(std::uint32_t pages);
    [[nodiscard]] void* AllocateLargeRegion(std::uint32_t bytes);

    void AllocateSmallBlocksAmount(SmallBlockRequestLane* request, std::uint32_t kind, std::int32_t count, bool canGrow);

    /**
     * Address: 0x00957DE0 (FUN_00957DE0)
     *
     * What it does:
     * Pushes `count` strided nodes into one request lane and returns the next
     * cursor after the copied range.
     */
    [[nodiscard]] SmallBlockNode* PushStridedNodesToRequestLane(
      SmallBlockNode* node,
      std::int32_t count,
      SmallBlockRequestLane* const request,
      const std::uint32_t strideBytes
    ) noexcept
    {
      while (count > 0) {
        node->next = request->head;
        ++request->count;
        request->head = node;
        node = reinterpret_cast<SmallBlockNode*>(reinterpret_cast<std::uint8_t*>(node) + strideBytes);
        --count;
      }
      return node;
    }

    [[nodiscard]] SmallBlockNode* AllocateInSmallBlock(std::uint32_t sizeBytes, bool canGrow);

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
        // The binary's body binary-searches `kSmallBlockSizes` for the first
        // class `>= bytes` (lower bound; 44 for anything above the last class).
        // Every class size is a multiple of 4, so all sizes in one 4-byte word
        // `(4w-3 .. 4w]` share the lower bound of `4w`: the table below holds
        // that lower bound per word and returns the identical index for every
        // `bytes` (checked exhaustively over all 2^32 inputs against the search).
        if (!gpg::mem_SmallBlockIndexTable) {
            // The binary's lower-bound binary search.
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
        if (bytes > kSmallBlockSizes[kSmallBlockClassCount - 1u]) {
            return kSmallBlockClassCount;
        }
        return kSmallBlockIndexByWord[(bytes + 3u) >> 2u];
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

        gNextAvailableHeapRecord = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes, true));
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
        if (ReadAllocatorLockStateLane(token) != 0) {
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
        HeapRecord* tailRecord = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes, false));
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
            gNextAvailableHeapRecord = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes, true));
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

#if defined(_M_X64)
        // Not in the binary: the x64 FAF_HIGHMEM test mode has to run before
        // the CRT allocates anything, and this callback is the first code the
        // loader runs in the image.
        if (reason == DLL_PROCESS_ATTACH) {
            BeginHighMemoryMode();
        }
#endif
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

        HeapRecord* metadataRecord = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes, false));

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
    [[nodiscard]] HeapRecord* AllocateFreeRegion(const std::uint32_t pages, const bool canGrow)
    {
        std::uint32_t bucket = ClampSizeMinusOneToBucket(pages);
        bool canGrowAllocator = canGrow;

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
        HeapRecord* const block = AllocateFreeRegion(pages, true);
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
        HeapRecord* const block = AllocateFreeRegion(pages, true);
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
      std::int32_t count,
      const bool canGrow
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
            prototype = AllocateFreeRegion(pages, canGrow);
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

            node = PushStridedNodesToRequestLane(node, blocksToRequest, request, blockSize);

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
    [[nodiscard]] SmallBlockNode* AllocateInSmallBlock(const std::uint32_t sizeBytes, const bool canGrow)
    {
        SmallBlockRequestLane request{};
        (void)ResetSmallBlockRequestLane(&request);
        const std::uint32_t kind = GetSmallBlockIndex(sizeBytes);
        AllocateSmallBlocksAmount(&request, kind, 1, canGrow);
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
        (void)ResetSmallBlockRequestLane(&request);
        const std::uint32_t kind = GetSmallBlockIndex(kThreadCacheSizeBytes);
        AllocateSmallBlocksAmount(&request, kind, 1, true);

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

/**
 * The shipped image registers `TlsCallback_1` (0x009583F0) through the PE's own
 * TLS callback directory: the TLS data directory at RVA 0x00A4FA30 points its
 * `AddressOfCallBacks` at 0x00D410F8, whose two entries are 0x00AC6060 and
 * 0x009583F0.
 *
 * That registration is load bearing, and emulating it with a `thread_local`
 * object whose destructor calls `TlsCallback_1(nullptr, DLL_THREAD_DETACH,
 * nullptr)` -- which is what this file did until now -- is wrong twice over.
 *
 *  - It reports the wrong reason at process exit. Windows delivers
 *    `DLL_PROCESS_DETACH` there, and `TlsCallback_1` acts only on
 *    `DLL_THREAD_DETACH`, so the shipped engine flushes nothing while the
 *    process is tearing down. The bridge forced the thread-detach path anyway,
 *    from a CRT dynamic TLS destructor inside `LdrShutdownProcess`, long after
 *    the allocator's page-owner map is usable: `FlushCurrentThreadHeapCache` ->
 *    `TrimThreadCache` -> `PushHeapBlock` then read `owner->blocks` through a
 *    null `GetPageOwner` result and faulted on address 0x00000020 (observed
 *    live, with that exact stack).
 *  - A namespace-scope `thread_local` with a non-trivial destructor is only
 *    constructed on threads that actually touch it, and nothing referenced this
 *    one, so on every other thread the per-thread cache was never returned to
 *    the global free lists at all.
 *
 * Registering the real callback fixes both: the reason code is whatever Windows
 * passes, and every thread exit runs it.
 */
#if defined(_M_IX86)
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_gAllocatorTlsCallbackEntry")
#else // x64 C names carry no leading underscore
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:gAllocatorTlsCallbackEntry")
#endif
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK gAllocatorTlsCallbackEntry = &TlsCallback_1;
#pragma const_seg()

#if defined(_M_X64)
void gpg::LogHighMemoryReservation()
{
    // Plan 7.1: Stage A keeps the image below 4 GB (static addresses still
    // fit 32 bits) while the heap may go above; say where the image landed.
    const auto* const imageBase = static_cast<const void*>(::GetModuleHandleW(nullptr));
    gpg::Logf(
        "x64 image base %p (%s 4 GB)", imageBase,
        (reinterpret_cast<std::uintptr_t>(imageBase) < 0x100000000ull) ? "below" : "above"
    );
    gpg::Logf(
        "mem: small-block pool %s (blocks up to %u bytes; /smallpool 0 or FAF_SMALLPOOL=0 turns it off)",
        small_pool::Enabled() ? "on" : "off", static_cast<unsigned int>(small_pool::kMaxPooledBytes)
    );

    if (!gHighMemoryReservation.requested) {
        return;
    }
    if (!gHighMemoryReservation.active) {
        gpg::Warnf("FAF_HIGHMEM: skipped, the image is not large-address-aware (build with /p:FafX64LargeAddress=heap|full)");
        return;
    }
    gpg::Logf(
        "FAF_HIGHMEM: reserved %llu MB below 4 GB in %u regions; engine heap %p",
        static_cast<unsigned long long>(gHighMemoryReservation.reservedBytes >> 20),
        static_cast<unsigned int>(gHighMemoryReservation.reservedRegions),
        static_cast<void*>(gHighMemoryReservation.engineHeap)
    );
}
#endif

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
 *
 * The binary links the CRT statically, so this is `malloc` itself there. This
 * project links the DLL CRT, whose import library also defines `malloc` (and
 * `free`): any library that imports either one pulls that definition in, and
 * a second `malloc` here is a duplicate symbol the link only got past with
 * `/FORCE`. Every other translation unit already binds to the DLL's
 * `__imp_malloc` through `<cstdlib>`, so the engine allocator is reached by
 * name: `operator new` calls this thunk, and `malloc_0`, `realloc_0` and
 * `free_0` carry the same suffix for the same reason (see `realloc_0`).
 */
extern "C" void* __cdecl malloc_crt(size_t size)
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
#if defined(_M_X64)
    void* block = (size <= small_pool::kMaxPooledBytes && small_pool::Enabled()) ? small_pool::Allocate(size) : nullptr;
    if (block == nullptr) {
        block = SystemHeapAlloc(size); // larger blocks, no pool, or the pool's range is used up
    }
    if (gMemHook != nullptr) {
        gMemHook(0, static_cast<int>(size), block);
    }
#if defined(TRACY_ENABLE)
    if (block != nullptr) {
        thread_local bool tInMem = false;
        if (!tInMem) {
            tInMem = true;
            FAF_PROFILE_ALLOC(block, size);
            tInMem = false;
        }
    }
#endif
    return block;
#else
    ThreadHeapCache* const threadCache = GetOrCreateThreadHeapCache();
    SmallBlockNode* allocation = nullptr;

    if (size <= 0x4000u) {
        if (threadCache == kThreadCacheDisabled || threadCache == nullptr) {
            SmallBlockRequestLane request{};
            (void)ResetSmallBlockRequestLane(&request);
            const std::uint32_t kind = GetSmallBlockIndex(size);
            AllocateSmallBlocksAmount(&request, kind, 1, true);
            allocation = request.head;
        } else {
            const std::uint32_t kind = GetSmallBlockIndex(size);
            ThreadSmallBlockLane& lane = GetLane(threadCache, kind);

            // A lane that reports free blocks but has no chain to hand them out
            // from is a state the free lists can only reach through corruption:
            // `PopLaneNode` sets `head = node->next` and decrements the count by
            // one, so a freed block whose first word is overwritten truncates the
            // chain and strands the remaining count. The count is then non-zero
            // forever, the refill below never runs again, and every subsequent
            // request for this size class returns null - which the callers report
            // as an out-of-memory failure while the heap still has hundreds of
            // megabytes free. Resynchronise the count to the chain that actually
            // exists so the refill path can recover the lane.
            if (lane.head == nullptr && lane.count != 0) {
                lane.count = 0;
                lane.lowWatermark = 0;
            }

            if (lane.count == 0) {
                ::EnterCriticalSection(&gAllocatorSentinel);
                AllocateSmallBlocksAmount(reinterpret_cast<SmallBlockRequestLane*>(&lane), kind, 16, true);

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
#if defined(TRACY_ENABLE)
    if (allocation != nullptr) {
        thread_local bool tInMem = false;
        if (!tInMem) {
            tInMem = true;
            FAF_PROFILE_ALLOC(allocation, size);
            tInMem = false;
        }
    }
#endif

    return allocation;
#endif
}

/**
 * Address: 0x00958C40 (FUN_00958C40, free)
 *
 * What it does:
 * Releases small-block or large allocations and updates allocator counters.
 *
 * `free` in the binary; named `free_0` here because the DLL CRT's import
 * library defines `free` too (see `malloc_crt`). `free_crt` and `realloc_0`
 * call it by name.
 */
extern "C" void __cdecl free_0(void* ptr)
{
    if (ptr == nullptr) {
        return;
    }
#if defined(TRACY_ENABLE)
    thread_local bool tInMem = false;
    if (!tInMem) {
        tInMem = true;
        FAF_PROFILE_FREE(ptr);
        tInMem = false;
    }
#endif

#if defined(_M_X64)
    // This has to come before `GetPageOwner`, which is only meaningful for
    // pages the engine allocator owns.
    if (gMemHook != nullptr) {
        gMemHook(1, 0, ptr);
    }
    if (small_pool::Owns(ptr)) {
        small_pool::Free(ptr);
        return;
    }
    SystemHeapFree(ptr);
#else
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
#endif
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
    if (memblock == nullptr) {
        return 0;
    }

#if defined(_M_X64)
    // `realloc_0` sizes its copy from this, so it has to answer for system-heap
    // blocks; `HeapSize` reports `(SIZE_T)-1` for a pointer it does not own.
    if (small_pool::Owns(memblock)) {
        return small_pool::ClassBytes(small_pool::ClassOfBlock(memblock));
    }
    return SystemHeapSize(memblock);
#else
    if (gPageOwnerByPage == nullptr) {
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
#endif
}

#if defined(_DLL)
// Only with the DLL runtime (/MD, `_DLL`). A statically linked CRT (/MT)
// brings its own `_msize` (msize.obj, beside `_msize_base`), which this would
// collide with. Nothing in the engine calls `_msize` by name, so with /MD the
// definition is unreferenced too.
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
#endif // _DLL

/**
 * Address: 0x00957B00 (FUN_00957B00, realloc)
 *
 * What it does:
 * Reallocates allocator-managed blocks with grow/shrink thresholds matching
 * recovered binary behavior.
 *
 * Named `realloc_0` for the same reason `malloc_0` carries its suffix: the
 * project links the DLL CRT, so `<cstdlib>` declares `realloc` as
 * `__declspec(dllimport)` and every translation unit that includes it binds
 * to `__imp__realloc` instead of this definition. A caller that then released
 * the block through `free_crt` - which does reach the engine allocator -
 * would be freeing a CRT block against the engine's page map. Callers that
 * want the engine allocator must name it explicitly.
 */
extern "C" void* __cdecl realloc_0(void* pblock, size_t newsize)
{
    if (pblock == nullptr) {
        return malloc_0(static_cast<std::uint32_t>(newsize));
    }

    if (newsize == 0) {
        free_0(pblock);
        return nullptr;
    }

    const size_t previousSize = msize(pblock);
    if (newsize > previousSize) {
        void* const grown = malloc_0(static_cast<std::uint32_t>(newsize));
        if (grown == nullptr) {
            return nullptr;
        }

        // Raw realloc-grow blob copy (malloc-backed block move).
        std::memcpy(grown, pblock, previousSize);
        free_0(pblock);
        return grown;
    }

    if (newsize <= (previousSize >> 1u)) {
        void* const shrunk = malloc_0(static_cast<std::uint32_t>(newsize));
        if (shrunk == nullptr) {
            return nullptr;
        }

        // Raw realloc-shrink blob copy (malloc-backed block move).
        std::memcpy(shrunk, pblock, newsize);
        free_0(pblock);
        return shrunk;
    }

    return pblock;
}

#if defined(_DLL)
// Only with the DLL runtime (/MD, `_DLL`). A statically linked CRT (/MT) calls
// `_expand` from its own `_aligned_realloc` (align.obj) on blocks of its own
// heap; this definition would take those calls over. Nothing in the engine
// calls `_expand` by name, so with /MD the definition is unreferenced too.
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
        free_0(pblock);
        return nullptr;
    }

    return (msize(pblock) >= newsize) ? pblock : nullptr;
}
#endif // _DLL

/**
 * Address: 0x00957AF0 (FUN_00957AF0, _free_crt)
 *
 * IDA signature:
 * void __cdecl free_crt(void *ptr);
 *
 * What it does:
 * CRT-lane thunk that forwards to the allocator's `free` (`free_0`). `operator delete`
 * reaches the small-block allocator through this hop rather than calling
 * `free` directly.
 */
extern "C" void __cdecl free_crt(void* const ptr)
{
    free_0(ptr);
}

/**
 * Address: 0x00A825B9 (FUN_00A825B9, ??2@YAPAXI@Z)
 * Mangled: ??2@YAPAXI@Z
 *
 * IDA signature:
 * void *__cdecl operator new(size_t size);
 *
 * What it does:
 * Global `operator new`. Retries `malloc` (`malloc_crt`) for as long as the installed
 * new-handler keeps reporting that it freed memory, and throws `std::bad_alloc`
 * once the handler gives up (or when none is installed).
 *
 * This override is what keeps C++ allocation on the engine allocator. MSVC's
 * own debug `operator new` calls `malloc` - which this translation unit already
 * replaces - but its debug `operator delete` calls `_free_dbg` directly, so
 * without this pair every `new`/`delete` round-trip would allocate from the
 * engine's small-block lanes and free into the CRT debug heap.
 */
void* __cdecl operator new(const std::size_t size)
{
    for (;;) {
        if (void* const block = malloc_crt(size)) {
            return block;
        }

        if (_callnewh(size) == 0) {
            throw std::bad_alloc{};
        }
    }
}

/**
 * Address: 0x00957A60 (FUN_00957A60, ??3@YAXPAX@Z)
 * Mangled: ??3@YAXPAX@Z
 *
 * IDA signature:
 * void __cdecl operator delete(void *ptr);
 *
 * What it does:
 * Global `operator delete`; a straight tail-jump to `free_crt` in the binary.
 */
void __cdecl operator delete(void* const ptr) noexcept
{
    free_crt(ptr);
}

/**
 * Address: 0x00A82542 (FUN_00A82542, ??_V@YAXPAX@Z)
 * Mangled: ??_V@YAXPAX@Z
 *
 * IDA signature:
 * void __cdecl operator delete[](void *a1);
 *
 * What it does:
 * Global array `operator delete`; a tail-jump to the scalar form.
 */
void __cdecl operator delete[](void* const ptr) noexcept
{
    ::operator delete(ptr);
}

/**
 * Sized and array forms C++14 onward lets the compiler emit. The 2007 binary
 * predates them, so they carry no address of their own and simply funnel into
 * the recovered scalar lanes - the allocator ignores the size hint.
 */
void __cdecl operator delete(void* const ptr, std::size_t) noexcept
{
    ::operator delete(ptr);
}

void __cdecl operator delete[](void* const ptr, std::size_t) noexcept
{
    ::operator delete(ptr);
}

void* __cdecl operator new[](const std::size_t size)
{
    return ::operator new(size);
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

#if defined(_M_X64)
    // On the x64 system heap the engine allocator never starts, and must not
    // be started here just to read its (empty) counters.
    FillSystemHeapStats(*outStats);
#else
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
#endif
}

/**
 * Address: 0x008D8FA0 (FUN_008D8FA0, func_ParseNum)
 *
 * What it does:
 * Parses one signed integer from `[start,end)` using legacy base autodetect
 * rules (`0x` hex, leading `0` octal, otherwise decimal).
 */
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
 *
 * What it does:
 * Nothing. FAF hot-patch (FA-Binary-Patches Kill_maploader_except): 0x009071FE jumps
 * straight to the epilogue at 0x0090723B, so the 0x406D1388 thread-naming exception the
 * stock binary raised (when AQtime instrumentation was on) is never raised.
 */
void gpg::SetThreadName([[maybe_unused]] const unsigned int id, [[maybe_unused]] const char* const name)
{
  FAF_PROFILE_SET_THREAD_NAME(name);
}
