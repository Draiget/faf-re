// Included at the END of Global.cpp only in an isolated x86 test build.
// No copied allocator bodies, OS stubs, live-state reset, or fake addresses.
#if !defined(_WIN32) || defined(_M_X64) || defined(__x86_64__)
#error Allocator boundary acceptance requires native Windows x86
#endif
#include <cstdio>
static_assert(sizeof(void*) == 4);
namespace {
[[noreturn]] void BoundsFail(const char* why, unsigned code = 1)
{
    std::fprintf(stderr, "%s: %s\n", code == 77 ? "BLOCKED" : "FAIL", why);
    std::fflush(stdout);
    std::fflush(stderr);
    ::ExitProcess(code); // Each CTest invocation is an isolated process.
}
void BoundsCheck(bool ok, const char* why) { if (!ok) BoundsFail(why); }
void BoundsSmoke()
{
    for (unsigned size : {1u, 40u, 16384u, 16385u, 65536u}) {
        auto* p = static_cast<unsigned char*>(malloc_0(size));
        BoundsCheck(p != nullptr && msize(p) >= size, "public malloc/size");
        std::memset(p, 0xA7, size);
        auto* q = static_cast<unsigned char*>(realloc_0(p, size * 2));
        BoundsCheck(q != nullptr && msize(q) >= size * 2, "public realloc/size");
        for (unsigned i = 0; i < size; ++i) BoundsCheck(q[i] == 0xA7, "realloc preservation");
        free_0(q);
    }
}
DWORD WINAPI BoundsThread(void*) { for (unsigned i=0; i<16; ++i) BoundsSmoke(); return 0; }
// Reconstructed retry fixture: bounded free-region discovery, never VA filling.
// All arithmetic stays 64-bit until a verified in-range native pointer is formed.
std::uint8_t* BoundsReserve(std::uint64_t first, std::uint64_t last, bool pair = false)
{
    constexpr std::uint64_t granularity = 65536;
    constexpr unsigned maxQueries = 1024, maxAllocations = 64;
    BoundsCheck(first < last && last <= 0x100000000ull && first % granularity == 0 &&
                last % granularity == 0, "fixture interval");
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    BoundsCheck(si.dwAllocationGranularity == granularity && si.dwPageSize == 4096, "Windows geometry");
    const auto osFirst = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress));
    const auto osLast = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress)) + 1;
    if (last > osLast) last = osLast;
    auto cursor = first > osFirst ? first : osFirst;
    cursor = (cursor + granularity - 1) & ~(granularity - 1);
    const std::uint64_t needed = pair ? 2 * granularity : granularity;
    unsigned queries = 0, allocations = 0;
    DWORD error = 0;
    std::printf("fixture interval=[%llx,%llx) heap_base=%p initialized=%d pair=%d\n",
                static_cast<unsigned long long>(cursor), static_cast<unsigned long long>(last),
                gHeapBase, gAllocatorSentinelIsCritical ? 1 : 0, pair ? 1 : 0);
    while (cursor < last && last - cursor >= needed && queries < maxQueries &&
           allocations + (pair ? 2u : 1u) <= maxAllocations) {
        MEMORY_BASIC_INFORMATION info{};
        ++queries;
        const auto address = reinterpret_cast<void*>(static_cast<std::uintptr_t>(cursor));
        if (::VirtualQuery(address, &info, sizeof(info)) != sizeof(info)) { error = ::GetLastError(); break; }
        const auto regionFirst = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(info.BaseAddress));
        const auto regionLast = regionFirst + static_cast<std::uint64_t>(info.RegionSize);
        BoundsCheck(regionFirst <= cursor && regionLast > cursor && regionLast <= 0x100000000ull,
                    "VirtualQuery progress/range");
        const auto end = regionLast < last ? regionLast : last;
        if (info.State != MEM_FREE || end - cursor < needed) {
            cursor = (end + granularity - 1) & ~(granularity - 1);
            continue;
        }
        ++allocations;
        auto* p = static_cast<std::uint8_t*>(::VirtualAlloc(address, granularity,
                                                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!p) { error = ::GetLastError(); cursor += granularity; continue; }
        BoundsCheck(p == address, "exact reservation address");
        auto* q = static_cast<std::uint8_t*>(nullptr);
        if (pair) {
            ++allocations;
            q = static_cast<std::uint8_t*>(::VirtualAlloc(p + granularity, granularity,
                                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!q) {
                error = ::GetLastError();
                BoundsCheck(::VirtualFree(p, 0, MEM_RELEASE) != 0, "pair race cleanup");
                cursor += granularity;
                continue;
            }
            BoundsCheck(q == p + granularity, "exact second reservation address");
        }
        for (unsigned i = 0; i < (pair ? 2u : 1u); ++i) {
            auto* allocation = i ? q : p;
            MEMORY_BASIC_INFORMATION actual{};
            BoundsCheck(::VirtualQuery(allocation, &actual, sizeof(actual)) == sizeof(actual) &&
                        actual.BaseAddress == allocation && actual.AllocationBase == allocation &&
                        actual.State == MEM_COMMIT && actual.RegionSize >= granularity,
                        "real independent reservation");
        }
        std::printf("fixture selected=%p queries=%u allocations=%u\n", p, queries, allocations);
        return p;
    }
    std::printf("fixture unavailable queries=%u allocations=%u last_error=%lu\n", queries, allocations,
                static_cast<unsigned long>(error));
    BoundsFail("required range unavailable within bounded discovery; not proof of OS exhaustion", 77);
}
HeapRecord* BoundsRecord(void* address, unsigned pages, void* reservation)
{
    auto* record = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes, true));
    BoundsCheck(record != nullptr, "production descriptor allocation");
    return ConstructHeapRecord(record, address, pages, kRecordTagLargeAllocation, reservation, 0);
}
void BoundsDispose(HeapRecord* record)
{
    (void)PopHeapRecord(record);
    SetPageOwnerRange(record->allocation, record->sizePages, nullptr);
    (void)PushHeapBlock(reinterpret_cast<SmallBlockNode*>(record),
                        static_cast<std::int32_t>(GetSmallBlockIndex(kHeapRecordSizeBytes)));
}
void BoundsMerge(std::uint64_t first, std::uint64_t last, bool releaseLeftFirst)
{
    auto* p = BoundsReserve(first, last);
    std::printf("reservation=%p bytes=65536 order=%s\n", p, releaseLeftFirst ? "left-first" : "right-first");
    ::EnterCriticalSection(&gAllocatorSentinel);
    // Real writable pages and descriptors allocated by the production allocator.
    auto* left = BoundsRecord(p, 1, p);
    auto* right = BoundsRecord(p + 4096, 1, p);
    p[0] = 1; p[4096] = 2;
    HeapRecord* survivor = releaseLeftFirst ? right : left;
    (void)ReleaseHeapRecord(releaseLeftFirst ? left : right);
    (void)ReleaseHeapRecord(survivor);
    BoundsCheck(survivor->allocation == p && survivor->sizePages == 2, "adjacent same-reservation merge");
    BoundsCheck(GetPageOwner(p) == survivor && GetPageOwner(p + 4096) == survivor, "merged ownership");
    BoundsCheck(survivor->next != nullptr && *survivor->next == survivor, "free bucket linkage");
    MEMORY_BASIC_INFORMATION info{};
    BoundsCheck(::VirtualQuery(p, &info, sizeof(info)) == sizeof(info) && info.State == MEM_RESERVE,
                "production release decommitted pages");
    BoundsDispose(survivor);
    ::LeaveCriticalSection(&gAllocatorSentinel);
    BoundsCheck(::VirtualFree(p, 0, MEM_RELEASE) != 0, "reservation cleanup");
}
void BoundsSeparateReservations()
{
    // Reserve two independent adjacent 64 KiB allocations; never substitute a false AllocationBase.
    auto* p = BoundsReserve(0xC0000000ull, 0xFFC00000ull, true);
    auto* q = p + 65536;
    ::EnterCriticalSection(&gAllocatorSentinel);
    auto* left = BoundsRecord(p + 61440,1,p);
    auto* right = BoundsRecord(q,1,q);
    (void)ReleaseHeapRecord(right);
    (void)ReleaseHeapRecord(left);
    BoundsCheck(left->sizePages==1 && right->sizePages==1, "different reservations must not merge");
    BoundsCheck(GetPageOwner(p+61440)==left && GetPageOwner(q)==right,"separate ownership");
    BoundsDispose(left); BoundsDispose(right);
    ::LeaveCriticalSection(&gAllocatorSentinel);
    BoundsCheck(::VirtualFree(p,0,MEM_RELEASE)!=0 && ::VirtualFree(q,0,MEM_RELEASE)!=0,"separate cleanup");
}
} // namespace
extern "C" int FafRunAllocatorBoundsCase(const char* mode)
{
    BOOL wow64 = FALSE;
    BoundsCheck(::IsWow64Process(::GetCurrentProcess(), &wow64) && wow64, "requires x86 on 64-bit Windows");
    // Initialization goes through public allocator, never overwrites initialized globals.
    BoundsSmoke();
    BoundsCheck(gAllocatorSentinelIsCritical && gPageOwnerByPage != nullptr, "production initialization");
    if (std::strcmp(mode,"normal") == 0) {
        HANDLE threads[2] = {::CreateThread(nullptr,0,BoundsThread,nullptr,0,nullptr),
                             ::CreateThread(nullptr,0,BoundsThread,nullptr,0,nullptr)};
        BoundsCheck(threads[0] && threads[1],"thread creation");
        BoundsCheck(::WaitForMultipleObjects(2,threads,TRUE,60000)==WAIT_OBJECT_0,"thread completion");
        for (auto handle: threads) { DWORD code=1; BoundsCheck(::GetExitCodeThread(handle,&code)&&code==0,"thread exit"); ::CloseHandle(handle); }
    } else if (std::strcmp(mode,"low") == 0) {
        BoundsMerge(0x10000ull,0xC0000000ull,false); BoundsMerge(0x10000ull,0xC0000000ull,true);
    } else if (std::strcmp(mode,"high") == 0) {
        BoundsMerge(0xC0000000ull,0xFFC00000ull,false); BoundsMerge(0xC0000000ull,0xFFC00000ull,true);
    } else if (std::strcmp(mode,"map") == 0) {
        // Baseline refuses BEFORE its known out-of-bounds access; no deliberate corruption.
        BoundsCheck(kPageOwnerMapBytes/sizeof(HeapRecord*) == 0x100000u,"full x86 map capacity");
        BoundsCheck(kMaxPageIndex == 0x100000u,"exclusive bound");
        BoundsMerge(0xFFC00000ull,0x100000000ull,false); BoundsMerge(0xFFC00000ull,0x100000000ull,true);
    } else if (std::strcmp(mode,"separate") == 0) {
        BoundsSeparateReservations();
    } else BoundsFail("unknown test case");
    std::printf("PASS native production-backed allocator case=%s\n",mode);
    return 0;
}
