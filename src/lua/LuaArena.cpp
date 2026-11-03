#include "lua/LuaArena.h"

#if INTPTR_MAX != INT32_MAX

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#else
#include <sys/mman.h>
#endif

namespace
{
  constexpr std::size_t kSpanBytes = 64u * 1024u;
  constexpr std::size_t kCommitChunkBytes = 1024u * 1024u;
  // Far above any game seen: Lua holds 117 MB live on a 6v6 game on a server. The range only reserves.
  // Windows keeps a page just below 2 GB in every process, so nothing larger is free below 4 GB.
  constexpr std::size_t kMaxReserveBytes = std::size_t{2} << 30;
  constexpr std::size_t kMinReserveBytes = std::size_t{1} << 29;
  constexpr std::uintptr_t kAddressStep = std::uintptr_t{1} << 24;
  constexpr std::uintptr_t kAddressLimit = std::uintptr_t{1} << 32;
  constexpr std::size_t kSpanCount = kMaxReserveBytes / kSpanBytes;
  constexpr std::size_t kMaxSmallBytes = 16384u;
  constexpr std::uint32_t kClassCount = 7u + 12u + 8u * 6u;
  constexpr std::uint8_t kLargeStart = 0xFEu;
  constexpr std::uint8_t kLargeInside = 0xFFu;

  /// Class sizes: 16..64 by 8, 80..256 by 16, then 8 classes each by 32, 64, ... 2048 up to 16 KB. A free
  /// block holds two links, so 16 is the floor. The fine steps keep what packing saved on table headers.
  [[nodiscard]] constexpr std::uint32_t ClassBytes(const std::uint32_t sizeClass) noexcept
  {
    if (sizeClass < 7u) {
      return (sizeClass + 2u) * 8u;
    }
    if (sizeClass < 19u) {
      return 64u + (sizeClass - 6u) * 16u;
    }
    const std::uint32_t band = (sizeClass - 19u) / 8u;
    return (256u << band) + ((sizeClass - 19u) % 8u + 1u) * (32u << band);
  }
  static_assert(ClassBytes(6) == 64u && ClassBytes(18) == 256u && ClassBytes(19) == 288u);
  static_assert(ClassBytes(kClassCount - 1u) == kMaxSmallBytes);

  struct ClassTable
  {
    std::uint8_t classOfQuantum[kMaxSmallBytes / 8u + 1u]{};
    constexpr ClassTable()
    {
      std::uint32_t sizeClass = 0;
      for (std::uint32_t quantum = 0; quantum <= kMaxSmallBytes / 8u; ++quantum) {
        while (ClassBytes(sizeClass) < quantum * 8u) {
          ++sizeClass;
        }
        classOfQuantum[quantum] = static_cast<std::uint8_t>(sizeClass);
      }
    }
  };
  constexpr ClassTable kClassTable{};

  [[nodiscard]] inline std::uint32_t ClassOf(const std::size_t bytes) noexcept
  {
    return kClassTable.classOfQuantum[(bytes + 7u) / 8u];
  }

  struct FreeBlock
  {
    FreeBlock* next;
    FreeBlock* nextBatch; // on a batch's first block in a global list: the next batch
  };

  [[nodiscard]] constexpr std::uint32_t BatchBlocks(const std::uint32_t sizeClass) noexcept
  {
    const std::uint32_t blocks = 8192u / ClassBytes(sizeClass);
    return (blocks < 4u) ? 4u : (blocks > 256u ? 256u : blocks);
  }

  struct GlobalClassLists
  {
    std::mutex lock;
    FreeBlock* batches = nullptr;
    FreeBlock* loose = nullptr;
    std::uint32_t looseCount = 0;
  };

  struct ThreadLists
  {
    FreeBlock* head[kClassCount];
    std::uint32_t count[kClassCount];
    bool registered;
    bool retired; // thread is exiting: every block goes through the global lists
  };

  struct LargeRun
  {
    std::size_t firstSpan;
    std::size_t spans;
  };

  std::uintptr_t gBase = 0;
  std::size_t gReserveBytes = 0;
  std::once_flag gReserveOnce;
  std::mutex gSpanLock;
  std::size_t gNextSpan = 0;
  std::size_t gCommittedBytes = 0;
  std::uint8_t gSpanClass[kSpanCount];
  std::uint32_t gLargeSpans[kSpanCount]; // on a large block's first span: its span count
  std::vector<LargeRun>* gFreeRuns = nullptr; // made on first use: the range is reserved before the CRT starts
  GlobalClassLists gGlobal[kClassCount];
  constinit thread_local ThreadLists tLists{};

  [[nodiscard]] std::uintptr_t TryReserve(const std::uintptr_t address, const std::size_t bytes) noexcept
  {
#if defined(_WIN32)
    return reinterpret_cast<std::uintptr_t>(
      ::VirtualAlloc(reinterpret_cast<void*>(address), bytes, MEM_RESERVE, PAGE_NOACCESS)
    );
#else
    void* const mapped = ::mmap(
      reinterpret_cast<void*>(address), bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0
    );
    if (mapped == MAP_FAILED) {
      return 0;
    }
    const std::uintptr_t got = reinterpret_cast<std::uintptr_t>(mapped);
    if (got != address) {
      ::munmap(mapped, bytes);
      return 0;
    }
    return got;
#endif
  }

  void Reserve() noexcept
  {
    // Every span of the range has to read back from 32 bits, so it ends below 4 GB. A crowded process
    // (overlays, injected DLLs) gets a smaller range before it gets none.
    for (std::size_t bytes = kMaxReserveBytes; bytes >= kMinReserveBytes && gBase == 0; bytes /= 2u) {
      for (std::uintptr_t address = kAddressStep; address + bytes <= kAddressLimit; address += kAddressStep) {
        gBase = TryReserve(address, bytes);
        if (gBase != 0) {
          gReserveBytes = bytes;
          break;
        }
      }
    }
    if (gBase == 0) {
      std::fputs("Lua arena: no free address range below 4 GB\n", stderr);
      std::abort();
    }
  }

  [[nodiscard]] bool CommitThrough(const std::size_t endBytes) noexcept
  {
    if (endBytes <= gCommittedBytes) {
      return true;
    }
    const std::size_t want = (endBytes - gCommittedBytes + kCommitChunkBytes - 1u) / kCommitChunkBytes * kCommitChunkBytes;
    const std::size_t commit = (want > gReserveBytes - gCommittedBytes) ? gReserveBytes - gCommittedBytes : want;
    void* const start = reinterpret_cast<void*>(gBase + gCommittedBytes);
#if defined(_WIN32)
    if (::VirtualAlloc(start, commit, MEM_COMMIT, PAGE_READWRITE) == nullptr) {
      return false;
    }
#else
    if (::mprotect(start, commit, PROT_READ | PROT_WRITE) != 0) {
      return false;
    }
#endif
    gCommittedBytes += commit;
    return endBytes <= gCommittedBytes;
  }

  /// Takes `spans` new spans. Caller holds gSpanLock.
  [[nodiscard]] std::size_t TakeSpans(const std::size_t spans) noexcept
  {
    if ((gNextSpan + spans) * kSpanBytes > gReserveBytes || !CommitThrough((gNextSpan + spans) * kSpanBytes)) {
      return kSpanCount;
    }
    const std::size_t first = gNextSpan;
    gNextSpan += spans;
    return first;
  }

  [[nodiscard]] FreeBlock* CarveSpan(const std::uint32_t sizeClass, std::uint32_t& outCount) noexcept
  {
    std::size_t span = kSpanCount;
    {
      std::lock_guard<std::mutex> guard(gSpanLock);
      span = TakeSpans(1u);
      if (span == kSpanCount) {
        return nullptr;
      }
      gSpanClass[span] = static_cast<std::uint8_t>(sizeClass);
    }
    const std::uintptr_t start = gBase + span * kSpanBytes;
    const std::size_t blockBytes = ClassBytes(sizeClass);
    const std::uint32_t blocks = static_cast<std::uint32_t>(kSpanBytes / blockBytes);
    FreeBlock* head = nullptr;
    for (std::uint32_t index = blocks; index-- > 0;) {
      auto* const block = reinterpret_cast<FreeBlock*>(start + index * blockBytes);
      block->next = head;
      head = block;
    }
    outCount = blocks;
    return head;
  }

  [[nodiscard]] FreeBlock* Refill(const std::uint32_t sizeClass, std::uint32_t& outCount) noexcept
  {
    GlobalClassLists& global = gGlobal[sizeClass];
    FreeBlock* taken = nullptr;
    {
      std::lock_guard<std::mutex> guard(global.lock);
      taken = global.batches;
      if (taken != nullptr) {
        global.batches = taken->nextBatch;
        outCount = BatchBlocks(sizeClass);
      } else if (global.loose != nullptr) {
        taken = global.loose;
        outCount = global.looseCount;
        global.loose = nullptr;
        global.looseCount = 0;
      }
    }
    return (taken != nullptr) ? taken : CarveSpan(sizeClass, outCount);
  }

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
    std::lock_guard<std::mutex> guard(global.lock);
    first->nextBatch = global.batches;
    global.batches = first;
  }

  void ReturnAll(ThreadLists& lists) noexcept
  {
    for (std::uint32_t sizeClass = 0; sizeClass < kClassCount; ++sizeClass) {
      FreeBlock* block = lists.head[sizeClass];
      if (block == nullptr) {
        continue;
      }
      GlobalClassLists& global = gGlobal[sizeClass];
      std::lock_guard<std::mutex> guard(global.lock);
      while (block != nullptr) {
        FreeBlock* const next = block->next;
        block->next = global.loose;
        global.loose = block;
        ++global.looseCount;
        block = next;
      }
      lists.head[sizeClass] = nullptr;
      lists.count[sizeClass] = 0;
    }
  }

  struct ThreadExitGuard
  {
    ~ThreadExitGuard()
    {
      tLists.retired = true;
      ReturnAll(tLists);
    }
  };
  thread_local ThreadExitGuard tExitGuard;

  [[nodiscard]] void* AllocateLarge(const std::size_t bytes) noexcept
  {
    const std::size_t spans = (bytes + kSpanBytes - 1u) / kSpanBytes;
    std::lock_guard<std::mutex> guard(gSpanLock);
    std::size_t first = kSpanCount;
    if (gFreeRuns == nullptr) {
      gFreeRuns = new std::vector<LargeRun>();
    }
    std::vector<LargeRun>& runs = *gFreeRuns;
    for (std::size_t index = 0; index < runs.size(); ++index) {
      if (runs[index].spans >= spans) {
        first = runs[index].firstSpan;
        runs[index].firstSpan += spans;
        runs[index].spans -= spans;
        if (runs[index].spans == 0u) {
          runs[index] = runs.back();
          runs.pop_back();
        }
        break;
      }
    }
    if (first == kSpanCount) {
      first = TakeSpans(spans);
      if (first == kSpanCount) {
        return nullptr;
      }
    }
    gSpanClass[first] = kLargeStart;
    gLargeSpans[first] = static_cast<std::uint32_t>(spans);
    for (std::size_t index = 1; index < spans; ++index) {
      gSpanClass[first + index] = kLargeInside;
    }
    return reinterpret_cast<void*>(gBase + first * kSpanBytes);
  }

  void FreeLarge(const std::size_t first) noexcept
  {
    std::lock_guard<std::mutex> guard(gSpanLock);
    gFreeRuns->push_back(LargeRun{first, gLargeSpans[first]});
  }

  [[nodiscard]] std::size_t BlockBytes(const void* const block) noexcept
  {
    const std::size_t span = (reinterpret_cast<std::uintptr_t>(block) - gBase) / kSpanBytes;
    const std::uint8_t sizeClass = gSpanClass[span];
    return (sizeClass == kLargeStart) ? std::size_t{gLargeSpans[span]} * kSpanBytes : ClassBytes(sizeClass);
  }

  struct LightCells
  {
    std::mutex lock;
    std::vector<void**> cells;
  };
  LightCells& Lights()
  {
    static LightCells* const lights = new LightCells();
    return *lights;
  }
} // namespace

namespace lua
{
  void ArenaReserve() noexcept
  {
    std::call_once(gReserveOnce, &Reserve);
  }

  void* ArenaAllocate(const std::size_t bytes) noexcept
  {
    ArenaReserve();
    if (bytes > kMaxSmallBytes) {
      return AllocateLarge(bytes);
    }

    const std::uint32_t sizeClass = ClassOf(bytes != 0u ? bytes : 1u);
    ThreadLists& lists = tLists;
    if (!lists.registered) {
      lists.registered = true;
      (void)&tExitGuard;
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
    if (lists.retired) {
      ReturnAll(lists);
    }
    return block;
  }

  void* ArenaReallocate(void* const block, const std::size_t oldBytes, const std::size_t bytes) noexcept
  {
    if (block == nullptr) {
      return ArenaAllocate(bytes);
    }
    // The span table knows the block's real size, so a caller's stale `oldBytes` cannot overrun it.
    const std::size_t capacity = BlockBytes(block);
    if (bytes <= capacity && (bytes > kMaxSmallBytes || ClassBytes(ClassOf(bytes != 0u ? bytes : 1u)) == capacity)) {
      return block;
    }
    void* const moved = ArenaAllocate(bytes);
    if (moved == nullptr) {
      return nullptr;
    }
    const std::size_t keep = (oldBytes < capacity) ? oldBytes : capacity;
    std::memcpy(moved, block, (keep < bytes) ? keep : bytes);
    ArenaFree(block);
    return moved;
  }

  void ArenaFree(void* const block) noexcept
  {
    if (block == nullptr) {
      return;
    }
    const std::size_t span = (reinterpret_cast<std::uintptr_t>(block) - gBase) / kSpanBytes;
    const std::uint8_t sizeClass = gSpanClass[span];
    if (sizeClass == kLargeStart) {
      FreeLarge(span);
      return;
    }
    ThreadLists& lists = tLists;
    auto* const freed = static_cast<FreeBlock*>(block);
    freed->next = lists.head[sizeClass];
    lists.head[sizeClass] = freed;
    ++lists.count[sizeClass];
    if (lists.retired) {
      ReturnAll(lists);
    } else if (lists.count[sizeClass] >= 2u * BatchBlocks(sizeClass)) {
      ReturnBatch(lists, sizeClass);
    }
  }

  void* const* ArenaLightCell(void* const pointer) noexcept
  {
    LightCells& lights = Lights();
    std::lock_guard<std::mutex> guard(lights.lock);
    for (void** const cell : lights.cells) {
      if (*cell == pointer) {
        return cell;
      }
    }
    void** const cell = static_cast<void**>(ArenaAllocate(sizeof(void*)));
    if (cell != nullptr) {
      *cell = pointer;
      lights.cells.push_back(cell);
    }
    return cell;
  }
} // namespace lua

#endif
