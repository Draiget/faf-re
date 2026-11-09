#include "editor/EdMemTrace.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <DbgHelp.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"

namespace faf::editor::memtrace
{
  namespace
  {
    HANDLE gHeap = nullptr; // the tracker's own records, never through malloc_0

    template<class T>
    struct PrivateAllocator
    {
      using value_type = T;
      PrivateAllocator() = default;
      template<class U>
      PrivateAllocator(const PrivateAllocator<U>&) noexcept
      {}
      T* allocate(const std::size_t n)
      {
        void* const block = ::HeapAlloc(gHeap, 0, n * sizeof(T));
        if (block == nullptr) {
          throw std::bad_alloc{};
        }
        return static_cast<T*>(block);
      }
      void deallocate(T* const p, std::size_t) noexcept { ::HeapFree(gHeap, 0, p); }
      template<class U>
      bool operator==(const PrivateAllocator<U>&) const noexcept
      {
        return true;
      }
      template<class U>
      bool operator!=(const PrivateAllocator<U>&) const noexcept
      {
        return false;
      }
    };

    constexpr int kFrames = 16;
    using Frames = std::array<void*, kFrames>;

    struct Block
    {
      std::uint32_t size;
      std::uint32_t play;
      std::uint32_t stack;
    };

    struct Tracker
    {
      SRWLOCK lock = SRWLOCK_INIT;
      std::unordered_map<void*, Block, std::hash<void*>, std::equal_to<>, PrivateAllocator<std::pair<void* const, Block>>> blocks;
      std::unordered_map<std::uint64_t, std::uint32_t, std::hash<std::uint64_t>, std::equal_to<>,
                         PrivateAllocator<std::pair<const std::uint64_t, std::uint32_t>>>
        stackIds;
      std::vector<Frames, PrivateAllocator<Frames>> stacks;
    };

    Tracker* gTracker = nullptr;
    std::atomic<std::uint32_t> gPlay{0};
    thread_local int tInside = 0;

    void Hook(const int op, const int size, ...)
    {
      if (tInside != 0 || gTracker == nullptr) {
        return;
      }
      va_list args;
      va_start(args, size);
      void* const block = va_arg(args, void*);
      va_end(args);
      if (block == nullptr) {
        return;
      }
      ++tInside;
      if (op == 0) {
        Frames frames{};
        const USHORT captured = ::RtlCaptureStackBackTrace(2, kFrames, frames.data(), nullptr);
        std::uint64_t hash = 1469598103934665603ULL;
        for (USHORT i = 0; i < captured; ++i) {
          hash = (hash ^ reinterpret_cast<std::uintptr_t>(frames[i])) * 1099511628211ULL;
        }
        ::AcquireSRWLockExclusive(&gTracker->lock);
        auto [found, inserted] = gTracker->stackIds.try_emplace(hash, static_cast<std::uint32_t>(gTracker->stacks.size()));
        if (inserted) {
          gTracker->stacks.push_back(frames);
        }
        gTracker->blocks[block] = Block{static_cast<std::uint32_t>(size), gPlay.load(std::memory_order_relaxed), found->second};
        ::ReleaseSRWLockExclusive(&gTracker->lock);
      } else {
        ::AcquireSRWLockExclusive(&gTracker->lock);
        gTracker->blocks.erase(block);
        ::ReleaseSRWLockExclusive(&gTracker->lock);
      }
      --tInside;
    }

    /** "Function (file:line)" for one return address, or the module and offset. */
    std::string Describe(void* const address)
    {
      const HANDLE process = ::GetCurrentProcess();
      alignas(SYMBOL_INFO) char buffer[sizeof(SYMBOL_INFO) + 512] = {};
      auto* const symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
      symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
      symbol->MaxNameLen = 511;
      DWORD64 displacement = 0;
      std::string text;
      if (::SymFromAddr(process, reinterpret_cast<DWORD64>(address), &displacement, symbol)) {
        text = symbol->Name;
      } else {
        char raw[32];
        std::snprintf(raw, sizeof(raw), "%p", address);
        text = raw;
      }
      IMAGEHLP_LINE64 line{};
      line.SizeOfStruct = sizeof(line);
      DWORD lineDisplacement = 0;
      if (::SymGetLineFromAddr64(process, reinterpret_cast<DWORD64>(address), &lineDisplacement, &line)) {
        const char* const file = std::strrchr(line.FileName, '\\');
        text += " (" + std::string(file != nullptr ? file + 1 : line.FileName) + ":" + std::to_string(line.LineNumber) + ")";
      }
      return text;
    }

    /** The allocator's own frames, skipped in reports. */
    bool IsAllocatorFrame(const std::string& text)
    {
      static const char* const kSkip[] = {"malloc_0", "malloc_crt", "free_0", "realloc_0", "operator new", "Hook",
                                          "std::_Allocate", "std::allocator", "_Allocate_manually_vector_aligned", "malloc"};
      for (const char* skip : kSkip) {
        if (text.rfind(skip, 0) == 0 || text.find(std::string("::") + skip) != std::string::npos) {
          return true;
        }
      }
      return false;
    }
  } // namespace

  void Start()
  {
    if (gTracker != nullptr) {
      return;
    }
    gHeap = ::HeapCreate(0, 0, 0);
    void* const storage = ::HeapAlloc(gHeap, HEAP_ZERO_MEMORY, sizeof(Tracker));
    gTracker = new (storage) Tracker();
    ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    (void)::SymInitialize(::GetCurrentProcess(), nullptr, TRUE);
    gpg::SetMemHook(&Hook);
    gpg::Logf("memtrace: recording every block's call stack (slow)");
  }

  bool Running() noexcept
  {
    return gTracker != nullptr;
  }

  std::uint32_t NextPlay()
  {
    return gPlay.fetch_add(1) + 1;
  }

  void Report(const std::uint32_t play, const int count)
  {
    if (gTracker == nullptr) {
      return;
    }
    ++tInside; // nothing this does is recorded
    struct Site
    {
      std::uint32_t stack;
      std::uint64_t bytes;
      std::uint32_t blocks;
    };
    std::vector<Site, PrivateAllocator<Site>> sites;
    std::uint64_t totalBytes = 0;
    std::uint32_t totalBlocks = 0;
    {
      std::unordered_map<std::uint32_t, Site, std::hash<std::uint32_t>, std::equal_to<>, PrivateAllocator<std::pair<const std::uint32_t, Site>>> byStack;
      ::AcquireSRWLockShared(&gTracker->lock);
      for (const auto& [address, block] : gTracker->blocks) {
        if (block.play != play) {
          continue;
        }
        Site& site = byStack.try_emplace(block.stack, Site{block.stack, 0, 0}).first->second;
        site.bytes += block.size;
        ++site.blocks;
        totalBytes += block.size;
        ++totalBlocks;
      }
      ::ReleaseSRWLockShared(&gTracker->lock);
      for (const auto& [stack, site] : byStack) {
        sites.push_back(site);
      }
    }
    std::sort(sites.begin(), sites.end(), [](const Site& a, const Site& b) { return a.bytes > b.bytes; });
    gpg::Logf("memtrace: play %u left %.2f MB in %u blocks alive; the largest call sites:", play,
              static_cast<double>(totalBytes) / 1048576.0, totalBlocks);
    for (int i = 0; i < count && i < static_cast<int>(sites.size()); ++i) {
      Frames frames{};
      ::AcquireSRWLockShared(&gTracker->lock);
      frames = gTracker->stacks[sites[static_cast<std::size_t>(i)].stack];
      ::ReleaseSRWLockShared(&gTracker->lock);
      std::string where;
      int shown = 0;
      for (void* const frame : frames) {
        if (frame == nullptr || shown >= 6) {
          break;
        }
        const std::string text = Describe(frame);
        if (shown == 0 && IsAllocatorFrame(text)) {
          continue;
        }
        where += (shown == 0 ? "" : " < ") + text;
        ++shown;
      }
      gpg::Logf("memtrace:   %8.1f KB in %6u blocks: %s", static_cast<double>(sites[static_cast<std::size_t>(i)].bytes) / 1024.0,
                sites[static_cast<std::size_t>(i)].blocks, where.c_str());
    }
    --tInside;
  }
} // namespace faf::editor::memtrace
