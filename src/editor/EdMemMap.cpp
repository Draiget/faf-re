#include "editor/EdMemMap.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "gpg/core/utils/Logging.h"

namespace faf::editor::memmap
{
  namespace
  {
    constexpr double kMB = 1048576.0;

    struct ThreadBasicInformation
    {
      LONG exitStatus;
      void* tebBaseAddress;
      void* clientId[2];
      ULONG_PTR affinityMask;
      LONG priority;
      LONG basePriority;
    };

    using NtQueryInformationThreadFn = LONG(NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);

    /** The allocation base of every Win32 heap's pieces (segments and large blocks), to its heap. */
    void MapHeaps(std::map<std::uintptr_t, std::uintptr_t>& owner, Snapshot& snapshot)
    {
      const DWORD count = ::GetProcessHeaps(0, nullptr);
      std::vector<HANDLE> heaps(count + 16);
      const DWORD got = ::GetProcessHeaps(static_cast<DWORD>(heaps.size()), heaps.data());
      heaps.resize(got < heaps.size() ? got : heaps.size());
      snapshot.processHeap = reinterpret_cast<std::uintptr_t>(::GetProcessHeap());
      for (HANDLE heap : heaps) {
        const auto key = reinterpret_cast<std::uintptr_t>(heap);
        snapshot.heaps[key] = 0;
        if (!::HeapLock(heap)) {
          continue;
        }
        PROCESS_HEAP_ENTRY entry{};
        std::uintptr_t knownLow = 0;
        std::uintptr_t knownHigh = 0;
        while (::HeapWalk(heap, &entry)) {
          const auto address = reinterpret_cast<std::uintptr_t>(entry.lpData);
          if (address >= knownLow && address < knownHigh) {
            continue;
          }
          MEMORY_BASIC_INFORMATION info{};
          if (::VirtualQuery(entry.lpData, &info, sizeof(info)) == 0) {
            continue;
          }
          knownLow = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
          knownHigh = knownLow + info.RegionSize;
          owner[reinterpret_cast<std::uintptr_t>(info.AllocationBase)] = key;
        }
        ::HeapUnlock(heap);
      }
    }

    /** The allocation base of every thread's stack. */
    std::set<std::uintptr_t> StackBases(unsigned long& threads)
    {
      std::set<std::uintptr_t> bases;
      threads = 0;
      const auto query = reinterpret_cast<NtQueryInformationThreadFn>(
        reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"))
      );
      const HANDLE list = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
      if (list == INVALID_HANDLE_VALUE) {
        return bases;
      }
      const DWORD self = ::GetCurrentProcessId();
      THREADENTRY32 thread{};
      thread.dwSize = sizeof(thread);
      for (BOOL more = ::Thread32First(list, &thread); more; more = ::Thread32Next(list, &thread)) {
        if (thread.th32OwnerProcessID != self) {
          continue;
        }
        ++threads;
        if (query == nullptr) {
          continue;
        }
        const HANDLE handle = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, thread.th32ThreadID);
        if (handle == nullptr) {
          continue;
        }
        ThreadBasicInformation basic{};
        if (query(handle, 0, &basic, sizeof(basic), nullptr) >= 0 && basic.tebBaseAddress != nullptr) {
          const auto* const tib = static_cast<const NT_TIB*>(basic.tebBaseAddress);
          MEMORY_BASIC_INFORMATION info{};
          if (::VirtualQuery(tib->StackLimit, &info, sizeof(info)) != 0) {
            bases.insert(reinterpret_cast<std::uintptr_t>(info.AllocationBase));
          }
        }
        ::CloseHandle(handle);
      }
      ::CloseHandle(list);
      return bases;
    }

    std::string HeapName(const Snapshot& snapshot, const std::uintptr_t heap)
    {
      char text[64];
      std::snprintf(text, sizeof(text), "heap %llx%s", static_cast<unsigned long long>(heap),
                    heap == snapshot.processHeap ? " (the process heap)" : "");
      return text;
    }
  } // namespace

  Snapshot Take()
  {
    Snapshot snapshot;
    std::map<std::uintptr_t, std::uintptr_t> heapOwner;
    MapHeaps(heapOwner, snapshot);
    const std::set<std::uintptr_t> stackBases = StackBases(snapshot.threads);

    SYSTEM_INFO system{};
    ::GetSystemInfo(&system);
    auto address = reinterpret_cast<std::uintptr_t>(system.lpMinimumApplicationAddress);
    const auto end = reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
    std::map<std::uintptr_t, std::size_t> reserved;
    while (address < end) {
      MEMORY_BASIC_INFORMATION info{};
      if (::VirtualQuery(reinterpret_cast<const void*>(address), &info, sizeof(info)) == 0) {
        break;
      }
      const std::size_t size = info.RegionSize;
      if (info.State != MEM_FREE) {
        reserved[reinterpret_cast<std::uintptr_t>(info.AllocationBase)] += size;
      }
      if (info.State == MEM_COMMIT) {
        const auto base = reinterpret_cast<std::uintptr_t>(info.AllocationBase);
        if (info.Type == MEM_PRIVATE) {
          snapshot.privateTotal += size;
          if (const auto heap = heapOwner.find(base); heap != heapOwner.end()) {
            snapshot.heaps[heap->second] += size;
          } else if (stackBases.count(base) != 0) {
            snapshot.stacks += size;
          } else {
            if (snapshot.loose.count(base) == 0) {
              snapshot.looseProtect[base] = info.Protect;
            }
            snapshot.loose[base] += size;
          }
        } else if (info.Type == MEM_MAPPED) {
          snapshot.mapped += size;
        } else if (info.Type == MEM_IMAGE) {
          snapshot.image += size;
        }
      }
      address = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + size;
    }
    for (const auto& [base, size] : snapshot.loose) {
      snapshot.looseReserved[base] = reserved[base];
    }

    snapshot.handles = 0;
    ::GetProcessHandleCount(::GetCurrentProcess(), &snapshot.handles);
    snapshot.gdiObjects = ::GetGuiResources(::GetCurrentProcess(), GR_GDIOBJECTS);
    snapshot.userObjects = ::GetGuiResources(::GetCurrentProcess(), GR_USEROBJECTS);
    return snapshot;
  }

  void LogChanges(const Snapshot& before, const Snapshot& after)
  {
    std::size_t heapTotal = 0;
    for (const auto& [heap, size] : after.heaps) {
      heapTotal += size;
    }
    std::size_t looseTotal = 0;
    for (const auto& [base, size] : after.loose) {
      looseTotal += size;
    }
    gpg::Logf("editor: memory map: %.1f MB private = heaps %.1f (%zu heaps) + stacks %.1f (%lu threads) + other %.1f; "
              "mapped %.1f MB, images %.1f MB; %lu handles, %lu GDI, %lu USER objects",
              after.privateTotal / kMB, heapTotal / kMB, after.heaps.size(), after.stacks / kMB, after.threads,
              looseTotal / kMB, after.mapped / kMB, after.image / kMB, after.handles, after.gdiObjects, after.userObjects);
    if (before.privateTotal == 0) {
      return;
    }

    auto delta = [](const std::size_t now, const std::size_t was) {
      return (static_cast<double>(now) - static_cast<double>(was)) / kMB;
    };
    gpg::Logf("editor: memory map since the last play: private %+.2f MB, stacks %+.2f MB, threads %+ld, mapped %+.2f MB, "
              "handles %+ld, GDI %+ld, USER %+ld",
              delta(after.privateTotal, before.privateTotal), delta(after.stacks, before.stacks),
              static_cast<long>(after.threads) - static_cast<long>(before.threads), delta(after.mapped, before.mapped),
              static_cast<long>(after.handles) - static_cast<long>(before.handles),
              static_cast<long>(after.gdiObjects) - static_cast<long>(before.gdiObjects),
              static_cast<long>(after.userObjects) - static_cast<long>(before.userObjects));

    for (const auto& [heap, size] : after.heaps) {
      const auto was = before.heaps.find(heap);
      const std::size_t previous = was != before.heaps.end() ? was->second : 0;
      if (size > previous + 65536 || previous > size + 65536 || was == before.heaps.end()) {
        gpg::Logf("editor:   %s%s: %+.2f MB, now %.2f MB", HeapName(after, heap).c_str(),
                  was == before.heaps.end() ? " (new)" : "", delta(size, previous), size / kMB);
      }
    }
    for (const auto& [heap, size] : before.heaps) {
      if (after.heaps.count(heap) == 0) {
        gpg::Logf("editor:   %s: gone (was %.2f MB)", HeapName(before, heap).c_str(), size / kMB);
      }
    }

    // Direct allocations: the new ones grouped by size and protection, and the ones that grew.
    std::map<std::pair<std::size_t, unsigned long>, int> added;
    std::multimap<double, std::uintptr_t> changed;
    double addedBytes = 0.0;
    double grownBytes = 0.0;
    double goneBytes = 0.0;
    for (const auto& [base, size] : after.loose) {
      const auto was = before.loose.find(base);
      if (was == before.loose.end()) {
        ++added[{size, after.looseProtect.at(base)}];
        addedBytes += static_cast<double>(size);
      } else if (size != was->second) {
        const double change = static_cast<double>(size) - static_cast<double>(was->second);
        grownBytes += change;
        changed.emplace(change < 0.0 ? -change : change, base);
      }
    }
    for (const auto& [base, size] : before.loose) {
      if (after.loose.count(base) == 0) {
        goneBytes += static_cast<double>(size);
      }
    }
    gpg::Logf("editor:   direct allocations: %.2f MB new, %.2f MB gone, %+.2f MB in ones that changed size", addedBytes / kMB,
              goneBytes / kMB, grownBytes / kMB);
    int lines = 0;
    for (auto it = changed.rbegin(); it != changed.rend() && lines < 6; ++it, ++lines) {
      const std::uintptr_t base = it->second;
      gpg::Logf("editor:     at %llx (reserves %.1f MB): %.2f -> %.2f MB committed", static_cast<unsigned long long>(base),
                after.looseReserved.at(base) / kMB, before.loose.at(base) / kMB, after.loose.at(base) / kMB);
    }
    lines = 0;
    for (auto it = added.rbegin(); it != added.rend() && lines < 16; ++it, ++lines) {
      gpg::Logf("editor:     %d new of %zu KB (protection 0x%lx)", it->second, it->first.first / 1024, it->first.second);
    }
  }
} // namespace faf::editor::memmap
