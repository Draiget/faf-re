// Engine addition, not in the shipped binary (see FrameSampler.h).

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <DbgHelp.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gpg/core/diagnostics/CrashHooks.h"
#include "gpg/core/diagnostics/FrameSampler.h"
#include "gpg/core/utils/Logging.h"

namespace gpg::diag
{
  bool DiagSymbolsReady();

  namespace
  {
    constexpr std::size_t kMaxDepth = 48;
    constexpr std::size_t kRingSamples = 8192; // ~8 s at one sample a millisecond
    constexpr std::size_t kTopInclusive = 28;
    constexpr std::size_t kTopSelf = 12;
    constexpr std::size_t kTopCallerLeaves = 6; // the leaves whose caller chains are printed
    constexpr std::size_t kChainsPerLeaf = 3;
    constexpr std::uint32_t kCallerChainDepth = 10;

    struct Sample
    {
      LONGLONG time = 0;
      std::uint32_t depth = 0;
      std::uintptr_t frames[kMaxDepth] = {};
    };

    struct Window
    {
      LONGLONG start = 0;
      LONGLONG end = 0;
      double milliseconds = 0.0;
    };

    struct SamplerState
    {
      double thresholdMs = 0.0;
      HANDLE target = nullptr;
      HANDLE wake = nullptr;
      LONGLONG frequency = 1;
      LONGLONG lastMark = 0;
      std::vector<Sample> ring = std::vector<Sample>(kRingSamples);
      std::atomic<std::uint64_t> written{0}; // samples taken so far (ring index = written % size)
      std::mutex windowsLock;
      std::deque<Window> windows;
      std::unordered_map<std::uintptr_t, std::pair<std::uintptr_t, std::string>> symbols; // address -> function start, name
    };

    SamplerState& State()
    {
      static SamplerState* const state = new SamplerState(); // never destroyed: the thread outlives statics
      return *state;
    }

    [[nodiscard]] LONGLONG Now() noexcept
    {
      LARGE_INTEGER value{};
      ::QueryPerformanceCounter(&value);
      return value.QuadPart;
    }

    /** Walks the suspended thread's stack from `context`. Must not allocate: the target may hold the heap lock. */
    std::uint32_t Walk(CONTEXT& context, std::uintptr_t* const frames)
    {
#if defined(_M_X64)
      std::uint32_t depth = 0;
      while (depth < kMaxDepth && context.Rip != 0) {
        frames[depth++] = static_cast<std::uintptr_t>(context.Rip);
        DWORD64 imageBase = 0;
        PRUNTIME_FUNCTION const function = ::RtlLookupFunctionEntry(context.Rip, &imageBase, nullptr);
        if (function == nullptr) {
          // A leaf function: the return address is at the top of the stack.
          context.Rip = *reinterpret_cast<const DWORD64*>(context.Rsp);
          context.Rsp += 8;
          continue;
        }
        void* handlerData = nullptr;
        DWORD64 establisherFrame = 0;
        (void)::RtlVirtualUnwind(
          UNW_FLAG_NHANDLER, imageBase, context.Rip, function, &context, &handlerData, &establisherFrame, nullptr
        );
      }
      return depth;
#else
      frames[0] = static_cast<std::uintptr_t>(context.Eip);
      return 1U;
#endif
    }

    /** Walk under SEH: a stack in an unusual state must cost the sample, not the process. */
    std::uint32_t GuardedWalk(CONTEXT& context, std::uintptr_t* const frames)
    {
      __try {
        return Walk(context, frames);
      } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0U;
      }
    }

    void TakeSample(SamplerState& state)
    {
      if (::SuspendThread(state.target) == static_cast<DWORD>(-1)) {
        return;
      }
      CONTEXT context{};
      context.ContextFlags = CONTEXT_FULL;
      const std::uint64_t index = state.written.load(std::memory_order_relaxed);
      Sample& sample = state.ring[index % kRingSamples];
      sample.time = Now();
      sample.depth = ::GetThreadContext(state.target, &context) != FALSE ? GuardedWalk(context, sample.frames) : 0U;
      (void)::ResumeThread(state.target);
      state.written.store(index + 1U, std::memory_order_release);
    }

    const std::pair<std::uintptr_t, std::string>& Resolve(SamplerState& state, const std::uintptr_t address)
    {
      auto found = state.symbols.find(address);
      if (found != state.symbols.end()) {
        return found->second;
      }
      std::pair<std::uintptr_t, std::string> entry{address, {}};
      if (DiagSymbolsReady()) {
        alignas(SYMBOL_INFO) unsigned char storage[sizeof(SYMBOL_INFO) + 256] = {};
        auto* const symbol = reinterpret_cast<SYMBOL_INFO*>(storage);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = 255;
        DWORD64 offset = 0;
        if (::SymFromAddr(::GetCurrentProcess(), address, &offset, symbol) != FALSE) {
          entry.first = static_cast<std::uintptr_t>(symbol->Address);
          entry.second = symbol->Name;
        }
      }
      if (entry.second.empty()) {
        char described[420] = {};
        DiagDescribeAddress(reinterpret_cast<const void*>(address), described, sizeof(described));
        entry.second = described;
      }
      return state.symbols.emplace(address, std::move(entry)).first->second;
    }

    void Report(SamplerState& state, const Window& window)
    {
      std::unordered_map<std::uintptr_t, std::uint32_t> inclusive;
      std::unordered_map<std::uintptr_t, std::uint32_t> self;
      std::unordered_map<std::uintptr_t, const std::string*> names;
      std::uint32_t samples = 0;
      const std::uint64_t written = state.written.load(std::memory_order_acquire);
      const std::uint64_t first = written > kRingSamples ? written - kRingSamples : 0U;
      // Per leaf function, how often each chain of its callers appears: where the time goes.
      std::unordered_map<std::uintptr_t, std::unordered_map<std::string, std::uint32_t>> callers;
      std::unordered_set<std::uintptr_t> seen;
      for (std::uint64_t index = first; index < written; ++index) {
        const Sample& sample = state.ring[index % kRingSamples];
        if (sample.time < window.start || sample.time > window.end || sample.depth == 0U) {
          continue;
        }
        ++samples;
        seen.clear();
        std::string chain;
        std::uint32_t chained = 0;
        std::uintptr_t previous = 0;
        for (std::uint32_t depth = 0; depth < sample.depth; ++depth) {
          const auto& resolved = Resolve(state, sample.frames[depth]);
          names[resolved.first] = &resolved.second;
          if (depth == 0U) {
            ++self[resolved.first];
          } else if (chained < kCallerChainDepth && resolved.first != previous) {
            chain += " < ";
            chain += resolved.second;
            ++chained;
          }
          previous = resolved.first;
          if (seen.insert(resolved.first).second) {
            ++inclusive[resolved.first];
          }
        }
        ++callers[Resolve(state, sample.frames[0]).first][chain];
      }
      gpg::Logf("[FRAMESAMPLE] frame of %.1f ms: %u samples", window.milliseconds, samples);
      if (samples == 0U) {
        return;
      }
      const auto print = [&](const char* const kind, std::unordered_map<std::uintptr_t, std::uint32_t>& counts, const std::size_t top) {
        std::vector<std::pair<std::uint32_t, std::uintptr_t>> sorted;
        sorted.reserve(counts.size());
        for (const auto& [function, count] : counts) {
          sorted.emplace_back(count, function);
        }
        std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
        for (std::size_t index = 0; index < sorted.size() && index < top; ++index) {
          gpg::Logf("[FRAMESAMPLE]   %s %5.1f%% %4u  %s", kind, 100.0 * sorted[index].first / samples, sorted[index].first,
            names[sorted[index].second]->c_str());
        }
      };
      print("incl", inclusive, kTopInclusive);
      print("self", self, kTopSelf);

      std::vector<std::pair<std::uint32_t, std::uintptr_t>> leaves;
      for (const auto& [function, count] : self) {
        leaves.emplace_back(count, function);
      }
      std::sort(leaves.begin(), leaves.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
      for (std::size_t leaf = 0; leaf < leaves.size() && leaf < kTopCallerLeaves; ++leaf) {
        std::vector<std::pair<std::uint32_t, const std::string*>> chains;
        for (const auto& [chain, count] : callers[leaves[leaf].second]) {
          chains.emplace_back(count, &chain);
        }
        std::sort(chains.begin(), chains.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
        for (std::size_t index = 0; index < chains.size() && index < kChainsPerLeaf; ++index) {
          gpg::Logf("[FRAMESAMPLE]   path %4u  %s%s", chains[index].first, names[leaves[leaf].second]->c_str(), chains[index].second->c_str());
        }
      }
    }

    DWORD WINAPI SamplerThread(LPVOID)
    {
      SamplerState& state = State();
      (void)::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
      // A one-millisecond sleep needs the one-millisecond timer resolution.
      using TimeBeginPeriod = UINT(WINAPI*)(UINT);
      if (HMODULE const winmm = ::LoadLibraryA("winmm.dll"); winmm != nullptr) {
        if (auto const begin = reinterpret_cast<TimeBeginPeriod>(::GetProcAddress(winmm, "timeBeginPeriod")); begin != nullptr) {
          (void)begin(1U);
        }
      }
      while (true) {
        if (::WaitForSingleObject(state.wake, 1U) == WAIT_OBJECT_0) {
          std::deque<Window> pending;
          {
            const std::lock_guard<std::mutex> lock(state.windowsLock);
            pending.swap(state.windows);
          }
          for (const Window& window : pending) {
            Report(state, window);
          }
        }
        TakeSample(state);
      }
    }
  } // namespace

  void FrameSamplerMark()
  {
    static const double threshold = [] {
      char value[16]{};
      std::size_t length = 0U;
      if (::getenv_s(&length, value, sizeof(value), "FAF_FRAME_SAMPLER") != 0 || length == 0U) {
        return 0.0;
      }
      return std::atof(value);
    }();
    if (threshold <= 0.0) {
      return;
    }

    SamplerState& state = State();
    const LONGLONG now = Now();
    if (state.target == nullptr) {
      LARGE_INTEGER frequency{};
      ::QueryPerformanceFrequency(&frequency);
      state.frequency = frequency.QuadPart;
      state.thresholdMs = threshold;
      if (::DuplicateHandle(::GetCurrentProcess(), ::GetCurrentThread(), ::GetCurrentProcess(), &state.target,
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, 0U) == FALSE) {
        state.target = nullptr;
        return;
      }
      state.wake = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
      (void)DiagSymbolsReady();
      HANDLE const thread = ::CreateThread(nullptr, 0U, &SamplerThread, nullptr, 0U, nullptr);
      if (thread != nullptr) {
        (void)::CloseHandle(thread);
      }
      state.lastMark = now;
      gpg::Logf("[FRAMESAMPLE] sampling this thread, reporting frames of %.0f ms and more", threshold);
      return;
    }

    const double milliseconds = 1000.0 * static_cast<double>(now - state.lastMark) / static_cast<double>(state.frequency);
    if (milliseconds >= state.thresholdMs) {
      {
        const std::lock_guard<std::mutex> lock(state.windowsLock);
        state.windows.push_back(Window{state.lastMark, now, milliseconds});
      }
      (void)::SetEvent(state.wake);
    }
    state.lastMark = now;
  }
} // namespace gpg::diag
