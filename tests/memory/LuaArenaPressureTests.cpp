// Standalone x64 allocator test. From the repository root:
// g++ -std=c++20 -O2 -pthread -Isrc tests/memory/LuaArenaPressureTests.cpp -o lua-arena-pressure
// Compile this file alone: it includes the implementation to check internal invariants.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

#if INTPTR_MAX == INT32_MAX
#error This test requires the x64 Lua arena implementation.
#endif

#include "../../src/lua/LuaArena.cpp"

namespace
{
  constexpr std::size_t kTestSpans = 257;
  constexpr std::size_t kOperations = 100000;

  struct LiveAllocation
  {
    void* pointer;
    std::size_t spans;
    unsigned char tag;
  };

  void Require(const bool condition, const char* const message)
  {
    if (!condition) {
      std::fprintf(stderr, "%s\n", message);
      std::abort();
    }
  }

  std::size_t FirstSpan(const void* const pointer)
  {
    return (reinterpret_cast<std::uintptr_t>(pointer) - gBase) / kSpanBytes;
  }

  void CheckFreeRuns(const bool (&used)[kTestSpans])
  {
    bool free[kTestSpans]{};
    Require(gFreeRunCount <= kTestSpans, "Free-run count exceeds capacity");
    for (std::size_t index = 0; index < gFreeRunCount; ++index) {
      const LargeRun run = gFreeRuns[index];
      Require(run.spans > 0 && run.firstSpan < kTestSpans && run.spans <= kTestSpans - run.firstSpan,
              "Free run is empty or out of bounds");
      for (std::size_t offset = 0; offset < run.spans; ++offset) {
        const std::size_t span = run.firstSpan + offset;
        Require(!used[span] && !free[span], "Free runs overlap each other or a live allocation");
        free[span] = true;
      }
    }
    for (std::size_t span = 0; span < kTestSpans; ++span) {
      Require(free[span] != used[span], "Free-list coverage differs from the occupancy map");
    }
  }
}

int main()
{
  lua::ArenaReserve();
  Require(gReserveBytes >= kTestSpans * kSpanBytes, "Reserved arena is too small for this test");
  // Restrict usable capacity without changing the OS reservation. This forces frequent
  // pressure recovery cheaply; it does not test the OS reservation fallback branches.
  // Run in a fresh standalone process. These internal-state checks and this capacity
  // override must not run alongside other threads or other users of the arena.
  gReserveBytes = kTestSpans * kSpanBytes;

  std::vector<LiveAllocation> live;
  bool used[kTestSpans]{};
  std::mt19937 random(39148);
  for (std::size_t span = 0; span < kTestSpans; ++span) {
    void* const pointer = lua::ArenaAllocate(kSpanBytes);
    Require(pointer != nullptr && FirstSpan(pointer) == span, "Initial fill failed");
    std::memset(pointer, 17, kSpanBytes);
    live.push_back({pointer, 1, 17});
    used[span] = true;
  }

  for (std::size_t step = 0; step < kOperations; ++step) {
    if (!live.empty() && random() % 2 != 0) {
      const std::size_t index = random() % live.size();
      const LiveAllocation allocation = live[index];
      const std::size_t first = FirstSpan(allocation.pointer);
      for (std::size_t offset = 0; offset < allocation.spans; ++offset) {
        Require(used[first + offset], "Live allocation missing from occupancy map");
        Require(static_cast<unsigned char*>(allocation.pointer)[offset * kSpanBytes] == allocation.tag,
                "Live payload was overwritten");
        used[first + offset] = false;
      }
      lua::ArenaFree(allocation.pointer);
      live[index] = live.back();
      live.pop_back();
    } else {
      const std::size_t spans = 1 + random() % 70;
      std::size_t consecutive = 0;
      bool possible = false;
      for (const bool occupied : used) {
        consecutive = occupied ? 0 : consecutive + 1;
        if (consecutive >= spans) {
          possible = true;
        }
      }
      void* const pointer = lua::ArenaAllocate(spans * kSpanBytes);
      Require((pointer != nullptr) == possible, "Allocation disagrees with contiguous free-space oracle");
      if (pointer != nullptr) {
        const std::size_t first = FirstSpan(pointer);
        Require(first < kTestSpans && spans <= kTestSpans - first, "Allocation exceeds test capacity");
        const auto tag = static_cast<unsigned char>(1 + random() % 254);
        for (std::size_t offset = 0; offset < spans; ++offset) {
          Require(!used[first + offset], "Allocation overlaps a live block");
          used[first + offset] = true;
          static_cast<unsigned char*>(pointer)[offset * kSpanBytes] = tag;
        }
        live.push_back({pointer, spans, tag});
      }
    }
    CheckFreeRuns(used);
  }

  // Validate allocations still live at the end as well as those freed during the run.
  for (const LiveAllocation allocation : live) {
    for (std::size_t offset = 0; offset < allocation.spans; ++offset) {
      Require(static_cast<unsigned char*>(allocation.pointer)[offset * kSpanBytes] == allocation.tag,
              "Final live payload was overwritten");
    }
    lua::ArenaFree(allocation.pointer);
  }
  void* const whole = lua::ArenaAllocate(kTestSpans * kSpanBytes);
  Require(whole != nullptr && FirstSpan(whole) == 0, "Whole-arena reuse failed");
  lua::ArenaFree(whole);
  std::puts("PASS: 100000 randomized operations; free-run coverage, overlap, payload and final reuse");
}
