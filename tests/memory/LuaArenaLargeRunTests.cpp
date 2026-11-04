// Standalone x64 allocator tests; no game data or renderer required.
// Compile from the repository root:
// g++ -std=c++20 -O2 -pthread -Isrc tests/memory/LuaArenaLargeRunTests.cpp -o /tmp/lua-arena-tests
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <string_view>
#include <thread>
#include <vector>

#include "../../src/lua/LuaArena.cpp"

namespace
{
  bool failNew = false;

  void Check(const bool condition)
  {
    if (!condition) {
      std::fputs("Lua arena regression failed\n", stderr);
      std::abort();
    }
  }

  std::vector<void*> FillArena()
  {
    std::vector<void*> blocks;
    while (void* const block = lua::ArenaAllocate(16385)) {
      blocks.push_back(block);
    }
    Check(blocks.size() == gReserveBytes / kSpanBytes);
    return blocks;
  }

  void FullCapacity()
  {
    const auto blocks = FillArena();
    for (std::size_t index = 0; index < blocks.size(); index += 2) {
      lua::ArenaFree(blocks[index]);
    }
    for (std::size_t index = 1; index < blocks.size(); index += 2) {
      lua::ArenaFree(blocks[index]);
    }
    void* const all = lua::ArenaAllocate(gReserveBytes);
    Check(all != nullptr && reinterpret_cast<std::uintptr_t>(all) == gBase);
    Check(lua::ArenaAllocate(16385) == nullptr);
    lua::ArenaFree(all);
    Check(lua::ArenaAllocate(gReserveBytes) != nullptr);
    std::puts("Full arena joins adjacent runs and reuses the entire range");
  }

  void FailedRequestOrder()
  {
    const auto blocks = FillArena();
    for (std::size_t index = blocks.size(); index-- > 0;) {
      if (index % 2 != 0) {
        lua::ArenaFree(blocks[index]);
      }
    }
    const auto start = std::chrono::steady_clock::now();
    for (int attempt = 0; attempt < 1000; ++attempt) {
      Check(lua::ArenaAllocate(kSpanBytes + 1) == nullptr);
    }
    const auto milliseconds =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    Check(lua::ArenaAllocate(16385) == blocks.back());
    std::printf("1000 failed requests preserve next allocation; %.3f ms\n", milliseconds);
  }

  void HostHeapFailure()
  {
    // No harness allocations after failNew. Reserving virtual space does not populate it.
    static void* blocks[kSpanCount];
    lua::ArenaReserve();
    failNew = true;
    std::size_t count = 0;
    while (count < kSpanCount && (blocks[count] = lua::ArenaAllocate(16385)) != nullptr) {
      ++count;
    }
    for (std::size_t index = 0; index < count; ++index) {
      lua::ArenaFree(blocks[index]);
    }
    void* const all = lua::ArenaAllocate(count * kSpanBytes);
    Check(all != nullptr);
    lua::ArenaFree(all);
    failNew = false;
    std::puts("Large allocation, free and adjacent-run reuse work with host new disabled");
  }

  void Oversize()
  {
    void* const block = lua::ArenaAllocate(50000);
    Check(block != nullptr);
    std::memset(block, 42, 50000);
    Check(lua::ArenaAllocate(std::numeric_limits<std::size_t>::max()) == nullptr);
    Check(lua::ArenaReallocate(block, 50000, std::numeric_limits<std::size_t>::max()) == nullptr);
    Check(static_cast<unsigned char*>(block)[49999] == 42);
    lua::ArenaFree(block);
    std::puts("Oversize requests fail without losing the old allocation");
  }

  void CrossThreadFree()
  {
    std::vector<void*> blocks(4096);
    for (void*& block : blocks) {
      block = lua::ArenaAllocate(65537);
      Check(block != nullptr);
      std::memset(block, 0x5a, 65537);
    }
    std::vector<std::thread> workers;
    for (std::size_t worker = 0; worker < 8; ++worker) {
      workers.emplace_back([&, worker] {
        for (std::size_t index = worker; index < blocks.size(); index += 8) {
          Check(static_cast<unsigned char*>(blocks[index])[65536] == 0x5a);
          lua::ArenaFree(blocks[index]);
          for (int iteration = 0; iteration < 100; ++iteration) {
            void* const block = lua::ArenaAllocate(20001);
            Check(block != nullptr);
            std::memset(block, 1, 20001);
            lua::ArenaFree(block);
          }
        }
      });
    }
    for (auto& worker : workers) {
      worker.join();
    }
    std::puts("Cross-thread free and 409600 allocate/free pairs pass");
  }
} // namespace

void* operator new(const std::size_t bytes)
{
  if (!failNew) {
    if (void* const allocation = std::malloc(bytes != 0 ? bytes : 1)) {
      return allocation;
    }
  }
  throw std::bad_alloc{};
}

void operator delete(void* const block) noexcept { std::free(block); }
void operator delete(void* const block, std::size_t) noexcept { std::free(block); }

int main(const int argc, char** const argv)
{
  std::set_terminate([] { std::fputs("Unexpected termination\n", stderr); std::_Exit(42); });
  if (argc != 2) {
    std::fputs("Expected: capacity | failed-order | host-oom | oversized | threads\n", stderr);
    return 2;
  }
  const std::string_view mode(argv[1]);
  if (mode == "capacity") FullCapacity();
  else if (mode == "failed-order") FailedRequestOrder();
  else if (mode == "host-oom") HostHeapFailure();
  else if (mode == "oversized") Oversize();
  else if (mode == "threads") CrossThreadFree();
  else return 2;
}
