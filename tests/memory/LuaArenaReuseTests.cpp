// Standalone x64 allocator tests. Each process limits usable arena capacity to 64 spans.
// Run bash tools/test-lua-arena-reuse.sh; optionally set SANITIZER=undefined or SANITIZER=thread.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <limits>
#include <thread>
#include <vector>

#include "../../src/lua/LuaArena.cpp"

namespace
{
  bool failHostNew = false;

  void Require(bool condition)
  {
    if (!condition) {
      std::abort();
    }
  }

  void FullCapacity()
  {
    std::vector<void*> blocks(gReserveBytes / 16);
    void* const entireArena = lua::ArenaAllocate(gReserveBytes);
    Require(entireArena != nullptr);
    lua::ArenaFree(entireArena);

    failHostNew = true;
    for (std::size_t index = 0; index < blocks.size(); ++index) {
      blocks[index] = lua::ArenaAllocate(16);
      Require(blocks[index] != nullptr);
      std::memset(blocks[index], static_cast<int>(index % 251), 16);
    }
    Require(lua::ArenaAllocate(16) == nullptr);
    Require(lua::ArenaAllocate(32768) == nullptr);
    for (std::size_t index = 0; index < blocks.size(); ++index) {
      Require(static_cast<unsigned char*>(blocks[index])[0] == index % 251);
      lua::ArenaFree(blocks[index]);
    }
    failHostNew = false;
    std::puts("PASS: all 64 large-free spans reused as 16-byte blocks without host allocation");
  }

  void MixedSizes()
  {
    void* const entireArena = lua::ArenaAllocate(gReserveBytes);
    Require(entireArena != nullptr);
    lua::ArenaFree(entireArena);

    void* const small = lua::ArenaAllocate(16384);
    Require(reinterpret_cast<std::uintptr_t>(small) == gBase);
    std::memset(small, 53, 16384);
    void* const large = lua::ArenaAllocate(2 * kSpanBytes);
    Require(reinterpret_cast<std::uintptr_t>(large) == gBase + kSpanBytes);
    std::memset(large, 97, 2 * kSpanBytes);
    lua::ArenaFree(large);

    for (unsigned index = 0; index < 3; ++index) {
      void* const block = lua::ArenaAllocate(16384);
      Require(block != nullptr);
      std::memset(block, 42, 16384);
    }
    Require(static_cast<char*>(small)[0] == 53);
    Require(static_cast<char*>(small)[16383] == 53);
    Require(lua::ArenaAllocate(16384) != nullptr);
    std::puts("PASS: splitting a free run preserves its remainder and live small payload");
  }

  void ZeroSpanRecord()
  {
    // The current allocator can round SIZE_MAX to zero spans. Keep this existing
    // failure case from turning into an overlapping small allocation during reuse.
    void* const zero = lua::ArenaAllocate(std::numeric_limits<std::size_t>::max());
    Require(zero != nullptr);
    lua::ArenaFree(zero);
    void* const live = lua::ArenaAllocate(gReserveBytes);
    Require(live != nullptr);
    std::memset(live, 61, 16384);
    Require(lua::ArenaAllocate(16384) == nullptr);
    Require(static_cast<char*>(live)[0] == 61);
    Require(static_cast<char*>(live)[16383] == 61);
    lua::ArenaFree(live);
    void* const recovered = lua::ArenaAllocate(16384);
    Require(recovered == live);
    std::puts("PASS: zero-span records neither underflow nor overlap live allocations");
  }

  void ConcurrentReuse()
  {
    std::vector<void*> large;
    for (unsigned index = 0; index < 64; ++index) {
      void* const block = lua::ArenaAllocate(32768);
      Require(block != nullptr);
      large.push_back(block);
    }
    std::atomic<unsigned> finished = 0;
    std::vector<std::thread> threads;
    for (unsigned worker = 0; worker < 8; ++worker) {
      threads.emplace_back([&, worker] {
        for (unsigned index = worker; index < 64; index += 8) {
          lua::ArenaFree(large[index]);
        }
        ++finished;
      });
    }
    std::vector<void*> small;
    while (finished < 8) {
      if (void* const block = lua::ArenaAllocate(16384)) {
        std::memset(block, 73, 16384);
        small.push_back(block);
      }
    }
    for (auto& thread : threads) {
      thread.join();
    }
    while (void* const block = lua::ArenaAllocate(16384)) {
      std::memset(block, 73, 16384);
      small.push_back(block);
    }
    Require(small.size() == 256);
    for (std::size_t index = 0; index < small.size(); ++index) {
      Require(static_cast<char*>(small[index])[0] == 73);
      Require(static_cast<char*>(small[index])[16383] == 73);
      for (std::size_t other = 0; other < index; ++other) {
        Require(small[index] != small[other]);
      }
    }
    std::puts("PASS: concurrent large frees and small refills recover exactly 256 blocks");
  }
}

void* operator new(std::size_t bytes)
{
  if (failHostNew) {
    throw std::bad_alloc();
  }
  if (void* const block = std::malloc(bytes != 0 ? bytes : 1)) {
    return block;
  }
  throw std::bad_alloc();
}

void operator delete(void* block) noexcept { std::free(block); }
void operator delete(void* block, std::size_t) noexcept { std::free(block); }

int main(int argc, char** argv)
{
  lua::ArenaReserve();
  gReserveBytes = 64 * kSpanBytes;
  const char* const mode = argc > 1 ? argv[1] : "full";
  if (std::strcmp(mode, "full") == 0) {
    FullCapacity();
  } else if (std::strcmp(mode, "mixed") == 0) {
    MixedSizes();
  } else if (std::strcmp(mode, "zero-run") == 0) {
    ZeroSpanRecord();
  } else if (std::strcmp(mode, "threads") == 0) {
    ConcurrentReuse();
  } else {
    return 2;
  }
}
