// Host x64 regression tests; each CTest case gets its own 64-span arena.
#include <gtest/gtest.h>
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

  class HostNewFailure
  {
  public:
    HostNewFailure() { failHostNew = true; }
    ~HostNewFailure() { failHostNew = false; }
    HostNewFailure(const HostNewFailure&) = delete;
    HostNewFailure& operator=(const HostNewFailure&) = delete;
  };

  class LuaArenaReuse : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      ASSERT_EQ(::testing::UnitTest::GetInstance()->test_to_run_count(), 1)
        << "Run through CTest: each Lua arena case requires a fresh process.";
      static bool ran = false;
      ASSERT_FALSE(ran) << "Repeated cases also require a fresh process.";
      ran = true;
      lua::ArenaReserve();
      ASSERT_GE(gReserveBytes, 64 * kSpanBytes);
      gReserveBytes = 64 * kSpanBytes;
    }
  };

  TEST_F(LuaArenaReuse, FullCapacity)
  {
    std::vector<void*> blocks(gReserveBytes / 16);
    void* const entireArena = lua::ArenaAllocate(gReserveBytes);
    ASSERT_TRUE(entireArena != nullptr);
    lua::ArenaFree(entireArena);

    // Do not call GoogleTest while host allocations are disabled.
    bool allocatedAll = true;
    bool payloadIntact = true;
    bool exhaustedSmall = false;
    bool exhaustedLarge = false;
    bool threw = false;
    try {
      const HostNewFailure failure;
      for (std::size_t index = 0; index < blocks.size(); ++index) {
        blocks[index] = lua::ArenaAllocate(16);
        if (!blocks[index]) { allocatedAll = false; break; }
        std::memset(blocks[index], static_cast<int>(index % 251), 16);
      }
      exhaustedSmall = lua::ArenaAllocate(16) == nullptr;
      exhaustedLarge = lua::ArenaAllocate(32768) == nullptr;
      for (std::size_t index = 0; index < blocks.size(); ++index) {
        if (blocks[index]) {
          payloadIntact &= static_cast<unsigned char*>(blocks[index])[0] == index % 251;
          lua::ArenaFree(blocks[index]);
        }
      }
    } catch (...) { threw = true; }
    ASSERT_FALSE(threw);
    EXPECT_TRUE(allocatedAll);
    EXPECT_TRUE(exhaustedSmall);
    EXPECT_TRUE(exhaustedLarge);
    EXPECT_TRUE(payloadIntact);
  }

  TEST_F(LuaArenaReuse, MixedSizes)
  {
    void* const entireArena = lua::ArenaAllocate(gReserveBytes);
    ASSERT_TRUE(entireArena != nullptr);
    lua::ArenaFree(entireArena);

    void* const small = lua::ArenaAllocate(16384);
    ASSERT_TRUE(reinterpret_cast<std::uintptr_t>(small) == gBase);
    std::memset(small, 53, 16384);
    void* const large = lua::ArenaAllocate(2 * kSpanBytes);
    ASSERT_TRUE(reinterpret_cast<std::uintptr_t>(large) == gBase + kSpanBytes);
    std::memset(large, 97, 2 * kSpanBytes);
    lua::ArenaFree(large);

    for (unsigned index = 0; index < 3; ++index) {
      void* const block = lua::ArenaAllocate(16384);
      ASSERT_TRUE(block != nullptr);
      std::memset(block, 42, 16384);
    }
    ASSERT_TRUE(static_cast<char*>(small)[0] == 53);
    ASSERT_TRUE(static_cast<char*>(small)[16383] == 53);
    ASSERT_TRUE(lua::ArenaAllocate(16384) != nullptr);
  }

  TEST_F(LuaArenaReuse, OversizedRejected)
  {
    // SIZE_MAX used to round to a zero-span block that overlapped the next allocation.
    EXPECT_EQ(lua::ArenaAllocate(std::numeric_limits<std::size_t>::max()), nullptr);
    EXPECT_EQ(lua::ArenaAllocate(gReserveBytes + 1u), nullptr);
    void* const live = lua::ArenaAllocate(gReserveBytes);
    ASSERT_NE(live, nullptr);
    std::memset(live, 61, 16384);
    EXPECT_EQ(lua::ArenaAllocate(16384), nullptr);
    EXPECT_EQ(static_cast<char*>(live)[16383], 61);
    lua::ArenaFree(live);
    EXPECT_EQ(lua::ArenaAllocate(16384), live);
  }

  TEST_F(LuaArenaReuse, ConcurrentReuse)
  {
    std::vector<void*> large;
    for (unsigned index = 0; index < 64; ++index) {
      void* const block = lua::ArenaAllocate(32768);
      ASSERT_TRUE(block != nullptr);
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
    ASSERT_TRUE(small.size() == 256);
    for (std::size_t index = 0; index < small.size(); ++index) {
      ASSERT_TRUE(static_cast<char*>(small[index])[0] == 73);
      ASSERT_TRUE(static_cast<char*>(small[index])[16383] == 73);
      for (std::size_t other = 0; other < index; ++other) {
        ASSERT_TRUE(small[index] != small[other]);
      }
    }
  }
}

// clang's ThreadSanitizer runtime defines operator new itself, so the replacement (and with it the
// FullCapacity host-new check) is left out there; GCC's TSan and the other builds keep it.
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define FAF_LUA_ARENA_RUNTIME_OWNS_NEW 1
#endif
#endif

#ifndef FAF_LUA_ARENA_RUNTIME_OWNS_NEW
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


// Keep the replacement allocation family paired, including GoogleTest's
// nothrow temporary-buffer path (for example std::stable_sort).
void* operator new[](std::size_t bytes) { return ::operator new(bytes); }
void* operator new(std::size_t bytes, const std::nothrow_t&) noexcept
{
  try { return ::operator new(bytes); } catch (...) { return nullptr; }
}
void* operator new[](std::size_t bytes, const std::nothrow_t&) noexcept
{
  return ::operator new(bytes, std::nothrow);
}
void operator delete[](void* block) noexcept { std::free(block); }
void operator delete[](void* block, std::size_t) noexcept { std::free(block); }
void operator delete(void* block, const std::nothrow_t&) noexcept { std::free(block); }
void operator delete[](void* block, const std::nothrow_t&) noexcept { std::free(block); }
#endif
