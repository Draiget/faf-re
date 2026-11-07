// Host x64 regression tests; CTest runs each case in a fresh process.
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <thread>
#include <vector>

#include "../../src/lua/LuaArena.cpp"

namespace
{
  bool failNew = false;

  class HostNewFailure
  {
  public:
    HostNewFailure() { failNew = true; }
    ~HostNewFailure() { failNew = false; }
    HostNewFailure(const HostNewFailure&) = delete;
    HostNewFailure& operator=(const HostNewFailure&) = delete;
  };

  class LuaArenaLargeRun : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      ASSERT_EQ(::testing::UnitTest::GetInstance()->test_to_run_count(), 1)
        << "Run through CTest: each Lua arena case requires a fresh process.";
      static bool ran = false;
      ASSERT_FALSE(ran) << "Repeated cases also require a fresh process.";
      ran = true;
    }
  };

  std::vector<void*> FillArena()
  {
    std::vector<void*> blocks;
    while (void* const block = lua::ArenaAllocate(16385)) {
      blocks.push_back(block);
    }
    EXPECT_EQ(blocks.size(), gReserveBytes / kSpanBytes);
    return blocks;
  }

  TEST_F(LuaArenaLargeRun, FullCapacity)
  {
    const auto blocks = FillArena();
    ASSERT_EQ(blocks.size(), gReserveBytes / kSpanBytes);
    for (std::size_t index = 0; index < blocks.size(); index += 2) {
      lua::ArenaFree(blocks[index]);
    }
    for (std::size_t index = 1; index < blocks.size(); index += 2) {
      lua::ArenaFree(blocks[index]);
    }
    void* const all = lua::ArenaAllocate(gReserveBytes);
    ASSERT_TRUE(all != nullptr && reinterpret_cast<std::uintptr_t>(all) == gBase);
    ASSERT_TRUE(lua::ArenaAllocate(16385) == nullptr);
    lua::ArenaFree(all);
    ASSERT_TRUE(lua::ArenaAllocate(gReserveBytes) != nullptr);
  }

  TEST_F(LuaArenaLargeRun, FailedRequestOrder)
  {
    const auto blocks = FillArena();
    ASSERT_EQ(blocks.size(), gReserveBytes / kSpanBytes);
    for (std::size_t index = blocks.size(); index-- > 0;) {
      if (index % 2 != 0) {
        lua::ArenaFree(blocks[index]);
      }
    }
    const auto start = std::chrono::steady_clock::now();
    for (int attempt = 0; attempt < 1000; ++attempt) {
      ASSERT_TRUE(lua::ArenaAllocate(kSpanBytes + 1) == nullptr);
    }
    const auto milliseconds =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    ASSERT_TRUE(lua::ArenaAllocate(16385) == blocks.back());
    std::printf("1000 failed requests preserve next allocation; %.3f ms\n", milliseconds);
  }

  TEST_F(LuaArenaLargeRun, HostHeapFailure)
  {
    // No harness allocations after failNew. Reserving virtual space does not populate it.
    static void* blocks[kSpanCount];
    lua::ArenaReserve();
    std::size_t count = 0;
    void* all = nullptr;
    {
      const HostNewFailure failure;
      while (count < kSpanCount && (blocks[count] = lua::ArenaAllocate(16385)) != nullptr) {
        ++count;
      }
      for (std::size_t index = 0; index < count; ++index) {
        lua::ArenaFree(blocks[index]);
      }
      all = lua::ArenaAllocate(count * kSpanBytes);
      lua::ArenaFree(all);
    }
    ASSERT_EQ(count, gReserveBytes / kSpanBytes);
    ASSERT_NE(all, nullptr);
  }

  TEST_F(LuaArenaLargeRun, Oversize)
  {
    void* const block = lua::ArenaAllocate(50000);
    ASSERT_TRUE(block != nullptr);
    std::memset(block, 42, 50000);
    ASSERT_TRUE(lua::ArenaAllocate(std::numeric_limits<std::size_t>::max()) == nullptr);
    ASSERT_TRUE(lua::ArenaReallocate(block, 50000, std::numeric_limits<std::size_t>::max()) == nullptr);
    ASSERT_TRUE(static_cast<unsigned char*>(block)[49999] == 42);
    lua::ArenaFree(block);
  }

  TEST_F(LuaArenaLargeRun, CrossThreadFree)
  {
    std::vector<void*> blocks(4096);
    for (void*& block : blocks) {
      block = lua::ArenaAllocate(65537);
      ASSERT_TRUE(block != nullptr);
      std::memset(block, 0x5a, 65537);
    }
    std::atomic<bool> payloadIntact{true};
    std::atomic<bool> allocationsSucceeded{true};
    std::vector<std::thread> workers;
    for (std::size_t worker = 0; worker < 8; ++worker) {
      workers.emplace_back([&, worker] {
        for (std::size_t index = worker; index < blocks.size(); index += 8) {
          if (static_cast<unsigned char*>(blocks[index])[65536] != 0x5a) {
            payloadIntact.store(false, std::memory_order_relaxed);
          }
          lua::ArenaFree(blocks[index]);
          for (int iteration = 0; iteration < 100; ++iteration) {
            void* const block = lua::ArenaAllocate(20001);
            if (!block) {
              allocationsSucceeded.store(false, std::memory_order_relaxed);
              return;
            }
            std::memset(block, 1, 20001);
            lua::ArenaFree(block);
          }
        }
      });
    }
    for (auto& worker : workers) {
      worker.join();
    }
    EXPECT_TRUE(payloadIntact.load());
    EXPECT_TRUE(allocationsSucceeded.load());
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
