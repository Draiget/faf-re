#include <gtest/gtest.h>

#include "moho/sim/COGrid.h"

#if defined(FAF_OCCUPATION_DELETE_TRACE)
namespace
{
  struct AllocationTrace;
  thread_local AllocationTrace* activeTrace = nullptr;
  // Only the outermost new/delete entry point counts: the array forms forward
  // to the scalar ones, and that inner call must not show up as a second one.
  thread_local int traceDepth = 0;

  struct AllocationTrace
  {
    struct Entry
    {
      void* pointer = nullptr;
      bool arrayNew = false;
      int scalarDeletes = 0;
      int arrayDeletes = 0;
    };
    Entry entries[256]{};
    int size = 0;
    bool overflow = false;
    AllocationTrace* previous = activeTrace;

    AllocationTrace() { activeTrace = this; }
    ~AllocationTrace() { activeTrace = previous; }

    void RecordNew(void* pointer, bool array)
    {
      if (size == 256) {
        overflow = true;
        return;
      }
      entries[size].pointer = pointer;
      entries[size].arrayNew = array;
      ++size;
    }

    void RecordDelete(void* pointer, bool array)
    {
      // The newest allocation at this address is the one being freed.
      for (int i = size - 1; i >= 0; --i) {
        if (entries[i].pointer == pointer) {
          ++(array ? entries[i].arrayDeletes : entries[i].scalarDeletes);
          return;
        }
      }
    }

    const Entry* Find(const void* pointer) const
    {
      for (int i = size - 1; i >= 0; --i) {
        if (entries[i].pointer == pointer) return &entries[i];
      }
      return nullptr;
    }
  };
}

// GNU/LLVM linker wrapping observes which overload a call site selects without
// replacing the engine's allocator. Every call goes on to the real function.
extern "C" void* __real__Znwm(std::size_t);
extern "C" void* __real__Znam(std::size_t);
extern "C" void __real__ZdlPv(void*) noexcept;
extern "C" void __real__ZdaPv(void*) noexcept;
extern "C" void* __wrap__Znwm(std::size_t bytes)
{
  ++traceDepth;
  void* const pointer = __real__Znwm(bytes);
  --traceDepth;
  if (activeTrace && traceDepth == 0) activeTrace->RecordNew(pointer, false);
  return pointer;
}
extern "C" void* __wrap__Znam(std::size_t bytes)
{
  ++traceDepth;
  void* const pointer = __real__Znam(bytes);
  --traceDepth;
  if (activeTrace && traceDepth == 0) activeTrace->RecordNew(pointer, true);
  return pointer;
}
extern "C" void __wrap__ZdlPv(void* pointer) noexcept
{
  if (activeTrace && traceDepth == 0) activeTrace->RecordDelete(pointer, false);
  ++traceDepth;
  __real__ZdlPv(pointer);
  --traceDepth;
}
extern "C" void __wrap__ZdaPv(void* pointer) noexcept
{
  if (activeTrace && traceDepth == 0) activeTrace->RecordDelete(pointer, true);
  ++traceDepth;
  __real__ZdaPv(pointer);
  --traceDepth;
}
#endif

namespace
{
  // These cases execute the actual engine manager and its ordinary allocator.
  void CheckBucketsChunksAndRepeatedGrowth(const int requested)
  {
    moho::EntityOccupationManager manager(128, 256);
    EXPECT_EQ(manager.mWidth, 32);
    EXPECT_EQ(manager.mHeight, 64);
    EXPECT_EQ(manager.mLastIndex, 2047);
    EXPECT_EQ(manager.mGridWidthShift, 5);
    EXPECT_EQ(manager.mFreeNodeCount, 0);
    EXPECT_EQ(manager.mFreeNodeHead, nullptr);
    EXPECT_TRUE(manager.mAllBlocks.empty());
    for (int i = 0; i <= manager.mLastIndex; ++i) {
      ASSERT_EQ(manager.mUnitBuckets[i], nullptr);
      ASSERT_EQ(manager.mPropBuckets[i], nullptr);
      ASSERT_EQ(manager.mEntityBuckets[i], nullptr);
    }
    const int expected = ((requested + 8191) / 8192) * 8192;
    manager.EnsureSize(requested);
    EXPECT_EQ(manager.mFreeNodeCount, expected);
    EXPECT_EQ(manager.mAllBlocks.size(), expected / 8192);
    int count = 0;
    for (auto* node = manager.mFreeNodeHead; node; node = node->next) {
      ASSERT_LT(count, expected) << "Free-list cycle";
      ++count;
    }
    EXPECT_EQ(count, expected);
    auto* const first = manager.mFreeNodeHead;
    manager.EnsureSize(requested);
    EXPECT_EQ(manager.mFreeNodeHead, first);
    EXPECT_EQ(manager.mAllBlocks.size(), expected / 8192);
  }

  // A plain loop rather than INSTANTIATE_TEST_SUITE_P: gtest 1.15's macro
  // declares a tuple it only reads in decltype, which clang reports as
  // -Wunused-variable on Linux, where gtest's headers are not system headers.
  TEST(OccupationManagerGrowth, BucketsChunksAndRepeatedGrowth)
  {
    for (const int requested : {0, 1, 16385, 155649}) {
      SCOPED_TRACE(::testing::Message() << "request=" << requested);
      CheckBucketsChunksAndRepeatedGrowth(requested);
    }
  }

  TEST(OccupationManagerLifecycle, RepeatedConstructionAndDestruction)
  {
    for (int i = 0; i < 32; ++i) {
      moho::EntityOccupationManager manager(128, 128);
      manager.EnsureSize(8193);
      ASSERT_EQ(manager.mAllBlocks.size(), 2);
    }
  }

  TEST(OccupationManagerLifecycle, IncreasingRequestsPreserveTheExistingFreeList)
  {
    moho::EntityOccupationManager manager(128, 128);
    for (const int requested : {1, 8193, 16385, 155649}) {
      auto* const oldHead = manager.mFreeNodeHead;
      auto* const oldNext = oldHead ? oldHead->next : nullptr;
      const int expected = ((requested + 8191) / 8192) * 8192;
      manager.EnsureSize(requested);
      EXPECT_EQ(manager.mFreeNodeCount, expected);
      EXPECT_EQ(manager.mAllBlocks.size(), expected / 8192);
      int count = 0;
      int oldHeadCount = 0;
      for (auto* node = manager.mFreeNodeHead; node; node = node->next) {
        ASSERT_LT(count, expected);
        ++count;
        oldHeadCount += node == oldHead;
      }
      EXPECT_EQ(count, expected);
      if (oldHead) {
        EXPECT_EQ(oldHeadCount, 1);
        EXPECT_EQ(oldHead->next, oldNext);
      }
    }
  }

#if defined(FAF_OCCUPATION_DELETE_TRACE)
  // Retail allocates the three bucket arrays (0x004FCD60/82/A4) and every node
  // block (0x004FCEA5) with operator new[] (0x00A82130) and frees all four in
  // the destructor with operator delete[] (0x00A82542, 0x004FCE15..0x004FCE4C).
  TEST(OccupationManagerDeallocation, EveryArrayAllocationUsesArrayDelete)
  {
    for (const int requested : {0, 1, 16385, 155649}) {
      AllocationTrace trace;
      void* watched[32]{};
      int watchedCount = 0;
      {
        moho::EntityOccupationManager manager(128, 256);
        manager.EnsureSize(requested);
        ASSERT_LE(manager.mAllBlocks.size() + 3, 32u);
        watched[watchedCount++] = manager.mUnitBuckets;
        watched[watchedCount++] = manager.mPropBuckets;
        watched[watchedCount++] = manager.mEntityBuckets;
        for (auto* block : manager.mAllBlocks) watched[watchedCount++] = block;
      }
      // Stop observing before assertion reporting can allocate or reuse memory.
      activeTrace = trace.previous;
      ASSERT_FALSE(trace.overflow) << "request=" << requested;
      for (int i = 0; i < watchedCount; ++i) {
        const auto* const entry = trace.Find(watched[i]);
        ASSERT_NE(entry, nullptr) << "request=" << requested << ", allocation=" << i;
        EXPECT_TRUE(entry->arrayNew) << "request=" << requested << ", allocation=" << i;
        EXPECT_EQ(entry->arrayDeletes, 1) << "request=" << requested << ", allocation=" << i;
        EXPECT_EQ(entry->scalarDeletes, 0) << "request=" << requested << ", allocation=" << i;
      }
    }
  }
#endif
}
