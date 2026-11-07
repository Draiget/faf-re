#include <gtest/gtest.h>

#include "moho/sim/COGrid.h"

#if defined(FAF_OCCUPATION_DELETE_TRACE)
namespace
{
  struct DeallocationTrace;
  thread_local DeallocationTrace* activeTrace = nullptr;

  struct DeallocationTrace
  {
    struct Entry
    {
      void* pointer = nullptr;
      int scalarCalls = 0;
      int arrayCalls = 0;
    };
    Entry entries[32]{};
    int size = 0;
    DeallocationTrace* previous = activeTrace;

    DeallocationTrace() { activeTrace = this; }
    ~DeallocationTrace() { activeTrace = previous; }

    void Watch(void* pointer) { entries[size++].pointer = pointer; }
    void Record(void* pointer, bool array)
    {
      for (int i = 0; i < size; ++i) {
        if (entries[i].pointer == pointer) {
          if (array) {
            ++entries[i].arrayCalls;
          } else {
            ++entries[i].scalarCalls;
          }
        }
      }
    }
  };
}

// GNU/LLVM linker wrapping observes overload selection without replacing the
// engine's allocator. Delegate every call to its unchanged real implementation.
extern "C" void __real__ZdlPv(void*) noexcept;
extern "C" void __real__ZdaPv(void*) noexcept;
extern "C" void __wrap__ZdlPv(void* pointer) noexcept
{
  if (activeTrace) activeTrace->Record(pointer, false);
  __real__ZdlPv(pointer);
}
extern "C" void __wrap__ZdaPv(void* pointer) noexcept
{
  if (activeTrace) activeTrace->Record(pointer, true);
  __real__ZdaPv(pointer);
}
#endif

namespace
{
  class OccupationManager : public ::testing::TestWithParam<int>
  {};

  // These cases execute the actual engine manager and its ordinary allocator.
  TEST_P(OccupationManager, BucketsChunksAndRepeatedGrowth)
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
    const int requested = GetParam();
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

  INSTANTIATE_TEST_SUITE_P(ChunkCounts, OccupationManager, ::testing::Values(0, 1, 16385, 155649));

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
  TEST(OccupationManagerDeallocation, EveryScalarAllocationUsesScalarDelete)
  {
    for (const int requested : {0, 1, 16385, 155649}) {
      DeallocationTrace trace;
      {
        moho::EntityOccupationManager manager(128, 256);
        manager.EnsureSize(requested);
        ASSERT_LE(manager.mAllBlocks.size() + 3, 32);
        trace.Watch(manager.mUnitBuckets);
        trace.Watch(manager.mPropBuckets);
        trace.Watch(manager.mEntityBuckets);
        for (auto* block : manager.mAllBlocks) trace.Watch(block);
      }
      // Stop observing before assertion reporting can allocate or reuse memory.
      activeTrace = trace.previous;
      for (int i = 0; i < trace.size; ++i) {
        EXPECT_EQ(trace.entries[i].scalarCalls, 1) << "request=" << requested << ", allocation=" << i;
        EXPECT_EQ(trace.entries[i].arrayCalls, 0) << "request=" << requested << ", allocation=" << i;
      }
    }
  }
#endif
}
