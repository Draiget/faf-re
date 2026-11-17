// gpg/core/utils/Global: the engine allocator's public edges. The memory hook sees every allocation and free that
// goes through the engine's operator new / delete, GetHeapInfo reports the live heap, and Die hands its formatted
// message to the die handler. The hook records only on the test's own thread while a test arms it, into a fixed
// array, so it never allocates itself.

#include "gpg/core/utils/Global.h"

#include <gtest/gtest.h>

#include <cstdarg>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>

namespace
{
  struct HookCall
  {
    int op;
    int size;
    void* ptr;
  };

  thread_local bool tArmed = false;
  thread_local int tCount = 0;
  thread_local HookCall tCalls[64];

  void RecordingHook(
    const int op,
    const int size,
    ...
  )
  {
    if (!tArmed || tCount >= 64) {
      return;
    }
    va_list va;
    va_start(va, size);
    void* const ptr = va_arg(va, void*);
    va_end(va);
    tCalls[tCount++] = HookCall{op, size, ptr};
  }

  /** Arms the hook for one scope and removes it afterwards, so other tests run without it. */
  struct ArmedHook
  {
    ArmedHook()
    {
      tCount = 0;
      gpg::SetMemHook(&RecordingHook);
      tArmed = true;
    }
    ~ArmedHook()
    {
      tArmed = false;
      gpg::SetMemHook(nullptr);
    }
  };

  const HookCall* FindCall(
    const int op,
    const void* ptr
  )
  {
    for (int i = 0; i < tCount; ++i) {
      if (tCalls[i].op == op && tCalls[i].ptr == ptr) {
        return &tCalls[i];
      }
    }
    return nullptr;
  }

  void ThrowingDieHandler(
    const char* message
  )
  {
    throw std::runtime_error(message);
  }
} // namespace

// Allocations report (0, requested size, block); frees report (1, size, block), where the size is the block's on
// x86 and 0 on x64 (the x64 free path has no size to hand over).
TEST(
  Heap,
  MemHookSeesAllocationsAndFrees
)
{
  void* small = nullptr;
  void* large = nullptr;
  {
    ArmedHook hook;
    small = ::operator new(24);
    large = ::operator new(1u << 20);
    ::operator delete(small);
    ::operator delete(large);
  }

  const HookCall* const smallNew = FindCall(0, small);
  ASSERT_NE(smallNew, nullptr);
  EXPECT_EQ(smallNew->size, 24);
  const HookCall* const largeNew = FindCall(0, large);
  ASSERT_NE(largeNew, nullptr);
  EXPECT_EQ(largeNew->size, 1 << 20);
  EXPECT_NE(FindCall(1, small), nullptr);
  EXPECT_NE(FindCall(1, large), nullptr);

  // Removed again: nothing more is recorded.
  const int before = tCount;
  tArmed = true;
  delete new int(5);
  tArmed = false;
  EXPECT_EQ(tCount, before);
}

TEST(
  Heap,
  HeapInfoCountsALiveMegabyte
)
{
  gpg::GetHeapInfo(nullptr); // ignored

  gpg::HeapStats before{};
  gpg::GetHeapInfo(&before);
  EXPECT_GE(before.committed, before.inUse);
  EXPECT_GE(before.reserved, before.committed);

  // Scalar operator new, the path the memory hook test proves goes through the engine allocator on every platform.
  constexpr std::size_t kBytes = 4u << 20;
  auto* const block = static_cast<char*>(::operator new(kBytes));
  block[kBytes - 1] = 1;
  gpg::HeapStats during{};
  gpg::GetHeapInfo(&during);
  EXPECT_GE(during.inUse + during.inSmallBlocks, before.inUse + before.inSmallBlocks + kBytes / 2)
    << "a live 4 MB block shows in the counters";
  ::operator delete(block);

  gpg::HeapStats after{};
  gpg::GetHeapInfo(&after);
  EXPECT_LT(after.inUse + after.inSmallBlocks, during.inUse + during.inSmallBlocks);
}

TEST(
  Heap,
  DieFormatsItsMessageForTheDieHandler
)
{
  const gpg::die_handler_t previous = gpg::SetDieHandler(&ThrowingDieHandler);
  try {
    gpg::Die("fatal %s %d", "code", 7);
    ADD_FAILURE() << "Die returned";
  } catch (const std::runtime_error& error) {
    EXPECT_STREQ(error.what(), "fatal code 7");
  }
  EXPECT_EQ(gpg::SetDieHandler(previous), &ThrowingDieHandler) << "SetDieHandler returns the handler it replaces";
}
