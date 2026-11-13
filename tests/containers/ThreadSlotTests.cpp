// gpg::core::TssPtr (a value per thread, deleted when the thread ends; the log context's per-thread state) and
// moho::THREAD_InvokeAsync (a callback queued to another thread, run in its next alertable wait).

#include "gpg/core/utils/Tss.h"
#include "moho/core/Thread.h"

#include <atomic>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

namespace
{
  // Each test uses its own value type: a TssPtr type has one slot per thread, and the main thread's slot
  // outlives a test.
  template <int Tag>
  struct Counted
  {
    inline static std::atomic<int> sDeleted{0};
    int value = 0;
  };

  template <int Tag>
  struct CountingDeleter
  {
    void operator()(
      Counted<Tag>* const value
    ) const noexcept
    {
      ++Counted<Tag>::sDeleted;
      delete value;
    }
  };
} // namespace

TEST(
  TssPtr,
  EachThreadSeesItsOwnValue
)
{
  using Value = Counted<1>;
  gpg::core::TssPtr<Value, CountingDeleter<1>> slot;
  EXPECT_EQ(slot.get(), nullptr);

  auto* const mine = new Value{};
  mine->value = 7;
  slot.reset(mine);
  EXPECT_EQ(slot.get(), mine);

  Value* seenByOther = mine;
  std::thread other([&] {
    seenByOther = slot.get();
  });
  other.join();
  EXPECT_EQ(seenByOther, nullptr);
  EXPECT_EQ(slot->value, 7);
}

TEST(
  TssPtr,
  ResetDeletesThePreviousValue
)
{
  using Value = Counted<2>;
  gpg::core::TssPtr<Value, CountingDeleter<2>> slot;
  slot.reset(new Value{});
  slot.reset(new Value{});
  EXPECT_EQ(Value::sDeleted.load(), 1);
  slot.reset();
  EXPECT_EQ(Value::sDeleted.load(), 2);
  EXPECT_EQ(slot.get(), nullptr);
}

TEST(
  TssPtr,
  AThreadsValueIsDeletedWhenTheThreadEnds
)
{
  using Value = Counted<3>;
  gpg::core::TssPtr<Value, CountingDeleter<3>> slot;
  std::thread worker([&] {
    slot.reset(new Value{});
  });
  worker.join();
  EXPECT_EQ(Value::sDeleted.load(), 1);
}

TEST(
  ThreadInvokeAsync,
  RunsInTheTargetThreadsAlertableWaitAndFreesTheCallback
)
{
  std::atomic<bool> ran{false};
  auto owned = std::make_shared<int>(0);
  std::thread target([&] {
    moho::THREAD_InvokeAsync([&ran, owned]() {
      ran = true;
    }, static_cast<std::uint32_t>(::GetCurrentThreadId()));
    ::SleepEx(1000, TRUE); // runs the queued call
  });
  target.join();
  EXPECT_TRUE(ran.load());
  EXPECT_EQ(owned.use_count(), 1); // the queued copy of the callback was freed after it ran
}
