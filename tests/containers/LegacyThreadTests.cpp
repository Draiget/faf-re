// fa::mutex, fa::recursive_mutex, fa::condition, fa::thread and fa::xtime (src/legacy/thread): the behaviour the
// engine relied on from boost 1.34.1's versions of them.

#include "legacy/thread/Condition.h"
#include "legacy/thread/Mutex.h"
#include "legacy/thread/Thread.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace
{
  using namespace std::chrono_literals;

  // Waits up to `limit` for `done`; the tests use it so a broken lock fails instead of hanging the run.
  bool WaitFor(
    const std::atomic<bool>& done,
    const std::chrono::milliseconds limit = 5000ms
  )
  {
    const auto until = std::chrono::steady_clock::now() + limit;
    while (!done.load()) {
      if (std::chrono::steady_clock::now() > until) {
        return false;
      }
      std::this_thread::sleep_for(1ms);
    }
    return true;
  }
} // namespace

// boost::mutex on Windows is a critical section, which its owner may take again (STAT_GetLuaTable relies on it).
TEST(
  LegacyThread,
  MutexOwnerMayLockAgain
)
{
  fa::mutex mutex;
  fa::mutex::scoped_lock outer(mutex);
  fa::mutex::scoped_lock inner(mutex);
  EXPECT_TRUE(outer.owns_lock());
  EXPECT_TRUE(inner.owns_lock());
}

// A wait on a recursive mutex held twice releases both levels, so another thread can take it, and restores both
// after waking: one unlock later the mutex is still held.
TEST(
  LegacyThread,
  RecursiveWaitReleasesEveryLevelAndRestoresThem
)
{
  fa::recursive_mutex mutex;
  fa::condition condition;
  bool signalled = false;
  std::atomic<bool> waiterWoke{false};
  std::atomic<bool> waiterHoldsOneLevel{false};
  std::atomic<bool> otherLocked{false};

  std::thread waiter([&] {
    fa::recursive_mutex::scoped_lock outer(mutex);
    fa::recursive_mutex::scoped_lock inner(mutex);
    while (!signalled) {
      condition.wait(inner);
    }
    waiterWoke = true;
    inner.unlock(); // one level left
    waiterHoldsOneLevel = true;
    std::this_thread::sleep_for(100ms); // the other thread must not get in meanwhile
    outer.unlock();
  });

  std::this_thread::sleep_for(50ms); // the waiter is in wait(), both levels released
  {
    fa::recursive_mutex::scoped_lock lock(mutex); // only possible if the wait released both levels
    signalled = true;
    condition.notify_all();
  }
  ASSERT_TRUE(WaitFor(waiterHoldsOneLevel));

  std::thread other([&] {
    fa::recursive_mutex::scoped_lock lock(mutex);
    otherLocked = true;
  });
  std::this_thread::sleep_for(50ms);
  EXPECT_FALSE(otherLocked.load()) << "the waiter's second level was not restored after the wait";
  waiter.join();
  other.join();
  EXPECT_TRUE(waiterWoke.load());
  EXPECT_TRUE(otherLocked.load());
}

// boost's Win32 condition never wakes a waiter without a notify, and a notify with nobody waiting is not kept for a
// later waiter: the waiter below wakes once, for the notify that sets the flag.
TEST(
  LegacyThread,
  ConditionWakesOnceForOneNotifyAndForgetsEarlierOnes
)
{
  fa::mutex mutex;
  fa::condition condition;
  condition.notify_all(); // nobody waits yet
  condition.notify_all();

  bool ready = false;
  int wakes = 0;
  std::atomic<bool> done{false};
  std::thread waiter([&] {
    fa::mutex::scoped_lock lock(mutex);
    while (!ready) {
      condition.wait(lock);
      ++wakes;
    }
    done = true;
  });
  std::this_thread::sleep_for(50ms);
  {
    fa::mutex::scoped_lock lock(mutex);
    ready = true;
    condition.notify_all();
  }
  ASSERT_TRUE(WaitFor(done));
  waiter.join();
#if FAFRE_PLATFORM_WINDOWS
  EXPECT_EQ(wakes, 1);
#else
  EXPECT_GE(wakes, 1); // pthread_cond_wait may wake spuriously, as boost's POSIX build did
#endif
}

// notify_all wakes every thread waiting at the time, round after round (the gate and the counters reset each time).
TEST(
  LegacyThread,
  NotifyAllWakesEveryWaiterEveryRound
)
{
  constexpr int kWaiters = 8;
  constexpr int kRounds = 200;
  fa::mutex mutex;
  fa::condition condition;
  int round = 0;
  int waiting = 0;
  std::vector<std::thread> threads;
  for (int i = 0; i < kWaiters; ++i) {
    threads.emplace_back([&] {
      fa::mutex::scoped_lock lock(mutex);
      for (int seen = 0; seen < kRounds; ++seen) {
        ++waiting;
        condition.notify_all(); // tell the driver one more waits
        const int mine = round;
        while (round == mine) {
          condition.wait(lock);
        }
      }
    });
  }
  std::atomic<bool> finished{false};
  std::thread driver([&] {
    for (int r = 0; r < kRounds; ++r) {
      fa::mutex::scoped_lock lock(mutex);
      while (waiting < kWaiters) {
        condition.wait(lock);
      }
      waiting = 0;
      ++round;
      condition.notify_all();
    }
    finished = true;
  });
  ASSERT_TRUE(WaitFor(finished, 30000ms)) << "a waiter missed a notify_all";
  driver.join();
  for (std::thread& t : threads) {
    t.join();
  }
  EXPECT_EQ(round, kRounds);
}

// A thread object destroyed while its thread runs lets the thread go on (boost 1.34), instead of ending the program.
TEST(
  LegacyThread,
  DestroyedRunningThreadDetaches
)
{
  std::atomic<bool> release{false};
  std::atomic<bool> finished{false};
  auto* const worker = new fa::thread([&] {
    while (!release.load()) {
      std::this_thread::sleep_for(1ms);
    }
    finished = true;
  });
  delete worker;
  release = true;
  EXPECT_TRUE(WaitFor(finished));
}

TEST(
  LegacyThread,
  JoinWaitsForTheThread
)
{
  std::atomic<bool> finished{false};
  fa::thread worker([&] {
    std::this_thread::sleep_for(20ms);
    finished = true;
  });
  worker.join();
  EXPECT_TRUE(finished.load());
  worker.join(); // a second join does nothing
}

TEST(
  LegacyThread,
  XtimeIsUtcAndSleepWaitsUntilIt
)
{
  fa::xtime now{};
  EXPECT_EQ(fa::xtime_get(&now, fa::kXtimeUtc), fa::kXtimeUtc);
  const auto systemSeconds =
    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  EXPECT_LE(std::abs(now.sec - static_cast<std::int64_t>(systemSeconds)), 1);
  EXPECT_GE(now.nsec, 0);
  EXPECT_LT(now.nsec, 1000000000);

  fa::xtime later = now;
  later.nsec += 50 * 1000000;
  if (later.nsec >= 1000000000) {
    later.nsec -= 1000000000;
    ++later.sec;
  }
  EXPECT_LT(fa::xtime_cmp(now, later), 0);
  EXPECT_GT(fa::xtime_cmp(later, now), 0);
  EXPECT_EQ(fa::xtime_cmp(now, now), 0);

  const auto start = std::chrono::steady_clock::now();
  fa::thread::sleep(later);
  EXPECT_GE(std::chrono::steady_clock::now() - start, 40ms);
}
