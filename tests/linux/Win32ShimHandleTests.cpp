// Engine addition (issue #259): the POSIX Win32 shim's handles behave as Windows' do when one
// thread closes a handle another thread still uses. ~CSimDriver closes its connection event while
// the UDP connector's thread may still signal it (CNetUDPConnector::SelectEvent's event); Windows
// fails that call with ERROR_INVALID_HANDLE, and the shim must not reach freed memory instead.

#include <gtest/gtest.h>

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <thread>

TEST(
  Win32ShimHandles,
  SignallingAClosedEventFails
)
{
  const HANDLE event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  ASSERT_NE(event, nullptr);
  ASSERT_TRUE(CloseHandle(event));
  EXPECT_FALSE(SetEvent(event));
  EXPECT_EQ(GetLastError(), static_cast<DWORD>(ERROR_INVALID_HANDLE));
  EXPECT_EQ(WaitForSingleObject(event, 0), WAIT_FAILED);
}

TEST(
  Win32ShimHandles,
  ClosingTwiceFailsTheSecondTime
)
{
  const HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  ASSERT_TRUE(CloseHandle(event));
  EXPECT_FALSE(CloseHandle(event));
  EXPECT_EQ(GetLastError(), static_cast<DWORD>(ERROR_INVALID_HANDLE));
}

TEST(
  Win32ShimHandles,
  AWaitOutlivesTheHandleClosedUnderIt
)
{
  // Windows keeps the object while a wait holds it; closing the handle doesn't signal it.
  const HANDLE event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  std::atomic<DWORD> result{0xFFFFFFFFu};
  std::thread waiter([&] {
    result = WaitForSingleObject(event, 300);
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  ASSERT_TRUE(CloseHandle(event));
  waiter.join();
  EXPECT_EQ(result.load(), static_cast<DWORD>(WAIT_TIMEOUT));
}

TEST(
  Win32ShimHandles,
  SignallingWhileTheOwnerClosesIsSafe
)
{
  // The ~CSimDriver order: a connector thread signals while the owner closes the event.
  for (int round = 0; round < 2000; ++round) {
    const HANDLE event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    std::atomic<bool> started{false};
    std::thread signaller([&] {
      started = true;
      while (SetEvent(event) != FALSE) {}
    });
    while (!started) {
      std::this_thread::yield();
    }
    ASSERT_TRUE(CloseHandle(event));
    signaller.join();
  }
}
