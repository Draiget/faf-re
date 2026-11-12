#pragma once

#include <chrono>
#include <cstdint>
#include <thread>
#include <utility>

namespace fa
{
  /**
   * The 2007 binary's `boost::xtime` (boost 1.34.1): an absolute UTC time in seconds and nanoseconds. Its layout
   * matters where a recovered type holds one (`ResourceManager::mLastLoadTime`, +0x60): 16 bytes.
   */
  struct xtime
  {
    std::int64_t sec;
    std::int_fast32_t nsec;
  };

  /** boost's TIME_UTC, the only clock the engine asks for. */
  constexpr int kXtimeUtc = 1;

  /** boost's xtime_get: the current UTC time (system clock since the Unix epoch). Returns the clock asked for. */
  inline int xtime_get(
    xtime* const out,
    const int clock
  )
  {
    const auto since = std::chrono::system_clock::now().time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(since);
    out->sec = static_cast<std::int64_t>(seconds.count());
    out->nsec =
      static_cast<std::int_fast32_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(since - seconds).count());
    return clock;
  }

  /** boost's xtime_cmp: negative, zero or positive as `a` is before, at or after `b`. */
  inline int xtime_cmp(
    const xtime& a,
    const xtime& b
  )
  {
    if (a.sec != b.sec) {
      return a.sec < b.sec ? -1 : 1;
    }
    return a.nsec < b.nsec ? -1 : (a.nsec > b.nsec ? 1 : 0);
  }

  /**
   * The 2007 binary's `boost::thread` (boost 1.34.1): starts the function at once and is held through a pointer.
   *
   * It keeps boost's rule for a thread object destroyed while its thread still runs: the thread goes on, detached.
   * `std::thread` would end the program there instead, and the engine deletes running threads on purpose
   * (`CGpgNetInterface`, `CReplayClient`, `WldSessionInfo` replace their worker, `CNetUDPConnector` starts one it
   * never joins). Like boost's, an exception that leaves the thread function ends the program.
   */
  class thread
  {
  public:
    template <class F>
    explicit thread(
      F&& function
    )
      : mThread(std::forward<F>(function))
    {}

    /**
     * Address: 0x00AC2760 (FUN_00AC2760, boost::thread::~thread)
     *
     * boost closes the thread handle when the object is still joinable (byte +0x08): the thread runs on,
     * detached. std::thread::detach does the same.
     */
    ~thread()
    {
      if (mThread.joinable()) {
        mThread.detach();
      }
    }

    thread(const thread&) = delete;
    thread& operator=(const thread&) = delete;

    /** Waits for the thread to finish. */
    void join()
    {
      if (mThread.joinable()) {
        mThread.join();
      }
    }

    /** boost's thread::sleep: sleeps the calling thread until the UTC time `until`. */
    static void sleep(
      const xtime& until
    )
    {
      const auto when = std::chrono::system_clock::time_point(
        std::chrono::duration_cast<std::chrono::system_clock::duration>(
          std::chrono::seconds(until.sec) + std::chrono::nanoseconds(until.nsec)
        )
      );
      std::this_thread::sleep_until(when);
    }

  private:
    std::thread mThread;
  };
} // namespace fa
