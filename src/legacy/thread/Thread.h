#pragma once

#include <thread>
#include <utility>

namespace fa
{
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

    /**
     * Waits for the thread to finish. Like boost's, it never throws: called on the thread itself, where
     * `std::thread::join` would throw `resource_deadlock_would_occur`, it detaches instead, so the thread
     * runs on as it does when its object is destroyed.
     */
    void join() noexcept
    {
      if (!mThread.joinable()) {
        return;
      }
      if (mThread.get_id() == std::this_thread::get_id()) {
        mThread.detach();
        return;
      }
      mThread.join();
    }

  private:
    std::thread mThread;
  };
} // namespace fa
