#pragma once
#include "boost/condition.h"
#include "boost/mutex.h"
#include <cstddef>
#include <cstdint>

namespace moho
{
  struct CWaitHandle
  {
    HANDLE* begin; // begin()
    HANDLE* end;   // end()
    HANDLE* cap;   // capacity end

    void reset() noexcept
    {
      begin = end = cap = nullptr;
    }
    [[nodiscard]] size_t size() const noexcept
    {
      return begin ? static_cast<size_t>(end - begin) : 0u;
    }
    [[nodiscard]] size_t capacity() const noexcept
    {
      return begin ? static_cast<size_t>(cap - begin) : 0u;
    }

    /**
     * Address: 0x00414A00
     *
     * Insert `count` copies of *value at position `pos` (vector::insert fill).
     * Only the first three fields (begin/end/cap) are used here.
     */
    HANDLE* AppendHandle(HANDLE* pos, unsigned count, const HANDLE* value);
  };
  static_assert(sizeof(CWaitHandle) == 0x0C, "CWaitHandle size must be 0x0C");

  class CWaitHandleSet
  {
  public:
    /**
     * Address: 0x00414220
     */
    CWaitHandleSet();

    /**
     * Address: 0x004143C0
     *
     * @param handle
     */
    void AddHandle(HANDLE handle);

    /**
     * Address: 0x004144D0
     *
     * @param handle
     */
    void RemoveHandle(HANDLE handle);

    /**
     * Address: 0x004145E0
     *
     * Wait for either a registered handle or window messages.
     */
    void MsgWaitEx(DWORD timeoutMs);

    /**
     * Address: 0x004145E0
     *
     * Compatibility wrapper retained while callsites migrate to MsgWaitEx naming.
     */
    void Wait(DWORD timeoutMs);

  public:
    boost::mutex lock;
    CWaitHandle handleSet;
    // +0x18 in FA layout: incremented while MsgWaitForMultipleObjectsEx is active.
    std::int32_t activeWaiters;
    boost::condition objectSender;
    // +0x34 in FA layout: number of AddHandle/RemoveHandle mutators in-flight.
    std::int32_t mutatorCount;
    boost::condition objectReceiver;
  };
} // namespace moho
