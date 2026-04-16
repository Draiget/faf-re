#pragma once
#include "boost/condition.h"
#include "boost/mutex.h"
#include <cstddef>
#include <cstdint>
#include "platform/Platform.h"

namespace moho
{
  struct CWaitHandle
  {
    HANDLE* begin; // begin()
    HANDLE* end;   // end()
    HANDLE* cap;   // capacity end

    /**
     * Address: 0x00414750 (FUN_00414750)
     *
     * What it does:
     * Resets begin/end/capacity pointers to an empty-vector state.
     */
    void reset() noexcept;

    /**
     * Address: 0x004147B0 (FUN_004147B0)
     *
     * What it does:
     * Returns the current number of stored HANDLE entries.
     */
    [[nodiscard]] size_t size() const noexcept;

    [[nodiscard]] size_t capacity() const noexcept;

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
     * Address: 0x00414300 (FUN_00414300)
     *
     * What it does:
     * Tears down runtime wait-handle storage and closes the wake event.
     */
    ~CWaitHandleSet();

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
       * Address: 0x004145E0 (FUN_004145E0)
     *
     * Wait for either a registered handle or window messages.
     */
    void MsgWaitEx(DWORD timeoutMs);

    /**
      * Alias of FUN_004145E0 (non-canonical helper lane).
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

#if defined(MOHO_ABI_MSVC8_COMPAT)
  static_assert(offsetof(CWaitHandleSet, handleSet) == 0x0C, "CWaitHandleSet::handleSet offset must be 0x0C");
  static_assert(offsetof(CWaitHandleSet, activeWaiters) == 0x18, "CWaitHandleSet::activeWaiters offset must be 0x18");
  static_assert(offsetof(CWaitHandleSet, objectSender) == 0x1C, "CWaitHandleSet::objectSender offset must be 0x1C");
  static_assert(offsetof(CWaitHandleSet, mutatorCount) == 0x34, "CWaitHandleSet::mutatorCount offset must be 0x34");
  static_assert(offsetof(CWaitHandleSet, objectReceiver) == 0x38, "CWaitHandleSet::objectReceiver offset must be 0x38");
  static_assert(sizeof(CWaitHandleSet) == 0x50, "CWaitHandleSet size must be 0x50");
#endif
} // namespace moho
