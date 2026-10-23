#include "CWaitHandleSet.h"

#include <cstring>
#include <new>
#include <stdexcept>

using namespace moho;

/**
 * Address: 0x00414750 (FUN_00414750)
 *
 * What it does:
 * Resets begin/end/capacity pointers to an empty-vector state.
 */
void CWaitHandle::reset() noexcept
{
  begin = nullptr;
  end = nullptr;
  cap = nullptr;
}

/**
 * Address: 0x004147B0 (FUN_004147B0)
 *
 * What it does:
 * Returns the current number of HANDLE entries.
 */
size_t CWaitHandle::size() const noexcept
{
  return begin ? static_cast<size_t>(end - begin) : 0u;
}

size_t CWaitHandle::capacity() const noexcept
{
  return begin ? static_cast<size_t>(cap - begin) : 0u;
}

/**
 * Address: 0x00414A00 (FUN_00414A00)
 *
 * Insert `count` copies of `*value` at iterator `pos`.
 */
HANDLE* CWaitHandle::AppendHandle(HANDLE* pos, const unsigned count, const HANDLE* value)
{
  if (count == 0) {
    return end;
  }

  // Current size / capacity in elements (HANDLE is 4 bytes on x86)
  const unsigned curElems = begin ? static_cast<unsigned>(end - begin) : 0u;
  const unsigned capElems = begin ? static_cast<unsigned>(cap - begin) : 0u;

  // Overflow guard like in 0x00414A00 (0x3FFFFFFF accounts for 4-byte elems)
  constexpr unsigned maxElems = 0x3FFFFFFF;
  if (count > (maxElems - curElems)) {
    throw std::length_error("CWaitHandle::AppendHandle overflow");
  }

  // Fast path: enough capacity
  if (begin && capElems >= curElems + count) {
    if (pos == end) {
      // Pure append
      for (unsigned i = 0; i < count; ++i) {
        end[i] = *value;
      }
      end += count;
      return end;
    }

    const unsigned tail = static_cast<unsigned>(end - pos);

    if (tail >= count) {
      // Shift tail up by count
      std::memmove(pos + count, pos, tail * sizeof(HANDLE));
      // Fill the gap
      for (unsigned i = 0; i < count; ++i) {
        pos[i] = *value;
      }
      end += count;
      return end;
    }

    // Partly beyond old end
    const unsigned beyond = count - tail;

    // 1) Write the beyond-end part
    for (unsigned i = 0; i < beyond; ++i) {
      end[i] = *value;
    }

    // 2) Move the old tail up
    std::memmove(pos + count, pos, tail * sizeof(HANDLE));

    // 3) Fill the remaining gap
    for (unsigned i = 0; i < tail; ++i) {
      pos[i] = *value;
    }

    end += count;
    return end;
  }

  // Realloc path: grow ~1.5x, but at least curElems + count
  unsigned newCap = capElems + (capElems >> 1);
  const unsigned need = curElems + count;
  if (newCap < need) {
    newCap = need;
  }

  // Byte-size overflow check for operator new
  if (newCap && (0xFFFFFFFFu / newCap) < sizeof(HANDLE)) {
    throw std::bad_alloc();
  }

  const auto newBegin = static_cast<HANDLE*>(operator new(newCap * sizeof(HANDLE)));

  // Copy prefix [begin, pos)
  const unsigned prefix = begin ? static_cast<unsigned>(pos - begin) : 0u;
  if (prefix) {
    std::memmove(newBegin, begin, prefix * sizeof(HANDLE));
  }

  // Fill middle [prefix, prefix+count)
  for (unsigned i = 0; i < count; ++i) {
    newBegin[prefix + i] = *value;
  }

  // Copy suffix [pos, end)
  if (const unsigned suffix = curElems - prefix) {
    std::memmove(newBegin + prefix + count, pos, suffix * sizeof(HANDLE));
  }

  // Release old buffer
  if (begin) {
    operator delete(begin);
  }

  // Install new pointers
  begin = newBegin;
  end = newBegin + need;
  cap = newBegin + newCap;

  return end;
}

/**
 * Address: 0x00414220 (FUN_00414220)
 */
CWaitHandleSet::CWaitHandleSet()
{
  // Reset handle vector and synchronization counters.
  handleSet.reset();
  activeWaiters = 0;

  mutatorCount = 0;

  // Create the internal auto-reset event (gate)
  const HANDLE h = CreateEventW(nullptr, FALSE, FALSE, nullptr);

  // Fast in-place append if capacity is available, else grow via AppendHandle
  if (handleSet.begin &&
      static_cast<unsigned>(handleSet.end - handleSet.begin) < static_cast<unsigned>(handleSet.cap - handleSet.begin)) {
    *handleSet.end = h;
    ++handleSet.end;
  } else {
    handleSet.AppendHandle(handleSet.end, 1u, &h);
  }
}

/**
 * Address: 0x00414300 (FUN_00414300)
 *
 * What it does:
 * Closes the wake event handle and releases dynamic handle storage before
 * member teardown.
 */
CWaitHandleSet::~CWaitHandleSet()
{
  lock.lock();
  if (handleSet.begin != nullptr && *handleSet.begin != nullptr) {
    (void)::CloseHandle(*handleSet.begin);
  }
  lock.unlock();

  if (handleSet.begin != nullptr) {
    ::operator delete(handleSet.begin);
  }
  handleSet.reset();
}

/**
 * Address: 0x004143C0 (FUN_004143C0)
 */
void CWaitHandleSet::AddHandle(const HANDLE handle)
{
  boost::mutex::scoped_lock l(lock);

  // Producer enters
  ++mutatorCount;

  // Wait while the wait-thread side is inside MsgWaitForMultipleObjectsEx.
  while (activeWaiters != 0) {
    // First slot stores the internal auto-reset event created in the ctor.
    if (handleSet.begin && *handleSet.begin) {
      SetEvent(*handleSet.begin);
    }

    // Wait on sender condition; this releases the mutex and reacquires it upon wake.
    objectSender.wait(l);
  }

  // Fast path: capacity available -> append in place
  if (handleSet.begin &&
      static_cast<unsigned>(handleSet.end - handleSet.begin) < static_cast<unsigned>(handleSet.cap - handleSet.begin)) {
    *handleSet.end = handle;
    ++handleSet.end;
  } else {
    // Slow path: grow and insert
    handleSet.AppendHandle(handleSet.end, 1u, &handle);
  }

  // Producer leaves
  if (--mutatorCount == 0) {
    // Wake all consumers/waiters on the receiver side
    objectReceiver.notify_all();
  }
  // guard unlocks automatically here
}

/**
 * Address: 0x004144D0 (FUN_004144D0)
 */
void CWaitHandleSet::RemoveHandle(const HANDLE handle)
{
  boost::mutex::scoped_lock guard(lock);

  // Producer enters
  ++mutatorCount;

  // If the wait-thread side is busy, wake it and wait until it leaves.
  while (activeWaiters != 0) {
    if (handleSet.begin && *handleSet.begin) {
      SetEvent(*handleSet.begin);
    }
    objectSender.wait(guard);
  }

  // Erase 'h' from [begin, end)
  HANDLE* first = handleSet.begin;
  const HANDLE* last = handleSet.end;

  if (first && first != last) {
    HANDLE* it = first;
    for (; it != last; ++it) {
      if (*it == handle) {
        break;
      }
    }

    if (it != last) {
      const size_t tail = static_cast<size_t>(last - (it + 1));
      if (tail > 0) {
        std::memmove(it, it + 1, tail * sizeof(HANDLE));
      }
      --handleSet.end;
    }
  }

  // Producer leaves
  if (--mutatorCount == 0) {
    objectReceiver.notify_all();
  }
}

/**
 * Address: 0x004145E0 (FUN_004145E0)
 */
void CWaitHandleSet::MsgWaitEx(const DWORD timeoutMs)
{
  boost::mutex::scoped_lock guard(lock);

  for (;;) {
    while (mutatorCount != 0) {
      objectReceiver.wait(guard);
    }

    ++activeWaiters;
    guard.unlock();

    HANDLE* const handles = handleSet.begin;
    const DWORD handleCount = handles ? static_cast<DWORD>(handleSet.end - handleSet.begin) : 0u;
    const DWORD result = MsgWaitForMultipleObjectsEx(handleCount, handles, timeoutMs, 0x4FFu, 0x6u);

    guard.lock();
    --activeWaiters;
    if (activeWaiters == 0 && mutatorCount != 0) {
      objectSender.notify_all();
    }

    if (result == WAIT_OBJECT_0) {
      // Internal wake event (slot 0) fired; restart the wait loop.
      continue;
    }

    if (result == WAIT_FAILED) {
      throw std::runtime_error("CWaitHandleSet::Wait failed");
    }

    return;
  }
}

/**
  * Alias of FUN_004145E0 (non-canonical helper lane).
 *
 * Compatibility wrapper retained while callsites migrate to MsgWaitEx naming.
 */
void CWaitHandleSet::Wait(const DWORD timeoutMs)
{
  MsgWaitEx(timeoutMs);
}
