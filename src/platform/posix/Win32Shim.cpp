// Engine addition (dedicated-server plan WPL.5): POSIX implementations of the Win32 calls
// declared in platform/posix/win32/Windows.h, for the Linux build. Windows builds do not
// compile this file.

#if !defined(_WIN32)

#include "platform/posix/win32/Windows.h"

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <thread>

#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

namespace
{
  thread_local DWORD tLastError = 0;

  /// A Win32 event (manual or auto reset) or semaphore: the kernel objects the engine
  /// creates and waits on. A HANDLE is a pointer to one.
  struct WaitObject
  {
    enum class Kind { Event, Semaphore };

    Kind kind;
    bool manualReset = false;
    LONG count = 0; // event: 1 signalled, 0 not; semaphore: the count
    LONG maximum = 1;
    std::mutex mutex;
    std::condition_variable signalled;

    /// Takes the object when signalled (auto-reset events and semaphores consume it).
    [[nodiscard]] bool TryAcquireLocked() noexcept
    {
      if (count <= 0) {
        return false;
      }
      if (kind == Kind::Semaphore || !manualReset) {
        --count;
      }
      return true;
    }
  };

  [[nodiscard]] WaitObject* AsWaitObject(const HANDLE handle) noexcept
  {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
      return nullptr;
    }
    return static_cast<WaitObject*>(handle);
  }

  // GetCurrentThread / GetCurrentProcess pseudo handles, as on Windows.
  const HANDLE kCurrentThreadPseudoHandle = reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-2));
  const HANDLE kCurrentProcessPseudoHandle = reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1));
} // namespace

HANDLE CreateEventW(void*, const BOOL manualReset, const BOOL initialState, const wchar_t*)
{
  auto* const event = new WaitObject{};
  event->kind = WaitObject::Kind::Event;
  event->manualReset = manualReset != FALSE;
  event->count = initialState != FALSE ? 1 : 0;
  return event;
}

HANDLE CreateEventA(void* const attributes, const BOOL manualReset, const BOOL initialState, const char*)
{
  return CreateEventW(attributes, manualReset, initialState, nullptr);
}

HANDLE CreateSemaphoreW(void*, const LONG initialCount, const LONG maximumCount, const wchar_t*)
{
  auto* const semaphore = new WaitObject{};
  semaphore->kind = WaitObject::Kind::Semaphore;
  semaphore->count = initialCount;
  semaphore->maximum = maximumCount;
  return semaphore;
}

BOOL ReleaseSemaphore(const HANDLE handle, const LONG releaseCount, LONG* const previousCount)
{
  WaitObject* const object = AsWaitObject(handle);
  if (object == nullptr || object->kind != WaitObject::Kind::Semaphore || releaseCount <= 0) {
    return FALSE;
  }
  {
    std::lock_guard<std::mutex> lock(object->mutex);
    if (object->count + releaseCount > object->maximum) {
      return FALSE;
    }
    if (previousCount != nullptr) {
      *previousCount = object->count;
    }
    object->count += releaseCount;
  }
  object->signalled.notify_all();
  return TRUE;
}

BOOL SetEvent(const HANDLE handle)
{
  WaitObject* const object = AsWaitObject(handle);
  if (object == nullptr || object->kind != WaitObject::Kind::Event) {
    return FALSE;
  }
  {
    std::lock_guard<std::mutex> lock(object->mutex);
    object->count = 1;
  }
  if (object->manualReset) {
    object->signalled.notify_all();
  } else {
    object->signalled.notify_one();
  }
  return TRUE;
}

BOOL ResetEvent(const HANDLE handle)
{
  WaitObject* const object = AsWaitObject(handle);
  if (object == nullptr || object->kind != WaitObject::Kind::Event) {
    return FALSE;
  }
  std::lock_guard<std::mutex> lock(object->mutex);
  object->count = 0;
  return TRUE;
}

DWORD WaitForSingleObject(const HANDLE handle, const DWORD milliseconds)
{
  WaitObject* const object = AsWaitObject(handle);
  if (object == nullptr) {
    return WAIT_FAILED;
  }
  std::unique_lock<std::mutex> lock(object->mutex);
  if (milliseconds == INFINITE) {
    object->signalled.wait(lock, [object] { return object->count > 0; });
  } else if (!object->signalled.wait_for(
               lock, std::chrono::milliseconds(milliseconds), [object] { return object->count > 0; }
             )) {
    return WAIT_TIMEOUT;
  }
  (void)object->TryAcquireLocked();
  return WAIT_OBJECT_0;
}

DWORD WaitForSingleObjectEx(const HANDLE handle, const DWORD milliseconds, BOOL)
{
  return WaitForSingleObject(handle, milliseconds);
}

DWORD WaitForMultipleObjects(const DWORD count, const HANDLE* const handles, const BOOL waitAll, const DWORD milliseconds)
{
  // Polls: the engine waits on a handful of handles at most.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
  for (;;) {
    if (waitAll != FALSE) {
      bool all = true;
      for (DWORD index = 0; index < count && all; ++index) {
        WaitObject* const object = AsWaitObject(handles[index]);
        if (object == nullptr) {
          return WAIT_FAILED;
        }
        std::lock_guard<std::mutex> lock(object->mutex);
        all = object->count > 0;
      }
      if (all) {
        for (DWORD index = 0; index < count; ++index) {
          WaitObject* const object = AsWaitObject(handles[index]);
          std::lock_guard<std::mutex> lock(object->mutex);
          (void)object->TryAcquireLocked();
        }
        return WAIT_OBJECT_0;
      }
    } else {
      for (DWORD index = 0; index < count; ++index) {
        WaitObject* const object = AsWaitObject(handles[index]);
        if (object == nullptr) {
          return WAIT_FAILED;
        }
        std::lock_guard<std::mutex> lock(object->mutex);
        if (object->TryAcquireLocked()) {
          return WAIT_OBJECT_0 + index;
        }
      }
    }
    if (milliseconds != INFINITE && std::chrono::steady_clock::now() >= deadline) {
      return WAIT_TIMEOUT;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

BOOL CloseHandle(const HANDLE handle)
{
  if (handle == kCurrentThreadPseudoHandle || handle == kCurrentProcessPseudoHandle) {
    return TRUE;
  }
  WaitObject* const object = AsWaitObject(handle);
  if (object == nullptr) {
    return FALSE;
  }
  delete object;
  return TRUE;
}

DWORD GetCurrentThreadId()
{
  return static_cast<DWORD>(::syscall(SYS_gettid));
}

HANDLE GetCurrentThread()
{
  return kCurrentThreadPseudoHandle;
}

HANDLE GetCurrentProcess()
{
  return kCurrentProcessPseudoHandle;
}

DWORD GetCurrentProcessId()
{
  return static_cast<DWORD>(::getpid());
}

void Sleep(const DWORD milliseconds)
{
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

DWORD SleepEx(const DWORD milliseconds, BOOL)
{
  Sleep(milliseconds);
  return 0;
}

DWORD GetTickCount()
{
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  return static_cast<DWORD>(static_cast<std::uint64_t>(now.tv_sec) * 1000u + static_cast<std::uint64_t>(now.tv_nsec) / 1000000u);
}

BOOL QueryPerformanceCounter(LARGE_INTEGER* const count)
{
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  count->QuadPart = static_cast<std::int64_t>(now.tv_sec) * 1000000000LL + static_cast<std::int64_t>(now.tv_nsec);
  return TRUE;
}

BOOL QueryPerformanceFrequency(LARGE_INTEGER* const frequency)
{
  frequency->QuadPart = 1000000000LL; // QueryPerformanceCounter counts nanoseconds here
  return TRUE;
}

void GetSystemInfo(SYSTEM_INFO* const info)
{
  *info = SYSTEM_INFO{};
  info->dwPageSize = static_cast<DWORD>(::sysconf(_SC_PAGESIZE));
  const long processors = ::sysconf(_SC_NPROCESSORS_ONLN);
  info->dwNumberOfProcessors = processors > 0 ? static_cast<DWORD>(processors) : 1u;
  info->dwActiveProcessorMask = info->dwNumberOfProcessors >= sizeof(DWORD_PTR) * 8
                                  ? ~DWORD_PTR{0}
                                  : (DWORD_PTR{1} << info->dwNumberOfProcessors) - 1u;
  info->dwAllocationGranularity = 65536u;
}

DWORD GetLastError()
{
  return tLastError;
}

void SetLastError(const DWORD error)
{
  tLastError = error;
}

BOOL SetThreadPriority(HANDLE, int)
{
  // Thread priorities are a scheduling hint; the server keeps the default policy.
  return TRUE;
}

DWORD_PTR SetThreadAffinityMask(const HANDLE thread, const DWORD_PTR mask)
{
  if (thread != kCurrentThreadPseudoHandle || mask == 0) {
    return 0;
  }
  cpu_set_t previous;
  CPU_ZERO(&previous);
  (void)::pthread_getaffinity_np(::pthread_self(), sizeof(previous), &previous);
  cpu_set_t wanted;
  CPU_ZERO(&wanted);
  for (unsigned cpu = 0; cpu < sizeof(DWORD_PTR) * 8; ++cpu) {
    if ((mask & (DWORD_PTR{1} << cpu)) != 0) {
      CPU_SET(cpu, &wanted);
    }
  }
  if (::pthread_setaffinity_np(::pthread_self(), sizeof(wanted), &wanted) != 0) {
    return 0;
  }
  DWORD_PTR previousMask = 0;
  for (unsigned cpu = 0; cpu < sizeof(DWORD_PTR) * 8; ++cpu) {
    if (CPU_ISSET(cpu, &previous)) {
      previousMask |= DWORD_PTR{1} << cpu;
    }
  }
  return previousMask != 0 ? previousMask : 1u;
}

LPVOID VirtualAlloc(const LPVOID address, const SIZE_T size, const DWORD allocationType, const DWORD protect)
{
  const int protection = protect == PAGE_NOACCESS ? PROT_NONE : (PROT_READ | PROT_WRITE);
  if (address != nullptr && (allocationType & MEM_COMMIT) != 0 && (allocationType & MEM_RESERVE) == 0) {
    // Commit within a reservation.
    return ::mprotect(address, size, protection) == 0 ? address : nullptr;
  }
  void* const mapped = ::mmap(
    address, size, (allocationType & MEM_COMMIT) != 0 ? protection : PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
  );
  return mapped == MAP_FAILED ? nullptr : mapped;
}

BOOL VirtualFree(const LPVOID address, const SIZE_T size, const DWORD freeType)
{
  if ((freeType & MEM_RELEASE) != 0) {
    // MEM_RELEASE passes size 0 on Windows; the reservation's size is not known here.
    return size != 0 && ::munmap(address, size) == 0 ? TRUE : FALSE;
  }
  return ::mprotect(address, size, PROT_NONE) == 0 ? TRUE : FALSE;
}

#endif // !defined(_WIN32)
